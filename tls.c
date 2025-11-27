#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

/* Structs */

typedef struct page {
    void *addr;
    int ref_count;
} page_t;

typedef struct tls {
    pthread_t tid;
    unsigned int size;
    unsigned int page_count;
    page_t **pages;

    struct tls *next;
} tls_t;

/* Global variables */

static tls_t *tls_ll = NULL;
static unsigned int page_size = 0;
static pthread_once_t once_control = PTHREAD_ONCE_INIT;

/* Function declarations */

// Helpers
static tls_t *find_tls(pthread_t tid);
static void ensure_private_page(tls_t *t, unsigned int index);

static void init_tls();
static void sigsegv_handler(int sig, siginfo_t *si, void *ctx);

// Actual tls api functions
int tls_create(unsigned int size);
int tls_write(unsigned int offset, unsigned int length, char *buffer);
int tls_read(unsigned int offset, unsigned int length, char *buffer);
int tls_destroy();
int tls_clone(pthread_t tid);

void *tls_get_internal_start_address();

/* Function definitions */

static tls_t *find_tls(pthread_t tid) {
    for (tls_t *t = tls_ll; t; t = t->next) {
        if (pthread_equal(t->tid, tid)) {
            return t;
        }
    }

    return NULL;
}

static void ensure_private_page(tls_t *t, unsigned int index) {
    page_t *page = t->pages[index];

    if (page->ref_count > 1) {
        void *new_addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        mprotect(page->addr, page_size, PROT_READ);
        memcpy(new_addr, page->addr, page_size);
        mprotect(page->addr, page_size, PROT_NONE);

        page->ref_count--;

        page_t *new_page = (page_t*)malloc(sizeof(page_t*));
        new_page->addr = new_addr;
        new_page->ref_count = 1;
        t->pages[index] = new_page;
        mprotect(new_addr, page_size, PROT_NONE);
    }
}

static void init_tls() {
    page_size = getpagesize();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    
    sigaction(SIGSEGV, &sa, NULL);    
#ifdef SIGBUS
    sigaction(SIGBUS, &sa, NULL);
#endif
}

static void sigsegv_handler(int sig, siginfo_t *si, void *ctx) {
    void *fault_addr = si->si_addr;
    
    for (tls_t *t = tls_ll; t; t = t->next) {
        for (int i = 0; i < t->page_count; i++) {
            void *page_start = t->pages[i]->addr;
            void *page_end = (char*)t->pages[i]->addr + page_size;

            if (fault_addr >= page_start && fault_addr < page_end) {
                pthread_exit(NULL);
            }
        }
    }

    struct sigaction sa;
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
    raise(sig);
}

int tls_create(unsigned int size) {
    pthread_once(&once_control, init_tls);
    
    if (size == 0 || find_tls(pthread_self())) {    
        return -1;
    }
    
    tls_t *t = (tls_t*)malloc(sizeof(tls_t));
    t->size = size;
    t->tid = pthread_self();
    t->page_count = (size + page_size - 1) / page_size;
    t->pages = (page_t**)calloc(t->page_count, sizeof(page_t*));
    
    for (int i = 0; i < t->page_count; i++) {
        page_t *page = (page_t*)malloc(sizeof(page_t*));
        page->addr = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, - 1, 0);
        page->ref_count = 1;
        t->pages[i] = page;
    }

    t->next = tls_ll;
    tls_ll = t;

    return 0;
}

int tls_write(unsigned int offset, unsigned int length, char *buffer) {
    pthread_once(&once_control, init_tls);
    
    if (length == 0) {
        return 0;
    }
    
    tls_t *t = find_tls(pthread_self());

    if (!t || offset + length > t->size)
        return -1;

    unsigned int first = offset / page_size;
    unsigned int last  = (offset + length - 1) / page_size;

    for (int i = first; i <= last; i++) {
        ensure_private_page(t, i);
        mprotect(t->pages[i]->addr, page_size, PROT_READ | PROT_WRITE);
    }
    
    unsigned int remaining = length;
    unsigned int pos = offset;

    while (remaining > 0) {
        int p = pos / page_size;
        int off = pos % page_size;
        int chunk = page_size - off;
        
        if (chunk > (int)remaining) {
            chunk = remaining;
        }
        
        memcpy((char*)t->pages[p]->addr + off, buffer + (length - remaining), chunk);

        remaining -= chunk;
        pos += chunk;
    }

    for (int i = first; i <= last; i++) {
        mprotect(t->pages[i]->addr, page_size, PROT_NONE);
    }

    return 0;
}

int tls_read(unsigned int offset, unsigned int length, char *buffer) {
    pthread_once(&once_control, init_tls);
    
    if (length == 0) {
        return 0;
    }

    tls_t *t = find_tls(pthread_self());

    if (!t || offset + length > t->size) {
        return -1;
    }

    unsigned int first = offset / page_size;
    unsigned int last  = (offset + length - 1) / page_size;

    for (int i = first; i <= last; i++) {
        mprotect(t->pages[i]->addr, page_size, PROT_READ);
    }

    unsigned int remaining = length;
    unsigned int pos = offset;

    while (remaining > 0) {
        int p = pos / page_size;
        int off = pos % page_size;
        int chunk = page_size - off;
        
        if (chunk > (int)remaining) {
            chunk = remaining;
        }
        
        memcpy(buffer + (length - remaining), (char*)t->pages[p]->addr + off, chunk);

        remaining -= chunk;
        pos += chunk;
    }

    for (int i = first; i <= last; i++) {
        mprotect(t->pages[i]->addr, page_size, PROT_NONE);
    }

    return 0;
}

int tls_destroy() {
    pthread_once(&once_control, init_tls);
    
    tls_t *prev = NULL;
    tls_t *t = tls_ll;
    pthread_t self = pthread_self();

    while(t && !pthread_equal(t->tid, self)) {
        prev = t;
        t = t->next;
    }

    if (!t) {
        return -1;
    }

    if(prev) {
        prev->next = t->next;
    } else {
        tls_ll = t->next;
    }

    for(int i = 0; i < t->page_count; i++) {
        if (t->pages[i]->ref_count > 1) {
            t->pages[i]->ref_count--;
        } else {
            munmap(t->pages[i]->addr, page_size);
            free(t->pages[i]);
        }
    }
    
    free(t->pages);
    free(t);

    return 0;
}

int tls_clone(pthread_t tid) {
    pthread_once(&once_control, init_tls);
    
    if (find_tls(pthread_self())) {
        return -1; 
    }

    tls_t *src = find_tls(tid);
    
    if(!src) {
        return -1;
    }

    tls_t *t = (tls_t*)malloc(sizeof(tls_t));
    t->size = src->size;
    t->tid = pthread_self();
    t->page_count = src->page_count;
    t->pages = (page_t**)calloc(t->page_count, sizeof(page_t*));
    
    for(int i = 0; i < t->page_count; i++) {
        t->pages[i] = src->pages[i];
        t->pages[i]->ref_count++;
    }

    t->next = tls_ll;
    tls_ll = t;

    return 0;
}

void *tls_get_internal_start_address() {
    pthread_once(&once_control, init_tls);

    tls_t *t = find_tls(pthread_self());

    if (!t || t->page_count == 0) {
        return NULL;
    }

    return t->pages[0]->addr; 
}
