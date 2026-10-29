// Disposable instrumentation target. Never attaches to WeChat.
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((noinline, visibility("default")))
void wmpf_smoke_tick(unsigned n) { __asm__ volatile("" : : "r"(n) : "memory"); }

static void *load_images(void *ignored) {
    (void)ignored;
    for (;;) {
        void *h = dlopen("/usr/lib/libobjc.A.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (h) dlclose(h);
        usleep(20000);
    }
    return NULL;
}
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    pthread_t worker;
    pthread_create(&worker, NULL, load_images, NULL);
    for (unsigned n = 1;; n++) {
        wmpf_smoke_tick(n);
        printf("heartbeat %u\n", n);
        usleep(50000);
    }
}
