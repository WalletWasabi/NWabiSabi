/* Concurrent first-initialization regression test.
 *
 * The generators (WABISABI_Gw, WABISABI_Gh, ...) are global state that starts in
 * the zero-initialized BSS: a wabisabi_ge_t whose pk is all-zero and whose
 * is_infinity flag is 0. That is an invalid secp256k1 point (not a real point,
 * and not the encoded infinity). wabisabi_generators_init() fills them in.
 *
 * Before the one-time-init guard, wabisabi_init() ran ctx_init() then
 * generators_init() with no synchronization. Two threads calling in for the
 * first time could interleave so that one set WABISABI_CTX (a valid context)
 * while the generators were still zero, and a second thread proceeding to a
 * crypto op fed a zero pubkey to secp256k1 -> its ARG_CHECK fired
 * ("illegal argument: !secp256k1_fe_is_zero(&ge->x)") -> abort(). On Linux's
 * single-threaded test runs this never showed; under WalletWasabi's parallel
 * test suite on Windows it aborted the whole run (exit code 3).
 *
 * This test reproduces that window deterministically: it MUST run before any
 * other init (so the generators are still zero), then launches many threads that
 * each hit an exported FFI entry point (which self-initializes) at once. With the
 * fix every caller blocks until initialization is complete, so none observes a
 * zero generator. Without the fix this aborts the process. It drives the exported
 * C ABI — the exact path the managed/host wrappers P/Invoke.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wabisabi_ffi.h"

#define WABI_CONC_THREADS 32

/* Each worker races the first initialization, then performs a crypto op that
 * dereferences the generators (iparams = w*Gw + wp*Gwp, I = GV - ...). */
static void
conc_worker_body(void) {
    uint8_t sk[WABISABI_SK_SIZE];
    for (int i = 0; i < WABISABI_SK_SIZE; i++) {
        sk[i] = (uint8_t)(1 + (i % 5));
    }
    uint8_t iparams[WABISABI_IPARAMS_SIZE];
    /* wabisabi_iparams_from_sk self-initializes and uses the generators. */
    (void)wabisabi_iparams_from_sk(sk, iparams);
}

#if defined(_WIN32)
#include <windows.h>

static DWORD WINAPI
conc_worker(LPVOID arg) {
    (void)arg;
    conc_worker_body();
    return 0;
}

static int
run_concurrent_first_init(void) {
    HANDLE th[WABI_CONC_THREADS];
    for (int i = 0; i < WABI_CONC_THREADS; i++) {
        th[i] = CreateThread(NULL, 0, conc_worker, NULL, 0, NULL);
        if (th[i] == NULL) {
            return -1;
        }
    }
    WaitForMultipleObjects(WABI_CONC_THREADS, th, TRUE, INFINITE);
    for (int i = 0; i < WABI_CONC_THREADS; i++) {
        CloseHandle(th[i]);
    }
    return 0;
}

#else
#include <pthread.h>

static void*
conc_worker(void* arg) {
    (void)arg;
    conc_worker_body();
    return NULL;
}

static int
run_concurrent_first_init(void) {
    pthread_t th[WABI_CONC_THREADS];
    for (int i = 0; i < WABI_CONC_THREADS; i++) {
        if (pthread_create(&th[i], NULL, conc_worker, NULL) != 0) {
            return -1;
        }
    }
    for (int i = 0; i < WABI_CONC_THREADS; i++) {
        pthread_join(th[i], NULL);
    }
    return 0;
}
#endif

int run_concurrency_tests(void);

int
run_concurrency_tests(void) {
    printf("Testing concurrent first-init (%d threads racing library init)...\n", WABI_CONC_THREADS);
    if (run_concurrent_first_init() != 0) {
        printf("  ERROR: could not create the concurrency worker threads\n");
        return 1;
    }
    printf("  Concurrent first-init OK — no zero-generator abort\n");
    return 0;
}
