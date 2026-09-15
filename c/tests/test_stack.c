/* Stack-overflow regression test.
 *
 * The proof-system structs are enormous — wabisabi_statement_t is ~585 KB and
 * wabisabi_knowledge_t is ~590 KB (each wabisabi_ge_t wraps a 64-byte
 * secp256k1_pubkey, and a statement holds a dense sparse-generator matrix).
 * They must never live on the stack: an earlier version returned them by value
 * from the proof.c constructors, which put a ~585 KB frame on the call stack.
 * On Linux's ~8 MB worker stacks this was invisible, but on the ~1 MB Windows
 * (and macOS non-main) thread-pool stacks it overflowed. The .NET CLR reported
 * it as "Stack overflow." at the P/Invoke boundary (e.g. IssuerHandleZero).
 *
 * This test reproduces that low-stack condition *deterministically on every
 * architecture* by running the full FFI protocol round-trip on a thread whose
 * stack is capped well below what the old by-value code needed (~650 KB for a
 * single builder frame) yet far above what the fixed out-pointer code uses
 * (~135 KB peak, dominated by the FFI request/response buffers). If a
 * regression reintroduces a large stack local, this thread overflows and the
 * process dies with a non-zero status — failing CI. With the fix it completes
 * and returns 0.
 *
 * It intentionally drives the exported C ABI (wabisabi_ffi.h) — the exact entry
 * points the managed WabiSabi.Native wrappers P/Invoke — rather than the
 * internal helpers, so it guards the real crashing path.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wabisabi_ffi.h"

/* Cap the worker stack below the old code's single-builder frame (~650 KB) and
 * well above the fixed code's peak (~135 KB). 512 KiB satisfies both on x64 and
 * arm64, Windows/macOS/Linux. */
#define WABI_TEST_STACK_BYTES (512 * 1024)

/* Large FFI I/O buffers are heap-allocated (as the managed marshaller does),
 * so the pressure under test is the library's own internal frames, not our
 * scratch buffers. */
static int
ffi_full_roundtrip(void) {
    int rc = 100; /* generic allocation failure sentinel */

    uint8_t sk[WABISABI_SK_SIZE];
    uint8_t iparams[WABISABI_IPARAMS_SIZE];
    uint8_t rand_zero_client[WABISABI_RAND_SIZE];
    uint8_t rand_zero_issuer[WABISABI_RAND_SIZE];
    uint8_t rand_real_client[WABISABI_RAND_SIZE];
    uint8_t rand_real_issuer[WABISABI_RAND_SIZE];
    uint8_t zero_val[WABISABI_VALIDATION_SIZE];
    uint8_t real_val[WABISABI_VALIDATION_SIZE];
    uint8_t mstate[WABISABI_ISSUER_MSTATE_MAX_SIZE];
    int mstate_len = 0;

    /* Distinct, deterministic, valid (nonzero, < curve order) byte patterns. */
    for (int i = 0; i < WABISABI_SK_SIZE; i++) sk[i] = (uint8_t)(1 + (i % 5));
    memset(rand_zero_client, 0x42, sizeof(rand_zero_client));
    memset(rand_zero_issuer, 0x37, sizeof(rand_zero_issuer));
    memset(rand_real_client, 0x5a, sizeof(rand_real_client));
    memset(rand_real_issuer, 0x6b, sizeof(rand_real_issuer));

    uint8_t* req = malloc(WABISABI_MAX_REQUEST_SIZE);
    uint8_t* resp = malloc(WABISABI_MAX_REQUEST_SIZE);
    uint8_t* creds = malloc((size_t)WABISABI_CREDENTIAL_COUNT * WABISABI_CREDENTIAL_SIZE);
    uint8_t* new_creds = malloc((size_t)WABISABI_CREDENTIAL_COUNT * WABISABI_CREDENTIAL_SIZE);
    if (!req || !resp || !creds || !new_creds) {
        goto done;
    }

    const int64_t max_amount = 1000000;

    if (wabisabi_iparams_from_sk(sk, iparams) != WABISABI_OK) { rc = 1; goto done; }

    /* --- Bootstrap (zero) round-trip --- */
    int req_len = 0;
    if (wabisabi_client_create_zero_request(rand_zero_client, req, WABISABI_MAX_REQUEST_SIZE, &req_len, zero_val)
        != WABISABI_OK) { rc = 2; goto done; }

    int resp_len = 0;
    if (wabisabi_issuer_handle_zero(sk, max_amount, NULL, 0, req, req_len, rand_zero_issuer,
                                    resp, WABISABI_MAX_REQUEST_SIZE, &resp_len,
                                    mstate, WABISABI_ISSUER_MSTATE_MAX_SIZE, &mstate_len) != WABISABI_OK) {
        rc = 3; goto done;
    }

    int n_creds = 0;
    if (wabisabi_client_handle_response(iparams, resp, resp_len, zero_val, creds,
                                        WABISABI_CREDENTIAL_COUNT * WABISABI_CREDENTIAL_SIZE, &n_creds)
        != WABISABI_OK) { rc = 4; goto done; }
    if (n_creds != WABISABI_CREDENTIAL_COUNT) { rc = 5; goto done; }

    /* --- Real (input registration) round-trip: exercises range proofs, the
     * widest statements and thus the deepest frames. --- */
    const int64_t amounts[WABISABI_CREDENTIAL_COUNT] = {500000, 300000};
    req_len = 0;
    if (wabisabi_client_create_real_request(iparams, max_amount, amounts, WABISABI_CREDENTIAL_COUNT,
                                            creds, WABISABI_CREDENTIAL_COUNT, rand_real_client,
                                            req, WABISABI_MAX_REQUEST_SIZE, &req_len, real_val) != WABISABI_OK) {
        rc = 6; goto done;
    }

    uint8_t mstate2[WABISABI_ISSUER_MSTATE_MAX_SIZE];
    int mstate2_len = 0;
    resp_len = 0;
    if (wabisabi_issuer_handle_real(sk, max_amount, mstate, mstate_len, req, req_len, rand_real_issuer,
                                    resp, WABISABI_MAX_REQUEST_SIZE, &resp_len,
                                    mstate2, WABISABI_ISSUER_MSTATE_MAX_SIZE, &mstate2_len) != WABISABI_OK) {
        rc = 7; goto done;
    }

    n_creds = 0;
    if (wabisabi_client_handle_response(iparams, resp, resp_len, real_val, new_creds,
                                        WABISABI_CREDENTIAL_COUNT * WABISABI_CREDENTIAL_SIZE, &n_creds)
        != WABISABI_OK) { rc = 8; goto done; }
    if (n_creds != WABISABI_CREDENTIAL_COUNT) { rc = 9; goto done; }

    rc = 0; /* full round-trip completed on the constrained stack */

done:
    free(req);
    free(resp);
    free(creds);
    free(new_creds);
    return rc;
}

/* ---- Portable "run on a small stack" thread wrapper ---- */

#if defined(_WIN32)
#include <windows.h>

static DWORD WINAPI
stack_worker(LPVOID arg) {
    *(int*)arg = ffi_full_roundtrip();
    return 0;
}

static int
run_on_small_stack(int* out_status) {
    /* STACK_SIZE_PARAM_IS_A_RESERVATION makes dwStackSize the *reserved* size;
     * without it Windows would still reserve the PE header default (~1 MB) and
     * the cap would not take effect. */
    HANDLE h = CreateThread(NULL, WABI_TEST_STACK_BYTES, stack_worker, out_status,
                            STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (h == NULL) {
        return -1;
    }
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    return 0;
}

#else
#include <pthread.h>

static void*
stack_worker(void* arg) {
    *(int*)arg = ffi_full_roundtrip();
    return NULL;
}

static int
run_on_small_stack(int* out_status) {
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        return -1;
    }
    if (pthread_attr_setstacksize(&attr, WABI_TEST_STACK_BYTES) != 0) {
        pthread_attr_destroy(&attr);
        return -1;
    }
    pthread_t th;
    int rc = pthread_create(&th, &attr, stack_worker, out_status);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        return -1;
    }
    pthread_join(th, NULL);
    return 0;
}
#endif

int run_stack_tests(void);

int
run_stack_tests(void) {
    printf("Testing FFI round-trip on a %d KiB stack (overflow regression)...\n", WABI_TEST_STACK_BYTES / 1024);

    int status = -999;
    if (run_on_small_stack(&status) != 0) {
        printf("  ERROR: could not create the constrained-stack thread\n");
        return 1;
    }
    if (status != 0) {
        printf("  ERROR: FFI round-trip failed on the small stack (status %d)\n", status);
        return 1;
    }

    printf("  Small-stack FFI round-trip OK — no stack overflow\n");
    return 0;
}
