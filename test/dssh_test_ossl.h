/*
 * dssh_test_ossl.h -- OpenSSL + C11 threads failure injection.
 *
 * Under DSSH_TESTING, library calls to OpenSSL and C11 thread
 * functions are redirected via macros in ssh-internal.h.  This
 * header declares the wrapper functions and control API.
 *
 * The wrappers use a shared atomic countdown: each failable call
 * decrements the counter, and when it reaches zero, returns the
 * appropriate failure value (NULL, 0, thrd_error).  Non-failable
 * calls (free, destroy, cleanse) are not wrapped.
 */

#ifndef DSSH_TEST_OSSL_H
#define DSSH_TEST_OSSL_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <threads.h>
#include <time.h>

/*
 * Control API -- call from test code (NOT redirected).
 */
void dssh_test_ossl_reset(void);
void dssh_test_ossl_fail_after(int n);
void dssh_test_ossl_exclude_thread(void);
int  dssh_test_ossl_count(void);

/* Thread-local reported-metadata overrides for helper boundary tests.
 * Real computation still runs; reset disables the overrides. */
void dssh_test_ossl_md_size(int value);
void dssh_test_ossl_digest_length(unsigned int value);
void dssh_test_ossl_encoded_length(int value);
void dssh_test_ossl_encrypt_length(int value);
bool dssh_test_ossl_encrypt_observed(int *actual_length);
/* Observe the actual private RNG request. Post-failure runs native generation
 * first and reports failure afterward; it does not promise output rollback. */
void dssh_test_ossl_random_post_failure(bool enabled);
bool dssh_test_ossl_random_observed(size_t *length, unsigned int *strength, bool *native_completed);

/*
 * Separate countdown for lock/condvar wrappers and the legacy join hook.
 * Independent of the OpenSSL + init countdown.
 * dssh_test_ossl_reset() resets both countdowns.
 */
void dssh_test_thrd_fail_after(int n);
void dssh_test_thrd_reset(void);
int  dssh_test_thrd_count(void);
/* Target join independently of earlier termination/wake operations. */
void dssh_test_join_fail_next(void);
int dssh_test_join_count(void);

/* Reject one acquisition of this mutex on the current thread. Record and
 * suppress any subsequent unlock without a successful reacquisition: the
 * fixture must never invoke a native unlock on an unowned mutex. */
void dssh_test_mtx_reject_once(mtx_t *mutex);
unsigned dssh_test_mtx_rejected_unlocks(void);
/* Fatal-path control, independent of the recoverable operation countdown.
 * skip is the number of successful matching releases before reporting failure.
 * release_real distinguishes retained ownership from error after real release. */
void dssh_test_unlock_fail_after(mtx_t *mutex, unsigned skip, bool release_real);

/* Target termination wake operations on the controlling thread. Report the
 * final selected failure for fresh-process provenance. complete_real chooses
 * failure before or after performing the native operation. */
void dssh_test_wake_lock(mtx_t *mutex, bool complete_real);
void dssh_test_wake_condition(cnd_t *condition, unsigned failures,
    bool complete_real, bool report);
unsigned dssh_test_wake_hits(void);

/* Observe entry into an actual wait wrapper for this condition. No callback
 * is invoked under the mutex. Configure/disable while no waiter can race a
 * reconfiguration; the returned flag has process lifetime. */
atomic_bool *dssh_test_thrd_watch_condition(cnd_t *condition);

/* Pause a matching native acquisition before calling mtx_lock. Configure and
 * disable only while no worker can race reconfiguration; resume before join. */
atomic_bool *dssh_test_thrd_pause_mutex(mtx_t *mutex);
/* Current-thread-only pause after skip matching acquisitions. */
atomic_bool *dssh_test_thrd_pause_mutex_after(mtx_t *mutex, unsigned skip);
void dssh_test_thrd_resume_mutex(void);

/* Target one valid condition wait on this thread. The first matching call
 * reports result, optionally after a real native wait/reacquisition. A test
 * controller acknowledges returning only after observing the owned mutex.
 * Later matching calls run normally and count repeated predicate waits.
 * Only the waiter writes non-atomic release statistics; read them after join.
 * Initialize all fields and keep the record live until that waiter joins. */
struct dssh_test_wait_probe {
	cnd_t *condition;
	mtx_t *mutex;
	atomic_uint calls;
	atomic_uint native_calls;
	atomic_int native_result;
	atomic_bool returning;
	atomic_bool release;
	unsigned releases;
	int unlock_result;
	int result;
	bool complete_real;
	bool until_timeout;
	bool timed;
};
void dssh_test_wait_probe(struct dssh_test_wait_probe *probe);

/* Observe wrapped library ownership of one mutex on this thread. Configure
 * with no ownership of that mutex; native test/controller calls are not counted.
 * No callback or native mutex operation occurs when querying the flag. */
void dssh_test_mtx_watch_ownership(mtx_t *mutex);
bool dssh_test_mtx_ownership(void);

/* Independent per-thread controls for the library UTC clock. */
void dssh_test_clock_reset(void);
void dssh_test_clock_fail_after(int n);
void dssh_test_clock_set(struct timespec value);
/* Return first for the first count UTC reads, then second, on this thread. */
void dssh_test_clock_schedule(struct timespec first, unsigned count, struct timespec second);
int dssh_test_clock_count(void);

#include "dssh_test_key_file.h"

#endif /* DSSH_TEST_OSSL_H */
