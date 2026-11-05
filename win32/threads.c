/*
 * C11 <threads.h> shim — MinGW-w64 implementation.  See the header
 * for scope and rationale.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <process.h>	/* _beginthreadex */
#include <stdlib.h>	/* malloc / free */

#include "threads.h"
#include "../ssh-time.h"

/* ------------------------------------------------------------- mutexes */

int
mtx_init(mtx_t *mtx, int type)
{
	/* DeuceSSH only uses mtx_plain; the other C11 attributes (timed,
	 * recursive) aren't exercised.  Accept any combination silently —
	 * CRITICAL_SECTION is already recursive on the same thread, and
	 * timed-lock support would need SRWLock or a condition variable
	 * retrofit that we don't need today. */
	(void)type;
	InitializeCriticalSection(mtx);
	return thrd_success;
}

void
mtx_destroy(mtx_t *mtx)
{
	DeleteCriticalSection(mtx);
}

int
mtx_lock(mtx_t *mtx)
{
	EnterCriticalSection(mtx);
	return thrd_success;
}

int
mtx_trylock(mtx_t *mtx)
{
	return TryEnterCriticalSection(mtx) ? thrd_success : thrd_busy;
}

int
mtx_unlock(mtx_t *mtx)
{
	LeaveCriticalSection(mtx);
	return thrd_success;
}

/* ----------------------------------------------------- condition vars */

int
cnd_init(cnd_t *cnd)
{
	InitializeConditionVariable(cnd);
	return thrd_success;
}

void
cnd_destroy(cnd_t *cnd)
{
	/* CONDITION_VARIABLE has no destructor on Windows. */
	(void)cnd;
}

int
cnd_signal(cnd_t *cnd)
{
	WakeConditionVariable(cnd);
	return thrd_success;
}

int
cnd_broadcast(cnd_t *cnd)
{
	WakeAllConditionVariable(cnd);
	return thrd_success;
}

int
cnd_wait(cnd_t *cnd, mtx_t *mtx)
{
	return SleepConditionVariableCS(cnd, mtx, INFINITE)
	    ? thrd_success : thrd_error;
}

int
cnd_timedwait(cnd_t *cnd, mtx_t *mtx, const struct timespec *ts)
{
	if (ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000L)
		return thrd_error;
	bool waited = false;

	for (;;) {
		/* Windows waits use a bounded relative millisecond interval. Read
		 * the absolute clock again after expiration, including when the
		 * deadline needs multiple intervals or the clock moved backwards. */
		struct timespec now;
		if (timespec_get(&now, TIME_UTC) != TIME_UTC)
			return thrd_error;
		if (now.tv_nsec < 0 || now.tv_nsec >= 1000000000L)
			return thrd_error;
		bool expired = ts->tv_sec < now.tv_sec
		    || (ts->tv_sec == now.tv_sec && ts->tv_nsec <= now.tv_nsec);
		if (expired && waited)
			return thrd_timedout;
		DWORD timeout = 0;
		if (!expired) {
			/* Clamp before subtraction or multiplication. Below this
			 * threshold, widening the signed Win32 time_t values to
			 * int64_t makes their difference provably representable. */
			if (dssh_time_interval_reached(ts->tv_sec, now.tv_sec, UINT32_C(4294969)))
				timeout = UINT32_C(0xfffffffe);
			else {
				int64_t due = ts->tv_sec;
				int64_t current = now.tv_sec;
				int64_t difference = due - current;
				if (difference < 0)
					return thrd_error;
				uint64_t seconds = (uint64_t)difference;
				long nanos = ts->tv_nsec - now.tv_nsec;
				uint32_t millis;
				if (!dssh_relative_wait_ms(seconds, nanos, UINT32_C(0xfffffffe), &millis))
					return thrd_error;
				timeout = millis;
			}
		}
		if (SleepConditionVariableCS(cnd, mtx, timeout))
			return thrd_success;
		if (GetLastError() != ERROR_TIMEOUT)
			return thrd_error;
		if (expired)
			return thrd_timedout;
		waited = true;
	}
}

/* ------------------------------------------------------------ threads */

/*
 * C11 `thrd_start_t` is `int(*)(void *)`; Windows `_beginthreadex`
 * wants `unsigned __stdcall (*)(void *)`.  Funnel through a small
 * context struct so we can convert the calling convention + return
 * type at the edge.
 */
struct dssh_thrd_ctx {
	thrd_start_t func;
	void        *arg;
};

static unsigned __stdcall
dssh_thrd_trampoline(void *arg)
{
	struct dssh_thrd_ctx *ctx = arg;
	int rc = ctx->func(ctx->arg);
	free(ctx);
	return (unsigned)rc;
}

int
thrd_create(thrd_t *thr, thrd_start_t func, void *arg)
{
	struct dssh_thrd_ctx *ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return thrd_nomem;
	ctx->func = func;
	ctx->arg  = arg;
	/* _beginthreadex rather than CreateThread so the MSVCRT per-thread
	 * state is initialised (errno, locale, etc.). */
	uintptr_t h = _beginthreadex(NULL, 0, dssh_thrd_trampoline, ctx, 0, NULL);
	if (h == 0) {
		free(ctx);
		return thrd_error;
	}
	*thr = (HANDLE)h;
	return thrd_success;
}

int
thrd_join(thrd_t thr, int *res)
{
	/* Consume the handle only after every operation needed by this join
	 * succeeds.  A failure must allow the owner to retry joining. */
	if (WaitForSingleObject(thr, INFINITE) != WAIT_OBJECT_0)
		return thrd_error;
	int result = 0;

	if (res != NULL) {
		DWORD code;
		if (!GetExitCodeThread(thr, &code))
			return thrd_error;
		/* The trampoline converts int to the unsigned Windows exit code.
		 * Restore its signed value without an out-of-range signed cast. */
		int64_t signed_code = code;
		if (signed_code > INT32_MAX)
			signed_code -= INT64_C(4294967296);
		if (signed_code < INT_MIN || signed_code > INT_MAX)
			return thrd_error;
		int checked_result = (int)signed_code;
		result = checked_result;
	}
	if (!CloseHandle(thr))
		return thrd_error;
	if (res != NULL)
		*res = result;
	return thrd_success;
}

void
thrd_yield(void)
{
	SwitchToThread();
}
