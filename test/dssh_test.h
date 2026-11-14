/*
 * dssh_test.h -- Minimal test framework for DeuceSSH.
 *
 * Each test is a function returning int: 1=PASS, 0=FAIL, -1=SKIP.
 * Define the test table and call DSSH_TEST_MAIN() from main().
 */

#ifndef DSSH_TEST_H
#define DSSH_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "deucessh.h"
#include "deucessh-result.h"
#include "../ssh-timespec.h"

static inline bool
dssh_test_bytes_equal(struct dssh_bytes bytes, const void *data, size_t len)
{
	return bytes.len == len && (len == 0
	    || (bytes.data != NULL && data != NULL && memcmp(bytes.data, data, len) == 0));
}


/*
 * Accept-all host key verification callback for tests.
 * Set on client sessions before handshake.
 */
static inline dssh_hostkey_decision
dssh_test_accept_hostkey(const char *algo_name, unsigned int key_bits,
    const uint8_t *sha256_hash, const uint8_t *key_blob,
    size_t key_blob_len, void *cbdata)
{
	(void)algo_name;
	(void)key_bits;
	(void)sha256_hash;
	(void)key_blob;
	(void)key_blob_len;
	(void)cbdata;
	return DSSH_HOSTKEY_ACCEPT;
}

#define TEST_PASS  1
#define TEST_FAIL  0
#define TEST_SKIP -1

typedef int (*dssh_test_fn)(void);

struct dssh_test_entry {
	const char *name;
	dssh_test_fn fn;
};

/* Called before an assertion returns, while stack-owned contexts and thread
 * arguments are still alive.  Cleanup after the test returns is too late. */
void dssh_test_failure_cleanup(void);

#define ASSERT_TRUE(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "  ASSERT_TRUE failed: %s\n    at %s:%d\n", \
		    #cond, __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

#define ASSERT_FALSE(cond) do { \
	if ((cond)) { \
		fprintf(stderr, "  ASSERT_FALSE failed: %s\n    at %s:%d\n", \
		    #cond, __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

#define ASSERT_EQ(a, b) do { \
	long long _a = (long long)(a); \
	long long _b = (long long)(b); \
	if (_a != _b) { \
		fprintf(stderr, "  ASSERT_EQ failed: %s == %lld, expected %s == %lld\n    at %s:%d\n", \
		    #a, _a, #b, _b, __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

#define ASSERT_NE(a, b) do { \
	long long _a = (long long)(a); \
	long long _b = (long long)(b); \
	if (_a == _b) { \
		fprintf(stderr, "  ASSERT_NE failed: %s == %s == %lld\n    at %s:%d\n", \
		    #a, #b, _a, __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

/* For unsigned comparisons (size_t, uint32_t, etc.) */
#define ASSERT_EQ_U(a, b) do { \
	unsigned long long _a = (unsigned long long)(a); \
	unsigned long long _b = (unsigned long long)(b); \
	if (_a != _b) { \
		fprintf(stderr, "  ASSERT_EQ_U failed: %s == %llu, expected %s == %llu\n    at %s:%d\n", \
		    #a, _a, #b, _b, __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

#define ASSERT_OK(expr) do { \
	int64_t _r = (int64_t)(expr); \
	if (_r < 0) { \
		fprintf(stderr, "  ASSERT_OK failed: %s returned %" PRId64 "\n    at %s:%d\n", \
		    #expr, _r, __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

#define ASSERT_ERR(expr, code) do { \
	int64_t _r = (int64_t)(expr); \
	if (_r != (int64_t)(code)) { \
		fprintf(stderr, "  ASSERT_ERR failed: %s returned %" PRId64 ", expected %d (%s)\n    at %s:%d\n", \
		    #expr, _r, (int)(code), #code, __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

#define ASSERT_NULL(ptr) do { \
	if ((ptr) != NULL) { \
		fprintf(stderr, "  ASSERT_NULL failed: %s is not NULL\n    at %s:%d\n", \
		    #ptr, __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

#define ASSERT_NOT_NULL(ptr) do { \
	if ((ptr) == NULL) { \
		fprintf(stderr, "  ASSERT_NOT_NULL failed: %s is NULL\n    at %s:%d\n", \
		    #ptr, __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

#define ASSERT_MEM_EQ(a, b, n) do { \
	if (memcmp((a), (b), (n)) != 0) { \
		fprintf(stderr, "  ASSERT_MEM_EQ failed: %s != %s (len %zu)\n    at %s:%d\n", \
		    #a, #b, (size_t)(n), __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

#define ASSERT_STR_EQ(a, b) do { \
	if (strcmp((a), (b)) != 0) { \
		fprintf(stderr, "  ASSERT_STR_EQ failed: \"%s\" != \"%s\"\n    at %s:%d\n", \
		    (a), (b), __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

#include <threads.h>
#define ASSERT_THRD_CREATE(thr, func, arg) do { \
	if (thrd_create((thr), (func), (arg)) != thrd_success) { \
		fprintf(stderr, "  thrd_create failed: %s\n    at %s:%d\n", \
		    #func, __FILE__, __LINE__); \
		dssh_test_failure_cleanup(); \
		return TEST_FAIL; \
	} \
} while (0)

/*
 * Main loop macro.  Define a tests[] array of dssh_test_entry before
 * calling this.  Usage:
 *
 *   static struct dssh_test_entry tests[] = {
 *       { "test_foo", test_foo },
 *       { "test_bar", test_bar },
 *   };
 *   DSSH_TEST_MAIN(tests)
 */
/* Files without stack-owned resources use the no-op failure hook. */
#define DSSH_TEST_NO_CLEANUP \
	void dssh_test_failure_cleanup(void) { }

#include <float.h>
#include <math.h>
#include <signal.h>
#include <time.h>

/* Defined before library test redirections: measuring a leaf must not consume
 * that leaf's library-clock fault counter. Overrides are private selftest hooks. */
#ifndef DSSH_TEST_RUNNER_CLOCK
 #define DSSH_TEST_RUNNER_CLOCK timespec_get
#endif
#ifndef DSSH_TEST_RUNNER_SIGNAL
 #define DSSH_TEST_RUNNER_SIGNAL signal
#endif
#ifndef DSSH_TEST_RUNNER_PRINTF
 #define DSSH_TEST_RUNNER_PRINTF printf
#endif
#ifndef DSSH_TEST_RUNNER_FLUSH
 #define DSSH_TEST_RUNNER_FLUSH fflush
#endif

static inline bool
dssh_test_runner_clock(struct timespec *value)
{
	return DSSH_TEST_RUNNER_CLOCK(value, TIME_UTC) == TIME_UTC
	    && value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}

/* The double interval comes from standard difftime, avoiding subtraction in
 * time_t. Leave headroom before multiplication and the bounded fractional add. */
static inline bool
dssh_test_runner_elapsed(double seconds, long first, long last, double *out)
{
	if (!isfinite(seconds) || seconds < 0 || seconds > DBL_MAX / 2000.0
	    || first < 0 || first >= 1000000000L || last < 0 || last >= 1000000000L)
		return false;
	long nanos = last - first;
	double fraction = (double)nanos;
	double elapsed = seconds * 1000.0 + fraction / 1000000.0;
	if (elapsed < 0)
		return false;
	*out = elapsed;
	return true;
}

static inline int
dssh_test_runner_error(const char *message)
{
	if (fputs(message, stderr) < 0 || fflush(stderr) != 0)
		return 2;
	return 2;
}

static inline int
dssh_test_run(const struct dssh_test_entry *table, size_t count, int argc, char **argv)
{
	if (argc < 1 || argc > 3 || argv == NULL || table == NULL
	    || count == 0 || count > SIZE_MAX / sizeof(*table))
		return dssh_test_runner_error("Invalid test runner configuration\n");
	bool exact = argc == 3;
	const char *filter = argc > 1 ? argv[argc - 1] : NULL;
	if ((argc == 2 && (argv[1] == NULL || strcmp(argv[1], "--exact") == 0))
	    || (exact && (argv[1] == NULL || strcmp(argv[1], "--exact") != 0))
	    || (argc > 1 && (filter == NULL || filter[0] == 0)))
		return dssh_test_runner_error("Invalid test selection\n");
	size_t selected = 0;
	for (size_t i = 0; i < count; i++) {
		if (table[i].name == NULL || table[i].name[0] == 0 || table[i].fn == NULL)
			return dssh_test_runner_error("Invalid test table entry\n");
		if (filter == NULL || (exact ? strcmp(table[i].name, filter) == 0
		    : strstr(table[i].name, filter) != NULL))
			selected++;
	}
	if (exact && selected > 1)
		return dssh_test_runner_error("Ambiguous exact test selection\n");
	if (selected == 0) {
		if (DSSH_TEST_RUNNER_PRINTF("\n0 tests: 0 passed, 0 failed, 0 skipped\n") < 0
		    || DSSH_TEST_RUNNER_FLUSH(stdout) != 0)
			return 2;
		return 1;
	}
#ifdef SIGPIPE
	if (DSSH_TEST_RUNNER_SIGNAL(SIGPIPE, SIG_IGN) == SIG_ERR)
		return dssh_test_runner_error("Unable to ignore SIGPIPE for tests\n");
#endif
	/* Each tally is bounded by the validated actual table extent. */
	size_t total = 0, passed = 0, failed = 0, skipped = 0;
	for (size_t i = 0; i < count; i++) {
		if (filter != NULL && (exact ? strcmp(table[i].name, filter) != 0
		    : strstr(table[i].name, filter) == NULL))
			continue;
		if (DSSH_TEST_RUNNER_PRINTF("%-60s ", table[i].name) < 0
		    || DSSH_TEST_RUNNER_FLUSH(stdout) != 0)
			return 2;
		struct timespec start, end;
		bool started = dssh_test_runner_clock(&start);
		int result = table[i].fn();
		bool ended = dssh_test_runner_clock(&end);
		total++;
		const char *label;
		if (result == TEST_PASS) {
			passed++;
			label = "PASS";
		}
		else if (result == TEST_SKIP) {
			skipped++;
			label = "SKIP";
		}
		else {
			failed++;
			label = "FAIL";
		}
		if (DSSH_TEST_RUNNER_PRINTF("%s", label) < 0)
			return 2;
		if (result != TEST_PASS && result != TEST_FAIL && result != TEST_SKIP) {
			if (DSSH_TEST_RUNNER_PRINTF(" (invalid result %d)", result) < 0)
				return 2;
		}
		double milliseconds;
		bool timed = started && ended && dssh_test_runner_elapsed(
		    difftime(end.tv_sec, start.tv_sec), start.tv_nsec, end.tv_nsec, &milliseconds);
		if (!timed) {
			if (DSSH_TEST_RUNNER_PRINTF(" (timing unavailable)") < 0)
				return 2;
		}
		else if (milliseconds >= 100.0) {
			if (DSSH_TEST_RUNNER_PRINTF(" (%.0fms)", milliseconds) < 0)
				return 2;
		}
		if (DSSH_TEST_RUNNER_PRINTF("\n") < 0)
			return 2;
	}
	if (DSSH_TEST_RUNNER_PRINTF("\n%zu tests: %zu passed, %zu failed, %zu skipped\n",
	    total, passed, failed, skipped) < 0 || DSSH_TEST_RUNNER_FLUSH(stdout) != 0)
		return 2;
	return failed > 0 ? 1 : 0;
}

#define DSSH_TEST_MAIN(test_table) \
int main(int argc, char *argv[]) \
{ \
	return dssh_test_run(test_table, sizeof(test_table) / sizeof(test_table[0]), argc, argv); \
}

#endif
