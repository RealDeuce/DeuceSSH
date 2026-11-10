/* GNU --wrap controls for the separate production-linked peer executables.
 * Only the thread that creates the first application worker is controlled.
 * Library-created demux workers continue to use real native operations. */
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

#include "deucessh.h"

int __real_thrd_create(thrd_t *, thrd_start_t, void *);
int __real_thrd_join(thrd_t, int *);
int __real_mock_tx_client(uint8_t *, size_t, dssh_session, void *);

static once_flag configured = ONCE_FLAG_INIT;
static thrd_t controller;
static const char *mode;
static unsigned create_index;
static unsigned join_index;
static thrd_t application_workers[4];
static bool owned[4];
static atomic_bool tx_failed;

static void
configure(void)
{
	controller = thrd_current();
	mode = getenv("DSSH_PEER_FAILURE");
	if (mode == NULL)
		mode = "plain";
}

static bool
selected(const char *prefix, unsigned index, const char *suffix)
{
	size_t length = strlen(prefix);
	return index < 4 && strncmp(mode, prefix, length) == 0
	    && mode[length] == '0' + index && strcmp(mode + length + 1, suffix) == 0;
}

int
__wrap_thrd_create(thrd_t *thread, thrd_start_t start, void *arg)
{
	call_once(&configured, configure);
	if (thrd_equal(controller, thrd_current())) {
		unsigned index = create_index;
		if (create_index != UINT_MAX)
			create_index++;
		if (selected("create-", index, "")) {
			fprintf(stderr, "PEER_CREATE_FAILURE index=%u\n", index);
			return thrd_error;
		}
		int ret = __real_thrd_create(thread, start, arg);
		if (ret == thrd_success && index < 4) {
			application_workers[index] = *thread;
			owned[index] = true;
		}
		return ret;
	}
	return __real_thrd_create(thread, start, arg);
}

int
__wrap_thrd_join(thrd_t thread, int *result)
{
	call_once(&configured, configure);
	if (!thrd_equal(controller, thrd_current()))
		return __real_thrd_join(thread, result);
	bool application = false;
	for (unsigned i = 0; i < 4; i++) {
		if (owned[i] && thrd_equal(application_workers[i], thread)) {
			owned[i] = false;
			application = true;
			break;
		}
	}
	if (!application)
		return __real_thrd_join(thread, result);
	unsigned index = join_index;
	if (join_index != UINT_MAX)
		join_index++;
	if (selected("join-", index, "-retained")) {
		fprintf(stderr, "PEER_JOIN_FAILURE index=%u retained=1\n", index);
		return thrd_error;
	}
	int ret = __real_thrd_join(thread, result);
	fprintf(stderr, "PEER_NATIVE_JOIN index=%u success=%u\n", index,
	    ret == thrd_success ? 1U : 0U);
	if (ret == thrd_success && selected("join-", index, "-released")) {
		fprintf(stderr, "PEER_JOIN_FAILURE index=%u retained=0\n", index);
		return thrd_error;
	}
	return ret;
}

int
__wrap_mock_tx_client(uint8_t *buf, size_t len, dssh_session sess, void *opaque)
{
	call_once(&configured, configure);
	if (strcmp(mode, "tx") == 0 && !atomic_exchange(&tx_failed, true)) {
		fputs("PEER_TX_FAILURE\n", stderr);
		return -1;
	}
	return __real_mock_tx_client(buf, len, sess, opaque);
}
