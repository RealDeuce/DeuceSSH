/*
 * test_thread_errors.c -- C11 threading failure injection tests.
 *
 * Recoverable lock/condition failures use the independent thread countdown.
 * Unrecoverable owned-mutex release failures use provenance-checked fresh-exec
 * fatal tests, including retained ownership and error after a real release.
 */

#include <string.h>
#include <threads.h>

#include "dssh_test.h"
#include "deucessh.h"
#include "deucessh-algorithms.h"
#include "deucessh-auth.h"
#include "deucessh-conn.h"
#include "ssh-trans.h"
#include "ssh-internal.h"
#include "dssh_test_internal.h"
#include "dssh_test_ossl.h"
#include "mock_io.h"
#include "test_dhgex_provider.h"

/* ================================================================
 * Mock I/O dispatch
 * ================================================================ */

static int
mock_tx_dispatch(uint8_t *buf, size_t bufsz,
    dssh_session sess, void *cbdata)
{
	if (sess->trans.client)
		return mock_tx_client(buf, bufsz, sess, cbdata);
	else
		return mock_tx_server(buf, bufsz, sess, cbdata);
}

static int
mock_rx_dispatch(uint8_t *buf, size_t bufsz,
    dssh_session sess, void *cbdata)
{
	if (sess->trans.client)
		return mock_rx_client(buf, bufsz, sess, cbdata);
	else
		return mock_rx_server(buf, bufsz, sess, cbdata);
}

static int
mock_rxline_dispatch(uint8_t *buf, size_t bufsz,
    size_t *bytes_received, dssh_session sess, void *cbdata)
{
	if (sess->trans.client)
		return mock_rxline_client(buf, bufsz, bytes_received,
		    sess, cbdata);
	else
		return mock_rxline_server(buf, bufsz, bytes_received,
		    sess, cbdata);
}

/* ================================================================
 * Algorithm registration + server helpers
 * ================================================================ */

static dssh_session
init_server_session(void)
{
	dssh_session s = dssh_session_init(false, 0);
	if (s != NULL)
		test_dhgex_setup(s);
	return s;
}

static int
register_all_algorithms(void)
{
	int res;
	if (test_using_dhgex())
		res = dssh_register_dh_gex_sha256();
	else if (test_using_sntrup())
		res = dssh_register_sntrup761x25519_sha512();
	else if (test_using_mlkem())
		res = dssh_register_mlkem768x25519_sha256();
	else
		res = dssh_register_curve25519_sha256();
	if (res < 0)
		return res;
	res = test_register_key_algos();
	if (res < 0)
		return res;
	res = dssh_register_aes256_ctr();
	if (res < 0)
		return res;
	res = test_register_mac_algos();
	if (res < 0)
		return res;
	res = dssh_register_none_comp();
	if (res < 0)
		return res;
	return 0;
}

/* ================================================================
 * Handshake helpers
 * ================================================================ */

struct handshake_ctx {
	struct mock_io_state io;
	dssh_session client;
	dssh_session server;
	int client_result;
	int server_result;
};

static int
handshake_client_thread(void *arg)
{
	struct handshake_ctx *ctx = arg;
	ctx->client_result = dssh_transport_handshake(ctx->client);
	if (ctx->client_result != 0) {
		mock_io_close_c2s(&ctx->io);
		mock_io_close_s2c(&ctx->io);
	}
	return 0;
}

static int
handshake_server_thread(void *arg)
{
	struct handshake_ctx *ctx = arg;
	ctx->server_result = dssh_transport_handshake(ctx->server);
	if (ctx->server_result != 0) {
		mock_io_close_c2s(&ctx->io);
		mock_io_close_s2c(&ctx->io);
	}
	return 0;
}

static int
handshake_setup(struct handshake_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	dssh_test_reset_global_config();

	if (register_all_algorithms() < 0)
		return -1;
	if (test_generate_host_key() < 0)
		return -1;

	if (mock_io_init(&ctx->io, 0) < 0)
		return -1;

	dssh_transport_set_callbacks(mock_tx_dispatch, mock_rx_dispatch,
	    mock_rxline_dispatch, mock_extra_line_cb);

	ctx->client = dssh_session_init(true, 0);
	if (ctx->client == NULL) {
		mock_io_free(&ctx->io);
		return -1;
	}
	dssh_session_set_cbdata(ctx->client, &ctx->io, &ctx->io,
	    &ctx->io, &ctx->io);
	dssh_session_set_hostkey_verify_cb(ctx->client, dssh_test_accept_hostkey, NULL);

	ctx->server = init_server_session();
	if (ctx->server == NULL) {
		dssh_session_cleanup(ctx->client);
		mock_io_free(&ctx->io);
		return -1;
	}
	dssh_session_set_cbdata(ctx->server, &ctx->io, &ctx->io,
	    &ctx->io, &ctx->io);

	thrd_t ct, st;
	if (thrd_create(&ct, handshake_client_thread, ctx) != thrd_success) {
		dssh_session_cleanup(ctx->server);
		dssh_session_cleanup(ctx->client);
		mock_io_free(&ctx->io);
		return -1;
	}
	if (thrd_create(&st, handshake_server_thread, ctx) != thrd_success) {
		dssh_session_terminate(ctx->client);
		mock_io_close_c2s(&ctx->io);
		mock_io_close_s2c(&ctx->io);
		thrd_join(ct, NULL);
		dssh_session_cleanup(ctx->server);
		dssh_session_cleanup(ctx->client);
		mock_io_free(&ctx->io);
		return -1;
	}

	thrd_join(ct, NULL);
	thrd_join(st, NULL);

	if (ctx->client_result != 0 || ctx->server_result != 0)
		return -1;

	return 0;
}

static void
handshake_cleanup(struct handshake_ctx *ctx)
{
	if (ctx->server)
		dssh_session_cleanup(ctx->server);
	if (ctx->client)
		dssh_session_cleanup(ctx->client);
	mock_io_free(&ctx->io);
	dssh_test_reset_global_config();
}

/* ================================================================
 * Tests
 * ================================================================ */

/*
 * send_packet mtx_lock failure: first thrd call in send_packet is
 * mtx_lock(tx_mtx).  Inject failure, verify session terminates.
 */
static int
test_send_lock_fail(void)
{
	struct handshake_ctx ctx;
	if (handshake_setup(&ctx) < 0) {
		handshake_cleanup(&ctx);
		return TEST_SKIP;
	}

	ASSERT_FALSE(ctx.client->terminate);

	dssh_test_thrd_fail_after(0);
	uint8_t msg[] = { SSH_MSG_SERVICE_REQUEST, 0x42 };
	int ret = send_packet(ctx.client, msg, sizeof(msg), NULL);
	dssh_test_thrd_reset();

	ASSERT_ERR(ret, DSSH_ERROR_TERMINATED);
	ASSERT_TRUE(ctx.client->terminate);

	handshake_cleanup(&ctx);
	return TEST_PASS;
}

/* Normal real release keeps the session usable and peer packet intact. */
static int
test_send_unlock_success(void)
{
	struct handshake_ctx ctx;
	if (handshake_setup(&ctx) < 0) {
		handshake_cleanup(&ctx);
		return TEST_FAIL;
	}
	uint8_t msg[] = {SSH_MSG_SERVICE_REQUEST, 0x42};
	int ret = send_packet(ctx.client, msg, sizeof(msg), NULL);
	uint8_t type = 0;
	uint8_t *payload = NULL;
	size_t len = 0;
	int received = ret == 0 ? recv_packet(ctx.server, &type, &payload, &len) : ret;
	bool valid = ret == 0 && received == 0 && !ctx.client->terminate
	    && type == SSH_MSG_SERVICE_REQUEST && len == sizeof(msg)
	    && memcmp(payload, msg, sizeof(msg)) == 0;
	handshake_cleanup(&ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

/* The demux is the sole RX owner, so recv_packet performs no C11 lock
 * operation.  An armed thread-failure injector must remain untouched. */
static int
test_recv_has_no_lock(void)
{
	struct handshake_ctx ctx;
	if (handshake_setup(&ctx) < 0) {
		handshake_cleanup(&ctx);
		return TEST_SKIP;
	}

	/* Send a packet from client so server has something to receive */
	uint8_t msg[] = { SSH_MSG_SERVICE_REQUEST, 0x42 };
	ASSERT_OK(send_packet(ctx.client, msg,
	    sizeof(msg), NULL));

	ASSERT_FALSE(ctx.server->terminate);

	dssh_test_thrd_fail_after(0);
	uint8_t mt;
	uint8_t *payload;
	size_t plen;
	int ret = recv_packet(ctx.server, &mt, &payload, &plen);
	dssh_test_thrd_reset();

	ASSERT_OK(ret);
	ASSERT_EQ(mt, SSH_MSG_SERVICE_REQUEST);
	ASSERT_FALSE(ctx.server->terminate);

	handshake_cleanup(&ctx);
	return TEST_PASS;
}

/*
 * Once termination finishes, repeated termination must perform no new
 * synchronization or callback operations.
 */
static int
test_terminate_idempotent(void)
{
	struct handshake_ctx ctx;
	if (handshake_setup(&ctx) < 0) {
		handshake_cleanup(&ctx);
		return TEST_SKIP;
	}

	/* Start the connection layer so set_terminate exercises
	 * accept_mtx, channel_mtx, and buf_mtx paths. */
	ASSERT_OK(dssh_session_start(ctx.client));
	ASSERT_OK(dssh_session_start(ctx.server));

	ASSERT_FALSE(ctx.client->terminate);

	session_set_terminate(ctx.client);
	dssh_test_thrd_fail_after(0);
	session_set_terminate(ctx.client);
	int calls = dssh_test_thrd_count();
	dssh_test_thrd_reset();
	ASSERT_EQ(calls, 0);

	ASSERT_TRUE(ctx.client->terminate);

	/* Clean up: close pipes so demux threads exit */
	mock_io_close_c2s(&ctx.io);
	mock_io_close_s2c(&ctx.io);
	dssh_session_stop(ctx.client);
	dssh_session_stop(ctx.server);
	dssh_session_cleanup(ctx.server);
	dssh_session_cleanup(ctx.client);
	mock_io_free(&ctx.io);
	dssh_test_reset_global_config();
	return TEST_PASS;
}

/* ================================================================
 * Termination must synchronize its rekey wake with tx_mtx even when
 * another thread currently owns the mutex.  A trylock cannot tell
 * whether that owner is the terminating thread.
 * ================================================================ */

struct terminate_wakeup_ctx {
	dssh_session sess;
	atomic_bool  owner_ready;
	atomic_bool  enter_wait;
	atomic_bool  terminator_done;
	atomic_int   wait_result;
};

static int
terminate_wakeup_owner(void *arg)
{
	struct terminate_wakeup_ctx *ctx = arg;

	if (mtx_lock(&ctx->sess->trans.tx_mtx) != thrd_success)
		return -1;
	atomic_store(&ctx->owner_ready, true);
	while (!atomic_load(&ctx->enter_wait))
		thrd_yield();

	struct timespec deadline;

	if (dssh_deadline_from_ms(&deadline, 2000) < 0) {
		atomic_store(&ctx->wait_result, thrd_error);
		mtx_unlock(&ctx->sess->trans.tx_mtx);
		return -1;
	}
	int wr = cnd_timedwait(&ctx->sess->trans.rekey_cnd,
	    &ctx->sess->trans.tx_mtx, &deadline);

	atomic_store(&ctx->wait_result, wr);
	mtx_unlock(&ctx->sess->trans.tx_mtx);
	return 0;
}

static int
terminate_wakeup_terminator(void *arg)
{
	struct terminate_wakeup_ctx *ctx = arg;

	session_set_terminate(ctx->sess);
	atomic_store(&ctx->terminator_done, true);
	return 0;
}

static int
test_set_terminate_rekey_wakeup(void)
{
	dssh_session sess = dssh_session_init(true, 0);

	ASSERT_NOT_NULL(sess);
	struct terminate_wakeup_ctx ctx = {
	    .sess = sess,
	};
	atomic_init(&ctx.owner_ready, false);
	atomic_init(&ctx.enter_wait, false);
	atomic_init(&ctx.terminator_done, false);
	atomic_init(&ctx.wait_result, thrd_error);

	thrd_t owner;
	thrd_t terminator;

	ASSERT_EQ(thrd_create(&owner, terminate_wakeup_owner, &ctx), thrd_success);
	while (!atomic_load(&ctx.owner_ready))
		thrd_yield();
	ASSERT_EQ(thrd_create(&terminator, terminate_wakeup_terminator, &ctx), thrd_success);
	while (!dssh_session_is_terminated(sess))
		thrd_yield();

	/* With the old trylock path, termination broadcasts and returns while
	 * another owner still has the packet engine.  Give it ample time to complete before the
	 * owner enters cnd_timedwait, making the lost wake deterministic. */
	struct timespec settle = { .tv_sec = 0, .tv_nsec = 100000000 };

	thrd_sleep(&settle, NULL);
	atomic_store(&ctx.enter_wait, true);
	int owner_result;
	int terminator_result;

	ASSERT_EQ(thrd_join(owner, &owner_result), thrd_success);
	ASSERT_EQ(thrd_join(terminator, &terminator_result), thrd_success);
	ASSERT_EQ(owner_result, 0);
	ASSERT_EQ(terminator_result, 0);
	ASSERT_TRUE(atomic_load(&ctx.terminator_done));
	ASSERT_EQ(atomic_load(&ctx.wait_result), thrd_success);

	dssh_session_cleanup(sess);
	return TEST_PASS;
}

/*
 * Sweep: iterate over all thrd calls in send_packet, failing each
 * in turn.  Verify the session always terminates.
 */
static int
test_send_sweep(void)
{
	struct handshake_ctx ctx;
	if (handshake_setup(&ctx) < 0) {
		handshake_cleanup(&ctx);
		return TEST_SKIP;
	}

	/* Count thrd calls in a normal send */
	dssh_test_thrd_fail_after(1000);
	uint8_t msg[] = { SSH_MSG_SERVICE_REQUEST, 0x42 };
	send_packet(ctx.client, msg, sizeof(msg), NULL);
	int count = dssh_test_thrd_count();
	dssh_test_thrd_reset();
	ASSERT_TRUE(count >= 2);

	handshake_cleanup(&ctx);

	/* Now fail each thrd call in turn */
	for (int n = 0; n < count; n++) {
		if (handshake_setup(&ctx) < 0) {
			handshake_cleanup(&ctx);
			return TEST_SKIP;
		}

		dssh_test_thrd_fail_after(n);
		send_packet(ctx.client, msg,
		    sizeof(msg), NULL);
		dssh_test_thrd_reset();

		ASSERT_TRUE(ctx.client->terminate);

		handshake_cleanup(&ctx);
	}

	return TEST_PASS;
}

/* Verify the single-owner RX path has no injectable C11 synchronization. */
static int
test_recv_sweep(void)
{
	struct handshake_ctx ctx;
	if (handshake_setup(&ctx) < 0) {
		handshake_cleanup(&ctx);
		return TEST_SKIP;
	}

	/* Send a packet */
	uint8_t msg[] = { SSH_MSG_SERVICE_REQUEST, 0x42 };
	ASSERT_OK(send_packet(ctx.client, msg,
	    sizeof(msg), NULL));

	/* Count thrd calls in a normal recv */
	dssh_test_thrd_fail_after(1000);
	uint8_t mt;
	uint8_t *payload;
	size_t plen;
	recv_packet(ctx.server, &mt, &payload, &plen);
	int count = dssh_test_thrd_count();
	dssh_test_thrd_reset();
	ASSERT_EQ(count, 0);

	handshake_cleanup(&ctx);
	return TEST_PASS;
}

/* ================================================================
 * session_start() init failure tests
 *
 * dssh_session_start() calls mtx_init × 2, cnd_init × 1,
 * thrd_create × 1.  These go through the ossl countdown
 * (not the thrd countdown), so we use dssh_test_ossl_fail_after.
 * We handshake first with no injection, then arm before start().
 * ================================================================ */

/*
 * Sweep all 4 init/create calls in dssh_session_start().
 * n=0: mtx_init(&channel_mtx) fails
 * n=1: mtx_init(&accept_mtx) fails
 * n=2: cnd_init(&accept_cnd) fails
 * n=3: thrd_create() fails
 */
static int
test_start_init_sweep(void)
{
	for (int n = 0; n < 4; n++) {
		struct handshake_ctx ctx;
		if (handshake_setup(&ctx) < 0) {
			handshake_cleanup(&ctx);
			return TEST_SKIP;
		}

		/* Arm ossl countdown to fail the Nth init/create call */
		dssh_test_ossl_fail_after(n);
		int res = dssh_session_start(ctx.client);
		dssh_test_ossl_reset();

		ASSERT_ERR(res, DSSH_ERROR_INIT);

		/* session_start failed, so no demux thread to stop.
		 * Close pipes and clean up. */
		mock_io_close_c2s(&ctx.io);
		mock_io_close_s2c(&ctx.io);
		handshake_cleanup(&ctx);
	}

	return TEST_PASS;
}

/*
 * Verify session_start(NULL) returns DSSH_ERROR_INVALID.
 */
static int
test_start_null(void)
{
	ASSERT_ERR(dssh_session_start(NULL), DSSH_ERROR_INVALID);
	return TEST_PASS;
}

/*
 * Verify double-start returns DSSH_ERROR_INIT.
 */
static int
test_start_double(void)
{
	struct handshake_ctx ctx;
	if (handshake_setup(&ctx) < 0) {
		handshake_cleanup(&ctx);
		return TEST_SKIP;
	}

	ASSERT_OK(dssh_session_start(ctx.client));
	ASSERT_ERR(dssh_session_start(ctx.client), DSSH_ERROR_INIT);

	/* Clean up: close pipes so demux thread exits */
	mock_io_close_c2s(&ctx.io);
	mock_io_close_s2c(&ctx.io);
	dssh_session_stop(ctx.client);
	dssh_session_stop(ctx.server);
	handshake_cleanup(&ctx);
	return TEST_PASS;
}

/* ================================================================
 * Test list
 * ================================================================ */

static void
unused_event_cb(dssh_channel ch, const struct dssh_chan_event *event, void *data)
{
	(void)ch;
	(void)event;
	(void)data;
}

/* Check both the protected state and the acquisition/release discipline.
 * The targeted reject hook suppresses an invalid native unlock in the before
 * implementation, so the regression itself does not rely on undefined behavior. */
static int
channel_mutex_failure(unsigned operation)
{
	for (unsigned prior = 0; prior < 2; prior++) {
		dssh_test_ossl_reset();
		dssh_session sess = dssh_session_init(true, 0);
		if (sess == NULL)
			return TEST_FAIL;
		struct dssh_channel_s ch = {
			.sess = sess,
			.open = true,
			.event_cb = NULL,
			.event_cbdata = NULL,
		};
		ch.eof_sent = prior != 0;
		ch.close_sent = prior != 0;
		ch.events.count = prior != 0 ? 50 : 0;
		ch.events.max_events = 64;
		int ret = mtx_init(&ch.buf_mtx, mtx_plain);
		if (ret != thrd_success) {
			dssh_session_cleanup(sess);
			return TEST_FAIL;
		}
		ret = mtx_init(&ch.cb_mtx, mtx_plain);
		if (ret != thrd_success) {
			mtx_destroy(&ch.buf_mtx);
			dssh_session_cleanup(sess);
			return TEST_FAIL;
		}
		mtx_t *target = operation == 2 ? &ch.cb_mtx : &ch.buf_mtx;
		dssh_test_mtx_reject_once(target);
		if (operation == 0)
			ret = send_eof(sess, &ch);
		else if (operation == 1)
			ret = conn_close(sess, &ch);
		else if (operation == 2)
			ret = dssh_chan_set_event_cb(&ch, unused_event_cb, &ch);
		else
			ret = dssh_chan_set_max_events(&ch, 40);
		bool valid = ret == DSSH_ERROR_TERMINATED && sess->terminate
		    && dssh_test_mtx_rejected_unlocks() == 0;
		valid = valid && ch.eof_sent == (prior != 0)
		    && ch.close_sent == (prior != 0) && ch.open
		    && ch.event_cb == NULL && ch.event_cbdata == NULL
		    && ch.events.max_events == 64;
		dssh_test_ossl_reset();
		mtx_destroy(&ch.cb_mtx);
		mtx_destroy(&ch.buf_mtx);
		dssh_session_cleanup(sess);
		ASSERT_TRUE(valid);
	}
	return TEST_PASS;
}

static int
test_eof_acquire(void)
{
	return channel_mutex_failure(0);
}

static int
test_close_acquire(void)
{
	return channel_mutex_failure(1);
}

static int
test_event_acquire(void)
{
	return channel_mutex_failure(2);
}

static int
test_limit_acquire(void)
{
	return channel_mutex_failure(3);
}

#include "termination_wakeup_cases.h"
#include "condition_wait_cases.h"

static struct dssh_test_entry tests[] = {
	{ "thrd/wait_contract_errors", test_wait_contract_errors },
	{ "thrd/wait_contract_spurious", test_wait_contract_spurious },
	{ "thrd/wait_contract_timeout_errors", test_wait_contract_timeout_errors },
	{ "thrd/wait_contract_timeouts", test_wait_contract_timeouts },
	{ "thrd/wake_rekey", test_wake_rekey },
	{ "thrd/wake_slot", test_wake_slot },
	{ "thrd/wake_accept", test_wake_accept },
	{ "thrd/wake_poll", test_wake_poll },
	{ "thrd/deferred_rekey", test_deferred_rekey },
	{ "thrd/deferred_slot", test_deferred_slot },
	{ "thrd/deferred_accept", test_deferred_accept },
	{ "thrd/deferred_poll", test_deferred_poll },
	{ "thrd/wake_retry", test_wake_retry },
	{ "thrd/deferred_retry", test_deferred_retry },
	{ "thrd/signal_retry", test_signal_retry },
	{ "thrd/eof_acquire",          test_eof_acquire },
	{ "thrd/close_acquire",        test_close_acquire },
	{ "thrd/event_acquire",        test_event_acquire },
	{ "thrd/limit_acquire",        test_limit_acquire },
	{ "thrd/demux_exit_deferred",  test_demux_exit_deferred },
	{ "thrd/send_lock_fail",      test_send_lock_fail },
	{ "thrd/send_unlock_success", test_send_unlock_success },
	{ "thrd/recv_has_no_lock",    test_recv_has_no_lock },
	{ "thrd/terminate_idempotent", test_terminate_idempotent },
	{ "thrd/set_terminate_rekey_wakeup", test_set_terminate_rekey_wakeup },
	{ "thrd/send_sweep",          test_send_sweep },
	{ "thrd/recv_sweep",          test_recv_sweep },
	{ "thrd/start_init_sweep",    test_start_init_sweep },
	{ "thrd/start_null",          test_start_null },
	{ "thrd/start_double",        test_start_double },
};

static dssh_log_action
forward_test_log(const struct dssh_log_record *record, void *opaque)
{
	(void)record;
	(void)opaque;
	return DSSH_LOG_SEND_DEBUG;
}

/* Fresh exec only. An unexpected return exits without touching the retained
 * mutex. The driver requires both fault provenance and actual SIGABRT. */
static int
unlock_fatal_child(const char *name, const char *mode)
{
	bool release_real = strcmp(mode, "released") == 0;
	if (!release_real && strcmp(mode, "held") != 0)
		return 2;
	dssh_test_ossl_reset();
	if (strcmp(name, "primitive") == 0) {
		mtx_t mutex;
		if (mtx_init(&mutex, mtx_plain) != thrd_success || mtx_lock(&mutex) != thrd_success)
			return 3;
		dssh_test_unlock_fail_after(&mutex, 0, release_real);
		dssh_test_unlock_boundary(&mutex);
		_Exit(4);
	}
	bool transport = strcmp(name, "log-empty") == 0 || strcmp(name, "log-data") == 0
	    || strcmp(name, "wa-send") == 0;
	struct handshake_ctx ctx;
	dssh_session sess;
	if (transport) {
		if (handshake_setup(&ctx) != 0)
			return 3;
		sess = ctx.client;
	}
	else {
		sess = dssh_session_init(true, 0);
		if (sess == NULL)
			return 3;
	}
	if (strncmp(name, "log-", 4) == 0) {
		if (dssh_session_set_log_cb(sess, forward_test_log, NULL) != 0)
			return 3;
		if (strcmp(name, "log-data") == 0)
			sess->log_forward->count = 1;
		if (transport && tx_acquire(sess, SSH_MSG_DEBUG) != 0)
			return 3;
		dssh_test_unlock_fail_after(&sess->log_forward->mtx, 0, release_real);
		if (strcmp(name, "log-queue") == 0)
			dssh_log_emit(sess, DSSH_LOG_ERROR, DSSH_LOG_SOURCE_LIBRARY, 0, 0,
			    false, false, NULL, 0, NULL, 0);
		else if (transport)
			drain_log_forwards(sess);
		else
			return 2;
		_Exit(4);
	}
	struct dssh_channel_s ch = {.sess = sess, .open = true};
	if (mtx_init(&ch.buf_mtx, mtx_plain) != thrd_success
	    || mtx_init(&ch.cb_mtx, mtx_plain) != thrd_success
	    || cnd_init(&ch.poll_cnd) != thrd_success)
		return 3;
	if (strncmp(name, "wa-", 3) == 0) {
		bool idle = strcmp(name, "wa-idle") == 0;
		bool wire = strcmp(name, "wa-send") == 0;
		if (!idle && !wire && strcmp(name, "wa-zero") != 0)
			return 2;
		atomic_init(&ch.wa_slot.ready, !idle);
		if (wire) {
			ch.window_adjust_pending = 1;
			ch.wa_slot.buf = malloc(sess->trans.packet_buf_sz);
			if (ch.wa_slot.buf == NULL || tx_acquire(sess, SSH_MSG_CHANNEL_WINDOW_ADJUST) != 0)
				return 3;
		}
		dssh_test_unlock_fail_after(&ch.buf_mtx, wire ? 1U : 0U, release_real);
		bool progress = false;
		int status = drain_one_wa_slot(sess, &ch, &progress);
		_Exit(status == 0 ? 4 : 5);
	}
	mtx_t *target = strcmp(name, "event") == 0 ? &ch.cb_mtx : &ch.buf_mtx;
	dssh_test_unlock_fail_after(target, 0, release_real);
	if (strcmp(name, "event") == 0)
		dssh_chan_set_event_cb(&ch, unused_event_cb, NULL);
	else if (strcmp(name, "limit") == 0)
		dssh_chan_set_max_events(&ch, 1);
	else if (strcmp(name, "eof") == 0) {
		ch.eof_sent = true;
		send_eof(sess, &ch);
	}
	else if (strcmp(name, "close") == 0) {
		ch.close_sent = true;
		conn_close(sess, &ch);
	}
	else
		return 2;
	_Exit(4);
}

#define main dssh_test_thread_errors_main
DSSH_TEST_NO_CLEANUP
DSSH_TEST_MAIN(tests)
#undef main

int
main(int argc, char **argv)
{
	if (argc == 4 && strcmp(argv[1], "--unlock-fatal") == 0)
		return unlock_fatal_child(argv[2], argv[3]);
	if (argc == 4 && strcmp(argv[1], "--wake-fatal") == 0)
		return wake_fatal_child(argv[2], argv[3]);
	return dssh_test_thread_errors_main(argc, argv);
}
