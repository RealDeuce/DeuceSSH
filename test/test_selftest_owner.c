/* Exercise the actual self-test owner with private, caller-only controls.
 * Include its source once; library and provider calls retain their real paths. */
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "dssh_test.h"
#include "ssh-internal.h"

static int owner_create(thrd_t *, thrd_start_t, void *);
static int owner_join(thrd_t, int *);
static int owner_callbacks(dssh_transport_io_cb, dssh_transport_io_cb,
    dssh_transport_rxline_cb, dssh_transport_extra_line_cb);
static int owner_cbdata(dssh_session, void *, void *, void *, void *);
static int owner_trust(dssh_session, dssh_hostkey_verify_cb, void *);
static dssh_session owner_session(bool, size_t);
static void owner_cleanup(dssh_session);
static int owner_close(int);

/* Capture the existing native/test redirections before overriding only calls
 * in the included fixture. No library demux create/join is intercepted. */
static int native_create(thrd_t *t, thrd_start_t f, void *a)
{
	return thrd_create(t, f, a);
}
static int native_join(thrd_t t, int *r)
{
	return thrd_join(t, r);
}

#undef thrd_create
#undef thrd_join
#define thrd_create owner_create
#define thrd_join owner_join
#define dssh_transport_set_callbacks owner_callbacks
#define dssh_session_set_cbdata owner_cbdata
#define dssh_session_set_hostkey_verify_cb owner_trust
#define dssh_session_init owner_session
#define dssh_session_cleanup owner_cleanup
#define close owner_close
#define main selftest_suite_main
#include "test_selftest.c"
#undef main
#undef close
#undef dssh_session_cleanup
#undef dssh_session_init
#undef dssh_session_set_hostkey_verify_cb
#undef dssh_session_set_cbdata
#undef dssh_transport_set_callbacks
#undef thrd_join
#undef thrd_create

static const char *owner_mode;
static unsigned owner_created;
static unsigned owner_joined;
static unsigned owner_attempts;
static unsigned owner_join_attempts;
static unsigned owner_setters;
static unsigned owner_sessions;
static unsigned owner_released;
static unsigned owner_closed;

#define owner_note(...) do { \
	if (fprintf(stderr, __VA_ARGS__) < 0 || fflush(stderr) != 0) \
		_Exit(7); \
} while (0)

static bool
owner_selected(const char *prefix, unsigned index, const char *suffix)
{
	size_t length = strlen(prefix);
	return index < 6 && strncmp(owner_mode, prefix, length) == 0
	    && owner_mode[length] == '0' + index
	    && strcmp(owner_mode + length + 1, suffix) == 0;
}

static int
owner_create(thrd_t *thread, thrd_start_t function, void *argument)
{
	if (owner_attempts >= 5)
		abort();
	unsigned index = owner_attempts++;
	if (owner_selected("create-", index, "")) {
		owner_note("SELFTEST_CREATE_FAILURE index=%u\n", index);
		return thrd_error;
	}
	int ret = native_create(thread, function, argument);
	if (ret == thrd_success)
		owner_created++;
	return ret;
}

static int
owner_join(thrd_t thread, int *result)
{
	if (owner_join_attempts >= 5)
		abort();
	unsigned index = owner_join_attempts++;
	if (owner_selected("join-", index, "-retained")) {
		owner_note("SELFTEST_JOIN_FAILURE index=%u retained=1\n", index);
		return thrd_error;
	}
	int ret = native_join(thread, result);
	owner_note("SELFTEST_NATIVE_JOIN index=%u success=%u\n", index,
	    ret == thrd_success ? 1U : 0U);
	if (ret == thrd_success) {
		owner_joined++;
		if (owner_selected("join-", index, "-released")) {
			owner_note("SELFTEST_JOIN_FAILURE index=%u retained=0\n", index);
			return thrd_error;
		}
	}
	return ret;
}

static bool
owner_setter_refusal(unsigned index, const char *suffix)
{
	if (!owner_selected("setter-", index, suffix))
		return false;
	owner_note("SELFTEST_SETTER_FAILURE index=%u phase=%s\n", index, suffix);
	return true;
}

static int
owner_callbacks(dssh_transport_io_cb tx, dssh_transport_io_cb rx,
    dssh_transport_rxline_cb line, dssh_transport_extra_line_cb extra)
{
	unsigned index = owner_setters++;
	if (owner_setter_refusal(index, "-before"))
		return DSSH_ERROR_INIT;
	int ret = dssh_transport_set_callbacks(tx, rx, line, extra);
	if (ret == 0 && owner_setter_refusal(index, "-after"))
		return DSSH_ERROR_INIT;
	return ret;
}

static int
owner_cbdata(dssh_session sess, void *tx, void *rx, void *line, void *extra)
{
	unsigned index = owner_setters++;
	if (owner_setter_refusal(index, "-before"))
		return DSSH_ERROR_INIT;
	int ret = dssh_session_set_cbdata(sess, tx, rx, line, extra);
	if (ret == 0 && owner_setter_refusal(index, "-after"))
		return DSSH_ERROR_INIT;
	return ret;
}

static int
owner_trust(dssh_session sess, dssh_hostkey_verify_cb callback, void *data)
{
	unsigned index = owner_setters++;
	if (owner_setter_refusal(index, "-before"))
		return DSSH_ERROR_INIT;
	int ret = dssh_session_set_hostkey_verify_cb(sess, callback, data);
	if (ret == 0 && owner_setter_refusal(index, "-after"))
		return DSSH_ERROR_INIT;
	return ret;
}

static dssh_session
owner_session(bool client, size_t extra)
{
	dssh_session sess = dssh_session_init(client, extra);
	if (sess != NULL) {
		if (owner_sessions >= 2)
			abort();
		owner_sessions++;
	}
	return sess;
}

static void
owner_cleanup(dssh_session sess)
{
	if (owner_joined != owner_created) {
		owner_note("SELFTEST_PREMATURE_RETIRE\n");
		abort();
	}
	bool owned = sess != NULL;
	dssh_session_cleanup(sess);
	if (owned) {
		if (owner_released >= owner_sessions)
			abort();
		owner_released++;
	}
}

static int
owner_close(int fd)
{
	if (owner_joined != owner_created || owner_released != owner_sessions) {
		owner_note("SELFTEST_PREMATURE_RETIRE\n");
		abort();
	}
	int ret = close(fd);
	if (ret == 0) {
		if (owner_closed >= 2)
			abort();
		owner_closed++;
	}
	return ret;
}

static bool
owner_retired(const struct selftest_ctx *ctx)
{
	return !ctx->registered && g_active_ctx == NULL
	    && !ctx->setup_thread_active[0] && !ctx->setup_thread_active[1]
	    && !ctx->server_thread_active && ctx->client == NULL && ctx->server == NULL
	    && ctx->client_fd == -1 && ctx->server_fd == -1
	    && owner_joined == owner_created && owner_released == owner_sessions
	    && owner_closed == 2;
}

static int
owner_assertion(void)
{
	ASSERT_TRUE(false);
	return TEST_PASS;
}

/* Remains blocked until the assertion hook cancels its borrowed session. */
static int
owner_body(void *argument)
{
	struct selftest_ctx *ctx = argument;
	uint8_t byte;
	return socket_rx(&byte, sizeof(byte), ctx->server, &ctx->server_fd);
}

static int
owner_finish(struct selftest_ctx *ctx, bool valid)
{
	selftest_cleanup(ctx);
	selftest_cleanup(ctx);
	valid &= owner_retired(ctx);
	owner_note("SELFTEST_OWNER mode=%s created=%u joined=%u sessions=%u released=%u closed=%u valid=%u\n",
	    owner_mode, owner_created, owner_joined, owner_sessions, owner_released,
	    owner_closed, valid ? 1U : 0U);
	return valid ? 0 : 2;
}

int
main(int argc, char **argv)
{
	if (argc != 2 || signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return 2;
	owner_mode = argv[1];
	struct selftest_ctx ctx;
	if (strncmp(owner_mode, "assert-hs-", 10) == 0
	    || strncmp(owner_mode, "assert-auth-", 12) == 0) {
		bool auth = strncmp(owner_mode, "assert-auth-", 12) == 0;
		const char *prefix = auth ? "assert-auth-" : "assert-hs-";
		unsigned count;
		for (count = 0; count < 3; count++) {
			if (owner_selected(prefix, count, ""))
				break;
		}
		if (count >= 3 || selftest_prepare(&ctx) != 0)
			return 2;
		if (auth && (selftest_run_setup_pair(&ctx, client_handshake_thread,
		        server_handshake_thread) != 0 || ctx.client_hs_result != 0
		        || ctx.server_hs_result != 0))
			return owner_finish(&ctx, false);
		thrd_start_t operations[] = { auth ? client_auth_thread : client_handshake_thread,
		    auth ? server_auth_thread : server_handshake_thread };
		for (unsigned i = 0; i < count; i++) {
			if (selftest_start_setup_thread(&ctx, i, operations[i]) != 0)
				return owner_finish(&ctx, false);
		}
		int result = owner_assertion();
		return owner_finish(&ctx, result == TEST_FAIL && owner_retired(&ctx));
	}
	int ret = selftest_setup(&ctx);
	if (ret != 0)
		return owner_finish(&ctx, strncmp(owner_mode, "setter-", 7) == 0
		    || strncmp(owner_mode, "create-", 7) == 0);
	if (strncmp(owner_mode, "setter-", 7) == 0)
		return owner_finish(&ctx, false);
	ret = selftest_start_thread(&ctx, owner_body, &ctx);
	if (strcmp(owner_mode, "assert-body") == 0) {
		if (ret != 0)
			return owner_finish(&ctx, false);
		int result = owner_assertion();
		return owner_finish(&ctx, result == TEST_FAIL && owner_retired(&ctx));
	}
	bool valid = owner_selected("create-", 4, "") ? ret < 0 : ret == 0;
	if (ret == 0) {
		/* A live handle may not be overwritten by a second start. */
		valid &= selftest_start_thread(&ctx, owner_body, &ctx) < 0;
		selftest_cancel(&ctx);
		selftest_join(&ctx.server_thread, &ctx.server_thread_active);
		selftest_join(&ctx.server_thread, &ctx.server_thread_active);
	}
	return owner_finish(&ctx, valid);
}
