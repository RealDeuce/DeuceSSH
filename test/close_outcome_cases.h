/* Selected B close contract. The historical characterization now supplies
 * strict wire, disposal and ownership regressions for the sole v1.0 policy. */
struct close_outcome_lifetime {
	const void *handle;
	unsigned frees;
};

static void
close_outcome_observe_free(const void *pointer, void *opaque)
{
	struct close_outcome_lifetime *watch = opaque;
	if (pointer != NULL && pointer == watch->handle) {
		watch->handle = NULL;
		watch->frees++;
	}
}
struct close_outcome_accept {
	dssh_session session;
	dssh_channel channel;
	unsigned callbacks;
};

static int
close_outcome_terminal(dssh_channel channel, const struct dssh_chan_params *params,
    struct dssh_chan_accept_result *result, void *opaque)
{
	(void)channel;
	(void)params;
	struct close_outcome_accept *job = opaque;
	job->callbacks++;
	result->max_window = 4096;
	return 0;
}

static int
close_outcome_accept_worker(void *opaque)
{
	struct close_outcome_accept *job = opaque;
	struct dssh_chan_accept_cbs callbacks = {.exec = close_outcome_terminal, .cbdata = job};
	job->channel = dssh_chan_accept(job->session, &callbacks, 3000);
	return 0;
}

static dssh_channel
close_outcome_open(struct conn_ctx *ctx)
{
	if (ctx->server->trans.client)
		return half_close_accept(ctx, 42);
	struct close_outcome_accept job = {.session = ctx->server};
	thrd_t worker;
	if (thrd_create(&worker, close_outcome_accept_worker, &job) != thrd_success)
		return NULL;
	uint32_t remote = 0;
	bool valid = accept_failure_open(ctx->client, 42) == 0
	    && request_frame_receive(ctx->client, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 42, &remote)
	    && request_frame_exec(ctx->client, remote, 42);
	if (!valid) {
		mock_io_close_c2s(&ctx->io);
		mock_io_close_s2c(&ctx->io);
	}
	if (thrd_join(worker, NULL) != thrd_success)
		abort();
	return valid && job.callbacks == 1 ? job.channel : NULL;
}

static int
close_outcome_invalid_tx(dssh_session session)
{
	(void)session;
	return DSSH_ERROR_INVALID;
}

static _Thread_local unsigned close_outcome_packets, close_outcome_fail_after;
static _Thread_local dssh_session close_outcome_publication_session;

static int
close_outcome_after_tx(dssh_session session)
{
	close_outcome_packets++;
	if (close_outcome_publication_session == session
	    && close_outcome_packets == (session->trans.client ? 2U : 3U))
		dssh_test_mtx_reject_once(&session->channel_mtx);
	if (close_outcome_fail_after != 0 && close_outcome_packets == close_outcome_fail_after)
		setup_tx_test_hook = half_close_fail_tx;
	else
		window_tx_return_test_hook = close_outcome_after_tx;
	return 0;
}

struct close_outcome_wire {
	unsigned status, eof, close;
	uint32_t exit_code;
	int end;
};

static bool
close_outcome_drain(dssh_session peer, struct close_outcome_wire *wire)
{
	/* The sender's native write end has been closed. Absence is EOF, not an
	 * empty-read timeout. Read at most the complete three-packet sequence. */
	for (unsigned i = 0; i < 4; i++) {
		uint8_t type;
		uint8_t *packet;
		size_t length;
		int ret = recv_packet(peer, &type, &packet, &length);
		if (ret < 0) {
			wire->end = ret;
			return ret == -1;
		}
		if (length < 5 || DSSH_GET_U32(packet + 1) != 42)
			return false;
		if (type == SSH_MSG_CHANNEL_REQUEST && length == 25
		    && DSSH_GET_U32(packet + 5) == 11 && memcmp(packet + 9, "exit-status", 11) == 0
		    && packet[20] == 0 && wire->status == 0 && wire->eof == 0 && wire->close == 0) {
			wire->status++;
			wire->exit_code = DSSH_GET_U32(packet + 21);
		}
		else if (type == SSH_MSG_CHANNEL_EOF && length == 5 && wire->eof == 0 && wire->close == 0)
			wire->eof++;
		else if (type == SSH_MSG_CHANNEL_CLOSE && length == 5 && wire->close == 0)
			wire->close++;
		else
			return false;
	}
	return false;
}

static const char *const close_outcome_names[] = {
	"zero", "max_u32", "omit", "min_i64", "over_u32", "max_i64",
	"status_io", "eof_io", "close_io", "terminated", "peer_closed",
	"status_capacity", "terminal_capacity", "hard_counter", "detach_acquisition",
	"local_closed", "close_publication", "send_invalid"
};

static int
close_outcome_run(struct conn_ctx *ctx, unsigned kind, unsigned role, unsigned gather,
    struct close_outcome_lifetime *watch)
{
	if (dssh_session_start(ctx->server) != 0)
		return TEST_FAIL;
	dssh_channel ch = close_outcome_open(ctx);
	if (ch == NULL)
		return TEST_FAIL;
	const char *command = dssh_chan_get_command(ch);
	if (dssh_chan_get_type(ch) != DSSH_CHAN_EXEC || command == NULL
	    || strcmp(command, role != 0 ? "half-close" : "test") != 0)
		return TEST_FAIL;
	uint32_t local = ch->local_id;
	int64_t exit_code = 42;
	if (kind == 0)
		exit_code = 0;
	else if (kind == 1)
		exit_code = UINT32_MAX;
	else if (kind == 2 || kind == 14)
		exit_code = -1;
	else if (kind == 3)
		exit_code = INT64_MIN;
	else if (kind == 4)
		exit_code = INT64_C(4294967296);
	else if (kind == 5)
		exit_code = INT64_MAX;

	if (kind == 10 && post_close_receive_close(ctx, ch) != TEST_PASS)
		return TEST_FAIL;
	if (kind == 14 || kind == 15) {
		/* With local CLOSE already committed, the next close(-1) has exactly
		 * two ordinary BUF acquisitions before its registry detach. */
		if (conn_close(ctx->server, ch) != 0
		    || !peer_id_receive_control(ctx->client, SSH_MSG_CHANNEL_CLOSE, 5, 42))
			return TEST_FAIL;
	}
	close_outcome_packets = 0;
	close_outcome_fail_after = kind == 7 && role == 0 ? 1
	    : kind == 8 ? (role == 0 ? 2 : 1) : 0;
	close_outcome_publication_session = kind == 16 ? ctx->server : NULL;
	window_tx_return_test_hook = close_outcome_after_tx;
	if (kind == 6 || (kind == 7 && role != 0))
		setup_tx_test_hook = half_close_fail_tx;
	if (kind == 17)
		setup_tx_test_hook = close_outcome_invalid_tx;
	if (kind == 9)
		dssh_session_terminate(ctx->server);
	if (kind == 11 || kind == 12) {
		if (tx_acquire(ctx->server, SSH_MSG_IGNORE) != 0)
			return TEST_FAIL;
		size_t limit = kind == 11 ? 5 : 4;
		ctx->server->trans.comp_tx_payload_limit = limit;
		bool bounded = tx_payload_capacity(ctx->server) == limit;
		tx_unlock_with_slots(ctx->server);
		if (!bounded)
			return TEST_FAIL;
	}
	if (kind == 13)
		atomic_store(&ctx->server->trans.tx_since_rekey, DSSH_REKEY_HARD_LIMIT);
	if (kind == 14)
		dssh_test_thrd_fail_after(2);

	watch->handle = ch;
	int result = dssh_chan_close(ch, exit_code);
	/* ch is never inspected or used again. On detach failure the registry
	 * still owns its storage; session cleanup, not this probe, retires it. */
	setup_tx_test_hook = NULL;
	window_tx_return_test_hook = NULL;
	close_outcome_publication_session = NULL;
	int thread_calls = kind == 14 ? dssh_test_thrd_count() : 0;
	unsigned unowned_unlocks = dssh_test_mtx_rejected_unlocks();
	dssh_test_thrd_reset();
	bool terminated = dssh_session_is_terminated(ctx->server);
	size_t registered = 0;
	if (mtx_lock(&ctx->server->channel_mtx) != thrd_success)
		abort();
	for (size_t i = 0; i < ctx->server->channel_count; i++) {
		if (ctx->server->channels[i]->local_id == local)
			registered++;
	}
	size_t retired = ctx->server->retired_channel_ids;
	if (mtx_unlock(&ctx->server->channel_mtx) != thrd_success)
		abort();
	if (ctx->server->trans.client)
		mock_io_close_c2s_write(&ctx->io);
	else
		mock_io_close_s2c_write(&ctx->io);
	struct close_outcome_wire wire = {0};
	bool valid = close_outcome_drain(ctx->client, &wire);
	bool expect_status = role == 0 && (kind == 0 || kind == 1 || kind == 7
	    || kind == 8 || kind == 10 || kind == 16);
	bool expect_eof = kind <= 5 || kind == 8 || kind == 10 || kind == 11 || kind == 16;
	bool expect_close = kind <= 5 || kind == 10 || kind == 11 || kind == 16;
	bool expect_terminated = (kind >= 6 && kind <= 9) || kind == 12 || kind == 13
	    || kind == 14 || kind == 16 || kind == 17;
	uint32_t expected_code = kind == 0 ? 0 : kind == 1 ? UINT32_MAX : 42;
	unsigned expected_retired = kind == 10 || kind == 14 ? 0 : 1;
	unsigned expected_registered = kind == 14 ? 1 : 0;
	unsigned expected_frees = kind == 14 ? 0 : 1;
	valid = valid && result == (kind == 14 ? DSSH_ERROR_TERMINATED : 0)
	    && registered == expected_registered && retired == expected_retired
	    && terminated == expect_terminated && wire.status == (expect_status ? 1U : 0U)
	    && wire.eof == (expect_eof ? 1U : 0U) && wire.close == (expect_close ? 1U : 0U)
	    && (!expect_status || wire.exit_code == expected_code) && watch->frees == expected_frees
	    && close_outcome_packets == wire.status + wire.eof + wire.close
	    && unowned_unlocks == 0 && !atomic_load(&ctx->server->trans.tx_owner_active);
	if (kind == 14)
		valid = valid && thread_calls >= 3;
	intmax_t input_wide = exit_code;
	uintmax_t code_wide = wire.exit_code;
	printf("close_outcome name=%s role=%u gather=%u input=%jd result=%d registered=%zu retired=%zu terminated=%u callbacks=%u status=%u code=%ju eof=%u close=%u end=%d thread_calls=%d immediate_frees=%u valid=%u\n",
	    close_outcome_names[kind], role, gather, input_wide, result, registered,
	    retired, terminated ? 1U : 0U, close_outcome_packets, wire.status,
	    code_wide, wire.eof, wire.close, wire.end, thread_calls, watch->frees, valid ? 1U : 0U);
	return valid ? TEST_PASS : TEST_FAIL;
}

static bool
close_disposal_selected(unsigned kind, int part)
{
	if (part < 0)
		return true;
	if (part == 0)
		return kind <= 5;
	if (part == 1)
		return (kind >= 6 && kind <= 9) || (kind >= 11 && kind <= 13) || kind == 16 || kind == 17;
	return kind == 10 || kind == 14 || kind == 15;
}

static int
close_disposal_profiles(int part)
{
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return 2;
	unsigned cases = 0, failed = 0;
	const char *compression = getenv("DSSH_TEST_COMPRESSION");
	bool capacity_cases = compression != NULL && strcmp(compression, "test-growth") == 0;
	for (unsigned role = 0; role < 2; role++) {
		for (unsigned gather = 0; gather < 2; gather++) {
			for (unsigned kind = 0; kind < sizeof(close_outcome_names) / sizeof(close_outcome_names[0]); kind++) {
				if (!close_disposal_selected(kind, part)
				    || ((kind == 11 || kind == 12) && !capacity_cases)
				    || (kind == 6 && role != 0))
					continue;
				struct conn_ctx ctx;
				window_test_gather = gather != 0;
				int setup = conn_setup_mode(&ctx, false);
				window_test_gather = false;
				if (setup != 0)
					return 2;
				if (!half_close_algorithms(&ctx)) {
					conn_cleanup(&ctx);
					return 2;
				}
				if (role != 0) {
					dssh_session swap = ctx.client;
					ctx.client = ctx.server;
					ctx.server = swap;
				}
				struct close_outcome_lifetime watch = {0};
				dssh_test_alloc_observe_frees(close_outcome_observe_free, &watch);
				int ret = close_outcome_run(&ctx, kind, role, gather, &watch);
				conn_cleanup(&ctx);
				dssh_test_alloc_observe_frees(NULL, NULL);
				cases++;
				if (ret != TEST_PASS || watch.frees != 1 || watch.handle != NULL)
					failed++;
				printf("close_disposal_retired name=%s role=%u gather=%u frees=%u valid=%u\n",
				    close_outcome_names[kind], role, gather, watch.frees,
				    watch.frees == 1 && watch.handle == NULL ? 1U : 0U);
			}
		}
	}
	unsigned expected = part == 0 ? 24 : part == 1 ? (capacity_cases ? 34 : 26)
	    : part == 2 ? 12 : capacity_cases ? 70 : 62;
	printf("close_disposal part=%d cases=%u failures=%u\n", part, cases, failed);
	return failed == 0 && cases == expected ? 0 : 1;
}

static int
close_outcome_probe(void)
{
	return close_disposal_profiles(-1);
}

static int
test_close_disposal_values(void)
{
	return close_disposal_profiles(0) == 0 ? TEST_PASS : TEST_FAIL;
}

static int
test_close_disposal_send(void)
{
	return close_disposal_profiles(1) == 0 ? TEST_PASS : TEST_FAIL;
}

static int
test_close_disposal_retirement(void)
{
	return close_disposal_profiles(2) == 0 ? TEST_PASS : TEST_FAIL;
}
