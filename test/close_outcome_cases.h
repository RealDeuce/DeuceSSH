/* Audit characterization, not acceptance of a new close result contract.
 * The dedicated CLI reports current public outcomes before API selection. */
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

static _Thread_local unsigned close_outcome_packets, close_outcome_fail_after;

static int
close_outcome_after_tx(dssh_session session)
{
	(void)session;
	close_outcome_packets++;
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
	"status_capacity", "terminal_capacity", "hard_counter", "detach_acquisition"
};

static int
close_outcome_run(struct conn_ctx *ctx, unsigned kind, unsigned role, unsigned gather)
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
	if (kind == 14) {
		/* With local CLOSE already committed, the next close(-1) has exactly
		 * two ordinary BUF acquisitions before its registry detach. */
		if (conn_close(ctx->server, ch) != 0
		    || !peer_id_receive_control(ctx->client, SSH_MSG_CHANNEL_CLOSE, 5, 42))
			return TEST_FAIL;
	}
	close_outcome_packets = 0;
	close_outcome_fail_after = kind == 7 ? 1 : kind == 8 ? 2 : 0;
	window_tx_return_test_hook = close_outcome_after_tx;
	if (kind == 6)
		setup_tx_test_hook = half_close_fail_tx;
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

	int result = dssh_chan_close(ch, exit_code);
	/* ch is never inspected or used again. On detach failure the registry
	 * still owns its storage; session cleanup, not this probe, retires it. */
	setup_tx_test_hook = NULL;
	window_tx_return_test_hook = NULL;
	int thread_calls = kind == 14 ? dssh_test_thrd_count() : 0;
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
	intmax_t input_wide = exit_code;
	uintmax_t code_wide = wire.exit_code;
	printf("close_outcome name=%s role=%u gather=%u input=%jd result=%d registered=%zu retired=%zu terminated=%u callbacks=%u status=%u code=%ju eof=%u close=%u end=%d thread_calls=%d observed=%u\n",
	    close_outcome_names[kind], role, gather, input_wide, result, registered,
	    retired, terminated ? 1U : 0U, close_outcome_packets, wire.status,
	    code_wide, wire.eof, wire.close, wire.end, thread_calls, valid ? 1U : 0U);
	return valid ? TEST_PASS : TEST_FAIL;
}

static int
close_outcome_probe(void)
{
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return 2;
	unsigned cases = 0, failed = 0;
	const char *compression = getenv("DSSH_TEST_COMPRESSION");
	bool capacity_cases = compression != NULL && strcmp(compression, "test-growth") == 0;
	for (unsigned role = 0; role < 2; role++) {
		for (unsigned gather = 0; gather < 2; gather++) {
			for (unsigned kind = 0; kind < sizeof(close_outcome_names) / sizeof(close_outcome_names[0]); kind++) {
				if ((kind == 11 || kind == 12) && !capacity_cases)
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
				int ret = close_outcome_run(&ctx, kind, role, gather);
				conn_cleanup(&ctx);
				cases++;
				if (ret != TEST_PASS)
					failed++;
			}
		}
	}
	printf("close_outcome_probe cases=%u observation_failures=%u\n", cases, failed);
	return failed == 0 && cases == (capacity_cases ? 60U : 52U) ? 0 : 1;
}
