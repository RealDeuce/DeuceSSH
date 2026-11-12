/* Actual channel handles and native peer packets, after post_close_cases.h. */
static bool
half_close_algorithms(struct conn_ctx *ctx)
{
	const char *expected_kex = test_kex_algo_name();
	const char *expected_key = test_using_rsa512() ? "rsa-sha2-512"
	    : test_using_rsa() ? "rsa-sha2-256" : "ssh-ed25519";
	dssh_session sessions[] = {ctx->client, ctx->server};
	for (size_t i = 0; i < 2; i++) {
		const char *kex = dssh_transport_get_kex_name(sessions[i]);
		const char *key = dssh_transport_get_hostkey_name(sessions[i]);
		if (kex == NULL || key == NULL || strcmp(kex, expected_kex) != 0 || strcmp(key, expected_key) != 0)
			return false;
	}
	const char *comp = dssh_transport_get_comp_name(ctx->client, DSSH_CLIENT_TO_SERVER);
	if (comp == NULL || !compression_fixture_selected(ctx->client, ctx->server))
		return false;
	printf("half_close_algorithms kex=%s key=%s comp=%s\n", expected_kex, expected_key, comp);
	return true;
}

static bool
half_close_sent(dssh_channel ch)
{
	if (mtx_lock(&ch->buf_mtx) != thrd_success)
		abort();
	bool sent = ch->eof_sent;
	if (mtx_unlock(&ch->buf_mtx) != thrd_success)
		abort();
	return sent;
}

/* A peer probe orders a definite reply after every preceding EOF. This makes
 * zero or duplicate EOFs observable without an empty-read timeout. */
static int
half_close_count_wire(dssh_session peer, uint32_t number)
{
	int ret = send_packet(peer, channel_id_probe_request, sizeof(channel_id_probe_request), NULL);
	if (ret != 0)
		return -1;
	int count = 0;
	for (unsigned i = 0; i < 3; i++) {
		uint8_t type;
		uint8_t *payload;
		size_t length;
		if (recv_packet(peer, &type, &payload, &length) != 0)
			return -1;
		if (type == SSH_MSG_REQUEST_FAILURE && length == 1)
			return count;
		if (type != SSH_MSG_CHANNEL_EOF || length != 5 || DSSH_GET_U32(&payload[1]) != number)
			return -1;
		count++;
	}
	return -1;
}

struct half_close_open_job {
	dssh_session session;
	dssh_channel channel;
	int result;
};

static int
half_close_open_worker(void *opaque)
{
	struct half_close_open_job *job = opaque;
	struct dssh_chan_params params;
	int ret = dssh_chan_params_init(&params, DSSH_CHAN_EXEC);
	if (ret != 0) {
		job->result = ret;
		return 0;
	}
	ret = dssh_chan_params_set_command(&params, "half-close");
	if (ret == 0)
		ret = dssh_chan_params_set_pty(&params, false);
	if (ret == 0) {
		job->channel = dssh_chan_open(job->session, &params);
		if (job->channel == NULL)
			ret = DSSH_ERROR_INIT;
	}
	dssh_chan_params_free(&params);
	job->result = ret;
	return 0;
}

static dssh_channel
half_close_accept(struct conn_ctx *ctx, uint32_t number)
{
	if (!ctx->server->trans.client)
		return post_close_accept(ctx, number);
	/* A client opens an outbound session channel. Its synchronous native
	 * server peer supplies OPEN/exec replies; it never opens a server-origin
	 * session channel, which this implementation correctly refuses. */
	struct half_close_open_job job = {.session = ctx->server};
	thrd_t opener;
	if (thrd_create(&opener, half_close_open_worker, &job) != thrd_success)
		return NULL;
	uint8_t type;
	uint8_t *payload;
	size_t length;
	bool valid = recv_packet(ctx->client, &type, &payload, &length) == 0
	    && type == SSH_MSG_CHANNEL_OPEN && length == 24
	    && DSSH_GET_U32(&payload[1]) == 7 && memcmp(&payload[5], "session", 7) == 0;
	uint32_t local = valid ? DSSH_GET_U32(&payload[12]) : 0;
	uint8_t reply[17];
	size_t reply_length = channel_id_build_reply(reply, local, true, number);
	if (valid)
		valid = send_packet(ctx->client, reply, reply_length, NULL) == 0
		    && recv_packet(ctx->client, &type, &payload, &length) == 0
		    && type == SSH_MSG_CHANNEL_REQUEST && length == 28
		    && DSSH_GET_U32(&payload[1]) == number && DSSH_GET_U32(&payload[5]) == 4
		    && memcmp(&payload[9], "exec", 4) == 0 && payload[13] == 1
		    && DSSH_GET_U32(&payload[14]) == 10 && memcmp(&payload[18], "half-close", 10) == 0;
	if (valid) {
		size_t pos = 0;
		reply[pos++] = SSH_MSG_CHANNEL_SUCCESS;
		DSSH_PUT_U32(local, reply, &pos);
		valid = send_packet(ctx->client, reply, pos, NULL) == 0
		    && peer_id_receive_control(ctx->client, SSH_MSG_CHANNEL_WINDOW_ADJUST, 9, number);
	}
	if (!valid) {
		mock_io_close_c2s(&ctx->io);
		mock_io_close_s2c(&ctx->io);
	}
	if (thrd_join(opener, NULL) != thrd_success)
		abort();
	return valid && job.result == 0 ? job.channel : NULL;
}

static int
test_half_close_retry(void)
{
	unsigned cases = 0, mismatches = 0;
	for (unsigned role = 0; role < 2; role++) {
		for (unsigned gather = 0; gather < 2; gather++) {
			for (unsigned refusal = 0; refusal < 2; refusal++) {
				struct conn_ctx ctx;
				window_test_gather = gather != 0;
				int setup = conn_setup_mode(&ctx, false);
				window_test_gather = false;
				ASSERT_OK(setup);
				ASSERT_TRUE(half_close_algorithms(&ctx));
				if (role != 0) {
					dssh_session swap = ctx.client;
					ctx.client = ctx.server;
					ctx.server = swap;
				}
				ASSERT_OK(dssh_session_start(ctx.server));
				const uint32_t number = UINT32_MAX;
				dssh_channel ch = half_close_accept(&ctx, number);
				ASSERT_NOT_NULL(ch);
				uint_fast32_t saved = atomic_load(&ctx.server->trans.tx_since_rekey);
				if (refusal != 0)
					atomic_store(&ctx.server->trans.tx_since_rekey, DSSH_REKEY_HARD_LIMIT);
				int first = dssh_chan_shutwr(ch);
				atomic_store(&ctx.server->trans.tx_since_rekey, saved);
				bool published = half_close_sent(ch);
				int retry = dssh_chan_shutwr(ch);
				int repeated = dssh_chan_shutwr(ch);
				int wire = half_close_count_wire(ctx.client, number);
				bool valid = first == (refusal != 0 ? DSSH_ERROR_REKEY_NEEDED : 0)
				    && published == (refusal == 0) && retry == 0 && repeated == 0
				    && wire == 1 && half_close_sent(ch)
				    && !dssh_session_is_terminated(ctx.server);
				printf("half_close_retry role=%u gather=%u refusal=%u first=%d published=%u retry=%d repeated=%d wire=%d valid=%u\n",
				    role, gather, refusal, first, published ? 1U : 0U, retry, repeated,
				    wire, valid ? 1U : 0U);
				cases++;
				if (!valid)
					mismatches++;
				conn_cleanup(&ctx);
			}
		}
	}
	printf("half_close_retry cases=%u mismatches=%u\n", cases, mismatches);
	ASSERT_EQ_U(cases, 8);
	ASSERT_EQ_U(mismatches, 0);
	return TEST_PASS;
}

struct half_close_job {
	dssh_channel channel;
	atomic_bool entered, resume, finished;
	bool pause;
	int result;
};
static _Thread_local struct half_close_job *half_close_active;

static int
half_close_pause_tx(dssh_session sess)
{
	(void)sess;
	struct half_close_job *job = half_close_active;
	atomic_store(&job->entered, true);
	return dssh_test_wait_bool(&job->resume, true) ? 0 : DSSH_ERROR_INIT;
}

static int
half_close_worker(void *opaque)
{
	struct half_close_job *job = opaque;
	if (job->pause) {
		half_close_active = job;
		window_tx_return_test_hook = half_close_pause_tx;
	}
	job->result = dssh_chan_shutwr(job->channel);
	window_tx_return_test_hook = NULL;
	half_close_active = NULL;
	atomic_store(&job->finished, true);
	return 0;
}

static bool
half_close_wait_observation(struct half_close_job *job, const atomic_bool *waiting)
{
	struct timespec start;
	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return false;
	while (!atomic_load(&job->finished) && !atomic_load(waiting)) {
		if (!dssh_test_wait_tick(&start))
			return false;
	}
	return true;
}

static int
half_close_concurrent_run(struct conn_ctx *ctx, unsigned role, unsigned gather)
{
	ASSERT_OK(dssh_session_start(ctx->server));
	const uint32_t number = 23;
	dssh_channel ch = half_close_accept(ctx, number);
	ASSERT_NOT_NULL(ch);
	struct half_close_job first = {.channel = ch, .pause = true};
	struct half_close_job second = {.channel = ch};
	atomic_bool *waiting = dssh_test_thrd_watch_condition(&ctx->server->trans.rekey_cnd);
	thrd_t a, b;
	bool a_started = thrd_create(&a, half_close_worker, &first) == thrd_success;
	bool b_started = false;
	bool valid = a_started && dssh_test_wait_bool(&first.entered, true);
	bool early = valid && half_close_sent(ch);
	if (valid)
		b_started = thrd_create(&b, half_close_worker, &second) == thrd_success;
	valid = valid && b_started && half_close_wait_observation(&second, waiting);
	bool premature = atomic_load(&second.finished);
	bool blocked = atomic_load(waiting);
	/* Retire both real workers before any assertion can return their storage. */
	atomic_store(&first.resume, true);
	if (a_started && thrd_join(a, NULL) != thrd_success)
		abort();
	if (b_started && thrd_join(b, NULL) != thrd_success)
		abort();
	dssh_test_thrd_watch_condition(NULL);
	int wire = half_close_count_wire(ctx->client, number);
	valid = valid && !early && !premature && blocked && first.result == 0 && second.result == 0
	    && wire == 1 && half_close_sent(ch) && !dssh_session_is_terminated(ctx->server);
	printf("half_close_concurrent role=%u gather=%u early=%u premature=%u blocked=%u first=%d second=%d wire=%d valid=%u\n",
	    role, gather, early ? 1U : 0U, premature ? 1U : 0U, blocked ? 1U : 0U,
	    first.result, second.result, wire, valid ? 1U : 0U);
	return valid ? TEST_PASS : TEST_FAIL;
}

static int
half_close_fail_tx(dssh_session sess)
{
	(void)sess;
	return DSSH_ERROR_INIT;
}

static _Thread_local dssh_channel half_close_publication_channel;

static int
half_close_reject_publication(dssh_session sess)
{
	if (half_close_publication_channel == NULL || half_close_publication_channel->sess != sess)
		return DSSH_ERROR_INVALID;
	dssh_test_mtx_reject_once(&half_close_publication_channel->buf_mtx);
	return 0;
}

static int
half_close_failure_run(struct conn_ctx *ctx, unsigned role, unsigned gather, bool publication)
{
	ASSERT_OK(dssh_session_start(ctx->server));
	dssh_channel ch = half_close_accept(ctx, 41);
	ASSERT_NOT_NULL(ch);
	if (publication) {
		half_close_publication_channel = ch;
		window_tx_return_test_hook = half_close_reject_publication;
	}
	else
		setup_tx_test_hook = half_close_fail_tx;
	int first = dssh_chan_shutwr(ch);
	setup_tx_test_hook = NULL;
	window_tx_return_test_hook = NULL;
	half_close_publication_channel = NULL;
	unsigned unowned_unlocks = dssh_test_mtx_rejected_unlocks();
	dssh_test_thrd_reset();
	bool published = half_close_sent(ch);
	int repeated = dssh_chan_shutwr(ch);
	/* End native output after the operation. Queued packet bytes still drain,
	 * while absence of a packet is a definite native EOF, never a timeout. */
	if (ctx->server->trans.client)
		mock_io_close_c2s_write(&ctx->io);
	else
		mock_io_close_s2c_write(&ctx->io);
	bool wire = !publication || peer_id_receive_control(ctx->client, SSH_MSG_CHANNEL_EOF, 5, 41);
	uint8_t type;
	uint8_t *payload;
	size_t length;
	int end = recv_packet(ctx->client, &type, &payload, &length);
	bool valid = first == (publication ? DSSH_ERROR_TERMINATED : DSSH_ERROR_INIT)
	    && !published && repeated == DSSH_ERROR_TERMINATED && wire && end < 0
	    && unowned_unlocks == 0 && !atomic_load(&ctx->server->trans.tx_owner_active)
	    && dssh_session_is_terminated(ctx->server);
	printf("half_close_%s role=%u gather=%u first=%d published=%u repeated=%d wire=%u end=%d unowned_unlocks=%u valid=%u\n",
	    publication ? "publication" : "failure", role, gather, first, published ? 1U : 0U,
	    repeated, publication && wire ? 1U : 0U, end, unowned_unlocks, valid ? 1U : 0U);
	return valid ? TEST_PASS : TEST_FAIL;
}

static int
half_close_profiles(bool concurrent, bool publication)
{
	unsigned cases = 0, mismatches = 0;
	for (unsigned role = 0; role < 2; role++) {
		for (unsigned gather = 0; gather < 2; gather++) {
			struct conn_ctx ctx;
			window_test_gather = gather != 0;
			int setup = conn_setup_mode(&ctx, false);
			window_test_gather = false;
			ASSERT_OK(setup);
			ASSERT_TRUE(half_close_algorithms(&ctx));
			if (role != 0) {
				dssh_session swap = ctx.client;
				ctx.client = ctx.server;
				ctx.server = swap;
			}
			int ret = concurrent ? half_close_concurrent_run(&ctx, role, gather)
			    : half_close_failure_run(&ctx, role, gather, publication);
			conn_cleanup(&ctx);
			cases++;
			if (ret != TEST_PASS)
				mismatches++;
		}
	}
	printf("half_close_%s cases=%u mismatches=%u\n", concurrent ? "concurrent" : publication ? "publication" : "failure", cases, mismatches);
	ASSERT_EQ_U(cases, 4);
	ASSERT_EQ_U(mismatches, 0);
	return TEST_PASS;
}

static int
test_half_close_concurrent(void)
{
	return half_close_profiles(true, false);
}

static int
test_half_close_failure(void)
{
	return half_close_profiles(false, false);
}

static int
test_half_close_publication(void)
{
	return half_close_profiles(false, true);
}
