/* Public stream-read completion on actual paired encrypted channels. */
#ifndef DSSH_TEST_READ_RESULT_CASES_H
#define DSSH_TEST_READ_RESULT_CASES_H

enum read_result_kind {
	RR_NORMAL, RR_TX, RR_LOCK_BEFORE, RR_LOCK_AFTER, RR_QUEUE_LOCK,
	RR_RANDOM, RR_KEY, RR_SIZE, RR_COMPRESS, RR_EOF, RR_TERMINATED
};

struct read_result_fixture {
	struct conn_ctx ctx;
	dssh_channel client, server;
	unsigned tx_failures;
};
static _Thread_local struct read_result_fixture *read_result_current;

static int
read_result_client(void *opaque)
{
	struct read_result_fixture *fixture = opaque;
	struct dssh_chan_params params;
	int ret = dssh_chan_params_init(&params, DSSH_CHAN_EXEC);
	if (ret != 0)
		return ret;
	ret = dssh_chan_params_set_command(&params, "read-result");
	if (ret == 0)
		ret = dssh_chan_params_set_pty(&params, false);
	if (ret == 0)
		ret = dssh_chan_params_set_max_window(&params, 32);
	if (ret == 0) {
		fixture->client = dssh_chan_open(fixture->ctx.client, &params);
		ret = wait_stream_writable(fixture->client);
	}
	dssh_chan_params_free(&params);
	return ret;
}

static int
read_result_terminal(dssh_channel channel, const struct dssh_chan_params *params,
    struct dssh_chan_accept_result *result, void *data)
{
	(void)channel;
	(void)params;
	(void)data;
	result->max_window = 32;
	return 0;
}

static int
read_result_server(void *opaque)
{
	struct read_result_fixture *fixture = opaque;
	struct dssh_chan_accept_cbs callbacks = {.exec = read_result_terminal};
	fixture->server = dssh_chan_accept(fixture->ctx.server, &callbacks, 3000);
	return wait_stream_writable(fixture->server);
}

static bool
read_result_setup(struct read_result_fixture *fixture, bool gather)
{
	window_test_gather = gather;
	int ret = conn_setup(&fixture->ctx);
	window_test_gather = false;
	if (ret != 0)
		return false;
	return open_channel_pair(&fixture->ctx, read_result_client, fixture, &fixture->client,
	    read_result_server, fixture, &fixture->server) == 0;
}

static int
read_result_fail_tx(dssh_session session)
{
	(void)session;
	read_result_current->tx_failures++;
	return DSSH_ERROR_INIT;
}

static bool
read_result_fill(dssh_channel writer, dssh_channel reader, int stream)
{
	uint8_t input[24];
	for (size_t i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)(i + 1);
	if (dssh_chan_write(writer, stream, input, sizeof(input)) != 24)
		return false;
	struct timespec start;
	if (!conn_zc_start_clock(&start, 5))
		return false;
	while (dssh_chan_read(reader, stream, NULL, 0) != 24) {
		if (!conn_zc_tick(&start, 5))
			return false;
	}
	return atomic_load(&writer->remote_window) == 8;
}

static bool
read_result_bytes(const uint8_t *bytes, size_t length, size_t offset)
{
	if (offset > 24 || length > 24 - offset)
		return false;
	for (size_t i = 0; i < length; i++) {
		if (bytes[i] != i + offset + 1)
			return false;
	}
	return true;
}

static bool
read_result_case(enum read_result_kind kind, bool reverse, int stream,
    bool gather, size_t amount)
{
	struct read_result_fixture fixture = {0};
	if (!read_result_setup(&fixture, gather)) {
		conn_cleanup(&fixture.ctx);
		return false;
	}
	dssh_channel writer = reverse ? fixture.server : fixture.client;
	dssh_channel reader = reverse ? fixture.client : fixture.server;
	dssh_session session = reader->sess;
	bool valid = read_result_fill(writer, reader, stream);
	uint8_t output[26];
	memset(output, 0xa5, sizeof(output));
	uint_fast32_t saved_packets = atomic_load(&session->trans.tx_since_rekey);
	size_t saved_capacity = session->trans.comp_tx_payload_limit;
	read_result_current = &fixture;
	if (kind == RR_EOF) {
		valid = valid && dssh_chan_shutwr(writer) == 0;
		struct timespec start;
		valid = valid && conn_zc_start_clock(&start, 5);
		bool eof = false;
		while (valid && !eof) {
			if (mtx_lock(&reader->buf_mtx) != thrd_success)
				abort();
			eof = reader->eof_received;
			if (mtx_unlock(&reader->buf_mtx) != thrd_success)
				abort();
			if (!eof)
				valid = conn_zc_tick(&start, 5);
		}
	}
	if (kind == RR_TERMINATED)
		dssh_session_terminate(session);
	if (valid) {
		if (kind == RR_TX)
			setup_tx_test_hook = read_result_fail_tx;
		else if (kind == RR_LOCK_BEFORE)
			dssh_test_mtx_reject_once(&reader->buf_mtx);
		else if (kind == RR_LOCK_AFTER)
			dssh_test_thrd_fail_after(1);
		else if (kind == RR_QUEUE_LOCK)
			dssh_test_mtx_reject_once(&session->trans.tx_queue_mtx);
		else if (kind == RR_RANDOM)
			dssh_test_ossl_fail_after(0);
		else if (kind == RR_KEY)
			atomic_store(&session->trans.tx_since_rekey, DSSH_REKEY_HARD_LIMIT);
		else if (kind == RR_SIZE)
			session->trans.comp_tx_payload_limit = 1;
		else if (kind == RR_COMPRESS)
			dssh_test_comp_fail(DSSH_TEST_COMP_COMPRESS, DSSH_ERROR_TOOLONG);
	}
	int64_t delivered = valid ? dssh_chan_read(reader, stream, output + 1, amount) : DSSH_ERROR_INIT;
	unsigned unowned = dssh_test_mtx_rejected_unlocks();
	int thread_calls = dssh_test_thrd_count();
	size_t random_length = 0;
	unsigned int random_strength = 0;
	bool random_completed = false;
	bool random_seen = dssh_test_ossl_random_observed(&random_length, &random_strength, &random_completed);
	setup_tx_test_hook = NULL;
	dssh_test_ossl_reset();
	dssh_test_comp_fail(DSSH_TEST_COMP_NONE, 0);
	bool refused = kind == RR_KEY || kind == RR_SIZE;
	bool failed = kind == RR_TX || kind == RR_LOCK_AFTER || kind == RR_QUEUE_LOCK
	    || kind == RR_RANDOM || kind == RR_COMPRESS || refused;
	int expected_error = kind == RR_KEY ? DSSH_ERROR_REKEY_NEEDED
	    : kind == RR_SIZE || kind == RR_COMPRESS ? DSSH_ERROR_TOOLONG
	    : kind == RR_LOCK_AFTER || kind == RR_QUEUE_LOCK ? DSSH_ERROR_TERMINATED : DSSH_ERROR_INIT;
	int64_t expected_delivered = kind == RR_LOCK_BEFORE ? DSSH_ERROR_TERMINATED : (int64_t)amount;
	valid = valid && delivered == expected_delivered && output[0] == 0xa5
	    && output[amount + 1] == 0xa5 && unowned == 0;
	if (kind == RR_LOCK_BEFORE) {
		for (size_t i = 0; i < sizeof(output); i++)
			valid = valid && output[i] == 0xa5;
		amount = 0;
	}
	else
		valid = valid && read_result_bytes(output + 1, amount, 0);
	valid = valid && dssh_chan_read(reader, stream, NULL, 0) == 24 - (int64_t)amount;
	if (failed) {
		int events = dssh_chan_poll(reader, DSSH_POLL_READ | DSSH_POLL_READEXT, 0);
		uint8_t sentinel = 0xa5;
		int other = stream == 0 ? 1 : 0;
		int64_t error = dssh_chan_read(reader, other, &sentinel, 1);
		valid = valid && events == (DSSH_POLL_READ | DSSH_POLL_READEXT)
		    && error == expected_error && sentinel == 0xa5
		    && dssh_chan_read(reader, stream, NULL, 0) == 24 - (int64_t)amount;
	}
	if (kind == RR_TX)
		valid = valid && fixture.tx_failures == 1;
	if (kind == RR_LOCK_AFTER)
		valid = valid && thread_calls > 1;
	if (kind == RR_RANDOM)
		valid = valid && random_seen && random_length > 0 && random_strength == 256 && !random_completed;
	if (refused) {
		/* The peer is quiescent; these are bounded pre-wire state models. */
		atomic_store(&session->trans.tx_since_rekey, saved_packets);
		session->trans.comp_tx_payload_limit = saved_capacity;
	}
	uint8_t remainder[24];
	memset(remainder, 0xa5, sizeof(remainder));
	int64_t remaining = dssh_chan_read(reader, stream, remainder, sizeof(remainder));
	if (amount == 24) {
		int64_t expected = failed && !refused ? 0
		    : kind == RR_EOF || kind == RR_TERMINATED ? 0 : DSSH_ERROR_NOMORE;
		valid = valid && remaining == expected;
	}
	else
		valid = valid && remaining == 24 - (int64_t)amount
		    && read_result_bytes(remainder, 24 - amount, amount);
	if (refused)
		valid = valid && window_credit_ready(writer, 32)
		    && !dssh_session_is_terminated(session) && !atomic_load(&reader->wa_slot.ready);
	if (kind == RR_EOF || kind == RR_TERMINATED || (failed && !refused)
	    || kind == RR_LOCK_BEFORE) {
		uint8_t sentinel = 0xa5;
		valid = valid && dssh_chan_read(reader, stream, &sentinel, 1) == 0 && sentinel == 0xa5;
	}
	if (printf("read_result kind=%u reverse=%u stream=%d gather=%u delivered=%lld amount=%zu valid=%u\n",
	    (unsigned)kind, reverse ? 1U : 0U, stream, gather ? 1U : 0U,
	    (long long)delivered, amount, valid ? 1U : 0U) < 0)
		valid = false;
	read_result_current = NULL;
	conn_cleanup(&fixture.ctx);
	return valid && fixture.ctx.client == NULL && fixture.ctx.server == NULL;
}

static int
read_result_group(unsigned group)
{
	unsigned cases = 0;
	const char *compression = getenv("DSSH_TEST_COMPRESSION");
	bool growth = compression != NULL && strcmp(compression, "test-growth") == 0;
	for (unsigned kind = 0; kind <= RR_TERMINATED; kind++) {
		bool selected = group == 0 ? kind == RR_TX
		    : group == 1 ? kind <= RR_QUEUE_LOCK && kind != RR_TX
		    : group == 2 ? kind == RR_KEY || (growth && kind == RR_SIZE)
		    : group == 3 ? kind == RR_EOF || kind == RR_TERMINATED
		    : group == 4 ? kind == RR_RANDOM || (growth && kind == RR_COMPRESS) : false;
#ifndef DSSH_CRYPTO_OPENSSL
		if (kind == RR_RANDOM)
			selected = false;
#endif
		if (!selected)
			continue;
		for (unsigned reverse = 0; reverse < 2; reverse++) {
			for (int stream = 0; stream < 2; stream++) {
				for (unsigned gather = 0; gather < 2; gather++) {
					for (unsigned partial = 0; partial < 2; partial++) {
						enum read_result_kind kind_value = (enum read_result_kind)kind;
						if (!read_result_case(kind_value, reverse != 0, stream, gather != 0, partial != 0 ? 8 : 24))
							return TEST_FAIL;
						cases++;
					}
				}
			}
		}
	}
	if (printf("read_result_group=%u cases=%u valid=1\n", group, cases) < 0 || fflush(stdout) != 0)
		return TEST_FAIL;
	return cases != 0 || (group == 4 && !growth) ? TEST_PASS : TEST_FAIL;
}

static int
test_read_result_deferred(void)
{
	return read_result_group(0);
}

static int
test_read_result_failures(void)
{
	return read_result_group(1);
}

static int
test_read_result_retry(void)
{
	return read_result_group(2);
}

static int
test_read_result_terminal(void)
{
	return read_result_group(3);
}

static int
test_read_result_provider(void)
{
	return read_result_group(4);
}

#endif
