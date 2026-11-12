/* Terminal mode builder, exact wire bytes and application callback/getter trace. */
static int
test_terminal_mode_validation(void)
{
	unsigned cases = 0, failures = 0;
	for (unsigned populated = 0; populated < 3; populated++) {
		struct dssh_chan_params params;
		ASSERT_OK(dssh_chan_params_init(&params, DSSH_CHAN_SHELL));
		if (populated != 0)
			ASSERT_OK(dssh_chan_params_set_mode(&params, 42, 1));
		if (populated == 2) {
			ASSERT_OK(dssh_chan_params_set_mode(&params, 53, 1));
			params.modes[1].opcode = 0;
		}
		struct dssh_chan_mode_entry *storage = params.modes;
		size_t count = params.mode_count, capacity = params.mode_capacity;
		dssh_test_alloc_fail_after(0);
		int result = dssh_chan_params_set_mode(&params, populated == 2 ? 42 : 0, UINT32_MAX);
		int attempts = dssh_test_alloc_count();
		dssh_test_alloc_reset();
		bool valid = result == DSSH_ERROR_INVALID && attempts == 0 && params.modes == storage
		    && params.mode_count == count && params.mode_capacity == capacity;
		if (populated != 0)
			valid = valid && params.modes[0].opcode == 42 && params.modes[0].value == 1;
		if (populated == 2)
			valid = valid && params.modes[1].opcode == 0 && params.modes[1].value == 1;
		if (!valid)
			failures++;
		dssh_chan_params_free(&params);
		cases++;
	}
	struct conn_ctx ctx;
	ASSERT_OK(conn_setup(&ctx));
	struct dssh_chan_params params;
	ASSERT_OK(dssh_chan_params_init(&params, DSSH_CHAN_EXEC));
	ASSERT_OK(dssh_chan_params_set_command(&params, "terminal-mode"));
	for (unsigned zc = 0; zc < 2; zc++) {
		for (unsigned pty = 0; pty < 2; pty++) {
			for (unsigned position = 0; position < 3; position++) {
				struct dssh_chan_mode_entry modes[] = {{.opcode = 1, .value = 0},
				    {.opcode = 42, .value = 1}, {.opcode = 159, .value = UINT32_MAX}};
				modes[position].opcode = 0;
				struct dssh_chan_params trial = params;
				trial.flags = pty != 0 ? DSSH_PARAM_HAS_PTY : 0;
				trial.modes = modes;
				trial.mode_count = 3;
				trial.mode_capacity = 3;
				dssh_test_alloc_fail_after(0);
				dssh_channel channel = zc != 0 ? dssh_chan_zc_open(ctx.client, &trial, event_zc_data, NULL)
				    : dssh_chan_open(ctx.client, &trial);
				int attempts = dssh_test_alloc_count();
				dssh_test_alloc_reset();
				bool valid = channel == NULL && attempts == 0 && ctx.client->channel_count == 0
				    && modes[position].opcode == 0 && trial.mode_count == 3 && trial.modes == modes
				    && !dssh_session_is_terminated(ctx.client);
				if (!valid)
					failures++;
				cases++;
			}
		}
	}
	dssh_chan_params_free(&params);
	conn_cleanup(&ctx);
	printf("terminal_mode_validation cases=%u failures=%u\n", cases, failures);
	return cases == 15 && failures == 0 ? TEST_PASS : TEST_FAIL;
}

struct terminal_mode_capture {
	uint8_t bytes[16];
	atomic_uint count;
	atomic_bool bad;
};

static uint32_t
terminal_mode_data(dssh_channel channel, int stream, const uint8_t *bytes, size_t length, void *opaque)
{
	(void)channel;
	struct terminal_mode_capture *capture = opaque;
	unsigned count = atomic_load(&capture->count);
	if (stream != 0 || count > sizeof(capture->bytes) || length > sizeof(capture->bytes) - count) {
		atomic_store(&capture->bad, true);
		return 0;
	}
	memcpy(capture->bytes + count, bytes, length);
	unsigned received = (unsigned)length;
	atomic_store(&capture->count, count + received);
	uint32_t consumed = (uint32_t)length;
	return consumed;
}

struct terminal_mode_job {
	dssh_session session;
	struct dssh_chan_params *params;
	dssh_channel channel;
	struct terminal_mode_capture capture;
	unsigned mode, pty_calls, terminal_calls;
	bool accept, zc, valid;
};

static bool
terminal_mode_values(const struct dssh_chan_params *params, unsigned mode)
{
	size_t expected = mode == 0 ? 1 : 2;
	if (params == NULL || params->mode_count != expected || params->modes == NULL
	    || params->term == NULL || strcmp(params->term, "dumb") != 0
	    || params->cols != 87 || params->rows != 29 || params->wpx != 0 || params->hpx != 0
	    || params->modes[0].opcode != 53 || params->modes[0].value != 1)
		return false;
	return mode == 0 || (params->modes[1].opcode == 42
	    && params->modes[1].value == (mode == 1 ? 0U : 1U));
}

static int
terminal_mode_pty(dssh_channel channel, const struct dssh_chan_params *params, void *opaque)
{
	struct terminal_mode_job *job = opaque;
	job->pty_calls++;
	job->valid = job->valid && dssh_chan_get_pty(channel) == params
	    && dssh_chan_has_pty(channel) && terminal_mode_values(params, job->mode);
	return job->valid ? 0 : DSSH_ERROR_REJECTED;
}

static int
terminal_mode_exec(dssh_channel channel, const struct dssh_chan_params *params,
    struct dssh_chan_accept_result *result, void *opaque)
{
	struct terminal_mode_job *job = opaque;
	job->terminal_calls++;
	job->valid = job->valid && dssh_chan_get_pty(channel) == params
	    && dssh_chan_get_type(channel) == DSSH_CHAN_EXEC
	    && strcmp(dssh_chan_get_command(channel), "terminal-mode") == 0
	    && terminal_mode_values(params, job->mode);
	if (job->zc) {
		result->zc_cb = terminal_mode_data;
		result->zc_cbdata = &job->capture;
	}
	return job->valid ? 0 : DSSH_ERROR_REJECTED;
}

static int
terminal_mode_worker(void *opaque)
{
	struct terminal_mode_job *job = opaque;
	if (job->accept) {
		struct dssh_chan_accept_cbs cbs = {.pty_req = terminal_mode_pty,
		    .exec = terminal_mode_exec, .cbdata = job};
		job->channel = dssh_chan_accept(job->session, &cbs, 30000);
	}
	else
		job->channel = job->zc ? dssh_chan_zc_open(job->session, job->params, terminal_mode_data, &job->capture)
		    : dssh_chan_open(job->session, job->params);
	return job->channel != NULL ? 0 : DSSH_ERROR_INIT;
}

static void
terminal_mode_job_init(struct terminal_mode_job *job)
{
	atomic_init(&job->capture.count, 0);
	atomic_init(&job->capture.bad, false);
	job->valid = true;
}

static bool
terminal_mode_params(struct dssh_chan_params *params, unsigned mode)
{
	if (dssh_chan_params_init(params, DSSH_CHAN_EXEC) != 0)
		return false;
	if (dssh_chan_params_set_command(params, "terminal-mode") != 0
	    || dssh_chan_params_set_pty(params, true) != 0
	    || dssh_chan_params_set_size(params, 87, 29, 0, 0) != 0
	    || dssh_chan_params_set_mode(params, mode % 2 != 0 ? 255 : 160, UINT32_MAX) != 0
	    || dssh_chan_params_set_mode(params, 53, 1) != 0)
		return false;
	if (mode != 0 && dssh_chan_params_set_mode(params, 42, mode == 1 ? 0 : 1) != 0)
		return false;
	if (mode == 3) {
		struct dssh_chan_mode_entry *storage = params->modes;
		size_t capacity = params->mode_capacity;
		dssh_test_alloc_fail_after(0);
		int first = dssh_chan_params_set_mode(params, 42, 0);
		int second = dssh_chan_params_set_mode(params, 42, 1);
		int attempts = dssh_test_alloc_count();
		dssh_test_alloc_reset();
		return first == 0 && second == 0 && attempts == 0
		    && params->modes == storage && params->mode_count == 3 && params->mode_capacity == capacity;
	}
	return true;
}

static bool
terminal_mode_transmit(struct terminal_mode_job *job, const uint8_t *bytes, size_t length)
{
	if (!job->zc)
		return dssh_chan_poll(job->channel, DSSH_POLL_WRITE, 5000) == DSSH_POLL_WRITE
		    && dssh_chan_write(job->channel, 0, bytes, length) == 5;
	if (!control_frame_window_ready(job->channel))
		return false;
	uint8_t *buffer;
	size_t capacity;
	int result = dssh_chan_zc_getbuf(job->channel, 0, &buffer, &capacity);
	if (result != 0)
		return false;
	if (capacity < length) {
		int cancelled = dssh_chan_zc_cancel(job->channel);
		if (cancelled != 0)
			abort();
		return false;
	}
	memcpy(buffer, bytes, length);
	result = dssh_chan_zc_send(job->channel, length);
	if (result != 0) {
		int cancelled = dssh_chan_zc_cancel(job->channel);
		if (cancelled != 0 && cancelled != DSSH_ERROR_INVALID)
			return false;
	}
	return result == 0;
}

static int
test_terminal_mode_roundtrip(void)
{
	unsigned cases = 0;
	for (unsigned gather = 0; gather < 2; gather++) {
		for (unsigned zc = 0; zc < 2; zc++) {
			for (unsigned mode = 0; mode < 4; mode++) {
				struct conn_ctx ctx;
				window_test_gather = gather != 0;
				int setup = conn_setup(&ctx);
				window_test_gather = false;
				ASSERT_OK(setup);
				struct dssh_chan_params params;
				bool valid = terminal_mode_params(&params, mode);
				struct terminal_mode_job jobs[2] = {{.session = ctx.client, .params = &params,
				    .zc = zc != 0, .mode = mode}, {.session = ctx.server, .accept = true,
				    .zc = zc != 0, .mode = mode}};
				for (unsigned i = 0; i < 2; i++)
					terminal_mode_job_init(&jobs[i]);
				struct channel_workers workers;
				channel_workers_init(&workers, &ctx);
				if (valid)
					valid = channel_worker_start(&workers, 1, terminal_mode_worker, &jobs[1]) == 0
					    && channel_worker_start(&workers, 0, terminal_mode_worker, &jobs[0]) == 0;
				if (!valid)
					channel_workers_cancel(&workers);
				channel_workers_finish(&workers);
				valid = valid && workers.results[0] == 0 && workers.results[1] == 0
				    && jobs[0].channel != NULL && jobs[1].channel != NULL && jobs[1].valid
				    && jobs[1].pty_calls == 1 && jobs[1].terminal_calls == 1;
				if (valid) {
					const struct dssh_chan_params *copy = dssh_chan_get_pty(jobs[0].channel);
					valid = copy != NULL && copy->modes != params.modes && copy->mode_count == params.mode_count;
					if (valid) {
						for (size_t i = 0; i < copy->mode_count; i++)
							valid = copy->modes[i].opcode == params.modes[i].opcode
							    && copy->modes[i].value == params.modes[i].value && valid;
					}
				}
				dssh_chan_params_free(&params);
				valid = valid && terminal_mode_values(dssh_chan_get_pty(jobs[1].channel), mode);
				static const uint8_t bytes[] = {0, 0xc3, 0xa9, 0xff, 27};
				for (unsigned writer = 0; writer < 2 && valid; writer++) {
					struct terminal_mode_job *receiver = &jobs[writer == 0 ? 1 : 0];
					valid = terminal_mode_transmit(&jobs[writer], bytes, sizeof(bytes));
					if (valid && zc != 0) {
						struct timespec start;
						valid = clock_gettime(CLOCK_MONOTONIC, &start) == 0;
						while (valid && atomic_load(&receiver->capture.count) < sizeof(bytes))
							valid = dssh_test_wait_tick(&start);
						valid = valid && atomic_load(&receiver->capture.count) == sizeof(bytes)
						    && !atomic_load(&receiver->capture.bad)
						    && memcmp(receiver->capture.bytes, bytes, sizeof(bytes)) == 0;
					}
					else if (valid) {
						uint8_t output[sizeof(bytes)];
						valid = dssh_chan_poll(receiver->channel, DSSH_POLL_READ, 5000) == DSSH_POLL_READ
						    && dssh_chan_read(receiver->channel, 0, output, sizeof(output)) == 5
						    && memcmp(output, bytes, sizeof(bytes)) == 0;
					}
				}
				conn_cleanup(&ctx);
				ASSERT_TRUE(valid);
				cases++;
			}
		}
	}
	printf("terminal_mode_roundtrip cases=%u valid=1\n", cases);
	return cases == 16 ? TEST_PASS : TEST_FAIL;
}

static int
test_terminal_mode_wire(void)
{
	unsigned cases = 0;
	for (unsigned gather = 0; gather < 2; gather++) {
		for (unsigned zc = 0; zc < 2; zc++) {
			for (unsigned mode = 0; mode < 4; mode++) {
				struct conn_ctx ctx;
				window_test_gather = gather != 0;
				int setup = conn_setup_mode(&ctx, false);
				window_test_gather = false;
				ASSERT_OK(setup);
				ASSERT_OK(dssh_session_start(ctx.client));
				struct dssh_chan_params params;
				bool valid = terminal_mode_params(&params, mode);
				struct terminal_mode_job job = {.session = ctx.client, .params = &params, .zc = zc != 0};
				terminal_mode_job_init(&job);
				thrd_t worker;
				bool started = valid && thrd_create(&worker, terminal_mode_worker, &job) == thrd_success;
				uint32_t local = 0;
				valid = started && channel_id_receive_open(ctx.server, &local);
				uint8_t reply[17];
				size_t reply_length = valid ? channel_id_build_reply(reply, local, true, 42) : 0;
				uint8_t type, *payload;
				size_t length;
				uint8_t absent[] = {53, 0, 0, 0, 1, 160, 255, 255, 255, 255, 0};
				uint8_t present[] = {53, 0, 0, 0, 1, 42, 0, 0, 0, 1, 160, 255, 255, 255, 255, 0};
				present[9] = mode == 1 ? 0 : 1;
				present[10] = mode % 2 != 0 ? 255 : 160;
				const uint8_t *expected = mode == 0 ? absent : present;
				size_t mode_length = mode == 0 ? sizeof(absent) : sizeof(present);
				if (valid)
					valid = send_packet(ctx.server, reply, reply_length, NULL) == 0
					    && recv_packet(ctx.server, &type, &payload, &length) == 0
					    && type == SSH_MSG_CHANNEL_REQUEST && length == 45 + mode_length
					    && DSSH_GET_U32(payload + 1) == 42 && DSSH_GET_U32(payload + 5) == 7
					    && memcmp(payload + 9, "pty-req", 7) == 0 && payload[16] == 1
					    && DSSH_GET_U32(payload + 17) == 4 && memcmp(payload + 21, "dumb", 4) == 0
					    && DSSH_GET_U32(payload + 25) == 87 && DSSH_GET_U32(payload + 29) == 29
					    && DSSH_GET_U32(payload + 33) == 0 && DSSH_GET_U32(payload + 37) == 0
					    && DSSH_GET_U32(payload + 41) == mode_length
					    && memcmp(payload + 45, expected, mode_length) == 0;
				if (valid) {
					size_t pos = 0;
					reply[pos++] = SSH_MSG_CHANNEL_SUCCESS;
					DSSH_PUT_U32(local, reply, &pos);
					valid = send_packet(ctx.server, reply, pos, NULL) == 0
					    && recv_packet(ctx.server, &type, &payload, &length) == 0
					    && type == SSH_MSG_CHANNEL_REQUEST && length == 31
					    && DSSH_GET_U32(payload + 1) == 42 && DSSH_GET_U32(payload + 5) == 4
					    && memcmp(payload + 9, "exec", 4) == 0 && payload[13] == 1
					    && DSSH_GET_U32(payload + 14) == 13 && memcmp(payload + 18, "terminal-mode", 13) == 0
					    && send_packet(ctx.server, reply, pos, NULL) == 0
					    && peer_id_receive_control(ctx.server, SSH_MSG_CHANNEL_WINDOW_ADJUST, 9, 42);
				}
				if (!valid) {
					mock_io_close_c2s(&ctx.io);
					mock_io_close_s2c(&ctx.io);
				}
				int result = 1;
				if (started && thrd_join(worker, &result) != thrd_success)
					abort();
				valid = valid && started && result == 0 && job.channel != NULL;
				dssh_chan_params_free(&params);
				conn_cleanup(&ctx);
				ASSERT_TRUE(valid);
				cases++;
			}
		}
	}
	printf("terminal_mode_wire cases=%u valid=1\n", cases);
	return cases == 16 ? TEST_PASS : TEST_FAIL;
}
