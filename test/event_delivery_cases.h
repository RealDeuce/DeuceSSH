/* Actual transport peers, with explicit direct-dispatch cases for deterministic
 * allocation and synchronization boundaries. Capture storage outlives cleanup. */
#define EVENT_CAPTURE_CAP 144
struct event_capture {
	atomic_int count;
	atomic_bool bad;
	atomic_bool entered;
	atomic_bool release;
	bool pause;
	bool demux;
	bool lifecycle;
	bool fail_reacquire;
	bool self_disable;
	struct dssh_chan_event events[EVENT_CAPTURE_CAP];
	uint8_t names[EVENT_CAPTURE_CAP][128];
	uint8_t errors[EVENT_CAPTURE_CAP][512];
	uint8_t languages[EVENT_CAPTURE_CAP][128];
};

static void
event_capture_init(struct event_capture *capture, bool demux)
{
	atomic_init(&capture->count, 0);
	atomic_init(&capture->bad, false);
	atomic_init(&capture->entered, false);
	atomic_init(&capture->release, false);
	capture->demux = demux;
}

static void
capture_event(dssh_channel ch, const struct dssh_chan_event *event, void *opaque)
{
	struct event_capture *capture = opaque;
	int count = atomic_load(&capture->count);
	if (count < 0 || count >= EVENT_CAPTURE_CAP || event == NULL) {
		atomic_store(&capture->bad, true);
		return;
	}
	if (capture->demux != session_on_demux_thread(ch->sess))
		atomic_store(&capture->bad, true);
	capture->events[count] = *event;
	struct dssh_bytes name = {0};
	if (event->type == DSSH_EVENT_SIGNAL)
		name = event->signal.name;
	else if (event->type == DSSH_EVENT_EXIT_SIGNAL)
		name = event->exit_signal.signal_name;
	if (name.len > sizeof(capture->names[count]))
		atomic_store(&capture->bad, true);
	else {
		if (name.len != 0)
			memcpy(capture->names[count], name.data, name.len);
		name.data = name.len != 0 ? capture->names[count] : NULL;
		if (event->type == DSSH_EVENT_SIGNAL)
			capture->events[count].signal.name = name;
		else if (event->type == DSSH_EVENT_EXIT_SIGNAL)
			capture->events[count].exit_signal.signal_name = name;
	}
	if (event->type == DSSH_EVENT_EXIT_SIGNAL) {
		struct dssh_bytes error = event->exit_signal.error_message;
		struct dssh_bytes language = event->exit_signal.language;
		if (error.len > sizeof(capture->errors[count])
		    || language.len > sizeof(capture->languages[count]))
			atomic_store(&capture->bad, true);
		else {
			if (error.len != 0)
				memcpy(capture->errors[count], error.data, error.len);
			if (language.len != 0)
				memcpy(capture->languages[count], language.data, language.len);
			error.data = error.len != 0 ? capture->errors[count] : NULL;
			language.data = language.len != 0 ? capture->languages[count] : NULL;
			capture->events[count].exit_signal.error_message = error;
			capture->events[count].exit_signal.language = language;
		}
	}
	/* These calls must reject immediately, before waiting or mutation. */
	uint8_t byte = 0;
	uint8_t *out = NULL;
	size_t available = 0;
	struct dssh_chan_event ignored;
	bool rejected = dssh_chan_write(ch, 0, &byte, 1) == DSSH_ERROR_INVALID
	    && dssh_chan_zc_getbuf(ch, 0, &out, &available) == DSSH_ERROR_INVALID
	    && dssh_chan_shutwr(ch) == DSSH_ERROR_INVALID
	    && dssh_chan_send_signal(ch, "TERM") == DSSH_ERROR_INVALID
	    && dssh_chan_send_break(ch, 1) == DSSH_ERROR_INVALID
	    && dssh_chan_send_window_change(ch, 1, 2, 3, 4) == DSSH_ERROR_INVALID
	    && dssh_chan_read(ch, 0, NULL, 0) == DSSH_ERROR_INVALID
	    && dssh_chan_poll(ch, DSSH_POLL_READ, 0) == DSSH_ERROR_INVALID
	    && dssh_chan_read_event(ch, &ignored) == DSSH_ERROR_INVALID
	    && dssh_chan_close(ch, -1) == DSSH_ERROR_INVALID
	    && dssh_chan_zc_send(ch, 0) == DSSH_ERROR_INVALID
	    && dssh_chan_zc_cancel(ch) == DSSH_ERROR_INVALID;
	if (!rejected)
		atomic_store(&capture->bad, true);
	if (capture->pause) {
		atomic_store(&capture->entered, true);
		if (!dssh_test_wait_bool(&capture->release, true))
			atomic_store(&capture->bad, true);
	}
	if (capture->lifecycle)
		dssh_session_cleanup(ch->sess);
	if (capture->fail_reacquire)
		dssh_test_mtx_reject_once(&ch->buf_mtx);
	if (capture->self_disable) {
		if (dssh_chan_get_type(ch) != DSSH_CHAN_EXEC || dssh_chan_get_command(ch) == NULL
		    || dssh_chan_set_event_cb(ch, NULL, NULL) != 0)
			atomic_store(&capture->bad, true);
	}
	atomic_store(&capture->count, count + 1);
}

static void
capture_other_event(dssh_channel ch, const struct dssh_chan_event *event, void *opaque)
{
	capture_event(ch, event, opaque);
}

static uint32_t
event_zc_data(dssh_channel ch, int stream, const uint8_t *data, size_t len, void *opaque)
{
	(void)ch;
	(void)stream;
	(void)data;
	(void)opaque;
	uint32_t consumed = len > UINT32_MAX ? UINT32_MAX : (uint32_t)len;
	return consumed;
}

static int
event_accept_zc(dssh_channel ch, const struct dssh_chan_params *params,
    struct dssh_chan_accept_result *result, void *opaque)
{
	(void)ch;
	(void)params;
	(void)opaque;
	result->zc_cb = event_zc_data;
	return 0;
}

struct event_fixture {
	struct conn_ctx ctx;
	struct open_exec_ctx open;
	struct dssh_chan_accept_cbs cbs;
};

static bool
event_setup(struct event_fixture *fixture, struct event_capture *capture, bool zc)
{
	if (conn_setup_no_start(&fixture->ctx) < 0)
		return false;
	if (capture != NULL && dssh_session_set_event_cb(fixture->ctx.server,
	    capture_event, capture) != 0)
		return false;
	if (dssh_session_start(fixture->ctx.client) != 0
	    || dssh_session_start(fixture->ctx.server) != 0)
		return false;
	fixture->cbs = accept_cbs_all;
	if (zc)
		fixture->cbs.exec = event_accept_zc;
	fixture->open = (struct open_exec_ctx){
		.client = fixture->ctx.client, .server = fixture->ctx.server,
		.command = "event-delivery", .cbs = &fixture->cbs, .accept_timeout = 30000,
	};
	return open_exec_channel(&fixture->ctx, &fixture->open) == 0;
}

static int
event_packet(struct dssh_channel_s *ch, int type, uint8_t *buf, size_t cap, size_t *length)
{
	size_t pos = 0;
	if (cap == 0)
		return DSSH_ERROR_TOOLONG;
	buf[pos++] = type == DSSH_EVENT_EOF ? SSH_MSG_CHANNEL_EOF
	    : type == DSSH_EVENT_CLOSE ? SSH_MSG_CHANNEL_CLOSE : SSH_MSG_CHANNEL_REQUEST;
	int ret = dssh_serialize_uint32(ch->local_id, buf, cap, &pos);
	if (ret != 0)
		return ret;
	if (type != DSSH_EVENT_EOF && type != DSSH_EVENT_CLOSE) {
		const char *request = type == DSSH_EVENT_SIGNAL ? "signal"
		    : type == DSSH_EVENT_WINDOW_CHANGE ? "window-change"
		    : type == DSSH_EVENT_BREAK ? "break"
		    : type == DSSH_EVENT_EXIT_STATUS ? "exit-status" : "exit-signal";
		size_t len = strlen(request);
		uint32_t len_u32 = (uint32_t)len;
		ret = dssh_serialize_uint32(len_u32, buf, cap, &pos);
		if (ret != 0 || !dssh_buffer_has(cap, pos, len + 1))
			return DSSH_ERROR_TOOLONG;
		memcpy(buf + pos, request, len);
		pos += len;
		buf[pos++] = 0;
		if (type == DSSH_EVENT_SIGNAL || type == DSSH_EVENT_EXIT_SIGNAL) {
			ret = dssh_serialize_uint32(4, buf, cap, &pos);
			if (ret != 0 || !dssh_buffer_has(cap, pos, 4))
				return DSSH_ERROR_TOOLONG;
			memcpy(buf + pos, "TERM", 4);
			pos += 4;
			if (type == DSSH_EVENT_EXIT_SIGNAL) {
				if (!dssh_buffer_has(cap, pos, 1))
					return DSSH_ERROR_TOOLONG;
				buf[pos++] = 1;
				ret = dssh_serialize_uint32(7, buf, cap, &pos);
				if (ret != 0 || !dssh_buffer_has(cap, pos, 7))
					return DSSH_ERROR_TOOLONG;
				memcpy(buf + pos, "message", 7);
				pos += 7;
				ret = dssh_serialize_uint32(0, buf, cap, &pos);
			}
		}
		else {
			ret = dssh_serialize_uint32(UINT32_MAX, buf, cap, &pos);
			if (type == DSSH_EVENT_WINDOW_CHANGE) {
				for (uint32_t i = 2; i <= 4 && ret == 0; i++)
					ret = dssh_serialize_uint32(i, buf, cap, &pos);
			}
		}
		if (ret != 0)
			return ret;
	}
	*length = pos;
	return 0;
}

static int
event_send(struct event_fixture *fixture, int type, bool direct)
{
	uint8_t packet[128];
	size_t len = 0;
	int ret = event_packet(fixture->open.server_ch, type, packet, sizeof(packet), &len);
	if (ret != 0)
		return ret;
	if (direct)
		return dssh_test_demux_dispatch(fixture->ctx.server, packet[0], packet, len);
	return send_packet(fixture->ctx.client, packet, len, NULL);
}

static int
event_peer_case(bool zc)
{
	struct event_capture capture = {0};
	event_capture_init(&capture, true);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &capture, zc));
	static const int types[] = {DSSH_EVENT_SIGNAL, DSSH_EVENT_WINDOW_CHANGE,
		DSSH_EVENT_BREAK, DSSH_EVENT_EXIT_STATUS, DSSH_EVENT_EXIT_SIGNAL,
		DSSH_EVENT_EOF, DSSH_EVENT_CLOSE};
	uint8_t data[] = {1, 2, 3};
	ASSERT_EQ(dssh_chan_write(fixture.open.client_ch, 0, data, 3), 3);
	ASSERT_EQ(dssh_chan_write(fixture.open.client_ch, 1, data, 2), 2);
	for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
		ASSERT_OK(event_send(&fixture, types[i], false));
	bool delivered = dssh_test_wait_int(&capture.count, 7);
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(delivered);
	ASSERT_FALSE(atomic_load(&capture.bad));
	for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		ASSERT_EQ(capture.events[i].type, types[i]);
		ASSERT_EQ_U(capture.events[i].stdout_pos, 3);
		ASSERT_EQ_U(capture.events[i].stderr_pos, 2);
	}
	ASSERT_TRUE(dssh_test_bytes_equal(capture.events[0].signal.name, "TERM", 4));
	ASSERT_EQ_U(capture.events[1].window_change.cols, UINT32_MAX);
	ASSERT_EQ_U(capture.events[1].window_change.rows, 2);
	ASSERT_EQ_U(capture.events[1].window_change.wpx, 3);
	ASSERT_EQ_U(capture.events[1].window_change.hpx, 4);
	ASSERT_EQ_U(capture.events[2].brk.length, UINT32_MAX);
	ASSERT_EQ_U(capture.events[3].exit_status.exit_code, UINT32_MAX);
	ASSERT_TRUE(dssh_test_bytes_equal(capture.events[4].exit_signal.signal_name, "TERM", 4));
	ASSERT_TRUE(capture.events[4].exit_signal.core_dumped);
	ASSERT_TRUE(dssh_test_bytes_equal(capture.events[4].exit_signal.error_message, "message", 7));
	return TEST_PASS;
}

static int
test_event_peer_stream(void)
{
	return event_peer_case(false);
}

static int
test_event_peer_zc(void)
{
	return event_peer_case(true);
}

static int
test_event_stress(void)
{
	struct event_capture capture = {0};
	event_capture_init(&capture, false);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &capture, false));
	ASSERT_OK(dssh_chan_set_max_events(fixture.open.server_ch, 1));
	int ret = 0;
	dssh_test_alloc_fail_after(0);
	for (int i = 0; i < 130 && ret == 0; i++)
		ret = event_send(&fixture, DSSH_EVENT_SIGNAL, true);
	int allocations = dssh_test_alloc_count();
	dssh_test_alloc_reset();
	bool valid = ret == 0 && atomic_load(&capture.count) == 130
	    && !atomic_load(&capture.bad) && allocations == 0;
	ASSERT_EQ(mtx_lock(&fixture.open.server_ch->buf_mtx), thrd_success);
	valid = valid && fixture.open.server_ch->events.count == 0
	    && !fixture.open.server_ch->events.has_frozen && fixture.open.server_ch->open;
	ASSERT_EQ(mtx_unlock(&fixture.open.server_ch->buf_mtx), thrd_success);
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_event_switch(void)
{
	struct event_capture first = {0};
	struct event_capture second = {0};
	event_capture_init(&first, false);
	event_capture_init(&second, false);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, NULL, false));
	ASSERT_OK(event_send(&fixture, DSSH_EVENT_SIGNAL, true));
	ASSERT_EQ(dssh_chan_poll(fixture.open.server_ch, DSSH_POLL_EVENT, 0), DSSH_POLL_EVENT);
	ASSERT_OK(event_send(&fixture, DSSH_EVENT_BREAK, true));
	ASSERT_OK(dssh_chan_set_event_cb(fixture.open.server_ch, capture_event, &first));
	ASSERT_OK(event_send(&fixture, DSSH_EVENT_EXIT_SIGNAL, true));
	ASSERT_OK(dssh_chan_set_event_cb(fixture.open.server_ch, capture_other_event, &second));
	ASSERT_OK(event_send(&fixture, DSSH_EVENT_WINDOW_CHANGE, true));
	struct dssh_chan_event old;
	ASSERT_OK(dssh_chan_read_event(fixture.open.server_ch, &old));
	bool valid = old.type == DSSH_EVENT_SIGNAL && dssh_test_bytes_equal(old.signal.name, "TERM", 4)
	    && atomic_load(&first.count) == 1 && atomic_load(&second.count) == 1;
	ASSERT_OK(dssh_chan_set_event_cb(fixture.open.server_ch, NULL, NULL));
	ASSERT_OK(event_send(&fixture, DSSH_EVENT_EXIT_STATUS, true));
	valid = valid && dssh_test_bytes_equal(old.signal.name, "TERM", 4);
	ASSERT_EQ(dssh_chan_poll(fixture.open.server_ch, DSSH_POLL_EVENT, 0), DSSH_POLL_EVENT);
	ASSERT_OK(dssh_chan_read_event(fixture.open.server_ch, &old));
	valid = valid && old.type == DSSH_EVENT_BREAK;
	ASSERT_EQ(dssh_chan_poll(fixture.open.server_ch, DSSH_POLL_EVENT, 0), DSSH_POLL_EVENT);
	ASSERT_OK(dssh_chan_read_event(fixture.open.server_ch, &old));
	valid = valid && old.type == DSSH_EVENT_EXIT_STATUS
	    && !atomic_load(&first.bad) && !atomic_load(&second.bad);
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_event_replacement(void)
{
	struct event_capture first = {.pause = true};
	struct event_capture second = {0};
	event_capture_init(&first, true);
	event_capture_init(&second, true);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &first, false));
	ASSERT_OK(event_send(&fixture, DSSH_EVENT_SIGNAL, false));
	bool entered = dssh_test_wait_bool(&first.entered, true);
	bool valid = entered;
	if (entered) {
		/* Acquire each mutex separately while the real demux callback is
		 * paused. A lock retained by that callback would prevent progress. */
		mtx_t *locks[] = {&fixture.open.server_ch->buf_mtx,
			&fixture.open.server_ch->cb_mtx, &fixture.ctx.server->channel_mtx,
			&fixture.ctx.server->accept_mtx, &fixture.ctx.server->trans.tx_mtx,
			&fixture.ctx.server->trans.tx_queue_mtx};
		for (size_t i = 0; i < sizeof(locks) / sizeof(locks[0]); i++) {
			if (mtx_lock(locks[i]) != thrd_success)
				abort();
			if (mtx_unlock(locks[i]) != thrd_success)
				abort();
		}
		valid = dssh_chan_set_event_cb(fixture.open.server_ch, capture_other_event, &second) == 0;
	}
	atomic_store(&first.release, true);
	valid = valid && dssh_test_wait_int(&first.count, 1);
	if (valid)
		valid = event_send(&fixture, DSSH_EVENT_BREAK, false) == 0
		    && dssh_test_wait_int(&second.count, 1);
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	ASSERT_FALSE(atomic_load(&first.bad));
	ASSERT_FALSE(atomic_load(&second.bad));
	ASSERT_EQ(first.events[0].type, DSSH_EVENT_SIGNAL);
	ASSERT_EQ(second.events[0].type, DSSH_EVENT_BREAK);
	return TEST_PASS;
}

static int
test_event_lifecycle(void)
{
	struct event_capture capture = {.lifecycle = true};
	event_capture_init(&capture, true);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &capture, false));
	ASSERT_OK(event_send(&fixture, DSSH_EVENT_SIGNAL, false));
	bool valid = dssh_test_wait_int(&capture.count, 1)
	    && dssh_session_is_terminated(fixture.ctx.server)
	    && fixture.ctx.server->trans.rx_packet != NULL;
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	ASSERT_FALSE(atomic_load(&capture.bad));
	return TEST_PASS;
}

static int
test_event_acquire(void)
{
	struct event_capture capture = {0};
	event_capture_init(&capture, false);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &capture, false));
	dssh_test_mtx_reject_once(&fixture.open.server_ch->cb_mtx);
	int ret = event_send(&fixture, DSSH_EVENT_SIGNAL, true);
	bool valid = ret == DSSH_ERROR_TERMINATED && fixture.ctx.server->terminate
	    && dssh_test_mtx_rejected_unlocks() == 0 && atomic_load(&capture.count) == 0
	    && atomic_load(&fixture.open.server_ch->dispatch_state) == DSSH_CHANNEL_DISPATCH_IDLE;
	dssh_test_ossl_reset();
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_event_queue_allocation(void)
{
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, NULL, false));
	for (int i = 0; i < 8; i++)
		ASSERT_OK(event_send(&fixture, DSSH_EVENT_SIGNAL, true));
	dssh_test_alloc_fail_after(0);
	int ret = event_send(&fixture, DSSH_EVENT_SIGNAL, true);
	int count = dssh_test_alloc_count();
	dssh_test_alloc_reset();
	bool valid = ret == DSSH_ERROR_ALLOC && count == 1
	    && atomic_load(&fixture.open.server_ch->dispatch_state) == DSSH_CHANNEL_DISPATCH_IDLE;
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_event_malformed(void)
{
	struct event_capture capture = {0};
	event_capture_init(&capture, false);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &capture, false));
	int types[] = {DSSH_EVENT_SIGNAL, DSSH_EVENT_WINDOW_CHANGE, DSSH_EVENT_BREAK,
		DSSH_EVENT_EXIT_STATUS, DSSH_EVENT_EXIT_SIGNAL};
	bool valid = true;
	for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		uint8_t packet[128];
		size_t len = 0;
		ASSERT_OK(event_packet(fixture.open.server_ch, types[i], packet, sizeof(packet), &len));
		uint32_t request_len = DSSH_GET_U32(packet + 5);
		size_t first = 10 + request_len;
		for (size_t n = first; n < len; n++) {
			int ret = dssh_test_demux_dispatch(fixture.ctx.server, packet[0], packet, n);
			valid = valid && ret == DSSH_ERROR_PARSE && atomic_load(&capture.count) == 0;
		}
	}
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_event_close_race(void)
{
	struct event_capture capture = {.pause = true};
	event_capture_init(&capture, true);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &capture, false));
	ASSERT_OK(event_send(&fixture, DSSH_EVENT_SIGNAL, false));
	bool valid = dssh_test_wait_bool(&capture.entered, true);
	struct close_channel_ctx close = {.ch = fixture.open.server_ch};
	atomic_init(&close.started, false);
	atomic_init(&close.done, false);
	thrd_t closer;
	bool started = valid && thrd_create(&closer, close_channel_thread, &close) == thrd_success;
	valid = valid && started;
	if (started) {
		valid = dssh_test_wait_bool(&close.ch->closing, true) && !atomic_load(&close.done);
	}
	atomic_store(&capture.release, true);
	if (started) {
		if (thrd_join(closer, NULL) != thrd_success)
			abort();
		valid = valid && atomic_load(&close.done) && close.result == 0;
	}
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	ASSERT_EQ(atomic_load(&capture.count), 1);
	ASSERT_FALSE(atomic_load(&capture.bad));
	ASSERT_TRUE(dssh_test_bytes_equal(capture.events[0].signal.name, "TERM", 4));
	return TEST_PASS;
}

struct event_client_open {
	dssh_session sess;
	dssh_channel channel;
	bool zc;
};

static int
event_client_opener(void *opaque)
{
	struct event_client_open *state = opaque;
	struct dssh_chan_params params;
	int ret = dssh_chan_params_init(&params, DSSH_CHAN_EXEC);
	if (ret != 0)
		return ret;
	ret = dssh_chan_params_set_command(&params, "event-client");
	if (ret == 0) {
		if (state->zc)
			state->channel = dssh_chan_zc_open(state->sess, &params, event_zc_data, NULL);
		else
			state->channel = dssh_chan_open(state->sess, &params);
	}
	dssh_chan_params_free(&params);
	return ret == 0 && state->channel != NULL ? 0 : DSSH_ERROR_INIT;
}

static int
test_event_client_defaults(void)
{
	for (unsigned mode = 0; mode < 2; mode++) {
		struct event_capture capture = {0};
		event_capture_init(&capture, true);
		struct conn_ctx ctx;
		ASSERT_OK(conn_setup_no_start(&ctx));
		ASSERT_OK(dssh_session_set_event_cb(ctx.client, capture_event, &capture));
		ASSERT_OK(dssh_session_start(ctx.client));
		ASSERT_OK(dssh_session_start(ctx.server));
		struct event_client_open opener = {.sess = ctx.client, .zc = mode != 0};
		struct open_exec_ctx acceptor = {
			.server = ctx.server, .cbs = &accept_cbs_all, .accept_timeout = 30000,
		};
		thrd_t client;
		thrd_t server;
		if (thrd_create(&server, server_accept_exec_thread, &acceptor) != thrd_success) {
			conn_cleanup(&ctx);
			return TEST_FAIL;
		}
		bool started = thrd_create(&client, event_client_opener, &opener) == thrd_success;
		if (!started) {
			dssh_session_terminate(ctx.server);
			mock_io_close_c2s(&ctx.io);
			mock_io_close_s2c(&ctx.io);
		}
		int client_ret = DSSH_ERROR_INIT;
		int server_ret = DSSH_ERROR_INIT;
		if (started && thrd_join(client, &client_ret) != thrd_success)
			abort();
		if (thrd_join(server, &server_ret) != thrd_success)
			abort();
		bool valid = started && client_ret == 0 && server_ret == 0;
		if (valid) {
			uint8_t packet[128];
			size_t len = 0;
			valid = event_packet(opener.channel, DSSH_EVENT_SIGNAL, packet, sizeof(packet), &len) == 0
			    && send_packet(ctx.server, packet, len, NULL) == 0
			    && dssh_test_wait_int(&capture.count, 1);
		}
		conn_cleanup(&ctx);
		ASSERT_TRUE(valid);
		ASSERT_FALSE(atomic_load(&capture.bad));
		ASSERT_TRUE(dssh_test_bytes_equal(capture.events[0].signal.name, "TERM", 4));
	}
	return TEST_PASS;
}

static int
test_event_lengths(void)
{
	struct event_capture capture = {0};
	event_capture_init(&capture, false);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &capture, false));
	uint8_t packet[640];
	size_t pos = 0;
	ASSERT_OK(event_packet(fixture.open.server_ch, DSSH_EVENT_EXIT_SIGNAL,
	    packet, sizeof(packet), &pos));
	/* Unknown requests do not invent events. */
	memcpy(packet + 9, "not-a-thing", 11);
	ASSERT_OK(dssh_test_demux_dispatch(fixture.ctx.server, packet[0], packet, pos));
	ASSERT_EQ(atomic_load(&capture.count), 0);
	ASSERT_OK(event_packet(fixture.open.server_ch, DSSH_EVENT_EXIT_SIGNAL,
	    packet, sizeof(packet), &pos));
	pos = 10 + DSSH_STRLEN("exit-signal");
	ASSERT_OK(dssh_serialize_uint32(100, packet, sizeof(packet), &pos));
	memset(packet + pos, 'N', 100);
	pos += 100;
	packet[pos++] = 1;
	ASSERT_OK(dssh_serialize_uint32(300, packet, sizeof(packet), &pos));
	memset(packet + pos, 'E', 300);
	pos += 300;
	ASSERT_OK(dssh_serialize_uint32(0, packet, sizeof(packet), &pos));
	ASSERT_OK(dssh_test_demux_dispatch(fixture.ctx.server, packet[0], packet, pos));
	bool valid = atomic_load(&capture.count) == 1 && !atomic_load(&capture.bad);
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	ASSERT_EQ_U(capture.events[0].exit_signal.signal_name.len, 100);
	ASSERT_EQ_U(capture.events[0].exit_signal.error_message.len, 300);
	for (size_t i = 0; i < 100; i++)
		ASSERT_EQ(capture.events[0].exit_signal.signal_name.data[i], 'N');
	for (size_t i = 0; i < 300; i++)
		ASSERT_EQ(capture.events[0].exit_signal.error_message.data[i], 'E');
	return TEST_PASS;
}

static int
test_event_positions(void)
{
	struct event_capture capture = {0};
	event_capture_init(&capture, false);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &capture, true));
	struct dssh_channel_s *ch = fixture.open.server_ch;
	ASSERT_EQ(mtx_lock(&ch->buf_mtx), thrd_success);
	ch->buf.stdout_buf.total = SIZE_MAX - 1;
	ch->buf.stderr_buf.total = SIZE_MAX - 1;
	ASSERT_EQ(mtx_unlock(&ch->buf_mtx), thrd_success);
	for (unsigned stream = 0; stream < 2; stream++) {
		uint8_t packet[32] = {0};
		size_t pos = 1;
		packet[0] = stream == 0 ? SSH_MSG_CHANNEL_DATA : SSH_MSG_CHANNEL_EXTENDED_DATA;
		ASSERT_OK(dssh_serialize_uint32(ch->local_id, packet, sizeof(packet), &pos));
		if (stream != 0)
			ASSERT_OK(dssh_serialize_uint32(1, packet, sizeof(packet), &pos));
		ASSERT_OK(dssh_serialize_uint32(3, packet, sizeof(packet), &pos));
		memcpy(packet + pos, "abc", 3);
		pos += 3;
		ASSERT_OK(dssh_test_demux_dispatch(fixture.ctx.server, packet[0], packet, pos));
	}
	ASSERT_OK(event_send(&fixture, DSSH_EVENT_SIGNAL, true));
	bool valid = atomic_load(&capture.count) == 1 && !atomic_load(&capture.bad);
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	ASSERT_EQ_U(capture.events[0].stdout_pos, SIZE_MAX);
	ASSERT_EQ_U(capture.events[0].stderr_pos, SIZE_MAX);
	return TEST_PASS;
}

static int
test_event_reacquire(void)
{
	struct event_capture capture = {.fail_reacquire = true};
	event_capture_init(&capture, false);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &capture, false));
	int ret = event_send(&fixture, DSSH_EVENT_SIGNAL, true);
	bool valid = ret == DSSH_ERROR_TERMINATED && fixture.ctx.server->terminate
	    && atomic_load(&capture.count) == 1 && !atomic_load(&capture.bad)
	    && dssh_test_mtx_rejected_unlocks() == 0
	    && atomic_load(&fixture.open.server_ch->dispatch_state) == DSSH_CHANNEL_DISPATCH_IDLE;
	dssh_test_ossl_reset();
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_event_self_disable(void)
{
	struct event_capture capture = {.self_disable = true};
	event_capture_init(&capture, true);
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, &capture, false));
	ASSERT_OK(event_send(&fixture, DSSH_EVENT_SIGNAL, false));
	bool valid = dssh_test_wait_int(&capture.count, 1) && !atomic_load(&capture.bad);
	if (valid) {
		valid = event_send(&fixture, DSSH_EVENT_BREAK, false) == 0
		    && dssh_chan_poll(fixture.open.server_ch, DSSH_POLL_EVENT, 5000) == DSSH_POLL_EVENT;
		struct dssh_chan_event event;
		valid = valid && dssh_chan_read_event(fixture.open.server_ch, &event) == 0
		    && event.type == DSSH_EVENT_BREAK && atomic_load(&capture.count) == 1;
	}
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

struct event_dispatch_job {
	struct event_fixture *fixture;
	int type;
	int result;
};

static int
event_dispatch_worker(void *opaque)
{
	struct event_dispatch_job *job = opaque;
	job->result = event_send(job->fixture, job->type, true);
	return 0;
}

static int
test_event_atomic_state(void)
{
	const int types[] = {DSSH_EVENT_EOF, DSSH_EVENT_CLOSE, DSSH_EVENT_EXIT_STATUS};
	for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		struct event_fixture fixture = {0};
		ASSERT_TRUE(event_setup(&fixture, NULL, false));
		struct event_dispatch_job job = {.fixture = &fixture, .type = types[i]};
		atomic_bool *entered = dssh_test_thrd_pause_mutex(&fixture.open.server_ch->cb_mtx);
		thrd_t worker;
		bool started = thrd_create(&worker, event_dispatch_worker, &job) == thrd_success;
		bool reached = started && dssh_test_wait_bool(entered, true);
		bool valid = reached;
		if (reached) {
			/* The dispatch has dropped buf_mtx but has not acquired its
			 * callback snapshot. No event state may be visible yet. */
			int ready = dssh_chan_poll(fixture.open.server_ch,
			    DSSH_POLL_READ | DSSH_POLL_EVENT, 0);
			if (mtx_lock(&fixture.open.server_ch->buf_mtx) != thrd_success)
				abort();
			valid = ready == 0 && !fixture.open.server_ch->eof_received
			    && !fixture.open.server_ch->close_received
			    && !fixture.open.server_ch->exit_code_received;
			if (mtx_unlock(&fixture.open.server_ch->buf_mtx) != thrd_success)
				abort();
		}
		dssh_test_thrd_resume_mutex();
		if (started && thrd_join(worker, NULL) != thrd_success)
			abort();
		dssh_test_thrd_pause_mutex(NULL);
		if (started && job.result == 0) {
			int ready = dssh_chan_poll(fixture.open.server_ch,
			    DSSH_POLL_READ | DSSH_POLL_EVENT, 0);
			struct dssh_chan_event event;
			valid = valid && (ready & DSSH_POLL_EVENT) != 0
			    && dssh_chan_read_event(fixture.open.server_ch, &event) == 0
			    && event.type == types[i];
		}
		else
			valid = false;
		conn_cleanup(&fixture.ctx);
		ASSERT_TRUE(valid);
	}
	return TEST_PASS;
}
