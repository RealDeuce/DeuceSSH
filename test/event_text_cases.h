struct event_text_capture {
	struct dssh_bytes name;
	struct dssh_bytes error;
	struct dssh_bytes language;
	atomic_int count;
	atomic_bool bad;
	bool identity;
};

static void
event_text_capture(dssh_channel ch, const struct dssh_chan_event *event, void *data)
{
	(void)ch;
	struct event_text_capture *capture = data;
	struct dssh_bytes name = event->type == DSSH_EVENT_SIGNAL
	    ? event->signal.name : event->exit_signal.signal_name;
	bool valid = dssh_test_bytes_equal(name, capture->name.data, capture->name.len);
	if (capture->identity)
		valid = valid && name.data == capture->name.data;
	if (event->type == DSSH_EVENT_EXIT_SIGNAL) {
		valid = valid && dssh_test_bytes_equal(event->exit_signal.error_message,
		    capture->error.data, capture->error.len)
		    && dssh_test_bytes_equal(event->exit_signal.language,
		        capture->language.data, capture->language.len);
		if (capture->identity)
			valid = valid && event->exit_signal.error_message.data == capture->error.data
			    && event->exit_signal.language.data == capture->language.data;
	}
	if (!valid)
		atomic_store(&capture->bad, true);
	atomic_fetch_add(&capture->count, 1);
}

/* Test packets deliberately contain embedded zero, multibyte UTF-8 and fields
 * larger than the former internal arrays. Expected views point into the packet. */
static int
event_text_packet(struct dssh_channel_s *ch, int type, uint8_t *packet,
    size_t capacity, size_t *length, struct event_text_capture *capture, bool empty)
{
	int ret = event_packet(ch, type, packet, capacity, length);
	if (ret != 0)
		return ret;
	size_t pos = type == DSSH_EVENT_SIGNAL ? 16 : 21;
	size_t lengths[] = {empty ? 0 : 100, empty ? 0 : 300, empty ? 0 : 12};
	struct dssh_bytes *views[] = {&capture->name, &capture->error, &capture->language};
	size_t fields = type == DSSH_EVENT_SIGNAL ? 1 : 3;
	for (size_t field = 0; field < fields; field++) {
		size_t bytes = lengths[field];
		uint32_t wire = (uint32_t)bytes;
		ret = dssh_serialize_uint32(wire, packet, capacity, &pos);
		if (ret != 0 || !dssh_buffer_has(capacity, pos, bytes))
			return DSSH_ERROR_TOOLONG;
		for (size_t i = 0; i < bytes; i++) {
			uint8_t value = (uint8_t)((i + field) % 127);
			packet[pos + i] = value;
		}
		if (bytes > 3) {
			packet[pos] = 0;
			packet[pos + 1] = 0xc3;
			packet[pos + 2] = 0xa9;
		}
		*views[field] = (struct dssh_bytes){.data = bytes != 0 ? packet + pos : NULL, .len = bytes};
		pos += bytes;
		if (type == DSSH_EVENT_EXIT_SIGNAL && field == 0) {
			if (!dssh_buffer_has(capacity, pos, 1))
				return DSSH_ERROR_TOOLONG;
			packet[pos++] = 1;
		}
	}
	*length = pos;
	return 0;
}

static int
event_text_case(bool callback, bool empty)
{
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, NULL, false));
	struct event_text_capture capture = {.identity = callback};
	atomic_init(&capture.count, 0);
	atomic_init(&capture.bad, false);
	if (callback)
		ASSERT_OK(dssh_chan_set_event_cb(fixture.open.server_ch, event_text_capture, &capture));
	int types[] = {DSSH_EVENT_SIGNAL, DSSH_EVENT_EXIT_SIGNAL};
	for (size_t type = 0; type < sizeof(types) / sizeof(types[0]); type++) {
		uint8_t packet[1024];
		size_t length = 0;
		ASSERT_OK(event_text_packet(fixture.open.server_ch, types[type], packet,
		    sizeof(packet), &length, &capture, empty));
		if (callback)
			dssh_test_alloc_fail_after(0);
		int ret = dssh_test_demux_dispatch(fixture.ctx.server, packet[0], packet, length);
		int allocations = dssh_test_alloc_count();
		dssh_test_alloc_reset();
		ASSERT_OK(ret);
		if (callback)
			ASSERT_EQ(allocations, 0);
		else {
			ASSERT_EQ(dssh_chan_poll(fixture.open.server_ch, DSSH_POLL_EVENT, 0), DSSH_POLL_EVENT);
			struct dssh_chan_event event;
			ASSERT_OK(dssh_chan_read_event(fixture.open.server_ch, &event));
			event_text_capture(fixture.open.server_ch, &event, &capture);
			/* Packet storage can change immediately after dispatch in poll mode. */
			memset(packet, 0xee, sizeof(packet));
			struct dssh_bytes name = types[type] == DSSH_EVENT_SIGNAL
			    ? event.signal.name : event.exit_signal.signal_name;
			ASSERT_EQ_U(name.len, empty ? 0 : 100);
			if (!empty) {
				ASSERT_EQ(name.data[0], 0);
				ASSERT_EQ(name.data[1], 0xc3);
				ASSERT_EQ(name.data[99], 99);
				if (types[type] == DSSH_EVENT_EXIT_SIGNAL) {
					ASSERT_EQ_U(event.exit_signal.error_message.len, 300);
					ASSERT_EQ(event.exit_signal.error_message.data[299], 46);
					ASSERT_EQ_U(event.exit_signal.language.len, 12);
					ASSERT_EQ(event.exit_signal.language.data[11], 13);
				}
			}
			else {
				ASSERT_NULL(name.data);
				if (types[type] == DSSH_EVENT_EXIT_SIGNAL) {
					ASSERT_NULL(event.exit_signal.error_message.data);
					ASSERT_NULL(event.exit_signal.language.data);
				}
			}
		}
	}
	bool valid = atomic_load(&capture.count) == 2 && !atomic_load(&capture.bad);
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_event_text_binary_callback(void)
{
	return event_text_case(true, false);
}
static int
test_event_text_binary_poll(void)
{
	return event_text_case(false, false);
}
static int
test_event_text_empty_callback(void)
{
	return event_text_case(true, true);
}
static int
test_event_text_empty_poll(void)
{
	return event_text_case(false, true);
}

static int
test_event_text_packet_boundary(void)
{
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, NULL, false));
	size_t capacity = tx_payload_capacity(fixture.ctx.client);
	ASSERT_TRUE(capacity > 20 && capacity <= UINT32_MAX);
	uint8_t *packet = malloc(capacity);
	ASSERT_NOT_NULL(packet);
	size_t length = 0;
	ASSERT_OK(event_packet(fixture.open.server_ch, DSSH_EVENT_SIGNAL, packet, capacity, &length));
	size_t pos = 16;
	size_t bytes = capacity - pos - 4;
	uint32_t wire = (uint32_t)bytes;
	ASSERT_OK(dssh_serialize_uint32(wire, packet, capacity, &pos));
	memset(packet + pos, 0xb5, bytes);
	packet[pos] = 0;
	ASSERT_OK(send_packet(fixture.ctx.client, packet, capacity, NULL));
	ASSERT_TRUE(dssh_chan_poll(fixture.open.server_ch, DSSH_POLL_EVENT, 30000) & DSSH_POLL_EVENT);
	struct dssh_chan_event event;
	ASSERT_OK(dssh_chan_read_event(fixture.open.server_ch, &event));
	bool valid = dssh_test_bytes_equal(event.signal.name, packet + pos, bytes);
	free(packet);
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

struct event_text_free_check {
	dssh_channel ch;
	const void *metadata;
	bool seen;
	bool unlocked;
};

static void
event_text_free_check(const void *ptr, void *opaque)
{
	struct event_text_free_check *check = opaque;
	if (ptr != check->metadata)
		return;
	check->seen = true;
	int ret = mtx_trylock(&check->ch->buf_mtx);
	check->unlocked = ret == thrd_success;
	if (ret == thrd_success && mtx_unlock(&check->ch->buf_mtx) != thrd_success)
		abort();
}

static int
test_event_text_free_observer(void)
{
	struct dssh_channel_s ch = {0};
	if (mtx_init(&ch.buf_mtx, mtx_plain) != thrd_success)
		return TEST_FAIL;
	unsigned char metadata = 0;
	struct event_text_free_check check = {.ch = &ch, .metadata = &metadata};
	event_text_free_check(NULL, &check);
	bool valid = !check.seen;
	event_text_free_check(&metadata, &check);
	valid = valid && check.metadata == NULL && check.seen && check.unlocked;
	check.seen = false;
	check.unlocked = false;
	event_text_free_check(NULL, &check);
	valid = valid && !check.seen && !check.unlocked;
	mtx_destroy(&ch.buf_mtx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_event_text_growth_unlocked(void)
{
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, NULL, false));
	for (int i = 0; i < 8; i++)
		ASSERT_OK(event_send(&fixture, DSSH_EVENT_SIGNAL, true));
	ASSERT_EQ(mtx_lock(&fixture.open.server_ch->buf_mtx), thrd_success);
	struct event_text_free_check check = {.ch = fixture.open.server_ch,
	    .metadata = fixture.open.server_ch->events.entries};
	ASSERT_EQ(mtx_unlock(&fixture.open.server_ch->buf_mtx), thrd_success);
	dssh_test_alloc_observe_frees(event_text_free_check, &check);
	int ret = event_send(&fixture, DSSH_EVENT_SIGNAL, true);
	dssh_test_alloc_observe_frees(NULL, NULL);
	bool valid = ret == 0 && check.seen && check.unlocked;
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

struct event_text_poll_job {
	struct event_fixture *fixture;
	atomic_bool done;
	int result;
};

static int
event_text_poll_writer(void *opaque)
{
	struct event_text_poll_job *job = opaque;
	uint8_t packet[256];
	size_t length = 0;
	job->result = event_packet(job->fixture->open.server_ch, DSSH_EVENT_SIGNAL,
	    packet, sizeof(packet), &length);
	for (size_t i = 0; i < 512 && job->result == 0; i++) {
		size_t pos = 16;
		job->result = dssh_serialize_uint32(100, packet, sizeof(packet), &pos);
		if (job->result != 0)
			break;
		uint8_t byte = (uint8_t)(i % 251);
		memset(packet + pos, byte, 100);
		job->result = dssh_test_demux_dispatch(job->fixture->ctx.server,
		    packet[0], packet, pos + 100);
	}
	atomic_store(&job->done, true);
	return 0;
}

static int
test_event_text_poll_race(void)
{
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, NULL, false));
	ASSERT_OK(dssh_chan_set_max_events(fixture.open.server_ch, 0));
	struct event_text_poll_job job = {.fixture = &fixture};
	atomic_init(&job.done, false);
	thrd_t writer;
	ASSERT_EQ(thrd_create(&writer, event_text_poll_writer, &job), thrd_success);
	bool valid = true;
	size_t count = 0;
	struct timespec start;
	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		abort();
	while (valid && count < 512) {
		int ready = dssh_chan_poll(fixture.open.server_ch, DSSH_POLL_EVENT, 0);
		if (ready == 0) {
			if (atomic_load(&job.done) && job.result != 0)
				break;
			if (!dssh_test_wait_tick(&start)) {
				valid = false;
				break;
			}
			continue;
		}
		struct dssh_chan_event event;
		valid = ready == DSSH_POLL_EVENT
		    && dssh_chan_read_event(fixture.open.server_ch, &event) == 0;
		if (valid) {
			uint8_t expected[100];
			uint8_t byte = (uint8_t)(count % 251);
			memset(expected, byte, sizeof(expected));
			valid = event.type == DSSH_EVENT_SIGNAL
			    && dssh_test_bytes_equal(event.signal.name, expected, sizeof(expected));
			/* Writer can grow/wrap the ring while this borrowed view is live. */
			thrd_yield();
			valid = valid && dssh_test_bytes_equal(event.signal.name, expected, sizeof(expected));
			count++;
		}
	}
	if (thrd_join(writer, NULL) != thrd_success)
		abort();
	valid = valid && job.result == 0 && count == 512;
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_event_text_poll_reuse(void)
{
	struct event_fixture fixture = {0};
	ASSERT_TRUE(event_setup(&fixture, NULL, false));
	ASSERT_OK(dssh_chan_set_max_events(fixture.open.server_ch, 1));
	uint8_t packet[1024];
	size_t length = 0;
	struct event_text_capture capture = {0};
	atomic_init(&capture.count, 0);
	atomic_init(&capture.bad, false);
	ASSERT_OK(event_text_packet(fixture.open.server_ch, DSSH_EVENT_EXIT_SIGNAL,
	    packet, sizeof(packet), &length, &capture, false));
	int ret = 0;
	bool valid = true;
	for (int i = 0; i < 160 && ret == 0 && valid; i++) {
		if (i == 16)
			dssh_test_alloc_fail_after(0);
		ret = dssh_test_demux_dispatch(fixture.ctx.server, packet[0], packet, length);
		struct dssh_chan_event event;
		valid = ret == 0
		    && dssh_chan_poll(fixture.open.server_ch, DSSH_POLL_EVENT, 0) == DSSH_POLL_EVENT
		    && dssh_chan_read_event(fixture.open.server_ch, &event) == 0;
		if (valid)
			event_text_capture(fixture.open.server_ch, &event, &capture);
	}
	int allocations = dssh_test_alloc_count();
	dssh_test_alloc_reset();
	valid = valid && ret == 0 && atomic_load(&capture.count) == 160
	    && !atomic_load(&capture.bad) && allocations == 0;
	conn_cleanup(&fixture.ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}
