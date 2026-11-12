/* Real public ZC handles. The fill/close/send-or-cancel worker always finishes
 * before the owning frame cleans up either session or its callback storage. */
struct close_reservation_open {
	struct open_exec_ctx channels;
	struct dssh_chan_accept_cbs callbacks;
	bool client_zc;
};

static int
close_reservation_client(void *opaque)
{
	struct close_reservation_open *job = opaque;
	struct dssh_chan_params params;
	int ret = dssh_chan_params_init(&params, DSSH_CHAN_EXEC);
	if (ret != 0)
		return ret;
	ret = dssh_chan_params_set_command(&params, job->channels.command);
	if (ret == 0)
		ret = dssh_chan_params_set_pty(&params, false);
	if (ret == 0) {
		if (job->client_zc)
			job->channels.client_ch = dssh_chan_zc_open(job->channels.client, &params, event_zc_data, NULL);
		else
			job->channels.client_ch = dssh_chan_open(job->channels.client, &params);
		if (job->channels.client_ch == NULL)
			ret = DSSH_ERROR_INIT;
	}
	dssh_chan_params_free(&params);
	return ret == 0 ? wait_stream_writable(job->channels.client_ch) : ret;
}

static bool
close_reservation_pair(struct conn_ctx *ctx, struct close_reservation_open *job, unsigned role)
{
	job->callbacks = accept_cbs_all;
	job->client_zc = role == 0;
	if (role != 0)
		job->callbacks.exec = event_accept_zc;
	job->channels = (struct open_exec_ctx){.client = ctx->client, .server = ctx->server,
	    .command = "close-reservation", .cbs = &job->callbacks, .accept_timeout = 30000};
	struct channel_workers workers;
	channel_workers_init(&workers, ctx);
	if (channel_worker_start(&workers, 0, close_reservation_client, job) != 0
	    || channel_worker_start(&workers, 1, server_accept_exec_thread, &job->channels) != 0) {
		channel_workers_finish(&workers);
		return false;
	}
	channel_worker_join(&workers, 0);
	if (workers.results[0] != 0 || job->channels.client_ch == NULL)
		channel_workers_cancel(&workers);
	channel_workers_finish(&workers);
	return workers.results[0] == 0 && workers.results[1] == 0
	    && job->channels.client_ch != NULL && job->channels.server_ch != NULL;
}

static bool
close_reservation_credit(dssh_channel channel)
{
	struct timespec start;
	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return false;
	while (atomic_load(&channel->remote_window) == 0) {
		if (dssh_session_is_terminated(channel->sess) || !dssh_test_wait_tick(&start))
			return false;
	}
	return true;
}

static const uint8_t close_reservation_bytes[] = {0, 13, 255, 1, 2, 3, 4};
struct close_reservation_job {
	dssh_channel owner, target;
	bool same, send, valid;
	int rejected, released, closed;
	unsigned frees;
};

static int
close_reservation_worker(void *opaque)
{
	struct close_reservation_job *job = opaque;
	dssh_session session = job->owner->sess;
	uint8_t *buffer = NULL;
	size_t capacity = 0;
	if (dssh_chan_zc_getbuf(job->owner, 0, &buffer, &capacity) != 0)
		return TEST_FAIL;
	if (capacity < sizeof(close_reservation_bytes)) {
		if (dssh_chan_zc_cancel(job->owner) != 0)
			return TEST_FAIL;
		return TEST_FAIL;
	}
	memcpy(buffer, close_reservation_bytes, sizeof(close_reservation_bytes));
	uint_least32_t window = atomic_load(&job->owner->remote_window);
	struct close_outcome_lifetime watch = {.handle = job->target};
	dssh_test_alloc_observe_frees(close_outcome_observe_free, &watch);
	job->rejected = dssh_chan_close(job->target, INT64_MAX);
	bool valid = job->rejected == DSSH_ERROR_INVALID && watch.frees == 0
	    && tx_owner_is_current(session) && !dssh_session_is_terminated(session);
	if (!valid) {
		/* Do not reuse any possibly consumed channel. Unwind only this
		 * thread's session engine, then exit before owner cleanup. */
		dssh_test_alloc_observe_frees(NULL, NULL);
		if (tx_owner_is_current(session))
			tx_unlock_with_slots(session);
		return TEST_FAIL;
	}
	valid = memcmp(buffer, close_reservation_bytes, sizeof(close_reservation_bytes)) == 0
	    && atomic_load(&job->owner->remote_window) == window
	    && dssh_chan_get_command(job->target) != NULL;
	job->released = job->send ? dssh_chan_zc_send(job->owner, sizeof(close_reservation_bytes))
	    : dssh_chan_zc_cancel(job->owner);
	if (job->released != 0 || tx_owner_is_current(session)) {
		dssh_test_alloc_observe_frees(NULL, NULL);
		if (tx_owner_is_current(session))
			tx_unlock_with_slots(session);
		return TEST_FAIL;
	}
	/* The same out-of-range argument must now dispose normally; it never
	 * becomes an exit-status validation error. No consumed handle is retried. */
	job->closed = dssh_chan_close(job->target, INT64_MAX);
	job->frees = watch.frees;
	valid = valid && job->closed == 0 && watch.frees == 1 && watch.handle == NULL;
	dssh_test_alloc_observe_frees(NULL, NULL);
	if (!job->same) {
		int result = dssh_chan_close(job->owner, -1);
		valid = valid && result == 0;
	}
	job->valid = valid && !dssh_session_is_terminated(session);
	return job->valid ? TEST_PASS : TEST_FAIL;
}

static int
test_close_reservation(void)
{
	unsigned cases = 0, failed = 0;
	for (unsigned role = 0; role < 2; role++) {
		for (unsigned gather = 0; gather < 2; gather++) {
			for (unsigned same = 0; same < 2; same++) {
				for (unsigned send = 0; send < 2; send++) {
					struct conn_ctx ctx;
					window_test_gather = gather != 0;
					int setup = conn_setup(&ctx);
					window_test_gather = false;
					ASSERT_OK(setup);
					ASSERT_TRUE(half_close_algorithms(&ctx));
					struct close_reservation_open owner = {0};
					ASSERT_TRUE(close_reservation_pair(&ctx, &owner, role));
					struct open_exec_ctx other = {.client = ctx.client, .server = ctx.server,
					    .command = "close-other", .cbs = &accept_cbs_all, .accept_timeout = 30000};
					ASSERT_OK(open_exec_channel(&ctx, &other));
					dssh_channel owner_channel = role == 0 ? owner.channels.client_ch : owner.channels.server_ch;
					dssh_channel peer = role == 0 ? owner.channels.server_ch : owner.channels.client_ch;
					dssh_channel target = same != 0 ? owner_channel : role == 0 ? other.client_ch : other.server_ch;
					ASSERT_TRUE(close_reservation_credit(owner_channel));
					struct close_reservation_job job = {.owner = owner_channel, .target = target,
					    .same = same != 0, .send = send != 0};
					thrd_t worker;
					int created = thrd_create(&worker, close_reservation_worker, &job);
					int result = TEST_FAIL;
					if (created == thrd_success && thrd_join(worker, &result) != thrd_success)
						abort();
					bool valid = created == thrd_success && result == TEST_PASS && job.valid;
					if (valid && send != 0) {
						uint8_t received[sizeof(close_reservation_bytes)];
						valid = (dssh_chan_poll(peer, DSSH_POLL_READ, 5000) & DSSH_POLL_READ) != 0
						    && dssh_chan_read(peer, 0, received, sizeof(received)) == sizeof(received)
						    && memcmp(received, close_reservation_bytes, sizeof(received)) == 0;
					}
					/* All application workers have ended before session retirement. */
					conn_cleanup(&ctx);
					cases++;
					if (!valid)
						failed++;
					printf("close_reservation role=%u gather=%u same=%u send=%u rejected=%d released=%d closed=%d frees=%u valid=%u\n",
					    role, gather, same, send, job.rejected, job.released, job.closed,
					    job.frees, valid ? 1U : 0U);
				}
			}
		}
	}
	printf("close_reservation cases=%u failures=%u\n", cases, failed);
	ASSERT_EQ_U(cases, 16);
	ASSERT_EQ_U(failed, 0);
	return TEST_PASS;
}
