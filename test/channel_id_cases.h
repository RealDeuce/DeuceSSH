#ifndef DSSH_TEST_CHANNEL_ID_CASES_H
#define DSSH_TEST_CHANNEL_ID_CASES_H

static int64_t
channel_id_candidate(dssh_session sess, uint32_t id)
{
	if (mtx_lock(&sess->channel_mtx) != thrd_success)
		abort();
	sess->next_channel_id = id;
	if (mtx_unlock(&sess->channel_mtx) != thrd_success)
		abort();
	return alloc_channel_id(sess);
}

static int
channel_id_lifetime_run(struct conn_ctx *ctx)
{
	struct open_exec_ctx first = {.client = ctx->client, .server = ctx->server,
	    .command = "first-id", .cbs = &accept_cbs_all, .accept_timeout = 30000};
	struct open_exec_ctx marker = {.client = ctx->client, .server = ctx->server,
	    .command = "marker-id", .cbs = &accept_cbs_all, .accept_timeout = 30000};
	ASSERT_OK(open_exec_channel(ctx, &first));
	ASSERT_OK(open_exec_channel(ctx, &marker));
	uint32_t id = first.client_ch->local_id;
	ASSERT_OK(dssh_chan_close(first.client_ch, -1));
	first.client_ch = NULL;
	bool observed_close = false;
	for (unsigned i = 0; i < 2; i++) {
		ASSERT_EQ(dssh_chan_poll(first.server_ch, DSSH_POLL_EVENT, 5000), DSSH_POLL_EVENT);
		struct dssh_chan_event event;
		ASSERT_OK(dssh_chan_read_event(first.server_ch, &event));
		observed_close = observed_close || event.type == DSSH_EVENT_CLOSE;
	}
	int64_t before_reply = channel_id_candidate(ctx->client, id);
	ASSERT_OK(dssh_chan_close(first.server_ch, -1));
	first.server_ch = NULL;
	/* This packet follows the reciprocal CLOSE on the same transport.
	 * Receiving it proves that the earlier CLOSE has been dispatched. */
	uint8_t expected = 47;
	uint8_t received = 0;
	ASSERT_EQ(dssh_chan_write(marker.server_ch, 0, &expected, 1), 1);
	ASSERT_TRUE(dssh_chan_poll(marker.client_ch, DSSH_POLL_READ, 5000) & DSSH_POLL_READ);
	ASSERT_EQ(dssh_chan_read(marker.client_ch, 0, &received, 1), 1);
	int64_t after_reply = channel_id_candidate(ctx->client, id);
	ASSERT_EQ(mtx_lock(&ctx->client->channel_mtx), thrd_success);
	ctx->client->next_channel_id = id;
	ASSERT_EQ(mtx_unlock(&ctx->client->channel_mtx), thrd_success);
	struct open_exec_ctx reused = {.client = ctx->client, .server = ctx->server,
	    .command = "reused-id", .cbs = &accept_cbs_all, .accept_timeout = 30000};
	int ret = open_exec_channel(ctx, &reused);
	bool valid = observed_close && before_reply >= 0 && before_reply != id
	    && after_reply == id && received == expected && ret == 0;
	if (ret == 0)
		valid = valid && reused.client_ch->local_id == id
		    && dssh_chan_write(reused.client_ch, 0, &expected, 1) == 1
		    && (dssh_chan_poll(reused.server_ch, DSSH_POLL_READ, 5000) & DSSH_POLL_READ) != 0
		    && dssh_chan_read(reused.server_ch, 0, &received, 1) == 1 && received == expected;
	printf("channel_id_lifetime before=%" PRId64 " after=%" PRId64
	    " original=%" PRIu32 " peer_close=%d reused=%d data=%d\n",
	    before_reply, after_reply, id, observed_close, ret == 0, received == expected);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_channel_id_lifetime(void)
{
	struct conn_ctx ctx;
	if (conn_setup(&ctx) != 0)
		return TEST_FAIL;
	int ret = channel_id_lifetime_run(&ctx);
	conn_cleanup(&ctx);
	return ret;
}

#endif
