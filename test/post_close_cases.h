/* Included after the native peer channel helpers. */

static dssh_channel
post_close_accept(struct conn_ctx *ctx, uint32_t remote)
{
	struct dssh_incoming_open incoming;
	if (peer_id_send_open(ctx->client, remote) != 0
	    || accept_incoming(ctx->server, &incoming, 3000) != 0
	    || incoming.peer_channel != remote)
		return NULL;
	dssh_channel ch = accept_channel_init(ctx->server, &incoming);
	if (ch == NULL || !peer_id_receive_control(ctx->client, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 17, remote))
		return NULL;
	return ch;
}

static int
post_close_receive_close(struct conn_ctx *ctx, dssh_channel ch)
{
	uint8_t close[5];
	size_t pos = 0;
	close[pos++] = SSH_MSG_CHANNEL_CLOSE;
	DSSH_PUT_U32(ch->local_id, close, &pos);
	ASSERT_OK(send_packet(ctx->client, close, pos, NULL));
	ASSERT_TRUE(channel_id_wire_barrier(ctx->client));
	ASSERT_OK(setup_release(ctx->server, ch));
	return TEST_PASS;
}

static int
post_close_direct_run(struct conn_ctx *ctx)
{
	const uint32_t remote = UINT32_MAX;
	ASSERT_OK(dssh_session_start(ctx->server));
	dssh_channel old = post_close_accept(ctx, remote);
	ASSERT_NOT_NULL(old);
	ASSERT_OK(post_close_receive_close(ctx, old));
	ASSERT_OK(conn_close(ctx->server, old));
	ASSERT_TRUE(peer_id_receive_control(ctx->client, SSH_MSG_CHANNEL_CLOSE, 5, remote));
	dssh_channel replacement = post_close_accept(ctx, remote);
	ASSERT_NOT_NULL(replacement);

	int signal = dssh_chan_send_signal(old, "TERM");
	int resize = dssh_chan_send_window_change(old, 80, 24, 0, 0);
	int brk = dssh_chan_send_break(old, 100);
	int credit = send_window_adjust(ctx->server, old, 1);
	int eof = dssh_chan_shutwr(old);
	int close = dssh_chan_close(old, 42);
	bool ordered = channel_id_wire_barrier(ctx->client);
	printf("post_close_direct signal=%d resize=%d break=%d credit=%d eof=%d close=%d ordered=%d\n",
	    signal, resize, brk, credit, eof, close, ordered);
	ASSERT_TRUE(ordered);
	ASSERT_EQ(signal, DSSH_ERROR_TERMINATED);
	ASSERT_EQ(resize, DSSH_ERROR_TERMINATED);
	ASSERT_EQ(brk, DSSH_ERROR_TERMINATED);
	ASSERT_EQ(credit, DSSH_ERROR_TERMINATED);
	ASSERT_OK(eof);
	ASSERT_OK(close);
	ASSERT_FALSE(dssh_session_is_terminated(ctx->server));
	ASSERT_OK(dssh_chan_send_break(replacement, 100));
	ASSERT_TRUE(peer_id_receive_control(ctx->client, SSH_MSG_CHANNEL_REQUEST, 19, remote));
	return TEST_PASS;
}

static int
test_post_close_direct(void)
{
	for (unsigned gather = 0; gather < 2; gather++) {
		struct conn_ctx ctx;
		window_test_gather = gather != 0;
		int setup = conn_setup_mode(&ctx, false);
		window_test_gather = false;
		ASSERT_OK(setup);
		int ret = post_close_direct_run(&ctx);
		conn_cleanup(&ctx);
		if (ret != TEST_PASS)
			return ret;
	}
	return TEST_PASS;
}
