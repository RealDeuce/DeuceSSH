/* Included by test_conn.c after the channel wire fixture helpers. */

static int
peer_id_dispatch_open(dssh_session receiver, const char *type, uint32_t number)
{
	uint8_t message[32];
	size_t len = build_channel_open(message, sizeof(message), type, number, 123, 456);
	if (len == 0)
		return DSSH_ERROR_INIT;
	return dssh_test_demux_dispatch(receiver, SSH_MSG_CHANNEL_OPEN, message, len);
}

static bool
peer_id_receive_control(dssh_session peer, uint8_t expected, size_t length, uint32_t number)
{
	uint8_t type;
	uint8_t *payload;
	size_t len;
	return recv_packet(peer, &type, &payload, &len) == 0 && type == expected
	    && len == length && len >= 5 && DSSH_GET_U32(&payload[1]) == number;
}

enum peer_id_open_stage {
	PEER_ID_QUEUED,
	PEER_ID_POPPED,
	PEER_ID_CONFIRMED,
};

static int
peer_id_open_stage_run(struct conn_ctx *ctx, enum peer_id_open_stage stage)
{
	static const uint32_t numbers[] = {0, UINT32_MAX};
	ASSERT_OK(dssh_session_start(ctx->server));
	for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++)
		ASSERT_OK(peer_id_dispatch_open(ctx->server, "session", numbers[i]));

	if (stage != PEER_ID_QUEUED) {
		/* Keep both pops alive through the ownership check. Each represents
		 * a different acceptor after leaving the FIFO. */
		struct dssh_incoming_open incoming[2];
		for (size_t i = 0; i < sizeof(incoming) / sizeof(incoming[0]); i++) {
			ASSERT_OK(accept_incoming(ctx->server, &incoming[i], 0));
			ASSERT_EQ_U(incoming[i].peer_channel, numbers[i]);
		}
		if (stage == PEER_ID_CONFIRMED) {
			for (size_t i = 0; i < sizeof(incoming) / sizeof(incoming[0]); i++) {
				ASSERT_NOT_NULL(accept_channel_init(ctx->server, &incoming[i]));
				ASSERT_TRUE(peer_id_receive_control(ctx->client,
				    SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 17, numbers[i]));
			}
		}
	}

	int zero = peer_id_dispatch_open(ctx->server, "session", numbers[0]);
	int maximum = peer_id_dispatch_open(ctx->server, "session", numbers[1]);
	int unsupported = peer_id_dispatch_open(ctx->server, "unknown", numbers[1]);
	int distinct = peer_id_dispatch_open(ctx->server, "session", 1);
	printf("peer_id_open stage=%d zero=%d maximum=%d unsupported=%d distinct=%d\n",
	    stage, zero, maximum, unsupported, distinct);
	ASSERT_EQ(zero, DSSH_ERROR_PARSE);
	ASSERT_EQ(maximum, DSSH_ERROR_PARSE);
	ASSERT_EQ(unsupported, DSSH_ERROR_PARSE);
	ASSERT_OK(distinct);

	struct dssh_incoming_open next;
	if (stage == PEER_ID_QUEUED) {
		for (size_t i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++) {
			ASSERT_OK(accept_incoming(ctx->server, &next, 0));
			ASSERT_EQ_U(next.peer_channel, numbers[i]);
		}
	}
	ASSERT_OK(accept_incoming(ctx->server, &next, 0));
	ASSERT_EQ_U(next.peer_channel, 1);
	ASSERT_EQ(accept_incoming(ctx->server, &next, 0), DSSH_ERROR_NOMORE);
	return TEST_PASS;
}

static int
peer_id_open_stage_test(enum peer_id_open_stage stage)
{
	struct conn_ctx ctx;
	if (conn_setup_mode(&ctx, false) < 0)
		return TEST_FAIL;
	int ret = peer_id_open_stage_run(&ctx, stage);
	conn_cleanup(&ctx);
	return ret;
}

static int
test_peer_id_queued(void)
{
	return peer_id_open_stage_test(PEER_ID_QUEUED);
}

static int
test_peer_id_popped(void)
{
	return peer_id_open_stage_test(PEER_ID_POPPED);
}

static int
test_peer_id_confirmed(void)
{
	return peer_id_open_stage_test(PEER_ID_CONFIRMED);
}

static int
peer_id_dispatch_confirmation(dssh_session receiver, uint32_t local, uint32_t remote)
{
	uint8_t message[17];
	size_t len = channel_id_build_reply(message, local, true, remote);
	return dssh_test_demux_dispatch(receiver, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, message, len);
}

static int
peer_id_late_confirmation_run(struct conn_ctx *ctx)
{
	ASSERT_OK(dssh_session_set_timeout(ctx->client, 10));
	ASSERT_OK(dssh_session_start(ctx->client));
	uint32_t first;
	uint32_t second;
	ASSERT_OK(channel_id_open_without_reply(ctx));
	ASSERT_TRUE(channel_id_receive_open(ctx->server, &first));
	ASSERT_OK(channel_id_open_without_reply(ctx));
	ASSERT_TRUE(channel_id_receive_open(ctx->server, &second));
	ASSERT_EQ_U(channel_id_pending_count(ctx->client), 2);

	ASSERT_OK(peer_id_dispatch_confirmation(ctx->client, first, UINT32_MAX));
	ASSERT_TRUE(peer_id_receive_control(ctx->server, SSH_MSG_CHANNEL_CLOSE, 5, UINT32_MAX));
	int duplicate = peer_id_dispatch_confirmation(ctx->client, second, UINT32_MAX);
	int distinct = peer_id_dispatch_confirmation(ctx->client, second, 0);
	printf("peer_id_late_confirmation duplicate=%d distinct=%d\n", duplicate, distinct);
	ASSERT_EQ(duplicate, DSSH_ERROR_PARSE);
	ASSERT_OK(distinct);
	ASSERT_TRUE(peer_id_receive_control(ctx->server, SSH_MSG_CHANNEL_CLOSE, 5, 0));
	return TEST_PASS;
}

static int
test_peer_id_late_confirmation(void)
{
	struct conn_ctx ctx;
	if (conn_setup_mode(&ctx, false) < 0)
		return TEST_FAIL;
	int ret = peer_id_late_confirmation_run(&ctx);
	conn_cleanup(&ctx);
	return ret;
}
