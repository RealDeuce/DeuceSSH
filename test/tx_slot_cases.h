#ifndef DSSH_TEST_TX_SLOT_CASES_H
#define DSSH_TEST_TX_SLOT_CASES_H

static bool
tx_slot_receive_reply(dssh_session peer, uint8_t expected)
{
	uint8_t type;
	uint8_t *payload;
	size_t length;
	return recv_packet(peer, &type, &payload, &length) == 0
	    && type == expected && length == 1 && payload[0] == expected;
}

static bool
tx_slot_ordinary_reply(dssh_session sender, dssh_session peer)
{
	uint8_t reply = SSH_MSG_REQUEST_FAILURE;
	return send_to_slot(sender, &sender->trans.global_reply_slot, &reply, 1) == 0
	    && tx_slot_receive_reply(peer, reply);
}

static bool
tx_slot_foreign_owner(struct conn_ctx *ctx, bool credit)
{
	if (tx_acquire(ctx->client, SSH_MSG_IGNORE) != 0)
		return false;
	uint8_t reply = SSH_MSG_REQUEST_FAILURE;
	int ret = credit ? schedule_wa_slot(ctx->server)
	    : send_to_slot(ctx->server, &ctx->server->trans.global_reply_slot, &reply, 1);
	bool owned = tx_owner_is_current(ctx->client) && atomic_load(&ctx->client->trans.tx_owner_active);
	if (tx_owner_is_current(ctx->client))
		tx_unlock_with_slots(ctx->client);
	bool valid = ret == DSSH_ERROR_INVALID && owned
	    && !atomic_load(&ctx->client->trans.tx_owner_active)
	    && !dssh_session_is_terminated(ctx->server);
	printf("tx_slot_foreign credit=%d result=%d owner_retained=%d\n", credit, ret, owned);
	return valid && tx_slot_ordinary_reply(ctx->client, ctx->server)
	    && tx_slot_ordinary_reply(ctx->server, ctx->client);
}

static bool
tx_slot_owned_wait(struct conn_ctx *ctx)
{
	dssh_session sess = ctx->client;
	struct dssh_tx_slot *slot = &sess->trans.global_reply_slot;
	if (tx_acquire(sess, SSH_MSG_IGNORE) != 0)
		return false;
	uint8_t first = SSH_MSG_REQUEST_FAILURE;
	int queued = send_to_slot(sess, slot, &first, 1);
	/* If the old path attempts to wait, model a native refusal and let it
	 * unwind without waiting for work only this caller can drain. */
	struct dssh_test_wait_probe probe = {.condition = &sess->trans.tx_slot_cnd,
	    .mutex = &sess->trans.tx_queue_mtx, .result = thrd_error};
	atomic_init(&probe.calls, 0);
	atomic_init(&probe.native_calls, 0);
	atomic_init(&probe.native_result, thrd_busy);
	atomic_init(&probe.returning, false);
	atomic_init(&probe.release, true);
	dssh_test_wait_probe(&probe);
	uint8_t second = SSH_MSG_REQUEST_SUCCESS;
	int ret = queued == 0 ? send_to_slot(sess, slot, &second, 1) : queued;
	dssh_test_wait_probe(NULL);
	unsigned waits = atomic_load(&probe.calls);
	bool valid = queued == 0 && ret == DSSH_ERROR_INVALID && waits == 0
	    && atomic_load(&slot->ready) && tx_owner_is_current(sess)
	    && !dssh_session_is_terminated(sess);
	tx_unlock_with_slots(sess);
	printf("tx_slot_owner_wait queued=%d result=%d waits=%u\n", queued, ret, waits);
	return valid && !atomic_load(&slot->ready) && tx_slot_receive_reply(ctx->server, first);
}

static bool
tx_slot_capacity(struct conn_ctx *ctx)
{
	dssh_session sess = ctx->client;
	struct dssh_tx_slot *slot = &sess->trans.global_reply_slot;
	if (tx_acquire(sess, SSH_MSG_IGNORE) != 0)
		return false;
	/* Two bytes fit in the old allocation's padding area. The fixture
	 * checks admission and drops any unexpectedly accepted test packet. */
	uint8_t oversized[] = {SSH_MSG_REQUEST_FAILURE, 0};
	int ret = send_to_slot(sess, slot, oversized, sizeof(oversized));
	bool ready = atomic_load(&slot->ready);
	if (ready)
		atomic_store(&slot->ready, false);
	bool valid = ret == DSSH_ERROR_TOOLONG && !ready && !dssh_session_is_terminated(sess);
	uint8_t reply = SSH_MSG_REQUEST_FAILURE;
	if (valid)
		valid = send_to_slot(sess, slot, &reply, 1) == 0 && atomic_load(&slot->ready);
	tx_unlock_with_slots(sess);
	printf("tx_slot_capacity result=%d published=%d\n", ret, ready);
	return valid && !atomic_load(&slot->ready) && tx_slot_receive_reply(ctx->server, reply);
}

static int
test_tx_slot_admission(void)
{
	bool passed = true;
	for (unsigned mode = 0; mode < 4; mode++) {
		struct conn_ctx ctx;
		if (conn_setup_mode(&ctx, false) != 0)
			return TEST_FAIL;
		bool valid = mode < 2 ? tx_slot_foreign_owner(&ctx, mode == 1)
		    : mode == 2 ? tx_slot_owned_wait(&ctx) : tx_slot_capacity(&ctx);
		conn_cleanup(&ctx);
		passed = valid && passed;
	}
	ASSERT_TRUE(passed);
	return TEST_PASS;
}


struct tx_slot_sender {
	dssh_session sess;
	uint8_t reply;
};

static int
tx_slot_send_worker(void *opaque)
{
	struct tx_slot_sender *sender = opaque;
	return send_to_slot(sender->sess, &sender->sess->trans.global_reply_slot, &sender->reply, 1);
}

static bool
tx_slot_resize_while_waiting(struct conn_ctx *ctx)
{
	dssh_session sess = ctx->client;
	struct dssh_tx_slot *slot = &sess->trans.global_reply_slot;
	uint8_t first = SSH_MSG_REQUEST_FAILURE;
	/* An empty slot still supports a direct send with no queue storage. */
	struct dssh_tx_slot unallocated = {0};
	if (send_to_slot(sess, &unallocated, &first, 1) != 0
	    || !tx_slot_receive_reply(ctx->server, first)
	    || tx_acquire(sess, SSH_MSG_IGNORE) != 0)
		return false;
	bool valid = send_to_slot(sess, slot, &first, 1) == 0 && atomic_load(&slot->ready);
	struct tx_slot_sender sender = {.sess = sess, .reply = SSH_MSG_REQUEST_SUCCESS};
	atomic_bool *waited = dssh_test_thrd_watch_condition(&sess->trans.tx_slot_cnd);
	thrd_t worker;
	bool started = valid && thrd_create(&worker, tx_slot_send_worker, &sender) == thrd_success;
	valid = started && dssh_test_wait_bool(waited, true);
	if (valid) {
		/* The owner replaces storage while a real producer waits on the
		 * occupied slot. The new allocation also fits the active epoch. */
		size_t old_size = slot->buf_sz;
		valid = resize_tx_slot_live(sess, slot, 1, 128, 64) == 0
		    && slot->buf_sz > old_size && slot->payload_capacity == 1
		    && atomic_load(&slot->ready) && slot->payload_len == 1 && slot->buf[9] == first;
	}
	if (valid) {
		dssh_test_alloc_fail_after(0);
		int ret = resize_tx_slot_live(sess, slot, 1, 128, 64);
		int allocations = dssh_test_alloc_count();
		dssh_test_alloc_reset();
		valid = ret == 0 && allocations == 0;
	}
	if (!valid)
		session_set_terminate(sess);
	tx_unlock_with_slots(sess);
	int result = DSSH_ERROR_INIT;
	if (started && thrd_join(worker, &result) != thrd_success)
		abort();
	dssh_test_thrd_watch_condition(NULL);
	return valid && result == 0 && !atomic_load(&slot->ready)
	    && tx_slot_receive_reply(ctx->server, first)
	    && tx_slot_receive_reply(ctx->server, sender.reply);
}

static int
test_tx_slot_resize(void)
{
	struct conn_ctx ctx;
	if (conn_setup_mode(&ctx, false) != 0)
		return TEST_FAIL;
	bool valid = tx_slot_resize_while_waiting(&ctx);
	conn_cleanup(&ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

#endif
