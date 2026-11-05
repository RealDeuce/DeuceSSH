#ifndef DSSH_PACKET_BOUNDS_CASES_H
#define DSSH_PACKET_BOUNDS_CASES_H

static bool
packet_metadata_case(bool client, uint16_t block, size_t length)
{
	dssh_test_reset_global_config();
	struct module_fixture fixture = {0};
	active = &fixture;
	bool valid = dssh_transport_set_callbacks(memory_tx, memory_rx, memory_line, NULL) == 0;
	dssh_enc enc = calloc(1, sizeof(*enc) + sizeof("bounds"));
	size_t packet_size = UINT16_MAX;
	if (packet_size <= SIZE_MAX / 2)
		packet_size *= 2;
	else
		packet_size -= 4;
	dssh_session sender = dssh_session_init(client, packet_size);
	dssh_session receiver = dssh_session_init(!client, packet_size);
	valid = valid && enc != NULL && sender != NULL && receiver != NULL;
	int ret = DSSH_ERROR_INIT;
	int expected = DSSH_ERROR_INIT;
	if (valid) {
		memcpy(enc->name, "bounds", sizeof("bounds"));
		enc->blocksize = block;
		enc->bytes_per_key = UINT64_MAX;
		enc->encrypt = stateless_encrypt;
		enc->decrypt = stateless_decrypt;
		sender->trans.enc_c2s_active = enc;
		sender->trans.enc_s2c_active = enc;
		receiver->trans.enc_c2s_active = enc;
		receiver->trans.enc_s2c_active = enc;
		uint8_t payload[256];
		memset(payload, 0x33, length);
		payload[0] = SSH_MSG_CHANNEL_DATA;
		size_t alignment = block < 8 ? 8 : block;
		/* Test arithmetic uses uint64_t independently of the packet engine. */
		uint64_t overhead_payload = 5 + length;
		uint64_t pad = alignment - overhead_payload % alignment;
		if (pad < 4)
			pad += alignment;
		uint64_t total = overhead_payload + pad;
		if (length > tx_payload_capacity(sender))
			expected = DSSH_ERROR_TOOLONG;
		else
			expected = pad > UINT8_MAX ? DSSH_ERROR_INVALID : 0;
		ret = send_packet(sender, payload, length, NULL);
		valid = ret == expected;
		if (expected != 0)
			valid = valid && fixture.encrypts == 0 && fixture.writes == 0 && sender->trans.tx_seq == 0;
		else {
			valid = valid && fixture.encrypts == 1 && fixture.writes == 1 && fixture.used == total;
			if (valid) {
				uint8_t type;
				uint8_t *received = NULL;
				size_t received_length = 0;
				ret = recv_packet(receiver, &type, &received, &received_length);
				valid = ret == 0 && type == payload[0] && received_length == length
				    && memcmp(received, payload, length) == 0;
			}
		}
	}
	dssh_session_cleanup(receiver);
	dssh_session_cleanup(sender);
	free(enc);
	active = NULL;
	dssh_test_reset_global_config();
	if (!valid)
		fprintf(stderr, "packet bounds: client=%d block=%u length=%zu result=%d expected=%d encrypts=%u writes=%u\n",
		    client, block, length, ret, expected, fixture.encrypts, fixture.writes);
	return valid;
}

static int
test_packet_metadata_bounds(void)
{
	const uint16_t blocks[] = { 1, 8, 16, 252, 253, 254, 255, 256, 257, 512, UINT16_MAX };
	const size_t lengths[] = { 1, 31, 245, 246, 247, 248, 256 };
	bool valid = true;
	for (unsigned role = 0; role < 2; role++) {
		for (size_t b = 0; b < sizeof(blocks) / sizeof(blocks[0]); b++) {
			for (size_t n = 0; n < sizeof(lengths) / sizeof(lengths[0]); n++) {
				bool matched = packet_metadata_case(role != 0, blocks[b], lengths[n]);
				valid = valid && matched;
			}
		}
	}
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_receive_block_bounds(void)
{
	const uint16_t blocks[] = { 16, 33280, 33281, UINT16_MAX };
	for (unsigned role = 0; role < 2; role++) {
		for (size_t i = 0; i < sizeof(blocks) / sizeof(blocks[0]); i++) {
			dssh_test_reset_global_config();
			struct module_fixture fixture = {0};
			active = &fixture;
			ASSERT_OK(dssh_transport_set_callbacks(memory_tx, memory_rx, memory_line, NULL));
			dssh_session sess = dssh_session_init(role != 0, 0);
			ASSERT_NOT_NULL(sess);
			struct dssh_enc_s enc = { .blocksize = blocks[i], .decrypt = stateless_decrypt };
			sess->trans.enc_c2s_active = &enc;
			sess->trans.enc_s2c_active = &enc;
			bool fits = blocks[i] <= sess->trans.packet_buf_sz;
			uint8_t type;
			uint8_t *payload;
			size_t length;
			int ret = recv_packet(sess, &type, &payload, &length);
			bool valid = ret == (fits ? DSSH_ERROR_INIT : DSSH_ERROR_INVALID)
			    && fixture.rx_calls == (fits ? 1U : 0U) && fixture.decrypts == 0;
			dssh_session_cleanup(sess);
			active = NULL;
			dssh_test_reset_global_config();
			ASSERT_TRUE(valid);
		}
	}
	return TEST_PASS;
}

static int
test_slot_size_bounds(void)
{
	ASSERT_EQ_U(tx_slot_buf_size(1, 16, 16), 36);
	ASSERT_EQ_U(tx_slot_buf_size(9, 16, 64), 100);
	const struct {
		size_t payload;
		size_t block;
		uint16_t mac;
	} invalid[] = {
		{ SIZE_MAX, 16, 16 }, { SIZE_MAX - 4, 16, 0 },
		{ SIZE_MAX - 5, 16, 0 }, { 1, SIZE_MAX, 0 },
		{ SIZE_MAX - 8, SIZE_MAX, UINT16_MAX }, { 245, 253, 16 },
		{ 1, 512, 0 },
#if SIZE_MAX > UINT32_MAX
		{ UINT32_MAX, 16, 0 },
#endif
#if SIZE_MAX == UINT16_MAX
		{ 1, 16, UINT16_MAX },
#endif
	};
	for (unsigned reuse = 0; reuse < 2; reuse++) {
		for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
			struct dssh_tx_slot slot = {0};
			if (reuse != 0) {
				ASSERT_OK(alloc_tx_slot(&slot, 1, 16, 16));
				memset(slot.buf, 0xa5, slot.buf_sz);
				slot.payload_len = 1;
				atomic_store(&slot.ready, true);
			}
			uint8_t *old = slot.buf;
			size_t capacity = slot.buf_sz;
			dssh_test_alloc_watch_free(old, capacity);
			dssh_test_alloc_fail_after(0);
			size_t size = tx_slot_buf_size(invalid[i].payload, invalid[i].block, invalid[i].mac);
			int ret = alloc_tx_slot(&slot, invalid[i].payload, invalid[i].block, invalid[i].mac);
			int allocations = dssh_test_alloc_count();
			bool released = dssh_test_alloc_watched_free(NULL);
			dssh_test_alloc_reset();
			bool valid = !released && slot.buf_sz == capacity;
			if (valid)
				valid = slot.buf == old;
			if (reuse != 0)
				valid = valid && atomic_load(&slot.ready) && slot.payload_len == 1
				    && mac_bytes_equal(slot.buf, capacity, 0xa5);
			free_tx_slot(&slot);
			ASSERT_EQ_U(size, 0);
			ASSERT_EQ(ret, DSSH_ERROR_INVALID);
			ASSERT_EQ(allocations, 0);
			ASSERT_TRUE(valid);
		}
	}
	return TEST_PASS;
}

#endif
