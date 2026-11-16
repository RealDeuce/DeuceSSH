#ifndef DSSH_TEST_TRANSPORT_STATE_CASES_H
#define DSSH_TEST_TRANSPORT_STATE_CASES_H

#include <limits.h>

static atomic_bool state_io_called;

static int
state_io(uint8_t *buf, size_t length, dssh_session sess, void *data)
{
	(void)buf;
	(void)length;
	(void)sess;
	(void)data;
	atomic_store(&state_io_called, true);
	return DSSH_ERROR_INIT;
}

static int
state_other_io(uint8_t *buf, size_t length, dssh_session sess, void *data)
{
	(void)buf;
	(void)length;
	(void)sess;
	(void)data;
	atomic_store(&state_io_called, true);
	return DSSH_ERROR_INVALID;
}

static int
state_line(uint8_t *buf, size_t length, size_t *received, dssh_session sess, void *data)
{
	(void)buf;
	(void)length;
	(void)sess;
	(void)data;
	atomic_store(&state_io_called, true);
	if (received != NULL)
		*received = 0;
	return DSSH_ERROR_INIT;
}

static int
state_gather(const struct dssh_tx_iov *iov, size_t count, dssh_session sess, void *data)
{
	(void)iov;
	(void)count;
	(void)sess;
	(void)data;
	atomic_store(&state_io_called, true);
	return DSSH_ERROR_INIT;
}

static int
state_prepare(struct test_session_pair *pair, bool ciphers)
{
	test_pair_begin(pair);
	atomic_init(&state_io_called, false);
	dssh_test_alloc_reset();
	dssh_test_ossl_reset();
	dssh_test_reset_global_config();
	int ret = dssh_register_none_comp();
	if (ret == 0 && ciphers)
		ret = dssh_register_aes256_ctr();
	if (ret == 0 && ciphers)
		ret = dssh_register_aes128_cbc();
	if (ret == 0)
		ret = dssh_transport_set_callbacks(state_io, state_io, state_line, NULL);
	return ret;
}

static void
state_finish(struct test_session_pair *pair)
{
	dssh_test_alloc_reset();
	dssh_test_ossl_reset();
	transport_pair_finish(pair);
}

static bool
state_retired(struct test_session_pair *pair)
{
	return transport_pair_retired(pair) && !atomic_load(&state_io_called);
}

static int
state_prepare_algorithms(struct test_session_pair *pair)
{
	test_pair_begin(pair);
	atomic_init(&state_io_called, false);
	dssh_test_alloc_reset();
	dssh_test_ossl_reset();
	dssh_test_reset_global_config();
	int ret = register_all_algorithms();
	if (ret == 0)
		ret = dssh_transport_set_callbacks(state_io, state_io, state_line, NULL);
	return ret;
}

static int
state_sessions(struct test_session_pair *pair, bool both)
{
	pair->client = dssh_session_init(true, 0);
	if (pair->client == NULL)
		return DSSH_ERROR_ALLOC;
	if (both) {
		pair->server = dssh_session_init(false, 0);
		if (pair->server == NULL)
			return DSSH_ERROR_ALLOC;
	}
	return 0;
}

static int
state_cipher_contexts(dssh_session sess, dssh_enc first, dssh_enc second)
{
	if (sess == NULL || first == NULL || second == NULL || first->init == NULL || second->init == NULL
	    || sess->trans.enc_c2s_ctx != NULL || sess->trans.enc_s2c_ctx != NULL)
		return DSSH_ERROR_INVALID;
	static const uint8_t key[32] = {0x42};
	static const uint8_t iv[16] = {0};
	sess->trans.enc_c2s_selected = first;
	sess->trans.enc_s2c_selected = second;
	int ret = first->init(key, iv, sess->trans.client, &sess->trans.enc_c2s_ctx);
	if (ret == 0 && sess->trans.enc_c2s_ctx == NULL)
		ret = DSSH_ERROR_INIT;
	if (ret == 0) {
		sess->trans.enc_c2s_active = first;
		ret = second->init(key, iv, !sess->trans.client, &sess->trans.enc_s2c_ctx);
	}
	if (ret == 0 && sess->trans.enc_s2c_ctx == NULL)
		ret = DSSH_ERROR_INIT;
	if (ret == 0)
		sess->trans.enc_s2c_active = second;
	return ret;
}

struct transport_state_result {
	int ret;
	int allocations;
	bool valid;
	bool retired;
};

static struct transport_state_result
state_block_case(int allocation_failure)
{
	struct transport_state_result result = {.ret = DSSH_ERROR_INIT};
	struct test_session_pair pair;
	result.ret = state_prepare(&pair, true);
	if (result.ret != 0)
		goto done;
	dssh_enc first = gconf.enc_head;
	if (first == NULL) {
		result.ret = DSSH_ERROR_INIT;
		goto done;
	}
	dssh_enc second = first->next;
	if (second == NULL || first->init == NULL || second->init == NULL
	    || strcmp(first->name, "aes256-ctr") != 0 || strcmp(second->name, "aes128-cbc") != 0) {
		result.ret = DSSH_ERROR_INIT;
		goto done;
	}
	dssh_test_alloc_fail_after(allocation_failure);
	result.ret = state_sessions(&pair, true);
	if (result.ret == 0 && (tx_block_size(pair.client) != 8 || rx_block_size(pair.client) != 8
	    || tx_block_size(pair.server) != 8 || rx_block_size(pair.server) != 8))
		result.ret = DSSH_ERROR_INVALID;
	if (result.ret == 0)
		result.ret = state_cipher_contexts(pair.client, first, second);
	if (result.ret == 0)
		result.ret = state_cipher_contexts(pair.server, first, second);
	result.allocations = dssh_test_alloc_count();
	dssh_test_alloc_reset();
	if (result.ret != 0)
		goto done;
	uint16_t saved_first = first->blocksize;
	uint16_t saved_second = second->blocksize;
	static const struct {
		uint16_t first;
		uint16_t second;
		size_t first_expected;
		size_t second_expected;
	} cases[] = {{0, 32, 8, 32}, {1, 16, 8, 16}, {4, 8, 8, 8}, {7, 1, 8, 8},
	    {8, 4, 8, 8}, {16, 7, 16, 8}, {32, 0, 32, 8}, {UINT16_MAX, 16, UINT16_MAX, 16}};
	result.valid = true;
	dssh_session sessions[] = {pair.client, pair.server};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		first->blocksize = cases[i].first;
		second->blocksize = cases[i].second;
		for (unsigned active = 0; active < 2; active++) {
			for (size_t role = 0; role < sizeof(sessions) / sizeof(sessions[0]); role++) {
				dssh_session sess = sessions[role];
				/* Real contexts remain with their producers. An active module
				 * takes precedence over the next selected candidate, as at rekey. */
				sess->trans.enc_c2s_active = active ? first : NULL;
				sess->trans.enc_s2c_active = active ? second : NULL;
				sess->trans.enc_c2s_selected = active ? second : first;
				sess->trans.enc_s2c_selected = active ? first : second;
				size_t tx = sess->trans.client ? cases[i].first_expected : cases[i].second_expected;
				size_t rx = sess->trans.client ? cases[i].second_expected : cases[i].first_expected;
				result.valid = tx_block_size(sess) == tx && rx_block_size(sess) == rx && result.valid;
			}
		}
	}
	first->blocksize = saved_first;
	second->blocksize = saved_second;
	for (size_t role = 0; role < sizeof(sessions) / sizeof(sessions[0]); role++) {
		sessions[role]->trans.enc_c2s_active = first;
		sessions[role]->trans.enc_s2c_active = second;
		sessions[role]->trans.enc_c2s_selected = first;
		sessions[role]->trans.enc_s2c_selected = second;
	}
done:
	state_finish(&pair);
	result.retired = state_retired(&pair);
	result.valid = result.valid && result.retired;
	return result;
}

static int
test_blocksize_clamp_direct(void)
{
	struct transport_state_result result = state_block_case(-1);
	int printed = printf("typed_blocks roles=2 paths=2 pairs=8 queries=64 baseline=4 retired=%d valid=%d\n",
	    result.retired, result.valid);
	ASSERT_TRUE(result.ret == 0 && result.valid && printed > 0);
	return TEST_PASS;
}

static int
test_state_context_refusals(void)
{
	struct transport_state_result baseline = state_block_case(INT_MAX);
	bool valid = baseline.ret == 0 && baseline.valid && baseline.allocations > 0 && baseline.allocations < INT_MAX;
	int refused = 0;
	int tolerated = 0;
	for (int i = 0; valid && i < baseline.allocations; i++) {
		struct transport_state_result result = state_block_case(i);
		valid = result.retired && result.allocations >= i + 1;
		if (result.ret < 0 && valid)
			refused++;
		else if (result.ret == 0 && result.valid && valid)
			tolerated++;
		else
			valid = false;
	}
	struct transport_state_result final = state_block_case(baseline.allocations);
	valid = valid && final.ret == 0 && final.valid && final.allocations == baseline.allocations;
	int printed = printf("typed_contexts allocations=%d refused=%d tolerated=%d final=%d valid=%d\n",
	    baseline.allocations, refused, tolerated, final.allocations, valid);
	ASSERT_TRUE(valid && printed > 0);
	return TEST_PASS;
}

static bool
state_late_case(bool gather)
{
	bool valid = true;
	for (unsigned refused = 0; refused < 2; refused++) {
		struct test_session_pair pair;
		int ret = state_prepare(&pair, false);
		if (ret == 0)
			ret = dssh_transport_set_tx_gather(state_gather);
		if (ret == 0) {
			if (refused != 0)
				dssh_test_alloc_fail_after(0);
			pair.client = dssh_session_init(true, 0);
			int allocations = dssh_test_alloc_count();
			dssh_test_alloc_reset();
			valid = valid && (refused ? pair.client == NULL && allocations == 1 : pair.client != NULL)
			    && atomic_load(&gconf.used);
			for (unsigned disposed = 0; disposed < 2; disposed++) {
				if (disposed) {
					dssh_session sess = pair.client;
					pair.client = NULL;
					dssh_session_cleanup(sess);
				}
				ret = gather ? dssh_transport_set_tx_gather(NULL)
				    : dssh_transport_set_callbacks(state_other_io, state_other_io, NULL, NULL);
				valid = valid && ret == DSSH_ERROR_TOOLATE && gconf.tx_gather == state_gather
				    && gconf.tx == state_io && gconf.rx == state_io && gconf.rx_line == state_line;
			}
		}
		else
			valid = false;
		state_finish(&pair);
		valid = state_retired(&pair) && valid;
	}
	return valid;
}

static int
test_set_callbacks_after_session(void)
{
	ASSERT_TRUE(state_late_case(false));
	return TEST_PASS;
}

static int
test_tx_gather_toolate(void)
{
	ASSERT_TRUE(state_late_case(true));
	return TEST_PASS;
}

static int
test_tx_gather_set(void)
{
	struct test_session_pair pair;
	int ret = state_prepare(&pair, false);
	bool valid = ret == 0;
	if (valid) {
		ret = dssh_transport_set_tx_gather(NULL);
		valid = ret == 0 && gconf.tx_gather == NULL;
		ret = dssh_transport_set_tx_gather(state_gather);
		valid = ret == 0 && gconf.tx_gather == state_gather && valid;
		ret = dssh_transport_set_tx_gather(NULL);
		valid = ret == 0 && gconf.tx_gather == NULL && valid;
	}
	state_finish(&pair);
	valid = state_retired(&pair) && valid;
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

struct state_global_probe {
	unsigned calls;
	bool valid;
};

static int
state_global_request(const uint8_t *name, size_t name_length, bool reply,
    const uint8_t *data, size_t length, void *opaque)
{
	struct state_global_probe *probe = opaque;
	if (probe == NULL)
		return DSSH_ERROR_INVALID;
	probe->valid = probe->calls == 0 && name != NULL && name_length == 5 && reply
	    && memcmp(name, "probe", 5) == 0 && data != NULL && length == 1 && data[0] == 7;
	probe->calls = 1;
	return 17;
}

static int
test_set_global_request_cb(void)
{
	struct test_session_pair pair;
	int ret = state_prepare(&pair, false);
	if (ret == 0)
		ret = state_sessions(&pair, false);
	struct state_global_probe probe = {0};
	bool valid = ret == 0;
	if (valid) {
		ret = dssh_session_set_global_request_cb(pair.client, state_global_request, &probe);
		valid = ret == 0 && pair.client->global_request_cb == state_global_request
		    && pair.client->global_request_cbdata == &probe;
		if (valid) {
			static const uint8_t name[] = "probe";
			static const uint8_t data[] = {7};
			ret = pair.client->global_request_cb(name, 5, true, data, sizeof(data), pair.client->global_request_cbdata);
			valid = ret == 17 && probe.valid && probe.calls == 1;
		}
		ret = dssh_session_set_global_request_cb(pair.client, NULL, NULL);
		valid = ret == 0 && pair.client->global_request_cb == NULL && pair.client->global_request_cbdata == NULL && valid;
		ret = dssh_session_set_global_request_cb(NULL, state_global_request, &probe);
		valid = ret == DSSH_ERROR_INVALID && valid;
		/* Leave live caller-owned data installed through session disposal. */
		ret = dssh_session_set_global_request_cb(pair.client, state_global_request, &probe);
		valid = ret == 0 && valid;
	}
	state_finish(&pair);
	valid = state_retired(&pair) && probe.calls == 1 && probe.valid && valid;
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_get_names_before_handshake(void)
{
	struct test_session_pair pair;
	int ret = state_prepare_algorithms(&pair);
	if (ret == 0)
		ret = state_sessions(&pair, true);
	bool valid = ret == 0 && gconf.kex_head != NULL && gconf.key_algo_head != NULL
	    && gconf.enc_head != NULL && gconf.mac_head != NULL && gconf.comp_head != NULL;
	dssh_session sessions[] = {pair.client, pair.server};
	enum dssh_direction directions[] = {DSSH_CLIENT_TO_SERVER, DSSH_SERVER_TO_CLIENT};
	for (size_t role = 0; valid && role < sizeof(sessions) / sizeof(sessions[0]); role++) {
		valid = dssh_transport_get_kex_name(sessions[role]) == NULL
		    && dssh_transport_get_hostkey_name(sessions[role]) == NULL;
		for (size_t i = 0; i < sizeof(directions) / sizeof(directions[0]); i++) {
			valid = dssh_transport_get_enc_name(sessions[role], directions[i]) == NULL
			    && dssh_transport_get_mac_name(sessions[role], directions[i]) == NULL
			    && dssh_transport_get_comp_name(sessions[role], directions[i]) == NULL && valid;
		}
	}
	state_finish(&pair);
	valid = state_retired(&pair) && valid;
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_aes256_ctr_null_ctx(void)
{
	struct test_session_pair pair;
	int ret = state_prepare(&pair, true);
	uint8_t data[16], original[16];
	memset(data, 0x5a, sizeof(data));
	memcpy(original, data, sizeof(original));
	bool valid = ret == 0 && gconf.enc_head != NULL && gconf.enc_head->encrypt != NULL
	    && gconf.enc_head->decrypt != NULL && strcmp(gconf.enc_head->name, "aes256-ctr") == 0;
	if (valid) {
		dssh_enc enc = gconf.enc_head;
		int encrypt = enc->encrypt(data, sizeof(data), NULL);
		int decrypt = enc->decrypt(data, sizeof(data), NULL);
		valid = encrypt == DSSH_ERROR_INIT && decrypt == DSSH_ERROR_INIT
		    && memcmp(data, original, sizeof(data)) == 0;
	}
	state_finish(&pair);
	valid = state_retired(&pair) && valid;
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

#ifdef DSSH_CRYPTO_OPENSSL
static int
test_aes256_ctr_encrypt_update_failure(void)
{
	struct test_session_pair pair;
	int ret = state_prepare(&pair, true);
	if (ret == 0)
		ret = state_sessions(&pair, false);
	if (ret == 0)
		ret = state_cipher_contexts(pair.client, gconf.enc_head, gconf.enc_head->next);
	bool valid = ret == 0;
	if (valid) {
		uint8_t data[16] = {0};
		dssh_test_ossl_fail_after(0);
		ret = gconf.enc_head->encrypt(data, sizeof(data), pair.client->trans.enc_c2s_ctx);
		int calls = dssh_test_ossl_count();
		dssh_test_ossl_reset();
		valid = ret == DSSH_ERROR_INIT && calls == 1;
	}
	state_finish(&pair);
	valid = state_retired(&pair) && valid;
	ASSERT_TRUE(valid);
	return TEST_PASS;
}
#endif

#endif
