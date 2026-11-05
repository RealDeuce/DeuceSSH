/* Shared-handler framing tests. Deterministic crypto/host-key adapters isolate
 * parsing and cleanup; production crypto/peer tests remain separate evidence. */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dssh_test.h"
#include "dssh_test_alloc.h"
#include "kex/workspace.h"
#include "deucessh-crypto.h"
#include "deucessh-kex.h"
#include "kex/curve25519-sha256-ops.h"
#include "kex/hybrid-pq-kex-ops.h"

struct framing_fixture {
	uint8_t signature_storage;
	uint8_t message[1300];
	size_t length;
	const struct hybrid_pq_params *params;
	unsigned live;
	unsigned agreements;
	unsigned kems;
	unsigned signatures;
	unsigned verifications;
	unsigned sends;
	unsigned host_fault;
	unsigned backend_mode;
	unsigned backend_inits;
	unsigned backend_cleanups;
	uint8_t *raw_key;
	size_t raw_key_capacity;
	unsigned raw_key_releases;
	int host_result;
	bool client;
};

#include "auth_result_fixture.h"

static struct framing_fixture *active;

static int
new_private(void **out)
{
	*out = malloc(1);
	if (*out == NULL)
		return DSSH_ERROR_ALLOC;
	active->live++;
	return 0;
}

static void
free_private(void *priv)
{
	if (priv != NULL) {
		active->live--;
		free(priv);
	}
}

static int
x_keygen(uint8_t pub[32], void **priv)
{
	memset(pub, 0x11, 32);
	return new_private(priv);
}

static int
curve_backend_init(void **backend)
{
	*backend = NULL;
	active->backend_inits++;
	if (active->backend_mode == 1 || active->backend_mode == 3 || active->backend_mode == 4) {
		int ret = new_private(backend);
		if (ret < 0)
			return ret;
	}
	if (active->backend_mode == 2 || active->backend_mode == 3)
		return DSSH_ERROR_INIT;
	if (active->backend_mode == 4)
		return 1;
	return 0;
}

static void
curve_backend_cleanup(void *backend)
{
	active->backend_cleanups++;
	free_private(backend);
}

static int
curve_keygen(void *backend, uint8_t pub[32], void **priv)
{
	(void)backend;
	return x_keygen(pub, priv);
}

static int
curve_derive(void *priv, const uint8_t *peer, size_t len, uint8_t out[32])
{
	(void)peer;
	if (priv == NULL || len != 32)
		return DSSH_ERROR_INVALID;
	memset(out, 0x42, 32);
	active->agreements++;
	return 0;
}

static int
pq_keygen(uint8_t *pub, uint8_t *storage, size_t capacity, void **priv)
{
	memset(pub, 0x11, active->params->pq_pk_len);
	if (storage != NULL) {
		memset(storage, 0x71, capacity);
		active->raw_key = storage;
		active->raw_key_capacity = capacity;
		*priv = storage;
		return 0;
	}
	return new_private(priv);
}

static void
pq_free_key(void *priv)
{
	if (priv != NULL && priv == active->raw_key)
		active->raw_key_releases++;
	else
		free_private(priv);
}

static int
pq_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pub, size_t len)
{
	(void)pub;
	if (len != active->params->pq_pk_len)
		return DSSH_ERROR_INVALID;
	memset(ct, 0x11, active->params->pq_ct_len);
	memset(ss, 0x22, active->params->pq_ss_len);
	active->kems++;
	return 0;
}

static int
pq_decaps(uint8_t *ss, const uint8_t *ct, size_t len, void *priv)
{
	(void)ct;
	if (priv == NULL || len != active->params->pq_ct_len)
		return DSSH_ERROR_INVALID;
	memset(ss, 0x22, active->params->pq_ss_len);
	active->kems++;
	return 0;
}

static int
host_pubkey(const uint8_t **out, size_t *len, dssh_key_algo_ctx *ctx)
{
	(void)ctx;
	static const uint8_t key = 7;
	if (active->host_fault == 4)
		return 0;
	if (active->host_fault == 5) {
		*out = &key;
		return 0;
	}
	if (active->host_fault == 6) {
		*len = 1;
		return 0;
	}
	if (active->host_fault == 7) {
		*out = &key;
		*len = SIZE_MAX;
		return 0;
	}
	*out = &key;
	*len = 1;
	return active->host_fault == 1 ? active->host_result : 0;
}

static int
host_sign(struct dssh_bytes_result *output_result, const uint8_t *data, size_t data_len, dssh_key_algo_ctx *ctx)
{
	uint8_t *fixture_output = NULL;
	size_t fixture_length = 0;
	uint8_t **out = &fixture_output;
	size_t *len = &fixture_length;

	(void)ctx;
	(void)data;
	if (data_len != (active->params == NULL ? 32 : active->params->digest_len))
		return test_auth_output_finish(output_result, fixture_output, fixture_length, DSSH_ERROR_INVALID);
	if (active->host_fault == 12 || active->host_fault == 13) {
		active->signature_storage = 7;
		if (active->host_fault == 12) {
			fixture_output = &active->signature_storage;
			fixture_length = 1;
		}
		else
			output_result->lease.owner = active;
		return test_auth_output_finish(output_result, fixture_output, fixture_length, 0);
	}
	if (active->host_fault == 8)
		return test_auth_output_finish(output_result, fixture_output, fixture_length, 0);
	if (active->host_fault == 10) {
		*len = 1;
		return test_auth_output_finish(output_result, fixture_output, fixture_length, 0);
	}
	*out = test_auth_output_alloc(output_result, 1);
	if (*out == NULL)
		return test_auth_output_finish(output_result, fixture_output, fixture_length, DSSH_ERROR_ALLOC);
	(*out)[0] = 7;
	if (active->host_fault == 9)
		return test_auth_output_finish(output_result, fixture_output, fixture_length, 0);
	if (active->host_fault == 11) {
		*len = SIZE_MAX;
		return test_auth_output_finish(output_result, fixture_output, fixture_length, 0);
	}
	*len = 1;
	active->signatures++;
	return test_auth_output_finish(output_result, fixture_output, fixture_length, active->host_fault == 2 ? active->host_result : 0);
}

static int
host_verify(const uint8_t *key, size_t key_len, const uint8_t *sig, size_t sig_len,
    const uint8_t *data, size_t data_len)
{
	(void)data;
	if (key_len != 1 || key[0] != 7 || sig_len != 1 || sig[0] != 7
	    || data_len != (active->params == NULL ? 32 : active->params->digest_len))
		return DSSH_ERROR_INVALID;
	active->verifications++;
	return active->host_fault == 3 ? active->host_result : 0;
}

static int
fixture_send(const uint8_t *payload, size_t len, void *opaque)
{
	struct framing_fixture *fixture = opaque;
	if (len == 0 || payload[0] != (fixture->client ? SSH_MSG_KEX_ECDH_INIT : SSH_MSG_KEX_ECDH_REPLY))
		return DSSH_ERROR_INVALID;
	fixture->sends++;
	return 0;
}

static int
fixture_recv(uint8_t *type, uint8_t **payload, size_t *len, void *opaque)
{
	struct framing_fixture *fixture = opaque;
	*type = fixture->message[0];
	*payload = fixture->message;
	*len = fixture->length;
	return 0;
}

static const struct dssh_x25519_ops curve_ops = {
	.init = curve_backend_init, .cleanup = curve_backend_cleanup,
	.keygen = curve_keygen, .derive = curve_derive, .free_priv = free_private,
};

static const struct hybrid_pq_ops hybrid_ops = {
	.x25519 = &curve_ops,
	.pq_keygen = pq_keygen, .pq_encaps = pq_encaps,
	.pq_decaps = pq_decaps, .pq_free_sk = pq_free_key,
};

static const struct hybrid_pq_params params[] = {
	{ .hash_name = "SHA-512", .digest_len = 64, .pq_pk_len = 1158,
	    .pq_ct_len = 1039, .pq_ss_len = 32, .q_c_len = 1190, .q_s_len = 1071 },
	{ .hash_name = "SHA-256", .digest_len = 32, .pq_pk_len = 1184,
	    .pq_ct_len = 1088, .pq_ss_len = 32, .q_c_len = 1216, .q_s_len = 1120 },
};

static int
framing_case_options(const struct hybrid_pq_params *p, bool client, unsigned fault, int result)
{
	dssh_key_algo ka = calloc(1, sizeof(*ka) + sizeof("framing-key"));
	ASSERT_NOT_NULL(ka);
	memcpy(ka->name, "framing-key", sizeof("framing-key"));
	ka->pubkey = host_pubkey;
	ka->sign = host_sign;
	ka->verify = host_verify;
	bool valid = true;
	unsigned shapes = fault == 0 ? 3 : 1;
	for (unsigned shape = 0; shape < shapes; shape++) {
		struct framing_fixture fixture = {
			.params = p, .client = client, .host_fault = fault, .host_result = result,
		};
		active = &fixture;
		size_t pos = 0;
		int ret;
		fixture.message[pos++] = client ? SSH_MSG_KEX_ECDH_REPLY : SSH_MSG_KEX_ECDH_INIT;
		if (client) {
			ret = dssh_serialize_uint32(1, fixture.message, sizeof(fixture.message), &pos);
			valid = valid && ret == 0;
			fixture.message[pos++] = 7;
		}
		size_t pub_len = p == NULL ? 32 : (client ? p->q_s_len : p->q_c_len);
		if (pub_len > sizeof(fixture.message) - pos - 9) {
			valid = false;
			break;
		}
		/* These are the three fixed production method parameter sets. */
		uint32_t wire_pub_len = (uint32_t)pub_len;
		ret = dssh_serialize_uint32(wire_pub_len, fixture.message, sizeof(fixture.message), &pos);
		valid = valid && ret == 0;
		memset(&fixture.message[pos], 0x11, pub_len);
		pos += pub_len;
		if (client) {
			ret = dssh_serialize_uint32(1, fixture.message, sizeof(fixture.message), &pos);
			valid = valid && ret == 0;
			fixture.message[pos++] = 7;
		}
		fixture.length = pos;
		if (shape == 1)
			fixture.length--;
		else if (shape == 2)
			fixture.message[fixture.length++] = 0xff;
		void *state = NULL;
		ret = p == NULL ? curve25519_init_impl(client, NULL, &state, &curve_ops)
		                : hybrid_pq_init_impl(client, NULL, &state, p, &hybrid_ops);
		if (ret < 0) {
			valid = false;
			break;
		}
		struct dssh_kex_result output = {0};
		struct dssh_kex_context kctx = {
			.v_c = "client", .v_c_len = 6, .v_s = "server", .v_s_len = 6,
			.i_c = fixture.message, .i_c_len = 1, .i_s = fixture.message, .i_s_len = 1,
			.key_algo = ka, .state = state, .send = fixture_send, .recv = fixture_recv,
			.io_ctx = &fixture, .client = client,
		};
		ret = p == NULL ? curve25519_handler_impl(&kctx, &output, &curve_ops)
		                     : hybrid_pq_handler_impl(&kctx, &output, p, &hybrid_ops);
		bool matched = fixture.live == 0;
		if (p != NULL && client && p->pq_sk_len != 0) {
			matched = matched && fixture.raw_key != NULL && fixture.raw_key_capacity == p->pq_sk_len
			    && fixture.raw_key_releases == 1;
			if (fixture.raw_key != NULL) {
				for (size_t i = 0; i < fixture.raw_key_capacity; i++)
					matched = matched && fixture.raw_key[i] == 0;
			}
		}
		if (fault >= 12)
			matched = matched && fixture.signature_storage == 7;
		if (fault != 0) {
			int expected = fault >= 4 || result > 0 ? DSSH_ERROR_INVALID : result;
			matched = matched && ret == expected && output.shared_secret.data == NULL
			    && output.exchange_hash.data == NULL;
		}
		else if (shape == 0)
			matched = matched && ret == 0 && output.shared_secret.data != NULL && output.exchange_hash.data != NULL
			    && fixture.agreements == 1 && fixture.kems == (p == NULL ? 0U : 1U)
			    && fixture.signatures == (client ? 0U : 1U)
			    && fixture.verifications == (client ? 1U : 0U);
		else
			matched = matched && ret == DSSH_ERROR_PARSE
			    && output.shared_secret.data == NULL && output.exchange_hash.data == NULL
			    && fixture.agreements == 0 && fixture.kems == 0
			    && fixture.signatures == 0 && fixture.verifications == 0;
		if (!matched)
			fprintf(stderr, "client=%d hybrid=%d shape=%u ret=%d live=%u agree=%u kem=%u sign=%u verify=%u\n",
			    client, p != NULL, shape, ret, fixture.live, fixture.agreements,
			    fixture.kems, fixture.signatures, fixture.verifications);
		dssh_result_release(&output.lease);
		if (p == NULL)
			curve25519_cleanup(state);
		else
			hybrid_pq_cleanup(state);
		valid = valid && matched;
	}
	active = NULL;
	free(ka);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
framing_case(const struct hybrid_pq_params *p, bool client)
{
	return framing_case_options(p, client, 0, 0);
}

static int
host_callback_results(void)
{
	const struct hybrid_pq_params *methods[] = { NULL, &params[0], &params[1] };
	const int results[] = { DSSH_ERROR_INIT, 1 };
	for (size_t method = 0; method < sizeof(methods) / sizeof(methods[0]); method++) {
		for (unsigned fault = 1; fault <= 3; fault++) {
			for (size_t result = 0; result < sizeof(results) / sizeof(results[0]); result++) {
				ASSERT_EQ(framing_case_options(methods[method], fault == 3, fault, results[result]), TEST_PASS);
			}
		}
	}
	return TEST_PASS;
}

static int
host_callback_outputs(void)
{
	const struct hybrid_pq_params *methods[] = { NULL, &params[0], &params[1] };
	for (size_t method = 0; method < sizeof(methods) / sizeof(methods[0]); method++) {
		for (unsigned fault = 4; fault <= 13; fault++) {
#if SIZE_MAX <= UINT32_MAX
			/* A borrowed one-byte span cannot represent this oversized-prefix
			 * fixture on a host where every size_t already fits uint32. */
			if (fault == 7)
				continue;
#endif
			ASSERT_EQ(framing_case_options(methods[method], false, fault, 0), TEST_PASS);
		}
	}
	return TEST_PASS;
}

static int
curve_client(void)
{
	return framing_case(NULL, true);
}

static int
curve_server(void)
{
	return framing_case(NULL, false);
}

static int
sntrup_client(void)
{
	return framing_case(&params[0], true);
}

static int
sntrup_server(void)
{
	return framing_case(&params[0], false);
}

static int
mlkem_client(void)
{
	return framing_case(&params[1], true);
}

static int
mlkem_server(void)
{
	return framing_case(&params[1], false);
}

static int
test_backend_initialization(void)
{
	const struct hybrid_pq_params *methods[] = {NULL, &params[0], &params[1]};
	for (size_t method = 0; method < sizeof(methods) / sizeof(methods[0]); method++) {
		for (unsigned role = 0; role < 2; role++) {
			for (unsigned mode = 0; mode < 5; mode++) {
				struct framing_fixture fixture = {.backend_mode = mode};
				active = &fixture;
				void *state = NULL;
				int ret = methods[method] == NULL
				    ? curve25519_init_impl(role != 0, NULL, &state, &curve_ops)
				    : hybrid_pq_init_impl(role != 0, NULL, &state, methods[method], &hybrid_ops);
				int expected = mode >= 2 ? (mode == 4 ? DSSH_ERROR_INVALID : DSSH_ERROR_INIT) : 0;
				bool valid = ret == expected && fixture.backend_inits == 1;
				if (ret == 0) {
					void *original = state;
					dssh_test_alloc_fail_after(0);
					ret = methods[method] == NULL
					    ? curve25519_init_impl(role != 0, NULL, &state, &curve_ops)
					    : hybrid_pq_init_impl(role != 0, NULL, &state, methods[method], &hybrid_ops);
					int allocations = dssh_test_alloc_count();
					dssh_test_alloc_reset();
					valid = valid && ret == 0 && state == original && allocations == 0
					    && fixture.backend_inits == 1 && fixture.backend_cleanups == 0;
				}
				else
					valid = valid && state == NULL;
				if (methods[method] == NULL)
					curve25519_cleanup(state);
				else
					hybrid_pq_cleanup(state);
				valid = valid && fixture.live == 0 && fixture.backend_cleanups == (mode == 2 ? 0U : 1U);
				active = NULL;
				ASSERT_TRUE(valid);
			}
		}
	}
	return TEST_PASS;
}

static int
test_hybrid_raw_key_storage(void)
{
	for (size_t method = 0; method < sizeof(params) / sizeof(params[0]); method++) {
		struct hybrid_pq_params raw = params[method];
		raw.pq_sk_len = 64;
		ASSERT_EQ(framing_case(&raw, true), TEST_PASS);
	}
	return TEST_PASS;
}

static struct dssh_test_entry tests[] = {
	{ "methods/backend_initialization", test_backend_initialization },
	{ "hybrid/raw_key_storage", test_hybrid_raw_key_storage },
	{ "host/callback_results", host_callback_results },
	{ "host/callback_outputs", host_callback_outputs },
	{ "curve/client", curve_client }, { "curve/server", curve_server },
	{ "sntrup/client", sntrup_client }, { "sntrup/server", sntrup_server },
	{ "mlkem/client", mlkem_client }, { "mlkem/server", mlkem_server },
};

void
dssh_test_failure_cleanup(void)
{
	/* Assertions run before ownership starts or after all resources are freed. */
}

DSSH_TEST_MAIN(tests)
