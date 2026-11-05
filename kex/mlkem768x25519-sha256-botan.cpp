// mlkem768x25519-sha256: ML-KEM-768 + X25519 hybrid PQ KEX (Botan3 native C++ backend)

#include <botan/ml_kem.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>
#include <botan/system_rng.h>

#include <cstdlib>
#include <cstring>
#include <memory>

#include "deucessh-crypto.h"
#include "deucessh.h"
#include "hybrid-pq-kex-ops.h"

#define MLKEM_PK_LEN 1184
#define MLKEM_CT_LEN 1088
#define MLKEM_SS_LEN 32

/* --- PQ operations (Botan3 native ML-KEM-768) --- */

static int
mlkem_keygen_botan(uint8_t *pk_out, uint8_t *storage, size_t capacity, void **sk_ctx)
{
	if (storage != nullptr || capacity != 0)
		return DSSH_ERROR_INVALID;
	try {
		auto priv = std::make_unique<Botan::ML_KEM_PrivateKey>(Botan::system_rng(), Botan::ML_KEM_Mode::ML_KEM_768);

		auto pub_raw = priv->raw_public_key_bits();

		if (pub_raw.size() != MLKEM_PK_LEN) {
			return DSSH_ERROR_INIT;
		}
		memcpy(pk_out, pub_raw.data(), MLKEM_PK_LEN);
		*sk_ctx = priv.release();
		return 0;
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}

static int
mlkem_encaps_botan(uint8_t *ct_out, uint8_t *ss_out, const uint8_t *pk, size_t pk_len)
{
	try {
		Botan::ML_KEM_PublicKey pub(std::span<const uint8_t>(pk, pk_len), Botan::ML_KEM_Mode::ML_KEM_768);

		Botan::PK_KEM_Encryptor enc(pub, "Raw");
		if (enc.shared_key_length(MLKEM_SS_LEN) != MLKEM_SS_LEN
		    || enc.encapsulated_key_length() != MLKEM_CT_LEN)
			return DSSH_ERROR_INIT;
		enc.encrypt(std::span<uint8_t>(ct_out, MLKEM_CT_LEN),
		    std::span<uint8_t>(ss_out, MLKEM_SS_LEN), Botan::system_rng(), MLKEM_SS_LEN);
		return 0;
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}

static int
mlkem_decaps_botan(uint8_t *ss_out, const uint8_t *ct, size_t ct_len, void *sk_ctx)
{
	auto *priv = static_cast<Botan::ML_KEM_PrivateKey *>(sk_ctx);

	try {
		Botan::PK_KEM_Decryptor dec(*priv, Botan::system_rng(), "Raw");
		if (dec.shared_key_length(MLKEM_SS_LEN) != MLKEM_SS_LEN
		    || ct_len != dec.encapsulated_key_length())
			return DSSH_ERROR_INVALID;
		dec.decrypt(std::span<uint8_t>(ss_out, MLKEM_SS_LEN),
		    std::span<const uint8_t>(ct, ct_len), MLKEM_SS_LEN);
		return 0;
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}

static void
mlkem_free_sk_botan(void *sk_ctx)
{
	delete static_cast<Botan::ML_KEM_PrivateKey *>(sk_ctx);
}

#ifdef DSSH_TESTING
/* Build a valid client fixture through Botan, matching the production
 * KEX path rather than depending on the vendored OpenSSL-side KEM. */
extern "C" DSSH_TESTABLE int
dssh_test_mlkem768_public_key(uint8_t *pk_out, size_t pk_len)
{
	if (pk_out == NULL || pk_len != MLKEM_PK_LEN)
		return DSSH_ERROR_INVALID;

	void *sk_ctx = nullptr;
	int   ret    = mlkem_keygen_botan(pk_out, nullptr, 0, &sk_ctx);

	mlkem_free_sk_botan(sk_ctx);
	return ret;
}
#endif

static const struct hybrid_pq_params mlkem_params = {
    .kex_name     = "mlkem768x25519-sha256",
    .kex_name_len = 21,
    .hash_name    = "SHA-256",
    .digest_len   = 32,
    .pq_pk_len    = MLKEM_PK_LEN,
    .pq_ct_len    = MLKEM_CT_LEN,
    .pq_ss_len    = MLKEM_SS_LEN,
	.pq_sk_len    = 0,
    .q_c_len      = MLKEM_PK_LEN + DSSH_X25519_LEN,
    .q_s_len      = MLKEM_CT_LEN + DSSH_X25519_LEN,
};

static const struct hybrid_pq_ops botan_mlkem_ops = {
	.x25519          = &dssh_x25519_backend,
    .pq_keygen        = mlkem_keygen_botan,
    .pq_encaps        = mlkem_encaps_botan,
    .pq_decaps        = mlkem_decaps_botan,
    .pq_free_sk       = mlkem_free_sk_botan,
};

extern "C" int
mlkem768x25519_init(bool client, void *config, void **state)
{
	try {
		return hybrid_pq_init_impl(client, config, state, &mlkem_params, &botan_mlkem_ops);
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}

extern "C" int
dssh_botan_mlkem768x25519_handler(const struct dssh_kex_context *kctx, struct dssh_kex_result *out)
{
	try {
		return hybrid_pq_handler_impl(kctx, out, &mlkem_params, &botan_mlkem_ops);
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}
