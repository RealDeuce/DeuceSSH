/* Deterministic official answers for the actual selected bundled ML-KEM roots. */
#include <string.h>

#include "mlkem_acvp.h"
#include "kex/libcrux_mlkem768_sha3.h"

static bool
evaluate(const struct dssh_acvp_case *test, const struct dssh_acvp_decoded *bytes)
{
	uint8_t seed[64];
	memcpy(seed, bytes->d, 32);
	memcpy(seed + 32, bytes->z, 32);
	if (test->kind == DSSH_ACVP_KEYGEN || test->kind == DSSH_ACVP_DECAP_SEED) {
		libcrux_ml_kem_mlkem768_MlKem768KeyPair key = libcrux_ml_kem_mlkem768_portable_generate_key_pair(seed);
		bool equal = memcmp(key.pk.value, bytes->ek, sizeof(bytes->ek)) == 0
		    && memcmp(key.sk.value, bytes->dk, sizeof(bytes->dk)) == 0;
		if (test->kind == DSSH_ACVP_KEYGEN)
			return equal;
		libcrux_ml_kem_mlkem768_MlKem768Ciphertext ciphertext;
		memcpy(ciphertext.value, bytes->c, sizeof(bytes->c));
		uint8_t secret[32];
		libcrux_ml_kem_mlkem768_portable_decapsulate(&key.sk, &ciphertext, secret);
		return equal && memcmp(secret, bytes->k, sizeof(secret)) == 0;
	}
	if (test->kind == DSSH_ACVP_ENCAP || test->kind == DSSH_ACVP_PUBLIC_CHECK) {
		libcrux_ml_kem_types_MlKemPublicKey_15 key;
		memcpy(key.value, bytes->ek, sizeof(bytes->ek));
		bool admitted = libcrux_ml_kem_mlkem768_portable_validate_public_key(&key);
		if (test->kind == DSSH_ACVP_PUBLIC_CHECK)
			return admitted == test->valid;
		if (!admitted)
			return false;
		uint8_t randomness[32];
		memcpy(randomness, bytes->m, sizeof(randomness));
		tuple_3c result = libcrux_ml_kem_mlkem768_portable_encapsulate(&key, randomness);
		return memcmp(result.fst.value, bytes->c, sizeof(bytes->c)) == 0
		    && memcmp(result.snd, bytes->k, sizeof(bytes->k)) == 0;
	}
	libcrux_ml_kem_types_MlKemPrivateKey_55 key;
	libcrux_ml_kem_mlkem768_MlKem768Ciphertext ciphertext = {0};
	memcpy(key.value, bytes->dk, sizeof(bytes->dk));
	if (test->kind == DSSH_ACVP_PRIVATE_CHECK)
		return libcrux_ml_kem_mlkem768_portable_validate_private_key(&key, &ciphertext) == test->valid;
	if (test->kind != DSSH_ACVP_DECAP)
		return false;
	memcpy(ciphertext.value, bytes->c, sizeof(bytes->c));
	uint8_t secret[32];
	libcrux_ml_kem_mlkem768_portable_decapsulate(&key, &ciphertext, secret);
	return memcmp(secret, bytes->k, sizeof(secret)) == 0;
}

int
main(int argc, char **argv)
{
	return dssh_acvp_run(argc, argv, "bundled", evaluate);
}
