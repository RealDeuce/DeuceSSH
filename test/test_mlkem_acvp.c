/* Deterministic official answers for the actual selected bundled ML-KEM roots. */
#include <string.h>

#include "mlkem_acvp.h"
#ifdef DSSH_TEST_MLKEM_RETIREMENT
#include <stdio.h>
static void observe_clear(const char *, const char *, const void *, size_t);
#define DSSH_MLKEM_CLEAR_OBSERVER observe_clear
#endif
#include "kex/libcrux_mlkem768_sha3.h"

static bool
evaluate_primitive(const struct dssh_acvp_case *test, const struct dssh_acvp_decoded *bytes)
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

#ifdef DSSH_TEST_MLKEM_RETIREMENT
/* Match actual live owner sites, not just buffer sizes. Logical returned
 * values and deeper polynomial/hash owners have separate acceptance work. */
static const struct {
	const char *function;
	const char *owner;
	size_t bytes;
	unsigned counts[3]; /* key generation, encapsulation, decapsulation */
} clear_sites[] = {
	{"libcrux_ml_kem_types_from_17_35", "sk", sizeof(libcrux_ml_kem_types_MlKemPrivateKey_55), {1, 0, 0}},
	{"libcrux_ml_kem_types_from_05_f2", "copy_of_value", 2400, {1, 0, 0}},
	{"libcrux_ml_kem_utils_into_padded_array_ea0", "out", 1120, {0, 0, 1}},
	{"libcrux_ml_kem_utils_into_padded_array_ea", "out", 64, {0, 1, 1}},
	{"libcrux_ml_kem_constant_time_ops_select_ct", "out", 32, {0, 0, 1}},
	{"libcrux_ml_kem_constant_time_ops_compare_ciphertexts_select_shared_secret_in_constant_time", "ret0", 32, {0, 0, 1}},
	{"libcrux_ml_kem_variant_kdf_d8_41", "out", 32, {0, 1, 2}},
	{"libcrux_ml_kem_ind_cca_decapsulate_70", "decrypted", 32, {0, 0, 1}},
	{"libcrux_ml_kem_ind_cca_decapsulate_70", "to_hash0", 64, {0, 0, 1}},
	{"libcrux_ml_kem_ind_cca_decapsulate_70", "hashed", 64, {0, 0, 1}},
	{"libcrux_ml_kem_ind_cca_decapsulate_70", "to_hash", 1120, {0, 0, 1}},
	{"libcrux_ml_kem_ind_cca_decapsulate_70", "implicit_rejection_shared_secret0", 32, {0, 0, 1}},
	{"libcrux_ml_kem_ind_cca_decapsulate_70", "copy_of_decrypted", 32, {0, 0, 1}},
	{"libcrux_ml_kem_ind_cca_decapsulate_70", "expected_ciphertext", 1088, {0, 0, 1}},
	{"libcrux_ml_kem_ind_cca_decapsulate_70", "implicit_rejection_shared_secret", 32, {0, 0, 1}},
	{"libcrux_ml_kem_ind_cca_decapsulate_70", "shared_secret", 32, {0, 0, 1}},
	{"libcrux_ml_kem_ind_cca_decapsulate_70", "ret0", 32, {0, 0, 1}},
	{"libcrux_ml_kem_variant_entropy_preprocess_d8_63", "out", 32, {0, 1, 0}},
	{"libcrux_ml_kem_ind_cca_encapsulate_cd", "randomness0", 32, {0, 1, 0}},
	{"libcrux_ml_kem_ind_cca_encapsulate_cd", "to_hash", 64, {0, 1, 0}},
	{"libcrux_ml_kem_ind_cca_encapsulate_cd", "hashed", 64, {0, 1, 0}},
	{"libcrux_ml_kem_ind_cca_encapsulate_cd", "copy_of_randomness", 32, {0, 1, 0}},
	{"libcrux_ml_kem_ind_cca_encapsulate_cd", "shared_secret_array", 32, {0, 1, 0}},
	{"libcrux_ml_kem_ind_cca_encapsulate_cd", "copy_of_shared_secret_array", 32, {0, 1, 0}},
	{"libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_c6", "copy_of_randomness", 32, {0, 1, 0}},
	{"libcrux_ml_kem_mlkem768_portable_encapsulate", "copy_of_randomness", 32, {0, 1, 0}},
	{"libcrux_ml_kem_variant_cpa_keygen_seed_d8_0e", "seed", 33, {1, 0, 0}},
	{"libcrux_ml_kem_variant_cpa_keygen_seed_d8_0e", "ret0", 64, {1, 0, 0}},
	{"libcrux_ml_kem_ind_cca_serialize_kem_secret_key_48", "out", 2400, {1, 0, 0}},
	{"libcrux_ml_kem_ind_cca_generate_keypair_8c", "uu____0", sizeof(libcrux_ml_kem_utils_extraction_helper_Keypair768), {1, 0, 0}},
	{"libcrux_ml_kem_ind_cca_generate_keypair_8c", "ind_cpa_private_key", 1152, {1, 0, 0}},
	{"libcrux_ml_kem_ind_cca_generate_keypair_8c", "secret_key_serialized", 2400, {1, 0, 0}},
	{"libcrux_ml_kem_ind_cca_generate_keypair_8c", "copy_of_secret_key_serialized", 2400, {1, 0, 0}},
	{"libcrux_ml_kem_ind_cca_generate_keypair_8c", "private_key", sizeof(libcrux_ml_kem_types_MlKemPrivateKey_55), {1, 0, 0}},
	{"libcrux_ml_kem_ind_cca_generate_keypair_8c", "uu____2", sizeof(libcrux_ml_kem_types_MlKemPrivateKey_55), {1, 0, 0}},
	{"libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_d5", "copy_of_randomness", 64, {1, 0, 0}},
	{"libcrux_ml_kem_mlkem768_portable_generate_key_pair", "copy_of_randomness", 64, {1, 0, 0}},
};

struct clear_observation {
	unsigned calls[sizeof(clear_sites) / sizeof(clear_sites[0])];
	bool valid;
};

/* This runner is single-threaded; publish only during evaluate_primitive. */
static struct clear_observation *active_observation;
static size_t observed_cases;
static size_t observed_clears;

static void
observe_clear(const char *function, const char *owner, const void *buffer, size_t bytes)
{
	struct clear_observation *observation = active_observation;
	if (observation == NULL)
		return;
	for (size_t i = 0; i < sizeof(clear_sites) / sizeof(clear_sites[0]); i++) {
		if (strcmp(function, clear_sites[i].function) != 0
		    || strcmp(owner, clear_sites[i].owner) != 0)
			continue;
		if (bytes != clear_sites[i].bytes || buffer == NULL
		    || observation->calls[i] >= 2) {
			observation->valid = false;
			return;
		}
		const unsigned char *octets = buffer;
		for (size_t j = 0; j < bytes; j++) {
			if (octets[j] != 0)
				observation->valid = false;
		}
		observation->calls[i]++;
		return;
	}
	observation->valid = false;
}

static bool
check_observer(void)
{
	uint8_t buffer[32] = {0};
	bool valid = true;
	for (unsigned scenario = 0; scenario < 5; scenario++) {
		struct clear_observation observation = {{0}, true};
		active_observation = &observation;
		buffer[0] = scenario == 1 ? 1 : 0;
		const char *function = scenario == 3 ? "unknown" : clear_sites[4].function;
		size_t bytes = scenario == 2 ? sizeof(buffer) - 1 : sizeof(buffer);
		observe_clear(function, clear_sites[4].owner, buffer, bytes);
		if (scenario == 4) {
			observe_clear(function, clear_sites[4].owner, buffer, bytes);
			observe_clear(function, clear_sites[4].owner, buffer, bytes);
		}
		active_observation = NULL;
		if (observation.valid != (scenario == 0))
			valid = false;
	}
	printf("ML-KEM retirement observer: controls=5 valid=%u\n", valid ? 1U : 0U);
	return valid;
}

static bool
evaluate(const struct dssh_acvp_case *test, const struct dssh_acvp_decoded *bytes)
{
	struct clear_observation observation = {{0}, true};
	active_observation = &observation;
	bool matched = evaluate_primitive(test, bytes);
	active_observation = NULL;
	bool keygen = test->kind == DSSH_ACVP_KEYGEN || test->kind == DSSH_ACVP_DECAP_SEED;
	bool encap = test->kind == DSSH_ACVP_ENCAP;
	bool decap = test->kind == DSSH_ACVP_DECAP || test->kind == DSSH_ACVP_DECAP_SEED;
	for (size_t i = 0; i < sizeof(clear_sites) / sizeof(clear_sites[0]); i++) {
		unsigned expected = (keygen ? clear_sites[i].counts[0] : 0U)
		    + (encap ? clear_sites[i].counts[1] : 0U)
		    + (decap ? clear_sites[i].counts[2] : 0U);
		if (observation.calls[i] != expected)
			observation.valid = false;
		/* All counts are bounded above by 2, across 145 finite cases. */
		observed_clears += observation.calls[i];
	}
	observed_cases++;
	if (!observation.valid)
		fprintf(stderr, "ML-KEM owner retirement mismatch: kind=%d group=%u case=%u\n",
		    test->kind, test->group, test->id);
	return matched && observation.valid;
}
#else
#define evaluate evaluate_primitive
#endif

int
main(int argc, char **argv)
{
	#ifdef DSSH_TEST_MLKEM_RETIREMENT
	if (!check_observer())
		return 2;
	int ret = dssh_acvp_run(argc, argv, "bundled retirement", evaluate);
	printf("ML-KEM retirement: cases=%zu sites=%zu clears=%zu active=%u\n",
	    observed_cases, sizeof(clear_sites) / sizeof(clear_sites[0]), observed_clears,
	    active_observation != NULL ? 1U : 0U);
	return ret;
#else
	return dssh_acvp_run(argc, argv, "bundled", evaluate);
#endif
}
