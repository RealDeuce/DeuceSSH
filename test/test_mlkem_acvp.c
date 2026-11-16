/* Deterministic official answers for the actual selected bundled ML-KEM roots. */
#include <string.h>

#include "mlkem_acvp.h"
#ifdef DSSH_TEST_MLKEM_RETIREMENT
#include <stdio.h>
static void observe_clear(const char *, const char *, const void *, size_t);
#define DSSH_MLKEM_CLEAR_OBSERVER observe_clear
#endif
#include "kex/libcrux_mlkem768_sha3.h"
#ifdef DSSH_TEST_MLKEM_RETIREMENT
#include <inttypes.h>
#include "mlkem_hash_retirement.h"
#endif

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
 * values and deeper polynomial/serialization owners have separate acceptance work. */
static const struct {
	const char *function;
	const char *owner;
	size_t bytes;
	unsigned counts[5]; /* keygen, encap, decap, public check, private check */
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
	{"libcrux_ml_kem_ind_cpa_generate_keypair_fc", "hashed", sizeof(uint8_t[64]), {1, 0, 0}},
	{"libcrux_ml_kem_ind_cpa_generate_keypair_fc", "prf_input", sizeof(uint8_t[33]), {1, 0, 0}},
	{"libcrux_ml_kem_ind_cpa_generate_keypair_fc", "secret_sample", sizeof(tuple_b0), {1, 0, 0}},
	{"libcrux_ml_kem_ind_cpa_generate_keypair_fc", "error_sample", sizeof(tuple_b0), {1, 0, 0}},
	{"libcrux_ml_kem_ind_cpa_generate_keypair_fc", "t_as_ntt", sizeof(libcrux_ml_kem_polynomial_PolynomialRingElement_f0[3]), {1, 0, 0}},
	{"libcrux_ml_kem_ind_cpa_sample_vector_cbd_then_ntt_fc", "prf_inputs", sizeof(uint8_t[3][33]), {2, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_sample_vector_cbd_then_ntt_fc", "prf_outputs", sizeof(uint8_t[3][128]), {2, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_ac", "prf_inputs", sizeof(uint8_t[3][33]), {0, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_ac", "prf_outputs", sizeof(uint8_t[3][128]), {0, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_encrypt_60", "prf_input", sizeof(uint8_t[33]), {0, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_encrypt_60", "prf_output", sizeof(uint8_t[128]), {0, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_encrypt_60", "r_sample", sizeof(tuple_b0), {0, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_encrypt_60", "error_sample", sizeof(tuple_b0), {0, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_encrypt_60", "error_2", sizeof(libcrux_ml_kem_polynomial_PolynomialRingElement_f0), {0, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_encrypt_60", "u", sizeof(libcrux_ml_kem_polynomial_PolynomialRingElement_f0[3]), {0, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_encrypt_60", "message_as_ring_element", sizeof(libcrux_ml_kem_polynomial_PolynomialRingElement_f0), {0, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_encrypt_60", "v", sizeof(libcrux_ml_kem_polynomial_PolynomialRingElement_f0), {0, 1, 1}},
	{"libcrux_ml_kem_ind_cpa_decrypt_unpacked_6d", "message", sizeof(libcrux_ml_kem_polynomial_PolynomialRingElement_f0), {0, 0, 1}},
	{"libcrux_ml_kem_ind_cpa_decrypt_43", "secret_key_unpacked", sizeof(libcrux_ml_kem_ind_cpa_unpacked_IndCpaPrivateKeyUnpacked_f8), {0, 0, 1}},
	{"libcrux_ml_kem_serialize_compress_then_serialize_message_aa", "coefficient", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {0, 0, 1}},
	{"libcrux_ml_kem_serialize_compress_then_serialize_message_aa", "coefficient_compressed", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {0, 0, 1}},
	{"libcrux_ml_kem_serialize_compress_then_serialize_4_9a", "coefficient", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {0, 1, 1}},
	{"libcrux_ml_kem_matrix_compute_As_plus_e_60", "product", sizeof(libcrux_ml_kem_polynomial_PolynomialRingElement_f0), {1, 0, 0, 0, 0}},
	{"libcrux_ml_kem_matrix_compute_vector_u_59", "product", sizeof(libcrux_ml_kem_polynomial_PolynomialRingElement_f0), {0, 1, 1, 0, 0}},
	{"libcrux_ml_kem_matrix_compute_ring_element_v_54", "product", sizeof(libcrux_ml_kem_polynomial_PolynomialRingElement_f0), {0, 1, 1, 0, 0}},
	{"libcrux_ml_kem_matrix_compute_message_b3", "product", sizeof(libcrux_ml_kem_polynomial_PolynomialRingElement_f0), {0, 0, 1, 0, 0}},
	{"libcrux_ml_kem_polynomial_add_standard_error_reduce_89_03", "coefficient_normal_form", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {3, 0, 0, 0, 0}},
	{"libcrux_ml_kem_polynomial_add_error_reduce_89_38", "coefficient_normal_form", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {0, 3, 3, 0, 0}},
	{"libcrux_ml_kem_polynomial_add_message_error_reduce_89_ea", "coefficient_normal_form", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {0, 1, 1, 0, 0}},
	{"libcrux_ml_kem_polynomial_add_message_error_reduce_89_ea", "tmp", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {0, 1, 1, 0, 0}},
	{"libcrux_ml_kem_polynomial_subtract_reduce_89_d4", "coefficient_normal_form", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {0, 0, 1, 0, 0}},
	{"libcrux_ml_kem_sampling_sample_from_binomial_distribution_2_85", "sampled_i16s", sizeof(int16_t[256]), {6, 7, 7, 0, 0}},
	{"libcrux_ml_kem_serialize_compress_then_serialize_10_fc", "coefficient", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {0, 3, 3, 0, 0}},
	{"libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_5b", "coefficient", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {6, 3, 0, 3, 0}},
	{"libcrux_ml_kem_ntt_ntt_at_layer_4_plus_51", "t", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {18, 9, 21, 0, 0}},
	{"libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_6e", "a_minus_b", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {0, 16, 20, 0, 0}},
	{"libcrux_ml_kem_ntt_ntt_at_layer_7_f4", "t", sizeof(libcrux_ml_kem_vector_portable_vector_type_PortableVector), {6, 3, 3, 0, 0}},
	{"libcrux_ml_kem_vector_portable_serialize_serialize_4", "encoded", sizeof(uint8_t_x4), {0, 16, 16, 0, 0}},
	{"libcrux_ml_kem_vector_portable_serialize_serialize_10", "encoded", sizeof(uint8_t_x5), {0, 48, 48, 0, 0}},
	{"libcrux_ml_kem_vector_portable_serialize_serialize_12", "encoded", sizeof(uint8_t_x3), {96, 48, 0, 48, 0}},
	{"libcrux_ml_kem_vector_portable_serialize_deserialize_4", "decoded", sizeof(int16_t_x8), {0, 0, 16, 0, 0}},
	{"libcrux_ml_kem_vector_portable_serialize_deserialize_10", "decoded", sizeof(int16_t_x8), {0, 0, 48, 0, 0}},
	{"libcrux_ml_kem_vector_portable_serialize_deserialize_12", "decoded", sizeof(int16_t_x2), {0, 96, 96, 48, 0}},
};

struct clear_observation {
	uint32_t calls[sizeof(clear_sites) / sizeof(clear_sites[0])];
	struct dssh_hash_wipes hash;
	bool valid;
};

/* This runner is single-threaded; publish only during evaluate_primitive. */
static struct clear_observation *active_observation;
static size_t observed_cases;
static uint64_t observed_clears;
static uint64_t observed_hash_clears;
static bool observed_hash_valid = true;

static void
observe_clear(const char *function, const char *owner, const void *buffer, size_t bytes)
{
	struct clear_observation *observation = active_observation;
	if (observation == NULL)
		return;
	if (dssh_hash_wipe_record(&observation->hash, function, owner, buffer, bytes))
		return;
	for (size_t i = 0; i < sizeof(clear_sites) / sizeof(clear_sites[0]); i++) {
		if (strcmp(function, clear_sites[i].function) != 0
		    || strcmp(owner, clear_sites[i].owner) != 0)
			continue;
		if (bytes != clear_sites[i].bytes || buffer == NULL
		    || observation->calls[i] == UINT32_MAX) {
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
		struct clear_observation observation = {.hash = {.valid = true}, .valid = true};
		active_observation = &observation;
		buffer[0] = scenario == 1 ? 1 : 0;
		const char *function = scenario == 3 ? "unknown" : clear_sites[4].function;
		size_t bytes = scenario == 2 ? sizeof(buffer) - 1 : sizeof(buffer);
		if (scenario == 4)
			observation.calls[4] = UINT32_MAX;
		observe_clear(function, clear_sites[4].owner, buffer, bytes);
		active_observation = NULL;
		if (observation.valid != (scenario == 0))
			valid = false;
	}
	if (printf("ML-KEM retirement observer: controls=5 valid=%u\n", valid ? 1U : 0U) < 0)
		return false;
	return valid;
}

static bool
evaluate(const struct dssh_acvp_case *test, const struct dssh_acvp_decoded *bytes)
{
	struct clear_observation observation = {.hash = {.valid = true}, .valid = true};
	active_observation = &observation;
	bool matched = evaluate_primitive(test, bytes);
	active_observation = NULL;
	bool keygen = test->kind == DSSH_ACVP_KEYGEN || test->kind == DSSH_ACVP_DECAP_SEED;
	bool encap = test->kind == DSSH_ACVP_ENCAP;
	bool decap = test->kind == DSSH_ACVP_DECAP || test->kind == DSSH_ACVP_DECAP_SEED;
	bool public_check = test->kind == DSSH_ACVP_PUBLIC_CHECK;
	bool private_check = test->kind == DSSH_ACVP_PRIVATE_CHECK;
	for (size_t i = 0; i < sizeof(clear_sites) / sizeof(clear_sites[0]); i++) {
		unsigned expected = (keygen ? clear_sites[i].counts[0] : 0U)
		    + (encap ? clear_sites[i].counts[1] : 0U)
		    + (decap ? clear_sites[i].counts[2] : 0U)
		    + (public_check ? clear_sites[i].counts[3] : 0U)
		    + (private_check ? clear_sites[i].counts[4] : 0U);
		if (observation.calls[i] != expected)
			observation.valid = false;
		/* 80 uint32_t counters across 145 finite cases sum to less than 2^46. */
		observed_clears += observation.calls[i];
	}
	observed_cases++;
	struct dssh_hash_wipes expected_hash = {.valid = true};
	uint32_t generations = keygen ? 1U : 0U;
	uint32_t encapsulations = encap ? 1U : 0U;
	uint32_t decapsulations = decap ? 1U : 0U;
	uint32_t private_checks = test->kind == DSSH_ACVP_PRIVATE_CHECK ? 1U : 0U;
	expected_hash.calls[DSSH_HASH_FINAL72] = generations + encapsulations + decapsulations;
	expected_hash.calls[DSSH_HASH_FINAL136_SHA] = generations + encapsulations + private_checks;
	expected_hash.calls[DSSH_HASH_FINAL136_SHAKE] = 6U * generations + 7U * encapsulations + 8U * decapsulations;
	expected_hash.calls[DSSH_HASH_FINAL168] = 9U * (generations + encapsulations + decapsulations);
	expected_hash.calls[DSSH_HASH_STATE72] = expected_hash.calls[DSSH_HASH_FINAL72];
	expected_hash.calls[DSSH_HASH_STATE136_SHA] = expected_hash.calls[DSSH_HASH_FINAL136_SHA];
	expected_hash.calls[DSSH_HASH_STATE136_SHAKE] = expected_hash.calls[DSSH_HASH_FINAL136_SHAKE];
	expected_hash.calls[DSSH_HASH_FIRST_LAST72] = expected_hash.calls[DSSH_HASH_FINAL72];
	expected_hash.calls[DSSH_HASH_FIRST_LAST136] = expected_hash.calls[DSSH_HASH_FINAL136_SHA]
	    + expected_hash.calls[DSSH_HASH_FINAL136_SHAKE];
	/* Each matrix row absorbs three lanes and squeezes three initial blocks.
	 * Every further sampler block advances all three lanes. Its number is
	 * public-input dependent; direct hash fixtures check exact permutations. */
	uint32_t minimum = 43U * generations + 44U * encapsulations + 44U * decapsulations + 9U * private_checks;
	uint32_t core = observation.hash.calls[DSSH_HASH_C];
	if (core < minimum || (core - minimum) % 3U != 0
	    || (expected_hash.calls[DSSH_HASH_FINAL168] == 0 && core != minimum))
		observation.hash.valid = false;
	expected_hash.calls[DSSH_HASH_C] = core;
	expected_hash.calls[DSSH_HASH_T] = core;
	expected_hash.calls[DSSH_HASH_OLD] = core;
	/* At most145 observations, each a sum of14 uint32_t counters. */
	observed_hash_clears += dssh_hash_wipe_total(&observation.hash);
	if (!dssh_hash_wipe_match(&observation.hash, &expected_hash)) {
		observed_hash_valid = false;
		observation.valid = false;
	}
	if (!observation.valid
	    && fprintf(stderr, "ML-KEM owner retirement mismatch: kind=%d group=%u case=%u\n",
	        test->kind, test->group, test->id) < 0)
		return false;
	return matched && observation.valid;
}
#else
#define evaluate evaluate_primitive
#endif

int
main(int argc, char **argv)
{
	#ifdef DSSH_TEST_MLKEM_RETIREMENT
	if (!check_observer() || !dssh_hash_wipe_controls())
		return 2;
	int ret = dssh_acvp_run(argc, argv, "bundled retirement", evaluate);
	if (printf("ML-KEM retirement: cases=%zu sites=%zu clears=%" PRIu64 " active=%u\n",
	    observed_cases, sizeof(clear_sites) / sizeof(clear_sites[0]), observed_clears,
	    active_observation != NULL ? 1U : 0U) < 0)
		return 2;
	if (printf("ML-KEM hash retirement in KEM: cases=%zu sites=14 clears=%" PRIu64
	    " active=%u valid=%u\n", observed_cases, observed_hash_clears,
	    active_observation != NULL ? 1U : 0U, observed_hash_valid ? 1U : 0U) < 0)
		return 2;
	return ret;
#else
	return dssh_acvp_run(argc, argv, "bundled", evaluate);
#endif
}
