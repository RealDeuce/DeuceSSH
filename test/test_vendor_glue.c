/* Direct checks of private bundled glue against independent scalar models. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kex/libcrux_mlkem768_sha3.h"

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expr); \
		return 1; \
	} \
} while (0)

static int
test_ranges(void)
{
	static const size_t ends[][2] = {
		{0, 0}, {1, 0}, {SIZE_MAX, 0}, {SIZE_MAX, SIZE_MAX}
	};
	for (size_t i = 0; i < sizeof(ends) / sizeof(ends[0]); i++) {
		core_ops_range_Range_b3 range = {ends[i][0], ends[i][1]};
		for (size_t j = 0; j < 2; j++) {
			Option_b3 next = Eurydice_range_iter_next(&range, size_t, Option_b3);
			CHECK(next.tag == None);
			CHECK(range.start == ends[i][0]);
		}
	}
	core_ops_range_Range_b3 range = {SIZE_MAX - 1, SIZE_MAX};
	Option_b3 next = Eurydice_range_iter_next(&range, size_t, Option_b3);
	CHECK(next.tag == Some);
	CHECK(next.f0 == SIZE_MAX - 1);
	CHECK(range.start == SIZE_MAX);
	next = Eurydice_range_iter_next(&range, size_t, Option_b3);
	CHECK(next.tag == None);
	return 0;
}

static void
pack_11(uint8_t out[352], size_t index, uint32_t value)
{
	for (size_t bit = 0; bit < 11; bit++) {
		size_t offset = index * 11 + bit;
		uint8_t octet = (uint8_t)(((value >> bit) & 1U) << (offset % 8));
		out[offset / 8] |= octet;
	}
}

static int
test_serialization(void)
{
	/* Cover the full coefficient domain in every lane and the entire output. */
	for (uint32_t value = 0; value < 3329; value++) {
		libcrux_ml_kem_polynomial_PolynomialRingElement_f0 ring;
		uint8_t actual[354];
		uint8_t expected[352] = {0};
		memset(actual, 0xa5, sizeof(actual));
		for (size_t index = 0; index < 256; index++) {
			uint32_t lane = (uint32_t)index;
			uint32_t coefficient = (value + lane) % 3329;
			int16_t bounded = (int16_t)coefficient;
			ring.coefficients[index / 16].elements[index % 16] = bounded;
			uint32_t compressed = ((coefficient * UINT32_C(2048) + 1664) / 3329) & 2047;
			pack_11(expected, index, compressed);
		}
		libcrux_ml_kem_serialize_compress_then_serialize_11_e1(&ring, actual + 1);
		CHECK(actual[0] == 0xa5);
		CHECK(actual[353] == 0xa5);
		CHECK(memcmp(actual + 1, expected, sizeof(expected)) == 0);
	}
	return 0;
}

static int
test_shuffle_table(void)
{
	for (uint32_t mask = 0; mask < 256; mask++) {
		size_t offset = 0;
		const uint8_t *row = libcrux_ml_kem_vector_rej_sample_table_REJECTION_SAMPLE_SHUFFLE_TABLE[mask];
		for (uint32_t bit = 0; bit < 8; bit++) {
			if ((mask & (UINT32_C(1) << bit)) != 0) {
				CHECK(row[offset++] == 2 * bit);
				CHECK(row[offset++] == 2 * bit + 1);
			}
		}
		while (offset < 16) {
			CHECK(row[offset] == UINT8_MAX);
			offset++;
		}
	}
	return 0;
}

static int
test_zetas(void)
{
	for (uint32_t index = 0; index < 128; index++) {
		uint32_t reversed = 0;
		for (uint32_t bit = 0; bit < 7; bit++)
			reversed = 2 * reversed + ((index >> bit) & 1U);
		uint32_t power = 1;
		for (uint32_t exponent = 0; exponent < reversed; exponent++)
			power = power * 17 % 3329;
		uint32_t residue = power * (UINT32_C(65536) % 3329) % 3329;
		int32_t centered = (int32_t)residue;
		if (centered > 1664)
			centered -= 3329;
		CHECK(libcrux_ml_kem_polynomial_ZETAS_TIMES_MONTGOMERY_R[index] == centered);
	}
	return 0;
}

int
main(void)
{
	if (test_ranges() != 0 || test_serialization() != 0
	    || test_shuffle_table() != 0 || test_zetas() != 0)
		return 1;
	puts("vendor glue: range boundaries, 3329 polynomial encodings, 256 shuffle rows and 128 zetas passed");
	return 0;
}
