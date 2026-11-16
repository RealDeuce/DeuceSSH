#ifndef DSSH_SNTRUP_KAT_CASES_H
#define DSSH_SNTRUP_KAT_CASES_H

/* Official round-three response/intermediate files, independently supplied by
 * the NTRU Prime authors. Read one record into reusable bounded storage. */
struct sntrup_kat_record {
	uint8_t seed[48];
	uint8_t pk[1158];
	uint8_t sk[1763];
	uint8_t ct[1039];
	uint8_t ss[32];
	uint8_t r[191];
};

static bool
sntrup_kat_line(FILE *file, char *line, size_t capacity)
{
	if (capacity < 2 || capacity > INT_MAX)
		return false;
	int bound = (int)capacity;
	if (fgets(line, bound, file) == NULL)
		return false;
	size_t length = strlen(line);
	if (length == 0 || line[length - 1] != '\n')
		return false;
	line[--length] = 0;
	if (length != 0 && line[length - 1] == '\r')
		line[length - 1] = 0;
	return true;
}

static int
sntrup_kat_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static bool
sntrup_kat_hex(FILE *file, const char *prefix, uint8_t *out, size_t size)
{
	char line[4096];
	size_t start = strlen(prefix);
	if (!sntrup_kat_line(file, line, sizeof(line)) || start > sizeof(line) - 1
	    || size > (sizeof(line) - 1 - start) / 2
	    || strlen(line) != start + 2 * size || memcmp(line, prefix, start) != 0)
		return false;
	for (size_t i = 0; i < size; i++) {
		int high = sntrup_kat_digit(line[start + 2 * i]);
		int low = sntrup_kat_digit(line[start + 2 * i + 1]);
		if (high < 0 || low < 0)
			return false;
		uint8_t octet = (uint8_t)(16 * high + low); /*0..255. */
		out[i] = octet;
	}
	return true;
}

static bool
sntrup_kat_read(FILE *response, FILE *intermediate, unsigned count,
    struct sntrup_kat_record *record)
{
	char line[64], expected[64];
	int printed = snprintf(expected, sizeof(expected), "count = %u", count);
	if (printed <= 0)
		return false;
	size_t extent = (size_t)printed;
	if (extent >= sizeof(expected) || !sntrup_kat_line(response, line, sizeof(line))
	    || strcmp(line, expected) != 0)
		return false;
	uint8_t repeated[191];
	return sntrup_kat_hex(response, "seed = ", record->seed, sizeof(record->seed))
	    && sntrup_kat_hex(response, "pk = ", record->pk, sizeof(record->pk))
	    && sntrup_kat_hex(response, "sk = ", record->sk, sizeof(record->sk))
	    && sntrup_kat_hex(response, "ct = ", record->ct, sizeof(record->ct))
	    && sntrup_kat_hex(response, "ss = ", record->ss, sizeof(record->ss))
	    && sntrup_kat_line(response, line, sizeof(line)) && line[0] == 0
	    && sntrup_kat_hex(intermediate, "Hide r_enc: ", record->r, sizeof(record->r))
	    && sntrup_kat_hex(intermediate, "Hide r_enc: ", repeated, sizeof(repeated))
	    && memcmp(record->r, repeated, sizeof(repeated)) == 0;
}

static bool
sntrup_kat_encoding(const struct sntrup_kat_record *record)
{
	Inputs input;
	uint8_t ciphertext[1041], encoded[193], secret[34], cache[32];
	memset(ciphertext, 0xa5, sizeof(ciphertext));
	memset(encoded, 0xa5, sizeof(encoded));
	memset(secret, 0xa5, sizeof(secret));
	Small_decode(input, record->r);
	unsigned weight = 0;
	for (size_t i = 0; i < sizeof(input) / sizeof(input[0]); i++) {
		if (input[i] < -1 || input[i] > 1)
			return false;
		if (input[i] != 0)
			weight++;
	}
	bool valid = weight == 286 && Hash_prefix(cache, 4, record->pk, sizeof(record->pk)) == 0
	    && memcmp(cache, &record->sk[1731], sizeof(cache)) == 0
	    && Hide(ciphertext + 1, encoded + 1, input, record->pk, cache) == 0
	    && memcmp(ciphertext + 1, record->ct, sizeof(record->ct)) == 0
	    && memcmp(encoded + 1, record->r, sizeof(record->r)) == 0
	    && HashSession(secret + 1, 1, encoded + 1, ciphertext + 1) == 0
	    && memcmp(secret + 1, record->ss, sizeof(record->ss)) == 0
	    && ciphertext[0] == 0xa5 && ciphertext[sizeof(ciphertext) - 1] == 0xa5
	    && encoded[0] == 0xa5 && encoded[sizeof(encoded) - 1] == 0xa5
	    && secret[0] == 0xa5 && secret[sizeof(secret) - 1] == 0xa5;
	return valid;
}

static bool
sntrup_kat_decapsulation(const struct sntrup_kat_record *record)
{
	uint8_t actual[34];
	memset(actual, 0xa5, sizeof(actual));
	return crypto_kem_sntrup761_dec(actual + 1, record->ct, record->sk) == 0
	    && memcmp(actual + 1, record->ss, sizeof(record->ss)) == 0
	    && actual[0] == 0xa5 && actual[sizeof(actual) - 1] == 0xa5;
}

static bool
sntrup_kat_run(bool encoding, unsigned *completed)
{
	FILE *response = fopen(DSSH_SNTRUP_KAT_RESPONSE, "rb");
	FILE *intermediate = fopen(DSSH_SNTRUP_KAT_INTERMEDIATE, "rb");
	bool valid = response != NULL && intermediate != NULL;
	struct sntrup_kat_record record;
	char line[64];
	if (valid)
		valid = sntrup_kat_line(response, line, sizeof(line)) && strcmp(line, "# kem/sntrup761") == 0
		    && sntrup_kat_line(response, line, sizeof(line)) && line[0] == 0;
	*completed = 0;
	for (unsigned i = 0; valid && i < 100; i++) {
		valid = sntrup_kat_read(response, intermediate, i, &record)
		    && memcmp(record.pk, &record.sk[382], sizeof(record.pk)) == 0;
		if (valid)
			valid = encoding ? sntrup_kat_encoding(&record) : sntrup_kat_decapsulation(&record);
		if (valid)
			(*completed)++;
	}
	if (valid)
		valid = fgetc(response) == EOF && !ferror(response)
		    && fgetc(intermediate) == EOF && !ferror(intermediate);
	if (response != NULL && fclose(response) != 0)
		valid = false;
	if (intermediate != NULL && fclose(intermediate) != 0)
		valid = false;
	dssh_cleanse(&record, sizeof(record));
	return valid && *completed == 100;
}

static int
test_sntrup_kat_decapsulation(void)
{
	unsigned completed = 0;
	bool valid = sntrup_kat_run(false, &completed);
	int printed = printf("sntrup_kat kind=decapsulation vectors=%u valid=%d\n", completed, valid);
	ASSERT_TRUE(valid && completed == 100 && printed > 0);
	return TEST_PASS;
}

static int
test_sntrup_kat_encoding(void)
{
	unsigned completed = 0;
	bool valid = sntrup_kat_run(true, &completed);
	int printed = printf("sntrup_kat kind=encoding vectors=%u valid=%d\n", completed, valid);
	ASSERT_TRUE(valid && completed == 100 && printed > 0);
	return TEST_PASS;
}

#endif
