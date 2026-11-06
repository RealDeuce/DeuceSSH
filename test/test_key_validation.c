/* Native key-file validation transaction, driven by real file fixtures. */
#include "dssh_test.h"
#include "dssh_test_internal.h"
#include "deucessh-algorithms.h"

struct validation_ops {
	int (*reg)(void);
	int (*load)(const char *, dssh_pem_password_cb, void *);
	int (*generate)(void);
	const char *name;
	const char *cache;
};

static int
rsa256_generate(void)
{
	return dssh_rsa_sha2_256_generate_key(2048);
}

static int
rsa512_generate(void)
{
	return dssh_rsa_sha2_512_generate_key(2048);
}

static const struct validation_ops operations[] = {
	{dssh_register_ssh_ed25519, dssh_ed25519_load_key_file, dssh_ed25519_generate_key,
	    "ssh-ed25519", "DSSH_TEST_ED25519_KEY"},
	{dssh_register_rsa_sha2_256, dssh_rsa_sha2_256_load_key_file, rsa256_generate,
	    "rsa-sha2-256", "DSSH_TEST_RSA_KEY"},
	{dssh_register_rsa_sha2_512, dssh_rsa_sha2_512_load_key_file, rsa512_generate,
	    "rsa-sha2-512", "DSSH_TEST_RSA_KEY"},
};

static bool
snapshot(dssh_key_algo key, uint8_t *copy, size_t *length)
{
	const uint8_t *blob = NULL;
	size_t count = 0;
	if (key->pubkey(&blob, &count, key->ctx) != 0 || blob == NULL || count == 0 || count > 512)
		return false;
	memcpy(copy, blob, count);
	*length = count;
	return true;
}

static bool
signable(dssh_key_algo key, const uint8_t *blob, size_t length)
{
	const uint8_t message[] = {'v', 'a', 'l', 'i', 'd'};
	struct dssh_bytes_result signature = {0};
	int ret = key->sign(&signature, message, sizeof(message), key->ctx);
	bool valid = ret == 0 && signature.bytes.data != NULL && signature.bytes.len != 0
	    && signature.lease.release != NULL;
	if (valid)
		valid = key->verify(blob, length, signature.bytes.data, signature.bytes.len,
		    message, sizeof(message)) == 0;
	dssh_result_release(&signature.lease);
	return valid;
}

static int
test_transaction(void)
{
	const char *name = getenv("DSSH_VALIDATION_ALGORITHM");
	const char *path = getenv("DSSH_VALIDATION_CANDIDATE");
	const char *mode = getenv("DSSH_VALIDATION_EXPECT");
	const struct validation_ops *ops = NULL;
	bool valid = false;
	int result = DSSH_ERROR_INIT;
	for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); i++) {
		if (name != NULL && strcmp(name, operations[i].name) == 0)
			ops = &operations[i];
	}
	if (ops == NULL || path == NULL || mode == NULL
	    || (strcmp(mode, "accept") != 0 && strcmp(mode, "reject") != 0))
		goto done;
	const char *cache = getenv(ops->cache);
	if (cache == NULL || ops->reg() != 0 || ops->load(cache, NULL, NULL) != 0)
		goto done;
	dssh_key_algo key = find_key_algo(ops->name);
	uint8_t candidate[512], before[512], after[512];
	size_t candidate_len = 0, before_len = 0, after_len = 0;
	if (key == NULL || !snapshot(key, candidate, &candidate_len) || ops->generate() != 0
	    || !snapshot(key, before, &before_len))
		goto done;
	if (before_len == candidate_len && memcmp(before, candidate, before_len) == 0)
		goto done;
	dssh_key_algo_ctx *prior = key->ctx;
	result = ops->load(path, NULL, NULL);
	if (strcmp(mode, "reject") == 0) {
		/* Never sign using an accepted negative fixture. */
		valid = result < 0 && key->ctx == prior
		    && snapshot(key, after, &after_len) && after_len == before_len
		    && memcmp(after, before, before_len) == 0 && signable(key, before, before_len);
	}
	else {
		valid = result == 0 && snapshot(key, after, &after_len) && after_len == candidate_len
		    && memcmp(after, candidate, candidate_len) == 0 && signable(key, candidate, candidate_len);
	}
done:
	dssh_test_reset_global_config();
	printf("key-validation transaction: result=%d valid=%u\n", result, valid ? 1U : 0U);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static struct dssh_test_entry tests[] = {
	{"transaction", test_transaction},
};
DSSH_TEST_NO_CLEANUP
DSSH_TEST_MAIN(tests)
