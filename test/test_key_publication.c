/* Real key publication transactions under every library allocation rejection. */
#include <limits.h>
#include <unistd.h>
#include "dssh_test.h"
#include "dssh_test_internal.h"
#include "dssh_test_alloc.h"
#include "dssh_test_ossl.h"
#include "deucessh-algorithms.h"

struct publication_ops {
	int (*reg)(void);
	int (*load)(const char *, dssh_pem_password_cb, void *);
	int (*save)(const char *, dssh_pem_password_cb, void *);
	int (*generate)(unsigned int);
	int64_t (*text)(char *, size_t);
	const char *name, *cache;
};
static int
ed_generate(unsigned int unused)
{
	(void)unused;
	return dssh_ed25519_generate_key();
}
static const struct publication_ops operations[] = {
	{dssh_register_ssh_ed25519, dssh_ed25519_load_key_file, dssh_ed25519_save_key_file,
	    ed_generate, dssh_ed25519_get_pub_str, "ssh-ed25519", "DSSH_TEST_ED25519_KEY"},
	{dssh_register_rsa_sha2_256, dssh_rsa_sha2_256_load_key_file, dssh_rsa_sha2_256_save_key_file,
	    dssh_rsa_sha2_256_generate_key, dssh_rsa_sha2_256_get_pub_str, "rsa-sha2-256", "DSSH_TEST_RSA_KEY"},
	{dssh_register_rsa_sha2_512, dssh_rsa_sha2_512_load_key_file, dssh_rsa_sha2_512_save_key_file,
	    dssh_rsa_sha2_512_generate_key, dssh_rsa_sha2_512_get_pub_str, "rsa-sha2-512", "DSSH_TEST_RSA_KEY"},
};
struct snapshot {
	uint8_t public[512];
	size_t public_len;
	char text[1024];
	size_t text_len;
	const uint8_t *cache;
};
struct password_state { unsigned int calls; bool valid; };
static int
password(char *buf, int capacity, int writing, void *opaque)
{
	const char phrase[] = {'p', 'u', 'b', 0, 'l', 'i', 's', 'h'};
	struct password_state *state = opaque;
	if (buf == NULL || capacity < 8 || (writing != 0 && writing != 1) || state->calls == UINT_MAX) {
		state->valid = false;
		return -1;
	}
	state->calls++;
	memcpy(buf, phrase, sizeof(phrase));
	return 8;
}
static bool
snapshot(const struct publication_ops *ops, dssh_key_algo key, struct snapshot *out)
{
	const uint8_t *blob = NULL;
	size_t length = 0;
	if (key == NULL || !key->haskey(key->ctx) || key->pubkey(&blob, &length, key->ctx) != 0
	    || blob == NULL || length == 0 || length > sizeof(out->public))
		return false;
	memcpy(out->public, blob, length);
	out->public_len = length;
	out->cache = blob;
	int64_t count = ops->text(out->text, sizeof(out->text));
	if (count < 1 || count > 1024)
		return false;
	size_t text_len = (size_t)count;
	if (out->text[text_len - 1] != 0)
		return false;
	out->text_len = text_len;
	return true;
}
static bool
same_key(const struct snapshot *a, const struct snapshot *b)
{
	return a->public_len == b->public_len && memcmp(a->public, b->public, a->public_len) == 0
	    && a->text_len == b->text_len && memcmp(a->text, b->text, a->text_len) == 0;
}
static bool
verify(dssh_key_algo key, const struct snapshot *identity, const struct dssh_bytes_result *signature)
{
	const uint8_t message[] = {'p', 'u', 'b'};
	return signature->bytes.data != NULL && signature->bytes.len != 0 && signature->lease.release != NULL
	    && key->verify(identity->public, identity->public_len, signature->bytes.data,
	        signature->bytes.len, message, sizeof(message)) == 0;
}
static int
sign(dssh_key_algo key, struct dssh_bytes_result *signature)
{
	const uint8_t message[] = {'p', 'u', 'b'};
	return key->sign(signature, message, sizeof(message), key->ctx);
}
static bool
temporary(char *path, bool *created)
{
	int fd = mkstemp(path);
	if (fd < 0)
		return false;
	*created = true;
	return close(fd) == 0;
}

/* mode0 generates; mode1 imports plain; mode2 imports encrypted PKCS8.
 * A new old-key owner is installed before every attempt, outside injection. */
static bool
family(const struct publication_ops *ops, unsigned int mode, unsigned int *failures,
    unsigned int *recoveries)
{
	char candidate_path[] = "/tmp/dssh-pub-candidate-XXXXXX";
	char old_path[] = "/tmp/dssh-pub-old-XXXXXX";
	bool a = false, b = false, valid = false, finished = false;
	struct snapshot candidate = {0}, original = {0};
	struct password_state state = {.valid = true};
	const char *cache = getenv(ops->cache);
	dssh_test_alloc_reset();
	dssh_test_key_stdio_reset();
	dssh_test_reset_global_config();
	if (cache == NULL || ops->reg() != 0 || ops->load(cache, NULL, NULL) != 0
	    || !temporary(candidate_path, &a) || !temporary(old_path, &b))
		goto done;
	dssh_key_algo key = find_key_algo(ops->name);
	if (!snapshot(ops, key, &candidate)
	    || ops->save(candidate_path, mode == 2 ? password : NULL, mode == 2 ? &state : NULL) != 0
	    || !state.valid || ops->generate(2048) != 0 || !snapshot(ops, key, &original)
	    || same_key(&candidate, &original) || ops->save(old_path, NULL, NULL) != 0)
		goto done;
	valid = true;
	for (int point = 0; valid && point < 64; point++) {
		struct dssh_bytes_result held = {0}, next = {0};
		struct snapshot before = {0}, after = {0};
		uint8_t held_copy[1024];
		if (ops->load(old_path, NULL, NULL) != 0 || !snapshot(ops, key, &before)
		    || !same_key(&before, &original) || sign(key, &held) != 0 || !verify(key, &before, &held)
		    || held.bytes.len > sizeof(held_copy)) {
			dssh_result_release(&held.lease);
			valid = false;
			break;
		}
		memcpy(held_copy, held.bytes.data, held.bytes.len);
		dssh_key_algo_ctx *prior = key->ctx;
		state = (struct password_state){.valid = true};
		dssh_test_key_stdio_reset();
		dssh_test_alloc_reset();
#ifdef DSSH_CRYPTO_BOTAN
		if (mode != 0)
			dssh_test_key_watch_read_free();
#endif
		dssh_test_alloc_fail_after(point);
		int ret = mode == 0 ? ops->generate(2048)
		    : ops->load(candidate_path, mode == 2 ? password : NULL, mode == 2 ? &state : NULL);
		int calls = dssh_test_alloc_count();
		unsigned int closes = dssh_test_key_close_calls();
		bool input_retired = true;
#ifdef DSSH_CRYPTO_BOTAN
		/* The first owned input allocation must reject before any read or
		 * password callback. A later metadata failure is not this path. */
		if (mode != 0 && point == 0)
			input_retired = dssh_test_key_read_calls() == 0 && state.calls == 0;
		if (mode != 0 && point != 0) {
			bool zero = false;
			input_retired = dssh_test_alloc_watched_free(&zero) && zero;
		}
#endif
		dssh_test_alloc_reset();
		valid = input_retired && state.valid && snapshot(ops, key, &after)
		    && closes == (mode == 0 ? 0U : 1U)
		    && verify(key, &before, &held) && memcmp(held_copy, held.bytes.data, held.bytes.len) == 0;
		if (ret < 0) {
			valid = ret == DSSH_ERROR_ALLOC && calls == point + 1 && key->ctx == prior
			    && before.cache == after.cache && same_key(&before, &after) && valid;
			if (valid)
				(*failures)++;
		}
		else {
			valid = ret == 0 && calls == point && !same_key(&before, &after)
			    && (mode == 0 || same_key(&candidate, &after)) && valid;
			valid = valid && (mode == 2 ? state.calls == 1 : state.calls == 0);
			finished = valid;
			if (valid)
				(*recoveries)++;
		}
		if (valid)
			valid = sign(key, &next) == 0 && verify(key, &after, &next)
			    && next.bytes.data != held.bytes.data && verify(key, &before, &held);
		dssh_result_release(&next.lease);
		dssh_result_release(&held.lease);
		printf("key publication: algorithm=%s mode=%u point=%d calls=%d result=%d valid=%u\n",
		    ops->name, mode, point, calls, ret, valid ? 1U : 0U);
		if (finished)
			break;
	}
	valid = valid && finished;
done:
	dssh_test_alloc_reset();
	dssh_test_key_stdio_reset();
	dssh_test_reset_global_config();
	if (a && unlink(candidate_path) != 0)
		valid = false;
	if (b && unlink(old_path) != 0)
		valid = false;
	return valid;
}
static int
run(unsigned int mode)
{
	unsigned int failures = 0, recoveries = 0;
	bool valid = true;
	for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); i++) {
		bool one = family(&operations[i], mode, &failures, &recoveries);
		valid = one && valid;
	}
	printf("key publication summary: families=3 mode=%u rejected=%u recovered=%u valid=%u\n",
	    mode, failures, recoveries, valid ? 1U : 0U);
	ASSERT_TRUE(valid && failures >= 9 && recoveries == 3);
	return TEST_PASS;
}
static int
test_generation(void)
{
	return run(0);
}
static int
test_plain(void)
{
	return run(1);
}
static int
test_encrypted(void)
{
	return run(2);
}
static struct dssh_test_entry tests[] = {
	{"generation", test_generation}, {"plain", test_plain}, {"encrypted", test_encrypted},
};
DSSH_TEST_NO_CLEANUP
DSSH_TEST_MAIN(tests)
