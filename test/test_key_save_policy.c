/* Selected direct-overwrite contract, using only private nonsensitive fixtures. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include "dssh_test.h"
#include "dssh_test_internal.h"
#include "dssh_test_alloc.h"
#include "dssh_test_ossl.h"
#include "deucessh-algorithms.h"

struct policy_ops {
	int (*reg)(void);
	int (*load)(const char *, dssh_pem_password_cb, void *);
	int (*save)(const char *, dssh_pem_password_cb, void *);
	const char *name, *cache;
};
static const struct policy_ops operations[] = {
	{dssh_register_ssh_ed25519, dssh_ed25519_load_key_file, dssh_ed25519_save_key_file,
	    "ssh-ed25519", "DSSH_TEST_ED25519_KEY"},
	{dssh_register_rsa_sha2_256, dssh_rsa_sha2_256_load_key_file, dssh_rsa_sha2_256_save_key_file,
	    "rsa-sha2-256", "DSSH_TEST_RSA_KEY"},
	{dssh_register_rsa_sha2_512, dssh_rsa_sha2_512_load_key_file, dssh_rsa_sha2_512_save_key_file,
	    "rsa-sha2-512", "DSSH_TEST_RSA_KEY"},
};
static const char marker[] = "private output policy fixture";

struct password_state {
	unsigned int calls;
	int writing;
	bool valid;
};
static int
password(char *buffer, int capacity, int writing, void *data)
{
	struct password_state *state = data;
	if (buffer == NULL || capacity < 3 || writing != state->writing || state->calls == UINT_MAX) {
		state->valid = false;
		return -1;
	}
	state->calls++;
	memcpy(buffer, "pem", 3);
	return 3;
}
static bool
join(char *out, const char *root, const char *name)
{
	int count = snprintf(out, 128, "%s/%s", root, name);
	return count > 0 && count < 128;
}
static bool
seed(const char *path)
{
	FILE *fp = fopen(path, "wb");
	if (fp == NULL)
		return false;
	bool valid = fwrite(marker, 1, sizeof(marker), fp) == sizeof(marker);
	if (fclose(fp) != 0)
		valid = false;
	return chmod(path, 0640) == 0 && valid;
}
static bool
unchanged_bytes(const char *path)
{
	FILE *fp = fopen(path, "rb");
	if (fp == NULL)
		return false;
	char observed[sizeof(marker)];
	bool valid = fread(observed, 1, sizeof(observed), fp) == sizeof(marker)
	    && memcmp(observed, marker, sizeof(marker)) == 0 && fgetc(fp) == EOF && ferror(fp) == 0;
	if (fclose(fp) != 0)
		valid = false;
	return valid;
}
static bool
same_object(const struct stat *before, const struct stat *after)
{
	return before->st_dev == after->st_dev && before->st_ino == after->st_ino
	    && before->st_mode == after->st_mode && before->st_uid == after->st_uid
	    && before->st_gid == after->st_gid && before->st_nlink == after->st_nlink
	    && before->st_size == after->st_size;
}

/* 0 existing, 1 new, 2 writable file/read-only parent, 3 native parent symlink;
 * 4 final symlink, 5 multiple links, 6 directory, 7 FIFO with peer,
 * 8 dangling final symlink, 9 FIFO without peer. Only 0..3 may succeed. */
static bool
policy_case(const struct policy_ops *ops, unsigned int kind, bool encrypted)
{
	char root[] = "/tmp/dssh-save-policy-XXXXXX";
	char actual[128] = {0}, alias[128] = {0}, inner[128] = {0}, chosen[128] = {0};
	bool created = false, alias_created = false, inner_created = false, had_target = false;
	bool valid = false, retired = false;
	int peer = -1, status = DSSH_ERROR_INIT;
	struct stat before, after, alias_before, alias_after;
	struct dssh_test_key_open_report report = {0};
	struct dssh_test_key_stream_report stream = {0};
	struct dssh_bytes_result held = {0}, next = {0};
	uint8_t public[512], held_copy[1024];
	size_t public_length = 0;
	struct password_state pw = {.writing = 1, .valid = true};
	const char *cache = getenv(ops->cache);
	dssh_test_key_stdio_reset();
	dssh_test_alloc_reset();
	dssh_test_reset_global_config();
	if (cache == NULL || ops->reg() != 0 || ops->load(cache, NULL, NULL) != 0 || mkdtemp(root) == NULL)
		goto done;
	created = true;
	if (!join(actual, root, "key") || !join(alias, root, "selected") || !join(inner, root, "inner"))
		goto done;
	const char *path = actual;
	if (kind == 3) {
		if (mkdir(inner, 0700) != 0)
			goto done;
		inner_created = true;
		if (!join(actual, inner, "key") || !join(chosen, alias, "key") || symlink("inner", alias) != 0)
			goto done;
		alias_created = true;
		path = chosen;
	}
	if (kind == 6) {
		if (mkdir(actual, 0750) != 0)
			goto done;
	}
	else if (kind == 7 || kind == 9) {
		if (mkfifo(actual, 0640) != 0 || chmod(actual, 0640) != 0)
			goto done;
		if (kind == 7) {
			peer = open(actual, O_RDWR | O_NONBLOCK);
			if (peer < 0)
				goto done;
		}
	}
	else if (kind != 1 && kind != 8 && !seed(actual))
		goto done;
	if (kind == 4 || kind == 8) {
		if (symlink("key", alias) != 0)
			goto done;
		alias_created = true;
		path = alias;
	}
	else if (kind == 5) {
		if (link(actual, alias) != 0)
			goto done;
		alias_created = true;
		path = alias;
	}
	if (kind == 2 && chmod(root, 0500) != 0)
		goto done;
	had_target = kind != 1 && kind != 8;
	if ((had_target && lstat(actual, &before) != 0)
	    || (alias_created && lstat(alias, &alias_before) != 0))
		goto done;
	dssh_key_algo key = find_key_algo(ops->name);
	dssh_key_algo_ctx *prior = key->ctx;
	const uint8_t *blob = NULL;
	if (key->pubkey(&blob, &public_length, prior) != 0 || blob == NULL
	    || public_length == 0 || public_length > sizeof(public))
		goto done;
	memcpy(public, blob, public_length);
	const uint8_t message[] = {'p', 'o', 'l', 'i', 'c', 'y'};
	if (key->sign(&held, message, sizeof(message), prior) != 0 || held.bytes.data == NULL
	    || held.bytes.len == 0 || held.bytes.len > sizeof(held_copy) || held.lease.release == NULL)
		goto done;
	memcpy(held_copy, held.bytes.data, held.bytes.len);
	dssh_test_key_stdio_reset();
	dssh_test_key_watch_stream();
	status = ops->save(path, encrypted ? password : NULL, &pw);
	report = dssh_test_key_open_report();
	stream = dssh_test_key_stream_report();
	if (kind >= 4 && report.target_checks != 0)
		retired = dssh_test_key_failed_fd_closed();
	bool accepted = kind < 4;
	bool acquired_rejection = kind == 5 || kind == 7;
	valid = status == (accepted ? 0 : DSSH_ERROR_INIT) && pw.valid
	    && pw.calls == (accepted && encrypted ? 1U : 0U)
	    && report.native_opens == 1 && report.stdio_opens == 0
	    && report.target_checks == (accepted || acquired_rejection ? 1U : 0U)
	    && report.status_updates == (accepted ? 1U : 0U)
	    && report.permissions == (accepted ? 1U : 0U) && report.truncations == (accepted ? 1U : 0U)
	    && report.associations == (accepted ? 1U : 0U)
	    && report.raw_closes == (acquired_rejection ? 1U : 0U)
	    && (!acquired_rejection || retired)
	    && (!accepted || (report.descriptor_valid && report.close_on_exec && report.blocking_io && report.status_arguments_valid))
	    && stream.valid && !stream.active && stream.configurations == (accepted ? 1U : 0U)
	    && stream.closes == (accepted ? 1U : 0U) && stream.clears == (accepted ? 1U : 0U);
	dssh_test_key_stdio_reset();
	const uint8_t *current = NULL;
	size_t current_length = 0;
	valid = valid && key->ctx == prior && key->pubkey(&current, &current_length, prior) == 0
	    && current == blob && current_length == public_length && memcmp(current, public, public_length) == 0
	    && memcmp(held_copy, held.bytes.data, held.bytes.len) == 0
	    && key->verify(public, public_length, held.bytes.data, held.bytes.len, message, sizeof(message)) == 0;
	if (valid)
		valid = key->sign(&next, message, sizeof(message), prior) == 0 && next.bytes.data != NULL
		    && next.bytes.len != 0 && next.lease.release != NULL && next.bytes.data != held.bytes.data
		    && key->verify(public, public_length, next.bytes.data, next.bytes.len, message, sizeof(message)) == 0;
	if (valid && alias_created)
		valid = lstat(alias, &alias_after) == 0 && same_object(&alias_before, &alias_after);
	if (valid && accepted) {
		valid = stat(actual, &after) == 0 && S_ISREG(after.st_mode) && after.st_uid == geteuid()
		    && after.st_nlink == 1 && (after.st_mode & 0777) == 0600 && after.st_size > 0
		    && (!had_target || (before.st_dev == after.st_dev && before.st_ino == after.st_ino));
		pw = (struct password_state){.writing = 0, .valid = true};
		valid = valid && ops->load(path, encrypted ? password : NULL, &pw) == 0 && pw.valid
		    && pw.calls == (encrypted ? 1U : 0U)
		    && key->pubkey(&current, &current_length, key->ctx) == 0 && current_length == public_length
		    && memcmp(current, public, public_length) == 0
		    && memcmp(held_copy, held.bytes.data, held.bytes.len) == 0
		    && key->verify(public, public_length, held.bytes.data, held.bytes.len, message, sizeof(message)) == 0;
	}
	else if (valid && had_target) {
		valid = lstat(actual, &after) == 0 && same_object(&before, &after)
		    && (!S_ISREG(before.st_mode) || unchanged_bytes(actual));
		if (valid && peer >= 0) {
			char byte;
			errno = 0;
			valid = read(peer, &byte, 1) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK);
		}
	}
	else if (valid) {
		errno = 0;
		valid = lstat(actual, &after) == -1 && errno == ENOENT;
	}
done:
	dssh_result_release(&next.lease);
	dssh_result_release(&held.lease);
	dssh_test_key_stdio_reset();
	dssh_test_alloc_reset();
	dssh_test_reset_global_config();
	if (peer >= 0 && close(peer) != 0)
		valid = false;
	if (created) {
		if (chmod(root, 0700) != 0)
			valid = false;
		if (alias_created && unlink(alias) != 0)
			valid = false;
		if (actual[0] != 0) {
			struct stat cleanup;
			if (lstat(actual, &cleanup) == 0) {
				if ((S_ISDIR(cleanup.st_mode) ? rmdir(actual) : unlink(actual)) != 0)
					valid = false;
			}
			else if (errno != ENOENT)
				valid = false;
		}
		if (inner_created && rmdir(inner) != 0)
			valid = false;
		if (rmdir(root) != 0)
			valid = false;
	}
	printf("key save policy: algorithm=%s kind=%u encrypted=%u status=%d targets=%u flags=%u chmod=%u truncate=%u "
	    "associations=%u raw-close=%u retired=%u configured=%u closed=%u cleared=%u valid=%u\n",
	    ops->name, kind, encrypted ? 1U : 0U, status, report.target_checks, report.status_updates,
	    report.permissions, report.truncations, report.associations, report.raw_closes, retired ? 1U : 0U,
	    stream.configurations, stream.closes, stream.clears, valid ? 1U : 0U);
	return valid;
}
static int
cases(unsigned int first, unsigned int last, bool both)
{
	unsigned int completed = 0;
	for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); i++) {
		for (unsigned int kind = first; kind <= last; kind++) {
			for (unsigned int encrypted = both ? 0U : 1U; encrypted < 2; encrypted++) {
				if (policy_case(&operations[i], kind, encrypted != 0))
					completed++;
			}
		}
	}
	unsigned int expected = first == 0 ? 24U : first == 4 ? 15U : 3U;
	printf("key save policy summary: first=%u last=%u expected=%u completed=%u\n", first, last, expected, completed);
	ASSERT_EQ(completed, expected);
	return TEST_PASS;
}
static int
test_identity(void)
{
	return cases(0, 3, true);
}
static int
test_rejected(void)
{
	return cases(4, 8, false);
}
static int
test_nonblocking(void)
{
	return cases(9, 9, false);
}
static struct dssh_test_entry tests[] = {
	{"identity", test_identity},
	{"rejected", test_rejected},
	{"nonblocking", test_nonblocking},
};
DSSH_TEST_NO_CLEANUP
DSSH_TEST_MAIN(tests)
