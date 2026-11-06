/* Real native descriptor properties and public key-file entry validation. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "dssh_test.h"
#include "dssh_test_internal.h"
#include "dssh_test_alloc.h"
#include "dssh_test_ossl.h"
#include "deucessh-algorithms.h"

struct descriptor_ops {
	int (*reg)(void);
	int (*load)(const char *, dssh_pem_password_cb, void *);
	int (*save)(const char *, dssh_pem_password_cb, void *);
	int (*public_save)(const char *);
	const char *name, *cache;
};
static const struct descriptor_ops operations[] = {
	{dssh_register_ssh_ed25519, dssh_ed25519_load_key_file, dssh_ed25519_save_key_file,
	    dssh_ed25519_save_pub_file, "ssh-ed25519", "DSSH_TEST_ED25519_KEY"},
	{dssh_register_rsa_sha2_256, dssh_rsa_sha2_256_load_key_file, dssh_rsa_sha2_256_save_key_file,
	    dssh_rsa_sha2_256_save_pub_file, "rsa-sha2-256", "DSSH_TEST_RSA_KEY"},
	{dssh_register_rsa_sha2_512, dssh_rsa_sha2_512_load_key_file, dssh_rsa_sha2_512_save_key_file,
	    dssh_rsa_sha2_512_save_pub_file, "rsa-sha2-512", "DSSH_TEST_RSA_KEY"},
};

/* kind0 normal property, kind1 NULL, kind2 empty, kind3 rejected fdopen,
 * kind4 actual missing-parent open error. Never inspect a native object layout. */
static bool
file_case(const struct descriptor_ops *ops, unsigned int action, unsigned int kind)
{
	char output[] = "/tmp/dssh-fd-output-XXXXXX";
	char absent[] = "/tmp/dssh-fd-absent-XXXXXX";
	char missing[128];
	bool output_created = false, directory_created = false, valid = false;
	struct dssh_bytes_result held = {0}, next = {0};
	uint8_t public[512], held_copy[1024];
	size_t public_length = 0;
	struct dssh_test_key_open_report report = {0};
	bool closed = false;
	int status = DSSH_ERROR_INIT;
	const char *cache = getenv(ops->cache);
	dssh_test_alloc_reset();
	dssh_test_key_stdio_reset();
	dssh_test_reset_global_config();
	if (cache == NULL || ops->reg() != 0 || ops->load(cache, NULL, NULL) != 0)
		goto done;
	int fd = mkstemp(output);
	if (fd < 0)
		goto done;
	output_created = true;
	if (close(fd) != 0 || mkdtemp(absent) == NULL)
		goto done;
	directory_created = true;
	if (rmdir(absent) != 0)
		goto done;
	directory_created = false;
	int count = snprintf(missing, sizeof(missing), "%s/key", absent);
	if (count < 1 || count >= 128)
		goto done;
	dssh_key_algo key = find_key_algo(ops->name);
	dssh_key_algo_ctx *prior = key->ctx;
	const uint8_t *blob = NULL;
	if (key->pubkey(&blob, &public_length, prior) != 0 || blob == NULL
	    || public_length == 0 || public_length > sizeof(public))
		goto done;
	memcpy(public, blob, public_length);
	const uint8_t message[] = {'f', 'i', 'l', 'e'};
	if (key->sign(&held, message, sizeof(message), prior) != 0 || held.bytes.data == NULL
	    || held.bytes.len == 0 || held.bytes.len > sizeof(held_copy) || held.lease.release == NULL)
		goto done;
	memcpy(held_copy, held.bytes.data, held.bytes.len);
	const char *path = action == 0 ? cache : output;
	if (kind == 1)
		path = NULL;
	else if (kind == 2)
		path = "";
	else if (kind == 4)
		path = missing;
	dssh_test_key_stdio_reset();
	if (kind == 3)
		dssh_test_key_fdopen_error_once();
	status = action == 0 ? ops->load(path, NULL, NULL)
	    : action == 1 ? ops->save(path, NULL, NULL) : ops->public_save(path);
	report = dssh_test_key_open_report();
	if (kind == 3)
		closed = dssh_test_key_failed_fd_closed();
	unsigned int calls = report.stdio_opens + report.native_opens;
	valid = status == (kind == 0 ? 0 : DSSH_ERROR_INIT)
	    && (kind == 0 ? report.descriptor_valid && report.close_on_exec && calls == 1
	        : kind == 1 || kind == 2 ? calls == 0 && report.associations == 0
	        : kind == 3 ? report.rejected_associations == 1 && closed
	        : calls == 1 && report.associations == 0 && !report.descriptor_valid)
	    && (kind == 3 || report.rejected_associations == 0);
	const uint8_t *after = NULL;
	size_t after_length = 0;
	valid = valid && key->pubkey(&after, &after_length, key->ctx) == 0 && after_length == public_length
	    && after != NULL && memcmp(after, public, public_length) == 0
	    && ((kind == 0 && action == 0) || (key->ctx == prior && after == blob))
	    && memcmp(held_copy, held.bytes.data, held.bytes.len) == 0
	    && key->verify(public, public_length, held.bytes.data, held.bytes.len, message, sizeof(message)) == 0;
	if (valid)
		valid = key->sign(&next, message, sizeof(message), key->ctx) == 0
		    && next.bytes.data != NULL && next.bytes.len != 0 && next.lease.release != NULL
		    && next.bytes.data != held.bytes.data
		    && key->verify(public, public_length, next.bytes.data, next.bytes.len, message, sizeof(message)) == 0;
	if (valid && kind == 0 && action != 0) {
		struct stat info;
		valid = stat(output, &info) == 0 && info.st_size > 0;
	}
done:
	dssh_result_release(&next.lease);
	dssh_result_release(&held.lease);
	dssh_test_key_stdio_reset();
	dssh_test_alloc_reset();
	dssh_test_reset_global_config();
	if (output_created && unlink(output) != 0)
		valid = false;
	if (directory_created && rmdir(absent) != 0)
		valid = false;
	printf("key descriptors: algorithm=%s action=%u kind=%u status=%d stdio=%u native=%u associations=%u "
	    "rejected=%u observed-valid=%u cloexec=%u retired=%u valid=%u\n", ops->name, action, kind, status,
	    report.stdio_opens, report.native_opens, report.associations, report.rejected_associations,
	    report.descriptor_valid ? 1U : 0U, report.close_on_exec ? 1U : 0U, closed ? 1U : 0U, valid ? 1U : 0U);
	return valid;
}

static int
cases(unsigned int first, unsigned int last)
{
	unsigned int completed = 0;
	for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); i++) {
		for (unsigned int action = 0; action < 3; action++) {
			for (unsigned int kind = first; kind <= last; kind++) {
				if (file_case(&operations[i], action, kind))
					completed++;
			}
		}
	}
	unsigned int expected = first == last ? 9U : 18U;
	printf("key descriptors summary: first=%u last=%u expected=%u completed=%u\n", first, last, expected, completed);
	ASSERT_EQ(completed, expected);
	return TEST_PASS;
}
static int
test_modes(void)
{
	return cases(0, 0);
}
static int
test_invalid_paths(void)
{
	return cases(1, 2);
}
static int
test_association_failure(void)
{
	return cases(3, 3);
}
static int
test_native_open_failure(void)
{
	return cases(4, 4);
}
static int
test_exec_controls(void)
{
	unsigned int completed = 0;
	for (unsigned int sealed = 0; sealed < 2; sealed++) {
		char path[] = "/tmp/dssh-fd-control-XXXXXX";
		int fd = mkstemp(path);
		if (fd < 0)
			continue;
		int flags = fcntl(fd, F_GETFD);
		int selected = sealed != 0 ? flags | FD_CLOEXEC : flags & ~FD_CLOEXEC;
		bool valid = flags >= 0 && fcntl(fd, F_SETFD, selected) == 0;
		char number[32];
		int count = snprintf(number, sizeof(number), "%d", fd);
		valid = valid && count > 0 && count < 32;
		if (valid) {
			char *args[] = {DSSH_FD_EXEC_PROBE, number, path, sealed != 0 ? "closed" : "open", NULL};
			pid_t pid = fork();
			if (pid == 0) {
				execv(DSSH_FD_EXEC_PROBE, args);
				_exit(125);
			}
			if (pid < 0)
				valid = false;
			else {
				int status;
				pid_t waited;
				do {
					waited = waitpid(pid, &status, 0);
				} while (waited < 0 && errno == EINTR);
				valid = waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
			}
		}
		if (close(fd) != 0)
			valid = false;
		if (unlink(path) != 0)
			valid = false;
		if (valid)
			completed++;
	}
	printf("key descriptors exec controls: expected=2 completed=%u\n", completed);
	ASSERT_EQ(completed, 2);
	return TEST_PASS;
}
static struct dssh_test_entry tests[] = {
	{"modes", test_modes},
	{"invalid_paths", test_invalid_paths},
	{"association_failure", test_association_failure},
	{"native_open_failure", test_native_open_failure},
	{"exec_controls", test_exec_controls},
};
DSSH_TEST_NO_CLEANUP
DSSH_TEST_MAIN(tests)
