/* Exercise the actual POSIX example against production libraries. Native I/O
 * faults are local to the included application; library calls are not wrapped. */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include "deucessh.h"
#include "deucessh-algorithms.h"
#include "deucessh-auth.h"
#include "deucessh-conn.h"
#include "dssh_test.h"

struct example_io {
	bool enabled;
	bool interrupt;
	short events;
	unsigned polls, sends, receives, writes;
	int transfer_errno, write_errno;
	bool zero_transfer, zero_write;
	uint8_t bytes[64];
	size_t length, offset;
};
static struct example_io io;
static bool deny_resolution;
static unsigned resolutions;

static int example_poll(struct pollfd *, nfds_t, int);
static ssize_t example_send(int, const void *, size_t, int);
static ssize_t example_recv(int, void *, size_t, int);
static ssize_t example_write(int, const void *, size_t);
static int example_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);

#define main client_example_main
#define poll example_poll
#define send example_send
#define recv example_recv
#define write example_write
#define getaddrinfo example_getaddrinfo
#include "../examples/client.c"
#undef getaddrinfo
#undef write
#undef recv
#undef send
#undef poll
#undef main

static int
example_poll(struct pollfd *fds, nfds_t count, int timeout)
{
	if (!io.enabled)
		return poll(fds, count, timeout);
	io.polls++;
	if (io.interrupt) {
		io.interrupt = false;
		errno = EINTR;
		return -1;
	}
	if (count != 1 || fds[0].fd != sock) {
		errno = EINVAL;
		return -1;
	}
	fds[0].revents = io.events;
	return 1;
}

static ssize_t
example_send(int fd, const void *buf, size_t length, int flags)
{
	if (!io.enabled)
		return send(fd, buf, length, flags);
	io.sends++;
	if (io.transfer_errno != 0) {
		errno = io.transfer_errno;
		io.transfer_errno = 0;
		return -1;
	}
	if (io.zero_transfer)
		return 0;
	if (fd != sock || length > sizeof(io.bytes) - io.length) {
		errno = EIO;
		return -1;
	}
	/* Force successful short writes; the application must retain the suffix. */
	size_t count = length > 3 ? 3 : length;
	memcpy(&io.bytes[io.length], buf, count);
	io.length += count;
	ssize_t result = (ssize_t)count;
	return result;
}

static ssize_t
example_recv(int fd, void *buf, size_t length, int flags)
{
	if (!io.enabled)
		return recv(fd, buf, length, flags);
	io.receives++;
	if (io.transfer_errno != 0) {
		errno = io.transfer_errno;
		io.transfer_errno = 0;
		return -1;
	}
	if (io.zero_transfer)
		return 0;
	if (fd != sock || io.offset > io.length) {
		errno = EIO;
		return -1;
	}
	size_t remaining = io.length - io.offset;
	size_t count = length < remaining ? length : remaining;
	if (count > 3)
		count = 3;
	if (count > 0)
		memcpy(buf, &io.bytes[io.offset], count);
	io.offset += count;
	ssize_t result = (ssize_t)count;
	return result;
}

static ssize_t
example_write(int fd, const void *buf, size_t length)
{
	if (!io.enabled)
		return write(fd, buf, length);
	io.writes++;
	if (io.write_errno != 0) {
		errno = io.write_errno;
		io.write_errno = 0;
		return -1;
	}
	if (io.zero_write)
		return 0;
	if (fd != sock || io.length > sizeof(io.bytes) || length > sizeof(io.bytes) - io.length) {
		errno = EIO;
		return -1;
	}
	size_t count = length > 3 ? 3 : length;
	memcpy(&io.bytes[io.length], buf, count);
	io.length += count;
	ssize_t result = (ssize_t)count;
	return result;
}

static int
example_getaddrinfo(const char *host, const char *port, const struct addrinfo *hints,
    struct addrinfo **result)
{
	if (!deny_resolution)
		return getaddrinfo(host, port, hints, result);
	resolutions++;
	*result = NULL;
	return EAI_FAIL;
}

static int
begin_io(short events)
{
	io = (struct example_io){ .enabled = true, .events = events };
	sock = 17; /* Never used by a native syscall while io.enabled is true. */
	sess = dssh_session_init(true, 0);
	return sess != NULL ? 0 : -1;
}

static void
end_io(void)
{
	dssh_session_cleanup(sess);
	sess = NULL;
	sock = -1;
	io.enabled = false;
}

static int
test_host_pin(void)
{
	static const char matching[] = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	static const char different[] = "SHA256:BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	uint8_t hash[32] = {0};
	uint8_t blob = 1;
	/* These are callback-format controls; native peer tests supply real keys. */
	void *matching_data = (void *)matching;
	void *different_data = (void *)different;
	dssh_hostkey_decision accepted = verify_hostkey("ssh-ed25519", 256, hash, &blob, 1, matching_data);
	dssh_hostkey_decision rejected = verify_hostkey("rsa-sha2-256", 2048, hash, &blob, 1, different_data);
	dssh_hostkey_decision missing = verify_hostkey("rsa-sha2-512", 2048, hash, &blob, 1, NULL);
	ASSERT_EQ(accepted, DSSH_HOSTKEY_ACCEPT);
	ASSERT_EQ(rejected, DSSH_HOSTKEY_REJECT);
	ASSERT_EQ(missing, DSSH_HOSTKEY_REJECT);
	return TEST_PASS;
}

static int
test_tx_interruption(void)
{
	ASSERT_OK(begin_io(POLLOUT));
	io.interrupt = true;
	uint8_t bytes[] = {1, 2, 3, 4, 5, 6, 7};
	int ret = tx(bytes, sizeof(bytes), sess, NULL);
	bool valid = ret == 0 && io.polls == 4 && io.sends == 3
	    && io.length == sizeof(bytes) && memcmp(io.bytes, bytes, sizeof(bytes)) == 0;
	end_io();
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_rx_interruption(void)
{
	ASSERT_OK(begin_io(POLLIN));
	io.interrupt = true;
	io.length = 7;
	for (size_t i = 0; i < io.length; i++)
		io.bytes[i] = (uint8_t)i;
	uint8_t bytes[7];
	int ret = rx(bytes, sizeof(bytes), sess, NULL);
	bool valid = ret == 0 && io.polls == 4 && io.receives == 3
	    && io.offset == sizeof(bytes) && memcmp(io.bytes, bytes, sizeof(bytes)) == 0;
	end_io();
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_empty_line_buffer(void)
{
	ASSERT_OK(begin_io(POLLIN));
	io.bytes[0] = 'x';
	io.length = 1;
	uint8_t guard = 0xa5;
	size_t received = 0;
	int ret = rxline(&guard, 0, &received, sess, NULL);
	bool valid = ret == DSSH_ERROR_INVALID && guard == 0xa5 && received == 0
	    && io.polls == 0 && io.receives == 0;
	end_io();
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_invalid_poll_descriptor(void)
{
	ASSERT_OK(begin_io(POLLNVAL));
	uint8_t byte = 1;
	int ret = tx(&byte, 1, sess, NULL);
	bool valid = ret == DSSH_ERROR_INIT && io.polls == 1 && io.sends == 0;
	io.polls = 0;
	ret = rx(&byte, 1, sess, NULL);
	valid = valid && ret == DSSH_ERROR_INIT && io.polls == 1 && io.receives == 0;
	end_io();
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

/* Fixed vectors were independently generated with Python's standard base64
 * encoder for 31 zero bytes followed by values 0..15. */
static int
test_fingerprint_classes(void)
{
	static const char *const vectors[] = {
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAc",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAk",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAo",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAs",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8",
	};
	bool valid = true;
	uint8_t hash[32] = {0}, blob = 1;
	for (size_t i = 0; i < 16; i++) {
		uint8_t tail = (uint8_t)i;
		hash[31] = tail;
		void *pin = (void *)vectors[i];
		valid = valid_fingerprint(vectors[i]) && valid;
		valid = verify_hostkey("ssh-ed25519", 256, hash, &blob, 1, pin) == DSSH_HOSTKEY_ACCEPT && valid;
		char noncanonical[51];
		memcpy(noncanonical, vectors[i], sizeof(noncanonical));
		noncanonical[49]++;
		valid = !valid_fingerprint(noncanonical) && valid;
	}
	static const char *const rejected[] = {"", "SHA1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	    "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	    "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-",
	    "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"};
	for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++)
		valid = !valid_fingerprint(rejected[i]) && valid;
	void *pin = (void *)vectors[0];
	valid = !valid_fingerprint(NULL) && valid;
	valid = verify_hostkey(NULL, 256, hash, &blob, 1, pin) == DSSH_HOSTKEY_REJECT && valid;
	valid = verify_hostkey("ssh-ed25519", 256, NULL, &blob, 1, pin) == DSSH_HOSTKEY_REJECT && valid;
	valid = verify_hostkey("ssh-ed25519", 256, hash, NULL, 1, pin) == DSSH_HOSTKEY_REJECT && valid;
	valid = verify_hostkey("ssh-ed25519", 256, hash, &blob, 0, pin) == DSSH_HOSTKEY_REJECT && valid;
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_port_values(void)
{
	static const struct { const char *text; unsigned expected; } good[] = {
		{"1", 1}, {"22", 22}, {"00022", 22}, {"65535", 65535},
	};
	bool valid = true;
	for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
		uint16_t port = 0;
		valid = parse_port(good[i].text, &port) == 0 && port == good[i].expected && valid;
	}
	static const char *const bad[] = {NULL, "", "0", "65536", "99999999999999999999999",
	    "-1", "+22", " 22", "22 ", "22x"};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		uint16_t port = 123;
		valid = parse_port(bad[i], &port) != 0 && port == 123 && valid;
	}
	valid = parse_port("22", NULL) != 0 && valid;
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_method_tokens(void)
{
	ASSERT_TRUE(offered_method("publickey,password,keyboard-interactive", "password"));
	ASSERT_TRUE(offered_method("publickey,password,keyboard-interactive", "keyboard-interactive"));
	ASSERT_TRUE(offered_method("password", "password"));
	ASSERT_FALSE(offered_method("notpassword,password2", "password"));
	ASSERT_FALSE(offered_method("keyboard-interactive-other", "keyboard-interactive"));
	ASSERT_FALSE(offered_method("", "password"));
	ASSERT_FALSE(offered_method(",,,", "password"));
	return TEST_PASS;
}

static int
test_argument_validation(void)
{
	char pin[] = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	char *args[] = {"client", pin, "audit", "password", "127.0.0.1", "22", "cmd", NULL};
	deny_resolution = true;
	bool valid = true;
	const int bad_counts[] = {0, 1, 2, 3, 8};
	for (size_t i = 0; i < sizeof(bad_counts) / sizeof(bad_counts[0]); i++) {
		resolutions = 0;
		valid = client_example_main(bad_counts[i], args) == 1 && resolutions == 0 && valid;
	}
	resolutions = 0;
	args[1] = "bad";
	valid = client_example_main(7, args) == 1 && resolutions == 0 && valid;
	args[1] = pin;
	args[2] = "";
	valid = client_example_main(7, args) == 1 && resolutions == 0 && valid;
	args[2] = "audit";
	args[4] = "";
	valid = client_example_main(7, args) == 1 && resolutions == 0 && valid;
	args[4] = "127.0.0.1";
	static const char *const bad_ports[] = {"0", "65536", "-1", "+22", "22x", ""};
	for (size_t i = 0; i < sizeof(bad_ports) / sizeof(bad_ports[0]); i++) {
		char *text = (char *)bad_ports[i];
		args[5] = text;
		valid = client_example_main(7, args) == 1 && resolutions == 0 && valid;
	}
	args[5] = "65535";
	/* Valid syntax reaches the explicitly refused resolver, without network I/O. */
	valid = client_example_main(7, args) == 1 && resolutions == 1 && valid;
	resolutions = 0;
	valid = client_example_main(4, args) == 1 && resolutions == 1 && valid;
	deny_resolution = false;
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_output_transfers(void)
{
	const uint8_t bytes[] = {1, 2, 3, 4, 5, 6, 7};
	const int errors[] = {0, EINTR, EAGAIN, EIO};
	for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		ASSERT_OK(begin_io(POLLOUT));
		io.write_errno = errors[i];
		int ret = write_output(sock, bytes, sizeof(bytes));
		bool valid = errors[i] == EIO ? ret != 0 && io.length == 0 && io.writes == 1
		    : ret == 0 && io.length == sizeof(bytes) && memcmp(io.bytes, bytes, sizeof(bytes)) == 0;
		valid = valid && io.polls == (errors[i] == EAGAIN ? 1U : 0U);
		end_io();
		ASSERT_TRUE(valid);
	}
	ASSERT_OK(begin_io(POLLOUT));
	io.zero_write = true;
	int ret = write_output(sock, bytes, sizeof(bytes));
	bool valid = ret != 0 && io.writes == 1 && io.length == 0;
	end_io();
	ASSERT_TRUE(valid);
	ASSERT_OK(begin_io(POLLNVAL));
	io.write_errno = EAGAIN;
	ret = write_output(sock, bytes, sizeof(bytes));
	valid = ret != 0 && io.writes == 1 && io.polls == 1 && io.length == 0;
	end_io();
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_native_transfer_errors(void)
{
	const int errors[] = {EINTR, EAGAIN, EIO};
	for (unsigned receiving = 0; receiving < 2; receiving++) {
		for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
			ASSERT_OK(begin_io(receiving != 0 ? POLLIN : POLLOUT));
			io.transfer_errno = errors[i];
			uint8_t bytes[7] = {1, 2, 3, 4, 5, 6, 7};
			if (receiving != 0) {
				memcpy(io.bytes, bytes, sizeof(bytes));
				io.length = sizeof(bytes);
			}
			int ret = receiving != 0 ? rx(bytes, sizeof(bytes), sess, NULL) : tx(bytes, sizeof(bytes), sess, NULL);
			bool valid = errors[i] == EIO ? ret == DSSH_ERROR_INIT : ret == 0;
			valid = valid && (errors[i] == EIO || memcmp(io.bytes, bytes, sizeof(bytes)) == 0);
			end_io();
			ASSERT_TRUE(valid);
		}
		ASSERT_OK(begin_io(receiving != 0 ? POLLIN : POLLOUT));
		io.zero_transfer = true;
		uint8_t byte = 1;
		int ret = receiving != 0 ? rx(&byte, 1, sess, NULL) : tx(&byte, 1, sess, NULL);
		end_io();
		ASSERT_EQ(ret, DSSH_ERROR_INIT);
	}
	return TEST_PASS;
}

static int
test_line_framing(void)
{
	static const uint8_t input[] = "a\rx\nb\r\n";
	for (size_t capacity = sizeof(input) - 2; capacity < sizeof(input); capacity++) {
		ASSERT_OK(begin_io(POLLIN));
		memcpy(io.bytes, input, sizeof(input) - 1);
		io.length = sizeof(input) - 1;
		uint8_t bytes[9];
		memset(bytes, 0xa5, sizeof(bytes));
		size_t received = 0;
		int ret = rxline(bytes, capacity, &received, sess, NULL);
		bool complete = capacity == sizeof(input) - 1;
		bool valid = bytes[capacity] == 0xa5 && (complete
		    ? ret == 0 && received == sizeof(input) - 1 && memcmp(bytes, input, received) == 0
		    : ret == DSSH_ERROR_TOOLONG && received == 0);
		end_io();
		ASSERT_TRUE(valid);
	}
	return TEST_PASS;
}

static int
test_termination(void)
{
	ASSERT_OK(begin_io(POLLIN));
	bool valid = dssh_session_terminate(sess);
	uint8_t byte = 1;
	valid = tx(&byte, 1, sess, NULL) == DSSH_ERROR_TERMINATED && valid;
	valid = rx(&byte, 1, sess, NULL) == DSSH_ERROR_TERMINATED && valid;
	valid = tx(NULL, 0, sess, NULL) == 0 && rx(NULL, 0, sess, NULL) == 0 && valid;
	valid = io.polls == 0 && io.sends == 0 && io.receives == 0 && valid;
	end_io();
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static int
test_invalid_callback_spans(void)
{
	ASSERT_OK(begin_io(POLLIN));
	uint8_t byte = 1;
	size_t received = 0;
	bool valid = tx(NULL, 1, sess, NULL) == DSSH_ERROR_INVALID;
	valid = rx(NULL, 1, sess, NULL) == DSSH_ERROR_INVALID && valid;
	valid = tx(&byte, 1, NULL, NULL) == DSSH_ERROR_INVALID && valid;
	valid = rx(&byte, 1, NULL, NULL) == DSSH_ERROR_INVALID && valid;
	valid = rxline(NULL, 1, &received, sess, NULL) == DSSH_ERROR_INVALID && valid;
	valid = rxline(&byte, 1, NULL, sess, NULL) == DSSH_ERROR_INVALID && valid;
	valid = io.polls == 0 && io.sends == 0 && io.receives == 0 && valid;
	end_io();
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

static const struct dssh_test_entry tests[] = {
	{"client/host_pin", test_host_pin},
	{"client/tx_interruption", test_tx_interruption},
	{"client/rx_interruption", test_rx_interruption},
	{"client/empty_line_buffer", test_empty_line_buffer},
	{"client/invalid_poll_descriptor", test_invalid_poll_descriptor},
	{"client/fingerprint_classes", test_fingerprint_classes},
	{"client/port_values", test_port_values},
	{"client/method_tokens", test_method_tokens},
	{"client/argument_validation", test_argument_validation},
	{"client/output_transfers", test_output_transfers},
	{"client/native_transfer_errors", test_native_transfer_errors},
	{"client/line_framing", test_line_framing},
	{"client/termination", test_termination},
	{"client/invalid_callback_spans", test_invalid_callback_spans},
};
void
dssh_test_failure_cleanup(void)
{
	if (sess != NULL)
		end_io();
	deny_resolution = false;
}

#define main component_main
DSSH_TEST_MAIN(tests)
#undef main

int
main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "--run-client") == 0)
		return client_example_main(argc - 1, &argv[1]);
	return component_main(argc, argv);
}
