#ifndef DSSH_TRANSPORT_IDENTIFICATION_CASES_H
#define DSSH_TRANSPORT_IDENTIFICATION_CASES_H

struct identification_io {
	uint8_t input[512];
	size_t length;
	size_t line_length;
	size_t consumed;
	unsigned tx_calls;
	unsigned line_calls;
	unsigned extra_calls;
	bool callback_input_valid;
};

static int
identification_tx(uint8_t *buf, size_t size, dssh_session sess, void *data)
{
	(void)sess;
	struct identification_io *io = data;
	io->tx_calls++;
	io->callback_input_valid = io->callback_input_valid && size >= 10 && size <= 255
	    && memcmp(buf, "SSH-2.0-", 8) == 0 && buf[size - 2] == '\r' && buf[size - 1] == '\n';
	return 0;
}

static int
identification_rx(uint8_t *buf, size_t size, dssh_session sess, void *data)
{
	(void)sess;
	struct identification_io *io = data;
	if (io->consumed > io->length || size > io->length - io->consumed)
		return DSSH_ERROR_TERMINATED;
	memcpy(buf, &io->input[io->consumed], size);
	io->consumed += size;
	return 0;
}

static int
identification_line(uint8_t *buf, size_t size, size_t *received, dssh_session sess, void *data)
{
	struct identification_io *io = data;
	io->line_calls++;
	if (io->line_length > size)
		return DSSH_ERROR_TOOLONG;
	int ret = identification_rx(buf, io->line_length, sess, data);
	if (ret == 0)
		*received = io->line_length;
	return ret;
}

static int
identification_extra(uint8_t *buf, size_t size, void *data)
{
	(void)buf;
	(void)size;
	struct identification_io *io = data;
	io->extra_calls++;
	return 0;
}

/* Exercise the actual receive operation and transcript publication. The binary
 * packet immediately after a valid line must survive either line-reader path. */
static bool
identification_case(const uint8_t *line, size_t length, bool client, bool supplied_line,
    bool accepted)
{
	struct identification_io io = { .callback_input_valid = true };
	if (length > sizeof(io.input) - 16)
		return false;
	memcpy(io.input, line, length);
	io.line_length = length;
	io.length = length + 16;
	uint8_t *packet = &io.input[length];
	memset(packet, 0, 16);
	packet[3] = 12;
	packet[4] = 10;
	packet[5] = SSH_MSG_USERAUTH_SUCCESS;
	dssh_test_reset_global_config();
	dssh_transport_rxline_cb reader = supplied_line ? identification_line : NULL;
	if (dssh_transport_set_callbacks(identification_tx, identification_rx, reader, identification_extra) < 0)
		return false;
	dssh_session sess = dssh_session_init(client, 0);
	if (sess == NULL) {
		dssh_test_reset_global_config();
		return false;
	}
	bool valid = dssh_session_set_cbdata(sess, &io, &io, &io, &io) == 0;
	int ret = valid ? version_exchange(sess) : DSSH_ERROR_INIT;
	valid = valid && io.callback_input_valid && io.tx_calls == 1 && io.extra_calls == 0;
	if (accepted) {
		valid = valid && ret == 0 && !dssh_session_is_terminated(sess)
		    && io.consumed == length && sess->trans.remote_id_str_sz == length - 2
		    && memcmp(sess->trans.remote_id_str, line, length - 2) == 0
		    && sess->trans.remote_id_str[length - 2] == 0;
		uint8_t type = 0;
		uint8_t *payload = NULL;
		size_t payload_len = 0;
		if (valid) {
			ret = recv_packet(sess, &type, &payload, &payload_len);
			valid = ret == 0 && type == SSH_MSG_USERAUTH_SUCCESS && payload_len == 1
			    && payload[0] == SSH_MSG_USERAUTH_SUCCESS && io.consumed == length + 16;
		}
	}
	else {
		valid = valid && ret < 0 && dssh_session_is_terminated(sess)
		    && sess->trans.remote_id_str_sz == 0 && sess->trans.remote_id_str[0] == 0
		    && io.consumed <= length;
	}
	if (supplied_line)
		valid = valid && io.line_calls == 1;
	dssh_session_cleanup(sess);
	dssh_test_reset_global_config();
	return valid;
}

static int
test_identification_grammar(void)
{
	static const struct {
		const char *line;
		bool accepted;
	} cases[] = {
		{ "SSH-2.0-x\r\n", true },
		{ "SSH-1.99-x\r\n", true },
		{ "SSH-2.0-MySSH-1.0\r\n", true },
		{ "SSH-2.0-x comment with spaces\r\n", true },
		{ "SSH-1.99-x compatible server\r\n", true },
		{ "SSH-2.0-x \r\n", true },
		{ "SSH-2.0-\r\n", false },
		{ "SSH-1.99-\r\n", false },
		{ "SSH-2.0- comment\r\n", false },
		{ "SSH-1.99- comment\r\n", false },
		{ "SSH-2.0-   \r\n", false },
		{ "SSH-2.0-x\tcomment\r\n", false },
		{ "SSH-2.0-x\rcomment\r\n", false },
		{ "SSH-2.0-x\ncomment\r\n", false },
		{ "SSH-2.0-x\177comment\r\n", false },
		{ "SSH-2.0-x\200comment\r\n", false },
		{ "SSH-1.0-x\r\n", false },
		{ "SSH-2.1-x\r\n", false },
		{ "SSH-2.0\r\n", false },
		{ "SSH-1.99\r\n", false },
		{ "SSH-\r\n", false },
	};
	for (unsigned client = 0; client < 2; client++) {
		for (unsigned supplied = 0; supplied < 2; supplied++) {
			for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
				const uint8_t *line = (const uint8_t *)cases[i].line;
				ASSERT_TRUE(identification_case(line, strlen(cases[i].line), client != 0,
				    supplied != 0, cases[i].accepted));
			}
		}
	}
	return TEST_PASS;
}

static int
test_identification_bytes(void)
{
	static const uint8_t bytes[] = { 0, 1, 9, 10, 13, 31, 32, 33, 45, 65, 126, 127, 128, 255 };
	for (unsigned client = 0; client < 2; client++) {
		for (unsigned supplied = 0; supplied < 2; supplied++) {
			for (size_t i = 0; i < sizeof(bytes); i++) {
				uint8_t line[] = "SSH-2.0-Xtail\r\n";
				line[8] = bytes[i];
				bool accepted = bytes[i] > 32 && bytes[i] < 127;
				ASSERT_TRUE(identification_case(line, sizeof(line) - 1, client != 0,
				    supplied != 0, accepted));
			}
		}
	}
	return TEST_PASS;
}

static int
test_identification_bounds(void)
{
	static const char *prefixes[] = { "SSH-2.0-", "SSH-1.99-" };
	for (unsigned client = 0; client < 2; client++) {
		for (unsigned supplied = 0; supplied < 2; supplied++) {
			for (size_t p = 0; p < sizeof(prefixes) / sizeof(prefixes[0]); p++) {
				for (size_t length = 254; length <= 256; length++) {
					uint8_t line[256];
					memset(line, 'x', sizeof(line));
					memcpy(line, prefixes[p], strlen(prefixes[p]));
					line[length - 2] = '\r';
					line[length - 1] = '\n';
					ASSERT_TRUE(identification_case(line, length, client != 0,
					    supplied != 0, length <= 255));
					line[strlen(prefixes[p]) + 1] = ' ';
					ASSERT_TRUE(identification_case(line, length, client != 0,
					    supplied != 0, length <= 255));
				}
			}
		}
	}
	return TEST_PASS;
}

#endif
