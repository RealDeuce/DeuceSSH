/* Current-contract observations, invoked only by --audit-auth-boundaries.
 * These are not desired-behavior regressions or authentication policy. */
struct auth_boundary_observer {
	unsigned calls;
	unsigned releases;
	unsigned identities[3];
	bool zero_shapes[3];
	bool valid;
};

static unsigned
auth_boundary_identity(const uint8_t *username, size_t length)
{
	if (length == 5 && memcmp(username, "alpha", 5) == 0)
		return 1;
	if (length == 4 && memcmp(username, "beta", 4) == 0)
		return 2;
	return 0;
}

static int
auth_boundary_none(const uint8_t *username, size_t length, void *opaque)
{
	struct auth_boundary_observer *observer = opaque;
	if (observer->calls >= 3) {
		observer->valid = false;
		return DSSH_AUTH_DISCONNECT;
	}
	observer->identities[observer->calls++] = auth_boundary_identity(username, length);
	return DSSH_AUTH_FAILURE;
}

static void
auth_boundary_release(void *opaque)
{
	struct auth_boundary_observer *observer = opaque;
	observer->releases++;
}

static int
auth_boundary_kbi(const uint8_t *username, size_t length, uint32_t count,
    const uint8_t **responses, const size_t *lengths, struct dssh_auth_challenge *out, void *opaque)
{
	struct auth_boundary_observer *observer = opaque;
	if (observer->calls >= 3) {
		observer->valid = false;
		return DSSH_AUTH_DISCONNECT;
	}
	unsigned index = observer->calls++;
	observer->identities[index] = auth_boundary_identity(username, length);
	observer->zero_shapes[index] = count == 0 && responses == NULL && lengths == NULL;
	out->lease.owner = observer;
	out->lease.release = auth_boundary_release;
	/* An empty challenge is valid and still requires a response. */
	return DSSH_AUTH_KBI_PROMPT;
}

static int
auth_boundary_request(dssh_session client, const char *username, const char *method)
{
	uint8_t packet[128];
	size_t pos = 1;
	packet[0] = SSH_MSG_USERAUTH_REQUEST;
	if (!auth_frame_string(packet, sizeof(packet), &pos, username, strlen(username))
	    || !auth_frame_string(packet, sizeof(packet), &pos, "ssh-connection", 14)
	    || !auth_frame_string(packet, sizeof(packet), &pos, method, strlen(method)))
		return DSSH_ERROR_INVALID;
	if (strcmp(method, "keyboard-interactive") == 0
	    && (!auth_frame_string(packet, sizeof(packet), &pos, "", 0)
	    || !auth_frame_string(packet, sizeof(packet), &pos, "", 0)))
		return DSSH_ERROR_INVALID;
	return send_packet(client, packet, pos, NULL);
}

static bool
auth_boundary_receive(dssh_session client, uint8_t wanted)
{
	uint8_t type, *payload;
	size_t length;
	if (recv_packet(client, &type, &payload, &length) != 0 || type != wanted)
		return false;
	if (wanted == SSH_MSG_SERVICE_ACCEPT)
		return length == 17 && DSSH_GET_U32(payload + 1) == 12
		    && memcmp(payload + 5, "ssh-userauth", 12) == 0;
	if (wanted == SSH_MSG_USERAUTH_FAILURE)
		return length == 14 && DSSH_GET_U32(payload + 1) == 8
		    && memcmp(payload + 5, "password", 8) == 0 && payload[13] == 0;
	if (wanted == SSH_MSG_USERAUTH_INFO_REQUEST) {
		if (length != 17)
			return false;
		for (size_t i = 1; i < length; i++) {
			if (payload[i] != 0)
				return false;
		}
		return true;
	}
	return false;
}

static bool
auth_boundary_one(bool kbi, unsigned shape)
{
	struct handshake_ctx ctx;
	if (handshake_setup(&ctx) != 0) {
		handshake_cleanup(&ctx);
		return false;
	}
	struct auth_boundary_observer observer = { .valid = true };
	struct auth_server_arg server = { .ctx = &ctx };
	server.cbs.methods_str = "password";
	server.cbs.cbdata = &observer;
	server.cbs.none_cb = auth_boundary_none;
	if (kbi)
		server.cbs.keyboard_interactive_cb = auth_boundary_kbi;
	thrd_t worker;
	bool worker_owned = thrd_create(&worker, auth_server_thread, &server) == thrd_success;
	bool valid = worker_owned && inject_auth_service_request(ctx.client) == 0
	    && auth_boundary_receive(ctx.client, SSH_MSG_SERVICE_ACCEPT);
	unsigned requests = 0;
	if (kbi) {
		if (valid) {
			valid = auth_boundary_request(ctx.client, "alpha", "keyboard-interactive") == 0
			    && auth_boundary_receive(ctx.client, SSH_MSG_USERAUTH_INFO_REQUEST);
			requests++;
		}
		if (valid) {
			uint8_t response[] = {SSH_MSG_USERAUTH_INFO_RESPONSE, 0, 0, 0, 0};
			valid = send_packet(ctx.client, response, sizeof(response), NULL) == 0
			    && auth_boundary_receive(ctx.client, SSH_MSG_USERAUTH_INFO_REQUEST);
		}
		if (valid && shape == 2) {
			valid = auth_boundary_request(ctx.client, "alpha", "opaque") == 0
			    && auth_boundary_receive(ctx.client, SSH_MSG_USERAUTH_FAILURE);
			requests++;
		}
		if (valid) {
			valid = auth_boundary_request(ctx.client, shape == 1 ? "beta" : "alpha",
			    "keyboard-interactive") == 0
			    && auth_boundary_receive(ctx.client, SSH_MSG_USERAUTH_INFO_REQUEST);
			requests++;
		}
	}
	else {
		static const struct {
			const char *users[3];
			const char *methods[3];
			unsigned count;
		} sequences[] = {
			{{"alpha", "alpha"}, {"none", "none"}, 2},
			{{"alpha", "beta"}, {"none", "none"}, 2},
			{{"alpha", "beta", "alpha"}, {"none", "opaque", "none"}, 3},
			{{"alpha", "beta"}, {"opaque", "none"}, 2},
		};
		for (unsigned i = 0; i < sequences[shape].count && valid; i++) {
			valid = auth_boundary_request(ctx.client, sequences[shape].users[i], sequences[shape].methods[i]) == 0
			    && auth_boundary_receive(ctx.client, SSH_MSG_USERAUTH_FAILURE);
			requests++;
		}
	}
	/* End without granting any identity or completing authentication. */
	mock_io_close_c2s(&ctx.io);
	mock_io_close_s2c(&ctx.io);
	if (worker_owned && thrd_join(worker, NULL) != thrd_success)
		abort();
	valid &= observer.valid && server.result == DSSH_ERROR_TERMINATED
	    && !ctx.server->auth_complete && !ctx.client->auth_complete;
	if (kbi) {
		valid &= observer.calls == 3 && observer.releases == 3
		    && observer.identities[0] == 1 && observer.identities[1] == 1
		    && observer.identities[2] == (shape == 1 ? 2u : 1u)
		    && observer.zero_shapes[0] && observer.zero_shapes[1] && observer.zero_shapes[2];
	}
	else {
		static const unsigned expected[][3] = {{2, 1, 1}, {2, 1, 2}, {2, 1, 1}, {1, 2, 0}};
		valid &= observer.calls == expected[shape][0] && observer.identities[0] == expected[shape][1]
		    && observer.identities[1] == expected[shape][2] && observer.releases == 0;
	}
	const char *kex = dssh_transport_get_kex_name(ctx.client);
	const char *c2s = dssh_transport_get_mac_name(ctx.client, DSSH_CLIENT_TO_SERVER);
	const char *s2c = dssh_transport_get_mac_name(ctx.client, DSSH_SERVER_TO_CLIENT);
	if (kex == NULL || c2s == NULL || s2c == NULL)
		valid = false;
	else
		printf("auth_boundary_negotiated kbi=%d shape=%u kex=%s c2s=%s s2c=%s\n", kbi, shape, kex, c2s, s2c);
	handshake_cleanup(&ctx);
	printf("auth_boundary kbi=%d shape=%u requests=%u callbacks=%u identities=%u/%u/%u zero=%d/%d/%d releases=%u valid=%d\n",
	    kbi, shape, requests, observer.calls, observer.identities[0], observer.identities[1], observer.identities[2],
	    observer.zero_shapes[0], observer.zero_shapes[1], observer.zero_shapes[2], observer.releases, valid);
	return valid;
}

static int
auth_boundary_probe(void)
{
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return 2;
	unsigned failures = 0;
	for (unsigned shape = 0; shape < 4; shape++) {
		if (!auth_boundary_one(false, shape))
			failures++;
	}
	for (unsigned shape = 0; shape < 3; shape++) {
		if (!auth_boundary_one(true, shape))
			failures++;
	}
	printf("auth_boundaries cases=7 failures=%u completed=0\n", failures);
	return failures == 0 ? 0 : 1;
}
