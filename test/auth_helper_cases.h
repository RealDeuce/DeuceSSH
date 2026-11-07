#ifndef DSSH_TEST_AUTH_HELPER_CASES_H
#define DSSH_TEST_AUTH_HELPER_CASES_H

struct auth_setup_allocation_probe {
	unsigned target;
	unsigned sessions;
	bool failed;
};

static void
auth_setup_fail_session(size_t count, size_t size, void *data)
{
	struct auth_setup_allocation_probe *probe = data;
	if (count == 1 && size == sizeof(struct dssh_session_s)) {
		probe->sessions++;
		if (probe->sessions == probe->target) {
			probe->failed = true;
			dssh_test_alloc_fail_after(0);
		}
	}
}

static int
test_auth_setup_ownership(void)
{
	struct auth_setup_allocation_probe probe = {.target = 2};
	dssh_test_alloc_observe_allocations(auth_setup_fail_session, &probe);
	struct handshake_ctx ctx;
	int ret = handshake_setup(&ctx);
	dssh_test_alloc_reset();
	handshake_cleanup(&ctx);
	ASSERT_TRUE(probe.failed);
	ASSERT_EQ_U(probe.sessions, 2);
	ASSERT_TRUE(ret < 0);
	return TEST_PASS;
}

#endif
