#ifndef DSSH_TEST_CONN_HELPER_CASES_H
#define DSSH_TEST_CONN_HELPER_CASES_H

struct conn_setup_allocation_probe {
	unsigned sessions;
	bool failed;
};

static void
conn_setup_fail_second_session(size_t count, size_t size, void *data)
{
	struct conn_setup_allocation_probe *probe = data;
	if (count == 1 && size == sizeof(struct dssh_session_s)) {
		probe->sessions++;
		if (probe->sessions == 2) {
			probe->failed = true;
			dssh_test_alloc_fail_after(0);
		}
	}
}

static int
conn_setup_ownership_case(bool start)
{
	struct conn_setup_allocation_probe probe = {0};
	dssh_test_alloc_observe_allocations(conn_setup_fail_second_session, &probe);
	struct conn_ctx ctx;
	int ret = start ? conn_setup(&ctx) : conn_setup_no_start(&ctx);
	dssh_test_alloc_reset();
	conn_cleanup(&ctx);
	conn_cleanup(&ctx);
	ASSERT_TRUE(ret < 0 && probe.failed && probe.sessions == 2);
	ASSERT_NULL(g_active_ctx);
	return TEST_PASS;
}

static int
test_conn_setup_ownership(void)
{
	return conn_setup_ownership_case(true);
}

static int
test_conn_no_start_ownership(void)
{
	return conn_setup_ownership_case(false);
}

#endif
