#ifndef DSSH_TEST_CHANNEL_WORKER_CASES_H
#define DSSH_TEST_CHANNEL_WORKER_CASES_H

struct channel_worker_job {
	thrd_start_t function;
	void *data;
	atomic_bool done;
};
struct channel_worker_probe {
	struct conn_ctx *owner;
	unsigned calls;
	unsigned created;
	unsigned joined;
	bool cancelled_before_join;
	struct channel_worker_job jobs[2];
};
static struct channel_worker_probe *channel_worker_probe;

static int
channel_worker_probe_run(void *data)
{
	struct channel_worker_job *job = data;
	int ret = job->function(job->data);
	atomic_store(&job->done, true);
	return ret;
}

static int
channel_worker_probe_create(thrd_t *thread, thrd_start_t function, void *data)
{
	struct channel_worker_probe *probe = channel_worker_probe;
	unsigned index = probe->calls++;
	if (index == 1)
		return thrd_error;
	if (index >= 2)
		abort();
	struct channel_worker_job *job = &probe->jobs[index];
	job->function = function;
	job->data = data;
	int ret = thrd_create(thread, channel_worker_probe_run, job);
	if (ret == thrd_success)
		probe->created++;
	return ret;
}

static int
channel_worker_probe_join(thrd_t thread, int *result)
{
	struct channel_worker_probe *probe = channel_worker_probe;
	probe->cancelled_before_join = dssh_session_is_terminated(probe->owner->client)
	    && dssh_session_is_terminated(probe->owner->server);
	/* Preserve the observation above, then let the before implementation
	 * finish without a timeout or a blocked worker borrowing this stack. */
	if (!probe->cancelled_before_join) {
		dssh_session_terminate(probe->owner->client);
		dssh_session_terminate(probe->owner->server);
		mock_io_close_c2s(&probe->owner->io);
		mock_io_close_s2c(&probe->owner->io);
	}
	int ret = thrd_join(thread, result);
	if (ret == thrd_success)
		probe->joined++;
	return ret;
}

static int
test_channel_worker_ownership(void)
{
	struct conn_ctx ctx;
	if (conn_setup(&ctx) != 0)
		return TEST_FAIL;
	struct channel_worker_probe probe = {.owner = &ctx};
	for (size_t i = 0; i < 2; i++)
		atomic_init(&probe.jobs[i].done, false);
	struct open_exec_ctx open = {.client = ctx.client, .server = ctx.server,
	    .command = "worker-ownership", .cbs = &accept_cbs_all, .accept_timeout = 30000};
	channel_worker_probe = &probe;
	channel_fixture_thread_create = channel_worker_probe_create;
	channel_fixture_thread_join = channel_worker_probe_join;
	int ret = open_exec_channel(&open);
	channel_fixture_thread_create = thrd_create;
	channel_fixture_thread_join = thrd_join;
	channel_worker_probe = NULL;
	bool valid = ret != 0 && probe.calls == 2 && probe.created == 1
	    && probe.joined == 1 && atomic_load(&probe.jobs[0].done)
	    && probe.cancelled_before_join;
	conn_cleanup(&ctx);
	ASSERT_TRUE(valid);
	return TEST_PASS;
}

#endif
