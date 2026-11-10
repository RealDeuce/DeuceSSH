/* POSIX test driver: require the child to terminate by the actual SIGABRT. */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
	if (argc != 3 && argc != 5)
		return 2;
	bool traced = argc == 5;
	bool wake = traced && strcmp(argv[2], "--wake-fatal") == 0;
	bool channel = traced && strcmp(argv[2], "--channel-fatal") == 0;
	if (traced && !wake && !channel && strcmp(argv[2], "--unlock-fatal") != 0)
		return 2;
	int descriptors[2] = {-1, -1};
	if (traced && pipe(descriptors) != 0)
		return 3;
	struct rlimit core = {0, 0};
	if (setrlimit(RLIMIT_CORE, &core) != 0)
		return 3;
	pid_t child = fork();
	if (child < 0)
		return 4;
	if (child == 0) {
		if (traced) {
			if (close(descriptors[0]) != 0)
				_exit(127);
			if (dup2(descriptors[1], STDERR_FILENO) < 0)
				_exit(127);
			if (descriptors[1] != STDERR_FILENO && close(descriptors[1]) != 0)
				_exit(127);
		}
		char *arguments[] = {argv[1], traced ? argv[2] : "--join-fatal",
		    traced ? argv[3] : argv[2], traced ? argv[4] : NULL, NULL};
		execv(argv[1], arguments);
		_exit(127);
	}
	char captured[64];
	size_t used = 0;
	if (traced) {
		if (close(descriptors[1]) != 0)
			return 5;
		for (;;) {
			char part[256];
			ssize_t got = read(descriptors[0], part, sizeof(part));
			if (got < 0 && errno == EINTR)
				continue;
			if (got < 0)
				return 5;
			if (got == 0)
				break;
			size_t bytes = (size_t)got;
			/* Preserve the new child's full diagnostics for the strict CTest
			 * runner; the prefix below separately proves failure provenance. */
			if (channel && fwrite(part, 1, bytes, stderr) != bytes)
				return 5;
			size_t keep = bytes < sizeof(captured) - used ? bytes : sizeof(captured) - used;
			memcpy(captured + used, part, keep);
			used += keep;
		}
		if (close(descriptors[0]) != 0)
			return 5;
	}
	int status;
	pid_t waited;
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited != child)
		return 5;
	const char *marker = channel ? "DSSH_TEST_CHANNEL_JOIN_FAILURE\n"
	    : wake ? "DSSH_TEST_WAKE_FAILURE\n" : "DSSH_TEST_UNLOCK_FAILURE\n";
	size_t marker_len = strlen(marker);
	if (traced && (used < marker_len || memcmp(captured, marker, marker_len) != 0))
		return 8;
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGABRT) {
		fprintf(stderr, "fatal child wait status %d; expected SIGABRT\n", status);
		return 6;
	}
	if (channel)
		puts("channel_join_fatal=1");
	return 0;
}
