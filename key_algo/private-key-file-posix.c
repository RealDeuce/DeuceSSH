/* Native key-file streams. Each descriptor is non-inheritable on creation. */
#include "private-key-file.h"
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef DSSH_TESTING
#include "dssh_test_key_file.h"
#define open(path, flags, mode) dssh_test_key_native_open(path, flags, mode)
#define fdopen(fd, mode) dssh_test_key_native_fdopen(fd, mode)
#define fchmod(fd, mode) dssh_test_key_native_fchmod(fd, mode)
#define ftruncate(fd, length) dssh_test_key_native_ftruncate(fd, length)
#define close(fd) dssh_test_key_native_close(fd)
#endif

/* Paths are validated by public wrappers. POSIX.1-2008 supplies O_CLOEXEC;
 * never create an inheritable descriptor and try to fix it afterward. */
static FILE *
open_stream(const char *path, int flags, mode_t mode, const char *access, bool private_output)
{
	int fd = open(path, flags | O_CLOEXEC, mode);
	if (fd < 0)
		return NULL;
	FILE *fp = NULL;
	if (!private_output || (fchmod(fd, S_IRUSR | S_IWUSR) == 0 && ftruncate(fd, 0) == 0))
		fp = fdopen(fd, access);
	if (fp == NULL) {
		int saved_error = errno;
		if (close(fd) != 0)
			return NULL;
		errno = saved_error;
	}
	return fp;
}

FILE *
dssh_private_key_open(const char *path)
{
	return open_stream(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR, "wb", true);
}

DSSH_PRIVATE FILE *
dssh_key_file_open_read(const char *path)
{
	return open_stream(path, O_RDONLY, 0, "rb", false);
}

DSSH_PRIVATE FILE *
dssh_key_file_open_public(const char *path)
{
	return open_stream(path, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR
	    | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, "w", false);
}
