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
#define fstat(fd, info) dssh_test_key_native_fstat(fd, info)
#define fcntl(fd, command, value) dssh_test_key_native_fcntl(fd, command, value)
#endif

/* Validate the acquired object before modifying permissions or contents.
 * The opening flags reject a final symlink and avoid waiting on a FIFO.
 * Clear the temporary status flag before handing a regular file to stdio. */
static bool
private_descriptor(int fd)
{
	struct stat info;
	if (fstat(fd, &info) != 0)
		return false;
	if (!S_ISREG(info.st_mode) || info.st_nlink != 1 || info.st_uid != geteuid()) {
		errno = EACCES;
		return false;
	}
	if (fcntl(fd, F_SETFL, 0) != 0)
		return false;
	return fchmod(fd, S_IRUSR | S_IWUSR) == 0 && ftruncate(fd, 0) == 0;
}

/* Paths are validated by public wrappers. POSIX.1-2008 supplies O_CLOEXEC;
 * never create an inheritable descriptor and try to fix it afterward. */
static FILE *
open_stream(const char *path, int flags, mode_t mode, const char *access, bool private_output)
{
	int fd = open(path, flags | O_CLOEXEC, mode);
	if (fd < 0)
		return NULL;
	FILE *fp = NULL;
	if (!private_output || private_descriptor(fd))
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
	return open_stream(path, O_CREAT | O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY,
	    S_IRUSR | S_IWUSR, "wb", true);
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
