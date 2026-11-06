/* Test-only key-file controls usable by C17 and native C++ fixtures. */
#ifndef DSSH_TEST_KEY_FILE_H
#define DSSH_TEST_KEY_FILE_H
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#ifndef _WIN32
#include <sys/types.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Key-file stdio controls, separate from the native-call countdown.
 * A close error is reported only after performing the real fclose once. */
void dssh_test_key_stdio_reset(void);
void dssh_test_key_close_error_once(void);
void dssh_test_key_watch_read_free(void);
typedef void (*dssh_test_key_clear_observer)(const void *ptr, size_t length, void *data);
void dssh_test_key_observe_clear(dssh_test_key_clear_observer observer, void *data);
void dssh_test_key_read_short_once(void);
void dssh_test_key_write_short_after(unsigned int calls);
void dssh_test_key_put_error_after(unsigned int calls);
unsigned int dssh_test_key_write_calls(void);
unsigned int dssh_test_key_short_write_calls(void);
unsigned int dssh_test_key_put_calls(void);
unsigned int dssh_test_key_put_errors(void);
unsigned int dssh_test_key_native_write_errors(void);
unsigned int dssh_test_key_short_read_calls(void);
unsigned int dssh_test_key_close_calls(void);
unsigned int dssh_test_key_close_errors(void);
unsigned int dssh_test_key_native_close_errors(void);
unsigned int dssh_test_key_read_calls(void);

/* Observe only explicitly watched, non-nested streams in the focused tests.
 * Buffer bytes are read only while the supplied storage is still live. */
struct dssh_test_key_stream_report {
	unsigned int configurations, closes, clears, nonzero, injected, native_errors;
	bool valid, active;
};
void dssh_test_key_watch_stream(void);
void dssh_test_key_setvbuf_error_once(void);
struct dssh_test_key_stream_report dssh_test_key_stream_report(void);
int dssh_test_key_file_setvbuf(FILE *stream, char *buffer, int mode, size_t capacity);
int dssh_test_key_file_close(FILE *stream);
void dssh_test_key_file_cleared(const void *ptr, size_t length);

struct dssh_test_key_open_report {
	unsigned int stdio_opens, native_opens, associations, rejected_associations;
	unsigned int permissions, truncations, raw_closes;
	unsigned int permission_errors, truncation_errors, raw_close_errors, native_close_errors;
	unsigned int target_checks, target_errors, reported_owners, status_updates, status_errors;
	bool descriptor_valid, close_on_exec, blocking_io, status_arguments_valid;
};
struct dssh_test_key_open_report dssh_test_key_open_report(void);
void dssh_test_key_fdopen_error_once(void);
bool dssh_test_key_failed_fd_closed(void);
FILE *dssh_test_key_file_fopen(const char *path, const char *mode);
#ifndef _WIN32
int dssh_test_key_native_open(const char *path, int flags, mode_t mode);
FILE *dssh_test_key_native_fdopen(int fd, const char *mode);
/* Metadata errors are reported before the real operation. A reported raw
 * close error follows the real close; it never simulates an unretired fd. */
void dssh_test_key_permission_error_once(void);
void dssh_test_key_truncate_error_once(void);
void dssh_test_key_raw_close_error_once(void);
int dssh_test_key_native_fchmod(int fd, mode_t mode);
int dssh_test_key_native_ftruncate(int fd, off_t length);
int dssh_test_key_native_close(int fd);
struct stat;
void dssh_test_key_target_error_once(void);
void dssh_test_key_status_error_once(void);
void dssh_test_key_different_owner_once(void);
int dssh_test_key_native_fstat(int fd, struct stat *info);
int dssh_test_key_native_fcntl(int fd, int command, int value);
#endif

#ifdef __cplusplus
}
#endif
#endif
