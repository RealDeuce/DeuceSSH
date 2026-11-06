#ifndef DSSH_PRIVATE_KEY_FILE_H
#define DSSH_PRIVATE_KEY_FILE_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

FILE *dssh_private_key_open(const char *path);

#ifdef DSSH_TESTING
/* Library-only stdio observations; provider-internal stdio is not redirected. */
int dssh_test_key_file_close(FILE *stream);
void dssh_test_key_file_cleared(const void *ptr, size_t length);
size_t dssh_test_key_file_read(void *ptr, size_t size, size_t count, FILE *stream);
#ifdef __cplusplus
void dssh_test_free(void *ptr);
#define free(ptr) dssh_test_free(ptr)
#endif
#define fclose(stream) dssh_test_key_file_close(stream)
#define fread(ptr, size, count, stream) dssh_test_key_file_read(ptr, size, count, stream)
#endif


#ifdef __cplusplus
}
#endif

#endif
