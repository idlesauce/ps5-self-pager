#include <sys/types.h>
#include <sys/elf64.h>

// Optional progress diagnostics, flushed before operations that may block.
#ifdef SELF_PAGER_TRACE
#include <stdio.h>
extern FILE *selfpager_trace_log;
#define PAGER_TRACE(...) do { \
    fprintf(stderr, __VA_ARGS__); fflush(stderr); \
    if (selfpager_trace_log) { fprintf(selfpager_trace_log, __VA_ARGS__); fflush(selfpager_trace_log); } \
} while (0)
#else
#define PAGER_TRACE(...) ((void)0)
#endif

// errors only
#define SELF_PAGER_DO_LOGGING 1

// these return the same values as mmap, but errno may be ENOSYS if the current firmware is not supported
void *mmap_self(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
void *map_self_segment(int fd, Elf64_Phdr *phdr, int segment_index);

// these are the return values for decrypt_self
#define DECRYPT_SUCCESS_PLAINTEXT_SELF 1
#define DECRYPT_ERROR_IO -2
#define DECRYPT_ERROR_INTERNAL -3
#define DECRYPT_ERROR_UNSUPPORTED_FW -4
#define DECRYPT_ERROR_INPUT_NOT_SELF -5
// the kernel pager could not load an encrypted/compressed segment
#define DECRYPT_ERROR_FAILED_TO_DECRYPT_SEGMENT_DATA -6

// Success is 0 (pager used) or DECRYPT_SUCCESS_PLAINTEXT_SELF (plaintext unwrapped).
// out_data holds a reconstructed ELF in either case; free it with munmap.
int decrypt_self(int input_file_fd, char **out_data, uint64_t *out_size);
