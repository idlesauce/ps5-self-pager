/* Execute production ELF reconstruction against synthetic SELF containers. */
#define _CRT_SECURE_NO_WARNINGS
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int64_t off_t;
typedef int64_t ssize_t;
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;
typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr;
struct stat { int64_t st_size; };
struct rlimit { uint64_t rlim_cur, rlim_max; };
#define SSIZE_MAX INT64_MAX
#define MAP_FAILED ((void *)-1)
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_ANONYMOUS 4
#define MAP_PRIVATE 8
#define RLIMIT_MEMLOCK 6
#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define PT_LOAD 1
#define LOG_ERROR(...) fprintf(stderr, __VA_ARGS__)
#define PAGER_TRACE(...) ((void)0)
#include "self-constants.inc"
#include "self-structs.inc"
#include "self-errors.inc"

static unsigned char input[0x500];
static int pager_calls, lock_failure, live_allocations;
static uint16_t fwver = 0x1320;
static ssize_t pread(int fd, void *dest, size_t len, off_t offset) {
    (void)fd;
    if (offset < 0 || (uint64_t)offset > sizeof(input) || len > sizeof(input) - offset) return 0;
    memcpy(dest, input + offset, len);
    return (ssize_t)len;
}
static int fstat(int fd, struct stat *st) { (void)fd; st->st_size = sizeof(input); return 0; }
static void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    (void)addr; (void)prot; (void)flags; (void)fd; (void)offset;
    if (len > 0x10000) return MAP_FAILED;
    void *mem = calloc(1, len);
    assert(mem);
    live_allocations++;
    return mem;
}
static int munmap(void *mem, size_t len) { (void)len; live_allocations--; free(mem); return 0; }
static int mlock(void *mem, size_t len) {
    (void)mem; (void)len;
    if (lock_failure) { errno = ENOMEM; return -1; }
    return 0;
}
static int getrlimit(int resource, struct rlimit *limit) {
    (void)resource; limit->rlim_cur = limit->rlim_max = INT64_MAX; return 0;
}
static void *map_self_segment(int fd, Elf64_Phdr *phdr, int index) {
    pager_calls++;
    void *mem = mmap(NULL, phdr->p_filesz, 0, 0, fd, 0);
    if (mem != MAP_FAILED) memset(mem, index == 0 ? 0xa5 : 0x5a, phdr->p_filesz);
    return mem;
}
#include "plain-reader.inc"
#include "self-decrypt.inc"

static void fixture(uint32_t magic, uint64_t flags) {
    memset(input, 0, sizeof(input));
    struct sce_self_header header = {0};
    header.magic = magic; header.key_type = 0x101; header.flags = 0x22;
    header.header_size = 0x1c0; header.segment_count = 4; header.file_size = sizeof(input);
    memcpy(input, &header, sizeof(header));
    // Metadata precedes each data entry, as in the user's log. Its bytes must
    // never be mistaken for ELF payload, even when its index matches.
    struct sce_self_segment_header entries[] = {
        {0x110004, 0x200, 0x20, 0x20},
        {flags, 0x300, 0x100, 0x100},
        {0x310004, 0x220, 0x20, 0x20},
        {UINT64_C(0x102804), 0x400, 8, 8}
    };
    memcpy(input + sizeof(header), entries, sizeof(entries));
    Elf64_Ehdr elf = {0};
    memcpy(elf.e_ident, "\x7f" "ELF\x02\x01", 6);
    elf.e_ehsize = sizeof(elf); elf.e_phoff = sizeof(elf);
    elf.e_phentsize = sizeof(Elf64_Phdr); elf.e_phnum = 3;
    size_t elf_offset = sizeof(header) + sizeof(entries);
    memcpy(input + elf_offset, &elf, sizeof(elf));
    Elf64_Phdr phdrs[] = {
        {PT_LOAD, 5, 0, 0, 0, 0x100, 0x100, 0x4000},
        {PT_LOAD, 6, 0x100, 0x4000, 0, 8, 8, 0x4000},
        {PT_SCE_VERSION, 0, 0x108, 0, 0, 4, 4, 1}
    };
    memcpy(input + elf_offset + elf.e_phoff, phdrs, sizeof(phdrs));
    memset(input + 0x200, 0xee, 0x40);
    memset(input + 0x300, 0xa5, 0x100);
    memset(input + 0x400, 0x5a, 8);
    memcpy(input + sizeof(input) - 4, "VERS", 4);
    pager_calls = lock_failure = 0;
    assert(live_allocations == 0);
}
static void expect_success(int expected_result, int expected_pager_calls) {
    char *output = NULL; uint64_t size = 0;
    assert(decrypt_self(3, &output, &size) == expected_result);
    assert(pager_calls == expected_pager_calls && size == 0x10c);
    assert(memcmp(output, "\x7f" "ELF", 4) == 0);
    // Payload beyond the ELF headers, second segment, and version trailer.
    for (size_t i = sizeof(Elf64_Ehdr) + 3 * sizeof(Elf64_Phdr); i < 0x100; i++)
        assert((unsigned char)output[i] == 0xa5);
    for (size_t i = 0x100; i < 0x108; i++) assert((unsigned char)output[i] == 0x5a);
    assert(memcmp(output + 0x108, "VERS", 4) == 0);
    munmap(output, size);
    assert(live_allocations == 0);
}
static void expect_failure(int result) {
    char *output = (char *)1; uint64_t size = 99;
    assert(decrypt_self(3, &output, &size) == result);
    assert(output == NULL && size == 0 && live_allocations == 0);
}
int main(void) {
    fixture(SELF_ORBIS_MAGIC, 0x2804);
    expect_success(DECRYPT_SUCCESS_PLAINTEXT_SELF, 0);
    fixture(SELF_PROSPERO_MAGIC, 0x2804);
    expect_success(DECRYPT_SUCCESS_PLAINTEXT_SELF, 0);
    fixture(SELF_PROSPERO_MAGIC, 0x2806); // Encrypted: never copy stored bytes.
    memset(input + 0x300, 0x99, 0x100);
    expect_success(0, 1);
    fixture(SELF_PROSPERO_MAGIC, 0x280c); // Compressed: kernel path retained.
    expect_success(0, 1);
    fixture(SELF_PROSPERO_MAGIC, 0x2806);
    lock_failure = 1;
    expect_failure(DECRYPT_ERROR_FAILED_TO_DECRYPT_SEGMENT_DATA);
    fixture(SELF_PROSPERO_MAGIC, 0x2804);
    struct sce_self_segment_header entry;
    size_t data_entry_offset = sizeof(struct sce_self_header) + sizeof(entry);
    memcpy(&entry, input + data_entry_offset, sizeof(entry));
    entry.offset = sizeof(input) - 1; // Truncated payload.
    memcpy(input + data_entry_offset, &entry, sizeof(entry));
    expect_failure(DECRYPT_ERROR_INTERNAL);
    fixture(SELF_PROSPERO_MAGIC, 0x2804);
    memcpy(&entry, input + data_entry_offset, sizeof(entry));
    entry.uncompressed_size--;
    memcpy(input + data_entry_offset, &entry, sizeof(entry));
    expect_failure(DECRYPT_ERROR_INTERNAL);
    fixture(SELF_PROSPERO_MAGIC, 0x2804);
    memcpy(&entry, input + data_entry_offset, sizeof(entry));
    memcpy(input + data_entry_offset + sizeof(entry), &entry, sizeof(entry));
    expect_failure(DECRYPT_ERROR_INTERNAL); // Duplicate mapping for segment 0.
    fixture(SELF_PROSPERO_MAGIC, 0x2804);
    struct sce_self_header header;
    memcpy(&header, input, sizeof(header)); header.header_size = 0x20;
    memcpy(input, &header, sizeof(header));
    expect_failure(DECRYPT_ERROR_INTERNAL);
    puts("PASS: ORBIS/PROSPERO plaintext reconstruction, payload bytes, encrypted/compressed pager path, failure cleanup, bounds, duplicates");
    return 0;
}
