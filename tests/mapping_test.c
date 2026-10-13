#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

typedef int64_t off_t;
typedef struct { uint64_t p_vaddr, p_filesz, p_align; } Elf64_Phdr;
#define MAP_FAILED ((void *)-1)
#define PROT_READ 1
#define MAP_PRIVATE 2
#define MAP_ALIGNED(n) ((int)(n))
#define SUPERPAGE_SIZE 0x200000
static uint16_t fwver, detected_firmware;
static int init_error, mapping_calls;
static off_t actual_offset;
static int init(void) {
    if (init_error) return init_error;
    fwver = detected_firmware;
    return 0;
}
static void *mmap_self(void *addr, uint64_t len, int prot, int flags, int fd, off_t offset) {
    (void)addr; (void)len; (void)prot; (void)flags; (void)fd;
    mapping_calls++;
    actual_offset = offset;
    return (void *)1;
}
#include "mapping.inc"
int main(void) {
    // Firmware 9.00's documented segment fixture must work on the first call,
    // when fwver still has its startup value of zero.
    Elf64_Phdr phdr = { 0xedf7e10, 0xce8b98, 0x4000 };
    detected_firmware = 0x900;
    assert(map_self_segment(3, &phdr, 8) != MAP_FAILED);
    assert((uint64_t)actual_offset == UINT64_C(0x8001f4000));
    fwver = 0;
    detected_firmware = 0x850;
    assert(map_self_segment(3, &phdr, 8) != MAP_FAILED);
    assert((uint64_t)actual_offset == UINT64_C(0x800000000));
    init_error = ENOSYS;
    assert(map_self_segment(3, &phdr, 0) == MAP_FAILED);
    assert(errno == ENOSYS && mapping_calls == 2);
    puts("PASS: first-call firmware initialization, 9.00 offset fixture, older firmware, unsupported firmware");
    return 0;
}
