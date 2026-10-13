#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/elf64.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <ps5/kernel.h>

#include "selfpager.h"

#ifdef SELF_PAGER_TRACE
FILE *selfpager_trace_log = NULL;
#endif

#define SELF_ORBIS_MAGIC 0x1D3D154F
#define SELF_PROSPERO_MAGIC 0xEEF51454
#define PAGE_SIZE 0x4000
#define SUPERPAGE_SIZE 0x200000

#define PT_SCE_DYNLIBDATA 0x61000000
#define PT_SCE_RELRO 0x61000010
#define PT_SCE_COMMENT 0x6FFFFF00
#define PT_SCE_VERSION 0x6FFFFF01

#ifdef SELF_PAGER_DO_LOGGING
#define LOG_ERROR(...)                \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
    } while (0)
#else
#define LOG_ERROR(...)
#endif

// https://github.com/Cryptogenic/PS5-SELF-Decrypter/blob/def326f36c1f1b461030222daa9ea6124d4ce610/include/self.h#L21
struct sce_self_header {
    uint32_t magic;         // 0x00
    uint8_t version;        // 0x04
    uint8_t mode;           // 0x05
    uint8_t endian;         // 0x06
    uint8_t attributes;     // 0x07
    uint32_t key_type;      // 0x08
    uint16_t header_size;   // 0x0C
    uint16_t metadata_size; // 0x0E
    uint64_t file_size;     // 0x10
    uint16_t segment_count; // 0x18
    uint16_t flags;         // 0x1A
    char pad_2[0x4];        // 0x1C
}; // Size: 0x20

struct sce_self_segment_header {
    uint64_t flags;             // 0x00
    uint64_t offset;            // 0x08
    uint64_t compressed_size;   // 0x10
    uint64_t uncompressed_size; // 0x18
}; // Size: 0x20

static uint16_t fwver = 0;
static intptr_t pagertab_addr = 0;
static intptr_t vnodepagerops_addr = 0;
static intptr_t selfpagerops_addr = 0;

static const int pagertab_vnodepagerops_index = 2;
static const int pagertab_selfpagerops_index = 7;

static int init() {
    if (pagertab_addr != 0) {
        return 0;
    }

    fwver = kernel_get_fw_version() >> 16;
    switch (fwver) {
    case 0x100:
    case 0x101:
    case 0x102:
    case 0x105:
    case 0x110:
    case 0x111:
    case 0x112:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC27C40;
        break;

    case 0x113:
    case 0x114:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC27CA0;
        break;

    case 0x200:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC4EF60;
        break;

    case 0x220:
    case 0x225:
    case 0x226:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC4EFA0;
        break;

    case 0x230:
    case 0x250:
    case 0x270:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xC4F120;
        break;

    case 0x300:
    case 0x310:
    case 0x320:
    case 0x321:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xCAF8C0;
        break;

    case 0x400:
    case 0x402:
    case 0x403:
    case 0x450:
    case 0x451:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xD20840;
        break;

    case 0x500:
    case 0x502:
    case 0x510:
    case 0x550:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE0FEF0;
        break;

    case 0x600:
    case 0x602:
    case 0x650:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE30410;
        break;

    case 0x700:
    case 0x701:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE310C0;
        break;

    case 0x720:
    case 0x740:
    case 0x760:
    case 0x761:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE31180;
        break;

    case 0x800:
    case 0x820:
    case 0x840:
    case 0x860:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE31250;
        break;

    case 0x900:
    case 0x905:
    case 0x920:
    case 0x940:
    case 0x960:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xDE0420;
        break;

    case 0x1000:
    case 0x1001:
    case 0x1020:
    case 0x1040:
    case 0x1060:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xDE04F0;
        break;

    case 0x1100:
    case 0x1120:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xDF1940;
        break;

    case 0x1140:
    case 0x1160:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xDF1960;
        break;

    case 0x1200:
    case 0x1202:
    case 0x1220:
    case 0x1240:
    case 0x1260:
    case 0x1270:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xDF2860;
        break;

    case 0x1300:
    case 0x1320:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE038D0;
        break;

    case 0x1340:
        pagertab_addr = KERNEL_ADDRESS_DATA_BASE + 0xE03910;
        break;

    default:
        return ENOSYS;
    }
    vnodepagerops_addr = kernel_getlong(pagertab_addr + pagertab_vnodepagerops_index * 8);
    selfpagerops_addr = kernel_getlong(pagertab_addr + pagertab_selfpagerops_index * 8);

    return 0;
}

void *mmap_self(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    int init_res = init();
    if (init_res != 0) {
        errno = init_res;
        return MAP_FAILED;
    }

    // make vnode pagerops point to selfpagerops
    kernel_setlong(pagertab_addr + (pagertab_vnodepagerops_index * 8), selfpagerops_addr);
    void *res = mmap(addr, len, prot, flags, fd, offset);
    // restore vnode pagerops
    kernel_setlong(pagertab_addr + (pagertab_vnodepagerops_index * 8), vnodepagerops_addr);
    return res;
}

// Entry layout: https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain/blob/master/scripts/make_fself.py
#define SELF_ENTRY_ENCRYPTED (UINT64_C(1) << 1)
#define SELF_ENTRY_COMPRESSED (UINT64_C(1) << 3)
#define SELF_ENTRY_HAS_BLOCKS (UINT64_C(1) << 11)
#define SELF_ENTRY_METADATA_MASK UINT64_C(0xf0000)

// 1: read plaintext, 0: use the kernel pager, negative: invalid/read error.
static int read_plain_self_segment(int fd, const struct sce_self_header *header,
                                   uint64_t input_size, const Elf64_Phdr *phdr,
                                   int segment_index, void *dest) {
    struct sce_self_segment_header data_entry = {0};
    int found = 0;
    for (int j = 0; j < header->segment_count; j++) {
        struct sce_self_segment_header entry;
        off_t offset = sizeof(*header) + j * sizeof(entry);
        if (pread(fd, &entry, sizeof(entry), offset) != sizeof(entry)) {
            return DECRYPT_ERROR_IO;
        }
        if (!(entry.flags & SELF_ENTRY_HAS_BLOCKS) ||
            (entry.flags & SELF_ENTRY_METADATA_MASK) ||
            ((entry.flags >> 20) & 0xffff) != (uint64_t)segment_index) continue;
        if (found) return DECRYPT_ERROR_INTERNAL;
        data_entry = entry;
        found = 1;
    }
    if (!found || (data_entry.flags & (SELF_ENTRY_ENCRYPTED | SELF_ENTRY_COMPRESSED))) {
        return 0;
    }
    // A direct read is only valid for a contiguous, uncompressed data entry.
    uint64_t payload_start = (uint64_t)header->header_size + header->metadata_size;
    if (data_entry.compressed_size != phdr->p_filesz ||
        data_entry.uncompressed_size != phdr->p_filesz ||
        data_entry.offset < payload_start || data_entry.offset > input_size ||
        phdr->p_filesz > input_size - data_entry.offset || phdr->p_filesz > SSIZE_MAX) {
        return DECRYPT_ERROR_INTERNAL;
    }
    PAGER_TRACE("Reading plaintext segment %d: source offset=0x%llx size=%llu bytes\n",
                segment_index, (unsigned long long)data_entry.offset, (unsigned long long)phdr->p_filesz);
    if (pread(fd, dest, phdr->p_filesz, data_entry.offset) != (ssize_t)phdr->p_filesz) {
        return DECRYPT_ERROR_IO;
    }
    PAGER_TRACE("Finished plaintext segment %d\n", segment_index);
    return 1;
}

void *map_self_segment(int fd, Elf64_Phdr *phdr, int segment_index) {
    // The first mapping must know the firmware before encoding its offset.
    int init_res = init();
    if (init_res != 0) {
        errno = init_res;
        return MAP_FAILED;
    }
    off_t offset = ((uint64_t)segment_index) << 32;
    if (fwver >= 0x900) {
        // for example, for this segment:
        // Index  Type     VirtAddr     FileSize   MemSize    Align
        // 8      PT_LOAD  0xedf7e10    0xce8b98   0xce8b98   0x4000
        // the kernel expects 0x1f4000 in the lower 32 bits, by providing 0 it tells us in the klogs:
        // self_pager.c(122) self_pager_seg_decode_pindex: off=0, diff=0x1f4000
        uint64_t aligned_vaddr = phdr->p_vaddr & ~(phdr->p_align - 1);
        offset |= aligned_vaddr & (SUPERPAGE_SIZE - 1);
    }
    return mmap_self(NULL, phdr->p_filesz, PROT_READ, MAP_PRIVATE | MAP_ALIGNED(phdr->p_align), fd, offset);
}

int decrypt_self(int input_file_fd, char **out_data, uint64_t *out_size) {
    if (!out_data || !out_size) {
        return DECRYPT_ERROR_INTERNAL;
    }
    *out_data = NULL;
    *out_size = 0;

    struct sce_self_header self_header;
    PAGER_TRACE("Reading SELF header\n");
    ssize_t pread_res = pread(input_file_fd, &self_header, sizeof(self_header), 0);
    if (pread_res == -1) {
        LOG_ERROR("Failed to read self header | errno: %d (%s)\n", errno, strerror(errno));
        return DECRYPT_ERROR_IO;
    } else if (pread_res != sizeof(self_header)) {
        // https://man.freebsd.org/cgi/man.cgi?query=pread&apropos=0&sektion=2&manpath=FreeBSD+11.4-RELEASE&arch=default&format=html
        // The system guarantees to read the number of bytes requested if the descriptor
        // references a normal file that has that many bytes left before the end-of-file

        // the file is smaller than 0x20 bytes, so not a self
        return DECRYPT_ERROR_INPUT_NOT_SELF;
    }

    if (self_header.magic != SELF_ORBIS_MAGIC && self_header.magic != SELF_PROSPERO_MAGIC) {
        return DECRYPT_ERROR_INPUT_NOT_SELF;
    }

    struct stat input_file_stat;
    PAGER_TRACE("Checking SELF file size\n");
    if (fstat(input_file_fd, &input_file_stat) != 0 || input_file_stat.st_size < 0) {
        return DECRYPT_ERROR_IO;
    }
    uint64_t input_size = input_file_stat.st_size;
    Elf64_Ehdr elf_header;
    PAGER_TRACE("Reading embedded ELF header (%u SELF entries)\n", self_header.segment_count);
    int self_elf_header_offset = sizeof(struct sce_self_header) + (sizeof(struct sce_self_segment_header) * self_header.segment_count);
    if ((uint64_t)self_elf_header_offset + sizeof(elf_header) > self_header.header_size ||
        (uint64_t)self_header.header_size + self_header.metadata_size > input_size) {
        LOG_ERROR("Invalid SELF header bounds\n");
        return DECRYPT_ERROR_INTERNAL;
    }
    if (pread(input_file_fd, &elf_header, sizeof(elf_header), self_elf_header_offset) != sizeof(elf_header)) {
        LOG_ERROR("Failed to read ELF header\n");
        return DECRYPT_ERROR_IO;
    }

    if (elf_header.e_ident[EI_MAG0] != ELFMAG0 || elf_header.e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header.e_ident[EI_MAG2] != ELFMAG2 || elf_header.e_ident[EI_MAG3] != ELFMAG3) {
        LOG_ERROR("Failed to find ELF header offset\n");
        return DECRYPT_ERROR_INTERNAL;
    }

    if (elf_header.e_ident[EI_CLASS] != ELFCLASS64 || elf_header.e_ident[EI_DATA] != ELFDATA2LSB ||
        elf_header.e_phentsize != sizeof(Elf64_Phdr) ||
        elf_header.e_phnum == 0 || elf_header.e_phnum > 256 ||
        elf_header.e_phoff < sizeof(elf_header) ||
        elf_header.e_phoff > self_header.header_size - (uint64_t)self_elf_header_offset ||
        (uint64_t)elf_header.e_phnum * sizeof(Elf64_Phdr) >
            self_header.header_size - (uint64_t)self_elf_header_offset - elf_header.e_phoff) {
        LOG_ERROR("Invalid ELF program header bounds\n");
        return DECRYPT_ERROR_INTERNAL;
    }
    Elf64_Phdr phdrs[elf_header.e_phnum];
    int phdrs_size = elf_header.e_phnum * sizeof(Elf64_Phdr);
    off_t self_elf_phdrs_offset = self_elf_header_offset + elf_header.e_phoff;
    PAGER_TRACE("Reading ELF program headers (%u segments)\n", elf_header.e_phnum);
    if (pread(input_file_fd, phdrs, phdrs_size, self_elf_phdrs_offset) != phdrs_size) {
        LOG_ERROR("Failed to read program headers\n");
        return DECRYPT_ERROR_IO;
    }

    uint64_t output_file_size = 0;
    int version_segment_index = -1;
    for (int i = 0; i < elf_header.e_phnum; i++) {
        Elf64_Phdr *phdr = &phdrs[i];
        if (phdr->p_filesz > SSIZE_MAX || phdr->p_offset > SIZE_MAX - phdr->p_filesz) {
            LOG_ERROR("Invalid ELF segment bounds\n");
            return DECRYPT_ERROR_INTERNAL;
        }
        if (phdr->p_offset + phdr->p_filesz > output_file_size) {
            output_file_size = phdr->p_offset + phdr->p_filesz;
        }
        if (phdr->p_type == PT_SCE_VERSION) {
            version_segment_index = i;
        }
    }

    if (output_file_size < elf_header.e_phoff + phdrs_size) {
        LOG_ERROR("Output is too small for ELF headers\n");
        return DECRYPT_ERROR_INTERNAL;
    }

    PAGER_TRACE("Allocating ELF output buffer: %llu bytes\n", (unsigned long long)output_file_size);
    void *out_buf = mmap(NULL, output_file_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (out_buf == MAP_FAILED) {
        LOG_ERROR("Failed to mmap output buffer | errno: %d (%s)\n", errno, strerror(errno));
        return DECRYPT_ERROR_INTERNAL;
    }

    int plain_segments = 0, pager_segments = 0;
    for (int i = 0; i < elf_header.e_phnum; i++) {
        Elf64_Phdr *phdr = &phdrs[i];
        if ((phdr->p_type != PT_LOAD && phdr->p_type != PT_SCE_DYNLIBDATA && phdr->p_type != PT_SCE_RELRO && phdr->p_type != PT_SCE_COMMENT) || phdr->p_filesz == 0) {
            continue;
        }
        PAGER_TRACE("Processing ELF segment %d: type=0x%x size=%llu bytes\n",
                    i, phdr->p_type, (unsigned long long)phdr->p_filesz);
        int plain_res = read_plain_self_segment(input_file_fd, &self_header, input_size,
                                               phdr, i, (uint8_t *)out_buf + phdr->p_offset);
        if (plain_res < 0) {
            LOG_ERROR("Failed to read plaintext SELF segment %d | error: %d\n", i, plain_res);
            munmap(out_buf, output_file_size);
            return plain_res;
        }
        if (plain_res == 1) {
            plain_segments++;
            continue;
        }
        pager_segments++;
        PAGER_TRACE("Mapping segment %d with kernel SELF pager\n", i);
        void *mapped_segment = map_self_segment(input_file_fd, phdr, i);
        if (mapped_segment == MAP_FAILED) {
            if (errno == ENOSYS) {
                LOG_ERROR("Unsupported firmware version\n");
                munmap(out_buf, output_file_size);
                return DECRYPT_ERROR_UNSUPPORTED_FW;
            }
            LOG_ERROR("Failed to mmap_self segment %d | errno: %d (%s)\n", i, errno, strerror(errno));
            munmap(out_buf, output_file_size);
            return DECRYPT_ERROR_INTERNAL;
        }

        PAGER_TRACE("Loading kernel SELF pager segment %d\n", i);
        if (mlock(mapped_segment, phdr->p_filesz)) {
            int lock_errno = errno;
            LOG_ERROR("Failed to decrypt segment data | segment %d | errno: %d (%s) | firmware: 0x%x\n",
                      i, lock_errno, strerror(lock_errno), fwver);
            LOG_ERROR("SELF header: magic=0x%x key_type=0x%x attributes=0x%x flags=0x%x entries=%u\n",
                      self_header.magic, self_header.key_type, self_header.attributes,
                      self_header.flags, self_header.segment_count);
            LOG_ERROR("ELF segment: type=0x%x vaddr=0x%llx filesz=0x%llx align=0x%llx\n",
                      phdr->p_type, (unsigned long long)phdr->p_vaddr,
                      (unsigned long long)phdr->p_filesz, (unsigned long long)phdr->p_align);
            // Raw entries help distinguish the container's storage format
            // without treating a failed pager operation as successful output.
            for (int j = 0; j < self_header.segment_count && j < 4; j++) {
                struct sce_self_segment_header segment;
                off_t entry_offset = sizeof(self_header) + j * sizeof(segment);
                if (pread(input_file_fd, &segment, sizeof(segment), entry_offset) != sizeof(segment)) break;
                LOG_ERROR("SELF entry %d: flags=0x%llx offset=0x%llx stored=0x%llx size=0x%llx\n",
                          j, (unsigned long long)segment.flags, (unsigned long long)segment.offset,
                          (unsigned long long)segment.compressed_size, (unsigned long long)segment.uncompressed_size);
            }
            struct rlimit lock_limit;
            if (getrlimit(RLIMIT_MEMLOCK, &lock_limit) == 0) {
                LOG_ERROR("Memory lock limit: current=0x%llx maximum=0x%llx\n",
                          (unsigned long long)lock_limit.rlim_cur, (unsigned long long)lock_limit.rlim_max);
            }
            munmap(mapped_segment, phdr->p_filesz);
            munmap(out_buf, output_file_size);
            return DECRYPT_ERROR_FAILED_TO_DECRYPT_SEGMENT_DATA;
        }

        PAGER_TRACE("Copying kernel SELF pager segment %d\n", i);
        memcpy((uint8_t *)out_buf + phdr->p_offset, mapped_segment, phdr->p_filesz);

        munmap(mapped_segment, phdr->p_filesz);
    }

    if (version_segment_index != -1) {
        PAGER_TRACE("Reading version segment %d\n", version_segment_index);
        Elf64_Phdr *phdr = &phdrs[version_segment_index];
        if (phdr->p_filesz > input_size) {
            LOG_ERROR("Invalid version segment bounds\n");
            munmap(out_buf, output_file_size);
            return DECRYPT_ERROR_INTERNAL;
        }

        off_t version_segment_self_offset = input_size - phdr->p_filesz;
        uint64_t version_segment_elf_offset = phdr->p_offset;
        if (pread(input_file_fd, out_buf + version_segment_elf_offset, phdr->p_filesz, version_segment_self_offset) != (ssize_t)phdr->p_filesz) {
            LOG_ERROR("Failed to read version segment from input file\n");
            munmap(out_buf, output_file_size);
            return DECRYPT_ERROR_IO;
        }
    }

    // copy elf header
    memcpy(out_buf, &elf_header, sizeof(elf_header));
    memcpy(out_buf + elf_header.e_phoff, phdrs, phdrs_size);

    *out_data = out_buf;
    *out_size = output_file_size;
    PAGER_TRACE("ELF reconstruction complete: %d plaintext segments %d pager segments\n", plain_segments, pager_segments);
    return plain_segments && !pager_segments ? DECRYPT_SUCCESS_PLAINTEXT_SELF : 0;
}
