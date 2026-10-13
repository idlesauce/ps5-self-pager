#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/elf64.h>
#include <sys/stat.h>
#ifdef DUMP_GAME
#include <sys/param.h>
#include <sys/mount.h>
#endif

#include "selfpager.h"

static void mkdirs(const char *dir) {
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0777);
            *p = '/';
        }
    mkdir(tmp, 0777);
}

static int is_usb_mounted(int index) {
    char path[64];
    snprintf(path, sizeof(path), "/mnt/usb%d", index);
    struct stat parent_stat;
    if (stat("/mnt", &parent_stat) != 0) {
        return 0;
    }
    struct stat usb_stat;
    if (stat(path, &usb_stat) != 0) {
        return 0;
    }
    return (parent_stat.st_dev != usb_stat.st_dev);
}

int decrypt_self_by_path(const char *input_file_path, const char *output_file_path, int *num_success, int *num_failed) {
    PAGER_TRACE("Opening candidate: %s\n", input_file_path);
    int input_file_fd = open(input_file_path, O_RDONLY);
    if (input_file_fd < 0) {
        puts("Failed to open input file");
        if (num_failed) (*num_failed)++;
        return -1;
    }

    uint64_t output_file_size = 0;
    char *out_data = NULL;
    PAGER_TRACE("Reading candidate: %s\n", input_file_path);
    int res = decrypt_self(input_file_fd, &out_data, &output_file_size);
    close(input_file_fd);
    if (res == DECRYPT_ERROR_INPUT_NOT_SELF) {
        PAGER_TRACE("Skipped non-SELF: %s\n", input_file_path);
        return res;
    } else if (res != 0 && res != DECRYPT_SUCCESS_PLAINTEXT_SELF) {
        printf("Failed to decrypt self: %s , error %d\n", input_file_path, res);
        if (num_failed) (*num_failed)++;
        return res;
    }

    char *last_slash = strrchr(output_file_path, '/');
    if (last_slash) {
        PAGER_TRACE("Creating output directories: %s\n", output_file_path);
        char output_dir_path[PATH_MAX];
        long dir_path_len = last_slash - output_file_path;
        strncpy(output_dir_path, output_file_path, dir_path_len);
        output_dir_path[dir_path_len] = '\0';
        mkdirs(output_dir_path);
    }
    PAGER_TRACE("Opening output: %s\n", output_file_path);
    int output_file_fd = open(output_file_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (output_file_fd < 0) {
        puts("Failed to open output file");
        munmap(out_data, output_file_size);
        unlink(output_file_path);
        if (num_failed) (*num_failed)++;
        return -1;
    }
    PAGER_TRACE("Writing ELF: %s (%llu bytes)\n", output_file_path, (unsigned long long)output_file_size);
    ssize_t write_res = write(output_file_fd, out_data, output_file_size);
    PAGER_TRACE("Write returned: %lld bytes\n", (long long)write_res);
    munmap(out_data, output_file_size);
    close(output_file_fd);
    if (write_res != output_file_size) {
        puts("Failed to write complete output file");
        unlink(output_file_path);
        if (num_failed) (*num_failed)++;
        return -1;
    }
    printf("%s: '%s' -> '%s'\n",
           res == DECRYPT_SUCCESS_PLAINTEXT_SELF ? "Unwrapped plaintext self" : "Decrypted self",
           input_file_path, output_file_path);

    if (num_success) (*num_success)++;
    return res;
}

static const char *allowed_exts[] = {".elf", ".self", ".prx", ".sprx", ".bin"};
static const int allowed_exts_count = sizeof(allowed_exts) / sizeof(allowed_exts[0]);

static int decrypt_all_selfs_in_directory(const char *input_dir_path, const char *output_dir_path, int recursive, int *num_success, int *num_failed) {
    if (!input_dir_path || !output_dir_path) {
        return -1;
    }

    PAGER_TRACE("Opening directory: %s\n", input_dir_path);
    DIR *dir = opendir(input_dir_path);
    if (!dir) {
        perror("Failed to open input directory");
        return -1;
    }

    struct dirent *entry;
    char inpath[PATH_MAX];
    char outpath[PATH_MAX];

    size_t entries_seen = 0;
    // Visit this directory's files before descending into asset directories.
    // Otherwise a large data tree can hide eboot.bin behind a long silent scan.
    for (int pass = 0; pass < (recursive ? 2 : 1); pass++) {
        if (pass == 1) rewinddir(dir);
        size_t pass_entries = 0;
        PAGER_TRACE("Reading directory entries: %s (%s)\n", input_dir_path, pass == 0 ? "files" : "subdirectories");
        while ((entry = readdir(dir)) != NULL) {
            pass_entries++;
            if (pass == 0) entries_seen++;
            const char *name = entry->d_name;
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                continue;
            }

            unsigned char entry_type = entry->d_type;
            if (entry_type != DT_UNKNOWN &&
                entry_type != (pass == 0 ? DT_REG : DT_DIR)) continue;
            int path_len = snprintf(inpath, sizeof(inpath), "%s/%s", input_dir_path, name);
            if (path_len < 0 || (size_t)path_len >= sizeof(inpath)) {
                printf("Skipping input path that is too long: %s/%s\n", input_dir_path, name);
                continue;
            }
            path_len = snprintf(outpath, sizeof(outpath), "%s/%s", output_dir_path, name);
            if (path_len < 0 || (size_t)path_len >= sizeof(outpath)) {
                printf("Skipping output path that is too long: %s/%s\n", output_dir_path, name);
                continue;
            }

            if (entry_type == DT_UNKNOWN) {
                struct stat st;
                if (pass_entries == 1 || pass_entries % 512 == 0) {
                    PAGER_TRACE("Resolving unknown entry type: %s (entry %llu)\n", inpath, (unsigned long long)pass_entries);
                }
                // Do not follow symlinks: keep the same scope as known d_type entries.
                if (lstat(inpath, &st) != 0) {
                    printf("Failed to determine entry type: %s: %s\n", inpath, strerror(errno));
                    continue;
                }
                if (S_ISDIR(st.st_mode)) entry_type = DT_DIR;
                else if (S_ISREG(st.st_mode)) entry_type = DT_REG;
            }

            if (entry_type == DT_DIR && pass == 1) {
                // if the input dir starts with "/mnt/sandbox/pfsmnt" skip entry if ends with "-app0-patch0-union",
                // we only care about app0 and patch0
                if (entry->d_namlen == sizeof("PPSA00000-app0-patch0-union") - 1 &&
                    strncmp(input_dir_path, "/mnt/sandbox/pfsmnt", sizeof("/mnt/sandbox/pfsmnt") - 1) == 0 &&
                    strncmp(name + 9, "-app0-patch0-union", sizeof("-app0-patch0-union") - 1) == 0) {
                    continue;
                }

                decrypt_all_selfs_in_directory(inpath, outpath, recursive, num_success, num_failed);
            } else if (entry_type == DT_REG && pass == 0) {
                int has_allowed_ext = 0;
                const char *ext = strrchr(name, '.');
                for (int i = 0; i < allowed_exts_count; i++) {
                    if (ext && strcasecmp(ext, allowed_exts[i]) == 0) {
                        has_allowed_ext = 1;
                        break;
                    }
                }
                if (!has_allowed_ext) {
                    continue;
                }

                decrypt_self_by_path(inpath, outpath, num_success, num_failed);
            }
        }
    }

    closedir(dir);
    PAGER_TRACE("Finished directory: %s (%llu entries)\n", input_dir_path, (unsigned long long)entries_seen);
    (void)entries_seen;
    return 0;
}

#ifdef DUMP_GAME
static void decrypt_shadowmount_games(const char *output_base_path, int *num_success, int *num_failed) {
    // ShadowMountPlus mounts its game sources here using nullfs, optionally
    // with a unionfs backport overlay. Do not scan unmounted title directories
    // or raw image/container mounts, which can duplicate the same game.
    const char *root = "/system_ex/app";
    PAGER_TRACE("Checking mounted title directories: %s\n", root);
    DIR *dir = opendir(root);
    if (!dir) {
        printf("Cannot scan ShadowMount game mounts: %s: %s\n", root, strerror(errno));
        return;
    }

    struct dirent *entry;
    unsigned int inspected = 0, selected = 0;
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno) printf("Failed to read title directory: %s: %s\n", root, strerror(errno));
            break;
        }
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

        char inpath[PATH_MAX], outpath[PATH_MAX];
        int len = snprintf(inpath, sizeof(inpath), "%s/%s", root, name);
        if (len < 0 || (size_t)len >= sizeof(inpath)) continue;
        inspected++;
        PAGER_TRACE("Inspecting title entry: %s (d_type=%u)\n", inpath, entry->d_type);
        struct stat st;
        if (lstat(inpath, &st) != 0) {
            printf("Failed to inspect title directory: %s: %s\n", inpath, strerror(errno));
            continue;
        }
        if (!S_ISDIR(st.st_mode)) {
            PAGER_TRACE("Skipping title entry: %s is not a directory\n", inpath);
            continue;
        }
        struct statfs fs;
        PAGER_TRACE("Reading mount metadata: %s\n", inpath);
        if (statfs(inpath, &fs) != 0) {
            printf("Failed to inspect game mount: %s: %s\n", inpath, strerror(errno));
            continue;
        }
        PAGER_TRACE("Mount metadata: %s type=%s mounted_on=%s source=%s\n",
                    inpath, fs.f_fstypename, fs.f_mntonname, fs.f_mntfromname);
        if (strcmp(fs.f_mntonname, inpath) != 0) {
            PAGER_TRACE("Skipping title entry: %s is not an exact mount point\n", inpath);
            continue;
        }
        if (strcmp(fs.f_fstypename, "nullfs") != 0 && strcmp(fs.f_fstypename, "unionfs") != 0) {
            PAGER_TRACE("Skipping title mount: %s filesystem %s is not nullfs or unionfs\n", inpath, fs.f_fstypename);
            continue;
        }

        len = snprintf(outpath, sizeof(outpath), "%s%s", output_base_path, inpath);
        if (len < 0 || (size_t)len >= sizeof(outpath)) continue;
        selected++;
        printf("Scanning mounted game: %s (%s)\n", inpath, fs.f_fstypename);
        decrypt_all_selfs_in_directory(inpath, outpath, 1, num_success, num_failed);
    }
    closedir(dir);
    PAGER_TRACE("Title mount scan complete: inspected=%u selected=%u\n", inspected, selected);
    (void)inspected;
    if (!selected) {
        puts("No mounted ShadowMount-style game titles found; launch the game and keep it running while dumping");
    }
}
#endif

int main() {
#ifdef SELF_PAGER_TRACE
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Progress diagnostics enabled");
#endif
    int num_success = 0;
    int num_failed = 0;
    char output_path[PATH_MAX];
    const char *output_base_path = is_usb_mounted(0) ? "/mnt/usb0/dump" : "/data/dump";
#ifdef SELF_PAGER_TRACE
    mkdirs(output_base_path);
    char trace_path[PATH_MAX];
    snprintf(trace_path, sizeof(trace_path), "%s/pager-progress.log", output_base_path);
    selfpager_trace_log = fopen(trace_path, "w");
    if (!selfpager_trace_log) {
        fprintf(stderr, "Cannot open progress log: %s: %s\n", trace_path, strerror(errno));
    }
    PAGER_TRACE("Progress log: %s\n", trace_path);
#endif
    printf("Output base path: %s\n", output_base_path);

#ifdef DUMP_SYSTEM_COMMON_LIB
    snprintf(output_path, sizeof(output_path), "%s/system/common/lib", output_base_path);
    decrypt_all_selfs_in_directory("/system/common/lib", output_path, 0, &num_success, &num_failed);
#endif

#ifdef DUMP_FULL_SYSTEM
    snprintf(output_path, sizeof(output_path), "%s/system", output_base_path);
    decrypt_all_selfs_in_directory("/system", output_path, 1, &num_success, &num_failed);
    snprintf(output_path, sizeof(output_path), "%s/system_ex", output_base_path);
    decrypt_all_selfs_in_directory("/system_ex", output_path, 1, &num_success, &num_failed);
#endif

#ifdef DUMP_SHELLCORE
    snprintf(output_path, sizeof(output_path), "%s/system/vsh/SceShellCore.elf", output_base_path);
    decrypt_self_by_path("/system/vsh/SceShellCore.elf", output_path, &num_success, &num_failed);
#endif

#ifdef DUMP_GAME
    snprintf(output_path, sizeof(output_path), "%s/mnt/sandbox/pfsmnt", output_base_path);
    decrypt_all_selfs_in_directory("/mnt/sandbox/pfsmnt", output_path, 1, &num_success, &num_failed);
    decrypt_shadowmount_games(output_base_path, &num_success, &num_failed);
#endif

    printf("Done. Success: %d, Failed: %d\n", num_success, num_failed);
#ifdef SELF_PAGER_TRACE
    if (selfpager_trace_log) {
        fprintf(selfpager_trace_log, "Done. Success: %d, Failed: %d\n", num_success, num_failed);
        fclose(selfpager_trace_log);
        selfpager_trace_log = NULL;
    }
#endif
    return 0;
}
