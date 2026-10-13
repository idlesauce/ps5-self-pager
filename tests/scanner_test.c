/* Host tests of the production scanner with mocked filesystem/decryption APIs.
 * scanner.inc is extracted from main.c by run-scanner-tests.ps1. */
#define _CRT_SECURE_NO_WARNINGS
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_MAX 1024
#define DT_UNKNOWN 0
#define DT_DIR 4
#define DT_REG 8
#define DT_LNK 10
#define S_ISDIR(mode) ((mode) == DT_DIR)
#define S_ISREG(mode) ((mode) == DT_REG)
#define strcasecmp _stricmp
#define DUMP_GAME
#define PAGER_TRACE(...) ((void)0)

struct dirent { unsigned char d_type; size_t d_namlen; char d_name[128]; };
struct stat { int st_mode; };
struct statfs { char f_mntonname[PATH_MAX]; char f_fstypename[16]; };
typedef struct { const char *path; int index; struct dirent entry; } DIR;
struct node { const char *path; int type; const char *fs; const char *mount; };
static const struct node nodes[] = {
    {"/mnt/sandbox/pfsmnt", DT_DIR},
    {"/mnt/sandbox/pfsmnt/PPSA00001-app0", DT_DIR},
    {"/mnt/sandbox/pfsmnt/PPSA00001-app0/lib", DT_DIR},
    {"/mnt/sandbox/pfsmnt/PPSA00001-app0/lib/test.SPRX", DT_REG},
    {"/mnt/sandbox/pfsmnt/PPSA00001-app0/eboot.bin", DT_REG},
    {"/mnt/sandbox/pfsmnt/PPSA00001-app0/readme.txt", DT_REG},
    {"/mnt/sandbox/pfsmnt/PPSA00001-app0/link.self", DT_LNK},
    {"/mnt/sandbox/pfsmnt/PPSA00001-app0/gone.self", -1},
    {"/mnt/sandbox/pfsmnt/PPSA00001-patch0", DT_DIR},
    {"/mnt/sandbox/pfsmnt/PPSA00001-patch0/update.prx", DT_REG},
    {"/mnt/sandbox/pfsmnt/PPSA00001-app0-patch0-union", DT_DIR},
    {"/mnt/sandbox/pfsmnt/PPSA00001-app0-patch0-union/duplicate.bin", DT_REG},
    {"/system_ex/app", DT_DIR},
    {"/system_ex/app/PPSA00002", DT_DIR, "nullfs", "/system_ex/app/PPSA00002"},
    {"/system_ex/app/PPSA00002/eboot.bin", DT_REG},
    {"/system_ex/app/PPSA00003", DT_DIR, "unionfs", "/system_ex/app/PPSA00003"},
    {"/system_ex/app/PPSA00003/lib", DT_DIR},
    {"/system_ex/app/PPSA00003/lib/test.self", DT_REG},
    {"/system_ex/app/PPSA00004", DT_DIR, "pfs", "/system_ex/app/PPSA00004"},
    {"/system_ex/app/PPSA00004/duplicate.bin", DT_REG},
    {"/system_ex/app/PPSA00005", DT_DIR, "nullfs", "/system_ex"},
    {"/system_ex/app/PPSA00005/unmounted.bin", DT_REG},
    {"/system_ex/app/PPSA00006", DT_LNK},
};
static int unknown_entries, lstat_calls, decrypt_calls;
static char first_input[PATH_MAX];
static const struct node *find_node(const char *path) {
    for (size_t i = 0; i < sizeof(nodes)/sizeof(nodes[0]); i++)
        if (strcmp(nodes[i].path, path) == 0) return &nodes[i];
    return NULL;
}
static int lstat(const char *path, struct stat *st) {
    lstat_calls++;
    const struct node *node = find_node(path);
    if (!node || node->type == -1) { errno = ENOENT; return -1; }
    st->st_mode = node->type;
    return 0;
}
static int statfs(const char *path, struct statfs *fs) {
    const struct node *node = find_node(path);
    if (!node || !node->fs) { errno = ENOENT; return -1; }
    snprintf(fs->f_mntonname, sizeof(fs->f_mntonname), "%s", node->mount);
    snprintf(fs->f_fstypename, sizeof(fs->f_fstypename), "%s", node->fs);
    return 0;
}
static DIR *opendir(const char *path) {
    const struct node *node = find_node(path);
    if (!node || node->type != DT_DIR) { errno = ENOENT; return NULL; }
    DIR *dir = calloc(1, sizeof(*dir));
    assert(dir);
    dir->path = node->path;
    return dir;
}
static struct dirent *readdir(DIR *dir) {
    size_t len = strlen(dir->path);
    while ((size_t)dir->index < sizeof(nodes)/sizeof(nodes[0])) {
        const struct node *node = &nodes[dir->index++];
        if (strncmp(node->path, dir->path, len) != 0 || node->path[len] != '/') continue;
        const char *name = node->path + len + 1;
        if (strchr(name, '/')) continue;
        snprintf(dir->entry.d_name, sizeof(dir->entry.d_name), "%s", name);
        dir->entry.d_namlen = strlen(name);
        dir->entry.d_type = unknown_entries || node->type == -1 ? DT_UNKNOWN : node->type;
        return &dir->entry;
    }
    return NULL;
}
static void rewinddir(DIR *dir) { dir->index = 0; }
static int closedir(DIR *dir) { free(dir); return 0; }
static int decrypt_self_by_path(const char *in, const char *out, int *success, int *failed) {
    (void)failed;
    assert(strstr(in, "duplicate") == NULL);
    assert(strstr(in, "unmounted") == NULL);
    assert(strstr(in, "link") == NULL);
    assert(strstr(in, "readme") == NULL);
    assert(strncmp(out, "/dump", 5) == 0 && strcmp(out + 5, in) == 0);
    if (decrypt_calls == 0) snprintf(first_input, sizeof(first_input), "%s", in);
    decrypt_calls++;
    (*success)++;
    return 0;
}

#include "scanner.inc"

int main(void) {
    for (unknown_entries = 0; unknown_entries <= 1; unknown_entries++) {
        int success = 0, failed = 0;
        decrypt_calls = lstat_calls = 0;
        assert(decrypt_all_selfs_in_directory("/mnt/sandbox/pfsmnt", "/dump/mnt/sandbox/pfsmnt", 1, &success, &failed) == 0);
        assert(success == 3 && failed == 0 && decrypt_calls == 3);
        // The library directory is listed first, but eboot must be processed
        // before recursion so a large asset tree cannot delay root files.
        assert(strcmp(first_input, "/mnt/sandbox/pfsmnt/PPSA00001-app0/eboot.bin") == 0);
        // Known types only stat the disappearing entry in the two passes.
        assert(unknown_entries ? lstat_calls > 2 : lstat_calls == 2);
        decrypt_shadowmount_games("/dump", &success, &failed);
        assert(success == 5 && failed == 0 && decrypt_calls == 5);
        success = decrypt_calls = 0;
        assert(decrypt_all_selfs_in_directory("/mnt/sandbox/pfsmnt/PPSA00001-app0", "/dump/mnt/sandbox/pfsmnt/PPSA00001-app0", 0, &success, &failed) == 0);
        assert(success == 1 && decrypt_calls == 1);
        assert(decrypt_all_selfs_in_directory(NULL, "/dump", 1, &success, &failed) == -1);
    }
    puts("PASS: known/unknown types, files before recursion, extension filters, symlinks, missing entries, union exclusion, mount selection, output paths");
    return 0;
}
