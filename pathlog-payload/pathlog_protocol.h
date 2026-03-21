#pragma once

#include <stddef.h>
#include <stdint.h>

enum
{
    UELF_PATH_LOG_ENTRY_COUNT = 100,
    UELF_PATH_LOG_PATH_MAX = 240,
};

enum
{
    UELF_PATH_LOG_KIND_OPEN = 1,
    UELF_PATH_LOG_KIND_OPENAT = 2,
    UELF_PATH_LOG_KIND_STAT = 3,
    UELF_PATH_LOG_KIND_LSTAT = 4,
    UELF_PATH_LOG_KIND_NSTAT = 5,
    UELF_PATH_LOG_KIND_FSTATAT = 6,
    UELF_PATH_LOG_KIND_ACCESS = 7,
    UELF_PATH_LOG_KIND_FACCESSAT = 8,
    UELF_PATH_LOG_KIND_READLINK = 9,
    UELF_PATH_LOG_KIND_READLINKAT = 10,
    UELF_PATH_LOG_KIND_MKDIR = 11,
    UELF_PATH_LOG_KIND_MKDIRAT = 12,
    UELF_PATH_LOG_KIND_UNLINK = 13,
    UELF_PATH_LOG_KIND_UNLINKAT = 14,
    UELF_PATH_LOG_KIND_RENAME = 15,
    UELF_PATH_LOG_KIND_RENAMEAT = 16,
    UELF_PATH_LOG_KIND_LINK = 17,
    UELF_PATH_LOG_KIND_LINKAT = 18,
    UELF_PATH_LOG_KIND_SYMLINK = 19,
    UELF_PATH_LOG_KIND_SYMLINKAT = 20,
};

#define UELF_PATH_LOG_MASK(kind) (1ull << ((kind) - 1))

enum
{
    UELF_PATH_LOG_FLAG_HAS_PATH2 = 0x0001,
};

#define UELF_PATH_LOG_DEFAULT_EVENT_MASK ( \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_OPEN) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_OPENAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_STAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_LSTAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_NSTAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_FSTATAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_ACCESS) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_FACCESSAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_READLINK) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_READLINKAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_MKDIR) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_MKDIRAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_UNLINK) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_UNLINKAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_RENAME) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_RENAMEAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_LINK) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_LINKAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_SYMLINK) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_SYMLINKAT))

#define UELF_PATH_LOG_STABLE_EVENT_MASK ( \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_OPEN) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_OPENAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_STAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_LSTAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_NSTAT) | \
    UELF_PATH_LOG_MASK(UELF_PATH_LOG_KIND_FSTATAT))

struct uelf_path_log_entry
{
    uint64_t seq;
    uint64_t retval;
    uint64_t arg0;
    uint64_t arg1;
    uint32_t pid;
    uint16_t kind;
    uint16_t flags;
    int32_t error;
    uint16_t path1_length;
    uint16_t path2_length;
    char path1[UELF_PATH_LOG_PATH_MAX];
    char path2[UELF_PATH_LOG_PATH_MAX];
};

struct uelf_path_log_snapshot
{
    uint64_t write_seq;
    uint64_t event_mask;
    uint64_t dropped_count;
    uint32_t entry_count;
    uint32_t logging_enabled;
    uint32_t filter_length;
    uint32_t pid_filter;
    char filter[UELF_PATH_LOG_PATH_MAX];
    struct uelf_path_log_entry entries[UELF_PATH_LOG_ENTRY_COUNT];
};

struct uelf_path_log_delta
{
    uint64_t write_seq;
    uint64_t oldest_available_seq;
    uint64_t dropped_count;
    uint32_t entry_count;
    uint32_t reserved;
    struct uelf_path_log_entry entries[UELF_PATH_LOG_ENTRY_COUNT];
};

_Static_assert(sizeof(struct uelf_path_log_entry) == 528, "Unexpected pathlog entry ABI size");
_Static_assert(offsetof(struct uelf_path_log_snapshot, entries) == 280, "Unexpected pathlog snapshot header ABI");
_Static_assert(sizeof(struct uelf_path_log_snapshot) == 53080, "Unexpected pathlog snapshot ABI size");
_Static_assert(offsetof(struct uelf_path_log_delta, entries) == 32, "Unexpected pathlog delta header ABI");
_Static_assert(sizeof(struct uelf_path_log_delta) == 52832, "Unexpected pathlog delta ABI size");
