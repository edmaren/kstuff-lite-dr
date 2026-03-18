#pragma once
#include <stdint.h>

#ifndef KSTUFF_PATHLOG
#define KSTUFF_PATHLOG 0
#endif

enum
{
    UELF_SHARED_AREA_SIZE = 16384,
};

#if KSTUFF_PATHLOG
enum
{
    UELF_PATH_LOG_ENTRY_COUNT = 50,
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
};

struct uelf_path_log_entry
{
    uint64_t seq;
    uint16_t kind;
    uint16_t length;
    char path[UELF_PATH_LOG_PATH_MAX];
};

struct uelf_path_log_snapshot
{
    uint64_t write_seq;
    uint32_t entry_count;
    uint32_t logging_enabled;
    uint32_t filter_length;
    char filter[UELF_PATH_LOG_PATH_MAX];
    struct uelf_path_log_entry entries[UELF_PATH_LOG_ENTRY_COUNT];
};
#endif

struct uelf_shared_area
{
    uint64_t bitmask;
    uint64_t ready_mask;
    char pad0[16];
    char key_data[63][32];
#if KSTUFF_PATHLOG
    uint32_t path_log_settings_seq;
    uint32_t path_log_enabled;
    uint32_t path_log_filter_length;
    uint64_t path_log_write_seq;
    char path_log_filter[UELF_PATH_LOG_PATH_MAX];
    struct uelf_path_log_entry path_log_entries[UELF_PATH_LOG_ENTRY_COUNT];
#endif
};

_Static_assert(sizeof(struct uelf_shared_area) <= UELF_SHARED_AREA_SIZE, "shared area too large");

extern struct uelf_shared_area shared_area;
