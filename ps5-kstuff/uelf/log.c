#include "log.h"
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include "utils.h"

uint64_t log[512];
uint64_t* p_log = log;

void log_word(uint64_t word) {}

#if KSTUFF_PATHLOG
static void copy_literal_string(char* dst, size_t dst_size, const char* src)
{
    size_t i = 0;
    if(!dst_size)
        return;
    while(i + 1 < dst_size && src[i])
    {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static size_t copy_user_cstring(char* dst, size_t dst_size, uint64_t src, size_t src_limit)
{
    // The syscall hook runs before normal copyin/copyout is safe. Read the
    // caller's userspace through the captured CR3 instead.
    if(!dst_size)
        return 0;
    if(!src)
    {
        copy_literal_string(dst, dst_size, "<null>");
        return strlen(dst);
    }
    size_t i = 0;
    while(i + 1 < dst_size && i < src_limit)
    {
        char ch;
        if(copy_from_kernel(&ch, src + i, 1))
        {
            if(!i)
                copy_literal_string(dst, dst_size, "<fault>");
            else
                dst[i] = '\0';
            return strlen(dst);
        }
        dst[i] = ch;
        if(!ch)
            return i;
        i++;
    }
    dst[i < dst_size ? i : (dst_size - 1)] = '\0';
    return strlen(dst);
}

static int path_contains_substring(const char* path, const char* needle, size_t needle_len)
{
    if(!needle_len)
        return 1;
    for(size_t i = 0; path[i]; i++)
    {
        size_t j = 0;
        while(j < needle_len && path[i + j] && path[i + j] == needle[j])
            j++;
        if(j == needle_len)
            return 1;
    }
    return 0;
}

static void snapshot_path_log_settings(uint32_t* enabled, char filter[UELF_PATH_LOG_PATH_MAX], uint32_t* filter_length)
{
    for(;;)
    {
        uint32_t seq1 = __atomic_load_n(&shared_area.path_log_settings_seq, __ATOMIC_ACQUIRE);
        if(seq1 & 1)
            continue;
        *enabled = shared_area.path_log_enabled;
        *filter_length = shared_area.path_log_filter_length;
        memcpy(filter, shared_area.path_log_filter, UELF_PATH_LOG_PATH_MAX);
        uint32_t seq2 = __atomic_load_n(&shared_area.path_log_settings_seq, __ATOMIC_ACQUIRE);
        if(seq1 == seq2 && !(seq2 & 1))
            return;
    }
}

static void update_path_log_settings(uint32_t enabled, const char* filter, uint32_t filter_length)
{
    __atomic_add_fetch(&shared_area.path_log_settings_seq, 1, __ATOMIC_RELEASE);
    shared_area.path_log_enabled = enabled;
    shared_area.path_log_filter_length = filter_length;
    memset(shared_area.path_log_filter, 0, sizeof(shared_area.path_log_filter));
    if(filter_length)
        memcpy(shared_area.path_log_filter, filter, filter_length);
    __atomic_add_fetch(&shared_area.path_log_settings_seq, 1, __ATOMIC_RELEASE);
}

void log_path_event(uint16_t kind, uint64_t path_ptr)
{
    uint32_t enabled;
    uint32_t filter_length;
    char filter[UELF_PATH_LOG_PATH_MAX];
    char path[UELF_PATH_LOG_PATH_MAX];
    snapshot_path_log_settings(&enabled, filter, &filter_length);
    if(!enabled)
        return;

    size_t path_length = copy_user_cstring(path, sizeof(path), path_ptr, UELF_PATH_LOG_PATH_MAX - 1);
    if(filter_length && !path_contains_substring(path, filter, filter_length))
        return;

    uint64_t seq = __atomic_add_fetch(&shared_area.path_log_write_seq, 1, __ATOMIC_RELAXED);
    struct uelf_path_log_entry* entry =
        &shared_area.path_log_entries[(seq - 1) % UELF_PATH_LOG_ENTRY_COUNT];

    __atomic_store_n(&entry->seq, 0, __ATOMIC_RELAXED);
    entry->kind = kind;
    entry->length = (uint16_t)path_length;
    memcpy(entry->path, path, sizeof(entry->path));
    __atomic_store_n(&entry->seq, seq, __ATOMIC_RELEASE);
}

static void snapshot_path_log_entry(struct uelf_path_log_entry* dst,
                                    const struct uelf_path_log_entry* src)
{
    for(int attempts = 0; attempts < 8; attempts++)
    {
        uint64_t seq1 = __atomic_load_n(&src->seq, __ATOMIC_ACQUIRE);
        if(!seq1)
        {
            memset(dst, 0, sizeof(*dst));
            return;
        }
        memcpy(dst, src, sizeof(*dst));
        uint64_t seq2 = __atomic_load_n(&src->seq, __ATOMIC_ACQUIRE);
        if(seq1 == seq2 && dst->seq == seq1)
            return;
    }
    memset(dst, 0, sizeof(*dst));
}

int copy_path_log_snapshot(uint64_t dst, uint64_t sz)
{
    enum { SNAPSHOT_HEADER_SIZE = offsetof(struct uelf_path_log_snapshot, entries) };
    uint8_t header[SNAPSHOT_HEADER_SIZE];
    uint32_t logging_enabled;
    uint32_t filter_length;
    uint32_t entry_count = UELF_PATH_LOG_ENTRY_COUNT;
    uint64_t write_seq;
    char filter[UELF_PATH_LOG_PATH_MAX];

    if(sz < sizeof(struct uelf_path_log_snapshot))
        return EINVAL;

    write_seq = __atomic_load_n(&shared_area.path_log_write_seq, __ATOMIC_ACQUIRE);
    snapshot_path_log_settings(&logging_enabled, filter, &filter_length);

    memset(header, 0, sizeof(header));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, write_seq), &write_seq, sizeof(write_seq));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, entry_count), &entry_count, sizeof(entry_count));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, logging_enabled), &logging_enabled, sizeof(logging_enabled));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, filter_length), &filter_length, sizeof(filter_length));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, filter), filter, sizeof(filter));

    int err = copy_to_kernel(dst, header, sizeof(header));
    if(err)
        return err;

    for(int i = 0; i < UELF_PATH_LOG_ENTRY_COUNT; i++)
    {
        struct uelf_path_log_entry entry;
        snapshot_path_log_entry(&entry, &shared_area.path_log_entries[i]);
        err = copy_to_kernel(
            dst + offsetof(struct uelf_path_log_snapshot, entries) + sizeof(entry) * i,
            &entry,
            sizeof(entry));
        if(err)
            return err;
    }

    return 0;
}

int set_path_log_enabled(uint64_t enabled)
{
    uint32_t old_enabled;
    uint32_t filter_length;
    char filter[UELF_PATH_LOG_PATH_MAX];
    snapshot_path_log_settings(&old_enabled, filter, &filter_length);
    update_path_log_settings(!!enabled, filter, filter_length);
    return 0;
}

int set_path_log_filter(uint64_t src, uint64_t sz)
{
    uint32_t enabled;
    uint32_t ignored_length;
    char ignored_filter[UELF_PATH_LOG_PATH_MAX];
    char filter[UELF_PATH_LOG_PATH_MAX] = {0};
    if(!src || !sz)
    {
        snapshot_path_log_settings(&enabled, ignored_filter, &ignored_length);
        update_path_log_settings(enabled, filter, 0);
        return 0;
    }

    size_t filter_length = copy_user_cstring(filter, sizeof(filter), src, sz);
    if(filter_length >= UELF_PATH_LOG_PATH_MAX)
        filter_length = UELF_PATH_LOG_PATH_MAX - 1;
    snapshot_path_log_settings(&enabled, ignored_filter, &ignored_length);
    update_path_log_settings(enabled, filter, (uint32_t)filter_length);
    return 0;
}
#else
void log_path_event(uint16_t kind, uint64_t path_ptr)
{
    (void)kind;
    (void)path_ptr;
}

int copy_path_log_snapshot(uint64_t dst, uint64_t sz)
{
    (void)dst;
    (void)sz;
    return ENOSYS;
}

int set_path_log_enabled(uint64_t enabled)
{
    (void)enabled;
    return ENOSYS;
}

int set_path_log_filter(uint64_t src, uint64_t sz)
{
    (void)src;
    (void)sz;
    return ENOSYS;
}
#endif
