#include "log.h"
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include "utils.h"
#include "structs.h"

uint64_t log[512];
uint64_t* p_log = log;

void log_word(uint64_t word) {}

#if KSTUFF_PATHLOG
enum
{
    UELF_PATH_LOG_PENDING_SLOT_COUNT = 256,
};

struct pathlog_pending_slot
{
    uint64_t td;
    struct uelf_path_log_entry entry;
};

static struct pathlog_pending_slot g_pathlog_pending_slots[UELF_PATH_LOG_PENDING_SLOT_COUNT];

int pathlog_enabled_fast(void)
{
    return !!__atomic_load_n(&shared_area.path_log_enabled, __ATOMIC_ACQUIRE);
}

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

static void copy_empty_string(char* dst, size_t dst_size)
{
    if(dst_size)
        dst[0] = '\0';
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

static uint64_t pathlog_normalize_event_mask(uint64_t event_mask)
{
    return event_mask ? event_mask : UELF_PATH_LOG_DEFAULT_EVENT_MASK;
}

static int pathlog_kind_enabled(uint64_t event_mask, uint16_t kind)
{
    return !!(pathlog_normalize_event_mask(event_mask) & UELF_PATH_LOG_MASK(kind));
}

static int pathlog_pid_matches_filter(uint32_t pid, uint32_t pid_filter)
{
    return !pid_filter || pid == pid_filter;
}

static int path_matches_filter(const char* path1, const char* path2, const char* filter, size_t filter_length)
{
    if(!filter_length)
        return 1;
    return path_contains_substring(path1, filter, filter_length)
        || path_contains_substring(path2, filter, filter_length);
}

static uint32_t pathlog_get_pid(uint64_t td)
{
    uint64_t proc;
    uint64_t pid;

    if(kpeek64_checked(td + td_proc, &proc))
        return 0;
    if(kpeek64_checked(proc + p_pid, &pid))
        return 0;
    return (uint32_t)pid;
}

static struct pathlog_pending_slot* acquire_pathlog_pending_slot(uint64_t td)
{
    uint64_t start = (td >> 4) % UELF_PATH_LOG_PENDING_SLOT_COUNT;

    for(uint64_t i = 0; i < UELF_PATH_LOG_PENDING_SLOT_COUNT; i++)
    {
        struct pathlog_pending_slot* slot =
            &g_pathlog_pending_slots[(start + i) % UELF_PATH_LOG_PENDING_SLOT_COUNT];
        uint64_t expected = 0;
        if(__atomic_compare_exchange_n(&slot->td, &expected, td, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return slot;
    }

    return 0;
}

static void release_pathlog_pending_slot(struct uelf_path_log_entry* pending)
{
    struct pathlog_pending_slot* slot = (void*)((char*)pending - offsetof(struct pathlog_pending_slot, entry));
    __atomic_store_n(&slot->td, 0, __ATOMIC_RELEASE);
}

static void snapshot_path_log_settings(uint32_t* enabled, char filter[UELF_PATH_LOG_PATH_MAX],
                                       uint32_t* filter_length, uint32_t* pid_filter,
                                       uint64_t* event_mask)
{
    for(;;)
    {
        uint32_t seq1 = __atomic_load_n(&shared_area.path_log_settings_seq, __ATOMIC_ACQUIRE);
        if(seq1 & 1)
            continue;
        *enabled = shared_area.path_log_enabled;
        *filter_length = shared_area.path_log_filter_length;
        *pid_filter = shared_area.path_log_pid_filter;
        *event_mask = shared_area.path_log_event_mask;
        memcpy(filter, shared_area.path_log_filter, UELF_PATH_LOG_PATH_MAX);
        uint32_t seq2 = __atomic_load_n(&shared_area.path_log_settings_seq, __ATOMIC_ACQUIRE);
        if(seq1 == seq2 && !(seq2 & 1))
            return;
    }
}

static void update_path_log_settings(uint32_t enabled, const char* filter, uint32_t filter_length,
                                     uint32_t pid_filter, uint64_t event_mask)
{
    __atomic_add_fetch(&shared_area.path_log_settings_seq, 1, __ATOMIC_RELEASE);
    shared_area.path_log_enabled = enabled;
    shared_area.path_log_filter_length = filter_length;
    shared_area.path_log_pid_filter = pid_filter;
    shared_area.path_log_event_mask = event_mask;
    memset(shared_area.path_log_filter, 0, sizeof(shared_area.path_log_filter));
    if(filter_length)
        memcpy(shared_area.path_log_filter, filter, filter_length);
    __atomic_add_fetch(&shared_area.path_log_settings_seq, 1, __ATOMIC_RELEASE);
}

int pathlog_should_wrap_syscall(uint64_t td, uint16_t kind)
{
    uint32_t enabled;
    uint32_t filter_length;
    uint32_t pid_filter;
    uint64_t event_mask;
    char filter[UELF_PATH_LOG_PATH_MAX];

    snapshot_path_log_settings(&enabled, filter, &filter_length, &pid_filter, &event_mask);
    (void)filter;
    (void)filter_length;
    if(!enabled)
        return 0;
    if(!pathlog_kind_enabled(event_mask, kind))
        return 0;
    if(pid_filter && !pathlog_pid_matches_filter(pathlog_get_pid(td), pid_filter))
        return 0;
    return 1;
}

struct uelf_path_log_entry* prepare_pathlog_event(uint64_t td, uint16_t kind,
                                                  uint64_t path1_ptr, uint64_t path2_ptr,
                                                  uint64_t arg0, uint64_t arg1)
{
    uint32_t enabled;
    uint32_t filter_length;
    uint32_t pid_filter;
    uint64_t event_mask;
    char filter[UELF_PATH_LOG_PATH_MAX];
    struct pathlog_pending_slot* slot;
    struct uelf_path_log_entry* pending;

    snapshot_path_log_settings(&enabled, filter, &filter_length, &pid_filter, &event_mask);
    if(!enabled)
        return 0;
    if(!pathlog_kind_enabled(event_mask, kind))
        return 0;

    slot = acquire_pathlog_pending_slot(td);
    if(!slot)
    {
        __atomic_add_fetch(&shared_area.path_log_dropped_count, 1, __ATOMIC_RELAXED);
        return 0;
    }
    pending = &slot->entry;

    memset(pending, 0, sizeof(*pending));
    pending->pid = pathlog_get_pid(td);
    if(!pathlog_pid_matches_filter(pending->pid, pid_filter))
    {
        release_pathlog_pending_slot(pending);
        return 0;
    }
    pending->kind = kind;
    pending->arg0 = arg0;
    pending->arg1 = arg1;

    if(path1_ptr)
        pending->path1_length = (uint16_t)copy_user_cstring(
            pending->path1, sizeof(pending->path1), path1_ptr, UELF_PATH_LOG_PATH_MAX - 1);
    else
        copy_empty_string(pending->path1, sizeof(pending->path1));

    if(path2_ptr)
    {
        pending->path2_length = (uint16_t)copy_user_cstring(
            pending->path2, sizeof(pending->path2), path2_ptr, UELF_PATH_LOG_PATH_MAX - 1);
        if(pending->path2[0])
            pending->flags |= UELF_PATH_LOG_FLAG_HAS_PATH2;
    }
    else
        copy_empty_string(pending->path2, sizeof(pending->path2));

    if(!path_matches_filter(pending->path1, pending->path2, filter, filter_length))
    {
        release_pathlog_pending_slot(pending);
        return 0;
    }

    return pending;
}

static void commit_pathlog_event(const struct uelf_path_log_entry* pending)
{
    uint64_t seq = __atomic_add_fetch(&shared_area.path_log_write_seq, 1, __ATOMIC_RELAXED);
    struct uelf_path_log_entry* entry =
        &shared_area.path_log_entries[(seq - 1) % UELF_PATH_LOG_ENTRY_COUNT];

    __atomic_store_n(&entry->seq, 0, __ATOMIC_RELAXED);
    memcpy(entry, pending, sizeof(*entry));
    __atomic_store_n(&entry->seq, seq, __ATOMIC_RELEASE);
}

__attribute__((noinline))
int pathlog_syscall_wrapper(uint64_t td, void* uap, struct uelf_path_log_entry* pending,
                            int (*target)(void*, void*))
{
    int error = target((void*)td, uap);

    pending->error = error;
    pending->retval = 0;
    if(!error)
        copy_from_kernel(&pending->retval, td + td_retval, sizeof(pending->retval));

    commit_pathlog_event(pending);
    release_pathlog_pending_slot(pending);
    return error;
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

struct pathlog_delta_ref
{
    uint64_t seq;
    uint16_t slot;
};

static void sort_path_log_delta_refs(struct pathlog_delta_ref* refs, uint32_t count)
{
    for(uint32_t i = 1; i < count; i++)
    {
        struct pathlog_delta_ref cur = refs[i];
        int j = (int)i - 1;

        while(j >= 0 && refs[j].seq > cur.seq)
        {
            refs[j + 1] = refs[j];
            j--;
        }

        refs[j + 1] = cur;
    }
}

int copy_path_log_snapshot(uint64_t dst, uint64_t sz)
{
    enum { SNAPSHOT_HEADER_SIZE = offsetof(struct uelf_path_log_snapshot, entries) };
    uint8_t header[SNAPSHOT_HEADER_SIZE];
    uint32_t logging_enabled;
    uint32_t filter_length;
    uint32_t pid_filter;
    uint32_t entry_count = UELF_PATH_LOG_ENTRY_COUNT;
    uint64_t write_seq;
    uint64_t event_mask;
    uint64_t dropped_count;
    char filter[UELF_PATH_LOG_PATH_MAX];

    if(sz < sizeof(struct uelf_path_log_snapshot))
        return EINVAL;

    write_seq = __atomic_load_n(&shared_area.path_log_write_seq, __ATOMIC_ACQUIRE);
    dropped_count = __atomic_load_n(&shared_area.path_log_dropped_count, __ATOMIC_ACQUIRE);
    snapshot_path_log_settings(&logging_enabled, filter, &filter_length, &pid_filter, &event_mask);

    memset(header, 0, sizeof(header));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, write_seq), &write_seq, sizeof(write_seq));
    event_mask = pathlog_normalize_event_mask(event_mask);
    memcpy(header + offsetof(struct uelf_path_log_snapshot, event_mask), &event_mask, sizeof(event_mask));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, dropped_count), &dropped_count, sizeof(dropped_count));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, entry_count), &entry_count, sizeof(entry_count));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, logging_enabled), &logging_enabled, sizeof(logging_enabled));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, filter_length), &filter_length, sizeof(filter_length));
    memcpy(header + offsetof(struct uelf_path_log_snapshot, pid_filter), &pid_filter, sizeof(pid_filter));
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

int copy_path_log_delta(uint64_t dst, uint64_t sz, uint64_t after_seq)
{
    enum { DELTA_HEADER_SIZE = offsetof(struct uelf_path_log_delta, entries) };
    uint8_t header[DELTA_HEADER_SIZE];
    struct pathlog_delta_ref refs[UELF_PATH_LOG_ENTRY_COUNT];
    uint32_t entry_capacity;
    uint32_t ref_count = 0;
    uint32_t entry_count = 0;
    uint64_t write_seq;
    uint64_t oldest_available_seq = 0;
    uint64_t dropped_count;

    if(sz < DELTA_HEADER_SIZE)
        return EINVAL;

    entry_capacity = (uint32_t)((sz - DELTA_HEADER_SIZE) / sizeof(struct uelf_path_log_entry));
    if(entry_capacity > UELF_PATH_LOG_ENTRY_COUNT)
        entry_capacity = UELF_PATH_LOG_ENTRY_COUNT;

    write_seq = __atomic_load_n(&shared_area.path_log_write_seq, __ATOMIC_ACQUIRE);
    dropped_count = __atomic_load_n(&shared_area.path_log_dropped_count, __ATOMIC_ACQUIRE);
    if(write_seq)
    {
        oldest_available_seq = (write_seq > UELF_PATH_LOG_ENTRY_COUNT)
            ? (write_seq - UELF_PATH_LOG_ENTRY_COUNT + 1)
            : 1;
    }

    for(int i = 0; i < UELF_PATH_LOG_ENTRY_COUNT; i++)
    {
        struct uelf_path_log_entry entry;

        snapshot_path_log_entry(&entry, &shared_area.path_log_entries[i]);
        if(!entry.seq || entry.seq <= after_seq || entry.seq > write_seq)
            continue;
        refs[ref_count].seq = entry.seq;
        refs[ref_count].slot = (uint16_t)i;
        ref_count++;
    }

    sort_path_log_delta_refs(refs, ref_count);
    if(ref_count > entry_capacity)
        ref_count = entry_capacity;

    for(uint32_t i = 0; i < ref_count; i++)
    {
        struct uelf_path_log_entry entry;
        int err;

        snapshot_path_log_entry(&entry, &shared_area.path_log_entries[refs[i].slot]);
        if(entry.seq != refs[i].seq)
            continue;

        err = copy_to_kernel(
            dst + offsetof(struct uelf_path_log_delta, entries) + sizeof(entry) * entry_count,
            &entry,
            sizeof(entry));
        if(err)
            return err;
        entry_count++;
    }

    memset(header, 0, sizeof(header));
    memcpy(header + offsetof(struct uelf_path_log_delta, write_seq), &write_seq, sizeof(write_seq));
    memcpy(header + offsetof(struct uelf_path_log_delta, oldest_available_seq),
           &oldest_available_seq, sizeof(oldest_available_seq));
    memcpy(header + offsetof(struct uelf_path_log_delta, dropped_count), &dropped_count, sizeof(dropped_count));
    memcpy(header + offsetof(struct uelf_path_log_delta, entry_count), &entry_count, sizeof(entry_count));

    int err = copy_to_kernel(dst, header, sizeof(header));
    if(err)
        return err;

    return 0;
}

int set_path_log_enabled(uint64_t enabled)
{
    uint32_t ignored_enabled;
    uint32_t filter_length;
    uint32_t pid_filter;
    uint64_t event_mask;
    char filter[UELF_PATH_LOG_PATH_MAX];
    snapshot_path_log_settings(&ignored_enabled, filter, &filter_length, &pid_filter, &event_mask);
    update_path_log_settings(!!enabled, filter, filter_length, pid_filter, event_mask);
    return 0;
}

int set_path_log_filter(uint64_t src, uint64_t sz)
{
    uint32_t enabled;
    uint32_t ignored_length;
    uint32_t pid_filter;
    uint64_t event_mask;
    char ignored_filter[UELF_PATH_LOG_PATH_MAX];
    char filter[UELF_PATH_LOG_PATH_MAX] = {0};
    if(!src || !sz)
    {
        snapshot_path_log_settings(&enabled, ignored_filter, &ignored_length, &pid_filter, &event_mask);
        update_path_log_settings(enabled, filter, 0, pid_filter, event_mask);
        return 0;
    }

    size_t filter_length = copy_user_cstring(filter, sizeof(filter), src, sz);
    if(filter_length >= UELF_PATH_LOG_PATH_MAX)
        filter_length = UELF_PATH_LOG_PATH_MAX - 1;
    snapshot_path_log_settings(&enabled, ignored_filter, &ignored_length, &pid_filter, &event_mask);
    update_path_log_settings(enabled, filter, (uint32_t)filter_length, pid_filter, event_mask);
    return 0;
}

int set_path_log_event_mask(uint64_t mask)
{
    uint32_t enabled;
    uint32_t filter_length;
    uint32_t pid_filter;
    uint64_t ignored_mask;
    char filter[UELF_PATH_LOG_PATH_MAX];

    snapshot_path_log_settings(&enabled, filter, &filter_length, &pid_filter, &ignored_mask);
    update_path_log_settings(enabled, filter, filter_length, pid_filter, mask);
    return 0;
}

int set_path_log_pid_filter(uint64_t pid)
{
    uint32_t enabled;
    uint32_t filter_length;
    uint32_t ignored_pid_filter;
    uint64_t event_mask;
    char filter[UELF_PATH_LOG_PATH_MAX];

    if(pid >> 32)
        return EINVAL;

    snapshot_path_log_settings(&enabled, filter, &filter_length, &ignored_pid_filter, &event_mask);
    update_path_log_settings(enabled, filter, filter_length, (uint32_t)pid, event_mask);
    return 0;
}
#else
int pathlog_enabled_fast(void)
{
    return 0;
}

int pathlog_should_wrap_syscall(uint64_t td, uint16_t kind)
{
    (void)td;
    (void)kind;
    return 0;
}

struct uelf_path_log_entry* prepare_pathlog_event(uint64_t td, uint16_t kind,
                                                  uint64_t path1_ptr, uint64_t path2_ptr,
                                                  uint64_t arg0, uint64_t arg1)
{
    (void)td;
    (void)kind;
    (void)path1_ptr;
    (void)path2_ptr;
    (void)arg0;
    (void)arg1;
    return 0;
}

int pathlog_syscall_wrapper(uint64_t td, void* uap, struct uelf_path_log_entry* pending,
                            int (*target)(void*, void*))
{
    (void)td;
    (void)uap;
    (void)pending;
    (void)target;
    return ENOSYS;
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

int set_path_log_event_mask(uint64_t mask)
{
    (void)mask;
    return ENOSYS;
}

int set_path_log_pid_filter(uint64_t pid)
{
    (void)pid;
    return ENOSYS;
}
#endif
