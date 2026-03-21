#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include "monitor_common.h"
#include "pathlog_protocol.h"

#if !defined(PATHLOG_MONITOR_MODE_ALL) && !defined(PATHLOG_MONITOR_MODE_APPS)
#error "Build with PATHLOG_MONITOR_MODE_ALL or PATHLOG_MONITOR_MODE_APPS"
#endif

#define KEKCALL_READ_PATH_LOG         0x600000027ull
#define KEKCALL_SET_PATH_LOG_ENABLED  0x700000027ull
#define KEKCALL_SET_PATH_LOG_FILTER   0x800000027ull
#define KEKCALL_SET_PATH_LOG_EVENT_MASK 0x900000027ull
#define KEKCALL_SET_PATH_LOG_PID_FILTER 0xa00000027ull
#define KEKCALL_READ_PATH_LOG_DELTA 0xb00000027ull
#define APP_PATH_FILTER "/app0/"

static volatile sig_atomic_t g_stop_requested;
static struct uelf_path_log_delta g_delta;

#if defined(PATHLOG_MONITOR_MODE_APPS)
struct app_session
{
    pid_t pid;
    char title_id[10];
    FILE* log_file;
    uint64_t last_seq;
    uint64_t last_dropped_count;
};
#endif

static int64_t kekcall(uint64_t a, uint64_t b, uint64_t c,
                       uint64_t d, uint64_t e, uint64_t f, uint64_t g)
{
    register uint64_t r10 __asm__("r10") = d;
    register uint64_t r8 __asm__("r8") = e;
    register uint64_t r9 __asm__("r9") = f;
    uint64_t ret;
    unsigned char is_error;

    __asm__ __volatile__(
        "syscall"
        : "=a"(ret), "=@ccc"(is_error), "+r"(r10), "+r"(r8), "+r"(r9)
        : "a"(g), "D"(a), "S"(b), "d"(c)
        : "rcx", "r11", "memory");

    return is_error ? -(int64_t)ret : (int64_t)ret;
}

static void request_stop(int sig)
{
    (void)sig;
    g_stop_requested = 1;
}

static void install_signal_handlers(void)
{
    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);
    signal(SIGQUIT, request_stop);
    signal(SIGHUP, request_stop);
}

static void notify_debug(const char* fmt, ...)
{
    notify_request_t req = {0};
    va_list args;

    va_start(args, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, args);
    va_end(args);

    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static void sleep_brief(void)
{
    static const struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = PATHLOG_POLL_NSEC};
    nanosleep(&sleep_time, NULL);
}

static const char* kind_name(uint16_t kind)
{
    switch(kind)
    {
    case UELF_PATH_LOG_KIND_OPEN: return "open";
    case UELF_PATH_LOG_KIND_OPENAT: return "openat";
    case UELF_PATH_LOG_KIND_STAT: return "stat";
    case UELF_PATH_LOG_KIND_LSTAT: return "lstat";
    case UELF_PATH_LOG_KIND_NSTAT: return "nstat";
    case UELF_PATH_LOG_KIND_FSTATAT: return "fstatat";
    case UELF_PATH_LOG_KIND_ACCESS: return "access";
    case UELF_PATH_LOG_KIND_FACCESSAT: return "faccessat";
    case UELF_PATH_LOG_KIND_READLINK: return "readlink";
    case UELF_PATH_LOG_KIND_READLINKAT: return "readlinkat";
    case UELF_PATH_LOG_KIND_MKDIR: return "mkdir";
    case UELF_PATH_LOG_KIND_MKDIRAT: return "mkdirat";
    case UELF_PATH_LOG_KIND_UNLINK: return "unlink";
    case UELF_PATH_LOG_KIND_UNLINKAT: return "unlinkat";
    case UELF_PATH_LOG_KIND_RENAME: return "rename";
    case UELF_PATH_LOG_KIND_RENAMEAT: return "renameat";
    case UELF_PATH_LOG_KIND_LINK: return "link";
    case UELF_PATH_LOG_KIND_LINKAT: return "linkat";
    case UELF_PATH_LOG_KIND_SYMLINK: return "symlink";
    case UELF_PATH_LOG_KIND_SYMLINKAT: return "symlinkat";
    default: return "unknown";
    }
}

static void format_timestamp(char* dst, size_t dst_size)
{
    struct timespec ts;
    struct tm tm;
    time_t sec;

    clock_gettime(CLOCK_REALTIME, &ts);
    sec = ts.tv_sec;
    localtime_r(&sec, &tm);
    snprintf(dst, dst_size, "%04d-%02d-%02dT%02d:%02d:%02d.%03ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
}

static void write_escaped_field(FILE* stream, const char* value)
{
    const unsigned char* p = (const unsigned char*)value;

    while(*p)
    {
        switch(*p)
        {
        case '\\':
            fputs("\\\\", stream);
            break;
        case '\t':
            fputs("\\t", stream);
            break;
        case '\n':
            fputs("\\n", stream);
            break;
        case '\r':
            fputs("\\r", stream);
            break;
        default:
            fputc(*p, stream);
            break;
        }
        p++;
    }
}

static void format_status(char* dst, size_t dst_size, int error)
{
    if(error)
        snprintf(dst, dst_size, "err:%d", error);
    else
        snprintf(dst, dst_size, "ok");
}

static void format_retval(char* dst, size_t dst_size, const struct uelf_path_log_entry* entry)
{
    if(entry->error)
        snprintf(dst, dst_size, "-");
    else
        snprintf(dst, dst_size, "%llu", (unsigned long long)entry->retval);
}

static void format_arg(char* dst, size_t dst_size, uint64_t value)
{
    snprintf(dst, dst_size, "%lld", (long long)value);
}

static void emit_record(FILE* log_file, const char* kind, uint32_t pid, const char* status,
                        const char* retval, const char* arg0, const char* arg1,
                        const char* path1, const char* path2)
{
    char timestamp[32];

    format_timestamp(timestamp, sizeof(timestamp));

    fprintf(stdout, "%s\t%u\t%s\t%s\t%s\t%s\t%s\t", timestamp, pid, kind, status, retval, arg0, arg1);
    write_escaped_field(stdout, path1);
    fputc('\t', stdout);
    write_escaped_field(stdout, path2);
    fputc('\n', stdout);

    if(log_file)
    {
        fprintf(log_file, "%s\t%u\t%s\t%s\t%s\t%s\t%s\t", timestamp, pid, kind, status, retval, arg0, arg1);
        write_escaped_field(log_file, path1);
        fputc('\t', log_file);
        write_escaped_field(log_file, path2);
        fputc('\n', log_file);
    }
}

static void emit_line(FILE* log_file, const struct uelf_path_log_entry* entry)
{
    char status[32];
    char retval[32];
    char arg0[32];
    char arg1[32];

    format_status(status, sizeof(status), entry->error);
    format_retval(retval, sizeof(retval), entry);
    format_arg(arg0, sizeof(arg0), entry->arg0);
    format_arg(arg1, sizeof(arg1), entry->arg1);
    emit_record(log_file, kind_name(entry->kind), entry->pid, status, retval, arg0, arg1,
                entry->path1, entry->path2);
}

static void emit_drop_notice(FILE* log_file, uint64_t first_seq, uint64_t last_seq)
{
    char dropped[96];

    if(first_seq == last_seq)
        snprintf(dropped, sizeof(dropped), "seq=%llu", (unsigned long long)first_seq);
    else
        snprintf(dropped, sizeof(dropped), "seq=%llu..%llu",
                 (unsigned long long)first_seq,
                 (unsigned long long)last_seq);

    emit_record(log_file, "dropped", 0, "-", "-", "-", "-", dropped, "");
}

static void emit_drop_counter_notice(FILE* log_file, uint64_t count)
{
    char dropped[96];

    snprintf(dropped, sizeof(dropped), "pending_overflow=%llu",
             (unsigned long long)count);
    emit_record(log_file, "dropped", 0, "-", "-", "-", "-", dropped, "");
}

static int pathlog_clear_filter(void)
{
    return (int)kekcall(0, 0, 0, 0, 0, 0, KEKCALL_SET_PATH_LOG_FILTER);
}

static int pathlog_set_filter(const char* filter)
{
    if(!filter || !filter[0])
        return pathlog_clear_filter();

    return (int)kekcall((uint64_t)(uintptr_t)filter, strlen(filter) + 1, 0, 0, 0, 0,
                        KEKCALL_SET_PATH_LOG_FILTER);
}

static int pathlog_set_enabled(int enabled)
{
    return (int)kekcall((uint64_t)enabled, 0, 0, 0, 0, 0, KEKCALL_SET_PATH_LOG_ENABLED);
}

static int pathlog_set_event_mask(uint64_t mask)
{
    return (int)kekcall(mask, 0, 0, 0, 0, 0, KEKCALL_SET_PATH_LOG_EVENT_MASK);
}

static int pathlog_clear_pid_filter(void)
{
    return (int)kekcall(0, 0, 0, 0, 0, 0, KEKCALL_SET_PATH_LOG_PID_FILTER);
}

static int pathlog_set_pid_filter(uint32_t pid)
{
    if(!pid)
        return pathlog_clear_pid_filter();

    return (int)kekcall((uint64_t)pid, 0, 0, 0, 0, 0, KEKCALL_SET_PATH_LOG_PID_FILTER);
}

static int pathlog_read_delta(struct uelf_path_log_delta* delta, uint64_t after_seq)
{
    memset(delta, 0, sizeof(*delta));
    return (int)kekcall((uint64_t)delta, sizeof(*delta), after_seq, 0, 0, 0,
                        KEKCALL_READ_PATH_LOG_DELTA);
}

static int pathlog_sync_state(uint64_t* last_seq, uint64_t* dropped_count)
{
    int err = pathlog_read_delta(&g_delta, UINT64_MAX);

    if(err)
        return err;

    *last_seq = g_delta.write_seq;
    if(dropped_count)
        *dropped_count = g_delta.dropped_count;
    return 0;
}

static int start_logging_session(uint64_t* last_seq, uint64_t* dropped_count,
                                 const char* filter, uint64_t event_mask, uint32_t pid_filter)
{
    int err = pathlog_set_filter(filter);
    if(err)
        return err;

    err = pathlog_set_event_mask(event_mask);
    if(err)
        return err;

    err = pathlog_set_pid_filter(pid_filter);
    if(err)
        return err;

    err = pathlog_sync_state(last_seq, dropped_count);
    if(err)
        return err;

    return pathlog_set_enabled(1);
}

#if defined(PATHLOG_MONITOR_MODE_APPS)
static int path_has_prefix(const char* path, const char* prefix)
{
    while(*prefix)
    {
        if(*path++ != *prefix++)
            return 0;
    }

    return 1;
}

static int entry_has_app_path(const struct uelf_path_log_entry* entry)
{
    return path_has_prefix(entry->path1, APP_PATH_FILTER)
        || path_has_prefix(entry->path2, APP_PATH_FILTER);
}
#endif

static int should_emit_entry(const struct uelf_path_log_entry* entry, pid_t session_pid)
{
#if defined(PATHLOG_MONITOR_MODE_APPS)
    return entry->pid == (uint32_t)session_pid
        || entry_has_app_path(entry);
#else
    (void)session_pid;
    return 1;
#endif
}

static void drain_delta(FILE* log_file, uint64_t* last_seq, uint64_t* last_dropped_count,
                        const struct uelf_path_log_delta* delta, pid_t session_pid)
{
    if(delta->dropped_count > *last_dropped_count)
    {
        emit_drop_counter_notice(log_file, delta->dropped_count - *last_dropped_count);
        *last_dropped_count = delta->dropped_count;
    }

    if(delta->oldest_available_seq && *last_seq + 1 < delta->oldest_available_seq)
    {
        emit_drop_notice(log_file, *last_seq + 1, delta->oldest_available_seq - 1);
        *last_seq = delta->oldest_available_seq - 1;
    }

    for(uint32_t i = 0; i < delta->entry_count && i < UELF_PATH_LOG_ENTRY_COUNT; i++)
    {
        const struct uelf_path_log_entry* entry = &delta->entries[i];

        if(!entry->seq || entry->seq <= *last_seq)
            continue;
        if(should_emit_entry(entry, session_pid))
            emit_line(log_file, entry);
        if(entry->seq > *last_seq)
            *last_seq = entry->seq;
    }
}

static void stop_logging_session(FILE* log_file, uint64_t* last_seq, uint64_t* last_dropped_count,
                                 pid_t session_pid)
{
    int err = pathlog_set_enabled(0);

    if(!err)
        err = pathlog_read_delta(&g_delta, *last_seq);

    if(!err)
        drain_delta(log_file, last_seq, last_dropped_count, &g_delta, session_pid);

    pathlog_clear_filter();
    pathlog_clear_pid_filter();
}

static int poll_and_emit(FILE* log_file, uint64_t* last_seq, uint64_t* last_dropped_count,
                         pid_t session_pid)
{
    int err = pathlog_read_delta(&g_delta, *last_seq);

    if(err)
        return err;

    drain_delta(log_file, last_seq, last_dropped_count, &g_delta, session_pid);
    return 0;
}

static int ensure_log_dir(void)
{
    if(mkdir(PATHLOG_LOG_DIR, 0777) && errno != EEXIST)
        return -1;

    return 0;
}

static FILE* open_log_file(const char* path)
{
    FILE* log_file = fopen(path, "a");

    if(log_file)
        setvbuf(log_file, NULL, _IOLBF, 0);

    return log_file;
}

static void set_monitor_process_name(void)
{
    syscall(SYS_thr_set_name, -1, PATHLOG_MONITOR_PROC_NAME);
}

static pid_t find_pid(const char* name)
{
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    pid_t mypid = getpid();
    pid_t pid = -1;
    size_t buf_size = 0;
    uint8_t* buf = NULL;

    if(sysctl(mib, 4, NULL, &buf_size, NULL, 0))
        return -1;

    buf = malloc(buf_size);
    if(!buf)
        return -1;

    if(sysctl(mib, 4, buf, &buf_size, NULL, 0))
    {
        free(buf);
        return -1;
    }

    for(uint8_t* ptr = buf; ptr < buf + buf_size;)
    {
        struct kinfo_proc* ki = (struct kinfo_proc*)ptr;

        ptr += ki->ki_structsize;
        if(ki->ki_pid == mypid)
            continue;
        if(strcmp(ki->ki_tdname, name) == 0)
            pid = ki->ki_pid;
    }

    free(buf);
    return pid;
}

static int wait_for_pid_exit(pid_t pid)
{
    for(int i = 0; i < 100; i++)
    {
        if(kill(pid, 0) && errno == ESRCH)
            return 0;
        sleep_brief();
    }

    return -1;
}

static int terminate_old_instances(void)
{
    pid_t pid;

    while((pid = find_pid(PATHLOG_MONITOR_PROC_NAME)) > 0)
    {
        if(kill(pid, SIGTERM))
        {
            fprintf(stderr, "failed to stop existing monitor pid %d: %d\n", pid, errno);
            return -1;
        }
        wait_for_pid_exit(pid);
        sleep(1);
    }

    return 0;
}

#if defined(PATHLOG_MONITOR_MODE_ALL)
static int run_all_mode(void)
{
    FILE* log_file = open_log_file(PATHLOG_ALL_LOG_PATH);
    uint64_t last_seq = 0;
    uint64_t last_dropped_count = 0;
    int logging_active = 0;
    int last_err = 0;

    if(!log_file)
    {
        fprintf(stderr, "failed to open %s: %d\n", PATHLOG_ALL_LOG_PATH, errno);
        return 1;
    }

    notify_debug("Pathlog all monitoring starting");
    while(!g_stop_requested)
    {
        if(!logging_active)
        {
            int err = start_logging_session(
                &last_seq, &last_dropped_count, NULL, UELF_PATH_LOG_STABLE_EVENT_MASK, 0);

            if(err)
            {
                if(err != last_err)
                {
                    fprintf(stderr, "start_logging_session failed: %d\n", err);
                    last_err = err;
                }
                sleep_brief();
                continue;
            }

            logging_active = 1;
            last_err = 0;
            notify_debug("Pathlog all monitoring started");
        }

        if(poll_and_emit(log_file, &last_seq, &last_dropped_count, -1))
        {
            fprintf(stderr, "poll_and_emit failed, retrying\n");
            logging_active = 0;
            pathlog_set_enabled(0);
            pathlog_clear_filter();
            pathlog_clear_pid_filter();
            sleep_brief();
            continue;
        }

        sleep_brief();
    }

    if(logging_active)
        stop_logging_session(log_file, &last_seq, &last_dropped_count, -1);
    else
    {
        pathlog_set_enabled(0);
        pathlog_clear_filter();
        pathlog_clear_pid_filter();
    }
    notify_debug("Pathlog all monitoring stopped");
    fclose(log_file);
    return 0;
}
#endif

#if defined(PATHLOG_MONITOR_MODE_APPS)
static int register_proc_filter(int kq, pid_t pid, uint32_t flags)
{
    struct kevent kev;

    EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR, flags, 0, NULL);
    return kevent(kq, &kev, 1, NULL, 0, NULL);
}

static void app_session_reset(struct app_session* session)
{
    session->pid = -1;
    session->title_id[0] = '\0';
    session->log_file = NULL;
    session->last_seq = 0;
    session->last_dropped_count = 0;
}

static int begin_app_session(struct app_session* session, pid_t pid, const char* title_id)
{
    char log_path[PATH_MAX];
    int err;

    snprintf(log_path, sizeof(log_path), "%s/%s.log", PATHLOG_LOG_DIR, title_id);
    session->log_file = open_log_file(log_path);
    if(!session->log_file)
        return -1;

    session->pid = pid;
    snprintf(session->title_id, sizeof(session->title_id), "%s", title_id);

    err = start_logging_session(
        &session->last_seq, &session->last_dropped_count,
        APP_PATH_FILTER, UELF_PATH_LOG_STABLE_EVENT_MASK, (uint32_t)pid);
    if(err)
    {
        fclose(session->log_file);
        app_session_reset(session);
        return err;
    }

    notify_debug("Pathlog start %s", session->title_id);
    return 0;
}

static void end_app_session(struct app_session* session)
{
    if(session->pid <= 0)
        return;

    stop_logging_session(session->log_file, &session->last_seq, &session->last_dropped_count,
                         session->pid);
    notify_debug("Pathlog stop %s", session->title_id);
    fclose(session->log_file);
    app_session_reset(session);
}

static int run_apps_mode(void)
{
    struct app_session session;
    pid_t child_pid = -1;
    int kq = -1;
    int arm_state = 0;

    app_session_reset(&session);
    notify_debug("Pathlog app monitoring starting");
    while(!g_stop_requested)
    {
        struct timespec timeout = {.tv_sec = 0, .tv_nsec = PATHLOG_POLL_NSEC};
        struct kevent event;

        if(kq < 0)
        {
            pid_t syscore_pid = find_pid("SceSysCore.elf");

            if(syscore_pid <= 0)
            {
                if(arm_state != 1)
                {
                    fprintf(stderr, "SceSysCore.elf not found, waiting\n");
                    arm_state = 1;
                }
                sleep_brief();
                continue;
            }

            kq = kqueue();
            if(kq < 0)
            {
                if(arm_state != 2)
                {
                    fprintf(stderr, "kqueue failed: %d\n", errno);
                    arm_state = 2;
                }
                sleep_brief();
                continue;
            }

            if(register_proc_filter(kq, syscore_pid, NOTE_FORK | NOTE_EXEC | NOTE_TRACK))
            {
                if(arm_state != 3)
                {
                    fprintf(stderr, "register_proc_filter failed: %d\n", errno);
                    arm_state = 3;
                }
                close(kq);
                kq = -1;
                sleep_brief();
                continue;
            }

            arm_state = 0;
            notify_debug("Pathlog app monitoring armed");
        }

        int nev = kevent(kq, NULL, 0, &event, 1, &timeout);

        if(session.pid > 0)
        {
            if(poll_and_emit(session.log_file, &session.last_seq, &session.last_dropped_count,
                             session.pid))
            {
                fprintf(stderr, "poll_and_emit failed during app session\n");
                end_app_session(&session);
            }
        }

        if(nev < 0)
        {
            if(errno == EINTR)
                continue;
            fprintf(stderr, "kevent failed: %d\n", errno);
            if(kq >= 0)
            {
                close(kq);
                kq = -1;
            }
            arm_state = 0;
            sleep_brief();
            continue;
        }

        if(nev == 0)
            continue;

        if((event.fflags & NOTE_EXIT) && session.pid > 0 && (pid_t)event.ident == session.pid)
        {
            end_app_session(&session);
            continue;
        }

        if(event.fflags & NOTE_CHILD)
            child_pid = (pid_t)event.ident;

        if((event.fflags & NOTE_EXEC) && child_pid > 0 && (pid_t)event.ident == child_pid && session.pid <= 0)
        {
            app_info_t appinfo = {0};
            char title_id[10] = {0};

            if(sceKernelGetAppInfo(child_pid, &appinfo) == 0)
            {
                memcpy(title_id, appinfo.title_id, 9);
                if(strncmp(title_id, "PPSA", 4) == 0 || strncmp(title_id, "CUSA", 4) == 0)
                {
                    if(begin_app_session(&session, child_pid, title_id) == 0)
                    {
                        if(register_proc_filter(kq, child_pid, NOTE_EXIT))
                        {
                            fprintf(stderr, "register NOTE_EXIT failed for %s: %d\n", title_id, errno);
                            end_app_session(&session);
                        }
                    }
                    else
                        fprintf(stderr, "begin_app_session failed for %s\n", title_id);
                }
            }

            child_pid = -1;
        }
    }

    end_app_session(&session);
    if(kq >= 0)
        close(kq);
    notify_debug("Pathlog app monitoring stopped");
    return 0;
}
#endif

int main(void)
{
    if(ensure_log_dir())
    {
        fprintf(stderr, "ensure_log_dir failed: %d\n", errno);
        return 1;
    }

    install_signal_handlers();
    set_monitor_process_name();
    setvbuf(stdout, NULL, _IOLBF, 0);

    if(terminate_old_instances())
        return 1;

#if defined(PATHLOG_MONITOR_MODE_ALL)
    return run_all_mode();
#else
    return run_apps_mode();
#endif
}
