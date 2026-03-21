#pragma once
#include <sys/types.h>
#include "shared_area.h"

#define KEKCALL_READ_PATH_LOG 0x600000027ull
#define KEKCALL_SET_PATH_LOG_ENABLED 0x700000027ull
#define KEKCALL_SET_PATH_LOG_FILTER 0x800000027ull
#define KEKCALL_SET_PATH_LOG_EVENT_MASK 0x900000027ull
#define KEKCALL_SET_PATH_LOG_PID_FILTER 0xa00000027ull
#define KEKCALL_READ_PATH_LOG_DELTA 0xb00000027ull

void log_word(uint64_t word);
int pathlog_enabled_fast(void);
int pathlog_should_wrap_syscall(uint64_t td, uint16_t kind);
struct uelf_path_log_entry* prepare_pathlog_event(uint64_t td, uint16_t kind,
                                                  uint64_t path1_ptr, uint64_t path2_ptr,
                                                  uint64_t arg0, uint64_t arg1);
int pathlog_syscall_wrapper(uint64_t td, void* uap, struct uelf_path_log_entry* pending,
                            int (*target)(void*, void*));
int copy_path_log_snapshot(uint64_t dst, uint64_t sz);
int copy_path_log_delta(uint64_t dst, uint64_t sz, uint64_t after_seq);
int set_path_log_enabled(uint64_t enabled);
int set_path_log_filter(uint64_t src, uint64_t sz);
int set_path_log_event_mask(uint64_t mask);
int set_path_log_pid_filter(uint64_t pid);
