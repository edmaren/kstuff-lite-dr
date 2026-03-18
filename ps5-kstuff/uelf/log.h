#pragma once
#include <sys/types.h>
#include "shared_area.h"

#define KEKCALL_READ_PATH_LOG 0x600000027ull
#define KEKCALL_SET_PATH_LOG_ENABLED 0x700000027ull
#define KEKCALL_SET_PATH_LOG_FILTER 0x800000027ull

void log_word(uint64_t word);
void log_path_event(uint16_t kind, uint64_t path_ptr);
int copy_path_log_snapshot(uint64_t dst, uint64_t sz);
int set_path_log_enabled(uint64_t enabled);
int set_path_log_filter(uint64_t src, uint64_t sz);
