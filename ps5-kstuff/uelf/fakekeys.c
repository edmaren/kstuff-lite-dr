#include <stdint.h>
#include <string.h>
#include "fakekeys.h"

extern struct
{
    uint64_t bitmask;
    uint64_t ready_mask;
    char pad[16];
    char key_data[63][32];
} shared_area;

int register_fake_key(const char key_data[32])
{
    uint64_t mask, mask1;
    mask = __atomic_load_n(&shared_area.bitmask, __ATOMIC_ACQUIRE);
    do
    {
        mask1 = (mask | (mask + 1)) & ((1ull << 63) - 1);
        if(mask1 == mask)
            return -1;
    }
    while(!__atomic_compare_exchange_n(&shared_area.bitmask, &mask, mask1, 1, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));
    int key_idx = 63 - __builtin_clzll(mask ^ mask1);
    uint64_t bit = 1ull << key_idx;
    memcpy(shared_area.key_data[key_idx], key_data, 32);
    __atomic_fetch_or(&shared_area.ready_mask, bit, __ATOMIC_RELEASE);
    return key_idx;
}

int unregister_fake_key(int key_id)
{
    if(key_id < 0 || key_id >= 63)
        return 0;
    uint64_t bit = 1ull << key_id;
    uint64_t mask, mask1;
    mask = __atomic_load_n(&shared_area.ready_mask, __ATOMIC_ACQUIRE);
    do
    {
        if(!(mask & bit))
            return 0;
        mask1 = mask & ~bit;
    }
    while(!__atomic_compare_exchange_n(&shared_area.ready_mask, &mask, mask1, 1, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    __atomic_fetch_and(&shared_area.bitmask, ~bit, __ATOMIC_RELEASE);
    return 1;
}

int get_fake_key(int key_id, char key_data[32])
{
    if(key_id < 0 || key_id >= 63)
        return 0;
    uint64_t bit = 1ull << key_id;
    uint64_t mask = __atomic_load_n(&shared_area.ready_mask, __ATOMIC_ACQUIRE);
    if(!(mask & bit))
        return 0;
    memcpy(key_data, shared_area.key_data[key_id], 32);
    return 1;
}
