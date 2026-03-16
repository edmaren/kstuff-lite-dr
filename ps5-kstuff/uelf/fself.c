#include <string.h>
#include <errno.h>
#include "fself.h"
#include "utils.h"
#include "traps.h"
#include "log.h"
#include "syscall_fixes.h"

#ifndef FREEBSD

static uint64_t s_auth_info_for_dynlib[17] = {0x4900000000000002, 0x0000000000000000, 0x800000000000ff00, 0x0000000000000000, 0x0000000000000000, 0x7000700080000000, 0x8000000000000000, 0x0000000000000000, 0xf0000000ffff4000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000};
static uint64_t s_auth_info_for_exec[17] = {0x4400001084c2052d, 0x2000038000000000, 0x000000000000ff00, 0x0000000000000000, 0x0000000000000000, 0x4000400040000000, 0x4000000000000000, 0x0080000000000002, 0xf0000000ffff4000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000};

static uint64_t s_auth_info_for_dynlib_ps4[17] = {0x3100000000000002, 0x0000000000000000, 0x000000000000ff00, 0x0000000000000000, 0x0000000000000000, 0x3000300040000000, 0x4000000000000000, 0x0080000000000000, 0xf0000000ffff4000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000};
static uint64_t s_auth_info_for_exec_ps4[17] = {0x3100000000000001, 0x2000038000000000, 0x000000000000ff00, 0x0000000000000000, 0x0000000000000000, 0x4000400040000000, 0x4000000000000000, 0x0080000000000002, 0xf0000000ffff4000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000};

enum { SELF_BLOCK_SIZE = 16384 };

static int fself_block_ranges_overlap(uint64_t src, uint64_t dst, size_t size)
{
    return src < dst ? dst - src < size : src - dst < size;
}

static void copy_decrypted_self_blocks(char* dmem, const uint64_t* src, const uint64_t* dst, uint32_t count)
{
    for(uint32_t i = 0; i < count;)
    {
        uint64_t run_src = src[i];
        uint64_t run_dst = dst[i];
        size_t run_size = SELF_BLOCK_SIZE;

        if(run_src == run_dst)
        {
            while(i + 1 < count
               && src[i + 1] == run_src + run_size
               && dst[i + 1] == run_dst + run_size)
            {
                i++;
                run_size += SELF_BLOCK_SIZE;
            }
            i++;
            continue;
        }

        // Overlapping runs rely on per-block copy order.
        while(i + 1 < count
           && src[i + 1] == run_src + run_size
           && dst[i + 1] == run_dst + run_size
           && !fself_block_ranges_overlap(run_src, run_dst, run_size + SELF_BLOCK_SIZE))
        {
            i++;
            run_size += SELF_BLOCK_SIZE;
        }

        memcpy(dmem + run_dst, dmem + run_src, run_size);
        i++;
    }
}

struct fself_header_info
{
    int is_fself;
    uint16_t e_type;
    int is_ps4;
    int authinfo_loaded;
    int have_authinfo;
    uint64_t authinfo_offset;
    uint64_t authinfo[17];
};

static struct
{
    uint64_t header;
    uint32_t size;
    int valid;
    struct fself_header_info info;
} s_header_cache;

static struct
{
    uint64_t ctx;
    uint64_t header;
    uint32_t size;
    uint64_t snapshot[8];
    int valid;
} s_context_cache;

static int copy_from_kernel_buffer(void* dst, uint64_t src, uint64_t src_end, uint64_t offset, size_t sz)
{
    if(src + offset < src || src + offset > src_end)
        return EFAULT;
    if(src + offset + sz < src + offset || src + offset + sz > src_end)
        return EFAULT;
    return copy_from_kernel(dst, src + offset, sz);
}

static int parse_header_fself(uint64_t header, uint32_t size, struct fself_header_info* info)
{
    uint64_t header_end = header + size;
    uint16_t n_entries;
    memset(info, 0, sizeof(*info));
    if(copy_from_kernel_buffer(&n_entries, header, header_end, 24, sizeof(n_entries)))
        return 0;
    uint64_t elf_offset = 32 + 32 * n_entries;
    uint64_t elf[8];
    if(copy_from_kernel_buffer(elf, header, header_end, elf_offset, sizeof(elf)))
        return 0;
    info->e_type = elf[2];
    info->is_ps4 = (uint8_t)elf[1] < 2;
    uint64_t e_phoff = elf[4];
    uint16_t e_phnum = elf[7];
    uint64_t ex_offset = elf_offset + e_phoff + 56 * e_phnum;
    ex_offset = ((ex_offset - 1) | 15) + 1;
    uint64_t ex[4];
    if(copy_from_kernel_buffer(ex, header, header_end, ex_offset, sizeof(ex)))
        return 0;
    if(ex[1] != 1) //not fself
        return 0;
    info->is_fself = 1;
    info->authinfo_offset = ex_offset + 64 + 48 + n_entries * 80 + 80;
    return info->is_fself;
}

static void load_header_fself_authinfo(uint64_t header, uint32_t size, struct fself_header_info* info)
{
    uint64_t header_end = header + size;
    uint64_t signature[18] = {0};

    if(!copy_from_kernel_buffer(signature, header, header_end, info->authinfo_offset, sizeof(signature))
    && signature[0] == 0x88)
    {
        memcpy(info->authinfo, signature+1, 0x88);
        info->have_authinfo = 1;
    }
    info->authinfo_loaded = 1;
}

static struct fself_header_info* get_header_fself_info(uint64_t header, uint32_t size)
{
    if(!s_header_cache.valid || s_header_cache.header != header || s_header_cache.size != size)
    {
        s_header_cache.header = header;
        s_header_cache.size = size;
        s_header_cache.valid = 1;
        parse_header_fself(header, size, &s_header_cache.info);
    }
    return &s_header_cache.info;
}

static int is_header_fself(uint64_t header, uint32_t size, uint16_t* e_type, int* is_ps4, uint64_t* authinfo, int* have_authinfo)
{
    struct fself_header_info* info = get_header_fself_info(header, size);
    if(!info->is_fself)
        return 0;
    if((authinfo || have_authinfo) && !info->authinfo_loaded)
        load_header_fself_authinfo(header, size, info);
    if(e_type)
        *e_type = info->e_type;
    if(is_ps4)
        *is_ps4 = info->is_ps4;
    if(authinfo)
        memcpy(authinfo, info->authinfo, sizeof(info->authinfo));
    if(have_authinfo)
        *have_authinfo = info->have_authinfo;
    return 1;
}

static int same_context_fself_info(uint64_t ctx, const uint64_t snapshot[8])
{
    return s_context_cache.valid
        && s_context_cache.ctx == ctx
        && !memcmp(s_context_cache.snapshot, snapshot, sizeof(s_context_cache.snapshot));
}

static void remember_context_fself_info(uint64_t ctx, uint64_t header, uint32_t size,
                                        const uint64_t snapshot[8])
{
    s_context_cache.ctx = ctx;
    s_context_cache.header = header;
    s_context_cache.size = size;
    memcpy(s_context_cache.snapshot, snapshot, sizeof(s_context_cache.snapshot));
    s_context_cache.valid = 1;
}

static int get_context_fself_info(uint64_t ctx, uint16_t* e_type, int* is_ps4, uint64_t* authinfo, int* have_authinfo)
{
    uint64_t ctx_data[8];
    if(!ctx)
        return 0;
    if(copy_from_kernel(ctx_data, ctx, sizeof(ctx_data)))
        return 0;
    if(!same_context_fself_info(ctx, ctx_data))
    {
        s_header_cache.valid = 0;
        remember_context_fself_info(ctx, ctx_data[7], (uint32_t)ctx_data[1], ctx_data);
    }
    return is_header_fself(s_context_cache.header, s_context_cache.size, e_type, is_ps4, authinfo, have_authinfo);
}

extern char doreti_iret[];
extern char sceSblAuthMgrSmIsLoadable2[];
extern char sceSblServiceMailbox[];
extern char sceSblServiceMailbox_lr_verifyHeader[];
extern char sceSblServiceMailbox_lr_loadSelfSegment[];
extern char sceSblServiceMailbox_lr_decryptSelfBlock[];
extern char sceSblServiceMailbox_lr_decryptMultipleSelfBlocks[];
extern char loadSelfSegment_watchpoint[];
extern char loadSelfSegment_watchpoint_lr[];
extern char loadSelfSegment_epilogue[];
extern char decryptSelfBlock_watchpoint_lr[];
extern char decryptSelfBlock_epilogue[];
extern char decryptMultipleSelfBlocks_watchpoint_lr[];
extern char decryptMultipleSelfBlocks_epilogue[];
extern char mini_syscore_header[];

static int set_dbgregs_for_watchpoint(uint64_t* regs, const uint64_t* dbgregs, size_t frame_size)
{
    uint64_t buf[frame_size/8 + 7];
    uint64_t new_rsp;
    uint64_t p_pcb_flags;
    uint64_t pcb_flags_value;
    int had_dbregs;
    if(peek_stack_checked(regs, buf, frame_size))
        return 0;
    if(read_dbgregs_checked(buf + frame_size/8))
        return 0;
    if(get_current_pcb_flags_ptr_checked(&p_pcb_flags))
        return 0;
    if(get_pcb_dbregs_checked_at(p_pcb_flags, &pcb_flags_value, &had_dbregs))
        return 0;
    buf[frame_size/8 + 6] = had_dbregs;
    new_rsp = regs[RSP] - (sizeof(buf) - frame_size);
    if(copy_to_kernel(new_rsp, buf, sizeof(buf)))
        return 0;
    if(set_pcb_dbregs_checked_at(p_pcb_flags, pcb_flags_value))
        return 0;
    if(write_dbgregs_checked(dbgregs))
    {
        restore_dbgregs_state_checked_at(p_pcb_flags, pcb_flags_value, buf + frame_size/8, had_dbregs);
        return 0;
    }
    regs[RSP] = new_rsp;
    return 1;
}

static int unset_dbgregs_for_watchpoint(uint64_t* regs)
{
    uint64_t dbgregs[7];
    if(peek_stack_checked(regs, dbgregs, sizeof(dbgregs)))
        return 0;
    if(restore_dbgregs_state_checked(dbgregs, dbgregs[6]))
        return 0;
    regs[RSP] += sizeof(dbgregs);
    return 1;
}

static uint64_t dbgregs_for_fself[6] = {
    (uint64_t)sceSblServiceMailbox, (uint64_t)sceSblAuthMgrSmIsLoadable2,
    (uint64_t) aslr_fix_start, 0,
    0, 0x415,
};

static uint64_t dbgregs_for_loadSelfSegment[6] = {
    (uint64_t)sceSblServiceMailbox, (uint64_t)loadSelfSegment_epilogue, 0, 0,
    0, 0x405,
};

static uint64_t dbgregs_for_decryptSelfBlock[6] = {
    (uint64_t)sceSblServiceMailbox, (uint64_t)decryptSelfBlock_epilogue, 0, 0,
    0, 0x405,
};

static uint64_t dbgregs_for_decryptMultipleSelfBlocks[6] = {
    (uint64_t)sceSblServiceMailbox, (uint64_t)decryptMultipleSelfBlocks_epilogue, 0, 0,
    0, 0x405,
};

void handle_fself_syscall(uint64_t* regs)
{
    s_header_cache.valid = 0;
    s_context_cache.valid = 0;
	start_syscall_with_dbgregs(regs, dbgregs_for_fself);
}

void handle_fself_trap(uint64_t* regs, uint32_t trapno)
{
    if (trapno == 1)
    {
        char fself_header_backup[(48 + mini_syscore_header_size + 15) & -16];
        uint64_t self_header;
        if(peek_stack_checked(regs, fself_header_backup, sizeof(fself_header_backup)))
            return;
        if(kpeek64_checked(regs[(FWVER >= 0x800) ? RBX : R14] + 56, &self_header))
            return;
        if(copy_to_kernel(self_header, fself_header_backup + 40, mini_syscore_header_size))
            return;
        regs[RSP] += sizeof(fself_header_backup);
        regs[RIP] = *(uint64_t*)(fself_header_backup + sizeof(fself_header_backup) - 8);
    }
}


int try_handle_fself_mailbox(uint64_t* regs, uint64_t lr)
{
    if(lr == (uint64_t)sceSblServiceMailbox_lr_verifyHeader)
    {
        uint64_t self_context = regs[(FWVER >= 0x800) ? RBX : R14];
        uint64_t ctx_data[8];
        uint64_t self_header;
		uint32_t size;
        if(copy_from_kernel(&size, regs[RDX]+16, 4))
            return 0;
        if(copy_from_kernel(ctx_data, self_context, sizeof(ctx_data)))
            return 0;
        self_header = ctx_data[7];
        remember_context_fself_info(self_context, self_header, size, ctx_data);
        if(is_header_fself(self_header, size, 0, 0, 0, 0))
        {
            char fself_header_backup[(48 + mini_syscore_header_size + 15) & -16];
            char mini_header[(mini_syscore_header_size + 15) & -16];
            uint32_t original_size = size;
            uint64_t trap_frame[6] = {
                (uint64_t)doreti_iret,
                MKTRAP(TRAP_FSELF, 1), 0, 0, 0, 0,
            };
            memcpy(fself_header_backup, trap_frame, 48);
            if(copy_from_kernel(fself_header_backup+48, self_header, mini_syscore_header_size))
                return 0;
            if(copy_from_kernel(mini_header, (uint64_t)mini_syscore_header, mini_syscore_header_size))
                return 0;
            if(copy_to_kernel(self_header, mini_header, mini_syscore_header_size))
                return 0;
            size = mini_syscore_header_size;
            if(copy_to_kernel(regs[RDX]+16, &size, 4))
            {
                copy_to_kernel(self_header, fself_header_backup+48, mini_syscore_header_size);
                return 0;
            }
            if(push_stack_checked(regs, fself_header_backup, sizeof(fself_header_backup)))
            {
                copy_to_kernel(self_header, fself_header_backup+48, mini_syscore_header_size);
                copy_to_kernel(regs[RDX]+16, &original_size, 4);
                return 0;
            }
        }
    }
    else if(lr == (uint64_t)sceSblServiceMailbox_lr_loadSelfSegment)
    {
        uint64_t ctx;
        if(FWVER >= 0x1000)
        {
            if(kpeek64_checked(regs[RBP] - 232, &ctx))
                return 0;
        }
        else if(FWVER >= 0x900 && FWVER <= 0x960)
            ctx = regs[R14];
        else if(FWVER >= 0x800 && FWVER <= 0x860)
        {
            if(kpeek64_checked(regs[RBP] - 240, &ctx))
                return 0;
        }
        else
            ctx = regs[RBX];
        if(get_context_fself_info(ctx, 0, 0, 0, 0))
        {
            if(pop_stack_checked(regs, &regs[RIP], 8))
                return 0;
            regs[RAX] = 0;
        }
    }
    else if(lr == (uint64_t)sceSblServiceMailbox_lr_decryptSelfBlock)
    {
        uint64_t ctx;
        if(FWVER >= 0x800)
            ctx = regs[R12];
        else if(FWVER >= 0x500 && FWVER <= 0x761)
        {
            if(kpeek64_checked(regs[RBP] - 192, &ctx))
                return 0;
        }
        else if(kpeek64_checked(regs[RBP] - sceSblServiceMailbox_decryptSelfBlock_rsp_to_rbp +
                                sceSblServiceMailbox_decryptSelfBlock_rsp_to_self_context, &ctx))
            return 0;
        if(get_context_fself_info(ctx, 0, 0, 0, 0))
        {
            uint64_t request[8];
            if(copy_from_kernel(request, regs[RDX], sizeof(request)))
                return 0;
            if(pop_stack_checked(regs, &regs[RIP], 8))
                return 0;
            memcpy(DMEM+request[1], DMEM+request[2], (uint32_t)request[6]);
            regs[RAX] = 0;
        }
    }
    else if(lr == (uint64_t)sceSblServiceMailbox_lr_decryptMultipleSelfBlocks)
    {
        uint64_t ctx;
        if(FWVER >= 0x600)
        {
            if(kpeek64_checked(regs[RBP] - 208, &ctx))
                return 0;
        }
        else if(FWVER >= 0x500 && FWVER <= 0x550)
        {
            if(kpeek64_checked(regs[RBP] - 216, &ctx))
                return 0;
        }
        else
            ctx = regs[R13];
        if(get_context_fself_info(ctx, 0, 0, 0, 0))
        {
            uint64_t request[8];
            if(copy_from_kernel(request, regs[RDX], sizeof(request)))
                return 0;
            if(pop_stack_checked(regs, &regs[RIP], 8))
                return 0;
            uint64_t* src = (uint64_t*)(DMEM + request[1]);
            uint64_t* dst = (uint64_t*)(DMEM + request[2]);
            copy_decrypted_self_blocks(DMEM, src, dst, request[5]);
            regs[RAX] = 0;
        }
    }
    else
        return 0;

    return 1;
}

int try_handle_fself_trap(uint64_t* regs)
{
    if(regs[RIP] == (uint64_t)sceSblAuthMgrSmIsLoadable2)
    {
        uint16_t e_type;
        int have_authinfo;
        uint64_t authinfo[17];
        int is_ps4;
        if(get_context_fself_info(regs[RDI], &e_type, &is_ps4, authinfo, &have_authinfo))
        {
            uint64_t ret_addr;
            uint64_t* p_authinfo;
            if(have_authinfo)
                p_authinfo = authinfo;
            else if(is_ps4)
            {
                if(e_type == 0xfe18)
                    p_authinfo = s_auth_info_for_dynlib_ps4;
                else
                    p_authinfo = s_auth_info_for_exec_ps4;
            }
            else
            {
                if(e_type == 0xfe18)
                    p_authinfo = s_auth_info_for_dynlib;
                else
                    p_authinfo = s_auth_info_for_exec;
            }
            if(copy_from_kernel(&ret_addr, regs[RSP], sizeof(ret_addr)))
                return 1;
            if(copy_to_kernel(regs[R8], p_authinfo, 0x88))
                return 1;
            if(copy_to_kernel(regs[RDI] + 62, &(const uint16_t[1]){0xdeb7}, 2))
                return 1;
            regs[RSP] += 8;
            regs[RIP] = ret_addr;
            regs[RAX] = 0;
        }
    }
    else if(regs[RIP] == (uint64_t)loadSelfSegment_watchpoint)
    {
        uint64_t frame[4];
        if(copy_from_kernel(frame, regs[RSP], sizeof(frame)))
            return 1;
        regs[(FWVER >= 0x800) ? RAX : R10] |= 0xffffull << 48;
        if(frame[3] == (uint64_t)loadSelfSegment_watchpoint_lr)
        {
            if(!set_dbgregs_for_watchpoint(regs, dbgregs_for_loadSelfSegment, sizeof(frame)))
                return 1;
        }
        else if(frame[3] == (uint64_t)decryptSelfBlock_watchpoint_lr)
        {
            if(!set_dbgregs_for_watchpoint(regs, dbgregs_for_decryptSelfBlock, sizeof(frame)))
                return 1;
        }
        else if(frame[3] == (uint64_t)decryptMultipleSelfBlocks_watchpoint_lr)
        {
            if(!set_dbgregs_for_watchpoint(regs, dbgregs_for_decryptMultipleSelfBlocks, sizeof(frame)))
                return 1;
        }
    }
    else if(regs[RIP] == (uint64_t)loadSelfSegment_epilogue
         || regs[RIP] == (uint64_t)decryptSelfBlock_epilogue
         || regs[RIP] == (uint64_t)decryptMultipleSelfBlocks_epilogue)
    {
         if(!unset_dbgregs_for_watchpoint(regs))
             return 1;
    }
    else
        return 0;
    return 1;
}

#endif
