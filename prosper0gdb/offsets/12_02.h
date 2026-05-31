// offsets/12_02_H
#ifndef OFFSETS_12_02_H
#define OFFSETS_12_02_H
#include "../offsets.h"

START_FW(1202)
DEF(allproc, 0x2885e00) //Confirmed
DEF(idt, 0x2e88300) //Confirmed
DEF(gdt_array, 0x2e895e0) //Confirmed
DEF(tss_array, 0x2e8afe0) //Confirmed
DEF(pcpu_array, 0x2e9cf00) //Confirmed
DEF(doreti_iret, -0xa9c9d3) //Confirmed
DEF(add_rsp_iret, doreti_iret - 7) //Confirmed
DEF(swapgs_add_rsp_iret, doreti_iret - 10) //Confirmed
DEF(rep_movsb_pop_rbp_ret, -0xa60246) //Confirmed
DEF(rdmsr_start, -0xa9e10a) //Confirmed
DEF(wrmsr_ret, -0xa9f4dc) //Confirmed
DEF(nop_ret, wrmsr_ret + 2) //Confirmed
DEF(dr2gpr_start, -0xaa3b13)
DEF(gpr2dr_1_start, -0xaa39fa)
DEF(gpr2dr_2_start, -0xaa3907)
DEF(mov_cr3_rax_mov_ds, -0xaa3569) //Confirmed
DEF(mov_rax_cr3, -0x3cf570) //Checked
DEF(cpu_switch, -0xaa3d00) //Confirmed
DEF(mprotect_fix_start, -0x9d4da3)
DEF(mprotect_fix_end, mprotect_fix_start+6)
DEF(aslr_fix_start, -0x915668)
DEF(aslr_fix_end, aslr_fix_start+2)
DEF(sysents, 0x1af4d0) //Confirmed
DEF(sysents_ps4, 0x1a6f80) //Confirmed
DEF(sysentvec, 0xdcc978) //Confirmed
DEF(sysentvec_ps4, 0xdccaf0) //Confirmed
DEF(sceSblServiceMailbox, -0x714c00)
DEF(sceSblAuthMgrSmIsLoadable2, -0x968080)
DEF(syscall_before, -0x8b6344)
DEF(syscall_after, -0x8b6310)
DEF(malloc, -0xc0380)
DEF(M_something, 0x1519bf0)
DEF(loadSelfSegment_epilogue, -0x96797C)
DEF(loadSelfSegment_watchpoint, -0x2ff9b4)
DEF(loadSelfSegment_watchpoint_lr, -0x967BC7)
DEF(decryptSelfBlock_watchpoint_lr, -0x967852)
DEF(decryptSelfBlock_epilogue, -0x9677E1)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x967119)
DEF(decryptMultipleSelfBlocks_epilogue, -0x967073)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x967d64)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x9679e9)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x96742f)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x966C72)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x9680f8)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0xA17739)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0xA17DC2)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0xA17D5D)
DEF(sceSblServiceMailbox_lr_npdrm_cmd_5, -0x3526fa)
DEF(sceSblServiceMailbox_lr_npdrm_cmd_6, -0x3524c5)
DEF(sceSblPfsSetKeys, -0xA18AB0)
DEF(sceSblServiceCryptAsync, -0x9B6F30)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x9B6EF6)
DEF(copyin, -0xa60bf0)
DEF(copyout, -0xa60ca0)
DEF(crypt_message_resolve, -0x4C0310)
DEF(justreturn, -0xa9cc00) //Confirmed
DEF(justreturn_pop, justreturn+8) //Confirmed
DEF(mini_syscore_header, 0xf34228) //Confirmed
DEF(pop_all_iret, -0xa9ca32) //Confirmed
DEF(pop_all_except_rdi_iret, pop_all_iret+4) //Confirmed
DEF(push_pop_all_iret, -0xa37668) //Confirmed
DEF(kernel_pmap_store, 0x2e1cfb8) //Confirmed
DEF(crypt_singleton_array, 0x2d61e30) //Confirmed
DEF(mov_rax_cr0, -0xaa3c61)
DEF(mov_cr0_rax, -0xaa3c5c)
#include "offset_list.txt"
END_FW()

#endif