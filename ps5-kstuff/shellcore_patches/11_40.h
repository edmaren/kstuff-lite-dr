#ifndef SHELLCORE_PATCHES_11_40
#define SHELLCORE_PATCHES_11_40

static struct shellcore_patch shellcore_patches_1140_retail[] = {

    {0x7AC260, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x17282F0, "\x31\xc0\xc3", 3}, // VR2 Min Fw Check
    {0xACBB13, "\xeb\x03", 2}, // disable game error message
    {0x3147A0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x31481A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x31491C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x3149F0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x314C11, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x314D22, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x3151FA, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x31528D, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7620B8, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7620B8, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x769720, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1140_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1140_devkit[] = {
};

#endif // SHELLCORE_PATCHES_11_40
