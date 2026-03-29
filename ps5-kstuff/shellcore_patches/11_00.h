#ifndef SHELLCORE_PATCHES_11_00
#define SHELLCORE_PATCHES_11_00

static struct shellcore_patch shellcore_patches_1100_retail[] = {

    {0x7AA9C0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1725BB0, "\x31\xc0\xc3", 3}, // VR2 Min Fw Check
    {0xAC9BD3, "\xeb\x03", 2}, // disable game error message
    {0x313710, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x31378A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x31388C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x313960, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x313B81, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x313C92, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x31416A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3141FD, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x760F68, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7649C2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7685D0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1100_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1100_devkit[] = {
};

#endif // SHELLCORE_PATCHES_11_00
