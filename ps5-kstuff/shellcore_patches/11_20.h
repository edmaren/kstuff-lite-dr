#ifndef SHELLCORE_PATCHES_11_20
#define SHELLCORE_PATCHES_11_20

static struct shellcore_patch shellcore_patches_1120_retail[] = {

    {0x7AAB30, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1725FB0, "\x31\xc0\xc3", 3}, // VR2 Min Fw Check
    {0xAC9F63, "\xeb\x03", 2}, // disable game error message
    {0x3137C0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x31383A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x31393C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x313A10, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x313C31, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x313D42, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x31421A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3142AD, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7610D8, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x764B32, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x768740, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1120_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1120_devkit[] = {
};

#endif // SHELLCORE_PATCHES_11_20
