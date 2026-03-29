#ifndef SHELLCORE_PATCHES_10_60
#define SHELLCORE_PATCHES_10_60

static struct shellcore_patch shellcore_patches_1060_retail[] = {

    {0x747880, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x16A74E0, "\x31\xc0\xc3", 3}, // VR2 Min Fw Check
    {0xA8C8E3, "\xeb\x03", 2}, // disable game error message
    {0x307150, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x3071CA, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x3072CC, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x3073A0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x3077A7, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x30794F, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x307CFE, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x307D91, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x702508, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7059D2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7090B0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1060_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1060_devkit[] = {
};

#endif // SHELLCORE_PATCHES_10_60
