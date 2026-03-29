#ifndef SHELLCORE_PATCHES_10_20
#define SHELLCORE_PATCHES_10_20

static struct shellcore_patch shellcore_patches_1020_retail[] = {

    {0x7460A0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x16A5C40, "\x31\xc0\xc3", 3}, // VR2 Min Fw Check
    {0xA8B033, "\xeb\x03", 2}, // disable game error message
    {0x305790, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x30580A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x30590C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x3059E0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x305DE7, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x305F8F, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x30633E, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3063D1, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x700D28, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7041F2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7078D0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1020_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1020_devkit[] = {
};

#endif // SHELLCORE_PATCHES_10_20
