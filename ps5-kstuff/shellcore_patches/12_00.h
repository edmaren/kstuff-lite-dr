#ifndef SHELLCORE_PATCHES_12_00
#define SHELLCORE_PATCHES_12_00

static struct shellcore_patch shellcore_patches_1200_retail[] = {

    {0x7D16A0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1742A40, "\x31\xc0\xc3", 3}, // VR2 Min Fw Check
    {0xAF85F3, "\xeb\x03", 2}, // disable game error message
    {0x328EE0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x328F5A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x32905C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x329130, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x329351, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x329462, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x32993A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3299CD, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7876C8, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x78B2C2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x78F160, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1200_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1200_devkit[] = {
};

#endif // SHELLCORE_PATCHES_12_00
