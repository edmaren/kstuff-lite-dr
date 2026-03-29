#ifndef SHELLCORE_PATCHES_10_40
#define SHELLCORE_PATCHES_10_40

static struct shellcore_patch shellcore_patches_1040_retail[] = {

    {0x745FF0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x16A5C60, "\x31\xc0\xc3", 3}, // VR2 Min Fw Check
    {0xA8B053, "\xeb\x03", 2}, // disable game error message
    {0x3057F0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x30586A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x30596C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x305A40, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x305E47, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x305FEF, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x30639E, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x306431, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x700C78, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x704142, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x707820, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1040_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1040_devkit[] = {
};

#endif // SHELLCORE_PATCHES_10_40
