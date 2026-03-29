#ifndef SHELLCORE_PATCHES_11_60
#define SHELLCORE_PATCHES_11_60

static struct shellcore_patch shellcore_patches_1160_retail[] = {

    {0x7B3CD0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1731330, "\x31\xc0\xc3", 3}, // VR2 Min Fw Check
    {0xAD3873, "\xeb\x03", 2}, // disable game error message
    {0x318AC0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x318B1A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x318C1C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x318CF0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x318F11, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x319022, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x3194FA, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x31958D, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x769B28, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x76D582, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x771190, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1160_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1160_devkit[] = {
};

#endif // SHELLCORE_PATCHES_11_60
