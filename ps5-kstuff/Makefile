PROSPER0GDB_OPT ?= -O0
PAYLOAD_OPT ?= -O0
UELF_OPT ?= -O3
UELF_ARCH ?= -march=znver2 -mtune=znver2

all: payload.bin

clean:
	rm -f payload.elf payload.bin  freebsd-loader kelf kelf.o structs.h structs.inc uelf/uelf uelf/uelf.bin uelf/crt.o

../lib/lib-elf-ps5.a:
	cd ../lib; $(MAKE)

../prosper0gdb/prosper0gdb.o:
	cd ../prosper0gdb; $(MAKE) PROSPER0GDB_OPT="$(PROSPER0GDB_OPT)"

structs.inc: structs-ps5.inc
	cp structs-ps5.inc structs.inc

payload.elf: ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o main.c kelf uelf/uelf.bin
	gcc $(PAYLOAD_OPT) -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o $(EXTRA_CFLAGS) main.c -DPS5KEK ../prosper0gdb/dbg.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding -no-pie -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384

payloa%.bin: payloa%.elf
	objcopy $< --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary $@
	python3 ../lib/frankenelf.py $@

kelf.o: kelf.asm structs.inc
	yasm -f elf64 -g dwarf2 kelf.asm -o kelf.o

kelf: kelf.o
	gcc -nostdlib -shared kelf.o -o kelf

structs.h: structs.inc
	sed 's/^%/#/' structs.inc > structs.h

uelf/crt.o: uelf/crt.asm
	yasm uelf/crt.asm -f elf64 -o uelf/crt.o

uelf/uelf: uelf/*.c uelf/*.h structs.h uelf/crt.o BearSSL/build/libbearssl.a isa-l_crypto/bin/isa-l_crypto.a
	gcc -Wl,-Bsymbolic -Wl,-gc-sections -ffunction-sections -fdata-sections $(UELF_OPT) $(UELF_ARCH) -g -isystem ../freebsd-headers -isystem isa-l_crypto/include -nostdinc -nostdlib -mgeneral-regs-only -fno-stack-protector -fPIE -fPIC -shared -fvisibility=hidden -ffreestanding uelf/crt.o $(EXTRA_CFLAGS) uelf/*.c BearSSL/build/libbearssl.a isa-l_crypto/bin/isa-l_crypto.a -o uelf/uelf -Wl,-z,max-page-size=4096

uelf/uelf.bin: uelf/uelf
	objcopy --strip-all $< $@

BearSSL/build/libbearssl.a: build_bearssl.sh overrides.h
	bash build_bearssl.sh

isa-l_crypto/bin/isa-l_crypto.a: build_isal_crypto.sh isa_l_crypto_ps5_minimal.c isa_l_crypto_ps5_sha256_zen2.asm
	bash build_isal_crypto.sh
