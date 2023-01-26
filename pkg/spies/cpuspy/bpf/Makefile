CLANG ?= clang

CFLAGS := $(CFLAGS) -ggdb -gdwarf -O2 -Wall -fpie -Wno-unused-variable -Wno-unused-function


profile.bpf.o: profile.bpf.c profile.bpf.h vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 -I. -c profile.bpf.c -o $@

.PHONY: clean
clean:
	rm -rf profile.bpf.o
