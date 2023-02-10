CLANG ?= clang

CFLAGS := $(CFLAGS) -ggdb -gdwarf -O2 -Wall -fpie -Wno-unused-variable -Wno-unused-function


biotrace.bpf.o: biotrace.bpf.c biotrace.bpf.h vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 -I. -c biotrace.bpf.c -o $@

.PHONY: clean
clean:
	rm -rf biotrace.bpf.o
