
.PHONY: all
all: build-bpf

.PHONY: build-bpf
build-bpf:
	CFLAGS="-I$(abspath ../../thirdparty/libbpf/lib/include)" make -C cpuspy/bpf
	CFLAGS="-I$(abspath ../../thirdparty/libbpf/lib/include)" make -C biospy/bpf

.PHONY: clean
clean:
	make -C cpuspy/bpf clean
	make -C biospy/bpf clean

	