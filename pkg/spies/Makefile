
.PHONY: all
all: build-bpf

.PHONY: build-bpf
build-bpf:
	CFLAGS="-I$(abspath ../../thirdparty/libbpf/lib/include)" make -C cpuspy/bpf

.PHONY: clean
clean:
	make -C cpuspy/bpf clean

	