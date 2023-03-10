EXTRA_CGO_CFLAGS := $(EXTRA_CGO_CFLAGS) -I$(abspath ./thirdparty/libbpf/lib/include) \
	-I$(abspath ./thirdparty/bcc/lib/include)
EXTRA_CGO_LDFLAGS := $(EXTRA_CGO_LDFLAGS)  -L$(abspath ./thirdparty/libbpf/lib/lib64) -lbpf \
	-L$(abspath ./thirdparty/bcc/lib/lib) -lbcc-syms -lstdc++ -lelf -lz
LD_LIBRARY_PATH := $(LD_LIBRARY_PATH):$(abspath ./thirdparty/libbpf/lib/lib64):$(abspath ./thirdparty/bcc/lib/lib)

.PHONY: all
all: build

.PHONY: build
build: build-bcc build-libbpf build-bpf
	CGO_CFLAGS="$(CGO_CFLAGS) $(EXTRA_CGO_CFLAGS)" \
	CGO_LDFLAGS="-static $(CGO_LDFLAGS) $(EXTRA_CGO_LDFLAGS)" \
	go build -o bin/pyro ./cmd/main.go


.PHONY: build-bcc
build-bcc:
	make -C thirdparty/bcc

.PHONY: build-libbpf
build-libbpf:
	make -C thirdparty/libbpf

.PHONY: build-bpf
build-bpf: build-libbpf
	make -C pkg/spies build-bpf

.PHONY: tests
tests: build
	CGO_CFLAGS="$(CGO_CFLAGS) $(EXTRA_CGO_CFLAGS)" \
	CGO_LDFLAGS="$(CGO_LDFLAGS) $(EXTRA_CGO_LDFLAGS)" \
	LD_LIBRARY_PATH="$(LD_LIBRARY_PATH)" \
	go test -v ./...

.PHONY: clean
clean:
	make -C thirdparty/bcc clean
	make -C thirdparty/libbpf clean
	make -C pkg/spies clean
	rm -rf bin