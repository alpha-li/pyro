	EXTRA_CGO_CFLAGS := $(EXTRA_CGO_CFLAGS) -I$(abspath ./thirdparty/libbpf/lib/include) \
		-I$(abspath ./thirdparty/bcc/lib/include)
	EXTRA_CGO_LDFLAGS := $(EXTRA_CGO_LDFLAGS)  -L$(abspath ./thirdparty/libbpf/lib/lib64) -lbpf \
		-L$(abspath ./thirdparty/bcc/lib/lib) -lbcc-syms -lstdc++ -lelf -lz

.PHONY: all
all: build

.PHONY: build
build: build-bcc build-libbpf
	CGO_CFLAGS="$(CGO_CFLAGS) $(EXTRA_CGO_CFLAGS)" \
	CGO_LDFLAGS="-static $(CGO_LDFLAGS) $(EXTRA_CGO_LDFLAGS)" \
	go build ./symtab


.PHONY: build-bcc
build-bcc:
	make -C thirdparty/bcc

.PHONY: build-libbpf
build-libbpf:
	make -C thirdparty/libbpf

.PHONY: tests
tests: build
	CGO_CFLAGS="$(CGO_CFLAGS) $(EXTRA_CGO_CFLAGS)" \
	CGO_LDFLAGS="-static $(CGO_LDFLAGS) $(EXTRA_CGO_LDFLAGS)" \
	go test ./...

.PHONY: clean
clean:
	make -C thirdparty/bcc clean
	make -C thirdparty/libbpf clean