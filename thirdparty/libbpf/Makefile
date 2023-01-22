
.PHONY: build-libbpf
build-libbpf:
	PREFIX=$(shell pwd)/lib make -C src/src -j16 install

.PHONY: clean
clean:
	rm -rf lib
	make -C src/src clean
