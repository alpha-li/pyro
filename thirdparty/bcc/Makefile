
.PHONY: build-bcc
build-bcc:
	test -d build || mkdir build
	cd build \
		&& cmake ../src/build-syms  \
			-DCMAKE_C_COMPILER=clang \
			-DCMAKE_CXX_COMPILER=clang++ \
			-DCMAKE_BUILD_TYPE=Release \
			-DCMAKE_INSTALL_PREFIX=$(shell pwd)/lib \
        		&& make -j16 install

.PHONY: clean
clean:
	rm -rf lib build 
