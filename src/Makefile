MCL_DIR?=./mcl
OBJ_DIR?=./obj
WASM_DIR=$(MCL_DIR)/src/wasm
LLVM_VER?=-21

CC=clang$(LLVM_VER)
CXX=clang++$(LLVM_VER)
LD=wasm-ld$(LLVM_VER)
WASM_OPT?=wasm-opt

TARGET=--target=wasm32-unknown-unknown
CFLAGS=$(TARGET) -O3 -DNDEBUG -flto -fvisibility=hidden
CFLAGS+=-fno-threadsafe-statics -fno-rtti -fno-stack-protector -fno-exceptions
CFLAGS+=-DMCL_SIZEOF_UNIT=4 -DMCL_STANDALONE
# do not export mclBn* functions in fp.cpp (only ecdsa* are exported)
CFLAGS+=-DMCL_DONT_EXPORT
CFLAGS+=-DMCL_USE_WEB_CRYPTO_API
CFLAGS+=-DMCL_FP_BIT=256
CFLAGS+=-DCYBOZU_MINIMUM_EXCEPTION
CFLAGS+=-DMCLSHE_WIN_SIZE=8
CFLAGS+=-I $(WASM_DIR) -I $(MCL_DIR)/include -I $(MCL_DIR)/src
CFLAGS+=-Wall -Wextra -MMD -MP
CXXFLAGS=$(CFLAGS) -std=c++03

STACK_SIZE?=1048576
LDFLAGS=--no-entry --export-dynamic -z stack-size=$(STACK_SIZE)
LDFLAGS+=--export=__stack_pointer --export=__wasm_call_ctors
LDFLAGS+=--export=malloc --export=free
LDFLAGS+=--export=stackSave --export=stackAlloc --export=stackRestore
LDFLAGS+=--import-memory --allow-undefined
LDFLAGS+=--lto-O3

DLMALLOC_FLAGS=-DLACKS_SYS_TYPES_H -DLACKS_FCNTL_H -DLACKS_UNISTD_H
DLMALLOC_FLAGS+=-DLACKS_SYS_MMAN_H -DLACKS_STRINGS_H -DLACKS_SYS_PARAM_H
DLMALLOC_FLAGS+=-DLACKS_SCHED_H -DLACKS_TIME_H
DLMALLOC_FLAGS+=-DHAVE_MORECORE=1 -DHAVE_MMAP=0 -DNO_MALLOC_STATS=1
DLMALLOC_FLAGS+=-DMORECORE_CONTIGUOUS=0
DLMALLOC_FLAGS+=-Dsize_t=unsigned\ long -Dptrdiff_t=long
DLMALLOC_FLAGS+=-DMALLOC_ALIGNMENT=16

OBJS=$(OBJ_DIR)/fp.o
OBJS+=$(OBJ_DIR)/ecdsa_c.o
OBJS+=$(OBJ_DIR)/dlmalloc.o $(OBJ_DIR)/libc.o $(OBJ_DIR)/stack.o

WASM=ecdsa.wasm
ECDSA_JS=../ecdsa_c.js

all: $(ECDSA_JS)

$(ECDSA_JS): $(WASM) $(WASM_DIR)/glue.js
	python3 -c "import base64;w=base64.b64encode(open('$(WASM)','rb').read()).decode();print(open('$(WASM_DIR)/glue.js').read().replace('@@WASM_BASE64@@',w).replace('@@STACK_SIZE@@','$(STACK_SIZE)'),end='')" > $@

$(WASM): $(OBJS)
	$(LD) -o $@.pre $(OBJS) $(LDFLAGS)
	$(WASM_OPT) -O3 --strip-debug $@.pre -o $@
	rm $@.pre

$(OBJ_DIR)/fp.o: $(MCL_DIR)/src/fp.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJ_DIR)/ecdsa_c.o: $(MCL_DIR)/src/ecdsa_c.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJ_DIR)/dlmalloc.o: $(WASM_DIR)/dlmalloc.c | $(OBJ_DIR)
	$(CC) $(TARGET) -O3 -DNDEBUG -flto -I $(WASM_DIR) $(DLMALLOC_FLAGS) -c -o $@ $< -DUSE_LOCKS=0

$(OBJ_DIR)/libc.o: $(WASM_DIR)/libc.c | $(OBJ_DIR)
	$(CC) $(TARGET) -O3 -DNDEBUG -flto -I $(WASM_DIR) -c -o $@ $<

$(OBJ_DIR)/stack.o: $(WASM_DIR)/stack.s | $(OBJ_DIR)
	$(CC) $(TARGET) -c -o $@ $<

$(OBJ_DIR):
	mkdir -p $@

DEPS=$(OBJS:.o=.d)
-include $(DEPS)

wasm: $(ECDSA_JS)

clean:
	rm -f $(ECDSA_JS) $(OBJS) $(DEPS) $(WASM) $(WASM).pre

.PHONY: clean all wasm
