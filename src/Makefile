MCL_DIR?=./mcl
include $(MCL_DIR)/common.mk

all: ../ecdsa_c.js

EMCC_OPT=-I./include -I./src -Wall -Wextra
EMCC_OPT+=-DMCLSHE_WIN_SIZE=8
EMCC_OPT+=-O3 -DNDEBUG -std=c++03
EMCC_OPT+=-DMCL_SIZEOF_UNIT=4
EMCC_OPT+=-s WASM=1 -s NO_EXIT_RUNTIME=1 -s NODEJS_CATCH_EXIT=0 -s NODEJS_CATCH_REJECTION=0
EMCC_OPT+=-s MODULARIZE=1
EMCC_OPT+=-s STRICT_JS=1
EMCC_OPT+=-s SINGLE_FILE=1
EMCC_OPT+=--minify 0
EMCC_OPT+=-DCYBOZU_MINIMUM_EXCEPTION
EMCC_OPT+=-s ABORTING_MALLOC=0

../ecdsa_c.js: $(MCL_DIR)/src/ecdsa_c.cpp $(MCL_DIR)/src/fp.cpp $(MCL_DIR)/include/mcl/ecdsa.hpp $(MCL_DIR)/include/mcl/ecdsa.h Makefile
	emcc -o $@ $(MCL_DIR)/src/fp.cpp $(MCL_DIR)/src/ecdsa_c.cpp $(EMCC_OPT) -DMCL_MAX_BIT_SIZE=256 -DMCL_USE_WEB_CRYPTO_API -s DISABLE_EXCEPTION_CATCHING=1 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -fno-exceptions -I $(MCL_DIR)/include -I ./include
	# disable require fs, path
	perl -i -pe 's@(.* = require\(.*)@//\1@' $@

wasm:
	$(MAKE) ../ecdsa_c.js

clean:
	$(RM) ../ecdsa_c.js

ALL_SRC=$(SRC_SRC) $(TEST_SRC) $(SAMPLE_SRC)
DEPEND_FILE=$(addprefix $(OBJ_DIR)/, $(addsuffix .d,$(basename $(ALL_SRC))))
-include $(DEPEND_FILE)

.PHONY: test

# don't remove these files automatically
.SECONDARY: $(addprefix $(OBJ_DIR)/, $(ALL_SRC:.cpp=.o))

