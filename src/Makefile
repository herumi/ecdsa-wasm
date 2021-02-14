MCL_DIR=../../mcl
include $(MCL_DIR)/common.mk
LIB_DIR=lib
OBJ_DIR=obj
EXE_DIR=bin
TEST_SRC=ecdsa_test.cpp ecdsa_c_test.cpp
CFLAGS+=-I ./include -I $(MCL_DIR)/include

MCL_LIB=$(MCL_DIR)/lib/libmcl.a
ECDSA_LIB=$(LIB_DIR)/libmclecdsa.a
all: $(ECDSA_LIB)

VPATH=src test
ECDSA_OBJ=$(OBJ_DIR)/ecdsa_c.o

$(ECDSA_LIB): $(ECDSA_OBJ)
	$(AR) $@ $(ECDSA_OBJ)

$(OBJ_DIR)/%.o: %.cpp
	$(PRE)$(CXX) $(CFLAGS) -c $< -o $@ -MMD -MP -MF $(@:.o=.d)

$(EXE_DIR)/%.exe: $(OBJ_DIR)/%.o $(MCL_LIB)
	$(PRE)$(CXX) $< -o $@ $(MCL_LIB) $(LDFLAGS)

$(EXE_DIR)/ecdsa_c_test.exe: $(OBJ_DIR)/ecdsa_c_test.o $(ECDSA_LIB) $(MCL_LIB) src/ecdsa_c.cpp include/mcl/ecdsa.hpp include/mcl/ecdsa.h
	$(PRE)$(CXX) $< -o $@ $(ECDSA_LIB) $(MCL_LIB) $(LDFLAGS)

SAMPLE_EXE=$(addprefix $(EXE_DIR)/,$(addsuffix .exe,$(basename $(SAMPLE_SRC))))
sample: $(SAMPLE_EXE) $(MCL_LIB)

TEST_EXE=$(addprefix $(EXE_DIR)/,$(TEST_SRC:.cpp=.exe))

test: $(TEST_EXE)
	@echo test $(TEST_EXE)
	@sh -ec 'for i in $(TEST_EXE); do $$i|grep "ctest:name"; done' > result.txt
	@grep -v "ng=0, exception=0" result.txt; if [ $$? -eq 1 ]; then echo "all unit tests succeed"; else exit 1; fi

EMCC_OPT=-I./include -I./src -Wall -Wextra
EMCC_OPT+=-O3 -DNDEBUG -DMCLSHE_WIN_SIZE=8
EMCC_OPT+=-s WASM=1 -s NO_EXIT_RUNTIME=1 -s NODEJS_CATCH_EXIT=0 -s NODEJS_CATCH_REJECTION=0  -s MODULARIZE=1 #-s ASSERTIONS=1
EMCC_OPT+=-DCYBOZU_MINIMUM_EXCEPTION
EMCC_OPT+=-s ABORTING_MALLOC=0

../ecdsa_c.js: $(MCL_DIR)/src/ecdsa_c.cpp $(MCL_DIR)/src/fp.cpp include/mcl/ecdsa.hpp include/mcl/ecdsa.h Makefile
	emcc -o $@ $(MCL_DIR)/src/fp.cpp src/ecdsa_c.cpp $(EMCC_OPT) -DMCL_MAX_BIT_SIZE=256 -DMCL_USE_WEB_CRYPTO_API -s DISABLE_EXCEPTION_CATCHING=1 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -fno-exceptions -I $(MCL_DIR)/include -I ./include

wasm:
	$(MAKE) ../ecdsa_c.js

clean:
	$(RM) $(LIB_DIR)/*.a $(LIB_DIR)/*.$(LIB_SUF) $(OBJ_DIR)/*.o $(OBJ_DIR)/*.obj $(OBJ_DIR)/*.d $(EXE_DIR)/*.exe

ALL_SRC=$(SRC_SRC) $(TEST_SRC) $(SAMPLE_SRC)
DEPEND_FILE=$(addprefix $(OBJ_DIR)/, $(addsuffix .d,$(basename $(ALL_SRC))))
-include $(DEPEND_FILE)

.PHONY: test

# don't remove these files automatically
.SECONDARY: $(addprefix $(OBJ_DIR)/, $(ALL_SRC:.cpp=.o))

