AR     ?= ar
LLC    ?= llc
CLANG  ?= clang
CC     ?= gcc

# Configure paths of locally built dependencies
LIB_DIR := ./xdp-tools/lib
LIBXDP_DIR := $(LIB_DIR)/libxdp
LIBXDP_SOURCES = $(wildcard $(LIBXDP_DIR)/*.[ch] $(LIBXDP_DIR)/*.in)
OBJECT_LIBXDP := $(LIBXDP_DIR)/libxdp.a
LIBXDP_INCLUDE_DIR := $(LIB_DIR)/../headers
LIBBPF_DIR := $(LIB_DIR)/libbpf/src
LIBBPF_SOURCES = $(wildcard $(LIBBPF_DIR)/*.[ch])
OBJECT_LIBBPF := $(LIBBPF_DIR)/libbpf.a
LIBBPF_INCLUDE_DIR := $(LIBBPF_DIR)/root/usr/include

# Allows to pass additional cflags from the make command
override CFLAGS += -I./src -I./headers -I$(LIBXDP_INCLUDE_DIR) \
				   -I$(LIBBPF_INCLUDE_DIR) -O2 -flto

# Configure library paths
XSKNF_DIR    := ./src
XSKNF_H      := $(XSKNF_DIR)/xsknf.h
XSKNF_C      := $(XSKNF_DIR)/xsknf.c
XSKNF_O      := ${XSKNF_C:.c=.o}
XSKNF_TARGET := $(XSKNF_DIR)/libxsknf.a

EXAMPLES := drop_macswap/drop_macswap			\
			firewall/firewall 					\
			redirect_macswap/redirect_macswap	\
			load_balancer/load_balancer			\
			checksummer/checksummer				\
			hybrid_macswap/hybrid_macswap		\
			hybrid_lbfw/hybrid_lbfw				\
			test_memory/test_memory
EXAMPLES_DIR     := ./examples
EXAMPLES_TARGETS := $(addprefix $(EXAMPLES_DIR)/,$(EXAMPLES))
EXAMPLES_USER	 := $(addsuffix _user.o,$(EXAMPLES_TARGETS))
EXAMPLES_KERN    := $(addsuffix _kern.o,$(EXAMPLES_TARGETS))
EXAMPLES_LD      := -L./src/ -lxsknf -L$(LIBXDP_DIR) -l:libxdp.a \
					-L$(LIBBPF_DIR) -l:libbpf.a -lelf -lz -lpthread -lmnl
EXAMPLES_COMMON  := $(EXAMPLES_DIR)/common/statistics.o \
					$(EXAMPLES_DIR)/common/utils.o \
					$(EXAMPLES_DIR)/common/khashmap.o

.PHONY: update_submodules clean $(CLANG) $(LLC)

all: llvm-check update_submodules $(XSKNF_TARGET) $(EXAMPLES_TARGETS)

update_submodules:
	git submodule update --init --recursive

clean:
	$(MAKE) -C ./xdp-tools clean
	$(RM) $(XSKNF_O)
	$(RM) $(XSKNF_TARGET)
	$(RM) $(EXAMPLES_USER)
	$(RM) $(EXAMPLES_TARGETS)
	$(RM) $(EXAMPLES_KERN)
	$(RM) $(EXAMPLES_COMMON)

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OBJECT_LIBBPF): update_submodules $(LIBBPF_SOURCES)
	$(MAKE) -C $(LIB_DIR) libbpf

$(OBJECT_LIBXDP): update_submodules $(LIBXDP_SOURCES)
	$(MAKE) -C ./xdp-tools libxdp

$(XSKNF_O): $(XSKNF_C) $(XSKNF_H) $(OBJECT_LIBXDP) $(OBJECT_LIBBPF)

$(XSKNF_TARGET): $(XSKNF_O)
	$(AR) r -o $@ $(XSKNF_O)

$(EXAMPLES_KERN): %_kern.o: %_kern.c %.h $(OBJECT_LIBBPF)
	$(CLANG) -S \
		-target bpf \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		$(CFLAGS) \
		-emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	$(RM) ${@:.o=.ll}

$(EXAMPLES_TARGETS): %: %_user.o %_kern.o %.h $(EXAMPLES_COMMON) $(XSKNF_TARGET)
	$(CC) $@_user.o $(EXAMPLES_COMMON) -o $@ $(EXAMPLES_LD) $(CFLAGS)