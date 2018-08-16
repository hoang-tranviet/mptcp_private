# SPDX-License-Identifier: GPL-2.0
# copied from tools/testing/selftests/bpf/Makefile

LIBDIR := ../tools/lib
BPFDIR := $(LIBDIR)/bpf
APIDIR := ../tools/include/uapi
GENDIR := ../include/generated
GENHDR := $(GENDIR)/autoconf.h

ifneq ($(wildcard $(GENHDR)),)
  GENFLAGS := -DHAVE_GENHDR
endif

CFLAGS += -Wall -O2 -I$(APIDIR) -I$(LIBDIR) -I$(GENDIR) $(GENFLAGS) -I../tools/include
LDLIBS += -lcap -lelf -lrt -lpthread


# Order correspond to 'make run_tests' order
TEST_GEN_PROGS = test_mptcp_user

TEST_GEN_FILES = bpf_mptcp_option_kern.o bpf_mptcp_cap_bw_kern.o \
		 bpf_mptcp_priority_kern.o bpf_mptcp_reinject_data_acks_kern.o \

# Compile but not part of 'make run_tests'
TEST_GEN_PROGS_EXTENDED = test_libbpf_open

include ../tools/testing/selftests/lib.mk

BPFOBJ := $(OUTPUT)/libbpf.a

$(TEST_GEN_PROGS): $(BPFOBJ)

$(TEST_GEN_PROGS_EXTENDED): $(OUTPUT)/libbpf.a

.PHONY: force

# force a rebuild of BPFOBJ when its dependencies are updated
force:

$(BPFOBJ): force
	$(MAKE) -C $(BPFDIR) OUTPUT=$(OUTPUT)/

CLANG ?= clang
LLC   ?= llc

PROBE := $(shell $(LLC) -march=bpf -mcpu=probe -filetype=null /dev/null 2>&1)

# Let newer LLVM versions transparently probe the kernel for availability
# of full BPF instruction set.
ifeq ($(PROBE),)
  CPU ?= probe
else
  CPU ?= generic
endif

CLANG_FLAGS = -I. -I./tools/testing/selftests/bpf/include/uapi -I../tools/include/uapi \
	      -Wno-compare-distinct-pointer-types

$(OUTPUT)/%.o: %.c
	$(CLANG) $(CLANG_FLAGS) \
		 -O2 -target bpf -emit-llvm -c $< -o - |      \
	$(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@
