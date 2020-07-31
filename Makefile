CC := clang
MAKE := make
CFLAGS := -Wall -Werror -std=gnu11 -Iinclude -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE $(CFLAGS)
DEBUG_CFLAGS := -D_DEBUG -ggdb3 -O0
RELEASE_CFLAGS := -DNDEBUG -O2
LDFLAGS += -lpthread -lcapstone

BINDIR := build-x86

HDRS := $(wildcard include/*/*.h)
SRCS := \
	address_space.c \
	kvm.c \
	memory.c \
	pio.c \
	vm.c \
	x86.c \

ifeq ($(CONFIG_TEST),y)
	SRCS += test_main.c
	CFLAGS += -DCONFIG_TEST
	LDFLAGS += -Wl,-Ttest.lds -lcunit
else
	SRCS += main.c
endif

OBJS := $(patsubst %.c,$(BINDIR)/%.o,$(SRCS))
TARGET := $(BINDIR)/wbvm

BIOS := $(BINDIR)/bios.bin

debug: CFLAGS += $(DEBUG_CFLAGS)
release: CFLAGS += $(RELEASE_CFLAGS)
debug release: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BIOS): seabios.config
	cp seabios.config seabios/.config
	make -C seabios/
	mv seabios/out/bios.bin $@

$(TARGET): $(BINDIR) $(BIOS) $(HDRS) $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

clean:
	rm -rf $(OBJS) $(TARGET)

clean_all:
	rm -rf $(BINDIR)
	make -C seabios/ clean

.PHONY: debug release test clean clean_all
.DEFAULT_GOAL := debug
