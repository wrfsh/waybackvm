CC := clang
MAKE := make
CFLAGS := -Wall -Werror -std=gnu11 -Iinclude -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE $(CFLAGS)
DEBUG_CFLAGS := -D_DEBUG -ggdb3 -O0
RELEASE_CFLAGS := -DNDEBUG -O2
LDFLAGS += -lpthread

BINDIR := build-x86

HDRS := $(wildcard include/*/*.h)
SRCS := \
	address_space.c \
	kvm.c \
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

debug: CFLAGS += $(DEBUG_CFLAGS)
release: CFLAGS += $(RELEASE_CFLAGS)
debug release: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(BINDIR) $(HDRS) $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

clean:
	rm -rf $(BINDIR)

.PHONY: debug release test clean
.DEFAULT_GOAL := debug
