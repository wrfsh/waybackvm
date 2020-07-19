CC := clang
MAKE := make
CFLAGS := -Wall -Werror -std=gnu11 -Iinclude -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE $(CFLAGS)
DEBUG_CFLAGS := -D_DEBUG -ggdb3 -O0
RELEASE_CFLAGS := -DNDEBUG -O2
LDFLAGS += -lpthread

BINDIR := build-x86

HDRS := $(wildcard include/*/*.h)
SRCS := $(wildcard *.c)
OBJS := $(patsubst %.c,$(BINDIR)/%.o,$(SRCS))

TARGET := $(BINDIR)/wbvm

test: LDFLAGS += -Wl,-T test_sec.lds -lcunit
test: CFLAGS += $(DEBUG_CFLAGS) -DTEST
debug: CFLAGS += $(DEBUG_CFLAGS)
release: CFLAGS += $(RELEASE_CFLAGS)
debug release test: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(BINDIR) $(HDRS) $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

clean:
	rm -rf $(OBJS) $(TARGET)

.PHONY: debug release clean
.DEFAULT_GOAL := release
