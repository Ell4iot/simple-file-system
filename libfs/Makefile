# Target library
targets:= libfs
lib := libfs.a
CC := gcc
CFLAGS := -Wall -Werror -Wextra -MMD
objs :=  fs.o disk.o
AR := ar rcs
all: $(targets)

deps := $(patsubst %.o,%.d,$(objs))
-include $(deps)

ifneq ($(V),1)
Q=@
endif

libfs: $(objs)
	@echo "AR $@"
	$(Q)$(AR) $(lib) $^

%.o: %.c
	@echo "CC $@"
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "CLEAN"
	$(Q)rm -f $(lib) $(objs) $(deps)
