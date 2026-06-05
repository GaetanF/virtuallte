CC ?= gcc

TARGET := virtuallte

SRC := \
	$(wildcard src/acm/*.c) \
	$(wildcard src/apn_context/*.c) \
	$(wildcard src/common/*.c) \
	$(wildcard src/ep0/*.c) \
	$(wildcard src/ims_service/*.c) \
	$(wildcard src/mbim_frontend/*.c) \
	$(wildcard src/modem_state/*.c) \
	$(wildcard src/state_bridge/*.c) \
	$(wildcard src/ue_engine/*.c) \
	src/runtime/ue_instance_config.c \
	src/runtime/ue_timers.c \
	src/core.c \
	src/main.c

SRC := $(sort $(SRC))

OBJ := $(SRC:.c=.o)

# CFLAGS/CPPFLAGS/LDFLAGS may be provided by the environment (e.g. Debian's
# dpkg-buildflags for hardening); the language standard, warnings and include
# path are always appended via override so the build stays correct.
CFLAGS  ?= -O2 -g
LDLIBS  ?= -pthread
override CPPFLAGS += -Isrc
override CFLAGS   += -std=gnu11 -Wall -Wextra

# Install layout (overridable; Debian's dh sets DESTDIR).
DESTDIR        ?=
prefix         ?= /usr
sbindir        ?= $(prefix)/sbin
sysconfdir     ?= /etc
unitdir        ?= /lib/systemd/system
modulesloaddir ?= $(prefix)/lib/modules-load.d
modprobedir    ?= $(sysconfdir)/modprobe.d
confdir        := $(sysconfdir)/virtuallte

# Standalone unit tests (compiled+run by `make check`). ue_network_backend_test
# is intentionally excluded: it depends on headers that are not in the tree.
TESTS := ims_ip_test ims_digest_test apn_context_test ue_rls_test mbim_ntb_test ue_nas_security_test ue_instance_config_test mbim_indications_test ue_nas_codec_test mbim_sms_store_test ims_rpdata_test
TEST_BINS := $(addprefix tests/,$(TESTS))

.PHONY: all clean install check test

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(DESTDIR)$(sbindir)/virtuallte
	install -D -m 0644 packaging/virtuallte@.service \
		$(DESTDIR)$(unitdir)/virtuallte@.service
	install -D -m 0644 packaging/virtuallte.modules-load.conf \
		$(DESTDIR)$(modulesloaddir)/virtuallte.conf
	# Shipped DISABLED: modprobe.d only loads *.conf, so the .example suffix
	# keeps the CDC-driver blacklist inert until the admin renames it.
	install -D -m 0644 packaging/virtuallte.blacklist.conf \
		$(DESTDIR)$(modprobedir)/virtuallte.conf.example
	install -d -m 0755 $(DESTDIR)$(confdir)
	install -D -m 0644 packaging/ue.conf.example \
		$(DESTDIR)$(confdir)/ue1.conf.example

# `make check`/`test` (the latter is what Debian's dh_auto_test runs).
check test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "RUN $$t"; ./$$t || exit 1; done
	@echo "All tests passed"

tests/ims_ip_test: tests/ims_ip_test.c src/ims_service/ims_ip.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

tests/ims_digest_test: tests/ims_digest_test.c src/ims_service/ims_digest.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

tests/apn_context_test: tests/apn_context_test.c src/apn_context/apn_context.c src/common/log.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

tests/ue_rls_test: tests/ue_rls_test.c src/ue_engine/ue_rls.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

tests/mbim_ntb_test: tests/mbim_ntb_test.c src/mbim_frontend/mbim_ntb.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

tests/ue_nas_security_test: tests/ue_nas_security_test.c src/ue_engine/ue_nas_security.c src/common/log.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

tests/ue_instance_config_test: tests/ue_instance_config_test.c src/runtime/ue_instance_config.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

tests/mbim_indications_test: tests/mbim_indications_test.c src/mbim_frontend/mbim_indications.c src/mbim_frontend/mbim_protocol.c src/mbim_frontend/mbim_wire.c src/common/log.c src/common/utils.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

tests/ue_nas_codec_test: tests/ue_nas_codec_test.c src/ue_engine/ue_nas_encode.c src/ue_engine/ue_nas_decode.c src/common/log.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

tests/mbim_sms_store_test: tests/mbim_sms_store_test.c src/mbim_frontend/mbim_handlers.c src/mbim_frontend/mbim_wire.c src/mbim_frontend/mbim_protocol.c src/common/log.c src/common/utils.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

tests/ims_rpdata_test: tests/ims_rpdata_test.c src/ims_service/ims_rpdata.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET) $(OBJ) $(TEST_BINS)
	rm -rf tests/*.dSYM
