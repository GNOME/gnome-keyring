
# ------------------------------------------------------------------------------
# The ssh-agent component code

noinst_LTLIBRARIES += \
	libgkd-ssh-agent.la

libgkd_ssh_agent_la_SOURCES = \
	daemon/ssh-agent/gkd-ssh-agent-interaction.c \
	daemon/ssh-agent/gkd-ssh-agent-interaction.h \
	daemon/ssh-agent/gkd-ssh-agent-process.h \
	daemon/ssh-agent/gkd-ssh-agent-process.c \
	daemon/ssh-agent/gkd-ssh-agent-preload.h \
	daemon/ssh-agent/gkd-ssh-agent-preload.c \
	daemon/ssh-agent/gkd-ssh-agent-private.h \
	daemon/ssh-agent/gkd-ssh-agent-service.c \
	daemon/ssh-agent/gkd-ssh-agent-service.h \
	daemon/ssh-agent/gkd-ssh-agent-util.c \
	daemon/ssh-agent/gkd-ssh-agent-util.h \
	$(NULL)
libgkd_ssh_agent_la_CFLAGS = \
	$(DAEMON_CFLAGS)

# Tests

noinst_LTLIBRARIES += \
	libgkd-ssh-agent-test.la

libgkd_ssh_agent_test_la_SOURCES = \
	daemon/ssh-agent/test-common.c \
	daemon/ssh-agent/test-common.h

libgkd_ssh_agent_test_la_CFLAGS = \
	$(DAEMON_CFLAGS)

libgkd_ssh_agent_test_la_LIBADD = \
	libegg-buffer.la \
	libgkm-wrap-layer.la \
	$(DAEMON_LIBS)

ssh_agent_CFLAGS = \
	$(DAEMON_CFLAGS)

ssh_agent_LIBS = \
	libgkd-ssh-agent.la \
	libgkd-ssh-agent-test.la \
	libegg-buffer.la \
	libegg-test.la \
	$(DAEMON_LIBS)

ssh_agent_TESTS = \
	test-gkd-ssh-agent-interaction \
	test-gkd-ssh-agent-preload \
	test-gkd-ssh-agent-process \
	test-gkd-ssh-agent-service \
	test-gkd-ssh-agent-util

test_gkd_ssh_agent_preload_SOURCES = daemon/ssh-agent/test-gkd-ssh-agent-preload.c
test_gkd_ssh_agent_preload_CFLAGS = $(ssh_agent_CFLAGS)
test_gkd_ssh_agent_preload_LDADD = $(ssh_agent_LIBS)

test_gkd_ssh_agent_process_SOURCES = daemon/ssh-agent/test-gkd-ssh-agent-process.c
test_gkd_ssh_agent_process_CFLAGS = $(ssh_agent_CFLAGS)
test_gkd_ssh_agent_process_LDADD = $(ssh_agent_LIBS)

test_gkd_ssh_agent_service_SOURCES = daemon/ssh-agent/test-gkd-ssh-agent-service.c
test_gkd_ssh_agent_service_CFLAGS = $(ssh_agent_CFLAGS)
test_gkd_ssh_agent_service_LDADD = $(ssh_agent_LIBS) libgkd-login.la libgkm-wrap-layer.la

test_gkd_ssh_agent_util_SOURCES = daemon/ssh-agent/test-gkd-ssh-agent-util.c
test_gkd_ssh_agent_util_CFLAGS = $(ssh_agent_CFLAGS)
test_gkd_ssh_agent_util_LDADD = $(ssh_agent_LIBS)

test_gkd_ssh_agent_interaction_SOURCES = daemon/ssh-agent/test-gkd-ssh-agent-interaction.c
test_gkd_ssh_agent_interaction_CFLAGS = $(ssh_agent_CFLAGS)
test_gkd_ssh_agent_interaction_LDADD = $(ssh_agent_LIBS) libgkd-login.la

if WITH_SSH
check_PROGRAMS += $(ssh_agent_TESTS)
TESTS += $(ssh_agent_TESTS)
endif
