
# ------------------------------------------------------------------------------
# The ssh-agent component code

noinst_LTLIBRARIES += \
	libgkd-ssh-agent.la

libgkd_ssh_agent_la_SOURCES = \
	daemon/ssh-agent/gkd-ssh-agent.c \
	daemon/ssh-agent/gkd-ssh-agent.h \
	daemon/ssh-agent/gkd-ssh-agent-process.h \
	daemon/ssh-agent/gkd-ssh-agent-process.c \
	daemon/ssh-agent/gkd-ssh-agent-preload.h \
	daemon/ssh-agent/gkd-ssh-agent-preload.c \
	daemon/ssh-agent/gkd-ssh-agent-private.h \
	daemon/ssh-agent/gkd-ssh-agent-ops.c \
	daemon/ssh-agent/gkd-ssh-interaction.h \
	daemon/ssh-agent/gkd-ssh-interaction.c \
	daemon/ssh-agent/gkd-ssh-openssh.h \
	daemon/ssh-agent/gkd-ssh-openssh.c \
	$(NULL)
libgkd_ssh_agent_la_CFLAGS = \
	$(DAEMON_CFLAGS)

# Tests

ssh_agent_CFLAGS = \
	$(DAEMON_CFLAGS)

ssh_agent_LIBS = \
	libgkd-ssh-agent.la \
	libegg-buffer.la \
	$(DAEMON_LIBS)

ssh_agent_TESTS = \
	test-gkd-ssh-openssh \
	test-gkd-ssh-agent-process

test_gkd_ssh_openssh_SOURCES = daemon/ssh-agent/test-gkd-ssh-openssh.c
test_gkd_ssh_openssh_CFLAGS = $(ssh_agent_CFLAGS)
test_gkd_ssh_openssh_LDADD = $(ssh_agent_LIBS)

test_gkd_ssh_agent_process_SOURCES = daemon/ssh-agent/test-gkd-ssh-agent-process.c
test_gkd_ssh_agent_process_CFLAGS = $(ssh_agent_CFLAGS)
test_gkd_ssh_agent_process_LDADD = $(ssh_agent_LIBS)

check_PROGRAMS += $(ssh_agent_TESTS)
TESTS += $(ssh_agent_TESTS)
