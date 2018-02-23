
# ------------------------------------------------------------------------------
# The ssh-agent component code

noinst_LTLIBRARIES += \
	libgkd-ssh-agent.la

libgkd_ssh_agent_la_SOURCES = \
	daemon/ssh-agent/gkd-ssh-agent.c \
	daemon/ssh-agent/gkd-ssh-agent.h \
	daemon/ssh-agent/gkd-ssh-agent-interaction.c \
	daemon/ssh-agent/gkd-ssh-agent-interaction.h \
	daemon/ssh-agent/gkd-ssh-agent-private.h \
	daemon/ssh-agent/gkd-ssh-agent-ops.c \
	daemon/ssh-agent/gkd-ssh-agent-proto.c
libgkd_ssh_agent_la_CFLAGS = \
	$(DAEMON_CFLAGS)

# ------------------------------------------------------------------------------
# Standalone binary

noinst_PROGRAMS += \
	gkd-ssh-agent-standalone

gkd_ssh_agent_standalone_SOURCES = \
	daemon/ssh-agent/gkd-ssh-agent-standalone.c
gkd_ssh_agent_standalone_CFLAGS = \
	$(DAEMON_CFLAGS)
gkd_ssh_agent_standalone_LDADD = \
	libgkd-ssh-agent.la \
	libegg-buffer.la \
	libegg-secure.la \
	libgkm.la \
	$(DAEMON_LIBS)

# ------------------------------------------------------------------------------
# Tests

ssh_agent_CFLAGS = \
	$(GCK_CFLAGS)

ssh_agent_LIBS = \
	libgkd-ssh-agent.la \
	libgkm.la \
	libegg.la \
	$(GLIB_LIBS) \
	$(GCK_LIBS)
	$(GTHREAD_LIBS)

ssh_agent_TESTS = \
	test-communication \
	test-keytypes \
	test-gkd-ssh-agent-interaction

test_keytypes_SOURCES = daemon/ssh-agent/test-keytypes.c
test_keytypes_CFLAGS = $(ssh_agent_CFLAGS)
test_keytypes_LDADD = $(ssh_agent_LIBS)

test_communication_SOURCES = daemon/ssh-agent/test-communication.c
test_communication_CFLAGS = $(ssh_agent_CFLAGS)
test_communication_LDADD = $(ssh_agent_LIBS)

test_gkd_ssh_agent_interaction_SOURCES = daemon/ssh-agent/test-gkd-ssh-agent-interaction.c
test_gkd_ssh_agent_interaction_CFLAGS = $(ssh_agent_CFLAGS)
test_gkd_ssh_agent_interaction_LDADD = $(ssh_agent_LIBS) libgkd-login.la libgkm-wrap-layer.la

check_PROGRAMS += $(ssh_agent_TESTS)
TESTS += $(ssh_agent_TESTS)
