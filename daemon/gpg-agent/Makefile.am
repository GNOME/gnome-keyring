
# ------------------------------------------------------------------------------
# The ssh-agent component code

noinst_LTLIBRARIES += \
	libgkd-gpg-agent.la

libgkd_gpg_agent_la_SOURCES = \
	daemon/gpg-agent/gkd-gpg-agent.c \
	daemon/gpg-agent/gkd-gpg-agent.h \
	daemon/gpg-agent/gkd-gpg-agent-private.h \
	daemon/gpg-agent/gkd-gpg-agent-ops.c
libgkd_gpg_agent_la_CFLAGS = \
	$(GCK_CFLAGS) \
	$(GCR_CFLAGS)

# ------------------------------------------------------------------------------
# Standalone binary

noinst_PROGRAMS += \
	gkd-gpg-agent-standalone

gkd_gpg_agent_standalone_SOURCES = \
	daemon/gpg-agent/gkd-gpg-agent-standalone.c
gkd_gpg_agent_standalone_CFLAGS = \
	$(GCK_CFLAGS)
gkd_gpg_agent_standalone_LDADD = \
	libgkd-gpg-agent.la \
	libegg.la \
	$(DAEMON_LIBS)
