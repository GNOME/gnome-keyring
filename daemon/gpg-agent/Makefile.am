
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
