
# ------------------------------------------------------------------------------
# The ssh-agent component code

noinst_LTLIBRARIES += \
	libgkd-ssh-agent.la

libgkd_ssh_agent_la_SOURCES = \
	daemon/ssh-agent/gkd-ssh-agent.c \
	daemon/ssh-agent/gkd-ssh-agent.h \
	daemon/ssh-agent/gkd-ssh-agent-client.h \
	daemon/ssh-agent/gkd-ssh-agent-client.c \
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
