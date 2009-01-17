
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	-I$(top_srcdir)/pkcs11 \
    	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS)
	
			
# ------------------------------------------------------------------------------
# The ssh-agent component code

noinst_LTLIBRARIES = \
	libgck-ssh-agent.la

libgck_ssh_agent_la_SOURCES = \
	gck-ssh-agent.c gck-ssh-agent.h \
	gck-ssh-agent-private.h \
	gck-ssh-agent-ops.c \
	gck-ssh-agent-proto.c

# ------------------------------------------------------------------------------
# Standalone binary

noinst_PROGRAMS = \
	gck-ssh-agent-standalone
	
gck_ssh_agent_standalone_SOURCES = \
	gck-ssh-agent-standalone.c

gck_ssh_agent_standalone_LDADD = \
	libgck-ssh-agent.la \
	$(top_builddir)/gp11/libgp11.la \
	$(top_builddir)/egg/libegg-buffer.la \
	$(top_builddir)/egg/libegg-secure.la \
    	$(GOBJECT_LIBS) \
    	$(GTHREAD_LIBS) \
    	$(LIBGCRYPT_LIBS) \
	$(GLIB_LIBS) 

# -------------------------------------------------------------------------------

# if WITH_TESTS
# TESTS_DIR = tests
# else
# TESTS_DIR = 
# endif
# 
# SUBDIRS = . $(TESTS_DIR)
