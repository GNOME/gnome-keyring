
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	-I$(top_srcdir)/pkcs11 \
    	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)
	
# ------------------------------------------------------------------------------
# The openssh component code

noinst_LTLIBRARIES = \
	libgck-dot-ssh.la	

libgck_dot_ssh_la_SOURCES = \
	gck-ssh-module.c gck-ssh-module.h \
	gck-ssh-openssh.c gck-ssh-openssh.h \
	gck-ssh-private-key.c gck-ssh-private-key.h \
	gck-ssh-public-key.c gck-ssh-public-key.h

libgck_dot_ssh_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(top_builddir)/pkcs11/gck/libgck.la
	
# -------------------------------------------------------------------------------

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
