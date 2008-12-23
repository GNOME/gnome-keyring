
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	-I$(top_srcdir)/pkcs11 \
    	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)
	
			
# ------------------------------------------------------------------------------
# The dot-ssh component code

noinst_LTLIBRARIES = \
	libgck-dot-ssh.la

libgck_dot_ssh_la_SOURCES = \
	gck-ssh-module.c gck-ssh-module.h \
	gck-ssh-openssh.c gck-ssh-openssh.h \
	gck-ssh-private-key.c gck-ssh-private-key.h \
	gck-ssh-public-key.c gck-ssh-public-key.h

# ------------------------------------------------------------------------------
# The standalone module 

moduledir = $(libdir)/gnome-keyring/standalone/

module_LTLIBRARIES = \
	gck-dot-ssh-module.la

gck_dot_ssh_module_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

gck_dot_ssh_module_la_SOURCES = \
	gck-ssh-standalone.c

gck_dot_ssh_module_la_LIBADD = \
	libgck-dot-ssh.la \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(top_builddir)/common/libgkr-module-common.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(LIBTASN1_LIBS) \
	$(LIBGCRYPT_LIBS)


# -------------------------------------------------------------------------------

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
