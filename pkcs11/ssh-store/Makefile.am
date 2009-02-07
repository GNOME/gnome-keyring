
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	-I$(top_srcdir)/pkcs11 \
    	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)
	
			
# ------------------------------------------------------------------------------
# The ssh-store component code

noinst_LTLIBRARIES = \
	libgck-ssh-store.la

libgck_ssh_store_la_SOURCES = \
	gck-ssh-store.h \
	gck-ssh-module.c gck-ssh-module.h \
	gck-ssh-openssh.c gck-ssh-openssh.h \
	gck-ssh-private-key.c gck-ssh-private-key.h \
	gck-ssh-public-key.c gck-ssh-public-key.h

# ------------------------------------------------------------------------------
# The standalone module 

moduledir = $(libdir)/gnome-keyring/devel/

module_LTLIBRARIES = \
	gck-ssh-store-standalone.la

gck_ssh_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

gck_ssh_store_standalone_la_SOURCES = \
	gck-ssh-standalone.c

gck_ssh_store_standalone_la_LIBADD = \
	libgck-ssh-store.la \
	$(top_builddir)/pkcs11/gck/libgck.la \
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
