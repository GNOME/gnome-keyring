
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	-I$(top_srcdir)/pkcs11 \
    	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)
	
			
# ------------------------------------------------------------------------------
# The user-store component code

noinst_LTLIBRARIES = \
	libgck-user-store.la

libgck_user_store_la_SOURCES = \
	gck-user-store.h \
	gck-user-module.c gck-user-module.h \
	gck-user-private-key.c gck-user-private-key.h \
	gck-user-public-key.c gck-user-public-key.h \
	gck-user-storage.c gck-user-storage.h

# ------------------------------------------------------------------------------
# The standalone module 

moduledir = $(libdir)/gnome-keyring/devel/

module_LTLIBRARIES = \
	gck-user-store-standalone.la

gck_user_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

gck_user_store_standalone_la_SOURCES = \
	gck-user-standalone.c

gck_user_store_standalone_la_LIBADD = \
	libgck-user-store.la \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(LIBTASN1_LIBS) \
	$(LIBGCRYPT_LIBS)


# -------------------------------------------------------------------------------

# if WITH_TESTS
# TESTS_DIR = tests
# else
TESTS_DIR = 
# endif

SUBDIRS = . $(TESTS_DIR)
