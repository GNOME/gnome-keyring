
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	-I$(top_srcdir)/pkcs11 \
    	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS)

# ------------------------------------------------------------------------------
# The secret store component code

noinst_LTLIBRARIES = \
	libgck-secret-store.la

libgck_secret_store_la_SOURCES = \
	gck-secret-binary.c gck-secret-binary.h \
	gck-secret-collection.h gck-secret-collection.c \
	gck-secret-compat.h \
	gck-secret-fields.h gck-secret-fields.c \
	gck-secret-item.h gck-secret-item.c \
	gck-secret-module.h gck-secret-module.c \
	gck-secret-object.h gck-secret-object.c \
	gck-secret-search.h gck-secret-search.c \
	gck-secret-store.h \
	gck-secret-types.h \
	gck-secret-textual.c gck-secret-textual.h

# ------------------------------------------------------------------------------
# The standalone module

moduledir = $(libdir)/gnome-keyring/standalone/

module_LTLIBRARIES = \
	gck-secret-store-standalone.la

gck_secret_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

gck_secret_store_standalone_la_SOURCES = \
	gck-secret-standalone.c

gck_secret_store_standalone_la_LIBADD = \
	libgck-secret-store.la \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

# -------------------------------------------------------------------------------
