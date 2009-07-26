
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	-I$(top_srcdir)/pkcs11 \
    	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS)

# ------------------------------------------------------------------------------
# The roots component code

noinst_LTLIBRARIES = \
	libgck-secret-store.la

libgck_secret_store_la_SOURCES = \
	gck-secret-binary.c gck-secret-binary.h \
	gck-secret-collection.h gck-secret-collection.c \
	gck-secret-fields.h gck-secret-fields.c \
	gck-secret-item.h gck-secret-item.c \
	gck-secret-module.h gck-secret-module.c \
	gck-secret-object.h gck-secret-object.c \
	gck-secret-search.h gck-secret-search.c \
	gck-secret-textual.c gck-secret-textual.h

# -------------------------------------------------------------------------------
