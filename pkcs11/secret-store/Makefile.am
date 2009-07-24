
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
	gck-secret-collection.h gck-secret-collection.c \
	gck-secret-item.h gck-secret-item.c \
	gck-secret-object.h gck-secret-object.c

# -------------------------------------------------------------------------------
