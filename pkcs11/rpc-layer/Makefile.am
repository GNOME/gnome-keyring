
noinst_LTLIBRARIES = \
	libgck-rpc-layer.la

noinst_PROGRAMS = \
	gck-rpc-daemon-standalone
	
INCLUDES = -I. \
	-I$(top_srcdir) \
	-I$(top_builddir)
	
# ------------------------------------------------------------------------------
# The dispatch code

libgck_rpc_layer_la_SOURCES = \
	gck-rpc-dispatch.c \
	gck-rpc-layer.h \
	gck-rpc-message.c \
	gck-rpc-private.h \
	gck-rpc-util.c

libgck_rpc_layer_la_LIBADD = \
	$(top_builddir)/egg/libegg-buffer.la \
	$(top_builddir)/egg/libegg-creds.la \
	$(GOBJECT_LIBS) \
    	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) 

libgck_rpc_layer_la_CFLAGS = \
	$(GOBJECT_CFLAGS) \
    	$(GTHREAD_CFLAGS) \
	$(GLIB_CFLAGS) 

# ------------------------------------------------------------------------------
# The module code, built as the public gnome-keyring module

moduledir = $(libdir)/gnome-keyring/

module_LTLIBRARIES = \
	gnome-keyring-pkcs11.la

gnome_keyring_pkcs11_la_SOURCES = \
	gck-rpc-private.h \
	gck-rpc-module.c \
	gck-rpc-message.c \
	gck-rpc-util.c

gnome_keyring_pkcs11_la_LIBADD = \
	$(top_builddir)/egg/libegg-buffer.la \
	$(top_builddir)/egg/libegg-creds.la 

gnome_keyring_pkcs11_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

# -----------------------------------------------------------------------------
# The test daemon 

gck_rpc_daemon_standalone_SOURCES = \
	gck-rpc-daemon-standalone.c
	
gck_rpc_daemon_standalone_LDADD = \
	$(DL_LIBS) libgck-rpc-layer.la
	
