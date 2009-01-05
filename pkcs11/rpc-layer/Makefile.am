
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
	$(top_builddir)/common/libgkr-common-buffer.la \
	$(GOBJECT_LIBS) \
    	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) 

libgck_rpc_layer_la_CFLAGS = \
	$(GOBJECT_CFLAGS) \
    	$(GTHREAD_CFLAGS) \
	$(GLIB_CFLAGS) 

# ------------------------------------------------------------------------------
# The module code 

moduledir = $(libdir)/gnome-keyring/devel/

module_LTLIBRARIES = \
	gck-rpc-layer-standalone.la

gck_rpc_layer_standalone_la_SOURCES = \
	gck-rpc-private.h \
	gck-rpc-module.c \
	gck-rpc-message.c \
	gck-rpc-util.c

gck_rpc_layer_standalone_la_LIBADD = \
	$(top_builddir)/common/libgkr-common-buffer.la 

gck_rpc_layer_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

# -----------------------------------------------------------------------------
# The test daemon 

gck_rpc_daemon_standalone_SOURCES = \
	gck-rpc-daemon-standalone.c
	
gck_rpc_daemon_standalone_LDADD = \
	-ldl -lpthread libgck-rpc-layer.la
	
