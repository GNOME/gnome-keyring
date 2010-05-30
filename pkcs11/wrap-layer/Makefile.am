
noinst_LTLIBRARIES = \
	libgkm-wrap-layer.la

INCLUDES = -I. \
	-I$(top_srcdir) \
	-I$(top_builddir)

# ------------------------------------------------------------------------------
# The code

libgkm_wrap_layer_la_SOURCES = \
	gkm-wrap-layer.c gkm-wrap-layer.h

libgkm_wrap_layer_la_LIBADD = \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS)

libgkm_wrap_layer_la_CFLAGS = \
	$(GTHREAD_CFLAGS) \
	$(GLIB_CFLAGS)
