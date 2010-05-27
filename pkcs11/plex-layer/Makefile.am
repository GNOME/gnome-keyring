
noinst_LTLIBRARIES = \
	libgkm-plex-layer.la

INCLUDES = -I. \
	-I$(top_srcdir) \
	-I$(top_builddir)

# ------------------------------------------------------------------------------
# The code

libgkm_plex_layer_la_SOURCES = \
	gkm-plex-layer.c gkm-plex-layer.h

libgkm_plex_layer_la_LIBADD = \
    	$(GTHREAD_LIBS) \
	$(GLIB_LIBS)

libgkm_plex_layer_la_CFLAGS = \
    	$(GTHREAD_CFLAGS) \
	$(GLIB_CFLAGS)
