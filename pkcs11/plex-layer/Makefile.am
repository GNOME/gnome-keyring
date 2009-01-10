
noinst_LTLIBRARIES = \
	libgck-plex-layer.la

INCLUDES = -I. \
	-I$(top_srcdir) \
	-I$(top_builddir)
	
# ------------------------------------------------------------------------------
# The code

libgck_plex_layer_la_SOURCES = \
	gck-plex-layer.c gck-plex-layer.h 

libgck_plex_layer_la_LIBADD = \
    	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) 

libgck_plex_layer_la_CFLAGS = \
    	$(GTHREAD_CFLAGS) \
	$(GLIB_CFLAGS)
	 