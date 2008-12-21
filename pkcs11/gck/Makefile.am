
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)
	
# ------------------------------------------------------------------------------
# The dispatch code

noinst_LTLIBRARIES = \
	libgck.la	

libgck_la_SOURCES = \
	gck-crypto.c gck-crypto.h \
	gck-key.c gck-key.h \
	gck-manager.c gck-manager.h \
	gck-module.c gck-module.h gck-module-ep.h \
	gck-object.c gck-object.h \
	gck-private-key.c gck-private-key.h \
	gck-public-key.c gck-public-key.h \
	gck-session.c gck-session.h \
	gck-sexp.c gck-sexp.h \
	gck-util.c gck-util.h 
	
# ------------------------------------------------------------------------------
# TEMPORARY TEST BINARY

noinst_PROGRAMS = \
	temporary-test
	
temporary_test_SOURCES = \
	temporary-test.c
	
temporary_test_LDADD = \
	libgck.la \
    	$(GOBJECT_LIBS) \
    	$(LIBGCRYPT_LIBS) \
	$(GLIB_LIBS)
	