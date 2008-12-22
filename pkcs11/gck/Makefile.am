
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)
	
# ------------------------------------------------------------------------------
# The GCK library

noinst_LTLIBRARIES = \
	libgck.la	

BUILT_SOURCES = \
	asn1-def-pk.h asn1-def-pkix.h

libgck_la_SOURCES = \
	gck-crypto.c gck-crypto.h \
	gck-data-asn1.c gck-data-asn1.h \
	gck-data-der.c gck-data-der.h \
	gck-data-openssl.c gck-data-openssl.h \
	gck-data-pem.c gck-data-pem.h \
	gck-data-types.h \
	gck-file-tracker.c gck-file-tracker.h \
	gck-key.c gck-key.h \
	gck-manager.c gck-manager.h \
	gck-module.c gck-module.h gck-module-ep.h \
	gck-object.c gck-object.h \
	gck-private-key.c gck-private-key.h \
	gck-public-key.c gck-public-key.h \
	gck-session.c gck-session.h \
	gck-sexp.c gck-sexp.h \
	gck-util.c gck-util.h 
	
asn1-def-pk.h: pk.asn
	asn1Parser -o asn1-def-pk.h pk.asn 
	
asn1-def-pkix.h: pkix.asn
	asn1Parser -o asn1-def-pkix.h pkix.asn 

EXTRA_DIST = \
	pkix.asn \
	pk.asn

# ------------------------------------------------------------------------------
# TEMPORARY TEST BINARY

noinst_PROGRAMS = \
	temporary-test
	
temporary_test_SOURCES = \
	temporary-test.c

temporary_test_LDFLAGS = \
	-lpthread
	
temporary_test_LDADD = \
	libgck.la \
	$(top_builddir)/common/libgkr-module-common.la \
    	$(GOBJECT_LIBS) \
    	$(LIBGCRYPT_LIBS) \
	$(GLIB_LIBS) 

# -------------------------------------------------------------------------------

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
