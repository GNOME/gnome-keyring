
noinst_LTLIBRARIES = \
	libegg.la \
	libegg-buffer.la \
	libegg-creds.la \
	libegg-secure.la

BUILT_SOURCES = \
	asn1-def-pk.h asn1-def-pkix.h

INCLUDES = \
	-I$(top_srcdir) 
	-I$(top_builddir) 

libegg_la_CFLAGS = \
	$(LIBTASN1_CFLAGS) \
	$(GLIB_CFLAGS)

libegg_la_SOURCES = \
	egg-asn1.c egg-asn1.h \
	egg-buffer.c egg-buffer.h \
	egg-hex.c egg-hex.h \
	egg-openssl.c egg-openssl.h \
	egg-unix-credentials.c egg-unix-credentials.h \
	egg-secure-memory.c egg-secure-memory.h \
	egg-symkey.c egg-symkey.h \
	$(BUILT_SOURCES)
	
asn1-def-pk.h: pk.asn
	asn1Parser -o asn1-def-pk.h $(srcdir)/pk.asn 
	
asn1-def-pkix.h: pkix.asn
	asn1Parser -o asn1-def-pkix.h $(srcdir)/pkix.asn 

EXTRA_DIST = \
	pkix.asn \
	pk.asn

DISTCLEANFILES = \
	$(BUILT_SOURCES)
	
# --------------------------------------------------------------------
# COMMON STUFF COMPILED INTO SMALLER COMPONENTS
 
libegg_secure_la_SOURCES = \
 	egg-secure-memory.c egg-secure-memory.h

libegg_buffer_la_SOURCES = \
	egg-buffer.c egg-buffer.h 
 	
libegg_creds_la_SOURCES = \
	egg-unix-credentials.c egg-unix-credentials.h	

# -------------------------------------------------------------------

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
