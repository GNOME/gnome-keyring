
noinst_LTLIBRARIES = \
	libegg.la \
	libegg-buffer.la \
	libegg-creds.la \
	libegg-dbus.la \
	libegg-secure.la \
	libegg-secure-entry.la

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
	egg-cleanup.c egg-cleanup.h \
	egg-hex.c egg-hex.h \
	egg-libgcrypt.c egg-libgcrypt.h \
	egg-oid.c egg-oid.h \
	egg-openssl.c egg-openssl.h \
	egg-unix-credentials.c egg-unix-credentials.h \
	egg-secure-memory.c egg-secure-memory.h \
	egg-symkey.c egg-symkey.h \
	$(BUILT_SOURCES)
	
asn1-def-pk.h: pk.asn
	$(ASN1PARSER) -o asn1-def-pk.h $(srcdir)/pk.asn 
	
asn1-def-pkix.h: pkix.asn
	$(ASN1PARSER) -o asn1-def-pkix.h $(srcdir)/pkix.asn 

EXTRA_DIST = \
	pkix.asn \
	pk.asn

DISTCLEANFILES = \
	$(BUILT_SOURCES)
	
# --------------------------------------------------------------------
# COMMON STUFF COMPILED INTO SMALLER COMPONENTS
 
libegg_secure_la_SOURCES = \
 	egg-secure-memory.c egg-secure-memory.h

libegg_secure_entry_la_SOURCES = \
 	egg-secure-entry.c egg-secure-entry.h

libegg_secure_entry_la_CFLAGS = \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS)
	
libegg_buffer_la_SOURCES = \
	egg-buffer.c egg-buffer.h 
 	
libegg_creds_la_SOURCES = \
	egg-unix-credentials.c egg-unix-credentials.h	

libegg_dbus_la_SOURCES = \
	egg-dbus.c egg-dbus.h 

libegg_dbus_la_CFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS)

libegg_dbus_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)
	
# -------------------------------------------------------------------

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
