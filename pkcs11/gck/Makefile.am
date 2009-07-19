
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
	gck-marshal.c gck-marshal.h \
	asn1-def-pk.h asn1-def-pkix.h

libgck_la_SOURCES = \
	gck-attributes.c gck-attributes.h \
	gck-authenticator.c gck-authenticator.h \
	gck-certificate.c gck-certificate.h \
	gck-certificate-key.c gck-certificate-key.h \
	gck-certificate-trust.c gck-certificate-trust.h \
	gck-crypto.c gck-crypto.h \
	gck-data-asn1.c gck-data-asn1.h \
	gck-data-der.c gck-data-der.h \
	gck-data-file.c gck-data-file.h \
	gck-data-types.h \
	gck-factory.c gck-factory.h \
	gck-file-tracker.c gck-file-tracker.h \
	gck-key.c gck-key.h \
	gck-login.c gck-login.h \
	gck-manager.c gck-manager.h \
	gck-memory-store.c gck-memory-store.h \
	gck-module.c gck-module.h gck-module-ep.h \
	gck-object.c gck-object.h \
	gck-private-key.c gck-private-key.h \
	gck-public-key.c gck-public-key.h \
	gck-serializable.c gck-serializable.h \
	gck-session.c gck-session.h \
	gck-sexp.c gck-sexp.h \
	gck-store.c gck-store.h \
	gck-timer.c gck-timer.h \
	gck-transaction.c gck-transaction.h \
	gck-types.h \
	gck-util.c gck-util.h \
	$(BUILT_SOURCES)

libgck_la_CFLAGS = \
	$(GOBJECT_CFLAGS) \
    	$(LIBGCRYPT_CFLAGS) \
    	$(LIBTASN1_CFLAGS) \
	$(GLIB_CFLAGS) 
	
libgck_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(GOBJECT_LIBS) \
    	$(LIBGCRYPT_LIBS) \
	$(GLIB_LIBS) 
	
gck-marshal.h: gck-marshal.list $(GLIB_GENMARSHAL)
	$(GLIB_GENMARSHAL) $< --header --prefix=gck_marshal > $@

gck-marshal.c: gck-marshal.list $(GLIB_GENMARSHAL)
	echo "#include \"gck-marshal.h\"" > $@ && \
	$(GLIB_GENMARSHAL) $< --body --prefix=gck_marshal >> $@

asn1-def-pk.h: pk.asn
	$(ASN1PARSER) -o asn1-def-pk.h $<
	
asn1-def-pkix.h: pkix.asn
	$(ASN1PARSER) -o asn1-def-pkix.h $<

EXTRA_DIST = \
	gck-marshal.list \
	pkix.asn \
	pk.asn

# -------------------------------------------------------------------------------

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
