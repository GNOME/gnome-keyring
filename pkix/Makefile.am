
noinst_LTLIBRARIES=libgkr-pkix.la

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_builddir) 				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

BUILT_SOURCES = \
	gkr-pkix-marshal.c gkr-pkix-marshal.h \
	asn1-def-pk.h asn1-def-pkix.h
	
libgkr_pkix_la_SOURCES = \
	gkr-pkix-asn1.c gkr-pkix-asn1.h \
	gkr-pkix-cert.c gkr-pkix-cert.h \
	gkr-pkix-der.c gkr-pkix-der.h \
	gkr-pkix-openssl.c gkr-pkix-openssl.h \
	gkr-pkix-parser.c gkr-pkix-parser.h \
	gkr-pkix-pem.c gkr-pkix-pem.h \
	$(BUILT_SOURCES)

gkr-pkix-marshal.h: gkr-pkix-marshal.list $(GLIB_GENMARSHAL)
	$(GLIB_GENMARSHAL) $< --header --prefix=gkr_pkix_marshal > $@

gkr-pkix-marshal.c: gkr-pkix-marshal.list $(GLIB_GENMARSHAL)
	echo "#include \"gkr-pkix-marshal.h\"" > $@ && \
	$(GLIB_GENMARSHAL) $< --body --prefix=gkr_pkix_marshal >> $@

asn1-def-pk.h: pk.asn
	asn1Parser -o asn1-def-pk.h pk.asn 
	
asn1-def-pkix.h: pkix.asn
	asn1Parser -o asn1-def-pkix.h pkix.asn 

EXTRA_DIST = gkr-pkix-marshal.list \
	pkix.asn \
	pk.asn

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
