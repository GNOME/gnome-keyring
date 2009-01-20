incdir = $(includedir)/gcr

inc_HEADERS = \
	gcr-parser.h \
	gcr-types.h

INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS)

BUILT_SOURCES = \
	gcr-marshal.c gcr-marshal.h

lib_LTLIBRARIES = libgcr.la

libgcr_la_SOURCES = \
	gcr-internal.c gcr-internal.h \
	gcr-parser.c gcr-parser.h \
	gcr-types.h \
	$(BUILT_SOURCES)
    
libgcr_la_LDFLAGS = \
    	-version-info $(GCR_LT_RELEASE) \
	-no-undefined -export-symbols-regex 'gcr_*'
    
libgcr_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/gp11/libgp11.la \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS)

gcr-marshal.h: gcr-marshal.list $(GLIB_GENMARSHAL)
	$(GLIB_GENMARSHAL) $< --header --prefix=_gcr_marshal > $@

gcr-marshal.c: gcr-marshal.list $(GLIB_GENMARSHAL)
	echo "#include \"gcr-marshal.h\"" > $@ && \
	$(GLIB_GENMARSHAL) $< --body --prefix=_gcr_marshal >> $@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gcr-$(GCR_MAJOR).pc

EXTRA_DIST = \
	gcr.pc.in \
	gcr-marshal.list \
	gcr-import-dialog.glade
    
DISTCLEANFILES = \
	gcr-$(GCR_MAJOR).pc
    
gcr-$(GCR_MAJOR).pc: gcr.pc
	cp gcr.pc gcr-$(GCR_MAJOR).pc

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . \
	$(TESTS_DIR)
	
