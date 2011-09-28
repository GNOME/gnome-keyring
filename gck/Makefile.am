
SUBDIRS = . tests

incdir = $(includedir)/gck-@GCK_MAJOR@/gck

inc_HEADERS = \
	gck.h \
	gck-deprecated.h

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(P11_KIT_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DG_LOG_DOMAIN=\"Gck\" \
	-DGCK_API_SUBJECT_TO_CHANGE \
	-DP11_KIT_API_SUBJECT_TO_CHANGE \
	-DPKCS11_REGISTRY_DIR=\"$(libdir)/pkcs11\"

BUILT_SOURCES = \
	gck-marshal.c gck-marshal.h

lib_LTLIBRARIES = libgck-@GCK_MAJOR@.la

PUBLIC_FILES = \
	gck.h \
	gck-attributes.c \
	gck-dump.c \
	gck-enumerator.c \
	gck-misc.c \
	gck-module.c \
	gck-modules.c \
	gck-object.c \
	gck-session.c \
	gck-slot.c \
	gck-uri.c

INTERNAL_FILES = \
	gck-call.c \
	gck-debug.c gck-debug.h \
	gck-deprecated.h \
	gck-private.h \
	pkcs11.h

libgck_@GCK_MAJOR@_la_SOURCES = \
	$(PUBLIC_FILES) \
	$(INTERNAL_FILES) \
	$(BUILT_SOURCES)

libgck_@GCK_MAJOR@_la_LDFLAGS = \
	-version-info $(GCK_LT_RELEASE) \
	-no-undefined \
	-export-symbols-regex '^gck_*'

libgck_@GCK_MAJOR@_la_LIBADD = \
	$(top_builddir)/egg/libegg-hex.la \
	$(P11_KIT_LIBS) \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GIO_LIBS) \
	$(GLIB_LIBS)

noinst_LTLIBRARIES = libgck-testable.la
libgck_testable_la_SOURCES = \
	gck-mock.c \
	gck-mock.h \
	gck-test.c \
	gck-test.h
libgck_testable_la_LIBADD = $(libgck_@GCK_MAJOR@_la_OBJECTS) \
	$(libgck_@GCK_MAJOR@_la_LIBADD)
libgck_testable_la_DEPENDENCIES = $(libgck_@GCK_MAJOR@_la_OBJECTS)

gck-marshal.h: gck-marshal.list $(GLIB_GENMARSHAL)
	$(GLIB_GENMARSHAL) $< --header --prefix=_gck_marshal > $@

gck-marshal.c: gck-marshal.list $(GLIB_GENMARSHAL)
	echo "#include \"gck-marshal.h\"" > $@ && \
	$(GLIB_GENMARSHAL) $< --body --prefix=_gck_marshal >> $@

# ------------------------------------------------------------------
# INTROSPECTION

if HAVE_INTROSPECTION

include $(INTROSPECTION_MAKEFILE)

INTROSPECTION_GIRS = Gck-@GCK_MAJOR@.gir
INTROSPECTION_SCANNER_ARGS = $(INTROSPECTION_FLAGS) --warn-all --add-include-path=$(srcdir) --add-include-path=.
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir) --includedir=.

Gck-@GCK_MAJOR@.gir: libgck-@GCK_MAJOR@.la

Gck_@GCK_MAJOR@_gir_PACKAGES = gobject-2.0 gtk+-3.0 p11-kit-1
Gck_@GCK_MAJOR@_gir_EXPORT_PACKAGES = gck-@GCK_MAJOR@
Gck_@GCK_MAJOR@_gir_INCLUDES = GObject-2.0 Gtk-3.0
Gck_@GCK_MAJOR@_gir_LIBS = libgck-@GCK_MAJOR@.la
Gck_@GCK_MAJOR@_gir_CFLAGS = -I$(top_srcdir) -I$(top_builddir) -DGCK_COMPILATION -DGCK_API_SUBJECT_TO_CHANGE
Gck_@GCK_MAJOR@_gir_FILES = $(PUBLIC_FILES)
Gck_@GCK_MAJOR@_gir_SCANNERFLAGS = --c-include "gck.h"

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibsdir = $(libdir)/girepository-1.0
typelibs_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

endif

# ----------------------------------------------------------------

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gck-$(GCK_MAJOR).pc

gck-expected.abi: gck.symbols
	$(AM_V_GEN) cpp -P $< | sort > $@

gck-actual.abi: $(builddir)/.libs/libgck-@GCK_MAJOR@.so
	$(AM_V_GEN)  $(NM) -D -g --defined-only $< | \
		cut -d ' ' -f 3 | grep -Ev '^(__bss_start|_edata|_end)' | sort > $@

check-symbols: gck-expected.abi gck-actual.abi
	$(AM_V_GEN) diff -U0 --ignore-blank-lines gck-expected.abi gck-actual.abi || \
		(echo "check-symbols: Symbols have CHANGED. Fix gck.symbols"; exit 1)

check-local: check-symbols

EXTRA_DIST = \
	gck.pc.in \
	gck-marshal.list \
	gck.symbols \
	pkcs11-trust-assertions.h

CLEANFILES = \
	gck-actual.abi \
	gck-expected.abi

DISTCLEANFILES = \
	gck-$(GCK_MAJOR).pc

gck-$(GCK_MAJOR).pc: gck.pc
	cp gck.pc gck-$(GCK_MAJOR).pc
