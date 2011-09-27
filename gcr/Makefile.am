SUBDIRS = . icons tests

# ------------------------------------------------------------------
# UI BUILDER
# 

uidir = $(datadir)/gcr-@GCR_MAJOR@/ui/

ui_DATA = \
	gcr-import-dialog.ui \
	gcr-unlock-options-widget.ui

# ------------------------------------------------------------------
# HEADERS

HEADER_BASE_FILES = \
	gcr-base.h \
	gcr-certificate.h \
	gcr-certificate-chain.h \
	gcr-collection.h \
	gcr-comparable.h \
	gcr-deprecated-base.h \
	gcr-icons.h \
	gcr-importer.h \
	gcr-library.h \
	gcr-parser.h \
	gcr-pkcs11-certificate.h \
	gcr-simple-certificate.h \
	gcr-trust.h \
	gcr-types.h \
	gcr-union-collection.h \
	gcr-unlock-options.h

HEADER_UI_FILES = \
	gcr.h \
	gcr-certificate-basics-widget.h \
	gcr-certificate-details-widget.h \
	gcr-certificate-renderer.h \
	gcr-certificate-widget.h \
	gcr-collection-model.h \
	gcr-column.h \
	gcr-combo-selector.h \
	gcr-deprecated.h \
	gcr-failure-renderer.h \
	gcr-key-renderer.h \
	gcr-key-widget.h \
	gcr-import-button.h \
	gcr-list-selector.h \
	gcr-renderer.h \
	gcr-simple-collection.h \
	gcr-tree-selector.h \
	gcr-unlock-options-widget.h \
	gcr-viewer.h \
	gcr-viewer-widget.h

incdir = $(includedir)/gcr-@GCR_MAJOR@/gcr

inc_HEADERS = \
	$(HEADER_BASE_FILES) \
	$(HEADER_UI_FILES) \
	gcr-enum-types-base.h \
	gcr-enum-types.h

# ------------------------------------------------------------------
# LIBRARY

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(P11_KIT_CFLAGS) \
	-DG_LOG_DOMAIN=\"Gcr\"

lib_LTLIBRARIES = \
	libgcr-base-@GCR_MAJOR@.la \
	libgcr-@GCR_MAJOR@.la

BUILT_BASE_FILES = \
	gcr-marshal.c gcr-marshal.h \
	gcr-enum-types-base.c gcr-enum-types-base.h \
	gcr-oids.c gcr-oids.h

BUILT_UI_FILES = \
	gcr-marshal.c gcr-marshal.h \
	gcr-enum-types.c gcr-enum-types.h \
	gcr-oids.c gcr-oids.h

BUILT_SOURCES = \
	$(BUILT_BASE_FILES) \
	$(BUILT_UI_FILES)

libgcr_base_@GCR_MAJOR@_la_SOURCES = \
	gcr-callback-output-stream.c gcr-callback-output-stream.h \
	gcr-certificate.c gcr-certificate.h \
	gcr-certificate-chain.c gcr-certificate-chain.h \
	gcr-collection.c gcr-collection.h \
	gcr-comparable.c gcr-comparable.h \
	gcr-debug.c gcr-debug.h \
	gcr-gnupg-collection.c gcr-gnupg-collection.h \
	gcr-gnupg-importer.c gcr-gnupg-importer.h \
	gcr-gnupg-key.c gcr-gnupg-key.h \
	gcr-gnupg-process.c gcr-gnupg-process.h \
	gcr-gnupg-records.c gcr-gnupg-records.h \
	gcr-gnupg-util.c gcr-gnupg-util.h \
	gcr-icons.c gcr-icons.h \
	gcr-importer.c gcr-importer.h \
	gcr-internal.h \
	gcr-library.c gcr-library.h \
	gcr-memory.c \
	gcr-memory-icon.c gcr-memory-icon.h \
	gcr-openpgp.c gcr-openpgp.h \
	gcr-openssh.c gcr-openssh.h \
	gcr-parser.c gcr-parser.h \
	gcr-pkcs11-certificate.c gcr-pkcs11-certificate.h \
	gcr-pkcs11-importer.c gcr-pkcs11-importer.h \
	gcr-record.c gcr-record.h \
	gcr-simple-certificate.c gcr-simple-certificate.h \
	gcr-simple-collection.c gcr-simple-collection.h \
	gcr-single-collection.c gcr-single-collection.h \
	gcr-trust.c gcr-trust.h \
	gcr-types.h \
	gcr-union-collection.c gcr-union-collection.h \
	gcr-util.c gcr-util.h \
	$(BUILT_BASE_FILES)

libgcr_@GCR_MAJOR@_la_SOURCES = \
	gcr-certificate-basics-widget.c gcr-certificate-basics-widget.h \
	gcr-certificate-details-widget.c gcr-certificate-details-widget.h \
	gcr-certificate-exporter.c gcr-certificate-exporter.h \
	gcr-certificate-extensions.c gcr-certificate-extensions.h \
	gcr-certificate-renderer.c gcr-certificate-renderer.h \
	gcr-certificate-widget.c gcr-certificate-widget.h \
	gcr-collection-model.c gcr-collection-model.h \
	gcr-combo-selector.c gcr-combo-selector.h \
	gcr-debug.c gcr-debug.h \
	gcr-display-scrolled.c gcr-display-scrolled.h \
	gcr-display-view.c gcr-display-view.h \
	gcr-failure-renderer.c gcr-failure-renderer.h \
	gcr-fingerprint.c gcr-fingerprint.h \
	gcr-gnupg-renderer.c gcr-gnupg-renderer.h \
	gcr-gnupg-records.c gcr-gnupg-records.h \
	gcr-import-button.c gcr-import-button.h \
	gcr-import-dialog.c gcr-import-dialog.h \
	gcr-key-renderer.c gcr-key-renderer.h \
	gcr-key-widget.c gcr-key-widget.h \
	gcr-list-selector.c gcr-list-selector.h gcr-list-selector-private.h \
	gcr-live-search.c gcr-live-search.h \
	gcr-memory.c \
	gcr-memory-icon.c gcr-memory-icon.h \
	gcr-menu-button.c gcr-menu-button.h \
	gcr-record.c gcr-record.h \
	gcr-renderer.c gcr-renderer.h \
	gcr-tree-selector.c gcr-tree-selector.h \
	gcr-unlock-options.h \
	gcr-unlock-options-widget.c gcr-unlock-options-widget.h \
	gcr-unlock-renderer.c gcr-unlock-renderer.h \
	gcr-viewer.c gcr-viewer.h \
	gcr-viewer-widget.c gcr-viewer-widget.h \
	gcr-viewer-window.c gcr-viewer-window.h \
	$(BUILT_UI_FILES)

libgcr_base_@GCR_MAJOR@_la_CFLAGS = \
	-DGCK_API_SUBJECT_TO_CHANGE \
	-DGCR_API_SUBJECT_TO_CHANGE \
	-DP11_KIT_API_SUBJECT_TO_CHANGE \
	-DGCR_COMPILATION

libgcr_@GCR_MAJOR@_la_CFLAGS = \
	$(GTK_CFLAGS) \
	-DUIDIR=\""$(uidir)"\" \
	$(libgcr_base_@GCR_MAJOR@_la_CFLAGS)

libgcr_base_@GCR_MAJOR@_la_LDFLAGS = \
	-version-info $(GCR_LT_RELEASE) \
	-no-undefined \
	-export-symbols-regex '^gcr_*'

libgcr_@GCR_MAJOR@_la_LDFLAGS = \
	$(libgcr_base_@GCR_MAJOR@_la_LDFLAGS)

libgcr_base_@GCR_MAJOR@_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/egg/libegg-entry-buffer.la \
	$(top_builddir)/gck/libgck-@GCK_MAJOR@.la \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(P11_KIT_LIBS)

libgcr_@GCR_MAJOR@_la_LIBADD = \
	$(GTK_LIBS) \
	$(libgcr_base_@GCR_MAJOR@_la_LIBADD) \
	$(builddir)/libgcr-base-$(GCR_MAJOR).la

noinst_LTLIBRARIES = libgcr-testable.la
libgcr_testable_la_SOURCES =
libgcr_testable_la_LIBADD = \
	$(libgcr_base_@GCR_MAJOR@_la_OBJECTS) \
	$(libgcr_@GCR_MAJOR@_la_OBJECTS) \
	$(libgcr_@GCR_MAJOR@_la_LIBADD)
libgcr_testable_la_DEPENDENCIES = \
	$(libgcr_base_@GCR_MAJOR@_la_OBJECTS) \
	$(libgcr_@GCR_MAJOR@_la_OBJECTS)

gcr-marshal.h: gcr-marshal.list $(GLIB_GENMARSHAL)
	$(AM_V_GEN) $(GLIB_GENMARSHAL) $< --header --prefix=_gcr_marshal > $@

gcr-marshal.c: gcr-marshal.list $(GLIB_GENMARSHAL)
	$(AM_V_GEN) ( echo "#include \"gcr-marshal.h\"" > $@ && \
		$(GLIB_GENMARSHAL) $< --body --prefix=_gcr_marshal >> $@ )

gcr-enum-types.h: $(HEADER_UI_FILES) gcr-enum-types.h.template
	$(AM_V_GEN) $(GLIB_MKENUMS) --template $(srcdir)/gcr-enum-types.h.template \
		$(HEADER_UI_FILES) > $@

gcr-enum-types.c: $(HEADER_UI_FILES) gcr-enum-types.c.template
	$(AM_V_GEN) $(GLIB_MKENUMS) --template $(srcdir)/gcr-enum-types.c.template \
		$(HEADER_UI_FILES) > $@

gcr-enum-types-base.h: $(HEADER_BASE_FILES) gcr-enum-types.h.template
	$(AM_V_GEN) $(GLIB_MKENUMS) --template $(srcdir)/gcr-enum-types.h.template \
		$(HEADER_BASE_FILES) > $@

gcr-enum-types-base.c: $(HEADER_BASE_FILES) gcr-enum-types.c.template
	$(AM_V_GEN) $(GLIB_MKENUMS) --template $(srcdir)/gcr-enum-types.c.template \
		$(HEADER_BASE_FILES) > $@

gcr-oids.c: gcr-oids.list gcr-mkoids
	$(AM_V_GEN) sh gcr-mkoids -p GCR -c gcr-oids.c -h gcr-oids.h gcr-oids.list

gcr-oids.h: gcr-oids.c

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gcr-$(GCR_MAJOR).pc gcr-base-$(GCR_MAJOR).pc

gcr-$(GCR_MAJOR).pc: gcr.pc
	cp gcr.pc gcr-$(GCR_MAJOR).pc
gcr-base-$(GCR_MAJOR).pc: gcr-base.pc
	cp gcr-base.pc gcr-base-$(GCR_MAJOR).pc

# ----------------------------------------------------------------
# SYSTEM INTEGRATION

# The new mime system
mimedir = $(datadir)/mime/packages
mime_DATA = gcr-crypto-types.xml

if WITH_UPDATE_MIME
update_mime_database_cmd = update-mime-database $(datadir)/mime/

install-data-hook: update_mime_database
uninstall-hook: update_mime_database

update_mime_database:
	@-if test -z "$(DESTDIR)"; then \
		echo "Updating MIME database."; \
		$(update_mime_database_cmd); \
	else \
		echo "*** MIME database not updated.  After (un)install, run this:"; \
		echo "***   $(update_mime_database_cmd)"; \
	fi
endif

desktopdir = $(datadir)/applications
desktop_in_in_files = gcr-viewer.desktop.in.in
desktop_in_files = $(desktop_in_in_files:.desktop.in.in=.desktop.in)
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
@INTLTOOL_DESKTOP_RULE@

# ----------------------------------------------------------------
# TOOLS

bin_PROGRAMS = gcr-viewer

gcr_viewer_SOURCES = \
	gcr-viewer-tool.c

gcr_viewer_CFLAGS = \
	$(GTK_CFLAGS) \
	-DLOCALEDIR=\""$(datadir)/locale"\" \
	-DGCR_API_SUBJECT_TO_CHANGE

gcr_viewer_LDADD = \
	$(builddir)/libgcr-$(GCR_MAJOR).la \
	$(top_builddir)/gck/libgck-@GCK_MAJOR@.la \
	$(GTK_LIBS)

# ----------------------------------------------------------------

gcr-expected-base.abi: gcr-base.symbols
	$(AM_V_GEN) cpp -P $< | sort > $@
gcr-expected.abi: gcr.symbols
	$(AM_V_GEN) cpp -P $< | sort > $@

gcr-actual-base.abi: $(builddir)/.libs/libgcr-base-@GCR_MAJOR@.so
	$(AM_V_GEN)  $(NM) -D -g --defined-only $< | \
		cut -d ' ' -f 3 | grep -Ev '^(__bss_start|_edata|_end)' | sort > $@
gcr-actual.abi: $(builddir)/.libs/libgcr-@GCR_MAJOR@.so
	$(AM_V_GEN)  $(NM) -D -g --defined-only $< | \
		cut -d ' ' -f 3 | grep -Ev '^(__bss_start|_edata|_end)' | sort > $@

check-symbols: gcr-expected.abi gcr-actual.abi gcr-expected-base.abi gcr-actual-base.abi
	$(AM_V_GEN) diff -U0 --ignore-blank-lines gcr-expected-base.abi gcr-actual-base.abi || \
		(echo "check-symbols: Symbols have CHANGED. Fix gcr-base.symbols"; exit 1)
	$(AM_V_GEN) diff -U0 --ignore-blank-lines gcr-expected.abi gcr-actual.abi || \
		(echo "check-symbols: Symbols have CHANGED. Fix gcr.symbols"; exit 1)

check-local: check-symbols

EXTRA_DIST = \
	gcr.pc.in \
	gcr-base.pc.in \
	gcr-marshal.list \
	gcr-oids.list \
	gcr-mkoids \
	$(ui_DATA) \
	$(conf_DATA) \
	gcr-enum-types.h.template \
	gcr-enum-types.c.template \
	gcr.symbols \
	gcr-base.symbols \
	$(desktop_in_in_files) \
	$(desktop_in_files) \
	$(desktop_DATA) \
	$(mime_DATA)

CLEANFILES = \
	$(BUILT_SOURCES) \
	$(pkgconfig_DATA) \
	gcr-actual.abi \
	gcr-actual-base.abi \
	gcr-expected.abi \
	gcr-expected-base.abi

DISTCLEANFILES = \
	$(desktop_in_files) \
	$(desktop_DATA) \
	$(pkgconfig_DATA)
