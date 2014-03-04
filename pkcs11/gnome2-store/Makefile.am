include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_builddir)/pkcs11 \
	-I$(top_srcdir) \
	-I$(top_srcdir)/pkcs11 \
	-DSRCDIR="\"@abs_srcdir@\"" \
	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)


# ------------------------------------------------------------------------------
# The gnome2-store component code

noinst_LTLIBRARIES = \
	libgkm-gnome2-store.la

libgkm_gnome2_store_la_SOURCES = \
	gkm-gnome2-store.h \
	gkm-gnome2-file.c gkm-gnome2-file.h \
	gkm-gnome2-module.c gkm-gnome2-module.h \
	gkm-gnome2-private-key.c gkm-gnome2-private-key.h \
	gkm-gnome2-public-key.c gkm-gnome2-public-key.h \
	gkm-gnome2-storage.c gkm-gnome2-storage.h

# ------------------------------------------------------------------------------
# The standalone module

moduledir = $(pkcs11standalonedir)

module_LTLIBRARIES = \
	gkm-gnome2-store-standalone.la

gkm_gnome2_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

gkm_gnome2_store_standalone_la_SOURCES = \
	gkm-gnome2-standalone.c

gkm_gnome2_store_standalone_la_LIBADD = \
	libgkm-gnome2-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)


# -------------------------------------------------------------------------------

LDADD = \
	$(top_builddir)/pkcs11/gnome2-store/libgkm-gnome2-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

if WITH_P11_TESTS
CHECK_PROGS = check-gnome2-module
else
CHECK_PROGS =
endif

CHECK_FILES = \
	p11-tests.conf

TEST_PROGS = \
	test-gnome2-file \
	test-gnome2-storage \
	test-gnome2-private-key \
	test-import

test_gnome2_storage_SOURCES = \
	test-gnome2-storage.c \
	mock-gnome2-module.c mock-gnome2-module.h

test_gnome2_private_key_SOURCES = \
	test-gnome2-private-key.c \
	mock-gnome2-module.c mock-gnome2-module.h

test_import_CFLAGS = $(GCR_BASE_CFLAGS) $(GCK_CFLAGS)
test_import_LDADD = $(GCR_BASE_LIBS) $(GCK_LIBS) $(LDADD)

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS) $(CHECK_PROGS) $(CHECK_FILES)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)
	@for prog in $(CHECK_PROGS); do SRCDIR='.' ./$$prog || exit 1; done

check-local: test

all-local: $(check_PROGRAMS)

noinst_PROGRAMS = \
	frob-gnome2-file \
	$(CHECK_PROGS)

check_gnome2_module_CFLAGS = $(P11_TESTS_CFLAGS)
check_gnome2_module_LDADD = $(P11_TESTS_LIBS) $(LDADD)

EXTRA_DIST = \
	p11-tests.conf.in \
	fixtures

CLEANFILES = \
	$(CHECK_FILES)
