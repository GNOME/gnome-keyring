
# Keep these in the order they should be tested
TESTING_FILES = \
	test-gck-attributes.c \
	test-gck-mechanism.c \
	test-gck-module.c \
	test-gck-slot.c \
	test-gck-session.c \
	test-gck-object.c \
	test-gck-crypto.c \
	test-gck-uri.c \
	test-gck-enumerator.c \
	test-gck-modules.c

TESTING_FLAGS = \
	-I$(top_srcdir)/gck/ \
	-DEXTERNAL_TEST

TESTING_LIBS = \
	$(GIO_LIBS) \
	$(top_builddir)/gck/libgck.la \
	libgck-test-module.la

EXTRA_DIST = \
	gck-test.h

include $(top_srcdir)/testing/testing.make

# ------------------------------------------------------------------------

lib_LTLIBRARIES = libgck-test-module.la

libgck_test_module_la_LDFLAGS = \
	-avoid-version

libgck_test_module_la_CFLAGS = \
	-I$(top_srcdir)/gck \
	-I$(top_srcdir) \
	$(GLIB_CFLAGS)

libgck_test_module_la_SOURCES = \
	gck-test-module.c

libgck_test_module_la_LIBADD = \
	$(top_builddir)/gck/libgck.la
