UNIT_AUTO = \
	unit-test-gp11-attributes.c \
	unit-test-gp11-module.c \
	unit-test-gp11-object.c \
	unit-test-gp11-session.c \
	unit-test-gp11-slot.c 


UNIT_FLAGS = \
	-I.. \
	-DEXTERNAL_TEST
	
UNIT_PROMPT = 

UNIT_LIBS = \
	$(GIO_LIBS) \
	$(top_builddir)/gp11/libgp11.la \
	libgp11-test-module.la 
	
include $(top_srcdir)/tests/check.make

# ------------------------------------------------------------------------

lib_LTLIBRARIES = libgp11-test-module.la

libgp11_test_module_la_LDFLAGS = \
	-avoid-version

libgp11_test_module_la_CFLAGS = \
	-I. -I../ \
	-I$(top_srcdir) \
	$(GLIB_CFLAGS)

libgp11_test_module_la_SOURCES = \
	gp11-test-module.c

libgp11_test_module_la_LIBADD = \
	$(top_builddir)/gp11/libgp11.la
	
