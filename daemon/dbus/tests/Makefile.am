
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/daemon/dbus \
	-DSRCDIR="\"@abs_srcdir@\"" \
	-DTOP_SRCDIR="\"@abs_top_srcdir@\"" \
	-DTOP_BUILDDIR="\"@abs_top_builddir@\"" \
	-DGCR_API_SUBJECT_TO_CHANGE \
	$(DAEMON_CFLAGS) \
	$(GCR_BASE_CFLAGS) \
	$(GIO_CFLAGS) \
	$(GLIB_CFLAGS)

noinst_LTLIBRARIES = \
	libtestservice.la

libtestservice_la_SOURCES = \
	test-service.c test-service.h

LDADD =  \
	$(builddir)/libtestservice.la \
	$(top_builddir)/daemon/dbus/libgkd-dbus.la \
	$(top_builddir)/egg/libegg-test.la \
	$(GCR_BASE_LIBS) \
	$(GIO_LIBS) \
	$(GLIB_LIBS)

TEST_PROGS = \
	test-secret-util \
	test-secret-search \
	test-secret-items \
	test-secret-signals \
	test-secret-lock

check_PROGRAMS = $(TEST_PROGS)

EXTRA_DIST = files

test: $(TEST_PROGS)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)

check-local: test

all-local: $(check_PROGRAMS)
