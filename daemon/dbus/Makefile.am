
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/daemon \
	-I$(top_srcdir)/daemon/dbus \
	-I$(top_builddir) \
	$(DAEMON_CFLAGS) \
	$(GCR_BASE_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DGCK_API_SUBJECT_TO_CHANGE \
	-DGCR_API_SUBJECT_TO_CHANGE \
	-DSRCDIR="\"@abs_srcdir@\"" \
	-DTOP_SRCDIR="\"@abs_top_srcdir@\"" \
	-DTOP_BUILDDIR="\"@abs_top_builddir@\""

noinst_LTLIBRARIES = libgkd-dbus.la

libgkd_dbus_la_SOURCES = \
	gkd-dbus.c gkd-dbus.h \
	gkd-dbus-environment.c \
	gkd-dbus-private.h \
	gkd-dbus-secrets.c \
	gkd-dbus-session.c \
	gkd-dbus-util.c gkd-dbus-util.h \
	gkd-secret-change.c gkd-secret-change.h \
	gkd-secret-create.c gkd-secret-create.h \
	gkd-secret-dispatch.c gkd-secret-dispatch.h \
	gkd-secret-error.c gkd-secret-error.h \
	gkd-secret-exchange.c gkd-secret-exchange.h \
	gkd-secret-introspect.c gkd-secret-introspect.h \
	gkd-secret-lock.c gkd-secret-lock.h \
	gkd-secret-objects.c gkd-secret-objects.h \
	gkd-secret-property.c gkd-secret-property.h \
	gkd-secret-prompt.c gkd-secret-prompt.h \
	gkd-secret-secret.c gkd-secret-secret.h \
	gkd-secret-service.c gkd-secret-service.h \
	gkd-secret-session.c gkd-secret-session.h \
	gkd-secret-types.h \
	gkd-secret-unlock.c gkd-secret-unlock.h \
	gkd-secret-util.c gkd-secret-util.h

libgkd_dbus_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

# -------------------------------------------------------------------
# TESTS

noinst_LTLIBRARIES += \
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

EXTRA_DIST = fixtures

test: $(TEST_PROGS)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)

check-local: test

all-local: $(check_PROGRAMS)
