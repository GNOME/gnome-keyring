
INCLUDES = \
	-I$(top_srcdir)/daemon/dbus \
	-DSRCDIR=$(srcdir) \
	$(DAEMON_CFLAGS) \
	$(GLIB_CFLAGS)

LDADD =  \
	$(top_builddir)/daemon/dbus/libgkd-dbus.la

TEST_PROGS = \
	test-secret-util

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS)
	SRCDIR='$(srcdir)' gtester -k --verbose ${TEST_PROGS}

check-local: test

if WITH_TESTS
all-local: $(check_PROGRAMS)
endif
