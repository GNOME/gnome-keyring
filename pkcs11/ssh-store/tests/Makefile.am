include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	-I$(top_srcdir)/pkcs11 \
	-DSRCDIR="\"@abs_srcdir@\"" \
	$(GLIB_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

LDADD = \
	libgkm-mock-ssh-module.a \
	$(top_builddir)/pkcs11/ssh-store/libgkm-ssh-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

if WITH_P11_TESTS
CHECK_PROGS = check-ssh-module
else
CHECK_PROGS =
endif

CHECK_FILES = \
	p11-tests.conf

TEST_PROGS = \
	test-ssh-openssh \
	test-private-key

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS) $(CHECK_PROGS) $(CHECK_FILES)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)
	@for prog in $(CHECK_PROGS); do SRCDIR='.' ./$$prog || exit 1; done

check-local: test

all-local: $(check_PROGRAMS)

noinst_PROGRAMS = \
	$(CHECK_PROGS)

check_ssh_module_CFLAGS = $(P11_TESTS_CFLAGS)
check_ssh_module_LDADD = $(P11_TESTS_LIBS) $(LDADD)

noinst_LIBRARIES = libgkm-mock-ssh-module.a

libgkm_mock_ssh_module_a_SOURCES = \
	mock-ssh-module.c mock-ssh-module.h

EXTRA_DIST = \
	p11-tests.conf.in \
	files

CLEANFILES = \
	$(CHECK_FILES)
