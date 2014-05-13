NULL =

SUBDIRS = \
	. \
	po

ACLOCAL_AMFLAGS = -I build/m4 ${ACLOCAL_FLAGS}

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-doc \
	--enable-pam \
	--enable-ssh-agent \
	--enable-gpg-agent \
	--disable-strict \
	--disable-coverage \
	--disable-silent-rules \
	--with-pkcs11-modules=$(abs_srcdir)/$(top_distdir)/_inst/lib \
	--with-pkcs11-config=$(abs_srcdir)/$(top_distdir)/_inst/etc/pkcs11 \
	$(NULL)

DISTCLEANFILES = \
	intltool-extract \
	intltool-merge \
	intltool-update

CHANGELOG_START = \
	efb922c92fae5929ecc8c702770ebb6c390d38a4

dist-hook:
	@if test -d "$(srcdir)/.git"; \
	then \
		echo Creating ChangeLog && \
		( cd "$(top_srcdir)" && \
		  echo '# Generate automatically. Do not edit.'; echo; \
		  git log $(CHANGELOG_START).. --stat --date=short ) > ChangeLog.tmp \
		&& mv -f ChangeLog.tmp $(top_distdir)/ChangeLog \
		|| ( rm -f ChangeLog.tmp ; \
		     echo Failed to generate ChangeLog >&2 ); \
	else \
		echo A git clone is required to generate a ChangeLog >&2; \
	fi

install-pam:
	@echo "WARNING: install-pam is no longer used, use the --with-pam-dir configure option instead"

if ENABLE_DOC
# include docs/Makefile.am

distcheck-hook:
	@true

else
distcheck-hook:
	@echo "*** doc must be enabled  (with --enable-doc) in order to make distcheck"
	@false
endif

upload-release: $(DIST_ARCHIVES)
	scp $(DIST_ARCHIVES) master.gnome.org:
	ssh master.gnome.org ftpadmin install $(DIST_ARCHIVES)

asn1-reparse:
	for a in $(ASN1_FILES); do \
		asn1Parser -o $$a.h $a \
		sed -i 's|#include.*|/* \0 */|' $$a.h \
	done

# Default executable tests
LOG_DRIVER = $(srcdir)/build/tap-driver
LOG_DRIVER_FLAGS = --format=tap
LOG_COMPILER = $(srcdir)/build/tap-gtester

VALGRIND_ARGS = --trace-children=no --quiet --error-exitcode=33 \
	--suppressions=valgrind-suppressions --gen-suppressions=all \
	--num-callers=16
VALGRIND_SUPPRESSIONS = \
	build/gcr.supp \
	build/gcrypt.supp \
	build/glib.supp \
	build/glibc.supp \
	build/p11-kit.supp \
	build/pthread.supp \
	build/unknown.supp

valgrind-suppressions: $(VALGRIND_SUPPRESSIONS)
	$(AM_V_GEN) cat $^ > $@

check-memory: valgrind-suppressions
	$(MAKE) LOG_FLAGS="-- libtool --mode=execute valgrind $(VALGRIND_ARGS)" \
		$(AM_MAKEFLAGS) check
recheck-memory: valgrind-suppressions
	$(MAKE) LOG_FLAGS="-- libtool --mode=execute valgrind $(VALGRIND_ARGS)" \
		$(AM_MAKEFLAGS) recheck

coverage:
	mkdir -p $(top_builddir)/build/coverage
	$(LCOV) --directory . --capture --output-file $(top_builddir)/build/coverage.info
	$(GENHTML) --output-directory $(top_builddir)/build/coverage $(top_builddir)/build/coverage.info
	$(LCOV) --directory . --zerocounters
	@echo "file://$(abs_top_builddir)/build/coverage/index.html"

clear-coverage:
	$(LCOV) --directory . --zerocounters

# Set the relevant capabilities on the daemon
if WITH_CAPS
install-caps:
	setcap cap_ipc_lock=ep $(DESTDIR)$(bindir)/gnome-keyring-daemon || true
else
install-caps:
	@true
endif

# Install a link from gnome-keyring > gnome-keyring-@GKR_MAJOR@ to maintain compatibility
install-exec-hook: install-caps
	@test -e "$(DESTDIR)$(bindir)/gnome-keyring" || (cd $(DESTDIR)$(bindir) && $(LN_S) gnome-keyring-@GKR_MAJOR@ gnome-keyring)

V_SED = $(V_SED_$(V))
V_SED_ = $(V_SED_$(AM_DEFAULT_VERBOSITY))
V_SED_0 = @echo "  SED   " $@;

SED_SUBST = sed \
	-e 's,[@]datadir[@],$(datadir),g' \
	-e 's,[@]libexecdir[@],$(libexecdir),g' \
	-e 's,[@]libdir[@],$(libdir),g' \
	-e 's,[@]includedir[@],$(includedir),g' \
	-e 's,[@]datarootdir[@],$(datarootdir),g' \
	-e 's,[@]sysconfdir[@],$(sysconfdir),g' \
	-e 's,[@]bindir[@],$(bindir),g' \
	-e 's,[@]exec_prefix[@],$(exec_prefix),g' \
	-e 's,[@]prefix[@],$(prefix),g' \
	-e 's,[@]abs_srcdir[@],$(abs_srcdir),g' \
	-e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]builddir[@],$(builddir),g' \
	-e 's,[@]abs_builddir[@],$(abs_builddir),g' \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]VERSION[@],$(VERSION),g' \
	$(NULL)

SUFFIXES = .desktop.in .desktop.in.in .service .service.in

.service.in.service:
	$(V_SED) ( $(SED_SUBST) $< > $@.tmp ) && mv $@.tmp $@

.desktop.in.in.desktop.in:
	$(V_SED) ( $(SED_SUBST) $< > $@.tmp ) && mv $@.tmp $@

@INTLTOOL_DESKTOP_RULE@

prep-builddir:
	$(MKDIR_P) $(builddir)/daemon
	$(MKDIR_P) $(builddir)/schema

AM_CPPFLAGS = \
	-DPREFIX=\""$(prefix)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\" \
	-DSRCDIR="\"@abs_srcdir@\"" \
	-DBUILDDIR="\"@abs_builddir@\"" \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-I$(top_srcdir)/pkcs11 \
	$(GLIB_CFLAGS)

bin_PROGRAMS =
check_PROGRAMS =
noinst_DATA =
noinst_LIBRARIES =
noinst_LTLIBRARIES =
noinst_PROGRAMS = $(check_PROGRAMS)
TESTS =

ASN1_FILES =
BUILT_SOURCES = prep-builddir

moduledir = $(pkcs11standalonedir)
module_LTLIBRARIES =

CLEANFILES = \
	$(BUILT_SOURCES) \
	*.gcno \
	*.gcda

EXTRA_DIST = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	ChangeLog.old \
	HACKING \
	$(ASN1_FILES) \
	build/tap-driver \
	build/tap-gtester \
	$(VALGRIND_SUPPRESSIONS) \
	$(NULL)

include egg/Makefile.am
include daemon/Makefile.am
include daemon/control/Makefile.am
include daemon/dbus/Makefile.am
include daemon/gpg-agent/Makefile.am
include daemon/login/Makefile.am
include daemon/ssh-agent/Makefile.am
include pkcs11/Makefile.am
include pkcs11/gkm/Makefile.am
include pkcs11/gnome2-store/Makefile.am
include pkcs11/rpc-layer/Makefile.am
include pkcs11/secret-store/Makefile.am
include pkcs11/ssh-store/Makefile.am
include pkcs11/wrap-layer/Makefile.am
include pkcs11/xdg-store/Makefile.am
include schema/Makefile.am
include tool/Makefile.am

if ENABLE_DOC
include docs/Makefile.am
endif

if WITH_PAM
include pam/Makefile.am
endif
