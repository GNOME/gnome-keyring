AC_INIT(gnome-keyring,
        3.14.0,
        [gnome-keyring-list@gnome.org],
        [gnome-keyring],
        [https://wiki.gnome.org/Projects/GnomeKeyring])

dnl ****************************************************************************
dnl Dependency versions

GLIB_REQ=2.38.0
GLIB_MIN=GLIB_VERSION_2_38
GLIB_MAX=GLIB_VERSION_2_38

GCK_REQ=3.3.4
GCR_REQ=3.5.3

DBUS_REQ=1.1.1

GCRYPT_REQ=1.2.2
GCRYPT_LIBVER=1

dnl ****************************************************************************

GKR_MAJOR=3

version_bits=`echo $VERSION | tr '.' ' '`
full_version=`printf %03d%03d%03d $version_bits`
AC_DEFINE_UNQUOTED(GKR_VERSION, $full_version, [The gnome-keyring version as a number])

AC_CONFIG_MACRO_DIR([build/m4])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_SRCDIR([daemon/gkd-main.c])
AM_INIT_AUTOMAKE([1.12 foreign dist-bzip2 no-dist-gzip parallel-tests subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_SANITY_CHECK
AM_MAINTAINER_MODE([enable])

AC_GNU_SOURCE
AC_ISC_POSIX
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_DISABLE_STATIC
AM_PROG_LIBTOOL
IT_PROG_INTLTOOL([0.35.0])
AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

AC_TYPE_PID_T
AC_TYPE_SIGNAL
AC_TYPE_SIZE_T
AC_TYPE_UID_T

DISTCHECK_CONFIGURE_FLAGS="--enable-doc"
AC_SUBST(DISTCHECK_CONFIGURE_FLAGS)

PKG_CHECK_MODULES(GLIB, glib-2.0 >= $GLIB_REQ)
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=$GLIB_MIN"
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MAX_ALLOWED=$GLIB_MAX"
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(GMODULE, gmodule-no-export-2.0)
AC_SUBST(GMODULE_CFLAGS)
AC_SUBST(GMODULE_LIBS)

PKG_CHECK_MODULES(GOBJECT, glib-2.0 gobject-2.0)
AC_SUBST(GOBJECT_CFLAGS)
AC_SUBST(GOBJECT_LIBS)

PKG_CHECK_MODULES(GIO, glib-2.0 gio-2.0)
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)

DAEMON_CFLAGS="$DAEMON_CFLAGS $GLIB_CFLAGS $GTHREAD_CFLAGS $GOBJECT_CFLAGS $GIO_CFLAGS"
DAEMON_LIBS="$DAEMON_LIBS $GLIB_LIBS $GTHREAD_LIBS $GOBJECT_LIBS $GIO_LIBS"

GETTEXT_PACKAGE=gnome-keyring
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [The gettext domain name])
AC_SUBST(GETTEXT_PACKAGE)

AM_GLIB_GNU_GETTEXT

AC_PATH_PROG(GLIB_GENMARSHAL, glib-genmarshal)

GLIB_GSETTINGS

# --------------------------------------------------------------------
# Check for socklen_t
#

AC_MSG_CHECKING(whether socklen_t is defined)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
],[
socklen_t foo;
foo = 1;
foo = foo;
],have_socklen_t=yes,have_socklen_t=no)
AC_MSG_RESULT($have_socklen_t)

if test "x$have_socklen_t" = "xyes"; then
    AC_DEFINE(HAVE_SOCKLEN_T,1,[Have socklen_t type])
fi

# --------------------------------------------------------------------
# Check for various credentials.
#

AC_MSG_CHECKING(for struct cmsgcred)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
],[
struct cmsgcred cred;

cred.cmcred_pid = 0;
],have_struct_cmsgcred=yes,have_struct_cmsgcred=no)
AC_MSG_RESULT($have_struct_cmsgcred)

if test x$have_struct_cmsgcred = xyes; then
    AC_DEFINE(HAVE_CMSGCRED,1,[Have cmsgcred structure])
fi

# --------------------------------------------------------------------
# Check for getpeerucred
#

AC_CHECK_FUNCS(getpeerucred, AC_DEFINE(HAVE_GETPEERUCRED,1,[Have getpeerucred]))

# --------------------------------------------------------------------
# Check for getpeereid
#

AC_CHECK_FUNCS(getpeereid, AC_DEFINE(HAVE_GETPEEREID, 1, [Have getpeereid function]))

# --------------------------------------------------------------------
# Check for flock
#

AC_CHECK_FUNCS(flock, AC_DEFINE(HAVE_FLOCK,1,[Have flock]))

# --------------------------------------------------------------------
# Check for timegm
#

AC_CHECK_FUNCS(timegm, AC_DEFINE(HAVE_TIMEGM,1,[Have timegm]))

AC_STAT_MACROS_BROKEN
  AC_CACHE_CHECK([for inttypes.h], jm_ac_cv_header_inttypes_h,
  [AC_TRY_COMPILE(
    [#include <sys/types.h>
#include <inttypes.h>],
    [uintmax_t i = (uintmax_t) -1;],
    jm_ac_cv_header_inttypes_h=yes,
    jm_ac_cv_header_inttypes_h=no)])
  if test $jm_ac_cv_header_inttypes_h = yes; then
    AC_DEFINE_UNQUOTED(HAVE_INTTYPES_H_WITH_UINTMAX, 1,
[Define if <inttypes.h> exists, doesn't clash with <sys/types.h>,
   and declares uintmax_t. ])
  fi
  AC_CACHE_CHECK([for stdint.h], jm_ac_cv_header_stdint_h,
  [AC_TRY_COMPILE(
    [#include <sys/types.h>
#include <stdint.h>],
    [uintmax_t i = (uintmax_t) -1;],
    jm_ac_cv_header_stdint_h=yes,
    jm_ac_cv_header_stdint_h=no)])
  if test $jm_ac_cv_header_stdint_h = yes; then
    AC_DEFINE_UNQUOTED(HAVE_STDINT_H_WITH_UINTMAX, 1,
[Define if <stdint.h> exists, doesn't clash with <sys/types.h>,
   and declares uintmax_t. ])
  fi
AC_CHECK_HEADERS(fcntl.h sys/time.h time.h unistd.h)
AC_CHECK_FUNCS(gettimeofday fsync)

# --------------------------------------------------------------------
# Memory locking
#

AC_CHECK_FUNCS(mlock)

# --------------------------------------------------------------------
# socket()
#

AC_CHECK_LIB(socket, socket)

have_socket=no
AC_CHECK_FUNCS(socket, have_socket=yes)
if test $have_socket = no; then
  # socket is not in the default libraries.  See if it's in some other.
  for lib in bsd socket inet; do
    AC_CHECK_LIB($lib, socket, [
	  DAEMON_LIBS="$DAEMON_LIBS -l$lib"
	  have_socket=yes
	  AC_DEFINE(HAVE_SOCKET)
	  break])
  done
fi

# --------------------------------------------------------------------
# GCR and GCK libraries

PKG_CHECK_MODULES(GCK, gck-1 >= $GCK_REQ)
PKG_CHECK_MODULES(GCR, gcr-3 >= $GCR_REQ)
PKG_CHECK_MODULES(GCR_BASE, gcr-base-3 >= $GCR_REQ)

DAEMON_CFLAGS="$DAEMON_CFLAGS $GCK_CFLAGS $GCR_BASE_CFLAGS"
DAEMON_LIBS="$DAEMON_LIBS $GCK_LIBS $GCR_BASE_LIBS"

AC_SUBST(GCK_CFLAGS)
AC_SUBST(GCR_CFLAGS)
AC_SUBST(GCR_BASE_CFLAGS)
AC_SUBST(GCK_LIBS)
AC_SUBST(GCR_LIBS)
AC_SUBST(GCR_BASE_LIBS)

AC_DEFINE(GCK_API_SUBJECT_TO_CHANGE, 1, [Nod nod])
AC_DEFINE(GCR_API_SUBJECT_TO_CHANGE, 1, [Nod nod])

# --------------------------------------------------------------------
# DBus Checks
#

PKG_CHECK_MODULES([DBUS], dbus-1 >= $DBUS_REQ)

DAEMON_CFLAGS="$DAEMON_CFLAGS $DBUS_CFLAGS"
DAEMON_LIBS="$DAEMON_LIBS $DBUS_LIBS"

AC_ARG_WITH(dbus-services,
		  [AC_HELP_STRING([--with-dbus-services=<dir>],
		  [where D-BUS session services directory is])])
if ! test -z "$with_dbus_services" ; then
	DBUS_SERVICES_DIR="$with_dbus_services"
else
	DBUS_SERVICES_DIR="$datadir/dbus-1/services"
fi

AC_SUBST(DBUS_SERVICES_DIR)

# --------------------------------------------------------------------
# PAM Checks

AC_ARG_ENABLE(pam,
	    AC_HELP_STRING([--disable-pam],
	    [Build GNOME keyring PAM helper]))

pam_status="no"
if test "$enable_pam" != "no"; then
	AC_CHECK_HEADERS(security/pam_modules.h pam/pam_modules.h, [have_pam=yes; break], have_pam=no)
	if test "$enable_pam" = "yes" -a "$have_pam" = "no"; then
		AC_MSG_ERROR(The PAM headers are missing)
	elif test "$have_pam" = "yes"; then
		old_LIBS=$LIBS
		AC_CHECK_LIB(pam, pam_start, have_pam=yes, have_pam=no)
		if test "$enable_pam" = "yes" -a "$have_pam" = "no"; then
			AC_MSG_ERROR(The PAM library is missing)
		fi
		LIBS=$old_LIBS
	fi
fi

# --------------------------------------------------------------------
# Find DL functionality

AC_CHECK_LIB(c, dlopen, DL_LIBS="",
	AC_CHECK_LIB(dl, dlopen, DL_LIBS="-ldl",
		AC_MSG_ERROR([Could not find a library with the dlopen function])
	)
)

AC_SUBST(DL_LIBS)

# --------------------------------------------------------------------
# p11-kit

AC_MSG_CHECKING([where to put pkcs11 module configuration])
AC_ARG_WITH(pkcs11-config, [
            AC_HELP_STRING([--with-pkcs11-config=<dir>],
                           [directory to install PKCS#11 config])
            ])
if test -z "$with_pkcs11_config" ; then
	P11_SYSTEM_CONFIG_MODULES=$($PKG_CONFIG p11-kit-1 --variable=p11_system_config_modules)
else
	P11_SYSTEM_CONFIG_MODULES="$with_pkcs11_config"
fi
if test "$P11_SYSTEM_CONFIG_MODULES" = ""; then
	AC_MSG_ERROR([Could not find location for pkcs11 module config])
fi
AC_MSG_RESULT($P11_SYSTEM_CONFIG_MODULES)
AC_SUBST(P11_SYSTEM_CONFIG_MODULES)

AC_MSG_CHECKING([module path to install pkcs11 modules])
AC_ARG_WITH(pkcs11-modules, [
            AC_HELP_STRING([--with-pkcs11-modules=<dir>],
                           [directory to install PKCS#11 modules])
            ])
if test -z "$with_pkcs11_modules" ; then
	P11_MODULE_PATH=$($PKG_CONFIG p11-kit-1 --variable=p11_module_path)
else
	P11_MODULE_PATH="$with_pkcs11_modules"
fi
if test "$P11_MODULE_PATH" = ""; then
	AC_MSG_ERROR([Could not find directory to install pkcs11 modules])
fi
AC_MSG_RESULT($P11_MODULE_PATH)
AC_SUBST(P11_MODULE_PATH)

pkcs11standalonedir="${libdir}/gnome-keyring/devel"
AC_SUBST(pkcs11standalonedir)

# --------------------------------------------------------------------
# PAM Module Directory

AC_ARG_WITH([pam-dir],
            [AC_HELP_STRING([--with-pam-dir=DIR],
                             [directory to install pam modules in])],
             [], [with_pam_dir='${libdir}/security'])
PAM_DEST_DIR="$with_pam_dir"
AC_SUBST(PAM_DEST_DIR)

AM_CONDITIONAL(WITH_PAM, test "$have_pam" = "yes")

if test "$have_pam" = "yes"; then
	pam_status="yes ($with_pam_dir)"
fi

# --------------------------------------------------------------------
# SSH Agent support
#

AC_ARG_ENABLE([ssh-agent],
		AC_HELP_STRING([--disable-ssh-agent],
		[Don't include SSH agent in gnome-keyring]))

if test "$enable_ssh_agent" != "no"; then
	AC_DEFINE(WITH_SSH, 1, [Whether to build SSH agent or not])
	ssh_status="yes"
else
	ssh_status="no"
fi

AM_CONDITIONAL(WITH_SSH, test "$enable_ssh_agent" != "no")

# --------------------------------------------------------------------
# GPG Agent support
#

AC_ARG_ENABLE([gpg-agent],
		AC_HELP_STRING([--disable-gpg-agent],
		[Don't include GPG agent in gnome-keyring]))

if test "$enable_gpg_agent" != "no"; then
	AC_DEFINE(WITH_GPG, 1, [Whether to build GPG agent or not])
	gpg_status="yes"
else
	gpg_status="no"
fi

AM_CONDITIONAL(WITH_GPG, test "$enable_gpg_agent" != "no")

# --------------------------------------------------------------------
# libgcrypt
#

AM_PATH_LIBGCRYPT($GCRYPT_LIBVER:$GCRYPT_REQ,,
	AC_MSG_ERROR([[
***
*** libgcrypt was not found. You may want to get it from
*** ftp://ftp.gnupg.org/gcrypt/libgcrypt/
***
]]))
libgcrypt=yes
AC_DEFINE_UNQUOTED(LIBGCRYPT_VERSION, "$GCRYPT_REQ", [Version of GCRYPT we expect])

DAEMON_CFLAGS="$DAEMON_CFLAGS $LIBGCRYPT_CFLAGS"
DAEMON_LIBS="$DAEMON_LIBS $LIBGCRYPT_LIBS"

AC_SUBST([LIBGCRYPT_CFLAGS])
AC_SUBST([LIBGCRYPT_LIBS])

# -------------------------------------------------------------------
# libcap-ng
#

AC_ARG_WITH([libcap-ng],
            [AC_HELP_STRING([--without-libcap-ng],
                            [build without libcap-ng (disables Linux capabilities support)])],,
            [with_libcap_ng=auto])

if test x"$with_libcap_ng" != x"no" ; then
    AC_CHECK_LIB([cap-ng], [capng_clear],
                 [
                   with_libcap_ng="yes"
                   AC_DEFINE([HAVE_LIBCAPNG], [1], [have libcap-ng headers and library])
                   DAEMON_LIBS="$DAEMON_LIBS -lcap-ng"
                 ],
                 [
                   if test x"$with_libcap_ng" = x"yes" ; then
                     AC_MSG_ERROR([libcap-ng support requested, but package not found])
                   else
                     AC_MSG_WARN([libcap-ng headers not installed])
                   fi
                   with_libcap_ng="no"
                 ])
fi

AM_CONDITIONAL([WITH_CAPS], [test x"$with_libcap_ng" = x"yes"])
libcapng_status="$with_libcap_ng"

# ----------------------------------------------------------------------
# selinux

LIBSELINUX=""
selinux_status="no"
AC_ARG_ENABLE([selinux],
        AC_HELP_STRING([--disable-selinux],[do not use SELinux]))
if test "x$enable_selinux" != "xno"; then
    AC_CHECK_LIB([selinux],[getfilecon],
        [AC_CHECK_LIB([selinux],[setexeccon],
            [AC_DEFINE([WITH_SELINUX], 1, [Defined if SE Linux support is compiled in])
             LIBSELINUX="-lselinux"
             selinux_status="yes"])
        ])
fi
AC_SUBST(LIBSELINUX)
AM_CONDITIONAL([HAVE_LIBSELINUX], [test ! -z "$LIBSELINUX"])

# ----------------------------------------------------------------------
# dotlock.c support

AC_DEFINE(DOTLOCK_USE_PTHREAD,1,[Define if POSIX threads are in use.])
AC_DEFINE(DOTLOCK_GLIB_LOGGING,1,[Define this to use Glib logging functions.])
AC_DEFINE_UNQUOTED(DOTLOCK_EXT_SYM_PREFIX,[_gkm_],
                  [Prefix used for external functions of dotlock.])

# ----------------------------------------------------------------------
# p11-tests

AC_ARG_ENABLE(p11_tests,
	AC_HELP_STRING([--disable-p11-tests],
	[Build in p11-tests for testing PKCS#11 modules]))

p11_tests_status="no"

if test "$enable_p11_tests" != "no"; then
	PKG_CHECK_MODULES(P11_TESTS, p11-tests >= 0.1,
	                  p11_tests_status=yes, p11_tests_status=no)
fi

AM_CONDITIONAL(WITH_P11_TESTS, test "$p11_tests_status" = "yes")

if test "$p11_tests_status" = "yes"; then
	AC_DEFINE_UNQUOTED(WITH_P11_TESTS, 1, [Run p11-tests module testing])
fi

# --------------------------------------------------------------------
# Documentation options

AC_MSG_CHECKING([whether to build documentation])
AC_ARG_ENABLE(doc,
              AC_HELP_STRING([--enable-doc],
                             [Disable building documentation])
             )

if test "$enable_doc" = "no"; then
	AC_MSG_RESULT($enable_doc)

else
	if test "$enable_doc" = ""; then
		disable_msg="(perhaps --disable-doc)"
	fi

	enable_doc="yes"
	AC_MSG_RESULT($enable_doc)

	AC_PATH_PROG([XSLTPROC], [xsltproc], [no])
	if test "$XSLTPROC" = "no"; then
		AC_MSG_ERROR([the xsltproc command was not found $disable_msg])
	fi

	AC_SUBST(XSLTPROC)
fi

AM_CONDITIONAL([ENABLE_DOC], [test "$enable_doc" = "yes"])
doc_status=$enable_doc

# --------------------------------------------------------------------
# Compilation and linking options
#

AC_MSG_CHECKING([for debug mode])
AC_ARG_ENABLE(debug,
              AC_HELP_STRING([--enable-debug=no/default/yes],
              [Turn on or off debugging]))

if test "$enable_debug" != "no"; then
	AC_DEFINE_UNQUOTED(WITH_DEBUG, 1, [Print debug output])
	AC_DEFINE_UNQUOTED(_DEBUG, 1, [In debug mode])
	CFLAGS="$CFLAGS -g"
fi

if test "$enable_debug" = "yes"; then
	debug_status="yes (-g, -O0, debug output, testable)"
	CFLAGS="$CFLAGS -O0"
elif test "$enable_debug" = "no"; then
	debug_status="no (no debug output, not testable, G_DISABLE_ASSERT)"
	AC_DEFINE_UNQUOTED(G_DISABLE_ASSERT, 1, [Disable glib assertions])
else
	debug_status="default (-g, debug output, testable)"
fi

AC_MSG_RESULT($debug_status)

AC_MSG_CHECKING(for more warnings)
if test "$GCC" = "yes"; then
	AC_MSG_RESULT(yes)
	CFLAGS="\
	-Wall \
	-Wchar-subscripts -Wmissing-declarations -Wmissing-prototypes \
	-Wnested-externs -Wpointer-arith \
	-Wcast-align -Wsign-compare \
	$CFLAGS"

	for option in -Wno-strict-aliasing -Wno-sign-compare; do
		SAVE_CFLAGS="$CFLAGS"
		CFLAGS="$CFLAGS $option"
		AC_MSG_CHECKING([whether gcc understands $option])
		AC_TRY_COMPILE([], [],
			has_option=yes,
			has_option=no,)
		if test $has_option = no; then
			CFLAGS="$SAVE_CFLAGS"
		fi
		AC_MSG_RESULT($has_option)
		unset has_option
		unset SAVE_CFLAGS
	done
	unset option
else
	AC_MSG_RESULT(no)
fi

AC_ARG_ENABLE(strict, [
               AS_HELP_STRING([--enable-strict], [Strict code compilation])
             ])

AC_MSG_CHECKING([build strict])

if test "$enable_strict" = "yes"; then
	CFLAGS="$CFLAGS -Werror \
		-DGDK_DISABLE_DEPRECATED \
		-DG_DISABLE_DEPRECATED \
		-DGDK_PIXBUF_DISABLE_DEPRECATED"
	TEST_MODE="thorough"
	INTROSPECTION_FLAGS="--warn-error"
	AC_DEFINE_UNQUOTED(WITH_STRICT, 1, [More strict checks])
	strict_status="yes (-Werror, thorough tests, fatals, no deprecations)"
else
	TEST_MODE="quick"
	INTROSPECTION_FLAGS=""
	strict_status="no (quick tests, non-fatal warnings)"
fi

AC_MSG_RESULT($strict_status)
AC_SUBST(INTROSPECTION_FLAGS)
AC_SUBST(TEST_MODE)

AC_MSG_CHECKING([whether to build with gcov testing])
AC_ARG_ENABLE([coverage],
		AS_HELP_STRING([--enable-coverage],
			[Whether to enable coverage testing ]),
		[],
		[enable_coverage=no])

AC_MSG_RESULT([$enable_coverage])

if test "$enable_coverage" = "yes"; then
	if test "$GCC" != "yes"; then
		AC_MSG_ERROR(Coverage testing requires GCC)
	fi

	AC_PATH_PROG(GCOV, gcov, no)
	if test "$GCOV" = "no" ; then
		AC_MSG_ERROR(gcov tool is not available)
	fi

	AC_PATH_PROG(LCOV, lcov, no)
	if test "$LCOV" = "no" ; then
		AC_MSG_ERROR(lcov tool is not installed)
	fi

	AC_PATH_PROG(GENHTML, genhtml, no)
	if test "$GENHTML" = "no" ; then
		AC_MSG_ERROR(lcov's genhtml tool is not installed)
	fi

	CFLAGS="$CFLAGS -O0 -g -fprofile-arcs -ftest-coverage"
	LDFLAGS="$LDFLAGS -lgcov"
fi

AM_CONDITIONAL([WITH_COVERAGE], [test "$enable_coverage" = "yes"])
AC_SUBST(LCOV)
AC_SUBST(GCOV)
AC_SUBST(GENHTML)

AC_ARG_ENABLE(valgrind,
	AC_HELP_STRING([--enable-valgrind],
	[Run gnome-keyring-daemon using valgrind]))

AC_MSG_CHECKING([valgrind])
valgrind_status="yes"

AM_CONDITIONAL(WITH_VALGRIND, test "$enable_valgrind" = "run")

# Build valgrind support into code
if test "$enable_valgrind" = "yes"; then
	AC_CHECK_HEADER([valgrind/valgrind.h], have_valgrind=yes, have_valgrind=no)
	if test "$have_valgrind" = "no"; then
		AC_MSG_ERROR(The valgrind headers are missing)
	fi
	AC_DEFINE_UNQUOTED(WITH_VALGRIND, 1, [Run under valgrind])
	AC_MSG_RESULT(yes)


# No valgrind
else
	AC_MSG_RESULT(no)
	valgrind_status="no"
fi

# ----------------------------------------------------------------------

AC_SUBST(GKR_MAJOR)

AC_SUBST(DAEMON_CFLAGS)
AC_SUBST(DAEMON_LIBS)

AC_SUBST(P11_TESTS_CFLAGS)
AC_SUBST(P11_TESTS_LIBS)

AC_OUTPUT([
Makefile
pkcs11/rpc-layer/gnome-keyring.module
po/Makefile.in
])

# ------------------------------------------------------------------------------
# Summary
#

echo
echo "OPTIONAL DEPENDENCIES"
echo "  PAM:                  $pam_status"
echo "  Linux capabilities:   $libcapng_status"
echo "  SELinux:              $selinux_status"
echo
echo "CONFIGURATION"
echo "  SSH Agent:            $ssh_status"
echo "  GPG Agent:            $gpg_status"
echo
echo "BUILD"
echo "  Debug Build:          $debug_status"
echo "  Strict Compilation:   $strict_status"
echo "  Valgrind:             $valgrind_status"
echo "  PKCS#11 Tests         $p11_tests_status"
echo "  Test Coverage:        $enable_coverage"
echo "  Documentation:        $doc_status"
echo
