SUBDIRS = \
	po

libgnomekeyringincludedir = $(includedir)/gnome-keyring-1.0/

bin_PROGRAMS= \
	gnome-keyring-daemon \
	gnome-keyring-ask

noinst_PROGRAMS= \
	list-keyrings \
	test-keyring

lib_LTLIBRARIES=libgnome-keyring.la

noinst_LTLIBRARIES=libgnome-keyring-common.la

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-I$(top_srcdir) 				\
	-I$(top_builddir) 				\
	$(GTK_CFLAGS) 					\
	$(GLIB_CFLAGS)

libgnome_keyring_common_la_SOURCES = \
	gnome-keyring-private.h \
	gnome-keyring-proto.c \
	gnome-keyring-proto.h \
	gnome-keyring-utils.c

libgnome_keyring_common_la_LIBADD = \
	$(GLIB_LIBS)

libgnome_keyring_la_SOURCES = \
	gnome-keyring.c \
	gnome-keyring.h

libgnomekeyringinclude_HEADERS =		\
	gnome-keyring.h


libgnome_keyring_la_LIBADD = \
	libgnome-keyring-common.la \
	$(GLIB_LIBS)

gnome_keyring_daemon_SOURCES = \
	aes.c \
	aes.h \
	aes_be.h \
	aes_le.h \
	beecrypt_compat.h \
	md5.c \
	md5.h \
	gnome-keyring-daemon.c \
	gnome-keyring-daemon-file.c \
	gnome-keyring-daemon.h \
	gnome-keyring-daemon-io.c

gnome_keyring_daemon_LDADD = \
	libgnome-keyring-common.la \
	$(GLIB_LIBS)

gnome_keyring_ask_SOURCES = \
	gnome-keyring-ask.c

gnome_keyring_ask_LDADD = \
	$(GTK_LIBS)

list_keyrings_SOURCES = \
	list-keyrings.c

list_keyrings_LDADD = \
	libgnome-keyring.la

test_keyring_SOURCES = \
	test.c

test_keyring_LDADD = \
	libgnome-keyring.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gnome-keyring-1.0.pc

EXTRA_DIST = \
	file-format.txt
