SUBDIRS = \
	po

bin_PROGRAMS= \
	gnome-keyring-daemon \
	gnome-keyring-ask

noinst_PROGRAMS= \
	list-keyrings

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

libgnome_keyring_la_LIBADD = \
	libgnome-keyring-common.la \
	$(GLIB_LIBS)

gnome_keyring_daemon_SOURCES = \
	aes.c \
	aes.h \
	aes_be.h \
	aes_le.h \
	beecrypt_compat.h \
	sha1.c \
	sha1.h \
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

EXTRA_DIST = \
	file-format.txt
