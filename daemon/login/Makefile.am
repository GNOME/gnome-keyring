
# ------------------------------------------------------------------
# DAEMON CODE

noinst_LTLIBRARIES += libgkd-login.la

libgkd_login_la_SOURCES = \
	daemon/login/gkd-login.c \
	daemon/login/gkd-login.h \
	$(NULL)
libgkd_login_la_CFLAGS = \
	$(GCK_CFLAGS) \
	$(GOBJECT_CFLAGS)
libgkd_login_la_LIBADD = \
	$(GCK_LIBS) \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS)
