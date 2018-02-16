
# ------------------------------------------------------------------
# DAEMON CODE

noinst_LTLIBRARIES += libgkd-login.la

libgkd_login_la_SOURCES = \
	daemon/login/gkd-login.c \
	daemon/login/gkd-login.h \
	daemon/login/gkd-login-interaction.c \
	daemon/login/gkd-login-interaction.h \
	daemon/login/gkd-login-password.c \
	daemon/login/gkd-login-password.h \
	$(NULL)
libgkd_login_la_CFLAGS = \
	$(GCK_CFLAGS) \
	$(GCR_CFLAGS) \
	$(GOBJECT_CFLAGS)
libgkd_login_la_LIBADD = \
	$(GCK_LIBS) \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS)
