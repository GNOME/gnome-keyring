
UNIT_AUTO = \
	unit-test-pk-index.c \
	unit-test-pk-cert.c \
	unit-test-pk-import.c \
	unit-test-pk-key.c \
	unit-test-pk-netscape-trust.c \
	unit-test-pk-object.c

UNIT_PROMPT = 

UNIT_LIBS =  \
	$(top_builddir)/daemon/pk/libgkr-pk.la \
	$(top_builddir)/daemon/keyrings/libgkr-keyrings.la \
	$(top_builddir)/library/libgnome-keyring-common.la \
	$(top_builddir)/common/libgkr-common.la

EXTRA_DIST = \
	check-attribute.c \
	test-data

include $(top_srcdir)/tests/test.make
