if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = \
	. \
	library \
	keyrings \
	ui \
	daemon \
	doc \
	po \
	reference \
	$(TESTS_DIR)

EXTRA_DIST = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc

DISTCLEANFILES = \
	intltool-extract \
	intltool-merge \
	intltool-update
