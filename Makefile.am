if WITH_PAM
PAM_DIR = pam
else
PAM_DIR = 
endif

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = \
	. \
	common \
	library \
	keyrings \
	ui \
	daemon \
	doc \
	po \
	reference \
	$(TESTS_DIR) \
	$(PAM_DIR)

EXTRA_DIST = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	HACKING

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --enable-tests

DISTCLEANFILES = \
	intltool-extract \
	intltool-merge \
	intltool-update

# Clean up any EXTRA_DIST we're distributing
dist-hook:
	rm -rf `find $(distdir)/ -name .svn`

distcheck-hook: 
	@echo "RUNNING AUTOMATIC UNIT TESTS ---------------------------"
	@echo
	@echo
	$(MAKE) -C tests run-auto-tests
	@echo
	@echo
	@echo "DONE AUTOMATIC UNIT TESTS ------------------------------"

install-pam:
	$(MAKE) -C pam install-pam
	
uninstall-pam:
	$(MAKE) -C pam uninstall-pam

