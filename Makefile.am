if WITH_PAM
PAM_DIR = pam
else
PAM_DIR = 
endif

if WITH_SSH
SSH_DIR = ssh
else
SSH_DIR =
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
	ui \
	keyrings \
	pkix \
	pk \
	$(SSH_DIR) \
	pkcs11 \
	daemon \
	data \
	po \
	reference \
	$(TESTS_DIR) \
	$(PAM_DIR)

EXTRA_DIST = \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	keyring-intro.txt \
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
	$(MAKE) -C tests run-auto
	@echo
	@echo
	@echo "DONE AUTOMATIC UNIT TESTS ------------------------------"

install-pam:
	@echo "WARNING: install-pam is no longer used, use the --with-pam-dir configure option instead"
