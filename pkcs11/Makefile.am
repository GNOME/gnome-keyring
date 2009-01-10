
# TODO: Are we sure this is the best location for these headers? 
incdir = $(includedir)/gp11

inc_HEADERS = \
	pkcs11g.h \
	pkcs11n.h 

EXTRA_DIST = \
	pkcs11.h

if WITH_ROOT_CERTS
ROOTS_DIR = roots-store
else
ROOTS_DIR = 
endif

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . \
	gck \
	rpc-layer \
	plex-layer \
	ssh-agent \
	ssh-store \
	$(ROOTS_DIR) \
	$(TESTS_DIR)
