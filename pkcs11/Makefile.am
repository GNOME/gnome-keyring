
# TODO: Are we sure this is the best location for these headers? 
incdir = $(includedir)/gp11

inc_HEADERS = \
	pkcs11g.h \
	pkcs11n.h 

EXTRA_DIST = \
	pkcs11.h

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . \
	gck \
	roots-store \
	rpc-layer \
	plex-layer \
	ssh-agent \
	ssh-store \
	$(ROOTS_DIR) \
	$(TESTS_DIR)
