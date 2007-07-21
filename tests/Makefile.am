
EXTRA_DIST = \
	cu-test \
	test-helpers.c \
	unit-tests-prep.sh

INCLUDES=					\
	-I$(top_srcdir) 		\
	-I$(top_builddir) 		\
	$(GTK_CFLAGS) 			\
	$(GLIB_CFLAGS) 
	
LIBS = \
	$(GTK_LIBS) \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS)
	
if WITH_PAM
PAM_TEST = run-pam-test
else
PAM_TEST = 
endif
	
noinst_PROGRAMS= \
	list-keyrings \
	test-keyring \
	test-keyring-two \
	run-library-test \
	run-prompt-test \
	run-base-test \
	$(PAM_TEST)
	
# ------------------------------------------------------------------------------
# Simply list all the keyrings and whatever they have access to

list_keyrings_SOURCES = \
	list-keyrings.c

list_keyrings_LDADD = \
	$(top_builddir)/library/libgnome-keyring.la

# ------------------------------------------------------------------------------
# A generic testing program

test_keyring_SOURCES = \
	test-keyrings.c

test_keyring_LDADD = \
	$(top_builddir)/library/libgnome-keyring.la

test_keyring_two_SOURCES = \
	test-keyrings.c

test_keyring_two_LDADD = \
	$(top_builddir)/library/libgnome-keyring.la
	
# ------------------------------------------------------------------------------
# Base tests

UNIT_TESTS_BASE = \
	unit-test-secmem.c \
	unit-test-async.c \
	unit-test-cleanup.c \
	unit-test-signal.c \
	unit-test-mainloop-setup.c \
	unit-test-private.h

run-base-test.c: $(UNIT_TESTS_BASE) unit-tests-prep.sh Makefile.am
	sh unit-tests-prep.sh -b run-base-test $(UNIT_TESTS_BASE)

run_base_test_SOURCES = \
	run-base-test.c \
	run-base-test.h \
	$(UNIT_TESTS_BASE) 

run_base_test_LDADD = \
	$(top_builddir)/common/libgkr-daemon-common.la

# ------------------------------------------------------------------------------
# Automatic library tests 

UNIT_TESTS_LIBRARY = \
	unit-test-memory.c \
	unit-test-keyrings.c \
	unit-test-other.c \
	unit-test-daemon-setup.c \
	unit-test-mainloop-setup.c \
	unit-test-private.h

run-library-test.c: $(UNIT_TESTS_LIBRARY) unit-tests-prep.sh Makefile.am
	sh unit-tests-prep.sh -b run-library-test $(UNIT_TESTS_LIBRARY)

run_library_test_SOURCES = \
	run-library-test.c \
	run-library-test.h \
	$(UNIT_TESTS_LIBRARY) 

run_library_test_LDADD = \
	$(top_builddir)/library/libgnome-keyring.la

# ------------------------------------------------------------------------------
# Propmting tests

UNIT_TESTS_PROMPT = \
	unit-test-keyrings-prompt.c \
	unit-test-daemon-setup.c

run-prompt-test.c: $(UNIT_TESTS_PROMPT) unit-tests-prep.sh Makefile.am
	sh unit-tests-prep.sh -b run-prompt-test $(UNIT_TESTS_PROMPT)

run_prompt_test_SOURCES = \
	run-prompt-test.c \
	run-prompt-test.h \
	$(UNIT_TESTS_PROMPT) 

run_prompt_test_LDADD = \
	$(top_builddir)/library/libgnome-keyring.la

# ------------------------------------------------------------------------------
# PAM tests

UNIT_TESTS_PAM = \
	unit-test-pam-setup.c \
	unit-test-pam.c
	
run-pam-test.c: $(UNIT_TESTS_PAM) unit-tests-prep.sh Makefile.am
	sh unit-tests-prep.sh -b run-pam-test $(UNIT_TESTS_PAM)
	
run_pam_test_SOURCES = \
	run-pam-test.c \
	run-pam-test.h \
	$(UNIT_TESTS_PAM)
	
run_pam_test_LDADD = \
	-lpam 

# ------------------------------------------------------------------------------
# Run the tests

run-auto-tests: $(noinst_PROGRAMS)
	./run-base-test 
	./run-library-test

run: $(noinst_PROGRAMS)
	./run-base-test
	./run-library-test
	./run-prompt-test

