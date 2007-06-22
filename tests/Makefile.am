
EXTRA_DIST = \
	cu-test/license.txt \
	unit-tests-prep.sh

INCLUDES=					\
	-I$(top_srcdir) 		\
	-I$(top_builddir) 		\
	$(GTK_CFLAGS) 			\
	$(GLIB_CFLAGS) 
	
LIBS = \
	$(top_builddir)/library/libgnome-keyring.la \
	$(GTK_LIBS)
	
noinst_PROGRAMS= \
	list-keyrings \
	test-keyring \
	test-keyring-two \
	run-library-test \
	run-prompt-test \
	run-base-test
	
# Simply list all the keyrings and whatever they have access to

list_keyrings_SOURCES = \
	list-keyrings.c

# A generic testing program

test_keyring_SOURCES = \
	test-keyrings.c

test_keyring_two_SOURCES = \
	test-keyrings.c
	
# ------------------------------------------------------------------------------
# Base tests

UNIT_TESTS_BASE = \
	unit-test-memory.c \
	unit-test-secmem.c

run-base-test.c: $(UNIT_TESTS_BASE) unit-tests-prep.sh
	sh unit-tests-prep.sh -b run-base-test $(UNIT_TESTS_BASE)

run_base_test_SOURCES = \
	run-base-test.c \
	run-base-test.h \
	$(srcdir)/cu-test/CuTest.h \
	$(srcdir)/cu-test/CuTest.c \
	$(UNIT_TESTS_BASE) 

# ------------------------------------------------------------------------------
# Automatic library tests 

UNIT_TESTS_LIBRARY = \
	unit-test-keyrings.c \
	unit-test-other.c \
	unit-test-daemon-setup.c

run-library-test.c: $(UNIT_TESTS_LIBRARY) unit-tests-prep.sh
	sh unit-tests-prep.sh -b run-library-test $(UNIT_TESTS_LIBRARY)

run_library_test_SOURCES = \
	run-library-test.c \
	run-library-test.h \
	$(srcdir)/cu-test/CuTest.h \
	$(srcdir)/cu-test/CuTest.c \
	$(UNIT_TESTS_LIBRARY) 

# ------------------------------------------------------------------------------
# Propmting tests

UNIT_TESTS_PROMPT = \
	unit-test-keyrings-prompt.c \
	unit-test-daemon-setup.c

run-prompt-test.c: $(UNIT_TESTS_PROMPT) unit-tests-prep.sh
	sh unit-tests-prep.sh -b run-prompt-test $(UNIT_TESTS_PROMPT)

run_prompt_test_SOURCES = \
	run-prompt-test.c \
	run-prompt-test.h \
	$(srcdir)/cu-test/CuTest.h \
	$(srcdir)/cu-test/CuTest.c \
	$(UNIT_TESTS_PROMPT) 

# -----------------------------------------------------------------------------
# Run the tests

run-auto-tests: $(noinst_PROGRAMS)
	./run-base-test 
	./run-library-test

run: $(noinst_PROGRAMS)
	./run-base-test
	./run-library-test
	./run-prompt-test

