
EXTRA_DIST = \
	cu-test/ \
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
	unit-test-auto \
	unit-test-prompt
	
# Simply list all the keyrings and whatever they have access to

list_keyrings_SOURCES = \
	list-keyrings.c

# A generic testing program

test_keyring_SOURCES = \
	test-keyrings.c

test_keyring_two_SOURCES = \
	test-keyrings.c

# Automatic tests 

UNIT_TESTS_AUTO = \
	unit-test-keyrings.c \
	unit-test-other.c 

unit-test-auto.c: $(UNIT_TESTS_AUTO) unit-tests-prep.sh
	sh unit-tests-prep.sh -b unit-test-auto $(UNIT_TESTS_AUTO)

unit_test_auto_SOURCES = \
	unit-test-auto.c \
	unit-test-auto.h \
	$(srcdir)/cu-test/CuTest.c \
	$(UNIT_TESTS_AUTO) 

# Propmting tests

UNIT_TESTS_PROMPT = \
	unit-test-keyrings-prompt.c 

unit-test-prompt.c: $(UNIT_TESTS_PROMPT) unit-tests-prep.sh
	sh unit-tests-prep.sh -b unit-test-prompt $(UNIT_TESTS_PROMPT)

unit_test_prompt_SOURCES = \
	unit-test-prompt.c \
	unit-test-prompt.h \
	$(srcdir)/cu-test/CuTest.c \
	$(UNIT_TESTS_PROMPT) 
