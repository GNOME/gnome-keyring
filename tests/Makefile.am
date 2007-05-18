
EXTRA_DIST = cu-test

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
	unit-test-auto 
	
#	\
#	unit-test-prompt 
	
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
	unit-test-keyrings.c 

unit-test-auto.c: $(UNIT_TESTS_AUTO) unit-tests-prep.sh
	sh unit-tests-prep.sh -b unit-test-auto $(UNIT_TESTS_AUTO)

unit_test_auto_SOURCES = \
	unit-test-auto.c \
	unit-test-auto.h \
	cu-test/CuTest.c \
	$(UNIT_TESTS_AUTO) 

