
TESTS = \
	unit-test-keyrings.c 

all: unit-test

unit-test-harness.c: $(TESTS) 
	sh unit-tests-prep.sh $(TESTS) > $@

unit-test: unit-test-harness.c $(TESTS)
	sh -c "gcc -o $@ -g -O0 -I cu-test `pkg-config --cflags --libs gnome-keyring-1 gtk+-2.0` \
	      unit-test-harness.c $(TESTS) cu-test/CuTest.c"
