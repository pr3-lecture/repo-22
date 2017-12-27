.PHONY: all clean run runtest
all: crypto
	cp crypto encrypt
	cp crypto decrypt
run: crypto
	./crypto
runtest: test
	./test
clean:
	rm -f main.o greeter.o crypto encrypt decrypt test
main.o: main.c
	cc -Wall -c main.c
crypto.o: crypto.c
	cc -Wall -c crypto.c
crypto: main.o crypto.o
	cc -o crypto main.o crypto.o
test.o: test.c
	cc -Wall -c test.c
test: crypto.o
	cc -o test test.o crypto.o
