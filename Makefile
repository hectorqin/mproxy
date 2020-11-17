CC = gcc
CFLAGS = -g -Wall -Werror

all: mproxy

mproxy: mproxy.o
	$(CC) $(CFLAGS) mproxy.o -o mproxy

mproxy.o:
	$(CC) $(CFLAGS) -c mproxy.c

clean:
	rm -rf *.o

t:
	rm -rf test.o
	$(CC) $(CFLAGS) -c test.c
	$(CC) $(CFLAGS) test.o -o test
	./test
