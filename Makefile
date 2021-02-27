CC = gcc
CFLAGS = -g -Wall -Werror

all: mproxy

mproxy: mproxy.o
	$(CC) $(CFLAGS) mproxy.o -o mproxy

mproxy.o: clean
	$(CC) $(CFLAGS) -c mproxy.c

clean:
	rm -rf *.o

debug: clean
	$(CC) $(CFLAGS) -DDEBUG mproxy.c -o mproxy

t:
	rm -rf test.o
	$(CC) $(CFLAGS) -c test.c
	$(CC) $(CFLAGS) test.o -o test
	./test
