.PHONY :  clean
CC = gcc

CFLAGS = -Wall -pedantic -std=gnu99

RUSHBSwitch: main.o invocation.o open_port.o
	$(CC) $(CFLAGS) -o $@ $^

main.o: main.c
	$(CC) $(CFLAGS) -c $<

invocation.o: invocation.c invocation.h
	$(CC) $(CFLAGS) -c $<

open_port.o: open_port.c open_port.h
	$(CC) $(CFLAGS) -c $<


clean:
	rm -f *.o RUSHBSwitch