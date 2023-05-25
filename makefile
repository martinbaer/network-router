.PHONY :  clean
CC = gcc

CFLAGS = -Wall -pedantic -std=gnu99

RUSHBSwitch: main.o invocation.o open_port.o packet.o connect_switch.o connect_adapter.o ip_allocation.o distance_relaying.o data_forwarding.o globals.o
	$(CC) $(CFLAGS) -o $@ $^

main.o: main.c
	$(CC) $(CFLAGS) -c $<

invocation.o: invocation.c invocation.h
	$(CC) $(CFLAGS) -c $<

open_port.o: open_port.c open_port.h
	$(CC) $(CFLAGS) -c $<

packet.o: packet.c packet.h
	$(CC) $(CFLAGS) -c $<

connect_switch.o: connect_switch.c connect_switch.h
	$(CC) $(CFLAGS) -c $<

connect_adapter.o: connect_adapter.c connect_adapter.h
	$(CC) $(CFLAGS) -c $<

ip_allocation.o: ip_allocation.c ip_allocation.h
	$(CC) $(CFLAGS) -c $<

distance_relaying.o: distance_relaying.c distance_relaying.h
	$(CC) $(CFLAGS) -c $<

data_forwarding.o: data_forwarding.c data_forwarding.h
	$(CC) $(CFLAGS) -c $<

globals.o: globals.c globals.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o RUSHBSwitch