#Makefile
#char code "LF(UNIX)" is required!!

OPTIONS = -g -Wall
PROGS = vnf-nat

all: $(PROGS)

clean :
	rm -f $(PROGS)
	rm -f *.o

vnf-nat: nm_main.o nm_nat.o nm_session.o
	$(CC) $(OPTIONS) -o $@ nm_main.o nm_nat.o nm_session.o -l pthread

nm_main.o : nm_main.c
	$(CC) $(OPTIONS) -c nm_main.c

nm_nat.o : nm_nat.c
	$(CC) $(OPTIONS) -c nm_nat.c

nm_session.o : nm_session.c
	$(CC) $(OPTIONS) -c nm_session.c

