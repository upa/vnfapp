# Makefile


CC = gcc -g -Wall
PROGNAME = vnfl3


all: $(PROGNAME)

.c.o:
	$(CC) -c $< -o $@

vnfl3: patricia.o vnfl3.c 
	$(CC) vnfl3.c -o $@ -lpthread patricia.o


