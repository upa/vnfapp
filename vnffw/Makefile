# Makefile


CC = gcc -g -Wall
PROGNAME = vnffw


all: $(PROGNAME)

.c.o:
	$(CC) -c $< -o $@

vnffw: patricia.o vnffw.c 
	$(CC) vnffw.c -o $@ -lpthread patricia.o


