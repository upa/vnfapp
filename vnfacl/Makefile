# Makefile


CC = gcc -g -Wall
PROGNAME = vnfacl


all: $(PROGNAME)

.c.o:
	$(CC) -c $< -o $@

vnfacl: patricia.o vnfacl.c 
	$(CC) vnfacl.c -o $@ -lpthread patricia.o


