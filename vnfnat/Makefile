# Makefile


CC = gcc -g -Wall
PROGNAME = vnf-nat


all: $(PROGNAME)

vnf-nat: nm_main.c nm_nat.c nm_session.c
	$(CC) $< -o $@ -lpthread
