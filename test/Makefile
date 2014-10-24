# Makefile


CC = gcc -g -Wall
PROGNAME = nm_template nm_hub


all: $(PROGNAME)

nm_template: nm_template.c
	$(CC) $< -o $@ -lpthread


nm_hub: nm_hub.c
	$(CC) $< -o $@ -lpthread
