# Makefile for V-Splash
CFLAGS = -O3 -g -Wall -Wextra
SHELL = /bin/sh

BINDIR = /usr/local/bin
MANDIR = /usr/local/man/man1

LDFLAGS = -lpthread -lrt -lpcap

.PHONY: all

all: trafw

trafw: trafw.c

clean:
	rm trafw
