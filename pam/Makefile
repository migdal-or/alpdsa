# Makefile
CC = gcc
CFLAGS = -Wall -Wextra -fPIC -O2
LDFLAGS = -shared -lssl -lcrypto
PAM_DIR = /lib/x86_64-linux-gnu/security

all: pam_alpdsa.so

pam_alpdsa.so: pam_alpdsa.c alpdsa.c alpdsa.h
	$(CC) $(CFLAGS) -o $@ pam_alpdsa.c alpdsa.c $(LDFLAGS)

install: pam_alpdsa.so
	install -m 644 pam_alpdsa.so $(PAM_DIR)/pam_alpdsa.so

clean:
	rm -f pam_alpdsa.so

.PHONY: all install clean
