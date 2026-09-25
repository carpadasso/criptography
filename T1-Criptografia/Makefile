CC = gcc
CPP = g++

CFLAGS = -O2 -Wall
CPPFLAGS = -std=c++17 -O2 -Wall

OPENSSL_LIBS = -lcrypto

OPENCV = $(shell pkg-config --exists opencv5 && echo opencv5)
OPENCV_FLAGS = $(shell pkg-config --cflags --libs $(OPENCV))

all: aes rsa ImSecret

aes: aes.c
	$(CC) $(CFLAGS) aes.c -o aes $(OPENSSL_LIBS)

rsa: rsa.c
	$(CC) $(CFLAGS) rsa.c -o rsa $(OPENSSL_LIBS)

ImSecret: ImSecret.cpp
	$(CPP) $(CPPFLAGS) ImSecret.cpp -o ImSecret $(OPENCV_FLAGS)

clean:
	rm -f aes rsa ImSecret
