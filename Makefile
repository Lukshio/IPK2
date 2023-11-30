CC = g++
CFLAGS = -g -Wall
LIBS = -lpcap
TARGET = main

all:
	$(CC) -std=c++2a -o ipk-sniffer $(TARGET).cpp $(CFLAGS) $(LIBS)

clean:
	rm ipk-sniffer