SRC=src
CPP=g++
CFLAGS=-O -Wall -std=c++11
LIB=-lpcap -lpthread -ltins

all: exorcist

exorcist: $(SRC)/exorcist.cpp
	$(CPP) $(CFLAGS) $^ $(LIB) -o $@

clean:
	- rm -f exorcist

