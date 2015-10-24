CPP=g++
CFLAGS=-O -Wall -std=c++11
LIB=-lpcap -lpthread libtins-master/build/lib/libtins.so
INC=-Ilibtins-master/include

all: exorcist

exorcist: exorcist.cpp
	$(CPP) $(CFLAGS) $^ $(INC) $(LIB) -o $@

clean:
	- rm -f exorcist

