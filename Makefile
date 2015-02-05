default: all

all: icmp.cpp
	g++ icmp.cpp -o icmp

clean:
	rm -rf *.o icmp
