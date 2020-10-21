all: dns.cpp
	g++ -Wall -pedantic  -o dns dns.cpp

clean:
	rm ./*.o
