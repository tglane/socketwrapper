cc = g++

CFLAGS = -std=c++17 -fpic -Wall -Werror -Wextra -pedantic

%.o: %.cpp
	$(cc) -c $< -o $@ $(CFLAGS)

.PHONY: all
all: tls tcp udp

.PHONY: tls
tls: tls_example.cpp
	$(cc) -o tls_example $^ $(CFLAGS) -lssl -lcrypto

.PHONY: tcp
tcp: tcp_example.cpp
	$(cc) -o tcp_example $^ $(CFLAGS)

.PHONY: udp
udp: udp_example.cpp
	$(cc) -o udp_example $^ $(CFLAGS)

