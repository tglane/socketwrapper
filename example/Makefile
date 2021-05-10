cc = g++

CFLAGS = -std=c++17 -fpic -Wall -Werror -Wextra -pedantic
LDFLAGS = -lpthread

%.o: %.cpp
	$(cc) -c $< -o $@ $(CFLAGS)

.PHONY: all
all: tls tcp udp span

.PHONY: tls
tls: tls_example.cpp
	$(cc) -o tls_example $^ $(CFLAGS) $(LDFLAGS) -lssl -lcrypto

.PHONY: tcp
tcp: tcp_example.cpp
	$(cc) -o tcp_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: async_tcp
async_tcp: async_tcp_example.cpp
	$(cc) -o async_tcp_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: udp
udp: udp_example.cpp
	$(cc) -o udp_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: async_udp
async_udp: async_udp_example.cpp
	$(cc) -o async_udp_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: span
span: span_example.cpp
	$(cc) -o span_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm tls_example
	rm tcp_example
	rm udp_example
	rm span_example
