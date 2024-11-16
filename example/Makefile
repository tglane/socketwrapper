# cc = g++
cc = clang++

CFLAGS = -std=c++20 -fpic -Wall -Werror -Wextra -pedantic -g -fsanitize=undefined -fsanitize=address
# -fsanitize=thread

LDFLAGS = -lpthread

.PHONY: all
all: tls async_tls tcp async_tcp coroutine_tcp udp async_udp coroutine_udp span options

.PHONY: tls
tls: tls_example.cpp
	$(cc) -o tls_example $^ $(CFLAGS) $(LDFLAGS) -lssl -lcrypto

PHONY: async_tls
async_tls: async_tls_example.cpp
	$(cc) -o async_tls_example $^ $(CFLAGS) $(LDFLAGS) -lssl -lcrypto

.PHONY: tcp
tcp: tcp_example.cpp
	$(cc) -o tcp_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: async_tcp
async_tcp: async_tcp_example.cpp
	$(cc) -o async_tcp_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: coroutine_tcp
coroutine_tcp: coroutine_tcp_example.cpp
	$(cc) -o coroutine_tcp_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: udp
udp: udp_example.cpp
	$(cc) -o udp_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: async_udp
async_udp: async_udp_example.cpp
	$(cc) -o async_udp_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: coroutine_udp
coroutine_udp: coroutine_udp_example.cpp
	$(cc) -o coroutine_udp_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: span
span: span_example.cpp
	$(cc) -o span_example $^ $(CFLAGS) $(LDFLAGS)

.PHONY: options
options: options_example.cpp
	$(cc) -o options_example $^ $(CFLAGS) $(LDFLAGS)

%.o: %.cpp
	$(cc) -c $< -o $@ $(CFLAGS)

.PHONY: clean
clean:
	rm tls_example \
	async_tls_example \
	tcp_example \
	async_tcp_example \
	coroutine_tcp_example \
	udp_example \
	async_udp_example \
	coroutine_udp_example \
	span_example \
	options_example
