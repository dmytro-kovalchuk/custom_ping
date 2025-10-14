#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

struct sockaddr_in get_ip_address(const char* input) {
	struct sockaddr_in socket_addr = {0};

	if (inet_pton(AF_INET, input, &socket_addr.sin_addr) <= 0) {
		struct addrinfo hints = {0}, *result;
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;

		if (getaddrinfo(input, NULL, &hints, &result) != 0) {
			puts("Error: bad hostname/ip address!");
			exit(EXIT_FAILURE);
		}

		socket_addr = *((struct sockaddr_in*) result->ai_addr);
	}

	return socket_addr;
}

int main(int argc, char* argv[]) {
	struct sockaddr_in socket_addr = get_ip_address(argv[1]);
	
	printf("%d\n", socket_addr.sin_addr.s_addr);

	return EXIT_SUCCESS;
}
