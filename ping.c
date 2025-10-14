#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>

struct sockaddr_in get_ip_address(const char* input) {
	struct sockaddr_in socket_addr = {0};
	socket_addr.sin_family = AF_INET;

	if (inet_pton(AF_INET, input, &socket_addr.sin_addr) <= 0) {
		struct addrinfo hints = {0}, *result;
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_RAW;

		if (getaddrinfo(input, NULL, &hints, &result) != 0) {
			puts("Error: bad hostname/ip address!");
			exit(EXIT_FAILURE);
		}

		socket_addr = *((struct sockaddr_in*) result->ai_addr);

		freeaddrinfo(result);
	}

	return socket_addr;
}

uint16_t checksum(void* buffer, size_t len) {
	uint16_t* word_ptr = buffer;
	uint32_t sum = 0;

	for (sum = 0; len > 1; len -= 2) {
		sum += *word_ptr++;
	}

	if (len == 1) {
		sum += *(uint8_t*)word_ptr;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += sum >> 16;

	return (uint16_t)~sum;
}

int main(int argc, char* argv[]) {
	int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	struct sockaddr_in socket_addr = get_ip_address(argv[1]);
	
	struct icmphdr icmp_header;
	icmp_header.type = ICMP_ECHO;
	icmp_header.un.echo.id = getpid();
	icmp_header.un.echo.sequence = 1;
	icmp_header.checksum = checksum(&icmp_header, sizeof(icmp_header));

	sendto(socket_fd, &icmp_header, sizeof(icmp_header), 0, (struct sockaddr*)&socket_addr, sizeof(socket_addr));

	char buffer[1024];
	socklen_t socket_addr_len = sizeof(socket_addr);
	ssize_t bytes = recvfrom(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&socket_addr, &socket_addr_len);

	printf("Recv %ld\n", bytes);

	return EXIT_SUCCESS;
}
