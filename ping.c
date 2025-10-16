#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include <time.h>

#define STANDART_ICMP_PACKET_SIZE 64
#define STANDART_PACKETS_COUNT 4
#define STANDART_TIME_TO_LIVE 128

struct Options {
	uint16_t icmp_packet_size;
	uint8_t packets_count;
	uint8_t time_to_live;
};

struct Options parse_arguments(int argc, char* argv[]) {
	struct Options options = {
		.icmp_packet_size = STANDART_ICMP_PACKET_SIZE,
		.packets_count = STANDART_PACKETS_COUNT,
		.time_to_live = STANDART_TIME_TO_LIVE
	};

	const struct option option_array[] = {
		{"help", no_argument, NULL, 'h'},
		{"size", required_argument, NULL, 's'},
		{"count", required_argument, NULL, 'c'},
		{"ttl", required_argument, NULL, 't'},
		{0, 0, 0, 0}
	};

	int curr_option;
	while ((curr_option = getopt_long(argc, argv, "hs:c:t:", option_array, NULL)) != -1) {
		switch (curr_option) {
			case 'h':
				printf("Usage: %s [-s size] [-c count] [-t ttl] destination\n", argv[0]);
				puts("	-h, --help		Show this help message");	
				puts("	-s, --size		Set number of bytes in ICMP packet(min 64 bytes, max 1024 bytes)");	
				puts("	-c, --count		Set number of packets");	
				puts("	-t, --ttl		Set time to live");
				exit(EXIT_SUCCESS);

			case 's':
				char* size_end_ptr;
				options.icmp_packet_size = (uint16_t) strtol(optarg, &size_end_ptr, 10);
				break;

			case 'c':
				char* count_end_ptr;
				options.packets_count = (uint8_t) strtol(optarg, &count_end_ptr, 10);
				break;

			case 't':
				char* ttl_end_ptr;
				options.time_to_live = (uint8_t) strtol(optarg, &ttl_end_ptr, 10);
				break;

			default:
				puts("Invalid option. Use -h for help.");
				exit(EXIT_FAILURE);
		}
	}

	if (optind == argc) {
		printf("Error! Destination host is required.");
		exit(EXIT_FAILURE);
	}

	return options;
}

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

int get_ttl_from_packet(char* packet) {
	struct iphdr* ip_header = (struct iphdr*) packet;
	return ip_header->ttl;
}

double calculate_round_time_trip(struct timespec sending_time, struct timespec receiving_time) {
	return (double)(receiving_time.tv_sec - sending_time.tv_sec) * 1000.0 +
			(double)(receiving_time.tv_nsec - sending_time.tv_nsec) / 1000000.0;
}

int main(int argc, char* argv[]) {
	struct Options options = parse_arguments(argc, argv);

	struct sockaddr_in socket_addr = get_ip_address(argv[optind]);
	
	int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (socket_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	struct timeval timeout = {3, 0};
	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
		perror("sersockopt SO_RCVTIMEO");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &options.time_to_live, sizeof(options.time_to_live))) {
		perror("setsockopt IP_TTL");
		exit(EXIT_FAILURE);
	}
	
	char send_buffer[1024];
	struct icmphdr *icmp_header;

	for (int i = 0; i < options.packets_count; i++) {
		icmp_header = (struct icmphdr*) send_buffer;
		icmp_header->type = ICMP_ECHO;
		icmp_header->code = 0;
		icmp_header->un.echo.id = htons(getpid() & 0xFFFF);
		icmp_header->un.echo.sequence = htons(i);
		memset(send_buffer + sizeof(struct icmphdr), 0xFF, options.icmp_packet_size - sizeof(struct icmphdr));
		icmp_header->checksum = 0;
		icmp_header->checksum = checksum(send_buffer, options.icmp_packet_size);

		struct timespec sending_time, receiving_time;
		clock_gettime(CLOCK_MONOTONIC, &sending_time);
		
		if (sendto(socket_fd, send_buffer, options.icmp_packet_size, 0, (struct sockaddr*)&socket_addr, sizeof(socket_addr)) < 0) {
			perror("sendto");
			continue;
		}
		
		struct sockaddr_in reply_addr;
		char buffer[1024];
		socklen_t reply_addr_len = sizeof(reply_addr);
		ssize_t bytes = recvfrom(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&reply_addr, &reply_addr_len);
			
		if (bytes <= 0) {
        	perror("recvfrom");
			continue;
		}

		clock_gettime(CLOCK_MONOTONIC, &receiving_time);

		printf("PING: sent %d bytes to %s\n", options.icmp_packet_size, argv[optind]);
		printf("PONG: received %ld bytes from %s, ttl=%d, round-trip time %.2f ms\n\n", bytes, argv[optind], get_ttl_from_packet(buffer), calculate_round_time_trip(sending_time, receiving_time));	
	}


	close(socket_fd);
	return EXIT_SUCCESS;
}
