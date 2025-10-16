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
#include <errno.h>

#define DEFAULT_ICMP_PACKET_SIZE 64
#define DEFAULT_PACKETS_COUNT 4
#define DEFAULT_TIME_TO_LIVE 128
#define DEFAULT_TIMEOUT_IN_SEC 3

struct Options {
	uint16_t icmp_packet_size;
	uint8_t packets_count;
	uint8_t time_to_live;
};

struct Options parse_arguments(int argc, char* argv[]) {
	struct Options options = {
		.icmp_packet_size = DEFAULT_ICMP_PACKET_SIZE,
		.packets_count = DEFAULT_PACKETS_COUNT,
		.time_to_live = DEFAULT_TIME_TO_LIVE
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

uint16_t create_socket() {
	uint16_t socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (socket_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	return socket_fd;
}

void set_socket_timeout(int socket_fd) {
	struct timeval timeout = {DEFAULT_TIMEOUT_IN_SEC, 0};
	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
		perror("sersockopt SO_RCVTIMEO");
		exit(EXIT_FAILURE);
	}
}

void set_socket_ttl(int socket_fd, uint8_t time_to_live) {
	if (setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &time_to_live, sizeof(time_to_live)) == -1) {
		perror("setsockopt IP_TTL");
		exit(EXIT_FAILURE);
	}
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

void set_packet_fields(char* send_packet, struct icmphdr* icmp_header, uint16_t icmp_packet_size, uint8_t sequence_num) {
	icmp_header = (struct icmphdr*) send_packet;
	icmp_header->type = ICMP_ECHO;
	icmp_header->code = 0;
	icmp_header->un.echo.id = htons(getpid() & 0xFFFF);
	icmp_header->un.echo.sequence = htons(sequence_num);
	memset(send_packet + sizeof(struct icmphdr), 0xFF, icmp_packet_size - sizeof(struct icmphdr));
	icmp_header->checksum = 0;
	icmp_header->checksum = checksum(send_packet, icmp_packet_size);
}

char* get_src_ip_address(char* packet) {
	struct iphdr* ip_header = (struct iphdr*) packet;
	char* src_ip_addr = malloc(INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->saddr), src_ip_addr, INET_ADDRSTRLEN);
	return src_ip_addr;
}

int get_ttl_from_packet(char* packet) {
	struct iphdr* ip_header = (struct iphdr*) packet;
	return ip_header->ttl;
}

double calculate_round_time_trip(struct timespec sending_time, struct timespec receiving_time) {
	return (double)(receiving_time.tv_sec - sending_time.tv_sec) * 1000.0 +
			(double)(receiving_time.tv_nsec - sending_time.tv_nsec) / 1000000.0;
}

void print_icmp_message(char* sender_ip_address, char* received_packet, uint8_t packet_size, double round_time_trip) {
	printf("PING: sent %d bytes to %s\n", packet_size, sender_ip_address);
	
	struct icmphdr* recv_icmp = (struct icmphdr*)(received_packet + sizeof(struct iphdr));
	char* src_ip_addr = get_src_ip_address(received_packet);
	if (recv_icmp->type == ICMP_ECHOREPLY) {
		printf("PONG: received %ld bytes from %s, ttl=%d, round-trip time %.2f ms\n\n", sizeof(received_packet), src_ip_addr, get_ttl_from_packet(received_packet), round_time_trip);
	} else if (recv_icmp->type == ICMP_TIME_EXCEEDED) {
		printf("PONG: packet was dropped due to TTL\n\n");
	}

	free(src_ip_addr);	
}

int main(int argc, char* argv[]) {
	struct Options options = parse_arguments(argc, argv);

	struct sockaddr_in socket_addr = get_ip_address(argv[optind]);
	
	uint16_t socket_fd = create_socket();
	set_socket_timeout(socket_fd);
	set_socket_ttl(socket_fd, options.time_to_live);
	
	char send_packet[1024];
	struct icmphdr *icmp_header;

	for (uint8_t i = 0; i < options.packets_count; i++) {
		set_packet_fields(send_packet, icmp_header, options.icmp_packet_size, i);

		struct timespec sending_time, receiving_time;
		clock_gettime(CLOCK_MONOTONIC, &sending_time);
		
		if (sendto(socket_fd, send_packet, options.icmp_packet_size, 0, (struct sockaddr*)&socket_addr, sizeof(socket_addr)) < 0) {
			perror("sendto");
			continue;
		}
		
		struct sockaddr_in reply_addr;
		char received_packet[1024];
		socklen_t reply_addr_len = sizeof(reply_addr);
		ssize_t bytes = recvfrom(socket_fd, received_packet, sizeof(received_packet), 0, (struct sockaddr*)&reply_addr, &reply_addr_len);
			
		if (bytes <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				puts("Request timed out! Exiting...");
				exit(EXIT_FAILURE);
			}

        	perror("recvfrom");
			continue;
		}

		clock_gettime(CLOCK_MONOTONIC, &receiving_time);
				
		print_icmp_message(argv[optind], received_packet, options.icmp_packet_size, calculate_round_time_trip(sending_time, receiving_time));	

	}

	close(socket_fd);
	return EXIT_SUCCESS;
}

