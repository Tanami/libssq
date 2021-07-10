#include "ssq.h"
#include <string.h>
#include <stdio.h>

#define SSQ_PACKET_SIZE 1400

#define A2S_INFO   "\xFF\xFF\xFF\xFF\x54Source Engine Query\0"
#define A2S_PLAYER "\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF"
#define A2S_RULES  "\xFF\xFF\xFF\xFF\x56\xFF\xFF\xFF\xFF"

#define S2A_CHALLENGE 0x41
#define S2A_INFO      0x49
#define S2A_PLAYER    0x44
#define S2A_RULES     0x45

#define CAST(x, y) *((x *) (y))

#ifdef _WIN32

#include <WS2tcpip.h>

#else // _WIN32

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>

#define INVALID_SOCKET -1

typedef int SOCKET;

#endif // _WIN32

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct
{
	/** -2 means the packet is split, -1 means the packet is not split */
	int32_t header;

	/** unique number assigned by server per answer */
	int32_t id;

	/** the total number of packets in the response */
	byte total;

	/** the number of the packet */
	byte number;

	/** maximum size of packet before packet switching occurs */
	uint16_t size;

	int8_t *payload;
} SSQPacket;

static size_t ssq_strncpy(char *const dest, const char *const src, const size_t len)
{
	size_t pos = 0;

	for (; src[pos] != 0 && pos < len - 1; ++pos)
	{
		dest[pos] = src[pos];
	}

	for (size_t i = pos; i < len; ++i)
	{
		dest[i] = 0;
	}

	return pos + 1;
}

static inline bool ssq_is_truncated(const void *const payload)
{
	return CAST(int32_t, payload) == -1;
}

static bool ssq_parse_packet(const char *const buffer, SSQPacket *packet)
{
	size_t pos = 0;

	packet->header = CAST(int32_t, buffer + pos);
	pos += sizeof (packet->header);

	if (packet->header == -2) // multi-packet response
	{
		packet->id = CAST(int32_t, buffer + pos);
		pos += sizeof (packet->id);

		packet->total = CAST(byte, buffer + pos);
		pos += sizeof (packet->total);

		packet->number = CAST(byte, buffer + pos);
		pos += sizeof (packet->number);

		packet->size = CAST(uint16_t, buffer + pos);
		pos += sizeof (packet->size);
	}
	else if (packet->header != -1) // not a single packet response
	{
		return 0;
	}

	packet->payload = malloc(SSQ_PACKET_SIZE - pos);
	memcpy(packet->payload, buffer + pos, SSQ_PACKET_SIZE - pos);

	return 1;
}

static void ssq_combine_packets(const SSQPacket *const packets, const uint16_t count, char **const resp)
{
	if (count == 1) // single-packet response
	{
		const size_t size = SSQ_PACKET_SIZE - sizeof (packets->header);
		*resp = calloc(size, sizeof (char));
		memcpy(*resp, packets->payload, size);
	}
	else // multi-packet response
	{
		size_t size = 0;

		for (uint16_t i = 0; i < count; ++i)
		{
			size += packets[i].size;
		}

		*resp = calloc(size, sizeof (char));

		size_t pos = 0;

		for (uint16_t i = 0; i < count; ++i)
		{
			memcpy(*resp + pos, packets[i].payload, packets[i].size);
			pos += packets[i].size;
		}
	}
}

static SSQCode ssq_send_query(SSQHandle *const handle, const void *const payload, size_t len, char **const resp)
{
	SSQCode code = SSQ_OK;

	// hints for getaddrinfo
	struct addrinfo hints;
	memset(&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	// address list obtained by getaddrinfo
	struct addrinfo *addr_list;

	struct addrinfo addr;

	SOCKET sockfd = INVALID_SOCKET;

	if (getaddrinfo(handle->hostname, handle->port, &hints, &addr_list) == 0)
	{
		for (struct addrinfo *cur = addr_list; cur != NULL; cur = cur->ai_next)
		{
			sockfd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);

			if (sockfd != INVALID_SOCKET)
			{
				// copy the address
				memcpy(&addr, cur, sizeof (struct addrinfo));
				break;
			}
		}
	}
	else
	{
		return SSQ_INVALID_ADDR;
	}

	// free the address list
	freeaddrinfo(addr_list);

	if (sockfd == INVALID_SOCKET)
		return SSQ_SOCK_CREATE_FAIL;

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sockfd, &fds);

	const int ndfs = sockfd + 1;

	// buffer to read the data from the socket
	char buffer[SSQ_PACKET_SIZE];

	// check for write state on the socket file descriptor
	if (select(ndfs, NULL, &fds, NULL, &handle->timeout_send) <= 0)
		code = SSQ_SOCK_SND_TIMEOUT;
	else if (sendto(sockfd, payload, len, 0, addr.ai_addr, addr.ai_addrlen) == -1)
		code = SSQ_SOCK_SND_ERR;
	// check for read state on the socket file descriptor
	else if (select(ndfs, NULL, &fds, NULL, &handle->timeout_recv) <= 0)
		code = SSQ_SOCK_RCV_TIMEOUT;
	else if (recvfrom(sockfd, buffer, SSQ_PACKET_SIZE, 0, NULL, NULL) == -1)
		code = SSQ_SOCK_RCV_ERR;

	if (code != SSQ_OK)
	{
#ifdef _WIN32
		closesocket(sockfd);
#else
		close(sockfd);
#endif // _WIN32

		return code;
	}

	SSQPacket packet;          // temporary packet
	SSQPacket *packets = NULL; // array of received packets (in the right order)

	if (!ssq_parse_packet(buffer, &packet))
		return SSQ_INVALID_RESP;

	const byte count = (packet.header == -2) ? packet.total : 1; // number of packets

	// allocate memory to store the packets
	packets = calloc(count, sizeof (SSQPacket));

	if (packet.header == -2) // multi-packet response
	{
		// copy the first packet received
		memcpy(packets, &packet, sizeof (SSQPacket));

		for (byte i = 1; i < count; ++i)
		{
			// check for read state on the socket file descriptor
			if (select(ndfs, NULL, &fds, NULL, &handle->timeout_recv) <= 0)
			{
				code = SSQ_SOCK_RCV_TIMEOUT;
				break;
			}

			if (recvfrom(sockfd, buffer, SSQ_PACKET_SIZE, 0, NULL, NULL) == -1)
			{
				code = SSQ_SOCK_RCV_ERR;
				break;
			}

			if (!ssq_parse_packet(buffer, &packet))
			{
				code = SSQ_INVALID_RESP;
				break;
			}

			// TODO: ID
			if (packet.header != -2)
			{
				code = SSQ_INVALID_RESP;
				break;
			}

			// copy the packet
			memcpy(packets + packet.number, &packet, sizeof (SSQPacket));
		}
	}
	else // single-packet response
	{
		// copy the packet
		memcpy(packets, &packet, sizeof (SSQPacket));
	}

#ifdef _WIN32
	closesocket(sockfd);
#else
	close(sockfd);
#endif // _WIN32

	if (code == SSQ_OK)
	{
		// combine the packets into a unique buffer
		ssq_combine_packets(packets, count, resp);
	}

	for (uint16_t i = 0; i < count; ++i)
	{
		free(packets[i].payload);
	}

	free(packets);

	return code;
}

void ssq_set_address(SSQHandle *handle, const char *hostname, const uint16_t port)
{
	strncpy(handle->hostname, hostname, SSQ_HOSTNAME_LEN);
	sprintf(handle->port, "%hu", port);
}

void ssq_set_timeout(SSQHandle *handle, const SSQTimeout timeout, const time_t millis)
{
	struct timeval *const tv = (timeout == SSQ_TIMEOUT_SEND) ? &handle->timeout_send : &handle->timeout_recv;
	tv->tv_sec = millis / 1000;
	tv->tv_usec = millis % 1000 * 1000;
}

SSQCode ssq_info(SSQHandle *handle, A2SInfo *info)
{
	SSQCode code = SSQ_OK;

	byte req[29] = A2S_INFO;
	char *resp;

	if ((code = ssq_send_query(handle, req, 25, &resp)) != SSQ_OK)
		return code;

	while (resp[0] == S2A_CHALLENGE)
	{
		// copy the challenge number
		memcpy(req + 25, resp + 1, 4);

		free(resp);

		// send the query with the challenge
		if ((code = ssq_send_query(handle, req, 9, &resp)) != SSQ_OK)
			return code;
	}

	size_t pos = 0;

	if (ssq_is_truncated(resp))
		pos += 4;

	if (resp[pos++] != S2A_INFO)
		code = SSQ_INVALID_RESP;

	if (code == SSQ_OK)
	{
		info->protocol = CAST(byte, resp + pos);
		pos += sizeof (info->protocol);

		pos += ssq_strncpy(info->name, resp + pos, 256);

		pos += ssq_strncpy(info->map, resp + pos, 32);

		pos += ssq_strncpy(info->folder, resp + pos, 32);

		pos += ssq_strncpy(info->game, resp + pos, 256);

		info->id = CAST(uint16_t, resp + pos);
		pos += sizeof (info->id);

		info->players = CAST(byte, resp + pos);
		pos += sizeof (info->players);

		info->max_players = CAST(byte, resp + pos);
		pos += sizeof (info->max_players);

		info->bots = CAST(byte, resp + pos);
		pos += sizeof (info->bots);

		int8_t server_type = CAST(int8_t, resp + pos);
		switch (server_type)
		{
		case 'd':
			info->server_type = SERVER_TYPE_DEDICATED;
			break;

		case 'p':
			info->server_type = SERVER_TYPE_SOURCETV_RELAY;
			break;

		default:
			info->server_type = SERVER_TYPE_NON_DEDICATED;
			break;

		}
		pos += sizeof (server_type);

		int8_t environment = CAST(int8_t, resp + pos);
		switch (environment)
		{
		case 'w':
			info->environment = ENVIRONMENT_WINDOWS;
			break;

		case 'm':
		case 'o':
			info->environment = ENVIRONMENT_MAC;
			break;

		default:
			info->environment = ENVIRONMENT_LINUX;
			break;
		}
		pos += sizeof (environment);

		info->visibility = CAST(byte, resp + pos);
		pos += sizeof (info->visibility);

		info->vac = CAST(byte, resp + pos);
		pos += sizeof (info->vac);

		pos += ssq_strncpy(info->version, resp + pos, 32);

		info->edf = CAST(byte, resp + pos);
		pos += sizeof (info->edf);

		if (info->edf & 0x80)
		{
			info->port = CAST(uint16_t, resp + pos);
			pos += sizeof (info->port);
		}

		if (info->edf & 0x10)
		{
			info->steamid = CAST(uint64_t, resp + pos);
			pos += sizeof (info->steamid);
		}

		if (info->edf & 0x40)
		{
			info->spectator_port = CAST(uint16_t, resp + pos);
			pos += sizeof (info->spectator_port);

			pos += ssq_strncpy(info->spectator_name, resp + pos, 256);
		}

		if (info->edf & 0x20)
		{
			pos += ssq_strncpy(info->keywords, resp + pos, 256);
		}

		if (info->edf & 0x01)
		{
			info->gameid = CAST(uint64_t, resp + pos);
			pos += sizeof (info->gameid);
		}
	}

	free(resp);

	return code;
}

SSQCode ssq_player(SSQHandle *handle, A2SPlayer **players, byte *count)
{
	SSQCode code = SSQ_OK;

	byte req[9] = A2S_PLAYER;
	char *resp;

	if ((code = ssq_send_query(handle, req, 9, &resp)) != SSQ_OK)
		return code;

	while (resp[0] == S2A_CHALLENGE)
	{
		// copy the challenge number
		memcpy(req + 5, resp + 1, 4);

		free(resp);

		// send the query with the challenge
		if ((code = ssq_send_query(handle, req, 9, &resp)) != SSQ_OK)
			return code;
	}

	size_t pos = 0;

	if (ssq_is_truncated(resp))
		pos += 4;

	if (resp[pos++] != S2A_PLAYER)
		code = SSQ_INVALID_RESP;

	if (code == SSQ_OK)
	{
		*count = CAST(byte, resp + pos);
		pos += sizeof (*count);

		*players = calloc(*count, sizeof (A2SPlayer));

		for (uint16_t i = 0; i < *count; ++i)
		{
			// skip 'index' field
			pos += sizeof (byte);

			pos += ssq_strncpy((*players)[i].name, resp + pos, 32);

			(*players)[i].score = CAST(int32_t, resp + pos);
			pos += sizeof ((*players)[i].score);

			(*players)[i].duration = CAST(float, resp + pos);
			pos += sizeof ((*players)[i].duration);
		}
	}

	free(resp);

	return code;
}

SSQCode ssq_rules(SSQHandle *handle, A2SRules **rules, uint16_t *count)
{
	SSQCode code = SSQ_OK;

	byte req[9] = A2S_RULES;
	char *resp;

	if ((code = ssq_send_query(handle, req, 9, &resp)) != SSQ_OK)
		return code;

	while (resp[0] == S2A_CHALLENGE)
	{
		// copy the challenge number
		memcpy(req + 5, resp + 1, 4);

		free(resp);

		// send the query with the challenge
		if ((code = ssq_send_query(handle, req, 9, &resp)) != SSQ_OK)
			return code;
	}

	size_t pos = 0;

	if (ssq_is_truncated(resp))
		pos += 4;

	if (resp[pos++] != S2A_RULES)
		code = SSQ_INVALID_RESP;

	if (code == SSQ_OK)
	{
		*count = CAST(uint16_t, resp + pos);
		pos += sizeof (*count);

		*rules = calloc(*count, sizeof (A2SRules));

		for (uint16_t i = 0; i < *count; ++i)
		{
			pos += ssq_strncpy((*rules)[i].name,  resp + pos, 128);
			pos += ssq_strncpy((*rules)[i].value, resp + pos, 256);
		}
	}

	free(resp);

	return code;
}

A2SRules *ssq_get_rule(const char *name, A2SRules *rules, const byte count)
{
	for (byte i = 0; i < count; ++i)
	{
		if (strcmp(rules[i].name, name) == 0)
			return &rules[i];
	}

	return NULL;
}

#ifdef __cplusplus
}
#endif // __cplusplus