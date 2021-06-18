#include "ssq.h"
#include <string.h>

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

#include <WinSock2.h>

#else

#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>

#define INVALID_SOCKET -1

typedef int SOCKET;

#endif // _WIN32

/** internal socket send timeout */
static struct timeval g_timeout_send;

/** internal socket recv timeout */
static struct timeval g_timeout_recv;

/** internal socket address currently set */
static struct sockaddr_in g_addr;

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
	return *((int32_t *) payload) == -1;
}

static bool ssq_parse_packet(const char *const buffer, SSQPacket *packet)
{
	size_t pos = 0;

	packet->header = CAST(int32_t, buffer + pos);
	pos += sizeof(packet->header);

	if (packet->header == -2) // multi-packet response
	{
		packet->id = CAST(int32_t, buffer + pos);
		pos += sizeof(packet->id);

		packet->total = CAST(byte, buffer + pos);
		pos += sizeof(packet->total);

		packet->number = CAST(byte, buffer + pos);
		pos += sizeof(packet->number);

		packet->size = CAST(uint16_t, buffer + pos);
		pos += sizeof(packet->size);
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
		const size_t size = SSQ_PACKET_SIZE - sizeof(packets->header);
		*resp = malloc(size);
		memcpy(*resp, packets->payload, size);
	}
	else // multi-packet response
	{
		size_t size = 0;

		for (uint16_t i = 0; i < count; ++i)
		{
			size += packets[i].size;
		}

		*resp = malloc(size);

		size_t pos = 0;

		for (uint16_t i = 0; i < count; ++i)
		{
			memcpy(*resp + pos, packets[i].payload, packets[i].size);
			pos += packets[i].size;
		}
	}
}

static SSQCode ssq_send_query(const void *const payload, size_t len, char **const resp)
{
	SSQCode code = SSQ_OK;

	const SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (sockfd == INVALID_SOCKET)
		return SSQ_SOCK_CREATE_FAIL;

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sockfd, &fds);

	const int ndfs = sockfd + 1;

	// buffer to read the data from the socket
	char buffer[SSQ_PACKET_SIZE];

	// check for write state on the socket file descriptor
	if (select(ndfs, NULL, &fds, NULL, &g_timeout_send) <= 0)
		code = SSQ_SOCK_SND_TIMEOUT;
	else if (sendto(sockfd, payload, len, 0, (struct sockaddr *) &g_addr, sizeof(g_addr)) == -1)
		code = SSQ_SOCK_SND_ERR;
	// check for read state on the socket file descriptor
	else if (select(ndfs, NULL, &fds, NULL, &g_timeout_recv) <= 0)
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
	packets = calloc(count, sizeof(SSQPacket));

	if (packet.header == -2) // multi-packet response
	{
		// copy the first packet received
		memcpy(packets, &packet, sizeof(SSQPacket));

		for (byte i = 1; i < count; ++i)
		{
			// check for read state on the socket file descriptor
			if (select(ndfs, NULL, &fds, NULL, &g_timeout_recv) <= 0)
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
			memcpy(packets + packet.number, &packet, sizeof(SSQPacket));
		}
	}
	else // single-packet response
	{
		// copy the packet
		memcpy(packets, &packet, sizeof(SSQPacket));
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

bool ssq_set_address(const char *const address, const uint16_t port)
{
#ifdef _WIN32
	const unsigned long addr = inet_addr(address);
#else
	const in_addr_t addr = inet_addr(address);
#endif // _WIN32

	if (addr == INADDR_NONE)
		return false;

	memset(&g_addr, 0, sizeof(g_addr));

	g_addr.sin_addr.s_addr = addr;
	g_addr.sin_family      = AF_INET;
	g_addr.sin_port        = htons(port);

	return true;
}

void ssq_set_timeout(const SSQTimeout timeout, const long sec, const long usec)
{
	struct timeval *const tv = (timeout == SSQ_TIMEOUT_SEND) ? &g_timeout_send : &g_timeout_recv;
	tv->tv_sec = sec;
	tv->tv_usec = usec;
}

SSQCode ssq_info(A2SInfo *const info)
{
	SSQCode code = SSQ_OK;

	byte req[29] = A2S_INFO;
	char *resp;

	if ((code = ssq_send_query(req, 25, &resp)) != SSQ_OK)
		return code;

	if (resp[0] == S2A_CHALLENGE)
	{
		// copy the challenge number
		memcpy(req + 25, resp + 1, 4);

		free(resp);

		// send the query with the challenge
		if ((code = ssq_send_query(req, 9, &resp)) != SSQ_OK)
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
		pos += sizeof(info->protocol);

		pos += ssq_strncpy(info->name, resp + pos, 256);

		pos += ssq_strncpy(info->map, resp + pos, 32);

		pos += ssq_strncpy(info->folder, resp + pos, 32);

		pos += ssq_strncpy(info->game, resp + pos, 256);

		info->id = CAST(uint16_t, resp + pos);
		pos += sizeof(info->id);

		info->players = CAST(byte, resp + pos);
		pos += sizeof(info->players);

		info->max_players = CAST(byte, resp + pos);
		pos += sizeof(info->max_players);

		info->bots = CAST(byte, resp + pos);
		pos += sizeof(info->bots);

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
		pos += sizeof(server_type);

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
		pos += sizeof(environment);

		info->visibility = CAST(byte, resp + pos);
		pos += sizeof(info->visibility);

		info->vac = CAST(byte, resp + pos);
		pos += sizeof(info->vac);

		pos += ssq_strncpy(info->version, resp + pos, 32);

		// extra data flag
		byte edf = CAST(byte, resp + pos);

		if (edf & 0x80)
		{
			info->port = CAST(uint16_t, resp + pos);
			pos += sizeof(info->port);
		}

		if (edf & 0x10)
		{
			info->steamid = CAST(uint64_t, resp + pos);
			pos += sizeof(info->steamid);
		}

		if (edf & 0x40)
		{
			info->spectator_port = CAST(uint16_t, resp + pos);
			pos += sizeof(info->spectator_port);

			pos += ssq_strncpy(info->spectator_name, resp + pos, 256);
		}

		if (edf & 0x20)
		{
			pos += ssq_strncpy(info->keywords, resp + pos, 256);
		}

		if (edf & 0x01)
		{
			info->gameid = CAST(uint64_t, resp + pos);
			pos += sizeof(info->gameid);
		}
	}

	free(resp);

	return code;
}

SSQCode ssq_player(A2SPlayer **const players, byte *const count)
{
	SSQCode code = SSQ_OK;

	byte req[9] = A2S_PLAYER;
	char *resp;

	if ((code = ssq_send_query(req, 9, &resp)) != SSQ_OK)
		return code;

	if (resp[0] != S2A_CHALLENGE)
	{
		free(resp);
		return SSQ_INVALID_RESP;
	}

	// copy the challenge number
	memcpy(req + 5, resp + 1, 4);

	free(resp);

	// send the query with the challenge
	if ((code = ssq_send_query(req, 9, &resp)) != SSQ_OK)
		return code;

	size_t pos = 0;

	if (ssq_is_truncated(resp))
		pos += 4;

	if (resp[pos++] != S2A_PLAYER)
		code = SSQ_INVALID_RESP;

	if (code == SSQ_OK)
	{
		*count = CAST(byte, resp + pos);
		pos += sizeof(*count);

		*players = calloc(*count, sizeof(A2SPlayer));

		for (uint16_t i = 0; i < *count; ++i)
		{
			// skip 'index' field
			pos += sizeof(byte);

			pos += ssq_strncpy((*players)[i].name, resp + pos, 32);

			(*players)[i].score = CAST(int32_t, resp + pos);
			pos += sizeof((*players)[i].score);

			(*players)[i].duration = CAST(float, resp + pos);
			pos += sizeof((*players)[i].duration);
		}
	}

	free(resp);

	return code;
}

SSQCode ssq_rules(A2SRules **const rules, uint16_t *const count)
{
	SSQCode code = SSQ_OK;

	byte req[9] = A2S_RULES;
	char *resp;

	if ((code = ssq_send_query(req, 9, &resp)) != SSQ_OK)
		return code;

	if (resp[0] == S2A_CHALLENGE)
	{
		// copy the challenge number
		memcpy(req + 5, resp + 1, 4);

		free(resp);

		// send the query with the challenge
		if ((code = ssq_send_query(req, 9, &resp)) != SSQ_OK)
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
		pos += sizeof(*count);

		*rules = calloc(*count, sizeof(A2SRules));

		for (uint16_t i = 0; i < *count; ++i)
		{
			pos += ssq_strncpy((*rules)[i].name,  resp + pos, 128);
			pos += ssq_strncpy((*rules)[i].value, resp + pos, 256);
		}
	}

	free(resp);

	return code;
}
