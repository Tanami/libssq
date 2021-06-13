#ifndef SSQ_H
#define SSQ_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint8_t byte;

#ifdef _WIN32

#include <WinSock2.h>

#else

#include <netinet/in.h>
#include <sys/socket.h>

#endif // _WIN32

typedef enum
{
	SSQ_OK = 0,
	SSQ_INVALID_ADDR,
	SSQ_SOCK_CREATE_FAIL,
	SSQ_SOCK_SND_ERR,
	SSQ_SOCK_SND_TIMEOUT,
	SSQ_SOCK_RCV_ERR,
	SSQ_SOCK_RCV_TIMEOUT,
	SSQ_INVALID_RESP
} SSQCode;

typedef enum
{
	SSQ_TIMEOUT_SEND,
	SSQ_TIMEOUT_RECV
} SSQTimeout;

typedef enum
{
	SERVER_TYPE_DEDICATED = 'd',
	SERVER_TYPE_NON_DEDICATED = 'l',
	SERVER_TYPE_SOURCETV_RELAY = 'p'
} A2SServerType;

typedef enum
{
	ENVIRONMENT_LINUX = 'l',
	ENVIRONMENT_WINDOWS = 'w',
	ENVIRONMENT_MAC = 'm'
} A2SEnvironment;

typedef struct
{
	/** protocol version used by the server */
	byte protocol;

	/** name of the server */
	char name[256];

	/** map the server has currently loaded */
	char map[32];

	/** name of the folder containing the game files */
	char folder[32];

	/** full name of the game */
	char game[256];

	/** Steam application ID of the game */
	uint16_t id;

	/** number of players on the server */
	byte players;

	/** maximum number of players the server reports it can hold */
	byte max_players;

	/** number of bots on the server */
	byte bots;

	/** type of server */
	A2SServerType server_type;

	/** operating system of server */
	A2SEnvironment environment;

	/** whether the server requires a password */
	byte visibility;

	/** whether the server uses VAC */
	byte vac;

	/** version of the game installed on the server */
	char version[32];

	/** the server's game port number */
	uint16_t port;

	/** server's SteamID */
	uint64_t steamid;

	/** spectator port number for SourceTV */
	uint16_t spectator_port;

	/** name of the spectator server for SourceTV */
	char spectator_name[256];

	/** tags that describe the game according to the server */
	char keywords[256];

	/** server's 64-bit GameID */
	uint64_t gameid;
} A2SInfo;

typedef struct
{
	/** name of the player */
	char name[32];

	/** player's score (usually "frags" or "kills".) */
	int32_t score;

	/** time (in seconds) player has been connected to the server */
	float duration;
} A2SPlayer;

typedef struct
{
	char name[128];
	char value[256];
} A2SRules;

/**
 * Sets the recv/send timeout of a SourceServer's internal socket
 * @param server pointer to the SourceServer
 * @param sec	 number of seconds for the timeout
 * @param usec	 number of microseconds for the timeout
 */
void ssq_set_timeout(const SSQTimeout timeout, const long sec, const long usec);

/**
 * Sets the IPv4 address and port of the server to query
 * @param address IPv4 address of the server in decimal-dotted notation
 * @param port    the port number
 * @returns false if the address is invalid, true otherwise
 */
bool ssq_set_address(const char *const address, const uint16_t port);

/**
 * Sends an A2S_INFO query to a server
 * @param info pointer to the A2S_INFO struct where to store the server's information
 * @returns SSQ_OK if the query was successful
 */
SSQCode ssq_info(A2SInfo *const info);

/**
 * Sends an A2S_PLAYER query to a server
 * @param players pointer where to store the dynamically-allocated A2SPlayer array
 * @param count   pointer to store the number of players in `players`
 * @returns SSQ_OK if the query was successful
 */
SSQCode ssq_player(A2SPlayer **const players, byte *const count);

/**
 * Sends an A2S_RULES query to a server
 * @param rules pointer where to store the dynamically-allocated A2SRules array
 * @param count pointer to store the number of rules in `rules`
 * @returns SSQ_OK if the query was successful
 */
SSQCode ssq_rules(A2SRules **const rules, uint16_t *const count);

#endif // SSQ_H
