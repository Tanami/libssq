#ifndef SSQ_H
#define SSQ_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32

#include <WinSock2.h>

#else

#include <netinet/in.h>
#include <sys/socket.h>

#endif // _WIN32

#define SSQ_HOSTNAME_LEN 128

typedef uint8_t byte;

typedef enum
{
	SSQ_OK               = 0,
	SSQ_INVALID_ADDR     = 1,
	SSQ_SOCK_CREATE_FAIL = 2,
	SSQ_SOCK_SND_ERR     = 3,
	SSQ_SOCK_SND_TIMEOUT = 4,
	SSQ_SOCK_RCV_ERR     = 5,
	SSQ_SOCK_RCV_TIMEOUT = 6,
	SSQ_INVALID_RESP     = 7
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

	/** extra data flag */
	byte edf;

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

typedef struct
{
	/** internal socket recv timeout */
	struct timeval timeout_recv;

	/** internal socket send timeout */
	struct timeval timeout_send;

	/** hostname currently set */
	char hostname[SSQ_HOSTNAME_LEN];

	/** port number currently set */
	char port[8];
} SSQHandle;

/**
 * Sets the recv/send timeout of an SSQ handle
 * @param handle  pointer to the SSQ handle
 * @param timeout the timeout to set (send or recv)
 * @param millis  number of milliseconds for the timeout
 */
void ssq_set_timeout(SSQHandle *handle, const SSQTimeout timeout, const time_t millis);

/**
 * Sets the server address of an SSQ handle
 * @param handle   pointer to the SSQ handle
 * @param hostname address of the server to query
 * @param port     port number of the server to query
 */
void ssq_set_address(SSQHandle *handle, const char *hostname, const uint16_t port);

/**
 * Sends an A2S_INFO query to a server
 * @param handle pointer to the SSQ handle to use
 * @param info   pointer to the A2S_INFO struct where to store the server's information
 * @returns SSQ_OK if the query was successful
 */
SSQCode ssq_info(SSQHandle *handle, A2SInfo *info);

/**
 * Sends an A2S_PLAYER query to a server
 * @param handle  pointer to the SSQ handle to use
 * @param players pointer where to store the dynamically-allocated A2SPlayer array
 * @param count   pointer to store the number of players in `players`
 * @returns SSQ_OK if the query was successful
 */
SSQCode ssq_player(SSQHandle *handle, A2SPlayer **players, byte *count);

/**
 * Sends an A2S_RULES query to a server
 * @param handle pointer to the SSQ handle to use
 * @param rules  pointer where to store the dynamically-allocated A2SRules array
 * @param count  pointer to store the number of rules in `rules`
 * @returns SSQ_OK if the query was successful
 */
SSQCode ssq_rules(SSQHandle *handle, A2SRules **rules, uint16_t *count);

/**
 * Searches for the rule with the provided name among an array of A2SRules
 * @param name  name of the rule to search for
 * @param rules array of A2SRules
 * @param count number of rules in the array
 * @returns NULL if no rule with the provided name was found, a pointer to the rule otherwise
 */
A2SRules *ssq_get_rule(const char *name, A2SRules *rules, const byte count);

#endif // SSQ_H
