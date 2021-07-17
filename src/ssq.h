/**
 * MIT License
 * Copyright (c) 2021 BinaryAlien
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef SSQ_H
#define SSQ_H

#include <stdbool.h>
#include <stdint.h>

#ifdef _WIN32
# include <ws2tcpip.h>
#else
# include <sys/types.h>
#endif // _WIN32

typedef uint8_t byte;

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

enum SSQCode
{
    SSQ_OK                      = 0,
    SSQ_SOCKET_CREATION_FAIL    = 1,
    SSQ_SOCKET_SENDTO_FAIL      = 2,
    SSQ_SOCKET_RECVFROM_FAIL    = 3,
    SSQ_SOCKET_CONFIG_FAIL      = 4,
    SSQ_MALFORMED_RESPONSE      = 5,
    SSQ_ALLOCATION_FAIL         = 6
};

enum SSQTimeout
{
    SSQ_TIMEOUT_RECV = 0,
    SSQ_TIMEOUT_SEND = 1,
    SSQ_TIMEOUT_BOTH = 2
};

enum A2SServerType
{
    SERVER_TYPE_DEDICATED      = 'd',
    SERVER_TYPE_NON_DEDICATED  = 'l',
    SERVER_TYPE_SOURCETV_RELAY = 'p'
};

enum A2SEnvironment
{
    ENVIRONMENT_LINUX   = 'l',
    ENVIRONMENT_WINDOWS = 'w',
    ENVIRONMENT_MAC     = 'm'
};

struct A2SInfo
{
    byte                protocol;      /** Protocol version used by the server */
    char               *name;          /** Name of the server */
    char               *map;           /** Map the server has currently loaded */
    char               *folder;        /** Name of the folder containing the game files */
    char               *game;          /** Full name of the game */
    uint16_t            id;            /** Steam Application ID of game */
    byte                players;       /** Number of players on the server */
    byte                max_players;   /** Maximum number of players the server reports it can hold */
    byte                bots;          /** Number of bots on the server */
    enum A2SServerType  server_type;   /** The type of server */
    enum A2SEnvironment environment;   /** The operating system of the server */
    bool                visibility;    /** Whether the server requires a password */
    bool                vac;           /** Whether the server uses VAC */
    char               *version;       /** Version of the game installed on the server */
    byte                edf;           /** Extra Data Flags */
    uint16_t            port;          /** The server's game port number */
    uint64_t            steamid;       /** Server's SteamID */
    uint16_t            port_sourcetv; /** Spectator port number for SourceTV */
    char               *name_sourcetv; /** Name of the spectator server for SourceTV */
    char               *keywords;      /** Tags that describe the game according to the server */
    uint64_t            gameid;        /** The server's 64-bit GameID */
};

struct A2SPlayer
{
    char   *name;     /** Name of the player */
    int32_t score;    /** Player's score (usually "frags" or "kills") */
    float   duration; /** Time (in seconds) player has been connected to the server */
};

struct A2SRules
{
    char *name;  /** Name of the rule */
    char *value; /** Value of the rule */
};

typedef void SSQHandle;

SSQHandle        *ssq_init(const char hostname[], const uint16_t port, const time_t timeout);                  /** Initializes an SSQ handle */
bool              ssq_set_address(SSQHandle *const handle, const char hostname[], const uint16_t port);        /** Resets the target address of an SSQ handle */
void              ssq_set_timeout(SSQHandle *const handle, const enum SSQTimeout timeout, const time_t value); /** Sets the sendto/recvfrom timeout of an SSQ handle */
void              ssq_free(const SSQHandle *const handle);                                                     /** Frees resources allocated by an SSQ handle */
struct A2SInfo   *ssq_info(const SSQHandle *const handle, enum SSQCode *const code);                           /** Sends an A2S_INFO query using the provided SSQ handle */
void              ssq_free_info(const struct A2SInfo *const info);                                             /** Frees resources allocated by an A2S_INFO struct */
struct A2SPlayer *ssq_player(const SSQHandle *const handle, byte *const count, enum SSQCode *const code);      /** Sends an A2S_PLAYER query using the provided SSQ handle */
void              ssq_free_players(const struct A2SPlayer players[], const byte count);                        /** Frees an A2S_PLAYER array */
struct A2SRules  *ssq_rules(const SSQHandle *const handle, uint16_t *const count, enum SSQCode *const code);   /** Sends an A2S_RULES query using the provided SSQ handle */
struct A2SRules  *ssq_get_rule(const char name[], struct A2SRules rules[], const uint16_t count);              /** Finds a rule by its name among an array of A2S_RULES */
void              ssq_free_rules(const struct A2SRules rules[], const uint16_t count);                         /** Frees an A2S_RULES array */

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // SSQ_H