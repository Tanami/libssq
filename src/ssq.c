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

#include "ssq.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
# include <winsock2.h>
#else
# include <netdb.h>
# include <unistd.h>
#endif // _WIN32

#define SSQ_PACKET_SIZE          1400

#define A2S_PACKET_HEADER_SINGLE -1
#define A2S_PACKET_HEADER_MULTI  -2

#define A2S_INFO                 "\xff\xff\xff\xff\x54Source Engine Query"
#define A2S_INFO_LEN             25

#define A2S_PLAYER               "\xff\xff\xff\xff\x55\xff\xff\xff\xff"
#define A2S_PLAYER_LEN           9

#define A2S_RULES                "\xff\xff\xff\xff\x56\xff\xff\xff\xff"
#define A2S_RULES_LEN            9

#define S2A_INFO                 0x49
#define S2A_PLAYER               0x44
#define S2A_RULES                0x45
#define S2A_CHALL                0x41

#define SSQ_CAST(type, ptr)      *((type *) (ptr))
#define SSQ_EXTRACT(dst)         memcpy(&(dst), resp + pos, sizeof (dst));  pos += sizeof (dst)
#define SSQ_EXTRACT_STR(dst)     dst = ssq_extract_str(resp + pos, &len); pos += len + 1

#define SSQ_SET_CODE(c)          if (code != NULL) *code = c

struct SSQHandle
{
    struct timeval   timeout_send;
    struct timeval   timeout_recv;
    struct addrinfo *addr_list;
};

struct SSQPacket
{
    int32_t  header;  /** The packet's header */
    int32_t  id;      /** Unique number assigned by server per answer */
    byte     total;   /** The total number of packets in the response */
    byte     number;  /** The number of the packet */
    uint16_t size;    /** The size of the payload */
    char    *payload; /** The packet's payload */
};

const struct SSQPacket *ssq_init_packet(const char buffer[], const size_t bytes_received, enum SSQCode *const code)
{
    struct SSQPacket *res = malloc(sizeof (*res));

    if (res == NULL)
    {
        SSQ_SET_CODE(SSQ_ALLOCATION_FAIL);
        return NULL;
    }

    size_t pos = 0;

    res->header = SSQ_CAST(int32_t, buffer + pos);
    pos         += sizeof (res->header);

    if (res->header == A2S_PACKET_HEADER_SINGLE)
    {
        res->number = 0;
        res->total  = 1;
        res->size   = bytes_received - sizeof (res->header);
    }
    else if (res->header == A2S_PACKET_HEADER_MULTI)
    {
        res->id     = SSQ_CAST(int32_t, buffer + pos);
        pos         += sizeof (res->id);

        res->total  = SSQ_CAST(byte, buffer + pos);
        pos         += sizeof (res->total);

        res->number = SSQ_CAST(byte, buffer + pos);
        pos         += sizeof (res->number);

        res->size   = SSQ_CAST(uint16_t, buffer + pos);
        pos         += sizeof (res->size);
    }
    else
    {
        free(res);
        return NULL;
    }

    res->payload = malloc(res->size);

    if (res->payload == NULL)
    {
        SSQ_SET_CODE(SSQ_ALLOCATION_FAIL);
        free(res);
        res = NULL;
    }
    else
    {
        memcpy(res->payload, buffer + pos, res->size);
    }

    return res;
}

void ssq_free_packet(const struct SSQPacket *const packet)
{
    free(packet->payload);
    free((void *) packet);
}

void ssq_free_packets(const struct SSQPacket **packets, const byte count)
{
    for (byte i = 0; i < count; ++i)
        ssq_free_packet(packets[i]);

    free((void *) packets);
}

const char *ssq_merge_packets(const struct SSQPacket *packets[], const byte count, size_t *const len, enum SSQCode *const code)
{
    *len = 0;

    // compute total length
    for (byte i = 0; i < count; ++i)
        *len += packets[i]->size;

    char *const res = calloc(*len, sizeof (*res));

    if (res != NULL)
    {
        size_t pos = 0;

        for (byte i = 0; i < count; ++i)
        {
            memcpy(res + pos, packets[i]->payload, packets[i]->size);
            pos += packets[i]->size;
        }
    }
    else
    {
        SSQ_SET_CODE(SSQ_ALLOCATION_FAIL);
    }

    return res;
}

const char *ssq_query(const struct SSQHandle *handle, const char payload[], const size_t payload_len, size_t *const len, enum SSQCode *const code)
{
    SSQ_SET_CODE(SSQ_OK);

    const struct SSQHandle *const hdl = handle;
    const struct addrinfo  *addr      = handle->addr_list;
    int                     sockfd    = -1;

    for (; addr != NULL; addr = addr->ai_next)
    {
        sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

        if (sockfd != -1)
            break;
    }

    const struct SSQPacket **packets      = NULL; // ordered array of pointers to packets in the response
    byte                     packet_count = 1;

    if (sockfd == -1)
    {
        SSQ_SET_CODE(SSQ_SOCKET_CREATION_FAIL);
    }
    else
    {
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &hdl->timeout_recv, sizeof (hdl->timeout_recv)) == -1 ||
            setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &hdl->timeout_send, sizeof (hdl->timeout_send)) == -1)
        {
            SSQ_SET_CODE(SSQ_SOCKET_CONFIG_FAIL);
        }
        else if (sendto(sockfd, payload, payload_len, 0, addr->ai_addr, addr->ai_addrlen) == -1)
        {
            SSQ_SET_CODE(SSQ_SOCKET_SENDTO_FAIL);
        }
        else
        {
            for (byte packets_received = 0; packets_received < packet_count; ++packets_received)
            {
                char          buffer[SSQ_PACKET_SIZE];

#ifdef _WIN32
                const int bytes_received = recvfrom(sockfd, buffer, SSQ_PACKET_SIZE, 0, NULL, NULL);
#else
                const ssize_t bytes_received = recvfrom(sockfd, buffer, SSQ_PACKET_SIZE, 0, NULL, NULL);
#endif // _WIN32

                if (bytes_received == -1)
                {
                    SSQ_SET_CODE(SSQ_SOCKET_RECVFROM_FAIL);

                    if (packets != NULL)
                    {
                        ssq_free_packets(packets, packet_count);
                        packets = NULL;
                    }

                    break;
                }

                const struct SSQPacket *const packet = ssq_init_packet(buffer, bytes_received, code);

                if (packet == NULL) // error in the received packet
                {
                    if (packets != NULL)
                    {
                        ssq_free_packets(packets, packet_count);
                        packets = NULL;
                    }

                    break;
                }
                else
                {
                    if (packets == NULL) // we received our first packet
                    {
                        // get the number of packets in the response
                        // and allocate some memory for each of them
                        packet_count = packet->total;
                        packets      = calloc(packet_count, sizeof (*packets));

                        if (packets == NULL)
                        {
                            SSQ_SET_CODE(SSQ_ALLOCATION_FAIL);
                            break;
                        }
                    }

                    // save the received packet at its corresponding slot
                    packets[packet->number] = packet;
                }
            }
        }

#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
    }

    const char *res = NULL;
    *len = 0;

    if (packets != NULL)
    {
        res = ssq_merge_packets(packets, packet_count, len, code);
        ssq_free_packets(packets, packet_count);
    }

    return res;
}

char *ssq_extract_str(const char src[], size_t *const len)
{
    *len = strlen(src);

    char *res = (char *) calloc(*len, sizeof (*res));

    if (res != NULL)
        memcpy(res, src, *len);

    return res;
}

bool ssq_payload_is_truncated(const char payload[])
{
    return SSQ_CAST(int32_t, payload) == A2S_PACKET_HEADER_SINGLE;
}

SSQHandle *ssq_init(const char hostname[], const uint16_t port, const time_t timeout)
{
    struct SSQHandle *res = malloc(sizeof (*res));

    if (res != NULL)
    {
        if (!ssq_set_address(res, hostname, port)) // invalid address
        {
            free(res);
            res = NULL;
        }
        else
        {
            ssq_set_timeout(res, SSQ_TIMEOUT_BOTH, timeout);
        }
    }

    return res;
}

bool ssq_set_address(SSQHandle *const handle, const char hostname[], const uint16_t port)
{
    struct SSQHandle *hdl = handle;
    char              service[16];

    if (hdl->addr_list != NULL)
        freeaddrinfo(hdl->addr_list);

    sprintf(service, "%hu", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof (hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    return getaddrinfo(hostname, service, &hints, &hdl->addr_list) == 0;
}

void ssq_set_timeout(SSQHandle *const handle, const enum SSQTimeout timeout, const time_t value)
{
    struct SSQHandle *const hdl = handle;

    if (timeout == SSQ_TIMEOUT_BOTH)
    {
        ssq_set_timeout(handle, SSQ_TIMEOUT_RECV, value);
        ssq_set_timeout(handle, SSQ_TIMEOUT_SEND, value);
    }
    else
    {
        struct timeval *const tv = (timeout == SSQ_TIMEOUT_RECV) ? &hdl->timeout_recv : &hdl->timeout_send;
        tv->tv_sec  = value / 1000;
        tv->tv_usec = value % 1000 * 1000;
    }
}

void ssq_free(const SSQHandle *const handle)
{
    const struct SSQHandle *const hdl = handle;
    freeaddrinfo(hdl->addr_list);
    free((void *) hdl);
}

struct A2SInfo *ssq_info(const SSQHandle *const handle, enum SSQCode *const code)
{
    char        req[A2S_INFO_LEN + 4] = A2S_INFO; // 4 additional bytes if a challenge number must be sent back
    size_t      resp_len;
    const char *resp                  = ssq_query(handle, req, A2S_INFO_LEN, &resp_len, code);

    if (resp == NULL)
        return NULL;

    while (SSQ_CAST(byte, resp) == S2A_CHALL)
    {
        // copy the challenge number
        memcpy(req + A2S_INFO_LEN, resp + 1, 4);

        free((void *) resp);
        resp = ssq_query(handle, req, A2S_INFO_LEN + 4, &resp_len, code);
    }

    struct A2SInfo *res = NULL;
    size_t          pos = 0;

    if (ssq_payload_is_truncated(resp))
        pos += 4;

    if (SSQ_CAST(byte, &resp[pos++]) == S2A_INFO)
    {
        res = malloc(sizeof (*res));

        if (res != NULL)
        {
            size_t len; // temporary variable to store extracted string lengths (used by SSQ_EXTRACT_STR macro)

            SSQ_EXTRACT(res->protocol);
            SSQ_EXTRACT_STR(res->name);
            SSQ_EXTRACT_STR(res->map);
            SSQ_EXTRACT_STR(res->folder);
            SSQ_EXTRACT_STR(res->game);
            SSQ_EXTRACT(res->id);
            SSQ_EXTRACT(res->players);
            SSQ_EXTRACT(res->max_players);
            SSQ_EXTRACT(res->bots);

            const byte server_type = SSQ_CAST(byte, resp + pos);
            switch (server_type)
            {
                case 'd':
                    res->server_type = SERVER_TYPE_DEDICATED;
                    break;

                case 'p':
                    res->server_type = SERVER_TYPE_SOURCETV_RELAY;
                    break;

                default: // 'l'
                    res->server_type = SERVER_TYPE_NON_DEDICATED;
                    break;
            }
            pos += sizeof (server_type);

            const byte environment = SSQ_CAST(byte, resp + pos);
            switch (environment)
            {
                case 'w':
                    res->environment = ENVIRONMENT_WINDOWS;
                    break;

                case 'm':
                case 'o':
                    res->environment = ENVIRONMENT_MAC;

                default: // 'l'
                    res->environment = ENVIRONMENT_LINUX;
                    break;
            }
            pos += sizeof (environment);

            SSQ_EXTRACT(res->visibility);
            SSQ_EXTRACT(res->vac);
            SSQ_EXTRACT_STR(res->version);

            if (pos < resp_len)
            {
                SSQ_EXTRACT(res->edf);
            }
            else
            {
                res->edf = 0;
            }

            if (res->edf & 0x80)
            {
                SSQ_EXTRACT(res->port);
            }

            if (res->edf & 0x10)
            {
                SSQ_EXTRACT(res->steamid);
            }

            if (res->edf & 0x40)
            {
                SSQ_EXTRACT(res->port_sourcetv);
                SSQ_EXTRACT_STR(res->name_sourcetv);
            }

            if (res->edf & 0x20)
            {
                SSQ_EXTRACT_STR(res->keywords);
            }

            if (res->edf & 0x01)
            {
                SSQ_EXTRACT(res->gameid);
            }
        }
        else
        {
            SSQ_SET_CODE(SSQ_ALLOCATION_FAIL);
        }
    }
    else
    {
        SSQ_SET_CODE(SSQ_MALFORMED_RESPONSE);
    }

    free((void *) resp);

    return res;
}

void ssq_free_info(const struct A2SInfo *const info)
{
    free(info->name);
    free(info->map);
    free(info->folder);
    free(info->game);
    free(info->version);

    if (info->edf & 0x40)
        free(info->name_sourcetv);

    if (info->edf & 0x20)
        free(info->keywords);

    free((void *) info);
}

struct A2SPlayer *ssq_player(const SSQHandle *const handle, byte *const count, enum SSQCode *const code)
{
    char        req[A2S_PLAYER_LEN] = A2S_PLAYER;
    size_t      resp_len;
    const char *resp                = ssq_query(handle, req, A2S_PLAYER_LEN, &resp_len, code);

    if (resp == NULL)
        return NULL;

    while (SSQ_CAST(byte, resp) == S2A_CHALL)
    {
        // copy the challenge number
        memcpy(req + A2S_PLAYER_LEN - 4, resp + 1, 4);

        free((void *) resp);
        resp = ssq_query(handle, req, A2S_PLAYER_LEN, &resp_len, code);

        if (resp == NULL)
            return NULL;
    }

    struct A2SPlayer *res = NULL;
    size_t            pos = 0;

    if (SSQ_CAST(byte, &resp[pos++]) == S2A_PLAYER)
    {
        SSQ_EXTRACT(*count);

        res = calloc(*count, sizeof (*res));

        if (res != NULL)
        {
            size_t len; // temporary variable to store extracted string lengths (used by SSQ_EXTRACT_STR macro)

            for (byte i = 0; i < *count; ++i)
            {
                pos += sizeof (byte); // skip 'Index'
                SSQ_EXTRACT_STR(res[i].name);
                SSQ_EXTRACT(res[i].score);
                SSQ_EXTRACT(res[i].duration);
            }
        }
        else
        {
            SSQ_SET_CODE(SSQ_ALLOCATION_FAIL);
        }
    }
    else
    {
        SSQ_SET_CODE(SSQ_MALFORMED_RESPONSE);
    }

    free((void *) resp);

    return res;
}

void ssq_free_players(const struct A2SPlayer players[], const byte count)
{
    for (byte i = 0; i < count; ++i)
        free(players[i].name);

    free((void *) players);
}

struct A2SRules *ssq_rules(const SSQHandle *const handle, uint16_t *const count, enum SSQCode *const code)
{
    char        req[A2S_RULES_LEN] = A2S_RULES;
    size_t      resp_len;
    const char *resp               = ssq_query(handle, req, A2S_RULES_LEN, &resp_len, code);

    if (resp == NULL)
        return NULL;

    while (SSQ_CAST(byte, resp) == S2A_CHALL)
    {
        // copy the challenge number
        memcpy(req + A2S_RULES_LEN - 4, resp + 1, 4);

        free((void *) resp);
        resp = ssq_query(handle, req, A2S_RULES_LEN, &resp_len, code);

        if (resp == NULL)
            return NULL;
    }

    struct A2SRules *res = NULL;
    size_t           pos = 0;

    if (ssq_payload_is_truncated(resp))
        pos += 4;

    if (SSQ_CAST(byte, &resp[pos++]) == S2A_RULES)
    {
        SSQ_EXTRACT(*count);

        res = calloc(*count, sizeof (*res));

        if (res != NULL)
        {
            size_t len; // temporary variable to store extracted string lengths (used by SSQ_EXTRACT_STR macro)

            for (uint16_t i = 0; i < *count; ++i)
            {
                SSQ_EXTRACT_STR(res[i].name);
                SSQ_EXTRACT_STR(res[i].value);
            }
        }
        else
        {
            SSQ_SET_CODE(SSQ_ALLOCATION_FAIL);
        }
    }
    else
    {
        SSQ_SET_CODE(SSQ_MALFORMED_RESPONSE);
    }

    free((void *) resp);

    return res;
}

struct A2SRules *ssq_get_rule(const char name[], struct A2SRules rules[], const uint16_t count)
{
    for (uint16_t i = 0; i < count; ++i)
    {
        if (strcmp(name, rules[i].name) == 0)
            return rules + i;
    }

    return NULL;
}

void ssq_free_rules(const struct A2SRules rules[], const uint16_t count)
{
    for (byte i = 0; i < count; ++i)
    {
        free(rules[i].name);
        free(rules[i].value);
    }

    free((void *) rules);
}