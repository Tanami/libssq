# libssq

## What is it ?

libssq is a C library for querying Source servers.

## How to use it

Up to this day, 3 different queries are supported :
- `A2S_INFO`: retrieves information about the server
- `A2S_PLAYER`: retrieves information about the players
- `A2S_RULES`: retrieves the server's rules

For more details, please refer to Valve's [server queries documentation](https://developer.valvesoftware.com/wiki/Server_queries).

## Issuing a query

Before we can issue any query, we must set a timeout for sending and receiving data as well as setting the
address of the server we would like to query.

```c
// setting a timeout

ssq_set_timeout(SSQ_TIMEOUT_SEND, 5, 0); // sets a 5s timeout for sending
ssq_set_timeout(SSQ_TIMEOUT_RECV, 5, 0); // sets a 5s timeout for receiving

// setting the server's address
ssq_set_address("xxx.xxx.xxx.xxx", 12345);
```

Once we set the timeout for both `SSQ_TIMEOUT_SEND` and `SSQ_TIMEOUT_RECV` as well as the address of the server
we would like to query, we can use the corresponding functions to issue any given query.

Here is an example using each supported query listed above

```c
#include <ssq.h>

#include <err.h>
#include <stdio.h>

int main()
{
    const char *address = "xxx.xxx.xxx.xxx";
    const uint16_t port = 27015;

    /**
     * initialization
     */

    // set the address of the server
    if (!ssq_set_address(address, port))
        errx(1, "invalid IPv4 address: %s", address);

    // set the send timeout to 5s
    ssq_set_timeout(SSQ_TIMEOUT_SEND, 5, 0);

    // set the recv timeout to 5s
    ssq_set_timeout(SSQ_TIMEOUT_SEND, 5, 0);


    SSQCode code; // result code of our function calls


    /**
     * sending an A2S_INFO query
     */

    A2SInfo info = {};

    if ((code = ssq_info(&info)) != SSQ_OK)
        errx(1, "A2S_INFO query failed: code %d", code);

    printf("Name: %s\n", info.name);
    printf("Players: %hhu/%hhu\n", info.players, info.max_players);

    // ...


    /**
     * sending an A2S_PLAYER query
     */

    A2SPlayer *players;
    uint8_t player_count;

    if ((code = ssq_player(&players, &player_count)) != SSQ_OK)
        errx(1, "A2S_PLAYER query failed: code %d", code);

    for (uint8_t i = 0; i < player_count; ++i)
    {
        printf("%s | score: %d | time connected: %fs\n", players[i].name, players[i].score, players[i].duration);
    }

    printf("\n");

    // ...

    free(players); // WARNING: must be freed


    /**
     * sending an A2S_RULES query
     */

     A2SRules *rules;
     uint16_t rules_count;

     if ((code = ssq_rules(&rules, &rules_count)) != SSQ_OK)
        errx(1, "A2S_RULES query failed: code %d", code);

    for (uint16_t i = 0; i < rules_count; ++i)
    {
        printf("%s = %s\n", rules[i].name, rules[i].value);
    }

    printf("\n");

    // ...

    free(rules); // WARNING: must be freed

    return 0;
}
```

## Dependencies

There are no dependencies for this project.

## Building

In order to build this library : clone this repository, and create a `build` folder.

From this folder, run `cmake ..` to generate the buildsystem.

Once the buildsystem is ready, run `cmake --build .` in order to build the library.

The resulting library will be static by default.

## Notice

This library is a personal project I've initiated in order to improve in the C programming language.

It is designed to work both under UNIX-like environment and Windows, however it was not fully tested yet.

Please be cautious if you plan to use this library, as it may have problems I have not yet noticed/unsupported features.
