#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <ssq.h>

void ssq_print_info(const A2SInfo *const info)
{
    printf("----- INFO BEGIN -----\n");

    printf("Protocol.......: %d\n", info->protocol);
    printf("Name...........: %s\n", info->name);
    printf("Map............: %s\n", info->map);
    printf("Folder.........: %s\n", info->folder);
    printf("Game...........: %s\n", info->game);
    printf("ID.............: %hu\n",info->id);
    printf("Players........: %hu/%hu (%hu bots)\n", info->players, info->max_players, info->bots);
    printf("Server type....: %s\n",
        ((info->server_type == SERVER_TYPE_DEDICATED)       ? "dedicated" :
        ((info->server_type == SERVER_TYPE_SOURCETV_RELAY)  ? "SourceTV relay (proxy)" : "non dedicated"))
    );
    printf("Environment....: %s\n",
        ((info->environment == ENVIRONMENT_WINDOWS) ? "windows" :
        ((info->environment == ENVIRONMENT_MAC)     ? "mac" : "linux"))
    );
    printf("Visibility.....: %s\n", ((info->visibility) ? "private" : "public"));
    printf("VAC............: %s\n", ((info->vac) ? "secured" : "unsecured"));
    printf("Version........: %s\n", info->version);

    if (info->edf & 0x80)
        printf("Port...........: %hu\n",    info->port);

    if (info->edf & 0x10)
        printf("SteamID........: %lu\n",    info->steamid);

    if (info->edf & 0x40)
    {
        printf("Port (SourceTV): %hu\n",    info->port_sourcetv);
        printf("Name (SourceTV): %s\n",     info->name_sourcetv);
    }

    if (info->edf & 0x20)
        printf("Keywords.......: %s\n",     info->keywords);

    if (info->edf & 0x01)
    printf("GameID.........: %lu\n",        info->gameid);

    printf("------ INFO END ------\n");
}

void ssq_print_players(const A2SPlayer players[], const byte player_count)
{
    for (byte i = 0; i < player_count; ++i)
    {
        printf("--- PLAYER %hhu BEGIN ---\n", i);
        printf("Name....: %s\n", players[i].name);
        printf("Score...: %d\n", players[i].score);
        printf("Duration: %f\n", players[i].duration);
        printf("---- PLAYER %hhu END ----\n", i);
    }
}

void ssq_print_rules(const A2SRules rules[], const byte rule_count)
{
    printf("----- RULES BEGIN -----\n");

    for (uint16_t i = 0; i < rule_count; ++i)
        printf("%s = %s\n", rules[i].name, rules[i].value);

    printf("------ RULES END ------\n");
}

int main(int argc, const char *argv[])
{
    if (argc != 3)
        errx(EXIT_FAILURE, "usage: %s hostname port", argv[0]);

    const char      *hostname   = argv[1];
    const uint16_t  port        = atoi(argv[2]);
    const SSQHandle *ssq;
    SSQCode         code;

    if ((ssq = ssq_init(hostname, port, 5000, &code)) == NULL)
        err(EXIT_FAILURE, "ssq_init: failed with code %d", code);


    /**
     * A2S_INFO
     */

    A2SInfo *info = ssq_info(ssq, &code);

    if (info == NULL)
        err(EXIT_FAILURE, "ssq_info: failed with code %d", code);

    ssq_print_info(info);

    ssq_free_info(info);


    /**
     * A2S_PLAYER
     */

    byte        player_count;
    A2SPlayer   *players = ssq_player(ssq, &player_count, &code);

    if (code != SSQ_OK)
        err(EXIT_FAILURE, "ssq_player: failed with code %d", code);

    ssq_print_players(players, player_count);

    ssq_free_players(players, player_count);


    /**
     * A2S_RULES
     */

    uint16_t    rule_count;
    A2SRules    *rules = ssq_rules(ssq, &rule_count, &code);

    if (code != SSQ_OK)
        err(EXIT_FAILURE, "ssq_rules: failed with code %d", code);

    ssq_print_rules(rules, rule_count);

    ssq_free_rules(rules, rule_count);


    ssq_free(ssq);

    return EXIT_SUCCESS;
}
