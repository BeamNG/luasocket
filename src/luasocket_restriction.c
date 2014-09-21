#include "luasocket_restriction.h"

typedef struct luasocket_ip_parsed_t {
    char ipb[4];
} luasocket_ip_parsed_t;

int parseIPString(const char* ip_str, luasocket_ip_parsed_t* ip) {
    return sscanf(ip_str, "%d.%d.%d.%d", &ip->ipb[0], &ip->ipb[1], &ip->ipb[2], &ip->ipb[3]) == 4 ? 0 : 1;
}

int isIPAllowed(luasocket_ip_parsed_t* ip)
{
    // see also http://en.wikipedia.org/wiki/Private_network

    // 127.0.0.1 - localhost
    if (ip->ipb[0] == 127 && ip->ipb[1] == 0 && ip->ipb[2] == 0 && ip->ipb[3] == 1)
        return 0;

    // 10.0.0.0/8 (255.0.0.0)
    if (ip->ipb[0] == 10)
        return 0;

    // 172.16.0.0/12 (255.240.0.0)
    if (ip->ipb[0] == 172 && ip->ipb[1] >= 16 && ip->ipb[1] <= 31)
        return 0;

    // 192.168.0.0/16 (255.255.0.0)
    if (ip->ipb[0] == 192 && ip->ipb[1] == 168)
        return 0;

    // TODO: add server public IP HERE

    // else, public, deny
    return 1;
}

int luasocket_ip_allowed(const char* hoststr)
{
    if (!hoststr)
        return 1;
    
    // allow localhost
    if(strcmp(hoststr, "localhost") == 0) {
        return 0;
    }
    
    //FILE *dfo = fopen("luasocket.debug.txt", "a");
    luasocket_ip_parsed_t ip_parsed;
    int parse_res = parseIPString(hoststr, &ip_parsed);
    if (parse_res) {
        //if(dfo) fprintf(dfo, "unable to parse IP: %s - DENIED\n", hoststr);
        //if(dfo) fclose(dfo);
        return 2;
    }

    int res = isIPAllowed(&ip_parsed);
    //if(dfo) fprintf(dfo, "%s [%d.%d.%d.%d] - %s\n", hoststr, ip_parsed.ipb[0], ip_parsed.ipb[1], ip_parsed.ipb[2], ip_parsed.ipb[3], res == 0 ? "ALLOWED" : "DENIED");
    //if(dfo) fclose(dfo);
    return res;
}
