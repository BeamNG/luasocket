#pragma once

// you need to define that in the application you link luasocket with
extern int luasocket_ip_allowed(const char* hoststr);


#ifndef LUASOCKET_SANDBOX_EXTERNAL
#include <stdio.h>

int luasocket_ip_is_private(char* ip)
{
    // see also http://en.wikipedia.org/wiki/Private_network

    // 127.0.0.1 - localhost
    if (ip[0] == 127 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1)
        return 0;

    // 10.0.0.0/8 (255.0.0.0)
    if (ip[0] == 10)
        return 0;

    // 172.16.0.0/12 (255.240.0.0)
    if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31)
        return 0;

    // 192.168.0.0/16 (255.255.0.0)
    if (ip[0] == 192 && ip[1] == 168)
        return 0;

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
    
    char ip[4] = {0,0,0,0};
    int parse_res = sscanf(hoststr, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
    if (parse_res != 4) {
        printf("unable to parse IP: %s - DENIED\n", hoststr);
        return 2;
    }

    int res = luasocket_ip_is_private(ip);
    printf("%s [%d.%d.%d.%d] - %s\n", hoststr, ip[0], ip[1], ip[2], ip[3], res == 0 ? "ALLOWED" : "DENIED");
    return res;
}

#endif // LUASOCKET_SANDBOX_EXTERNAL