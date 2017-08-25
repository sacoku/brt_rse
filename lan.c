#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "common.h"

int create_inet_udp(int port, int nb)
{
	int					sock;
	int					reuse = 1;
	struct sockaddr_in	addr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &reuse, sizeof(reuse)) == -1)
	{
		PRINT(ERROR, "error socket option : REUSEADDR");
		return RESULT_FAIL;
	}

	if(nb)
	{
		if(make_socket_non_blocking (sock) == -1)
		{
			return RESULT_FAIL;
		}
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons((unsigned short)port);

	if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1)
	{
		PRINT(ERROR, "socket bind fail - err:%d\n", errno);
		return RESULT_FAIL;
	}

	return sock;
}

