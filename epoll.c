#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "common.h"

void* epoll_events(void *args)
{
	int					ret;
	int 				efd;
	int 				i=0;
	int 				len, evt_cnt;
	struct epoll_event	ev, evlist[10];
	unsigned char		buff[1600];


retry_intf:
	if(rse_cb->w_ufd <= 0 || rse_cb->ifd <= 0)
	{
		PRINT(ERROR, "it's not ready to run\n");
		sleep(1);
		goto retry_intf;
	}

	efd = epoll_create(5);
	if(efd == -1)
	{
		PRINT(ERROR, "epoll create failed.\n");
		return NULL;
	}

	ev.events = EPOLLIN;
	ev.data.fd = rse_cb->w_ufd;

	ret = epoll_ctl(efd, EPOLL_CTL_ADD, rse_cb->ifd, &ev);
	if(ret == -1)
	{
		PRINT(ERROR, "inet fd add failed.\n");
		return NULL;
	}

	
	ret = epoll_ctl(efd, EPOLL_CTL_ADD, rse_cb->w_ufd, &ev);
	if(ret == -1)
	{
		PRINT(ERROR, "inet fd add failed.\n");
		return NULL;
	}

	PRINT(INFO, "wait event..\n");

	while(1)
	{
		evt_cnt = epoll_wait(efd, evlist, 10, 10);
		if(evt_cnt == -1)
		{
			if(errno == EINTR) continue;
			else
			{
				PRINT(ERROR, "epoll_wait error\n");
				return NULL;
			}
		}

		if(evt_cnt == 0) continue;

		for(i=0;i<evt_cnt;i++)
		{
			if( (evlist[i].events & EPOLLERR) ||
				(evlist[i].events & EPOLLHUP) ||
				(!(evlist[i].events & EPOLLIN)))
			{
				close(evlist[i].data.fd);
				continue;
			}
			else if(evlist[i].data.fd == rse_cb->ifd)
			{
				PRINT(DEBUG, "inet event..\n");
			}
			else if(evlist[i].data.fd == rse_cb->w_ufd)
			{
				utis_notify_msg_t	*noti;
				
				len = wlan_receive(buff, 1600);
				if(len == RESULT_FAIL)
				{
					PRINT(ERROR, "wlan receive fail.\n");
					continue;
				}

				noti = (utis_notify_msg_t *)buff;
				if(noti->type != UTIS_PROTOCOL)
				{
					PRINT(ERROR, "it's not UTIS PROTOCOL\n");
					continue;
				}

				if(!strncmp(noti->magic, "NOTI", 4))
				{
					if(noti_handler(buff, len) == RESULT_FAIL)
					{
						PRINT(ERROR, "utis handle error\n");
						continue;
					}
				}
				else if(!strncmp(noti->magic, "UTIS", 4))
				{
					if(utis_handler(buff, len) == RESULT_FAIL)
					{
						PRINT(ERROR, "utis handle error\n");
						continue;
					}
				}
				else
				{
					PRINT(ERROR, "unknown magic[%s]\n", noti->magic);
					continue;
				}
			}
		}

		memset(buff, 0, 1432);
	}

	return NULL;
}

