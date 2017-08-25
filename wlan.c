#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "common.h"

int wlan_receive(unsigned char* buf, int size)
{
	struct sockaddr_ll	ll;
	socklen_t	fromlen;
	int res;

	memset(&ll, 0, sizeof(ll));
	fromlen = sizeof(ll);

	res = recvfrom(rse_cb->w_ufd, buf, size, 0, (struct sockaddr*)&ll, &fromlen);
	if(res < 0)
	{
		return RESULT_FAIL;
	}

	return res;
}

int wlan_send(int fd, unsigned char *data, int len)
{
	int ret;

	if(!rse_cb || fd <= 0)
	{
		PRINT(ERROR, "wifi is not ready.!\n");
		return RESULT_FAIL;
	}

	ret = send(fd, data, len, 0);
	if(ret < 0)
	{
		PRINT(ERROR, "wifi send fail[%d][%s]\n", len, strerror(errno));
		return RESULT_FAIL;
	}

	return ret;
}

int wlan_usend(int fd, unsigned char* mac, unsigned char*  data, int len)
{
	int					ret;
	unsigned char		buffer[1600] = {0,};
	struct ether_header	*eh;
	unsigned int		eh_size = sizeof(struct ether_header);

	if (data == NULL)
	{
		PRINT(ERROR, "wlan_send: data==NULL\n");
		return RESULT_FAIL;
	}

	eh = (struct ether_header*)buffer;
	memcpy(eh->ether_dhost,mac,6);
	eh->ether_type = htons(UTIS_PROTOCOL);
	memcpy(buffer + eh_size, data,len);
	ret = send(fd, buffer, len + eh_size, 0);
	if (ret < 0)
	{
		PRINT(ERROR, "wlan_usend error[%s]\n", strerror(errno));
	}
	
	return ret;
}

int init_keytable(char *ktf)
{
	FILE				*fp;
	int					ret;
	int					len;
	unsigned char		buff[1024] = {0, }, notiBuff[1600];
	unsigned char		bcastMac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	unsigned char		notiMagic[4] = {'N','O','T','I'};
	utis_notify_msg_t	*pNoti = NULL;

	fp = fopen(ktf, "r");
	if(!fp)
	{
		PRINT(ERROR, "%s file open failed\n", ktf);
		return RESULT_FAIL;
	}

	while((len=fread(buff, 1, 1024, fp)) > 0)
	{
		memset(notiBuff, 0, 1600);
		pNoti = (utis_notify_msg_t*)notiBuff;
		strncpy(pNoti->ifName, UTISPORT_ALL, 5);
		memcpy(pNoti->da, bcastMac, ETHER_ALEN);
		pNoti->type = htons(UTIS_PROTOCOL);
		memcpy(pNoti->magic, notiMagic, 4);
		pNoti->arg1 = (len < 1024) ? len : 1024;
		memcpy(pNoti->data, buff, pNoti->arg1);
		pNoti->cmd = UTIS_NOTIFY_KEYTABLE;
		pNoti->black = 0;
		if(pNoti->arg1 < 1024) pNoti->black = 1;
		memcpy(pNoti->id, rse_cb->cfg.rse_id, RSE_ID_LEN);
		ret = wlan_send(rse_cb->w_ufd, notiBuff, (pNoti->arg1 + sizeof(utis_notify_msg_t)));
		if(ret == RESULT_FAIL) 
		{
			PRINT(ERROR, "keytable send error[%d]\n", ret);
			fclose(fp);
			return ret;
		}	
		PRINT(DEBUG, "send key table [%d]\n", ret);
	}

	fclose(fp);
	
	return RESULT_OK;
}

int init_secpolicy(char *sp_file)
{
	int					ret;
	int					len;
	FILE				*fp;
	unsigned char		buff[1024] = {0, }, notiBuff[1600];
	unsigned char		bcastMac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	unsigned char		notiMagic[4] = {'N','O','T','I'};
	utis_notify_msg_t	*pNoti = NULL;

	fp = fopen(sp_file, "r");
	if(!fp)
	{
		PRINT(ERROR, "%s file open failed\n", sp_file);
		return RESULT_FAIL;
	}

	len = fread(buff, 1, 17, fp);
	if(len != 17)
	{
		PRINT(ERROR, "security policy file size error\n");
		return RESULT_FAIL;
	}

	pNoti = (utis_notify_msg_t*)notiBuff;

	strncpy(pNoti->ifName,UTISPORT_MASTER,5);
	memcpy(pNoti->da, bcastMac, ETHER_ALEN);
	pNoti->type = htons(UTIS_PROTOCOL);
	memcpy(pNoti->magic, notiMagic, 4);
	pNoti->cmd = UTIS_NOTIFY_SECURITY_POLICY;
	pNoti->arg1 = 31;
	pNoti->black = 1;
	memcpy(pNoti->id, rse_cb->cfg.rse_id, RSE_ID_LEN);
	memcpy(pNoti->data, buff, 17);

	ret = wlan_send(rse_cb->w_ufd, notiBuff, sizeof(utis_notify_msg_t));
	if(ret == RESULT_FAIL) 
	{
		PRINT(ERROR, "keytable send error[%d]\n", ret);
		fclose(fp);
		return ret;
	}	
	PRINT(DEBUG, "send security policy [%d]\n", ret);

	fclose(fp);

	return RESULT_OK;
	
}

int create_wlan(char *ifname, unsigned short protocol)
{
	int fd = RESULT_FAIL;
	struct sockaddr_ll ll;
	struct ifreq ifr;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(fd <= 0)
	{
		PRINT(ERROR, "socket creation is failed[%s]\n", strerror(errno));
		goto create_wlan_bad;
	}

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("utisMac: ioctl[SIOCGIFINDEX]");
		goto create_wlan_bad;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(protocol);
	if (bind(fd, (struct sockaddr *) &ll, sizeof(ll)) < 0)
	{
		perror("utisMac:btask: bind");
		goto create_wlan_bad;
	}
	
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) 
	{
		perror("utisMac: ioctl[SIOCGIFHWADDR]");
		goto create_wlan_bad;
	}	

	return fd;

create_wlan_bad:
	if(fd != RESULT_FAIL) close(fd);	
	
	return RESULT_FAIL;
}

static int obe_handle_assoc(void* buff, size_t size)
{
	utis_notify_msg_t *noti = (utis_notify_msg_t*)buff;

	if(!add_obe(noti->sa, noti->id))
	{
		PRINT(INFO, "assoc obe[%02x%02x%02x%02x%02x%02x, %02x%02x%02x%02x%02x%02x%02x%02x]\n", 
			noti->sa[0], noti->sa[1], noti->sa[2], noti->sa[3], noti->sa[4], noti->sa[5],
			noti->id[0], noti->id[1], noti->id[2], noti->id[3], noti->id[4], noti->id[5],
			noti->id[6], noti->id[7]);
	} else
	{
		PRINT(INFO, "reassoc obe[%02x%02x%02x%02x%02x%02x, %02x%02x%02x%02x%02x%02x%02x%02x]\n",
			noti->sa[0], noti->sa[1], noti->sa[2], noti->sa[3], noti->sa[4], noti->sa[5],
			noti->id[0], noti->id[1], noti->id[2], noti->id[3], noti->id[4], noti->id[5],
			noti->id[6], noti->id[7]);
	}

#if 1
	struct listnode	*node = NULL;
	utis_obe_node_t	*item;

	PRINT(DEBUG, "------------------- sta list ----------------------\n");
	list_for_each(node, &rse_cb->obe_list)
	{
		item = node_to_item(node, utis_obe_node_t, list);
		if(!item) continue;

		PRINT(DEBUG, "list: obe[%02x%02x%02x%02x%02x%02x, %02x%02x%02x%02x%02x%02x%02x%02x]\n",
			item->mac[0], item->mac[1], item->mac[2], item->mac[3], item->mac[4], item->mac[5],
			item->id[0], item->id[1], item->id[2], item->id[3], item->id[4], item->id[5],
			item->id[6], item->id[7]);
	}
	PRINT(DEBUG, "-----------------------------------------------------\n");
#endif

	RseMsgToObeOp2000(noti->sa, noti->id);
	
	return RESULT_OK;
}

static int obe_handle_disassoc(void* buff, size_t size)
{
	utis_notify_msg_t *noti = (utis_notify_msg_t*)buff;

	if(!delete_obe(noti->sa))
	{
		PRINT(INFO, "disassoc obe[%02x%02x%02x%02x%02x%02x, %02x%02x%02x%02x%02x%02x%02x%02x]\n",
			noti->sa[0], noti->sa[1], noti->sa[2], noti->sa[3], noti->sa[4], noti->sa[5],
			noti->id[0], noti->id[1], noti->id[2], noti->id[3], noti->id[4], noti->id[5],
			noti->id[6], noti->id[7]);		
	} else
	{
		PRINT(INFO, "can't find obe for removing [%02x%02x%02x%02x%02x%02x, %02x%02x%02x%02x%02x%02x%02x%02x]\n", 
			noti->sa[0], noti->sa[1], noti->sa[2], noti->sa[3], noti->sa[4], noti->sa[5],
			noti->id[0], noti->id[1], noti->id[2], noti->id[3], noti->id[4], noti->id[5],
			noti->id[6], noti->id[7]);		
	}

#if 1
	struct listnode *node = NULL;
	utis_obe_node_t *item;

	PRINT(DEBUG, "------------------- sta list ----------------------\n");
	
	list_for_each(node, &rse_cb->obe_list)
	{
		item = node_to_item(node, utis_obe_node_t, list);
		if(!item) continue;

		PRINT(DEBUG, "list: obe[%02x%02x%02x%02x%02x%02x, %02x%02x%02x%02x%02x%02x%02x%02x]\n",
			item->mac[0], item->mac[1], item->mac[2], item->mac[3], item->mac[4], item->mac[5],
			item->id[0], item->id[1], item->id[2], item->id[3], item->id[4], item->id[5],
			item->id[6], item->id[7]);
	}
	PRINT(DEBUG, "-----------------------------------------------------\n");	
#endif
	
	return RESULT_OK;
}

static int obe_handle_reject(void* buff, size_t size)
{
	utis_notify_msg_t *noti = (utis_notify_msg_t*)buff;

	switch(noti->black)
	{
		case OBE_KEYINVALID :
			break;
		case OBE_OTHERFAIL :
			break;
		case OBE_NOTUTIS :
			break;
		case OBE_BLACKLIST :
			break;
		default:
			break;
	}

	return RESULT_OK;
}

static int obe_handle_pwe(void* buff, size_t size)
{
	PRINT(DEBUG, "obe password wrong\n");
	return RESULT_OK;
}

static int obe_handle_keytable(void* buff, size_t size)
{
	PRINT(DEBUG, "obe require to update keytable\n");
	return RESULT_OK;
}

void utis_wifi_handler_init(void)
{
	obe_handler_add(UTIS_NOTIFY_ASSOC,				obe_handle_assoc,		"obe assoc handler");
	obe_handler_add(UTIS_NOTIFY_DISASSOC,			obe_handle_disassoc,	"obe disassoc handler");
	obe_handler_add(UTIS_NOTIFY_KEYTABLE_UPDATE,	obe_handle_keytable,	"obe keytable handler");
	obe_handler_add(UTIS_NOTIFY_REJECT,				obe_handle_reject,		"obe assoc reject handler");
	obe_handler_add(UTIS_NOTIFY_PWE,				obe_handle_pwe,			"obe assoc pwe");
}


