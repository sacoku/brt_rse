#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

static utis_primitive_node_t *utis_primitive_table[OBE_HANDLER_HASH_SIZE];

static int obe_handler_hash_func(unsigned short opcode)
{
	return (opcode % OBE_HANDLER_HASH_SIZE);
}

static int obe_handle_0x0001(void* buff, size_t size)
{
	return RESULT_OK;
}

static int obe_handle_0x0002(void* buff, size_t size)
{
	return RESULT_OK;
}

static int obe_handle_0x0003(void* buff, size_t size)
{
	return RESULT_OK;
}

static int obe_handle_0x0015(void* buff, size_t size)
{
	return RESULT_OK;
}

static int obe_handle_0x3000(void* buff, size_t size)
{
	RseMsgAckToObe(buff);
	
	return RESULT_OK;
}

static int obe_handle_0x3001(void* buff, size_t size)
{
	return RESULT_OK;
}

static int obe_handle_0xf010(void* buff, size_t size)
{
	return RESULT_OK;
}

static int obe_handle_0x2001(void* buff, size_t size)
{
	return RESULT_OK;
}


void init_obe()
{
	list_init(&rse_cb->obe_list);
}

struct listnode* find_obe(unsigned char *mac)
{
	struct listnode	*node = NULL;
	utis_obe_node_t	*item;
	
	list_for_each(node, &rse_cb->obe_list)
	{
		item = node_to_item(node, utis_obe_node_t, list);
		if(!item) continue;
		if(!memcmp(item->mac, mac, ETHER_ALEN))
		{
			return node;
		}
	}

	return NULL;
}

int add_obe(unsigned char *mac, unsigned char *id)
{
	struct listnode *node;
	utis_obe_node_t	*item;

	node = find_obe(mac);
	if(node)
		return RESULT_FAIL;
	
	item = malloc(sizeof(utis_obe_node_t));

	memcpy(item->mac, mac, ETHER_ALEN);
	memcpy(item->id, id, OBE_ID_LEN);
	time(&item->t_assoc);

	list_add_tail(&rse_cb->obe_list, &item->list);

	return RESULT_OK;
}

int delete_obe(unsigned char *mac)
{
	struct listnode	*node;

	node = find_obe(mac);
	if(node != NULL)
	{
		list_remove(node);
		return RESULT_OK;
	}

	return RESULT_FAIL;
}

int obe_handler_add(unsigned short pid, handler func, char* desc)
{
	int hash_val;
    utis_primitive_node_t *new_primitive;
    new_primitive = malloc(sizeof (utis_primitive_node_t));

    if (new_primitive == NULL) 
    {
        return (RESULT_FAIL);
    }

    hash_val = obe_handler_hash_func(pid);
    new_primitive->pid = pid;
    new_primitive->func = func;
    new_primitive->desc = strdup(desc);

    if( new_primitive->desc==0 ) {
        perror("utis_primitive_add : malloc fail : ");

        if(new_primitive != 0x00){
            free(new_primitive) ;
            new_primitive = 0x00 ;
        }
        return 0;
    }
    
    new_primitive->next = utis_primitive_table[hash_val];
    utis_primitive_table[hash_val] = new_primitive;

    return (RESULT_OK);
}

utis_primitive_node_t* utis_primitive_get(unsigned short pid)
{
	int hash_val;
	utis_primitive_node_t *current;
	
	hash_val = obe_handler_hash_func(pid);

	current = utis_primitive_table[hash_val];
	while (current != NULL)
	{
		if (current->pid == pid) break;
		current = current->next;
	}

	return (current);
}

void utis_obe_handler_init(void)
{
	obe_handler_add(CONNECT_REQ,					obe_handle_0x0001,		"other device connect req handler");
	obe_handler_add(CONNECT_CONFM,					obe_handle_0x0002,		"other device connect confirm handler");
	obe_handler_add(CONNECT_VRFY,					obe_handle_0x0003,		"other device connect verify handler");
	obe_handler_add(LOCAL_SERVICE_BRDREQ,			obe_handle_0x0015,		"brocast req handler");

	obe_handler_add(SERVICE_INFO_SEND,				obe_handle_0x3000,		"other service to obe handler");
	obe_handler_add(SERVICE_INFO_SEND_OBE,			obe_handle_0x3001,		"other service from obe handler");
	obe_handler_add(BRT_SEND_PPC_INFO,				obe_handle_0xf010,		"brt broadcast req handler");
	obe_handler_add(COLLINFO_UPLOAD,				obe_handle_0x2001,		"coll traffic upload");
}

int noti_handler(unsigned char *buff, int len)
{
	utis_primitive_node_t	*node = NULL;
	utis_notify_msg_t		*noti = (utis_notify_msg_t*)buff;

	node = utis_primitive_get(noti->cmd);
	if(!node)
	{
		PRINT(ERROR, "handler is not exist\n");
		return RESULT_FAIL;
	}

	return node->func(buff, len);
}

int utis_handler(unsigned char *buff, int len)
{
	MU						*updu;
	utis_primitive_node_t	*utis_p;
	utis_notify_msg_t		*noti = (utis_notify_msg_t*)buff;
	IPCMU					*ipcmu = malloc(sizeof(IPCMU));
	struct listnode			*node;
	utis_obe_node_t			*obe;

	updu = (MU*)noti->magic;

	node = find_obe(noti->sa);
	if(node)
	{
		return RESULT_FAIL;
	}
	obe = node_to_item(node, utis_obe_node_t, list);
	
	memset(ipcmu, 0, sizeof(IPCMU));
	ipcmu->Primitive = updu->OpCode;
	memcpy(ipcmu->OBE_ID, obe->id, OBE_ID_LEN);
	memcpy(ipcmu->MAC, obe->mac, ETHER_ALEN);
	ipcmu->mu = updu;
	ipcmu->IPCLength = len;

	if(LibMUGetAckBitCheck(ipcmu->mu) != RESULT_OK) 
	{
		if(LibMUCrcCheck(ipcmu->mu) == RESULT_OK)
		{
			utis_p = utis_primitive_get(ipcmu->mu->OpCode);
		}
		else
		{
			utis_p = NULL;
		}
	}
	else
	{
		utis_p = NULL;
	}

	if (utis_p == NULL)
	{
		if(LibMUGetAckBitCheck(ipcmu->mu) == RESULT_OK) 
		{
			PRINT(INFO, "Received ACK OPCODE : 0x%04x \n", ipcmu->mu->OpCode);
		}
		else
		{
			PRINT(ERROR, "Unknown primitive received. pid = 0x%04x\n", ipcmu->mu->OpCode);
		}
	}
	else
	{
			(utis_p->func)(ipcmu, len);
	}
	return RESULT_OK;
}
