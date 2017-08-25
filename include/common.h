#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/types.h>
#include <linux/limits.h>
#include <malloc.h>
#include <memory.h>
#include <stdint.h>
#include <zlog.h>
#include <time.h>
#include "list.h"

#define RESULT_OK				0
#define RESULT_FAIL				-1
#define RSE_ID_LEN				8
#define OBE_ID_LEN				8
#define ETHER_ALEN				6
#define UTIS_PROTOCOL			0x88B6
#define UTIS_BCAST_PROTOCOL		0xeeee
#define OBE_HANDLER_HASH_SIZE	20

#define CFG_FILE_PATH			"/ffs/brt/rse.json"

#define CRYPTO_DEV				"/dev/kcrypto"
#define CRYPTO_ENC				1 //_IOWR('c', 0x80, char)
#define CRYPTO_DEC				2 //_IOWR('c', 0x81, char)
#define VENDOR_PASSWORD_KEY		"uy7rrY7wq10LjjY0"

#if 0
#define PRIM_ASSOC              0xfe01
#define PRIM_DISASSOC           0xfe02
#define PRIM_KEYTABLE           0xfe03
#define PRIM_RFINFO             0xfe04
#define PRIM_BLACKLIST          0xfe05
#define PRIM_SECURITY_POLICY    0xfe06
#define PRIM_ASSOC_REJECT       0xfe07
#define PRIM_CHANNEL            0xfe08
#define PRIM_DUMP               0xfe10
#else
#define UTIS_NOTIFY_BASE				0x10
#define UTIS_NOTIFY_ASSOC				(UTIS_NOTIFY_BASE + 1)
#define UTIS_NOTIFY_DISASSOC			(UTIS_NOTIFY_BASE + 2)
#define UTIS_NOTIFY_REJECT				(UTIS_NOTIFY_BASE + 3)
#define UTIS_NOTIFY_KEYTABLE			(UTIS_NOTIFY_BASE + 4)
#define UTIS_NOTIFY_BLACKLIST			(UTIS_NOTIFY_BASE + 5)
#define UTIS_NOTIFY_OLD					(UTIS_NOTIFY_BASE + 6)
#define UTIS_NOTIFY_SECURITY_POLICY		(UTIS_NOTIFY_BASE + 7)
#define UTIS_NOTIFY_KEYTABLE_UPDATE		(UTIS_NOTIFY_BASE + 8)/*OBE*/
#define UTIS_NOTIFY_SETKEY				(UTIS_NOTIFY_BASE + 9)
#define UTIS_NOTIFY_DELKEY				(UTIS_NOTIFY_BASE + 10)
#define UTIS_NOTIFY_PWE					(UTIS_NOTIFY_BASE + 11)/*OBE*/
#define UTIS_NOTIFY_ECHO				(UTIS_NOTIFY_BASE + 12)
#define UTIS_NOTIFY_KICKOFF				(UTIS_NOTIFY_BASE + 13) /*20091010*/
#endif

#define CONNECT_REQ						0x0001
#define CONNECT_CONFM					0x0002
#define CONNECT_VRFY					0x0003
#define LOCAL_SERVICE_BRDREQ			0x0015
#define COLLINFO_UPLOADORD				0x2000
#define COLLINFO_UPLOAD					0x2001
#define SERVICE_INFO_SEND				0x3000
#define SERVICE_INFO_SEND_OBE			0x3001
#define BRT_SEND_PPC_INFO				0xf010


#define MAX_KEY_TABLE			1

#define INIT_LOGGER(cfg)			\
{									\
	zlog_init(cfg);					\
	c = zlog_get_category("rse");	\
}

#define CLOSE_LOGGER()		zlog_fini();

#define INFO		ZLOG_LEVEL_INFO
#define DEBUG		ZLOG_LEVEL_DEBUG
#define ERROR		ZLOG_LEVEL_ERROR
#define WARN		ZLOG_LEVEL_WARN

//#define PRINT(level, fmt, args...) do { printf("[%20s:%04d] "fmt, __FUNCTION__, __LINE__, ##args); } while(0);

#define PRINT(level, fmt, args...) 			\
	zlog(c, __FILE__, sizeof(__FILE__)-1,	\
	__func__, sizeof(__func__)-1, __LINE__,	\
	level, fmt, ##args)

/*
	CODE BIT 
*/
#define CODE_ACK_BIT		0x8000
#define CODE_EMG_BIT		0x4000
#define CODE_RSV_BIT		0x2000
#define CODE_ENC_BIT		0x1000
#define CODE_RPR_BIT		0x0800
#define CODE_REP_BIT		0x0400
#define CODE_BID_BIT		0x0200
#define CODE_CHK_BIT		0x0100
#define CODE_PLD_BIT		0x0001

#define IPCMU_HEADER_SIZE	16

#define PROTOCOL_VERSION	0x01

#define DEVICE_CNS		0x00
#define DEVICE_OBE		0x40
#define DEVICE_STA		0x41
#define DEVICE_RSE		0x80

#define HEADER_BASE_SIZE	28
#define HEADER_PKTID_SIZE	4
#define HEADER_BCAST_SIZE	4
#define HEADER_CHKSUM_SIZE	4

#define IETYPE_1			1
#define IETYPE_2			2
#define IETYPE_3			4

#define IETYPE_1_SIZE		2
#define IETYPE_2_SIZE		3
#define IETYPE_3_SIZE		5	

#define IETYPE_1_VALUE		0x40
#define IETYPE_2_VALUE		0x8000
#define IETYPE_3_VALUE		0x00000000


#define EID_H00			0x00
#define EID_H0E			0x0E
#define EID_H04			0x04




#define MU_HDR_HAS_ACK(m) (m->Code & 0x8000)
#define MU_HDR_HAS_REQID(m) (m->Code & 0x0400)
#define MU_HDR_HAS_BCASTID(m) (m->Code & 0x0200)
#define MU_HDR_HAS_CHECKSUM(m) (m->Code & 0x0100)

typedef enum
{
	MSG_TYPE_P  = 1,   
	MSG_TYPE_R  = 2,
	MSG_TYPE_RP = 3,   
	MSG_TYPE_B  = 4,
	MSG_TYPE_BP = 5,   
	MSG_TYPE_RB = 6,
	MSG_TYPE_RBP = 7,  
	MSG_TYPE_C = 8,
	MSG_TYPE_CP = 9,   
	MSG_TYPE_RC = 10,
	MSG_TYPE_RCP = 11, 
	MSG_TYPE_BC = 12,
	MSG_TYPE_BCP = 13, 
	MSG_TYPE_RBC = 14,
	MSG_TYPE_RBCP = 15,

	MSG_TYPE_IPCMU = 100,
	MSG_TYPE_MU	= 101,
	MSG_TYPE_UNKNOWN   
} ENUM_MSG_TYPE;

typedef enum
{
	FIELD_P = 1,
	FIELD_R = 2,
	FIELD_B = 4,
	FIELD_C = 8 
} ENUM_FIELD_TYPE;

typedef int (*handler)(void *, size_t);

typedef struct utis_primitive_node
{
	unsigned short				pid;
	handler						func;
	char						*desc;
	struct utis_primitive_node	*next;
} utis_primitive_node_t;

typedef struct utis_obe_node
{
	unsigned char	id[OBE_ID_LEN];
	unsigned char	mac[ETHER_ALEN];
	time_t			t_assoc;

	struct listnode	list;
} utis_obe_node_t;

union var
{
	struct 
	{
		unsigned char Payload[12];
	} P;
	struct
	{
		unsigned int Checksum;
		unsigned char Payload[8];
	} CP;
	struct
	{
		unsigned int Bcast_ID;
		unsigned char Payload[8];
	} BP;
	struct 
	{
		unsigned int Bcast_ID;
		unsigned int Checksum;
		unsigned char Payload[4];
	} BCP;
	struct
	{
		unsigned int Req_ID;
		unsigned char Payload[8];
	} RP;
	struct
	{
		unsigned int Req_ID;
		unsigned int Checksum;
		unsigned char Payload[4];
	} RCP;
	struct
	{
		unsigned int Req_ID;
		unsigned int Bcast_ID;
		unsigned char Payload[4];
	} RBP;
	struct 
	{
		unsigned int Req_ID;
		unsigned int Bcast_ID;
		unsigned int Checksum;
		unsigned char Payload[0];
	} RBCP;
	struct 
	{
		unsigned int words[3];
	} Raw;
} __attribute__ ((packed));

typedef union var VAR;

struct mu
{
	unsigned char   MagicNumber1;
	unsigned char   MagicNumber2;
	unsigned char   MagicNumber3;
	unsigned char   MagicNumber4;
	unsigned char   Ptcol_Ver;
	unsigned char   Hdr_Length;
	unsigned short  Hdr_Crc;
	unsigned short  Code;
	unsigned short  OpCode;
	unsigned char   From;
	unsigned char   To;
	unsigned int    PacketID;
	unsigned int    Length;
	unsigned int    Offset;
	unsigned short  Frag_Plen;

	VAR Var;
} __attribute__ ((packed));

typedef struct mu MU;

struct ipcmu
{
	unsigned short  Primitive;
	unsigned char   OBE_ID[8];
	unsigned char   MAC[6];
	unsigned char   Priority;
	unsigned char   Temp;
	unsigned int    IPCLength;

	MU *mu;
} __attribute__ ((packed)); 

typedef struct ipcmu IPCMU;

struct eidHdrProto
{
	unsigned char eid;
	unsigned char size_m:1;
	unsigned char size_s:1;
	unsigned char size_l:6;
	unsigned char data[0];
} __attribute__ ((packed)); 

typedef struct eidHdrProto eidHdrProto_t;

struct eidHdrType1
{
	unsigned char eid;
	unsigned char size_m:1;
	unsigned char size_s:1;
	unsigned char size_l:6;
	unsigned char data[0];
} __attribute__ ((packed)); 

typedef struct eidHdrType1 eidHdrType1_t;

struct eidHdrType2
{
	unsigned char eid;
	unsigned short size_m:1;
	unsigned short size_s:1;
	unsigned short size_l:14;
	unsigned char data[0];
} __attribute__ ((packed));

typedef struct eidHdrType2 eidHdrType2_t;

struct eidHdrType3
{
	unsigned char eid;
	unsigned int size_m:1;
	unsigned int size_s:1;
	unsigned int size_l:30;
	unsigned char data[0];
} __attribute__ ((packed)); 

typedef struct eidHdrType3 eidHdrType3_t;

struct utis_notify_msg 
{
	unsigned char	da[ETHER_ALEN];			/* broadcast */
	unsigned char	sa[ETHER_ALEN];			/* OBE Wireless NIC addr */
	__be16			type;					/* UTIS_PROTOCOL = 0x88b6*/
	unsigned char	magic[4];				/* 'N' 'O' 'T' 'I' */
	unsigned char 	id[RSE_ID_LEN];			
	unsigned char	cmd;					/*UTIS_NOTIFY_XXX  */
	unsigned char	black;					/*blacklist obe(1) or not(0), keyauth-fail(2), other-reason(3)*/
#define OBE_NORMAL          0
#define OBE_BLACKLIST       0x03
#define OBE_KEYINVALID      0x20
#define OBE_OTHERFAIL       0x30
#define OBE_NOTUTIS         0x40
	unsigned int	arg1;
	unsigned int	arg2;
	unsigned int	arg3;
	char			ifName[16];				/*identify each radio virtual port*/
#define UTISPORT_ALL        "athff"
#define UTISPORT_MASTER     "athma"
#define UTISPORT_AUTH       "athau"
#define UTISPORT_BRIDGE     "athbr"
	unsigned char	data[128];
} __attribute__ ((packed));

typedef struct utis_notify_msg utis_notify_msg_t;

struct utisSecuPolicy
{
	unsigned char policy;
	unsigned char gKey[16];
} __attribute__ ((packed)); 

typedef struct utisSecuPolicy utisSecuPolicy_t;

typedef struct keytable
{
	int vendor;
	int	len;
	unsigned char data[5120];
} keytable_t;

typedef struct crypto_arg
{
	int				key_len;
	int				in_len;
	int				out_len;
	unsigned char	*key;
	unsigned char	*in;
	unsigned char	*out;
} crypto_arg_t;

typedef struct rse_config
{
	char	rse_id[RSE_ID_LEN];
	char	kt_file[PATH_MAX];
	char	se_file[PATH_MAX];
	char	log_file[PATH_MAX];
	char	obe_ctrl[8];
	char	map_ver[4];
	char	intf_name[10];
	int		ppc_port;
} rse_config_t;

typedef struct rse_control_block
{
	rse_config_t	cfg;
	int				w_ufd;
	int				w_bfd;
	int				ifd;
	unsigned int	saved_pktid;
	struct listnode	obe_list;
} rse_cb_t; 

extern void utis_primitive_init(void);
extern utis_primitive_node_t* utis_primitive_get(unsigned short pid);
extern int aes128_dec(unsigned char *key, unsigned char *in, unsigned char *out, size_t len);
extern int get_intf_status(char *intf_name);
extern int init_keytable(char *ktf);
extern int init_secpolicy(char *sp_file);
extern int create_wlan(char *ifname, unsigned short protocol);
extern int load_config(char *cfg_file);

extern int create_inet_udp(int port, int nb);
extern int make_socket_non_blocking (int sfd);

extern void* epoll_events(void *args);

extern int wlan_receive(unsigned char* buf, int size);
extern int wlan_send(int fd, unsigned char *data, int len);
extern int wlan_usend(int fd, unsigned char* mac, unsigned char*  data, int len);


extern int noti_handler(unsigned char *buff, int len);
extern int utis_handler(unsigned char *buff, int len);

extern void init_obe();
extern int obe_handler_add(unsigned short pid, handler func, char* desc);
extern void utis_obe_handler_init(void);
extern void utis_wifi_handler_init(void);

extern struct listnode* find_obe(unsigned char *mac);
extern int add_obe(unsigned char *mac, unsigned char *id);
int delete_obe(unsigned char *mac);

extern int RseMsgToObeOp2000(unsigned char *mac, unsigned char *obeid);


extern int LibMUGetAckBitCheck(MU *m);
extern int LibMUCrcCheck(MU *m);

extern int str2hex(char *str, uint8_t *hex);

extern rse_cb_t			*rse_cb;
extern zlog_category_t	*c;

#endif
