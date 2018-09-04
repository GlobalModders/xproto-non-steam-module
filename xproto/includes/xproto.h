#ifndef __XPROTO_H__
#define __XPROTO_H__
#include "osconfig.h"

#include <extdll.h>
#include <meta_api.h>
#include "common/const.h"
#include "engine/progs.h"
#include "common/usercmd.h"
#include <pthread.h>


#define XPROTO_VERSION "0.2.23"
#define XPROTO_BUILD SVN_REV

#define INDEX0_CLIENT(x)        (((int)x - (int)svs->clients) / sizeof(client_t))
#define CLIENT_INDEX0(x)        (client_t*)svs->clients + x

#ifdef MODULE_DEBUG
#define XPROTO_DEBUG(...)       UTIL_LogPrintf(__VA_ARGS__)
#else
#define XPROTO_DEBUG(...)
#endif

struct RevTicket_t {
	unsigned int Unk00;
	unsigned int Unk04;
	unsigned int Unk08;
	unsigned int Unk0C;
	unsigned int Unk10;
	unsigned int Unk14;
	char TicketBuf[128];
};

typedef enum {
        NS_CLIENT,
        NS_SERVER
} netsrc_t;

#define MAX_CONN_LIST	32
#define MIN_CONN_DELAY	2
#define MAX_CONN_LIMIT	5
struct connlist_t {
	in_addr ip;
	int	count;
	int	lasttime;
	int	logged;
};

struct client_t;

struct eclientdata_t {
	int iId;
	int Proto;
	int AuthId;
	int IP;
	void* cl;
	int IP2;
	bool isHLTV;
	int isAuthFailed;
	int isOldRevEmu;
	int isRevEmu;
	int isSteamEmu;
	int isBanned;
	bool bHasFuckedUserinfo;
};

struct clientid_t {
	unsigned int ID_Type;

	#if defined(linux)
	#else
		unsigned int ID_Pad;
	#endif

	unsigned int ID_Ident1;
	unsigned int ID_Ident2;

	#if defined(linux)
	#else
		unsigned int ID_Pad2;
	#endif

	unsigned int ID_Addr;
};

struct bannedid_t {
	clientid_t cid;
	float UnbanTime;
	union {
		float fBanTime;
		int iBanTime;
	};
};

enum netadrtype_t {
	NA_UNUSED = 0x0,
	NA_LOOPBACK = 0x1,
	NA_BROADCAST = 0x2,
	NA_IP = 0x3,
	NA_IPX = 0x4,
	NA_BROADCAST_IPX = 0x5,
};

struct netadr_t
{
  netadrtype_t type;
  in_addr ip;
  unsigned char ipx[10];
  unsigned short port;
};

struct net_message_t {
	int field_0;
	int field_4;
	int *buffer;
	int field_C;
	int msg_len;
};

struct svs_t {
  int field_0;
  client_t *clients;
  int max_clients;
  int field_C;
};

enum { CLC_BAD = 0, CLC_NOP, CLC_MOVE, CLC_CMD, CLC_DELTA, CLC_RESLIST, CLC_TMOVE, CLC_CONSISTENCY, CLC_VDATA, CLC_HLTV, CLC_CVAR, CLC_CVAR2, CLC_END };

struct clcfunc_t
{
        int index;
        char * name;
        void (*call)(client_t*);
};

struct sizebuf_t {
	const char *descr;
	qboolean overflowflags;
	byte *data;
	int maxsize;
	int cursize;
};

typedef struct packet_entities_s
{
  int num_entities;
  int max_entities;
  entity_state_t entities[64];
} packet_entities_t;

typedef struct  client_frame_s
{
  double senttime;
  float ping_time;
  clientdata_t *cdata;
  float frame_time;
  packet_entities_t entities;
} client_frame_t;

typedef struct flowstats_s
{
  int size;
  double time;
} flowstats_t;

typedef struct flow_s
{
  flowstats_t stats[32];
  int current;
  double nextcompute;
  float kbytespersec;
  float avgkbytespersec;
  int totalbytes;
} flow_t;

typedef struct fragbuf_s
{
  struct fragbuf_s *next;
  int bufferid;
  sizebuf_t frag_message;
  byte frag_message_buf[1400];
  qboolean isfile;
  qboolean isbuffer;
  char filename[64];
  int foffset;
  int size;
} fragbuf_t;

typedef struct fragbufwaiting_s
{
  struct fragbufwaiting_s *next;
  int fragbufcount;
  fragbuf_t *fragbufs;
} fragbufwaiting_t;

typedef struct netchan_s
{
  netsrc_t sock;
  netadr_t remote_address;
  int qport;
  float last_received;
  float connect_time;
  double rate;
  double cleartime;
  int incoming_sequence;
  int incoming_acknowledged;
  int incoming_reliable_acknowledged;
  int incoming_reliable_sequence;
  int outgoing_sequence;
  int reliable_sequence;
  int last_reliable_sequence;
  client_t *cl;
  int spawned;
  sizebuf_t message;
  char message_buf[3992];
  int reliable_length;
  char reliable_buf[3992];
  fragbufwaiting_t *waitlist[2];
  int reliable_fragment[2];
  unsigned int reliable_fragid[2];
  fragbuf_t *fragbufs[2];
  int fragbufcount[2];
  short frag_startpos[2];
  short frag_length[2];
  fragbuf_t *incomingbufs[2];
  qboolean incomingready[2];
  char incomingfilename[64];
  flow_t flow[2];
  int chanpayload[48];
  int tail;
} netchan_t;

typedef struct ipsocket_s
{
  int sock_client;
  int sock_server;
  int sock_multicast;
} ipsocket_t;

typedef void *FileHandle_t;

typedef struct steam_s
{
	int id_type;
	unsigned int id1;
	unsigned int id2;
	unsigned int id_address;
} steam_t;

struct USERID_t
{
	int idtype;
	__attribute__((packed)) __attribute__((aligned(1))) uint64 m_SteamID;
	unsigned int clientip;
};

struct client_t
{
  qboolean active;
  qboolean spawned;
  qboolean fully_connected;
  qboolean connected;
  qboolean uploading;
  qboolean hasusrmsgs;
  qboolean has_force_unmodified;
  netchan_t netchan;
  int chokecount;
  int delta_sequence;
  qboolean fakeclient;
  qboolean proxy;
  usercmd_t lastcmd;
  double connecttime;
  double cmdtime;
  double ignorecmdtime;
  float latency;
  float packet_loss;
  double localtime;
  double nextping;
  double svtimebase;
  sizebuf_t datagram;
  byte datagram_buf[4000];
  double connection_started;
  double next_messagetime;
  double next_messageinterval;
  qboolean send_message;
  qboolean skip_message;
  client_frame_t *frames;
  event_state_t events;
  edict_t *edict;
  const edict_t *pViewEntity;
  int userid;
  USERID_t network_userid;
  char userinfo[256];
  qboolean sendinfo;
  float sendinfo_time;
  char hashedcdkey[64];
  char name[32];
  int topcolor;
  int bottomcolor;
  int entityId;
  resource_t resourcesonhand;
  resource_t resourcesneeded;
  FileHandle_t upload;
  qboolean uploaddoneregistering;
  customization_t customdata;
  int crcValue;
  int lw;
  int lc;
  char physinfo[256];
  qboolean m_bLoopback;
  uint32 m_VoiceStreams[2];
  double m_lastvoicetime;
  int m_sendrescount;
};

enum { AUTH_NONE = 0, AUTH_STEAM, AUTH_REVEMU, AUTH_SXE, AUTH_HLTV };

struct clientstate_t
{
	int proto;
	int steam;
	int authtype;
};

typedef int (*SV_CheckUserInfo_t)(netadr_t*, char*, qboolean, int, char*);
typedef bool (*SV_FilterUser_t)(USERID_t*);
typedef void (*MSG_WriteLong_t)(sizebuf_t*, long);
typedef qboolean (*NET_CompareClassBAdr_t)();
typedef qboolean (*SV_RejectConnection_t)(netadr_t*, const char*, ...);
typedef void (*SV_ConnectClient_t)();
typedef void (*SV_SendServerinfo_t)(int*, client_t*);
typedef char* (*SV_GetClientIDString_t)(client_t*);
typedef char* (*Info_ValueForKey_t)(const char*, const char*);
typedef char* (*Cmd_Argv_t)(unsigned int);
typedef int (*Steam_GSBSecure_t)();
typedef void (*NET_SendPacket_t)(int, int, char*, netadr_t);
typedef int (*HandleIncomingPacket_t)(char*, int, int, int);
typedef qboolean (*Steam_NotifyClientConnect_t)(client_t*, char*, int, int);
typedef qboolean (*WasRestartRequested_t)();
typedef qboolean (*Netchan_Process_t)(netchan_t*);
typedef void (*SV_ReadPackets_t)();
typedef void (*SV_DropClient_t)(client_t*, int, char*, ...);
typedef void (*Info_SetValueForStarKey_t)(char*, char*, const char*, int);
typedef void (*Cmd_ExecuteString_t)(char*, int);
typedef void (*Cmd_TokenizeString_t)(char*);
typedef int (*SV_GetFragmentSize_t)(client_t*);
typedef int (*Netchan_CreateFragments_t)(int, netchan_t*, sizebuf_t*);
typedef void (*ED_LoadFromFile_t)(char *);
typedef void (*COM_WriteFile_t)(char*, void*, int);
typedef void (*SV_ParseVoiceData_t)(client_t*);


typedef void (*SVC_Info_t)(int);
typedef void (*SVC_RuleInfo_t)();
typedef void (*SVC_PlayerInfo_t)();
typedef void (*SVC_Ping_t)();

extern const char *xpGetGameDescription(void);
extern void xpClientCommand(edict_t *pEntity);
extern void UTIL_LogPrintf(char *fmt, ...);
extern bool xp_init();

#endif //__XPROTO_H__

