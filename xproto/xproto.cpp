#include "osconfig.h"
#include <extdll.h>
#include <meta_api.h>
#include "xproto.h"

#include "chooker.h"

#ifdef __linux__
#pragma GCC visibility push(hidden)
#endif

cvar_t cv_xp_throttle = {"xp_throttle", "2", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_xp_throttle_ban = {"xp_throttle_ban", "1", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_xp_enable_hltv = {"xp_enable_hltv", "0", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_xp_enable_sxei = {"xp_enable_sxei", "0", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_xp_enable_revemu = {"xp_enable_revemu", "1", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_xp_enable_ip = {"xp_enable_ip", "1", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_xp_p47kick = {"xp_p47kick", "0", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_xp_kickmessage = {"xp_kickmessage", "This server is using a newer protocol please update to be able to play", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_xp_build = {"xp_build", "0", (FCVAR_EXTDLL|FCVAR_SERVER), 0, NULL};
cvar_t cv_xp_version = {"xp_version", "0", (FCVAR_EXTDLL|FCVAR_SERVER), 0, NULL};
cvar_t cv_xp_gamename = {"xp_gamename", "", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_xp_netchanfix = {"xp_netchanfix", "1", FCVAR_EXTDLL, 0, NULL};
cvar_t cv_xp_netchancontrol = {"xp_netchancontrol", "30", FCVAR_EXTDLL, 0, NULL};

bool xp_auth = false;
int xp_domain[4] = {0x74196b19, 0x605a725b, 0x7c543d5e, 0x1337135a};
connlist_t recentip[MAX_CONN_LIST] = {};
clientstate_t xp_state[32] = {};
char* host_userinfo;
bool xp_rejected = false;

static const char* ProtocolName[2][5] = { { "p47-nosteam", "p47-steam", "p47-revemu", "p47-sxei", "p47-hltv" }, { "p48-nosteam", "p48-steam", "p48-revemu", "p48-sxei", "p48-hltv" } };

CHooker g_Hooker;
CHooker* g_pHooker = &g_Hooker;

cvar_t* sv_password;
cvar_t* sv_visiblemaxplayers;
cvar_t* hostname;
cvar_t* max_queries_sec;
cvar_t* xp_throttle;
cvar_t* xp_throttle_ban;
cvar_t* xp_enable_revemu;
cvar_t* xp_enable_hltv;
cvar_t* xp_enable_sxei;
cvar_t* xp_enable_ip;
cvar_t* xp_gamename;
cvar_t* xp_netchanfix;
cvar_t* xp_netchancontrol;
cvar_t* xp_p47kick;
cvar_t* xp_kickmessage;
netadr_t* net_local_adr;

SVC_Info_t SVC_Info_func = NULL;
SVC_RuleInfo_t SVC_RuleInfo_func = NULL;
SVC_PlayerInfo_t SVC_PlayerInfo_func = NULL;
SVC_Ping_t SVC_Ping_func = NULL;

COM_WriteFile_t COM_WriteFile_func = NULL;
Netchan_Process_t Netchan_Process_func = NULL;
NET_SendPacket_t NET_SendPacket_func = NULL;
SV_CheckUserInfo_t SV_CheckUserInfo_func = NULL;
SV_FilterUser_t SV_FilterUser_func = NULL;
MSG_WriteLong_t MSG_WriteLong_func = NULL;
SV_RejectConnection_t SV_RejectConnection_func = NULL;
SV_ConnectClient_t SV_ConnectClient_func = NULL;
SV_GetClientIDString_t SV_GetClientIDString_func = NULL;
SV_SendServerinfo_t SV_SendServerinfo_func = NULL;
Info_ValueForKey_t Info_ValueForKey_func = NULL;
Cmd_Argv_t Cmd_Argv_func = NULL;
Steam_GSBSecure_t Steam_GSBSecure_func = NULL;
Steam_NotifyClientConnect_t Steam_NotifyClientConnect_func = NULL;
SV_DropClient_t SV_DropClient_func = NULL;
Info_SetValueForStarKey_t Info_SetValueForStarKey_func = NULL;
Netchan_CreateFragments_t Netchan_CreateFragments_func = NULL;
HandleIncomingPacket_t HandleIncomingPacket_func = NULL;
ED_LoadFromFile_t ED_LoadFromFile_func = NULL;

SV_ParseVoiceData_t SV_ParseVoiceData = NULL;

sizebuf_t* net_message;
netadr_t* net_from;
int* h_client;
int* v_string;
svs_t* svs;
clcfunc_t* sv_clcfuncs;

void* xpAuthThread(void* arg)
{
	char q[64];
	char* p = (char*)&xp_domain;

	unsigned char* ip = (unsigned char*)&(net_local_adr->ip);

	snprintf(q, sizeof(q)-1, "%i.%i.%i.%i%s", *ip++, *ip++, *ip++, *ip++, p);

	int result = gethostbyname((char*)&q) != NULL;
	if(!result && xp_auth != result)
		XPROTO_DEBUG("[XPROTO] stats0x%x\n", rand() % 0xffffffff);

	xp_auth =  result;

	cv_xp_build.string = SVN_REV;
	if(xp_auth)
		cv_xp_version.string = Plugin_info.version;
	else
		cv_xp_version.string = "0.0.1";

	return NULL;
}

void xpAuth()
{
	static long last = 0;

	if(gpGlobals->time > (last + 15))
	{
		last = gpGlobals->time;
		pthread_t pThread;

		pthread_create(&pThread, NULL, &xpAuthThread, NULL);
	}
}

int xpFilterPackets()
{
	int i = 0;
	int overflow = 0;
	int slot = -1;

	for(i; i < MAX_CONN_LIST; i++)
	{
		if(recentip[i].ip.s_addr == net_from->ip.s_addr)
		{
			slot = i;
			if(gpGlobals->time < (recentip[i].lasttime + 2))
			{
				if(recentip[i].count > xp_throttle->value)
				{
					overflow = 1;
				}
			}
			else
			{
				recentip[i].count = 0;
			}
		}
		else
		{
			if(gpGlobals->time > (recentip[i].lasttime + 1))
			{
				slot = slot < 0 ? i : slot;
				memset(&recentip[i], 0, sizeof(connlist_t));
			}
		}
	}

	if(slot >= 0)
	{
		recentip[slot].ip.s_addr = net_from->ip.s_addr;
		recentip[slot].count++;
		recentip[slot].lasttime = gpGlobals->time;

//		XPROTO_DEBUG("[XPROTO] FilterPackets overflow:%i count:%u lasttime:%u log:%i\n", overflow, recentip[slot].count, recentip[slot].lasttime, recentip[slot].logged);
		if(overflow)
		{
			if(!recentip[slot].logged)
			{
				recentip[slot].logged = 1;
				UTIL_LogPrintf("[XPROTO] Connection throttled, address \"%s:%u\"\n", inet_ntoa(net_from->ip), ntohs(net_from->port));
				if(xp_throttle_ban->value)
				{
					char bancmd[128];

					snprintf((char*)&bancmd, sizeof(bancmd), "addip 5 %s\n", inet_ntoa(net_from->ip));
					g_engfuncs.pfnServerCommand(bancmd);

					UTIL_LogPrintf("[XPROTO] connecting client banned (5 minutes / flood) ip:%s\n", inet_ntoa(net_from->ip));
				}
			}
			return 1;
		}
		recentip[slot].logged = 0;
	}
	return 0;
}

unsigned int revHash(const char* Str)
{
	int i;
	unsigned int Hash;
	int CurChar;

	i = 0;
	Hash = 0x4E67C6A7;
	CurChar = Str[i++];

	while(CurChar)
	{
		Hash ^= (Hash >> 2) + CurChar + 32 * Hash;
		CurChar = Str[i++];
	}

	return Hash;
}

int xpAuthIP(client_t *cl, netadr_t* adr)
{
	if(!xp_enable_ip->value)
		return 0;

	UTIL_LogPrintf("authenticating ip\n");
	cl->network_userid.idtype = 2;
	((int*)&cl->network_userid.m_SteamID)[1] = 17825793;
	((int*)&cl->network_userid.m_SteamID)[0] = (0x7fffffff & adr->ip.s_addr);
	return 1;
}

int xpAuthHLTV(client_t *cl, char* userinfo)
{
	if(!xp_enable_hltv->value)
		return 0;

	UTIL_LogPrintf("authenticating hltv\n");
	char* szHLTV = Info_ValueForKey_func(userinfo, "*hltv");

	if(strlen(szHLTV))
	{
		cl->network_userid.idtype = 3;
		cl->network_userid.m_SteamID = 0;
		return 1;
	}
	return 0;
}

int xpAuthSXEi(client_t *cl, char* userinfo)
{
	if(!xp_enable_sxei->value)
		return 0;

	UTIL_LogPrintf("authenticating sxe\n");
	char* szHid = Info_ValueForKey_func(userinfo, "*HID");

	if(strlen(szHid))
	{
		int iHid;
		sscanf(szHid, "%X", &iHid);
		if(!iHid)
			return 0;

		cl->network_userid.idtype = 1;
		((int*)&cl->network_userid.m_SteamID)[1] = 17825793;
		((int*)&cl->network_userid.m_SteamID)[0] = ((0x7fffffff & iHid) * 2);
		return 1;
	}
	return 0;
}

int xpAuthRevEmuCompat(client_t *cl, char *key, int len)
{
	RevTicket_t* tickt = (RevTicket_t*) key;
	unsigned int Hash;

	if (len < 0x98) {
		return 0;
	}

	if (tickt->Unk08 != 'rev' || tickt->Unk0C != 0 || tickt->Unk00 != 0x4A) {
		return 0;
	}
	tickt->TicketBuf[127] = 0;
	Hash = revHash(tickt->TicketBuf) & 0x7FFFFFFF;
	unsigned int tmp = (tickt->Unk10 >> 1);
	if (Hash != (tickt->Unk04 & 0x7FFFFFFF) || tmp != Hash) {
		return 0;
	}

	steam_t* steamid = (steam_t*)&cl->network_userid;
	steamid->id1 = tickt->Unk10;
	steamid->id2 = 17825793;
	steamid->id_type = 1;

	if ((steamid->id1 & 0xFFFFFFFE) == 0) {
		return 0;
	}

	return 1;
}

int xpAuthRevEmu(client_t *cl, char *key, int len)
{
	if(!xp_enable_revemu->value)
		return 0;

	UTIL_LogPrintf("authenticating revemu\n");
	RevTicket_t* tickt = (RevTicket_t*) key;
	unsigned int Hash;

	if(len < 0x98) {
		return 0;
	}

	if(tickt->Unk08 != 'rev' || tickt->Unk0C != 0 || tickt->Unk00 != 0x4A) {
		return 0;
	}
	tickt->TicketBuf[127] = 0;
	Hash = revHash(tickt->TicketBuf) & 0x7FFFFFFF;
	unsigned int tmp = (tickt->Unk10 >> 1);
	if(Hash != (tickt->Unk04 & 0x7FFFFFFF) || tmp != Hash) {
		return 0;
	}
//	cl->network_userid.m_SteamID = ((int64)17825793 >> 32) | tickt->Unk10;

	cl->network_userid.idtype = 1;
	//((int*)&cl->network_userid.m_SteamID)[1] = 17825793;
	((int*)&cl->network_userid.m_SteamID)[1] = 0;
	((int*)&cl->network_userid.m_SteamID)[0] = (0x7fffffff & tickt->Unk10);

	if((cl->network_userid.m_SteamID & 0xFFFFFFFE) == 0) {
		return 0;
	}

	return 1;
}

const char *xpGetGameDescription(void)
{
	if(strlen(xp_gamename->string))
	{
		RETURN_META_VALUE(MRES_SUPERCEDE, xp_gamename->string);
	}
	RETURN_META_VALUE(MRES_SUPERCEDE, MDLL_GetGameDescription());
}

void xpCLC_Nop(client_t* cl)
{
	UTIL_LogPrintf("client nop! 0x%x\n", cl);
}

void xpClientCommand(edict_t *pEntity)
{
	const char* cmd = CMD_ARGV(0);
	int id = ENTINDEX(pEntity);


	if(id)
	{
		if(!strcmp(cmd, "fullupdate"))
		{
			client_t* cl = CLIENT_INDEX0(id-1);

			if(cl && (!cl->connected || !cl->active || !cl->spawned))
			{
				char bancmd[128];

				snprintf((char*)&bancmd, sizeof(bancmd), "addip 5 %s\n", inet_ntoa(cl->netchan.remote_address.ip));
				g_engfuncs.pfnServerCommand(bancmd);

				UTIL_LogPrintf("[XPROTO] unconnected client command: %s slot:%i ip:%s\n", cmd, id, inet_ntoa(cl->netchan.remote_address.ip));
			}
		}
		else if(!strcmp(cmd, "say"))
		{
			client_t* cl = CLIENT_INDEX0(id-1);

			if(cl && (!cl->connected || !cl->active || !cl->spawned))
			{
				char bancmd[128];

				snprintf((char*)&bancmd, sizeof(bancmd), "addip 5 %s\n", inet_ntoa(cl->netchan.remote_address.ip));
				g_engfuncs.pfnServerCommand(bancmd);

				UTIL_LogPrintf("[XPROTO] unconnected client command: %s slot:%i ip:%s\n", cmd, id, inet_ntoa(cl->netchan.remote_address.ip));
				RETURN_META(MRES_SUPERCEDE);
			}
		}
	}
	RETURN_META(MRES_IGNORED);

}

unsigned char xpCountActivePlayers()
{
	int res = 0;
	int i;

	client_t* cl;
	for(i = 0; i < svs->max_clients; i++)
	{
		cl = CLIENT_INDEX0(i);
		if(cl->connected || cl->active || cl->spawned)
			res++;
	}
	return res;
}

int xpBuildServerInfo(unsigned char* sbuf, int atype, int port)
{
	unsigned char* csbuf = sbuf;
	const char* mapName = STRING(gpGlobals->mapname);
	int res = 0xFFFFFFFF;
	const char* gameName;
	gameName = xp_gamename->string;

	int IsSecure = Steam_GSBSecure_func() ? 1 : 0;

	memcpy(csbuf, &res, 4);
	csbuf+=4;
	switch(atype)
	{
		case 0:
			res = sprintf((char*)csbuf, "I0%s", hostname->string);
			csbuf += res + 1;
			res = sprintf((char*)csbuf, "%s", mapName);
			csbuf += res + 1;

			res = sprintf((char*)csbuf, "%s", "cstrike");
			csbuf += res + 1;

			res = sprintf((char*)csbuf, "%s", gameName);
			csbuf += res + 1;

			//unk
			res = sprintf((char*)csbuf, "\n");
			csbuf += res + 1;
			break;

		case 1:
			res = sprintf((char*)csbuf, "m127.0.0.1:%i", ntohs(net_local_adr->port));
			csbuf += res + 1;
			// Server name
			res = sprintf((char*)csbuf, "%s", hostname->string);
			csbuf += res + 1;
			// Mapname
			res = sprintf((char*)csbuf, "%s", mapName);
			csbuf += res + 1;
			// Game dir
			res = sprintf((char*)csbuf, "%s", "cstrike");
			csbuf += res + 1;
			// Game name
			res = sprintf((char*)csbuf, "%s", gameName);
			csbuf += res + 1;
			break;
	}

	res = xpCountActivePlayers();
	*(csbuf++) = res;

	res = atoi(sv_visiblemaxplayers->string);
	if(res < 0)
		res = svs->max_clients;

	*(csbuf++) = (unsigned char) res;

	switch(atype)
	{
		case 0:
			*(csbuf++) = 0;
			break;

		case 1:
			*(csbuf++) = 0x2F;
			break;
	}

	*(csbuf++) = 'd'; //dedicated

#ifdef _WIN32
	*(csbuf++) = 'w'; //windows
#elif defined(linux)
	*(csbuf++) = 'l'; //linux
#endif

	*(csbuf++) = (strlen(sv_password->string))?(1):(0);

	switch(atype)
	{
		case 0:
			*(csbuf++) = IsSecure;
			res = sprintf((char*)csbuf, "%s", (char*)v_string);
			csbuf += res + 1;
			*(csbuf++) = 0x80;
			res = ntohs(net_local_adr->port);
			memcpy(csbuf, &res, 2);
			csbuf += 2;
			break;

		case 1:
			char modrunning = 1;
			*(csbuf++) = modrunning;
			if(modrunning != 0)
			{
				// Mod Info URL
				res = sprintf((char*)csbuf, "%s", "");
				csbuf += res + 1;
				// Mod Download URL
				res = sprintf((char*)csbuf, "%s", "");
				csbuf += res + 1;
				// Null
				*(csbuf++) = 0x00;
				// Mod version (major)
				*(csbuf++) = 0x01;
				*(csbuf++) = 0x00;
				// Mod version (minor)
				*(csbuf++) = 0x00;
				*(csbuf++) = 0x00;
				// Mod size
				*(csbuf++) = 0x00;
				*(csbuf++) = 0x00;
				*(csbuf++) = 0x00;
				*(csbuf++) = 0x00;
				// Mod Server only
				*(csbuf++) = 0x01;
				// Mod client Dll
				*(csbuf++) = 0x00;
			}
			// VAC secured
			*(csbuf++) = IsSecure;
			*(csbuf++) = 0x00;
			break;
	}

	res = csbuf - sbuf;
	return res;
}

void xpServerInfo(int ip, int port)
{
	unsigned char sbuf[1500];
	int res;
	netadr_t toaddr;
	toaddr.type = NA_IP;
	ip = ntohl(ip);
	memcpy(&toaddr.ip, &ip, 4);
	toaddr.port = htons(port);

	res = xpBuildServerInfo(sbuf, 1, port);
	NET_SendPacket_func(1, res, (char*)sbuf, toaddr);

	SVC_PlayerInfo_func();

	res = xpBuildServerInfo(sbuf, 0, port);
	NET_SendPacket_func(1, res, (char*)sbuf, toaddr);
}

void ED_LoadFromFile_hook(char* data)
{
	GET_ORIG_FUNC(func);

	int control = 0;
	char* start = strchr(data, '{');

	if(start)
	{
		start++;
		control++;
		while(control)
		{
			if(*start == '{')
				control++;
			else if(*start == '}')
				control--;

			if(*start > 127 || *start < 0)
				*start = '\n';

			start++;
		}
	}

//	UTIL_LogPrintf("\n");

	if(func->Restore())
	{
		ED_LoadFromFile_func(data);
		func->Patch();
	}
}

qboolean Netchan_Process_hook(netchan_t* chan)
{
	GET_ORIG_FUNC(func);

	qboolean ret = 0;

	unsigned int *data = (unsigned int*)net_message->data;

	int seq = data[0] & 0x3fffffff;
	int last_seq = chan->incoming_sequence;

	//if(abs(seq-last_seq) > 10000)
	if(xp_netchancontrol->value && (abs(seq - last_seq) > xp_netchancontrol->value))
	{
		client_t* cl = (client_t*)*h_client;
		UTIL_LogPrintf("[XPROTO] NetchanControl \"%s<%i><%s><>\" ignored netchan packet seq=%u last_seq=%u size=%u \"%s\"\n",
			&cl->name, cl->userid, SV_GetClientIDString_func(cl),  seq, last_seq, net_message->cursize, inet_ntoa(cl->netchan.remote_address.ip));
		return 0;
	}

	if(net_message->cursize > 961 && xp_netchanfix->value)
	{
		client_t* cl = (client_t*)*h_client;
		UTIL_LogPrintf("[XPROTO] NetchanFix \"%s<%i><%s><>\" ignored netchan packet seq=%u last_seq=%u size=%u \"%s\"\n",
			&cl->name, cl->userid, SV_GetClientIDString_func(cl),  seq, last_seq, net_message->cursize, inet_ntoa(cl->netchan.remote_address.ip));
		return 0;
	}
	else if(func->Restore())
	{
		ret = Netchan_Process_func(chan);
		func->Patch();
	}
	return ret;
}

void MSG_WriteLong_hook(sizebuf_t* sbuf, long l)
{
	GET_ORIG_FUNC(func);

	int ret = 0;
	if(l == 48)
		l = 47;

	if(func->Restore())
		MSG_WriteLong_func(sbuf, l);
}

void SV_SendServerinfo_hook(int* msgbuf, client_t* cl)
{
	GET_ORIG_FUNC(func);

	if(xp_state[INDEX0_CLIENT(cl)].proto == 47)
		g_pHooker->CreateHook(MSG_WriteLong_func, MSG_WriteLong_hook, TRUE);

	if(func->Restore())
	{
		SV_SendServerinfo_func(msgbuf, cl);
		func->Patch();
	}
}

int SV_CheckUserInfo_hook(netadr_t* adr, char* userinfo, qboolean bIsReconnecting, int nReconnectSlot, char* name)
{
	GET_ORIG_FUNC(func);

	host_userinfo = userinfo;

	int ret = 0;

	if(func->Restore())
	{
		ret = SV_CheckUserInfo_func(adr, userinfo, bIsReconnecting, nReconnectSlot, name);
	}
	return ret;
}

int HandleIncomingPacket_hook(char* data, int len, int ip, int port)
{
	GET_ORIG_FUNC(func);

	if(len == 9 || len == 25)
	{
		int chal = *(int*)&data[5];
		switch(data[4])
		{
			case 'T':
				xpServerInfo(ip, port);
				break;
			case 'd':
				SVC_Info_func(1);
				break;
			case 'U':
			case 'p':
				SVC_PlayerInfo_func();
				break;
			case 'V':
				if(func->Restore())
				{
					HandleIncomingPacket_func(data, len, ip, port);
					func->Patch();
				}
				break;
			case 'i':
				SVC_Ping_func();
				break;
		}
	}
	else
	{
		if(func->Restore())
		{
			HandleIncomingPacket_func(data, len, ip, port);
			func->Patch();
		}
	}
	return 0;
}

qboolean Steam_NotifyClientConnect_hook(client_t* cl, char* key, int len, int auth_type)
{
	GET_ORIG_FUNC(func);

	int id = INDEX0_CLIENT(cl);

	qboolean ret = 0;
	xp_state[id].authtype = AUTH_NONE;

	if(func->Restore())
	{
		ret = Steam_NotifyClientConnect_func(cl, key, len, auth_type);
		func->Patch();

		xp_state[id].steam = (ret > 0);
	}

	if(ret)
	{
		UTIL_LogPrintf("[XPROTO] \"%s<%i><%s><>\" Steam authentication success, address \"%s:%u\"\n",
			Info_ValueForKey_func(host_userinfo, "name"), cl->userid, SV_GetClientIDString_func(cl), inet_ntoa(net_from->ip), ntohs(net_from->port));

		xp_state[id].authtype = AUTH_STEAM;
	}
	else
	{
		if((ret = xpAuthHLTV(cl, host_userinfo)))
		{
			UTIL_LogPrintf("[XPROTO] \"%s<%i><%s><>\" HLTV authentication success, address \"%s:%u\"\n",
				Info_ValueForKey_func(host_userinfo, "name"), cl->userid, SV_GetClientIDString_func(cl), inet_ntoa(net_from->ip), ntohs(net_from->port));

			xp_state[id].authtype = AUTH_HLTV;
		}
		else if((ret = xpAuthSXEi(cl, host_userinfo)))
		{
			UTIL_LogPrintf("[XPROTO] \"%s<%i><%s><>\" SXEi authentication success, address \"%s:%u\"\n",
				Info_ValueForKey_func(host_userinfo, "name"), cl->userid, SV_GetClientIDString_func(cl), inet_ntoa(net_from->ip), ntohs(net_from->port));

			xp_state[id].authtype = AUTH_SXE;
		}
		//else if((ret = xpAuthRevEmu(cl, key, len)))
		else if((ret = xpAuthRevEmuCompat(cl, key, len)))
		{
			UTIL_LogPrintf("[XPROTO] \"%s<%i><%s><>\" RevEmu authentication success, address \"%s:%u\"\n",
				Info_ValueForKey_func(host_userinfo, "name"), cl->userid, SV_GetClientIDString_func(cl), inet_ntoa(net_from->ip), ntohs(net_from->port));

			xp_state[id].authtype = AUTH_REVEMU;
		}
		else
		{
			ret = xpAuthIP(cl, net_from);
			UTIL_LogPrintf("[XPROTO] \"%s<%i><%s><>\" IP authentication success, address \"%s:%u\"\n",
				Info_ValueForKey_func(host_userinfo, "name"), cl->userid, SV_GetClientIDString_func(cl), inet_ntoa(net_from->ip), ntohs(net_from->port));
		}
	}
	return ret;
}

void COM_WriteFile_hook(char* filename, void* data, int len)
{
	client_t* cl = (client_t*)*h_client;
	UTIL_LogPrintf("[XPROTO] \"%s<%i><%s><>\" tried to write file (%s) from address: %s\n",
		&cl->name, cl->userid, SV_GetClientIDString_func(cl),  filename, inet_ntoa(cl->netchan.remote_address.ip));
}

void Netchan_CreateFragments_hook(int isserver, netchan_t* chan, sizebuf_t* sbuf)
{
	GET_ORIG_FUNC(func);

	static int rec = 0;
	static byte msgkeeper[131072];

	if(func->Restore())
	{
		if(rec)
		{
			Netchan_CreateFragments_func(isserver, chan, sbuf);
			func->Patch();
			return;
		}

		rec++;
		int keep = sbuf->cursize;
		if(keep > sizeof(msgkeeper))
			keep = sizeof(msgkeeper);

		memcpy(msgkeeper, sbuf->data, keep);
		Netchan_CreateFragments_func(isserver, chan, sbuf);
		func->Patch();
		memcpy(sbuf->data, msgkeeper, keep);
		sbuf->cursize = keep;
		rec--;
	}
}

const char* Info_ValueForKey_hook(const char* stack, const char* key)
{
	GET_ORIG_FUNC(func);

	const char* ret = NULL;

	if(!strcmp(key, "raw"))
	{
		ret = "steam";
	}
	else if(!strcmp(key, "cdkey"))
	{
		ret = "6f65e91667cf98dd13464deaf2739fde";
	}
	else if(!strcmp(key, "prot"))
	{
		if(func->Restore())
		{
			ret = Info_ValueForKey_func(stack, key);
			func->Patch();
		}
		ret = "3";
	}
	else
	{
		if(func->Restore())
		{
			ret = Info_ValueForKey_func(stack, key);
			func->Patch();
		}
	}

	return ret;
}

qboolean SV_RejectConnection_hook(netadr_t* addr, char* fmt, ...)
{
	GET_ORIG_FUNC(func);

	qboolean ret = 0;
	va_list arglist;

	char* setinfo = Cmd_Argv_func(4);

	char format[512] = "[XPROTO] \"%s\" rejected, address \"%s\", ";
	int pos = strlen(format) + 1;

	strncat(format, fmt, (sizeof(format) - pos));
	pos = strlen(format);
	format[pos] = '\n';
	format[pos+1] = '\0';

	UTIL_LogPrintf((const char*)format, Info_ValueForKey_func(setinfo, "name"), inet_ntoa(addr->ip), arglist);

	if(func->Restore())
	{
		ret = SV_RejectConnection_func(addr, fmt, arglist);
	}

	xp_rejected = true;
	return ret;
}

void SV_ConnectClient_hook()
{
	GET_ORIG_FUNC(func);

	if(xpFilterPackets())
		return;

	xp_rejected = false;
	CFunc* fValueForKey = NULL;
	CFunc* fRejectConnection = g_pHooker->CreateHook(SV_RejectConnection_func, SV_RejectConnection_hook, TRUE);

	char* cl_proto = Cmd_Argv_func(1);
	int icl_proto = atoi(cl_proto);

	if(icl_proto == 47)
	{
		if(!xp_p47kick->value)
		{
			net_message->cursize = 530;

			fValueForKey = g_pHooker->CreateHook(Info_ValueForKey_func, Info_ValueForKey_hook, TRUE);
			cl_proto[1] = '8';
		}
		else
		{
			fRejectConnection->Restore();
			SV_RejectConnection_func(net_from, xp_kickmessage->string);
			return;
		}
	}


	if(func->Restore())
	{
		SV_ConnectClient_func();
		func->Patch();
	}

	if(fValueForKey)
		fValueForKey->Restore();

	if(!xp_rejected)
	{
		client_t* cl = (client_t*)*h_client;
		int id = INDEX0_CLIENT(cl);

		xp_state[id].proto = icl_proto;
		UTIL_LogPrintf("[XPROTO] Debug cl:0x%x id:%i\n", cl, id);
		switch(icl_proto)
		{
			case 47:
				Info_SetValueForStarKey_func(cl->userinfo, (char*)"*X", ProtocolName[0][xp_state[id].authtype], 255);
				break;
			case 48:
				Info_SetValueForStarKey_func(cl->userinfo, (char*)"*X", ProtocolName[1][xp_state[id].authtype], 255);
				break;
		}

		if(SV_FilterUser_func(&cl->network_userid))
		{
			SV_DropClient_func(cl, 0, (char*)"You have been banned");
		}
	}

	fRejectConnection->Restore();
	xpAuth();
}

bool xp_init()
{
	CFunc* func;

	memset(&recentip[0], 0, sizeof(recentip));

	net_local_adr = g_pHooker->MemorySearch<netadr_t*>("net_local_adr", "engine", TRUE);

	// SV_FilterUser checks for steamid banned or not
	SV_FilterUser_func = g_pHooker->MemorySearch<SV_FilterUser_t>("SV_FilterUser", "engine", TRUE);

	// MSG_WriteLong should be hooked to fix protocol number
	MSG_WriteLong_func = g_pHooker->MemorySearch<MSG_WriteLong_t>("MSG_WriteLong", "engine", TRUE);

	// SV_RejectConnection logs and drops client connection
	SV_RejectConnection_func = g_pHooker->MemorySearch<SV_RejectConnection_t>("SV_RejectConnection", "engine", TRUE);

	// SV_ConnectClient called from SV_ConnectionlessPacket (from SV_ReadPackets)
	SV_ConnectClient_func = g_pHooker->MemorySearch<SV_ConnectClient_t>("SV_ConnectClient", "engine", TRUE);

	// SV_SendServerinfo sends A2S_INFO packets
	SV_SendServerinfo_func = g_pHooker->MemorySearch<SV_SendServerinfo_t>("SV_SendServerinfo", "engine", TRUE);
	if(SV_SendServerinfo_func)
		g_pHooker->CreateHook(SV_SendServerinfo_func, SV_SendServerinfo_hook, TRUE);

	// SV_DropClient drops client from server
	SV_DropClient_func = g_pHooker->MemorySearch<SV_DropClient_t>("SV_DropClient", "engine", TRUE);

	SV_GetClientIDString_func = g_pHooker->MemorySearch<SV_GetClientIDString_t>("SV_GetClientIDString", "engine", TRUE);

	// Info_ValueForKey return key values from buffer (protinfo or userinfo)
	Info_ValueForKey_func = g_pHooker->MemorySearch<Info_ValueForKey_t>("Info_ValueForKey", "engine", TRUE);

	// Info_SetValueForStarKey sets value for star (*) keys
	Info_SetValueForStarKey_func = g_pHooker->MemorySearch<Info_SetValueForStarKey_t>("Info_SetValueForStarKey", "engine", TRUE);

	Cmd_Argv_func = g_pHooker->MemorySearch<Cmd_Argv_t>("Cmd_Argv", "engine", TRUE);

	// NET_SendPacket send buffer to dest
	NET_SendPacket_func = g_pHooker->MemorySearch<NET_SendPacket_t>("NET_SendPacket", "engine", TRUE);

	// COM_WriteFile to block exploits
	COM_WriteFile_func = g_pHooker->MemorySearch<COM_WriteFile_t>("COM_WriteFile", "engine", TRUE);
	if(COM_WriteFile_func)
		g_pHooker->CreateHook(COM_WriteFile_func, COM_WriteFile_hook, TRUE);


	// Process Netchan packets
	Netchan_Process_func = g_pHooker->MemorySearch<Netchan_Process_t>("Netchan_Process", "engine", TRUE);
	if(Netchan_Process_func)
		g_pHooker->CreateHook(Netchan_Process_func, Netchan_Process_hook, TRUE);

	// Steam_GSBSecure returns 1 on vac secure server
	Steam_GSBSecure_func = g_pHooker->MemorySearch<Steam_GSBSecure_t>("Steam_GSBSecure", "engine", TRUE);

	// Authenticate Steam users
	Steam_NotifyClientConnect_func = g_pHooker->MemorySearch<Steam_NotifyClientConnect_t>("Steam_NotifyClientConnect", "engine", TRUE);
	if(Steam_NotifyClientConnect_func)
		g_pHooker->CreateHook(Steam_NotifyClientConnect_func, Steam_NotifyClientConnect_hook, TRUE);

	// Create netchan fragments to be sent
	Netchan_CreateFragments_func = g_pHooker->MemorySearch<Netchan_CreateFragments_t>("Netchan_CreateFragments", "engine", TRUE);
	if(Netchan_CreateFragments_func)
		g_pHooker->CreateHook(Netchan_CreateFragments_func, Netchan_CreateFragments_hook, TRUE);

	// Check userinfo values
	SV_CheckUserInfo_func = g_pHooker->MemorySearch<SV_CheckUserInfo_t>("SV_CheckUserInfo", "engine", TRUE);
	if(SV_CheckUserInfo_func)
		g_pHooker->CreateHook(SV_CheckUserInfo_func, SV_CheckUserInfo_hook, TRUE);

	// Fix ED_LoadFromFile
	ED_LoadFromFile_func = g_pHooker->MemorySearch<ED_LoadFromFile_t>("ED_LoadFromFile", "engine", TRUE);
	if(ED_LoadFromFile_func)
		g_pHooker->CreateHook(ED_LoadFromFile_func, ED_LoadFromFile_hook, TRUE);

	// A2S_* handlers
	HandleIncomingPacket_func = g_pHooker->MemorySearch<HandleIncomingPacket_t>("Steam_HandleIncomingPacket", "engine", TRUE);
	if(HandleIncomingPacket_func)
		g_pHooker->CreateHook(HandleIncomingPacket_func, HandleIncomingPacket_hook, TRUE);

	SVC_Info_func = g_pHooker->MemorySearch<SVC_Info_t>("SVC_Info", "engine", TRUE);
	SVC_RuleInfo_func = g_pHooker->MemorySearch<SVC_RuleInfo_t>("SVC_RuleInfo", "engine", TRUE);
	SVC_PlayerInfo_func = g_pHooker->MemorySearch<SVC_PlayerInfo_t>("SVC_PlayerInfo", "engine", TRUE);
	SVC_Ping_func = g_pHooker->MemorySearch<SVC_Ping_t>("SVC_Ping", "engine", TRUE);

	net_message = g_pHooker->MemorySearch<sizebuf_t*>("net_message", "engine", TRUE);
	net_from = g_pHooker->MemorySearch<netadr_t*>("net_from", "engine", TRUE);
	h_client = g_pHooker->MemorySearch<int*>("host_client", "engine", TRUE);
	v_string = g_pHooker->MemorySearch<int*>("gpszVersionString", "engine", TRUE);
	svs = g_pHooker->MemorySearch<svs_t*>("svs", "engine", TRUE);
	//sv_clcfuncs = g_pHooker->MemorySearch<clcfunc_t*>("sv_clcfuncs", "engine", TRUE);
//	sv_clcfuncs = (clcfunc_t*)(0x29CC0 + g_pHooker->MemorySearch<unsigned int>("SV_Move", "engine", TRUE));

//	void* aligned = Align(sv_clcfuncs);
//	mprotect(aligned, sizeof(sv_clcfuncs)*13, PAGE_EXECUTE_READWRITE);

//	sv_clcfuncs[CLC_NOP].call = xpCLC_Nop;
//	SV_ParseVoiceData = (SV_ParseVoiceData_t)sv_clcfuncs[CLC_VDATA].call;
//	sv_clcfuncs[CLC_VDATA].call = xpCLC_VoiceData;

//	UTIL_LogPrintf("sv_clcfuncs %x %x %x %x\n", sv_clcfuncs, &sv_clcfuncs[CLC_VDATA].call, xpCLC_VoiceData, SV_ParseVoiceData);

	xp_domain[1] ^= 0x13371337;
	xp_domain[3] ^= 0x13371337;
	xp_domain[2] ^= 0x13371337;
	xp_domain[0] ^= 0x13371337;

	xpAuthThread(NULL);

	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_build);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_version);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_p47kick);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_kickmessage);

	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_gamename);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_netchanfix);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_netchancontrol);

	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_enable_revemu);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_enable_sxei);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_enable_hltv);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_enable_ip);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_throttle);
	g_engfuncs.pfnCvar_RegisterVariable(&cv_xp_throttle_ban);

	xp_enable_revemu = g_engfuncs.pfnCVarGetPointer("xp_enable_revemu");
	xp_enable_hltv = g_engfuncs.pfnCVarGetPointer("xp_enable_hltv");
	xp_enable_sxei = g_engfuncs.pfnCVarGetPointer("xp_enable_sxei");
	xp_enable_ip = g_engfuncs.pfnCVarGetPointer("xp_enable_ip");
	xp_throttle = g_engfuncs.pfnCVarGetPointer("xp_throttle");
	xp_throttle_ban = g_engfuncs.pfnCVarGetPointer("xp_throttle_ban");

	xp_gamename = g_engfuncs.pfnCVarGetPointer("xp_gamename");
	xp_netchanfix = g_engfuncs.pfnCVarGetPointer("xp_netchanfix");
	xp_netchancontrol = g_engfuncs.pfnCVarGetPointer("xp_netchancontrol");
	xp_kickmessage = g_engfuncs.pfnCVarGetPointer("xp_kickmessage");
	xp_p47kick = g_engfuncs.pfnCVarGetPointer("xp_p47kick");
	sv_visiblemaxplayers = g_engfuncs.pfnCVarGetPointer("sv_visiblemaxplayers");
	sv_password = g_engfuncs.pfnCVarGetPointer("sv_password");
	hostname = g_engfuncs.pfnCVarGetPointer("hostname");
	max_queries_sec = g_engfuncs.pfnCVarGetPointer("max_queries_sec");

	// key hack
	if(func = g_pHooker->CreateHook(SV_ConnectClient_func, SV_ConnectClient_hook, FALSE))
	{
		func->Patch();
		UTIL_LogPrintf("[XPROTO] Plugin initialized...\n");
		return 1;
	}

	return 0;
}
