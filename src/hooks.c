//---------------------------------------------------------------------------
// OllySocketTrace - A Socket Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#include <stdio.h>
#include <winsock2.h>

#include "hooks.h"

#pragma nopackwarning

#define SIZE_THRESHOLD	0x0000FFFF // 65535 bytes

extern LPVOID MyMalloc( DWORD dwSize );
extern BOOL MyFree( LPVOID lpAddress );


//---------------------------------------------------------------------------
struct FLAGS af_flags[] = {
	{ AF_UNSPEC,     "AF_UNSPEC" },
	{ AF_UNIX,       "AF_UNIX" },
	{ AF_INET,       "AF_INET" },
	{ AF_IMPLINK,    "AF_IMPLINK" },
	{ AF_PUP,        "AF_PUP" },
	{ AF_CHAOS,      "AF_CHAOS" },
	{ AF_NS,         "AF_NS" },
	{ AF_IPX,        "AF_IPX" },
	{ AF_ISO,        "AF_ISO" },
	{ AF_OSI,        "AF_OSI" },
	{ AF_ECMA,       "AF_ECMA" },
	{ AF_DATAKIT,    "AF_DATAKIT" },
	{ AF_CCITT,      "AF_CCITT" },
	{ AF_SNA,        "AF_SNA" },
	{ AF_DECnet,     "AF_DECnet" },
	{ AF_DLI,        "AF_DLI" },
	{ AF_LAT,        "AF_LAT" },
	{ AF_HYLINK,     "AF_HYLINK" },
	{ AF_APPLETALK,  "AF_APPLETALK" },
	{ AF_NETBIOS,    "AF_NETBIOS" },
	{ AF_VOICEVIEW,  "AF_VOICEVIEW" },
	{ AF_FIREFOX,    "AF_FIREFOX" },
	{ AF_UNKNOWN1,   "AF_UNKNOWN1" },
	{ AF_BAN,        "AF_BAN" },
	{ AF_ATM,        "AF_ATM" },
	{ AF_INET6,      "AF_INET6" },
	{ AF_CLUSTER,    "AF_CLUSTER" },
	{ AF_12844,      "AF_12844" },
	{ AF_IRDA,       "AF_IRDA" },
	{ AF_NETDES,     "AF_NETDES" },
	{ AF_TCNPROCESS, "AF_TCNPROCESS" },
	{ AF_TCNMESSAGE, "AF_TCNMESSAGE" },
	{ AF_ICLFXBM,    "AF_ICLFXBM" },
	{ NULL, NULL }
};

struct FLAGS type_flags[] = {
	{ SOCK_STREAM,    "SOCK_STREAM" },
	{ SOCK_DGRAM,     "SOCK_DGRAM" },
	{ SOCK_RAW,       "SOCK_RAW" },
	{ SOCK_RDM,       "SOCK_RDM" },
	{ SOCK_SEQPACKET, "SOCK_SEQPACKET" },
	{ NULL, NULL }
};

struct FLAGS protocol_flags[] = {
	{ IPPROTO_IP,       "IPPROTO_IP" },
	{ IPPROTO_ICMP,     "IPPROTO_ICMP" },
	{ IPPROTO_IGMP,     "IPPROTO_IGMP" },
	{ IPPROTO_GGP,      "IPPROTO_GGP" },
	{ IPPROTO_IPV4,     "IPPROTO_IPV4" },
	{ IPPROTO_TCP,      "IPPROTO_TCP" },
	{ IPPROTO_PUP,      "IPPROTO_PUP" },
	{ IPPROTO_UDP,      "IPPROTO_UDP" },
	{ IPPROTO_IDP,      "IPPROTO_IDP" },
	//{ IPPROTO_IPV,      "IPPROTO_IPV" },
	{ IPPROTO_ROUTING,  "IPPROTO_ROUTING" },
	{ IPPROTO_FRAGMENT, "IPPROTO_FRAGMENT" },
	{ IPPROTO_ESP,      "IPPROTO_ESP" },
	{ IPPROTO_AH,       "IPPROTO_AH" },
	{ IPPROTO_ICMPV6,   "IPPROTO_ICMPV6" },
	{ IPPROTO_NONE,     "IPPROTO_NONE" },
	{ IPPROTO_DSTOPTS,  "IPPROTO_DSTOPTS" },
	{ IPPROTO_ND,       "IPPROTO_ND" },
	{ IPPROTO_ICLFXBM,  "IPPROTO_ICLFXBM" },
	{ IPPROTO_RAW,      "IPPROTO_RAW" },
	{ NULL, NULL }
};

struct FLAGS msg_flags[] = {

	{ MSG_PEEK,      "MSG_PEEK" },
	{ MSG_OOB,       "MSG_OOB" },
	{ MSG_DONTROUTE, "MSG_DONTROUTE" },
	{ MSG_WAITALL,   "MSG_WAITALL" },
	{ MSG_PARTIAL,   "MSG_PARTIAL" },
	{ MSG_INTERRUPT, "MSG_INTERRUPT" },
	{ NULL, NULL }
};

struct FLAGS ioctl_flags[] = {
	{ FIONREAD,   "FIONREAD" },
	{ FIONBIO,    "FIONBIO" },
	{ FIOASYNC,   "FIOASYNC" },
	{ SIOCATMARK, "SIOCATMARK" },
	{ NULL, NULL }
};

struct FLAGS shutdown_flags[] = {
	{ SD_RECEIVE, "SD_RECEIVE" },
	{ SD_SEND,    "SD_SEND" },
	{ SD_BOTH,    "SD_BOTH" },
	{ NULL, NULL }
};
//---------------------------------------------------------------------------
VOID ResolveFlags( struct FLAGS * pFlags, BOOL bORed, DWORD dwFlags, char * cpOutput )
{
	int iCount = 0, i = 0;
	memset( cpOutput, 0, MAX_PATH );

	if( bORed )
	{
		while( pFlags[i].cpName != NULL )
		{
			if( ( dwFlags & pFlags[i].dwValue ) == pFlags[i].dwValue )
			{
				if( iCount > 0 )
					strcat( cpOutput, " | " );
				strcat( cpOutput, pFlags[i].cpName );
				iCount++;
			}
			i++;
		}
	}
	else
	{
		while( pFlags[i].cpName != NULL )
		{
			if( dwFlags == pFlags[i].dwValue )
			{
				strcat( cpOutput, pFlags[i].cpName );
				iCount++;
                break;
			}
			i++;
		}
    }

	if( iCount == 0 )
		sprintf( cpOutput, "0x%X", dwFlags );
}
//---------------------------------------------------------------------------
BOOL record_sockaddr( LPLOGDATA pLogData, const char * cpMessage, DWORD dw_pSockAddr, DWORD dwSockAddrLength )
{
    struct sockaddr_in * p_saddr;
    char cBuffer[BUFFER_SIZE];

    if( dwSockAddrLength != NULL && dw_pSockAddr != NULL )
    {
        p_saddr = (struct sockaddr_in *)MyMalloc( dwSockAddrLength );
        if( p_saddr != NULL && Readmemory( p_saddr, dw_pSockAddr, dwSockAddrLength, MM_SILENT ) != 0 )
        {
            snprintf( cBuffer, BUFFER_SIZE, "%s: %s:%d. ", cpMessage, inet_ntoa(p_saddr->sin_addr), ntohs(p_saddr->sin_port)  );
            strncat( pLogData->cHint, cBuffer, BUFFER_SIZE );
            MyFree( p_saddr );
            return TRUE;
        }
        MyFree( p_saddr );
    }
    return FALSE;
}
//---------------------------------------------------------------------------
BOOL record_buffer( LPLOGDATA pLogData, DWORD dwThreshold )
{
	if( pLogData->dwDbgBuffer != NULL && pLogData->dwDbgBufferSize > 0 )
	{
		if( pLogData->dwDbgBufferSize > dwThreshold  )
			pLogData->dwOllyBufferSize = dwThreshold;
		else
			pLogData->dwOllyBufferSize = pLogData->dwDbgBufferSize;

		pLogData->lpOllyBuffer = MyMalloc( pLogData->dwOllyBufferSize );
		if( pLogData->lpOllyBuffer != NULL )
        {
			if( Readmemory( pLogData->lpOllyBuffer, pLogData->dwDbgBuffer, pLogData->dwOllyBufferSize, MM_SILENT ) != 0 )
                return TRUE;

            MyFree( pLogData->lpOllyBuffer );
		}

        pLogData->dwOllyBufferSize = NULL;
	}
    return FALSE;
}
//---------------------------------------------------------------------------
BOOL DefaultINT_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // this is kind of cheating but works
    if( pRegisters->r[REG_EAX] == INVALID_SOCKET )
    {
        snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "INVALID_SOCKET" );
    }
    else
    {
	    snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "%d", pRegisters->r[REG_EAX] );
    }
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL DefaultBOOL_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
    snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "%s", ( pRegisters->r[REG_EAX] ? "TRUE" : "FALSE" ) );
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL listen_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // int listen( SOCKET s, int backlog );
    DWORD dwParameters[2];
    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*2, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];

	snprintf( pLogData->cMessage, BUFFER_SIZE, "listen( %d, %d )", dwParameters[0], dwParameters[1] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL ioctlsocket_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // int ioctlsocket( SOCKET s, long cmd, u_long* argp );
    DWORD dwParameters[3];
    char cFlagsOutput[MAX_PATH];

    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*3, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];

    ResolveFlags( (struct FLAGS *)&ioctl_flags, FALSE, dwParameters[1], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "ioctlsocket( %d, %s, 0x%08X )", dwParameters[0], cFlagsOutput, dwParameters[2] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL connect_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // int connect( SOCKET s, const struct sockaddr * name, int namelen );
    DWORD dwParameters[3];
    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*3, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];

    record_sockaddr( pLogData, "Connecting to", dwParameters[1], dwParameters[2] );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "connect( %d, 0x%08X, %d )", dwParameters[0], dwParameters[1], dwParameters[2] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL accept_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
    if( pRegisters->r[REG_EAX] == INVALID_SOCKET )
    {
        snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "INVALID_SOCKET" );
    }
    else
    {
        record_sockaddr( pLogData, "Connection from", pLogData->dwValueA, pLogData->dwValueB );
	    snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "%d", pRegisters->r[REG_EAX] );
    }
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL accept_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // SOCKET accept( SOCKET s, struct sockaddr* addr, int* addrlen );
    DWORD dwParameters[3];
    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*3, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];

    // accept_Return() will resolve the connecting sockaddr...
    if( dwParameters[2] != NULL )
    {
        if( Readmemory( &pLogData->dwValueB, dwParameters[2], sizeof(DWORD), MM_SILENT ) != 0 )
            pLogData->dwValueA = dwParameters[1];
    }

	snprintf( pLogData->cMessage, BUFFER_SIZE, "accept( %d, 0x%08X, 0x%08X )", dwParameters[0], dwParameters[1], dwParameters[2] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL bind_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // int bind( SOCKET s, const struct sockaddr * name, int namelen );
    DWORD dwParameters[3];
    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*3, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];

    record_sockaddr( pLogData, "Binding to", dwParameters[1], dwParameters[2] );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "bind( %d, 0x%08X, %d )", dwParameters[0], dwParameters[1], dwParameters[2] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL socket_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	// SOCKET socket( int af, int type, int protocol );
	DWORD dwParameters[3];
	char cFlagsOutput_AF[MAX_PATH];
	char cFlagsOutput_TYPE[MAX_PATH];
	char cFlagsOutput_PROTOCOL[MAX_PATH];

	if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*3, MM_SILENT ) == 0 )
        return FALSE;

	ResolveFlags( (struct FLAGS *)&af_flags, FALSE, dwParameters[0], (char *)&cFlagsOutput_AF );
	ResolveFlags( (struct FLAGS *)&type_flags, FALSE, dwParameters[1], (char *)&cFlagsOutput_TYPE );
	ResolveFlags( (struct FLAGS *)&protocol_flags, FALSE, dwParameters[2], (char *)&cFlagsOutput_PROTOCOL );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "socket( %s, %s, %s )", cFlagsOutput_AF, cFlagsOutput_TYPE, cFlagsOutput_PROTOCOL );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL socket_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
	pLogData->dwSocket = pRegisters->r[REG_EAX];
	if( pLogData->dwSocket == INVALID_SOCKET )
    {
		pLogData->dwSocket = NULL;
		snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "INVALID_SOCKET" );
	}
	else
	{
		snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "%d", pRegisters->r[REG_EAX] );
    }
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL shutdown_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // int shutdown( SOCKET s, int how );
	DWORD dwParameters[2];
    char cFlagsOutput[MAX_PATH];

	if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*2, MM_SILENT ) == 0 )
        return FALSE;

	pLogData->dwSocket = dwParameters[0];

    ResolveFlags( (struct FLAGS *)&shutdown_flags, TRUE, dwParameters[1], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "shutdown( %d, %s )", dwParameters[0], cFlagsOutput );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL closesocket_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // int closesocket( SOCKET s );
	DWORD dwParameter;

	if( Readmemory( &dwParameter, pRegisters->r[REG_ESP]+4, sizeof(DWORD), MM_SILENT ) == 0 )
        return FALSE;

	pLogData->dwSocket = dwParameter;

	snprintf( pLogData->cMessage, BUFFER_SIZE, "closesocket( %d )", dwParameter );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL recv_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // should we test the return value for success/bytes read and use that value>??
    if( pRegisters->r[REG_EAX] != 0 && pRegisters->r[REG_EAX] != (DWORD)SOCKET_ERROR )
        if( pRegisters->r[REG_EAX] > 0 && pRegisters->r[REG_EAX] < SIZE_THRESHOLD )
            record_buffer( pLogData, pRegisters->r[REG_EAX] );
        else
            record_buffer( pLogData, SIZE_THRESHOLD );

    if( pRegisters->r[REG_EAX] == (DWORD)SOCKET_ERROR )
    	snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "SOCKET_ERROR" );
    else
        snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "%d", pRegisters->r[REG_EAX] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL recv_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	// int recv( SOCKET s, char * buf, int len, int flags );
	DWORD dwParameters[4];
	char cFlagsOutput[MAX_PATH];

	if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*4, MM_SILENT ) == 0 )
        return FALSE;

	pLogData->dwSocket        = dwParameters[0];
 	pLogData->dwDbgBuffer     = dwParameters[1];
	pLogData->dwDbgBufferSize = dwParameters[2];

	ResolveFlags( (struct FLAGS *)&msg_flags, TRUE, dwParameters[3], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "recv( %d, 0x%08X, %d, %s )", dwParameters[0], dwParameters[1], dwParameters[2], cFlagsOutput );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL recvfrom_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
    if( pRegisters->r[REG_EAX] != (DWORD)SOCKET_ERROR )
        record_sockaddr( pLogData, "Recieved from", pLogData->dwValueA, pLogData->dwValueB );

    return recv_Return( pLogData, pRegisters );
}
//---------------------------------------------------------------------------
BOOL recvfrom_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	// int recvfrom( SOCKET s, char *buf, int len, int flags, struct sockaddr * from, int * fromlen );
	DWORD dwParameters[6];
	char cFlagsOutput[MAX_PATH];

	if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*6, MM_SILENT ) == 0 )
        return FALSE;

	pLogData->dwSocket        = dwParameters[0];
 	pLogData->dwDbgBuffer     = dwParameters[1];
	pLogData->dwDbgBufferSize = dwParameters[2];

    // recvfrom_Return will resolve the sockaddr if success...
    if( dwParameters[5] != NULL )
    {
        if( Readmemory( &pLogData->dwValueB, dwParameters[5], sizeof(DWORD), MM_SILENT ) != 0 )
            pLogData->dwValueA = dwParameters[4];
    }

	ResolveFlags( (struct FLAGS *)&msg_flags, TRUE, dwParameters[3], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "recvfrom( %d, 0x%08X, %d, %s, 0x%08X, 0x%08X )", dwParameters[0], dwParameters[1], dwParameters[2], cFlagsOutput, dwParameters[4], dwParameters[5] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL send_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	// int send(  SOCKET s, char *buf, int len, int flags );
	DWORD dwParameters[4];
	char cFlagsOutput[MAX_PATH];

	if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*4, MM_SILENT ) == 0 )
        return FALSE;

	pLogData->dwSocket        = dwParameters[0];
    pLogData->dwDbgBuffer     = dwParameters[1];
    pLogData->dwDbgBufferSize = dwParameters[2];

    record_buffer( pLogData, SIZE_THRESHOLD );

	ResolveFlags( (struct FLAGS *)&msg_flags, TRUE, dwParameters[3], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "send( %d, 0x%08X, %d, %s )", dwParameters[0], dwParameters[1], dwParameters[2], cFlagsOutput );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL sendto_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	// int sendto( SOCKET s, char * buf, int len, int flags, struct sockaddr * to, int * tolen );
	DWORD dwParameters[6];
	char cFlagsOutput[MAX_PATH];

	if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*6, MM_SILENT ) == 0 )
        return FALSE;

	pLogData->dwSocket        = dwParameters[0];
 	pLogData->dwDbgBuffer     = dwParameters[1];
	pLogData->dwDbgBufferSize = dwParameters[2];

    record_buffer( pLogData, SIZE_THRESHOLD );

    record_sockaddr( pLogData, "Sending to", dwParameters[4], dwParameters[5] );

	ResolveFlags( (struct FLAGS *)&msg_flags, TRUE, dwParameters[3], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "sendto( %d, 0x%08X, %d, %s, 0x%08X, %d )", dwParameters[0], dwParameters[1], dwParameters[2], cFlagsOutput, dwParameters[4], dwParameters[5] );

	return TRUE;
}
//---------------------------------------------------------------------------


