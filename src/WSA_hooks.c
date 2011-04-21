//---------------------------------------------------------------------------
// OllySocketTrace - A Socket Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#include <stdio.h>
#include <winsock2.h>

#include "WSA_hooks.h"

#pragma nopackwarning

#define SIZE_THRESHOLD	0x0000FFFF // 65535 bytes
//---------------------------------------------------------------------------
extern LPVOID MyMalloc( DWORD dwSize );
extern BOOL MyFree( LPVOID lpAddress );

extern struct FLAGS af_flags[];
extern struct FLAGS type_flags[];
extern struct FLAGS protocol_flags[];
extern struct FLAGS msg_flags[];
//---------------------------------------------------------------------------
struct FLAGS wsasocket_flags[] = {
	{ WSA_FLAG_OVERLAPPED,        "WSA_FLAG_OVERLAPPED" },
	{ WSA_FLAG_MULTIPOINT_C_ROOT, "WSA_FLAG_MULTIPOINT_C_ROOT" },
	{ WSA_FLAG_MULTIPOINT_C_LEAF, "WSA_FLAG_MULTIPOINT_C_LEAF" },
    { WSA_FLAG_MULTIPOINT_D_ROOT, "WSA_FLAG_MULTIPOINT_D_ROOT" },
    { WSA_FLAG_MULTIPOINT_D_LEAF, "WSA_FLAG_MULTIPOINT_D_LEAF" },
	{ NULL, NULL }
};

struct FLAGS asyncselect_flags[] = {
	{ FD_READ,                     "FD_READ"                     },
	{ FD_WRITE,                    "FD_WRITE"                    },
	{ FD_OOB,                      "FD_OOB"                      },
	{ FD_ACCEPT,                   "FD_ACCEPT"                   },
	{ FD_CONNECT,                  "FD_CONNECT"                  },
	{ FD_CLOSE,                    "FD_CLOSE"                    },
	{ FD_QOS,                      "FD_QOS"                      },
	{ FD_GROUP_QOS,                "FD_GROUP_QOS"                },
	{ FD_ROUTING_INTERFACE_CHANGE, "FD_ROUTING_INTERFACE_CHANGE" },
	{ FD_ADDRESS_LIST_CHANGE,      "FD_ADDRESS_LIST_CHANGE"      },
	{ NULL, NULL }
};
//---------------------------------------------------------------------------
BOOL WSASocket_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    //SOCKET WSASocket( int af, int type, int protocol, LPWSAPROTOCOL_INFO lpProtocolInfo, GROUP g, DWORD dwFlags );
	DWORD dwParameters[6];
	char cFlagsOutput[MAX_PATH];
    char cFlagsOutput_AF[MAX_PATH];
	char cFlagsOutput_TYPE[MAX_PATH];
	char cFlagsOutput_PROTOCOL[MAX_PATH];

	if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*6, MM_SILENT ) == 0 )
        return FALSE;

	ResolveFlags( (struct FLAGS *)&af_flags, FALSE, dwParameters[0], (char *)&cFlagsOutput_AF );
	ResolveFlags( (struct FLAGS *)&type_flags, FALSE, dwParameters[1], (char *)&cFlagsOutput_TYPE );
	ResolveFlags( (struct FLAGS *)&protocol_flags, FALSE, dwParameters[2], (char *)&cFlagsOutput_PROTOCOL );
    ResolveFlags( (struct FLAGS *)&wsasocket_flags, FALSE, dwParameters[5], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "WSASocket( %s, %s, %s, 0x%08X, %d, %s )", cFlagsOutput_AF, cFlagsOutput_TYPE, cFlagsOutput_PROTOCOL, dwParameters[3], dwParameters[4], cFlagsOutput );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL WSAAccept_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // SOCKET WSAAccept( SOCKET s, struct sockaddr* addr, LPINT addrlen, LPCONDITIONPROC lpfnCondition, DWORD dwCallbackData );
    DWORD dwParameters[5];
   	if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*5, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];

    // accept_Return() will resolve the connecting sockaddr...
    if( dwParameters[2] != NULL )
    {
        if( Readmemory( &pLogData->dwValueB, dwParameters[2], sizeof(DWORD), MM_SILENT ) != 0 )
            pLogData->dwValueA = dwParameters[1];
    }

	snprintf( pLogData->cMessage, BUFFER_SIZE, "WSAAccept( %d, 0x%08X, 0x%08X, 0x%08X, 0x%08X )", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], dwParameters[4] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL WSAConnect_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    //int WSAConnect( SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData,
    //                LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS );
    DWORD dwParameters[7];
   	if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*7, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];

    record_sockaddr( pLogData, "Connecting to", dwParameters[1], dwParameters[2] );
    
	snprintf( pLogData->cMessage, BUFFER_SIZE, "WSAConnect( %d, 0x%08X, %d, 0x%08X, 0x%08X, 0x%08X, 0x%08X )", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], dwParameters[4], dwParameters[5], dwParameters[6] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL WSARecv_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
    DWORD dwNumberOfBytesRecvd = NULL;
    char cBuffer[BUFFER_SIZE];
    if( pLogData->dwValueA != NULL && pRegisters->r[REG_EAX] != (DWORD)SOCKET_ERROR )
    {
        if( Readmemory( &dwNumberOfBytesRecvd, pLogData->dwValueA, sizeof(DWORD), MM_SILENT ) != 0 )
        {
            snprintf( cBuffer, BUFFER_SIZE, "Recieved %d bytes. ", dwNumberOfBytesRecvd );
            strncat( pLogData->cHint, cBuffer, BUFFER_SIZE );

            if( dwNumberOfBytesRecvd > 0 )
            {
                if( dwNumberOfBytesRecvd < SIZE_THRESHOLD )
                    record_buffer( pLogData, dwNumberOfBytesRecvd );
                else
                    record_buffer( pLogData, SIZE_THRESHOLD );
            }
        }
    }

    if( pRegisters->r[REG_EAX] == (DWORD)SOCKET_ERROR )
    	snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "SOCKET_ERROR" );
    else
        snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "%d", pRegisters->r[REG_EAX] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL WSARecv_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // int WSARecv( SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd,
    //              LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped,
    //              LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine );
    DWORD dwParameters[7];
    WSABUF wsaBuffer;
   	char cFlagsOutput[MAX_PATH];

    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*7, MM_SILENT ) == 0 )
        return FALSE;
    pLogData->dwSocket = dwParameters[0];

    if( dwParameters[2] > 0 )
    {
        // TO-DO: support multiple buffers...
        if( Readmemory( &wsaBuffer, dwParameters[1], sizeof(WSABUF), MM_SILENT ) != 0 )
        {
            pLogData->dwDbgBuffer     = (DWORD)wsaBuffer.buf;
	        pLogData->dwDbgBufferSize = wsaBuffer.len;
        }
    }

    pLogData->dwValueA = dwParameters[3];

    ResolveFlags( (struct FLAGS *)&msg_flags, TRUE, dwParameters[4], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "WSARecv( %d, 0x%08X, %d, 0x%08X, %s, 0x%08X, 0x%08X )", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], cFlagsOutput, dwParameters[5], dwParameters[6] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL WSASend_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
    DWORD dwNumberOfBytesSent = NULL;
    char cBuffer[BUFFER_SIZE];

    if( pLogData->dwValueA != NULL && pRegisters->r[REG_EAX] != (DWORD)SOCKET_ERROR )
    {
        if( Readmemory( &dwNumberOfBytesSent, pLogData->dwValueA, sizeof(DWORD), MM_SILENT ) != 0 )
        {
            snprintf( cBuffer, BUFFER_SIZE, "Sent %d bytes. ", dwNumberOfBytesSent );
            strncat( pLogData->cHint, cBuffer, BUFFER_SIZE );
        }
    }

    return DefaultINT_Return( pLogData, pRegisters );
}
//---------------------------------------------------------------------------
BOOL WSASend_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // int WSASend( SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent,
    //              DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine );
    DWORD dwParameters[7];
    WSABUF wsaBuffer;
   	char cFlagsOutput[MAX_PATH];

    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*7, MM_SILENT ) == 0 )
        return FALSE;
    pLogData->dwSocket = dwParameters[0];

    ResolveFlags( (struct FLAGS *)&msg_flags, TRUE, dwParameters[4], (char *)&cFlagsOutput );

    pLogData->dwValueA = dwParameters[3];

    if( dwParameters[2] > 0 )
    {
        // TO-DO: support multiple buffers...
        if( Readmemory( &wsaBuffer, dwParameters[1], sizeof(WSABUF), MM_SILENT ) != 0 )
        {
            pLogData->dwDbgBuffer     = (DWORD)wsaBuffer.buf;
	        pLogData->dwDbgBufferSize = wsaBuffer.len;

            record_buffer( pLogData, SIZE_THRESHOLD );
        }
    }

	snprintf( pLogData->cMessage, BUFFER_SIZE, "WSASend( %d, 0x%08X, %d, 0x%08X, %s, 0x%08X, 0x%08X )", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], cFlagsOutput, dwParameters[5], dwParameters[6] );

	return TRUE;
}
//---------------------------------------------------------------------------
BOOL WSAAsyncSelect_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    //int WSAAsyncSelect( SOCKET s, HWND hWnd, unsigned int wMsg, long lEvent );
    DWORD dwParameters[4];
	char cFlagsOutput[MAX_PATH];

    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*4, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];

    ResolveFlags( (struct FLAGS *)&asyncselect_flags, TRUE, dwParameters[3], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "WSAAsyncSelect( %d, 0x%08X, 0x%08X, %s )", dwParameters[0], dwParameters[1], dwParameters[2], cFlagsOutput );

    return TRUE;
}
//---------------------------------------------------------------------------
BOOL WSAEventSelect_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    //int WSAEventSelect( SOCKET s, WSAEVENT hEventObject, long lNetworkEvents );
    DWORD dwParameters[3];
	char cFlagsOutput[MAX_PATH];

    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*3, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];

    ResolveFlags( (struct FLAGS *)&asyncselect_flags, TRUE, dwParameters[2], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "WSAEventSelect( %d, 0x%08X, %s )", dwParameters[0], dwParameters[1], cFlagsOutput );

    return TRUE;
}
//---------------------------------------------------------------------------
BOOL WSACloseEvent_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // BOOL WSACloseEvent( WSAEVENT hEvent );
    DWORD dwParameter;

    if( Readmemory( &dwParameter, pRegisters->r[REG_ESP]+4, sizeof(DWORD), MM_SILENT ) == 0 )
        return FALSE;

	snprintf( pLogData->cMessage, BUFFER_SIZE, "WSACloseEvent( 0x%08X )", dwParameter );

    return TRUE;
}
//---------------------------------------------------------------------------
BOOL WSASendTo_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // int WSASendTo( SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent,
    //                DWORD dwFlags, const struct sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped,
    //                LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine );
    DWORD dwParameters[9];
    char cFlagsOutput[MAX_PATH];
    WSABUF wsaBuffer;

    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*9, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];

    pLogData->dwValueA = dwParameters[3];

    record_sockaddr( pLogData, "Sending to", dwParameters[5], dwParameters[6] );

    if( dwParameters[2] > 0 )
    {
        // TO-DO: support multiple buffers...
        if( Readmemory( &wsaBuffer, dwParameters[1], sizeof(WSABUF), MM_SILENT ) != 0 )
        {
            pLogData->dwDbgBuffer     = (DWORD)wsaBuffer.buf;
	        pLogData->dwDbgBufferSize = wsaBuffer.len;

            record_buffer( pLogData, SIZE_THRESHOLD );
        }
    }

    ResolveFlags( (struct FLAGS *)&msg_flags, TRUE, dwParameters[4], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "WSASendTo( %d, 0x%08X, %d, 0x%08X, %s, 0x%08X, %d, 0x%08X, 0x%08X )", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], cFlagsOutput, dwParameters[5], dwParameters[6], dwParameters[7], dwParameters[8] );

    return TRUE;
}
//---------------------------------------------------------------------------
BOOL WSARecvFrom_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
    record_sockaddr( pLogData, "Recieved from", pLogData->dwValueB, pLogData->dwValueC );
    return WSARecv_Return( pLogData, pRegisters );
}
//---------------------------------------------------------------------------
BOOL WSARecvFrom_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
    // int WSARecvFrom( SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd,
    //                  LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped,
    //                  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine );
    DWORD dwParameters[9];
    char cFlagsOutput[MAX_PATH];
    WSABUF wsaBuffer;

    if( Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*9, MM_SILENT ) == 0 )
        return FALSE;

    pLogData->dwSocket = dwParameters[0];
    if( dwParameters[2] > 0 )
    {
        // TO-DO: support multiple buffers...
        if( Readmemory( &wsaBuffer, dwParameters[1], sizeof(WSABUF), MM_SILENT ) != 0 )
        {
            pLogData->dwDbgBuffer     = (DWORD)wsaBuffer.buf;
	        pLogData->dwDbgBufferSize = wsaBuffer.len;
        }
    }

    pLogData->dwValueA = dwParameters[3]; // lpNumberOfBytesRecvd

    if( dwParameters[6] != NULL ) // lpFromlen
    {
        if( Readmemory( &pLogData->dwValueC, dwParameters[6], sizeof(DWORD), MM_SILENT ) != 0 )
            pLogData->dwValueB = dwParameters[5]; // lpFrom
    }

    ResolveFlags( (struct FLAGS *)&msg_flags, TRUE, dwParameters[4], (char *)&cFlagsOutput );

	snprintf( pLogData->cMessage, BUFFER_SIZE, "WSARecvFrom( %d, 0x%08X, %d, 0x%08X, %s, 0x%08X, 0x%08X, 0x%08X, 0x%08X )", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], cFlagsOutput, dwParameters[5], dwParameters[6], dwParameters[7], dwParameters[8] );

    return TRUE;
}
//---------------------------------------------------------------------------
