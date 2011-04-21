//---------------------------------------------------------------------------
// OllySocketTrace - A Socket Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#ifndef HOOKS_H
#define HOOKS_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "Plugin.h"

#pragma nopackwarning

#define BUFFER_SIZE	         256

typedef struct _LOGDATA
{
	DWORD dwAddress;
	DWORD dwSize;
	DWORD dwType;

    //LARGE_INTEGER liPerformanceCount_Start;
    //LARGE_INTEGER liPerformanceCount_End;

	DWORD dwCallerAddress;
	DWORD dwThreadId;

	DWORD dwSocket;

	DWORD dwDbgBuffer;    // the address of the buffer(if any) in the debugged process
	DWORD dwDbgBufferSize;

    LPVOID lpOllyBuffer;   // a malloced address in olly's address space
	DWORD dwOllyBufferSize;

	char cMessage[BUFFER_SIZE];
	char cReturnMessage[BUFFER_SIZE];
    char cHint[BUFFER_SIZE];
	BOOL bReturnMessageSet;
	int iHookIndex;

    DWORD dwValueA;
    DWORD dwValueB;
    DWORD dwValueC;

} LOGDATA, * LPLOGDATA;

typedef BOOL (* HOOK_FUNC)( LPLOGDATA pLogData, t_reg * pRegisters );

struct HOOK
{
	const char * cpModuleName;
	const char * cpFunctionName;
	DWORD dwFunctionAddress;
	HOOK_FUNC handle_call;
	HOOK_FUNC handle_return;
};

struct FLAGS
{
	DWORD dwValue;
	const char * cpName;
};

VOID ResolveFlags( struct FLAGS * pFlags, BOOL bORed, DWORD dwFlags, char * cpOutput );
BOOL record_sockaddr( LPLOGDATA pLogData, const char * cpMessage, DWORD dw_pSockAddr, DWORD dwSockAddrLength );
BOOL record_buffer( LPLOGDATA pLogData, DWORD dwThreshold );

//BOOL DefaultDWORD_Return( LPLOGDATA, t_reg *, t_reg * pRegisters );
BOOL DefaultBOOL_Return( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL DefaultINT_Return( LPLOGDATA pLogData, t_reg * pRegisters  );

BOOL listen_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL ioctlsocket_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL connect_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL bind_Call( LPLOGDATA pLogData, t_reg * pRegisters );

BOOL accept_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL accept_Return( LPLOGDATA pLogData, t_reg * pRegisters );

BOOL socket_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL socket_Return( LPLOGDATA pLogData, t_reg * pRegisters );

BOOL shutdown_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL closesocket_Call( LPLOGDATA pLogData, t_reg * pRegisters );

BOOL recv_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL recv_Return( LPLOGDATA pLogData, t_reg * pRegisters );

BOOL recvfrom_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL recvfrom_Return( LPLOGDATA pLogData, t_reg * pRegisters );

BOOL send_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL sendto_Call( LPLOGDATA pLogData, t_reg * pRegisters );

#endif
