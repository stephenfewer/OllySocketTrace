//---------------------------------------------------------------------------
// OllySocketTrace - A Socket Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#include "breakpoint.h"

struct HOOK hooks[] = {

    // wininet.dll
    // InternetOpenUrl ...
    // HttpOpenRequest ...

    // mswsock.dll
    // AcceptEx
    // WSARecvEx
    // WSARecvMsg
    // TransmitFile
    // ConnectEx
    // DisconnectEx
    // TransmitPackets

    // ws2_32.dll
    // WSAIoctl
    // WSAJoinLeaf 
    // WSARecvDisconnect
    // WSASendDisconnect
    // WSACloseEvent
    // WSASetEvent
    // WSACreateEvent
    // WSAResetEvent


    { "ws2_32",  "WSASocketA",     NULL, WSASocket_Call,         socket_Return     },
    { "ws2_32",  "WSASocketW",     NULL, WSASocket_Call,         socket_Return     },
    { "ws2_32",  "WSAAccept",      NULL, WSAAccept_Call,         accept_Return     },
    { "ws2_32",  "WSAConnect",     NULL, WSAConnect_Call,        DefaultINT_Return },
    { "ws2_32",  "WSARecv",        NULL, WSARecv_Call,           WSARecv_Return    },
    { "ws2_32",  "WSARecvFrom",    NULL, WSARecvFrom_Call,       WSARecvFrom_Return},
    { "ws2_32",  "WSASend",        NULL, WSASend_Call,           WSASend_Return    },
    { "ws2_32",  "WSASendTo",      NULL, WSASendTo_Call,         WSASend_Return    },
    { "ws2_32",  "WSAAsyncSelect", NULL, WSAAsyncSelect_Call,    DefaultINT_Return },
    { "ws2_32",  "WSAEventSelect", NULL, WSAAsyncSelect_Call,    DefaultINT_Return },
    { "ws2_32",  "WSACloseEvent",  NULL, WSACloseEvent_Call,     DefaultBOOL_Return},


    { "ws2_32",  "listen",         NULL, listen_Call,            DefaultINT_Return },
    { "ws2_32",  "ioctlsocket",    NULL, ioctlsocket_Call,       DefaultINT_Return },
    { "ws2_32",  "connect",        NULL, connect_Call,           DefaultINT_Return },
    { "ws2_32",  "bind",           NULL, bind_Call,              DefaultINT_Return },
    { "ws2_32",  "accept",         NULL, accept_Call,            accept_Return     },
	{ "ws2_32",  "socket",         NULL, socket_Call,            socket_Return     },
	{ "ws2_32",  "closesocket",    NULL, closesocket_Call,       DefaultINT_Return },
    { "ws2_32",  "shutdown",       NULL, shutdown_Call,          DefaultINT_Return },
	{ "ws2_32",  "recv",           NULL, recv_Call,              recv_Return       },
	{ "ws2_32",  "recvfrom",       NULL, recvfrom_Call,          recvfrom_Return   },
	{ "ws2_32",  "send",           NULL, send_Call,              DefaultINT_Return },
    { "ws2_32",  "sendto",         NULL, sendto_Call,            DefaultINT_Return },

    { "wsock32", "listen",         NULL, listen_Call,            DefaultINT_Return },
    { "wsock32", "ioctlsocket",    NULL, ioctlsocket_Call,       DefaultINT_Return },
    { "wsock32", "connect",        NULL, connect_Call,           DefaultINT_Return },
    { "wsock32", "bind",           NULL, bind_Call,              DefaultINT_Return },
    { "wsock32", "accept",         NULL, accept_Call,            accept_Return     },
	{ "wsock32", "socket",         NULL, socket_Call,            socket_Return     },
	{ "wsock32", "closesocket",    NULL, closesocket_Call,       DefaultINT_Return },
    { "wsock32", "shutdown",       NULL, shutdown_Call,          DefaultINT_Return },
	{ "wsock32", "recv",           NULL, recv_Call,              recv_Return       },
	{ "wsock32", "recvfrom",       NULL, recvfrom_Call,          recvfrom_Return   },
	{ "wsock32", "send",           NULL, send_Call,              DefaultINT_Return },
    { "wsock32", "sendto",         NULL, sendto_Call,            DefaultINT_Return },

	{ NULL, NULL, NULL, NULL, NULL }
};

volatile DWORD dwLogIndex = 0;
//---------------------------------------------------------------------------
t_module * Breakpoint_FindModule( t_table * modtable, const char * cpName )
{
	int i;
	t_module *  m = (t_module *)modtable->data.data;
	for( i=0 ; i<modtable->data.n ; i++ )
	{
		if( strnicmp( cpName, m[i].name, SHORTLEN ) == 0 )
			return &m[i];
	}
	return NULL;
}


//---------------------------------------------------------------------------
BOOL Breakpoint_Create( t_module * m, const char * cpName, DWORD * pAddress )
{
	if( Findlabelbyname( (char *)cpName, pAddress, m->codebase, (m->codebase + m->codesize) ) != NM_NONAME )
	{
		if( Setbreakpoint( *pAddress, TY_ACTIVE, 0 ) == 0 )
			return TRUE;
	}
	return FALSE;
}

//---------------------------------------------------------------------------
void Breakpoints_Disable( BOOL bDisable )
{
	int i = 0;

	while( hooks[i].cpModuleName != NULL )
	{
		if( hooks[i].dwFunctionAddress != NULL )
		{
			if( bDisable )
				Setbreakpoint( hooks[i].dwFunctionAddress, TY_DISABLED, 0 );
			hooks[i].dwFunctionAddress = NULL;
		}
		i++;
	}
}
//---------------------------------------------------------------------------
BOOL Breakpoints_Enable( void )
{
	BOOL bSuccess;
	t_module * m;
	int i = 0, count = 0;
	t_table * modtable = (t_table *)Plugingetvalue( VAL_MODULES );

	__try
	{
		while( hooks[i].cpModuleName != NULL )
		{
			// fix case insensitive search!!!
			m = Breakpoint_FindModule( modtable, hooks[i].cpModuleName );
			if( m == NULL )
			{
				Addtolist( 0, 1, "%s: Warning, failed to find the module %s", OLLYST_NAME, hooks[i].cpModuleName );
			}
            else
            {
			    if( !Breakpoint_Create( m, hooks[i].cpFunctionName, &hooks[i].dwFunctionAddress ) )
					Addtolist( 0, 1, "%s: Warning, failed to create a breakpoint for %s.%s", OLLYST_NAME, hooks[i].cpModuleName, hooks[i].cpFunctionName );
                else
                    count++;
            }

			i++;
		}

        if( count == 0 )
            RaiseException( 2, 0, 0, NULL );

		bSuccess = TRUE;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
        Breakpoints_Disable( TRUE );
        bSuccess = FALSE;
        Addtolist( 0, 1, "%s: Error, failed to enable any of the required breakpoints", OLLYST_NAME );
	}
	return bSuccess;
}
//---------------------------------------------------------------------------
BOOL Breakpoint_Handle( t_reg * pRegisters, DEBUG_EVENT * pDebugEvent, t_table * logtable )
{
    BOOL bFound = FALSE;
    BOOL bSuccess;
	int i = 0;
	LPLOGDATA pLogData;

	while( hooks[i].cpModuleName != NULL )
	{
		if( pRegisters->ip == hooks[i].dwFunctionAddress )
		{
			pLogData = (LPLOGDATA)MyMalloc( sizeof(LOGDATA) );
            if( pLogData == NULL )
                break;
			memset( pLogData, 0, sizeof(LOGDATA) );

            // we must record the freq to make proper use of the high perf counter
            // BOOL QueryPerformanceFrequency( LARGE_INTEGER* lpFrequency );
            // and save this to the xml, along with PID, process name, ...
            
            //QueryPerformanceCounter( &(pLogData->liPerformanceCount_Start) );

			pLogData->dwAddress  = dwLogIndex++;
			pLogData->dwSize     = 1;
			pLogData->iHookIndex = i;
			pLogData->dwThreadId = pDebugEvent->dwThreadId;

			if( Readmemory( &pLogData->dwCallerAddress, pRegisters->r[REG_ESP], 4, MM_SILENT ) == 0 )
                break;

			if( hooks[i].handle_call != NULL )
            {
				if( hooks[i].handle_call( pLogData, pRegisters ) )
                {
    			    if( hooks[i].handle_return != NULL )
				        Setbreakpoint( pLogData->dwCallerAddress, TY_ONESHOT, 0 );//TY_ONESHOT//TY_ACTIVE

			        Addsorteddata( &(logtable->data), pLogData );
			        bFound = TRUE;
                }
                else
                {
                    MyFree( pLogData );
                }
            }
			break;
		}
		i++;
	}

	if( !bFound )
	{
		pLogData = (LPLOGDATA)logtable->data.data;
		for( i=0 ; i<logtable->data.n ; i++ )
		{
			if( pRegisters->ip == pLogData[i].dwCallerAddress && !pLogData[i].bReturnMessageSet )
			{
                //QueryPerformanceCounter( &(pLogData->liPerformanceCount_End) );
				if( hooks[pLogData[i].iHookIndex].handle_return != NULL )
					pLogData[i].bReturnMessageSet = hooks[pLogData[i].iHookIndex].handle_return( &pLogData[i], pRegisters );
				bFound = TRUE;
				break;
			}
		}
	}

    return bFound;
}
//---------------------------------------------------------------------------
