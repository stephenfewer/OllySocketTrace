//---------------------------------------------------------------------------
// OllySocketTrace - A Socket Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "TraceDialog.h"
#include "hooks.h"
#include "breakpoint.h"
#pragma nopackwarning
//---------------------------------------------------------------------------
#pragma link ".\\bin\\OllyDbg.lib"
//---------------------------------------------------------------------------
struct COLORS
{
	BYTE bColor;
	DWORD dwSocket;
};

#define COLOR_COUNT         NCOLORS-1
struct COLORS colors[COLOR_COUNT] = {0};
//---------------------------------------------------------------------------
HINSTANCE hDll               = NULL;
HANDLE hOllyWindow           = NULL;
HANDLE hMyHeap               = NULL;
volatile BOOL bEnabled       = FALSE;
char cLogWindowClass[32]     = { 0 };
t_table logtable             = { 0 };
//---------------------------------------------------------------------------
LPVOID MyMalloc( DWORD dwSize )
{
    if( dwSize == NULL )
        return NULL;
    return HeapAlloc( hMyHeap, 0, dwSize );
}
//---------------------------------------------------------------------------
LPVOID MyReAlloc( LPVOID lpAddress, DWORD dwSize )
{
    if( lpAddress == NULL || dwSize == NULL )
        return NULL;
    return HeapReAlloc( hMyHeap, 0, lpAddress, dwSize );
}
//---------------------------------------------------------------------------
BOOL MyFree( LPVOID lpAddress )
{
    if( lpAddress == NULL )
        return FALSE;
    return (BOOL)HeapFree( hMyHeap, 0, lpAddress );
}
//---------------------------------------------------------------------------
int WINAPI DllEntryPoint( HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved )
{
  if( dwReason == DLL_PROCESS_ATTACH )
	hDll = hInstance;
  return 1;
}
//---------------------------------------------------------------------------
int _export cdecl ODBG_Plugindata( char cShortname[32] )
{
  strcpy( cShortname, OLLYST_NAME );
  return PLUGIN_VERSION;
}
//---------------------------------------------------------------------------
BYTE GetColor( DWORD dwSocket )
{
	int i;
	for( i=0 ; i<COLOR_COUNT ; i++ )
	{
		if( colors[i].dwSocket == dwSocket )
			return colors[i].bColor;
	}
	for( i=0 ; i<COLOR_COUNT ; i++ )
	{
		if( colors[i].dwSocket == NULL )
		{
			colors[i].dwSocket = dwSocket;
            return colors[i].bColor;
		}
	}
	return GRAY;
}
//---------------------------------------------------------------------------
int LogWindowGetText( char * cpBuffer, char * pMask, int * pSelect, t_sortheader * pHeader, int iColumn )
{
	int i = 0;
	LPLOGDATA pLogData = (LPLOGDATA)pHeader;
	BYTE bColor = GetColor( pLogData->dwSocket );

	if( iColumn == 0 )
	{
		*pSelect = DRAW_GRAY;
		i = Decodeaddress( pLogData->dwCallerAddress, 0, ADC_VALID, cpBuffer, BUFFER_SIZE, NULL );
		if( i == 0 )
			i = snprintf( cpBuffer, BUFFER_SIZE, "0x%.8X", pLogData->dwCallerAddress );
	}
	else if( iColumn == 1 )
	{
		*pSelect = DRAW_GRAY;
		i = snprintf( cpBuffer, BUFFER_SIZE, "0x%.8X", pLogData->dwThreadId );
	}
	else if( iColumn == 2 )
	{
		i = snprintf( cpBuffer, BUFFER_SIZE, "%s", pLogData->cMessage );
		*pSelect = DRAW_MASK;
		memset( pMask, DRAW_DIRECT|bColor, i );
	}
	else if( iColumn == 3 )
	{
		if( strlen( pLogData->cReturnMessage ) > 0 )
		{
			i = snprintf( cpBuffer, BUFFER_SIZE, "%s", pLogData->cReturnMessage );
			*pSelect = DRAW_MASK;
			memset( pMask, DRAW_DIRECT|bColor, i );
		}
	}
	else if( iColumn == 4 )
	{
		*pSelect = DRAW_GRAY;
        i = snprintf( cpBuffer, BUFFER_SIZE, "%s", pLogData->cHint );
	}
	return i;
}
//---------------------------------------------------------------------------
void CreateLogWindow( void )
{
	if( logtable.bar.nbar == 0 )
	{
		logtable.bar.name[0]    = "Caller";
		logtable.bar.defdx[0]   = 20;
		logtable.bar.mode[0]    = BAR_NOSORT;

		logtable.bar.name[1]    = "Thread";
		logtable.bar.defdx[1]   = 12;
		logtable.bar.mode[1]    = BAR_NOSORT;

		logtable.bar.name[2]    = "Function Call";
		logtable.bar.defdx[2]   = 48;
		logtable.bar.mode[2]    = BAR_NOSORT;

		logtable.bar.name[3]    = "Return Value";
		logtable.bar.defdx[3]   = 14;
		logtable.bar.mode[3]    = BAR_NOSORT;

        logtable.bar.name[4]    = "Hint";
		logtable.bar.defdx[4]   = 24;
		logtable.bar.mode[4]    = BAR_NOSORT;

		logtable.bar.nbar       = 5;
		logtable.mode           = TABLE_COPYMENU|TABLE_APPMENU|TABLE_SAVEPOS|TABLE_ONTOP;
		logtable.drawfunc       = LogWindowGetText;
	}
	Quicktablewindow( &logtable, 15, logtable.bar.nbar, cLogWindowClass, "OllySocketTrace - Log" );
}
//---------------------------------------------------------------------------
VOID HandleRightClick( HWND hw )
{
	LPLOGDATA pLogData;
	HMENU hMenu;
	int i;
	char cBuffer[BUFFER_SIZE];

	hMenu = CreatePopupMenu();
	pLogData = (LPLOGDATA)Getsortedbyselection( &(logtable.data), logtable.data.selected );
	if( hMenu != NULL && pLogData != NULL )
	{
		if( pLogData->dwSocket != NULL )
		{
            snprintf( cBuffer, BUFFER_SIZE, "Delete entire trace" );
			AppendMenu( hMenu, MF_STRING, 1, cBuffer );

			snprintf( cBuffer, BUFFER_SIZE, "Delete trace for socket %d", pLogData->dwSocket );
			AppendMenu( hMenu, MF_STRING, 2, cBuffer );

            AppendMenu( hMenu, MF_SEPARATOR, 3, NULL );

			snprintf( cBuffer, BUFFER_SIZE, "View data trace for socket %d", pLogData->dwSocket );
			AppendMenu( hMenu, MF_STRING, 4, cBuffer );

			if( pLogData->dwDbgBuffer != NULL )
			{
				snprintf( cBuffer, BUFFER_SIZE, "View dump of buffer 0x%.8X", pLogData->dwDbgBuffer );
				AppendMenu( hMenu, MF_STRING, 5, cBuffer );
			}

		}
	}
	i = Tablefunction( &logtable, hw, WM_USER_MENU, 0, (LPARAM)hMenu );
	if( hMenu != NULL )
		DestroyMenu( hMenu );

	if( i == 1 )
	{
        if( MessageBox( hOllyWindow, "Delete the entire trace?", "OllySocketTrace - Delete entire trace", MB_YESNO | MB_ICONQUESTION ) == IDYES )
        {
	        pLogData = (LPLOGDATA)logtable.data.data;
	        for( i=0 ; i<logtable.data.n ; i++ )
            {
                if( pLogData[i].lpOllyBuffer != NULL )
                    MyFree( pLogData[i].lpOllyBuffer );

                Deletesorteddata( &(logtable.data), pLogData[i].dwAddress );

                MyFree( &pLogData[i] );

                i = -1;
                continue;
            }
            InvalidateRect( hw, NULL, FALSE );
        }
    }
    else if( i == 2 )
	{
        snprintf( cBuffer, BUFFER_SIZE, "Delete the trace for socket %d", pLogData->dwSocket );
        if( MessageBox( hOllyWindow, cBuffer, "OllySocketTrace - Delete trace", MB_YESNO | MB_ICONQUESTION ) == IDYES )
        {
		    DWORD dwSocket = pLogData->dwSocket;
		    pLogData = (LPLOGDATA)logtable.data.data;
		    for( i=0 ; i<logtable.data.n ; i++ )
		    {
			    if( pLogData[i].dwSocket == dwSocket )
			    {
				    if( pLogData[i].lpOllyBuffer != NULL )
                        MyFree( pLogData[i].lpOllyBuffer );
                    Deletesorteddata( &(logtable.data), pLogData[i].dwAddress );
                    MyFree( &pLogData[i] );
				    i = -1;
				    continue;
			    }
		    }
		    InvalidateRect( hw, NULL, FALSE );
        }
	}
	else if( i == 4 )
	{
        char * cpText = TraceDialog_FormatTrace( (LPLOGDATA)logtable.data.data, logtable.data.n, pLogData->dwSocket );
        if( cpText == NULL )
        {
            MessageBox( hOllyWindow, "No data to display.", "OllySocketTrace - Data Trace", MB_OK | MB_ICONINFORMATION );
        }
        else
        {
            TraceDialog_Create( hDll, cpText );
            MyFree( cpText );
        }
    }
	else if( i == 5 )
	{
		Createdumpwindow( "OllySocketTrace - Dump Buffer", pLogData->dwDbgBuffer, pLogData->dwDbgBufferSize, 0, 0x01101, NULL );
	}
}
//---------------------------------------------------------------------------
LRESULT CALLBACK LogWindowProc( HWND hw,UINT msg,WPARAM wp,LPARAM lp)
{
	LPLOGDATA pLogData;

	switch( msg )
	{
		case WM_DESTROY:
		case WM_MOUSEMOVE:
		case WM_LBUTTONDOWN:
		case WM_LBUTTONDBLCLK:
		case WM_LBUTTONUP:
		case WM_RBUTTONDOWN:
		case WM_RBUTTONDBLCLK:
		case WM_HSCROLL:
		case WM_VSCROLL:
		case WM_TIMER:
		case WM_SYSKEYDOWN:
		case WM_USER_SCR:
		case WM_USER_VABS:
		case WM_USER_VREL:
		case WM_USER_VBYTE:
		case WM_USER_STS:
		case WM_USER_CNTS:
		case WM_USER_CHGS:
		case WM_KEYDOWN:
			return Tablefunction( &logtable, hw, msg, wp, lp );
		case WM_USER_MENU:
			HandleRightClick( hw );
			return 0;
		case WM_USER_DBLCLK:
			pLogData = (LPLOGDATA)Getsortedbyselection( &(logtable.data), logtable.data.selected );
			if ( pLogData != NULL )
				Setcpu( 0, pLogData->dwCallerAddress, 0, 0, CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS );
			return 1;
		case WM_USER_CHALL:
		case WM_USER_CHMEM:
			InvalidateRect( hw, NULL, FALSE );
			return 0;
		case WM_PAINT:
			Painttable( hw, &logtable, LogWindowGetText );
			return 0;
		default: break;
	}
	return DefMDIChildProc( hw, msg, wp, lp );
}
//---------------------------------------------------------------------------
int _export cdecl ODBG_Plugininit( int iOllyVersion, HWND hWindow, DWORD * features )
{
	int i;
	if( iOllyVersion < PLUGIN_VERSION )
		return -1;

    hMyHeap = HeapCreate( 0, 4096, 0 );
    if( !hMyHeap )
    {
        Addtolist( 0, 1, "%s: Error, failed to create internal heap", OLLYST_NAME );
        return -1;
    }

	hOllyWindow = hWindow;

	bEnabled = FALSE;

	if( Createsorteddata( &(logtable.data), NULL, sizeof(LOGDATA), 64, NULL, NULL ) != 0 )
		return -1;

	if( Registerpluginclass( cLogWindowClass, NULL, hDll, LogWindowProc ) < 0 )
	{
		Destroysorteddata( &(logtable.data) );
		return -1;
	}

	for( i=0 ; i<COLOR_COUNT ; i++ )
	{
		colors[i].bColor = i+1;
		colors[i].dwSocket = NULL;
	}
	colors[COLOR_COUNT-1].bColor = BLACK;

	Addtolist( 0, 0, "%s plugin v%s", OLLYST_NAME, OLLYST_VERSION );
	Addtolist( 0, -1, "  %s", OLLYST_ABOUT );

	return 0;
}
//---------------------------------------------------------------------------
void _export cdecl ODBG_Plugindestroy( void )
{
	int i;
	LPLOGDATA pLogData;
	bEnabled = FALSE;

	Unregisterpluginclass( cLogWindowClass );

	pLogData = (LPLOGDATA)logtable.data.data;
	for( i=0 ; i<logtable.data.n ; i++ )
    {
        if( pLogData[i].lpOllyBuffer != NULL )
            MyFree( pLogData[i].lpOllyBuffer );
		MyFree( &pLogData[i] );
    }

	Destroysorteddata( &(logtable.data) );
    // we dont need to create a new sorteddata when were are destroying the plugin
    
	Breakpoints_Disable( FALSE );

    HeapDestroy( hMyHeap );
}
//---------------------------------------------------------------------------
void _export cdecl ODBG_Pluginreset( void )
{
	int i;
	LPLOGDATA pLogData;
	bEnabled = FALSE;

	pLogData = (LPLOGDATA)logtable.data.data;
	for( i=0 ; i<logtable.data.n ; i++ )
    {
        if( pLogData[i].lpOllyBuffer != NULL )
            MyFree( pLogData[i].lpOllyBuffer );
		MyFree( &pLogData[i] );
    }

	Destroysorteddata( &(logtable.data) );
	Createsorteddata( &(logtable.data), NULL, sizeof(LOGDATA), 64, NULL, NULL );

	Breakpoints_Disable( FALSE );

    // we dont destroy our heap when we reset
}
//---------------------------------------------------------------------------
int _export cdecl ODBG_Pluginmenu( int iOrigin, char cData[4096], LPVOID lpItem )
{
	switch( iOrigin )
	{
		case PM_MAIN:
			strcpy( cData, "0 &Enable/Disable,1 &View Log,|2 &About" );
			return 1;
		default:
			break;
	}
	return 0;
}
//---------------------------------------------------------------------------
void _export cdecl ODBG_Pluginaction( int iOrigin, int iAction, LPVOID lpItem )
{
	char cBuffer[BUFFER_SIZE];

	if( iOrigin == PM_MAIN )
	{
		switch( iAction )
		{
			// Enable/Disable
			case 0:
				if( bEnabled )
					bEnabled = FALSE;
				else
					bEnabled = TRUE;

				if( bEnabled )
					bEnabled = Breakpoints_Enable();
				else
					Breakpoints_Disable( TRUE );
				
				Flash( "%s %s.", OLLYST_NAME, ( bEnabled ? "Enabled" : "Disabled" ) );
				break;

			// View Log
			case 1:
				CreateLogWindow();
				break;

			// About
			case 2:
				snprintf( cBuffer, BUFFER_SIZE, "%s v%s\n%s", OLLYST_NAME, OLLYST_VERSION, OLLYST_ABOUT );
				MessageBox( hOllyWindow, cBuffer, "About", MB_OK|MB_ICONINFORMATION );
				break;

			default:
				break;
		}
	}
}
//---------------------------------------------------------------------------
int  _export cdecl ODBG_Pausedex( int iReason, int iExtData, t_reg * pRegisters, DEBUG_EVENT * pDebugEvent )
{
	if( !bEnabled || pRegisters == NULL && ((iReason & PP_INT3BREAK) != PP_INT3BREAK) )
		return 0;

	if( Breakpoint_Handle( pRegisters, pDebugEvent, &logtable ) )
	{
		Go( 0, 0, STEP_RUN, 1, 1 );
    	return 1;
	}

	return 0;
}
//---------------------------------------------------------------------------

