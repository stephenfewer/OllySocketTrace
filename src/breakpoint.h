//---------------------------------------------------------------------------
// OllySocketTrace - A Socket Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "Plugin.h"
#include "hooks.h"
#include "WSA_hooks.h"

extern LPVOID MyMalloc( DWORD dwSize );
extern LPVOID MyReAlloc( LPVOID lpAddress, DWORD dwSize );
extern BOOL MyFree( LPVOID lpAddress );

void Breakpoints_Disable( BOOL bDisable );
BOOL Breakpoints_Enable( void );
BOOL Breakpoint_Handle( t_reg * pRegisters, DEBUG_EVENT * pDebugEvent, t_table * logtable );

#endif
