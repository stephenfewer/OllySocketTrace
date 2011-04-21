//---------------------------------------------------------------------------
// OllySocketTrace - A Socket Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#ifndef TRACEDIALOG_H
#define TRACEDIALOG_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "resource.h"
#include "hooks.h"

BOOL TraceDialog_Create( HINSTANCE hInstance, char * cpText );
char * TraceDialog_FormatTrace( LPLOGDATA pLogData, int iCount, DWORD dwSocket );

#endif
