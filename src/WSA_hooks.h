//---------------------------------------------------------------------------
// OllySocketTrace - A Socket Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#ifndef WSAHOOKS_H
#define WSAHOOKS_H

#include "hooks.h"

BOOL WSASocket_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSAAccept_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSAConnect_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSARecv_Return( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSARecv_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSASend_Return( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSASend_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSAAsyncSelect_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSAEventSelect_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSACloseEvent_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSASendTo_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSARecvFrom_Call( LPLOGDATA pLogData, t_reg * pRegisters );
BOOL WSARecvFrom_Return( LPLOGDATA pLogData, t_reg * pRegisters );
#endif
