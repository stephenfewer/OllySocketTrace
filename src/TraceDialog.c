//---------------------------------------------------------------------------
// OllySocketTrace - A Socket Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include "TraceDialog.h"

extern LPVOID MyMalloc( DWORD dwSize );
extern LPVOID MyReAlloc( LPVOID lpAddress, DWORD dwSize );
extern BOOL MyFree( LPVOID lpAddress );
//---------------------------------------------------------------------------
HWND hWnd           = NULL;
char * cpDialogText = NULL;
//---------------------------------------------------------------------------
void PrintHex( char * cpOutput, DWORD dwOutputSize, BYTE * pBuffer, int size )
{
	int x, y;
	char cBuff[1024];
	memset( cBuff, 0, 1024 );
	memset( cpOutput, 0, dwOutputSize );
	dwOutputSize -= 4;

	for( x=1; x<=size; x++ )
	{
		if( x == 1 )
		{
			snprintf( cBuff, 1024, "%04X  ", x-1 ); // Print an offset line header
			strncat( cpOutput, cBuff, dwOutputSize );
		}

		snprintf( cBuff, 1024, "%02X ", pBuffer[x-1] ); // print the hex value
		strncat( cpOutput, cBuff, dwOutputSize );

		//if( x % 8 == 0 )
		//	strncat( cpOutput, " ", dwOutputSize ); // padding space at 8 and 16 bytes

		if( x % 16 == 0 )
		{
			// We're at the end of a line of hex, print the printables
			strncat( cpOutput, " ", dwOutputSize );

			for( y = x - 15; y <= x; y++ )
			{
				if( isprint( pBuffer[y-1] ) )
				{
					snprintf( cBuff, 1024, "%c", pBuffer[y-1] ); // if it's printable, print it
					strncat( cpOutput, cBuff, dwOutputSize );
				}
				else
					strncat( cpOutput, ".", dwOutputSize ); // otherwise substitute a period

				//if( y % 8 == 0 )
				//	strncat( cpOutput, " ", dwOutputSize ); // 8 byte padding space
			}

			if( x < size )
			{
				snprintf( cBuff, 1024, "\r\n%04X  ", x ); // Print an offset line header
				strncat( cpOutput, cBuff, dwOutputSize );
			}
		}
	}
	x--;

	// If we didn't end on a 16 byte boundary, print some placeholder spaces before printing ascii
	if( x % 16 != 0 )
	{
		for( y = x+1; y <= x + (16-(x % 16)); y++ )
		{
			strncat( cpOutput, "   ", dwOutputSize ); // hex value placeholder spaces
			//if( y % 8 == 0 )
			//	strncat( cpOutput, " ", dwOutputSize ); // 8 and 16 byte padding spaces
		}

		// print the printables
		strncat( cpOutput, " ", dwOutputSize );
		for( y = (x+1) - (x % 16); y <= x; y++ )
		{
			if( isprint( pBuffer[y-1] ) )
			{
				snprintf( cBuff, 1024, "%c", pBuffer[y-1] ); // if it's printable, print it
				strncat( cpOutput, cBuff, dwOutputSize );
			}
			else
				strncat( cpOutput, ".", dwOutputSize ); // otherwise substitute a period

			//if( y % 8 == 0 )
			//	strncat( cpOutput, " ", dwOutputSize ); // 8 and 16 byte padding space
		}
	}

	strncat( cpOutput, "\r\n", dwOutputSize );
}
//---------------------------------------------------------------------------
LRESULT CALLBACK DlgProc( HWND hWndDlg, UINT Msg, WPARAM wParam, LPARAM lParam )
{
	HWND hEditText;
	switch( Msg )
	{
		case WM_INITDIALOG:
			hEditText = GetDlgItem( hWndDlg, IDC_EDIT1 );
			if( hEditText && cpDialogText )
				return SetWindowText( hEditText, cpDialogText );
			return TRUE;

		case WM_COMMAND:
			switch( wParam )
			{
				case IDOK:
					EndDialog( hWndDlg, 0 );
					return TRUE;
			}
		break;
	}
	return FALSE;
}
//---------------------------------------------------------------------------
BOOL TraceDialog_Create( HINSTANCE hInstance, char * cpText )
{
	cpDialogText = cpText;

	if( !DialogBox( hInstance, MAKEINTRESOURCE(IDD_DIALOG1), hWnd, (DLGPROC)DlgProc ) )
		return FALSE;

	return TRUE;
}
//---------------------------------------------------------------------------
char * TraceDialog_FormatTrace( LPLOGDATA pLogData, int iCount, DWORD dwSocket )
{
    int i, iPacketCount = 0;
    char * cpText       = (char *)MyMalloc( 4 );

    memset( cpText, 0, 4 );

    __try
    {
        for( i=0 ; i<iCount ; i++ )
        {
            if( pLogData[i].dwSocket == dwSocket && pLogData[i].lpOllyBuffer != NULL && pLogData[i].dwOllyBufferSize > 0 )
            {
                DWORD dwBuffSize  = (pLogData[i].dwOllyBufferSize * 4) + 4096;
                char * cpBuffer   = (char *)MyMalloc( dwBuffSize ); // calc this properly
                if( cpBuffer != NULL )
                {
                    iPacketCount++;
                    PrintHex( cpBuffer, dwBuffSize, pLogData[i].lpOllyBuffer, pLogData[i].dwOllyBufferSize );

                    dwBuffSize = strlen(cpText) + strlen(cpBuffer) + 128;
                    cpText = (char *)MyReAlloc( cpText, dwBuffSize );      // <-- we did fuck up in here :( why????
                    if( cpText != NULL )
                    {
                        char cHeader[128];
                        snprintf( cHeader, 128, "\r\n----[ %s == %s\r\n", pLogData[i].cMessage, pLogData[i].cReturnMessage );
                        strncat( cpText, cHeader, dwBuffSize );
                        strncat( cpText, cpBuffer, dwBuffSize );
                    }
                    MyFree( cpBuffer );
                }
                continue;
            }
        }

        if( cpText != NULL && iPacketCount == 0 )
        {
            MyFree( cpText );
            cpText = NULL;
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        MyFree( cpText );
        cpText = NULL;
    }

    return cpText;
}
