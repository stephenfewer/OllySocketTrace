About
=====

OllySocketTrace (Written in 2008) is a plugin for OllyDbg (version 1.10) to trace the socket operations being performed by a process. It will record all buffers being sent and received. All parameters as well as return values are recorded and the trace is highlighted with a unique color for each socket being traced.

The socket operations currently supported are: WSASocket, WSAAccept, WSAConnect, WSARecv, WSARecvFrom, WSASend, WSASendTo, WSAAsyncSelect, WSAEventSelect, WSACloseEvent, listen, ioctlsocket, connect, bind, accept, socket, closesocket, shutdown, recv, recvfrom, send and sendto. 

Build
=====

To build OllySocketTrace from source, checkout the latest revision from the SVN trunk and then open OllySocketTraceGroup.bdsgroup with either Borland's Turbo C++ Explorer (free) or any recent version of C++ Builder and build the OllySocketTrace project. 

Usage
=====

Simply install the plugin and activate OllySocketTrace when you wish to begin tracing socket operations. OllySocketTrace will automatically create the breakpoints needed and record the relevant information when these breakpoints are hit. To view the socket trace select the OllySocketTrace Log.

Double clicking on any row in the OllySocketTrace Log window will bring you to the callers location in the OllyDbg disassembly window. The recorded socket trace is highlighted with a unique color for each socket being traced. Right clicking on any row will give you some options such as to view the recorded data trace. You can also filter out unwanted information if you are only concerned with a specific socket. 

Screenshots
===========

![OllySocketTrace Screenshot 1](https://github.com/stephenfewer/OllySocketTrace/raw/master/screenshot1.gif "OllySocketTrace Screenshot 1")

![OllySocketTrace Screenshot 2](https://github.com/stephenfewer/OllySocketTrace/raw/master/screenshot2.gif "OllySocketTrace Screenshot 2")