#ifndef __OSCONFIG_H__
#define __OSCONFIG_H__

#ifdef _WIN32	//WINDOWS
	#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32	//WINDOWS
	#define _CRT_SECURE_NO_WARNINGS
	#define WIN32_LEAN_AND_MEAN

	#ifndef CDECL
		#define CDECL __cdecl
	#endif
	#define STDCALL __stdcall
	typedef int socklen_t;

	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <stdio.h>
	#include <windows.h>
	#pragma comment(lib, "ws2_32.lib")

	#define OSNAME "Windows"

	#define SOCKET_MSGLEN(s, r) ioctlsocket(s, FIONREAD, (u_long*)&r);
	#define SOCKET_CLOSE(s) closesocket(s);
	#define SIN_GET_ADDR(saddr, r) r = (saddr)->S_un.S_addr;
	#define SIN_SET_ADDR(saddr, r) (saddr)->S_un.S_addr = (r);

	typedef unsigned __int32 uint32_t;
	typedef unsigned __int16 uint16_t;
	typedef unsigned __int8 uint8_t;

#elif defined(__linux__) //LINUX

	#define CDECL __attribute__ ((cdecl))
	#define STDCALL __attribute__ ((stdcall))
	#include <sys/mman.h>
	#include <netinet/in.h>
	#include <dlfcn.h>
	#include <sys/mman.h>
	#include <sys/time.h>
	#include <arpa/inet.h>
	#include <netinet/in.h>
	#include <sys/ioctl.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <elf.h>
	#include <unistd.h>
	#include <netdb.h>
	#include <arpa/nameser.h>
	#include <resolv.h>

	#include <limits.h>
	#include <time.h>

	#ifndef PAGESIZE
		#define PAGESIZE 4096
	#endif
	
	#define OSNAME "Linux"

	#define SOCKET_MSGLEN(s, r) ioctl(s, FIONREAD, (char*)&r);
	#define SIN_GET_ADDR(saddr, r) r = (saddr)->s_addr;
	#define SIN_SET_ADDR(saddr, r) (saddr)->s_addr = (r);
	#define SOCKET_CLOSE(s) close(s);

	typedef unsigned int uint32_t;
	typedef unsigned short uint16_t;
	typedef unsigned char uint8_t;

#endif

#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_DLL
    #ifdef __GNUC__
      #define DLL_PUBLIC __attribute__ ((dllexport))
    #else
      #define DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define DLL_PUBLIC __attribute__ ((dllimport))
    #else
      #define DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
  #define DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define DLL_PUBLIC __attribute__ ((visibility ("default")))
    #define DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define DLL_PUBLIC
    #define DLL_LOCAL
  #endif
#endif

#endif //__OSCONFIG_H__

