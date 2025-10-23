/**
 * ghidra_types.h - Type definitions for Ghidra-decompiled code
 *
 * This header provides type definitions that Ghidra's decompiler uses
 * but aren't available in standard C. Include this in all compiled
 * decompiled code to enable successful compilation.
 */

#ifndef GHIDRA_TYPES_H
#define GHIDRA_TYPES_H

#include <stdint.h>
#include <windows.h>

// Ghidra basic types
typedef uint8_t byte;
typedef uint8_t undefined;
typedef uint16_t undefined2;
typedef uint32_t undefined3;
typedef uint32_t undefined4;
typedef uint64_t undefined7;
typedef uint64_t undefined8;

typedef unsigned int uint;
typedef unsigned int uint7;
typedef unsigned short ushort;
typedef unsigned short u_short;
typedef unsigned long u_long;
typedef int64_t longlong;
typedef uint64_t ulonglong;

// Function pointer type (generic)
typedef void (*code)(void);

// Windows types (in case windows.h is not fully included)
#ifndef _WINDOWS_
typedef unsigned long DWORD;
typedef int BOOL;
typedef void* LPVOID;
typedef const void* LPCVOID;
typedef char* LPSTR;
typedef const char* LPCSTR;
typedef wchar_t* LPWSTR;
typedef const wchar_t* LPCWSTR;
typedef void* HMODULE;
typedef void* HANDLE;
#endif

#endif // GHIDRA_TYPES_H
