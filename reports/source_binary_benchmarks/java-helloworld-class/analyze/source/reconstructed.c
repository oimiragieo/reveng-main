/* Reconstructed by REVENG AI-Powered Analysis */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else
typedef size_t SIZE_T;
typedef void * LPVOID;
typedef struct {
    long long QuadPart;
} LARGE_INTEGER;
typedef void * PEXCEPTION_POINTERS;
typedef void * PEXCEPTION_RECORD;
typedef void * PCONTEXT;
typedef void * PDISPATCHER_CONTEXT;
#endif

#include <stdnoreturn.h>

#ifdef NAN
#undef NAN
#endif
#define NAN(value) (((double)(value)) != ((double)(value)))

#ifndef __cdecl
#define __cdecl
#endif

#ifndef __stdcall
#define __stdcall
#endif

#ifndef __fastcall
#define __fastcall
#endif

#ifndef __thiscall
#define __thiscall
#endif

#ifndef swi
#define swi(...) ((uint64_t)0)
#endif

typedef struct {
    uint32_t LowPart;
    int32_t HighPart;
} _struct_19;

typedef uint8_t byte;
typedef uint8_t undefined;
typedef uint8_t undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
typedef int8_t sbyte;
typedef int16_t short16;
typedef int32_t int32;
typedef int64_t int64;
typedef uint8_t uchar;
typedef uint16_t ushort;
typedef uint32_t uint;
typedef uint64_t ulonglong;
typedef int64_t longlong;
typedef uint64_t qword;
typedef uint32_t dword;
typedef unsigned long ulong;
typedef uint64_t ulong64;
typedef uint32_t undefined3;
typedef uint64_t undefined5;
typedef uint64_t undefined6;
typedef uint64_t undefined7;
typedef int32_t int3;
typedef uint32_t uint3;
typedef uint64_t int7;
typedef uint64_t uint6;
typedef uint64_t uint7;
typedef void code();
typedef void type_info;
typedef int __scrt_module_type;
typedef int (__cdecl * _func___cdecl_int)(void);
typedef void (__cdecl * _func___cdecl_void)(void);
typedef void (__cdecl * _func___cdecl_void_void_ptr_ulong_void_ptr)(void *, ulong, void *);
typedef PEXCEPTION_POINTERS _EXCEPTION_POINTERS;
typedef PEXCEPTION_RECORD _EXCEPTION_RECORD;
#ifdef _WIN32
typedef CONTEXT _CONTEXT;
typedef DISPATCHER_CONTEXT _DISPATCHER_CONTEXT;
typedef SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES;
typedef BY_HANDLE_FILE_INFORMATION _BY_HANDLE_FILE_INFORMATION;
typedef CONSOLE_SCREEN_BUFFER_INFO _CONSOLE_SCREEN_BUFFER_INFO;
typedef CONSOLE_READCONSOLE_CONTROL _CONSOLE_READCONSOLE_CONTROL;
#else
typedef PCONTEXT _CONTEXT;
typedef PDISPATCHER_CONTEXT _DISPATCHER_CONTEXT;
#endif
typedef void ThrowInfo;
typedef int _crt_argv_mode;
typedef void _exception;

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 ghidra_uint128;
#else
typedef uint64_t ghidra_uint128;
#endif

typedef union {
    ghidra_uint128 whole;
    uint8_t bytes[16];
} ghidra_vec128;

typedef ghidra_uint128 unkuint10;

typedef union {
    uint64_t whole;
    uint8_t bytes[8];
} ghidra_vec64;

typedef uintptr_t (*ghidra_indirect_fn_0)(void);
typedef uintptr_t (*ghidra_indirect_fn)(uintptr_t, ...);

#define GHIDRA_U64(value) ((uint64_t)(uintptr_t)(value))
#define GHIDRA_U128(value) ((ghidra_uint128)(uintptr_t)(value))
#define GHIDRA_LARGE_INTEGER(value) ((LARGE_INTEGER){ .QuadPart = (long long)(uintptr_t)(value) })
#define SUB81(value, offset) ((uint8_t)(GHIDRA_U64(value) >> ((offset) * 8)))
#define SUB82(value, offset) ((uint16_t)(GHIDRA_U64(value) >> ((offset) * 8)))
#define SUB84(value, offset) ((uint32_t)(GHIDRA_U64(value) >> ((offset) * 8)))
#define ZEXT216(value) ((ghidra_uint128)(uint16_t)(value))
#define SUB168(value, offset) ((uint64_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB164(value, offset) ((uint32_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB158(value, offset) ((uint64_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB161(value, offset) ((uint64_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB1510(value, offset) ((uint64_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB1512(value, offset) ((uint64_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB87(value, offset) ((uint64_t)(GHIDRA_U64(value) >> ((offset) * 8)))
#define ZEXT816(value) ((uint64_t)(uint8_t)(value))
#define ZEXT716(value) ((ghidra_uint128)(GHIDRA_U64(value) & 0x00ffffffffffffffULL))
#define SEXT816(value) ((int64_t)GHIDRA_U64(value))
#define CONCAT11(high, low) ((((uint16_t)(uint8_t)(high)) << 8) | (uint16_t)(uint8_t)(low))
#define CONCAT12(high, low) ((((uint32_t)(uint8_t)(high)) << 16) | (uint32_t)(uint16_t)(low))
#define CONCAT13(high, low) ((((uint32_t)(uint8_t)(high)) << 24) | ((uint32_t)GHIDRA_U64(low) & 0x00ffffffU))
#define CONCAT14(high, low) ((((uint64_t)(uint8_t)(high)) << 32) | (uint64_t)(uint32_t)(low))
#define CONCAT15(high, low) ((((uint64_t)(uint8_t)(high)) << 40) | (GHIDRA_U64(low) & 0x000000ffffffffffULL))
#define CONCAT16(high, low) ((((uint64_t)(uint8_t)(high)) << 48) | (GHIDRA_U64(low) & 0x0000ffffffffffffULL))
#define CONCAT21(high, low) ((((uint32_t)(uint16_t)(high)) << 8) | (uint32_t)(uint8_t)(low))
#define CONCAT22(high, low) ((((uint32_t)(uint16_t)(high)) << 16) | (uint32_t)(uint16_t)(low))
#define CONCAT24(high, low) ((((uint64_t)(uint16_t)(high)) << 32) | (uint64_t)(uint32_t)(low))
#define CONCAT26(high, low) ((((uint64_t)(uint16_t)(high)) << 48) | (GHIDRA_U64(low) & 0x0000ffffffffffffULL))
#define CONCAT25(high, low) ((((uint64_t)(uint16_t)(high)) << 40) | (GHIDRA_U64(low) & 0x000000ffffffffffULL))
#define CONCAT31(high, low) ((((uint32_t)GHIDRA_U64(high) & 0x00ffffffU) << 8) | (uint32_t)(uint8_t)(low))
#define CONCAT34(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x00ffffffU) << 32) | (uint64_t)(uint32_t)(low))
#define CONCAT35(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x00ffffffU) << 40) | (GHIDRA_U64(low) & 0x000000ffffffffffULL))
#define CONCAT41(high, low) ((((uint64_t)(uint32_t)(high)) << 8) | (uint64_t)(uint8_t)(low))
#define CONCAT44(high, low) ((((uint64_t)(uint32_t)(high)) << 32) | (uint64_t)(uint32_t)(low))
#define CONCAT51(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x000000ffffffffffULL) << 8) | (uint64_t)(uint8_t)(low))
#define CONCAT52(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x000000ffffffffffULL) << 16) | (uint64_t)(uint16_t)(low))
#define CONCAT53(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x000000ffffffffffULL) << 24) | ((uint64_t)GHIDRA_U64(low) & 0x00ffffffULL))
#define CONCAT62(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x0000ffffffffffffULL) << 16) | (uint64_t)(uint16_t)(low))
#define CONCAT71(high, low) (((uint64_t)GHIDRA_U64(high) << 8) | (uint64_t)(uint8_t)(low))
#define CONCAT72(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x00ffffffffffffffULL) << 16) | (uint64_t)(uint16_t)(low))
#define CONCAT17(high, low) ((((uint64_t)(uint8_t)(high)) << 56) | (GHIDRA_U64(low) & 0x00ffffffffffffffULL))
#define CONCAT61(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x0000ffffffffffffULL) << 8) | (uint64_t)(uint8_t)(low))

void default main_java_lang_String_void(String * * param1);

void sayHello_void(HelloWorld this);
void default _init_java_lang_String_void(HelloWorld this, String * param1);

void _init_void(HelloWorld this);

void setMessage_java_lang_String_void(HelloWorld this,String *param1);

String * getMessage_java_lang_String(HelloWorld this);

int getCount_int(HelloWorld this);


/* Flags_
     ACC_PUBLIC
     ACC_STATIC
   
   public static void main(java_lang_String[])  */

void main_java_lang_String___void(String **param1)

{
  PrintStream *objectRef;
  int iVar1;
  String *pSVar2;
  HelloWorld *objectRef_00;
  
  objectRef_00 = new HelloWorld();
  ((ghidra_indirect_fn)objectRef_00_sayHello)(GHIDRA_U64(objectRef_00));
  if (0 < param1_length) {
    ((ghidra_indirect_fn)objectRef_00_setMessage)(GHIDRA_U64(objectRef_00), *param1);
    ((ghidra_indirect_fn)objectRef_00_sayHello)(GHIDRA_U64(objectRef_00));
  }
  objectRef = *System_out;
  iVar1 = ((ghidra_indirect_fn)objectRef_00_getCount)(GHIDRA_U64(objectRef_00));
  pSVar2 = ((ghidra_indirect_fn)makeConcatWithConstants)(iVar1);
  ((ghidra_indirect_fn)objectRef_println)(GHIDRA_U64(objectRef), pSVar2);
  return;
}


/* Flags_
     ACC_PUBLIC
   
   public void sayHello()  */

void sayHello_void(HelloWorld this)

{
  PrintStream *objectRef;
  
  objectRef = *System_out;
  ((ghidra_indirect_fn)objectRef_println)(GHIDRA_U64(objectRef), *this_message);
  *this_count = *this_count + 1;
  return;
}


/* Flags_
     ACC_PUBLIC
   
   public HelloWorld(java_lang_String)  */

void <init_java_lang_String_void(HelloWorld this,String *param1)

{
  ((ghidra_indirect_fn)this_init_)(GHIDRA_U64((void *)this));
  *this_message = param1;
  *this_count = 0;
  return;
}


/* Flags_
     ACC_PUBLIC
   
   public HelloWorld()  */

void _init_void(HelloWorld this)

{
  ((ghidra_indirect_fn)this_init_)(GHIDRA_U64((void *)this));
  *this_message = "Hello, World!";
  *this_count = 0;
  return;
}


/* Flags_
     ACC_PUBLIC
   
   public void setMessage(java_lang_String)  */

void setMessage_java_lang_String_void(HelloWorld this,String *param1)

{
  *this_message = param1;
  return;
}


/* Flags_
     ACC_PUBLIC
   
   public String getMessage()  */

String * getMessage_java_lang_String(HelloWorld this)

{
  return *this_message;
}


/* Flags_
     ACC_PUBLIC
   
   public int getCount()  */

int getCount_int(HelloWorld this)

{
  return *this_count;
}