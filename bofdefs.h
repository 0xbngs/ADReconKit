/*
 * bofdefs.h — BOF dynamic function resolution
 *
 * LDAP recon uses wldap32 (C API). No COM / ADSI / VARIANT.
 * COM in a BOF (CoUninitialize, IDirectorySearch vtables) is a
 * common way to kill the Beacon process.
 */

#pragma once
#pragma intrinsic(memcpy, strcpy, strcmp, strlen)

#include <windows.h>
#include <stdio.h>

#ifndef LDAPAPI
#define LDAPAPI __cdecl
#endif

/* Opaque LDAP types — do not include winldap.h (pulls schnlsp / UNICODE macros). */
typedef struct ldap LDAP;
typedef struct ldapmsg LDAPMessage;
struct l_timeval {
    LONG tv_sec;
    LONG tv_usec;
};
typedef struct l_timeval LDAP_TIMEVAL;

#define LDAP_PORT 389
#define LDAP_VERSION3 3
#define LDAP_SUCCESS 0x00
#define LDAP_SIZELIMIT_EXCEEDED 0x04
#define LDAP_STRONG_AUTH_REQUIRED 0x08
#define LDAP_INVALID_CREDENTIALS 0x31
#define LDAP_UNWILLING_TO_PERFORM 0x35
#define LDAP_SERVER_DOWN 0x51
#define LDAP_LOCAL_ERROR 0x52
#define LDAP_TIMEOUT 0x55
#define LDAP_CONNECT_ERROR 0x5b
#define LDAP_AUTH_OTHERKIND 0x86
#define LDAP_AUTH_NEGOTIATE (LDAP_AUTH_OTHERKIND | 0x0400)
#define LDAP_SCOPE_BASE 0x00
#define LDAP_SCOPE_ONELEVEL 0x01
#define LDAP_SCOPE_SUBTREE 0x02
#define LDAP_OPT_SIZELIMIT 0x03
#define LDAP_OPT_TIMELIMIT 0x04
#define LDAP_OPT_REFERRALS 0x08
#define LDAP_OPT_PROTOCOL_VERSION 0x11
#define LDAP_OPT_SIGN 0x95
#define LDAP_OPT_ENCRYPT 0x96
#define LDAP_OPT_AREC_EXCLUSIVE 0x98
#define LDAP_OPT_NETWORK_TIMEOUT 0x85
#define LDAP_OPT_ON  ((void *) 1)
#define LDAP_OPT_OFF ((void *) 0)

/* ─── Heap macros ─────────────────────────────────────────── */
#define intAlloc(size)         KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size)  (ptr) ? KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) \
                                     : KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr)          KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(addr, s) MSVCRT$memset((addr), 0, s)

#ifdef BOF

WINBASEAPI void *  WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI LPVOID  WINAPI KERNEL32$HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(VOID);

WINBASEAPI void *  __cdecl MSVCRT$memcpy(void * __restrict__ _Dst, const void * __restrict__ _Src, size_t _MaxCount);
WINBASEAPI void *  __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int     __cdecl MSVCRT$_snprintf(char * __restrict__ _Dest, size_t _Count, const char * __restrict__ _Format, ...);
WINBASEAPI size_t  __cdecl MSVCRT$strlen(const char *_Str);
WINBASEAPI int     __cdecl MSVCRT$strcmp(const char *_Str1, const char *_Str2);
WINBASEAPI int     __cdecl MSVCRT$_strnicmp(const char *_Str1, const char *_Str2, size_t _MaxCount);
WINBASEAPI char *  __cdecl MSVCRT$strstr(const char *_Str, const char *_SubStr);
WINBASEAPI int     __cdecl MSVCRT$atoi(const char *_Str);

DECLSPEC_IMPORT LDAP * LDAPAPI WLDAP32$ldap_initA(PCHAR HostName, ULONG PortNumber);
DECLSPEC_IMPORT ULONG  LDAPAPI WLDAP32$ldap_set_option(LDAP *ld, int option, const void *invalue);
DECLSPEC_IMPORT ULONG  LDAPAPI WLDAP32$ldap_connect(LDAP *ld, struct l_timeval *timeout);
DECLSPEC_IMPORT ULONG  LDAPAPI WLDAP32$ldap_bind_sA(LDAP *ld, PCHAR dn, PCHAR cred, ULONG method);
DECLSPEC_IMPORT ULONG  LDAPAPI WLDAP32$ldap_unbind_s(LDAP *ld);
DECLSPEC_IMPORT ULONG  LDAPAPI WLDAP32$ldap_search_ext_sA(
    LDAP *ld, const PCHAR base, ULONG scope, const PCHAR filter, PCHAR attrs[],
    ULONG attrsonly, void *ServerControls, void *ClientControls,
    struct l_timeval *timeout, ULONG SizeLimit, LDAPMessage **res);
DECLSPEC_IMPORT LDAPMessage * LDAPAPI WLDAP32$ldap_first_entry(LDAP *ld, LDAPMessage *res);
DECLSPEC_IMPORT LDAPMessage * LDAPAPI WLDAP32$ldap_next_entry(LDAP *ld, LDAPMessage *entry);
DECLSPEC_IMPORT PCHAR * LDAPAPI WLDAP32$ldap_get_valuesA(LDAP *ld, LDAPMessage *entry, const PCHAR attr);
DECLSPEC_IMPORT ULONG   LDAPAPI WLDAP32$ldap_value_freeA(PCHAR *vals);
DECLSPEC_IMPORT ULONG   LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage *res);
DECLSPEC_IMPORT PCHAR   LDAPAPI WLDAP32$ldap_err2stringA(ULONG err);

#else

#define KERNEL32$HeapAlloc              HeapAlloc
#define KERNEL32$HeapReAlloc            HeapReAlloc
#define KERNEL32$GetProcessHeap         GetProcessHeap
#define KERNEL32$HeapFree               HeapFree
#define KERNEL32$GetLastError           GetLastError

#define MSVCRT$memcpy       memcpy
#define MSVCRT$memset       memset
#define MSVCRT$_snprintf    _snprintf
#define MSVCRT$strlen       strlen
#define MSVCRT$strcmp       strcmp
#define MSVCRT$_strnicmp    _strnicmp
#define MSVCRT$strstr       strstr
#define MSVCRT$atoi         atoi

#define WLDAP32$ldap_initA              ldap_initA
#define WLDAP32$ldap_set_option         ldap_set_option
#define WLDAP32$ldap_connect            ldap_connect
#define WLDAP32$ldap_bind_sA            ldap_bind_sA
#define WLDAP32$ldap_unbind_s           ldap_unbind_s
#define WLDAP32$ldap_search_ext_sA      ldap_search_ext_sA
#define WLDAP32$ldap_first_entry        ldap_first_entry
#define WLDAP32$ldap_next_entry         ldap_next_entry
#define WLDAP32$ldap_get_valuesA        ldap_get_valuesA
#define WLDAP32$ldap_value_freeA        ldap_value_freeA
#define WLDAP32$ldap_msgfree            ldap_msgfree
#define WLDAP32$ldap_err2stringA        ldap_err2stringA

#endif /* BOF */
