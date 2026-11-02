/*
 * base.c — Buffered output utilities for BOF
 *
 * Provides internal_printf() which buffers output and flushes
 * via BeaconOutput in chunks, avoiding per-line Beacon callbacks.
 *
 * Based on TrustedSec CS-Situational-Awareness-BOF base.c
 */

#include <windows.h>
#include "bofdefs.h"
#include "beacon.h"

#ifndef bufsize
#define bufsize 8192
#endif

char * output = (char*)1;
WORD currentoutsize = 1;
HANDLE trash = (HANDLE)1; /* Needed for x64 to avoid relocation error */

int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);
void bofstop();


int bofstart()
{
    output = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

void internal_printf(const char* format, ...)
{
    int buffersize = 0;
    char * curloc = NULL;
    char * intBuffer = NULL;
    char * transferBuffer = (char*)intAlloc(bufsize);
    va_list args;

    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    intBuffer = (char*)intAlloc(buffersize);

    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args);
    va_end(args);

    if (buffersize + currentoutsize < bufsize)
    {
        memcpy(output + currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else
    {
        curloc = intBuffer;
        while (buffersize > 0)
        {
            int transfersize = 0;
            transfersize = bufsize - currentoutsize;
            if (buffersize < transfersize)
            {
                transfersize = buffersize;
            }
            memcpy(output + currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if (currentoutsize == bufsize)
            {
                printoutput(FALSE);
            }
            memset(transferBuffer, 0, transfersize);
            curloc += transfersize;
            buffersize -= transfersize;
        }
    }
    intFree(intBuffer);
    intFree(transferBuffer);
}

void printoutput(BOOL done)
{
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    memset(output, 0, bufsize);
    if (done)
    {
        MSVCRT$free(output);
        output = NULL;
    }
}

void bofstop()
{
    return;
}
