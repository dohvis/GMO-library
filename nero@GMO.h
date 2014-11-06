#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

#define MAX_THREAD 255

BOOL GetModuleNameByAddr(DWORD dwAddress, LPTSTR tszModuleName);

LPTSTR  GetModuleNameByPID(DWORD dwAddress);
DWORD GetPIDByName(LPCTSTR szProcessName);
DWORD GetThreadIdByPID( DWORD ProcessId,DWORD *ThreadID);