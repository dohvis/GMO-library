#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>


#define MAX_THREAD 255

DWORD GetPIDByName(LPCTSTR szProcessName)
{
	DWORD PID = 0xFFFFFFFF;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;
	char proc_name[260];

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	Process32First(hSnapShot, &pe);
	do
	{
		strncpy(proc_name, pe.szExeFile, strlen(pe.szExeFile));
		if (!_strnicmp(szProcessName, proc_name, strlen(szProcessName)))
		{
			PID = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapShot, &pe));
	CloseHandle(hSnapShot);
	return PID;
}

BOOL GetModuleNameByAddr(DWORD dwAddress, LPTSTR tszModuleName)
{
	HANDLE hSnapshot;
	MODULEENTRY32 me32;

	tszModuleName[0] = 0; //to make things easier to determine if we've succeeded or not 

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

	if (!hSnapshot)
		return FALSE;

	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hSnapshot, &me32))
		return FALSE;

	do {
		if (dwAddress >= (DWORD)me32.modBaseAddr &&
			dwAddress <= ((DWORD)me32.modBaseAddr + me32.modBaseSize)) {

			strncpy(tszModuleName, me32.szModule, strlen(me32.szModule));
			break;
		}
	} while (Module32Next(hSnapshot, &me32));

	CloseHandle(hSnapshot);

	return !(tszModuleName[0] == 0);
}


LPTSTR GetModuleNameByPID(DWORD PID)
{
	HANDLE hSnapshot;
	MODULEENTRY32 me32;
	LPTSTR tszModuleName;
	tszModuleName = (LPTSTR)malloc(255);
	tszModuleName[0] = 0; //to make things easier to determine if we've succeeded or not 

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

	if (!hSnapshot)
		return FALSE;

	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hSnapshot, &me32))
		return FALSE;

	do {
		if (me32.th32ProcessID == PID) {
			strncpy(tszModuleName, me32.szModule, strlen(me32.szModule));
			break;
		}
	} while (Module32Next(hSnapshot, &me32));

	CloseHandle(hSnapshot);

	//return !(tszModuleName[0] == 0);
	return tszModuleName;
}



DWORD GetThreadIdByPID(DWORD ProcessId, DWORD *ThreadID)
{
	THREADENTRY32 te;
	int cnt = 0;
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	HANDLE hThread;
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do {
				if (te.th32OwnerProcessID == ProcessId
					&& te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					//printf("Process 0x%04x Thread 0x%04x\n", te.th32OwnerProcessID, te.th32ThreadID);
					ThreadID[cnt] = te.th32ThreadID;
					SuspendThread(OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID));

					cnt++;
					
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));

		}
		CloseHandle(h);
	}
	
	return cnt;
}