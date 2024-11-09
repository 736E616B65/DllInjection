#ifndef __DLL_INJECTION_H__
#define __DLL_INJECTION_H__

#include<Windows.h>
#include<tchar.h>

class SetPrivilege
{
private:
	TOKEN_PRIVILEGES tp	= { 0, };
	HANDLE hToken		= NULL;
	LUID luid			= { 0, };
	LPCTSTR lpszPrivilege;
	BOOL bEnablePrivilege;

public:
	SetPrivilege(LPCTSTR, BOOL);
	bool _OpenProcessToken();
	// bool OpenProcessToken(HANDLE, DWORD, PHANDLE);
	bool _LookupPrivilegeValue();
	// bool LookupPrivilegeValue(LPCSTR, LPCSTR, PLUID);
	bool _AdjustTokenPrivileges();
	// bool AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
};

class DllInjection
{
private:
	DWORD dwPID							= 0;
	LPCTSTR szDllPath					= NULL;
	HANDLE hProcess = NULL, hThread		= NULL;
	HMODULE hMod						= NULL;
	LPVOID pRemoteBuf					= NULL;
	DWORD dwBufSize						= NULL;
	LPTHREAD_START_ROUTINE pThreadProc	= { 0, };

public:
	DllInjection(DWORD, LPCTSTR);
	bool _OpenProcess();
	bool _VirtualAllocEx();
	bool _WriteProcessMemory();
	bool _GetModuleHandle();
	bool _GetProcAddress();
	bool _CreateRemoteThread();
	bool _WaitForSingleObject();
	bool _CloseHandle();
};

#endif