#include "DllInjection.h"

/* define Set Privilege methods */
SetPrivilege::SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	this->lpszPrivilege		= lpszPrivilege;
	this->bEnablePrivilege	= bEnablePrivilege;
}

bool SetPrivilege::_OpenProcessToken()
{
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&this->hToken))
	{
		_tprintf(_T("OpenProcessToken error: [%u]\n"), GetLastError());
		return false;
	}
	return true;
}

bool SetPrivilege::_LookupPrivilegeValue()
{
	if (!LookupPrivilegeValue(NULL,
		this->lpszPrivilege,
		&this->luid))
	{
		_tprintf(_T("LookupPrivilegeValue error: [%u]\n"), GetLastError());
		return false;
	}
	return true;
}

bool SetPrivilege::_AdjustTokenPrivileges()
{
	this->tp.PrivilegeCount = 1;
	this->tp.Privileges[0].Luid = luid;
	if (this->bEnablePrivilege)
		this->tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		this->tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(this->hToken,
		FALSE,
		&this->tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		_tprintf(_T("AdjustTokenPrivileges error: [%u]\n"), GetLastError());
		return false;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		_tprintf(_T("The token does not have the specified privilege.\n"));
		return false;
	}
	return true;
}
/* end define */

/* define Dll Injection methods*/
DllInjection::DllInjection(DWORD dwPID, LPCTSTR szDllPath)
{
	this->dwPID = dwPID;
	this->szDllPath = szDllPath;
	this->dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
}

bool DllInjection::_OpenProcess()
{
	this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->dwPID);
	if (this->hProcess == NULL)
	{
		_tprintf(_T("OpenProcess(%d) failed!!! [%d]\n"), this->dwPID, GetLastError());
		return false;
	}
	return true;
}

bool DllInjection::_VirtualAllocEx()
{
	this->pRemoteBuf = VirtualAllocEx(this->hProcess, NULL, this->dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (this->pRemoteBuf == NULL)
	{
		_tprintf(_T("VirtualAllocEx() failed!!! [%d]\n"), GetLastError());
		return false;
	}
	return true;
}

bool DllInjection::_WriteProcessMemory()
{
	BOOL bResult = WriteProcessMemory(this->hProcess, this->pRemoteBuf, (LPVOID)this->szDllPath, this->dwBufSize, NULL);
	if (bResult == FALSE)
	{
		_tprintf(_T("WriteProcessMemory() failed!!! [%d]\n"), GetLastError());
		return false;
	}
	return true;
}

bool DllInjection::_GetModuleHandle()
{
	this->hMod = GetModuleHandle(_T("kernel32.dll"));
	if (this->hMod == NULL)
	{
		_tprintf(_T("GetModuleHandle() failed!!! [%d]\n"), GetLastError());
		return false;
	}
	return true;
}

bool DllInjection::_GetProcAddress()
{
	this->pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(this->hMod, "LoadLibraryW");
	if (this->pThreadProc == NULL)
	{
		_tprintf(_T("GetProcAddress() failed!!! [%d]\n"), GetLastError());
		return false;
	}
	return true;
}

bool DllInjection::_CreateRemoteThread()
{
	this->hThread = CreateRemoteThread(this->hProcess, NULL, 0, this->pThreadProc, this->pRemoteBuf, 0, NULL);
	if (this->hThread == NULL)
	{
		_tprintf(_T("CreateRemoteThread() failed!!! [%d]\n"), GetLastError());
		return false;
	}
	return true;
}

bool DllInjection::_WaitForSingleObject()
{
	WaitForSingleObject(this->hThread, INFINITE);
	return true;
}

bool DllInjection::_CloseHandle()
{
	CloseHandle(this->hThread);
	CloseHandle(this->hProcess);
	return true;
}
/* end define */