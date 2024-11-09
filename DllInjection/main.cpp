#include "DllInjection.h"

int _tmain(int argc, LPCTSTR argv[])
{
	DWORD dwPID = 0;
	LPCTSTR szDllName = { 0, };

	SetPrivilege setPrivilege = SetPrivilege(SE_DEBUG_NAME, TRUE);
	DllInjection dllInjection = DllInjection((DWORD)_tstol(argv[1]), argv[2]);

	setPrivilege._OpenProcessToken();
	setPrivilege._LookupPrivilegeValue();
	setPrivilege._AdjustTokenPrivileges();

	dllInjection._OpenProcess();
	dllInjection._VirtualAllocEx();
	dllInjection._WriteProcessMemory();
	dllInjection._GetModuleHandle();
	dllInjection._GetProcAddress();
	dllInjection._CreateRemoteThread();
	dllInjection._CreateRemoteThread();
	dllInjection._WaitForSingleObject();
	dllInjection._CloseHandle();
}