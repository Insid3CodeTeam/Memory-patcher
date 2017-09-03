
#include <windows.h>
#include <stdio.h>


#ifdef _WIN64
#define CAPTION "Memory patcher for chimera #01 (64-bit)"
#define EXENAME "target64.exe" // change it to target "target32.exe" for Wow64 test.
#else
#define CAPTION "Memory patcher for chimera #01 (32-bit)"
#define EXENAME "target32.exe"
#endif

int iWinMain() {
    PROCESS_INFORMATION lpProcessInfo = {0};
    STARTUPINFO lpStartupInfo = {0};

    printf("%s\nFilename: %s\n\n", CAPTION, EXENAME);

    if(CreateProcessA(EXENAME,
                      NULL,
                      NULL,
                      NULL,
                      0,
                      CREATE_SUSPENDED,
                      NULL,
                      NULL,
                      &lpStartupInfo,
                      &lpProcessInfo))	{

#ifdef _WIN64  // 64bit Application
        DWORD64* peb64bit;
        DWORD32* wowPeb;

        CONTEXT lpContext64bit = {0};
        WOW64_CONTEXT lpWoWContext = {0};

        DWORD64 uTargetAddress64bit;
        char newByte64bit;

        DWORD64 uTargetAddressWow64;
        char newByteWow64;

        BOOL  Wow64Process = FALSE;

        IsWow64Process(lpProcessInfo.hProcess, &Wow64Process);

        if (Wow64Process) { // Wow64 Process
            lpWoWContext.ContextFlags = CONTEXT_FULL;
            Wow64GetThreadContext(lpProcessInfo.hThread, &lpWoWContext);
            wowPeb = (DWORD32*)lpWoWContext.Ebx;

            DWORD32 ImageBaseAddress = NULL;
            ReadProcessMemory(lpProcessInfo.hProcess,
                              &wowPeb[2],
                              (LPVOID)&ImageBaseAddress,
                              sizeof(DWORD32),
                              NULL);

            printf("[-] Wow64 ImageBase Address     = 0x%08X\n", ImageBaseAddress);
            printf("[-] Wow64 EntryPoint Address    = 0x%08X\n", lpWoWContext.Eax);
            printf("[-] Wow64 Process (PEB Address) = 0x%08X\n", lpWoWContext.Ebx);

            uTargetAddressWow64 = lpWoWContext.Eax + 0x64;
            newByteWow64 = 0x74;

            WriteProcessMemory(lpProcessInfo.hProcess,
                               (LPVOID)uTargetAddressWow64,
                               &newByteWow64,
                               1,
                               NULL);
        } else { // 64bit Process

            lpContext64bit.ContextFlags = CONTEXT_FULL;
            GetThreadContext(lpProcessInfo.hThread, &lpContext64bit);
            peb64bit = (DWORD64*)lpContext64bit.Rdx;

            DWORD64 ImageBaseAddress = NULL;
            ReadProcessMemory(lpProcessInfo.hProcess,
                              &peb64bit[2],
                              (LPVOID)&ImageBaseAddress,
                              sizeof(DWORD64),
                              NULL);

            printf("[-] 64bit ImageBase Address     = 0x%p\n", ImageBaseAddress);
            printf("[-] 64bit EntryPoint Address    = 0x%p\n", lpContext64bit.Rcx);
            printf("[-] 64bit Process (PEB Address) = 0x%p\n", lpContext64bit.Rdx);

            uTargetAddress64bit = lpContext64bit.Rcx + 0x7E;
            newByte64bit = 0x75;

            WriteProcessMemory(lpProcessInfo.hProcess,
                               (LPVOID)uTargetAddress64bit,
                               &newByte64bit,
                               1,
                               NULL);

        }

        ResumeThread(lpProcessInfo.hThread);
        WaitForSingleObject(lpProcessInfo.hThread, INFINITE);

#else // 32bit Application
        DWORD32* peb32bit;
        CONTEXT lpContext32bit = {0};

        DWORD32 uTargetAddress32bit;
        char newByte32bit;

        lpContext32bit.ContextFlags = CONTEXT_FULL;
        GetThreadContext(lpProcessInfo.hThread, &lpContext32bit);
        peb32bit = (DWORD32*)lpContext32bit.Ebx;

        DWORD32 ImageBaseAddress = NULL;
        ReadProcessMemory(lpProcessInfo.hProcess,
                          &peb32bit[2],
                          (LPVOID)&ImageBaseAddress,
                          sizeof(DWORD32),
                          NULL);

        printf("[-] 32bit ImageBase Address     = 0x%08X\n", ImageBaseAddress);
        printf("[-] 32bit EntryPoint Address    = 0x%08X\n", lpContext32bit.Eax);
        printf("[-] 32bit Process (PEB Address) = 0x%08X\n", lpContext32bit.Ebx);

        uTargetAddress32bit = lpContext32bit.Eax + 0x64;
        newByte32bit = 0x74;

        WriteProcessMemory(lpProcessInfo.hProcess,
                           (LPVOID)uTargetAddress32bit,
                           &newByte32bit,
                           1,
                           NULL);

        ResumeThread(lpProcessInfo.hThread);
        WaitForSingleObject(lpProcessInfo.hThread, INFINITE);
#endif

    }

    return 0;
}

