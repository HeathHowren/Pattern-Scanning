#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

HANDLE process_handle;

#define m_iDefaultFOV 0x332C

template<typename T> T RPM(SIZE_T address) {
    T buffer;
    ReadProcessMemory(process_handle, (LPCVOID)address, &buffer, sizeof(T), NULL);
    return buffer;
}

template<typename T> void WPM(SIZE_T address, T buffer) {
    WriteProcessMemory(process_handle, (LPVOID)address, &buffer, sizeof(buffer), NULL);
}

MODULEENTRY32 get_module(const char* modName, DWORD proc_id) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc_id);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry)) {
            do {
                if (!strcmp(modEntry.szModule, modName)) {
                    CloseHandle(hSnap);
                    return modEntry;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    MODULEENTRY32 module = { -1 };
    return module;
}

uintptr_t get_module_base(const char* modName, DWORD proc_id) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc_id);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry)) {
            do {
                if (!strcmp(modEntry.szModule, modName)) {
                    CloseHandle(hSnap);
                    return (uintptr_t)modEntry.modBaseAddr;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
}

uintptr_t find_pattern(MODULEENTRY32 module, uint8_t* arr, const char* pattern, int offset, int extra) {
    uintptr_t scan = 0x0;
    const char* pat = pattern;
    uintptr_t firstMatch = 0;
    for (uintptr_t pCur = (uintptr_t)arr; pCur < (uintptr_t)arr + module.modBaseSize; ++pCur) { 
        if (!*pat) { scan = firstMatch; break; }
        if (*(uint8_t*)pat == '\?' || *(uint8_t*)pCur == ((((pat[0] & (~0x20)) >= 'A' && (pat[0] & (~0x20)) <= 'F') ? ((pat[0] & (~0x20)) - 'A' + 0xa) : ((pat[0] >= '0' && pat[0] <= '9') ? pat[0] - '0' : 0)) << 4 | (((pat[1] & (~0x20)) >= 'A' && (pat[1] & (~0x20)) <= 'F') ? ((pat[1] & (~0x20)) - 'A' + 0xa) : ((pat[1] >= '0' && pat[1] <= '9') ? pat[1] - '0' : 0)))) {
            if (!firstMatch) firstMatch = pCur;
            if (!pat[2]) { scan = firstMatch; break; }
            if (*(WORD*)pat == 16191 /*??*/ || *(uint8_t*)pat != '\?') pat += 3;
            else pat += 2;
        }
        else { pat = pattern; firstMatch = 0; }
    }
    if (!scan) return 0x0;
    uint32_t read;
    ReadProcessMemory(process_handle, (void*)(scan - (uintptr_t)arr + (uintptr_t)module.modBaseAddr + offset), &read, sizeof(read), NULL);
    return read + extra;
}

int main() {
    HWND hwnd = FindWindowA(NULL, "Counter-Strike: Global Offensive");
    DWORD proc_id; GetWindowThreadProcessId(hwnd, &proc_id);
    process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, proc_id);
    MODULEENTRY32 client;

    //optional!
    uintptr_t dwLocalPlayer;
    uintptr_t dwEntityList;
    
    //sig-scan
    client = get_module("client.dll", proc_id); //DLL module
    auto bytes = new uint8_t[client.modBaseSize]; //making a variable size of the module
    DWORD bytes_read;
    ReadProcessMemory(process_handle, client.modBaseAddr, bytes, client.modBaseSize, &bytes_read); //reading the module and storing as bytes_read
    if (bytes_read != client.modBaseSize) throw; //checking that the size of bytes read is = to size of bytes in the module

    //example
    uintptr_t LocalPlayer = find_pattern(client, bytes, "8D 34 85 ? ? ? ? 89 15 ? ? ? ? 8B 41 08 8B 48 04 83 F9 FF", 0x3, 0x4); //0x3 is the offset, 0x4 is the extra
    uintptr_t EntityList = find_pattern(client, bytes, "BB ? ? ? ? 83 FF 01 0F 8C ? ? ? ? 3B F8", 0x1, 0x0); //0x1 is the offset, there is no extra
    delete[] bytes;
    printf("[+] Found dwLocalPlayer @ 0x%X\n", LocalPlayer - (uintptr_t)client.modBaseAddr); 
    printf("[+] Found dwEntityList @ 0x%X\n", EntityList - (uintptr_t)client.modBaseAddr);
    system("pause");

    //optional!
    dwLocalPlayer = LocalPlayer - (uintptr_t)client.modBaseAddr; //getting rid of the base is optional, you will just have to add it back when you RPM
    dwEntityList = EntityList - (uintptr_t)client.modBaseAddr;

    //fov changer example
    int fov = 90;
    while (true)
    {
        uintptr_t localPlayer = RPM<uintptr_t>(LocalPlayer);
        int iFOV = RPM<int>(localPlayer + m_iDefaultFOV);
        std::cout << "FOV: " << iFOV << std::endl;

        if (GetAsyncKeyState(0x76 /*F7*/) & 1)
        {
            //minus
            fov = fov - 1;
            WPM<int>(localPlayer + m_iDefaultFOV, fov);
        }

        if (GetAsyncKeyState(0x77 /*F8*/) & 1)
        {
            //add
            fov = fov + 1;
            WPM<int>(localPlayer + m_iDefaultFOV, fov);
        }

        if (GetAsyncKeyState(0x78 /*F9*/) & 1)
        {
            //resets
            fov = 90;
            WPM<int>(localPlayer + m_iDefaultFOV, fov);
        }
    }

    system("pause");
}