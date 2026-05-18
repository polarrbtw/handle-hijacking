#include "includes.hpp"
#include "handle.hpp"

static void CreateConsole() {
    FreeConsole(); // clear previous console
    AllocConsole();

    FILE* fOut;
    freopen_s(&fOut, "CONOUT$", "w", stdout);
    freopen_s(&fOut, "CONOUT$", "w", stderr);

    FILE* fIn;
    freopen_s(&fIn, "CONIN$", "r", stdin);

    std::ios::sync_with_stdio(true);

    std::cout.clear();
    std::cerr.clear();
    std::cin.clear();

    HWND cw = GetConsoleWindow();
    if (cw) {
        ShowWindow(cw, SW_RESTORE);
        ShowWindow(cw, SW_SHOW);
        SetForegroundWindow(cw);
        BringWindowToTop(cw);
    }
}

DWORD WINAPI MainThread(LPVOID param)
{
    CreateConsole();

    info("resolving ntapi functions");
    if (!ResolveNt()) {
        error("failed to resolve ntapi functions");
    }

    info("Trying to get handle");

    HANDLE handle = GetHandle(L"cs2.exe");
    if (!(handle == INVALID_HANDLE_VALUE) && handle != nullptr ) {
        okay("Hijacked handle: 0x%X", (uintptr_t)handle);
    }
    else {
        error("Failed to get handle");
    }

    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        //stop();
        break;
    }
    return TRUE;
}

