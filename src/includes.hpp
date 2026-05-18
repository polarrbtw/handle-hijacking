#pragma once

// config
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

// PHNT configuration
#define PHNT_VERSION PHNT_WINDOWS_11
#define PHNT_MODE PHNT_MODE_USER
#define PHNT_NO_ZWAPI   // prevent ntzwapi.h from being included

// spdlog / fmt
#define FMT_UNICODE 0

// Ensure DEFAULT packing for Windows headers
#ifdef _MSC_VER
#pragma pack(push, 8)
#endif

#include <Windows.h>

#ifdef _MSC_VER
#pragma pack(pop)
#endif

// PHNT header fix
typedef struct _WORKER_FACTORY_DEFERRED_WORK WORKER_FACTORY_DEFERRED_WORK;
typedef WORKER_FACTORY_DEFERRED_WORK* PWORKER_FACTORY_DEFERRED_WORK;

#include <phnt_windows.h>
#include <phnt.h>

// other libs
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>

// Logging
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

#define infodbg(msg, ...) \
    do {                  \
        char _buf[1024];  \
        std::snprintf(_buf, sizeof(_buf), "[*] " msg "\n", ##__VA_ARGS__); \
        OutputDebugStringA(_buf); \
    } while (0)

// #include <spdlog/spdlog.h>