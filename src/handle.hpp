#pragma once
#define HANDLE_TYPE_PROCESS 8 // 8 for windows 11 25h2
#define TEST_STATUS_SUCCESS 0
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>

bool ResolveNt();
DWORD GetPidByName(const wchar_t* name);
HANDLE GetHandle(const wchar_t* name); // DWORD targetPID