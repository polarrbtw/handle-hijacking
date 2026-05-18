#include "includes.hpp"
#include "handle.hpp"

// code from: https://github.com/paskalian/HandleHijacking/blob/master/HandleHijacking/main.cpp

using pNtQuerySystemInformation = NTSTATUS(NTAPI*)(
	SYSTEM_INFORMATION_CLASS,
	PVOID,
	ULONG,
	PULONG);

pNtQuerySystemInformation NtQuerySystemInformation_ = nullptr;

using pNtQueryInformationProcess = NTSTATUS(NTAPI*)(
	HANDLE,
	PROCESSINFOCLASS,
	PVOID,
	ULONG,
	PULONG);

static pNtQueryInformationProcess NtQueryInformationProcess_ = nullptr;

using pNtReadVirtualMemory = NTSTATUS(NTAPI*)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead);

using pNtWriteVirtualMemory = NTSTATUS(NTAPI*)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten);

static pNtReadVirtualMemory NtReadVirtualMemory_ = nullptr;
static pNtWriteVirtualMemory NtWriteVirtualMemory_ = nullptr;

bool ResolveNt()
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) {
		error("failed to get ntdll handle");
		return false;
	}

	NtQuerySystemInformation_ = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	NtQueryInformationProcess_ = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
	NtReadVirtualMemory_ = (pNtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
	NtWriteVirtualMemory_ = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	
	if (NtQuerySystemInformation_ && NtQueryInformationProcess_ && NtReadVirtualMemory_ && NtWriteVirtualMemory_) {
		return true;
	}
	return false;
}

DWORD GetPidByName(const wchar_t* name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		error("CreateToolhelp32Snapshot failed, err: 0x%X\n", GetLastError());
	}

	PROCESSENTRY32W proc{};
	proc.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(snapshot, &proc)) {
		do {
			if (_wcsicmp(proc.szExeFile, name) == 0) {
				CloseHandle(snapshot);
				return proc.th32ProcessID;
			}
		} while (Process32NextW(snapshot, &proc));
	}

	CloseHandle(snapshot);
	return 0;
}

HANDLE GetHandle(const wchar_t* name) {
	DWORD targetPID = GetPidByName(name);
	if (targetPID == 0) {
		error("failed to find target PID");
		return NULL;
	}

	DWORD currentPID = GetCurrentProcessId();
	okay("Current PID: %ld, Target PID: %ld", currentPID, targetPID);

	ULONG bufferSize = 0x100000;
	std::vector<BYTE> buffer(bufferSize);
	NTSTATUS status;
	ULONG returnLength = 0;

	while ((status = NtQuerySystemInformation_(
		SystemExtendedHandleInformation,
		buffer.data(),
		bufferSize,
		&returnLength)) == STATUS_INFO_LENGTH_MISMATCH) {

		bufferSize = (returnLength > bufferSize) ? returnLength : bufferSize * 2;
		buffer.resize(bufferSize);
	}

	if (!NT_SUCCESS(status)) {
		error("NtQuerySystemInformation failed: 0x%X", status);
		return NULL;
	}

	PSYSTEM_HANDLE_INFORMATION_EX handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());
	info("Iterating through %ld handles", handleInfo->NumberOfHandles);

	for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
		const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& entry = handleInfo->Handles[i];

		// check if owned by current process
		if ((ULONG_PTR)entry.UniqueProcessId != (ULONG_PTR)currentPID ||
			entry.ObjectTypeIndex != HANDLE_TYPE_PROCESS) { // 8 on windows 11 25h2
			continue;
		}

		// check privileges
		if ((entry.GrantedAccess & 0x1F3FFF) != 0x1F3FFF) { // 0x1F3FFF is PROCESS_ALL_ACCESS
			continue;
		}

		HANDLE hijackedHandle = entry.HandleValue;

		// make sure handle isn't invalid
		if (hijackedHandle == NULL || hijackedHandle == INVALID_HANDLE_VALUE) {
			continue;
		}

		PROCESS_BASIC_INFORMATION pbi = { 0 };
		ULONG retLen = 0;

		status = NtQueryInformationProcess_(
			hijackedHandle,
			ProcessBasicInformation,
			&pbi,
			sizeof(pbi),
			&retLen
		);

		if (!NT_SUCCESS(status)) {
			continue;
		}

		DWORD queriedPID = (DWORD)(ULONG_PTR)pbi.UniqueProcessId;

		if (queriedPID == targetPID) {
			okay("Found matching handle (access: 0x%x, handle: 0x%X", entry.GrantedAccess, hijackedHandle);
			return hijackedHandle;
		}
	}

	error("no handle found");
	return NULL;
}