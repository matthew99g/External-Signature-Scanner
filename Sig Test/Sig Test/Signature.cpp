#include "Signature.h"

MODULEINFO GetModuleInfo(const char *szModule, DWORD dwProcessId, HANDLE hProcessT) {
	MODULEINFO modInfo = { 0 };
	MODULEENTRY32 mEntry = { sizeof(MODULEENTRY32) };
	HANDLE hProcess = NULL;

	do {
		hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (hProcess == INVALID_HANDLE_VALUE)
			return modInfo;

		if (Module32First(hProcess, &mEntry)) {

			do {

				if (!strcmp(mEntry.szModule, szModule)) {
					GetModuleInformation(hProcessT, mEntry.hModule, &modInfo, sizeof(MODULEINFO));
					printf("0x%X\n", modInfo.lpBaseOfDll);
					break;
				}

			} while (Module32Next(hProcess, &mEntry));

		}

	} while (!modInfo.lpBaseOfDll);

	return modInfo;
}

DWORD GetProcId(const char *szProcessName) {
	DWORD dwProcessId = NULL;
	PROCESSENTRY32 pEntry = { sizeof(PROCESSENTRY32) };
	HANDLE hProcess = NULL;

	do {
		hProcess = CreateToolhelp32Snapshot(PROCESS_ALL_ACCESS, 0);
		if (hProcess == INVALID_HANDLE_VALUE)
			return dwProcessId;

		if (Process32First(hProcess, &pEntry)) {

			do {

				if (!strcmp(pEntry.szExeFile, szProcessName)) {
					dwProcessId = pEntry.th32ProcessID;
					break;
				}

			} while (Process32Next(hProcess, &pEntry));

		}

	} while (!dwProcessId);

	return dwProcessId;
}

bool CheckSignatureValid(HANDLE hProcess, MODULEINFO modInfo, PBYTE szBytes) {
	DWORD dwOld = 0;
	DWORD count = 0;

	DWORD dwMemoryBase = (DWORD)modInfo.lpBaseOfDll;
	DWORD dwMemorySize = (DWORD)modInfo.SizeOfImage;

	DWORD dwSignatureSize = (DWORD)strlen((const char *)szBytes);

	bool bSearch = false;

	BYTE *buf = new BYTE[dwMemorySize];
	ZeroMemory(buf, sizeof(buf));

	VirtualProtectEx(hProcess, (LPVOID)(dwMemoryBase), dwMemorySize, PROCESS_ALL_ACCESS, &dwOld);
	ReadProcessMemory(hProcess, (LPCVOID)(dwMemoryBase), buf, dwMemorySize, NULL);

	for (int p = 0; p < dwMemorySize - dwSignatureSize; p++) {
		DWORD i = 0;
		for (i = 0; i < dwSignatureSize; i++) {
			bSearch = (*((char *)(buf + i + p)) == *((char *)(szBytes + i))) ? true : false;
			if (!bSearch)
				break;
		}

		if (bSearch) {
			count++;
			printf("%d @ 0x%X\n", count, (DWORD)(DWORD *)(p + dwMemoryBase));
		}

	}

	VirtualProtectEx(hProcess, (LPVOID)(dwMemoryBase), dwMemorySize, dwOld, NULL);

	if (count != 1)
		return false;

	printf("Found %d times\n", count);
	delete buf;
	return true;
}