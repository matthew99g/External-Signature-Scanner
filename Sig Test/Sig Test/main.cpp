#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "Signature.h"

const char szProcName[] = "ac_client.exe";
const char szMemory[] = "\x89\x10\x8B\x76\x14\xFF\x0E\x57\x8B\x7C";

int main(const int argc, const char *argv) {
	DWORD dwProcessId = GetProcId(szProcName);
	if (!dwProcessId) {
		fprintf(stderr, "Failed to get process ID\n");
		getchar();
		return EXIT_FAILURE;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, dwProcessId);
	if (hProcess == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Failed to get process handle\n");
		getchar();
		return EXIT_FAILURE;
	}

	MODULEINFO modInfo = GetModuleInfo(szProcName, dwProcessId, hProcess);
	if (!modInfo.lpBaseOfDll) {
		fprintf(stderr, "Failed to get module\n");
		fprintf(stderr, "0x%X\n", modInfo.lpBaseOfDll);
		getchar();
		return EXIT_FAILURE;
	}

	printf("%d | 0x%X | 0x%X\n", dwProcessId, modInfo.lpBaseOfDll, modInfo.SizeOfImage);

	if (!CheckSignatureValid(hProcess, modInfo, (PBYTE)szMemory)) {
		fprintf(stderr, "Unable to validate signature\n");
		getchar();
		return EXIT_FAILURE;
	}

	CloseHandle(hProcess);

	getchar();
	return EXIT_SUCCESS;
}