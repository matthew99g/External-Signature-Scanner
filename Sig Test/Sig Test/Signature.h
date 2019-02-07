#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>

MODULEINFO GetModuleInfo(const char *, DWORD, HANDLE);

DWORD GetProcId(const char *);

bool CheckSignatureValid(HANDLE, MODULEINFO, PBYTE);