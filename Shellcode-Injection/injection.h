#pragma once

#include <stdio.h>
#include <windows.h>

#define MAX_SHELLCODE_SIZE 9168

//------------------------------------------------------------------------------------------------\

#pragma region debugMacro

#define yapWarn(msg, ...) printf("[\"-\"] " msg "\n", __VA_ARGS__)
#define yapOkay(msg, ...) printf("[^-^] " msg "\n", __VA_ARGS__)
#define yapBad(msg, ...) printf("[*-*] " msg "\n", __VA_ARGS__)

#pragma endregion

//------------------------------------------------------------------------------------------------

#pragma region ShellcodeInjection

BOOL LoadShellcodeFromFile(const char* filename);
BOOL ShellcodeInjection(DWORD PID, unsigned char* shellcode, size_t shellcodeSize);

#pragma endregion