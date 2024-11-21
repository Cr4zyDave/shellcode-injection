#pragma once
#include <stdio.h>
#include <windows.h>

#define MAX_SHELLCODE_SIZE 9168

//------------------------------------------------------------------------------------------------

extern DWORD PID;
extern char procName[25];
extern size_t shellcodeSize;
extern unsigned char shellcode[MAX_SHELLCODE_SIZE];


//------------------------------------------------------------------------------------------------

#pragma region debugMacro

#define yapWarn(msg, ...) printf("[\"-\"] " msg "\n", __VA_ARGS__)
#define yapOkay(msg, ...) printf("[^-^] " msg "\n", __VA_ARGS__)
#define yapBad(msg, ...) printf("[*-*] " msg "\n", __VA_ARGS__)

#pragma endregion

//------------------------------------------------------------------------------------------------

#pragma region ShellcodeInjection

extern void banner(void);
extern DWORD findPID(char *procName);
extern BOOL LoadShellcodeFromFile(const char* filename);
extern BOOL ShellcodeInjection(DWORD PID, unsigned char* shellcode, size_t shellcodeSize);

#pragma endregion
