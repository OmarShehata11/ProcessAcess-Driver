#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Psapi.h>
#include <tchar.h>
#include "../ProcessAccessDriver/Header.h"

bool ListDlls(HANDLE hProcess);

int main(int argc, const char* argv[])
{
	if (argc < 2)
	{
		printf("Use: %s <pid>\n", argv[0]);
		return 1;
	}

	DWORD returnedVal;
	HANDLE hDriver, hProcess;
	bool success;
	int error;

	// get the PID of the target process
	int Pid = atoi(argv[1]);

	// open the process with full access rights
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);

	if (hProcess == NULL)
	{
		error = GetLastError();

		if (error == 5) // access denied, so we need the driver
		{
			
			hDriver = CreateFileA("\\\\.\\PorcessAccessOmarSym", GENERIC_ALL, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
			
			if (hDriver == INVALID_HANDLE_VALUE)
			{
				printf("error: while openning a handle to the driver, error code : %d\n", GetLastError());
				return 1;
			}


			success = DeviceIoControl(hDriver, IOCTL_PROC_ACCESS, &Pid, sizeof(Pid), &hProcess, sizeof(hProcess), &returnedVal, nullptr);

			if (!success)
			{
				printf("Error: while send the IO control request, error code : %d\n", GetLastError());
				return 1;
			}

		}
		
		else 
		{
			printf("error while opening the process, error code %d\n", error);
			return 1;
		}
	}

	success = ListDlls(hProcess);

	CloseHandle(hProcess);

	if (!success) {
		printf("ERROR: ListDlls error with code : %d", GetLastError());
		return 1;
	}


	return 0;
}

bool ListDlls(HANDLE hProcess)
{
	HMODULE hModuleArr[100]; /* holds all the modules handles*/
	DWORD cnNeeded; /* size needed to store all modules in bytes */

	WCHAR ModuleName[256]; /* holds the module name */
	WCHAR ModulePath[MAX_PATH]; /* holds the module full path*/

	// get all modules used by the process.
	bool status = EnumProcessModules(hProcess, hModuleArr, sizeof(hModuleArr), &cnNeeded);
	
	if (!status)
		return status;

	// check the size of array needed and the porvided:
	if (cnNeeded > sizeof(hModuleArr))
	{
		printf("you need more size for the array of modules bro. the size of array : %d, and size needed is %d\n", sizeof(hModuleArr), cnNeeded);
		return FALSE;
	}

	// loop to list all modules:
	for (int i = 0; i < (cnNeeded / sizeof(HMODULE)); i++)
	{

		// Get the module full path and its name:
		GetModuleFileNameEx(hProcess, hModuleArr[i], ModulePath, sizeof(ModulePath)); /*bath*/
		GetModuleBaseName(hProcess, hModuleArr[i], ModuleName, sizeof(ModuleName)); /*name*/

		// print the data:
		printf("Moduel Name:\t%ws\nModule Path:\t%ws\nModule address:\t0x%p\n\n", ModuleName, ModulePath, hModuleArr[i]);
	}

	return status;
}