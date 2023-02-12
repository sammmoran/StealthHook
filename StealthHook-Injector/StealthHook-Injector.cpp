// StealthHook-Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <tchar.h>
#include <string>
#include <cstring>
#include <Windows.h>
#include <easyhook.h>

using namespace std;

// Depending on the operating system being compiled on
#if _WIN64
#pragma comment(lib, "EasyHook64.lib")
#else
#pragma comment(lib, "EasyHook32.lib")
#endif


int _tmain(int argc, _TCHAR* argv[]) {


	// We need the process ID of Notepad.exe as it's running
	DWORD processId;
	wcout << "Enter the target process Id: ";
	cin >> processId;

	// We'll now attempt to inject the hook into the library
	NTSTATUS nt = RhInjectLibrary(
		processId,
		0,
		EASYHOOK_INJECT_DEFAULT,
		NULL,
		(WCHAR*)L"C:\\Users\\User\\source\\repos\\StealthHook\\x64\\Debug\\StealthHook-Hook.dll",
		NULL,
		0	
	);

	// Check if success
	if (nt != 0) {

		printf("RhInjectLibrary failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		wcout << err << "\n";

	}

	else
		wcout << L"Library injected successfully.\n";

	wcout << "Press Enter to exit";
	wstring input;
	getline(wcin, input);
	getline(wcin, input);

	return 0;

}