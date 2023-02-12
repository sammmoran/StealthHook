#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <easyhook.h>
#include <string>
#include <tchar.h>
#include <winnt.h>

using namespace std;


// Depending on the operating system being compiled on
#if _WIN64
#pragma comment(lib, "EasyHook64.lib")
#else
#pragma comment(lib, "EasyHook32.lib")
#endif


DWORD gFreqOffset = 0;


// Declaration of hook function to be run (will contain function pointer to exact functionality we want to run above)
NTSTATUS NtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
);


// Implementation of hook function
NTSTATUS NtCreateFileHook(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
) {


	MessageBox(GetActiveWindow(), (LPCWSTR)ObjectAttributes->ObjectName->Buffer, (LPCWSTR)L"Object Name", MB_OK);

	

	return NtCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength
	);

}


// Declaration of EasyHook export
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo);


// Implementation of EasyHook export
void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo) {

	// Create hook trace info
	// This will make it easier or possible at all to update managed classes containing a hook handle
	// If the native library is unloaded or someone removes such a hook or all hooks from unmanaged code, it will make it possible to modify the hook
	HOOK_TRACE_INFO hHook = { NULL };

	// Now install the hook into the specified process
	NTSTATUS result = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtCreateFile"),			// The function we want to hook
		NtCreateFileHook,														// Our hook
		NULL,
		&hHook																	// To keep track of our hook
	);

	// If our install failed
	if (FAILED(result)) {
	
		MessageBox(GetActiveWindow(), (LPCWSTR)RtlGetLastErrorString(), (LPCWSTR)L"Failed to install hook", MB_OK);
	
	}

	// Now, set the thread to activate the hook
	// The hook will now run on the current thread
	ULONG ACLEntries[1] = { 0 };
	LhSetExclusiveACL(ACLEntries, 1, &hHook);

	return;

}