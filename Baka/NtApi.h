#pragma once
#include "NOCrt.h"



typedef   NTSTATUS(NTAPI* t_ZwOpenSection)
(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	);





typedef   NTSTATUS(NTAPI* t_ZwMapViewOfSection)
(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
	);

typedef   NTSTATUS(NTAPI* t_NtClose)
(
	HANDLE Handle
	);

typedef   NTSTATUS(NTAPI* t_ZwUnmapViewOfSection)
(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
	);



typedef NTSTATUS(NTAPI* t_NtQueryInformationProcess)
(



	IN HANDLE               ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID               ProcessInformation,
	IN ULONG                ProcessInformationLength,
	OUT PULONG              ReturnLength
	);

typedef NTSTATUS(NTAPI* t_NtSetInformationThread)(



	IN HANDLE               ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID                ThreadInformation,
	IN ULONG                ThreadInformationLength);



typedef NTSTATUS(NTAPI* t_NtQuerySystemInformation)
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef NTSTATUS(NTAPI* t_NtQueryInformationThread)
(



	IN HANDLE               ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID               ThreadInformation,
	IN ULONG                ThreadInformationLength,
	OUT PULONG              ReturnLength OPTIONAL);




typedef  NTSTATUS(NTAPI* t_NtReadVirtualMemory)
(



	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL);



typedef  NTSTATUS(NTAPI* t_NtAllocateVirtualMemory)(



	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect); 
typedef  NTSTATUS(NTAPI* t_RtlGetVersion)
(
	PRTL_OSVERSIONINFOW lpVersionInformation
	);

