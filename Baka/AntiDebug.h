#pragma once

#include "SyscallHelp.hpp"
#include "WoW64ext.h"


 
namespace AntiDebug
{

	namespace ShellCode
	{

		__forceinline bool IsDebugPort()
		{
			DWORD64  DebugPort = NULL;
			NTSTATUS status = STATUS_UNSUCCESSFUL;


			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};
			
			auto SyscallNumber = SyscallStub::GetSyscallNumber(L"ntdll.dll", "NtQueryInformationProcess");// Get auto syscall number

			// can't find automatic sycall number ,so we get manual by Windows number
			if (!SyscallNumber)
			{
				ApiWrapper::printf(L"[!] Can't get syscall auto!\n");

				auto numberWindows = ApiWrapper::GetWindowsNumber();
				if (numberWindows > WINDOWS_NUMBER_8_1)
				{
					SyscallNumber = 25;

				}
				else if (numberWindows == WINDOWS_NUMBER_8_1)
				{
					SyscallNumber = 24;
				}
				else if (numberWindows == WINDOWS_NUMBER_8)
				{
					SyscallNumber = 23;
				}
				else if (numberWindows < WINDOWS_NUMBER_8)
				{
					SyscallNumber = 22;
				}
			}

			auto addressShellCode = (t_NtQueryInformationProcess)VirtualAlloc(0, 0x1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!addressShellCode)
			{
				return FALSE;
			}

			NoCRT::mem::memcpy(&shellSysCall64[1], &SyscallNumber, 2); //set syscall
			NoCRT::mem::memcpy((void*)addressShellCode, shellSysCall64, sizeof(shellSysCall64));// write shellcode

#ifdef _WIN64

			status = addressShellCode(NtCurrentProcess, ProcessDebugPort, &DebugPort, sizeof(DebugPort), 0);
#else

			status = WoW64Help::X64Call(
				(DWORD64)addressShellCode,
				5,
				(DWORD64)-1,	//NtCurrentProcess
				(DWORD64)ProcessDebugPort,
				(DWORD64)&DebugPort,
				(DWORD64)sizeof(DebugPort),
				(DWORD64)0);


#endif // 


			VirtualFree((PVOID)addressShellCode, 0, MEM_RELEASE);
			if (NT_SUCCESS(status) && DebugPort != 0)
			{
				return TRUE;
			}
			return FALSE;
		}


		__forceinline	bool IsDebugObjectHandle()
		{
			DWORD64	DebugObject = NULL;
			NTSTATUS  status = STATUS_UNSUCCESSFUL;


			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};

			auto SyscallNumber = SyscallStub::GetSyscallNumber(L"ntdll.dll", "NtQueryInformationProcess");// Get auto syscall number

			// can't find automatic sycall number ,so we get manual by Windows number
			if (!SyscallNumber)
			{
				auto numberWindows = ApiWrapper::GetWindowsNumber();
				if (numberWindows > WINDOWS_NUMBER_8_1)
				{
					SyscallNumber = 25;

				}
				else if (numberWindows == WINDOWS_NUMBER_8_1)
				{
					SyscallNumber = 24;
				}
				else if (numberWindows == WINDOWS_NUMBER_8)
				{
					SyscallNumber = 23;
				}
				else if (numberWindows < WINDOWS_NUMBER_8)
				{
					SyscallNumber = 22;
				}
			}

			auto addressShellCode = (t_NtQueryInformationProcess)VirtualAlloc(0, 0x1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!addressShellCode)
			{
				return FALSE;
			}

			NoCRT::mem::memcpy(&shellSysCall64[1], &SyscallNumber, 2); //set syscall
			NoCRT::mem::memcpy((void*)addressShellCode, shellSysCall64, sizeof(shellSysCall64));// write shellcode

#ifdef _WIN64

			status = addressShellCode(NtCurrentProcess, ProcessDebugObjectHandle, &DebugObject, sizeof(DebugObject), 0);
#else

			status = WoW64Help::X64Call(
				(DWORD64)addressShellCode,
				5,
				(DWORD64)-1,	//NtCurrentProcess
				(DWORD64)ProcessDebugObjectHandle,
				(DWORD64)&DebugObject,
				(DWORD64)sizeof(DebugObject),
				(DWORD64)0);


#endif // 


			VirtualFree((PVOID)addressShellCode, 0, MEM_RELEASE);
			if (NT_SUCCESS(status) && DebugObject != 0)
			{
				return TRUE;
			}
			return FALSE;
		}



		__forceinline bool IsDebugFlag()
		{
			DWORD  DebugFlag = NULL;
			NTSTATUS  status = STATUS_UNSUCCESSFUL;


			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};

			auto SyscallNumber = SyscallStub::GetSyscallNumber(L"ntdll.dll", "NtQueryInformationProcess");// Get auto syscall number


			/// can't find automatic sycall number ,so we get manual by Windows number
			if (!SyscallNumber)
			{
				auto numberWindows = ApiWrapper::GetWindowsNumber();
				if (numberWindows > WINDOWS_NUMBER_8_1)
				{
					SyscallNumber = 25;

				}
				else if (numberWindows == WINDOWS_NUMBER_8_1)
				{
					SyscallNumber = 24;
				}
				else if (numberWindows == WINDOWS_NUMBER_8)
				{
					SyscallNumber = 23;
				}
				else if (numberWindows < WINDOWS_NUMBER_8)
				{
					SyscallNumber = 22;
				}
			}

			auto addressShellCode = VirtualAlloc(0, 0x1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!addressShellCode)
			{
				return FALSE;
			}

			NoCRT::mem::memcpy(&shellSysCall64[1], &SyscallNumber, 2); //set syscall
			NoCRT::mem::memcpy((void*)addressShellCode, shellSysCall64, sizeof(shellSysCall64));// write shellcode

#ifdef _WIN64

			status = ((t_NtQueryInformationProcess)addressShellCode)(NtCurrentProcess, ProcessDebugFlags, &DebugFlag, sizeof(DebugFlag), 0);
#else

			status = WoW64Help::X64Call(
				(DWORD64)addressShellCode,
				5,
				(DWORD64)-1,	//NtCurrentProcess
				(DWORD64)ProcessDebugFlags,
				(DWORD64)&DebugFlag,
				(DWORD64)sizeof(DebugFlag),
				(DWORD64)0);


#endif // 


			VirtualFree((PVOID)addressShellCode, 0, MEM_RELEASE);
			if (status == STATUS_SUCCESS && DebugFlag == 0)
			{
				return TRUE;
			}
			return FALSE;
		}

		__forceinline	bool IsBadHideThread()
		{

			NTSTATUS  status = STATUS_UNSUCCESSFUL;
			bool IsThreadHide = FALSE;
			DWORD64 badGuy = NULL;

			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};

			auto syscallNumberSetInformathion = SyscallStub::GetSyscallNumber(L"ntdll.dll", "NtSetInformationThread");// Get auto syscall number

			auto syscallNumberQueryInfThread = SyscallStub::GetSyscallNumber(L"ntdll.dll", "NtQueryInformationThread");// Get auto syscall number

			if (!syscallNumberSetInformathion || !syscallNumberQueryInfThread)
			{
				/// can't find automatic sycall number ,so we get manual by Windows number
				auto numberWindows = ApiWrapper::GetWindowsNumber();
				if (numberWindows > WINDOWS_NUMBER_8_1)
				{
					syscallNumberSetInformathion = 13;
					syscallNumberQueryInfThread = 37;
				}
				else if (numberWindows == WINDOWS_NUMBER_8_1)
				{
					syscallNumberSetInformathion = 12;
					syscallNumberQueryInfThread = 36;
				}
				else if (numberWindows == WINDOWS_NUMBER_8)
				{
					syscallNumberSetInformathion = 11;
					syscallNumberQueryInfThread = 35;
				}
				else if (numberWindows < WINDOWS_NUMBER_8)
				{
					syscallNumberSetInformathion = 10;
					syscallNumberQueryInfThread = 34;
				}
			}

			auto addressShellCode = VirtualAlloc(0, 0x1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!addressShellCode)
			{
				return FALSE;
			}

			NoCRT::mem::memcpy(&shellSysCall64[1], &syscallNumberSetInformathion, 2); //set syscall
			NoCRT::mem::memcpy((void*)addressShellCode, shellSysCall64, sizeof(shellSysCall64));// write shellcode
#ifdef _WIN64

			status = ((t_NtSetInformationThread)addressShellCode)(NtCurrentThread, ThreadHideFromDebugger, &badGuy, 0x999);


			if (NT_SUCCESS(status))
			{
				return true;
			}

			status = ((t_NtSetInformationThread)addressShellCode)(NtCurrentThread, ThreadHideFromDebugger, 0, 0);
#else


			status = WoW64Help::X64Call(
				(DWORD64)addressShellCode,
				4,
				(DWORD64)-2,	//NtCurrentThread
				(DWORD64)0x11,	//HideFromDebugger
				(DWORD64)&badGuy,
				(DWORD64)0x999);

			if (NT_SUCCESS(status))
			{
				return true;
			}


			status = WoW64Help::X64Call(
				(DWORD64)addressShellCode,
				4,
				(DWORD64)-2,	//NtCurrentThread
				(DWORD64)0x11,	//HideFromDebugger
				(DWORD64)0,
				(DWORD64)0);
#endif

			if (!NT_SUCCESS(status))
			{
				return FALSE;
			}


			NoCRT::mem::memcpy(&shellSysCall64[1], &syscallNumberQueryInfThread, 2); //set syscall
			NoCRT::mem::memcpy((void*)addressShellCode, shellSysCall64, sizeof(shellSysCall64));// write shellcode

#ifdef _WIN64
			status = ((t_NtQueryInformationThread)addressShellCode)(NtCurrentThread, ThreadHideFromDebugger, &IsThreadHide, sizeof(bool), 0);
#else

			status = WoW64Help::X64Call(
				(
					DWORD64)addressShellCode,
				5,
				(DWORD64)-2,	//NtCurrentThread
				(DWORD64)0x11,	//HideFromDebugger
				(DWORD64)&IsThreadHide,
				(DWORD64)sizeof(bool),
				(DWORD64)0
			);
#endif

			VirtualFree((PVOID)addressShellCode, 0, MEM_RELEASE);
			if (NT_SUCCESS(status) && !IsThreadHide)
			{
				return TRUE;
			}
			return FALSE;
		}


	}


	namespace OverWriteSyscall
	{
		 bool IsDebugPort()
		{
			DWORD64  DebugPort = NULL;
			NTSTATUS status = STATUS_UNSUCCESSFUL;
			DWORD protect = NULL;
			BYTE safeByte[20];
			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};
			NoCRT::mem::memset(safeByte, 0, sizeof(safeByte));
			auto SyscallNumber = SyscallStub::GetSyscallNumber(L"ntdll.dll", "NtQueryInformationProcess");// Get auto syscall number

			/// can't find automatic sycall number ,so we get manual by Windows number
			if (!SyscallNumber)
			{

				auto numberWindows = ApiWrapper::GetWindowsNumber();
				if (numberWindows > WINDOWS_NUMBER_8_1)
				{
					SyscallNumber = 25;

				}
				else if (numberWindows == WINDOWS_NUMBER_8_1)
				{
					SyscallNumber = 24;
				}
				else if (numberWindows == WINDOWS_NUMBER_8)
				{
					SyscallNumber = 23;
				}
				else if (numberWindows < WINDOWS_NUMBER_8)
				{
					SyscallNumber = 22;
				}
			}
			auto addressApi = (t_NtQueryInformationProcess)ApiWrapper::GetProcAddress(L"ntdll.dll", "NtAddBootEntry");  //NtAddBootEntry
			if (!addressApi)
			{
				return FALSE;
			}
			//We write shellcode in ntdll Api for present allocate memory
			VirtualProtect(addressApi, 0x1024, PAGE_EXECUTE_READWRITE, &protect);
			NoCRT::mem::memcpy(&shellSysCall64[1], &SyscallNumber, 2); //set syscall
			NoCRT::mem::memcpy(safeByte, addressApi, sizeof(safeByte));
			NoCRT::mem::memcpy((void*)addressApi, shellSysCall64, sizeof(shellSysCall64));// write shellcode

#ifdef _WIN64

			status = addressApi(NtCurrentProcess, ProcessDebugPort, &DebugPort, sizeof(DebugPort), 0);
#else

			status = WoW64Help::X64Call(
				(DWORD64)addressApi,
				5,
				(DWORD64)-1,	//NtCurrentProcess
				(DWORD64)ProcessDebugPort,
				(DWORD64)&DebugPort,
				(DWORD64)sizeof(DebugPort),
				(DWORD64)0);


#endif // 
			NoCRT::mem::memcpy(addressApi ,safeByte, sizeof(safeByte));
			VirtualProtect(addressApi, 0x1024, protect, &protect);
			if (NT_SUCCESS(status) && DebugPort != 0)
			{
				return TRUE;
			}
			return FALSE;
		}

		bool IsBadHideThread()
		{

			NTSTATUS  status = STATUS_UNSUCCESSFUL;
			bool IsThreadHide = FALSE;
			DWORD64 badGuy = NULL;
			DWORD protect = NULL;
			BYTE safeByte[20];
			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};

			auto syscallNumberSetInformathion = SyscallStub::GetSyscallNumber(L"ntdll.dll", "NtSetInformationThread");// Get auto syscall number

			auto syscallNumberQueryInfThread = SyscallStub::GetSyscallNumber(L"ntdll.dll", "NtQueryInformationThread");// Get auto syscall number

			if (!syscallNumberSetInformathion || !syscallNumberQueryInfThread)
			{
				// can't find automatic value ,so we get manual by Windows number
				auto numberWindows = ApiWrapper::GetWindowsNumber();
				if (numberWindows > WINDOWS_NUMBER_8_1)
				{
					syscallNumberSetInformathion = 13;
					syscallNumberQueryInfThread = 37;
				}
				else if (numberWindows == WINDOWS_NUMBER_8_1)
				{
					syscallNumberSetInformathion = 12;
					syscallNumberQueryInfThread = 36;
				}
				else if (numberWindows == WINDOWS_NUMBER_8)
				{
					syscallNumberSetInformathion = 11;
					syscallNumberQueryInfThread = 35;
				}
				else if (numberWindows < WINDOWS_NUMBER_8)
				{
					syscallNumberSetInformathion = 10;
					syscallNumberQueryInfThread = 34;
				}
			}
			auto addressApi = (t_NtQueryInformationProcess)ApiWrapper::GetProcAddress(L"ntdll.dll", "NtLoadDriver");  //NtAddBootEntry

			if (!addressApi)
			{
				return FALSE;
			}
			VirtualProtect(addressApi, 0x1024, PAGE_EXECUTE_READWRITE, &protect);
			NoCRT::mem::memcpy(&shellSysCall64[1], &syscallNumberSetInformathion, 2); //set syscall
			NoCRT::mem::memcpy(safeByte, addressApi, sizeof(safeByte));// sade byte
			NoCRT::mem::memcpy((void*)addressApi, shellSysCall64, sizeof(shellSysCall64));// write shellcode
#ifdef _WIN64

			status = ((t_NtSetInformationThread)addressApi)(NtCurrentThread, ThreadHideFromDebugger, &badGuy, 0x999);


			if (NT_SUCCESS(status))
			{
				return true;
			}

			status = ((t_NtSetInformationThread)addressApi)(NtCurrentThread, ThreadHideFromDebugger, 0, 0);
#else


			status = WoW64Help::X64Call(
				(DWORD64)addressApi,
				4,
				(DWORD64)-2,	//NtCurrentThread
				(DWORD64)0x11,	//HideFromDebugger
				(DWORD64)&badGuy,
				(DWORD64)0x999);

			if (NT_SUCCESS(status))
			{
				return true;
			}


			status = WoW64Help::X64Call(
				(DWORD64)addressApi,
				4,
				(DWORD64)-2,	//NtCurrentThread
				(DWORD64)0x11,	//HideFromDebugger
				(DWORD64)0,
				(DWORD64)0);
#endif

			if (!NT_SUCCESS(status))
			{
				return FALSE;
			}


			NoCRT::mem::memcpy(&shellSysCall64[1], &syscallNumberQueryInfThread, 2); //set syscall
			NoCRT::mem::memcpy((void*)addressApi, shellSysCall64, sizeof(shellSysCall64));// write shellcode

#ifdef _WIN64
			status = ((t_NtQueryInformationThread)addressApi)(NtCurrentThread, ThreadHideFromDebugger, &IsThreadHide, sizeof(bool), 0);
#else

			status = WoW64Help::X64Call(
				(DWORD64)addressApi,
				5,
				(DWORD64)-2,	//NtCurrentThread
				(DWORD64)0x11,	//HideFromDebugger
				(DWORD64)&IsThreadHide,
				(DWORD64)sizeof(bool),
				(DWORD64)0
			);
#endif
			NoCRT::mem::memcpy(addressApi, safeByte, sizeof(safeByte));
			VirtualProtect(addressApi, 0x1024, protect, &protect);
			if (NT_SUCCESS(status) && !IsThreadHide)
			{
				return TRUE;
			}
			return FALSE;
		}
	



}

	namespace Util
	{

		/*
		Check only in execute module for present false detect
		 0xcc - can be code cave
		*/
		__forceinline bool IsModuleHaveBP() 
		{
				auto base = (PVOID)ApiWrapper::GetModuleBaseAddress(NULL);

				auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
				auto* sections = IMAGE_FIRST_SECTION(headers);

				for (auto i = 0; i <= headers->FileHeader.NumberOfSections;i++)
				{
					auto* section = &sections[i];
					//Check secthion rules
					auto virtualAddress = static_cast<PBYTE>(base) + section->VirtualAddress;
					if ((section->Characteristics & IMAGE_SCN_MEM_READ && section->Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(section->Characteristics & IMAGE_SCN_MEM_WRITE))
					{
						for (size_t j = 0; j <= section->Misc.VirtualSize; j++)
						{
							if (*(virtualAddress + j) == 0x0f && *(virtualAddress + j + 1) == 0xb)//ud2 breakpoint
							{ 
								return TRUE;
							}
#ifndef _WIN64  //false detect in x64 program :(
							
							else if (*(virtualAddress + j) == 0xcd && *(virtualAddress + j + 1) == 0x3)//long int 
							{
								return TRUE;
							}
#endif // !_WIN64
						}
					}
				
				}
				return FALSE;
		}


		/*
		Anti UM plugin change build number for bypass manual syscall in VMP and we will be check this
		*/
		__forceinline bool BuildNumberIsHooked()
		{

			bool bDeect = FALSE;

			if (ApiWrapper::GetWindowsNumber() >= WINDOWS_NUMBER_10)
			{
				// we can safe check by read  NtBuildNumber in KUSER_SHARED_DATA
				bDeect = ApiWrapper::GetNumberBuild() != ApiWrapper::PEBGetNumberBuild();

			}
			else
			{
				// windows number < 10 we check by RtlGetVersion
				RTL_OSVERSIONINFOW  lpVersionInformation;

				lpVersionInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);


				auto   RtlGetVersion = (t_RtlGetVersion)ApiWrapper::GetProcAddress(L"ntdll.dll", "RtlGetVersion");

				if (RtlGetVersion)
				{
					RtlGetVersion(&lpVersionInformation);
					if (lpVersionInformation.dwBuildNumber != ApiWrapper::PEBGetNumberBuild())
					{
						bDeect = TRUE;
					}

				}
			}


			return bDeect;
		}




#ifndef _WIN64



		// thanks colby57 https://github.com/colby57
		__forceinline bool IsWow64Hooked()
		{


			/*
			hooked(ShyllaHide)

			777C7000  | EA 52189000 2300                         | jmp far 23:901852                                       | 0023:00901852:"`QPè»ÿÿÿƒø"
			777C7007  | 0000                                     | add byte ptr ds:[eax],al                                |
			777C7009  | 41                                       | inc ecx                                                 |
			777C700A  | FFA7 F8000000                            | jmp dword ptr ds:[edi+F8]                               |


			don't hooked
			777C7000  | EA 09707C77 3300                         | jmp far 33:777C7009                                     | 0033:777C7009:"Aÿ§ø"
			777C7007  | 0000                                     | add byte ptr ds:[eax],al                                |
			777C7009  | 41                                       | inc ecx                                                 |
			777C700A  | FFA7 F8000000                            | jmp dword ptr ds:[edi+F8]                               |
			*/
			auto nt_status = STATUS_UNSUCCESSFUL;
			auto bDetect = TRUE;
			BYTE buffer[10];
			NoCRT::mem::memset(buffer, 0, sizeof(buffer));
			auto wow64Address = (PBYTE)__readfsdword(0xC0); 
			auto NtReadVirtualMemory = (t_NtReadVirtualMemory)ApiWrapper::GetProcAddress(L"ntdll.dll", "NtReadVirtualMemory");
			if (NtReadVirtualMemory)
			{
				//try read memory by NtReadVirtualMemory for present PB
				 nt_status = NtReadVirtualMemory(NtCurrentProcess, wow64Address, &buffer, 6, NULL);
				 if (NT_SUCCESS(nt_status))
				 {
					 for (BYTE i = 0; i <= 6; i++)
					 {
						 if (buffer[i] == 0x33)
						 {
							 bDetect = FALSE;
						 }

					 }
				 }
			}
			else if(!NT_SUCCESS(nt_status) || !NtReadVirtualMemory) //bad status or we can get address NtApi
			{
				


				for (BYTE i = 0; i <= 6; i++)
				{
					if (*(wow64Address + i) == 0x33)
					{
						bDetect = FALSE;
					}

				}
			}
			

			return bDetect;
		}
#endif 


	}

}