#pragma once
#include "ApiWrapper.h"
#include "NtApi.h"
#include "CRCpp.h"

#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])

namespace CRCSecthion
{

	SECTHION_CRC CRCSecthionResult[10];


	

	/*
	We try safe read memory for present BP
	*/


	__forceinline    bool StealsCRCSecthionInit(PVOID base)
	{


		PVOID buffer = 0;
		 
		auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
		auto* sections = IMAGE_FIRST_SECTION(headers);

		for (auto i = 0; i <= headers->FileHeader.NumberOfSections; i++)
		{
			auto* section = &sections[i];
			//Check secthion rules

			if ((section->Characteristics & IMAGE_SCN_MEM_READ) && !(section->Characteristics & IMAGE_SCN_MEM_WRITE))
			{
				
				buffer = VirtualAlloc(nullptr, section->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (buffer)
				{

					auto NtReadVirtualMemory = (t_NtReadVirtualMemory)ApiWrapper::GetProcAddress(L"ntdll.dll", "NtReadVirtualMemory");
					if (!NtReadVirtualMemory)
					{
						return FALSE;
					}

					//Write memory in allocated buffer for present fast detect by BP
					NTSTATUS nt_status = NtReadVirtualMemory(NtCurrentProcess, static_cast<char*>(base) + section->VirtualAddress, buffer, section->Misc.VirtualSize, NULL);


					if (NT_SUCCESS(nt_status))
					{
						
						CRCSecthionResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
						CRCSecthionResult[i].virtualSize = section->Misc.VirtualSize;
						CRCSecthionResult[i].resultCRC = CRC::Calculate(buffer, section->Misc.VirtualSize,CRC::CRC_32());

					}
					else // bad status NtReadVirtualMemory 
					{
						CRCSecthionResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
						CRCSecthionResult[i].virtualSize = section->Misc.VirtualSize;
						CRCSecthionResult[i].resultCRC = CRC::Calculate(static_cast<char*>(base) + section->VirtualAddress, section->Misc.VirtualSize, CRC::CRC_32());

					}
					VirtualFree(buffer, 0, MEM_RELEASE);
				}

			}
		}

		return TRUE;
	}



	__forceinline    bool SecthionIsCorrupt(PVOID base)
	{
		PVOID buffer = 0;
		bool secthionIsPatched = false;
		SECTHION_CRC newCRCResult[10];

		auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
		auto* sections = IMAGE_FIRST_SECTION(headers);

		for (auto i = 0; i <= headers->FileHeader.NumberOfSections; i++)
		{
			auto* section = &sections[i];
			//Check secthion rules
			if ((section->Characteristics & IMAGE_SCN_MEM_READ) && !(section->Characteristics & IMAGE_SCN_MEM_WRITE))
			{

				
				 buffer = VirtualAlloc(nullptr, section->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (buffer)
				{

					auto NtReadVirtualMemory = (t_NtReadVirtualMemory)ApiWrapper::GetProcAddress(L"ntdll.dll", "NtReadVirtualMemory");
					if (!NtReadVirtualMemory)
					{
						return 0;
					}
					//Write memory in allocated buffer for present fast detect by BP
					NTSTATUS nt_status = NtReadVirtualMemory(NtCurrentProcess, static_cast<char*>(base) + section->VirtualAddress, buffer, section->Misc.VirtualSize, NULL);


					if (NT_SUCCESS(nt_status))
					{
						newCRCResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
						newCRCResult[i].virtualSize = section->Misc.VirtualSize;
						newCRCResult[i].resultCRC = CRC::Calculate(buffer, section->Misc.VirtualSize,CRC::CRC_32());

						if (
							newCRCResult[i].resultCRC != CRCSecthionResult[i].resultCRC ||
							newCRCResult[i].virtualAddress != CRCSecthionResult[i].virtualAddress ||
							newCRCResult[i].virtualSize != CRCSecthionResult[i].virtualSize
							)
						{  
							secthionIsPatched = true;
						}
					}
					else // bad status NtReadVirtualMemory 
					{
						newCRCResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
						newCRCResult[i].virtualSize = section->Misc.VirtualSize;
						newCRCResult[i].resultCRC = CRC::Calculate(static_cast<char*>(base) + section->VirtualAddress, section->Misc.VirtualSize, CRC::CRC_32());
						if (
							newCRCResult[i].resultCRC != CRCSecthionResult[i].resultCRC ||
							newCRCResult[i].virtualAddress != CRCSecthionResult[i].virtualAddress ||
							newCRCResult[i].virtualSize != CRCSecthionResult[i].virtualSize
							)
						{
							secthionIsPatched = true;
						}
					}
					VirtualFree(buffer, 0, MEM_RELEASE);
				}

			}
		}

		return secthionIsPatched;
	}

	
}