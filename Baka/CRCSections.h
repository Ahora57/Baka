#pragma once
#include "ApiWrapper.h"
#include "NtApi.h"
#include "CRCpp.h"


namespace CRCSecthion
{

	SECTION_CRC CRCSectionsResult[10];

	__forceinline uint32_t fletcher32(PVOID  data, size_t len)
	{ 
		uint64_t data2 = (uint64_t)data;
		uint32_t sum1 = 0xffff, sum2 = 0xffff;

		while (len) {
			unsigned tlen = len > 359 ? 359 : len;

			len -= tlen;

			do {
				sum1 += *(uint64_t*)data2++;
				sum2 += sum1;
			} while (--tlen);

			sum1 = (sum1 & 0xffff) + (sum1 >> 16);
			sum2 = (sum2 & 0xffff) + (sum2 >> 16);

		}
		/* Second reduction step to reduce sums to 16 bits */
		sum1 = (sum1 & 0xffff) + (sum1 >> 16);
		sum2 = (sum2 & 0xffff) + (sum2 >> 16); 
		return sum2 << 16 | sum1;
		
	}

	

	/*
	We try safe read memory for present BP
	*/


	__forceinline    void  StealsCRCSectionsInit(PVOID base)
	{


		PVOID buffer = 0;
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
		auto* sections = IMAGE_FIRST_SECTION(headers);

		for (auto i = 0; i <= headers->FileHeader.NumberOfSections; i++)
		{
			auto* section = &sections[i];
			//Check sections rules

			if ((section->Characteristics & IMAGE_SCN_MEM_READ) && !(section->Characteristics & IMAGE_SCN_MEM_WRITE))
			{
				
				buffer = VirtualAlloc(nullptr, section->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (buffer)
				{

					auto NtReadVirtualMemory = (t_NtReadVirtualMemory)ApiWrapper::GetProcAddress(L"ntdll.dll", "NtReadVirtualMemory");
					if (NtReadVirtualMemory)
					{
						//Write memory in allocated buffer for present fast detect by BP
						nt_status = NtReadVirtualMemory(NtCurrentProcess, static_cast<char*>(base) + section->VirtualAddress, buffer, section->Misc.VirtualSize, NULL);


						if (NT_SUCCESS(nt_status))
						{

							CRCSectionsResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
							CRCSectionsResult[i].virtualSize = section->Misc.VirtualSize;
							CRCSectionsResult[i].resultCRC = CRC::Calculate(buffer, section->Misc.VirtualSize, CRC::CRC_32());
							CRCSectionsResult[i].fletcherCRC = fletcher32(buffer, section->Misc.VirtualSize);

						}
					}
					// bad status NtReadVirtualMemory or can't get address NtReadVirtualMemory
					else if(!NtReadVirtualMemory || !NT_SUCCESS(nt_status)) 
					{
						CRCSectionsResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
						CRCSectionsResult[i].virtualSize = section->Misc.VirtualSize;
						CRCSectionsResult[i].resultCRC = CRC::Calculate(CRCSectionsResult[i].virtualAddress, section->Misc.VirtualSize, CRC::CRC_32());
						CRCSectionsResult[i].fletcherCRC = fletcher32(CRCSectionsResult[i].virtualAddress, section->Misc.VirtualSize);

					}
					VirtualFree(buffer, 0, MEM_RELEASE);
				}
				//can't allocate memory
				else
				{
					CRCSectionsResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
					CRCSectionsResult[i].virtualSize = section->Misc.VirtualSize;
					CRCSectionsResult[i].resultCRC = CRC::Calculate(CRCSectionsResult[i].virtualAddress, section->Misc.VirtualSize, CRC::CRC_32());
					CRCSectionsResult[i].fletcherCRC = fletcher32(CRCSectionsResult[i].virtualAddress, section->Misc.VirtualSize);

				}

			}
		}

	}



	__forceinline    bool StealsSectionsIsCorrupt()
	{
		PVOID buffer = 0;
		bool secthionIsPatched = false;
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		SECTION_CRC newCRCResult[10];

		auto base = (PVOID)ApiWrapper::GetModuleBaseAddress(NULL);

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
					if (NtReadVirtualMemory)
					{


						//Write memory in allocated buffer for present fast detect by BP
						nt_status = NtReadVirtualMemory(NtCurrentProcess, static_cast<char*>(base) + section->VirtualAddress, buffer, section->Misc.VirtualSize, NULL);


						if (NT_SUCCESS(nt_status))
						{
							newCRCResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
							newCRCResult[i].virtualSize = section->Misc.VirtualSize;
							newCRCResult[i].resultCRC = CRC::Calculate(buffer, section->Misc.VirtualSize, CRC::CRC_32());
							newCRCResult[i].fletcherCRC = fletcher32(buffer, section->Misc.VirtualSize);

							if (
								newCRCResult[i].resultCRC != CRCSectionsResult[i].resultCRC ||
								newCRCResult[i].virtualAddress != CRCSectionsResult[i].virtualAddress ||
								newCRCResult[i].virtualSize != CRCSectionsResult[i].virtualSize || 
								newCRCResult[i].fletcherCRC != CRCSectionsResult[i].fletcherCRC
								)
							{
								secthionIsPatched = TRUE;
							}
						}
					}
					// bad status NtReadVirtualMemory or can't get address NtReadVirtualMemory
					else if(!NtReadVirtualMemory || !NT_SUCCESS(nt_status))
					{
						newCRCResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
						newCRCResult[i].virtualSize = section->Misc.VirtualSize;
						newCRCResult[i].resultCRC = CRC::Calculate(newCRCResult[i].virtualAddress, section->Misc.VirtualSize, CRC::CRC_32());
						newCRCResult[i].fletcherCRC = fletcher32(CRCSectionsResult[i].virtualAddress, section->Misc.VirtualSize);

						if (
							newCRCResult[i].resultCRC != CRCSectionsResult[i].resultCRC ||
							newCRCResult[i].virtualAddress != CRCSectionsResult[i].virtualAddress ||
							newCRCResult[i].virtualSize != CRCSectionsResult[i].virtualSize ||
							newCRCResult[i].fletcherCRC != CRCSectionsResult[i].fletcherCRC
							)
						{
							secthionIsPatched = TRUE;
						}
					}
					VirtualFree(buffer, 0, MEM_RELEASE);
				}
				//can't allocate memory
				else
				{
					newCRCResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
					newCRCResult[i].virtualSize = section->Misc.VirtualSize;
					newCRCResult[i].resultCRC = CRC::Calculate(CRCSectionsResult[i].virtualAddress, section->Misc.VirtualSize, CRC::CRC_32());
					newCRCResult[i].fletcherCRC = fletcher32(CRCSectionsResult[i].virtualAddress, section->Misc.VirtualSize);

					if (
						newCRCResult[i].resultCRC != CRCSectionsResult[i].resultCRC ||
						newCRCResult[i].virtualAddress != CRCSectionsResult[i].virtualAddress ||
						newCRCResult[i].virtualSize != CRCSectionsResult[i].virtualSize ||
						newCRCResult[i].fletcherCRC != CRCSectionsResult[i].fletcherCRC
						)
					{
						secthionIsPatched = TRUE;
					}
				}
			}
			
		
		}

		return secthionIsPatched;
	}

	__forceinline    bool SectionsIsCorrupt()
	{
		auto base = (PVOID)ApiWrapper::GetModuleBaseAddress(NULL);
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		SECTION_CRC newCRCResult[10];
		auto secthionCheckResult = NULL;
		auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
		auto* sections = IMAGE_FIRST_SECTION(headers);

		for (auto i = 0; i <= headers->FileHeader.NumberOfSections; i++)
		{

			auto* section = &sections[i];
			//Check section rules
			if ((section->Characteristics & IMAGE_SCN_MEM_READ) && !(section->Characteristics & IMAGE_SCN_MEM_WRITE))
			{

				secthionCheckResult++;

				newCRCResult[i].virtualAddress = static_cast<char*>(base) + section->VirtualAddress;
				newCRCResult[i].virtualSize = section->Misc.VirtualSize;
				newCRCResult[i].resultCRC = CRC::Calculate(newCRCResult[i].virtualAddress, section->Misc.VirtualSize, CRC::CRC_32());
				newCRCResult[i].fletcherCRC = fletcher32(newCRCResult[i].virtualAddress, section->Misc.VirtualSize);

				if (
					newCRCResult[i].resultCRC != CRCSectionsResult[i].resultCRC ||
					newCRCResult[i].virtualAddress != CRCSectionsResult[i].virtualAddress ||
					newCRCResult[i].virtualSize != CRCSectionsResult[i].virtualSize ||
					newCRCResult[i].fletcherCRC != CRCSectionsResult[i].fletcherCRC
					)
				{
					return TRUE;
				}

			}


		}
		if (secthionCheckResult != headers->FileHeader.NumberOfSections - 1) //we have 1 write section
		{
			return TRUE;
		}

		return FALSE;
	}
	
}
