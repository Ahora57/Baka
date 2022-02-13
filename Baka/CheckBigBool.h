#pragma once

#include "NtApi.h" 
#include "ApiWrapper.h"



namespace BlackListPool
{

	/*
	Just wallking in BigPool

	HyperHide:
	PoolTag: HyHd

	*/
	__forceinline bool IsHyperHideDebuggingProcess()
	{
		/*
		HyperHide don't clean big pool then he was unload ^_^ and under debugging NonPagedUsed = 384
		*/

		bool bDetect = FALSE;
		DWORD Lenght = NULL;
		PVOID bufferPoolInformathion = NULL;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		auto NtQuerySystemInformation = (t_NtQuerySystemInformation)ApiWrapper::GetProcAddress(L"ntdll.dll", "NtQuerySystemInformation");
		if (!NtQuerySystemInformation)
		{
			return FALSE;
		}
		status = NtQuerySystemInformation(SystemPoolTagInformation, bufferPoolInformathion, Lenght, &Lenght);

		while (status == STATUS_INFO_LENGTH_MISMATCH) {
			if (bufferPoolInformathion != NULL)
				VirtualFree(bufferPoolInformathion, 0, MEM_RELEASE);

			bufferPoolInformathion = VirtualAlloc(NULL, Lenght, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			status = NtQuerySystemInformation(SystemPoolTagInformation, bufferPoolInformathion, Lenght, &Lenght);
		}

		if (!NT_SUCCESS(status)) {
			if (bufferPoolInformathion != NULL)
				VirtualFree(bufferPoolInformathion, 0, MEM_RELEASE);
			return FALSE;
		}


		PSYSTEM_POOLTAG_INFORMATION sysPoolTagInfo = (PSYSTEM_POOLTAG_INFORMATION)bufferPoolInformathion;
		PSYSTEM_POOLTAG sysPoolTag = (PSYSTEM_POOLTAG)&sysPoolTagInfo->TagInfo->Tag;
		for (ULONG i = 0; i < sysPoolTagInfo->Count; i++)
		{


			if (NoCRT::string::stricmp((char*)sysPoolTag->Tag, "Hyhd") == 0)
			{
				if (sysPoolTag->PagedAllocs || sysPoolTag->NonPagedAllocs)
				{
					if (sysPoolTag->NonPagedUsed > 10 || sysPoolTag->PagedUsed > 10)//check for detect only for debugging 
					{

						bDetect = TRUE;
					}
				}
			}


			sysPoolTag++;
		}

		VirtualFree(bufferPoolInformathion, 0, MEM_RELEASE);



		return bDetect;
	}
}