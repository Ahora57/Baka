#pragma once
#include "NtApi.h"

#define CODEINTEGRITY_OPTION_TESTSIGN 0x00000002


namespace CheckTestMode
{

	__forceinline bool CodeIntCheck() {


		SYSTEM_CODEINTEGRITY_INFORMATION cInfo{};
		cInfo.Length = sizeof(cInfo);// set length and don't work without this

			auto NtQuerySystemInformation = (t_NtQuerySystemInformation)ApiWrapper::GetProcAddress(L"ntdll.dll", "NtQuerySystemInformation");
			if (!NtQuerySystemInformation)
			{
				return FALSE;
			}
		NtQuerySystemInformation(
			SystemCodeIntegrityInformation,
			&cInfo,
			sizeof(cInfo),
			NULL
		);



		return (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN); 
	}



	 bool Registry()
	{

		/*
		You can also detect kernel debugger (read -> https://shhoya.github.io/antikernel_kerneldebugging.html	)

		*/

		bool bRet = false;
		char RegKey[_MAX_PATH];
		DWORD BufSize = _MAX_PATH;
		DWORD dataType = REG_SZ;

		HKEY hKey;


		auto openResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control", NULL, KEY_QUERY_VALUE, &hKey);
		if (openResult == ERROR_SUCCESS)
		{
			auto valSystemOpthion = RegQueryValueExA(hKey, "SystemStartOptions", NULL, &dataType, (LPBYTE)&RegKey, &BufSize);
			if (valSystemOpthion == ERROR_SUCCESS)
			{
				if (NoCRT::string::strstr(RegKey, "TESTSIGNING"))
					bRet = true;
			}
			RegCloseKey(hKey);
		}


		return bRet;
	}


	/*
	 originale idea  https://github.com/mq1n/NoMercy/blob/3a375e27f56fe9eec9c553c641ce0abde2c6b22b/Source/Client/NM_Engine/ITestSignatureScanner.cpp#L106
	*/
	__forceinline bool RegistryEx()
	{
		HKEY hTestKey;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "BCD00000000\\Objects", 0, KEY_READ, &hTestKey) != ERROR_SUCCESS)
			return false;

		char    achKey[255];
		DWORD    cbName;
		char    achClass[MAX_PATH];
		DWORD    cchClassName = MAX_PATH;
		DWORD    cSubKeys = 0;
		DWORD    cbMaxSubKey;
		DWORD    cchMaxClass;
		DWORD    cValues;
		DWORD    cchMaxValue;
		DWORD    cbMaxValueData;
		DWORD    cbSecurityDescriptor;
		FILETIME ftLastWriteTime;

		bool bDetect = false;

		auto dwReturn = (PDWORD)VirtualAlloc(0, 0x4096, MEM_COMMIT, PAGE_READWRITE);
		DWORD dwBufSize = 0x4096;

		auto dwApiRetCode = RegQueryInfoKeyA(hTestKey, achClass, &cchClassName, NULL, &cSubKeys, &cbMaxSubKey, &cchMaxClass, &cValues, &cchMaxValue, &cbMaxValueData,
			&cbSecurityDescriptor, &ftLastWriteTime);

		
		if (cSubKeys)
		{
			for (DWORD i = 0; i < cSubKeys; i++)
			{
				cbName = 255;
				dwApiRetCode = RegEnumKeyExA(hTestKey, i, achKey, &cbName, NULL, NULL, NULL, &ftLastWriteTime);
				if (dwApiRetCode == ERROR_SUCCESS)
				{
					char* szNewWay = (char*)VirtualAlloc(0, 0x4096, MEM_COMMIT, PAGE_READWRITE);

					NoCRT::mem::memset(szNewWay, 0, 0x4096);

					NoCRT::string::strcatA(szNewWay, "BCD00000000\\Objects\\");
					NoCRT::string::strcatA(szNewWay, achKey);
					NoCRT::string::strcatA(szNewWay, "\\Elements\\16000049"); ;


					HKEY hnewKey;
					long lError = RegOpenKeyExA(HKEY_LOCAL_MACHINE, szNewWay, NULL, KEY_QUERY_VALUE, &hnewKey);
					if (lError == ERROR_SUCCESS)
					{

						long lVal = RegQueryValueExA(hnewKey, "Element", NULL, 0, (LPBYTE)dwReturn, &dwBufSize);
						if (lVal == ERROR_SUCCESS)
						{
							if (dwReturn[0] == 1UL)
								bDetect = true;
						}
						RegCloseKey(hnewKey);
					}
					VirtualFree((PVOID)szNewWay, 0, MEM_RELEASE);

				}
			}
		}
		

		VirtualFree(dwReturn, 0, MEM_RELEASE);
		RegCloseKey(hTestKey);
		return bDetect;
	}

}