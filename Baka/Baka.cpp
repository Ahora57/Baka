

#include "AntiDebug.h"
#include "TestModeCheck.h"
#include "CheckBigBool.h"
#include "CRCSections.h"


int Entry()
{

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN); // for fun

	auto baseAddress = (PVOID)ApiWrapper::GetModuleBaseAddress(NULL);
	 CRCSecthion::StealsCRCSectionsInit(baseAddress);


	ApiWrapper::printf(L"Some ntapi hooked ->\t%x\n", AntiDebug::Util::IsNtApiCorrupted());

	ApiWrapper::printf(L"execute module have bp ->\t%x\n", AntiDebug::Util::IsModuleHaveBP());




#ifndef _WIN64
		ApiWrapper::printf(L"WoW64Translate is hooded ->\t%x\n", AntiDebug::Util::IsWow64Hooked());
#endif

		

	ApiWrapper::printf(L"[ShellCode] Is debug port exist ->\t%x\n", AntiDebug::ShellCode::IsDebugPort());
	ApiWrapper::printf(L"[ShellCode] Is debug flag exist ->\t%x\n",AntiDebug::ShellCode::IsDebugFlag());
	ApiWrapper::printf(L"[ShellCode] Is debug object exist ->\t%x\n", AntiDebug::ShellCode::IsDebugObjectHandle());

	ApiWrapper::printf(L"[OverWriteSyscall] Is debug flag hooked ->\t%x\n", AntiDebug::OverWriteSyscall::IsDebugFlagHooked());
	ApiWrapper::printf(L"[OverWriteSyscall] Is thread don't hide  ->\t%x\n", AntiDebug::OverWriteSyscall::IsBadHideThread());

	
	


	ApiWrapper::printf(L"Is HyperHide help debugging some process ->\t%x\n", BlackListPool::IsHyperHideDebuggingProcess());
	ApiWrapper::printf(L"Is build number hooked ->\t%x\n", AntiDebug::Util::BuildNumberIsHooked());

	ApiWrapper::printf(L"Anti test mode by NtQuerySystemInformation ->\t%x\n", CheckTestMode::CodeIntCheck());
	ApiWrapper::printf(L"Anti test mode by SystemStartOptions ->\t%x\n", CheckTestMode::IsStartedWithDisableDSE());
	ApiWrapper::printf(L"Anti test mode by Elements in BCD00000000 ->\t%x\n", CheckTestMode::IsBcdLibraryBooleanAllowPrereleaseSignatures());

 





	
	if (GetAsyncKeyState(VK_SPACE))
	{


		if (CRCSecthion::SectionsIsCorrupt() || CRCSecthion::StealsSectionsIsCorrupt())
		{
			ApiWrapper::printf(L"Detect change section!\n");
		}
		else
		{
			ApiWrapper::printf(L"No detect change section!\n");
		}
		Sleep(500);
	}
	
	
   
	ApiWrapper::cin();

	return 0;
}
