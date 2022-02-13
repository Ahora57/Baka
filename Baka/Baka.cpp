

#include "AntiDebug.h"
#include "TestModeCheck.h"
#include "CheckBigBool.h"
#include "CRCSecthion.h"


int Entry()
{
	
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN); // for fun
	
	ApiWrapper::printf(L"execute module have bp ->\t%x\n", AntiDebug::Util::IsModuleHaveBP());

	

	
#ifndef _WIN64
		ApiWrapper::printf(L"WoW64Translate is hooded ->\t%x\n", AntiDebug::Util::IsWow64Hooked());
#endif 

	
	
	ApiWrapper::printf(L"[ShellCode] Is debug port exist ->\t%x\n", AntiDebug::ShellCode::IsDebugPort());
	ApiWrapper::printf(L"[ShellCode] Is debug flag exist ->\t%x\n",AntiDebug::ShellCode::IsDebugFlag());
	ApiWrapper::printf(L"[ShellCode] Is debug object exist ->\t%x\n", AntiDebug::ShellCode::IsDebugObjectHandle());
	ApiWrapper::printf(L"[ShellCode] Is thread don't hide? ->\t%x\n", AntiDebug::ShellCode::IsBadHideThread());
	
	ApiWrapper::printf(L"[OverWriteSyscall] Is debug port ->\t%x\n", AntiDebug::OverWriteSyscall::IsDebugPort());
	ApiWrapper::printf(L"[OverWriteSyscall] Is thread don't hide  ->\t%x\n", AntiDebug::OverWriteSyscall::IsBadHideThread());
	
	
	
	

	ApiWrapper::printf(L"Is HyperHide help debugging some process ->\t%x\n", BlackListPool::IsHyperHideDebuggingProcess());
	ApiWrapper::printf(L"Is build number hooked ->\t%x\n", AntiDebug::Util::BuildNumberIsHooked());

	ApiWrapper::printf(L"Anti test mode by NtQuerySystemInformation ->\t%x\n", CheckTestMode::CodeIntCheck());
	ApiWrapper::printf(L"Anti test mode by SystemStartOptions ->\t%x\n", CheckTestMode::Registry());
	ApiWrapper::printf(L"Anti test mode by Elements in BCD00000000 ->\t%x\n", CheckTestMode::RegistryEx());
	
	auto baseAddress = (PVOID)ApiWrapper::GetModuleBaseAddress(NULL);
	
	auto isInitCRC = CRCSecthion::StealsCRCSecthionInit(baseAddress);
	


	
	
	while (isInitCRC)
	{
		if (GetAsyncKeyState(VK_SPACE))
		{


			if (CRCSecthion::SecthionIsCorrupt(baseAddress))
			{
				ApiWrapper::printf(L"Detect change secthion!\n");
			}
			else
			{
				ApiWrapper::printf(L"No detect change secthion!\n");
			}
			Sleep(500);
		}
	}
	
	
   

	ApiWrapper::cin();

	return 0;
}
