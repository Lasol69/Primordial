#include <Windows.h>
#include <iostream>

namespace Hooks
{
	BOOL __stdcall hkDllMain( HMODULE hModule, DWORD ulReason, LPVOID lpReserved );
	void __cdecl hkDecryptMem( void* pFunction );
}