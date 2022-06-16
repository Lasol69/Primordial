#include "Hooks.hpp"
#include "CCheat.hpp"

#include "MinHook/minhook.hpp"

BOOL __stdcall Hooks::hkDllMain( HMODULE hModule, DWORD ulReason, LPVOID lpReserved )
{
	if ( ulReason != DLL_PROCESS_ATTACH )
		return 1;

	printf( "intercepted dllmain!\n" );

	CCheat* pCheat = new CCheat( );
	pCheat->Init( );

	( reinterpret_cast< void ( __cdecl* ) ( ) >( 0x3CB77950 ) )( );

	printf( "hooks %d\n", MH_EnableHook( MH_ALL_HOOKS ) );

	return 1;
}

void __cdecl Hooks::hkDecryptMem( void* pFunction )
{
	( ( decltype( &hkDecryptMem ) ) 0x3CCAC990 )( pFunction );

	*reinterpret_cast< uint32_t* >( 0x3CCAC366 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "GetTickCount" ) - 0x3CCAC36A;
	*reinterpret_cast< uint32_t* >( 0x3CB781D6 ) = ( uint32_t ) AddVectoredExceptionHandler - 0x3CB781DA;
	*reinterpret_cast< uint32_t* >( 0x3CC98B2B ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "_Thrd_hardware_concurrency" ) - 0x3CC98B2F;
	*reinterpret_cast< uint32_t* >( 0x3CC9D7AE ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "VirtualProtect" ) - 0x3CC9D7B2;

	*reinterpret_cast< uint32_t* >( 0x3CC5B130 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "user32.dll" ), "LoadCursorW" ) - 0x3CC5B134;
	*reinterpret_cast< uint32_t* >( 0x3CC5B157 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "user32.dll" ), "LoadCursorW" ) - 0x3CC5B15B;
	*reinterpret_cast< uint32_t* >( 0x3CC5B17E ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "user32.dll" ), "LoadCursorW" ) - 0x3CC5B182;
	*reinterpret_cast< uint32_t* >( 0x3CC5B1A5 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "user32.dll" ), "LoadCursorW" ) - 0x3CC5B1A9;
	*reinterpret_cast< uint32_t* >( 0x3CC5B1CC ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "user32.dll" ), "LoadCursorW" ) - 0x3CC5B1D0;
	*reinterpret_cast< uint32_t* >( 0x3CC5B1F3 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "user32.dll" ), "LoadCursorW" ) - 0x3CC5B1F7;
	*reinterpret_cast< uint32_t* >( 0x3CC5B21A ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "user32.dll" ), "LoadCursorW" ) - 0x3CC5B21E;

	*reinterpret_cast< uint32_t* >( 0x3CC98B57 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "ucrtbase.dll" ), "_beginthreadex" );
	*reinterpret_cast< uint32_t* >( 0x3CC70521 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "ucrtbase.dll" ), "_errno" );
	*reinterpret_cast< uint32_t* >( 0x3CBB1BF3 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "ucrtbase.dll" ), "_errno" );
	*reinterpret_cast< uint32_t* >( 0x3CB79C5B ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "ucrtbase.dll" ), "fread" );
	*reinterpret_cast< uint32_t* >( 0x3CB79C96 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "ucrtbase.dll" ), "fread" );
	*reinterpret_cast< uint32_t* >( 0x3CC98B5D ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "_Thrd_detach" );
	*reinterpret_cast< uint32_t* >( 0x3CC95F27 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "gdi32.dll" ), "AddFontMemResourceEx" );
	*reinterpret_cast< uint32_t* >( 0x3CB7D7E8 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "?id@?$codecvt@DDU_Mbstatet@@@std@@2V0locale@2@A" );
	*reinterpret_cast< uint32_t* >( 0x3CC989BC ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "_Cnd_wait" );
	*reinterpret_cast< uint32_t* >( 0x3CC98D44 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "_Cnd_wait" );
	*reinterpret_cast< uint32_t* >( 0x3CC14103 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "VirtualProtect" );
	*reinterpret_cast< uint32_t* >( 0x3CC98996 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "_Mtx_lock" );
	*reinterpret_cast< uint32_t* >( 0x3CBBA4C5 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "_Mtx_lock" );
	*reinterpret_cast< uint32_t* >( 0x3CC98A47 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "_Mtx_lock" );
	*reinterpret_cast< uint32_t* >( 0x3CBBA4DD ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "_Mtx_unlock" );
	*reinterpret_cast< uint32_t* >( 0x3CC8311F ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "?id@?$ctype@_W@std@@2V0locale@2@A" );
	*reinterpret_cast< uint32_t* >( 0x3CC81E28 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "?setprecision@std@@YA?AU?$_Smanip@_J@1@_J@Z" );
	*reinterpret_cast< uint32_t* >( 0x3CBF3FA3 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "VCRUNTIME140.dll" ), "strstr" );
	*reinterpret_cast< uint32_t* >( 0x3CBF404A ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "VCRUNTIME140.dll" ), "strstr" );
	*reinterpret_cast< uint32_t* >( 0x3CC0FA1F ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "VCRUNTIME140.dll" ), "strstr" );
	*reinterpret_cast< uint32_t* >( 0x3CC11EC0 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "msvcp140.dll" ), "_Thrd_id" );
	*reinterpret_cast< uint32_t* >( 0x3CB76E67 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "dbghelp.dll" ), "SymGetModuleBase64" );
	*reinterpret_cast< uint32_t* >( 0x3CB7713B ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "dbghelp.dll" ), "SymGetModuleBase64" );
	*reinterpret_cast< uint32_t* >( 0x3CB76E73 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "dbghelp.dll" ), "SymFunctionTableAccess64" );
	*reinterpret_cast< uint32_t* >( 0x3CB77147 ) = ( uint32_t ) GetProcAddress( GetModuleHandleA( "dbghelp.dll" ), "SymFunctionTableAccess64" );

	printf( "shit called!\n" );
}