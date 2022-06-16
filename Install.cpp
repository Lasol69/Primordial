#include "Install.hpp"
#include "Hooks.hpp"

#include "MinHook/minhook.hpp"

#include "Bin/Imports.hpp"
#include "Bin/GuiStub.hpp"

#include <Windows.h>

void CInstall::Init( )
{
	printf( "loading...\n" );

	for ( const auto& Import : g_aImports )
	{
		HMODULE hModule = LoadLibraryA( Import.m_sModule.c_str( ) );
		if ( !hModule )
		{
			printf( "failed to load %s\n", Import.m_sModule.c_str( ) );
			continue;
		}

		uint32_t pFunction = ( uint32_t ) GetProcAddress( hModule, Import.m_sFunction.c_str( ) );
		if ( !pFunction )
		{
			printf( "failed to find function %s %s\n", Import.m_sModule.c_str( ), Import.m_sFunction.c_str( ) );
			continue;
		}

		for ( const uint32_t& Address : Import.m_aAddresses )
			*reinterpret_cast< uint32_t* >( Address + 0x1 ) = pFunction - ( Address + 0x5 );
	}

	printf( "imports solved\n" );

	memcpy( reinterpret_cast< void* >( 0x3D190000 ), g_aGuiStub.data( ), g_aGuiStub.size( ) );
	memcpy( reinterpret_cast< void* >( 0x3D1A0000 ), g_aGuiStub2.data( ), g_aGuiStub2.size( ) );

	printf( "copied stubs\n" );

	*reinterpret_cast< uint32_t* >( 0x3CCACC31 ) = ( uint32_t ) Hooks::hkDecryptMem - 0x3CCACC35;
	*reinterpret_cast< uint32_t* >( 0x3CC0D351 ) = ( uint32_t ) Hooks::hkDllMain - 0x3CC0D355;
	*reinterpret_cast< uint8_t* >( 0x3CC0D350 ) = 0xE9;

	printf( "hooks have been set up\n" );

	( reinterpret_cast< BOOL ( __stdcall* ) ( uint32_t, DWORD, void* ) >( 0x3CCAFA70 ) )( 0x3CB10000, DLL_PROCESS_ATTACH, 0 );
}