#include "CCheat.hpp"

#include "Bin/NetVars.hpp"

#include "Helpers/Exports.hpp"
#include "Helpers/NetManager.hpp"
#include "Helpers/Utils.hpp"

#include "MinHook/minhook.hpp"

#include <Windows.h>

typedef void* ( *CreateInterfaceFn ) ( const char* pName, int* pReturnCode );

class InterfaceReg
{
private:
	using InstantiateInterfaceFn = void* (*)();
public:
	InstantiateInterfaceFn m_CreateFn;
	const char* m_pName;
	InterfaceReg* m_pNext;
};

template< typename T >
T* GetInterface( HMODULE hModule, const char* szInterfaceVersion, bool bExact = true )
{
	T* iface = nullptr;
	InterfaceReg* register_list;
	int part_match_len = strlen(szInterfaceVersion);

	DWORD interface_fn = reinterpret_cast< DWORD >( GetProcAddress( hModule, ( "CreateInterface" ) ) );

	if (!interface_fn) {
		return nullptr;
	}

	unsigned int jump_start = (unsigned int)(interface_fn)+4;
	unsigned int jump_target = jump_start + *(unsigned int*)(jump_start + 1) + 5;

	register_list = **reinterpret_cast<InterfaceReg***>(jump_target + 6);

	for (InterfaceReg* cur = register_list; cur; cur = cur->m_pNext) {
		if (bExact == true) {
			if (strcmp(cur->m_pName, szInterfaceVersion) == 0)
				iface = reinterpret_cast<T*>(cur->m_CreateFn());
		}
		else {
			if (!strncmp(cur->m_pName, szInterfaceVersion, part_match_len) && std::atoi(cur->m_pName + part_match_len) > 0)
				iface = reinterpret_cast<T*>(cur->m_CreateFn());
		}
	}
	return iface;
}

void CCheat::Init( )
{
	printf( "initing...\n" );

	InitAddresses( );

	SetupUserData( );
	SetupNetvars( );
	SetupOffsets( );

	SetupGameUpdates( );

	uint8_t* pSendMove = g_Utils.FindPattern( "engine.dll", "55 8B EC 8B 4D 04 81 EC FC 0F 00 00 53 56 57 8B" );

	DWORD ulOldProtect, ulNewProtect;
	VirtualProtect( pSendMove, 0x2000, PAGE_EXECUTE_READWRITE, &ulOldProtect );

	*reinterpret_cast< uint8_t* >( ( uint32_t ) pSendMove + 0xC5 ) = 0xFF; // TODO: fix this shit from loader
	*reinterpret_cast< uint8_t* >( ( uint32_t ) pSendMove + 0xE5 ) = 0x46;
	*reinterpret_cast< uint8_t* >( ( uint32_t ) pSendMove + 0xE9 ) = 0x0;
	*reinterpret_cast< uint8_t* >( ( uint32_t ) pSendMove + 0x293 ) = 0x0;

	VirtualProtect( pSendMove, 0x2000, ulOldProtect, &ulNewProtect );

	SetupHooks( );

	printf( "client 0x%p\n", GetModuleHandleA( "client.dll" ) );
}

__forceinline void CCheat::SetupUserData( )
{
	HMODULE hKernel = GetModuleHandleA( ( "kernel32.dll" ) );
	if ( !hKernel )
		return;
		
	using GetPrivateProfileStringA_t = DWORD ( __stdcall* ) ( LPCSTR, LPCSTR, LPCSTR, LPSTR, DWORD, LPCSTR );
		
	GetPrivateProfileStringA_t fnGetPrivateProfileStringA = reinterpret_cast< GetPrivateProfileStringA_t >
		( GetProcAddress( hKernel, ( "GetPrivateProfileStringA" ) ) );	
	if ( !fnGetPrivateProfileStringA )
		return;

	char szUsername[ 64 ];
		
	memset( szUsername, '\0', sizeof( szUsername ) );
	fnGetPrivateProfileStringA( ( "mono" ), ( "user" ), "", szUsername, 64, ( "C:\\Windows\\System32\\lic.ini" ) );

	std::string username = std::string( szUsername );
	memset( reinterpret_cast< void* >( 0x3CD38080 ), 0x0, 32 );
	memcpy( reinterpret_cast< void* >( 0x3CD38080 ), username.c_str( ), username.length( ) );
}

__forceinline void CCheat::SetupNetvars( )
{
	CNetManager::Get( ).m_aTables.clear( );

	IBaseClientDLL* pClient = GetInterface< IBaseClientDLL >( GetModuleHandleA( "client.dll" ), "VClient018" );
	ClientClass* pClientClass = pClient->GetAllClasses( );
	if ( !pClientClass )
		return;

	while ( pClientClass )
	{
		RecvTable* pTable = pClientClass->m_pRecvTable;
		if ( pTable )
			CNetManager::Get( ).m_aTables.emplace( std::string( pClientClass->m_pNetworkName ), pTable );

		pClientClass = pClientClass->m_pNext;
	}

	for ( auto CurrentTable : CNetManager::Get( ).m_aTables )
	{
		RecvTable* pCurrentTable = CurrentTable.second;
		if ( !pCurrentTable )
			continue;

		std::string sTableName = CurrentTable.first;
		CNetManager::Get( ).GetProperties( pCurrentTable, sTableName );
	}

	void* pNetvars = malloc( 0x5000 );
	size_t i = 0;

	for ( const auto& NetVar : g_aNetVars )
	{
		*reinterpret_cast< uint32_t* >( ( uint32_t ) pNetvars + i ) = CNetManager::Get( ).GetOffset(
			std::get< 0 >( NetVar ).c_str( ), std::get< 1 >( NetVar ).c_str( ) );

		for ( const auto& CurrentAddress : std::get< 2 >( NetVar ) )
			*reinterpret_cast< uint32_t* >( CurrentAddress ) = ( ( uint32_t ) pNetvars + i );

		i += 0x4;
	}

	*reinterpret_cast< uint32_t* >( ( uint32_t ) pNetvars + i ) = 0x23;
	*reinterpret_cast< uint8_t** >( 0x3CB97EE2 ) = ( uint8_t* )( ( uint32_t ) pNetvars + i );

	*reinterpret_cast< uint8_t** >( 0x3CC09E97 ) = g_aInlinedOffsets[ 0 ];

	std::vector< uint32_t > aAddresses =
	{
		0x3CBA1E89, 0x3CBA25DC, 0x3CBBE9F6, 0x3CBBF6F6,
		0x3CC01877, 0x3CC9DDB0, 0x3CC9DF3C, 0x3CCA9049
	};

	for ( const auto& Address : aAddresses )
		*reinterpret_cast< uint8_t** >( Address ) = g_aInlinedOffsets[ 5 ];

	*reinterpret_cast< uint8_t** >( 0x3CBA2266 ) = g_aInlinedOffsets[ 1 ];
	*reinterpret_cast< uint8_t** >( 0x3CBA2290 ) = g_aInlinedOffsets[ 2 ];
	*reinterpret_cast< uint8_t** >( 0x3CCA4100 ) = g_aInlinedOffsets[ 3 ];
	*reinterpret_cast< uint8_t** >( 0x3CCA4113 ) = g_aInlinedOffsets[ 4 ];

	aAddresses =
	{
		0x3CBC405E, 0x3CBCCF91, 0x3CBFA151, 0x3CBFB201,
		0x3CC99A71, 0x3CCA99E6
	};

	for ( const auto& Address : aAddresses )
		*reinterpret_cast< uint8_t** >( Address ) = g_aInlinedOffsets[ 6 ];

	aAddresses =
	{
		0x3CBAC06C, 0x3CBC4878, 0x3CBC49BA, 0x3CBC58BD,
		0x3CCA7B86, 0x3CCA8064
	};

	for ( const auto& Address : aAddresses )
		*reinterpret_cast< uint8_t** >( Address ) = g_aInlinedOffsets[ 7 ];

	aAddresses =
	{
		0x3CBF0B56, 0x3CBF0D01, 0x3CC03CC7, 0x3CC03FD4,
		0x3CC0408E
	};

	for ( const auto& Address : aAddresses )
		*reinterpret_cast< uint8_t** >( Address ) = g_aInlinedOffsets[ 8 ];

	*reinterpret_cast< uint8_t** >( 0x3CCA4705 ) = g_aInlinedOffsets[ 9 ];
	*reinterpret_cast< uint8_t** >( 0x3CBE6177 ) = g_aInlinedOffsets[ 10 ];
	*reinterpret_cast< uint8_t** >( 0x3CBCD1DC ) = g_aInlinedOffsets[ 11 ];
	*reinterpret_cast< uint8_t** >( 0x3CBCD1F2 ) = g_aInlinedOffsets[ 11 ];
	*reinterpret_cast< uint8_t** >( 0x3CBCD32C ) = g_aInlinedOffsets[ 12 ];
	*reinterpret_cast< uint8_t** >( 0x3CBCD5B4 ) = g_aInlinedOffsets[ 14 ];
	*reinterpret_cast< uint8_t** >( 0x3CBBA8B8 ) = g_aInlinedOffsets[ 15 ];
	*reinterpret_cast< uint8_t** >( 0x3CBEF4BB ) = g_aInlinedOffsets[ 16 ];
	*reinterpret_cast< uint8_t** >( 0x3CBEF5C7 ) = g_aInlinedOffsets[ 16 ];
	*reinterpret_cast< uint8_t** >( 0x3CB785AD ) = g_aInlinedOffsets[ 17 ];
	*reinterpret_cast< uint8_t** >( 0x3CC0F515 ) = g_aInlinedOffsets[ 18 ];
	*reinterpret_cast< uint8_t** >( 0x3CBC1D38 ) = g_aInlinedOffsets[ 19 ];
	*reinterpret_cast< uint8_t** >( 0x3CBDB0B9 ) = g_aInlinedOffsets[ 19 ];
	*reinterpret_cast< uint8_t** >( 0x3CC9F52C ) = g_aInlinedOffsets[ 19 ];
	*reinterpret_cast< uint8_t** >( 0x3CBC1917 ) = g_aInlinedOffsets[ 20 ];
	*reinterpret_cast< uint8_t** >( 0x3CBC0F43 ) = g_aInlinedOffsets[ 21 ];
	*reinterpret_cast< uint8_t** >( 0x3CC11B14 ) = g_aInlinedOffsets[ 22 ];
	*reinterpret_cast< uint8_t** >( 0x3CC0EBEE ) = g_aInlinedOffsets[ 23 ];
	*reinterpret_cast< uint8_t** >( 0x3CC0EB7C ) = g_aInlinedOffsets[ 24 ];
	*reinterpret_cast< uint8_t** >( 0x3CBF63BF ) = g_aInlinedOffsets[ 25 ];
	*reinterpret_cast< uint8_t** >( 0x3CBF0F9E ) = g_aInlinedOffsets[ 26 ];
	*reinterpret_cast< uint8_t** >( 0x3CC0E5E7 ) = g_aInlinedOffsets[ 27 ];
	*reinterpret_cast< uint8_t** >( 0x3CBF1985 ) = g_aInlinedOffsets[ 28 ];
	*reinterpret_cast< uint8_t** >( 0x3CBFAB00 ) = g_aInlinedOffsets[ 29 ];
	*reinterpret_cast< uint8_t** >( 0x3CBC179E ) = g_aInlinedOffsets[ 30 ];
	*reinterpret_cast< uint8_t** >( 0x3CBC17A9 ) = g_aInlinedOffsets[ 31 ];
	*reinterpret_cast< uint8_t** >( 0x3CBEF9CE ) = g_aInlinedOffsets[ 32 ];
	*reinterpret_cast< uint8_t** >( 0x3CBEFC74 ) = g_aInlinedOffsets[ 33 ];
	*reinterpret_cast< uint8_t** >( 0x3CC127C4 ) = g_aInlinedOffsets[ 34 ];
	*reinterpret_cast< uint8_t** >( 0x3CBD8589 ) = g_aInlinedOffsets[ 35 ];
	*reinterpret_cast< uint8_t** >( 0x3CC0F58E ) = g_aInlinedOffsets[ 36 ];
	*reinterpret_cast< uint8_t** >( 0x3CC0F5FB ) = g_aInlinedOffsets[ 36 ];
	*reinterpret_cast< uint8_t** >( 0x3CC0F651 ) = g_aInlinedOffsets[ 36 ];
	*reinterpret_cast< uint8_t** >( 0x3CBDB44F ) = g_aInlinedOffsets[ 37 ];
	*reinterpret_cast< uint8_t** >( 0x3CBD8A63 ) = g_aInlinedOffsets[ 38 ];
	*reinterpret_cast< uint8_t** >( 0x3CC01633 ) = g_aInlinedOffsets[ 39 ];
}

__forceinline void CCheat::SetupOffsets( )
{
	*reinterpret_cast< uint32_t* >( 0x3CD3BBA8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBAC ) = ( uint32_t ) g_aOffsets[ 0 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BBA8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBB0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBB4 ) = ( uint32_t ) g_aOffsets[ 1 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BBB0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBC0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBC4 ) = ( uint32_t ) g_aOffsets[ 2 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BBC0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBC8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBCC ) = ( uint32_t ) g_aOffsets[ 3 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BBC8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBD0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBD4 ) = ( uint32_t ) g_aOffsets[ 4 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BBD0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBD8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBDC ) = ( uint32_t ) g_aOffsets[ 5 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BBD8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBE0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBE4 ) = ( uint32_t ) g_aOffsets[ 6 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BBE0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBE8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBEC ) = ( uint32_t ) g_aOffsets[ 7 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BBE8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBF0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBF4 ) = ( uint32_t ) g_aOffsets[ 8 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BBF0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBF8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BBFC ) = ( uint32_t ) g_aOffsets[ 9 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BBF8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC00 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC04 ) = ( uint32_t ) g_aOffsets[ 10 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC00 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC08 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC0C ) = ( uint32_t ) g_aOffsets[ 11 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC08 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC10 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC14 ) = ( uint32_t ) g_aOffsets[ 12 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC10 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC18 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC1C ) = ( uint32_t ) g_aOffsets[ 13 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC18 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC28 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC2C ) = ( uint32_t ) g_aOffsets[ 14 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC28 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC38 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC3C ) = ( uint32_t ) g_aOffsets[ 15 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC38 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC40 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC44 ) = ( uint32_t ) g_aOffsets[ 16 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC40 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC48 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC4C ) = ( uint32_t ) g_aOffsets[ 17 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC48 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC50 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC54 ) = ( uint32_t ) g_aOffsets[ 18 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC50 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC58 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC5C ) = ( uint32_t ) g_aOffsets[ 19 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC58 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC60 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC64 ) = ( uint32_t ) g_aOffsets[ 20 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC60 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC68 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC6C ) = ( uint32_t ) g_aOffsets[ 21 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC68 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC88 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC8C ) = ( uint32_t ) g_aOffsets[ 22 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC88 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC90 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC94 ) = ( uint32_t ) g_aOffsets[ 23 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC90 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC98 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BC9C ) = ( uint32_t ) g_aOffsets[ 24 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BC98 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCA0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCA4 ) = ( uint32_t ) g_aOffsets[ 25 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BCA0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCA8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCAC ) = ( uint32_t ) g_aOffsets[ 26 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BCA8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCB0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCB4 ) = ( uint32_t ) g_aOffsets[ 27 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BCB0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCB8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCBC ) = ( uint32_t ) g_aOffsets[ 28 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BCB8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCC0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCC4 ) = ( uint32_t ) g_aOffsets[ 29 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BCC0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCC8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCCC ) = ( uint32_t ) g_aOffsets[ 30 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BCC8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCD8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCDC ) = ( uint32_t ) g_aOffsets[ 31 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BCD8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCE0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCE4 ) = ( uint32_t ) g_aOffsets[ 32 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BCE0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCF0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCF4 ) = ( uint32_t ) g_aOffsets[ 33 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BCF0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCF8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BCFC ) = ( uint32_t ) g_aOffsets[ 34 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BCF8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD08 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD0C ) = ( uint32_t ) g_aOffsets[ 35 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD08 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD10 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD14 ) = ( uint32_t ) g_aOffsets[ 36 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD10 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD18 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD1C ) = ( uint32_t ) g_aOffsets[ 37 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD18 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD20 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD24 ) = ( uint32_t ) g_aOffsets[ 38 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD20 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD28 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD2C ) = ( uint32_t ) g_aOffsets[ 39 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD28 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD40 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD44 ) = ( uint32_t ) g_aOffsets[ 40 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD40 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD48 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD4C ) = ( uint32_t ) g_aOffsets[ 41 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD48 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD50 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD54 ) = ( uint32_t ) g_aOffsets[ 42 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD50 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD58 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD5C ) = ( uint32_t ) g_aOffsets[ 43 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD58 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD60 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD64 ) = ( uint32_t ) g_aOffsets[ 44 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD60 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD68 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD6C ) = ( uint32_t ) g_aOffsets[ 45 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD68 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD70 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD74 ) = ( uint32_t ) g_aOffsets[ 46 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD70 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD78 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD7C ) = ( uint32_t ) g_aOffsets[ 47 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD78 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD80 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD84 ) = ( uint32_t ) g_aOffsets[ 48 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD80 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD88 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD8C ) = ( uint32_t ) g_aOffsets[ 49 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD88 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD90 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD94 ) = ( uint32_t ) g_aOffsets[ 50 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD90 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD98 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BD9C ) = ( uint32_t ) g_aOffsets[ 51 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BD98 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDA0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDA4 ) = ( uint32_t ) g_aOffsets[ 52 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDA0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDA8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDAC ) = ( uint32_t ) g_aOffsets[ 53 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDA8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDB0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDB4 ) = ( uint32_t ) g_aOffsets[ 54 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDB0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDB8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDBC ) = ( uint32_t ) g_aOffsets[ 55 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDB8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDC0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDC4 ) = ( uint32_t ) g_aOffsets[ 56 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDC0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDC8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDCC ) = ( uint32_t ) g_aOffsets[ 57 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDC8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDD0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDD4 ) = ( uint32_t ) g_aOffsets[ 58 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDD0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDD8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDDC ) = ( uint32_t ) g_aOffsets[ 59 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDD8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDE0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDE4 ) = ( uint32_t ) g_aOffsets[ 60 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDE0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDE8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDEC ) = ( uint32_t ) g_aOffsets[ 61 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDE8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDF0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDF4 ) = ( uint32_t ) g_aOffsets[ 62 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDF0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDF8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BDFC ) = ( uint32_t ) g_aOffsets[ 63 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BDF8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE00 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE04 ) = ( uint32_t ) g_aOffsets[ 64 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE00 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE10 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE14 ) = ( uint32_t ) g_aOffsets[ 65 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE10 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE18 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE1C ) = ( uint32_t ) g_aOffsets[ 66 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE18 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE20 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE24 ) = ( uint32_t ) g_aOffsets[ 67 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE20 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE28 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE2C ) = ( uint32_t ) g_aOffsets[ 68 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE28 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE38 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE3C ) = ( uint32_t ) g_aOffsets[ 69 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE38 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE40 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE44 ) = ( uint32_t ) g_aOffsets[ 70 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE40 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE48 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE4C ) = ( uint32_t ) g_aOffsets[ 71 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE48 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE58 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE5C ) = ( uint32_t ) g_aOffsets[ 72 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE58 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE60 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE64 ) = ( uint32_t ) g_aOffsets[ 73 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE60 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE68 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE6C ) = ( uint32_t ) g_aOffsets[ 74 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE68 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE70 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE74 ) = ( uint32_t ) g_aOffsets[ 75 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE70 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE78 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE7C ) = ( uint32_t ) g_aOffsets[ 76 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE78 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE80 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE84 ) = ( uint32_t ) g_aOffsets[ 77 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE80 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE88 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE8C ) = ( uint32_t ) g_aOffsets[ 78 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE88 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE90 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE94 ) = ( uint32_t ) g_aOffsets[ 79 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE90 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE98 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BE9C ) = ( uint32_t ) g_aOffsets[ 80 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BE98 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEA0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEA4 ) = ( uint32_t ) g_aOffsets[ 81 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BEA0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEA8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEAC ) = ( uint32_t ) g_aOffsets[ 82 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BEA8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEB0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEB4 ) = ( uint32_t ) g_aOffsets[ 83 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BEB0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEB8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEBC ) = ( uint32_t ) g_aOffsets[ 84 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BEB8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEC0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEC4 ) = ( uint32_t ) g_aOffsets[ 85 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BEC0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BED0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BED4 ) = ( uint32_t ) g_aOffsets[ 86 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BED0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BED8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEDC ) = ( uint32_t ) g_aOffsets[ 87 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BED8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEE0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEE4 ) = ( uint32_t ) g_aOffsets[ 88 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BEE0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEE8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEEC ) = ( uint32_t ) g_aOffsets[ 89 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BEE8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEF0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEF4 ) = ( uint32_t ) g_aOffsets[ 90 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BEF0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEF8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BEFC ) = ( uint32_t ) g_aOffsets[ 91 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BEF8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF00 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF04 ) = ( uint32_t ) g_aOffsets[ 92 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF00 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF08 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF0C ) = ( uint32_t ) g_aOffsets[ 93 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF08 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF18 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF1C ) = ( uint32_t ) g_aOffsets[ 94 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF18 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF20 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF24 ) = ( uint32_t ) g_aOffsets[ 95 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF20 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF28 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF2C ) = ( uint32_t ) g_aOffsets[ 96 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF28 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF30 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF34 ) = ( uint32_t ) g_aOffsets[ 97 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF30 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF38 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF3C ) = ( uint32_t ) g_aOffsets[ 98 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF38 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF48 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF4C ) = ( uint32_t ) g_aOffsets[ 99 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF48 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF50 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF54 ) = ( uint32_t ) g_aOffsets[ 100 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF50 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF58 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF5C ) = ( uint32_t ) g_aOffsets[ 101 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF58 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF60 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF64 ) = ( uint32_t ) g_aOffsets[ 102 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF60 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF68 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF6C ) = ( uint32_t ) g_aOffsets[ 103 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF68 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF78 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF7C ) = ( uint32_t ) g_aOffsets[ 104 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF78 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF88 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BF8C ) = ( uint32_t ) g_aOffsets[ 105 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BF88 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFA0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFA4 ) = ( uint32_t ) g_aOffsets[ 106 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BFA0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFA8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFAC ) = ( uint32_t ) g_aOffsets[ 107 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BFA8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFB0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFB4 ) = ( uint32_t ) g_aOffsets[ 108 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BFB0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFB8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFBC ) = ( uint32_t ) g_aOffsets[ 109 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BFB8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFC0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFC4 ) = ( uint32_t ) g_aOffsets[ 110 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BFC0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFC8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFCC ) = ( uint32_t ) g_aOffsets[ 111 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BFC8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFD8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFDC ) = ( uint32_t ) g_aOffsets[ 112 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BFD8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFF0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFF4 ) = ( uint32_t ) g_aOffsets[ 113 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BFF0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFF8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3BFFC ) = ( uint32_t ) g_aOffsets[ 114 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3BFF8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C008 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C00C ) = ( uint32_t ) g_aOffsets[ 115 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C008 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C010 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C014 ) = ( uint32_t ) g_aOffsets[ 116 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C010 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C018 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C01C ) = ( uint32_t ) g_aOffsets[ 117 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C018 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C020 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C024 ) = ( uint32_t ) g_aOffsets[ 118 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C020 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C028 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C02C ) = ( uint32_t ) g_aOffsets[ 119 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C028 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C030 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C034 ) = ( uint32_t ) g_aOffsets[ 120 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C030 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C038 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C03C ) = ( uint32_t ) g_aOffsets[ 121 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C038 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C040 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C044 ) = ( uint32_t ) g_aOffsets[ 122 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C040 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C048 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C04C ) = ( uint32_t ) g_aOffsets[ 123 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C048 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C050 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C054 ) = ( uint32_t ) g_aOffsets[ 124 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C050 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C058 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C05C ) = ( uint32_t ) g_aOffsets[ 125 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C058 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C060 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C064 ) = ( uint32_t ) g_aOffsets[ 126 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C060 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C068 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C06C ) = ( uint32_t ) g_aOffsets[ 127 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C068 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C070 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C074 ) = ( uint32_t ) g_aOffsets[ 128 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C070 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C078 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C07C ) = ( uint32_t ) g_aOffsets[ 129 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C078 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C080 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C084 ) = ( uint32_t ) g_aOffsets[ 130 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C080 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C088 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C08C ) = ( uint32_t ) g_aOffsets[ 131 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C088 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C090 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C094 ) = ( uint32_t ) g_aOffsets[ 132 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C090 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C098 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C09C ) = ( uint32_t ) g_aOffsets[ 133 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C098 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0A0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0A4 ) = ( uint32_t ) g_aOffsets[ 134 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C0A0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0A8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0AC ) = ( uint32_t ) g_aOffsets[ 135 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C0A8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0B0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0B4 ) = ( uint32_t ) g_aOffsets[ 136 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C0B0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0B8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0BC ) = ( uint32_t ) g_aOffsets[ 137 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C0B8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0C0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0C4 ) = ( uint32_t ) g_aOffsets[ 138 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C0C0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0C8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0CC ) = ( uint32_t ) g_aOffsets[ 139 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C0C8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0E0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0E4 ) = ( uint32_t ) g_aOffsets[ 140 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C0E0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0E8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0EC ) = ( uint32_t ) g_aOffsets[ 141 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C0E8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0F0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0F4 ) = ( uint32_t ) g_aOffsets[ 142 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C0F0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0F8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C0FC ) = ( uint32_t ) g_aOffsets[ 143 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C0F8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C100 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C104 ) = ( uint32_t ) g_aOffsets[ 144 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C100 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C128 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C12C ) = ( uint32_t ) g_aOffsets[ 145 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C128 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C130 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C134 ) = ( uint32_t ) g_aOffsets[ 146 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C130 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C138 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C13C ) = ( uint32_t ) g_aOffsets[ 147 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C138 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C140 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C144 ) = ( uint32_t ) g_aOffsets[ 148 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C140 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C148 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C14C ) = ( uint32_t ) g_aOffsets[ 149 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C148 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C160 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C164 ) = ( uint32_t ) g_aOffsets[ 150 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C160 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C168 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C16C ) = ( uint32_t ) g_aOffsets[ 151 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C168 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C170 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C174 ) = ( uint32_t ) g_aOffsets[ 152 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C170 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C178 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C17C ) = ( uint32_t ) g_aOffsets[ 153 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C178 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C180 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C184 ) = ( uint32_t ) g_aOffsets[ 154 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C180 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C188 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C18C ) = ( uint32_t ) g_aOffsets[ 155 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C188 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C190 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C194 ) = ( uint32_t ) g_aOffsets[ 156 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C190 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C198 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C19C ) = ( uint32_t ) g_aOffsets[ 157 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C198 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1A0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1A4 ) = ( uint32_t ) g_aOffsets[ 158 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1A0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1A8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1AC ) = ( uint32_t ) g_aOffsets[ 159 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1A8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1B0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1B4 ) = ( uint32_t ) g_aOffsets[ 160 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1B0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1B8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1BC ) = ( uint32_t ) g_aOffsets[ 161 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1B8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1C0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1C4 ) = ( uint32_t ) g_aOffsets[ 162 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1C0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1C8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1CC ) = ( uint32_t ) g_aOffsets[ 163 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1C8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1D0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1D4 ) = ( uint32_t ) g_aOffsets[ 164 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1D0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1D8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1DC ) = ( uint32_t ) g_aOffsets[ 165 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1D8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1E0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1E4 ) = ( uint32_t ) g_aOffsets[ 166 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1E0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1E8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1EC ) = ( uint32_t ) g_aOffsets[ 167 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1E8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1F0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1F4 ) = ( uint32_t ) g_aOffsets[ 168 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1F0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1F8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C1FC ) = ( uint32_t ) g_aOffsets[ 169 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C1F8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C200 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C204 ) = ( uint32_t ) g_aOffsets[ 170 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C200 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C208 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C20C ) = ( uint32_t ) g_aOffsets[ 171 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C208 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C210 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C214 ) = ( uint32_t ) g_aOffsets[ 172 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C210 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C218 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C21C ) = ( uint32_t ) g_aOffsets[ 173 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C218 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C220 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C224 ) = ( uint32_t ) g_aOffsets[ 174 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C220 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C228 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C22C ) = ( uint32_t ) g_aOffsets[ 175 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C228 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C230 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C234 ) = ( uint32_t ) g_aOffsets[ 176 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C230 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C238 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C23C ) = ( uint32_t ) g_aOffsets[ 177 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C238 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C240 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C244 ) = ( uint32_t ) g_aOffsets[ 178 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C240 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C248 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C24C ) = ( uint32_t ) g_aOffsets[ 179 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C248 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C250 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C254 ) = ( uint32_t ) g_aOffsets[ 180 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C250 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C258 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C25C ) = ( uint32_t ) g_aOffsets[ 181 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C258 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C260 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C264 ) = ( uint32_t ) g_aOffsets[ 182 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C260 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C268 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C26C ) = ( uint32_t ) g_aOffsets[ 183 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C268 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C270 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C274 ) = ( uint32_t ) g_aOffsets[ 184 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C270 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C278 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C27C ) = ( uint32_t ) g_aOffsets[ 185 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C278 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C280 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C284 ) = ( uint32_t ) g_aOffsets[ 186 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C280 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C288 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C28C ) = ( uint32_t ) g_aOffsets[ 187 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C288 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C290 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C294 ) = ( uint32_t ) g_aOffsets[ 188 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C290 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C298 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C29C ) = ( uint32_t ) g_aOffsets[ 189 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C298 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2A0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2A4 ) = ( uint32_t ) g_aOffsets[ 190 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2A0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2A8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2AC ) = ( uint32_t ) g_aOffsets[ 191 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2A8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2B0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2B4 ) = ( uint32_t ) g_aOffsets[ 192 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2B0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2B8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2BC ) = ( uint32_t ) g_aOffsets[ 193 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2B8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2C0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2C4 ) = ( uint32_t ) g_aOffsets[ 194 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2C0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2C8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2CC ) = ( uint32_t ) g_aOffsets[ 195 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2C8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2D0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2D4 ) = ( uint32_t ) g_aOffsets[ 196 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2D0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2D8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2DC ) = ( uint32_t ) g_aOffsets[ 197 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2D8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2E0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2E4 ) = ( uint32_t ) g_aOffsets[ 198 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2E0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2E8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2EC ) = ( uint32_t ) g_aOffsets[ 199 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2E8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2F0 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2F4 ) = ( uint32_t ) g_aOffsets[ 200 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2F0 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2F8 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C2FC ) = ( uint32_t ) g_aOffsets[ 201 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C2F8 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C300 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C304 ) = ( uint32_t ) g_aOffsets[ 202 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C300 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C308 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C30C ) = ( uint32_t ) g_aOffsets[ 203 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C308 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C310 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C314 ) = ( uint32_t ) g_aOffsets[ 204 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C310 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C318 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C31C ) = ( uint32_t ) g_aOffsets[ 205 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C318 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C320 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C324 ) = ( uint32_t ) g_aOffsets[ 206 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C320 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C328 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C32C ) = ( uint32_t ) g_aOffsets[ 207 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C328 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C330 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C334 ) = ( uint32_t ) g_aOffsets[ 208 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C330 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C338 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C33C ) = ( uint32_t ) g_aOffsets[ 209 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C338 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C340 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C344 ) = ( uint32_t ) g_aOffsets[ 210 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C340 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C348 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C34C ) = ( uint32_t ) g_aOffsets[ 211 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C348 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C350 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C354 ) = ( uint32_t ) g_aOffsets[ 212 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C350 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C358 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C35C ) = ( uint32_t ) g_aOffsets[ 213 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C358 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C360 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C364 ) = ( uint32_t ) g_aOffsets[ 214 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C360 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C368 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C36C ) = ( uint32_t ) g_aOffsets[ 215 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C368 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C370 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C374 ) = ( uint32_t ) g_aOffsets[ 216 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C370 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C378 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C37C ) = ( uint32_t ) g_aOffsets[ 217 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C378 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C380 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C384 ) = ( uint32_t ) g_aOffsets[ 218 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C380 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C388 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C38C ) = ( uint32_t ) g_aOffsets[ 219 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C388 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C390 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C394 ) = ( uint32_t ) g_aOffsets[ 220 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C390 );
	*reinterpret_cast< uint32_t* >( 0x3CD3C398 ) = ( uint32_t ) std::rand( );
	*reinterpret_cast< uint32_t* >( 0x3CD3C39C ) = ( uint32_t ) g_aOffsets[ 221 ] ^ *reinterpret_cast< uint32_t* >( 0x3CD3C398 );
}

__forceinline void CCheat::SetupHooks( )
{
	if ( MH_Initialize( ) != MH_OK )
		return;

	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 0 ] ), ( void* ) 0x3CCABEB0, ( void** ) 0x3D05B48C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 1 ] ), ( void* ) 0x3CCA94B0, ( void** ) 0x3D05B41C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 2 ] ), ( void* ) 0x3CC117B0, ( void** ) 0x3D05B1E0 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 3 ] ), ( void* ) 0x3CC123C0, ( void** ) 0x3D05B1D8 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 4 ] ), ( void* ) 0x3CCA9110, ( void** ) 0x3D05B420 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 5 ] ), ( void* ) 0x3CCA8E30, ( void** ) 0x3D05B414 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 6 ] ), ( void* ) 0x3CCA9070, ( void** ) 0x3D05B418 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 7 ] ), ( void* ) 0x3CCA9040, ( void** ) 0x0 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 8 ] ), ( void* ) 0x3CC121F0, ( void** ) 0x3D05B1C8 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 9 ] ), ( void* ) 0x3CC120D0, ( void** ) 0x3D05B1D0 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 10 ] ), ( void* ) 0x3CC127B0, ( void** ) 0x3D05B1CC );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 11 ] ), ( void* ) 0x3CC13410, ( void** ) 0x3D05B210 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 12 ] ), ( void* ) 0x3CC132F0, ( void** ) 0x3D05B20C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 13 ] ), ( void* ) 0x3CC0F4A0, ( void** ) 0x3D05B15C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 14 ] ), ( void* ) 0x3CC0DFF0, ( void** ) 0x3D05B120 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 15 ] ), ( void* ) 0x3CC0E000, ( void** ) 0x3D05B11C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 16 ] ), ( void* ) 0x3CC0D4C0, ( void** ) 0x3D05B110 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 17 ] ), ( void* ) 0x3CC11260, ( void** ) 0x3D05B1A0 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 18 ] ), ( void* ) 0x3CC0E160, ( void** ) 0x3D05B12C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 19 ] ), ( void* ) 0x3CC0E420, ( void** ) 0x3D05B128 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 20 ] ), ( void* ) 0x3CCAA180, ( void** ) 0x3D05B430 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 21 ] ), ( void* ) 0x3CCAA600, ( void** ) 0x3D05B458 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 22 ] ), ( void* ) 0x3CCAB0E0, ( void** ) 0x3D05B454 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 23 ] ), ( void* ) 0x3CC0E030, ( void** ) 0x3D05AFC4 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 24 ] ), ( void* ) 0x3CC12D10, ( void** ) 0x3D05B204 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 25 ] ), ( void* ) 0x3CC0E4D0, ( void** ) 0x3D05B138 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 26 ] ), ( void* ) 0x3CC11D50, ( void** ) 0x3D05B1C4 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 27 ] ), ( void* ) 0x3CC11E00, ( void** ) 0x3D05B1DC );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 28 ] ), ( void* ) 0x3CC12200, ( void** ) 0x3D05B1D4 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 29 ] ), ( void* ) 0x3CC0F120, ( void** ) 0x3D05B14C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 30 ] ), ( void* ) 0x3CC0E100, ( void** ) 0x3D05B130 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 31 ] ), ( void* ) 0x3CC0E110, ( void** ) 0x3D05B134 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 32 ] ), ( void* ) 0x3CC0E130, ( void** ) 0x3D05B124 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 33 ] ), ( void* ) 0x3CC0F460, ( void** ) 0x3D05B158 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 34 ] ), ( void* ) 0x3CC13D20, ( void** ) 0x3D05B238 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 35 ] ), ( void* ) 0x3CC13D40, ( void** ) 0x3D05B23C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 36 ] ), ( void* ) 0x3CC0D7C0, ( void** ) 0x3D05B118 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 37 ] ), ( void* ) 0x3CC0D6A0, ( void** ) 0x3D05B114 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 38 ] ), ( void* ) 0x3CC0D8E0, ( void** ) 0x3CFC0D68 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 39 ] ), ( void* ) 0x3CC0D880, ( void** ) 0x3CFC0D64 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 40 ] ), ( void* ) 0x3CC0D820, ( void** ) 0x3CFC0D60 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 41 ] ), ( void* ) 0x3CC0F1B0, ( void** ) 0x3D05B150 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 42 ] ), ( void* ) 0x3CC0F190, ( void** ) 0x3D05B154 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 43 ] ), ( void* ) 0x3CC0FC80, ( void** ) 0x3D05B184 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 44 ] ), ( void* ) 0x3CC10900, ( void** ) 0x3D05B188 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 45 ] ), ( void* ) 0x3CC10D80, ( void** ) 0x3D05B190 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 46 ] ), ( void* ) 0x3CC13290, ( void** ) 0x3D05B208 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 47 ] ), ( void* ) 0x3CC13450, ( void** ) 0x3D05B218 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 48 ] ), ( void* ) 0x3CCABC70, ( void** ) 0x3D05B480 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 49 ] ), ( void* ) 0x3CCABE40, ( void** ) 0x3D05B488 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 50 ] ), ( void* ) 0x3CC0E960, ( void** ) 0x3D05B144 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 51 ] ), ( void* ) 0x3CC0F170, ( void** ) 0x3D05B148 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 52 ] ), ( void* ) 0x3CC128A0, ( void** ) 0x3D05B1F4 );

	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 53 ] ), ( void* ) 0x3CC0F870, ( void** ) 0x3D05B174 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 54 ] ), ( void* ) 0x3CC0F9F0, ( void** ) 0x3D05B178 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 55 ] ), ( void* ) 0x3CC0F1D0, ( void** ) 0x3D05B164 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 56 ] ), ( void* ) 0x3CCABBB0, ( void** ) 0x3D05B450 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 57 ] ), ( void* ) 0x3CC0F480, ( void** ) 0x3D05B168 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 58 ] ), ( void* ) 0x3CC0F200, ( void** ) 0x3D05B16C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 59 ] ), ( void* ) 0x3CC11570, ( void** ) 0x3CFC0D0C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 60 ] ), ( void* ) 0x3CC0F250, ( void** ) 0x3D05B160 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 61 ] ), ( void* ) 0x3CC0E780, ( void** ) 0x3D05B140 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 62 ] ), ( void* ) 0x3CC0E8A0, ( void** ) 0x3D05B13C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 63 ] ), ( void* ) 0x3CC13470, ( void** ) 0x3D05B21C );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 64 ] ), ( void* ) 0x3CC111F0, ( void** ) 0x3D05B19C );

	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 65 ] ), ( void* ) 0x3CC10E70, ( void** ) 0x3D05B198 );
	
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 66 ] ), ( void* ) 0x3CC11270, ( void** ) 0x3D05B1A8 );
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 67 ] ), ( void* ) 0x3CC11480, ( void** ) 0x3D05B1AC );
	
	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 68 ] ), ( void* ) 0x3CC13D00, ( void** ) 0x3D05B224 );

	MH_CreateHook( reinterpret_cast< void* >( g_aHooks[ 69 ] ), ( void* ) 0x3CC134E0, ( void** ) 0x3D05B228 );
}

__forceinline void CCheat::SetupGameUpdates( )
{
	std::vector< uint32_t > aCommands =
	{
		0x3CBD8820, 0x3CBD88C2, 0x3CCA021C, 0x3CCA0474,
		0x3CCA0692, 0x3CCA07C0, 0x3CCA09CF, 0x3CCAB14C
	};

	//for ( const auto& pAddress : aCommands )
		//*reinterpret_cast< uint32_t* >( pAddress ) = 0x108;

	std::vector< uint32_t > aVerifiedCommands =
	{
		0x3CCA0222, 0x3CCA047A, 0x3CCA0698, 0x3CCA07C6,
		0x3CCA09D5, 0x3CCAB15B
	};

	//for ( const auto& pAddress : aVerifiedCommands )
		//*reinterpret_cast< uint32_t* >( pAddress ) = 0x10C;

	std::vector< uint32_t > aVecCamOffset =
	{
		0x3CBF65B1, 0x3CBF6608, 0x3cbf663d
	};

	//for ( size_t i = 0; i < aVecCamOffset.size( ); i++ )
		//*reinterpret_cast< uint32_t* >( aVecCamOffset[ i ] ) = 0xC4 + ( sizeof( float ) * i );

	aVecCamOffset.clear( );
	aVecCamOffset =
	{
		0x3ccaada2, 0x3CCAADE6, 0x3CCAAE1B
	};
	
	//for ( size_t i = 0; i < aVecCamOffset.size( ); i++ )
		//*reinterpret_cast< uint32_t* >( aVecCamOffset[ i ] ) = 0xC4 + ( sizeof( float ) * i );

	//*reinterpret_cast< uint32_t* >( 0x3CCAB057 ) = 0xCC;
	//*reinterpret_cast< uint32_t* >( 0x3ccab05f ) = 0xCC;

	std::vector< uint32_t > aInputInThirdPerson =
	{
		0x3CBFC2FC, 0x3CC0CDA6, 0x3CCAA825, 0x3CCAB08B
	};

	//for ( const auto& pbInThirdPerson : aInputInThirdPerson )
		//*reinterpret_cast< uint32_t* >( pbInThirdPerson ) = 0xC1;
}

__forceinline void CCheat::InitAddresses( )
{
	g_aHooks[ 0 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 56 8b f1 8b 86 80" );
	g_aHooks[ 1 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 b9 74" );
	g_aHooks[ 2 ] = g_Utils.FindPattern( "client.dll", "55 8b ec a1 ? ? ? ? 83 ec c 8b 40" );
	g_aHooks[ 3 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 81 ec 8 4 0 0 53" );
	g_aHooks[ 4 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 10 53 56 8b f1 57 80 be ee" );
	g_aHooks[ 5 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 1c 8b d ? ? ? ? 53" );
	g_aHooks[ 6 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 44 53 56 57 6a" );
	g_aHooks[ 7 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec c 56 8b f1 85" );
	g_aHooks[ 8 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 44 53 56 57 8b f9 8b" );
	g_aHooks[ 9 ] = g_Utils.FindPattern( "client.dll", "56 8b 35 ? ? ? ? 57 8b f9 8b ce 8b 6 ff 90 84 0 0 0 8b 7" );
	g_aHooks[ 10 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec c 53 56 8b f1 57 8b" );
	g_aHooks[ 11 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec c 53 56 8b f1 57 83" );
	g_aHooks[ 12 ] = g_Utils.FindPattern( "client.dll", "8b 89 d8 29 0 0 56" );
	g_aHooks[ 13 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 8B 4D 04 8B C1 83 C0 08 A1 ? ? ? ? 85 C0 0F 84 FE 00 00 00" );
	g_aHooks[ 14 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 10 53 56 8b 35 ? ? ? ? 57" );
	g_aHooks[ 15 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 30 c6" );
	g_aHooks[ 16 ] = g_Utils.FindPattern( "client.dll", "51 56 57 8b f9 b9" );
	g_aHooks[ 17 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 81 ec 0 2 0 0 56 8b f1 8b 4d 8" );
	g_aHooks[ 18 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 E4 F8 8B 4D 04 83 EC 58 56 57 8B C1" );
	g_aHooks[ 19 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 8B 4D 04 83 EC 08 57 8B C1" );
	g_aHooks[ 20 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 c0 83 ec 38 a1" );
	g_aHooks[ 21 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 E4 F8 81 EC C0 00 00 00 56 8B F1" );
	g_aHooks[ 22 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 18 53 56 8b f1 8b 4d" );
	g_aHooks[ 23 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 68 53 56 8b d9 c7" );
	g_aHooks[ 24 ] = g_Utils.FindPattern( "client.dll", "55 8b ec a1 ? ? ? ? 83 ec 54" );
	g_aHooks[ 25 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 8 53 8b 5d 10 56" );
	g_aHooks[ 26 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 18 56 57 8b f9 8b 87" );
	g_aHooks[ 27 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 56 8b f1 51 8d" );
	g_aHooks[ 28 ] = g_Utils.FindPattern( "client.dll", "56 8b f1 80 be 34 36" );
	g_aHooks[ 29 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 53 56 8b f1 bb c" );
	g_aHooks[ 30 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 EC 0C 53 8B D9 8B 4D 04 56 8B C1 83" );
	g_aHooks[ 31 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 51 53 56 57 8B F9 8B 4D 04 8B C1 83 C0 08 8B 35" );
	g_aHooks[ 32 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 8b 49 18 56 8b" );
	g_aHooks[ 33 ] = g_Utils.FindPattern( "client.dll", "57 8b f9 8b d ? ? ? ? 8b 1 8b 40 6c" );
	g_aHooks[ 34 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 EC 48 53 56 89 4D EC 8B 4D 04 57 8B" );
	g_aHooks[ 35 ] = g_Utils.FindPattern( "client.dll", "53 8b dc 83 ec 8 83 e4 f0 83 c4 4 55 8b 6b 4 89 6c 24 4 8b ec 83 ec 48 80" );
	g_aHooks[ 36 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 18 56 57 8b f9 f3" );
	g_aHooks[ 37 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 70 56 57 8b f9 89 7c 24 14" );
	g_aHooks[ 38 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 53 56 57 8b f9 8b 77 60" );
	g_aHooks[ 39 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 81 ec 88 0 0 0 56 57 8b 3d ? ? ? ? 8b" );
	g_aHooks[ 40 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 30 56 57 8b 3d" );
	g_aHooks[ 41 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 81 ec 90 0 0 0 56 57 8b 7d" );
	g_aHooks[ 42 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 81 ec c4 0 0 0 53 57" );
	g_aHooks[ 43 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 E4 F8 83 EC 78 56 89 4C 24 14 8B 4D" );
	g_aHooks[ 44 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 51 53 56 57 8b 7d 8 8b d9 8b cf 8b 7 ff 50 4 8b f0 a1" );
	g_aHooks[ 45 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 E4 F0 81 EC 88 01 00 00 56 57 8B F9" );
	g_aHooks[ 46 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 8b 45 8 f3 f 7e 45" );
	g_aHooks[ 47 ] = g_Utils.FindPattern( "client.dll", "83 b9 18 2a" );
	g_aHooks[ 48 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f0 83 ec 78 56 8b f1 8b" );
	g_aHooks[ 49 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 48 53 8b d9 f3" );
	g_aHooks[ 50 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec c 53 56 8b f1 8b 86" );
	g_aHooks[ 51 ] = g_Utils.FindPattern( "client.dll", "56 8b f1 8b d ? ? ? ? 57 8b 1 ff 76 70" );
	g_aHooks[ 52 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 30 56 57 8b f9 f" );
	g_aHooks[ 53 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec a1 ? ? ? ? b9 ? ? ? ? 8b 40 48 ff d0 84 c0 f 84 2e" );
	g_aHooks[ 54 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 81 ec 24 1 0 0 53 56" );
	g_aHooks[ 55 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 8b 55 c 8b 4d 8 68 0" );
	g_aHooks[ 56 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 81 ec 64 1" );
	g_aHooks[ 57 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 ec 14 a1 ? ? ? ? 53 56 89" );
	g_aHooks[ 58 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 81 ec 34 1 0 0 56" );
	g_aHooks[ 59 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 e4 f8 81 ec 94 2 0 0 53 56 89" );
	g_aHooks[ 60 ] = g_Utils.FindPattern( "engine.dll", "56 8b f1 83 be 8 5" );
	g_aHooks[ 61 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 ec 8 56 8b f1 8b 4d 4" );
	g_aHooks[ 62 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 e4 f8 a1 ? ? ? ? 81 ec 84" );
	g_aHooks[ 63 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 8b 55 8 f3" );
	g_aHooks[ 64 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 6a 0 ff 75 8 e8 f3" );
	g_aHooks[ 65 ] = g_Utils.FindPattern( "inputsystem.dll", "55 8B EC 83 EC 0C 80 3D" );
	g_aHooks[ 66 ] = g_Utils.FindPattern( "materialsystem.dll", "55 8B EC 83 EC 0C 56 8B F1 8A 46 20 C0 E8 02 A8" );
	g_aHooks[ 67 ] = g_Utils.FindPattern( "materialsystem.dll", "55 8B EC 83 E4 C0 81 EC F4 00 00 00 53 8B D9 8B" );
	g_aHooks[ 68 ] = g_Utils.FindPattern( "vguimatsurface.dll", "53 8B D9 8D 4D F8 56 57 51 8B" );
	g_aHooks[ 69 ] = g_Utils.FindPattern( "vgui2.dll", "55 8B EC 8B 01 FF 75 08 FF 90 04 01 00 00 FF 75 10 8B C8 FF 75 0C 8B 10 FF 52 0C 5D C2 0C 00 CC" );

	g_aOffsets[ 0 ] = *( uint8_t** ) g_Utils.FindPattern( "engine.dll", "? ? ? ? 01 e8 0c fc" );
	g_aOffsets[ 1 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 ec 14 a1 ? ? ? ? 53 56 89" );
	g_aOffsets[ 2 ] = g_Utils.FindPattern( "client.dll", "56 8b 35 ? ? ? ? 57 8b f9 8b ce 8b 06 ff 90 84 00 00 00 8b 07" );
	g_aOffsets[ 3 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 56 57 8B 7D 08 8B F1 F3 0F 10 07 0F 2E 86 D0 00 00 00 9F F6 C4 44 7A 24 F3 0F 10 47 04 0F 2E 86 D4 00 00 00 9F F6 C4 44 7A 12 F3 0F 10 47 08 0F 2E 86 D8 00 00 00 9F F6 C4 44 7B 21 6A 02 E8 ? ? ? ? 8B 07 89 86 D0 00 00 00 8B 47 04 89 86 D4 00 00 00 8B 47 08 89 86 D8 00 00 00 5F 5E 5D C2 04 00 CC CC" );
	g_aOffsets[ 4 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 c0 83 ec 34 53 56 8b 75" );
	g_aOffsets[ 5 ] = g_Utils.FindPattern( "engine.dll", "57 8b 3d ? ? ? ? 83 bf" );
	g_aOffsets[ 6 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 08 8b 45 08 53 56 57 8d" );
	g_aOffsets[ 7 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 8B 4D 04 56 8B C1 83 C0 08 8B 75 08 A1" );
	g_aOffsets[ 8 ] = g_Utils.FindPattern( "engine.dll", "53 56 57 8b da 8b f9 ff" );
	g_aOffsets[ 9 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 53 8b 5d 08 56 8b f1 83" );
	g_aOffsets[ 10 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 56 ff 75 08 8b f1 8b 06 ff 90 6c" );
	g_aOffsets[ 11 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 6c 53 8b d9 8b" );
	g_aOffsets[ 12 ] = g_Utils.FindPattern( "client.dll", "53 56 8b f1 57 8b 4e 3c" );
	g_aOffsets[ 13 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 8b 55 0c 56 8b 75 08 57" );
	g_aOffsets[ 14 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 f3 0f 10 42" );
	g_aOffsets[ 15 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 81 ec f8 00 00 00 56 8b f1 57 89" );
	g_aOffsets[ 16 ] = *( uint8_t** ) g_Utils.FindPattern( "engine.dll", "? ? ? ? 00 8b d8 89 5d f8 0f" );
	g_aOffsets[ 17 ] = *( uint8_t** ) g_Utils.FindPattern( "engine.dll", "? ? ? ? f3 0f e6 c9 2b" );
	g_aOffsets[ 18 ] = *( uint8_t** ) g_Utils.FindPattern( "engine.dll", "? ? ? ? 66 0f 6e c8 a1" );
	g_aOffsets[ 19 ] = *( uint8_t** ) g_Utils.FindPattern( "engine.dll", "? ? ? ? 74 26 e8 6e" );
	g_aOffsets[ 20 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 e4 f8 b8 c4" );
	g_aOffsets[ 21 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 14 56 57 8b f9 8b 0d" );
	g_aOffsets[ 22 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 53 8b 5d 08 56 57 8b f9 33 f6 39" );
	g_aOffsets[ 23 ] = g_Utils.FindPattern( "client.dll", "55 8b ec a1 ? ? ? ? 83 ec 08 56 8b f1 57" );
	g_aOffsets[ 24 ] = g_Utils.FindPattern( "client.dll", "55 8b ec a1 ? ? ? ? 53 56 8b f1 a8 01 75 23 8b 0d ? ? ? ? 83 c8 01 a3 ? ? ? ? 68 ? ? ? ? 8b 01 ff 90 68 02 00 00 66 a3 ? ? ? ? eb 06 66 a1 ? ? ? ? 80" );
	g_aOffsets[ 25 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 53 56 8b 75 08 8b d9 57 6b" );
	g_aOffsets[ 26 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 10 53 8b 5d 08 57 8b f9" );
	g_aOffsets[ 27 ] = g_Utils.FindPattern( "client.dll", "55 8b ec a1 ? ? ? ? 83 ec 3c 53 56" );
	g_aOffsets[ 28 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 81 ec 04 01 00 00 57 8b f9 c7" );
	g_aOffsets[ 29 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 56 ff 75 08 8b f1 8d 8e 44" );
	g_aOffsets[ 30 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 53 56 57 8b 7d 10 8b f1" );
	g_aOffsets[ 31 ] = g_Utils.FindPattern( "client.dll", "8b 0d ? ? ? ? 85 c9 74 07 8b 01 8b" );
	g_aOffsets[ 32 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f0 83 ec 7c 56 ff" );
	g_aOffsets[ 33 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f0 81 ec 88 03" );
	g_aOffsets[ 34 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 81 ec 34 01 00 00 56" );
	g_aOffsets[ 35 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 51 53 56 57 8b f1 e8 1f" );
	g_aOffsets[ 36 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 64 53 56 57 8b f1" );
	g_aOffsets[ 37 ] = g_Utils.FindPattern( "client.dll", "56 8B F1 83 BE 50 29 00  00 00 75 14 8B 46 04 8D 4E 04 FF 50 20 85 C0 74  07 8B CE E8 ? ? ? ? 8B 86 50 29 00 00 85 C0  74 05 83 38 00 75 02 33 C0 5E C3 CC" );
	g_aOffsets[ 38 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 e4 f0 83 ec 28" );
	g_aOffsets[ 39 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f0 83 ec 7c 56 52" );
	g_aOffsets[ 40 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 10 53 56 8b f1 57 80 be ee" );
	g_aOffsets[ 41 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 18 56 57 8b f9 f3" );
	g_aOffsets[ 42 ] = g_Utils.FindPattern( "client.dll", "56 6a 01 68 ? ? ? ? 8b f1" );
	g_aOffsets[ 43 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 51 53 56 8b d9" );
	g_aOffsets[ 44 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 8b 4d 04 81" );
	g_aOffsets[ 45 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 c0 81 ec f4 02" );
	g_aOffsets[ 46 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 EC 48 53 56 89 4D EC 8B 4D 04 57 8B" );
	g_aOffsets[ 47 ] = g_Utils.FindPattern( "client.dll", "53 8b dc 83 ec 08 83 e4 f0 83 c4 04 55 8b 6b 04 89 6c 24 04 8b ec 83 ec 48 80" );
	g_aOffsets[ 48 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 83 EC 10 53 56 57 8B 7D 10 8B D9 F3 0F" );
	g_aOffsets[ 49 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 83 E4 F8 81 EC C8 00 00 00 8B C1 89 54" );
	g_aOffsets[ 50 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 83 EC 10 53 8B D9 89 55 F8 56 57 89 5D" );
	g_aOffsets[ 51 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 83 E4 F0 B8 38 11 00 00 E8" );
	g_aOffsets[ 52 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 08 53 56 57 8b f9 89 7d f8 e8 dd" );
	g_aOffsets[ 53 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 8B 45 08 56 8B F1 89 06 C7 46 04 00 00 00 00 C7 46 08 00 00 00 00 C7 46 10 00 00 00 00" );
	g_aOffsets[ 54 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 0c 53 56 8b f1 57 89 75 f8 e8" );
	g_aOffsets[ 55 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 EC 08 53 56 57 8B F9 89 7D F8 E8 ? ? ? ? 83 7F 10 00 0F  84 8B 00 00 00 8B 87 8C" );
	g_aOffsets[ 56 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 b8 c4" );
	g_aOffsets[ 57 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 EC 10 A1 ? ? ? ? 53 56 57 8B F9 89 7D F4 A8 01 75 3F 83" );
	g_aOffsets[ 58 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 10 a1 ? ? ? ? 89 4d fc" );
	g_aOffsets[ 59 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 08 a1 ? ? ? ? 53 8b d9 56 8b 08 57 68" );
	g_aOffsets[ 60 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 81 ec ac 00 00 00 53 56" );
	g_aOffsets[ 61 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 8b 55 08 83 ec 1c f6" );
	g_aOffsets[ 62 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 b8 54" );
	g_aOffsets[ 63 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 E4 F8 83 EC 78 56 89 4C 24 14 8B 4D" );
	g_aOffsets[ 64 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 e4 f8 81 ec 94 02 00 00 53 56 89" );
	g_aOffsets[ 65 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 56 8b f1 80 be 14" );
	g_aOffsets[ 66 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 56 8b 75 08 57 8b f9 56 8b 07 ff 90" );
	g_aOffsets[ 67 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 57 8b f9 8b 8f 00" );
	g_aOffsets[ 68 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 81 ec fc 00 00 00 53 56" );
	g_aOffsets[ 69 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 8b 45 08 83 ec 24 56 8b" );
	g_aOffsets[ 70 ] = g_Utils.FindPattern( "client.dll", "83 b9 18 2a" );
	g_aOffsets[ 71 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 56 8b 35 ? ? ? ? 8b" );
	g_aOffsets[ 72 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f0 83 ec 78 56 8b f1 8b" );
	g_aOffsets[ 73 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 3c 53 8b d9 57" );
	g_aOffsets[ 74 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 48 53 8b d9 f3" );
	g_aOffsets[ 75 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 56 8b f1 8b 86 80" );
	g_aOffsets[ 76 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 8b 45 08 f3 0f 7e 45" );
	g_aOffsets[ 77 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 80 3d ? ? ? ? 00 75 06 32 c0 5d c2 04" );
	g_aOffsets[ 78 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 81 ec c0 00 00 00 56 8b f1" );
	g_aOffsets[ 79 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 8b 55 08 f3" );
	g_aOffsets[ 80 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 51 53 56 57 8b 7d 08 8b d9 8b cf 8b 07 ff 50 04 8b f0 a1" );
	g_aOffsets[ 81 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 0c 53 56 8b 71" );
	g_aOffsets[ 82 ] = g_Utils.FindPattern( "client.dll", "56 8b f1 e8 ? ? ? ? 8B 4E 28 85 C9 74 15 83" );
	g_aOffsets[ 83 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 53 56 8b f1 80" );
	g_aOffsets[ 84 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 8b 45 08 0f 28 c3" );
	g_aOffsets[ 85 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 E4 F0 81 EC 88 01 00 00 56 57 8B F9" );
	g_aOffsets[ 86 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 81 ec 8c 00 00 00 57 8b f9 8b" );
	g_aOffsets[ 87 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 c0 83 ec 38 a1" );
	g_aOffsets[ 88 ] = g_Utils.FindPattern( "engine.dll", "4e c7 45 b4" );
	g_aOffsets[ 89 ] = g_Utils.FindPattern( "engine.dll", "06 0f 85 8a" );
	g_aOffsets[ 90 ] = g_Utils.FindPattern( "engine.dll", "02 00 00 00 89 55 c4" );
	g_aOffsets[ 91 ] = g_Utils.FindPattern( "engine.dll", "0f 00 00 00 3b f0 0f" );
	g_aOffsets[ 92 ] = g_Utils.FindPattern( "engine.dll", "0f 84 ce 00 00 00 8b 0d" );
	g_aOffsets[ 93 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 0c 53 56 8b f1 8b 86" );
	g_aOffsets[ 94 ] = g_Utils.FindPattern( "client.dll", "53 8b dc 83 ec 08 83 e4 f0 83 c4 04 55 8b 6b 04 89 6c 24 04 8b ec 83 ec 10 0f 28" );
	g_aOffsets[ 95 ] = g_Utils.FindPattern( "server.dll", "53 8B DC 83 EC 08 83 E4 F0 83 C4 04 55 8B 6B 04 89 6C 24 04 8B EC 81 EC 88 04 00 00 56 57 68 00" );
	g_aOffsets[ 96 ] = g_Utils.FindPattern( "client.dll", "55 8b ec a1 ? ? ? ? 83 ec 54" );
	g_aOffsets[ 97 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 0c 53 56 8b f1 57 83" );
	g_aOffsets[ 98 ] = g_Utils.FindPattern( "client.dll", "8b 89 d8 29 00 00 56" );
	g_aOffsets[ 99 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 56 57 ff 75 0c 8b 7d 08 8b f1 57 e8" );
	g_aOffsets[ 100 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 44 53 56 57 8b f9 8b" );
	g_aOffsets[ 101 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 56 8b f1 83 be 50 29 00 00 00 75 14 8b 46 04 8d 4e 04 ff 50 20 85 c0 74 07 8b ce e8 4d 65" );
	g_aOffsets[ 102 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 70 56 57 8b f9 89 7c 24 38" );
	g_aOffsets[ 103 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 0c 53 56 8b f1 57 8b" );
	g_aOffsets[ 104 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 53 56 57 8b f9 83 7f 60" );
	g_aOffsets[ 105 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 51 a1 ? ? ? ? 56 8b f1 8b" );
	g_aOffsets[ 106 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 3c 53 56 8b c1" );
	g_aOffsets[ 107 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 18 56 57 8b f9 8b 87" );
	g_aOffsets[ 108 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 b9 74" );
	g_aOffsets[ 109 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 81 ec 84 00 00 00 56 57 8b 7d 0c" );
	g_aOffsets[ 110 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 53 56 8b f1 57 83 be 50" );
	g_aOffsets[ 111 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 E4 F8 83 EC 38 56 8B F1 57 8B 8E 50" );
	g_aOffsets[ 112 ] = g_Utils.FindPattern( "client.dll", "56 8b f1 80 be 34 36" );
	g_aOffsets[ 113 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 0c 56 8b f1 57 8b fa 85 f6 75 14" );
	g_aOffsets[ 114 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 56 8b f1 51 8d" );
	g_aOffsets[ 115 ] = g_Utils.FindPattern( "client.dll", "55 8b ec a1 ? ? ? ? 83 ec 0c 8b 40" );
	g_aOffsets[ 116 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 83 E4 F0 81 EC 18 01 00 00 33 D2 89 4C" );
	g_aOffsets[ 117 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 83 EC 24 8B 45 08 57 8B F9 89 7D F4 85" );
	g_aOffsets[ 118 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 81 EC BC 00 00 00 53 56 57 8B F9 0F 28" );
	g_aOffsets[ 119 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 83 E4 F0 81 EC 98 05 00 00 8B 81 F8 0F" );
	g_aOffsets[ 120 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 08 53 8b 5d 10 56" );
	g_aOffsets[ 121 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 18 57 8b f9 89 7d" );
	g_aOffsets[ 122 ] = *( uint8_t** )( g_Utils.FindPattern( "client.dll", "A1 ? ? ? ? 0F 94 C1 85  C0 74 0F 0F 1F 44 00 00" ) + 0x1 );
	g_aOffsets[ 123 ] = *( uint8_t** )( g_Utils.FindPattern( "client.dll", "83 3D ? ? ? ? 00 74 09 8D 4C 24 08 E8" ) + 0x2 );
	g_aOffsets[ 124 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 0c 53 56 8b f2 8b d1" );
	g_aOffsets[ 125 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? ff ff ff ff eb 08" );
	g_aOffsets[ 126 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec a1 ? ? ? ? b9 ? ? ? ? 8b 40 48 ff d0 84 c0 0f 84 2e" );
	g_aOffsets[ 127 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 ec 08 53 8b 5d 0c 56 8b f1 57 85 db 0f 84 ea" );
	g_aOffsets[ 128 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 ec 08 53 8b d9 8b 43 0c 8d 53 0c 3b 43 10 73 56" );
	g_aOffsets[ 129 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 8b 45 08 56 8b 30 81" );
	g_aOffsets[ 130 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 81 ec 00 04 00 00 53 57 8b 7d 08 8b 1f" );
	g_aOffsets[ 131 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 81 ec 04 01 00 00 56 8b 34" );
	g_aOffsets[ 132 ] = g_Utils.FindPattern( "inputsystem.dll", "55 8B EC 83 EC 0C 80 3D" );
	g_aOffsets[ 133 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 8b 0d ? ? ? ? 85 c9 74 15" );
	g_aOffsets[ 134 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 30 56 57 8b f9 0f" );
	g_aOffsets[ 135 ] = g_Utils.FindPattern( "materialsystem.dll", "55 8B EC 83 EC 0C 56 8B F1 8A 46 20 C0 E8 02 A8" );
	g_aOffsets[ 136 ] = g_Utils.FindPattern( "materialsystem.dll", "55 8B EC 83 E4 C0 81 EC F4 00 00 00 53 8B D9 8B" );
	g_aOffsets[ 137 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 8b 0d ? ? ? ? 83 ec 08 85 c9 75" );
	g_aOffsets[ 138 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 e4 f8 a1 ? ? ? ? 81 ec 84" );
	g_aOffsets[ 139 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 ec 08 56 8b f1 8b 4d 04" );
	g_aOffsets[ 140 ] = g_Utils.FindPattern( "client.dll", "51 56 57 8b f9 b9" );
	g_aOffsets[ 141 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 30 c6" );
	g_aOffsets[ 142 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 68 53 56 8b d9 c7" );
	g_aOffsets[ 143 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 10 53 56 8b 35 ? ? ? ? 57" );
	g_aOffsets[ 144 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 56 8D 75 04 8B 0E 8B C1 83 C0 08 8B 0E" );
	g_aOffsets[ 145 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 48 53 8b 5d" );
	g_aOffsets[ 146 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 81 ec 08 04 00 00 53" );
	g_aOffsets[ 147 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 81 ec 58 04" );
	g_aOffsets[ 148 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 7d 08 ff" );
	g_aOffsets[ 149 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 56 57 8b 7d 08 8b f1 f3 0f 10 07 0f 2e 86 d0 00 00 00 9f f6 c4 44 7a 24 f3 0f 10 47 04 0f 2e 86 d4 00 00 00 9f f6 c4 44 7a 12 f3 0f 10 47 08 0f 2e 86 d8 00 00 00 9f f6 c4 44 7b 21 6a 02 e8 ? ? ? ? 8B 07  89 86 D0 00 00 00 8B 47 04 89 86 D4 00 00 00 8B  47 08 89 86 D8 00 00 00 5F 5E 5D C2 04 00 CC CC" );
	g_aOffsets[ 150 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 1c 8b 0d ? ? ? ? 53" );
	g_aOffsets[ 151 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 44 53 56 57 6a" );
	g_aOffsets[ 152 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 0c 56 8b f1 85" );
	g_aOffsets[ 153 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 56 8b f1 85 f6 74 68" );
	g_aOffsets[ 154 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 0c 53 8b 5d 08 8b c3" );
	g_aOffsets[ 155 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 0c 53 56 57 8b 7d 08 8b f1 f3" );
	g_aOffsets[ 156 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 18 53 56 8b f1 8b 4d" );
	g_aOffsets[ 157 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 8b 49 18 56 8b" );
	g_aOffsets[ 158 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 8B 4D 04 83 EC 08 57 8B C1 83 C0 08 8B" );
	g_aOffsets[ 159 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 E4 F8 8B 4D 04 83 EC 58 56 57 8B C1" );
	g_aOffsets[ 160 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 83 EC 0C 53 8B D9 8B 4D 04 56 8B C1 83" );
	g_aOffsets[ 161 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 51 53 56 57 8B F9 8B 4D 04 8B C1 83 C0 08 8B 35" );
	g_aOffsets[ 162 ] = g_Utils.FindPattern( "client.dll", "56 8b f1 8b 0d ? ? ? ? 57 8b 01 ff 76 70" );
	g_aOffsets[ 163 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 53 56 8b f1 bb 0c" );
	g_aOffsets[ 164 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 81 ec 90 00 00 00 56 57 8b 7d" );
	g_aOffsets[ 165 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 81 ec c4 00 00 00 53 57" );
	g_aOffsets[ 166 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 8B 55 08 83 EC 30 56 8B F1 85 D2 0F 84" );
	g_aOffsets[ 167 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 34 53 56 8b 75 08 8b" );
	g_aOffsets[ 168 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 6a 00 ff 75 08 e8 f3" );
	g_aOffsets[ 169 ] = g_Utils.FindPattern( "client.dll", "53 8b d9 83 c8" );
	g_aOffsets[ 170 ] = g_Utils.FindPattern( "server.dll", "53 8B D9 F6 C3 03 74 0B FF 15" );
	g_aOffsets[ 171 ] = g_Utils.FindPattern( "server.dll", "55 8B EC 83 EC 08 8B 45 08 56 57 8B F9 8D 8F FC" );
	g_aOffsets[ 172 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 81 ec 00 02 00 00 56 8b f1 8b 4d 08" );
	g_aOffsets[ 173 ] = g_Utils.FindPattern( "client.dll", "53 8b dc 83 ec 08 83 e4 f8 83 c4 04 55 8b 6b 04 89 6c 24 04 8b ec a1 ? ? ? ? 81 ec 78" );
	g_aOffsets[ 174 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 70 6a" );
	g_aOffsets[ 175 ] = g_Utils.FindPattern( "vguimatsurface.dll", "53 8B D9 8D 4D F8 56 57 51 8B" );
	g_aOffsets[ 176 ] = g_Utils.FindPattern( "vguimatsurface.dll", "8B 0D ? ? ? ? 56 C6 05 ? ? ? ? 00 8B" );
	g_aOffsets[ 177 ] = g_Utils.FindPattern( "vgui2.dll", "55 8B EC 8B 01 FF 75 08 FF 90 04 01 00 00 FF 75 10 8B C8 FF 75 0C 8B 10 FF 52 0C 5D C2 0C 00 CC" );
	g_aOffsets[ 178 ] = g_Utils.FindPattern( "vguimatsurface.dll", "55 8B EC 83 E4 C0 83 EC 38 80 3D" );
	g_aOffsets[ 179 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 ec 08 53 56 57 8b fa 89" );
	g_aOffsets[ 180 ] = g_Utils.FindPattern( "client.dll", "57 8b f9 8b 0d ? ? ? ? 8b 01 8b 40 6c" );
	g_aOffsets[ 181 ] = g_Utils.FindPattern( "client.dll", "55 8B EC 8B 4D 04 8B C1 83 C0 08 A1 ? ? ? ? 85 C0 0F 84 FE 00 00 00" );
	g_aOffsets[ 182 ] = g_Utils.FindPattern( "engine.dll", "56 8b f1 83 be 08 05" );
	g_aOffsets[ 183 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 8b 55 0c 8b 4d 08 68 00" );
	g_aOffsets[ 184 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 81 ec 64 01" );
	g_aOffsets[ 185 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 ec 14 a1 ? ? ? ? 53 56 89" );
	g_aOffsets[ 186 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 83 ec 10 53 8b 1d ? ? ? ? 56 57" );
	g_aOffsets[ 187 ] = g_Utils.FindPattern( "engine.dll", "8b 0d ? ? ? ? 81 f9 ? ? ? ? 75 0c a1 ? ? ? ? 35 ? ? ? ? eb 05 8b 01 ff 50 34 85 c0 75 03 b0" );
	g_aOffsets[ 188 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? 80 bf 3a" );
	g_aOffsets[ 189 ] = *( uint8_t** ) g_Utils.FindPattern( "engine.dll", "? ? ? ? f2 0f 5c 47" );
	g_aOffsets[ 190 ] = g_Utils.FindPattern( "vgui2.dll", "55 8B EC 83 E4 F8 81 EC 9C 00 00 00 53 56 8B F1" );
	g_aOffsets[ 191 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 51 53 56 57 8b f9 8b 77 60" );
	g_aOffsets[ 192 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 70 56 57 8b f9 89 7c 24 14" );
	g_aOffsets[ 193 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 ec 08 53 56 8b 35 ? ? ? ? 57 8b f9 8b ce 8b 06 ff 90 84 00 00 00 8b 7f 60 0f" );
	g_aOffsets[ 194 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 81 ec 88 00 00 00 56 57 8b 3d ? ? ? ? 8b" );
	g_aOffsets[ 195 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? 0f 86 8b 00 00 00 f3" );
	g_aOffsets[ 196 ] = g_Utils.FindPattern( "client.dll", "55 8b ec 83 e4 f8 83 ec 30 56 57 8b 3d" );
	g_aOffsets[ 197 ] = g_Utils.FindPattern( "client.dll", "56 8b f1 85 f6 74 31" );
	g_aOffsets[ 198 ] = g_Utils.FindPattern( "engine.dll", "56 8b f1 57 8b 7e 08 83" );
	g_aOffsets[ 199 ] = g_Utils.FindPattern( "client.dll", "53 8b dc 83 ec 08 83 e4 f8 83 c4 04 55 8b 6b 04 89 6c 24 04 8b ec 83 ec 18 56 57 8b 7b" );
	g_aOffsets[ 200 ] = g_Utils.FindPattern( "client.dll", "a1 ? ? ? ? 85 c0 75 53" );
	g_aOffsets[ 201 ] = *( uint8_t** )( g_Utils.FindPattern( "vguimatsurface.dll", "B9 ? ? ? ? C7 83 A8 02 00 00 FF FF" ) + 0x1 );
	g_aOffsets[ 202 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? 83 c8 01 c7 05 ? ? ? ? 00 00 00 00 0f 28" );
	g_aOffsets[ 203 ] = *( uint8_t** )( g_Utils.FindPattern( "client.dll", "B9 ? ? ? ? 50 E8 ? ? ? ? 85 C0 74 4F 57 56 8B" ) + 0x1 );
	g_aOffsets[ 204 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? E8 ? ? ? ? 68 ? ? ? ? E8 ? ? ? ? 59 C3 CC CC CC CC CC CC CC CC CC CC 68 ? ? ? ? E8 ? ? ? ? 59 C3 CC CC CC CC A0" );
	g_aOffsets[ 205 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? ? ? ? ? ff 10" );
	g_aOffsets[ 206 ] = *( uint8_t** )( g_Utils.FindPattern( "client.dll", "B9 ? ? ? ? E8 ? ? ? ? 83 FE FF 74 12 8D" ) + 0x1 );
	g_aOffsets[ 207 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? 85 f6 74 25 8b 4d" );
	g_aOffsets[ 208 ] = *( uint8_t** )( g_Utils.FindPattern( "client.dll", "B9 ? ? ? ? F3 0F 11 04 24 FF 50 10" ) + 0x1 );
	g_aOffsets[ 209 ] = *( uint8_t** ) g_Utils.FindPattern( "engine.dll", "? ? ? ? b9 ? ? ? ? 56 8b 40 30" );
	g_aOffsets[ 210 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? 8b 4d fc 8b 40 10 89" );
	g_aOffsets[ 211 ] = *( uint8_t** ) g_Utils.FindPattern( "engine.dll", "? ? ? ? 8b 89 80 01 00 00 41" );
	g_aOffsets[ 212 ] = *( uint8_t** )( g_Utils.FindPattern( "client.dll", "8B 0D ? ? ? ? C7 40 78 00 00 00 00 C7 40 7C 00 00 00 00  C7 80 80 00 00 00 00 00" ) + 0x2 );
	g_aOffsets[ 213 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? 00 74 2a a1 ? ? ? ? b9" );
	g_aOffsets[ 214 ] = *( uint8_t** )( g_Utils.FindPattern( "client.dll", "B9 ? ? ? ? E8 ? ? ? ? FF 74 24 40 8D 45 10" ) + 0x1 );
	g_aOffsets[ 215 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? b9 ? ? ? ? 6a 00 ff 50 08 8b 80 8c" );
	g_aOffsets[ 216 ] = *( uint8_t** )( g_Utils.FindPattern( "client.dll", "8B 0D ? ? ? ? 8B 01 FF 50 2C 8B F0 68" ) + 0x2 );
	g_aOffsets[ 217 ] = *( uint8_t** ) g_Utils.FindPattern( "client.dll", "? ? ? ? b9 ? ? ? ? 56 ff 50 18" );
	g_aOffsets[ 218 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 0f 10 87 60 05 00 00 0f" );
	g_aOffsets[ 219 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 81 ec 24 01 00 00 53 56" );
	g_aOffsets[ 220 ] = g_Utils.FindPattern( "engine.dll", "55 8b ec 51 a1 ? ? ? ? 56 85" );
	g_aOffsets[ 221 ] = *( uint8_t** ) g_Utils.FindPattern( "engine.dll", "? ? ? ? 9f f6 c4 44 7a 78 0f" );

	g_aInlinedOffsets[ 0 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 50 8b 11 ff 52 40 b2" );
	g_aInlinedOffsets[ 1 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 48 01" );
	g_aInlinedOffsets[ 2 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? F3 0F 11 44 24 34 6A 00 68" );
	g_aInlinedOffsets[ 3 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? 66 c7 05 ? ? ? ? 00 00 c3 cc cc cc cc cc cc cc cc cc cc cc a1" );
	g_aInlinedOffsets[ 4 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? f3 0f 59 c1 89 44 24 1c f3" );
	g_aInlinedOffsets[ 5 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? df ac 24 90 00 00 00 de" );
	g_aInlinedOffsets[ 6 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 83 f9 ff 74 1b 0f b7 c1 c1 e0 04 05 ? ? ? ? 74 0e c1 e9 10 39 48 04 75 06 8b 00 5d c2 04 00 33 c0 5d c2 04 00 cc cc cc cc cc cc cc cc cc cc cc cc cc 55" );
	g_aInlinedOffsets[ 7 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 83 f8 ff 74 3d 0f" );
	g_aInlinedOffsets[ 8 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 53 56 57 8b 7d 0c 85 ff c7" );
	g_aInlinedOffsets[ 9 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? e8 ? ? ? ? b9 ? ? ? ? c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 5c" );
	g_aInlinedOffsets[ 10 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 38 2a" );
	g_aInlinedOffsets[ 11 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 00 00 00 00 f3 0f 10 83" );
	g_aInlinedOffsets[ 12 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 33 db 8b cf 89 4d" );
	g_aInlinedOffsets[ 13 ] = ( uint8_t* )( ( uint32_t ) GetModuleHandleA( "client.dll" ) + 0x3C + 0x1B1 );
	g_aInlinedOffsets[ 14 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? f0 00" );
	g_aInlinedOffsets[ 15 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 83 ff ff 74 26 8b 56 04 c1" );
	g_aInlinedOffsets[ 16 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 80 32" );
	g_aInlinedOffsets[ 17 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? e8 ? ? ? ? 0f 10 45 c4 83" );
	g_aInlinedOffsets[ 18 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 18 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? 66 c7 05 ? ? ? ? 00 00 c3 cc cc a1" );
	g_aInlinedOffsets[ 19 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 00 c7 86 d0 32" );
	g_aInlinedOffsets[ 20 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? e8 ? ? ? ? b9 ? ? ? ? c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? b8" );
	g_aInlinedOffsets[ 21 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 00 00 00 00 c7 86 80 32" );
	g_aInlinedOffsets[ 22 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 40 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 3c" );
	g_aInlinedOffsets[ 23 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? e4 31 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 08 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? 66 c7 05 ? ? ? ? 00 00 c3 cc cc e9 ? ? ? ? cc cc cc cc cc cc cc cc cc cc cc 68" );
	g_aInlinedOffsets[ 24 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? dc 31 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? e0 31 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? e4 31 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 08 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? 66 c7 05 ? ? ? ? 00 00 c3 cc cc e9 ? ? ? ? cc cc cc cc cc cc cc cc cc cc cc 68" );
	g_aInlinedOffsets[ 25 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 05 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? 66 c7 05 ? ? ? ? 00 00 c3 cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc c7" );
	g_aInlinedOffsets[ 26 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 02 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? 66 c7 05 ? ? ? ? 00 00 c3 cc cc cc cc cc cc cc cc cc cc cc cc a1 ? ? ? ? a3 ? ? ? ? c7 05 ? ? ? ? ? ? ? ? c3 cc cc cc cc cc cc cc cc cc cc cc 68 ? ? ? ? e8 ? ? ? ? 59 c3 cc cc cc cc a1 ? ? ? ? a8 01 0f 85 06" );
	g_aInlinedOffsets[ 27 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 60" );
	g_aInlinedOffsets[ 28 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 8b c6 c7 46 10 ? ? ? ? c7 46 28 05 00 00 00 5e c3 cc cc cc cc cc cc cc a1 ? ? ? ? 56 68 90 00 00 00 8b 08 8b 01 ff 50 04 8b f0 85 f6 74 26 68 90 00 00 00 6a 00 56 e8 ? ? ? ? 83 c4 0c 8b ce e8 ? ? ? ? c7 06 ? ? ? ? c7 46 0c ? ? ? ? eb 02 33 f6 c7 46 14 e4" );
	g_aInlinedOffsets[ 29 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 38 0b 00 00 c7 05 ? ? ? ? 01" );
	g_aInlinedOffsets[ 30 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 03 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? 66 c7 05 ? ? ? ? 00 00 c3 cc cc cc cc cc cc cc cc cc cc cc cc cc c7 05 ? ? ? ? 03" );
	g_aInlinedOffsets[ 31 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? ec 33" );
	g_aInlinedOffsets[ 32 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 94 29 00 00 c7 05 ? ? ? ? 01" );
	g_aInlinedOffsets[ 33 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? b8 29" );
	g_aInlinedOffsets[ 34 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 85 c0 5e 0f 95 c0 c3 33" );
	g_aInlinedOffsets[ 35 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? e8 33" );
	g_aInlinedOffsets[ 36 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? e8 09 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? f8" );
	g_aInlinedOffsets[ 37 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? 50 e8 ? ? ? ? 8b 4c 24 34 83 c4 0c" );
	g_aInlinedOffsets[ 38 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 74" );
	g_aInlinedOffsets[ 39 ] = g_Utils.FindPattern( "client.dll", "? ? ? ? c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 01 00 00 00 c7 05 ? ? ? ? ff ff ff ff c7 05 ? ? ? ? 00 00 00 00 c7 05 ? ? ? ? 00 00 00 00 c6 05 ? ? ? ? 00 c7 05 ? ? ? ? ? ? ? ? c7 05 ? ? ? ? f0 33" );
}