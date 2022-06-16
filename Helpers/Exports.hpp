#include <iostream>

extern "C"
{
	__declspec( dllexport ) uint8_t* g_aHooks[ 70 ];
	__declspec( dllexport ) uint8_t* g_aOffsets[ 222 ];
	__declspec( dllexport ) uint8_t* g_aInlinedOffsets[ 40 ];
	__declspec( dllexport ) uint8_t* g_aNetOffsets[ 90 ];
}