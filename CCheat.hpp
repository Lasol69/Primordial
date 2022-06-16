class CCheat
{

public:

	void Init( );

private:

	__forceinline void SetupUserData( );
	__forceinline void SetupNetvars( );
	__forceinline void SetupOffsets( );
	__forceinline void SetupHooks( );
	__forceinline void SetupGameUpdates( );

	__forceinline void InitAddresses( );

};