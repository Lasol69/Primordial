#include "Game.hpp"

#include <unordered_map>

class CNetManager
{

public:

	std::unordered_map< std::string, RecvTable* > m_aTables;
	std::unordered_map< uint32_t, uint16_t > offsets;

	int GetOffset(const char* tableName, const char* propName);
	int GetProperty(const char* tableName, const char* propName, RecvProp** prop = 0);
	int GetProperty(RecvTable* recvTable, const char* propName, RecvProp** prop = 0);

	int GetProperties(RecvTable* pTable, std::string sTable);

	static CNetManager& Get()
	{
		static CNetManager instance;
		return instance;
	}

private:

	RecvTable* get_table(const char* tableName);

};