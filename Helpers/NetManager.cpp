#include "NetManager.hpp"

static std::unordered_map< uint32_t, RecvProxy_t > m_aProxies;

int CNetManager::GetOffset(const char* tableName, const char* propName)
{
	int offs = GetProperty(tableName, propName);

	if (!offs)
		return 0;

	return offs;
}

int CNetManager::GetProperty(const char* tableName, const char* propName, RecvProp** prop)
{
	RecvTable* recvTable = this->get_table(tableName);

	if (!recvTable)
		return 0;

	int offs = GetProperty(recvTable, propName, prop);

	if (!offs)
		return 0;

	return offs;
}

int CNetManager::GetProperty(RecvTable* recvTable, const char* propName, RecvProp** prop)
{
	int extrOffs = 0;

	for (int i = 0; i < recvTable->m_nProps; i++)
	{
		auto* recvProp = &recvTable->m_aProps[i];
		auto recvChild = recvProp->m_pDataTable;

		if (recvChild && (recvChild->m_nProps > 0))
		{
			int tmp = GetProperty(recvChild, propName, prop);

			if (tmp)
				extrOffs += (recvProp->m_iOffset + tmp);
		}

		if (strcmp(recvProp->m_pszName, propName)) //-V526
			continue;

		if (prop)
			*prop = recvProp;

		return (recvProp->m_iOffset + extrOffs);
	}

	return extrOffs;
}

int CNetManager::GetProperties( RecvTable* pTable, std::string sTable )
{
	int extrOffs = 0;

	for ( int i = 0; i < pTable->m_nProps; i++ )
	{
		auto* recvProp = &pTable->m_aProps[ i ];
		auto recvChild = recvProp->m_pDataTable;

		if ( recvChild && ( recvChild->m_nProps > 0 ) )
		{
			int tmp = GetProperties( recvChild, sTable );
			if ( tmp )
				extrOffs += ( recvProp->m_iOffset + tmp );
		}
		
		// lol
	}

	return extrOffs;
}

RecvTable* CNetManager::get_table(const char* tableName)
{
	if (m_aTables.empty())
		return 0;

	for (auto table : m_aTables)
		if (!strcmp(table.first.c_str(), tableName))
			return table.second;

	return 0;
}