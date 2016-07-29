#pragma once

#include "..\NTFSParserDLL\NTFS.h"
#include "..\NTFSParserDLL\NTFS_DataType.h"

struct FileInfo_t
{
	CNTFSVolume* volume;
	CFileRecord* fileRecord;
	CIndexEntry* indexEntry;
	CAttrBase* data;
};
