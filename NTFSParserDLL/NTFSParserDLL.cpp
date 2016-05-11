/*
 * Copyright(C) 2016 Cyber Defense Institute, Inc.
 *
 * This program is modified from the following code: 
 *
 * https://github.com/clymb3r/PowerShell/blob/master/Invoke-NinjaCopy/NTFSParser/NTFSParserDLL/NTFSParserDLL.cpp
 * 
 * Copyright(C) 2013 Joe Bialek Twitter:@JosephBialek
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
//
// This code uses libraries released under GPLv2(or later) written by cyb70289 <cyb70289@gmail.com>

#include "stdafx.h"
#include "NTFS.h"
#include "NTFS_DataType.h"


using namespace std;

struct FileInfo_t
{
	CNTFSVolume* volume;
	CFileRecord* fileRecord;
	CIndexEntry* indexEntry;
	CAttrBase* data;
};

extern "C" HANDLE __declspec(dllexport) StealthOpenFile(char* filePathCStr)
{
	FileInfo_t* fileInfo = new FileInfo_t;
	string filePath = string(filePathCStr);
	_TCHAR volumeName = filePath.at(0);

	BOOL isADS = false;
	string ads_s;
	_TCHAR *ads;
	DWORD idx_ads;

	if ((idx_ads = filePath.find_first_of(':', 2)) != string::npos) {
		isADS = true;
		ads_s = filePath.substr(idx_ads + 1);
		ads = new _TCHAR[ads_s.size()];
		filePath = filePath.substr(0, idx_ads);
		sprintf(ads, "%s", ads_s.c_str());
	}

	fileInfo->volume = new CNTFSVolume(volumeName);
	if (!fileInfo->volume->IsVolumeOK())
	{
		return NULL;
	}

	//Parse root directory
	fileInfo->fileRecord = new CFileRecord(fileInfo->volume);
	fileInfo->fileRecord->SetAttrMask(MASK_INDEX_ROOT | MASK_INDEX_ALLOCATION);

	if (!fileInfo->fileRecord->ParseFileRecord(MFT_IDX_ROOT))
	{
		return NULL;
	}
	if (!fileInfo->fileRecord->ParseAttrs())
	{
		return NULL;
	}

	//Find subdirectory
	fileInfo->indexEntry = new CIndexEntry;
	int dirs = filePath.find(_T('\\'), 0);
	int dire = filePath.find(_T('\\'), dirs+1);

	while (dire != string::npos)
	{
		string pathname = filePath.substr(dirs+1, dire-dirs-1);
		const _TCHAR* pathnameCStr = (const _TCHAR*)pathname.c_str();
		if (fileInfo->fileRecord->FindSubEntry(pathnameCStr, *(fileInfo->indexEntry)))
		{
			if (!fileInfo->fileRecord->ParseFileRecord(fileInfo->indexEntry->GetFileReference()))
			{
				return NULL;
			}

			if (!fileInfo->fileRecord->ParseAttrs())
			{
				if (fileInfo->fileRecord->IsCompressed())
				{
					return NULL;
				}
				else if (fileInfo->fileRecord->IsEncrypted())
				{
					return NULL;
				}
				else
				{
					return NULL;
				}
			}
		}
		else
		{
			return NULL;
		}


		dirs = dire;
		dire = filePath.find(_T('\\'), dirs+1);
	}

	string fileName = filePath.substr(dirs+1, filePath.size()-1);
	const _TCHAR* fileNameCStr = (const _TCHAR*)fileName.c_str();
	if (fileInfo->fileRecord->FindSubEntry(fileNameCStr, *(fileInfo->indexEntry)))
	{
		if (!fileInfo->fileRecord->ParseFileRecord(fileInfo->indexEntry->GetFileReference()))
		{
			return NULL;
		}

		fileInfo->fileRecord->SetAttrMask(MASK_DATA);
		if (!fileInfo->fileRecord->ParseAttrs())
		{
			return NULL;
		}

		if (isADS) {
			fileInfo->data = (CAttrBase*)fileInfo->fileRecord->FindStream(ads);
		}
		else {
			fileInfo->data = (CAttrBase*)fileInfo->fileRecord->FindStream();
		}

		return fileInfo;
	}

	return NULL;
}

// add filesize argument
extern "C" DWORD __declspec(dllexport) StealthReadFile(FileInfo_t* fileInfo, BYTE* buffer, DWORD bufferSize, ULONGLONG offset, DWORD* bytesRead, ULONGLONG* dataRemaining, ULONGLONG fileSize)
{
	if (fileInfo->data)
	{
//		ULONGLONG dataLength = (ULONGLONG)fileInfo->data->GetDataSize();
		ULONGLONG dataLength = fileSize; // changed for datarun around multiple record
		ULONGLONG fullDataLength = dataLength;

		dataLength = dataLength - offset;
		if (dataLength > bufferSize)
		{
			dataLength = bufferSize;
		}
		if (dataLength > MAXUINT32)
		{
			return 1;
		}
			
		DWORD len;
		if (fileInfo->data->ReadData(offset, buffer, (DWORD)dataLength, &len) && len == (DWORD)dataLength)
		{
			*bytesRead = len;
			*dataRemaining = fullDataLength - len - offset;
			return 0; //Success
		}
		return 3;
	}
	return 2;
}


extern "C" void __declspec(dllexport) StealthCloseFile(FileInfo_t* fileInfo)
{
	delete (fileInfo->data);
	delete (fileInfo->indexEntry);
	delete (fileInfo->volume);
	delete fileInfo;
}
