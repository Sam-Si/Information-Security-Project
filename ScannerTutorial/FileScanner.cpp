#include "StdAfx.h"
#include "FileScanner.h"
#include "md5.h"


CFileScanner::CFileScanner(void)
{
	// Fill database (use lower case)
	m_vDatabase.push_back("44d88612fea8a8f36de82e1278abb02f");	// eicar.com hash
	m_vDatabase.push_back("7e28c727e6f5c43179254e2ccb6ffd3a");	// Some new folder.exe worm
	m_vDatabase.push_back("aa558d649dab330e989b9a95930125a0");  // Some new virus defined by me
	m_vDatabase.push_back("abbd7605ac274d59f08939e2cfe359dc");  // Some new virus defined by me
	m_vDatabase.push_back("bc807126c0da4446cd370aa016edb99d");  // Some new virus defined by me
	//m_vDatabase.push_back("");  // Some new virus defined by me
	//m_vDatabase.push_back("");  // Some new virus defined by me
	//m_vDatabase.push_back("");  // Some new virus defined by me


	m_vExcludedExt.push_back("txt");
	m_vExcludedExt.push_back("ini");
	m_vExcludedExt.push_back("inf");
	m_vExcludedExt.push_back("doc");
	m_vExcludedExt.push_back("rtf");
	m_vExcludedExt.push_back("cfg");

	m_vExcludedExt.push_back("zip");
	m_vExcludedExt.push_back("rar");
	m_vExcludedExt.push_back("tar");
	m_vExcludedExt.push_back("gz");
	m_vExcludedExt.push_back("bz2");

	m_vExcludedExt.push_back("jpg");
	m_vExcludedExt.push_back("jpeg");
	m_vExcludedExt.push_back("png");
	m_vExcludedExt.push_back("bmp");
	m_vExcludedExt.push_back("mp4");
	m_vExcludedExt.push_back("MP4");
	m_vExcludedExt.push_back("mov");
	m_vExcludedExt.push_back("m4v");
	m_vExcludedExt.push_back("flv");
	m_vExcludedExt.push_back("FLV");

}

CFileScanner::~CFileScanner(void)
{
}

/*
	Scan for a single file
		lpFileName		Filename to scan (full path)
		bDelete			Delete file if found infected
	Return Value
		TRUE			File is infected
		FALSE			File is clean
*/
BOOL CFileScanner::ScanFile(LPCSTR lpFileName, BOOL bDelete)
{
	// Get file extension
	const char *lpExt = lpFileName;
	for (unsigned int i=0; i<strlen(lpFileName); i++) {
		if (lpFileName[i] == '.')
			lpExt = lpFileName + i + 1;
	}

	// Exclude excluded file extension
	for (size_t i=0; i<m_vExcludedExt.size(); i++) {
		if (_stricmp(lpExt, m_vExcludedExt[i]) == 0)
			return FALSE;
	}

	HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;							// Error, cannot open file. Return FALSE

	// Get file size and proceed if file is below 50MB
	DWORD dwFileSize = GetFileSize(hFile, NULL);

	if (dwFileSize > 52428800)					// http://www.google.com/search?q=50megabyte+to+bytes
		return FALSE;							// More than 50MB

	// Start hash
	md5_state_t state;
	md5_byte_t digest[16];
	char buffer[1024];
	char szHash[16*2 + 1];
	DWORD dwRead, dwTotal = 0;

	md5_init(&state);
	do {
		ReadFile(hFile, buffer, 1024, &dwRead, NULL);
		md5_append(&state, (const md5_byte_t *)buffer, dwRead);

		dwTotal += dwRead;
	} while (dwTotal < dwFileSize);
	md5_finish(&state, digest);

	// Convert hash to hex
	for (int di = 0; di < 16; ++di)
	    sprintf(szHash + di * 2, "%02x", digest[di]);

	CloseHandle(hFile);				// Close file handle
	// End hash

	// Compare md5 with database
	for (size_t i=0; i<m_vDatabase.size(); i++)
	{
		if (strcmp(szHash, m_vDatabase[i]) == 0)
		{
			// Write output to console
			printf("Found: %s\n", lpFileName);

			// Delete file
			if (bDelete) DeleteFile(lpFileName);

			return TRUE;					// We found matched hash with database
		}
	}

	// Default return value
	return FALSE;
}

/*
	Scan drive/folder and its subfolder
		lpFolderName	Folder to scan (full path)
	Return Value
		None
*/
void CFileScanner::ScanFolder(LPCSTR lpFolderName)
{
	WIN32_FIND_DATA tFindData;
	HANDLE hFind;

	char szFolder[MAX_PATH];			// Folder with trailing backslash
	char szFind[MAX_PATH];				// Folder name with wildcat
	vector <char*> vFolder;				// Store subfolder. Used to scan subfolder

	// If file, just scan
	if (!(GetFileAttributes(lpFolderName) & FILE_ATTRIBUTE_DIRECTORY)) {
		ScanFile(lpFolderName, TRUE);
		return;
	}

	// Copy folder name to szNewFolder and add trailing backslash if neccessary
	strcpy(szFolder, lpFolderName);		// Copy string to szFolder
	if (szFolder[strlen(szFolder) - 1] != '\\')
		strcat(szFolder, "\\");			// Add trailing backslash

	// Add wildcat
	strcpy(szFind, szFolder);			// Copy szFolder
	strcat(szFind, "*");				// Add wildcat

	hFind = FindFirstFile(szFind, &tFindData);
	if (hFind == INVALID_HANDLE_VALUE)
		return;

	do {
		// Directory, copy to vFolder
		if (tFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			// File name is not . or ..
			if (!strcmp(tFindData.cFileName, ".") == 0 &&
				!strcmp(tFindData.cFileName, "..") == 0)
			{
				// Find maximum length with null string
				unsigned int nLen = strlen(szFolder) + strlen(tFindData.cFileName) + 1;

				// Create a new string
				char *lpFolder = new char[nLen];
				if (lpFolder == NULL) return;

				// Construct path
				strcpy(lpFolder, szFolder);
				strcat(lpFolder, tFindData.cFileName);

				// Add to vector array for later processing
				vFolder.push_back(lpFolder);
			}
		}
		else
		{
			// Find maximum length with null string
			unsigned int nLen = strlen(szFolder) + strlen(tFindData.cFileName) + 1;

			// Create a new string
			char *lpFile = new char[nLen];
			if (lpFile == NULL) return;

			// Construct path
			strcpy(lpFile, szFolder);
			strcat(lpFile, tFindData.cFileName);

			// Scan this file
			ScanFile(lpFile, TRUE);

			// Free memory
			delete []lpFile;
		}
	} while (FindNextFile(hFind, &tFindData) != 0);

	// We are done scanning this folder
	FindClose(hFind);

	// Now, let's scan subfolder
	for (size_t i=0; i<vFolder.size(); i++)
	{
		if (vFolder[i] != NULL) {
			ScanFolder(vFolder[i]);			// Call this function
			delete []vFolder[i];			// Free memory
		}
	}
}

void CFileScanner::ScanProcess()
{
	DWORD dwPIDs[1024], cbNeeded, cProcesses;

	// Enumerate running processes
	if (!EnumProcesses(dwPIDs, sizeof(dwPIDs), &cbNeeded))
        return;

	// Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

	for (unsigned int i=0; i<cProcesses; i++)
	{
		HMODULE hMods[1024];
		DWORD cbNeeded;
		HANDLE hProcess;

		// Get a list of all the modules in this process.
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, dwPIDs[i]);
		if (NULL != hProcess)
		{
			if(EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
			{
				for (unsigned int i = 0; i<(cbNeeded / sizeof(HMODULE)); i++ )
				{
					char szModName[MAX_PATH];

					// Get the full path to the module's file.
					if (GetModuleFileNameEx(hProcess, hMods[i], szModName, MAX_PATH))
					{
						// Scan file and if found, don't delete it because the file is in use
						if (ScanFile(szModName, FALSE))
						{
							// Terminate current process first, so we can delete file
							TerminateProcess(hProcess, 0);

							// Delete the file
							DeleteFile(szModName);

							// Continue to next process
							goto SKIP;
						}
					}
				}
			}
SKIP:
			// Close process handle
			CloseHandle( hProcess );
		}
	}
}