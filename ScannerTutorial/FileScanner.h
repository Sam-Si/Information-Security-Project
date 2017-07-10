#pragma once

class CFileScanner
{
public:
	CFileScanner(void);
	~CFileScanner(void);

	BOOL ScanFile(LPCSTR lpFileName, BOOL bDelete = FALSE);
    void ScanFolder(LPCSTR lpFolderName);
    void ScanProcess();
private:
	vector <char*> m_vDatabase;			// Hash database
	vector <char*> m_vExcludedExt;		// Excluded extension
};
