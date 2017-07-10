// ScannerTutorial.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "FileScanner.h"

int main(int argc, char* argv[])
{
	CFileScanner oScan;
	//oScan.ScanProcess();
	oScan.ScanFolder("G:\\");
	// Print usage
	if (argc == 1)
	{
		//printf("ScannerTutorial.exe [filename] [foldername]\n");
	}

	for (int i=1; i<argc; i++)
	{
		printf("Scanning: %s\n", argv[i]);
		oScan.ScanFolder(argv[i]);
	}
	getchar();
	return 0;
}

