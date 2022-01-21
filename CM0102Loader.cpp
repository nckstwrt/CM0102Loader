#include <windows.h>
#include <stdio.h>
#include "resource.h"

const DWORD ExpandedExeSize = 0x8DC000;
const DWORD OriginalExeSize = 7192576;

class HexPatch
{
public:
	HexPatch(unsigned int offset, const char *hex)
	{
		this->offset = offset;
		this->hex = hex;
	}

	unsigned int offset;
	const char *hex;
};

class Settings
{
public:
	Settings()
	{
		Year = 2001;
		SpeedMultiplier = 4.0;
		CurrencyMultiplier = 1.0;
		ColoredAttributes = true;
		DisableSplashScreen = true;
		Debug = false;
		DisableUnprotectedContracts = true;
		HideNonPublicBids = true;
		IncreaseToSevenSubs = true;
		RegenFixes = true;
		ForceLoadAllPlayers = false;
		AddTapaniRegenCode = false;
		UnCap20s = false;
		RemoveForeignPlayerLimit = false;
		NoWorkPermits = false;
		ChangeTo1280x800 = false;
		AutoLoadPatchFiles = false;
		strcpy(PatchFileDirectory, ".");
		strcpy(DataDirectory, "data");
		NoCD = false;
		DontExpandExe = false;
		strcpy(DumpEXE, "");
	}

	int ReadLine(FILE *fin, char *szAttribute, char *szValue, bool *gotEOF)
	{
		int Ret = 0;
		char szBuffer[100+MAX_PATH];
		int ptr = 0;
		while (true)
		{
			int c = getc(fin);
			if (c == '\n' || c == EOF)
			{
				if (c == EOF && gotEOF != NULL)
					*gotEOF = true;
				szBuffer[ptr] = 0;
				break;
			}
			if (c != '\r' && c != '"')
			{
				szBuffer[ptr++] = (char)c;
			}
		}
		if (strlen(szBuffer) > 1)
		{
			int attrNo = 0;
			char *szToken = strtok(szBuffer, " ");
			bool gotEquals = false;

			strcpy(szValue, "");
			while (szToken != NULL) 
			{ 
				switch (attrNo++)
				{
					case 0:
						strcpy(szAttribute, szToken);
						break;
					case 1:
						if (strcmp(szToken, "=") == 0)
							gotEquals = true;
						break;
					default:
						strcat(szValue, szToken);
						strcat(szValue, " ");
						if (gotEquals)
							Ret = 1;
						break;
				}
				szToken = strtok(NULL, " "); 
			}
			if (Ret == 1)
				szValue[strlen(szValue)-1] = 0; // Cut off the trailing space
		}
		return Ret;
	}

	void ReadSettings(char *szSettingsFile)
	{
		if (szSettingsFile == NULL || szSettingsFile[0] == 0)
			szSettingsFile = "CM0102Loader.ini";

		if (GetFileAttributes(szSettingsFile) != -1L)
		{
			char att[100], value[MAX_PATH];
			FILE *fin = fopen(szSettingsFile, "rt");
			
			while (true)
			{
				bool gotEOF = false;
				int ok = ReadLine(fin, att, value, &gotEOF);

				if (ok == 1)
				{
					if (stricmp(att, "year")==0)
					{
						Year = atoi(value);
					}
					else
					if (stricmp(att, "ColouredAttributes") == 0)
					{
						ColoredAttributes = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "DisableSplashScreen") == 0)
					{
						DisableSplashScreen = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "Debug") == 0)
					{
						Debug = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "DisableUnprotectedContracts") == 0)
					{
						DisableUnprotectedContracts = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "HideNonPublicBids") == 0)
					{
						HideNonPublicBids = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "IncreaseToSevenSubs") == 0)
					{
						IncreaseToSevenSubs = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "RegenFixes") == 0)
					{
						RegenFixes = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "ForceLoadAllPlayers") == 0)
					{
						ForceLoadAllPlayers = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "AddTapaniRegenCode") == 0)
					{
						AddTapaniRegenCode = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "UnCap20s") == 0)
					{
						UnCap20s = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "RemoveForeignPlayerLimit") == 0)
					{
						RemoveForeignPlayerLimit = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "NoWorkPermits") == 0)
					{
						NoWorkPermits = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "ChangeTo1280x800") == 0)
					{
						ChangeTo1280x800 = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "AutoLoadPatchFiles") == 0)
					{
						AutoLoadPatchFiles = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "PatchFileDirectory") == 0)
					{
						strcpy(PatchFileDirectory, value);
					}
					else
					if (stricmp(att, "DataDirectory") == 0)
					{
						strcpy(DataDirectory, value);
					}
					else
					if (stricmp(att, "NoCD") == 0)
					{
						NoCD = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "DontExpandExe") == 0)
					{
						DontExpandExe = (toupper(value[0]) == 'T');
					}
					else
					if (stricmp(att, "DumpEXE") == 0)
					{
						strcpy(DumpEXE, value);
					}
					else
					if (stricmp(att, "SpeedMultiplier")==0)
					{
						SpeedMultiplier = atof(value);
					}
					else
					if (stricmp(att, "CurrencyMultiplier")==0)
					{
						CurrencyMultiplier = atof(value);
					}
					else
						MessageBox(0, "CM0102Loader.ini has settings that are not recognised!", "CM0102Loader Error", MB_ICONEXCLAMATION);
				}

				if (gotEOF)
					break;
			}

			fclose(fin);
		}
		else
		{
			FILE *fout = fopen(szSettingsFile, "wt");
			if (fout != NULL)
			{
				fprintf(fout, "Year = 2001\n");
				fprintf(fout, "SpeedMultiplier = 4\n");
				fprintf(fout, "CurrencyMultiplier = 1.0\n");
				fprintf(fout, "ColouredAttributes = true\n");
				fprintf(fout, "DisableUnprotectedContracts = true\n");
				fprintf(fout, "HideNonPublicBids = true\n");
				fprintf(fout, "IncreaseToSevenSubs = true\n");
				fprintf(fout, "RegenFixes = true\n");
				fprintf(fout, "ForceLoadAllPlayers = false\n");
				fprintf(fout, "AddTapaniRegenCode = false\n");
				fprintf(fout, "UnCap20s = false\n");
				fprintf(fout, "RemoveForeignPlayerLimit = false\n");
				fprintf(fout, "NoWorkPermits = false\n");
				fprintf(fout, "ChangeTo1280x800 = false\n");
				fprintf(fout, "AutoLoadPatchFiles = false\n");
				fprintf(fout, "PatchFileDirectory = .\n");
				fprintf(fout, "DataDirectory = data\n");
				fprintf(fout, "DisableSplashScreen = true\n");
				fprintf(fout, "Debug = false\n");
				fclose(fout);
			}
			else
			{
				MessageBox(0, "Unable to write out Settings File!", "CM0102Loader Error", MB_ICONEXCLAMATION);
			}
		}
	}

	short Year;
	double SpeedMultiplier;
	double CurrencyMultiplier;
	bool ColoredAttributes;
	bool DisableSplashScreen;
	bool Debug;
	bool DisableUnprotectedContracts;
	bool HideNonPublicBids;
	bool IncreaseToSevenSubs;
	bool RegenFixes;
	bool ForceLoadAllPlayers;
	bool AddTapaniRegenCode;
	bool UnCap20s;
	bool RemoveForeignPlayerLimit;
	bool NoWorkPermits;
	bool ChangeTo1280x800;
	bool AutoLoadPatchFiles;
	char PatchFileDirectory[MAX_PATH];
	char DataDirectory[MAX_PATH];
	bool NoCD;
	bool DontExpandExe;
	char DumpEXE[MAX_PATH];
};


void WriteByte(HANDLE hProcess, DWORD addr, BYTE b)
{
	DWORD bytesWritten;
	DWORD base = 0x400000;
	if (addr >= 0x6DC000)
	{
		base = 0xDE7000;
		addr -= 0x6DC000;
	}
	WriteProcessMemory(hProcess, (void*)(base+addr), &b, 1, &bytesWritten);
}

void WriteWord(HANDLE hProcess, DWORD addr, WORD w)
{
	DWORD bytesWritten;
	WriteProcessMemory(hProcess, (void*)(0x400000+addr), &w, 2, &bytesWritten);
}

void WriteDWord(HANDLE hProcess, DWORD addr, DWORD dw)
{
	DWORD bytesWritten;
	WriteProcessMemory(hProcess, (void*)(0x400000+addr), &dw, 4, &bytesWritten);
}

void WriteDouble(HANDLE hProcess, DWORD addr, double d)
{
	DWORD bytesWritten;
	WriteProcessMemory(hProcess, (void*)(0x400000+addr), &d, sizeof(double), &bytesWritten);
}

void WriteString(HANDLE hProcess, DWORD addr, const char *szString)
{
	DWORD bytesWritten;
	WriteProcessMemory(hProcess, (void*)(0x400000+addr), (void*)szString, strlen(szString)+1, &bytesWritten);
}

void ApplyPatch(HANDLE hProcess, HexPatch* patch)
{
	char hexTemp[3];
	hexTemp[2] = 0;
	for (unsigned int j = 0; j < strlen(patch->hex); j+=2)
	{
		hexTemp[0] = patch->hex[j]; 
		hexTemp[1] = patch->hex[j+1]; 
		BYTE byte = (BYTE)strtol(hexTemp, NULL, 16);
		WriteByte(hProcess, patch->offset+(j/2), byte);
	}
}

void ApplyPatch(HANDLE hProcess, HexPatch* patch[], int count)
{
	for (int i = 0; i < count; i++)
	{
		ApplyPatch(hProcess, patch[i]);
	}
}

void ApplyPatch(BYTE *pFileBuffer, HexPatch* patch[], int count)
{
	for (int i = 0; i < count; i++)
	{
		char hexTemp[3];
		hexTemp[2] = 0;
		for (unsigned int j = 0; j < strlen(patch[i]->hex); j+=2)
		{
			hexTemp[0] = patch[i]->hex[j]; 
			hexTemp[1] = patch[i]->hex[j+1]; 
			BYTE byte = (BYTE)strtol(hexTemp, NULL, 16);
			pFileBuffer[patch[i]->offset+(j/2)] = byte;
		}
	}
}

void FreePatch(HexPatch* patch[], int count)
{
	for (int i = 0; i < count; i++)
	{
		delete patch[i];
	}
}

void YearChanger(HANDLE hProcess, WORD year)
{
	int i;
    int startYear[] = { 0x13386, 0x140e5, 0x224f0, 0x44270, 0x44297, 0x55830, 0x5583d, 0x5f4ee, 0x5f97c, 0x5f981, 0x16fc63, /*0x18b387,*/ 0x1aee53, 0x1bab86, 0x1bac32, 0x1BACE7, 0x1bb6ab, 0x1BC2C1, 0x1BC420, 0x1bc8b2, 0x1BF0AE, 0x1C070E, 0x1c3068, 0x1db242, 0x2673c3, 0x267495, 0x267582, 0x26766d, 0x26775a, 0x267829, 0x2678f8, 0x2679c6, 0x267aa1, 0x267b81, 0x267c6d, 0x267d5a, 0x267e55, 0x267f50, 0x268043, 0x268149, 0x268236, 0x268324, 0x268411, 0x2684ff, 0x2685ed, 0x2686bc, 0x2687ac, 0x268899, 0x268987, 0x268a77, 0x268b65, 0x268c54, 0x268d40, 0x268e2f, 0x268f1d, 0x26900b, 0x2690da, /*0x37d858,*/ 0x3d2410, 0x41b93d, 0x430591, 0x430598, 0x4305dc, 0x430a64, 0x430f8e, 0x430fb4, 0x43129a, 0x4312b4, 0x431608, 0x431622, 0x4318ad, 0x4318c6, 0x431b54, 0x431b6d, 0x431e66, 0x431e80, 0x4320b3, 0x4320cd, 0x432324, 0x432577, 0x43290d, 0x433055, 0x43339d, 0x4336eb, 0x433c84, 0x433f8e, 0x434382, 0x43475d, 0x434aad, 0x434dfd, 0x435297, 0x435c39, 0x435fca, 0x4362EF, 0x43668e, 0x436a55, 0x436d68, 0x4371a5, 0x4371d5, 0x4374e9, 0x43805d, 0x438357, 0x43869f, 0x456ce0, 0x4fddd2, 0x5041f3, 0x5059B9, 0x5291B4 };
    int startYearMinus19[] = { 0x12638d, 0x1263Ba };
    int startYearMinus3[] = { 0x3e6819, 0x461E36 };
    int startYearMinus2[] = { 0x135d83, 0x135df2 };
    int startYearMinus1[] = { 0x55fd1, 0xdc02c, 0x12d2e2, 0x2B4FF4, 0x3e68fe, 0x3e691f, 0x45e98f };
    int startYearPlus1[] = { 0xdc135 };
    int startYearPlus2[] = { 0x12d321, 0x29e84e /*, 0x45b841, 0x45b898,  0x45c40c */ };
    int startYearPlus3[] = { 0xdc113, 0x19ba24 };
    int startYearPlus9[] = { 0x135d89, 0x135df8, 0x3A3D64, 0x3A3FD1, 0x3A4224, 0x3A4844, 0x3A4CB4, 0x3A4F68, 0x3A4FA1 };

	for (i = 0; i < sizeof(startYear)/sizeof(int); i++)
		WriteWord(hProcess, startYear[i], year);

	for (i = 0; i < sizeof(startYearMinus19)/sizeof(int); i++)
		WriteWord(hProcess, startYearMinus19[i], year-19);

	for (i = 0; i < sizeof(startYearMinus3)/sizeof(int); i++)
		WriteWord(hProcess, startYearMinus3[i], year-3);

	for (i = 0; i < sizeof(startYearMinus2)/sizeof(int); i++)
		WriteWord(hProcess, startYearMinus2[i], year-2);

	for (i = 0; i < sizeof(startYearMinus1)/sizeof(int); i++)
		WriteWord(hProcess, startYearMinus1[i], year-1);

	for (i = 0; i < sizeof(startYearPlus1)/sizeof(int); i++)
		WriteWord(hProcess, startYearPlus1[i], year+1);

	for (i = 0; i < sizeof(startYearPlus2)/sizeof(int); i++)
		WriteWord(hProcess, startYearPlus2[i], year+2);

	for (i = 0; i < sizeof(startYearPlus3)/sizeof(int); i++)
		WriteWord(hProcess, startYearPlus3[i], year+3);

	for (i = 0; i < sizeof(startYearPlus9)/sizeof(int); i++)
		WriteWord(hProcess, startYearPlus9[i], year+9);

	// Special
    WORD mod4year = ((year + 1) - ((year - 1) % 4));
	WriteWord(hProcess, 0x18B387, mod4year);

    // Special 2 (the calc for season selection can cause England 18/09 without this)
	WriteByte(hProcess, 0x41e9ca, 0x64);

    // Special 3 - Need to fix Euro for 2019
    if ((year % 4) == 3)
		WriteWord(hProcess, 0x1f9c0a, year - 7);

    // Special 4 - World Cup - Oceania League Fix - So 2012, etc will work
    if ((year % 4) == 0)
    {
		WriteWord(hProcess, 0x5182dc, year);
		WriteByte(hProcess, 0x518473, 0xeb);
		WriteWord(hProcess, 0x52036e, year);
		WriteByte(hProcess, 0x5204b8, 0xeb);
    }

	// Special 5 - For going back in time (fixes Euros - might be a better generic fix for euros for the future too (unlike Special 3))
    if (year < 2000)
    {
        // Euro
        for (i = 1960; i < 2000; i+=4)
        {
            if (i >= year)
            {
				WriteWord(hProcess, 0x1F9C0a, (i - 4));
                break;
            }
        }

        // World Cup
        for (i = 1930; i < 2000; i += 4)
        {
            if (i >= year)
            {
				WriteWord(hProcess, 0x1F99A1, (i - 5));
				WriteWord(hProcess, 0x1F99BC, (i - 4));
                break;
            }
        }

        // Turn off World Cup 1438 error
		HexPatch nop1438(0x52F2AC, "9090909090");
		ApplyPatch(hProcess, &nop1438);
    }
}

void SpeedHack(HANDLE hProcess, double multiplier)
{
	WriteWord(hProcess, 0x5472ce, (WORD)((10000.0 / multiplier)+0.5));
}

void ApplyPatchFile(HANDLE hProcess, char *szPatchFile)
{
	char lineBuffer[1000];
	char part1[100], part2[100], part3[100];

	FILE *fin = fopen(szPatchFile, "rt");
	if (fin != NULL)
	{
		int bytePtr = 0;
		int bytesRead;
		
		while (true)
		{
			bytesRead = fread(&lineBuffer[bytePtr], 1, 1, fin);
			if (bytesRead == 0 || lineBuffer[bytePtr] == 0xa)
			{
				lineBuffer[bytePtr] = 0;
				if (bytePtr > 0 && lineBuffer[0] >= '0' && lineBuffer[0] <= '9')
				{
					if (sscanf(lineBuffer, "%s %s %s\n", part1, part2, part3) == 3)
					{
						DWORD addr = strtol(part1, NULL, 16);
						BYTE value = (BYTE)strtol(part3, NULL, 16);
						WriteByte(hProcess, addr, value);
					}
				}
				bytePtr = 0;
			}
			else
				bytePtr++;

			if (bytesRead == 0)
				break;
		}

		fclose(fin);
	}
}

void AutoLoadPatchFiles(HANDLE hProcess, char *szDirectory)
{
	char fullPath[MAX_PATH];
	WIN32_FIND_DATA findData;

	if (szDirectory == NULL || szDirectory[0] == 0)
		szDirectory = ".";

	sprintf(fullPath, "%s\\*.patch", szDirectory);

	HANDLE hFind = FindFirstFile(fullPath, &findData);

	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			sprintf(fullPath, "%s\\%s", szDirectory, findData.cFileName);
			ApplyPatchFile(hProcess, fullPath);
		} while (FindNextFile(hFind, &findData) != 0);
		FindClose(hFind);
	}
}

void ChangeDataDirectory(HANDLE hProcess, const char *szDataDirectory)
{
	if (GetFileAttributes(szDataDirectory) == FILE_ATTRIBUTE_DIRECTORY)
	{
		WriteString(hProcess, 0x5919A8, szDataDirectory);
		WriteDWord(hProcess, 0x1681F9, 0x9919A8);
		WriteDWord(hProcess, 0x16820E, 0x9919A8);
		WriteDWord(hProcess, 0x50BC94, 0x9919A8);
		WriteDWord(hProcess, 0x50BCB0, 0x9919A8);
		WriteDWord(hProcess, 0x50BD20, 0x9919A8);
	}
	else
		MessageBox(0, "Failed to change data directory.\r\nPlease ensure DataDirectory is set to a directory without spaces in the name.", "CM0102Loader Error", MB_ICONEXCLAMATION);
}

void OutputResourceFile(int ResId, const char *szFileOut)
{
	HMODULE hModule;
	HRSRC hResource;
	HGLOBAL hMemory;
	DWORD dwSize;
	LPVOID lpAddress;
	FILE *fout;

	hModule = GetModuleHandle(NULL);
	hResource = FindResource(hModule, MAKEINTRESOURCE(ResId), "BINARY");
	hMemory = LoadResource(hModule, hResource);
	dwSize = SizeofResource(hModule, hResource);
	lpAddress = LockResource(hMemory);

	fout = fopen(szFileOut,"wb");
	if (fout)
	{
		fwrite(lpAddress, 1, dwSize, fout);
		fclose(fout);
	}

	UnlockResource(hMemory);
	FreeResource(hMemory);
	FreeLibrary(hModule);
}

void EnableDebugPriv()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
 
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
 
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
 
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
 
    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
 
    CloseHandle(hToken);
}

// https://groups.google.com/g/comp.os.ms-windows.programmer.win32/c/Md3GKPc279A/m/Ax3bYgXhpD8J
ULONG protect(ULONG characteristics)
{
	static const ULONG mapping[] = { PAGE_NOACCESS, PAGE_EXECUTE, PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_EXECUTE_READWRITE };
	return mapping[characteristics >> 29];
}

BYTE *CreateExpandedExeInMemory(char *szExeName)
{
	// Patch to add extra storage to the exe
	HexPatch* addextraspaceheader[] = { new HexPatch(254, "05"), new HexPatch(330, "be"), new HexPatch(504, "0060"), new HexPatch(544, "000002"), new HexPatch(584, "00e0"), new HexPatch(624, "0020"), new HexPatch(656, "2e6e69636b"), new HexPatch(666, "20"), new HexPatch(669, "709e"), new HexPatch(674, "20"), new HexPatch(677, "c06d"), new HexPatch(692, "200000e0") };

	// Load the cm0102.exe into memory (into a block the size of the expanded cm0102.exe) 
	BYTE *pFileBuffer = new BYTE[ExpandedExeSize];
	DWORD dwFileSize, bytesRead;
	HANDLE hFile = CreateFile(szExeName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	dwFileSize = SetFilePointer(hFile, 0, NULL, SEEK_END);
	ZeroMemory(pFileBuffer, ExpandedExeSize);
	SetFilePointer(hFile, 0, NULL, SEEK_SET);
	ReadFile(hFile, pFileBuffer, dwFileSize, &bytesRead, NULL);
	CloseHandle(hFile);

	// Apply Expanded EXE patch to the in memory exe
	ApplyPatch(pFileBuffer, addextraspaceheader, sizeof(addextraspaceheader)/sizeof(HexPatch*)); 

	// Free up the patch and ntdll.dll
	FreePatch(addextraspaceheader, sizeof(addextraspaceheader)/sizeof(HexPatch*));

	return pFileBuffer;
}


BOOL CreateExpandedProcess(char *szExeName, STARTUPINFO *si, PROCESS_INFORMATION *pi)
{
	BOOL bRet = FALSE;

	// Firstly check the filesize, we don't want to expand an already expanded exe
	DWORD dwFileSize;
	HANDLE hFile = CreateFile(szExeName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		dwFileSize = GetFileSize(hFile, NULL);
		CloseHandle(hFile);

		if (dwFileSize == OriginalExeSize)
		{
			// Set up params
			si->cb = sizeof(STARTUPINFO);

			// Load up ZwUnmapViewOfSection function from ntdll.dll
			typedef unsigned long (__stdcall *pfZwUnmapViewOfSection)(HANDLE, PVOID);   
			pfZwUnmapViewOfSection ZwUnmapViewOfSection = NULL;   
			HMODULE m = LoadLibrary(TEXT("ntdll.dll"));
			if (m != NULL)
			{
				ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(m, "ZwUnmapViewOfSection");

				if (ZwUnmapViewOfSection != NULL)
				{
					// Create suspended cm0102.exe
					bRet = CreateProcess(szExeName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, si, pi);

					if (bRet)
					{
						// Get Context and Unmap it (EBX holds the pointer to the PBE(Process Enviroment Block) - https://stackoverflow.com/questions/305203/createprocess-from-memory-buffer)
						PVOID x; 
						CONTEXT context = { CONTEXT_INTEGER };
						if (GetThreadContext(pi->hThread, &context) != 0)
						{
							ReadProcessMemory(pi->hProcess, PCHAR(context.Ebx) + 8, &x, sizeof(x), 0);
							ZwUnmapViewOfSection(pi->hProcess, x);

							BYTE *pFileBuffer = CreateExpandedExeInMemory(szExeName);
							
							// Start writing the newly patched cm0102.exe into memory
							PIMAGE_NT_HEADERS nt = PIMAGE_NT_HEADERS(PCHAR(pFileBuffer) + PIMAGE_DOS_HEADER(pFileBuffer)->e_lfanew);

							PVOID q = VirtualAllocEx(pi->hProcess, PVOID(nt->OptionalHeader.ImageBase), nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

							WriteProcessMemory(pi->hProcess, q, pFileBuffer, nt->OptionalHeader.SizeOfHeaders, 0);

							PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);

							ULONG oldProtect;
							for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++) 
							{
								WriteProcessMemory(pi->hProcess, PCHAR(q) + sect[i].VirtualAddress, PCHAR(pFileBuffer) + sect[i].PointerToRawData, sect[i].SizeOfRawData, 0);
								VirtualProtectEx(pi->hProcess, PCHAR(q) + sect[i].VirtualAddress, sect[i].Misc.VirtualSize, protect(sect[i].Characteristics), &oldProtect);
							}

							// HACK: There's a part that's not getting written: 006DA00E to 006DB236 (inclusive) - however, writing this in - tends to break the running exe ??
							//WriteProcessMemory(pi->hProcess, (void*)(0x400000 + 0x006DA00E), pFileBuffer + 0x006DA00E, (0x006DB236-0x006DA00E)+1, NULL);

							WriteProcessMemory(pi->hProcess, PCHAR(context.Ebx) + 8, &q, sizeof(q), 0);

							context.Eax = ULONG(q) + nt->OptionalHeader.AddressOfEntryPoint;

							SetThreadContext(pi->hThread, &context);

							// Free up the file buffer
							delete [] pFileBuffer;
						}
						else
						{
							// We have created the process, but cannot get context, so we should kill it and try another method
							TerminateProcess(pi->hProcess, 0);
							CloseHandle(pi->hThread);
							CloseHandle(pi->hProcess);
							bRet = false;
						}
					}
					else
						bRet = false;
				}

				FreeLibrary(m);
			}
		}
	}

	// Failed to load the process so try to create an expanded exe manually and load that
	if (!bRet)
	{
		char *szExeNameToLoad = "cm0102_expanded.exe";
		// Create an expanded exe manually
		if (GetFileAttributes(szExeNameToLoad) == -1L)
		{
			BYTE *pFileBuffer = CreateExpandedExeInMemory(szExeName);
			hFile = CreateFile(szExeNameToLoad, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
			WriteFile(hFile, pFileBuffer, ExpandedExeSize, &dwFileSize, NULL);
			CloseHandle(hFile);
			delete [] pFileBuffer;

		}
		bRet = CreateProcess(szExeNameToLoad, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, si, pi);
	}

	return bRet;
}

void SetXP3Compatibility(const char *szExeFullPath)
{
	int success;
	HKEY layers;
	const char *szCompatFlags = "~ DWM8And16BitMitigation RUNASADMIN WINXPSP3";
	success = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers", 0, NULL, 0, KEY_ALL_ACCESS | 0x0100 /*KEY_WOW64_64KEY*/, NULL, &layers, NULL);
	if (success == ERROR_SUCCESS)
	{
		success = RegSetValueExA(layers, (LPCSTR)szExeFullPath, 0, REG_SZ, (CONST BYTE*)szCompatFlags, strlen(szCompatFlags)+1);
		RegCloseKey(layers);
	}
}

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	Settings settings;

	HexPatch* colouredattributes[] = { new HexPatch(0x47ABF1, "e8f2b40e009090"), new HexPatch(0x47AFA3, "e840b10e0091"), new HexPatch(0x5660E8, "528b542410668b0c55f66096005ac39014c610c60fc60ec68cc50be788f7c4ffc0ffe0ffe0ffe0fe80fee0fd80fd80f480f3c0f2c2f162f160") };
	HexPatch* idlesensitivity[] = { new HexPatch(0xE243A, "85d27507668b15de6bdd0083c2fc83fa2c0f87c4080000e81a3d480090"), new HexPatch(0x5472D5, "79ee01"), new HexPatch(0x566120, "60689c1597"), new HexPatch(0x566126, "ff15387196"), new HexPatch(0x56612C, "85c07417684c6196"), new HexPatch(0x566135, "50ff15b87096"), new HexPatch(0x56613C, "85c07407ff74242490ffd061c204"), new HexPatch(0x56614B, "90536c656570"), new HexPatch(0x566152, "fe0de67098"), new HexPatch(0x566158, "750ec605e67098"), new HexPatch(0x566160, "216a14e818"), new HexPatch(0x566168, "e95379feff9090906a60909090e8a6ffffff33dbc390909060a19c189f"), new HexPatch(0x566186, "85c07524689c1597"), new HexPatch(0x56618F, "ff15387196"), new HexPatch(0x566195, "85c0741b684c6196"), new HexPatch(0x56619E, "50ff15b87096"), new HexPatch(0x5661A5, "85c0740ba39c189f"), new HexPatch(0x5661AE, "ff742424ffd061c204"), new HexPatch(0x5661B8, "600fb7461283c01c662b05922cae"), new HexPatch(0x5661C7, "807f0f0f937e1a8a472ae822"), new HexPatch(0x5661D6, "28472a8a473af6d8e815"), new HexPatch(0x5661E3, "0410"), new HexPatch(0x5661E6, "473ae83b"), new HexPatch(0x5661ED, "e872"), new HexPatch(0x5661F2, "61c3909090903c9c537e07e8be6dfaff5bc333db6a0de8b36dfaff2ad86a0de8aa6dfaff2ad86a0de8a16dfaff2ad89383c40c5bc3908a4739e8c8ffffff040d2847398a4724e8bbffffff04102847248a471ee8aeffffff041028471e8a4743e8a1ffffff0408284743c3909090909090908b461a85c074478b407185c074408b"), new HexPatch(0x566274, "3b0508fa9c"), new HexPatch(0x56627A, "75366a02e83d6dfaff85c058752a6a04e8316dfaff"), new HexPatch(0x566290, "471b"), new HexPatch(0x566293, "472e6a06e8246dfaff"), new HexPatch(0x56629D, "4736"), new HexPatch(0x5662A0, "473d6a08e8176dfaff"), new HexPatch(0x5662AA, "4734"), new HexPatch(0x5662AD, "473c83c40cc3") };
	HexPatch* idlesensitivitytransferscreen[] = { new HexPatch(0x4EC743, "e9339d070090"), new HexPatch(0x56647B, "e8f0fcffff0fbfc80fbfd7e9be62f8ff") };
	HexPatch* disablecdremove[] = { new HexPatch(0x42A98B, "9090909090"), new HexPatch(0x42E400, "9090909090") };
	HexPatch* disablesplashscreen[] = { new HexPatch(0x1CCD3C, "e97203000090") };
	HexPatch* disableunprotectedcontracts[] = { new HexPatch(0x124CD2, "68d1770000") };
	HexPatch* sevensubs[] = { new HexPatch(0x16F224, "c6404907c20800"), new HexPatch(0x172E10, "07"), new HexPatch(0x174C03, "c64649075ec3"), new HexPatch(0x179DF4, "eb"), new HexPatch(0x176801, "07"), new HexPatch(0x17815C, "07"), new HexPatch(0x153A8C, "07"), new HexPatch(0x1BC48C, "07"), new HexPatch(0x3F2A46, "07"), new HexPatch(0x3F66D6, "eb"), new HexPatch(0x1BC48C, "07"), new HexPatch(0x170C6B, "66C746490503"), new HexPatch(0x16D3F0, "06") };
	HexPatch* showstarplayers[] = { new HexPatch(0x5B82C, "9090") };
	HexPatch* hideprivatebids[] = { new HexPatch(0x4D1493, "e90a01000090") };
	HexPatch* allowclosewindow[] = { new HexPatch(0x28D748, "E9E7812B000000") };
	HexPatch* forceloadallplayers[] = { new HexPatch(0x1255FF, "6683B8800000000190"), new HexPatch(0x125637, "6683B8800000000190"), new HexPatch(0x1269F1, "34080000") };
	HexPatch* regenfixes[] = { new HexPatch(0x3A6F48, "7c"), new HexPatch(0x3ABEAB, "e92d0500"), new HexPatch(0x3ABEB0, "90") };
	HexPatch* to1280x800[] = { new HexPatch(0x2B7E, "ff04"), new HexPatch(0x2B85, "ff04"), new HexPatch(0x2B8E, "1f03"), new HexPatch(0x384D, "2003"), new HexPatch(0x3924, "2003"), new HexPatch(0x39B7, "2003"), 
								new HexPatch(0x3B02, "ff04"), new HexPatch(0x3B65, "ff04"), new HexPatch(0x3BDE, "1f03"), new HexPatch(0x3C41, "1f03"), new HexPatch(0x59A22, "baeb1e60"), new HexPatch(0x59A27, "9090"), new HexPatch(0x59A3B, "0c"), 
								new HexPatch(0x5C018, "08"), new HexPatch(0x6041C, "1f03"), new HexPatch(0x60421, "ff04"), new HexPatch(0x70FAE, "1f03"), new HexPatch(0x70FB3, "ff04"), new HexPatch(0x72AD7, "1f03"), new HexPatch(0x72ADC, "ff04"), 
								new HexPatch(0xAF58C, "e42b15"), new HexPatch(0xAF670, "002b15"), new HexPatch(0x15F2CB, "1f03"), new HexPatch(0x15F2D0, "ff04"), new HexPatch(0x15F2E8, "1f03"), new HexPatch(0x15F2ED, "ff04"), new HexPatch(0x15F38E, "1f03"), 
								new HexPatch(0x15F393, "ff04"), new HexPatch(0x15F56C, "1f03"), new HexPatch(0x15F571, "ff04"), new HexPatch(0x15F58E, "1f03"), new HexPatch(0x15F593, "ff04"), new HexPatch(0x15F5EC, "1f03"), new HexPatch(0x15F5F1, "ff04"), 
								new HexPatch(0x15F990, "e92f250a"), new HexPatch(0x15F995, "909081ec00020000568bf1"), new HexPatch(0x15FBA0, "e813230a"), new HexPatch(0x1612A2, "ff04"), new HexPatch(0x1612A9, "ff04"), new HexPatch(0x1612CB, "1f03"), 
								new HexPatch(0x1612D2, "1f03"), new HexPatch(0x190F23, "1f03"), new HexPatch(0x190F2B, "ff04"), new HexPatch(0x1A32C4, "e86fec05009090"), new HexPatch(0x1A32CF, "50e853ec050090"), new HexPatch(0x1A33F5, "15"), 
								new HexPatch(0x1A3774, "e8bfe705005090"), new HexPatch(0x1A377E, "28"), new HexPatch(0x1A3783, "90e8afe7050090"), new HexPatch(0x1A38AB, "15"), new HexPatch(0x1A3CCE, "48e864e2050050"), new HexPatch(0x1A3CDB, "90e847e2050090"), 
								new HexPatch(0x1A3E06, "15"), new HexPatch(0x1A4240, "e8f3dc05005090"), new HexPatch(0x1A424B, "90e8d7dc050090"), new HexPatch(0x1A4376, "15"), new HexPatch(0x1A46A4, "d2"), new HexPatch(0x1A46AE, "33ffebf690"), 
								new HexPatch(0x1A46D4, "15"), new HexPatch(0x1A46F8, "15"), new HexPatch(0x1A472A, "d2"), new HexPatch(0x1A4733, "83ef15ebf79090"), new HexPatch(0x1A47FF, "d2"), new HexPatch(0x1A4809, "33ffebf6"), new HexPatch(0x1A482C, "15"), 
								new HexPatch(0x1A482F, "33ffebfa"), new HexPatch(0x1A4850, "15"), new HexPatch(0x1A4856, "eb2f"), new HexPatch(0x1A487E, "d2"), new HexPatch(0x1A4887, "83ef15ebf79090"), new HexPatch(0x1A4A66, "d2"), new HexPatch(0x1A4A6C, "33ffebfa"), 
								new HexPatch(0x1A4AD2, "15"), new HexPatch(0x1A4AD5, "33ffebfa"), new HexPatch(0x1A4B3F, "15"), new HexPatch(0x1A4B48, "eb76"), new HexPatch(0x1A4BB4, "d2"), new HexPatch(0x1A4BC0, "83ef15ebf79090"), new HexPatch(0x1A4D16, "d2"), 
								new HexPatch(0x1A4D1C, "33ffebfa"), new HexPatch(0x1A4D82, "15"), new HexPatch(0x1A4DEF, "15"), new HexPatch(0x1A4DF8, "eb76"), new HexPatch(0x1A4E64, "d2"), new HexPatch(0x1A4E70, "83ef15ebf700"), new HexPatch(0x1D79EE, "2003"), 
								new HexPatch(0x1D79F3, "0005"), new HexPatch(0x1D8646, "2003"), new HexPatch(0x1D864B, "0005"), new HexPatch(0x1D8686, "2003"), new HexPatch(0x1D868B, "0005"), new HexPatch(0x1E4588, "10"), new HexPatch(0x1E4712, "60"), 
								new HexPatch(0x1E4714, "60"), new HexPatch(0x1E5CEA, "6a"), new HexPatch(0x1E5CEC, "eb4290"), new HexPatch(0x1E5CF0, "6a"), new HexPatch(0x1E5CF2, "eb3c90"), new HexPatch(0x1E5CF6, "6a"), new HexPatch(0x1E5CF8, "eb3690"), 
								new HexPatch(0x1E5CFC, "6a"), new HexPatch(0x1E5CFE, "eb3090"), new HexPatch(0x1E5D02, "6a"), new HexPatch(0x1E5D04, "eb2a90"), new HexPatch(0x1E5D08, "6a"), new HexPatch(0x1E5D0A, "eb2490"), new HexPatch(0x1E5D0E, "6a"), 
								new HexPatch(0x1E5D10, "eb1e90"), new HexPatch(0x1E5D22, "9869c801050000ff348dac1dae00e853c10100c39090"), new HexPatch(0x1E774F, "ada70100"), new HexPatch(0x1E778B, "7ba70100"), new HexPatch(0x1E77AF, "4da70100"), 
								new HexPatch(0x1E77E3, "2da70100"), new HexPatch(0x1E780D, "f9a60100"), new HexPatch(0x1E7826, "f4a60100"), new HexPatch(0x1E78BC, "0005"), new HexPatch(0x1E78E6, "0005"), new HexPatch(0x1E78EE, "2003"), 
								new HexPatch(0x1E7B72, "69c200050000"), new HexPatch(0x1E7B7D, "909090"), new HexPatch(0x1E7BDA, "69c000050000"), new HexPatch(0x1E7BE5, "909090"), new HexPatch(0x1E7C37, "69c000050000"), new HexPatch(0x1E7C42, "909090"), 
								new HexPatch(0x1E7CA9, "69c3000500008b5c2414"), new HexPatch(0x1E7CB8, "909090"), new HexPatch(0x1E7D69, "69c000050000"), new HexPatch(0x1E7D73, "909090"), new HexPatch(0x1E7DD8, "69c300050000"), new HexPatch(0x1E7DE2, "909090"), 
								new HexPatch(0x1E7E3A, "69c300050000"), new HexPatch(0x1E7E44, "909090"), new HexPatch(0x1E7EB1, "69c000050000"), new HexPatch(0x1E7EBB, "909090"), new HexPatch(0x1E82F5, "2003"), new HexPatch(0x1E8305, "2003"), 
								new HexPatch(0x1E830A, "0005"), new HexPatch(0x1ED7AB, "60"), new HexPatch(0x1ED7AD, "60"), new HexPatch(0x1EE1F6, "ff04"), new HexPatch(0x1EE20B, "1f03"), new HexPatch(0x1F14C8, "1f03"), new HexPatch(0x1F14D0, "ff04"), 
								new HexPatch(0x201E49, "9090908b44240483f85a7f0869c05e0100"), 
								new HexPatch(0x201E5B, "eb0e83e85a69c09f01000005007f0000c1f808c2040090e821000000c38b44240469c055010000c1f808c2040052b8ffffffbff764240892405ac20400608d74242c8bfe6a0259ad50e8a3ffffffabad50e8c7ffffffabe2ee61c39090e8dbffffffa10c29ae00c390e8cfffffff668b91a0e91200f644240402740b837c2430027d04ff442430e9b0daf5ff"), 
								new HexPatch(0x201EEB, "06051e1006051e1006051e10050101050101050101e86dffffffe9e63efeffe863ffffffe96c4efeffe859ffffffe9321cfeffe84fffffffe9880ffeff60936a155b99f7fb408944241c61c3905393e8e9ffffff5bc390608d7424288bfe6a0259ad83c035abad50e820ffffffabe2f161668b91a0e912"), 
								new HexPatch(0x201F63, "e92fdaf5ff81c40c020000e825ffffff668b6c240481ec0c020000c390"), new HexPatch(0x202173, "9060ff742428ff742428e84e39feff5a5a69c02003000099f7"), new HexPatch(0x20218D, "f3795d"), 
								new HexPatch(0x202192, "44241c61c39060ff742428ff742428e82a39feff5a5a0faf05f3795d"), new HexPatch(0x2021AF, "99b9200300"), new HexPatch(0x2021B5, "f7f98944241c61c3909090"), new HexPatch(0x28D8D5, "0005"), 
								new HexPatch(0x28D8E0, "2003"), new HexPatch(0x319346, "1f03"), new HexPatch(0x35DC11, "1f03"), new HexPatch(0x35E16C, "02"), new HexPatch(0x388A33, "02"), new HexPatch(0x388A86, "02"), new HexPatch(0x38900F, "ab04"), 
								new HexPatch(0x400898, "e8cb16e0ff909090"), new HexPatch(0x408E77, "1f03"), new HexPatch(0x408E7C, "ff04"), new HexPatch(0x41BD12, "1f03"), new HexPatch(0x41BD17, "ff04"), new HexPatch(0x41D6DD, "15"), 
								new HexPatch(0x421D1D, "5068251d8200eb06060106010601"), new HexPatch(0x421D33, "06"), new HexPatch(0x421F62, "05"), new HexPatch(0x42259D, "50b8f71e60009090"), new HexPatch(0x4225A9, "90"), new HexPatch(0x4225B3, "09"), 
								new HexPatch(0x42283E, "06"), new HexPatch(0x470CCE, "8b"), new HexPatch(0x470F57, "8b"), new HexPatch(0x4750E2, "81"), new HexPatch(0x49C626, "02"), new HexPatch(0x49C69E, "02"), new HexPatch(0x49C73C, "02"), 
								new HexPatch(0x4AEED4, "2003"), new HexPatch(0x4AEED9, "0005"), new HexPatch(0x4AEEFC, "2003"), new HexPatch(0x4AEF01, "0005"), new HexPatch(0x4B9A74, "1f03"), new HexPatch(0x4B9A7C, "ff04"), new HexPatch(0x4BAA58, "1f03"), 
								new HexPatch(0x4BAA60, "ff04"), new HexPatch(0x5C3720, "626b6731323830"), new HexPatch(0x5C3728, "383030"), new HexPatch(0x5C372C, "72676e"), new HexPatch(0x616449, "3830302e6d627200"), new HexPatch(0x65A7CD, "383030"), 
								new HexPatch(0x15F3DF, "9090") };
	HexPatch* tapanispacemaker[] = { new HexPatch(0x12D8FB, "355f"), new HexPatch(0x203834, "81ec200200"), new HexPatch(0x20383A, "5355565751b9ec04000083c8ffbf78f19c"), new HexPatch(0x20384C, "f3ab6a1a59bf9c3cb600f3ab59a19423ae"), new HexPatch(0x20385E, "33db33f63bc3") };
	HexPatch* findallplayers[] = { new HexPatch(0x3AFC4B, "e99e00"), new HexPatch(0x3AFC50, "90") };
	HexPatch* jobsabroadboost[] = { new HexPatch(0x29EA36, "eb"), new HexPatch(0x29D315, "eb"), new HexPatch(0x29D665, "eb"), new HexPatch(0x29D6E4, "eb"), new HexPatch(0x29EA7E, "eb") };
	HexPatch* tapaninewregencode[] = { new HexPatch(0x202120, "608b0d6c23ae008b35c423ae0033c00fb6560703c283c63ee2f599f7356c23ae00a2e673980061c3"), new HexPatch(0x20249C, "e87ffcffffa0e673980084c074f2c3"), 
										new HexPatch(0x2024B8, "608b6c243055ff742430ff742430ff7424308a1c2fe8b40000000fb6142f3ad374208b44242c483ac27517526a64e8150000"), new HexPatch(0x2024EB, "5a3b4424247d08e82f0000"), new HexPatch(0x2024F7, "88042f61c210009090"), 
										new HexPatch(0x3ACFA0, "e85b57e5ff56e815bcd8ff83c408eb04"), new HexPatch(0x3ACFB2, "88015e"), new HexPatch(0x202500, "6905306cad006d4ec64105393000"), 
										new HexPatch(0x20250F, "a3306cad0033d2c1e81066f77424040fb7c2c20400909060526a02e8d1ffffffd1e05a488bd86a00594180f9147d25515268e80300"), new HexPatch(0x202545, "e8b6ffffff5a3d760300007d0ee2eb03d380fa017e0580fa147cd7598954241c61c39090"), 
										new HexPatch(0x202581, "9090909090608b6c24308a142f3a54242c7c173a5424287f116a64e81faa30005a3b4424247703fe0c2f61c21000900fbe142f03d083fa7d7c02b27c88142fc3"), 
										new HexPatch(0x2025C2, "0fbe142f2bd083fa837f02b28388142fc3905d6a006a346a2e6a1b6a406a366a2d6a276a266a336a2b6a386a256a376a436a316a426a446a396a326a3e6a1e6a246a1d6a3a6a356a2a6a21ffe590609384db75156a0ae8a3a930"), 
										new HexPatch(0x20261D, "936a0be89ba930004383c40802d86a095933d2526a16e888a9300083c4045a3ac37f0142e2edd1e242526a09e872a9300083c4045a3ad37d073c057d0142eb043c057df98954241c61c3909090"), 
										new HexPatch(0x202670, "ff356423ae00e845a930006bc06e5a0305bc23ae003878187f118b706185f6740a56e809"), new HexPatch(0x202695, "000085d87504e2d333f6c38b442404608d700f33d26a0759acd1e23c127c0142e2f68954241c61c204"), 
										new HexPatch(0x2026BF, "906a0158600fb746070fb75f072bc33bc2720cf7d83bc2720633c08944241c61c3526a64e8d8a830005a5a3bc27d0b8a042fe81affffff88042fc390"), 
										new HexPatch(0x2026FF, "90608b7e6185ff750261c3807f07787c466a7f5966bbff32e854ffffff85f674e86a325ae898ffffff4875e58a56238857238a56288857288a56308857308b56388957388b57418957416a0c59578d760f8d7f0ff3a45f57e844ffffff93e872feffff5d85ed7442b900400000b719e8fdfeffff85f674eb6a195ae841ffffff85c074eb56e817ffffff3ac3b0037502040250e829a830"), 
										new HexPatch(0x202797, "5a408a142e88142f5d85ed74054875f2ebbe6a06e850fdffffe85bfeffff88472f6a2f6a076a146a2be8c1fdffff6a065ae859fdffff8847218ac3b20542d0e072fb75fae846fdffff8847426a2e5d6a465ae8f2feffff6a2e6a0c6a146a42e8bdfcffff6a2d5d6a245ae8dafeffff6a2d6a096a146a3de8a5fcffff6a3d5d8a042f3c087f086a505ae8bbfeffff6a3d6a0d6a146a56e886fcffff6a345d8a042f3c097f086a505ae89cfeffff6a346a0f6a146a1be867fcffff6a2c5db20ae8cbfcffff88042f6a165ae87afeffff90906a1e5d6a03e84ea730005a0401e848fdffff6a245d6a025a803c2fd07c0380c20552e871fcffff9090e82cfdffff6a405d6a205ae83ffeffff6a406a0e6a146a4ee80afcffff6a235d803c2fe87f0c6a18e842fcffffe8edfcffff6a05e836fcffffe8f3fcffff6a426a076a14906a1b6a0f6a146a1fe8d5fbffff6a1d6a0d6a146a17e8c8fbffff9090906a366a0f6a146a22e8b8fbffff6a435d6a03e8b6a630005ae8a0fcffff6a3f5d8a042f3c077d08e8f1fcffff88042f6a0c5ae8fcfbffff8847446a58e884fbffff90807f0f027c430fb65707c1ea0442e8defbffff8847446a08e8aefbffff85c0750c8a572a8a473a88472a88573a6a04e897fbffff02d0e8b6fbffff884740e898fcffff88471c90eb266a2a5d6a02e878fbffffe835fcffff6a355de82dfcffff6a3a5d6a03e861fbffffe81efcffffe8f8faffff041e38470772336a32e849fbffff85c07435e8e1faffff043c384707721c6a19e832fbffff85c0741ee8cafaffff044a3847077707b0be38470772636a05e814fbffff85c075586a1b5db9"), 
										new HexPatch(0x2029F5, "080000b71ee871fcffff85f6740d8a570780ea0f3856077707ebea6a0158eb126a05e8e4faffff408a142e38142f7f0388142f4583fd2d74fa83fd2574f583fd457d8f487fe26a02e8befaffff85c075e2ebabe854faffff384707777a6a19e8a7faffff85c07417e83ffaffff2c1e38470877636a0ee890faffff85c075586a1b5db9"), new HexPatch(0x202A79, "080000b71ee8edfbffff85f6740d8a570780c2383856077207ebea6a0158eb136a05e860faffff408a142e38142f7c0388142f4583fd2d74fa83fd2574f583fd457d96487fe26a02e83afaffff85c075e2ebab61c3") };
	HexPatch* manageanyteam[] = { new HexPatch(0x82A74, "909090909090"), new HexPatch(0x6A357, "9090909090"), new HexPatch(0x82C9E, "8b74241c368b86cf00000085c07557eb099090"), new HexPatch(0x82CB6, "744c"), new HexPatch(0x1448AA, "0075") };
	HexPatch* remove3playerlimit[] = { new HexPatch(0x179C65, "01") };
	HexPatch* restricttactics[] = { new HexPatch(0x49A686, "00"), new HexPatch(0x49A688, "00"), new HexPatch(0x49A6A6, "00"), new HexPatch(0x49C6C1, "00"), new HexPatch(0x49C6C3, "00"), new HexPatch(0x49C6CB, "00"), new HexPatch(0x49C6D0, "00"), new HexPatch(0x49C6F6, "00"), new HexPatch(0x49C6FB, "00"), new HexPatch(0x49C6FF, "00"), new HexPatch(0x49C75F, "00"), new HexPatch(0x49C761, "00"), new HexPatch(0x49C769, "00"), new HexPatch(0x49C76E, "00"), new HexPatch(0x49A6B3, "eb"), new HexPatch(0x49A83F, "eb"), new HexPatch(0x49ABD9, "e9bb00"), new HexPatch(0x49ABDE, "90") };
	HexPatch* changegeneraldat[] = { new HexPatch(0x5C7B84, "6e6f636865"), new HexPatch(0x5C7B8A, "74") };
	HexPatch* changeregistrylocation[] = { new HexPatch(0x5F17A0, "41") };
	HexPatch* memorycheckfix[] = { new HexPatch(0x3A1737, "c1ea14c1e9148d041183c420c390") };
	HexPatch* removemutexcheck[] = { new HexPatch(0x28D3B6, "eb") };
	HexPatch* datecalcpatch[] = { new HexPatch(0x5662B4, "e87783beff60807c243b"), new HexPatch(0x5662BF, "75528b0d6423ae"), new HexPatch(0x5662C7, "8b74242833c0e849"), new HexPatch(0x5662D2, "66817e126d077c046601461266817e186d077c046601461866817e336d077c046601463366817e406d077c046601464066817e486d077c046601464883c66ee2bf61e99c5fbcff904a03053db981"), new HexPatch(0x566321, "662dd1076683f80ac38b442418ebeb8b44244ce8e2ffffff8944244c8b4424544febd7"), new HexPatch(0x566346, "608b0d7423ae"), new HexPatch(0x56634D, "8b35cc23ae"), new HexPatch(0x566353, "a13db981"), new HexPatch(0x566358, "662dd1076601460883c611e2f7613b9c24f007"), new HexPatch(0x56636D, "c3") };
	HexPatch* datecalcpatchjumps[] = { new HexPatch(0x12C2B0, "E9FF9F4300"), new HexPatch(0x3A41BA, "E85B211C00"), new HexPatch(0x3A3F77, "E89E231C00"), new HexPatch(0x3A47D0, "E8451B1C00"), new HexPatch(0x3A4C8C, "E899161C00909090"), new HexPatch(0x3A4EE5, "4BE845141C0089442450"), new HexPatch(0x12C61F, "E8229D43009090") };
	HexPatch* comphistory_datecalcpatch[] = { new HexPatch(0x139AE9, "E912D4420090"), new HexPatch(0x566F00, "8B35D423AE0060668B15863341006681EAD10731C06601560883C61A4039C875F461E9C82BBDFF") };
	HexPatch* noworkpermits[] = { new HexPatch(0x4c75f1, "eb") };
	HexPatch* currencyinflationpatch[] = { new HexPatch(0x566A00, "FF74240468146A96005589E583E4F8E9E28DADFFDD05C1969100DC0DB89CAD00DD1DB89CAD0083C404C3"), new HexPatch(0x3F7F0, "E90B72520090") };
	HexPatch* nocd[] = { new HexPatch(78299, "9090"), new HexPatch(78318, "00"), new HexPatch(78320, "2a"), new HexPatch(273164, "9090"), new HexPatch(273183, "00"), new HexPatch(273185, "2a"), new HexPatch(279927, "9090"), 
							new HexPatch(279946, "00"), new HexPatch(279948, "2a"), new HexPatch(811034, "9090"), new HexPatch(811053, "00"), new HexPatch(811055, "2a"), new HexPatch(815255, "9090"), new HexPatch(815274, "00"), 
							new HexPatch(815276, "2a"), new HexPatch(1398031, "9090"), new HexPatch(1398050, "00"), new HexPatch(1398052, "2a"), new HexPatch(1680323, "9090"), new HexPatch(1680342, "00"), new HexPatch(1680344, "2a"),
							new HexPatch(1744229, "9090"), new HexPatch(1744248, "00"), new HexPatch(1744250, "2a"), new HexPatch(1843238, "9090"), new HexPatch(1843257, "00"), new HexPatch(1843259, "2a"), 
							new HexPatch(2070522, "9090"), new HexPatch(2070541, "00"), new HexPatch(2070543, "2a"), new HexPatch(2077823, "9090"), new HexPatch(2077842, "00"), new HexPatch(2077844, "2a"), 
							new HexPatch(2270927, "9090"), new HexPatch(2270946, "00"), new HexPatch(2270948, "2a"), new HexPatch(2677825, "9090"), new HexPatch(2677844, "00"), new HexPatch(2677846, "2a"), 
							new HexPatch(3313801, "9090"), new HexPatch(3313820, "00"), new HexPatch(3313822, "2a"), new HexPatch(3581251, "9090"), new HexPatch(3581270, "00"), new HexPatch(3581272, "2a"), 
							new HexPatch(3693402, "9090"), new HexPatch(3693421, "00"), new HexPatch(3693423, "2a"), new HexPatch(3782082, "9090"), new HexPatch(3782101, "00"), new HexPatch(3782103, "2a"), 
							new HexPatch(3822537, "9090"), new HexPatch(3822556, "00"), new HexPatch(3822558, "2a"), new HexPatch(3931588, "9090"), new HexPatch(3931607, "00"), new HexPatch(3931609, "2a"), 
							new HexPatch(4087868, "9090"), new HexPatch(4087887, "00"), new HexPatch(4087889, "2a"), new HexPatch(4155345, "9090"), new HexPatch(4155364, "00"), new HexPatch(4155366, "2a"), 
							new HexPatch(4358574, "9090"), new HexPatch(4358593, "00"), new HexPatch(4358595, "2a"), new HexPatch(4366398, "9090"), new HexPatch(4366417, "00"), new HexPatch(4366419, "2a"), 
							new HexPatch(4369092, "9090"), new HexPatch(4369111, "00"), new HexPatch(4369113, "2a"), new HexPatch(4383580, "9090"), new HexPatch(4383599, "00"), new HexPatch(4383601, "2a"), 
							new HexPatch(4503968, "9090"), new HexPatch(4503987, "00"), new HexPatch(4503989, "2a"), new HexPatch(4561630, "9090"), new HexPatch(4561649, "00"), new HexPatch(4561651, "2a"), 
							new HexPatch(4568752, "9090"), new HexPatch(4568771, "00"), new HexPatch(4568773, "2a"), new HexPatch(4621323, "9090"), new HexPatch(4621342, "00"), new HexPatch(4621344, "2a"), 
							new HexPatch(4800037, "9090"), new HexPatch(4800056, "00"), new HexPatch(4800058, "2a"), new HexPatch(4919092, "9090"), new HexPatch(4919111, "00"), new HexPatch(4919113, "2a"), 
							new HexPatch(4963058, "9090"), new HexPatch(4963077, "00"), new HexPatch(4963079, "2a"), new HexPatch(5256098, "9090"), new HexPatch(5256117, "00"), new HexPatch(5256119, "2a"), 
							new HexPatch(5296550, "9090"), new HexPatch(5296569, "00"), new HexPatch(5296571, "2a"), new HexPatch(5383934, "9090"), new HexPatch(5383953, "00"), new HexPatch(5383955, "2a") };
	HexPatch* uncap20s[] = { new HexPatch(0x143624, "9090"), new HexPatch(0x1440B5, "9090"), new HexPatch(0x144357, "9090"), new HexPatch(0x1443E1, "9090"), new HexPatch(0x144471, "9090"), new HexPatch(0x40807C, "9090") };
	HexPatch* positionintacticsview[] = { new HexPatch(4825080, "0c"), new HexPatch(4825090, "04"), new HexPatch(4825095, "00"), new HexPatch(4825100, "39"), new HexPatch(4825105, "12"), new HexPatch(4825110, "15"), new HexPatch(4825115, "0b"), new HexPatch(4825120, "03"), new HexPatch(4836405, "d2"), new HexPatch(4837381, "027f"), new HexPatch(4837447, "8b0d7e31ae00740666b9ffff9090516a016a01"), new HexPatch(4837467, "006a01556a0653b95044b700e89470f6ff8a44241b3c01900f84df"), new HexPatch(6864332, "3e0020202020202020202063617074"), new HexPatch(0x49E03C, "05") };

	char szEXEDirectory[MAX_PATH];
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	DWORD size = OriginalExeSize;

	// Ensure wherever CM0102Loader.exe is, that is the current directory
	if (GetModuleFileName(NULL, szEXEDirectory, MAX_PATH) != 0)
	{
		*strrchr(szEXEDirectory, '\\') = 0;
		SetCurrentDirectory(szEXEDirectory);

		// Set XP3 Compatibility on the exe
		char szFullExePath[MAX_PATH];
		sprintf(szFullExePath, "%s\\cm0102.exe", szEXEDirectory);
		SetXP3Compatibility(szFullExePath);
	}

	if (GetFileAttributes("cm0102.exe") != -1L)
	{
		settings.ReadSettings((__argc >= 2 && __argv[1][0] != '-') ?  __argv[1] : NULL);

		BOOL bProcess;
		if (settings.Debug || settings.DontExpandExe)
			bProcess = CreateProcess("cm0102.exe", NULL, NULL, NULL, FALSE, (settings.Debug && !settings.DontExpandExe) ? DEBUG_ONLY_THIS_PROCESS : CREATE_SUSPENDED, NULL, NULL, &si, &pi);
		else
		{
			bProcess = CreateExpandedProcess("cm0102.exe", &si, &pi);
			size = ExpandedExeSize;
		}
  
		if (bProcess)
		{
			DWORD bytesRead, old;
			BYTE versionBuf[7];

			// Unprotect 8mb of memory ready for writing
			VirtualProtectEx(pi.hProcess, (void*)0x400000, size, PAGE_EXECUTE_READWRITE, &old);

			// Read the version
			ReadProcessMemory(pi.hProcess, (void*)(0x400000+0x6D4394), versionBuf, 7, &bytesRead);

			// Check if 3.9.68
			if (memcmp(versionBuf, "3.9.68", 6) == 0)
			{
				// Load any patch files first, so that our patches override it if needed
				if (settings.AutoLoadPatchFiles)
					AutoLoadPatchFiles(pi.hProcess, settings.PatchFileDirectory);

				// Apply Patches
				ApplyPatch(pi.hProcess, disablecdremove, sizeof(disablecdremove)/sizeof(HexPatch*));
				ApplyPatch(pi.hProcess, changeregistrylocation, sizeof(changeregistrylocation)/sizeof(HexPatch*));
				ApplyPatch(pi.hProcess, memorycheckfix, sizeof(memorycheckfix)/sizeof(HexPatch*));
				ApplyPatch(pi.hProcess, allowclosewindow, sizeof(allowclosewindow)/sizeof(HexPatch*));
				ApplyPatch(pi.hProcess, removemutexcheck, sizeof(removemutexcheck)/sizeof(HexPatch*));
				ApplyPatch(pi.hProcess, idlesensitivity, sizeof(idlesensitivity)/sizeof(HexPatch*));
				ApplyPatch(pi.hProcess, idlesensitivitytransferscreen, sizeof(idlesensitivitytransferscreen)/sizeof(HexPatch*));
				ApplyPatch(pi.hProcess, positionintacticsview, sizeof(positionintacticsview)/sizeof(HexPatch*));

				if (settings.DisableSplashScreen)
					ApplyPatch(pi.hProcess, disablesplashscreen, sizeof(disablesplashscreen)/sizeof(HexPatch*));
			
				if (settings.ColoredAttributes)
					ApplyPatch(pi.hProcess, colouredattributes, sizeof(colouredattributes)/sizeof(HexPatch*));

				if (settings.DisableUnprotectedContracts)
					ApplyPatch(pi.hProcess, disableunprotectedcontracts, sizeof(disableunprotectedcontracts)/sizeof(HexPatch*));

				if (settings.HideNonPublicBids)
					ApplyPatch(pi.hProcess, hideprivatebids, sizeof(hideprivatebids)/sizeof(HexPatch*));

				if (settings.IncreaseToSevenSubs)
					ApplyPatch(pi.hProcess, sevensubs, sizeof(sevensubs)/sizeof(HexPatch*));

				if (settings.RegenFixes)
					ApplyPatch(pi.hProcess, regenfixes, sizeof(regenfixes)/sizeof(HexPatch*));

				if (settings.ForceLoadAllPlayers)
					ApplyPatch(pi.hProcess, forceloadallplayers, sizeof(forceloadallplayers)/sizeof(HexPatch*));

				if (settings.AddTapaniRegenCode)
				{
					ApplyPatch(pi.hProcess, tapanispacemaker, sizeof(tapanispacemaker)/sizeof(HexPatch*));
					ApplyPatch(pi.hProcess, tapaninewregencode, sizeof(tapaninewregencode)/sizeof(HexPatch*));
				}

				if (settings.UnCap20s)
					ApplyPatch(pi.hProcess, uncap20s, sizeof(uncap20s)/sizeof(HexPatch*));

				if (settings.RemoveForeignPlayerLimit)
					ApplyPatch(pi.hProcess, remove3playerlimit, sizeof(remove3playerlimit)/sizeof(HexPatch*));

				if (settings.NoWorkPermits)
					ApplyPatch(pi.hProcess, noworkpermits, sizeof(noworkpermits)/sizeof(HexPatch*));

				if (settings.ChangeTo1280x800)
				{
					ApplyPatch(pi.hProcess, tapanispacemaker, sizeof(tapanispacemaker)/sizeof(HexPatch*));
					ApplyPatch(pi.hProcess, to1280x800, sizeof(to1280x800)/sizeof(HexPatch*));

					// Copy the 1280x800 images file out of the resources
					OutputResourceFile(IDR_BINARY1, "Data\\bkg1280_800.rgn");
					OutputResourceFile(IDR_BINARY2, "Data\\m800.mbr");
					OutputResourceFile(IDR_BINARY3, "Data\\g800.mbr");
				}
				
				// Year Change
				if (settings.Year != 2001 && settings.Year != 0)
				{
					YearChanger(pi.hProcess, (short)settings.Year);
					ApplyPatch(pi.hProcess, datecalcpatch, sizeof(datecalcpatch)/sizeof(HexPatch*));
					ApplyPatch(pi.hProcess, datecalcpatchjumps, sizeof(datecalcpatchjumps)/sizeof(HexPatch*));
					ApplyPatch(pi.hProcess, comphistory_datecalcpatch, sizeof(comphistory_datecalcpatch)/sizeof(HexPatch*));
				}

				if (settings.SpeedMultiplier != 1)
				{
					SpeedHack(pi.hProcess, settings.SpeedMultiplier);
				}

				if (settings.CurrencyMultiplier != 1.0)
				{
					ApplyPatch(pi.hProcess, currencyinflationpatch, sizeof(currencyinflationpatch)/sizeof(HexPatch*));
					WriteDouble(pi.hProcess, 0x5196C1, settings.CurrencyMultiplier);
				}

				// No CD
				if (settings.NoCD)
					ApplyPatch(pi.hProcess, nocd, sizeof(nocd)/sizeof(HexPatch*));

				if (stricmp(settings.DataDirectory, "data") != 0)
					ChangeDataDirectory(pi.hProcess, settings.DataDirectory);

				// DumpEXE
				if (settings.DumpEXE != NULL && strlen(settings.DumpEXE) > 0)
				{
					FILE *fout = fopen(settings.DumpEXE, "wb");
					if (fout)
					{
						BYTE *DumpBuffer = new BYTE[ExpandedExeSize];

						// Dump core part
						ReadProcessMemory(pi.hProcess, (void*)(0x400000), DumpBuffer, OriginalExeSize, &bytesRead);
						fwrite(DumpBuffer, bytesRead, 1, fout);
						
						// Dump added part (always exists now)
						ReadProcessMemory(pi.hProcess, (void*)(0xDE7000), DumpBuffer, 2 * 1024 * 1024, &bytesRead);
						fwrite(DumpBuffer, bytesRead, 1, fout);
						

						// HACK: Transfer over the non-copied section from the original exe
						BYTE buf[(0x006DB236-0x006DA00E)+1];
						FILE *fOrig = fopen("cm0102.exe", "rb");
						fseek(fOrig, 0x006DA00E, SEEK_SET);
						fread(buf, 1, (0x006DB236-0x006DA00E)+1, fOrig);
						fseek(fout, 0x006DA00E, SEEK_SET);
						fwrite(buf, 1, (0x006DB236-0x006DA00E)+1, fout);

						// HACK2: If Original Exe was expanded manually copy over those bits
						fseek(fOrig, 0, SEEK_END);
						if (ftell(fOrig) == ExpandedExeSize)
						{
							BYTE *buf2 = new BYTE[2*1024*1024];
							fseek(fOrig, 0x00006DC000, SEEK_SET);
							fread(buf2, 1, 2*1024*1024, fOrig);
							fseek(fout, 0x00006DC000, SEEK_SET);
							fwrite(buf2, 1, 2*1024*1024, fout);
							delete buf2;
						}

						fclose(fOrig);
						fclose(fout);
						delete [] DumpBuffer;
					}
					else
						MessageBox(0, "CM0102.exe does not appear to be version 3.9.68! Cannot dump!", "CM0102Loader Error", MB_ICONEXCLAMATION);
				}

				// Apply any patch files manually added in the commandline
				for (int i = 1; i < __argc; i++)
				{
					if (stricmp(__argv[i], "-patch") == 0)
					{
						if (__argc > i)
						{
							ApplyPatchFile(pi.hProcess, __argv[i+1]);
						}
					}
				}

				// Start Game
				if (settings.Debug)
				{
					DEBUG_EVENT debug_event = {0};
					for(;;)
					{
						if (!WaitForDebugEvent(&debug_event, INFINITE))
							return 0;

						ContinueDebugEvent(debug_event.dwProcessId,
										  debug_event.dwThreadId,
										  DBG_CONTINUE);

						if (debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
							break;
					}

				}
				else
				{
					ResumeThread(pi.hThread);
				}
			}
			else
				MessageBox(0, "CM0102.exe does not appear to be version 3.9.68! Cannot patch!", "CM0102Loader Error", MB_ICONEXCLAMATION);
		}
		else
			MessageBox(0, "Failed to Create Process CM0102.exe", "CM0102Loader Error", MB_ICONEXCLAMATION);
	}
	else
		MessageBox(0, "Cannot find CM0102.exe. Put CM0102Loader in same directory as CM0102.exe", "CM0102Loader Error", MB_ICONEXCLAMATION);

	// Free memory
	FreePatch(colouredattributes, sizeof(colouredattributes)/sizeof(HexPatch*));
	FreePatch(idlesensitivity, sizeof(idlesensitivity)/sizeof(HexPatch*));
	FreePatch(idlesensitivitytransferscreen, sizeof(idlesensitivitytransferscreen)/sizeof(HexPatch*));
	FreePatch(disablecdremove, sizeof(disablecdremove)/sizeof(HexPatch*));
	FreePatch(disablesplashscreen, sizeof(disablesplashscreen)/sizeof(HexPatch*));
	FreePatch(disableunprotectedcontracts, sizeof(disableunprotectedcontracts)/sizeof(HexPatch*));
	FreePatch(sevensubs, sizeof(sevensubs)/sizeof(HexPatch*));
	FreePatch(showstarplayers, sizeof(showstarplayers)/sizeof(HexPatch*));
	FreePatch(hideprivatebids, sizeof(hideprivatebids)/sizeof(HexPatch*));
	FreePatch(allowclosewindow, sizeof(allowclosewindow)/sizeof(HexPatch*));
	FreePatch(forceloadallplayers, sizeof(forceloadallplayers)/sizeof(HexPatch*));
	FreePatch(regenfixes, sizeof(regenfixes)/sizeof(HexPatch*));
	FreePatch(to1280x800, sizeof(to1280x800)/sizeof(HexPatch*));
	FreePatch(tapanispacemaker, sizeof(tapanispacemaker)/sizeof(HexPatch*));
	FreePatch(findallplayers, sizeof(findallplayers)/sizeof(HexPatch*));
	FreePatch(jobsabroadboost, sizeof(jobsabroadboost)/sizeof(HexPatch*));
	FreePatch(tapaninewregencode, sizeof(tapaninewregencode)/sizeof(HexPatch*));
	FreePatch(manageanyteam, sizeof(manageanyteam)/sizeof(HexPatch*));
	FreePatch(remove3playerlimit, sizeof(remove3playerlimit)/sizeof(HexPatch*));
	FreePatch(restricttactics, sizeof(restricttactics)/sizeof(HexPatch*));
	FreePatch(changegeneraldat, sizeof(changegeneraldat)/sizeof(HexPatch*));
	FreePatch(changeregistrylocation, sizeof(changeregistrylocation)/sizeof(HexPatch*));
	FreePatch(memorycheckfix, sizeof(memorycheckfix)/sizeof(HexPatch*));
	FreePatch(removemutexcheck, sizeof(removemutexcheck)/sizeof(HexPatch*));
	FreePatch(datecalcpatch, sizeof(datecalcpatch)/sizeof(HexPatch*));
	FreePatch(datecalcpatchjumps, sizeof(datecalcpatchjumps)/sizeof(HexPatch*));
	FreePatch(comphistory_datecalcpatch, sizeof(comphistory_datecalcpatch)/sizeof(HexPatch*));
	FreePatch(nocd, sizeof(nocd)/sizeof(HexPatch*));
	FreePatch(uncap20s, sizeof(uncap20s)/sizeof(HexPatch*));
	FreePatch(positionintacticsview, sizeof(positionintacticsview)/sizeof(HexPatch*));
	
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
} 