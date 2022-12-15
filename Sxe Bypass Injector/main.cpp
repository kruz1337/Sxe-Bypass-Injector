#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <iostream>
#include <Psapi.h>

void createAscii()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);
	std::cout << R"(
                               ____                             __ _  __    ____                  
                              / __ \___  ____ ___  _____  _____/ /| |/ /   / __ \___ _   __  
                             / /_/ / _ \/ __ `/ / / / _ \/ ___/ __|   /   / / / / _ | | / /  
                            / _, _/  __/ /_/ / /_/ /  __(__  / /_/   |   / /_/ /  __| |/ _    
                           /_/ |_|\___/\__, /\__,_/\___/____/\__/_/|_|  /_____/\___/|___(_)         
)" << '\n';
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 94);
}

void clearConsole()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 1);
	system("CLS");
	createAscii();
}

void clearColor()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

DWORD GetProcessIdByName(const char* ProcessName)
{
	PROCESSENTRY32 procEntry;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnap, &procEntry))
	{
		while (Process32Next(hSnap, &procEntry))
		{
			if (!_strcmpi(procEntry.szExeFile, ProcessName))
			{
				CloseHandle(hSnap);
				return procEntry.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnap);
	return 0;
}

HWND GetWindowByProcessId(DWORD processId)
{
	for (HWND hWindow = GetTopWindow(NULL); hWindow != NULL; hWindow = GetNextWindow(hWindow, GW_HWNDNEXT))
	{
		if (!IsWindowVisible(hWindow))
		{
			continue;
		}

		int length = GetWindowTextLength(hWindow);
		if (length == 0)
		{
			continue;
		}

		char* buffer = new char[length + 1];
		GetWindowText(hWindow, buffer, length + 1);
		std::string windowTitle(buffer);
		delete[] buffer;

		if (windowTitle.find("Video mode change failure") != std::string::npos)
		{
			continue;
		}

		DWORD procID;
		GetWindowThreadProcessId(hWindow, &procID);

		if (procID == processId)
		{
			return hWindow;
		}
	}

	return 0;
}

DWORD GetModule(DWORD processId, const char* name)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, processId);
	MODULEENTRY32 entry32;
	entry32.dwSize = sizeof(MODULEENTRY32);
	do
	{
		if (!strcmp(entry32.szModule, name))
		{
			CloseHandle(hSnapshot);
			return (DWORD)entry32.modBaseAddr;
		}
	} while (Module32Next(hSnapshot, &entry32));

	return 0;
}

bool IsSxeInjectedWithoutPEB()
{
	char sxePath[MAX_PATH];
	HANDLE sxeHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessIdByName("Injected.exe"));

	if (sxeHandle && GetModuleFileNameEx(sxeHandle, NULL, sxePath, MAX_PATH) != 0)
	{
		std::string sxePath_str = sxePath;
		sxePath_str.replace(sxePath_str.find("\\Injected.exe"), sxePath_str.length(), "");
		FILE* dllFile = fopen((sxePath_str + "\\sXe.dll").c_str(), "a+");
		if (dllFile == NULL)
		{
			return true;
		}
	}

	return false;
}

bool Inject(HANDLE hProcess, const char* dllFilePath)
{
	void* memory = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!memory)
	{
		CloseHandle(hProcess);
		return false;
	}

	if (!WriteProcessMemory(hProcess, memory, dllFilePath, strlen(dllFilePath) + 1, 0))
	{
		CloseHandle(hProcess);
		return false;
	}

	void* shellCode = LoadLibraryA;
	void* targetBase = memory;

	void* codeCave = VirtualAllocEx(hProcess, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!codeCave)
	{
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		return false;
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	HANDLE hThread = NULL;

	THREADENTRY32 te32;
	te32.dwSize = sizeof(te32);

	Thread32First(hSnapshot, &te32);
	while (Thread32Next(hSnapshot, &te32))
	{
		if (te32.th32OwnerProcessID == GetProcessId(hProcess))
		{
			hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
			if (!hThread)
			{
				VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
				VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
				VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
				return false;
			}
			break;
		}
	}
	CloseHandle(hSnapshot);

	if (SuspendThread(hThread) == (DWORD)-1)
	{
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
		return false;
	}

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(hThread, &ctx))
	{
		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
		return false;
	}

	BYTE code[] =
	{
		0x00, 0x00, 0x00, 0x00, 0x83, 0xEC, 0x04, 0xC7, 0x04,
		0x24, 0x00, 0x00, 0x00, 0x00, 0x50, 0x51, 0x52, 0x9C,
		0xB9, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00,
		0x00, 0x51, 0xFF, 0xD0, 0xA3, 0x00, 0x00, 0x00, 0x00,
		0x9D, 0x5A, 0x59, 0x58, 0xC6, 0x05, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xC3
	};

	DWORD funcOffset = 0x04;
	DWORD checkByteOffset = 0x02 + funcOffset;

	*reinterpret_cast<DWORD*>(code + 0x06 + funcOffset) = ctx.Eip;
	*reinterpret_cast<void**>(code + 0x0F + funcOffset) = targetBase;
	*reinterpret_cast<void**>(code + 0x14 + funcOffset) = shellCode;
	*reinterpret_cast<void**>(code + 0x1C + funcOffset) = codeCave;
	*reinterpret_cast<BYTE**>(code + 0x26 + funcOffset) = reinterpret_cast<BYTE*>(codeCave) + checkByteOffset;

	ctx.Eip = reinterpret_cast<DWORD>(codeCave) + funcOffset;

	if (!WriteProcessMemory(hProcess, codeCave, code, sizeof(code), NULL))
	{
		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
		return false;
	}

	if (!SetThreadContext(hThread, &ctx))
	{
		ResumeThread(hThread);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
		return false;
	}

	if (ResumeThread(hThread) == (DWORD)-1)
	{
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, targetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, shellCode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, codeCave, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);
	return true;
}

int main(int argc, char** argv)
{
	std::string dll = "";

	SetConsoleTitle("Sxe Bypass Injector | github.com/kruz1337");
	createAscii();

	if (argc > 1)
	{
		dll = argv[1];
	}
	else
	{
		printf("\n[*] DLL File Path: \n> ");
		std::cin >> dll;
	}

	clearConsole();

	std::ifstream fDll(dll, std::ios::binary | std::ios::ate);
	char buffer[MAX_PATH];
	GetFullPathNameA(dll.c_str(), MAX_PATH, buffer, nullptr);
	const char* dllFilePath = buffer;

	if (!fDll)
	{
		printf("[-] Dll file doesn't exist.\n");
		clearColor();
		system("PAUSE");
		return false;
	}
	if (fDll.fail())
	{
		printf("[-] Dll file open failed. (0x%X)\n", (DWORD)fDll.rdstate());
		clearColor();
		system("PAUSE");
		return false;
	}

	auto dllSize = fDll.tellg();
	if (fDll.tellg() < 0x1000)
	{
		printf("[-] Invalid dll file size.\n");
		clearColor();
		system("PAUSE");
		return false;
	}

	BYTE* sourceData = new BYTE[(UINT_PTR)dllSize];
	if (!sourceData) {
		printf("[-] Dll file can't allocate.\n");
		clearColor();
		fDll.close();
		system("PAUSE");
		return false;
	}

	fDll.seekg(0, std::ios::beg);
	fDll.read(reinterpret_cast<char*>(sourceData), dllSize);
	fDll.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(sourceData)->e_magic != 0x5A4D)
	{
		printf("[-] Invalid dll file.\n");
		clearColor();
		system("PAUSE");
		return false;
	}

	IMAGE_FILE_HEADER* fileHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(sourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(sourceData)->e_lfanew)->FileHeader;
	if (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		printf("[-] Invalid file architery.!\n");
		clearColor();
		system("PAUSE");
		return false;
	}

	DWORD exitCode;
	DWORD processId;
	HANDLE hProcess;
	HWND hWindow;

	printf("[*] Waiting for Half-Life to open with Sxe...\n");

	while (true)
	{
		processId = GetProcessIdByName("hl.exe");
		if (processId)
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
			if (hProcess)
			{
				if (GetExitCodeProcess(hProcess, &exitCode))
				{
					if (IsSxeInjectedWithoutPEB()
						&& GetModule(processId, "hw.dll")
						&& GetModule(processId, "GameUI.dll"))
					{
						hWindow = GetWindowByProcessId(processId);
						if (hWindow)
						{
							clearConsole();
							printf("[*] Process started.. Injecting.\n");
							break;
						}
					}
				}
			}
		}
	}

	Sleep(2000);

	SetWindowTextA(hWindow, "github.com/kruz1337");

	clearConsole();
	if (exitCode == 0xC0000005)
	{
		printf("[-] Process crashed.\n");
	}
	else
	{
		if (Inject(hProcess, dllFilePath))
		{
			printf("[*] DLL file succesfully injected into game.\n");
			printf("[*] Process ID: %X\n", processId);
			printf("[*] Window Address: %p\n", hWindow);
		}
		else
		{
			printf("[-] Sxe Bypass injection failed.\n");
		}
	}
	clearColor();

	system("PAUSE");
	return true;
}