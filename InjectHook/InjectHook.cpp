#include <iostream>
#include <string>
#include <ctype.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <Shlwapi.h>
//Library needed by Linker to check file existance
#pragma comment(lib, "Shlwapi.lib")

using namespace std;

//-----------------------------------------------------------
// Inject DLL to target process
//-----------------------------------------------------------
bool InjectDLLWithPID(const int& pid, const string& DLL_Path)
{
  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

  if (hProc == NULL)
  {
    cout << "Fail to open target process!" << endl;
    return false;
  }
  
  do
  {
    LPVOID MyAlloc = VirtualAllocEx(hProc, NULL, DLL_Path.length(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (MyAlloc == NULL)
    {
      cout << "Fail to allocate memory in Target Process." << endl;
      break;
    }

    int IsWriteOK = WriteProcessMemory(hProc, MyAlloc, DLL_Path.c_str(), DLL_Path.length(), 0);
    if (IsWriteOK == 0)
    {
      cout << "Fail to write in Target Process memory." << endl;
      break;
    }

    LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA");
    HANDLE ThreadReturn = CreateRemoteThread(hProc, NULL, 0, addrLoadLibrary, MyAlloc, 0, NULL);
    if (ThreadReturn == NULL)
    {
      cout << "Fail to create Remote Thread" << endl;
      break;
    }

    CloseHandle(ThreadReturn);
    CloseHandle(hProc);
    return true;
  }while(0);

  return false;
}

//-----------------------------------------------------------
// Get All Process ID by its name
//-----------------------------------------------------------
int InjectDLLWithProcName(const string& p_name, const string& DLL_Path)
{
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32 structprocsnapshot = { 0 };

  structprocsnapshot.dwSize = sizeof(PROCESSENTRY32);

  if (snapshot == INVALID_HANDLE_VALUE)
    return 0;
  if (Process32First(snapshot, &structprocsnapshot) == FALSE)
    return 0;

  while (Process32Next(snapshot, &structprocsnapshot))
  {
    if (!strcmp(structprocsnapshot.szExeFile, p_name.c_str()))
    {
      cout << "Process name is: " << p_name << "\nProcess ID: " << structprocsnapshot.th32ProcessID << endl;
      if (!InjectDLLWithPID(structprocsnapshot.th32ProcessID, DLL_Path))
      {
        CloseHandle(snapshot);
        cout << "Inject process with Process ID:" << structprocsnapshot.th32ProcessID << "fail!" << endl;
        return -1;
      }
    }
  }
  CloseHandle(snapshot);
  cout << "Unable to find Process ID" << endl;
  return 0;
}

void usage()
{
  cout << "Usage: DLL_Injector.exe <Process name | Process ID> <DLL Path to Inject>" << endl;
}

int main(int argc, char** argv)
{
  if (argc != 3)
  {
    usage();
    return EXIT_FAILURE;
  }

  if (PathFileExists(argv[2]) == FALSE)
  {
    cout << "DLL file does NOT exist!" << endl;
    return EXIT_FAILURE;
  }

  if (isdigit(argv[1][0]))
  {
    InjectDLLWithPID(atoi(argv[1]), argv[2]);
  }
  else 
  {
    InjectDLLWithProcName(argv[1], argv[2]);
  }

  return EXIT_SUCCESS;
}