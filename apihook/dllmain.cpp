#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include "../minhook/include/MinHook.h"

#pragma comment(lib, "libMinHook.x64.lib")

typedef BOOL (WINAPI* pSetWindowText)(HWND hWnd, LPCWSTR lpString);
pSetWindowText originSetWindowText = nullptr;

BOOL WINAPI DetourSetWindowTextW(HWND hWnd, LPCWSTR lpString) {
  OutputDebugStringA("hook detour");
  OutputDebugStringW(lpString);
  return originSetWindowText(hWnd, lpString);
}

BOOL SetExportHook(LPVOID originFuncAddress, LPVOID detourFunc, LPVOID originFunc) {
  if (MH_CreateHook(originFuncAddress, detourFunc, reinterpret_cast<LPVOID*>(originFunc)) != MH_OK) {
    OutputDebugStringA("CreateHook fail");
    return false;
  }

  if (MH_EnableHook(originFuncAddress) != MH_OK) {
    OutputDebugStringA("EnableHook fail");
    return false;
  }

  return true;
}

BOOL SetUnexportHook() {
  HMODULE hModule = GetModuleHandleA("chrome.dll");
  if(!hModule)
    OutputDebugStringA("Cannot find chrome.dll");

  unsigned int search_offset_start = 0x5952cc0;
  unsigned int search_offset_end = 0x4000;
  unsigned char pattern_header[] = {0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xec, 0x30, 0xc6, 0x02, 0x0, 0x48, 0x8b, 0x41, 0x30, 0x83, 0xb8, 0xac, 0x0, 0x0, 0x0, 0x0};
  unsigned int pattern_header_len = sizeof(pattern_header);
  unsigned char pattern_tail[] = {0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x30, 0x5b, 0x5d, 0x5f, 0x5e, 0x41, 0x5c, 0x41, 0x5e, 0x41, 0x5f, 0xc3};
  unsigned int pattern_tail_len = sizeof(pattern_tail);
  unsigned int pattern_ignore_len = 35;

  
  PBYTE StartSearchOffset = (PBYTE)hModule + search_offset_start;
  PBYTE EndSearchOffset = (PBYTE)hModule + search_offset_start + search_offset_end;

  for (PBYTE pbyTmp = StartSearchOffset; pbyTmp < EndSearchOffset; pbyTmp++)
  {
    if (memcmp(pbyTmp, pattern_header, pattern_header_len) == 0)
    {
      if (memcmp(pbyTmp + pattern_header_len + pattern_ignore_len, pattern_tail, pattern_tail_len) != 0)
        continue;

      OutputDebugStringA("Success Hook unexport tls_write_app_data ");
      break;
    }
  }
  OutputDebugStringA("Fail Hook unexport tls_write_app_data ");
  return true;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
      do {
        OutputDebugStringA("Start Hook!!");

        if (MH_Initialize() != MH_OK) {
          OutputDebugStringA("Init fail");
          break;
        }

        SetExportHook(&SetWindowTextW, &DetourSetWindowTextW, &originSetWindowText);
        SetUnexportHook();

      }while(0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

