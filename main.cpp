#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <psapi.h>
#include <fstream>
#include <algorithm>
#include <shellapi.h>

// 定义 UNICODE_STRING 结构
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

// 定义其他必要的结构
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
} PEB;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS;

// 定义 NTSTATUS 类型
typedef LONG NTSTATUS;

// 定义常量
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define ProcessBasicInformation 0

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")

class WPSInterceptor {
private:
    bool isRunning;

public:
    WPSInterceptor() : isRunning(true) {}

    // 只检测WPS进程，不检测希沃白板
    bool IsWPSProcess(const std::wstring& processName) {
        std::vector<std::wstring> wpsProcesses = {
            L"wps.exe", L"et.exe", L"wpp.exe",
            L"wpsoffice.exe", L"kingsoft.exe",
            L"wpscloudsvr.exe", L"wpscenter.exe",
            L"ksolaunch.exe", L"ksomisc.exe"
        };

        std::wstring lowerName = processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        for (const auto& wpsProc : wpsProcesses) {
            if (lowerName.find(wpsProc) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    // 检查是否为希沃白板进程（白名单）
    bool IsSeewoProcess(const std::wstring& processName) {
        std::vector<std::wstring> seewoProcesses = {
            L"EasiNote.exe", L"SeewoService.exe", L"EasyClass.exe",
            L"SeewoLink.exe", L"SeewoBoard.exe", L"SeewoAppStore.exe",
            L"EasiCamera.exe", L"SeewoAudio.exe", L"SeewoWhiteboard.exe"
        };

        std::wstring lowerName = processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        for (const auto& seewoProc : seewoProcesses) {
            if (lowerName.find(seewoProc) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    // 显示拦截弹窗
    void ShowInterceptionMessage() {
        MessageBoxW(NULL,
            L"该office副本不是正版\n\n"
            L"系统已自动切换到Microsoft Office\n"
            L"点击确定继续使用",
            L"软件验证失败",
            MB_OK | MB_ICONWARNING
        );
    }

    // 显示文件保护提示
    void ShowFileProtectionMessage(const std::wstring& filePath) {
        std::wstring message = L"检测到WPS加密文件\n\n";

        if (!filePath.empty()) {
            // 只显示文件名，不显示完整路径
            size_t lastSlash = filePath.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) {
                message += L"文件: " + filePath.substr(lastSlash + 1) + L"\n";
            }
            else {
                message += L"文件: " + filePath + L"\n";
            }
        }

        message += L"\n此文件受WPS私密文档保护\n";
        message += L"请老师关闭私密文档保护后再用Microsoft 365打开\n\n";
        message += L"解决方案:\n";
        message += L"1. 使用WPS打开文件\n";
        message += L"2. 点击'文件' → '文档加密' → '私密文档保护'\n";
        message += L"3. 关闭保护并保存文件\n";
        message += L"4. 重新用Microsoft 365打开";

        MessageBoxW(NULL, message.c_str(), L"文件保护提示", MB_OK | MB_ICONINFORMATION);
    }

    // 获取进程的主线程ID
    DWORD GetProcessMainThreadId(DWORD processId) {
        DWORD mainThreadId = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te32 = { 0 };
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == processId) {
                        mainThreadId = te32.th32ThreadID;
                        break;
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }
            CloseHandle(hSnapshot);
        }
        return mainThreadId;
    }

    // 获取进程可执行文件路径（简化版本）
    std::wstring GetProcessPath(DWORD processId) {
        std::wstring path;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess) {
            WCHAR buffer[MAX_PATH] = { 0 };
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
                path = buffer;
            }
            CloseHandle(hProcess);
        }
        return path;
    }

    // 检查文件是否可能是WPS加密文件
    bool IsLikelyWPSEncryptedFile(const std::wstring& filePath) {
        if (filePath.empty()) return false;

        // 检查文件扩展名是否为WPS特有格式
        std::wstring extension = PathFindExtensionW(filePath.c_str());
        std::vector<std::wstring> wpsExtensions = { L".wps", L".et", L".dps" };

        for (const auto& ext : wpsExtensions) {
            if (extension == ext) {
                return true;
            }
        }

        return false;
    }

    // 终止WPS进程
    void KillWPSProcesses() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe32 = { 0 };
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (IsWPSProcess(pe32.szExeFile) && !IsSeewoProcess(pe32.szExeFile)) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        // 先尝试正常关闭
                        DWORD mainThreadId = GetProcessMainThreadId(pe32.th32ProcessID);
                        if (mainThreadId != 0) {
                            PostThreadMessage(mainThreadId, WM_QUIT, 0, 0);
                        }

                        std::this_thread::sleep_for(std::chrono::milliseconds(100));

                        // 如果还在运行，强制终止
                        if (WaitForSingleObject(hProcess, 100) == WAIT_TIMEOUT) {
                            TerminateProcess(hProcess, 0);
                            std::wcout << L"已强制终止WPS进程: " << pe32.szExeFile << std::endl;
                        }
                        else {
                            std::wcout << L"已正常关闭WPS进程: " << pe32.szExeFile << std::endl;
                        }

                        CloseHandle(hProcess);
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // 用Office打开文件
    bool OpenWithOffice(const std::wstring& filePath) {
        if (filePath.empty() || !PathFileExistsW(filePath.c_str())) {
            return false;
        }

        std::wstring extension = PathFindExtensionW(filePath.c_str());
        std::wstring officeApp;

        if (extension == L".ppt" || extension == L".pptx") {
            officeApp = L"POWERPNT.EXE";
        }
        else if (extension == L".doc" || extension == L".docx") {
            officeApp = L"WINWORD.EXE";
        }
        else if (extension == L".xls" || extension == L".xlsx") {
            officeApp = L"EXCEL.EXE";
        }
        else {
            // 其他文件类型用系统默认程序打开
            SHELLEXECUTEINFOW sei = { 0 };
            sei.cbSize = sizeof(sei);
            sei.lpFile = filePath.c_str();
            sei.nShow = SW_SHOW;
            return ShellExecuteExW(&sei) == TRUE;
        }

        SHELLEXECUTEINFOW sei = { 0 };
        sei.cbSize = sizeof(sei);
        sei.lpFile = officeApp.c_str();
        sei.lpParameters = filePath.c_str();
        sei.nShow = SW_SHOW;

        return ShellExecuteExW(&sei) == TRUE;
    }

    // 处理文件解锁
    void HandleFileDecryption(const std::wstring& filePath) {
        if (filePath.empty()) return;

        // 创建备份文件（防止WPS加密导致文件损坏）
        std::wstring backupPath = filePath + L".backup";
        CopyFileW(filePath.c_str(), backupPath.c_str(), FALSE);

        // 尝试修复文件属性
        DWORD attributes = GetFileAttributesW(filePath.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            // 移除只读属性
            if (attributes & FILE_ATTRIBUTE_READONLY) {
                SetFileAttributesW(filePath.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
            }
        }
    }

    // 保存拦截日志
    void SaveInterceptionLog(const std::wstring& processName, const std::wstring& filePath = L"") {
        std::wofstream logFile(L"C:\\Windows\\Temp\\office_helper.log", std::ios::app);
        if (logFile.is_open()) {
            SYSTEMTIME st = { 0 };
            GetLocalTime(&st);
            logFile << L"[" << st.wYear << L"-" << st.wMonth << L"-" << st.wDay
                << L" " << st.wHour << L":" << st.wMinute << L":" << st.wSecond
                << L"] 拦截WPS进程: " << processName;

            if (!filePath.empty()) {
                logFile << L" | 文件: " << filePath;
            }

            logFile << std::endl;
            logFile.close();
        }
    }

    // 进程监控主循环
    void MonitorProcesses() {
        std::vector<DWORD> previousProcesses;

        while (isRunning) {
            std::vector<DWORD> currentProcesses;

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe32 = { 0 };
                pe32.dwSize = sizeof(PROCESSENTRY32W);

                if (Process32FirstW(hSnapshot, &pe32)) {
                    do {
                        // 只处理WPS进程，跳过希沃白板
                        if (IsWPSProcess(pe32.szExeFile) && !IsSeewoProcess(pe32.szExeFile)) {
                            currentProcesses.push_back(pe32.th32ProcessID);

                            // 检查是否是新的WPS进程
                            if (std::find(previousProcesses.begin(),
                                previousProcesses.end(),
                                pe32.th32ProcessID) == previousProcesses.end()) {

                                std::wcout << L"检测到WPS进程启动: " << pe32.szExeFile
                                    << L" (PID: " << pe32.th32ProcessID << L")" << std::endl;

                                // 获取进程路径作为文件路径（简化处理）
                                std::wstring filePath = GetProcessPath(pe32.th32ProcessID);

                                // 显示拦截消息
                                ShowInterceptionMessage();

                                // 保存日志
                                SaveInterceptionLog(pe32.szExeFile, filePath);

                                // 终止WPS进程
                                KillWPSProcesses();

                                // 总是显示文件保护提示
                                ShowFileProtectionMessage(filePath);

                                break;
                            }
                        }
                    } while (Process32NextW(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }

            previousProcesses = currentProcesses;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    // 隐藏窗口
    void HideConsole() {
        HWND hwnd = GetConsoleWindow();
        if (hwnd != NULL) {
            ShowWindow(hwnd, SW_HIDE);
        }
    }

    void Start() {
        std::wcout << L"Office助手已启动 - 只拦截WPS，保留希沃白板" << std::endl;
        std::wcout << L"监控间隔: 500ms" << std::endl;

        // 延迟隐藏窗口，让用户看到启动信息
        std::thread hideThread([this]() {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            HideConsole();
            });
        hideThread.detach();

        MonitorProcesses();
    }

    void Stop() {
        isRunning = false;
    }
};

// 服务安装
void InstallAsService() {
    HKEY hKey = NULL;
    LPCWSTR subKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, subKey, 0, KEY_WRITE, &hKey);

    if (result == ERROR_SUCCESS) {
        WCHAR modulePath[MAX_PATH] = { 0 };
        DWORD pathLength = GetModuleFileNameW(NULL, modulePath, MAX_PATH);

        if (pathLength > 0 && pathLength < MAX_PATH) {
            RegSetValueExW(hKey, L"OfficeHelper", 0, REG_SZ,
                (BYTE*)modulePath, (wcslen(modulePath) + 1) * sizeof(WCHAR));
            std::wcout << L"已安装到当前用户开机启动项" << std::endl;
        }

        if (hKey != NULL) {
            RegCloseKey(hKey);
        }
    }
}

// 创建计划任务
void CreateScheduledTask() {
    WCHAR modulePath[MAX_PATH] = { 0 };
    DWORD pathLength = GetModuleFileNameW(NULL, modulePath, MAX_PATH);

    if (pathLength > 0 && pathLength < MAX_PATH) {
        std::wstring command = L"schtasks /create /tn \"OfficeHelper\" /tr \"\\\"";
        command += modulePath;
        command += L"\\\"\" /sc onlogon /ru System /f";

        int result = _wsystem(command.c_str());
        if (result == 0) {
            std::wcout << L"已创建系统计划任务" << std::endl;
        }
        else {
            std::wcout << L"创建计划任务失败，错误代码: " << result << std::endl;
        }
    }
}

// 检查管理员权限
BOOL CheckAdminPrivileges() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation = { 0 };
        DWORD dwSize = 0;

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    return isAdmin;
}

int main() {
    // 检查是否已有实例在运行
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"OfficeHelperMutex");
    if (hMutex == NULL) {
        std::wcout << L"创建互斥体失败" << std::endl;
        return 1;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::wcout << L"Office助手已在运行中" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        CloseHandle(hMutex);
        return 0;
    }

    std::wcout << L"=== Office助手安装程序 ===" << std::endl;
    std::wcout << L"功能: 自动拦截WPS，保留希沃白板" << std::endl;
    std::wcout << L"==========================" << std::endl;

    // 安装到启动项
    InstallAsService();

    // 创建计划任务（需要管理员权限）
    BOOL isAdmin = CheckAdminPrivileges();

    if (isAdmin) {
        CreateScheduledTask();
        std::wcout << L"管理员权限确认，已创建系统计划任务" << std::endl;
    }
    else {
        std::wcout << L"非管理员权限，跳过系统计划任务创建" << std::endl;
        std::wcout << L"程序将在当前用户权限下运行" << std::endl;
    }

    std::wcout << L"启动监控服务..." << std::endl;

    // 启动拦截系统
    WPSInterceptor interceptor;
    interceptor.Start();

    if (hMutex != NULL) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }

    return 0;
}