#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_

#include <iostream>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <locale>
#include <codecvt>

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <fwpmu.h>
#include <initguid.h>
#include <evntrace.h>
#include <tdh.h>
#include <sddl.h>
#include <shlwapi.h>
#include <intrin.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// ETW Provider GUIDs
const GUID FileIoProviderGuid = { 0x90cbdc39, 0x4a3e, 0x11d1, { 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 } };
const GUID TcpIpProviderGuid = { 0x9a280ac0, 0xc8e0, 0x11d1, { 0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2 } };
const GUID RegistryProviderGuid = { 0xae53722e, 0xc863, 0x11d2, { 0x86, 0x59, 0x00, 0xc0, 0x4f, 0xa3, 0x21, 0xa1 } };

#ifndef KERNEL_LOGGER_NAME
#define KERNEL_LOGGER_NAME L"NT Kernel Logger"
#endif

class AdvancedBehaviorMonitor {
public:
    AdvancedBehaviorMonitor();
    ~AdvancedBehaviorMonitor();

    // 控制函数
    bool StartMonitoring(const std::string& targetProcess, const std::string& arguments = "");
    void StopMonitoring();
    void GenerateReport(const std::string& filename);

    // 配置选项
    void SetMonitoringDuration(int seconds) { m_monitorDuration = seconds; }
    void EnableETWMonitoring(bool enable) { m_enableETW = enable; }
    void EnableNetworkFilter(bool enable) { m_enableNetworkFilter = enable; }

private:
    // 事件数据结构
    struct BehaviorEvent {
        std::string timestamp;
        std::string type;
        std::string details;
        std::string processName;
        DWORD processId;
    };

    // ETW 相关
    bool StartETWTracing();
    void StopETWTracing();
    void ProcessETWEvents();
    static DWORD WINAPI ETWThread(LPVOID lpParam);
    static void WINAPI ETWEventCallback(PEVENT_RECORD eventRecord);
    void HandleFileIoEvent(PEVENT_RECORD eventRecord);
    void HandleRegistryEvent(PEVENT_RECORD eventRecord);
    void HandleNetworkEvent(PEVENT_RECORD eventRecord);

    // 网络过滤
    bool SetupNetworkFilter();
    void CleanupNetworkFilter();

    // 线程函数
    void MonitoringMain();
    void TerminateAllMonitoredProcesses(); // 新增函数

    // 工具函数
    std::string GetProcessName(DWORD pid);
    std::string GetCurrentTimestamp();
    void LogEvent(const std::string& type, const std::string& details, DWORD pid = 0);
    bool IsTargetProcessOrChild(DWORD pid);

    // ETW 会话
    TRACEHANDLE m_traceHandle;
    EVENT_TRACE_PROPERTIES* m_traceProperties;
    std::thread m_etwThread;

    // 网络过滤
    HANDLE m_engineHandle;
    std::vector<UINT64> m_filterIds;

    // 进程信息
    HANDLE m_targetProcess;
    DWORD m_targetPid;
    std::string m_targetName;
    std::string m_targetPath;

    // 监控数据
    std::vector<BehaviorEvent> m_events;
    std::unordered_set<DWORD> m_childProcesses;
    std::mutex m_dataMutex; // 保护共享数据

    // 配置
    int m_monitorDuration;
    bool m_enableETW;
    bool m_enableNetworkFilter;
    bool m_isMonitoring;
};