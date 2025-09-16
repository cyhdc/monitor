#include "monitor.h"

// 全局静态实例，用于在静态回调函数中访问成员变量
static AdvancedBehaviorMonitor* g_monitorInstance = nullptr;

AdvancedBehaviorMonitor::AdvancedBehaviorMonitor()
    : m_traceHandle(0), m_traceProperties(nullptr),
    m_engineHandle(nullptr), m_targetProcess(INVALID_HANDLE_VALUE),
    m_targetPid(0), m_monitorDuration(60), m_enableETW(true),
    m_enableNetworkFilter(false), m_isMonitoring(false) {
    g_monitorInstance = this;
}

AdvancedBehaviorMonitor::~AdvancedBehaviorMonitor() {
    StopMonitoring();
    g_monitorInstance = nullptr;
}

bool AdvancedBehaviorMonitor::StartMonitoring(const std::string& targetProcess, const std::string& arguments) {
    if (m_isMonitoring) {
        std::cerr << "[-] Monitoring is already in progress." << std::endl;
        return false;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    std::string commandLine = "\"" + targetProcess + "\" " + arguments;
    std::vector<char> cmdLineBuf(commandLine.begin(), commandLine.end());
    cmdLineBuf.push_back('\0');

    if (!CreateProcessA(
        targetProcess.c_str(),
        cmdLineBuf.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        nullptr,
        &si,
        &pi)) {
        std::cerr << "[-] Failed to start process: " << GetLastError() << std::endl;
        return false;
    }

    m_targetProcess = pi.hProcess;
    m_targetPid = pi.dwProcessId;
    m_targetName = PathFindFileNameA(targetProcess.c_str());
    m_targetPath = targetProcess;
    m_isMonitoring = true;

    std::cout << "[+] Target process created: " << m_targetName
        << " (PID: " << m_targetPid << ")" << std::endl;

    m_events.clear();
    m_childProcesses.clear();
    m_childProcesses.insert(m_targetPid);

    if (m_enableETW) {
        if (!StartETWTracing()) {
            std::cerr << "[-] ETW tracing setup failed" << std::endl;
        }
    }

    if (m_enableNetworkFilter) {
        if (!SetupNetworkFilter()) {
            std::cerr << "[-] Network filter setup failed" << std::endl;
        }
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    std::thread monitorThread(&AdvancedBehaviorMonitor::MonitoringMain, this);
    monitorThread.detach();

    return true;
}

void AdvancedBehaviorMonitor::StopMonitoring() {
    if (!m_isMonitoring) return;
    m_isMonitoring = false;

    if (m_etwThread.joinable()) {
        StopETWTracing();
        m_etwThread.join();
    }

    CleanupNetworkFilter();

    TerminateAllMonitoredProcesses();

    if (m_traceProperties) {
        free(m_traceProperties);
        m_traceProperties = nullptr;
    }

    std::cout << "[+] Monitoring stopped" << std::endl;
}

DWORD WINAPI AdvancedBehaviorMonitor::ETWThread(LPVOID lpParam) {
    AdvancedBehaviorMonitor* monitor = static_cast<AdvancedBehaviorMonitor*>(lpParam);
    monitor->ProcessETWEvents();
    return 0;
}

bool AdvancedBehaviorMonitor::StartETWTracing() {
    const wchar_t* loggerName = KERNEL_LOGGER_NAME;
    ULONG bufferSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(loggerName) + 1) * sizeof(wchar_t));
    m_traceProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!m_traceProperties) {
        std::cerr << "[-] Failed to allocate memory for ETW properties." << std::endl;
        return false;
    }
    ZeroMemory(m_traceProperties, bufferSize);

    m_traceProperties->Wnode.BufferSize = bufferSize;
    m_traceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    m_traceProperties->Wnode.ClientContext = 1;
    m_traceProperties->Wnode.Guid = SystemTraceControlGuid;
    m_traceProperties->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD |
        EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_REGISTRY |
        EVENT_TRACE_FLAG_NETWORK_TCPIP;
    m_traceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    m_traceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    wcsncpy_s((wchar_t*)((char*)m_traceProperties + m_traceProperties->LoggerNameOffset),
        (bufferSize - sizeof(EVENT_TRACE_PROPERTIES)) / sizeof(wchar_t),
        loggerName, wcslen(loggerName));

    ULONG status = StartTraceW(&m_traceHandle, KERNEL_LOGGER_NAME, m_traceProperties);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] StartTrace failed: " << status << std::endl;
        free(m_traceProperties);
        m_traceProperties = nullptr;
        return false;
    }

    m_etwThread = std::thread(&AdvancedBehaviorMonitor::ETWThread, this);
    std::cout << "[+] ETW tracing started successfully" << std::endl;
    return true;
}

void AdvancedBehaviorMonitor::StopETWTracing() {
    if (m_traceHandle != 0) {
        StopTraceW(m_traceHandle, KERNEL_LOGGER_NAME, m_traceProperties);
        m_traceHandle = 0;
    }
}

void AdvancedBehaviorMonitor::ProcessETWEvents() {

    EVENT_TRACE_LOGFILE logFile;
    ZeroMemory(&logFile, sizeof(logFile));
    logFile.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = &AdvancedBehaviorMonitor::ETWEventCallback;
    logFile.Context = this;

    m_traceHandle = OpenTraceW(&logFile);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "[-] OpenTraceW failed: " << GetLastError() << std::endl;
        return;
    }

    TRACEHANDLE traceHandles[1] = { m_traceHandle };
    ULONG status = ProcessTrace(traceHandles, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] ProcessTrace failed: " << status << std::endl;
    }

    CloseTrace(m_traceHandle);
}

void WINAPI AdvancedBehaviorMonitor::ETWEventCallback(PEVENT_RECORD eventRecord) {
    if (!g_monitorInstance) return;

    if (IsEqualGUID(eventRecord->EventHeader.ProviderId, FileIoProviderGuid)) {
        g_monitorInstance->HandleFileIoEvent(eventRecord);
    }
    else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, RegistryProviderGuid)) {
        g_monitorInstance->HandleRegistryEvent(eventRecord);
    }
    else if (IsEqualGUID(eventRecord->EventHeader.ProviderId, TcpIpProviderGuid)) {
        g_monitorInstance->HandleNetworkEvent(eventRecord);
    }
}

void AdvancedBehaviorMonitor::HandleFileIoEvent(PEVENT_RECORD eventRecord) {
    if (!IsTargetProcessOrChild(eventRecord->EventHeader.ProcessId)) return;

    std::string operation;
    bool logged = false;

    if (eventRecord->EventHeader.EventDescriptor.Opcode == 64) {
        operation = "READ";
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 65) {
        operation = "WRITE";
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 67) {
        operation = "CREATE";
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 68) {
        operation = "CLEANUP";
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 71) {
        operation = "DELETE";
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 72) {
        operation = "RENAME";
    }

    if (!operation.empty()) {
        std::string filePath = "Unknown Path";
        PBYTE pData = (PBYTE)eventRecord->UserData;
        if (pData) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            filePath = converter.to_bytes(reinterpret_cast<const wchar_t*>(pData));
        }
        LogEvent("FILE_" + operation, "Path: " + filePath, eventRecord->EventHeader.ProcessId);
        logged = true;
    }

    if (eventRecord->EventHeader.EventDescriptor.Opcode == 32) {
        std::string filePath = "Unknown Path";
        PBYTE pData = (PBYTE)eventRecord->UserData;
        if (pData) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            filePath = converter.to_bytes(reinterpret_cast<const wchar_t*>(pData));
        }
        LogEvent("FILE_CREATE", "Path: " + filePath, eventRecord->EventHeader.ProcessId);
        logged = true;
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 35) {
        std::string filePath = "Unknown Path";
        PBYTE pData = (PBYTE)eventRecord->UserData;
        if (pData) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            filePath = converter.to_bytes(reinterpret_cast<const wchar_t*>(pData));
        }
        LogEvent("FILE_DELETE", "Path: " + filePath, eventRecord->EventHeader.ProcessId);
        logged = true;
    }
}

void AdvancedBehaviorMonitor::HandleRegistryEvent(PEVENT_RECORD eventRecord) {
    if (!IsTargetProcessOrChild(eventRecord->EventHeader.ProcessId)) return;

    std::string operation;
    if (eventRecord->EventHeader.EventDescriptor.Opcode == 33) {
        operation = "CREATE_KEY";
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 34) {
        operation = "OPEN_KEY";
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 35) {
        operation = "DELETE_KEY";
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 36) {
        operation = "SET_VALUE";
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 37) {
        operation = "QUERY_VALUE";
    }

    if (!operation.empty()) {
        std::string keyPath = "Unknown Path";
        PBYTE pData = (PBYTE)eventRecord->UserData;
        if (pData) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            keyPath = converter.to_bytes(reinterpret_cast<const wchar_t*>(pData));
        }

        LogEvent("REGISTRY_" + operation, "Key: " + keyPath, eventRecord->EventHeader.ProcessId);
    }
}

void AdvancedBehaviorMonitor::HandleNetworkEvent(PEVENT_RECORD eventRecord) {
    if (!IsTargetProcessOrChild(eventRecord->EventHeader.ProcessId)) return;

    if (eventRecord->EventHeader.EventDescriptor.Opcode == 10) {
        // TcpIp_V6_Connect
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 12) {
        // TcpIp_V4_Connect
        PBYTE pData = (PBYTE)eventRecord->UserData;
        DWORD localAddr = *((DWORD*)pData);
        USHORT localPort = *((USHORT*)(pData + 4));
        DWORD remoteAddr = *((DWORD*)(pData + 8));
        USHORT remotePort = *((USHORT*)(pData + 12));

        char remoteAddrStr[INET_ADDRSTRLEN];
        InetNtopA(AF_INET, &remoteAddr, remoteAddrStr, INET_ADDRSTRLEN);

        LogEvent("NETWORK_TCP_CONNECT", "To: " + std::string(remoteAddrStr) + ":" + std::to_string(ntohs(remotePort)), eventRecord->EventHeader.ProcessId);
    }
    else if (eventRecord->EventHeader.EventDescriptor.Opcode == 13) {
        // TcpIp_V4_Disconnect
        LogEvent("NETWORK_TCP_DISCONNECT", "", eventRecord->EventHeader.ProcessId);
    }
}

bool AdvancedBehaviorMonitor::SetupNetworkFilter() {
    FWPM_SESSION0 session;
    ZeroMemory(&session, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &m_engineHandle);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmEngineOpen0 failed: " << status << std::endl;
        return false;
    }
    std::cout << "[+] FwpmEngine opened successfully." << std::endl;

    status = FwpmTransactionBegin0(m_engineHandle, 0);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmTransactionBegin0 failed: " << status << std::endl;
        return false;
    }

    FWPM_SUBLAYER0 sublayer;
    ZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = { 0x56a65529, 0xc10c, 0x4896, {0x8f, 0x42, 0x8a, 0x22, 0x2f, 0x4e, 0x3f, 0x4b} };
    sublayer.displayData.name = (wchar_t*)L"Advanced Behavior Monitor Sublayer";
    sublayer.displayData.description = (wchar_t*)L"Sublayer for monitoring a specific process's network activity.";
    sublayer.weight = 0x100;
    status = FwpmSubLayerAdd0(m_engineHandle, &sublayer, nullptr);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmSubLayerAdd0 failed: " << status << std::endl;
        FwpmTransactionAbort0(m_engineHandle);
        FwpmEngineClose0(m_engineHandle);
        return false;
    }
    m_filterIds.push_back(sublayer.subLayerKey.Data4[7]);

    FWPM_FILTER_CONDITION0 conditions[1];
    ZeroMemory(&conditions, sizeof(conditions));
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;

    std::wstring wProcessPathStr(m_targetPath.begin(), m_targetPath.end());
    FWP_BYTE_BLOB* pathBlob = nullptr;
    status = FwpmGetAppIdFromFileName0(wProcessPathStr.c_str(), &pathBlob);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmGetAppIdFromFileName0 failed: " << status << std::endl;
        FwpmTransactionAbort0(m_engineHandle);
        FwpmEngineClose0(m_engineHandle);
        return false;
    }
    conditions[0].conditionValue.byteBlob = pathBlob;

    FWPM_FILTER0 filter;
    ZeroMemory(&filter, sizeof(filter));
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = sublayer.subLayerKey;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_PERMIT;
    filter.displayData.name = (wchar_t*)L"Monitor Target Process Network";
    filter.numFilterConditions = 1;
    filter.filterCondition = conditions;

    UINT64 filterId;
    status = FwpmFilterAdd0(m_engineHandle, &filter, nullptr, &filterId);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmFilterAdd0 failed: " << status << std::endl;
        FwpmFreeMemory0((void**)&pathBlob);
        FwpmTransactionAbort0(m_engineHandle);
        FwpmEngineClose0(m_engineHandle);
        return false;
    }
    m_filterIds.push_back(filterId);
    FwpmFreeMemory0((void**)&pathBlob);

    status = FwpmTransactionCommit0(m_engineHandle);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] FwpmTransactionCommit0 failed: " << status << std::endl;
        FwpmEngineClose0(m_engineHandle);
        return false;
    }

    std::cout << "[+] Network filter installed" << std::endl;
    return true;
}

void AdvancedBehaviorMonitor::CleanupNetworkFilter() {
    if (m_engineHandle) {
        FwpmTransactionBegin0(m_engineHandle, 0);
        for (auto filterId : m_filterIds) {
            FwpmFilterDeleteById0(m_engineHandle, filterId);
        }
        FwpmTransactionCommit0(m_engineHandle);
        FwpmEngineClose0(m_engineHandle);
        m_engineHandle = nullptr;
    }
    m_filterIds.clear();
}

void AdvancedBehaviorMonitor::MonitoringMain() {
    auto startTime = std::chrono::steady_clock::now();
    while (m_isMonitoring) {
        auto currentTime = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();

        if (elapsed >= m_monitorDuration && m_monitorDuration > 0) {
            std::cout << "[!] Monitoring duration reached. Stopping." << std::endl;
            break;
        }

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    std::lock_guard<std::mutex> lock(m_dataMutex);
                    if (m_childProcesses.find(pe32.th32ParentProcessID) != m_childProcesses.end()) {
                        if (m_childProcesses.find(pe32.th32ProcessID) == m_childProcesses.end()) {
                            m_childProcesses.insert(pe32.th32ProcessID);

                            std::wstring wExeFile(pe32.szExeFile);
                            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
                            std::string exeFile = converter.to_bytes(wExeFile);

                            LogEvent("PROCESS_CREATE",
                                "Child process created: " + exeFile +
                                " (PID: " + std::to_string(pe32.th32ProcessID) + ")",
                                pe32.th32ProcessID);
                        }
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    StopMonitoring();
}

void AdvancedBehaviorMonitor::TerminateAllMonitoredProcesses() {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    if (m_targetPid != 0) {
        m_childProcesses.erase(m_targetPid);
    }

    for (DWORD pid : m_childProcesses) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            if (TerminateProcess(hProcess, 0)) {
                std::cout << "[+] Terminated child process with PID: " << pid << std::endl;
            }
            else {
                std::cerr << "[-] Failed to terminate child process with PID " << pid
                    << ", Error: " << GetLastError() << std::endl;
            }
            CloseHandle(hProcess);
        }
    }

    if (m_targetProcess != INVALID_HANDLE_VALUE) {
        if (TerminateProcess(m_targetProcess, 0)) {
            std::cout << "[+] Terminated target process with PID: " << m_targetPid << std::endl;
        }
        else {
            std::cerr << "[-] Failed to terminate target process with PID " << m_targetPid
                << ", Error: " << GetLastError() << std::endl;
        }
        CloseHandle(m_targetProcess);
        m_targetProcess = INVALID_HANDLE_VALUE;
        m_targetPid = 0;
    }
}

void AdvancedBehaviorMonitor::LogEvent(const std::string& type, const std::string& details, DWORD pid) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    BehaviorEvent event;
    event.timestamp = GetCurrentTimestamp();
    event.type = type;
    event.details = details;
    event.processId = (pid == 0) ? m_targetPid : pid;
    event.processName = GetProcessName(event.processId);

    m_events.push_back(event);

    if (type.rfind("FILE", 0) == 0 || type.rfind("REGISTRY", 0) == 0 || type.rfind("NETWORK", 0) == 0 || type.rfind("PROCESS_CREATE", 0) == 0) {
        std::cout << "[" << event.timestamp << "] " << event.processName << " (" << event.processId << ") " << type << " -> " << event.details << std::endl;
    }
}

bool AdvancedBehaviorMonitor::IsTargetProcessOrChild(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    return m_childProcesses.find(pid) != m_childProcesses.end();
}

std::string AdvancedBehaviorMonitor::GetProcessName(DWORD pid) {
    if (pid == m_targetPid) return m_targetName;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        char processName[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, nullptr, processName, MAX_PATH)) {
            CloseHandle(hProcess);
            return PathFindFileNameA(processName);
        }
        CloseHandle(hProcess);
    }
    return "Unknown";
}

std::string AdvancedBehaviorMonitor::GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm timeInfo;
    if (localtime_s(&timeInfo, &in_time_t) == 0) {
        std::stringstream ss;
        ss << std::put_time(&timeInfo, "%Y-%m-%d %X");
        return ss.str();
    }
    return "Timestamp Error";
}

void AdvancedBehaviorMonitor::GenerateReport(const std::string& filename) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    std::ofstream report(filename);
    if (!report.is_open()) {
        std::cerr << "[-] Failed to create report file" << std::endl;
        return;
    }

    report << "Advanced Behavior Monitoring Report\n";
    report << "===================================\n\n";
    report << "Target Process: " << m_targetName << " (PID: " << m_targetPid << ")\n";
    report << "Monitoring Duration: " << m_monitorDuration << " seconds\n";
    report << "Total Events Recorded: " << m_events.size() << "\n\n";

    std::unordered_map<std::string, int> eventCounts;
    for (const auto& event : m_events) {
        eventCounts[event.type]++;
    }

    report << "Event Statistics:\n";
    report << "----------------\n";
    for (const auto& count : eventCounts) {
        report << count.first << ": " << count.second << " events\n";
    }
    report << "\n";

    report << "Detailed Events:\n";
    report << "---------------\n";
    for (const auto& event : m_events) {
        report << "[" << event.timestamp << "] " << event.processName << " (" << event.processId << ") " << event.type
            << " -> " << event.details << "\n";
    }

    report.close();
    std::cout << "[+] Report generated: " << filename << std::endl;
}