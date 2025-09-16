#include "monitor.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <load_exe> <target_file> [duration]" << std::endl;
        return 1;
    }

    std::string loadExe = argv[1];
    std::string targetFile = argv[2];
    int duration = (argc > 3) ? std::stoi(argv[3]) : 60;

    // 高级行为监控
    AdvancedBehaviorMonitor monitor;
    monitor.SetMonitoringDuration(duration);
    monitor.EnableETWMonitoring(true);
    monitor.EnableNetworkFilter(true);

    std::cout << "[+] Starting advanced behavior monitoring..." << std::endl;

    // 通过load.exe运行目标文件
    std::string arguments = "\"" + targetFile + "\"";
    if (monitor.StartMonitoring(loadExe, arguments)) {
        // 等待监控完成
        std::this_thread::sleep_for(std::chrono::seconds(duration + 5));

        monitor.GenerateReport("advanced_behavior_report.txt");
        std::cout << "[+] Advanced behavior monitoring completed!" << std::endl;
    }

    return 0;
}