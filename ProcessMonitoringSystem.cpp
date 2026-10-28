#define NOMINMAX
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <conio.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <ctime>
#include <cctype>

#pragma comment(lib, "Psapi.lib")
using namespace std;

struct ProcessInfo {
    DWORD pid = 0, ppid = 0, threads = 0;
    string name;
    double cpu = 0.0, memoryMB = 0.0;
    bool accessible = false;
    string status = "Restricted";
};

const double WARN_CPU = 30.0, CRIT_CPU = 60.0;
const double WARN_MEM = 500.0, CRIT_MEM = 1000.0;
const int CRIT_REFRESHES = 3;
int refreshSeconds = 2, topN = 15, sortMode = 1;
DWORD processorCount = 1;

map<DWORD, ULONGLONG> previousProcessTimes;
map<DWORD, int> criticalCounts;
ULONGLONG previousWallTime = 0;

ULONGLONG fileTimeValue(const FILETIME& ft) {
    ULARGE_INTEGER value;
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

ULONGLONG wallTimeNow() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return fileTimeValue(ft);
}

string lowerCase(string value) {
    transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return value;
}

bool isNumber(const string& value) {
    if (value.empty()) return false;
    return all_of(value.begin(), value.end(),
        [](unsigned char c) { return isdigit(c) != 0; });
}

string readLine(const string& prompt) {
    cout << prompt;
    string value;
    getline(cin, value);
    return value;
}

bool isProtectedProcess(const ProcessInfo& p) {
    static const char* protectedNames[] = {
        "system", "system idle process", "registry", "smss.exe",
        "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe",
        "fontdrvhost.exe", nullptr
    };

    if (p.pid == 0 || p.pid == 4 || p.pid == GetCurrentProcessId())
        return true;

    const string name = lowerCase(p.name);
    for (int i = 0; protectedNames[i] != nullptr; ++i)
        if (name == protectedNames[i]) return true;

    return false;
}

string classifyProcess(const ProcessInfo& p) {
    if (!p.accessible) return "Restricted";

    const bool critical = p.cpu >= CRIT_CPU || p.memoryMB >= CRIT_MEM;
    const bool warning = p.cpu >= WARN_CPU || p.memoryMB >= WARN_MEM;

    if (critical) ++criticalCounts[p.pid];
    else criticalCounts[p.pid] = 0;

    if (criticalCounts[p.pid] >= CRIT_REFRESHES) return "HIGH USAGE";
    if (warning) return "Watch";
    return "Normal";
}

void collectProcesses(vector<ProcessInfo>& processes) {
    processes.clear();

    const ULONGLONG wall = wallTimeNow();
    const ULONGLONG wallDelta =
        (previousWallTime != 0 && wall >= previousWallTime)
        ? wall - previousWallTime : 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        cerr << "Could not take process snapshot. Windows error: "
             << GetLastError() << "\n";
        return;
    }

    map<DWORD, ULONGLONG> currentTimes;
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    if (Process32First(snapshot, &entry)) {
        do {
            ProcessInfo p;
            p.pid = entry.th32ProcessID;
            p.ppid = entry.th32ParentProcessID;
            p.name = entry.szExeFile;
            p.threads = entry.cntThreads;

            HANDLE process = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE, p.pid);

            if (process != nullptr) {
                PROCESS_MEMORY_COUNTERS_EX memoryInfo{};
                memoryInfo.cb = sizeof(memoryInfo);
                if (GetProcessMemoryInfo(process,
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryInfo),
                    sizeof(memoryInfo))) {
                    p.memoryMB = static_cast<double>(memoryInfo.WorkingSetSize)
                                 / (1024.0 * 1024.0);
                    p.accessible = true;
                }

                FILETIME creation{}, exitTime{}, kernel{}, user{};
                if (GetProcessTimes(process, &creation, &exitTime, &kernel, &user)) {
                    const ULONGLONG total =
                        fileTimeValue(kernel) + fileTimeValue(user);
                    currentTimes[p.pid] = total;

                    auto old = previousProcessTimes.find(p.pid);
                    if (old != previousProcessTimes.end() &&
                        wallDelta > 0 && total >= old->second) {
                        p.cpu = 100.0 * static_cast<double>(total - old->second)
                                / static_cast<double>(wallDelta)
                                / static_cast<double>(processorCount);
                        if (p.cpu > 100.0) p.cpu = 100.0;
                    }
                    p.accessible = true;
                }
                CloseHandle(process);
            }

            p.status = classifyProcess(p);
            processes.push_back(p);
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    previousProcessTimes.swap(currentTimes);
    previousWallTime = wall;

    for (auto it = criticalCounts.begin(); it != criticalCounts.end();) {
        if (previousProcessTimes.find(it->first) == previousProcessTimes.end())
            it = criticalCounts.erase(it);
        else
            ++it;
    }
}

struct SystemUsage {
    double cpu = 0.0, usedMB = 0.0, totalMB = 0.0;
    DWORD memoryPercent = 0;
};

SystemUsage getSystemUsage() {
    static ULONGLONG lastIdle = 0, lastKernel = 0, lastUser = 0;
    SystemUsage result;

    FILETIME idleTime{}, kernelTime{}, userTime{};
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        ULONGLONG idle = fileTimeValue(idleTime);
        ULONGLONG kernel = fileTimeValue(kernelTime);
        ULONGLONG user = fileTimeValue(userTime);

        if (lastKernel != 0 && kernel >= lastKernel && user >= lastUser &&
            idle >= lastIdle) {
            ULONGLONG totalDelta = (kernel - lastKernel) + (user - lastUser);
            ULONGLONG idleDelta = idle - lastIdle;
            if (totalDelta > 0 && idleDelta <= totalDelta)
                result.cpu = 100.0 * (totalDelta - idleDelta) / totalDelta;
        }
        lastIdle = idle;
        lastKernel = kernel;
        lastUser = user;
    }

    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory)) {
        result.totalMB = memory.ullTotalPhys / (1024.0 * 1024.0);
        result.usedMB = (memory.ullTotalPhys - memory.ullAvailPhys)
                        / (1024.0 * 1024.0);
        result.memoryPercent = memory.dwMemoryLoad;
    }
    return result;
}

bool byCPU(const ProcessInfo& a, const ProcessInfo& b) {
    return a.cpu > b.cpu;
}
bool byMemory(const ProcessInfo& a, const ProcessInfo& b) {
    return a.memoryMB > b.memoryMB;
}
bool byPID(const ProcessInfo& a, const ProcessInfo& b) {
    return a.pid < b.pid;
}
bool byName(const ProcessInfo& a, const ProcessInfo& b) {
    return lowerCase(a.name) < lowerCase(b.name);
}

void sortProcesses(vector<ProcessInfo>& processes) {
    switch (sortMode) {
        case 1: sort(processes.begin(), processes.end(), byCPU); break;
        case 2: sort(processes.begin(), processes.end(), byMemory); break;
        case 3: sort(processes.begin(), processes.end(), byPID); break;
        case 4: sort(processes.begin(), processes.end(), byName); break;
    }
}

string sortName() {
    switch (sortMode) {
        case 1: return "CPU";
        case 2: return "Memory";
        case 3: return "PID";
        default: return "Name";
    }
}

void showSummary(size_t count) {
    SystemUsage usage = getSystemUsage();
    cout << fixed << setprecision(1);
    cout << "================ PROCESS MONITORING SYSTEM ================\n";
    cout << "System CPU: " << usage.cpu << "%   Memory: "
         << static_cast<int>(usage.usedMB) << " / "
         << static_cast<int>(usage.totalMB) << " MB ("
         << usage.memoryPercent << "%)   Processes: " << count << "\n";
    cout << "Sorted by: " << sortName()
         << "   Refresh: " << refreshSeconds << " seconds\n\n";
}

void showTable(const vector<ProcessInfo>& processes, size_t limit) {
    cout << left << setw(8) << "PID" << setw(8) << "PPID"
         << setw(28) << "NAME" << right << setw(9) << "CPU %"
         << setw(12) << "MEM (MB)" << setw(10) << "THREADS"
         << "  STATUS\n";
    cout << string(88, '-') << "\n";

    const size_t count = min(limit, processes.size());
    for (size_t i = 0; i < count; ++i) {
        const ProcessInfo& p = processes[i];
        string name = p.name.size() > 27 ? p.name.substr(0, 27) : p.name;
        cout << left << setw(8) << p.pid << setw(8) << p.ppid
             << setw(28) << name << right << fixed << setprecision(1)
             << setw(9) << p.cpu << setw(12) << p.memoryMB
             << setw(10) << p.threads << "  " << p.status << "\n";
    }
    if (processes.size() > count)
        cout << "... " << processes.size() - count << " more processes not shown\n";
    cout << "\n";
}

void sampleTwice(vector<ProcessInfo>& processes) {
    collectProcesses(processes);
    Sleep(700);
    collectProcesses(processes);
}

void liveMonitor() {
    vector<ProcessInfo> processes;
    collectProcesses(processes);

    while (true) {
        Sleep(static_cast<DWORD>(refreshSeconds * 1000));
        collectProcesses(processes);
        sortProcesses(processes);

        system("cls");
        showSummary(processes.size());
        showTable(processes, static_cast<size_t>(topN));
        cout << "Live mode: press any key to return to menu.\n";

        for (int elapsed = 0; elapsed < 500; elapsed += 50) {
            if (_kbhit()) {
                _getch();
                return;
            }
            Sleep(50);
        }
    }
}

void searchMenu() {
    string key = readLine("Enter process name/part of name or PID: ");
    vector<ProcessInfo> processes;
    sampleTwice(processes);

    const bool numeric = isNumber(key);
    const string searchKey = lowerCase(key);
    vector<ProcessInfo> matches;

    for (const auto& p : processes) {
        if ((numeric && p.pid == static_cast<DWORD>(strtoul(key.c_str(), nullptr, 10))) ||
            (!numeric && lowerCase(p.name).find(searchKey) != string::npos))
            matches.push_back(p);
    }

    sort(matches.begin(), matches.end(), byCPU);
    if (matches.empty()) cout << "No matching process found.\n";
    else showTable(matches, matches.size());
}

void terminateProcess(const vector<ProcessInfo>& processes) {
    string input = readLine("Enter PID to terminate: ");
    if (!isNumber(input)) {
        cout << "Invalid PID.\n";
        return;
    }

    DWORD pid = static_cast<DWORD>(strtoul(input.c_str(), nullptr, 10));
    auto found = find_if(processes.begin(), processes.end(),
        [pid](const ProcessInfo& p) { return p.pid == pid; });

    if (found == processes.end()) {
        cout << "No process with that PID was found.\n";
        return;
    }
    if (isProtectedProcess(*found)) {
        cout << "Blocked: this process is protected by the program.\n";
        return;
    }

    cout << "Process: " << found->name << " (PID " << pid << ")\n";
    string confirm = readLine("Terminate this process? Type YES to confirm: ");
    if (confirm != "YES") {
        cout << "Cancelled.\n";
        return;
    }

    HANDLE process = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                                 FALSE, pid);
    if (process == nullptr) {
        cout << "Cannot open process. Windows error: " << GetLastError() << "\n";
        return;
    }

    if (TerminateProcess(process, 1))
        cout << "Termination request sent successfully.\n";
    else
        cout << "Termination failed. Windows error: " << GetLastError() << "\n";

    CloseHandle(process);
}

void saveLog(const vector<ProcessInfo>& processes) {
    if (processes.empty()) {
        cout << "No process data to save. Take a snapshot first.\n";
        return;
    }

    const bool newFile = !ifstream("process_log.csv").good();
    ofstream file("process_log.csv", ios::app);
    if (!file) {
        cout << "Cannot open process_log.csv for writing.\n";
        return;
    }

    if (newFile)
        file << "Timestamp,PID,PPID,Name,CPU_Percent,Memory_MB,Threads,Status\n";

    time_t now = time(nullptr);
    tm localTime{};
    tm* localTimePtr = localtime(&now);
    if (localTimePtr != nullptr) localTime = *localTimePtr;
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &localTime);

    for (const auto& p : processes) {
        string safeName = p.name;
        replace(safeName.begin(), safeName.end(), ',', ' ');
        file << timestamp << ',' << p.pid << ',' << p.ppid << ','
             << '"' << safeName << '"' << ','
             << fixed << setprecision(1) << p.cpu << ',' << p.memoryMB << ','
             << p.threads << ',' << p.status << '\n';
    }
    cout << "Saved " << processes.size() << " records to process_log.csv\n";
}

void settingsMenu() {
    string value = readLine("Refresh interval in seconds (1-60, 0=keep): ");
    if (isNumber(value)) {
        int n = atoi(value.c_str());
        if (n >= 1 && n <= 60) refreshSeconds = n;
        else if (n != 0) cout << "Use a value from 1 to 60, or 0 to keep.\n";
    }

    value = readLine("Rows to display (1-200, 0=keep): ");
    if (isNumber(value)) {
        int n = atoi(value.c_str());
        if (n >= 1 && n <= 200) topN = n;
        else if (n != 0) cout << "Use a value from 1 to 200, or 0 to keep.\n";
    }
}

int main() {
    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);
    processorCount = systemInfo.dwNumberOfProcessors;
    if (processorCount == 0) processorCount = 1;

    SetConsoleTitleA("Process Monitoring System");
    getSystemUsage(); // Initialize system CPU counters.

    vector<ProcessInfo> processes;

    while (true) {
        system("cls");
        cout << "PROCESS MONITORING SYSTEM (CPU cores: "
             << processorCount << ")\n"
             << "1. Show process snapshot\n"
             << "2. Live monitor\n"
             << "3. Search by name or PID\n"
             << "4. Change sorting order\n"
             << "5. Terminate a process\n"
             << "6. Settings\n"
             << "7. Save snapshot to CSV\n"
             << "0. Exit\n";

        string choice = readLine("Choice: ");

        if (choice == "1") {
            sampleTwice(processes);
            sortProcesses(processes);
            showSummary(processes.size());
            showTable(processes, static_cast<size_t>(topN));
        } else if (choice == "2") {
            liveMonitor();
        } else if (choice == "3") {
            searchMenu();
        } else if (choice == "4") {
            cout << "1. CPU  2. Memory  3. PID  4. Name\n";
            string value = readLine("Sort by: ");
            if (value == "1" || value == "2" || value == "3" || value == "4") {
                sortMode = atoi(value.c_str());
                cout << "Sorting by " << sortName() << ".\n";
            } else cout << "Invalid choice.\n";
        } else if (choice == "5") {
            sampleTwice(processes);
            sortProcesses(processes);
            showTable(processes, static_cast<size_t>(topN));
            terminateProcess(processes);
        } else if (choice == "6") {
            settingsMenu();
        } else if (choice == "7") {
            sampleTwice(processes);
            sortProcesses(processes);
            saveLog(processes);
        } else if (choice == "0") {
            cout << "Goodbye.\n";
            break;
        } else {
            cout << "Invalid choice.\n";
        }

        readLine("\nPress Enter to continue...");
    }
    return 0;
}
