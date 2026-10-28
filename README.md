# Windows Process Monitoring System

A C++ based Operating Systems mini project that monitors running processes and displays system resource usage on Windows.

## 📌 Project Overview

The Windows Process Monitoring System helps users observe running processes and understand how system resources are being used. It is developed using C++ and Windows system APIs.

## 🎯 Objectives

- Monitor running processes on Windows.
- Display process information.
- Observe system resource usage.
- Understand operating system concepts such as process management and CPU utilization.

## 🛠️ Technologies Used

- **Programming Language:** C++
- **Operating System:** Windows
- **Compiler:** GCC (MSYS2 UCRT64)
- **Libraries:** Windows API, PSAPI

## ✨ Features

- Lists running processes.
- Displays available process information.
- Monitors system resource usage.
- Provides a simple, terminal-based interface.

*Note: The exact features depend on the implementation in `ProcessMonitoringSystem.cpp`.*

## 💻 Requirements

- Windows 10 or Windows 11
- MSYS2 with the UCRT64 GCC compiler
- Git (optional, for version control)

## 🚀 How to Run

### 1. Clone the repository

```bash
git clone https://github.com/farazak2006/Process-Monitoring-System.git
cd Process-Monitoring-System
```

### 2. Compile the program

Open PowerShell in the project folder and run:

```bash
g++ ProcessMonitoringSystem.cpp -o ProcessMonitor.exe -lpsapi
```

### 3. Execute the program

```powershell
.\ProcessMonitor.exe
```

## 📂 Project Structure

```text
Process-Monitoring-System/
├── ProcessMonitoringSystem.cpp
├── README.md
└── .gitignore
```

## 📚 Concepts Covered

- Process management
- CPU utilization
- System monitoring
- Windows system calls and APIs
- Resource management in operating systems

## 🎓 Project Information

**Project Type:** Operating Systems Mini Project  
**Language:** C++  
**Platform:** Windows

## 👨‍💻 Author

**Faraz AK**

GitHub: [@farazak2006](https://github.com/farazak2006)

## 📄 License

This project is intended for educational purposes.
