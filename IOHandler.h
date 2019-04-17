//
// Created by Thomas Lynch on 2/8/19.
//

#ifndef DTRACECONSUMER_IOHANDLER_H
#define DTRACECONSUMER_IOHANDLER_H

#include <ctime>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <regex>
#include <iostream>
#include <fstream>
#include <chrono>

using std::string;

class IOHandler {
public:
    static string GetGroup(string& syscall);
    struct SyscallData {
        string pid;
        string tid;
        string relTime;
        string elapsedTime;
        string cpuTime;

        string name;
        std::vector <string> args;
        string ret;
        string retDesc;
        string toString(){
            string tmp = pid + "/" + tid + ":\t" + relTime + "|" + elapsedTime + "|" + cpuTime + "\n";
            tmp += "[" + GetGroup(name) + "]\t" + name + "\n";
            for(int i = 0; i < args.size(); i++){
                tmp += "\t" + std::to_string(i+1) + ": " + args[i] + "\n";
            }
            tmp += ret + ":" + retDesc;

            return tmp;
        };
    };
    static std::map<string, int> groupMap;
    static std::vector<string> groupNames;


    IOHandler();
    explicit IOHandler(const string& fn);
    static void Destroy();
    void GenerateReport(string targetName,
            std::map<string, int> syscallCounts,
            std::vector<string> syscallList,
            std::chrono::steady_clock::time_point targetStart,
            std::chrono::steady_clock::time_point progStart);
    void OpenFile();
    static void WriteToReports(char* output);
    void ReadInGroups(string filepath);
    void ParseTraceFile();
    static SyscallData ParseTraceLine(string& line);

private:
    string logFN;
    static string& getDefaultGroupPath();
    std::vector<SyscallData> dtrussSyscallList;
    std::string GetTotalCPUTime();
    void WriteHeader(string& targetName,
            std::chrono::steady_clock::time_point targetStart,
            std::chrono::steady_clock::time_point progStart);
    static void WriteSummary(std::map<string, int>& syscallCounts);
    static void WriteDTraceList(std::vector<string>& syscallList);
    void WriteDTrussList();
    static void DEBUGPrintVector(std::vector<string>& v);

};
#endif //DTRACECONSUMER_IOHANDLER_H

