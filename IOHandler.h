#ifndef STRACECONSUMER_IOHANDLER_H
#define STRACECONSUMER_IOHANDLER_H

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
        string timestamp;
        string cpuTime;
        string name;
        std::vector <string> args;
        string ret;
        string retDesc;
        string toString(){
            string tmp = pid + "\t" + timestamp + "\t" + "(" + cpuTime + ")" + "\n";
            tmp += "[" + GetGroup(name) +"]\t" + name + "\n";
            for(int i = 0; i < args.size(); i++){
                tmp += "\t" + std::to_string(i+1) + ": " + args[i] + "\n";
            }
            tmp += ret;
            tmp += (retDesc.empty()) ? "" : " " + retDesc;
            return tmp;
        };
        string toStringCompact(){
          string tmp = pid + " " + timestamp + "[" + GetGroup(name) + "]\t(" + cpuTime + ") " + name + "(";

          if (args.size() > 1) {
              for (int i = 0; i < args.size()-1; i++) {
                  tmp += args[i] + ", ";
              }
              tmp += args[args.size()-1];
          } else if (args.size() == 1) {
              tmp += args[0];
          }

          tmp += ") = " + ret + " " + retDesc;
          return tmp;
        };
    };

    static std::map<string, int> groupMap;
    static std::vector<string> groupNames;
    IOHandler();
    explicit IOHandler(const string& fn);
    void Destroy();
    void GenerateReport(const string& reportName,
            string targetName,
            std::chrono::steady_clock::time_point targetStart);
    void OpenFile();
    static void WriteToReports(char* output);
    void ReadInGroups(string filepath);
    void ParseTraceFile(const string& filepath);
    static SyscallData ParseTraceLine(string& line);
    void WriteDTrussList();

private:
    string logFN;
    static string& getDefaultGroupPath();
    std::vector<SyscallData> dtrussSyscallList;
    std::string GetTotalCPUTime();
    void WriteHeader(string& targetName, std::chrono::steady_clock::time_point targetStart);
    static void WriteSummary(std::map<string, int>& syscallCounts);
    static void DEBUGPrintVector(std::vector<string>& v);

};
#endif //STRACECONSUMER_IOHANDLER_H

