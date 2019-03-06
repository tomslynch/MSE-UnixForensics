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



using std::string;

class IOHandler {
    public:
        void WriteSummary(std::map <string, int> syscallCounts);
        IOHandler();
        explicit IOHandler(string fn);
        void OpenFile();
        void WriteToReports(char* output);
        void Destroy();
        static std::map<string, int> groupMap;
        static std::vector<string> groupNames;
        void ReadInGroups(string filepath);
        static string GetGroup(string syscall);

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
//    static FILE *fp;

    void ParseTraceFile();
    void ParseTraceLine(string line);
    private:
        void WriteHeader();
        void DEBUGPrintVector(std::vector<string> v);
        string logFN;
        string tmpFN;
        static string const DEFAULT_GROUP_PATH;

};
#endif //DTRACECONSUMER_IOHANDLER_H

