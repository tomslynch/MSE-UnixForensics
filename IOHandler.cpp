//
// Created by Thomas Lynch on 2/8/19.
//
//#include <stdio.h>

#include <ctime>
#include <map>
#include "IOHandler.h"
#include <regex>
#include <iostream>
#include <fstream>

//#include <zconf.h>


using namespace std;



struct SyscallData {
    string name;
    string group;
    string* args;
    string ret;
    string retDesc;
};

struct TraceData {
//    int pid;
    string pid;
    string tid;
    SyscallData sysInfo;
};

//string filename;
static FILE *fp;

IOHandler::IOHandler() = default;

IOHandler::IOHandler(string fn) {
    if (fn.length() == 0) {
        time_t t = time(nullptr);
        auto intNow = static_cast<long int> (t);
        logFN = std::to_string(intNow);
    } else {
        logFN = fn;
    }

    fp = NULL;
}

//fputs("<<Syscalls>>\nDETAILED SECTION:\n", fp);
void IOHandler::OpenFile(){
    fp = fopen(logFN.c_str(), "w+");
}

 void IOHandler::WriteToReports(char* output){
    char buffer[256];
    std::time_t t = std::time(nullptr);   // get time now
    std::tm* now = std::localtime(&t);
    strftime(buffer, sizeof(buffer), "%H:%M:%S", now);
//     std::cout << output << std::endl;

    fprintf(fp, "[%s]\t%s\n", buffer, output);
//     std::cout << output << std::endl;

 }

void IOHandler::Destroy() {
    if (fp != nullptr) {
        fclose(fp);
    }
}

template<typename A, typename B>
std::pair<B,A> flip_pair(const std::pair<A,B> &p)
{
    return std::pair<B,A>(p.second, p.first);
}

template<typename A, typename B>
std::multimap<B,A> flip_map(const std::map<A,B> &src)
{
    std::multimap<B,A> dst;
    std::transform(src.begin(), src.end(), std::inserter(dst, dst.begin()),
                   flip_pair<A,B>);
    return dst;
}

 void IOHandler::WriteSummary(std::map <string, int> syscallCounts){
    string summary = "\n************* SUMMARY *************\n";
    fprintf(fp, "%s", summary.c_str());

    std::multimap<int, string> SortedSyscallCounts = flip_map(syscallCounts);
    for (auto const& x : SortedSyscallCounts)
    {
        fprintf(fp, "%s\t%s\n", std::to_string(x.first).c_str(), x.second.c_str());
    }
}


////static TraceData ParseTraceLine(string line){
 void IOHandler::ParseTraceLine(string line){
    regex p("^.*:");
    regex p2(":.*\\(.*\\)");
    regex p3("=.*$");

    TraceData td;
    // grab pid and tid
    smatch m;
    if (regex_search(line, m, p)) {
//        std::cout << m.str(0) << std::endl;
        string test = m.str(0);
//        td.pid = stoi(test.substr(0, test.find('/')));
        td.pid = test.substr(0, test.find('/'));
        td.tid = test.substr(test.find('/')+1, (test.length()-2) - test.find('/'));
    }

    //grab syscall
    if (regex_search(line, m, p2)) {
        string match = m.str(0);
        td.sysInfo = SyscallData();
        td.sysInfo.name = match.substr(1, match.find('('));
        td.sysInfo.group = "";

        //grab args
        regex argR("\\(.*\\)");
        if (regex_search(match, m, argR)) {
            size_t pos = 1;
            string token;
            string tmp = m.str(0);
            cout << tmp << endl;
            tmp.erase(0,1);
            while((pos = tmp.find(',')) !=  string::npos){
                token = tmp.substr(0, pos);
                cout << "\t" + token << endl;
                tmp.erase(0, pos + 1);
            }
            tmp.erase(tmp.length()-1, tmp.length());
            cout << "\t" + tmp << endl;
        }

        //grab return info
    }
}

 void IOHandler::ParseTraceFile(){
    string line;
    ifstream myfile ("trace");
    if (myfile.is_open())
    {
        while (getline(myfile, line))
        {
            ParseTraceLine(line);
        }
        myfile.close();
    } else {
        cout << "Unable to open file\n";
    }
}
