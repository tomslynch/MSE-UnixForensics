#include <sys/stat.h>
#include "IOHandler.h"

using namespace std;

//string filename;
static FILE *fp;
 //Add to a conf file later?

string& IOHandler::getDefaultGroupPath(){
    static string DEFAULT_GROUP_PATH = "conf/groupInfo.txt";
    return DEFAULT_GROUP_PATH;
}
std::map<string, int> IOHandler::groupMap;
std::vector<string> IOHandler::groupNames;

IOHandler::IOHandler() = default;

IOHandler::IOHandler(const string& fn) {
    // Init directories
    // TODO: use constants
    mkdir("reports", S_IRWXU);
    mkdir("tmp", S_IRWXU);
    mkdir("conf", S_IRWXU);

    if (fn.length() == 0) {
        time_t t = time(nullptr);
        auto intNow = static_cast<long int> (t);
        logFN = std::to_string(intNow);
    } else {
        logFN = fn;
    }

    fp = nullptr;
}

void IOHandler::OpenFile(){
    fp = fopen(logFN.c_str(), "w+");
}

 void IOHandler::WriteToReports(char* output){
    char buffer[256];
    std::time_t t = std::time(nullptr);   // get time now
    std::tm* now = std::localtime(&t);
    strftime(buffer, sizeof(buffer), "%H:%M:%S", now);

    fprintf(fp, "[%s]\t%s\n", buffer, output);
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

vector<string> ParseArgs(string line){
    //TODO: replace with stream?
    vector<string> args;
    string arg;
    while (!line.empty() && line[0] != ' ') {
        arg = "";
        if (line[0] == '{') {
            arg = line.substr(0, line.find('}')+1);
            line.erase(0, line.find('}')+1);
        } else if (line[0] == '"') {
            arg += "\"";
            line.erase(0,1);
            arg += line.substr(0, line.find('"')+1);
            line.erase(0, line.find('"')+1);
        } else {
            arg = line.substr(0,line.find(','));
            line.erase(0, line.find(','));
        }

        args.push_back(arg);
        //remove comma and space
        if (!line.empty() && line[0] == ',') {
            line.erase(0, 2);
        }
    }
    return args;
}

 IOHandler::SyscallData IOHandler::ParseTraceLine(string& line){
     SyscallData sd;
     smatch m;

     // grab pid and tid
     sd.pid = line.substr(0, line.find(' '));
     line.erase(0, line.find(':')-2);

     sd.timestamp = line.substr(0, line.find(' '));
     line.erase(0, line.find(' ')+1);

     if (line[0] == '<') {
         // resumed statement
         sd.name = "resumed";
         line.erase(0, line.find('>')+2);
         sd.args = ParseArgs(line.substr(0, line.find_last_of(')')));

         // grab return code and cpuTime
         line.erase(0, line.find('=')+2);
         sd.ret = line.substr(0, line.find(' '));
         line.erase(0, line.find(' ')+1);
         sd.retDesc = line.substr(0, line.find('<')); // may be empty
         line.erase(0,line.find('<')+1);
         sd.cpuTime = line.substr(0, line.find('>'));
     } else if (line[0] == '+') {
         // TODO: does exited with == exit/exit_group argument?
         // exit statement
         sd.name = "Exited with";
         line.erase(0, line.find("with")+5);
         sd.ret = line.substr(0, line.find(' '));
     } else {
         // syscall start
         if (line.find("<unfinished ...>") == string::npos) {
             // full syscall
             // ')' seems to be a safe delimiter
             sd.name = line.substr(0, line.find('('));
             line.erase(0, line.find('(')+1);
             sd.args = ParseArgs(line.substr(0,line.find_last_of(')')));
             line.erase(0, line.find_last_of(')'));

             // grab return code and cpuTime
             line.erase(0, line.find('=')+2);
             sd.ret = line.substr(0, line.find(' '));

             // '?' return can occur on exit
             if (sd.ret != "?") {
                 line.erase(0, line.find(' ')+1);
                 sd.retDesc = line.substr(0, line.find('<')); // may be empty
                 line.erase(0,line.find('<')+1);
                 sd.cpuTime = line.substr(0, line.find('>'));
             }
         } else {
             // unfinished syscall
             // ')' seems to be a safe delimiter
             sd.name = line.substr(0, line.find('('));
             line.erase(0, line.find('(')+1);
             sd.args = ParseArgs(line.substr(0,line.find('<')-1));
         }
     }
     return sd;
}

int GetLastSyscallIDXFromPid(vector<IOHandler::SyscallData> list, string& pid){
    for (int i = list.size()-1; i >= 0; i--) {
        if (list[i].pid == pid) {
            return i;
        }
    }
}

void AppendSyscall(IOHandler::SyscallData& start, IOHandler::SyscallData end){
    for(auto const& arg : end.args){
        start.args.push_back(arg);
    }
    start.ret = end.ret;
    start.retDesc = end.retDesc;
}

 void IOHandler::ParseTraceFile(const string& filepath){
    string line;
    ifstream traceFile (filepath);
    if (traceFile.is_open())
    {
        SyscallData tmp;
        while (getline(traceFile, line))
        {
            tmp = ParseTraceLine(line);
            if (tmp.name == "resumed") {
                AppendSyscall(
                        IOHandler::dtrussSyscallList[GetLastSyscallIDXFromPid(IOHandler::dtrussSyscallList, tmp.pid)],
                        tmp);
            } else {
                IOHandler::dtrussSyscallList.push_back(tmp);
            }
        }
        traceFile.close();
    } else {
        cout << "Unable to open file" << endl;
    }
}

string IOHandler::GetTotalCPUTime() {
    long totalMS = 0;
    for (int i = 0; i < dtrussSyscallList.size(); i++) {
        if (!dtrussSyscallList[i].cpuTime.empty() ||
        (i == dtrussSyscallList.size()-1 && dtrussSyscallList[i].name != "thread_selfid")){
            totalMS += stol(dtrussSyscallList[i].cpuTime);
        }
    }

    return to_string(totalMS/60);
}

void IOHandler::ReadInGroups(string filepath){
    if(filepath.empty()){
        filepath = getDefaultGroupPath();
    }
    cout << "Reading in grouping file..." << filepath.c_str() << endl;

    ifstream file(filepath.c_str());
    int idx = 0;
    string tmp;
    string line;
    while(getline(file, line)){
        istringstream ss(line);
        groupNames.push_back(line.substr(0, line.find(',')));
        while (getline(ss, line, ',')) {
            std::transform (line.begin(), line.end(), line.begin(), ::tolower);
            line.erase(0,1);
            groupMap.insert({line, idx});
        }
        idx++;
    }
}

string IOHandler::GetGroup(string& syscall){
    if (groupMap.find(syscall) != groupMap.end()) {
        return IOHandler::groupNames[groupMap[syscall]];
    } else {
        return "UNKNOWN";
    }
}

void IOHandler::DEBUGPrintVector(vector<string>& v){
    for (auto& c : v) {
        cout << c << endl;
    }
}

void IOHandler::WriteHeader(string& targetName,
                            std::chrono::steady_clock::time_point targetStart) {
    auto end = chrono::steady_clock::now();
    fprintf(fp, "%.*s", 80, "#######################################################################################################################################");
    fprintf(fp, "\nMonitoring Tool created by UW-L MSE Student, Thomas Lynch\n");
    fprintf(fp, "Targeted Process:\t\t%s\n", targetName.c_str());
    fprintf(fp, "Total Monitored Time:\t\t%ld seconds\n",
            chrono::duration_cast<chrono::seconds>(end-targetStart).count());
//    fprintf(fp, "Total Target Elapsed Time:\t%ld seconds\n",
//            chrono::duration_cast<chrono::seconds>(end-targetStart).count());
//    fprintf(fp, "Total Target CPU Time:\t\t%s microseconds\n", GetTotalCPUTime().c_str());
    fprintf(fp, "%.*s", 80, "#######################################################################################################################################");
    fprintf(fp, "\n");
}

void IOHandler::WriteSummary(std::map<string, int>& syscallCounts) {
    fprintf(fp, "%s", "\n************* SUMMARY *************\n");

    std::multimap<int, string> SortedSyscallCounts = flip_map(syscallCounts);
    for (auto const& x : SortedSyscallCounts)
    {
        fprintf(fp, "%s\t%s\n", std::to_string(x.first).c_str(), x.second.c_str());
    }
}

void IOHandler::WriteDTrussList() {
    fprintf(fp, "%s", "\n************* STrace Basic Syscall List *************\n");
    string tmp;
    for (auto& dtrussSyscall : dtrussSyscallList) {
        tmp = dtrussSyscall.name + "(";
        for (int i = 0; i < dtrussSyscall.args.size(); i++) {
            if (i == dtrussSyscall.args.size()-1) {
                tmp += dtrussSyscall.args[i] + ")";
            } else {
                tmp += dtrussSyscall.args[i] + ", ";
            }
        }
        fprintf(fp, "%s\n", tmp.c_str());
    }

    fprintf(fp, "%s", "\n************* STrace Detailed Syscall List *************\n");
    for (auto& dtrussSyscall : dtrussSyscallList) {
        fprintf(fp, "%s\n", dtrussSyscall.toStringCompact().c_str());
    }
}

void IOHandler::GenerateReport( const string& reportName,
                                string targetName,
                                std::chrono::steady_clock::time_point targetStart){
    //TODO: write all filepaths
    //TODO: add error info
    //TODO: write all errored syscalls
    //TODO: write number of children
    //TODO: create tree structure with children
    ParseTraceFile(reportName);
    OpenFile();
    WriteHeader(targetName, targetStart);
//    WriteSummary(syscallCounts);
    WriteDTrussList();
    fprintf(fp, "%.*s", 80, "#######################################################################################################################################");
    fprintf(fp, "\n");
}