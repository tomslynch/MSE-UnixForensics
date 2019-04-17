//
// Created by Thomas Lynch on 2/8/19.
//
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

 IOHandler::SyscallData IOHandler::ParseTraceLine(string& line){
    SyscallData sd;
    smatch m;

    // grab pid and tid
    regex pidPattern("^.*:");
    string match;
    if (regex_search(line, m, pidPattern)) {
        match = m.str(0);
        sd.pid = match.substr(0, match.find('/'));
        sd.tid = match.substr(match.find('/')+1, (match.length()-2) - match.find('/'));
    }

    //grab times
    regex timePattern("(\\d+\\s+){3}");
    if (regex_search(line, m, timePattern)) {
        match = m.str(0);
        stringstream ssin(match);
        int i = 0;
        while (ssin.good() && i < 3){
            switch (i) {
                case 0:
                    ssin >> sd.relTime;
                    break;
                case 1:
                    ssin >> sd.elapsedTime;
                    break;
                case 2:
                    ssin >> sd.cpuTime;
                    break;
                default:
                    break;
            }
            ++i;
        }
    }

    //grab syscall
    regex syscallPattern("[^-\\s]*\\(.*=");
    if (regex_search(line, m, syscallPattern)) {
        match = m.str(0);
        sd.name = match.substr(0, match.find('('));

        //grab args
        regex argR("\\(.*\\)");
        if (regex_search(match, m, argR)) {
            string tmp = m.str(0);
            string token;
            size_t pos;

            if (tmp[0] == '"' || tmp[0] == '\'') {
                pos = tmp.find("\",");
                pos = (pos == string::npos) ? string::npos : pos + 1;
            } else {
                pos = tmp.find(',');
            }

            while(pos != string::npos){
                tmp.erase(0,1);
                token = tmp.substr(0, pos-1);
                sd.args.push_back(token);
                tmp.erase(0, pos);

                if (tmp[0] == '"' || (tmp.length() >= 2 && tmp[1] == '"')) {
                    pos = tmp.find("\",");
                    pos = (pos == string::npos) ? string::npos : pos + 1;
                } else {
                    pos = tmp.find(',');
                }
            }
            tmp.erase(0,1);
            tmp.erase(tmp.length()-1, tmp.length());
            sd.args.push_back(tmp);
        }

        //grab return info
        regex returnPattern("\\)\t\t =.*$");
        if (regex_search(line, m, returnPattern)) {
            match = m.str(0);
            match = match.substr(6, match.length());
            sd.ret = match.substr(0, match.find(' '));
            sd.retDesc = match.substr(match.find(' ')+1, (match.length()-1) - match.find(' '));
        }

//        cout << sd.toString() << endl;
    }
    return sd;
}

 void IOHandler::ParseTraceFile(){
    string line;
    ifstream myfile ("trace");
    if (myfile.is_open())
    {
        while (getline(myfile, line))
        {
            IOHandler::dtrussSyscallList.push_back(ParseTraceLine(line));
        }
        myfile.close();
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

void IOHandler::WriteHeader(string& targetName,
        std::chrono::steady_clock::time_point targetStart,
        std::chrono::steady_clock::time_point progStart) {
    auto end = chrono::steady_clock::now();
    fprintf(fp, "%.*s", 80, "#######################################################################################################################################");
    fprintf(fp, "\nMonitoring Tool created by UW-L MSE Student, Thomas Lynch\n");
    fprintf(fp, "Targeted Process:\t\t%s\n", targetName.c_str());
    fprintf(fp, "Total Monitored Time:\t\t%ld seconds\n",
            chrono::duration_cast<chrono::seconds>(end-progStart).count());
    fprintf(fp, "Total Target Elapsed Time:\t%ld seconds\n",
            chrono::duration_cast<chrono::seconds>(end-targetStart).count());
    fprintf(fp, "Total Target CPU Time:\t\t%s microseconds\n", GetTotalCPUTime().c_str());
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

void IOHandler::WriteDTraceList(std::vector<string>& syscallList) {
    fprintf(fp, "%s", "\n************* DTrace Syscall List *************\n");
    for (auto& syscall: syscallList) {
        fprintf(fp, "%s", syscall.c_str());
    }
}

void IOHandler::WriteDTrussList() {
    fprintf(fp, "%s", "\n************* DTruss Basic Syscall List *************\n");
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

    fprintf(fp, "%s", "\n************* DTruss Detailed Syscall List *************\n");
    for (auto& dtrussSyscall : dtrussSyscallList) {
        fprintf(fp, "%s\n", dtrussSyscall.toString().c_str());
    }
}

void IOHandler::GenerateReport( string targetName,
        std::map<string, int> syscallCounts,
        std::vector<string> syscallList,
        std::chrono::steady_clock::time_point targetStart,
        std::chrono::steady_clock::time_point progStart){
    //TODO: write all filepaths
    //TODO: add error info
    //TODO: write all errored syscalls
    //TODO: write number of children
    //TODO: create tree structure with children
    ParseTraceFile();
    WriteHeader(targetName, targetStart, progStart);
    WriteSummary(syscallCounts);
    WriteDTraceList(syscallList);
    WriteDTrussList();
    fprintf(fp, "%.*s", 80, "#######################################################################################################################################");
    fprintf(fp, "\n");
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

        if (getline(ss, line, ',')) {
            groupNames.push_back(line);
            std::transform (line.begin(), line.end(), line.begin(), ::tolower);
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