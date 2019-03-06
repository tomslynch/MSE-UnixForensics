//
// Created by Thomas Lynch on 2/8/19.
//
#include "IOHandler.h"

using namespace std;

//string filename;
static FILE *fp;
string const IOHandler::DEFAULT_GROUP_PATH = "conf/groupInfo.txt"; //Add to a conf file later?
map<string, int> IOHandler::groupMap;
vector<string> IOHandler::groupNames;

IOHandler::IOHandler() = default;

IOHandler::IOHandler(string fn) {
    if (fn.length() == 0) {
        time_t t = time(nullptr);
        auto intNow = static_cast<long int> (t);
        logFN = std::to_string(intNow);
    } else {
        logFN = fn;
    }

    fp = nullptr;
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

void IOHandler::Destroy() { // early march
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
                case 2:
                    ssin >> sd.cpuTime;
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
            while((pos = tmp.find(',')) != string::npos){
                tmp.erase(0,1);
                token = tmp.substr(0, pos-1);
                sd.args.push_back(token);
                tmp.erase(0, pos);
            }
            tmp.erase(0,1);
            tmp.erase(tmp.length()-1, tmp.length());
            sd.args.push_back(tmp);
        }

        //grab return info
        regex returnPattern("=.*$");
        if (regex_search(line, m, returnPattern)) {
            match = m.str(0);
            match = match.substr(2, match.length());
            sd.ret = match.substr(0, match.find(' '));
            sd.retDesc = match.substr(match.find(' ')+1, (match.length()-1) - match.find(' '));
        }

        cout << sd.toString() << endl;
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

void IOHandler::ReadInGroups(string filepath){
    cout << "Reading in grouping file..." << endl;
    if(filepath == ""){
        filepath = DEFAULT_GROUP_PATH;
    }

    cout << filepath << endl;

    ifstream file(filepath.c_str());
    int idx = 0;
    string tmp;
    string line;
    while(getline(file, line)){
        istringstream ss(line);

        if (getline(ss, line, ',')) {
            groupNames.push_back(line);

            while(getline(ss, line, ',')){
                tmp = "";
                line.erase(0,1);
                for (int i = 0; i < line.size(); i++){
                    tmp += tolower(line[i]);
                }

                groupMap.insert({tmp, idx});
            }
        }
        idx++;
    }
}

string IOHandler::GetGroup(string syscall){
    if (groupMap.find(syscall) != groupMap.end()) {
        return groupNames[groupMap[syscall]];
    } else {
        return "UNKNOWN";
    }
}

void IOHandler::DEBUGPrintVector(vector<string> v){
    for (int i = 0; i < v.size(); i++) {
        cout << v[i] << endl;
    }
}