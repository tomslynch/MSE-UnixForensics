#include <stdio.h>
#include <assert.h>
#include <string>
#include <zconf.h>

#include "dtraceHandler.h"
#include "IOHandler.h"

using namespace std;

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

void WriteSummary(std::map <string, int> syscallCounts,  FILE *fp) {
    string summary = "\n************* SUMMARY *************\n";
    fprintf(fp, "%s", summary.c_str());

    std::multimap<int, string> SortedSyscallCounts = flip_map(syscallCounts);
    for (auto const& x : SortedSyscallCounts)
    {
        fprintf(fp, "%s\t%s\n", std::to_string(x.first).c_str(), x.second.c_str());
    }
}


int main (int argc, char** argv) {
    string userDefinedFilename = "";
    string targetName = "";
    string processID = "";

    //parse arguments
    for (int i = 0; i < argc-1; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            processID = argv[i+1];
        }
        if (strcmp(argv[i], "-o") == 0) {
            userDefinedFilename = argv[i+1];
        }
        if (strcmp(argv[i], "-pn") == 0) {
            targetName = argv[i+1];
        }
    }

    IOHandler ioHandler = IOHandler(userDefinedFilename);
    dtraceHandler dtHandle = dtraceHandler(targetName, processID, ioHandler);
    if (dtHandle.StartDTrace()) {
//        if (!dtHandle.IsProcessRunning()) {
//            //write out
////                    WriteSummary(dtHandle.GetSyscallCounts(), ioHandler.fp );
//ioHandler.WriteSummary(dtHandle.GetSyscallCounts());
//                    ioHandler.ParseTraceFile();
//        }
std::cout << dtHandle.GetSyscallCounts().size() << std::endl;
        ioHandler.WriteSummary(dtHandle.GetSyscallCounts());
        ioHandler.ParseTraceFile();

    }

    dtHandle.Destroy();
    ioHandler.Destroy();
    return 0;
}