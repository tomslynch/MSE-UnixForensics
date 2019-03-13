#include <stdio.h>
#include <assert.h>
#include <string>
#include <zconf.h>

#include "dtraceHandler.h"
#include "IOHandler.h"

using namespace std;

int main (int argc, char** argv) {
    string userDefinedFilename;
    string targetName;
    string processID;

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


    // Init Config
    auto progStart = chrono::steady_clock::now();
    IOHandler ioHandler = IOHandler(userDefinedFilename);
    ioHandler.ReadInGroups("");

    // Start DTrace and Dtruss
    dtraceHandler dtHandle = dtraceHandler(targetName, processID, ioHandler);
    if (dtHandle.StartDTrace()) {

        //TODO: optimize - this is in place to prevent conflicts when looking at trace file
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        dtHandle.Destroy();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        string target = (targetName.empty()) ? processID : targetName;
        ioHandler.GenerateReport( target,
                dtHandle.GetSyscallCounts(),
                dtHandle.GetSyscallList(),
                dtHandle.GetTargetStart(),
                progStart);
    }

    ioHandler.Destroy();
    return 0;
}