#include <stdio.h>
#include <assert.h>
#include <string>
#include <zconf.h>
#include <cstring>
#include <chrono>
#include <thread>
#include <wait.h>

#include "straceHandler.h"
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
    straceHandler stHandle = straceHandler();
    stHandle.StartStraceProcess(processID);

    int status;
    waitpid(stHandle.getPid(), &status, 0);
    ioHandler.Destroy();
    return 0;
}