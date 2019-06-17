#include <cstdio>
#include <cassert>
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

    // parse arguments
    //TODO: Input validation
    for (int i = 0; i < argc-1; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            processID = argv[i+1];
            if (0 == kill(stoi(processID), 0)) {
                cout << "Process [" + processID + "] is not running..." << endl;
                return -1;
            }
        }
        if (strcmp(argv[i], "-o") == 0) {
            userDefinedFilename = argv[i+1];
            if (userDefinedFilename.empty()){
                cout << "Invalid filename..." << endl;
                return -1;
            }
        }
        if (strcmp(argv[i], "-pn") == 0) {
            targetName = argv[i+1];
            if (targetName.empty()) {
                cout << "Invalid target name..." << endl;
                return -1;
            }
        }
    }

    //TODO: strip path information before filename for strace record
    string reportName;
    if (userDefinedFilename.empty()) {
        time_t t = time(nullptr);
        std::stringstream ss;
        ss << t;
        reportName = ss.str();
    } else {
        reportName = userDefinedFilename;
    }

    string targetStr = (processID.empty()) ? targetName : processID;

    // Init Config
    IOHandler ioHandler = IOHandler("reports/" + reportName);
    ioHandler.ReadInGroups("");

    // Start strace
    auto startTime = chrono::steady_clock::now(); //TODO: extend to three decimal places
    cout << "Starting strace..." << endl;
    straceHandler stHandle;

    //TODO: kill child if timeout reached?
    if (!targetName.empty()) {
        stHandle = straceHandler();
        stHandle.StartStracePath(targetName, reportName);
    } else {
        //TODO: catch conversion exception
        if (0 == kill(stoi(processID), 0))
        {
            stHandle = straceHandler();
            stHandle.StartStraceProcess(processID, reportName);
        }
    }
    int status;
    waitpid(stHandle.getPid(), &status, 0);
    cout << "Exiting strace..." << endl;
//    auto endTime = chrono::steady_clock::now();

    ioHandler.GenerateReport(stHandle.getFn(), targetStr, startTime);
    ioHandler.Destroy();
    return 0;
}