//
// Created by thomaslynch on 4/9/19.
//

#include "straceHandler.h"
using namespace std;

void straceHandler::StartStraceProcess(const string& processID) {
    pid = fork();

    if (pid == 0) {
        cout << "Starting strace..." << endl;

        //tmp report name
        time_t t = time(nullptr);
        std::stringstream ss;
        ss << t;
        string tmpName = "strace_" + ss.str();
        fn = tmpName;


        int rs;
//        if (strcmp(targetName.c_str(), "") != 0){
            //-p "`pidof firefox`"
//            rs = execl("/usr/bin/strace", "strace", "-rtTyfyy", "-n", targetName.c_str(), nullptr);
//        } else {
        rs = execl("/usr/bin/strace", "strace", "-tTyfyy", "-p", processID.c_str(), "-o", tmpName.c_str(), nullptr);
//        }

        printf("Exiting strace...");
    }
}

const string &straceHandler::getFn() const {
    return fn;
}

void straceHandler::setFn(const string &fnIN) {
    straceHandler::fn = fnIN;
}

int straceHandler::getPid() const {
    return pid;
}

void straceHandler::setPid(int pidIN) {
    straceHandler::pid = pidIN;
}

straceHandler::straceHandler(){
    fn = "";
    pid = -1;
};

