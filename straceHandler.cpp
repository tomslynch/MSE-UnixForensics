#include "straceHandler.h"
using namespace std;

void straceHandler::StartStraceProcess(const string& processID, const string& reportName) {
    setFn("strace_" + reportName);
    pid = fork();
    if (pid == 0) {
        int rs = execl("/usr/bin/strace", "strace", "-tTyfyy", "-p", processID.c_str(), "-o", getFn().c_str(), nullptr);
    }
}

void straceHandler::StartStracePath(const string& path, const string& reportName) {
    setFn("strace_" + reportName);
    pid = fork();
    if (pid == 0) {
        int rs = execl("/usr/bin/strace", "strace", "-tTyfyy",  "-o", getFn().c_str(), path.c_str(), nullptr);
    }
}

const string &straceHandler::getFn() const {
    return straceHandler::fn;
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
}

