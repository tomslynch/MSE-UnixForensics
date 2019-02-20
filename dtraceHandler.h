//
// Created by Thomas Lynch on 10/31/18.
//

#ifndef UNTITLED_DTRACEHANDLER_H
#define UNTITLED_DTRACEHANDLER_H


#include <stdio.h>
#include <assert.h>
#include <string>
#include <zconf.h>

#include <cstdio>
#include <string>
#include <dtrace.h>
#include <ctime>
#include "IOHandler.h"
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <map>
#include <fstream>
#include <fcntl.h>

using std::string;
using std::time;
using std::to_string;

 class dtraceHandler {
    public:
        dtraceHandler(string targetName, string processID, IOHandler io);
        bool IsProcessRunning();
            bool StartDTrace();
            void Destroy();
    std::map <string, int> GetSyscallCounts();
    void static SetIsProcessRunning(bool vl);

private:
        bool static isProcessRunning;
        static FILE *fp;
        const string NAME_SCRIPT;
        const string ID_SCRIPT;
        const string NAME_END;
        const string ID_END;
        static IOHandler ioHandler;
        pid_t dtrussPid;

//        static dtrace_hdl_t* d_handle;

        string userDefinedFilename;
//        string targetName;
//        string processID;
//        static int g_intr;
//        static int g_exited;
    static std::map <string, int> SyscallCounts;
    static int chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg);
    void static StartDtrussProcess(string targetName, string processID, pid_t pid);
        bool InitDTrace(string targetName, string processID);
//    static int chewrec (const dtrace_probedata_t *data,
//            const dtrace_recdesc_t *rec,
//            void *arg);
};


#endif //UNTITLED_DTRACEHANDLER_H
