//
// Created by Thomas Lynch on 10/31/18.
//

#include "dtraceHandler.h"

//class dtraceHandler
//{
const string NAME_SCRIPT = "syscall:::entry /execname == \"";
const string ID_SCRIPT = "syscall:::entry /pid == ";
const string NAME_END = "\"/ { }";
const string ID_END = "/ {}";
static dtrace_hdl_t* d_handle;
IOHandler dtraceHandler::ioHandler;
bool dtraceHandler::isProcessRunning;
std::map <string, int> dtraceHandler::SyscallCounts;
pid_t dtrussPid;
bool test;

static int g_intr;
static void intr (int signo) {
    g_intr = 1;
}

dtraceHandler::dtraceHandler(string targetName, string processID, IOHandler io) {
    isProcessRunning = true;
    dtrussPid = -1;
    ioHandler = io;
    SyscallCounts = {};
    test = false;
    test = InitDTrace(targetName, processID);
}

std::map <string, int> dtraceHandler::GetSyscallCounts() {
    return SyscallCounts;
}

//TODO: add file
void dtraceHandler::StartDtrussProcess(string targetName, string processID, pid_t pid){
//    string[2] command;
    string command = (strcmp(targetName.c_str(), "") != 0) ? "-n " + targetName : "-p " + processID;

//    std::cout << command << std::endl;

    int rs;
    if (pid == 0) {
        printf("Starting DTruss...\n");

        time_t t = time(nullptr);
        auto intNow = static_cast<long int> (t);
//        string tmpName = "dtruss_" + std::to_string(intNow);

        string tmpName = "trace";
        std::ofstream outfile(tmpName);
        outfile << "";
        outfile.close();

        int fd = open(tmpName.c_str(), O_WRONLY);

        if (fd == 0) {
            printf("Could not open file...\n");
        }

        dup2(fd, STDERR_FILENO);
        close(fd);

        if (strcmp(targetName.c_str(), "") != 0) {
            rs = execl("/usr/bin/dtruss", "dtruss", "-af", "-n", targetName.c_str(), nullptr);
        } else {
            rs = execl("/usr/bin/dtruss", "dtruss", "-af", "-p", processID.c_str(), nullptr);
        }

        printf("Done");
    }
}

void  dtraceHandler::SetIsProcessRunning(bool vl) {
    dtraceHandler::isProcessRunning = vl;
}

int dtraceHandler::chewrec (const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg) {
    dtrace_probedesc_t *probeData = data->dtpda_pdesc;
    char name[DTRACE_FUNCNAMELEN];
    strncpy(name, probeData->dtpd_func, DTRACE_FUNCNAMELEN);

    if (strcmp("sigaction", name) != 0 && strcmp("sigprocmask", name) != 0 && strcmp("sigaltstack", name) != 0) {
        ioHandler.WriteToReports(name);

        //add to map
        auto search = SyscallCounts.find(name);
        if (search != SyscallCounts.end()) {
            SyscallCounts[name]++;
        } else {
            SyscallCounts.insert({name, 1});
        }

        //check if end of proc
        if (strcmp("exit", name) == 0) {
            SetIsProcessRunning(false);
        }
    }

    return (DTRACE_CONSUME_THIS);
}

bool dtraceHandler::InitDTrace(string targetName, string processID){
    string g_proc;

    // get targeted process info
    string g_prog;
    if (strcmp(targetName.c_str(), "") != 0) {
        g_prog = "syscall:::entry /execname == \"" + targetName + "\"/ { }";
    } else if (processID.length() == 0) {
        printf("Invalid arguments...");
        return -1;
    } else {
        g_prog = ID_SCRIPT + processID + ID_END;
    }

    // Start DTruss syscall inspection
    dtrussPid = fork();
    StartDtrussProcess(targetName, processID, dtrussPid);

    // Setup DTrace
    int err;
    if ((d_handle = dtrace_open(DTRACE_VERSION, 0, &err)) == nullptr) {
        fprintf(stderr, "failed to initialize dtrace: %s\n", dtrace_errmsg(nullptr, err));
        return false;
    }
    printf("Dtrace initialized\n");

    (void) dtrace_setopt(d_handle, "bufsize", "4m");
    (void) dtrace_setopt(d_handle, "aggsize", "4m");
    printf("dtrace options set\n");

    dtrace_prog_t *prog;
    if ((prog = dtrace_program_strcompile(d_handle, g_prog.c_str(), DTRACE_PROBESPEC_NAME, 0, 0, nullptr)) == nullptr) {
        fprintf(stderr, "failed to compile dtrace program\n");
        return false;
    } else {
        printf("dtrace program compiled\n");
    }

    dtrace_proginfo_t info;
    if (dtrace_program_exec(d_handle, prog, &info) == -1) {
        fprintf(stderr, "failed to enable dtrace probes\n");
        return false;
    } else {
        printf("dtrace probes enabled\n");
    }

    return true;
}

bool dtraceHandler::IsProcessRunning(){
    return isProcessRunning;
}

bool dtraceHandler::StartDTrace(){

    if (!test) {
        return test;
    }

    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = intr;
    (void) sigaction(SIGINT, &act, nullptr);
    (void) sigaction(SIGTERM, &act, nullptr);

    if (dtrace_go(d_handle) != 0) {
        fprintf(stderr, "could not start instrumentation\n");
        return false;
    } else {
        ioHandler.OpenFile();
        printf("instrumentation started and report file opened ..\n");
    }

    // Loop and chew
    clock_t start = clock();
    double duration;
    int TIMEOUT_S = 300;

    int done = 0;
    do {
        if (!g_intr && !done) {
            dtrace_sleep(d_handle);
        }

        if (done || g_intr) {
            done = 1;
            if (dtrace_stop(d_handle) == -1) {
                fprintf(stderr, "could not stop tracing\n");
                return -1;
            }
        }

//        int (dtraceHandler::*func) (const dtrace_probedata_t*, const dtrace_recdesc_t*, void*);
//        func = &dtraceHandler::chewrec;

        switch (dtrace_work(d_handle, stdout, nullptr, dtraceHandler::chewrec, nullptr)) {
            case DTRACE_WORKSTATUS_DONE:
                done = 1;
                break;
            case DTRACE_WORKSTATUS_OKAY:
                break;
            default:
                fprintf(stderr, "processing aborted");
                return false;
        }
        duration = ((std::clock() - start)/(double) CLOCKS_PER_SEC)*1000;
    } while (!done && isProcessRunning && duration < TIMEOUT_S);

    if (!isProcessRunning) {
        printf("Target process has exited...\n");
    }

    if (duration >= TIMEOUT_S) {
        std::cout << "Timeout value has been reached..." << std::endl;
    }

    return true;
}

void dtraceHandler::Destroy(){
    std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    printf("closing dtrace\n");
    dtrace_close(d_handle);
    printf("closing dtruss\n");
    if (dtrussPid != -1) {
        kill(dtrussPid, SIGTERM);
    }
}
