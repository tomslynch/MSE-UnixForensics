#include <dtrace.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <string>
#include <ctime>
#include <iostream>
#include <set>
#include <map>
#include <unordered_set>
#include <list>

using namespace std;

static dtrace_hdl_t* d_handle;
static FILE *fp;
string userDefinedFilename;
string targetName;
bool isProcessRunning = true;
map <string, int> SyscallCounts = {};

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

static void WriteToReports(char* output){
    char buffer[256];
    std::time_t t = std::time(nullptr);   // get time now
    std::tm* now = std::localtime(&t);
    strftime(buffer, sizeof(buffer), "%H:%M:%S", now);

    fprintf(fp, "[%s]\t%s\n", buffer, output);
}

static void WriteSummary(){
    string summary = "\n************* SUMMARY *************\n";
    fprintf(fp, "%s", summary.c_str());

    std::multimap<int, string> SortedSyscallCounts = flip_map(SyscallCounts);
    for (auto const& x : SortedSyscallCounts)
    {
        fprintf(fp, "%s\t%s\n", std::to_string(x.first).c_str(), x.second.c_str());
    }
}

//string trim(const string& str)
//{
//    size_t first = str.find_first_not_of(' ');
//    if (string::npos == first)
//    {
//        return str;
//    }
//    size_t last = str.find_last_not_of(' ');
//    return str.substr(first, (last - first + 1));
//}

static int chewrec (const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg) {
// A NULL rec indicates that we've processed the last record.
//    if (rec == NULL) {
//        return (DTRACE_CONSUME_NEXT);
//    }
    dtrace_probedesc_t *probeData = data->dtpda_pdesc;
    char name[DTRACE_FUNCNAMELEN];
    strncpy(name, probeData->dtpd_func, DTRACE_FUNCNAMELEN);

    if (strcmp("sigaction", name) != 0 && strcmp("sigprocmask", name) != 0 && strcmp("sigaltstack", name) != 0) {
        WriteToReports(name);
        //add to map
        auto search = SyscallCounts.find(name);
        if (search != SyscallCounts.end()) {
            SyscallCounts[name]++;
        } else {
            SyscallCounts.insert({name, 1});
        }
        //check if end of proc
        if (strcmp("exit", name) == 0) {
            isProcessRunning = false;
        }
    }

    return (DTRACE_CONSUME_THIS);
}

//static const char* g_prog = "syscall:::entry /pid == 55614/ { printf(\"%s %s\\n\", execname, copyinstr(arg0)); }";
static int g_intr;
static int g_exited;

static void intr (int signo) {
    g_intr = 1;
}

int main (int argc, char** argv) {
    int err;
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

    string g_prog;
    if (strcmp(targetName.c_str(), "") != 0) {
        g_prog ="syscall:::entry /execname == \"" + targetName + "\"/ {}";
    } else if (processID.length() == 0) {
        printf("Invalid arguments...");
        return -1;
    } else {
        g_prog ="syscall:::entry /pid == " + processID + "/ {}";
    }

    printf("%s/n", g_prog.c_str());

    if ((d_handle = dtrace_open(DTRACE_VERSION, 0, &err)) == nullptr) {
        fprintf(stderr, "failed to initialize dtrace: %s\n", dtrace_errmsg(nullptr, err));
        return -1;
    }
    printf("Dtrace initialized\n");

    (void) dtrace_setopt(d_handle, "bufsize", "4m");
    (void) dtrace_setopt(d_handle, "aggsize", "4m");
    printf("dtrace options set\n");

    dtrace_prog_t *prog;
    if ((prog = dtrace_program_strcompile(d_handle, g_prog.c_str(), DTRACE_PROBESPEC_NAME, 0, 0, nullptr)) == nullptr) {
        fprintf(stderr, "failed to compile dtrace program\n");
        return -1;
    } else {
        printf("dtrace program compiled\n");
    }

    dtrace_proginfo_t info;
    if (dtrace_program_exec(d_handle, prog, &info) == -1) {
        fprintf(stderr, "failed to enable dtrace probes\n");
        return -1;
    } else {
        printf("dtrace probes enabled\n");
    }


    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = intr;
    (void) sigaction(SIGINT, &act, nullptr);
    (void) sigaction(SIGTERM, &act, nullptr);

    printf("Hit");


    if (dtrace_go(d_handle) != 0) {
        fprintf(stderr, "could not start instrumentation\n");
        return -1;
    } else {
        //open file
        if (userDefinedFilename.length() == 0) {
            time_t t = std::time(nullptr);
            auto intNow = static_cast<long int> (t);
            fp = fopen(to_string(intNow).c_str(), "w+");
        } else {
            fp = fopen(userDefinedFilename.c_str(), "w+");
        }

        fputs("<<Syscalls>>\nDETAILED SECTION:\n", fp);
        printf("instrumentation started and report file opened ..\n");
    }

    int done = 0;
    do {
        if (!g_intr && !done) {
            dtrace_sleep(d_handle);
        }

        if (done || g_intr || g_exited) {
            done = 1;
            if (dtrace_stop(d_handle) == -1) {
                fprintf(stderr, "could not stop tracing\n");
                return -1;
            }
        }

        switch (dtrace_work(d_handle, stdout, nullptr, chewrec, nullptr)) {
//        switch (dtrace_work(d_handle, stdout, NULL, aggfun, NULL)) {
            case DTRACE_WORKSTATUS_DONE:
                done = 1;
                break;
            case DTRACE_WORKSTATUS_OKAY:
                break;
            default:
                fprintf(stderr, "processing aborted");
                return -1;
        }
    } while (!done && isProcessRunning);

    if (!isProcessRunning) {
        printf("Target process has exited...\n");
        WriteSummary();
    }

    printf("closing dtrace\n");
    dtrace_close(d_handle);
    fclose(fp);
    return 0;
}