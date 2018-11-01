#include <dtrace.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <string>
#include <ctime>
#include <iostream>

using namespace std;

static dtrace_hdl_t* d_handle;
static FILE *fp;
string userDefinedFilename = "";

static void WriteToReports(char* output){
    fprintf(fp, "%s\n", output);
}

string trim(const string& str)
{
    size_t first = str.find_first_not_of(' ');
    if (string::npos == first)
    {
        return str;
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

static int chewrec (const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg) {
//    printf("chewing dtrace record ..\n");

    // A NULL rec indicates that we've processed the last record.
//    if (rec == NULL) {
//        return (DTRACE_CONSUME_NEXT);
//    }
    dtrace_probedesc_t *probeData = data->dtpda_pdesc;

    char name[DTRACE_FUNCNAMELEN];
    strncpy(name, probeData->dtpd_func, DTRACE_FUNCNAMELEN);

    if (strcmp("sigaction", name) != 0 && strcmp("sigprocmask", name) != 0 && strcmp("sigaltstack", name) != 0) {
        WriteToReports(name);
    }

    return (DTRACE_CONSUME_THIS);
}



//static const char* g_prog = "syscall::open*:entry { printf(\"%s %s\\n\", execname, copyinstr(arg0)); }";

//static const char* g_prog = "BEGIN { printf(\"hello from dtrace\\n\"); }";
//static const char* g_prog = "syscall:::entry /pid == 55614/ { printf(\"%s %s\\n\", execname, copyinstr(arg0)); }";
//static const char* g_prog = "syscall:::entry /pid == 55614/ {printf(\"%s\\n\", execname)}";
//static const char* g_prog = "syscall:::entry /pid == 55614/ {}";


static int g_intr;
static int g_exited;

static void intr (int signo) {
    g_intr = 1;
}

int main (int argc, char** argv) {
    int err;
    string processID = "";

    //parse arguments
    for (int i = 0; i < argc-1; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            processID = argv[i+1];
        }

        if (strcmp(argv[i], "-o") == 0) {
            userDefinedFilename = argv[i+1];
        }
    }

    if (processID.length() == 0) {
        printf("Invalid arguments...");
        return -1;
    }

    string g_prog = "syscall:::entry /pid == " + processID + "/ {}";
    printf("%s/n", g_prog.c_str());

    if ((d_handle = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
        fprintf(stderr, "failed to initialize dtrace: %s\n", dtrace_errmsg(NULL, err));
        return -1;
    }
    printf("Dtrace initialized\n");

    (void) dtrace_setopt(d_handle, "bufsize", "4m");
    (void) dtrace_setopt(d_handle, "aggsize", "4m");
    printf("dtrace options set\n");

    dtrace_prog_t *prog;
    if ((prog = dtrace_program_strcompile(d_handle, g_prog.c_str(), DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL) {
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
    (void) sigaction(SIGINT, &act, NULL);
    (void) sigaction(SIGTERM, &act, NULL);

    printf("Hit");


    if (dtrace_go(d_handle) != 0) {
        fprintf(stderr, "could not start instrumentation\n");
        return -1;
    } else {
        //open file
        if (userDefinedFilename.length() == 0) {
            time_t t = std::time(0);
            long int intNow = static_cast<long int> (t);
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

        switch (dtrace_work(d_handle, stdout, NULL, chewrec, NULL)) {
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
    } while (!done);

    printf("closing dtrace\n");
    dtrace_close(d_handle);
    fclose(fp);
    return 0;
}