//
// Created by Thomas Lynch on 2/8/19.
//

#ifndef DTRACECONSUMER_IOHANDLER_H
#define DTRACECONSUMER_IOHANDLER_H


#include <string>
#include <map>

using std::string;

class IOHandler {
    public:
        void WriteSummary(std::map <string, int> syscallCounts);
        IOHandler();
        IOHandler(string fn);
        void OpenFile();
         void WriteToReports(char* output);
         void Destroy();
//    static FILE *fp;

    void ParseTraceFile();
    void ParseTraceLine(string line);
    private:
        void WriteHeader();
        string logFN;
        string tmpFN;
};
#endif //DTRACECONSUMER_IOHANDLER_H

