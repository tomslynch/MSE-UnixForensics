//
// Created by thomaslynch on 4/9/19.
//

#ifndef DTRACECONSUMER_STRACEHANDLER_H
#define DTRACECONSUMER_STRACEHANDLER_H

#include <stdio.h>
#include <string>
#include <zconf.h>
#include <ctime>
#include <iostream>
#include <fcntl.h>
#include <cstring>

#include "IOHandler.h"

using std::string;
using std::time;
using std::to_string;

class straceHandler {
public:
    straceHandler();
    void StartStraceProcess(const string& processID);
    const string &getFn() const;
    void setFn(const string &fn);
    int getPid() const;
    void setPid(int pid);

private:
    string fn;
    int pid;

};

#endif //DTRACECONSUMER_STRACEHANDLER_H
