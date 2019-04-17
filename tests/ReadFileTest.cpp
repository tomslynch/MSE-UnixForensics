//
// Created by Thomas Lynch on 10/31/18.
//

#include <iostream>
#include <zconf.h>
#include <fstream>
using namespace std;

int main(){
    pid_t processID = ::getpid();
    printf("pid = %jd\n", (intmax_t) processID);
    cout << "Press Enter to continue...";
    cin.ignore();

    std::ifstream file("../README");
    std::string str;
    while (std::getline(file, str))
    {
    }
    return 0;
}