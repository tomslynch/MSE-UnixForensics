//
// Created by Thomas Lynch on 10/31/18.
//

#include <iostream>
#include <cstdio>
#include <zconf.h>
#include <cstdint>
using namespace std;

int main(){
    pid_t processID = ::getpid();
    printf("pid = %jd\n", (intmax_t) processID);
    cout << "Press Enter to continue...";
    cin.ignore();

    printf("Hello, World!\n");
    return 0;
}
