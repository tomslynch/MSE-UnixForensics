//
// Created by Thomas Lynch on 11/1/18.
//

#include <iostream>
#include <zconf.h>
#include <stdio.h>
#include <stdint.h>
using namespace std;

int main(){
    pid_t processID = ::getpid();
    printf("pid = %jd\n", (intmax_t) processID);
    cout << "Press Enter to continue...";
    cin.ignore();

    fork();
}