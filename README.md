# UW-L Capstone

## Author(s):
Thomas Lynch

## Date:
10/23/2018

## Description:
This program targets a single process and records all system calls invoked by that process. After yo input the process ID the program will continue auditing until the program is terminated. The program will output a report of the audit named with the logFN entered on startup, or with a timestamp, to the same directory. The report contains a timestamped list of all the system calls from the target process.

The group option will restrict the system calls recorded based on a pre-defined list of groups stored in config/modes.txt. Each group is listed with the name and flag delimited by a colon as the first line and the categorized system calls on it's separate line below. Each group is then delimited by a blank line. Therefore any custom group or categorization can be added/edited.

## How To Build:
make

## How To Run:
Parameters can be in any order.
Required parameters (at most one)
	* -p <processID>        : process ID of process to audit
	* -pn <processName>	: name of target process to audit
Optional parameters
	* -o <reportFilename>   : user defined file name for report
	* -g <groupIDs>         : select the group(s) to record and delimited by commas if multiple

	Example: ./DTraceConsumer 51162 -o TerminalTest -g IO,sys,net

## Test Files
	- HelloWorldTest
	- ReadFileTest
	- BasicForkTest
##results
##issues

## Not Yet Implemented
Groups
