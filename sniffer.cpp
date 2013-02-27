//============================================================================
// Name        : sniffer.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <string>
#include <pthread.h>
#include "sniffing.h"
#include "statistics.h"
#include <cstdlib>
#include <stdio.h>
#include <map>
#include <fstream>
#include <time.h>
#include <sstream>
#include <list>
#include "URL_statistics.h"
#include <stdexcept>

using namespace std;

string convertInt(int number) {
	stringstream ss;//create a stringstream
	ss << number;//add number to the stream
	return ss.str();//return a string with the contents of the stream
}

void* input(void*arg) {

	string* state = (string*) arg;

	//cout<<"ins\n";


	while (1) {

		cin >> *state;

		if (*state == "stop")
			break;
	}
}

int main() {

	map<string, host> hosts;
	map<string, URL_rec> stat_url;
	list<ip_URL> temp;

	cout << "------SNIFFER------\n\n";



	pthread_t threadID;
	string status = "start";

	pthread_create(&threadID, NULL, input, (void*) &status);

	sniffing snf = sniffing();
	cout << "sniffing packets...\n\n";

	int pkt = snf.capture_routine(&status, &hosts, &stat_url, &temp);



	pthread_exit(NULL);

	return 0;
}
