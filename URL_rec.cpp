/*
 * URL_rec.cpp
 *
 *  Created on: 18/dic/2012
 *      Author: root
 */

#include "URL_rec.h"
#include <list>;
#include <ctime>;
#include <iostream>;

using namespace std;

URL_rec::URL_rec() {
	// TODO Auto-generated constructor stub
	URL = "";

	byte = 0;
	count = 1;

}

URL_rec::~URL_rec() {
	// TODO Auto-generated destructor stub
}

void URL_rec::set_URL(string res) {
	URL = res;
}

void URL_rec::set_byte(int b) {
	byte = b;
}

void URL_rec::increase_count(){
	count++;
}

void URL_rec:: add_tm(struct tm ts){
	timestamp.push_back(ts);

}
