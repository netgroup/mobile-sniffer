/*
 * ip_URL.cpp
 *
 *  Created on: 18/dic/2012
 *      Author: root
 */

#include "ip_URL.h"

#include <iostream>;
#include <ctime>;

using namespace std;

ip_URL::ip_URL() {
	// TODO Auto-generated constructor stub
	ip_src = "";
	ip_dest="";

	URL = "";

}

ip_URL::~ip_URL() {
	// TODO Auto-generated destructor stub
}

void ip_URL::set_URL(string u){
	URL=u;
}

void ip_URL::set_ip_src(string ip){
	ip_src=ip;
}

void ip_URL::set_ip_dest(string ip){
	ip_dest=ip;
}

void ip_URL::set_timestamp(struct tm ts){
	timestamp=ts;
}
