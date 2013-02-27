/*
 * host.cpp
 *
 *  Created on: 06/nov/2012
 *      Author: root
 */

#include "host.h"
#include <string>

using namespace std;

void host::setTrafficType(int flag) {
	traffic_type = flag;
}

void host::increaseTotalTraffic(long long t) {
	total_traffic += t;
}

void host::increaseSentTraffic(long long t){
	sent_traffic +=t;
}

void host::increaseRcvTraffic(long long t){
	rcv_traffic +=t;
}


void host::increaseNumberPkt() {
	total_packet++;
}

void host::increaseRcvPkt(){
	rcv_pkt++;
}

void host::increaseSentPkt(){
	sent_pkt++;
}

void host::increaseHttp(long long t) {
	http_traffic += t;
}

void host::increaseSentHttp(long long t){
	sent_http_traffic +=t;
}

void host::increaseRcvHttp(long long t){
	rcv_http_traffic +=t;
}

void host::increaseHttps(long long t) {
	https_traffic += t;
}

void host::increaseRcvHttps(long long t){
	rcv_https_traffic +=t;
}

void host::increaseSentHttps(long long t){
	sent_https_traffic +=t;
}

void host::setVendor(string s) {
	vendor = s;
}

host::host(string add) {
	// TODO Auto-generated constructor stub
	mac_address = add;

	traffic_type=0;


	/*TOTAL TRAFFIC*/
	total_traffic = 0;
	sent_traffic = 0;
	rcv_traffic = 0;

	/*TOTAL PACKETS*/
	total_packet = 0;
	sent_pkt = 0;
	rcv_pkt = 0;

	/*HTTP TRAFFIC*/
	http_traffic = 0;
	sent_http_traffic = 0;
	rcv_http_traffic = 0;


	/*HTTPS TRAFFIC*/
	https_traffic = 0;
	sent_https_traffic = 0;
	rcv_https_traffic = 0;

	vendor = "undefined";

}

host::~host() {
	// TODO Auto-generated destructor stub
}
