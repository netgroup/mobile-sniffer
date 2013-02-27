/*
 * sniffing.h
 *
 *  Created on: 06/nov/2012
 *      Author: root
 */

#ifndef SNIFFING_H_
#define SNIFFING_H_
#include <string>
#include <pcap.h>
#include <map>
#include "host.h"
#include <list>
#include "ip_URL.h"
#include "URL_rec.h"

using namespace std;

class sniffing {
public:
	//map<string, host> hosts;

	sniffing();
	virtual ~sniffing();
	int capture_routine(string*, map<string, host>*, map<string, URL_rec>*, list<ip_URL>*);
	void pkt_mgmt(const u_char*, pcap_pkthdr*, map<string, host>*, map<string, URL_rec>*, list<ip_URL>*,
			pcap_dumper_t*);
	void find_mobile_http(u_char*, map<string, host>::iterator);
	void find_mobile_dns(u_char*, int, map<string, host>::iterator);
	void find_mobile_mdns(u_char*, int, map<string, host>::iterator);
	void getHttp_mgmt(string, string, string, map<string, URL_rec>*, list<ip_URL>*);
	void responseHttp_mgmt(string, string, string, map<string, URL_rec>*, list<ip_URL>*);
	void dump_url_map(map<string, URL_rec>*, string );
	void dump_mac_map(map<string, host>*, string );

private:
	void Stampa_link_layer(int);
};

#endif /* SNIFFING_H_ */
