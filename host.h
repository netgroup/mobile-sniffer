/*
 * host.h
 *
 *  Created on: 06/nov/2012
 *      Author: root
 */

#ifndef HOST_H_
#define HOST_H_
#include <string>
#include <utility>

using namespace std;

class host {
public:
	string mac_address;

	int traffic_type; /*0--->UNDEFINED, 1--->MOBILE, 2--->LAPTOP*/

	/*TOTAL TRAFFIC*/
	long long total_traffic; /*byte*/
	long long sent_traffic;
	long long rcv_traffic;

	/*HTTP TRAFFIC*/
	long long http_traffic; /*byte*/
	long long sent_http_traffic;
	long long rcv_http_traffic;

	/*HTTPS TRAFFIC*/
	long long https_traffic; /*byte*/
	long long sent_https_traffic;
	long long rcv_https_traffic;

	/*TOTAL PACKETS*/
	long long total_packet;
	long long sent_pkt;
	long long rcv_pkt;

	string vendor;

	void setTrafficType(int);

	void increaseTotalTraffic(long long);
	void increaseSentTraffic(long long);
	void increaseRcvTraffic(long long);

	void increaseNumberPkt();
	void increaseSentPkt();
	void increaseRcvPkt();

	void increaseHttp(long long);
	void increaseRcvHttp(long long);
	void increaseSentHttp(long long);

	void increaseHttps(long long);
	void increaseRcvHttps(long long);
	void increaseSentHttps(long long);

	void setVendor(string);
	host(string);
	virtual ~host();
};

#endif /* HOST_H_ */
