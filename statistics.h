/*
 * statistics.h
 *
 *  Created on: 14/nov/2012
 *      Author: root
 */

#ifndef STATISTICS_H_
#define STATISTICS_H_

#include <string>
#include <pcap.h>
#include <map>
#include "host.h"

using namespace std;

class statistics {
public:

	map<string, host> *hosts; //puntatore alla mappa da cui trarre le statistiche

	/*PKT STATISTICS*/
	long long total_pkt;
	long long mob_pkt;
	long long lap_pkt;
	long long udf_pkt;

	double mob_pkt_prc;
	double lap_pkt_prc;
	double udf_pkt_prc;

	/*BYTE STATISTICS*/
	long long total_byte_cpt;
	long long mob_byte;
	long long lap_byte;
	long long udf_byte;

	long long total_rcv_byte;
	long long total_sent_byte;

	long long http_byte;
	long long https_byte;

	double mob_byte_prc;
	double lap_byte_prc;
	double udf_byte_prc;

	double http_prc;
	double https_prc;
	double other_traffic_prc;

	/*LAPTOP BYTE STATISTICS*/
	long long lap_byte_http;
	long long lap_byte_https;

	double lap_byte_http_prc;
	double lap_byte_https_prc;
	double lap_byte_other_prc;


	/*MOBILE BYTE STATISTICS*/
	long long mob_byte_http;
	long long mob_byte_https;

	double mob_byte_http_prc;
	double mob_byte_https_prc;
	double mob_byte_other_prc;

	/*OTHER STATISTICS*/
	int average_dim_pkt;
	int average_bytes_client;
	int average_sent_bytes_client;
	int average_rcv_bytes_client;

	/*VENDOR STATISTICS*/
	long long android_bytes;
	long long iphone_bytes;
	long long ipad_bytes;
	long long windows_bytes;



	/*FUNCTIONS*/

	void pkt_statistics();
	void byte_statistics();
	void generic_statistics();
	void vendor_statistics();

	statistics(map<string, host>*);
	virtual ~statistics();
};

#endif /* STATISTICS_H_ */
