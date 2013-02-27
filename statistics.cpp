/*
 * statistics.cpp
 *
 *  Created on: 14/nov/2012
 *      Author: root
 */

#include "statistics.h"
#include <map>

statistics::statistics(map<string, host> *host_map) {
	hosts = host_map;

	/*PKT STATISTICS*/
	total_pkt = 0;
	mob_pkt = 0;
	lap_pkt = 0;
	udf_pkt = 0;

	mob_pkt_prc = 0;
	lap_pkt_prc = 0;
	udf_pkt_prc = 0;

	/*BYTE STATISTICS*/
	total_byte_cpt = 0;
	mob_byte = 0;
	lap_byte = 0;
	udf_byte = 0;

	total_rcv_byte = 0;
	total_sent_byte = 0;

	http_byte = 0;
	https_byte = 0;

	mob_byte_prc = 0;
	lap_byte_prc = 0;
	udf_byte_prc = 0;

	http_prc = 0;
	https_prc = 0;
	other_traffic_prc = 0;

	/*LAPTOP BYTE STATISTICS*/
	lap_byte_http = 0;
	lap_byte_https = 0;
	lap_byte_http_prc = 0;
	lap_byte_https_prc = 0;
	lap_byte_other_prc = 0;

	/*MOBILE BYTE STATISTICS*/
	mob_byte_http = 0;
	mob_byte_https = 0;

	mob_byte_http_prc = 0;
	mob_byte_https_prc = 0;
	mob_byte_other_prc = 0;

	/*OTHER STATISTICS*/
	average_dim_pkt = 0;
	average_bytes_client = 0;
	average_rcv_bytes_client = 0;
	average_sent_bytes_client = 0;

	/*VENDOR STATISTICS*/
	android_bytes = 0;
	iphone_bytes = 0;
	ipad_bytes = 0;
	windows_bytes = 0;

}

statistics::~statistics() {
	// TODO Auto-generated destructor stub
}

void statistics::pkt_statistics() {
	map<string, host>::iterator it;
	it = (*hosts).begin();

	for (it; it != (*hosts).end(); it++) {

		total_pkt += (it->second).total_packet;
		if ((it->second).traffic_type == 1) {
			mob_pkt += (it->second).total_packet;
		} else if ((it->second).traffic_type == 2) {
			lap_pkt += (it->second).total_packet;
		} else {
			udf_pkt += (it->second).total_packet;
		}
	}

	if (total_pkt != 0) {
		mob_pkt_prc =  ((double)(mob_pkt) /(double)( total_pkt)) * 100;
		lap_pkt_prc =  ((double)(lap_pkt )/(double)( total_pkt)) * 100;
		udf_pkt_prc = (double)(100 - (mob_pkt_prc + lap_pkt_prc));
	}
}

void statistics::byte_statistics() {
	map<string, host>::iterator it;
	it = (*hosts).begin();

	for (it; it != (*hosts).end(); it++) {
		total_byte_cpt += (it->second).total_traffic;
		total_rcv_byte += (it->second).rcv_traffic;
		total_sent_byte += (it->second).sent_traffic;
		http_byte += (it->second).http_traffic;
		https_byte += (it->second).https_traffic;

		if ((it->second).traffic_type == 1) {
			mob_byte += (it->second).total_traffic;
			mob_byte_http += (it->second).http_traffic;
			mob_byte_https += (it->second).https_traffic;
		} else if ((it->second).traffic_type == 2) {
			lap_byte += (it->second).total_traffic;
			lap_byte_http += (it->second).http_traffic;
			lap_byte_https += (it->second).https_traffic;
		}

	}
	if (total_byte_cpt != 0) {

		mob_byte_prc = ((double)(mob_byte) / (double) (total_byte_cpt)) * 100;

		lap_byte_prc = ((double) (lap_byte) / (double) (total_byte_cpt)) * 100;

		udf_byte_prc =  (double)(100 - (mob_byte_prc + lap_byte_prc));

		http_prc =  ((double)(http_byte) / (double)(total_byte_cpt)) * 100;

		https_prc = ((double)(https_byte) / (double)(total_byte_cpt)) * 100;

		other_traffic_prc =  (double) (100 - (http_prc + https_prc));
	}

	if (mob_byte != 0) {
		mob_byte_http_prc  = ((double)(mob_byte_http) /(double)( mob_byte)) * 100;

		mob_byte_https_prc = ((double)(mob_byte_https) /(double) (mob_byte)) * 100;
		mob_byte_other_prc = (double)(100 - (mob_byte_http_prc
				+ mob_byte_https_prc));
	}
	if (lap_byte != 0) {
		lap_byte_http_prc = ((double)(lap_byte_http) /(double)( lap_byte)) * 100;
		lap_byte_https_prc = ((double)(lap_byte_https) /(double)( lap_byte)) * 100;
		lap_byte_other_prc =  (double)(100 - (lap_byte_http_prc
				+ lap_byte_https_prc));
	}
}

void statistics::generic_statistics() {

	if (total_byte_cpt != 0 && total_pkt != 0)
		average_dim_pkt = (int) (total_byte_cpt / total_pkt);
	if (total_byte_cpt != 0 && (*hosts).size() != 0)
		average_bytes_client = (int) (total_byte_cpt / ((*hosts).size()));
	if (total_rcv_byte != 0 && (*hosts).size() != 0)
		average_rcv_bytes_client = (int) (total_rcv_byte / ((*hosts).size()));
	if (total_sent_byte != 0 && (*hosts).size() != 0)
		average_sent_bytes_client = (int) (total_sent_byte / ((*hosts).size()));
}

void statistics::vendor_statistics() {
	map<string, host>::iterator it;
	it = (*hosts).begin();

	for (it; it != (*hosts).end(); it++) {
		if ((it->second).vendor == "Android") {
			android_bytes += (it->second).total_traffic;

		} else if ((it->second).vendor == "iPhone") {
			iphone_bytes += (it->second).total_traffic;

		} else if ((it->second).vendor == "iPad") {
			ipad_bytes += (it->second).total_traffic;

		} else if ((it->second).vendor == "Windows Mobile") {
			windows_bytes += (it->second).total_traffic;

		}

	}
}

