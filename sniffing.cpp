/*
 * sniffing.cpp
 *
 *  Created on: 06/nov/2012
 *      Author: root
 */

#include "sniffing.h"
#include <pcap.h>
#include "string"
#include<stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "ieee802_11_radio.h"
#include "ieee802_11.h"
#include "host.h"
#include <iostream>
#include "statistics.h";
#include "ip_URL.h"
#include"URL_rec.h"
#include <list>
#include<stdlib.h>
#include <sstream>
#include<fstream>
#include <stdexcept>
using namespace std;

string convertInteger(int number) {
	stringstream ss;//create a stringstream
	ss << number;//add number to the stream
	return ss.str();//return a string with the contents of the stream
}

struct frame_control {
	unsigned protocol :2;
	unsigned type :2;
	unsigned subtype :4;
	unsigned to_ds :1;
	unsigned from_ds :1;
	unsigned more_frag :1;
	unsigned retry :1;
	unsigned pwr_mgt :1;
	unsigned more_data :1;
	unsigned wep :1;
	unsigned order :1;
};

sniffing::sniffing() {
	// TODO Auto-generated constructor stub


}

sniffing::~sniffing() {
	// TODO Auto-generated destructor stub
}

int sniffing::capture_routine(string *state, map<string, host> *hosts,
		map<string, URL_rec>* stat_url, list<ip_URL>* temp) {

	char *dev = "wlan0"; //interfaccia di ascolto wlan0
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle; //gestore della sniffing session
	struct bpf_program fp; //filtro compilato
	char filter_exp[] = ""; //filtro in formato stringa
	struct pcap_pkthdr header; /* The header that pcap gives us */
	const u_char *packet; /* pacchetto in elaborazione */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	int link_l;
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return (2);
	}

	link_l = pcap_datalink(handle);
	if (link_l == DLT_IEEE802_11_RADIO) {
		Stampa_link_layer(link_l);

		int snf_pkt = 0;

		time_t t1;
		time(&t1);

		struct tm saved = *localtime(&t1);

		string filemac = "macmapser_" + convertInteger(saved.tm_mday)
				+ convertInteger(saved.tm_mon) + convertInteger(saved.tm_year)
				+ "_" + convertInteger(saved.tm_hour) + convertInteger(
				saved.tm_min);

		string fileurl = "urlmapser_" + convertInteger(saved.tm_mday)
						+ convertInteger(saved.tm_mon) + convertInteger(saved.tm_year)
						+ "_" + convertInteger(saved.tm_hour) + convertInteger(
						saved.tm_min);

		while (*state != "stop") {

			packet = pcap_next(handle, &header);

			snf_pkt++;
			try{
			pkt_mgmt(packet, &header, hosts, stat_url, temp, NULL);
				}
			catch(out_of_range& oor){
			cerr<<"ERRORE DI STRINGA "<<oor.what()<<endl;
				}
			time_t t2;
			time(&t2);

			struct tm* now= localtime(&t2);

			if(((now->tm_hour)==(saved.tm_hour))&&(((now->tm_min)-(saved.tm_min))>=5)){
				dump_mac_map(hosts, filemac);
				dump_url_map(stat_url, fileurl);
				saved=*now;

				cout<<"ultimo salvataggio: "<<string(ctime(&t2))<<"\n";

			} else if(((now->tm_hour)!=(saved.tm_hour))&&(((saved.tm_min)-(now->tm_min))>=50)){
				dump_mac_map(hosts, filemac);
				dump_url_map(stat_url, fileurl);
				saved=*now;

				cout<<"ultimo salvataggio: "<<string(ctime(&t2))<<"\n";

			}

		}

		//cout << "i pacchetti sniffati sono: " << snf_pkt << "\n";
		//	cout<<"i pacchetti scartati sono: "<<discarded<<"\n";


		pcap_close(handle);

		return snf_pkt;
	}
}

void sniffing::pkt_mgmt(const u_char*packet, pcap_pkthdr* hdr,
		map<string, host> *hosts, map<string, URL_rec>* stat_url,
		list<ip_URL>* temp, pcap_dumper_t*file) {

	const struct ieee80211_radiotap_header *radth;
	const struct mgmt_header_t* wifihdr;
	const struct ip* iphdr;
	const struct tcphdr* tcpheader;
	const struct udphdr* udpheader;
	struct frame_control* fchdr;
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	u_int sourcePort, destPort;
	u_char* data = NULL;
	string macsrc = "";
	string macdst = "";
	string bssid = "";
	host *hostSrc = NULL;
	host *hostDst = NULL;
	int dataSize = 0;

	radth = (struct ieee80211_radiotap_header*) packet; //radiotap header

	wifihdr = (struct mgmt_header_t*) (packet + radth->it_len); //wifi header
	fchdr = (struct frame_control*) (&wifihdr->fc);
	iphdr = (struct ip*) (packet + radth->it_len + sizeof(struct mgmt_header_t)
			+ 8); //ip header (nei 32 byte sono inclusi 8 di logical link)
	inet_ntop(AF_INET, &(iphdr->ip_src), sourceIp, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(iphdr->ip_dst), destIp, INET_ADDRSTRLEN);
	string ipsrc = string((char*) &sourceIp);
	string ipdest = string((char*) &destIp);

	dataSize
			= ((hdr->len) - (radth->it_len) - sizeof(struct mgmt_header_t) - 8); //32 byte di wifi+l.l.l.

	if (((fchdr->type) == T_DATA) && (dataSize > 0)) { //per non prendere in considerazione le beacon frames
		//cout << "campo fc: " << fchdr->type << "\n\n\n";
		struct ether_addr* addr = NULL;
		addr = (struct ether_addr*) wifihdr->sa;
		macsrc = string((char*) ether_ntoa(addr));
		addr = NULL;

		//cout << "mac sorgente: " << macsrc << "\n";

		addr = (struct ether_addr*) wifihdr->da;
		macdst = string((char*) ether_ntoa(addr));
		addr = NULL;
		//cout << "mac destinazione: " << macdst << "\n";

		if ((macdst != "ff:ff:ff:ff:ff:ff") && (macsrc != "ff:ff:ff:ff:ff:ff")) {

			if ((macsrc.compare(0, 6, "0:b:86") != 0) && (macsrc.compare(0, 6,
					"0:1a:1e") != 0)) {
				hostSrc = new host(macsrc);
			}

			if (((wifihdr->da[0] & 1) == 0) && (macdst.compare(0, 6, "0:b:86")
					!= 0) && (macdst.compare(0, 6, "0:1a:1e") != 0)) {
				hostDst = new host(macdst);
			}
			if (hostSrc != NULL) {

				if ((*hosts).find(hostSrc->mac_address) == (*hosts).end()) {

					pair<string, host> ele(hostSrc->mac_address, *hostSrc);

					(*hosts).insert(ele);
				}
			}

			if (hostDst != NULL) {

				if ((*hosts).find(hostDst->mac_address) == (*hosts).end()) {

					pair<string, host> ele(hostDst->mac_address, *hostDst);

					(*hosts).insert(ele);
				}
			}

			map<string, host>::iterator it1 = (*hosts).end(); //inizializzo gli iteratori
			map<string, host>::iterator it2 = (*hosts).end();

			if (hostSrc != NULL) {
				it1 = (*hosts).find(hostSrc->mac_address);
			}
			if (hostDst != NULL) {
				it2 = (*hosts).find(hostDst->mac_address);
			}

			if (it1 != (*hosts).end()) {
				(it1->second).increaseNumberPkt();
				(it1->second).increaseSentPkt();
				(it1->second).increaseTotalTraffic(dataSize);
				(it1->second).increaseSentTraffic(dataSize);
			}

			if (it2 != (*hosts).end()) {
				(it2->second).increaseNumberPkt();
				(it2->second).increaseRcvPkt();
				(it2->second).increaseTotalTraffic(dataSize);
				(it2->second).increaseRcvTraffic(dataSize);

			}

			if (iphdr->ip_p == SOL_TCP) {
				tcpheader = (struct tcphdr*) (packet + radth->it_len
						+ sizeof(struct mgmt_header_t) + 8 + sizeof(struct ip));

				data = (u_char*) (packet + radth->it_len
						+ sizeof(struct mgmt_header_t) + 8 + sizeof(struct ip)
						+ sizeof(struct tcphdr));
				string http = string((char*) data);

				sourcePort = ntohs(tcpheader->source);
				destPort = ntohs(tcpheader->dest);

				if (sourcePort == 80 || destPort == 80) {

					if (it1 != (*hosts).end()) {
						(it1->second).increaseHttp(dataSize);
						(it1->second).increaseSentHttp(dataSize);

						if (((it1->second).traffic_type != 2) && (destPort
								== 80)) {
							find_mobile_http(data, it1);
						}

					}
					if (it2 != (*hosts).end()) {
						(it2->second).increaseHttp(dataSize);
						(it2->second).increaseRcvHttp(dataSize);

					}

					//analisi richieste-risposte http
					if (destPort == 80) {
						
						getHttp_mgmt(http, ipsrc, ipdest, stat_url, temp);
						


					}

					if (sourcePort == 80) {
						
				responseHttp_mgmt(http, ipsrc, ipdest, stat_url, temp);
						}

				} else if (sourcePort == 443 || destPort == 443) {
					if (it1 != (*hosts).end()) {
						(it1->second).increaseHttps(dataSize);
						(it1->second).increaseSentHttps(dataSize);
					}

					if (it2 != (*hosts).end()) {
						(it2->second).increaseHttps(dataSize);
						(it2->second).increaseRcvHttps(dataSize);
					}
				}

			}

			else if (iphdr->ip_p == SOL_UDP) {

				udpheader = (struct udphdr*) (packet + radth->it_len
						+ sizeof(struct mgmt_header_t) + 8 + sizeof(struct ip));

				sourcePort = ntohs(udpheader->source);
				destPort = ntohs(udpheader->dest);
				if (sourcePort == 53 || destPort == 53) {

					if (it1 != (*hosts).end()) {
						if (((it1->second).traffic_type == 0) && (destPort
								== 53)) {
							data = (u_char*) (packet + radth->it_len
									+ sizeof(struct mgmt_header_t) + 8
									+ sizeof(struct ip) + sizeof(struct udphdr)
									+ 13); //12+1 byte sono l'header dns+ primo carattere che non fa parte dell'indirizzo
							dataSize = ((hdr->len) - (radth->it_len)
									- sizeof(struct mgmt_header_t) - 8
									- sizeof(struct ip) - sizeof(struct udphdr)
									- 13);

							find_mobile_dns(data, dataSize, it1);
						}
						//FUNZIONE FIND MOBILE DNS
					}
					if (it2 != (*hosts).end()) {
						if (((it2->second).traffic_type == 0) && (sourcePort
								== 53)) {
							data = (u_char*) (packet + radth->it_len + 32
									+ sizeof(struct ip) + sizeof(struct udphdr)
									+ 13); //12+1 byte sono l'header dns+ primo carattere che non fa parte dell'indirizzo
							dataSize = ((hdr->len) - (radth->it_len) - 32
									- sizeof(struct ip) - sizeof(struct udphdr)
									- 13);

							find_mobile_dns(data, dataSize, it2);
						}
						//FUNZIONE FIND MOBILE DNS
					}
				}

				else if (sourcePort == 5353 || destPort == 5353) {
					cout << "trovato mDNS\n";
					data = (u_char*) (packet + radth->it_len
							+ sizeof(struct mgmt_header_t) + 8
							+ sizeof(struct ip) + sizeof(struct udphdr));
					dataSize = ((hdr->len) - (radth->it_len)
							- sizeof(struct mgmt_header_t) - 8
							- sizeof(struct ip) - sizeof(struct udphdr));
					if (it1 != (*hosts).end()) {
						find_mobile_mdns(data, dataSize, it1);
					}

				}
			}

		}
		delete (hostDst);
		delete (hostSrc);
	}
}

void sniffing::find_mobile_http(u_char* data, map<string, host>::iterator it) {
	string http = "";
	http = string((char*) data);
	//cout << http << "\n\n\n";

	if (http.find("User-Agent") != string::npos) {
		cout << "found user-agent\n";

		if ((http.find("Android")) != string::npos) {
			(it->second).setTrafficType(1);
			(it->second).setVendor("Android");
			cout << "found Android\n";

		} else if ((http.find("BlackBerry")) != string::npos) {
			(it->second).setTrafficType(1);
			(it->second).setVendor("BlackBerry");
			cout << "found BlackBerry\n";

		} else if ((http.find("Nokia")) != string::npos) {
			(it->second).setTrafficType(1);
			(it->second).setVendor("Nokia");
			cout << "found Nokia\n";

		} else if ((http.find("Windows")) != string::npos && ((http.find(
				"Mobile")) != string::npos)) {
			(it->second).setTrafficType(1);
			(it->second).setVendor("Windows Mobile");
			cout << "found Windows Mobile\n";

		} else if ((http.find("Opera")) != string::npos) {
			(it->second).setTrafficType(1);
			(it->second).setVendor("Opera");
			cout << "found Opera\n";

		} else if ((http.find("iPhone")) != string::npos) {
			(it->second).setTrafficType(1);
			(it->second).setVendor("iPhone");
			cout << "found iPhone \n";

		} else if ((http.find("iPad")) != string::npos) {
			(it->second).setTrafficType(1);
			(it->second).setVendor("iPad");
			cout << "found iPad\n";

		} else if ((http.find("SonyEricsson")) != string::npos) {
			(it->second).setTrafficType(1);
			(it->second).setVendor("Sony_Ericsson");
			cout << "found SonyEricsson\n";
		}

		else {
			(it->second).setTrafficType(2);
			(it->second).setVendor("undefined");
			cout << "found laptop\n";

		}
	}

}

void sniffing::find_mobile_dns(u_char* data, int dataLength,
		map<string, host>::iterator it) {

	string dns = "";
	int pos = 0;

	for (int i = 0; i < dataLength; i++) {
		if ((data[i] >= 'a' && data[i] <= 'z') || (data[i] >= 'A' && data[i]
				<= 'Z') || data[i] == 10 || data[i] == 11 || data[i] == 13
				|| data[i] == '\n') {
			dns += (char) data[i];
		} else {
			if ((data[i + 1] >= 'a' && data[i + 1] <= 'z') && (data[i - 1]
					>= 'a' && data[i - 1] <= 'z'))
				dns += ".";
			else
				dns += " ";
		}
	}
	//	cout<<"--------------------\n\n";
	//cout<<dns<<"\n\n\n\n";
	pos = dns.find("m.");
	if ((pos != string::npos) && !((data[pos - 1] >= 'a' && data[pos - 1]
			<= 'z') || !(data[pos - 1] >= 'A' && data[pos - 1] <= 'Z'))) {

		(it->second).setTrafficType(1);

		//		cout << "found by DNS\n\n\n\n";
		//		cout << dns << "\n";
	}

	else {
		pos = dns.find(".m.");
		if (pos != string::npos) {
			(it->second).setTrafficType(1);
			cout << "found by DNS\n\n\n\n";
			cout << dns << "\n";
		}

	}
	if ((pos != string::npos)) {
		pos = dns.find("mobile.");
		if (pos != string::npos) {
			(it->second).setTrafficType(1);
			cout << "found by DNS\n\n\n\n";
			cout << dns << "\n";
		}

	}
	if ((pos != string::npos)) {
		pos = dns.find(".mobile.");
		if (pos != string::npos) {
			(it->second).setTrafficType(1);
			cout << "found by DNS\n\n\n\n";
			cout << dns << "\n";

		}
	}
}

void sniffing::find_mobile_mdns(u_char* data, int dataLength,
		map<string, host>::iterator it) {

	string mdns = "";

	for (int i = 0; i < dataLength; i++) {
		if ((data[i] >= 'a' && data[i] <= 'z') || (data[i] >= 'A' && data[i]
				<= 'Z') || data[i] == 10 || data[i] == 11 || data[i] == 13
				|| data[i] == '\n') {
			mdns += (char) data[i];
		} else {
			mdns += " ";
		}
	}

	if ((mdns.find("iPhone")) != string::npos) {
		(it->second).setTrafficType(1);
		(it->second).setVendor("iPhone");

	} else if ((mdns.find("apple") && (mdns.find("mobdev"))) != string::npos) {
		(it->second).setTrafficType(1);

	} else if ((mdns.find("iPad")) != string::npos) {
		(it->second).setTrafficType(1);
		(it->second).setVendor("iPhone");
	} else if ((mdns.find("PC")) != string::npos) {
		(it->second).setTrafficType(2);
	}

}

void sniffing::getHttp_mgmt(string http, string ip_dest, string ip_src,
		map<string, URL_rec>*stat_url, list<ip_URL>*temp) {

	string URL = "";
	int pos = 0;
	if (http.size() > 20) {
		if (http.find("GET") != string::npos) {
			pos = http.find("Host");
			if ((pos != string::npos)&&((pos+6)!=string::npos)) {
				for (int i = pos + 6; http.at(i) != '\r'; i++) {
					
					URL += http.at(i);
						
					if (i >= 200) {

						break;
					}
				}
			}
			pos = http.find("GET");
			if ((pos != string::npos)&&((pos+4)!=string::npos)) {
				for (int i = pos + 4; http.at(i) != ' '; i++) {
					
					URL += http.at(i);
						
					if (i >= 200){

						break;
					}

				}

				cout << URL << "\n";
			}
			if (URL != "") {
				URL_rec *tmp1 = new URL_rec();
				ip_URL *tmp2 = new ip_URL();

				(*tmp1).set_URL(URL);
				(*tmp2).set_URL(URL);

				time_t t1;
				time(&t1);
				struct tm *now = localtime(&t1);

				(*tmp1).add_tm(*now);
				(*tmp2).set_timestamp(*now);

				(*tmp2).set_ip_src(ip_src);
				(*tmp2).set_ip_dest(ip_dest);

				pair<string, URL_rec> ele1(URL, *tmp1);

				(*stat_url).insert(ele1);
				cout << "stat_url" << (*stat_url).size() << "\n";
				(*temp).push_back(*tmp2);

				delete (tmp1);
				delete (tmp2);
				//cout << URL << "\n";
			}
		}
	}


	//		list<ip_URL>::iterator it4;
	//
	//		if (temp.size() > 2) {
	//			time_t t1;
	//			time(&t1);
	//			struct tm *now = localtime(&t1);
	//
	//			it4 = temp.begin();
	//			while ((it4 != temp.end()) && (temp.size() > 2)) {
	//
	//				int i = (*now).tm_min;
	//				int h = (it4->timestamp).tm_min;
	//				int se = (*now).tm_sec;
	//				int s1 = (it4->timestamp).tm_sec;
	//				if (i != h) {
	//					it4 = temp.erase(it4);
	//					continue;
	//				} else if ((i == h) && ((se - s1) >= 2)) {
	//					it4 = temp.erase(it4);
	//					continue;
	//				} else {
	//					break;
	//				}
	//
	//			}
	//
	//		}


}

void sniffing::responseHttp_mgmt(string http, string ip_dest, string ip_src,
		map<string, URL_rec>*stat_url, list<ip_URL>*temp) {
	if ((http.size() > 17) && (http.find("HTTP") != string::npos)) {
		if ((http.substr(9, 3) == "200") && (http.find("OK") != string::npos)) {
			//cout << http.substr(9, 3) << "\n\n\n";
			int pos = 0;
			string length = "";
			int len = 0;
			pos = http.find("Content-Length");
			if (pos != string::npos) {
				for (int i = pos + 16; http.at(i) != '\r'; i++) {
					length += http.at(i);
				}

				len = atoi(length.c_str());
				//cout << http << "\n\n\n";
				//cout << len << "\n";


				list<ip_URL>::iterator it1;
				map<string, URL_rec>::iterator it2;

				for (it1 = (*temp).begin(); it1 != (*temp).end(); it1++) {

					if ((it1->ip_dest == ip_src) && (it1->ip_src == ip_dest)) {
						it2 = (*stat_url).find(it1->URL);
						if (((it2->second.byte) == 0) && (len != 0)) {
							(it2->second).set_byte(len);

						}
						if (len != 0) {
							(it2->second).increase_count();
							(it2->second).add_tm(it1->timestamp);

						}

						//cout << temp.size() << "\n";
						(*temp).erase(it1);
						//cout << temp.size() << "\n\n\n";

						break;
					}
				}

			} else {

				list<ip_URL>::iterator it1;

				for (it1 = (*temp).begin(); it1 != (*temp).end(); it1++) {

					if ((it1->ip_dest == ip_src) && (it1->ip_src == ip_dest)) {
						//cout << (*temp).size() << "\n";
						(*temp).erase(it1);
						//cout << temp.size() << "\n\n\n";
						break;
					}
				}

			}

		}

		else if ((http.substr(9, 3) == "100") || (http.substr(9, 3) == "101")
				|| (http.substr(9, 3) == "201") || (http.substr(9, 3) == "202")
				|| (http.substr(9, 3) == "203") || (http.substr(9, 3) == "204")
				|| (http.substr(9, 3) == "205") || (http.substr(9, 3) == "206")
				|| (http.substr(9, 3) == "300") || (http.substr(9, 3) == "301")
				|| (http.substr(9, 3) == "302") || (http.substr(9, 3) == "303")
				|| (http.substr(9, 3) == "304") || (http.substr(9, 3) == "305")
				|| (http.substr(9, 3) == "307") || (http.substr(9, 3) == "416")
				|| (http.substr(9, 3) == "417") || (http.substr(9, 3) == "400")
				|| (http.substr(9, 3) == "401") || (http.substr(9, 3) == "402")
				|| (http.substr(9, 3) == "403") || (http.substr(9, 3) == "404")
				|| (http.substr(9, 3) == "405") || (http.substr(9, 3) == "413")
				|| (http.substr(9, 3) == "406") || (http.substr(9, 3) == "407")
				|| (http.substr(9, 3) == "408") || (http.substr(9, 3) == "409")
				|| (http.substr(9, 3) == "410") || (http.substr(9, 3) == "414")
				|| (http.substr(9, 3) == "411") || (http.substr(9, 3) == "412")
				|| (http.substr(9, 3) == "415") || (http.substr(9, 3) == "500")
				|| (http.substr(9, 3) == "501") || (http.substr(9, 3) == "504")
				|| (http.substr(9, 3) == "502") || (http.substr(9, 3) == "503")
				|| (http.substr(9, 3) == "505")) {

			//cout << http.substr(9, 3) << "\n\n";
			list<ip_URL>::iterator it;

			for (it = (*temp).begin(); it != (*temp).end(); it++) {
				if ((it->ip_src == ip_dest) && (it->ip_dest == ip_src)) {
					//cout << temp.size() << "\n";
					(*temp).erase(it);
					//cout << temp.size() << "\n\n\n";
					break;
				}

			}
		}
	}

	list<ip_URL>::iterator it4;

	if ((*temp).size() > 4) {
		time_t t1;
		time(&t1);
		struct tm *now = localtime(&t1);

		it4 = (*temp).begin();
		while ((it4 != (*temp).end()) && ((*temp).size() > 20)) {

			int i = (*now).tm_min;
			int h = (it4->timestamp).tm_min;
			int se = (*now).tm_sec;
			int s1 = (it4->timestamp).tm_sec;
			if (i != h) {
				it4 = (*temp).erase(it4);
				continue;
			} else if ((i == h) && ((se - s1) >= 2)) {
				it4 = (*temp).erase(it4);

				continue;
			} else {
				break;
			}

		}

	}

}

void sniffing:: dump_mac_map(map<string, host>* mac_map, string filename) {

	ofstream file1;
	file1.open(filename.c_str());
	map<string, host>::iterator ite;
	file1 << "mac_addr\thttp_traffic\thttps_traffic\trcv_http\trcv_https\trcv_pkt\trcv_traffic\tsent_http\tsent_https\tsent_pkt\tsend_traffic\ttotal_traffic\ttraffic_type\tvendor"<<endl;

	for (ite = (*mac_map).begin(); ite != (*mac_map).end(); ite++) {
		file1 << (ite->first) << "\t";
		file1 << (ite->second).http_traffic << "\t"
				<< (ite->second).https_traffic << "\t"
				<< (ite->second).rcv_http_traffic << "\t"
				<< (ite->second).rcv_https_traffic << "\t"
				<< (ite->second).rcv_pkt << "\t" << (ite->second).rcv_traffic
				<< "\t" << (ite->second).sent_http_traffic << "\t"
				<< (ite->second).sent_https_traffic << "\t"
				<< (ite->second).sent_pkt << "\t" << (ite->second).sent_traffic
				<< "\t" << (ite->second).total_packet << "\t"
				<< (ite->second).total_traffic << "\t"
				<< (ite->second).traffic_type << "\t" << (ite->second).vendor
				<< "\t;\n";

	}

	file1.close();

}

void sniffing:: dump_url_map(map<string, URL_rec>* url_map, string filename) {
	ofstream file1;
	file1.open(filename.c_str());
	map<string, URL_rec>::iterator ite;

	file1 << "URL\tbyte\tcount\ttimestamp_list"<<endl;

	for (ite = (*url_map).begin(); ite != (*url_map).end(); ite++) {
		file1 << (ite->first) << "\t";
		file1 << (ite->second).byte << "\t" << (ite->second).count << "\t";
		list<struct tm>::iterator ite2;
		for (ite2 = (ite->second).timestamp.begin(); ite2
				!= (ite->second).timestamp.end(); ite2++) {

			file1 << ite2->tm_mday << "/" << ite2->tm_mon << "/"
					<< ite2->tm_year << "  " << ite2->tm_hour << ":"
					<< ite2->tm_min << ":" << ite2->tm_sec << ".";

		}

		file1 << "\t;\n";

	}

	file1.close();

}

void sniffing::Stampa_link_layer(int link_layer) {
	char *type = NULL;
	int length_header_frame;

	switch (link_layer) {
	case DLT_IEEE802_11_RADIO_AVS:
		type = "Link layer 802.11 radio AVS";
		break;
	case DLT_IEEE802_11_RADIO:
		type = "Link layer 802.11 Radio";
		break;
	case DLT_NULL:
		type = "Link_layer assente";
		length_header_frame = 4;
		break;
	case DLT_EN10MB:
		type = "Ethernet 10Mb";
		length_header_frame = 14;
		break;
	case DLT_IEEE802:
		type = "IEEE 802.5 Token Ring";
		break;
	case DLT_ARCNET:
		type = "Arcnet";
		break;
	case DLT_SLIP:
		type: "Serial Line IP";
		break;
	case DLT_PPP:
		type = "Point-to-point protocol";
		break;
	case DLT_FDDI:
		type = "FDDI";
		break;
	case DLT_ATM_RFC1483:
		type = "LLC/SNAP-encapsulated ATM";
		break;
	case DLT_RAW:
		type = "raw IP";
		length_header_frame = 0;
		break;
	case DLT_PPP_SERIAL:
		type = "PPP o Cisco PPP in HDLC framing";
		break;
	case DLT_PPP_ETHER:
		type = "PPPoE";
		break;
	case DLT_CHDLC:
		type = "Cisco HDLC";
		break;
	case DLT_IEEE802_11:
		type = "IEEE 802.11 wireless LAN";
		break;
	case DLT_LOOP:
		type = "OpenBSD loopback encapsulation";
		length_header_frame = 4;
		break;
	case DLT_LINUX_SLL:
		type = "Linux \"cooked\" capture encapsulation";
		length_header_frame = 16;
		break;
	case DLT_LTALK:
		type = "Apple LocalTalk";
		break;
	default:
		type = "Link layer sconosciuto";
		length_header_frame = 0;
		break;
	}
	printf("Link layer: %s\n\n", type);
}

