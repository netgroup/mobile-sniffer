/*
 * ip_URL.h
 *
 *  Created on: 18/dic/2012
 *      Author: root
 */

#ifndef IP_URL_H_
#define IP_URL_H_

#include <iostream>;
#include <ctime>;

using namespace std;

class ip_URL {
public:

	string ip_src;
	string ip_dest;
	struct tm timestamp;
	string URL;

	void set_ip_src(string);
	void set_ip_dest(string);
	void set_timestamp(struct tm);
	void set_URL(string);




	ip_URL();
	virtual ~ip_URL();
};

#endif /* IP_URL_H_ */
