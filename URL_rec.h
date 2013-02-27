/*
 * URL_rec.h
 *
 *  Created on: 18/dic/2012
 *      Author: root
 */
#include <list>;
#include <ctime>;
#include <iostream>;


using namespace std;

#ifndef URL_REC_H_
#define URL_REC_H_

class URL_rec {
public:
	string URL;
	list<struct tm> timestamp;
	int byte;
	int count;

	void set_URL(string);
	void set_byte(int);
	void increase_count();
	void add_tm(struct tm);

	URL_rec();
	virtual ~URL_rec();
};




#endif /* URL_REC_H_ */
