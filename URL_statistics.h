/*
 * URL_statistics.h
 *
 *  Created on: 16/gen/2013
 *      Author: root
 */

#ifndef URL_STATISTICS_H_
#define URL_STATISTICS_H_
#include <map>
#include "URL_rec.h"

using namespace std;

class URL_statistics {
public:
	map<string, URL_rec>* url_stat;
	map<int,int> graph;
	void compute_statistics();
	URL_statistics(map<string,URL_rec>*);
	virtual ~URL_statistics();
};

#endif /* URL_STATISTICS_H_ */
