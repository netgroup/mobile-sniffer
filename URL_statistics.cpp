/*
 * URL_statistics.cpp
 *
 *  Created on: 16/gen/2013
 *      Author: root
 */

#include "URL_statistics.h"
using namespace std;
#include <map>
#include <iterator>
#include <time.h>

URL_statistics::URL_statistics(map<string, URL_rec>* stat) {
	// TODO Auto-generated constructor stub
	url_stat = stat;

}

URL_statistics::~URL_statistics() {
	// TODO Auto-generated destructor stub
}

void URL_statistics::compute_statistics() {
	map<string, URL_rec>::iterator it1;

	for (it1 = (*url_stat).begin(); it1 != (*url_stat).end(); it1++) {
		if(((it1->second).byte==0)&&(((it1->second).count)<2)){
			continue;
		}
		else{
			list<struct tm>::iterator it2;
			list<struct tm>::iterator it3;

			it2=(it1->second).timestamp.begin();
			it3=it2++;
			for(it3;it3!=(it1->second).timestamp.end();it3++){
				int ah=(it3->tm_hour);
				int am=(it3->tm_min);
				int bh=(it2->tm_hour);
				int bm=(it2->tm_min);
				int index=0;
				if(ah!=bh){
					am=am+((ah-bh)*60);
				}
				index=((am-bm)/10)+1;

				pair<int, int> elem(index, 0);
				graph.insert(elem);
				map<int, int>::iterator it4;
				it4=graph.find(index);
				(it4->second)+=(it1->second).byte;
				it2=it3;

			}

		}

	}
}
