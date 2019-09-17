/*
    code by FatRabbit
This source code is free
you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation
This source code  is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE
See the GNU General Public License for more details.

*/



#include <getopt.h>
#include <sys/errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <libiptc/libiptc.h>
#include <iptables.h>

#include <sys/time.h>
#include <ncurses.h>
/*
    include some other header(s)
    - delta function
*/
#include "delta.h"
#include "processing.h"

/*
    maximum number of rules to be processed
*/
#define MAX_RULES 2048
/*
    number of rules to print per window
*/
#define PRINTABLE_RULES 15

/*
    convert __u32 address to x.x.x.x format
    got the code from iptables-save.c 
*/
#define IP_PARTS_NATIVE(n)      \
(unsigned int)((n)>>24)&0xFF,   \
(unsigned int)((n)>>16)&0xFF,   \
(unsigned int)((n)>>8)&0xFF,    \
(unsigned int)((n)&0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n)) 

/*
    processing
    void processing(char *, char *, struct bwcnt *, double *, struct timeval *, struct timeval *);
*/
int get_stats(char *tablename, char *chain, struct bwcnt *bw, double *totbw, struct timeval *to, struct timeval *ti, int cmd) {
    int i;
    struct xtc_handle *h = NULL;
    
    /*
        we are going to directly retrieve counters inside h with the use of ipt_entry variable type
        instead of iptc_read_counter() function
    */
    struct ipt_entry *e = NULL;
    
   
    /*
        take new snapshot
    */
    h = iptc_init(tablename);
    if( h == NULL ) {
        printf("Error initializing snapshot:   %s\n", iptc_strerror(errno));
        exit(errno);
    }
    /*
        have a timeshoot
    */
    i = gettimeofday(to, NULL);

    /*
        initialize "i" to 0
    */
    i = 0;

    
    /*
        go through all the remaining chain rules and retrieve the needed counters
        the condition i<MAX_RULES prevents the program from going through all the rules
        feel free to increase/decrease MAX_RULES or even disable it!
    */
    for(e = iptc_first_rule(chain, h); e; e = iptc_next_rule(e, h) ) {
        /*
            stop processing if too much rules (see the value of MAX_RULES macro)
        */
        if (i > MAX_RULES)
            break;

        /*
            check if the rule should be ignored
        */
        if(cmd && (e->ip.src.s_addr == 0) && (e->ip.dst.s_addr == 0))
            continue;
        /*
            case 1: the rule counter has not been initialized yet - initialize it
        */
        if(bw[i].start == 0) {
            bw[i].icnt = e->counters.bcnt;
            bw[i].rule_saddr = e->ip.src.s_addr;
            bw[i].rule_daddr = e->ip.dst.s_addr;
            bw[i].start = 1;
        }
        /*
            case 2: the rule counter has already been initialized (a previous measure is stored there) - add the current measure
            and calculate the download speed
        */
        else {
            bw[i].rule_saddr = e->ip.src.s_addr;
            bw[i].rule_daddr = e->ip.dst.s_addr;
            bw[i].ocnt = e->counters.bcnt;
            bw[i].rank = i+1;    /* yes, I need this :p */
            if(bw[i].ocnt == bw[i].icnt) /* no byte flowing <=> download speed is 0 */
                bw[i].bw = 0;
            else
                /*
                    the download speed is:
                        current byte count    bw[i].ocnt  *minus*
                        previous byte count   bw[i].icnt  * divided by*
                        1024 to convert bytes into kbytes * divided again by*
                        time difference in seconds
                      
                    to get flow in kbytes/sec
                */
                bw[i].bw = (bw[i].ocnt - bw[i].icnt)/(1024 * delta(*to, *ti));

            /*
                now, place the bw[i].ocnt inside bw[i].icnt
            */
            bw[i].icnt = bw[i].ocnt;
            
            /*
                update the value of total bandwidth
            */
            *totbw += bw[i].bw;
         }
        /*
            go to next bw[i]
        */
        i++; 
    }
    return i;

}

void float_to_hreadable(char *str, float x) {
    
    if(x<=1) {
        sprintf(str, "%5.2f ", x*1024);
    }
    else if(x < 1000) {
        sprintf(str, "%5.2f K", x);
    }
    else if(x < 1000000) {
        sprintf(str, "%5.2f M", x/1024);
    }
    else if (x > 1000000){
        sprintf(str, "%5.2f G", x/1048576);
    }
}


void print_stats(struct bwcnt *bw, int rulenum, WINDOW *main) {

    int i,
    MAX_X = getmaxx(main);
    char foo[16]="";
    
    for (i=0; i<PRINTABLE_RULES; i++) {
        if(i<rulenum) {
            float_to_hreadable(foo, bw[i].bw);
            mvwprintw(
                main,
                i+1,
                2,
                " %3d: %3u.%3u.%3u.%3u -> %3u.%3u.%3u.%3u = %sbytes/sec           ", bw[i].rank,
                IP_PARTS(bw[i].rule_saddr), IP_PARTS(bw[i].rule_daddr),
                foo
            );
            float_to_hreadable(foo, bw[i].ocnt/1024.);
            mvwprintw(
                main,
                i+1,
                MAX_X/2,
                "total traffic: %sbytes      ",
                foo
            );
            wrefresh(main);
        }
    }
}


void print_sorted_stats(struct bwcnt *bw, int rulenum, WINDOW *main) {
    struct bwcnt bw_draft[rulenum], temp;
    int i, j, index_max=0;
    
    for(i=0; i<rulenum; i++) {
        bw_draft[i] = bw[i];
    }



	/*
		1- Progressively select each cell of the array from the very first
		2- Find the index of the cell containing the highest value of the remaining cells
		3- Switch the values of index_max and the current selected cell
	*/
	
    for(i=0; i<rulenum; i++){
        index_max=i;
		for(j=i; j<rulenum; j++){
			if(bw_draft[j].bw>bw_draft[index_max].bw){
				index_max=j;
			}
			else;
		}
		
		/* Basic method of switching two variables's values */
		temp=bw_draft[i];
		bw_draft[i]=bw_draft[index_max];
		bw_draft[index_max]=temp;
	}

    print_stats(
        bw_draft,
        rulenum,
        main
    );
}
