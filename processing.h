#ifndef PROCESSING_H
#define PROCESSING_H

#include <ncurses.h>
/*
    structure which will be used to count bytes between time intervals
*/
struct bwcnt {
    int start;          /* to check if the rule rule has already been initialized */
    u_int64_t icnt;     /* bytes through ; previous measure */
    u_int64_t ocnt;     /* bytes through ; current measure  */
    double bw;          /* download speed corresponding to the iptables rule */
    u_int32_t rule_saddr; /* ip address: the source of an iptables rule */
    u_int32_t rule_daddr; /* ip address: the destination of an iptables rule */
    int rank;             /* it may seem absurde but you are going to see */
};

int get_stats(char *, char *, struct bwcnt *, double *, struct timeval *, struct timeval *, int);
void print_stats(struct bwcnt *, int, WINDOW *);
void print_sorted_stats(struct bwcnt *, int, WINDOW *);
void sort_stats(struct bwcnt *, int);
void float_to_hreadable(char *, float);
#endif
