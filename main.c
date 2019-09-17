/*
realtime monitoring with ncurses by FatRabbit
This source code is free
you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation
This source code  is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE
See the GNU General Public License for more details.

*/


/*
    required headers in order to compile and link with libiptc
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

#include <string.h>

/*
    ncurses library header
*/
#include <ncurses.h>

/*
    because we will need to calculate time intervals
*/
#include <sys/time.h>

/*
    include some other custom functions header(s)
    - delta() function
    - processing() function
    - ncurse window manupilation functions (create, destroy)
*/
#include "delta.h"
#include "processing.h"
#include "window.h"


#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n)) 


/*
    time interval between measures (in seconds)
*/
#define SLEEPTIME 2

/*
    maximum number of rules to process
*/
#define MAX_RULES 2048
/*
    number of rules to print per window
*/
#define PRINTABLE_RULES 15

/*
    title of the GUI
*/
#define TITLE_TXT "per rule monitoring - kbytes/sec"

/*
    main function
*/
int main(int argc, char *argv[]) {
    int i, /* counter we are going to use later */
    IGNORE_ANON = 0,    
    rulenum=0, /* to store the total number of rules */
    MAX_X, MAX_Y; /* the number of cols and rows of the terminal */

    WINDOW *title, *main;    
    /*
        the follwing variable will contain the total bandwidth speed
    */
    double totbw=0., foo=5.5;
    
    /*
        structures that will store date (in seconds) between two counters update.
    */
    struct timeval to, ti;
    
    /*
        the structure which will contain all the information we need 
    */
    struct bwcnt bw[MAX_RULES];
    
    /*
        the table and the chain names can be easily hardcoded
        do it now if you want
    */
    char *chain = NULL;
    char *tablename = NULL;
    
    
    /*
        first thing, process the arguments
    */
    if((argc != 3) && (argc != 4)) {
        printf("Not enough or too much arguments:\n\
- first argument must be a table name \n\
- second argument must be a valid chain name \n\
- -i to ignore rules with neither source nor destination \n\
");
        return EXIT_FAILURE;
    }
    else {
        tablename = argv[1];
        chain = argv[2];
        if((argc == 4) && (strcmp(argv[3], "-i")) == 0)
            IGNORE_ANON = 1;
    }
    
    /*
        NCURSES stuff goes here
    */
    initscr();
    noecho();
    cbreak();
    keypad(stdscr, TRUE);
    getmaxyx(stdscr, MAX_Y, MAX_X);
    refresh();
    curs_set(0);
    timeout(0); 
    title = create_newwin(
        8,
        MAX_X-4,
        2,
        1
    );
    
    /*
        print title on the top window
    */
    mvwprintw(title, 2, (MAX_X-2-strlen(TITLE_TXT))/2, TITLE_TXT);
    mvwprintw(title, 3, (MAX_X-2-strlen(TITLE_TXT))/2, "          ctrl-c to leave");
    mvwprintw(title, 4, 3, "table = %s    chain = %s", tablename, chain);
    mvwprintw(title, 5, 3, "displaying traffic flow speed in descending order", tablename, chain);
    wrefresh(title);

    /* 
        create the GUI
    */
    main = create_newwin(
        18,
        MAX_X-4,
        10,
        1
    );

    /*
        get time to start meter on variable ti ("i" like initial)
    */
    gettimeofday(&ti, NULL);
  
    /*
        initialize the array of rule
    */
    memset(&bw, 0, MAX_RULES*sizeof(struct bwcnt));
    

    /*
        We will use an infite loop - with sleeptime to avoid cpu overload
        use Ctrl + C  to end the program
    */

    do {               
        /*
            get iptables stats and fill the "bw" array with the decent values
            get_stats():
                - tablename
                - chain name
                - pointer to "bw" array
                - pointer to totbw variable
                - previous snapshot time ti
                - current snapshot time to
            returns the number of rules in the chain (int)
        */
        rulenum = get_stats(
            tablename,
            chain,
            bw,
            &totbw,
            &to,
            &ti,
            IGNORE_ANON
        );
        /*
            after a successful update, "ti" (the current time) becomes "to" (initial time) - we must update "ti"
        */
        ti = to;
                
        
        /* print the top 15*/
        print_sorted_stats(
            bw,
            rulenum,
            main
        );
        
        sleep(SLEEPTIME);
    } while(1);
    
    /*
        decently leave the program
    */
    endwin();
    
    return EXIT_SUCCESS;
}























