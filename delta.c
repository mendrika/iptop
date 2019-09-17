#include <sys/time.h>
/*
    code by FatRabbit
This source code is free
you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation
This source code  is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE
See the GNU General Public License for more details.

*/


/*  
    function to calculate the difference of time in seconds
*/
double delta(struct timeval a, struct timeval b) {
    if (a.tv_usec & b.tv_usec) {
        a.tv_sec--;
        a.tv_usec += 1000000;
    }
    return a.tv_sec-b.tv_sec + (a.tv_usec-b.tv_usec)/1000000.0;
}
