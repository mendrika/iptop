#include<ncurses.h>

/*
    function that destroys a WINDOW
    copy and pasted from "NCURSES Programming HOWTO"
*/
void destroy_win(WINDOW *the_window){
    /* box(the_window, ' ', ' '); : This won't produce the desired
    * result of erasing the window. It will leave it's four corners 
    * and so an ugly remnant of window. 
    */
    wborder(the_window, ' ', ' ', ' ',' ',' ',' ',' ',' ');
    /* The parameters taken are 
    * 1. win: the window on which to operate
    * 2. ls: character to be used for the left side of the window 
    * 3. rs: character to be used for the right side of the window 
    * 4. ts: character to be used for the top side of the window 
    * 5. bs: character to be used for the bottom side of the window 
    * 6. tl: character to be used for the top left corner of the window 
    * 7. tr: character to be used for the top right corner of the window 
    * 8. bl: character to be used for the bottom left corner of the window 
    * 9. br: character to be used for the bottom right corner of the window
    */
    wrefresh(the_window);
    delwin(the_window);
}

/*
    function that creates a new WINDOW
    copy and pasted from "NCURSES Programming HOWTO"
*/
WINDOW *create_newwin(int height, int width, int starty, int startx){
    WINDOW *the_window;

    the_window = newwin(height, width, starty, startx);
    
    box(the_window, 0 , 0);		
    /* 
        0, 0 gives default characters 
        * for the vertical and horizontal
        * lines			
    */
    wrefresh(the_window);

    return the_window;
}






















