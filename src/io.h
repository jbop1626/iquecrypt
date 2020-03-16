/*
    io.h
    Copyright © 2018, 2019, 2020 Jbop (https://github.com/jbop1626)

    This file is a part of iQueCrypt.

    iQueCrypt is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    iQueCrypt is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
 
void display_help(void);
void argument_error(void);
int open_file(FILE ** file, const char * filename, const char * mode);
size_t read_from_file(unsigned char * data_buffer, const char * filename, size_t data_length);
int save_to_file(const unsigned char * data, const char * filename, size_t data_length);
int get_input(char * line_buffer, int buffer_length, FILE * instream);
