/*
	Copyright © 2018 Jbop (https://github.com/jbop1626)

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
#ifndef IQUE_CRYPT_UTIL
#define IQUE_CRYPT_UTIL
#include <cstdint>
#include <string>

uint8_t * read_file(std::string in_file_name, bool length_known, int & expected_length);
void write_file(std::string out_file_name, uint8_t * buffer, int file_length);
void read_aes_keyiv(std::string par, std::string input, uint8_t * key_buffer);

void argument_error();
void file_size_error();
void file_error(std::string file_name);
void search_error(std::string query, std::string search_file_name);

void display_help();

#endif
