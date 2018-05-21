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
#ifndef IQUE_CRYPT
#define IQUE_CRYPT

#include <cstdint>
#include <string>

#define CBC 1

struct rec_args {
	std::string mode;
	std::string rc_fn;
	std::string v2_fn;
	std::string iv_par;
	std::string iv_in;
	std::string rs_fn;
	std::string cid;
};

struct crypt_args {
	std::string mode;
	std::string in_fn;
	std::string key_par;
	std::string key_in;
	std::string iv_par;
	std::string iv_in;
};

struct extract_args {
	std::string in_fn;
	std::string cid;
};

void parse_args(struct rec_args & a, char * argv[], int argc);
void parse_args(struct crypt_args & a, char * argv[], int argc);
void parse_args(struct extract_args & a, char * argv[], int argc);

void ique_crypt(char * argv[], int argc);
void ique_extract(char * argv[], int argc);

void aes_crypt(std::string mode, std::string file_name, bool length_known, int file_length,
	std::string k_par, std::string k_input, std::string iv_par, std::string iv_input);
void extract_cmd(std::string cmd_file_name);
void extract_ticket(std::string tkt_file_name, std::string content_id);
void rec_crypt(std::string mode, std::string rec_file_name, std::string v2_file_name,
	std::string iv_par, std::string iv_input, std::string rsys_file_name, std::string content_id);

uint8_t * read_file(std::string in_file_name, bool length_known, int & expected_length);
void write_file(std::string out_file_name, uint8_t * buffer, int file_length);
void read_aes_keyiv(std::string par, std::string input, uint8_t * key_buffer);

void argument_error();
void file_size_error();
void file_error(std::string file_name);
void search_error(std::string query, std::string search_file_name);

void display_help();

#endif
