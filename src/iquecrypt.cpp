/*
	Copyright 2018 Jbop (https://github.com/jbop1626)

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
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string>
#include "iquecrypt.hpp"
#include "aes/aes.hpp"

void ique_decrypt(char * argv[]) {
	if (std::string(argv[2]) == "-app") {
		aes_decrypt_file(argv[3], false, 0, argv[4], argv[5], argv[6], argv[7]);
	}
	else if (std::string(argv[2]) == "-tk") {
		aes_decrypt_file(argv[3], true, 16, argv[4], argv[5], argv[6], argv[7]);
	}
	else {
		argument_error();
	}
}

void ique_extract(char * argv[], int argc) {
	if (std::string(argv[2]) == "-cmd" && argc == 4) {
		extract_cmd(argv[3]);
	}
	else if (std::string(argv[2]) == "-ticket" && argc == 6) {
		extract_ticket(argv[3], argv[5]);
	}
	else {
		argument_error();
	}
}

void aes_decrypt_file(std::string file_name, bool length_known, int file_length,
	std::string k_par, std::string k_input, std::string iv_par, std::string iv_input) {

	uint8_t * file_buffer = read_file(file_name, length_known, file_length);
	if (file_length % 16 != 0) {
		file_size_error();
	}

	uint8_t key[16];
	read_aes_keyiv(k_par, k_input, key);

	uint8_t iv[16];
	read_aes_keyiv(iv_par, iv_input, iv);

	std::cout << "Decrypting..." << std::endl;
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, file_buffer, file_length);
	write_file("[dec]" + file_name, file_buffer, file_length);
	delete[] file_buffer;
	std::cout << "Decryption complete!" << std::endl;
}

void extract_cmd(std::string cmd_file_name) {
	bool is_SA = false;

	int cmd_file_length = 0;
	uint8_t * cmd_buffer = read_file(cmd_file_name, false, cmd_file_length);

	if (cmd_file_length == 0x1AC) {
		is_SA = true;
	}
	else if (cmd_file_length == 0x29AC) {
		is_SA = false;
	}
	else {
		file_size_error();
	}
	int offset = is_SA ? 0 : 0x2800;
	uint8_t * title_key_enc = &cmd_buffer[0x9c + offset];
	uint8_t * content_iv = &cmd_buffer[0x38 + offset];
	uint8_t * title_key_iv = &cmd_buffer[0x14 + offset];
	uint8_t * content_id = &cmd_buffer[0x98 + offset];

	std::stringstream ss;
	for (int i = 0; i < 4; ++i) {
		ss << std::setw(2) << std::setfill('0') << std::hex << (int)content_id[i];
	}
	std::string cid_str = ss.str();
	for (int s = 0; s < cid_str.length(); ++s) {
		cid_str[s] = tolower(cid_str[s]);
	}

	std::cout << "Extracting files from cmd..." << std::endl;
	std::cout << "Extracting title_key_enc..." << std::endl;
	write_file(cid_str + "_title_key_enc.bin", title_key_enc, 16);
	std::cout << "Extracting content_iv..." << std::endl;
	write_file(cid_str + "_content_iv.bin", content_iv, 16);
	std::cout << "Extracting title_key_iv..." << std::endl;
	write_file(cid_str + "_title_key_iv.bin", title_key_iv, 16);
	delete[] cmd_buffer;
	std::cout << "Extraction from cmd complete!" << std::endl;
}

void extract_ticket(std::string tkt_file_name, std::string content_id) {
	if (content_id.length() != 8) {
		std::cerr << "The provided content id is invalid." << std::endl << "Make sure it is in hexadecimal with all 8 digits." << std::endl << std::endl;
		argument_error();
	}
	for (int s = 0; s < content_id.length(); ++s) {
		content_id[s] = tolower(content_id[s]);
	}

	int tkt_file_length = 0;
	uint8_t * ticket_sys = read_file(tkt_file_name, false, tkt_file_length);

	uint8_t cid[4];
	int m = 0;
	for (int n = 0; n <= 6; n+=2) {
		cid[m] = std::stoi(content_id.substr(n, 2), nullptr, 16);
		m++;
	}

	uint8_t ticket_count = ticket_sys[3];
	uint8_t * cmd_start = nullptr;
	uint8_t * tmp_ptr = ticket_sys + 0x289C;
	for (int i = 1; i <= ticket_count; ++i) {
		if (std::memcmp(tmp_ptr, cid, 4) == 0) {
			cmd_start = tmp_ptr - 0x98;
			std::cout << "Entry for " << content_id << " found in " << tkt_file_name << std::endl;
			break;
		}
		tmp_ptr += 0x2B4C;
	}
	if (cmd_start == nullptr) {
		search_error(content_id, tkt_file_name);
	}

	std::cout << "Extracting files from content metadata..." << std::endl;
	uint8_t * title_key_enc = &cmd_start[0x9c];
	uint8_t * content_iv = &cmd_start[0x38];
	uint8_t * title_key_iv = &cmd_start[0x14];
	std::cout << "Extracting title_key_enc..." << std::endl;
	write_file(content_id + "_title_key_enc.bin", title_key_enc, 16);
	std::cout << "Extracting content_iv..." << std::endl;
	write_file(content_id + "_content_iv.bin", content_iv, 16);
	std::cout << "Extracting title_key_iv..." << std::endl;
	write_file(content_id + "_title_key_iv.bin", title_key_iv, 16);
	std::cout << "Extraction from content metadata complete!" << std::endl;

	uint8_t * ticket_start = &cmd_start[0x1AC];

	std::cout << "Extracting files from ticket head..." << std::endl;
	uint8_t * title_key_iv_2 = &ticket_start[0x10];
	uint8_t * ecc_public_key = &ticket_start[0x20];
	std::cout << "Extracting title_key_iv_2..." << std::endl;
	write_file(content_id + "_title_key_iv_2.bin", title_key_iv_2, 16);
	std::cout << "Extracting ecc_public_key..." << std::endl;
	write_file(content_id + "_ecc_public_key.bin", ecc_public_key, 64);
	delete[] ticket_sys;
	std::cout << "Extraction from ticket complete!" << std::endl;
}

uint8_t * read_file(std::string in_file_name, bool length_known, int & expected_length) {
	std::ifstream fin;
	fin.open(in_file_name, std::ios_base::in | std::ios_base::binary | std::ios_base::ate);
		if (!fin.is_open()) {
		fin.clear();
		file_error(in_file_name);
	}
	int file_length = fin.tellg();
	if (length_known && (file_length != expected_length)) {
		file_size_error();
	}
	expected_length = file_length;
	fin.seekg(0, std::ios::beg);
	uint8_t * buffer = new uint8_t[file_length];
	fin.read((char *)buffer, file_length);
	fin.clear();
	fin.close();
	return buffer;
}

void write_file(std::string out_file_name, uint8_t * buffer, int file_length) {
	std::ofstream fout(out_file_name, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
	if (!fout.is_open()) {
		std::cerr << "ERROR: Could not open file to write." << std::endl;
		std::exit(EXIT_FAILURE);
	}
	fout.write((char *)buffer, file_length);
	fout.close();
}

void read_aes_keyiv(std::string par, std::string input, uint8_t * key_buffer) {
	if (par == "-key" || par == "-iv") {
		if (input.length() != 32) {
			file_size_error();
		}
		int j = 0;
		for (int i = 0; i <= 30; i+=2) {
			key_buffer[j] = std::stoi(input.substr(i, 2), nullptr, 16);;
			j++;
		}
	}
	else if (par == "-fkey" || par == "-fiv") {
		int key_length = 16;
		uint8_t * tmp = read_file(input, true, key_length);
		std::memcpy(key_buffer, tmp, 16);
		delete[] tmp;
	}
	else {
		argument_error();
	}
}

void argument_error() {
	std::cerr << "ERROR: Invalid arguments." << std::endl << "Run iquecrypt with -h or --help for usage help and other info." << std::endl;
	std::exit(EXIT_FAILURE);
}

void file_size_error() {
	std::cerr << "ERROR: An input has an invalid size. Read the usage manual for more information about accepted files and formats." << std::endl;
	std::exit(EXIT_FAILURE);
}

void file_error(std::string file_name) {
	std::cerr << "ERROR: Could not open " << file_name << std::endl;
	std::exit(EXIT_FAILURE);
}

void search_error(std::string cid, std::string tkt_file_name) {
	std::cerr << "ERROR: Entry for " + cid + " not found in " << tkt_file_name << std::endl;
	std::exit(EXIT_FAILURE);
}

void display_help() {
	std::cout << "Please use the usage manual for now..." << std::endl;
}
