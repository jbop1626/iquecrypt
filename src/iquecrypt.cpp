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
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string>
#include "iquecrypt.hpp"
#include "aes/aes.hpp"

void ique_crypt(char * argv[], int argc) {
	if (std::string(argv[2]) == "-app") {
		struct crypt_args a = {"", "", "", "", "", ""};
		parse_args(a, argv, argc);
		aes_crypt(a.mode, a.in_fn, false, 0, a.key_par, a.key_in, a.iv_par, a.iv_in);
	}
	else if (std::string(argv[2]) == "-tk") {
		struct crypt_args a = { "", "", "", "", "", "" };
		parse_args(a, argv, argc);
		aes_crypt(a.mode, a.in_fn, true, 16, a.key_par, a.key_in, a.iv_par, a.iv_in);
	}
	else if (std::string(argv[2]) == "-rec") {
		struct rec_args a = {"", "", "", "", "", "", ""};
		parse_args(a, argv, argc);
		rec_crypt(a.mode, a.rc_fn, a.v2_fn, a.iv_par, a.iv_in, a.rs_fn, a.cid);
	}
	else {
		argument_error();
	}
}

void ique_extract(char * argv[], int argc) {
	if (std::string(argv[2]) == "-cmd") {
		struct extract_args a;
		parse_args(a, argv, argc);
		extract_cmd(a.in_fn);
	}
	else if (std::string(argv[2]) == "-ticket") {
		struct extract_args a;
		parse_args(a, argv, argc);
		extract_ticket(a.in_fn, a.cid);
	}
	else {
		argument_error();
	}
}

void aes_crypt(std::string mode, std::string file_name, bool length_known, int file_length,
	std::string k_par, std::string k_input, std::string iv_par, std::string iv_input) {

	uint8_t * file_buffer = read_file(file_name, length_known, file_length);
	if (file_length % 16 != 0) {
		file_size_error();
	}

	uint8_t key[16];
	read_aes_keyiv(k_par, k_input, key);

	uint8_t iv[16];
	read_aes_keyiv(iv_par, iv_input, iv);

	std::string prefix;
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	if (mode == "decrypt") {
		std::cout << "Decrypting..." << std::endl;
		AES_CBC_decrypt_buffer(&ctx, file_buffer, file_length);
		std::cout << "Decryption complete!" << std::endl;
		prefix = "[dec]";
	}
	else if (mode == "encrypt") {
		std::cout << "Encrypting..." << std::endl;
		AES_CBC_encrypt_buffer(&ctx, file_buffer, file_length);
		std::cout << "Encryption complete!" << std::endl;
		prefix = "[enc]";
	}
	else {
		argument_error();
	}
	write_file(prefix + file_name, file_buffer, file_length);
	delete[] file_buffer;
}

void rec_crypt(std::string mode, std::string rec_file_name, std::string v2_file_name,
	std::string iv_par, std::string iv_input, std::string rsys_file_name, std::string content_id) {
	int rec_size = 0;
	uint8_t * rec = read_file(rec_file_name, false, rec_size);
	if (rec_size % 16 != 0) {
		std::cerr << "The size of the input file to be encrypted/decrypted is not a multiple of 16.";
		std::cerr << "Try padding the file and re-running the program." << std::endl << std::endl;
		file_size_error();
	}

	int v2_size = 256;
	uint8_t * v2 = read_file(v2_file_name, true, v2_size);

	int rsys_size = 0;
	uint8_t * recrypt_sys = read_file(rsys_file_name, false, rsys_size);

	uint8_t content_iv[16];
	read_aes_keyiv(iv_par, iv_input, content_iv);

	uint8_t cid[4];
	int m = 0;
	for (int n = 0; n <= 6; n += 2) {
		cid[m] = std::stoi(content_id.substr(n, 2), nullptr, 16);
		m++;
	}

	// This method of generating the recrypt list iv from the BB ID *should*
	// work for any underlying byte ordering. ("should"...)
	int ovrflw[3] = { 0 };
	if (v2[0x97] > 0xFB) {
		for (int z = 0; z < (v2[0x97] - 0xFC); ++z) {
			ovrflw[z] = 1;
		}
	}
	uint8_t recrypt_list_iv[16] = { v2[0x94], v2[0x95], v2[0x96], v2[0x97],
									v2[0x94], v2[0x95], v2[0x96] + ovrflw[2], v2[0x97] + 1,
									v2[0x94], v2[0x95], v2[0x96] + ovrflw[1], v2[0x97] + 2,
									v2[0x94], v2[0x95], v2[0x96] + ovrflw[0], v2[0x97] + 3 };

	uint8_t recrypt_list_key[16];
	std::memcpy(recrypt_list_key, &v2[0xC8], 16);
	delete[] v2;

	int entries_count = recrypt_sys[0x43]; // seems like the best way to deal with endianness problems
	std::cout << "Searching recrypt.sys entries (" << entries_count << " total)..." << std::endl;
	uint8_t reckey[16] = { 0 };
	bool entry_not_found = true;
	uint8_t * entry = recrypt_sys + 0x44;
	for (int i = 0; i < entries_count; ++i) {
		uint8_t tmp[32] = { 0 };
		std::memcpy(tmp, entry, 32);
		struct AES_ctx ctx;
		AES_init_ctx_iv(&ctx, recrypt_list_key, (uint8_t *)recrypt_list_iv);
		AES_CBC_decrypt_buffer(&ctx, tmp, 32);

		std::stringstream ss;
		for (int g = 0; g < 4; ++g) {
			ss << std::setw(2) << std::setfill('0') << std::hex << (int)tmp[g];
		}
		std::cout << "Entry #" << i+1 << ": " << ss.str() << ", Query: " << content_id << std::endl;

		if (std::memcmp(tmp, cid, 4) == 0) {
			std::cout << "Entry found!" << std::endl;
			uint8_t * ptr = &tmp[4];
			std::memcpy(reckey, ptr, 16);
			entry_not_found = false;
			std::cout << "Key read." << std::endl;
			break;
		}
		else {
			entry += 0x20;
		}
	}
	delete[] recrypt_sys;
	if (entry_not_found) {
		search_error(content_id, rsys_file_name);
	}

	std::cout << "Recrypt key for " << content_id << ": ";
	for (int r = 0; r < 16; ++r) {
		std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)reckey[r];
	}
	std::cout << std::endl;

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, reckey, content_iv);
	if (mode == "decrypt") {
		std::cout << "Decrypting..." << std::endl;
		AES_CBC_decrypt_buffer(&ctx, rec, rec_size);
	}
	else if (mode == "encrypt") {
		std::cout << "Encrypting..." << std::endl;
		AES_CBC_encrypt_buffer(&ctx, rec, rec_size);
	}
	else {
		argument_error();
	}
	std::cout << "Writing output..." << std::endl;
	write_file("output.bin", rec, rec_size);
	std::cout << "Complete!" << std::endl;
	delete[] rec;
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
	for (char & s : cid_str) {
		s = tolower(s);
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
	for (char & s : content_id) {
		s = tolower(s);
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

void parse_args(struct rec_args & a, char * argv[], int argc) {
	a.mode = argv[1];
	bool rc = false;
	bool v2 = false;
	bool iv = false;
	bool rs = false;
	bool ci = false;
	for (int i = 0; i < argc - 1; ++i) {
		std::string arg = argv[i];
		if (arg == "-rec") {
			a.rc_fn = argv[i + 1];
			rc = true;
		}
		else if (arg == "-v2") {
			a.v2_fn = argv[i + 1];
			v2 = true;
		}
		else if (arg == "-iv" || arg == "-fiv") {
			a.iv_par = argv[i];
			a.iv_in = argv[i + 1];
			iv = true;
		}
		else if (arg == "-rsys") {
			a.rs_fn = argv[i + 1];
			rs = true;
		}
		else if (arg == "-cid") {
			a.cid = argv[i + 1];
			ci = true;
		}
	}
	if (!(rc && v2 && iv && rs && ci)) argument_error();
}

void parse_args(struct crypt_args & a, char * argv[], int argc) {
	a.mode = argv[1];
	bool in = false;
	bool key = false;
	bool iv = false;
	for (int i = 0; i < argc - 1; ++i) {
		std::string arg = argv[i];
		if (arg == "-app" || arg == "-tk") {
			a.in_fn = argv[i + 1];
			in = true;
		}
		else if (arg == "-key" || arg == "-fkey") {
			a.key_par = argv[i];
			a.key_in = argv[i + 1];
			key = true;
		}
		else if (arg == "-iv" || arg == "-fiv") {
			a.iv_par = argv[i];
			a.iv_in = argv[i + 1];
			iv = true;
		}
	}
	if (!(in && key && iv)) argument_error();
}

void parse_args(struct extract_args & a, char * argv[], int argc) {
	bool in = false;
	bool ci = false;
	bool ticket = false;
	for (int i = 0; i < argc - 1; ++i) {
		std::string arg = argv[i];
		if (arg == "-cmd" || arg == "-ticket") {
			a.in_fn = argv[i + 1];
			in = true;
			if (arg == "-ticket") ticket = true;
		}
		else if (arg == "-cid") {
			a.cid = argv[i + 1];
			ci = true;
		}
	}
	if (!in || (ticket && !ci)) {
		std::cerr << "Ticket extract requested, but no content ID was provided." << std::endl << std::endl;
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

void search_error(std::string query, std::string search_file_name) {
	std::cerr << "ERROR: Entry for " + query + " not found in " << search_file_name << std::endl;
	std::exit(EXIT_FAILURE);
}

void display_help() {
	std::cout << "Please use the usage manual for now..." << std::endl;
}
