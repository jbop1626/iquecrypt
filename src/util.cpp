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
#include <string>
#include <cstdint>
#include <cstdlib>
#include "util.hpp"

/*
	I/O utilities
*/
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

/*
	Error messages
*/
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
	std::cout << "Decrypt:" << std::endl;
	std::cout << "1. decrypt -app [app file] -(f)key [title key] -(f)iv [content iv]" << std::endl;
	std::cout << "2. decrypt -tk [encrypted title key] -(f)key [common key] -(f)iv [title key iv]" << std::endl;
	std::cout << "3. decrypt -rec [rec file] -v2 [virage2 dump] -(f)iv [content iv] -rsys [recrypt.sys] -cid [content ID]" << std::endl << std::endl;
	std::cout << "Encrypt:" << std::endl;
	std::cout << "1. encrypt -app [app file] -(f)key [title key] -(f)iv [content iv]" << std::endl;
	std::cout << "2. encrypt -tk [plaintext title key] -(f)key [common key] -(f)iv [title key iv]" << std::endl;
	std::cout << "3. encrypt -rec [app file] -v2 [virage2 dump] -(f)iv [content iv] -rsys [recrypt.sys] -cid [content ID]" << std::endl << std::endl;
	std::cout << "Extract:" << std::endl;
	std::cout << "1. extract -cmd [cmd file]" << std::endl;
	std::cout << "2. extract -ticket [ticket file] -cid [content ID]" << std::endl;
	std::cout << "3. extract -v2 [virage2 dump] (-all)" << std::endl << std::endl;
	std::cout << "ECDH:" << std::endl;
	std::cout << "1. ecdh -pvt [ECC priv key file] -pub [ECC pub key file]" << std::endl << std::endl;
}
