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
#include <string>
#include "args.hpp"
#include "util.hpp"

void parse_args(rec_args & a, char * argv[], int argc) {
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

void parse_args(crypt_args & a, char * argv[], int argc) {
	a.type = -1;
	a.mode = argv[1];
	bool in = false;
	bool key = false;
	bool iv = false;
	for (int i = 0; i < argc - 1; ++i) {
		std::string arg = argv[i];
		if (arg == "-app" || arg == "-tk") {
			a.in_fn = argv[i + 1];
			in = true;
			if (arg == "-app") a.type = 0;
			if (arg == "-tk") a.type = 1;
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

void parse_args(extract_args & a, char * argv[], int argc) {
	a.type = -1;
	a.all = false;
	bool in = false;
	bool ci = false;
	bool ticket = false;
	bool v2 = false;
	for (int i = 0; i < argc; ++i) {
		std::string arg = argv[i];
		if ((arg == "-cmd" || arg == "-ticket" || arg == "-v2") && i < argc - 1) {
			a.in_fn = argv[i + 1];
			in = true;
			if (arg == "-cmd") a.type = 0;
			if (arg == "-ticket") {
				a.type = 1;
				ticket = true;
			}
			if (arg == "-v2") {
				a.type = 2;
				v2 = true;
			}
		}
		if (arg == "-cid") {
			a.cid = argv[i + 1];
			ci = true;
		}
		if (arg == "-all") {
			a.all = true;
		}
	}
	if (!in || (ticket && !ci)) {
		if (ticket && !ci) {
			std::cerr << "Ticket extract requested, but no content ID was provided." << std::endl << std::endl;
		}
		argument_error();
	}
}

void parse_args(ecdh_args & a, char * argv[], int argc) {
	bool pvt = false;
	bool pub = false;
	for (int i = 0; i < argc - 1; ++i) {
		std::string arg = argv[i];
		if (arg == "-pvt") {
			a.pvt = argv[i + 1];
			pvt = true;
		}
		if (arg == "-pub") {
			a.pub = argv[i + 1];
			pub = true;
		}
	}
	if (!(pvt && pub)) argument_error();
}