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
#ifndef IQUE_CRYPT_ARGS
#define IQUE_CRYPT_ARGS

#include <string>

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
	int type;
	std::string mode;
	std::string in_fn;
	std::string key_par;
	std::string key_in;
	std::string iv_par;
	std::string iv_in;
};

struct extract_args {
	int type;
	bool all;
	std::string in_fn;
	std::string cid;
};

struct ecdh_args {
	std::string pvt;
	std::string pub;
};

void parse_args(rec_args & a, char * argv[], int argc);
void parse_args(crypt_args & a, char * argv[], int argc);
void parse_args(extract_args & a, char * argv[], int argc);
void parse_args(ecdh_args & a, char * argv[], int argc);

#endif
