/*
	ecc.cpp - inplementations of ECC operations using keys
			  defined with sect233r1 / NIST B-233
	This is NOT intended to be used in an actual cryptographic
	scheme; as written, it is vulnerable to several attacks.
	This might or might not change in the future. It is intended
	to be used for doing operations on keys which are already known.

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
#include <iomanip>
#include "ecc.hpp"

/*
	Printing
*/
void print_element(const element a) {
	for (int i = 0; i < 8; ++i) {
		std::cout << std::setw(8) << std::setfill('0') << std::hex << a[i] << " ";
	}
	std::cout << std::endl;
}

void print_point(const ec_point & a) {
	std::cout << "x: ";
	print_element(a.x);
	std::cout << "y: ";
	print_element(a.y);
	std::cout << std::endl;
}

/*
	Helper functions for working with elements in GF(2^m)
*/
bool gf2m_is_equal(const element a, const element b) {
	for (int i = 0; i < 7; ++i) {
		if (a[i] != b[i]) return false;
	}
	return true;
}

void gf2m_set_zero(element a) {
	for (int i = 0; i < 8; ++i) {
		a[i] = 0;
	}
}

void gf2m_copy(const element src, element dst) {
	std::memcpy(dst, src, 32);
}

int gf2m_get_bit(const element a, int index) {
	int w_index = ((index / 32) - 7) * -1;
	int shift = index - (32 * (7 - w_index));
	return (a[w_index] >> shift) & 1;
}

void gf2m_left_shift(element a, int shift) {
	if (!shift) {
		a[0] &= 0x1FF;
		return;
	}
	for (int i = 0; i < 7; ++i) {
		a[i] <<= 1;
		if (a[i + 1] >= 0x80000000) a[i] |= 1;
	}
	a[7] <<= 1;
	gf2m_left_shift(a, shift - 1);
}

bool gf2m_is_one(const element a) {
	if (a[7] != 1) return false;
	else {
		for (int i = 0; i < 7; ++i) {
			if (a[i] != 0) return false;
		}
	}
	return true;
}

int gf2m_degree(const element a) {
	int degree = 0;
	int i = 0;
	while (a[i] == 0) {
		i++;
	}
	degree = (7 - i) * 32;
	uint32_t temp = a[i];
	while (temp != 0) {
		temp >>= 1;
		degree += 1;
	}
	return degree - 1;
}

void gf2m_swap(element a, element b) {
	element temp;
	gf2m_copy(a, temp);
	gf2m_copy(b, a);
	gf2m_copy(temp, b);
}

/*
	Arithmetic operations on elements in GF(2^m)
*/
void gf2m_add(const element a, const element b, element c) {
	for (int i = 0; i < 8; ++i) {
		c[i] = a[i] ^ b[i];
	}
}

void gf2m_inv(const element a, element c) {
	element u, v, g_1, g_2, temp;
	gf2m_copy(a, u);
	gf2m_copy(poly_f, v);
	gf2m_set_zero(g_1);
	g_1[7] |= 1;
	gf2m_set_zero(g_2);
	int j = gf2m_degree(u) - 233;
	while (!gf2m_is_one(u)) {
		if (j < 0) {
			gf2m_swap(u, v);
			gf2m_swap(g_1, g_2);
			j = -j;
		}
		gf2m_copy(v, temp);
		gf2m_left_shift(temp, j);
		gf2m_add(u, temp, u);
		gf2m_copy(g_2, temp);
		gf2m_left_shift(temp, j);
		gf2m_add(g_1, temp, g_1);

		u[0] &= 0x1FF;
		g_1[0] &= 0x1FF;

		j = gf2m_degree(u) - gf2m_degree(v);
	}
	gf2m_copy(g_1, c);
}

// basic implementation
void gf2m_mul(const element a, const element b, element c) {
	element t1, t2, t3;
	gf2m_copy(a, t1);
	gf2m_copy(b, t2);
	gf2m_set_zero(t3);
	for (int i = 0; i < 233; ++i) {
		if (gf2m_get_bit(t2, i)) {
			gf2m_add(t3, t1, t3);
		}
		int carry = gf2m_get_bit(t1, 232);
		gf2m_left_shift(t1, 1);
		if (carry == 1) {
			gf2m_add(poly_r, t1, t1);
		}
	}
	gf2m_copy(t3, c);
}

void gf2m_div(const element a, const element b, element c) {
	element temp;
	gf2m_inv(b, temp);
	gf2m_mul(a, temp, c);
}
// void gf2m_reduce(element c)
// void gf2m_square(const element a, element c)

/*
	Arithmetic operations on points on the elliptic curve
	y^2 + xy = x^3 + ax^2 + b over GF(2^m)
*/
void ec_point_copy(const ec_point & src, ec_point & dst) {
	gf2m_copy(src.x, dst.x);
	gf2m_copy(src.y, dst.y);
}
	
bool ec_point_is_equal(const ec_point & a, const ec_point & c) {
	return gf2m_is_equal(a.x, c.x) && gf2m_is_equal(a.y, c.y);
}

void ec_point_neg(const ec_point & a, ec_point & c) {
	element temp;
	gf2m_copy(a.x, c.x);
	gf2m_add(a.x, a.y, temp);
	gf2m_copy(temp, c.y);
}

void ec_point_double(const ec_point & a, ec_point & c) {
	ec_point temp;
	ec_point zero;
	gf2m_set_zero(zero.x);
	gf2m_set_zero(zero.y);

	ec_point_neg(a, temp);
	if (ec_point_is_equal(a, temp) || ec_point_is_equal(a, zero)) {
		ec_point_copy(zero, c);
		return;
	}

	element lambda, x, y, t, t2;
	// Compute lambda (a.x + (a.y / a.x))
	gf2m_div(a.y, a.x, t);
	gf2m_add(a.x, t, lambda);
	// Compute X (lambda^2 + lambda + a_coeff)
	gf2m_mul(lambda, lambda, t);
	gf2m_add(t, lambda, t);
	gf2m_add(t, a_coeff, x);
	// Compute Y (a.x^2 + (lambda * X) + X)
	gf2m_mul(a.x, a.x, t);
	gf2m_mul(lambda, x, t2);
	gf2m_add(t, t2, t);
	gf2m_add(t, x, y);
	// Copy X,Y to output point c
	gf2m_copy(x, c.x);
	gf2m_copy(y, c.y);
}

void ec_point_add(const ec_point & a, const ec_point & b, ec_point & c) {
	if (!ec_point_is_equal(a, b)) {
		ec_point temp;
		ec_point zero;
		gf2m_set_zero(zero.x);
		gf2m_set_zero(zero.y);
		ec_point_neg(b, temp);
		if (ec_point_is_equal(a, temp)) {
			ec_point_copy(zero, c);
			return;
		}
		else if (ec_point_is_equal(a, zero)) {
			ec_point_copy(b, c);
			return;
		}
		else if (ec_point_is_equal(b, zero)) {
			ec_point_copy(a, c);
			return;
		}
		else {
			element lambda, x, y, t, t2;
			// Compute lambda ((b.y + a.y) / (b.x + a.x))
			gf2m_add(b.y, a.y, t);
			gf2m_add(b.x, a.x, t2);
			gf2m_div(t, t2, lambda);
			// Compute X (lambda^2 + lambda + a.x + b.x + a_coeff)
			gf2m_mul(lambda, lambda, t);
			gf2m_add(t, lambda, t2);
			gf2m_add(t2, a.x, t);
			gf2m_add(t, b.x, t2);
			gf2m_add(t2, a_coeff, x);
			// Compute Y ((lambda * (a.x + X)) + X + a.y)
			gf2m_add(a.x, x, t);
			gf2m_mul(lambda, t, t2);
			gf2m_add(t2, x, t);
			gf2m_add(t, a.y, y);
			// Copy X,Y to output point c
			gf2m_copy(x, c.x);
			gf2m_copy(y, c.y);
			return;
		}
	}
	else {
		ec_point_double(a, c);
	}
}

void ec_point_mul(const element a, const ec_point & b, ec_point & c) {
	element k;
	ec_point P;
	ec_point Q;

	gf2m_copy(a, k);
	ec_point_copy(b, P);
	gf2m_set_zero(Q.x);
	gf2m_set_zero(Q.y);
	for (int i = 0; i < 233; ++i) {
		if (gf2m_get_bit(k, i)) {
			ec_point_add(Q, P, Q);
		}
		ec_point_double(P, P);
	}
	ec_point_copy(Q, c);
}

/*
	I/O Helpers
		Private keys are expected to be 32 bytes; Public keys
		are expected to be 64 bytes and in uncompressed form.
		
		Wii keys will need to be padded - two 0 bytes at the
		start of the private key, and two 0 bytes before each
		coordinate in the public key.
*/
void parse_private(const uint8_t * privkey_os, element scalar_k) {
	int j = 0;
	for (int i = 0; i < 8; ++i) {
		uint32_t temp = 0;
		temp |= (privkey_os[j] << 24);
		temp |= (privkey_os[j + 1] << 16);
		temp |= (privkey_os[j + 2] << 8);
		temp |= privkey_os[j + 3];
		scalar_k[i] = temp;
		j += 4;
	}
}

void parse_public(const uint8_t * pubkey_os, ec_point & point_P) {
	int j = 0;
	int i = 0;
	for (i = 0; i < 8; ++i) {
		uint32_t temp = 0;
		temp |= (pubkey_os[j] << 24);
		temp |= (pubkey_os[j + 1] << 16);
		temp |= (pubkey_os[j + 2] << 8);
		temp |= pubkey_os[j + 3];
		point_P.x[i] = temp;
		j += 4;
	}
	for (i = 0; i < 8; ++i) {
		uint32_t temp = 0;
		temp |= (pubkey_os[j] << 24);
		temp |= (pubkey_os[j + 1] << 16);
		temp |= (pubkey_os[j + 2] << 8);
		temp |= pubkey_os[j + 3];
		point_P.y[i] = temp;
		j += 4;
	}
}

// Copies 16 bytes of the x-coordinate of Q, starting at
// offset 4, to output, to be used as an AES key.
void create_output(const ec_point & point_Q, uint8_t * output) {
	int j = 0;
	for (int i = 1; i < 5; ++i) {
		output[j] = ((point_Q.x[i] & 0xFF000000) >> 24);
		output[j + 1] = ((point_Q.x[i] & 0x00FF0000) >> 16);
		output[j + 2] = ((point_Q.x[i] & 0x0000FF00) >> 8);
		output[j + 3] = point_Q.x[i] & 0x000000FF;
		j += 4;
	}
}

/*
	ECC algorithm(s)
*/
void ecdh(const uint8_t * private_key, const uint8_t * public_key, uint8_t * output) {
	element private_copy;
	ec_point public_copy;
	ec_point shared_secret;
	
	parse_private(private_key, private_copy);
	parse_public(public_key, public_copy);
	
	ec_point_mul(private_copy, public_copy, shared_secret);
	
	create_output(shared_secret, output);
}
