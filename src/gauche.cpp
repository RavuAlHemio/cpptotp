/**
 * @file gauche.cpp
 *
 * @brief Sample TOTP application.
 *
 * @copyright The contents of this file have been placed into the public domain;
 * see the file COPYING for more details.
 */

#include "libcppotp/bytes.h"
#include "libcppotp/otp.h"

#include <iostream>

#include <cctype>
#include <cstdio>
#include <unistd.h>

using namespace CppTotp;

int main(void)
{
	// read the key
	std::string key;
	std::getline(std::cin, key);

	// right-trim
	while (isspace(key[key.length()-1]))
	{
		key.pop_back();
	}

	if (key.length() % 8 != 0)
	{
		fprintf(stderr, "key length (%zu) must be divisible by 8\n", key.length());
		return 1;
	}

	Bytes::ByteString qui = Bytes::fromBase32(key);

	while (1)
	{
		uint32_t p = totp(qui, time(NULL), 0, 30, 6);
		printf("%06u (%2us remain)\r", p, 30 - (time(NULL) % 30));
		fflush(stdout);
		sleep(1);
	}

	return 0;
}
