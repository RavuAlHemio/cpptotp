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

#include <termios.h>

using namespace CppTotp;

static int pwfromtty(std::string * inHere, const std::string & prompt = "Password: ", FILE * source = stdin)
{
	// read a password from a TTY

	struct termios oldtios, newtios;
	int ret;

	// turn echoing off if possible
	if (tcgetattr(fileno(source), &oldtios) != 0)
	{
		fputs("Cannot read terminal attributes.\n", stderr);
		return 1;
	}

	newtios = oldtios;
	newtios.c_lflag &= ~ECHO;

	if (tcsetattr(fileno(source), TCSAFLUSH, &newtios) != 0)
	{
		fputs("Cannot set terminal attributes.\n", stderr);
		return 2;
	}

	// output prompt
	fputs(prompt.c_str(), stderr);
	fflush(stderr);

	for (;;)
	{
		ret = fgetc(source);

		if (ret == EOF)
		{
			break;
		}
		else if (ret == '\n' || ret == '\r')
		{
			inHere->push_back('\n');
			break;
		}
		else
		{
			inHere->push_back(ret);
		}
	}

	// reset previous terminal properties
	if (tcsetattr(fileno(source), TCSAFLUSH, &oldtios) != 0)
	{
		fputs("Cannot reset terminal attributes.\n", stderr);
		return 3;
	}

	fputc('\n', stderr);

	return 0;
}

int main(void)
{
	// read the key
	std::string key;

	if (isatty(fileno(stdin)))
	{
		pwfromtty(&key, "Key: ", stdin);
	}
	else
	{
		// the fast path
		std::getline(std::cin, key);
	}

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
