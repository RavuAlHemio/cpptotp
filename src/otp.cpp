/**
 * @file otp.cpp
 *
 * @brief Implementations of one-time-password-related functions.
 *
 * @copyright The contents of this file have been placed into the public domain;
 * see the file COPYING for more details.
 */

#include "otp.h"

#include <iostream>

#include <cassert>
#include <cinttypes>
#include <cstring>

namespace CppTotp
{

Bytes::ByteString hmacSha1_64(const Bytes::ByteString & key, const Bytes::ByteString & msg)
{
	return hmacSha1(key, msg, 64);
}

//uint32_t hotp(const Bytes::ByteString & key, const Bytes::ByteString & msg, size_t digitCount, HmacFunc hmacf)
uint32_t hotp(const Bytes::ByteString & key, uint64_t counter, size_t digitCount, HmacFunc hmacf)
{
	Bytes::ByteString msg = Bytes::u64beToByteString(counter);
	Bytes::ByteStringDestructor dmsg(&msg);

	Bytes::ByteString hmac = hmacf(key, msg);
	Bytes::ByteStringDestructor dhmac(&hmac);

	uint32_t digits10 = 1;
	for (size_t i = 0; i < digitCount; ++i)
	{
		digits10 *= 10;
	}

	// fetch the offset (from the last nibble)
	uint8_t offset = hmac[hmac.size()-1] & 0x0F;

	// fetch the four bytes from the offset
	Bytes::ByteString fourWord = hmac.substr(offset, 4);
	Bytes::ByteStringDestructor dfourWord(&fourWord);

	// turn them into a 32-bit integer
	uint32_t ret =
		(fourWord[0] << 24) |
		(fourWord[1] << 16) |
		(fourWord[2] <<  8) |
		(fourWord[3] <<  0)
	;

	// snip off the MSB (to alleviate signed/unsigned troubles)
	// and calculate modulo digit count
	return (ret & 0x7fffffff) % digits10;
}

uint32_t totp(const Bytes::ByteString & key, uint64_t timeNow, uint64_t timeStart, uint64_t timeStep, size_t digitCount, HmacFunc hmacf)
{
	uint64_t timeValue = (timeNow - timeStart) / timeStep;
	return hotp(key, timeValue, digitCount, hmacf);
}

}

#if TEST_OTP
int main(void)
{
	using namespace CppTotp;

	uint64_t start  =  0;
	uint64_t step   = 30;
	uint8_t digitsH =  6;
	uint8_t digitsT =  8;
	const Bytes::ByteString key = reinterpret_cast<const uint8_t *>("12345678901234567890");

	std::cout
		<< (hotp(key, 0, digitsH) == 755224)
		<< (hotp(key, 1, digitsH) == 287082)
		<< (hotp(key, 2, digitsH) == 359152)
		<< (hotp(key, 3, digitsH) == 969429)
		<< (hotp(key, 4, digitsH) == 338314)
		<< (hotp(key, 5, digitsH) == 254676)
		<< (hotp(key, 6, digitsH) == 287922)
		<< (hotp(key, 7, digitsH) == 162583)
		<< (hotp(key, 8, digitsH) == 399871)
		<< (hotp(key, 9, digitsH) == 520489)
		<< (totp(key, 59, start, step, digitsT) == 94287082)
		<< (totp(key, 1111111109, start, step, digitsT) == 7081804)
		<< (totp(key, 1111111111, start, step, digitsT) == 14050471)
		<< (totp(key, 1234567890, start, step, digitsT) == 89005924)
		<< (totp(key, 2000000000, start, step, digitsT) == 69279037)
		<< (totp(key, 20000000000, start, step, digitsT) == 65353130)
	<< std::endl;

	const Bytes::ByteString tutestkey = reinterpret_cast<const uint8_t *>("HelloWorld");
	std::cout << totp(tutestkey, time(NULL), 0, 30, 6) << std::endl;

	return 0;
}
#endif
