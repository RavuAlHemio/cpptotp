/**
 * @file sha1.cpp
 *
 * @brief Implementation of the SHA-1 hash.
 *
 * @copyright The contents of this file have been placed into the public domain;
 * see the file COPYING for more details.
 */

#include "bytes.h"

#include <iostream>

#include <cassert>

namespace CppTotp
{

static inline uint32_t lrot32(uint32_t num, uint8_t rotcount)
{
	return (num << rotcount) | (num >> (32 - rotcount));
}

Bytes::ByteString sha1(const Bytes::ByteString & msg)
{
	const size_t size_bytes = msg.size();
	const uint64_t size_bits = size_bytes * 8;
	Bytes::ByteString bstr = msg;
	Bytes::ByteStringDestructor asplode(&bstr);

	// the size of msg in bits is always even. adding the '1' bit will make
	// it odd and therefore incongruent to 448 modulo 512, so we can get
	// away with tacking on 0x80 and then the 0x00s.
	bstr.push_back(0x80);
	while (bstr.size() % (512/8) != (448/8))
	{
		bstr.push_back(0x00);
	}

	// append the size in bits (uint64be)
	bstr.append(Bytes::u64beToByteString(size_bits));

	assert(bstr.size() % (512/8) == 0);

	// initialize the hash counters
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	// for each 64-byte chunk
	for (size_t i = 0; i < bstr.size()/64; ++i)
	{
		Bytes::ByteString chunk(bstr.begin() + i*64, bstr.begin() + (i+1)*64);
		Bytes::ByteStringDestructor xplode(&chunk);

		uint32_t words[80];
		size_t j;

		// 0-15: the chunk as a sequence of 32-bit big-endian integers
		for (j = 0; j < 16; ++j)
		{
			words[j] =
				(chunk[4*j + 0] << 24) |
				(chunk[4*j + 1] << 16) |
				(chunk[4*j + 2] <<  8) |
				(chunk[4*j + 3] <<  0)
			;
		}

		// 16-79: derivatives of 0-15
		for (j = 16; j < 32; ++j)
		{
			// unoptimized
			words[j] = lrot32(words[j-3] ^ words[j-8] ^ words[j-14] ^ words[j-16], 1);
		}
		for (j = 32; j < 80; ++j)
		{
			// Max Locktyuchin's optimization (SIMD)
			words[j] = lrot32(words[j-6] ^ words[j-16] ^ words[j-28] ^ words[j-32], 2);
		}

		// initialize hash values for the round
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;

		// the loop
		for (j = 0; j < 80; ++j)
		{
			uint32_t f = 0, k = 0;

			if (j < 20)
			{
				f = (b & c) | ((~ b) & d);
				k = 0x5A827999;
			}
			else if (j < 40)
			{
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			}
			else if (j < 60)
			{
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			}
			else if (j < 80)
			{
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}
			else
			{
				assert(0 && "how did I get here?");
			}

			uint32_t tmp = lrot32(a, 5) + f + e + k + words[j];
			e = d;
			d = c;
			c = lrot32(b, 30);
			b = a;
			a = tmp;
		}

		// add that to the result so far
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
	}

	// assemble the digest
	Bytes::ByteString first  = Bytes::u32beToByteString(h0);
	Bytes::ByteStringDestructor x1(&first);
	Bytes::ByteString second = Bytes::u32beToByteString(h1);
	Bytes::ByteStringDestructor x2(&second);
	Bytes::ByteString third  = Bytes::u32beToByteString(h2);
	Bytes::ByteStringDestructor x3(&third);
	Bytes::ByteString fourth = Bytes::u32beToByteString(h3);
	Bytes::ByteStringDestructor x4(&fourth);
	Bytes::ByteString fifth  = Bytes::u32beToByteString(h4);
	Bytes::ByteStringDestructor x5(&fifth);

	return first + second + third + fourth + fifth;
}

Bytes::ByteString hmacSha1(const Bytes::ByteString & key, const Bytes::ByteString & msg, size_t blockSize = 64);

Bytes::ByteString hmacSha1(const Bytes::ByteString & key, const Bytes::ByteString & msg, size_t blockSize)
{
	Bytes::ByteString realKey = key;
	Bytes::ByteStringDestructor asplode(&realKey);

	if (realKey.size() > blockSize)
	{
		// resize by calculating hash
		Bytes::ByteString newRealKey = sha1(realKey);
		Bytes::swizzleByteStrings(&realKey, &newRealKey);
	}
	if (realKey.size() < blockSize)
	{
		// pad with zeroes
		realKey.resize(blockSize, 0x00);
	}

	// prepare the pad keys
	Bytes::ByteString innerPadKey = realKey;
	Bytes::ByteStringDestructor xplodeI(&innerPadKey);
	Bytes::ByteString outerPadKey = realKey;
	Bytes::ByteStringDestructor xplodeO(&outerPadKey);

	// transform the pad keys
	for (size_t i = 0; i < realKey.size(); ++i)
	{
		innerPadKey[i] = innerPadKey[i] ^ 0x36;
		outerPadKey[i] = outerPadKey[i] ^ 0x5c;
	}

	// sha1(outerPadKey + sha1(innerPadKey + msg))
	Bytes::ByteString innerMsg  = innerPadKey + msg;
	Bytes::ByteStringDestructor xplodeIM(&innerMsg);
	Bytes::ByteString innerHash = sha1(innerMsg);
	Bytes::ByteStringDestructor xplodeIH(&innerHash);
	Bytes::ByteString outerMsg  = outerPadKey + innerHash;
	Bytes::ByteStringDestructor xplodeOM(&outerMsg);

	return sha1(outerMsg);
}

}

#if TEST_SHA1
int main(void)
{
	using namespace CppTotp;
	const uint8_t * strEmpty = reinterpret_cast<const uint8_t *>("");
	const uint8_t * strDog   = reinterpret_cast<const uint8_t *>("The quick brown fox jumps over the lazy dog");
	const uint8_t * strCog   = reinterpret_cast<const uint8_t *>("The quick brown fox jumps over the lazy cog");
	const uint8_t * strKey   = reinterpret_cast<const uint8_t *>("key");

	Bytes::ByteString shaEmpty = sha1(Bytes::ByteString(strEmpty));
	Bytes::ByteString shaDog   = sha1(Bytes::ByteString(strDog));
	Bytes::ByteString shaCog   = sha1(Bytes::ByteString(strCog));

	Bytes::ByteString hmacShaEmpty  = hmacSha1(Bytes::ByteString(), Bytes::ByteString());
	Bytes::ByteString hmacShaKeyDog = hmacSha1(strKey, strDog);

	std::cout
		<< (Bytes::toHexString(shaEmpty) == "da39a3ee5e6b4b0d3255bfef95601890afd80709") << std::endl
		<< (Bytes::toHexString(shaDog)   == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") << std::endl
		<< (Bytes::toHexString(shaCog)   == "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3") << std::endl
		<< std::endl
		<< (Bytes::toHexString(hmacShaEmpty)  == "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d") << std::endl
		<< (Bytes::toHexString(hmacShaKeyDog) == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9") << std::endl
	<< std::endl;

	return 0;
}
#endif
