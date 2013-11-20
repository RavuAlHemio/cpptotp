/**
 * @file bytes.cpp
 *
 * @brief Byte-related operations.
 *
 * @copyright The contents of this file have been placed into the public domain;
 * see the file COPYING for more details.
 */

#include "bytes.h"

#include <iostream>
#include <stdexcept>

#include <cassert>
#include <cstdlib>

namespace CppTotp
{
namespace Bytes
{

void clearByteString(ByteString * bstr)
{
	volatile Byte * bs = const_cast<volatile Byte *>(bstr->data());

	for (size_t i = 0; i < bstr->size(); ++i)
	{
		bs[i] = Byte(0);
	}
}

void swizzleByteStrings(ByteString * target, ByteString * source)
{
	clearByteString(target);
	target->assign(*source);
	clearByteString(source);
}

static char nibbleToLCHex(uint8_t nib)
{
	if (nib < 0xa)
	{
		return static_cast<char>(nib + '0');
	}
	else if (nib < 0x10)
	{
		return static_cast<char>((nib - 10) + 'a');
	}
	else
	{
		assert(0 && "not actually a nibble");
		return '\0';
	}
}

static uint8_t hexToNibble(char c)
{
	if (c >= '0' && c <= '9')
	{
		return static_cast<uint8_t>(c - '0');
	}
	else if (c >= 'A' && c <= 'F')
	{
		return static_cast<uint8_t>(c - 'A' + 10);
	}
	else if (c >= 'a' && c <= 'f')
	{
		return static_cast<uint8_t>(c - 'a' + 10);
	}
	else
	{
		assert(0 && "not actually a hex digit");
		return 0xff;
	}
}

std::string toHexString(const ByteString & bstr)
{
	std::string ret;

	for (Byte b : bstr)
	{
		ret.push_back(nibbleToLCHex((b >> 4) & 0x0F));
		ret.push_back(nibbleToLCHex((b >> 0) & 0x0F));
	}

	return ret;
}

ByteString fromHexStringSkipUnknown(const std::string & str)
{
	std::string hstr;
	for (char c : str)
	{
		if (
			(c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'F') ||
			(c >= 'a' && c <= 'f')
		)
		{
			hstr.push_back(c);
		}
		// ignore otherwise
	}

	if (hstr.size() % 2 != 0)
	{
		throw std::invalid_argument("hex string (unknown characters ignored) length not divisible by 2");
	}

	ByteString ret;
	for (size_t i = 0; i < hstr.size(); i += 2)
	{
		uint8_t top = hexToNibble(hstr[i+0]);
		uint8_t btm = hexToNibble(hstr[i+1]);

		ret.push_back((top << 4) | btm);
	}
	return ret;
}

Bytes::ByteString u32beToByteString(uint32_t num)
{
	Bytes::ByteString ret;
	ret.push_back((num >> 24) & 0xFF);
	ret.push_back((num >> 16) & 0xFF);
	ret.push_back((num >>  8) & 0xFF);
	ret.push_back((num >>  0) & 0xFF);
	return ret;
}

Bytes::ByteString u64beToByteString(uint64_t num)
{
	Bytes::ByteString left  = u32beToByteString((num >> 32) & 0xFFFFFFFF);
	Bytes::ByteString right = u32beToByteString((num >>  0) & 0xFFFFFFFF);
	return left + right;
}

static ByteString b32ChunkToBytes(const std::string & str)
{
	ByteString ret;
	uint64_t whole = 0x00;
	size_t padcount = 0;
	size_t finalcount;

	if (str.length() != 8)
	{
		throw std::invalid_argument("incorrect length of base32 chunk");
	}

	size_t i;

	for (i = 0; i < 8; ++i)
	{
		char c = str[i];
		uint64_t bits;

		if (c == '=')
		{
			bits = 0;
			++padcount;
		}
		else if (padcount > 0)
		{
			throw std::invalid_argument("padding character followed by non-padding character");
		}
		else if (c >= 'A' && c <= 'Z')
		{
			bits = static_cast<Byte>(c - 'A');
		}
		else if (c >= '2' && c <= '7')
		{
			bits = static_cast<Byte>(c - '2' + 26);
		}
		else
		{
			throw std::invalid_argument("not a base32 character: " + std::string(1, c));
		}

		// shift into the chunk
		whole |= (bits << ((7-i)*5));
	}

	switch (padcount)
	{
	case 0:
		finalcount = 5;
		break;
	case 1:
		finalcount = 4;
		break;
	case 3:
		finalcount = 3;
		break;
	case 4:
		finalcount = 2;
		break;
	case 6:
		finalcount = 1;
		break;
	default:
		throw std::invalid_argument("invalid number of padding characters");
	}

	for (i = 0; i < finalcount; ++i)
	{
		// shift out of the chunk
		ret.push_back(static_cast<Byte>((whole >> ((4-i)*8)) & 0xFF));
	}

	return ret;
}

static inline uint64_t u64(uint8_t n)
{
	return static_cast<uint64_t>(n);
}

static std::string bytesToB32Chunk(const ByteString & bs)
{
	if (bs.size() < 1 || bs.size() > 5)
	{
		throw std::invalid_argument("need a chunk of at least 1 and at most 5 bytes");
	}

	uint64_t whole = 0x00;
	size_t putchars = 2;
	std::string ret;

	// shift into the chunk
	whole |= (u64(bs[0]) << 32);
	if (bs.size() > 1)
	{
		whole |= (u64(bs[1]) << 24);
		putchars += 2;  // at least 4
	}
	if (bs.size() > 2)
	{
		whole |= (u64(bs[2]) << 16);
		++putchars;  // at least 5
	}
	if (bs.size() > 3)
	{
		whole |= (u64(bs[3]) <<  8);
		putchars += 2;  // at least 7
	}
	if (bs.size() > 4)
	{
		whole |= u64(bs[4]);
		++putchars;  // at least 8
	}

	size_t i;
	for (i = 0; i < putchars; ++i)
	{
		// shift out of the chunk

		Byte val = (whole >> ((7-i)*5)) & 0x1F;

		// map bits to base32

		if (val < 26)
		{
			ret.push_back(static_cast<char>(val + 'A'));
		}
		else
		{
			ret.push_back(static_cast<char>(val - 26 + '2'));
		}
	}

	// pad

	for (i = putchars; i < 8; ++i)
	{
		ret.push_back('=');
	}

	return ret;
}

ByteString fromBase32(const std::string & b32str)
{
	if (b32str.size() % 8 != 0)
	{
		throw std::invalid_argument("base32 string length not divisible by 8");
	}

	ByteString ret;

	for (size_t i = 0; i < b32str.size(); i += 8)
	{
		std::string sub(b32str, i, 8);
		ByteString chk = b32ChunkToBytes(sub);
		ret.append(chk);
	}

	return ret;
}

ByteString fromUnpaddedBase32(const std::string & b32str)
{
	std::string newstr = b32str;

	while (newstr.size() % 8 != 0)
	{
		newstr.push_back('=');
	}

	return fromBase32(newstr);
}

std::string toBase32(const ByteString & bs)
{
	std::string ret;

	size_t i, j, len;
	for (j = 0; j < bs.size() / 5; ++j)
	{
		i = j * 5;
		ByteString sub(bs, i, 5);
		std::string chk = bytesToB32Chunk(sub);
		ret.append(chk);
	}

	i = j * 5;
	len = bs.size() - i;
	if (len > 0)
	{
		// block of size < 5 remains
		ByteString sub(bs, i, std::string::npos);
		std::string chk = bytesToB32Chunk(sub);
		ret.append(chk);
	}

	return ret;
}

}
}
