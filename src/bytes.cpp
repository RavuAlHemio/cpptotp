/**
 * @file bytes.cpp
 *
 * @brief Byte-related operations.
 */

#include "bytes.h"

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

}
}
