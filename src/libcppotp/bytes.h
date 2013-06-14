/**
 * @file bytes.h
 *
 * @brief Byte-related operations.
 *
 * @copyright The contents of this file have been placed into the public domain;
 * see the file COPYING for more details.
 */

#ifndef __CPPTOTP_BYTES_H__
#define __CPPTOTP_BYTES_H__

#include <string>

#include <cstdint>

namespace CppTotp
{
namespace Bytes
{

/** The type of a single byte. */
typedef uint8_t Byte;

/** The type of a byte string. */
typedef std::basic_string<Byte> ByteString;

/** Deletes the contents of a byte string. */
void clearByteString(ByteString * bstr);

/** Replaces target with source, clearing as much as possible. */
void swizzleByteStrings(ByteString * target, ByteString * source);

/** Converts a byte string into a hex string. */
std::string toHexString(const ByteString & bstr);

/** Converts an unsigned 32-bit integer into a corresponding byte string. */
ByteString u32beToByteString(uint32_t num);

/** Converts an unsigned 64-bit integer into a corresponding byte string. */
ByteString u64beToByteString(uint64_t num);

/** Converts a Base32 string into the correspoding byte string. */
ByteString fromBase32(const std::string & b32str);

/**
 * Converts a potentially unpadded Base32 string into the corresponding byte
 * string.
 */
ByteString fromUnpaddedBase32(const std::string & b32str);

/** Converts byte string into the corresponding Base32 string. */
std::string toBase32(const ByteString & b32str);

/** Deletes the contets of a byte string on destruction. */
class ByteStringDestructor
{
private:
	/** The byte string to clear. */
	ByteString * m_bs;

public:
	ByteStringDestructor(ByteString * bs) : m_bs(bs) {}
	~ByteStringDestructor() { clearByteString(m_bs); }
};

}
}

#endif
