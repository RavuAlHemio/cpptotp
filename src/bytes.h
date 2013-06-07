/**
 * @file bytes.h
 *
 * @brief Byte-related operations.
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
