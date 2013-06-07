/**
 * @file sha1.h
 *
 * @brief The SHA-1 hash function.
 *
 * @copyright The contents of this file have been placed into the public domain;
 * see the file COPYING for more details.
 */

#ifndef __CPPTOTP_SHA1_H__
#define __CPPTOTP_SHA1_H__

#include "bytes.h"

namespace CppTotp
{

typedef Bytes::ByteString (*HmacFunc)(const Bytes::ByteString &, const Bytes::ByteString &);

/**
 * Calculate the SHA-1 hash of the given message.
 */
Bytes::ByteString sha1(const Bytes::ByteString & msg);

/**
 * Calculate the HMAC-SHA-1 hash of the given key/message pair.
 *
 * @note Most services assume a block size of 64.
 */
Bytes::ByteString hmacSha1(const Bytes::ByteString & key, const Bytes::ByteString & msg, size_t blockSize = 64);

}

#endif
