/**
 * @file otp.h
 *
 * @brief One-time-password-related functions.
 *
 * @copyright The contents of this file have been placed into the public domain;
 * see the file COPYING for more details.
 */

#ifndef __CPPTOTP_OTP_H__
#define __CPPTOTP_OTP_H__

#include "bytes.h"
#include "sha1.h"

#include <cstdint>

namespace CppTotp
{

/** The 64-bit-blocksize variant of HMAC-SHA1. */
Bytes::ByteString hmacSha1_64(const Bytes::ByteString & key, const Bytes::ByteString & msg);

/**
 * Calculate the HOTP value of the given key, message and digit count.
 */
//uint32_t hotp(const Bytes::ByteString & key, const Bytes::ByteString & msg, size_t digitCount = 6, HmacFunc hmac = hmacSha1_64);
uint32_t hotp(const Bytes::ByteString & key, uint64_t counter, size_t digitCount = 6, HmacFunc hmac = hmacSha1_64);

/**
 * Calculate the TOTP value from the given parameters.
 */
uint32_t totp(const Bytes::ByteString & key, uint64_t timeNow, uint64_t timeStart, uint64_t timeStep, size_t digitCount = 6, HmacFunc hmac = hmacSha1_64);

}

#endif
