// Copyright 2012 Cloudera Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "udf-crypto.h"

#include <cctype>
#include <cmath>
#include <string>
#include "hex.h"
#include "sha.h"
#include "sha3.h"
#include "keccak.h"
#include "ripemd.h"
#include "tiger.h"
#include "whrlpool.h"
#include "sm3.h"
#include "blake2.h"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <md5.h>
#include "aes.h"
#include "des.h"
#include "blowfish.h"
#include "twofish.h"
#include "serpent.h"
#include "rc6.h"
#include "idea.h"
#include "camellia.h"
#include "skipjack.h"
#include "tea.h"
#include "sm4.h"
#include "modes.h"

#include "common.h"

IMPALA_UDF_EXPORT
StringVal SHA1(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
  CryptoPP::SHA1().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal MD5(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::Weak::MD5::DIGESTSIZE];
  CryptoPP::Weak::MD5().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal SHA224(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::SHA224::DIGESTSIZE];
  CryptoPP::SHA224().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal SHA256(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
  CryptoPP::SHA256().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal SHA384(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::SHA384::DIGESTSIZE];
  CryptoPP::SHA384().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal SHA512(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::SHA512::DIGESTSIZE];
  CryptoPP::SHA512().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal SHA3(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::SHA3_512::DIGESTSIZE];
  CryptoPP::SHA3_512().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal RIPEMD128(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::RIPEMD128::DIGESTSIZE];
  CryptoPP::RIPEMD128().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal RIPEMD160(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::RIPEMD160::DIGESTSIZE];
  CryptoPP::RIPEMD160().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal RIPEMD256(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::RIPEMD256::DIGESTSIZE];
  CryptoPP::RIPEMD256().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal RIPEMD320(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::RIPEMD320::DIGESTSIZE];
  CryptoPP::RIPEMD320().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal Tiger(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::Tiger::DIGESTSIZE];
  CryptoPP::Tiger().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal Whirlpool(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::Whirlpool::DIGESTSIZE];
  CryptoPP::Whirlpool().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal SM3(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::SM3::DIGESTSIZE];
  CryptoPP::SM3().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal Keccak224(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::Keccak_224::DIGESTSIZE];
  CryptoPP::Keccak_224().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal Keccak256(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::Keccak_256::DIGESTSIZE];
  CryptoPP::Keccak_256().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal Keccak384(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::Keccak_384::DIGESTSIZE];
  CryptoPP::Keccak_384().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal Keccak512(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[CryptoPP::Keccak_512::DIGESTSIZE];
  CryptoPP::Keccak_512().CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

StringVal BLAKE2s(FunctionContext* context, const StringVal& arg1, int digestSize) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[digestSize];
  CryptoPP::BLAKE2s(false, digestSize).CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal BLAKE2s128(FunctionContext* context, const StringVal& arg1) {
  return BLAKE2s(context, arg1, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal BLAKE2s160(FunctionContext* context, const StringVal& arg1) {
  return BLAKE2s(context, arg1, 160 / 8);
}

IMPALA_UDF_EXPORT
StringVal BLAKE2s224(FunctionContext* context, const StringVal& arg1) {
  return BLAKE2s(context, arg1, 224 / 8);
}

IMPALA_UDF_EXPORT
StringVal BLAKE2s256(FunctionContext* context, const StringVal& arg1) {
  return BLAKE2s(context, arg1, 256 / 8);
}

StringVal BLAKE2b(FunctionContext* context, const StringVal& arg1, int digestSize) {
  if (arg1.is_null) return StringVal::null();
  CryptoPP::byte digest[digestSize];
  CryptoPP::BLAKE2b(false, digestSize).CalculateDigest(digest, arg1.ptr, arg1.len);
  std::string encoded;

  CryptoPP::StringSource ss(digest, sizeof(digest), true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)
      ) // HexEncoder
  ); // StringSource
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(encoded.c_str()), encoded.size());
}

IMPALA_UDF_EXPORT
StringVal BLAKE2b224(FunctionContext* context, const StringVal& arg1) {
  return BLAKE2b(context, arg1, 224 / 8);
}

IMPALA_UDF_EXPORT
StringVal BLAKE2b256(FunctionContext* context, const StringVal& arg1) {
  return BLAKE2b(context, arg1, 256 / 8);
}

IMPALA_UDF_EXPORT
StringVal BLAKE2b384(FunctionContext* context, const StringVal& arg1) {
  return BLAKE2b(context, arg1, 384 / 8);
}

IMPALA_UDF_EXPORT
StringVal BLAKE2b512(FunctionContext* context, const StringVal& arg1) {
  return BLAKE2b(context, arg1, 512 / 8);
}


StringVal AESDecryptWithKeySize(FunctionContext* context, const StringVal& arg1, const StringVal& arg2, int keySize) {
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

StringVal AESEncryptWithKeySize(FunctionContext* context, const StringVal& arg1, const StringVal& arg2, int keySize) {
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal AES128Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return AESDecryptWithKeySize(context, arg1, arg2, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal AES128Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return AESEncryptWithKeySize(context, arg1, arg2, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal AES192Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return AESDecryptWithKeySize(context, arg1, arg2, 192 / 8);
}

IMPALA_UDF_EXPORT
StringVal AES192Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return AESEncryptWithKeySize(context, arg1, arg2, 192 / 8);
}

IMPALA_UDF_EXPORT
StringVal AES256Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return AESDecryptWithKeySize(context, arg1, arg2, 256 / 8);
}

IMPALA_UDF_EXPORT
StringVal AES256Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return AESEncryptWithKeySize(context, arg1, arg2, 256 / 8);
}


IMPALA_UDF_EXPORT
StringVal TDEA2Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::DES_EDE2::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::DES_EDE2>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::DES_EDE2::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::DES_EDE2::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal TDEA2Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::DES_EDE2::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::DES_EDE2>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::DES_EDE2::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::DES_EDE2::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal TDEA3Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::DES_EDE3::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::DES_EDE3::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal TDEA3Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::DES_EDE3::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::DES_EDE3::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal BlowfishDecrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = arg2.len;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || keySize > CryptoPP::Blowfish::MAX_KEYLENGTH || keySize < CryptoPP::Blowfish::MIN_KEYLENGTH) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::Blowfish::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::Blowfish::BLOCKSIZE);
    for (int i = 0; i < keySize; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal BlowfishEncrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = arg2.len;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || keySize > CryptoPP::Blowfish::MAX_KEYLENGTH || keySize < CryptoPP::Blowfish::MIN_KEYLENGTH) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::Blowfish::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::Blowfish::BLOCKSIZE);
    for (int i = 0; i < keySize; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}


StringVal TwofishDecryptWithKeySize(FunctionContext* context, const StringVal& arg1, const StringVal& arg2, int keySize) {
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::Twofish>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::Twofish::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::Twofish::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

StringVal TwofishEncryptWithKeySize(FunctionContext* context, const StringVal& arg1, const StringVal& arg2, int keySize) {
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::Twofish>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::Twofish::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::Twofish::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal Twofish128Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return TwofishDecryptWithKeySize(context, arg1, arg2, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal Twofish128Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return TwofishEncryptWithKeySize(context, arg1, arg2, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal Twofish192Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return TwofishDecryptWithKeySize(context, arg1, arg2, 192 / 8);
}

IMPALA_UDF_EXPORT
StringVal Twofish192Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return TwofishEncryptWithKeySize(context, arg1, arg2, 192 / 8);
}

IMPALA_UDF_EXPORT
StringVal Twofish256Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return TwofishDecryptWithKeySize(context, arg1, arg2, 256 / 8);
}

IMPALA_UDF_EXPORT
StringVal Twofish256Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return TwofishEncryptWithKeySize(context, arg1, arg2, 256 / 8);
}


StringVal SerpentDecryptWithKeySize(FunctionContext* context, const StringVal& arg1, const StringVal& arg2, int keySize) {
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::Serpent>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::Serpent::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::Serpent::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

StringVal SerpentEncryptWithKeySize(FunctionContext* context, const StringVal& arg1, const StringVal& arg2, int keySize) {
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::Serpent>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::Serpent::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::Serpent::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal Serpent128Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return SerpentDecryptWithKeySize(context, arg1, arg2, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal Serpent128Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return SerpentEncryptWithKeySize(context, arg1, arg2, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal Serpent192Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return SerpentDecryptWithKeySize(context, arg1, arg2, 192 / 8);
}

IMPALA_UDF_EXPORT
StringVal Serpent192Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return SerpentEncryptWithKeySize(context, arg1, arg2, 192 / 8);
}

IMPALA_UDF_EXPORT
StringVal Serpent256Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return SerpentDecryptWithKeySize(context, arg1, arg2, 256 / 8);
}

IMPALA_UDF_EXPORT
StringVal Serpent256Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return SerpentEncryptWithKeySize(context, arg1, arg2, 256 / 8);
}


StringVal RC6_DecryptWithKeySize(FunctionContext* context, const StringVal& arg1, const StringVal& arg2, int keySize) {
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::RC6>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::RC6::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::RC6::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

StringVal RC6_EncryptWithKeySize(FunctionContext* context, const StringVal& arg1, const StringVal& arg2, int keySize) {
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::RC6>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::RC6::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::RC6::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal RC6_128Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return RC6_DecryptWithKeySize(context, arg1, arg2, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal RC6_128Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return RC6_EncryptWithKeySize(context, arg1, arg2, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal RC6_192Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return RC6_DecryptWithKeySize(context, arg1, arg2, 192 / 8);
}

IMPALA_UDF_EXPORT
StringVal RC6_192Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return RC6_EncryptWithKeySize(context, arg1, arg2, 192 / 8);
}

IMPALA_UDF_EXPORT
StringVal RC6_256Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return RC6_DecryptWithKeySize(context, arg1, arg2, 256 / 8);
}

IMPALA_UDF_EXPORT
StringVal RC6_256Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return RC6_EncryptWithKeySize(context, arg1, arg2, 256 / 8);
}


StringVal CamelliaDecryptWithKeySize(FunctionContext* context, const StringVal& arg1, const StringVal& arg2, int keySize) {
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::Camellia>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::Camellia::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::Camellia::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

StringVal CamelliaEncryptWithKeySize(FunctionContext* context, const StringVal& arg1, const StringVal& arg2, int keySize) {
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::Camellia>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::Camellia::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::Camellia::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal Camellia128Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return CamelliaDecryptWithKeySize(context, arg1, arg2, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal Camellia128Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return CamelliaEncryptWithKeySize(context, arg1, arg2, 128 / 8);
}

IMPALA_UDF_EXPORT
StringVal Camellia192Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return CamelliaDecryptWithKeySize(context, arg1, arg2, 192 / 8);
}

IMPALA_UDF_EXPORT
StringVal Camellia192Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return CamelliaEncryptWithKeySize(context, arg1, arg2, 192 / 8);
}

IMPALA_UDF_EXPORT
StringVal Camellia256Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return CamelliaDecryptWithKeySize(context, arg1, arg2, 256 / 8);
}

IMPALA_UDF_EXPORT
StringVal Camellia256Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  return CamelliaEncryptWithKeySize(context, arg1, arg2, 256 / 8);
}


IMPALA_UDF_EXPORT
StringVal IDEA_Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::IDEA::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::IDEA>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::IDEA::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::IDEA::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal IDEA_Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::IDEA::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::IDEA>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::IDEA::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::IDEA::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}


IMPALA_UDF_EXPORT
StringVal SkipjackDecrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::SKIPJACK::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::SKIPJACK>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::SKIPJACK::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::SKIPJACK::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal SkipjackEncrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::SKIPJACK::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::SKIPJACK>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::SKIPJACK::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::SKIPJACK::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}


IMPALA_UDF_EXPORT
StringVal TEA_Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::TEA::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::TEA>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::TEA::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::TEA::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal TEA_Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::TEA::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::TEA>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::TEA::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::TEA::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal XTEA_Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::XTEA::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::XTEA>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::XTEA::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::XTEA::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal XTEA_Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::XTEA::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::XTEA>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::XTEA::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::XTEA::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal SM4Decrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::SM4::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::SM4>::Decryption d;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::SM4::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::SM4::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    d.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(d,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}

IMPALA_UDF_EXPORT
StringVal SM4Encrypt(FunctionContext* context, const StringVal& arg1,
    const StringVal& arg2) {
  int keySize = CryptoPP::SM4::DEFAULT_KEYLENGTH;
  // return null for empty string
  if (arg1.is_null || arg2.is_null || arg2.len > keySize) {
    return StringVal::null();
  }
  if (arg1.len == 0) {
    return StringVal();
  }

  std::string result_str;
  try {
    CryptoPP::CBC_Mode<CryptoPP::SM4>::Encryption e;
    CryptoPP::byte key[keySize];
    CryptoPP::byte iv[CryptoPP::SM4::BLOCKSIZE];
    memset(key, 0x00, keySize);
    memset(iv, 0x00, CryptoPP::SM4::BLOCKSIZE);
    for (int i = 0; i < arg2.len; ++i) key[i % keySize] ^= arg2.ptr[i];
    e.SetKeyWithIV(key, sizeof(key), iv);
    std::string input(reinterpret_cast<char*>(arg1.ptr), arg1.len);
    // The StreamTransformationFilter removes
    //  padding as required.
    CryptoPP::StringSource s(input, true, 
      new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(result_str)
      ) // StreamTransformationFilter
    ); // StringSource
  } catch (const CryptoPP::Exception& e) {
    context->AddWarning(e.what());
    return StringVal::null();
  }
  return StringVal::CopyFrom(context, 
    reinterpret_cast<const uint8_t*>(result_str.c_str()), result_str.size());
}
