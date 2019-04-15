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
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <md5.h>
#include "aes.h"
#include "modes.h"

#include "common.h"

// In this sample we are declaring a UDF that adds two ints and returns an int.
IMPALA_UDF_EXPORT
IntVal AddUdf(FunctionContext* context, const IntVal& arg1, const IntVal& arg2) {
  if (arg1.is_null || arg2.is_null) return IntVal::null();
  return IntVal(arg1.val + arg2.val);
}

// Multiple UDFs can be defined in the same file
IMPALA_UDF_EXPORT
BooleanVal FuzzyEquals(FunctionContext* ctx, const DoubleVal& x, const DoubleVal& y) {
  const double EPSILON = 0.000001f;
  if (x.is_null || y.is_null) return BooleanVal::null();
  double delta = fabs(x.val - y.val);
  return BooleanVal(delta < EPSILON);
}

// Check if the input string has any occurrences of the letters (a,e,i,o,u).
// Case-insensitive, so also detects (A,E,I,O,U).
IMPALA_UDF_EXPORT
BooleanVal HasVowels(FunctionContext* context, const StringVal& input) {
  if (input.is_null) return BooleanVal::null();

  int index;
  uint8_t *ptr;

  for (ptr = input.ptr, index = 0; index < input.len; index++, ptr++) {
    uint8_t c = tolower(*ptr);
    if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
      return BooleanVal(true);
    }
  }
  return BooleanVal(false);
}

// Count all occurrences of the letters (a,e,i,o,u) in the input string.
// Case-insensitive, so also counts (A,E,I,O,U).
IMPALA_UDF_EXPORT
IntVal CountVowels(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return IntVal::null();

  int count;
  int index;
  uint8_t *ptr;

  for (ptr = arg1.ptr, count = 0, index = 0; index < arg1.len; index++, ptr++) {
    uint8_t c = tolower(*ptr);
    if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
      count++;
    }
  }
  return IntVal(count);
}

// Remove all occurrences of the letters (a,e,i,o,u) from the input string.
// Case-insensitive, so also removes (A,E,I,O,U).
IMPALA_UDF_EXPORT
StringVal StripVowels(FunctionContext* context, const StringVal& arg1) {
  if (arg1.is_null) return StringVal::null();

  int index;
  std::string original((const char *)arg1.ptr,arg1.len);
  std::string shorter("");

  for (index = 0; index < original.length(); index++) {
    uint8_t c = original[index];
    uint8_t l = tolower(c);

    if (l == 'a' || l == 'e' || l == 'i' || l == 'o' || l == 'u') {
      continue;
    }
    else {
        shorter.append(1, (char)c);
    }
  }
  // The modified string 'shorter' is destroyed when this function ends. We need to copy
  // the value into Impala-managed memory with StringVal::CopyFrom().
  // NB: CopyFrom() will return a null StringVal and and fail the query if the allocation
  // fails because of lack of memory.
  return StringVal::CopyFrom(context,
      reinterpret_cast<const uint8_t*>(shorter.c_str()), shorter.size());
}

// In the prepare function, allocate an IntVal and set it as the shared state. This
// IntVal will be set to the result to be returned, i.e. the argument if it's constant
// and null otherwise.
IMPALA_UDF_EXPORT
void ReturnConstantArgPrepare(
    FunctionContext* context, FunctionContext::FunctionStateScope scope) {
  // UDFs should check the version to avoid unimplemented functions from being called
  if (context->version() < FunctionContext::v1_3) {
    context->SetError("This UDF can only be used with Impala 1.3 or higher");
    return;
  }
  // NB: the state is created once per thread. In this case it would also be valid to
  // make it FRAGMENT_LOCAL since the data is read-only and it is safe to access from
  // multiple threads.
  if (scope == FunctionContext::THREAD_LOCAL) {
    // Get the constant value of the 'const_val' argument in ReturnConstantArg(). If this
    // value is not constant, 'arg' will be NULL.
    IntVal* arg = reinterpret_cast<IntVal*>(context->GetConstantArg(0));
    // Allocate shared state to store 'arg' or a null IntVal
    IntVal* state = reinterpret_cast<IntVal*>(context->Allocate(sizeof(IntVal)));
    // Allocations may fail. In that case return and let Impala cancel the query.
    if (state == NULL) return;
    *state = (arg != NULL) ? *arg : IntVal::null();
    // Set the shared state in the function context
    context->SetFunctionState(scope, state);
  }
}

// Retreives and returns the shared state set in the prepare function
IMPALA_UDF_EXPORT
IntVal ReturnConstantArg(FunctionContext* context, const IntVal& const_val) {
  IntVal* state = reinterpret_cast<IntVal*>(
      context->GetFunctionState(FunctionContext::THREAD_LOCAL));
  return *state;
}

// Cleans up the shared state
IMPALA_UDF_EXPORT
void ReturnConstantArgClose(
    FunctionContext* context, FunctionContext::FunctionStateScope scope) {
  if (scope == FunctionContext::THREAD_LOCAL) {
    // Retreive and deallocate the shared state
    void* state = context->GetFunctionState(scope);
    if (state != NULL) {
      context->Free(reinterpret_cast<uint8_t*>(state));
      context->SetFunctionState(scope, NULL);
    }
  }
}



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
