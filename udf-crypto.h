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


#ifndef SAMPLES_UDF_H
#define SAMPLES_UDF_H

#include <impala_udf/udf.h>

using namespace impala_udf;

// Usage: > create function sha1(string) returns string
//          location '/user/cloudera/libudfcrypto.so' SYMBOL='SHA1';
//        > select sha1('1');
StringVal SHA1(FunctionContext* context, const StringVal& arg1);

StringVal MD5(FunctionContext* context, const StringVal& arg1);

StringVal SHA224(FunctionContext* context, const StringVal& arg1);

StringVal SHA256(FunctionContext* context, const StringVal& arg1);

StringVal SHA384(FunctionContext* context, const StringVal& arg1);

StringVal SHA512(FunctionContext* context, const StringVal& arg1);

StringVal SHA3(FunctionContext* context, const StringVal& arg1);

// Usage: > create function aes128decrypt(string, string) returns string
//          location '/user/cloudera/libudfcrypto.so' SYMBOL='AES128Decrypt';
//        > select aes128decrypt(unhex('CBA4ACFB309839BA426E07D67F23564F'), '1234567890123456');
// Params: arg1 is cipher text, arg2 is key, return value is plain text
StringVal AES128Decrypt(FunctionContext* context, const StringVal& arg1, const StringVal& arg2);

// Usage: > create function aes128encrypt(string, string) returns string
//          location '/user/cloudera/libudfcrypto.so' SYMBOL='AES128Encrypt';
//        > select hex(aes128encrypt('ABC', '1234567890123456'));
// Params: arg1 is plain text, arg2 is key, return value is cipher text
StringVal AES128Encrypt(FunctionContext* context, const StringVal& arg1, const StringVal& arg2);

StringVal AES192Decrypt(FunctionContext* context, const StringVal& arg1, const StringVal& arg2);

StringVal AES192Encrypt(FunctionContext* context, const StringVal& arg1, const StringVal& arg2);

StringVal AES256Decrypt(FunctionContext* context, const StringVal& arg1, const StringVal& arg2);

StringVal AES256Encrypt(FunctionContext* context, const StringVal& arg1, const StringVal& arg2);

#endif
