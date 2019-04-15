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

#include <iostream>

#include <impala_udf/udf-test-harness.h>
#include "udf-crypto.h"
#include "hex.h"

using namespace impala;
using namespace impala_udf;
using namespace std;

int main(int argc, char** argv) {
  bool passed = true;
  // Using the test harness helpers, validate the UDF returns correct results.
  // This test validates:
  //  SHA1('1') == '356A192B7913B04C54574D18C28D46E6395428AB'
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      SHA1, StringVal("1"), StringVal("356A192B7913B04C54574D18C28D46E6395428AB"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      MD5, StringVal("1"), StringVal("C4CA4238A0B923820DCC509A6F75849B"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      SHA224, StringVal("1"), StringVal("E25388FDE8290DC286A6164FA2D97E551B53498DCBF7BC378EB1F178"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      SHA256, StringVal("1"), StringVal("6B86B273FF34FCE19D6B804EFF5A3F5747ADA4EAA22F1D49C01E52DDB7875B4B"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      SHA384, StringVal("1"), StringVal("47F05D367B0C32E438FB63E6CF4A5F35C2AA2F90DC7543F8A41A0F95CE8A40A313AB5CF36134A2068C4C969CB50DB776"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      SHA512, StringVal("1"), StringVal("4DFF4EA340F0A823F15D3F4F01AB62EAE0E5DA579CCB851F8DB9DFE84C58B2B37B89903A740E1EE172DA793A6E79D560E5F7F9BD058A12A280433ED6FA46510A"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      SHA3, StringVal("1"), StringVal("CA2C70BC13298C5109EE0CB342D014906E6365249005FD4BEEE6F01AEE44EDB531231E98B50BF6810DE6CF687882B09320FDD5F6375D1F2DEBD966FBF8D03EFA"));
  
  string encoded = "CBA4ACFB309839BA426E07D67F23564F";
  string decoded;
  CryptoPP::StringSource ss1(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      AES128Encrypt, StringVal("ABC"), StringVal("1234567890123456"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      AES128Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("1234567890123456"), StringVal("ABC"));
  
  encoded = "892C0783EA8E12B5605028FC1151009B";
  decoded = "";
  CryptoPP::StringSource ss2(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      AES192Encrypt, StringVal("ABC"), StringVal("123456789012345678901234"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      AES192Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("123456789012345678901234"), StringVal("ABC"));
  
  encoded = "135CE5FA90EFFC663824B936E7828021";
  decoded = "";
  CryptoPP::StringSource ss3(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      AES256Encrypt, StringVal("ABC"), StringVal("12345678901234567890123456789012"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      AES256Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("12345678901234567890123456789012"), StringVal("ABC"));

  cout << "Tests " << (passed ? "Passed." : "Failed.") << endl;
  return !passed;
}
