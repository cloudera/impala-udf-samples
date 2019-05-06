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
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      RIPEMD128, StringVal("1"), StringVal("964297086CACEDF34C500708065BCA73"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      RIPEMD160, StringVal("1"), StringVal("C47907ABD2A80492CA9388B05C0E382518FF3960"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      RIPEMD256, StringVal("1"), StringVal("03F0670DD2CD5186BC159A0BDD40207C6044B9FCA7FB2B72CE1AB8713D3CE9B1"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      RIPEMD320, StringVal("1"), StringVal("0CD35E506B546C0327A52783B6DAC40C766E0BC583FDA558438B92816E9BE0FE7E0AEFF65B07439E"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      Tiger, StringVal("1"), StringVal("1D573194A056EB3200F9D302900C843C3D41AB4ED06C03DF"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      Whirlpool, StringVal("1"), StringVal("8513C69D070A008DF008AEF8624ED24AFC81B170D242FAF5FAFE853D4FE9BF8AA7BADFB0FD045D7B350B19FBF8EF6B2A51F17A07A1F6819ABC9BA5CE43324244"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      SM3, StringVal("1"), StringVal("CBDDDB8E8421B23498480570D7D75330538A6882F5DFDC3B64115C647F3328C4"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      Keccak224, StringVal("1"), StringVal("F3AF0C2E122CB4D87350C0888092F2015EB6131FF2E9DD6893CC7645"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      Keccak256, StringVal("1"), StringVal("C89EFDAA54C0F20C7ADF612882DF0950F5A951637E0307CDCB4C672F298B8BC6"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      Keccak384, StringVal("1"), StringVal("8147A2689F508CC03278C313290588B44607B5C0CCC07DF5B0A80BAF7D25812F0928C018C81381EF1DC76B25DBF6BAFC"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      Keccak512, StringVal("1"), StringVal("00197A4F5F1FF8C356A78F6921B5A6BFBF71DF8DBD313FBC5095A55DE756BFA1EA7240695005149294F2A2E419AE251FE2F7DBB67C3BB647C2AC1BE05EEC7EF9"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      BLAKE2s128, StringVal("1"), StringVal("2F16BAFC6F6C35EA2E6EAC392FF30387"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      BLAKE2s160, StringVal("1"), StringVal("8FEAF2006F582E409CDCB6B4F578142F4D5FE892"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      BLAKE2s224, StringVal("1"), StringVal("9B8B908816B14C1379192F9DFDE5B34839B96B6E9A72C9E1D86F4EC3"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      BLAKE2s256, StringVal("1"), StringVal("625851E3876E6E6DA405C95AC24687CE4BB2CDD8FBD8459278F6F0CE803E13EE"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      BLAKE2b224, StringVal("1"), StringVal("4D50A11E297E7783383BF06DD6E4E481230323BD96CD8B8D9EE3888D"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      BLAKE2b256, StringVal("1"), StringVal("92CDF578C47085A5992256F0DCF97D0B19F1F1C9DE4D5FE30C3ACE6191B6E5DB"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      BLAKE2b384, StringVal("1"), StringVal("399A1BC596E664EE454404C92BB97043784F8007CB21A760C59E7290942B89D0FB9690C39636352166E8B45203400AD9"));
  
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal>(
      BLAKE2b512, StringVal("1"), StringVal("1CED8F5BE2DB23A6513EBA4D819C73806424748A7BC6FA0D792CC1C7D1775A9778E894AA91413F6EB79AD5AE2F871EAFCC78797E4C82AF6D1CBFB1A294A10D10"));
  
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
  
  
  encoded = "3ffdfd53f9258705";
  decoded = "";
  CryptoPP::StringSource ss4(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      TDEA2Encrypt, StringVal("ABC"), StringVal("1234567890123456"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      TDEA2Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8), StringVal("1234567890123456"), StringVal("ABC"));
  
  encoded = "32d94f388f940a93";
  decoded = "";
  CryptoPP::StringSource ss5(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      TDEA3Encrypt, StringVal("ABC"), StringVal("123456789012345678901234"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      TDEA3Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8), StringVal("123456789012345678901234"), StringVal("ABC"));
  
  encoded = "811151160c7c0e84";
  decoded = "";
  CryptoPP::StringSource ss6(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      BlowfishEncrypt, StringVal("ABC"), StringVal("1234567890123456789012345"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      BlowfishDecrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8), StringVal("1234567890123456789012345"), StringVal("ABC"));

  encoded = "93186A650E440D1EDECD61A92B3BD4C6";
  decoded = "";
  CryptoPP::StringSource ss7(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Twofish128Encrypt, StringVal("ABC"), StringVal("1234567890123456"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Twofish128Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("1234567890123456"), StringVal("ABC"));
  
  encoded = "6227caeb9ece9608b975261a5c0423a1";
  decoded = "";
  CryptoPP::StringSource ss8(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Twofish192Encrypt, StringVal("ABC"), StringVal("123456789012345678901234"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Twofish192Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("123456789012345678901234"), StringVal("ABC"));
  
  encoded = "5098e1c46dc75be0e40c4ee4a3e83521";
  decoded = "";
  CryptoPP::StringSource ss9(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Twofish256Encrypt, StringVal("ABC"), StringVal("12345678901234567890123456789012"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Twofish256Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("12345678901234567890123456789012"), StringVal("ABC"));
  
  
  encoded = "b2e4d2bacdd1cee73db8b36a23eeb63c";
  decoded = "";
  CryptoPP::StringSource ss10(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Serpent128Encrypt, StringVal("ABC"), StringVal("1234567890123456"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Serpent128Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("1234567890123456"), StringVal("ABC"));
  
  encoded = "ac68267b328b14f093229c3138b85f7e";
  decoded = "";
  CryptoPP::StringSource ss11(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Serpent192Encrypt, StringVal("ABC"), StringVal("123456789012345678901234"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Serpent192Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("123456789012345678901234"), StringVal("ABC"));
  
  encoded = "efa59cb43eebb9d3494db6fef3aa6c90";
  decoded = "";
  CryptoPP::StringSource ss12(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Serpent256Encrypt, StringVal("ABC"), StringVal("12345678901234567890123456789012"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Serpent256Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("12345678901234567890123456789012"), StringVal("ABC"));
  
  
  encoded = "48 3a 4f 40 43 a0 8b 0d 5d 5a 5e 54 ff 87 d3 d7";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      RC6_128Encrypt, StringVal("ABC"), StringVal("1234567890123456"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      RC6_128Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("1234567890123456"), StringVal("ABC"));
  
  encoded = "2a f9 5a 96 29 30 9e e3 f5 94 d7 4d 80 69 be 48";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      RC6_192Encrypt, StringVal("ABC"), StringVal("123456789012345678901234"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      RC6_192Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("123456789012345678901234"), StringVal("ABC"));
  
  encoded = "b1 bb ae af b7 f1 c8 8c ff 13 a2 d9 36 5b 21 3c";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      RC6_256Encrypt, StringVal("ABC"), StringVal("12345678901234567890123456789012"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      RC6_256Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("12345678901234567890123456789012"), StringVal("ABC"));
  
  
  encoded = "50 5f c3 93 67 48 04 ca 34 ad 24 7e c4 76 e2 3b";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Camellia128Encrypt, StringVal("ABC"), StringVal("1234567890123456"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Camellia128Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("1234567890123456"), StringVal("ABC"));
  
  encoded = "43 0c f2 15 fe ad 89 c2 2c 00 33 44 62 95 75 92";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Camellia192Encrypt, StringVal("ABC"), StringVal("123456789012345678901234"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Camellia192Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("123456789012345678901234"), StringVal("ABC"));
  
  encoded = "a1 3f 38 37 82 57 c5 c2 f4 ea 65 be e4 23 63 6e";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Camellia256Encrypt, StringVal("ABC"), StringVal("12345678901234567890123456789012"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      Camellia256Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("12345678901234567890123456789012"), StringVal("ABC"));
  
  
  encoded = "7a 11 04 e8 70 16 82 8b";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      IDEA_Encrypt, StringVal("ABC"), StringVal("1234567890123456"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      IDEA_Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8), StringVal("1234567890123456"), StringVal("ABC"));
  
  
  encoded = "B17C1A398E7290E1";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      SkipjackEncrypt, StringVal("ABC"), StringVal("1234567890"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      SkipjackDecrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8), StringVal("1234567890"), StringVal("ABC"));
  
  encoded = "2344554E1C3FDFD1";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      TEA_Encrypt, StringVal("ABC"), StringVal("1234567890123456"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      TEA_Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8), StringVal("1234567890123456"), StringVal("ABC"));
  
  encoded = "B43AFED679835EEE";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      XTEA_Encrypt, StringVal("ABC"), StringVal("1234567890123456"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      XTEA_Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 64 / 8), StringVal("1234567890123456"), StringVal("ABC"));
  
  encoded = "0051C88474BAF4AE5F123C128750BBFE";
  decoded = "";
  CryptoPP::StringSource(encoded, true,
    new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded)
    ) // HexDecoder
  ); // StringSource
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      SM4Encrypt, StringVal("ABC"), StringVal("1234567890123456"), StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8));
  passed &= UdfTestHarness::ValidateUdf<StringVal, StringVal, StringVal>(
      SM4Decrypt, StringVal(reinterpret_cast<uint8_t*>(&decoded[0]), 128 / 8), StringVal("1234567890123456"), StringVal("ABC"));
  
  cout << "Tests " << (passed ? "Passed." : "Failed.") << endl;
  return !passed;
}
