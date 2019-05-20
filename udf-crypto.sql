create function if not exists sha1(string) returns string location '/udf/libudfcrypto.so' SYMBOL='SHA1';

create function if not exists md5(string) returns string location '/udf/libudfcrypto.so' SYMBOL='MD5';

create function if not exists md2(string) returns string location '/udf/libudfcrypto.so' SYMBOL='MD2';

create function if not exists md4(string) returns string location '/udf/libudfcrypto.so' SYMBOL='MD4';

create function if not exists panamahash(string) returns string location '/udf/libudfcrypto.so' SYMBOL='PanamaHash';

create function if not exists sha224(string) returns string location '/udf/libudfcrypto.so' SYMBOL='SHA224';

create function if not exists sha256(string) returns string location '/udf/libudfcrypto.so' SYMBOL='SHA256';

create function if not exists sha384(string) returns string location '/udf/libudfcrypto.so' SYMBOL='SHA384';

create function if not exists sha512(string) returns string location '/udf/libudfcrypto.so' SYMBOL='SHA512';

create function if not exists sha3(string) returns string location '/udf/libudfcrypto.so' SYMBOL='SHA3';

create function if not exists ripemd128(string) returns string location '/udf/libudfcrypto.so' SYMBOL='RIPEMD128';

create function if not exists ripemd160(string) returns string location '/udf/libudfcrypto.so' SYMBOL='RIPEMD160';

create function if not exists ripemd256(string) returns string location '/udf/libudfcrypto.so' SYMBOL='RIPEMD256';

create function if not exists ripemd320(string) returns string location '/udf/libudfcrypto.so' SYMBOL='RIPEMD320';

create function if not exists tiger(string) returns string location '/udf/libudfcrypto.so' SYMBOL='Tiger';

create function if not exists whirlpool(string) returns string location '/udf/libudfcrypto.so' SYMBOL='Whirlpool';

create function if not exists sm3(string) returns string location '/udf/libudfcrypto.so' SYMBOL='SM3';

create function if not exists keccak224(string) returns string location '/udf/libudfcrypto.so' SYMBOL='Keccak224';

create function if not exists keccak256(string) returns string location '/udf/libudfcrypto.so' SYMBOL='Keccak256';

create function if not exists keccak384(string) returns string location '/udf/libudfcrypto.so' SYMBOL='Keccak384';

create function if not exists keccak512(string) returns string location '/udf/libudfcrypto.so' SYMBOL='Keccak512';

create function if not exists blake2s128(string) returns string location '/udf/libudfcrypto.so' SYMBOL='BLAKE2s128';

create function if not exists blake2s160(string) returns string location '/udf/libudfcrypto.so' SYMBOL='BLAKE2s160';

create function if not exists blake2s224(string) returns string location '/udf/libudfcrypto.so' SYMBOL='BLAKE2s224';

create function if not exists blake2s256(string) returns string location '/udf/libudfcrypto.so' SYMBOL='BLAKE2s256';

create function if not exists blake2b224(string) returns string location '/udf/libudfcrypto.so' SYMBOL='BLAKE2b224';

create function if not exists blake2b256(string) returns string location '/udf/libudfcrypto.so' SYMBOL='BLAKE2b256';

create function if not exists blake2b384(string) returns string location '/udf/libudfcrypto.so' SYMBOL='BLAKE2b384';

create function if not exists blake2b512(string) returns string location '/udf/libudfcrypto.so' SYMBOL='BLAKE2b512';


create function if not exists aes128encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='AES128Encrypt';

create function if not exists aes128decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='AES128Decrypt';

create function if not exists aes192encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='AES192Encrypt';

create function if not exists aes192decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='AES192Decrypt';

create function if not exists aes256encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='AES256Encrypt';

create function if not exists aes256decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='AES256Decrypt';

create function if not exists tdea2encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='TDEA2Encrypt';

create function if not exists tdea2decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='TDEA2Decrypt';

create function if not exists tdea3encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='TDEA3Encrypt';

create function if not exists tdea3decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='TDEA3Decrypt';

create function if not exists des_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='DES_Encrypt';

create function if not exists des_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='DES_Decrypt';

create function if not exists des_xex3_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='DES_XEX3_Encrypt';

create function if not exists des_xex3_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='DES_XEX3_Decrypt';

create function if not exists rc2_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='RC2Encrypt';

create function if not exists rc2_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='RC2Decrypt';

create function if not exists safer_k64_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SAFER_K64Encrypt';

create function if not exists safer_k64_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SAFER_K64Decrypt';

create function if not exists safer_k128_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SAFER_K128Encrypt';

create function if not exists safer_k128_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SAFER_K128Decrypt';

create function if not exists safer_sk64_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SAFER_SK64Encrypt';

create function if not exists safer_sk64_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SAFER_SK64Decrypt';

create function if not exists safer_sk128_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SAFER_SK128Encrypt';

create function if not exists safer_sk128_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SAFER_SK128Decrypt';

create function if not exists threeway_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='ThreeWayEncrypt';

create function if not exists threeway_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='ThreeWayDecrypt';

create function if not exists gost_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='GOST_Encrypt';

create function if not exists gost_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='GOST_Decrypt';

create function if not exists blowfish_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='BlowfishEncrypt';

create function if not exists blowfish_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='BlowfishDecrypt';

create function if not exists twofish128encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Twofish128Encrypt';

create function if not exists twofish128decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Twofish128Decrypt';

create function if not exists twofish192encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Twofish192Encrypt';

create function if not exists twofish192decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Twofish192Decrypt';

create function if not exists twofish256encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Twofish256Encrypt';

create function if not exists twofish256decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Twofish256Decrypt';

create function if not exists serpent128encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Serpent128Encrypt';

create function if not exists serpent128decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Serpent128Decrypt';

create function if not exists serpent192encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Serpent192Encrypt';

create function if not exists serpent192decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Serpent192Decrypt';

create function if not exists serpent256encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Serpent256Encrypt';

create function if not exists serpent256decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Serpent256Decrypt';

create function if not exists rc6_128encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='RC6_128Encrypt';

create function if not exists rc6_128decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='RC6_128Decrypt';

create function if not exists rc6_192encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='RC6_192Encrypt';

create function if not exists rc6_192decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='RC6_192Decrypt';

create function if not exists rc6_256encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='RC6_256Encrypt';

create function if not exists rc6_256decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='RC6_256Decrypt';

create function if not exists camellia128encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Camellia128Encrypt';

create function if not exists camellia128decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Camellia128Decrypt';

create function if not exists camellia192encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Camellia192Encrypt';

create function if not exists camellia192decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Camellia192Decrypt';

create function if not exists camellia256encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Camellia256Encrypt';

create function if not exists camellia256decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='Camellia256Decrypt';

create function if not exists idea_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='IDEA_Encrypt';

create function if not exists idea_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='IDEA_Decrypt';

create function if not exists skipjack_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SkipjackEncrypt';

create function if not exists skipjack_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SkipjackDecrypt';

create function if not exists tea_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='TEA_Encrypt';

create function if not exists tea_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='TEA_Decrypt';

create function if not exists xtea_encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='XTEA_Encrypt';

create function if not exists xtea_decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='XTEA_Decrypt';

create function if not exists sm4encrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SM4Encrypt';

create function if not exists sm4decrypt(string, string) returns string location '/udf/libudfcrypto.so' SYMBOL='SM4Decrypt';
