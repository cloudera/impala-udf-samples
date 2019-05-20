create function sha1(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SHA1';

create function md5(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='MD5';

create function sha224(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SHA224';

create function sha256(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SHA256';

create function sha384(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SHA384';

create function sha512(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SHA512';

create function sha3(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SHA3';

create function ripemd128(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='RIPEMD128';

create function ripemd160(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='RIPEMD160';

create function ripemd256(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='RIPEMD256';

create function ripemd320(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='RIPEMD320';

create function tiger(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Tiger';

create function whirlpool(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Whirlpool';

create function sm3(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SM3';

create function keccak224(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Keccak224';

create function keccak256(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Keccak256';

create function keccak384(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Keccak384';

create function keccak512(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Keccak512';

create function blake2s128(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='BLAKE2s128';

create function blake2s160(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='BLAKE2s160';

create function blake2s224(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='BLAKE2s224';

create function blake2s256(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='BLAKE2s256';

create function blake2b224(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='BLAKE2b224';

create function blake2b256(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='BLAKE2b256';

create function blake2b384(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='BLAKE2b384';

create function blake2b512(string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='BLAKE2b512';


create function aes128encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='AES128Encrypt';

create function aes128decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='AES128Decrypt';

create function aes192encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='AES192Encrypt';

create function aes192decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='AES192Decrypt';

create function aes256encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='AES256Encrypt';

create function aes256decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='AES256Decrypt';

create function tdea2encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='TDEA2Encrypt';

create function tdea2decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='TDEA2Decrypt';

create function tdea3encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='TDEA3Encrypt';

create function tdea3decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='TDEA3Decrypt';

create function blowfish_encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='BlowfishEncrypt';

create function blowfish_decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='BlowfishDecrypt';

create function twofish128encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Twofish128Encrypt';

create function twofish128decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Twofish128Decrypt';

create function twofish192encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Twofish192Encrypt';

create function twofish192decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Twofish192Decrypt';

create function twofish256encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Twofish256Encrypt';

create function twofish256decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Twofish256Decrypt';

create function serpent128encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Serpent128Encrypt';

create function serpent128decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Serpent128Decrypt';

create function serpent192encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Serpent192Encrypt';

create function serpent192decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Serpent192Decrypt';

create function serpent256encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Serpent256Encrypt';

create function serpent256decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Serpent256Decrypt';

create function rc6_128encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='RC6_128Encrypt';

create function rc6_128decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='RC6_128Decrypt';

create function rc6_192encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='RC6_192Encrypt';

create function rc6_192decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='RC6_192Decrypt';

create function rc6_256encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='RC6_256Encrypt';

create function rc6_256decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='RC6_256Decrypt';

create function camellia128encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Camellia128Encrypt';

create function camellia128decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Camellia128Decrypt';

create function camellia192encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Camellia192Encrypt';

create function camellia192decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Camellia192Decrypt';

create function camellia256encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Camellia256Encrypt';

create function camellia256decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='Camellia256Decrypt';

create function idea_encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='IDEA_Encrypt';

create function idea_decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='IDEA_Decrypt';

create function skipjack_encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SkipjackEncrypt';

create function skipjack_decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SkipjackDecrypt';

create function tea_encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='TEA_Encrypt';

create function tea_decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='TEA_Decrypt';

create function xtea_encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='XTEA_Encrypt';

create function xtea_decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='XTEA_Decrypt';

create function sm4encrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SM4Encrypt';

create function sm4decrypt(string, string) returns string location '/user/cloudera/libudfcrypto.so' SYMBOL='SM4Decrypt';
