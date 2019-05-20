select sha1('scalefree.com') = '251997C9B2D3CE133CE5EF2035346ADBCFCB353E';
select md5('scalefree.com') = 'CC8EB3A84F0B148CDFDA5A4D55369DA1';
select sha224('scalefree.com') = '1446E3F8F63383B4D9C939CDE183D614EB7688AE632364045FBC7CBD';
select sha256('scalefree.com') = '4479E782C8AA2FAB87A00405D1BA4797184A712C8DEE728306957DCE0C818E5A';
select sha384('scalefree.com') = 'B83E3C6B0D6D3E385427389A8B5B08C11DDDC762021790651D44CC56C036200F909E77A5E9601A95A88E5D1529A59F80';
select sha512('scalefree.com') = '364190D4D10C2816C5532F7DBFA91E66E8975F7F8A6663776F0D7811D9A7FAA13364A8ED7019CB362E5EE1D783388D73AF583AC2388559F82F262FD5C0EAE853';
select sha3('scalefree.com') = 'E75D2A4A38BB513C44B222C1AFA4A01FAA7B16FA64C5CE63AD9C28F51A80564EC31BF39727CCF25B85D58D354D5EDED86DC920D847D7CAF850A50CC675D7BBAD';

select ripemd128('scalefree.com') = '8161B54B706F719F5400DBA448291747';
select ripemd160('scalefree.com') = 'C3F08B9946A96ABF423F9FBA1400F8948D2B0BF6';
select ripemd256('scalefree.com') = '24D9A4578E5401CD0AEB00FD9846F8A62A00EAE9C8267E2AA2B4B3D8CAC3BE78';
select ripemd320('scalefree.com') = '135021BFCC1A0513B17F4BF3D25E4BC840D57BA2ACC3AB6E1E910D76CDFF0A79BB24270381AABA95';
select tiger('scalefree.com') = 'A1B6D39B37EB0DCF582C2EE738258E55ADC24729CB99F705';
select whirlpool('scalefree.com') = '0270E1E87CDC302D3368C7CD8BBFC5F317B28561DD666011AD40F012605B6E7A93B742C02548FAAFD9097A4C17FF7A600D985E7D771D19DACE16B9F6F59A01FB';
select sm3('scalefree.com') = '563BF217616EF2241815CDAE109E2EDC2DE3A5FC8ED6D070DCB18CF95C1C11B5';
select keccak224('scalefree.com') = '4B16331E23C23B8AD5F0213ABB789E2DBB5CC1CC41D7854693F1F59A';
select keccak256('scalefree.com') = '6075135B5141FA4218AA982ED2BAD71AB962F7640F5BAB11847A01BABF14F15D';
select keccak384('scalefree.com') = '91117C5FFAEF0EDDA73999CD8F5779C54E907B50AA647373E7D06C63E608CBD45828939DEB5F063D8A6DEA54594269A1';
select keccak512('scalefree.com') = '364916E9351A627ADF7678E50549B04EAFD736F75CC41F1BACE3AB5648D4B0A2F499175A2742D90CA5038376F917F8DB557FE1603F8C11162E09989BC1361E0A';
select blake2s128('scalefree.com') = 'F67391090722668B99E2133F80D07F5F';
select blake2s160('scalefree.com') = '626492972B301BA5910B0E9552E33377F0B604EC';
select blake2s224('scalefree.com') = 'B98933883A5D106A1832A9DD2DA6D09101B406DED619DBE9ACC171BF';
select blake2s256('scalefree.com') = 'B4091A4FE052731646A22EE55ED922287FD00E5F2F0F64BCBBE0259C00A7C4AF';
select blake2b224('scalefree.com') = 'FAA87E5204069D47A83926FE573938D12DA9A7AD8317CAFFCB096D2A';
select blake2b256('scalefree.com') = '40091487DD2B10AAE4EB296DC9F4BCBF7F55AB1A8ED09C146745AF6B8D132D4D';
select blake2b384('scalefree.com') = '67C8F429776DB801CD87A900EDADF72E9CDF36F5B5B091271CCB93038B92996FA6E9993EA48E6D3E340681C85A5E854C';
select blake2b512('scalefree.com') = '1FFDF955D51F5C279820712E8AC1B764807EC83BBFA2E1853E493D2718FDD4AD3CE2470B14B1426881EEDA46F182FE1D4708B56DEAE971C7D250E251BBD07C64';

select hex(aes128encrypt('scalefree.com', 'secret')) = 'BD1C60B01C7474BE1AE5433A619FE07B';
select aes128decrypt(unhex('BD1C60B01C7474BE1AE5433A619FE07B'), 'secret') = 'scalefree.com';
select hex(aes192encrypt('scalefree.com', 'secret')) = 'FFF9F1CF96925BD503CDC8424F4887F1';
select aes192decrypt(unhex('FFF9F1CF96925BD503CDC8424F4887F1'), 'secret') = 'scalefree.com';
select hex(aes256encrypt('scalefree.com', 'secret')) = '69E68E742665B1CE6BC15561AAF8A931';
select aes256decrypt(unhex('69E68E742665B1CE6BC15561AAF8A931'), 'secret') = 'scalefree.com';

select hex(tdea2encrypt('scalefree.com', 'secret')) = '93BD3605A3750B50306F62168BF4F00E';
select tdea2decrypt(unhex('93BD3605A3750B50306F62168BF4F00E'), 'secret') = 'scalefree.com';
select hex(tdea3encrypt('scalefree.com', 'secret')) = 'A6B22B80FE80F4508B1007FEA03D925D';
select tdea3decrypt(unhex('A6B22B80FE80F4508B1007FEA03D925D'), 'secret') = 'scalefree.com';

select hex(blowfish_encrypt('scalefree.com', 'secret')) = 'D9F15E8BB771C0A894D3D856C951AC48';
select blowfish_decrypt(unhex('D9F15E8BB771C0A894D3D856C951AC48'), 'secret') = 'scalefree.com';
select hex(twofish128encrypt('scalefree.com', 'secret')) = 'A039A9D30BC15BDD2B99C97649BC25FF';
select twofish128decrypt(unhex('A039A9D30BC15BDD2B99C97649BC25FF'), 'secret') = 'scalefree.com';
select hex(twofish192encrypt('scalefree.com', 'secret')) = '1A228C0D91DFDB625C8ADEDC4D1315D9';
select twofish192decrypt(unhex('1A228C0D91DFDB625C8ADEDC4D1315D9'), 'secret') = 'scalefree.com';
select hex(twofish256encrypt('scalefree.com', 'secret')) = '479BE696CF664504A594E66E1972556C';
select twofish256decrypt(unhex('479BE696CF664504A594E66E1972556C'), 'secret') = 'scalefree.com';

select hex(serpent128encrypt('scalefree.com', 'secret')) = 'DD09D5CA720DD384A2406AE9E4A11905';
select serpent128decrypt(unhex('DD09D5CA720DD384A2406AE9E4A11905'), 'secret') = 'scalefree.com';
select hex(serpent192encrypt('scalefree.com', 'secret')) = 'D3B57B2A325C102FF6E6E030B2601453';
select serpent192decrypt(unhex('D3B57B2A325C102FF6E6E030B2601453'), 'secret') = 'scalefree.com';
select hex(serpent256encrypt('scalefree.com', 'secret')) = 'EF99A38EE2C062803BF0D148185B0C1B';
select serpent256decrypt(unhex('EF99A38EE2C062803BF0D148185B0C1B'), 'secret') = 'scalefree.com';

select hex(rc6_128encrypt('scalefree.com', 'secret')) = '1FBA8F6A11F62082229DCB4C3E4FE43E';
select rc6_128decrypt(unhex('1FBA8F6A11F62082229DCB4C3E4FE43E'), 'secret') = 'scalefree.com';
select hex(rc6_192encrypt('scalefree.com', 'secret')) = 'CC3E61BC7536A07DBF52B32812F8CB86';
select rc6_192decrypt(unhex('CC3E61BC7536A07DBF52B32812F8CB86'), 'secret') = 'scalefree.com';
select hex(rc6_256encrypt('scalefree.com', 'secret')) = 'D71F0AD9C4F74DCA67FDC586F65C7E05';
select rc6_256decrypt(unhex('D71F0AD9C4F74DCA67FDC586F65C7E05'), 'secret') = 'scalefree.com';

select hex(camellia128encrypt('scalefree.com', 'secret')) = '9F1338C999B83E0BA977DF9F38D9C75F';
select camellia128decrypt(unhex('9F1338C999B83E0BA977DF9F38D9C75F'), 'secret') = 'scalefree.com';
select hex(camellia192encrypt('scalefree.com', 'secret')) = '4E7B144A3BDFBEA9A898C8CEAC1F25EF';
select camellia192decrypt(unhex('4E7B144A3BDFBEA9A898C8CEAC1F25EF'), 'secret') = 'scalefree.com';
select hex(camellia256encrypt('scalefree.com', 'secret')) = '4C2035A6CF65E23EC1B75073C28581F9';
select camellia256decrypt(unhex('4C2035A6CF65E23EC1B75073C28581F9'), 'secret') = 'scalefree.com';

select hex(idea_encrypt('scalefree.com', 'secret')) = 'B305C97D761C7CD95C6E7CB74B3523B9';
select idea_decrypt(unhex('B305C97D761C7CD95C6E7CB74B3523B9'), 'secret') = 'scalefree.com';

select hex(skipjack_encrypt('scalefree.com', 'secret')) = 'F541D42C59C9E3142F4A470DD9E6C22D';
select skipjack_decrypt(unhex('F541D42C59C9E3142F4A470DD9E6C22D'), 'secret') = 'scalefree.com';
select hex(tea_encrypt('scalefree.com', 'secret')) = '2A2E288D040F8AADF3C1A01F33990FB5';
select tea_decrypt(unhex('2A2E288D040F8AADF3C1A01F33990FB5'), 'secret') = 'scalefree.com';
select hex(xtea_encrypt('scalefree.com', 'secret')) = '02BF81B38A76B0E8CD98DEF3B1998E4B';
select xtea_decrypt(unhex('02BF81B38A76B0E8CD98DEF3B1998E4B'), 'secret') = 'scalefree.com';
select hex(sm4encrypt('scalefree.com', 'secret')) = '66CDE637DBB64DBED5AEDAE2C1B95ED8';
select sm4decrypt(unhex('66CDE637DBB64DBED5AEDAE2C1B95ED8'), 'secret') = 'scalefree.com';

--select hex(xxxxxxxxxxxx('scalefree.com', 'secret')) = 'BD1C60B01C7474BE1AE5433A619FE07B';
--select xxxxxxxxxxxx(unhex('BD1C60B01C7474BE1AE5433A619FE07B'), 'secret') = 'scalefree.com';






