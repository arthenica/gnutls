const char *mech_list[] = {
	[(0UL)] = "CKM_RSA_PKCS_KEY_PAIR_GEN",
	[(1UL)] = "CKM_RSA_PKCS",
	[(2UL)] = "CKM_RSA_9796",
	[(3UL)] = "CKM_RSA_X_509",
	[(4UL)] = "CKM_MD2_RSA_PKCS",
	[(5UL)] = "CKM_MD5_RSA_PKCS",
	[(6UL)] = "CKM_SHA1_RSA_PKCS",
	[(7UL)] = "CKM_RIPEMD128_RSA_PKCS",
	[(8UL)] = "CKM_RIPEMD160_RSA_PKCS",
	[(9UL)] = "CKM_RSA_PKCS_OAEP",
	[(0xaUL)] = "CKM_RSA_X9_31_KEY_PAIR_GEN",
	[(0xbUL)] = "CKM_RSA_X9_31",
	[(0xcUL)] = "CKM_SHA1_RSA_X9_31",
	[(0xdUL)] = "CKM_RSA_PKCS_PSS",
	[(0xeUL)] = "CKM_SHA1_RSA_PKCS_PSS",
	[(0x10UL)] = "CKM_DSA_KEY_PAIR_GEN",
	[(0x11UL)] = "CKM_DSA",
	[(0x12UL)] = "CKM_DSA_SHA1",
	[(0x20UL)] = "CKM_DH_PKCS_KEY_PAIR_GEN",
	[(0x21UL)] = "CKM_DH_PKCS_DERIVE",
	[(0x30UL)] = "CKM_X9_42_DH_KEY_PAIR_GEN",
	[(0x31UL)] = "CKM_X9_42_DH_DERIVE",
	[(0x32UL)] = "CKM_X9_42_DH_HYBRID_DERIVE",
	[(0x33UL)] = "CKM_X9_42_MQV_DERIVE",
	[(0x40UL)] = "CKM_SHA256_RSA_PKCS",
	[(0x41UL)] = "CKM_SHA384_RSA_PKCS",
	[(0x42UL)] = "CKM_SHA512_RSA_PKCS",
	[(0x43UL)] = "CKM_SHA256_RSA_PKCS_PSS",
	[(0x44UL)] = "CKM_SHA384_RSA_PKCS_PSS",
	[(0x45UL)] = "CKM_SHA512_RSA_PKCS_PSS",
	[(0x100UL)] = "CKM_RC2_KEY_GEN",
	[(0x101UL)] = "CKM_RC2_ECB",
	[(0x102UL)] = "CKM_RC2_CBC",
	[(0x103UL)] = "CKM_RC2_MAC",
	[(0x104UL)] = "CKM_RC2_MAC_GENERAL",
	[(0x105UL)] = "CKM_RC2_CBC_PAD",
	[(0x110UL)] = "CKM_RC4_KEY_GEN",
	[(0x111UL)] = "CKM_RC4",
	[(0x120UL)] = "CKM_DES_KEY_GEN",
	[(0x121UL)] = "CKM_DES_ECB",
	[(0x122UL)] = "CKM_DES_CBC",
	[(0x123UL)] = "CKM_DES_MAC",
	[(0x124UL)] = "CKM_DES_MAC_GENERAL",
	[(0x125UL)] = "CKM_DES_CBC_PAD",
	[(0x130UL)] = "CKM_DES2_KEY_GEN",
	[(0x131UL)] = "CKM_DES3_KEY_GEN",
	[(0x132UL)] = "CKM_DES3_ECB",
	[(0x133UL)] = "CKM_DES3_CBC",
	[(0x134UL)] = "CKM_DES3_MAC",
	[(0x135UL)] = "CKM_DES3_MAC_GENERAL",
	[(0x136UL)] = "CKM_DES3_CBC_PAD",
	[(0x140UL)] = "CKM_CDMF_KEY_GEN",
	[(0x141UL)] = "CKM_CDMF_ECB",
	[(0x142UL)] = "CKM_CDMF_CBC",
	[(0x143UL)] = "CKM_CDMF_MAC",
	[(0x144UL)] = "CKM_CDMF_MAC_GENERAL",
	[(0x145UL)] = "CKM_CDMF_CBC_PAD",
	[(0x150UL)] = "CKM_DES_OFB64",
	[(0x151UL)] = "CKM_DES_OFB8",
	[(0x152UL)] = "CKM_DES_CFB64",
	[(0x153UL)] = "CKM_DES_CFB8",
	[(0x200UL)] = "CKM_MD2",
	[(0x201UL)] = "CKM_MD2_HMAC",
	[(0x202UL)] = "CKM_MD2_HMAC_GENERAL",
	[(0x210UL)] = "CKM_MD5",
	[(0x211UL)] = "CKM_MD5_HMAC",
	[(0x212UL)] = "CKM_MD5_HMAC_GENERAL",
	[(0x220UL)] = "CKM_SHA_1",
	[(0x221UL)] = "CKM_SHA_1_HMAC",
	[(0x222UL)] = "CKM_SHA_1_HMAC_GENERAL",
	[(0x230UL)] = "CKM_RIPEMD128",
	[(0x231UL)] = "CKM_RIPEMD128_HMAC",
	[(0x232UL)] = "CKM_RIPEMD128_HMAC_GENERAL",
	[(0x240UL)] = "CKM_RIPEMD160",
	[(0x241UL)] = "CKM_RIPEMD160_HMAC",
	[(0x242UL)] = "CKM_RIPEMD160_HMAC_GENERAL",
	[(0x250UL)] = "CKM_SHA256",
	[(0x251UL)] = "CKM_SHA256_HMAC",
	[(0x252UL)] = "CKM_SHA256_HMAC_GENERAL",
	[(0x260UL)] = "CKM_SHA384",
	[(0x261UL)] = "CKM_SHA384_HMAC",
	[(0x262UL)] = "CKM_SHA384_HMAC_GENERAL",
	[(0x270UL)] = "CKM_SHA512",
	[(0x271UL)] = "CKM_SHA512_HMAC",
	[(0x272UL)] = "CKM_SHA512_HMAC_GENERAL",
	[(0x300UL)] = "CKM_CAST_KEY_GEN",
	[(0x301UL)] = "CKM_CAST_ECB",
	[(0x302UL)] = "CKM_CAST_CBC",
	[(0x303UL)] = "CKM_CAST_MAC",
	[(0x304UL)] = "CKM_CAST_MAC_GENERAL",
	[(0x305UL)] = "CKM_CAST_CBC_PAD",
	[(0x310UL)] = "CKM_CAST3_KEY_GEN",
	[(0x311UL)] = "CKM_CAST3_ECB",
	[(0x312UL)] = "CKM_CAST3_CBC",
	[(0x313UL)] = "CKM_CAST3_MAC",
	[(0x314UL)] = "CKM_CAST3_MAC_GENERAL",
	[(0x315UL)] = "CKM_CAST3_CBC_PAD",
	[(0x320UL)] = "CKM_CAST5_KEY_GEN",
	[(0x321UL)] = "CKM_CAST5_ECB",
	[(0x322UL)] = "CKM_CAST5_CBC",
	[(0x323UL)] = "CKM_CAST5_MAC",
	[(0x324UL)] = "CKM_CAST5_MAC_GENERAL",
	[(0x325UL)] = "CKM_CAST5_CBC_PAD",
	[(0x330UL)] = "CKM_RC5_KEY_GEN",
	[(0x331UL)] = "CKM_RC5_ECB",
	[(0x332UL)] = "CKM_RC5_CBC",
	[(0x333UL)] = "CKM_RC5_MAC",
	[(0x334UL)] = "CKM_RC5_MAC_GENERAL",
	[(0x335UL)] = "CKM_RC5_CBC_PAD",
	[(0x340UL)] = "CKM_IDEA_KEY_GEN",
	[(0x341UL)] = "CKM_IDEA_ECB",
	[(0x342UL)] = "CKM_IDEA_CBC",
	[(0x343UL)] = "CKM_IDEA_MAC",
	[(0x344UL)] = "CKM_IDEA_MAC_GENERAL",
	[(0x345UL)] = "CKM_IDEA_CBC_PAD",
	[(0x350UL)] = "CKM_GENERIC_SECRET_KEY_GEN",
	[(0x360UL)] = "CKM_CONCATENATE_BASE_AND_KEY",
	[(0x362UL)] = "CKM_CONCATENATE_BASE_AND_DATA",
	[(0x363UL)] = "CKM_CONCATENATE_DATA_AND_BASE",
	[(0x364UL)] = "CKM_XOR_BASE_AND_DATA",
	[(0x365UL)] = "CKM_EXTRACT_KEY_FROM_KEY",
	[(0x370UL)] = "CKM_SSL3_PRE_MASTER_KEY_GEN",
	[(0x371UL)] = "CKM_SSL3_MASTER_KEY_DERIVE",
	[(0x372UL)] = "CKM_SSL3_KEY_AND_MAC_DERIVE",
	[(0x373UL)] = "CKM_SSL3_MASTER_KEY_DERIVE_DH",
	[(0x374UL)] = "CKM_TLS_PRE_MASTER_KEY_GEN",
	[(0x375UL)] = "CKM_TLS_MASTER_KEY_DERIVE",
	[(0x376UL)] = "CKM_TLS_KEY_AND_MAC_DERIVE",
	[(0x377UL)] = "CKM_TLS_MASTER_KEY_DERIVE_DH",
	[(0x378UL)] = "CKM_TLS_PRF",
	[(0x380UL)] = "CKM_SSL3_MD5_MAC",
	[(0x381UL)] = "CKM_SSL3_SHA1_MAC",
	[(0x390UL)] = "CKM_MD5_KEY_DERIVATION",
	[(0x391UL)] = "CKM_MD2_KEY_DERIVATION",
	[(0x392UL)] = "CKM_SHA1_KEY_DERIVATION",
	[(0x393UL)] = "CKM_SHA256_KEY_DERIVATION",
	[(0x394UL)] = "CKM_SHA384_KEY_DERIVATION",
	[(0x395UL)] = "CKM_SHA512_KEY_DERIVATION",
	[(0x3a0UL)] = "CKM_PBE_MD2_DES_CBC",
	[(0x3a1UL)] = "CKM_PBE_MD5_DES_CBC",
	[(0x3a2UL)] = "CKM_PBE_MD5_CAST_CBC",
	[(0x3a3UL)] = "CKM_PBE_MD5_CAST3_CBC",
	[(0x3a4UL)] = "CKM_PBE_MD5_CAST5_CBC",
	[(0x3a5UL)] = "CKM_PBE_SHA1_CAST5_CBC",
	[(0x3a6UL)] = "CKM_PBE_SHA1_RC4_128",
	[(0x3a7UL)] = "CKM_PBE_SHA1_RC4_40",
	[(0x3a8UL)] = "CKM_PBE_SHA1_DES3_EDE_CBC",
	[(0x3a9UL)] = "CKM_PBE_SHA1_DES2_EDE_CBC",
	[(0x3aaUL)] = "CKM_PBE_SHA1_RC2_128_CBC",
	[(0x3abUL)] = "CKM_PBE_SHA1_RC2_40_CBC",
	[(0x3b0UL)] = "CKM_PKCS5_PBKD2",
	[(0x3c0UL)] = "CKM_PBA_SHA1_WITH_SHA1_HMAC",
	[(0x3d0UL)] = "CKM_WTLS_PRE_MASTER_KEY_GEN",
	[(0x3d1UL)] = "CKM_WTLS_MASTER_KEY_DERIVE",
	[(0x3d2UL)] = "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC",
	[(0x3d3UL)] = "CKM_WTLS_PRF",
	[(0x3d4UL)] = "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
	[(0x3d5UL)] = "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
	[(0x400UL)] = "CKM_KEY_WRAP_LYNKS",
	[(0x401UL)] = "CKM_KEY_WRAP_SET_OAEP",
	[(0x500UL)] = "CKM_CMS_SIG",
	[(0x1000UL)] = "CKM_SKIPJACK_KEY_GEN",
	[(0x1001UL)] = "CKM_SKIPJACK_ECB64",
	[(0x1002UL)] = "CKM_SKIPJACK_CBC64",
	[(0x1003UL)] = "CKM_SKIPJACK_OFB64",
	[(0x1004UL)] = "CKM_SKIPJACK_CFB64",
	[(0x1005UL)] = "CKM_SKIPJACK_CFB32",
	[(0x1006UL)] = "CKM_SKIPJACK_CFB16",
	[(0x1007UL)] = "CKM_SKIPJACK_CFB8",
	[(0x1008UL)] = "CKM_SKIPJACK_WRAP",
	[(0x1009UL)] = "CKM_SKIPJACK_PRIVATE_WRAP",
	[(0x100aUL)] = "CKM_SKIPJACK_RELAYX",
	[(0x1010UL)] = "CKM_KEA_KEY_PAIR_GEN",
	[(0x1011UL)] = "CKM_KEA_KEY_DERIVE",
	[(0x1020UL)] = "CKM_FORTEZZA_TIMESTAMP",
	[(0x1030UL)] = "CKM_BATON_KEY_GEN",
	[(0x1031UL)] = "CKM_BATON_ECB128",
	[(0x1032UL)] = "CKM_BATON_ECB96",
	[(0x1033UL)] = "CKM_BATON_CBC128",
	[(0x1034UL)] = "CKM_BATON_COUNTER",
	[(0x1035UL)] = "CKM_BATON_SHUFFLE",
	[(0x1036UL)] = "CKM_BATON_WRAP",
	[(0x1040UL)] = "CKM_ECDSA_KEY_PAIR_GEN",
	[(0x1041UL)] = "CKM_ECDSA",
	[(0x1042UL)] = "CKM_ECDSA_SHA1",
	[(0x1050UL)] = "CKM_ECDH1_DERIVE",
	[(0x1051UL)] = "CKM_ECDH1_COFACTOR_DERIVE",
	[(0x1052UL)] = "CKM_ECMQV_DERIVE",
	[(0x1060UL)] = "CKM_JUNIPER_KEY_GEN",
	[(0x1061UL)] = "CKM_JUNIPER_ECB128",
	[(0x1062UL)] = "CKM_JUNIPER_CBC128",
	[(0x1063UL)] = "CKM_JUNIPER_COUNTER",
	[(0x1064UL)] = "CKM_JUNIPER_SHUFFLE",
	[(0x1065UL)] = "CKM_JUNIPER_WRAP",
	[(0x1070UL)] = "CKM_FASTHASH",
	[(0x1080UL)] = "CKM_AES_KEY_GEN",
	[(0x1081UL)] = "CKM_AES_ECB",
	[(0x1082UL)] = "CKM_AES_CBC",
	[(0x1083UL)] = "CKM_AES_MAC",
	[(0x1084UL)] = "CKM_AES_MAC_GENERAL",
	[(0x1085UL)] = "CKM_AES_CBC_PAD",
	[(0x1090UL)] = "CKM_BLOWFISH_KEY_GEN",
	[(0x1091UL)] = "CKM_BLOWFISH_CBC",
	[(0x1092UL)] = "CKM_TWOFISH_KEY_GEN",
	[(0x1093UL)] = "CKM_TWOFISH_CBC",
	[(0x1100UL)] = "CKM_DES_ECB_ENCRYPT_DATA",
	[(0x1101UL)] = "CKM_DES_CBC_ENCRYPT_DATA",
	[(0x1102UL)] = "CKM_DES3_ECB_ENCRYPT_DATA",
	[(0x1103UL)] = "CKM_DES3_CBC_ENCRYPT_DATA",
	[(0x1104UL)] = "CKM_AES_ECB_ENCRYPT_DATA",
	[(0x1105UL)] = "CKM_AES_CBC_ENCRYPT_DATA",
	[(0x2000UL)] = "CKM_DSA_PARAMETER_GEN",
	[(0x2001UL)] = "CKM_DH_PKCS_PARAMETER_GEN",
	[(0x2002UL)] = "CKM_X9_42_DH_PARAMETER_GEN",
	[(0x255UL)] = "CKM_SHA224",
	[(0x256UL)] = "CKM_SHA224_HMAC",
	[(0x257UL)] = "CKM_SHA224_HMAC_GENERAL",
	[(0x46UL)] = "CKM_SHA224_RSA_PKCS",
	[(0x47UL)] = "CKM_SHA224_RSA_PKCS_PSS",
	[(0x396UL)] = "CKM_SHA224_KEY_DERIVATION",
	[(0x550UL)] = "CKM_CAMELLIA_KEY_GEN",
	[(0x551UL)] = "CKM_CAMELLIA_ECB",
	[(0x552UL)] = "CKM_CAMELLIA_CBC",
	[(0x553UL)] = "CKM_CAMELLIA_MAC",
	[(0x554UL)] = "CKM_CAMELLIA_MAC_GENERAL",
	[(0x555UL)] = "CKM_CAMELLIA_CBC_PAD",
	[(0x556UL)] = "CKM_CAMELLIA_ECB_ENCRYPT_DATA",
	[(0x557UL)] = "CKM_CAMELLIA_CBC_ENCRYPT_DATA",
	[(0x2109UL)] = "CKM_AES_KEY_WRAP",
	[(0x210aUL)] = "CKM_AES_KEY_WRAP_PAD",
};
