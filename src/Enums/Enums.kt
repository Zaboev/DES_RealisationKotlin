package Enums

enum class Endian {

    BIG_ENDIAN,
    LTL_ENDIAN

}

enum class IndexBase {

    ZERO_INDEX,
    ONE_INDEX

}

enum class Padding {

    Zeros,
    ANSI_X923,
    PKCS7,
    ISO10126

}

enum class EncryptionMode {

    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RandomDelta

}

enum class CipherOrDecipher {

    Decryption,
    Encryption

}

enum class Algorithm {

    DES,
    DEAL,
    TripleDes,
    Rijndael,
    //IDEA

}