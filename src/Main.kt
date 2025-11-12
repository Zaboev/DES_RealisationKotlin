import Enums.*

fun main() {

    try {
        for (i in 1..4) {

            var padding: Padding = Padding.Zeros

            when (i) {

                1 -> padding = Padding.PKCS7
                2 -> padding = Padding.ISO10126
                3 -> padding = Padding.ANSI_X923
                4 -> padding = Padding.Zeros

            }

            val obj = ContextCypherAlgorithm(
                byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8),
                EncryptionMode.OFB, // ECB, CBC, PCBC, OFB, CFB, RandomDelta, CTR
                padding,
                Endian.BIG_ENDIAN,
                IndexBase.ONE_INDEX,
                byteArrayOf(8, 7, 6, 5, 4, 3, 2, 1),
                byteArrayOf(2, 4, 6, 8, 1, 3, 5, 7)
            )

            obj.cipherStart(
                "C:\\Users\\Zaboev\\Desktop\\ExamplesForDES\\text.txt",
                "C:\\Users\\Zaboev\\Desktop\\ExamplesForDES\\cipheredWith${padding}.txt",
                CipherOrDecipher.Encryption,
                5
            )

            obj.cipherStart(
                "C:\\Users\\Zaboev\\Desktop\\ExamplesForDES\\cipheredWith${padding}.txt",
                "C:\\Users\\Zaboev\\Desktop\\ExamplesForDES\\deCipheredWith${padding}.txt",
                CipherOrDecipher.Decryption,
                5
            )
        }

        // private val encryptionKey: ByteArray,
        //    private val mode: EncryptionMode,
        //    private val paddingType: Padding,
        //    private val vectorInit: ByteArray,
        //    private val endian: Endian,
        //    private val indexBase: IndexBase,
        //    private val randomDelta: ByteArray
    }
    catch (e: Exception) {

        println(e.message)

    }
}