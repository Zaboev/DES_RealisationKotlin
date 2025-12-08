package DES

interface IRoundKeysGenerator<T> {

    suspend fun rKeysGenerator(entryKey: T): ArrayList<ByteArray>

}

interface IRoundFunction {

    suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray
    suspend fun decryptionTransformation(block: ByteArray, roundKey: ByteArray): ByteArray {

        return block

    }
    suspend fun lastEncryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray {

        return block

    }
    suspend fun lastDecryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray {

        return block

    }

}

interface IEncryptionAndDecryption<T> {

    suspend fun encryptionAlgorithm(enBlock: ByteArray): ByteArray

    suspend fun decryptionAlgorithm(deBlock: ByteArray): ByteArray

    suspend fun setRoundKeys(key: T)

}