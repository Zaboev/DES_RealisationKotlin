package DES

interface IRoundKeysGenerator<T, R> {

    suspend fun rKeysGenerator(entryKey: T): R
    suspend fun rKeysGeneratorDecryptionForIdea(entryKey: T): IntArray {

        return intArrayOf(0)

    }
    suspend fun rKeysGeneratorForDecryption(entryKeys: ArrayList<ByteArray>): ArrayList<ByteArray> {

        return entryKeys

    }
    /*suspend fun rKeysGenerator(entryKey: T): ArrayList<ByteArray>
    suspend fun rKeysGeneratorForDecryption(entryKeys: ArrayList<ByteArray>): ArrayList<ByteArray> {

        return entryKeys

    }*/

}

interface IRoundFunction<T> {

    suspend fun encryptionTransformation(block: ByteArray, roundKey: T) : ByteArray
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