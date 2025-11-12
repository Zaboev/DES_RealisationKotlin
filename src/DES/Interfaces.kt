package DES

interface IRoundKeysGenerator {

    suspend fun rKeysGenerator(entryKey: ByteArray): ArrayList<ByteArray>

}

interface IRoundFunction {

    suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray

}

interface IEncrDecr {

    suspend fun encryptionAlgorithm(enBlock: ByteArray): ByteArray

    suspend fun decryptionAlgorithm(deBlock: ByteArray): ByteArray

    suspend fun setRoundKeys(key: ByteArray)

}