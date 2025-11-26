package DES

interface IRoundKeysGenerator<T> {

    suspend fun rKeysGenerator(entryKey: T): ArrayList<ByteArray>

}

interface IRoundFunction {

    suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray

}

interface IEncrDecr<T> {

    suspend fun encryptionAlgorithm(enBlock: ByteArray): ByteArray

    suspend fun decryptionAlgorithm(deBlock: ByteArray): ByteArray

    suspend fun setRoundKeys(key: T)

}