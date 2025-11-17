package DES

interface IRoundKeysGenerator<T> {

    suspend fun rKeysGenerator(entryKey: T): ArrayList<ByteArray>

}

interface IRoundFunction<T> {

    suspend fun encryptionTransformation(block: T, roundKey: ByteArray) : T

}

interface IEncrDecr<T> {

    suspend fun encryptionAlgorithm(enBlock: T): T

    suspend fun decryptionAlgorithm(deBlock: T): T

    suspend fun setRoundKeys(key: T)

}