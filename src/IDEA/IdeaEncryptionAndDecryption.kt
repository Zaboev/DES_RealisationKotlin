import DES.*

class IdeaEncryptionAndDecryption (

    private val keyGenerator: IRoundKeysGenerator<ByteArray, IntArray>,
    private val roundFunction: IRoundFunction<IntArray>,
    private val key: ByteArray

) : IEncryptionAndDecryption<ByteArray> {

    private lateinit var encKeys: IntArray
    private lateinit var decKeys: IntArray

    override suspend fun encryptionAlgorithm(enBlock: ByteArray): ByteArray {

        setRoundKeys(key)
        return roundFunction.encryptionTransformation(enBlock.clone(), encKeys)

    }

    override suspend fun decryptionAlgorithm(deBlock: ByteArray): ByteArray {

        setRoundKeys(key)
        return roundFunction.encryptionTransformation(deBlock.clone(), decKeys)

    }

    override suspend fun setRoundKeys(key: ByteArray) {

        encKeys = keyGenerator.rKeysGenerator(key)
        decKeys = keyGenerator.rKeysGeneratorDecryptionForIdea(key)

    }

}
