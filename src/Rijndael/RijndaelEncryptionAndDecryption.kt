package Rijndael
import DES.IEncryptionAndDecryption
import DES.IRoundFunction
import DES.IRoundKeysGenerator

class RijndaelEncryptionAndDecryption(

    private val roundFunction: IRoundFunction,
    private val roundKeysGenerator: IRoundKeysGenerator<ByteArray>

): IEncryptionAndDecryption<ByteArray> {

    private var roundKeys = ArrayList<ByteArray>(0)

    override suspend fun encryptionAlgorithm(enBlock: ByteArray): ByteArray {

        return enBlock

    }

    override suspend fun decryptionAlgorithm(deBlock: ByteArray): ByteArray {

        return deBlock

    }

    override suspend fun setRoundKeys(key: ByteArray) {

        roundKeys = roundKeysGenerator.rKeysGenerator(key)

    }

}