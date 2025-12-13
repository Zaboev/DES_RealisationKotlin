package Rijndael
import DES.IEncryptionAndDecryption
import DES.IRoundFunction
import DES.IRoundKeysGenerator

class RijndaelEncryptionAndDecryption(

    private val roundFunction: IRoundFunction<ByteArray>,
    private val roundKeysGenerator: IRoundKeysGenerator<ByteArray, ArrayList<ByteArray>>,
    private val key: ByteArray,
    private val roundCount: Int

): IEncryptionAndDecryption<ByteArray> {

    private var roundKeys = ArrayList<ByteArray>()

    override suspend fun encryptionAlgorithm(enBlock: ByteArray): ByteArray {

        setRoundKeys(key)

        var temp = enBlock
        temp = ByteArray (temp.size) { i -> (temp[i].toInt() xor roundKeys[0][i].toInt()).toByte() }

        for (i in 0 until roundCount - 1) {

            temp = roundFunction.encryptionTransformation(temp, roundKeys[i + 1])

        }

        return roundFunction.lastEncryptionTransformation(temp, roundKeys[roundCount])

    }

    override suspend fun decryptionAlgorithm(deBlock: ByteArray): ByteArray {

        setRoundKeys(key)

        var temp = deBlock
        temp = ByteArray (temp.size) { i -> (temp[i].toInt() xor roundKeys[roundCount][i].toInt()).toByte() }

        for (i in roundCount - 1 downTo 1) {

            temp = roundFunction.decryptionTransformation(temp, roundKeys[i])

        }

        return roundFunction.lastDecryptionTransformation(temp, roundKeys[0])

    }

    override suspend fun setRoundKeys(key: ByteArray) {

        roundKeys = roundKeysGenerator.rKeysGenerator(key)

    }

}