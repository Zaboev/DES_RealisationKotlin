package Rijndael
import DES.IEncryptionAndDecryption
import DES.IRoundFunction
import DES.IRoundKeysGenerator

class RijndaelEncryptionAndDecryption(

    private val roundFunction: IRoundFunction,
    private val roundKeysGenerator: IRoundKeysGenerator<ByteArray>,
    private val key: ByteArray,
    private val roundCount: Int

): IEncryptionAndDecryption<ByteArray> {

    private var roundKeys = ArrayList<ByteArray>()
    private var isCycleBegun = false

    override suspend fun encryptionAlgorithm(enBlock: ByteArray): ByteArray {

        setRoundKeys(key)

        var temp = enBlock
        if (!isCycleBegun) {

            temp = ByteArray (temp.size) { i ->

                (temp[i].toInt() xor roundKeys[0][i].toInt()).toByte()

            }
            isCycleBegun = true

        }

        for (i in 0 until roundCount - 1) {

            temp = roundFunction.encryptionTransformation(temp, roundKeys[i + 1])

        }
        isCycleBegun = false

        return roundFunction.lastEncryptionTransformation(temp, roundKeys[roundCount])

    }

    override suspend fun decryptionAlgorithm(deBlock: ByteArray): ByteArray {

        setRoundKeys(key)

        var temp = deBlock
        if (!isCycleBegun) {

            temp = ByteArray (temp.size) { i ->

                (temp[i].toInt() xor roundKeys[roundCount][i].toInt()).toByte()

            }
            isCycleBegun = true

        }

        for (i in roundCount - 1 downTo 1) {

            temp = roundFunction.decryptionTransformation(temp, roundKeys[i])

        }
        isCycleBegun = false

        return roundFunction.lastDecryptionTransformation(temp, roundKeys[0])

    }

    override suspend fun setRoundKeys(key: ByteArray) {

        roundKeys = roundKeysGenerator.rKeysGenerator(key)

    }

}