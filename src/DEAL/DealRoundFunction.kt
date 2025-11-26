package DEAL
import DES.*
import DesContext
import Enums.CipherOrDecipher
import Enums.EncryptionMode
import Enums.Endian
import Enums.IndexBase

class DealRoundFunction (
    private val endian: Endian,
    private val indexBase: IndexBase,
) : IRoundFunction {

    override suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray): ByteArray {

        val roundKeys = RoundKeysGenerator(endian, indexBase)
        val roundFunction = RoundFunction(endian, indexBase)
        val desObject = FeistelStructure(roundFunction, roundKeys, endian, indexBase, roundKey)

        val tempLeft = ByteArray(8) { i -> block[i] }
        val oldRight = ByteArray(8) { i -> block[i + 8] }

        val tempRight = desObject.encryptionAlgorithm(oldRight)

        val rightBlock = ByteArray(8) { i ->

            ((tempLeft[i].toInt() xor tempRight[i].toInt()).toByte())

        }

        val result = oldRight + rightBlock

        return result

    }

}