package DEAL
import DES.*
import Enums.Endian
import Enums.IndexBase

class DealRoundFunction (
    private val endian: Endian,
    private val indexBase: IndexBase,
) : IRoundFunction {

    private fun desInit(): FeistelStructure {

        val roundKeys = RoundKeysGenerator(endian, indexBase)
        val roundFunction = RoundFunction(endian, indexBase)
        return FeistelStructure(roundFunction, roundKeys, endian, indexBase, byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0))

    }

    override suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray): ByteArray {

        val desObject = desInit()

        desObject.entryKey = roundKey

        val left = ByteArray(8) { i -> block[i] }
        val right = ByteArray(8) { i -> block[i + 8] }

        val newLeft = left

        val fLeft = desObject.encryptionAlgorithm(left)

        val newRight = ByteArray(8) { i ->

            ((fLeft[i].toInt() xor right[i].toInt()).toByte())

        }

        val result = newRight + newLeft

        return result

    }


}