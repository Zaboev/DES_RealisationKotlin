package DEAL
import DES.*
import Enums.Endian
import Enums.IndexBase

class DealRoundFunction (
    private val endian: Endian,
    private val indexBase: IndexBase,
) : IRoundFunction {

    private var desObject: FeistelStructure? = null

    init {

        val roundKeys = RoundKeysGenerator(endian, indexBase)
        val roundFunction = RoundFunction(endian, indexBase)
        desObject = FeistelStructure(roundFunction, roundKeys, endian, indexBase, byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0))

    }

    override suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray): ByteArray {

        desObject!!.entryKey = roundKey

        val left = ByteArray(8) { i -> block[i] }
        val right = ByteArray(8) { i -> block[i + 8] }

        val fRight = desObject!!.encryptionAlgorithm(right)

        val newRight = ByteArray(8) { i ->

            ((left[i].toInt() xor fRight[i].toInt()).toByte())

        }

        val result = right + newRight

        return result

    }

}