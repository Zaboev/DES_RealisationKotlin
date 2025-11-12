package DES
import Enums.*

class FeistelStructure(
    private val objectRF: IRoundFunction,
    private val keyGenerator: IRoundKeysGenerator,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private val entryKey: ByteArray
): IEncrDecr {

    private val initialPermutation = intArrayOf (

        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7

    )

    private val inverseInitialPermutation = intArrayOf (

        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25

    )

    private var roundKeys = ArrayList<ByteArray>(16)

    private suspend fun xor (left: ByteArray, keyedRight: ByteArray): ByteArray {

        return ByteArray(4) {i ->

            (left[i].toInt() xor keyedRight[i].toInt()).toByte()

        }

    }

    override suspend fun encryptionAlgorithm(enBlock: ByteArray): ByteArray {

        setRoundKeys(entryKey)

        val initialBlock = bitSwap(enBlock, initialPermutation, endian, indexBase)
        var cipheredBlock = initialBlock

        for (round in 1 .. 16) {

            val leftBytes = cipheredBlock.copyOfRange(0, 4)
            val rightBytes = cipheredBlock.copyOfRange(4, 8)

            val funFBlock = objectRF.encryptionTransformation(rightBytes, roundKeys[round - 1])

            val xored = xor(leftBytes, funFBlock)

            cipheredBlock = rightBytes + xored

        }

        val swapped = cipheredBlock.copyOfRange(4, 8) + cipheredBlock.copyOfRange(0, 4)

        return bitSwap(swapped, inverseInitialPermutation, endian, indexBase)

    }

    override suspend fun decryptionAlgorithm(deBlock: ByteArray): ByteArray {

        setRoundKeys(entryKey)

        val initialBlock = bitSwap(deBlock, initialPermutation, endian, indexBase)
        var cipheredBlock = initialBlock

        for (round in 16 downTo 1) {

            val leftBytes = cipheredBlock.copyOfRange(0, 4)
            val rightBytes = cipheredBlock.copyOfRange(4, 8)

            val funFBlock = objectRF.encryptionTransformation(rightBytes, roundKeys[round - 1])

            val xored = xor(leftBytes, funFBlock)

            cipheredBlock = rightBytes + xored

        }

        val swapped = cipheredBlock.copyOfRange(4, 8) + cipheredBlock.copyOfRange(0, 4)

        return bitSwap(swapped, inverseInitialPermutation, endian, indexBase)

    }

    override suspend fun setRoundKeys(key: ByteArray) {

        roundKeys = keyGenerator.rKeysGenerator(entryKey)

    }

}