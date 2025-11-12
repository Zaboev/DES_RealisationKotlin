package DES
import Enums.*

class RoundKeysGenerator(private val endian: Endian, private val indexBase: IndexBase): IRoundKeysGenerator {

    override suspend fun rKeysGenerator(entryKey: ByteArray): ArrayList<ByteArray> {

        val permutationChoice1: IntArray = intArrayOf(
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55 ,47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        )
        val permutationChoice2: IntArray = intArrayOf(
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        )

        val roundKeys = ArrayList<ByteArray>()

        fun leftCircularShift(round: Int, key: ByteArray): ByteArray { // From AI

            val bit = if (round in listOf(1,2,9,16)) 1 else 2

            val fullBits = when (endian) {

                Endian.BIG_ENDIAN -> key.fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 0xFF) }
                Endian.LTL_ENDIAN -> key.reversed().fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 0xFF) }

            }

            val mask28 = (1L shl 28) - 1
            val left = (fullBits shr 28) and mask28
            val right = fullBits and mask28

            fun rotateLeft28(value: Long): Long{

                return ((value shl bit) or (value shr (28 - bit))) and mask28

            }

            val leftShifted = rotateLeft28(left)
            val rightShifted = rotateLeft28(right)

            val merged = (leftShifted shl 28) or rightShifted

            val result = ByteArray(7)
            for (i in 0 until 7) {

                val shift = when (endian) {

                    Endian.BIG_ENDIAN -> (48 - i * 8)
                    Endian.LTL_ENDIAN -> (i * 8)

                }

                result[i] = ((merged shr shift) and 0xFF).toByte()

            }

            return result

        }


        val keyPC1 = bitSwap(entryKey, permutationChoice1, endian, indexBase)

        var nextRoundKey = keyPC1

        for(round in 1 .. 16) {

            nextRoundKey = leftCircularShift(round, nextRoundKey)
            roundKeys.add(bitSwap(nextRoundKey, permutationChoice2, endian, indexBase))

        }

        return roundKeys

    }

}