package DES
import Enums.*

fun bitSwap(block: ByteArray, ruleSwap: IntArray, endian: Endian, indexBase: IndexBase) : ByteArray {

    val bitCount = ruleSwap.size
    val byteCount = (bitCount + 7) / 8
    val outBlock = ByteArray(byteCount)

    fun getBit(ruleIndex: Int) : Int{

        val updatedRuleIndex = when(indexBase){

            IndexBase.ZERO_INDEX -> ruleIndex
            IndexBase.ONE_INDEX -> ruleIndex - 1

        }

        val byteIndexPosition = updatedRuleIndex / 8
        val bitPosition = updatedRuleIndex % 8

        val b = block[byteIndexPosition].toInt() and 0xFF

        val mask = when(endian){

            Endian.BIG_ENDIAN -> (1 shl (7 - bitPosition))
            Endian.LTL_ENDIAN -> (1 shl bitPosition)

        }

        return if ((b and mask) != 0) 1 else 0

    }

    fun setBit(outIndex: Int, bit: Int){

        if (bit == 0) return

        val byteIndexPosition = outIndex / 8
        val bitPosition = outIndex % 8

        val current = outBlock[byteIndexPosition].toInt() and 0xFF

        val mask = when(endian){

            Endian.BIG_ENDIAN -> (1 shl (7 - bitPosition))
            Endian.LTL_ENDIAN -> (1 shl bitPosition)

        }

        outBlock[byteIndexPosition] = ((current or mask) and 0xFF).toByte()

    }

    for (currentIndex in 0 until bitCount){

        val newBitPosition = ruleSwap[currentIndex]

        val bitValue = getBit(newBitPosition)

        setBit(currentIndex, bitValue)

    }

    return outBlock

}