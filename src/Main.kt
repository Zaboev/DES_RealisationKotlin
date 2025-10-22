import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import java.util.concurrent.atomic.AtomicInteger
import kotlin.contracts.Returns


enum class Endian {

    BIG_ENDIAN,
    LTL_ENDIAN

} //to bitSwap done

enum class IndexBase {

    ZERO_INDEX,
    ONE_INDEX

} //to bitSwap done

suspend fun bitSwap(block: ByteArray, ruleSwap: IntArray, endian: Endian, indexBase: IndexBase) : ByteArray {

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

        return if ((b and mask) != 1) 1 else 0

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

} //Done

enum class Padding {

    Zeros,
    ANSI_X923,
    PKCS7,
    ISO10126

} //to CypherAlgorithm

enum class EncryptionMode {

    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RandomDelta

} //to CypherAlgorithm

interface IRoundKeysGenerator {

    suspend fun rKeysGenerator(entryKey: ByteArray): ArrayList<ByteArray>

} //Done

interface IFeistelStructure {

    suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray

} //Done

interface IEncrDecr {

    suspend fun encryptionAlgorithm(enBlock: ByteArray, inputFile: String, outputFile: String)

    suspend fun decryptionAlgorithm(deBlock: ByteArray, inputFile: String, outputFile: String)

    suspend fun setRoundKeys(key: ByteArray)

} //Done

class CypherAlgorithm(

    private val encryptionKey: ByteArray,
    private val mode: EncryptionMode,
    private val paddingType: Padding,
    private val vectorInit: ByteArray? = null,
    private val endian: Endian,
    private val indexBase: IndexBase,
    vararg extraParams: Any // Исправить

) : IEncrDecr {

    override suspend fun encryptionAlgorithm(enBlock: ByteArray, inputFile: String, outputFile: String){

        when(mode){

            EncryptionMode.ECB -> 
            EncryptionMode.CBC -> return
            EncryptionMode.PCBC -> return
            EncryptionMode.CFB -> return
            EncryptionMode.OFB -> return
            EncryptionMode.CTR -> return
            EncryptionMode.RandomDelta -> return

        }

    }

    override suspend fun decryptionAlgorithm(deBlock: ByteArray, inputFile: String, outputFile: String) {

        val i = 0

    }

    override suspend fun setRoundKeys(key: ByteArray) {

        val roundKeysObject = RoundKeysGenerator(endian, indexBase)
        val roundKeys = roundKeysObject.rKeysGenerator(key)

    }

}

class RoundKeysGenerator(private val endian: Endian, private val indexBase: IndexBase): IRoundKeysGenerator{

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

            val bit = if (round in listOf(1,2,9,16)) 1 else 0

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

class FeistelStructure(private val objectFS: IFeistelStructure, private val keyGenerator: IRoundKeysGenerator)