import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import java.util.concurrent.atomic.AtomicInteger


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

        val byteIndexPosition = ruleIndex / 8
        val bitPosition = ruleIndex % 8

        val b = block[byteIndexPosition].toInt() and 0xFF

        val mask = when(endian){

            Endian.BIG_ENDIAN -> (1 shl bitPosition)
            Endian.LTL_ENDIAN -> (1 shl (7 - bitPosition))

        }

        return if ((b and mask) == 1) 1 else 0

    }

    fun setBit(outIndex: Int, bit: Int){

        if (bit == 0) return

        val byteIndexPosition = outIndex / 8
        val bitPosition = outIndex % 8

        val current = outBlock[byteIndexPosition].toInt() and 0xFF

        val mask = when(endian){

            Endian.BIG_ENDIAN -> (1 shl bitPosition)
            Endian.LTL_ENDIAN -> (1 shl (7 - bitPosition))

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

    suspend fun setRoundKeys(keys: ArrayList<ByteArray>)

} //Done

class CypherAlgorithm(

    encryptionKey: ByteArray,
    mode: EncryptionMode,
    paddingType: Padding,
    vectorInit: ByteArray? = null,
    vararg extraParams: Any // Исправить

) : IEncrDecr {

    override suspend fun encryptionAlgorithm(enBlock: ByteArray, inputFile: String, outputFile: String){

        val i = 0

    }

    override suspend fun decryptionAlgorithm(deBlock: ByteArray, inputFile: String, outputFile: String) {

        val i = 0

    }

    override suspend fun setRoundKeys(keys: ArrayList<ByteArray>) {

        val i = 0

    }

}

class FeistelStructure(objectFS: IFeistelStructure, objectED: IEncrDecr)