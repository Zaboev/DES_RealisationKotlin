import kotlinx.coroutines.*
import java.io.File
import java.util.concurrent.Executors
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom


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

enum class CipherOrDecipher {

    Decryption,
    Encryption

}

interface IRoundKeysGenerator {

    suspend fun rKeysGenerator(entryKey: ByteArray): ArrayList<ByteArray>

} //Done

interface IRoundFunction {

    suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray

} //Done

interface IEncrDecr {

    suspend fun encryptionAlgorithm(enBlock: ByteArray): ByteArray

    suspend fun decryptionAlgorithm(deBlock: ByteArray): ByteArray

    suspend fun setRoundKeys(key: ByteArray)

} //Done

class ContextCypherAlgorithm(

    private val encryptionKey: ByteArray,
    private val mode: EncryptionMode,
    private val paddingType: Padding,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private var randomDelta: ByteArray = byteArrayOf(0,0,0,0,0,0,0,0),
    private var vectorInit: ByteArray = byteArrayOf(0,0,0,0,0,0,0,0)

) {

    private var cBlock = vectorInit
    private var pBlock = ByteArray(8)
    private var isFirst = true
    private var shiftRegister = vectorInit
    private var stream = vectorInit

    fun cipherStart(input: String, output: String, cipherOrDecipher: CipherOrDecipher, threadCount: Int) = runBlocking {

        val dispatcher = Executors.newFixedThreadPool(threadCount).asCoroutineDispatcher()

        val _input = File(input)
        val _output = File(output)

        fileProcess(_input, _output, dispatcher, cipherOrDecipher)

        dispatcher.close()

    }

    private var countForCTR_RandomDelta: Long = 0

    private suspend fun fileProcess (
        input: File,
        output: File,
        dispatcher: CoroutineDispatcher,
        cipherOrDecipher: CipherOrDecipher
    ) = withContext(dispatcher) {

        isFirst = true
        cBlock = vectorInit.copyOf()
        pBlock = ByteArray(8)
        shiftRegister = vectorInit.copyOf()
        stream = vectorInit.copyOf()

        val buffer = ByteArray(8)

        fun isStreamMode() =
            mode == EncryptionMode.CFB ||
                    mode == EncryptionMode.OFB ||
                    mode == EncryptionMode.CTR ||
                    mode == EncryptionMode.RandomDelta

        RandomAccessFile(input, "r").use { inFile ->

            RandomAccessFile(output, "rw").use { outFile ->

                val inChannel = inFile.channel
                val outChannel = outFile.channel

                var position = 0L

                if (mode != EncryptionMode.ECB) {

                    while (true) {

                        val bytesRead = inChannel.read(ByteBuffer.wrap(buffer))
                        if (bytesRead == -1) break

                        var chunk = buffer.copyOf(bytesRead)

                        if (bytesRead < 8 && (mode == EncryptionMode.CBC || mode == EncryptionMode.PCBC)) {

                            chunk = paddingAdd(chunk)
                            val processed = enDeCryption(chunk, cipherOrDecipher)
                            outChannel.write(ByteBuffer.wrap(processed))

                        }

                        else {

                            if (bytesRead < 8 && !isStreamMode()) chunk += ByteArray(8 - bytesRead) { 0 }
                            val processed = enDeCryption(chunk, cipherOrDecipher)

                            if (isStreamMode()) {
                                println("WRITE stream block: bytesRead=$bytesRead processed.size=${processed.size}")
                                outChannel.write(ByteBuffer.wrap(processed, 0, bytesRead))
                            }
                            else {
                                println("WRITE stream block: bytesRead=$bytesRead processed.size=${processed.size}")
                                outChannel.write(ByteBuffer.wrap(processed))
                            }

                        }

                        position += bytesRead

                    }

                }
                else {

                    val jobs = mutableListOf<Deferred<Triple<Long, ByteArray, Int>>>()

                    while (true) {

                        val bytesRead = inChannel.read(ByteBuffer.wrap(buffer))
                        if (bytesRead == -1) break

                        var chunk = buffer.copyOf(bytesRead)
                        val pos = position

                        if (bytesRead < 8) chunk = paddingAdd(chunk)

                        else chunk += ByteArray(8 - bytesRead) { 0 }

                        val job = async(dispatcher) {

                            val processed = enDeCryption(chunk, cipherOrDecipher, countForCTR_RandomDelta, randomDelta)
                            Triple(pos, processed, bytesRead)

                        }

                        countForCTR_RandomDelta++
                        jobs.add(job)
                        position += bytesRead

                    }

                    val results = jobs.awaitAll().sortedBy { it.first }

                    for ((_, bytes, originalSize) in results) {

                        if (originalSize < 8 && isStreamMode())
                            outChannel.write(ByteBuffer.wrap(bytes, 0, originalSize))
                        else
                            outChannel.write(ByteBuffer.wrap(bytes))

                    }

                }

            }

        }

        if (cipherOrDecipher == CipherOrDecipher.Decryption && !isStreamMode()) {

            RandomAccessFile(output, "rw").use { raf ->
                    if (raf.length() >= 0L) {
                        // читаем весь файл
                        val data = ByteArray(raf.length().toInt())
                        raf.seek(0)
                        raf.readFully(data)

                        // вызываем removePadding, если паддинг не Zeros
                        val dePadded = paddingRemove(data)

                        // если длина изменилась — перезаписываем файл
                        if (dePadded.size < data.size) {
                            raf.setLength(0)
                            raf.seek(0)
                            raf.write(dePadded)
                        }
                    }
                }

        }

    }

    private fun paddingAdd(block: ByteArray): ByteArray {

        val paddingLength = 8 - (block.size.takeIf { it != 0 } ?: 8)

        return when (paddingType) {

            Padding.Zeros -> block + ByteArray(paddingLength) { 0 }
            Padding.ANSI_X923 -> block + ByteArray(paddingLength - 1) { 0 } + byteArrayOf(paddingLength.toByte())
            Padding.PKCS7 -> block + ByteArray(paddingLength) { paddingLength.toByte() }
            Padding.ISO10126 -> {

                val random = SecureRandom()
                val randomBytes = ByteArray(paddingLength - 1).also { random.nextBytes(it) }
                block + randomBytes + byteArrayOf(paddingLength.toByte())

            }

        }

    }

    private fun paddingRemove(block: ByteArray): ByteArray {

        return when (paddingType) {

            Padding.Zeros -> block.dropLastWhile { it == 0.toByte() }.toByteArray()
            else -> {

                val last = block.last().toInt() and 0xFF

                if (last < 1 || last > 8) return block

                if (last > block.size) return block
                block.dropLast(last).toByteArray()

            }

        }

    }

    private fun objectCreating(): FeistelStructure {

        val roundKeys = RoundKeysGenerator(endian, indexBase)
        val roundFunction = RoundFunction(endian, indexBase)
        return FeistelStructure(roundFunction, roundKeys, endian, indexBase, encryptionKey)

    }

    private fun shiftRegisterAppend(old: ByteArray, tail: ByteArray): ByteArray {

        val shift = tail.size
        val out = ByteArray(8)

        for (i in 0 until 8 - shift) out[i] = old[i + shift]

        for (j in 0 until shift) out[8 - shift + j] = tail[j]

        return out

    }

    private suspend fun enDeCryption(
        _block: ByteArray,
        cipherOrDecipher: CipherOrDecipher,
        counterForCTR_RandomDelta: Long = 0,
        randomDelta: ByteArray = ByteArray(8)
    ): ByteArray {

        val realSize = _block.size

        val block = if (_block.size < 8) {

            val padded = ByteArray(8)
            for (i in _block.indices) padded[i] = _block[i]
            padded

        }
        else _block

        val structureDeFeistel = objectCreating()

        return when (mode) {

            EncryptionMode.ECB -> {

                if (cipherOrDecipher == CipherOrDecipher.Encryption) structureDeFeistel.encryptionAlgorithm(block)
                else structureDeFeistel.decryptionAlgorithm(block)

            }

            EncryptionMode.CBC -> {

                if (cipherOrDecipher == CipherOrDecipher.Encryption) {

                    val newBlock = ByteArray(8) { i ->

                        (block[i].toInt() xor cBlock[i].toInt()).toByte()

                    }

                    cBlock = structureDeFeistel.encryptionAlgorithm(newBlock)
                    cBlock

                }
                else {

                    val outputBlock = structureDeFeistel.decryptionAlgorithm(block)

                    val result = ByteArray(8) { i -> (outputBlock[i].toInt() xor cBlock[i].toInt()).toByte() }

                    cBlock = block

                    result

                }

            }

            EncryptionMode.PCBC -> {

                if (cipherOrDecipher == CipherOrDecipher.Encryption) {

                    var newBlock = ByteArray(8)

                    if (isFirst) {

                        pBlock = block

                        newBlock = ByteArray(8) { i ->

                            (block[i].toInt() xor cBlock[i].toInt()).toByte()

                        }

                        isFirst = false

                    }
                    else {

                        newBlock = ByteArray(8) { i ->

                            (block[i].toInt() xor cBlock[i].toInt() xor pBlock[i].toInt()).toByte()

                        }

                        pBlock = block

                    }

                    cBlock = structureDeFeistel.encryptionAlgorithm(newBlock)
                    cBlock

                }
                else {

                    val newBlock = structureDeFeistel.decryptionAlgorithm(block)

                    if (isFirst) {

                        pBlock = ByteArray(8) { i -> (cBlock[i].toInt() xor newBlock[i].toInt()).toByte() }
                        cBlock = block
                        isFirst = false

                    }
                    else {

                        pBlock = ByteArray(8) { i-> (newBlock[i].toInt() xor cBlock[i].toInt() xor pBlock[i].toInt()).toByte() }
                        cBlock = block

                    }

                    pBlock
                }

            }

            EncryptionMode.CFB -> {

                val enShiftRegister = structureDeFeistel.encryptionAlgorithm(shiftRegister)
                if (cipherOrDecipher == CipherOrDecipher.Encryption) {

                    val cipherBytes = ByteArray(realSize) { i ->

                        (block[i].toInt() xor enShiftRegister[i].toInt()).toByte()

                    }

                    shiftRegister = if (realSize < 8) vectorInit.copyOf()
                    else shiftRegisterAppend(shiftRegister, cipherBytes)

                    cipherBytes

                }
                else {

                    val cipherInput = ByteArray(realSize) { i-> _block[i] }
                    val plainBytes = ByteArray(realSize) { i ->

                        (cipherInput[i].toInt() xor enShiftRegister[i].toInt()).toByte()

                    }

                    shiftRegister = if (realSize < 8) vectorInit.copyOf()
                    else shiftRegisterAppend(shiftRegister, cipherInput)

                    plainBytes
                }

            }

            EncryptionMode.OFB -> {

                stream = structureDeFeistel.encryptionAlgorithm(stream)
                ByteArray(8) { i ->

                    (block[i].toInt() xor stream[i].toInt()).toByte()

                }

            }

            EncryptionMode.CTR -> {

                val counterBlock = shiftRegister.copyOf()

                val counterBytes = ByteBuffer
                    .allocate(8)
                    .order(if (endian == Endian.BIG_ENDIAN) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN)
                    .putLong(counterForCTR_RandomDelta)
                    .array()

                for (i in 0 until 8) counterBlock[i] = (counterBlock[i].toInt() xor counterBytes[i].toInt()).toByte()

                val outputBlock = structureDeFeistel.encryptionAlgorithm(counterBlock)

                ByteArray(8) { i -> (block[i].toInt() xor outputBlock[i].toInt()).toByte()}

            }

            EncryptionMode.RandomDelta -> {

                val localIV = shiftRegister.copyOf()

                val delta = ByteArray(8)
                val counterBytes = ByteBuffer
                    .allocate(8)
                    .order(if (endian == Endian.BIG_ENDIAN) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN)
                    .putLong(counterForCTR_RandomDelta)
                    .array()

                val RD = randomDelta

                for (i in 0 until 8) delta[i] = (localIV[i].toInt() xor (RD[i].toInt() * counterBytes[i].toInt())).toByte()

                val outputBlock = structureDeFeistel.encryptionAlgorithm(delta)

                ByteArray(8) { i -> (block[i].toInt() xor outputBlock[i].toInt()).toByte() }

            }
        }

    }

}

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

class RoundFunction(private val endian: Endian, private val indexBase: IndexBase) : IRoundFunction {

    private val expansionPermutation: IntArray = intArrayOf (
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    )

    private val sBoxes = arrayOf (

        arrayOf (  // S1
            intArrayOf(14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
            intArrayOf(0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
            intArrayOf(4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
            intArrayOf(15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)
        ),
        arrayOf (  // S2
            intArrayOf(15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
            intArrayOf(3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
            intArrayOf(0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
            intArrayOf(13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)
        ),
        arrayOf (  // S3
            intArrayOf(10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
            intArrayOf(13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
            intArrayOf(13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
            intArrayOf(1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)
        ),
        arrayOf (  // S4
            intArrayOf(7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
            intArrayOf(13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
            intArrayOf(10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
            intArrayOf(3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)
        ),
        arrayOf (  // S5
            intArrayOf(2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9),
            intArrayOf(14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6),
            intArrayOf(4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14),
            intArrayOf(11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3)
        ),
        arrayOf (  // S6
            intArrayOf(12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11),
            intArrayOf(10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8),
            intArrayOf(9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6),
            intArrayOf(4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13)
        ),
        arrayOf (  // S7
            intArrayOf(4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1),
            intArrayOf(13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6),
            intArrayOf(1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2),
            intArrayOf(6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12)
        ),
        arrayOf (  // S8
            intArrayOf(13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7),
            intArrayOf(1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2),
            intArrayOf(7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8),
            intArrayOf(2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)
        )

    ) // Доспейсить

    private val transposition: IntArray = intArrayOf (

        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25

    )

    private suspend fun sBoxesPermutation(input48: ByteArray): ByteArray {

        val bits = input48.flatMap { byte ->

            (0..7).map { bitIndex ->

                val shift = when (endian) {

                    Endian.BIG_ENDIAN -> 7 - bitIndex
                    Endian.LTL_ENDIAN -> bitIndex

                }

                (byte.toInt() shr shift) and 1

            }

        }

        val outputBits = mutableListOf<Int>()
        for (i in 0 until 8) {

            var block = bits.slice(i * 6 until (i + 1) * 6)

            if (endian == Endian.LTL_ENDIAN) block = block.reversed()

            val row = (block[0] shl 1) or block[5]
            val col = (block[1] shl 3) or (block[2] shl 2) or (block[3] shl 1) or block[4]
            val sValue = sBoxes[i][row][col]

            for (bit in 3 downTo 0) {

                outputBits.add((sValue shr bit) and 1)

            }

        }

        val output = ByteArray(4)
        for (i in output.indices) {

            var value = 0
            for (bit in 0 until 8) {

                value = (value shl 1) or outputBits[i * 8 + bit]

            }
            output[i] = value.toByte()

        }

        return output

    } // From AI

    private suspend fun xor (block48: ByteArray, roundKey: ByteArray): ByteArray {

        return ByteArray(6) {i ->

            (block48[i].toInt() xor roundKey[i].toInt()).toByte()

        }

    }

    override suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray): ByteArray {

        val block48 = bitSwap(block, expansionPermutation, endian, indexBase)
        val keyedBlock48 = xor(block48, roundKey)
        val sBoxedBlock32 = sBoxesPermutation(keyedBlock48)
        return bitSwap(sBoxedBlock32, transposition, endian, indexBase)

    }

}

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

fun main() {

    for (i in 1 .. 4) {

        var padding: Padding = Padding.Zeros

        when (i) {

            1 -> padding = Padding.PKCS7
            2 -> padding = Padding.ISO10126
            3 -> padding = Padding.ANSI_X923
            4 -> padding = Padding.Zeros

        }

        val obj = ContextCypherAlgorithm(
            byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8),
            EncryptionMode.CFB, // ECB, CBC, PCBC, OFB, CFB, RandomDelta, CTR
            padding,
            Endian.BIG_ENDIAN,
            IndexBase.ONE_INDEX,
            byteArrayOf(8, 7, 6, 5, 4, 3, 2, 1),
            byteArrayOf(2, 4, 6, 8, 1, 3, 5, 7)
        )

        obj.cipherStart(
            "C:\\Users\\Zaboev\\Desktop\\ExamplesForDES\\text.txt",
            "C:\\Users\\Zaboev\\Desktop\\ExamplesForDES\\cipheredWith${padding.toString()}.txt",
            CipherOrDecipher.Encryption,
            5
        )

        obj.cipherStart(
            "C:\\Users\\Zaboev\\Desktop\\ExamplesForDES\\cipheredWith${padding.toString()}.txt",
            "C:\\Users\\Zaboev\\Desktop\\ExamplesForDES\\deCipheredWith${padding.toString()}.txt",
            CipherOrDecipher.Decryption,
            5
        )
    }

    // private val encryptionKey: ByteArray,
    //    private val mode: EncryptionMode,
    //    private val paddingType: Padding,
    //    private val vectorInit: ByteArray,
    //    private val endian: Endian,
    //    private val indexBase: IndexBase,
    //    private val randomDelta: ByteArray

}