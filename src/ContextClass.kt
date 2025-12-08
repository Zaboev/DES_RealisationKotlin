import DEAL.*
import DES.*
import TripleDES.*
import Rijndael.*
import kotlinx.coroutines.*
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import Enums.*
import Modes.Modes
import Padding.*

class ContextCypherAlgorithm (

    private val algorithm: Algorithm,
    private val encryptionKey: ByteArray,
    private val mode: EncryptionMode,
    private val paddingType: Padding,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private val randomDelta: ByteArray = byteArrayOf(0,0,0,0,0,0,0,0),
    private val vectorInit: ByteArray = byteArrayOf(0,0,0,0,0,0,0,0),
    private val rijndaelBlockSize: RijndaelBlockSize = RijndaelBlockSize.r128

) {

    private var desObject: FeistelStructure? = null
    private var dealObject: DealEncryptionAndDecryption? = null
    private var tripleDesObject: TripleDesEncryptionAndDecryption? = null
    private var rijndaelObject: RijndaelEncryptionAndDecryption? = null

    init {

        when (algorithm) {

            Algorithm.DES -> {

                val roundKeys = RoundKeysGenerator(endian, indexBase)
                val roundFunction = RoundFunction(endian, indexBase)
                desObject = FeistelStructure(roundFunction, roundKeys, endian, indexBase, encryptionKey)

            }
            Algorithm.DEAL -> {

                val fixedKey = "0123456789abcdef".chunked(2).map{ it.toInt(16).toByte() }.toByteArray()
                val roundKeys = RoundKeysGenerator(endian, indexBase)
                val roundFunction = RoundFunction(endian, indexBase)
                val desObject = FeistelStructure(roundFunction, roundKeys, endian, indexBase, fixedKey)
                val keyLength = when (encryptionKey.size) {

                    16 -> KeyLength.k128
                    24 -> KeyLength.k192
                    32 -> KeyLength.k256
                    else -> throw Exception("Invalid key length size, key should be 16 byte, 24 byte or 32 byte")

                }

                val dealRoundKeys = DealRoundKeysGenerator(encryptionKey, keyLength, desObject)
                val dealRoundFunction = DealRoundFunction(endian, indexBase)
                dealObject = DealEncryptionAndDecryption(dealRoundFunction, dealRoundKeys, keyLength)

            }
            Algorithm.TripleDes -> {

               val tripleDesMode = when (encryptionKey.size) {

                    8 -> TripleDesMode.oneKey
                    16 -> TripleDesMode.twoKeys
                    24 -> TripleDesMode.threeKeys
                    else -> throw Exception("Invalid key length size, key should be 8 byte, 16 byte or 24 byte")

                }

                tripleDesObject = TripleDesEncryptionAndDecryption(encryptionKey, endian, indexBase, tripleDesMode)

            }
            Algorithm.Rijndael -> {

                val keySize = if (encryptionKey.size == 16 || encryptionKey.size == 24 || encryptionKey.size == 32) encryptionKey.size
                else throw Exception("Key size should be 16 || 24 || 32")

                val blockSize = when (rijndaelBlockSize) {

                    RijndaelBlockSize.r128 -> 16
                    RijndaelBlockSize.r192 -> 24
                    RijndaelBlockSize.r256 -> 32

                }

                val rijndaelRoundKeysGenerator = RijndaelRoundKeysGenerator(endian, keySize, blockSize)
                val rijndaelRoundFunction = RijndaelRoundFunction(endian)

                val roundCount = maxOf(keySize / 4, blockSize / 4) + 6

                rijndaelObject = RijndaelEncryptionAndDecryption(rijndaelRoundFunction, rijndaelRoundKeysGenerator, encryptionKey, roundCount)

            }

        }

    }

    private val blockCipherSize = when (algorithm) {

        Algorithm.DEAL -> 16
        Algorithm.DES -> 8
        Algorithm.TripleDes -> 8
        Algorithm.Rijndael -> {

            when (rijndaelBlockSize) {

                RijndaelBlockSize.r128 -> 16
                RijndaelBlockSize.r192 -> 24
                RijndaelBlockSize.r256 -> 32

            }

        }

        //Algorithm.IDEA -> 8

    }

    private fun isStreamMode() =
        mode == EncryptionMode.CFB ||
                mode == EncryptionMode.OFB ||
                mode == EncryptionMode.CTR ||
                mode == EncryptionMode.RandomDelta

    private suspend fun sending(blockForCFB: ByteArray, cipherOrDecipher: CipherOrDecipher, countForCTR_RandomDelta: Long, blockCipherSize: Int): ByteArray {

        val realSize = blockForCFB.size
        val block = if (realSize < blockCipherSize && isStreamMode()) {
            val full = ByteArray(blockCipherSize)
            blockForCFB.copyInto(full)
            full
        }
        else if (realSize < blockCipherSize && !isStreamMode()) {
            val padded = ByteArray(blockCipherSize)
            blockForCFB.copyInto(padded)
            padded
        }
        else blockForCFB

        val modeObject = Modes(block, blockForCFB, realSize, algorithm, mode, cipherOrDecipher, vectorInit,
            endian, randomDelta, countForCTR_RandomDelta, desObject, dealObject, tripleDesObject, rijndaelObject)

        return modeObject.modes()

    }

    fun cipherStart(input: String, output: String, cipherOrDecipher: CipherOrDecipher, threadCount: Int) = runBlocking {

        val dispatcher = Executors.newFixedThreadPool(threadCount).asCoroutineDispatcher()

        val _input = File(input)
        val _output = File(output)

        fileProcess(_input, _output, dispatcher, cipherOrDecipher)

        dispatcher.close()

    }

    private suspend fun fileProcess (
        input: File,
        output: File,
        dispatcher: CoroutineDispatcher,
        cipherOrDecipher: CipherOrDecipher
    ) = withContext(dispatcher) {

        try {

            var countForCTR_RandomDelta: Long = 0L
            val buffer = ByteArray(blockCipherSize)

            RandomAccessFile(input, "r").use { inFile ->

                RandomAccessFile(output, "rw").use { outFile ->

                    outFile.setLength(0L)

                    val inChannel = inFile.channel
                    val outChannel = outFile.channel

                    var totalBytesProcessed: Long = 0

                    var position = 0L

                    if (mode != EncryptionMode.ECB) {

                        while (true) {

                            val bytesRead = inChannel.read(ByteBuffer.wrap(buffer))
                            if (bytesRead == -1) break

                            var chunk = buffer.copyOf(bytesRead)

                            if (bytesRead < blockCipherSize && (mode == EncryptionMode.CBC || mode == EncryptionMode.PCBC)) {

                                chunk = paddingAdd(chunk, paddingType, blockCipherSize)

                                val processed = sending(chunk, cipherOrDecipher, countForCTR_RandomDelta, blockCipherSize)
                                outChannel.write(ByteBuffer.wrap(processed))

                            } else {

                                if (bytesRead < blockCipherSize && !isStreamMode()) chunk += ByteArray(blockCipherSize - bytesRead) { 0 }
                                val processed = sending(chunk, cipherOrDecipher, countForCTR_RandomDelta, blockCipherSize)

                                countForCTR_RandomDelta++

                                if (isStreamMode()) outChannel.write(ByteBuffer.wrap(processed, 0, bytesRead))
                                else outChannel.write(ByteBuffer.wrap(processed))

                            }

                            position += bytesRead
                            totalBytesProcessed += bytesRead

                        }

                        if (cipherOrDecipher == CipherOrDecipher.Decryption && isStreamMode()) outFile.setLength(
                            totalBytesProcessed
                        )


                    }
                    else {

                        val jobs = mutableListOf<Deferred<Triple<Long, ByteArray, Int>>>()

                        while (true) {

                            val bytesRead = inChannel.read(ByteBuffer.wrap(buffer))
                            if (bytesRead == -1) break

                            var chunk = buffer.copyOf(bytesRead)
                            val pos = position

                            if (bytesRead < blockCipherSize) chunk = paddingAdd(chunk, paddingType, blockCipherSize)
                            else chunk += ByteArray(blockCipherSize - bytesRead) { 0 }

                            val job = async(dispatcher) {

                                val processed = sending(chunk, cipherOrDecipher, countForCTR_RandomDelta, blockCipherSize)
                                Triple(pos, processed, bytesRead)

                            }

                            jobs.add(job)
                            position += bytesRead

                        }

                        val results = jobs.awaitAll().sortedBy { it.first }

                        for ((_, bytes, originalSize) in results) {

                            if (originalSize < blockCipherSize && isStreamMode())
                                outChannel.write(ByteBuffer.wrap(bytes, 0, originalSize))
                            else
                                outChannel.write(ByteBuffer.wrap(bytes))

                        }

                    }

                }

            }

            countForCTR_RandomDelta = 0L

            if (cipherOrDecipher == CipherOrDecipher.Decryption && !isStreamMode()) {

                RandomAccessFile(output, "rw").use { raf ->
                    if (raf.length() >= 0L) {
                        val data = ByteArray(raf.length().toInt())
                        raf.seek(0)
                        raf.readFully(data)

                        val dePadded = paddingRemove(data, paddingType, blockCipherSize)

                        if (dePadded.size < data.size) {
                            raf.setLength(0)
                            raf.seek(0)
                            raf.write(dePadded)
                        }
                    }
                }

            }
        }
        catch(e: Exception) {

            e.printStackTrace()
            e.stackTrace.forEach { println(it.toString()) }
            throw e
        }

    }

}

