import DEAL.DealEncryptionAndDecryption
import DEAL.DealRoundFunction
import DEAL.DealRoundKeysGenerator
import DEAL.KeyLength
import DES.FeistelStructure
import DES.IEncrDecr
import DES.RoundFunction
import DES.RoundKeysGenerator
import kotlinx.coroutines.*
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import Enums.*
import Modes.Modes
import Padding.*
import TripleDES.TripleDesEncryptionAndDecryption
import TripleDES.TripleDesMode

class ContextCypherAlgorithm (

    private val algorithm: Algorithm,
    private val encryptionKey: ByteArray,
    private val mode: EncryptionMode,
    private val paddingType: Padding,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private val randomDelta: ByteArray = byteArrayOf(0,0,0,0,0,0,0,0),
    private val vectorInit: ByteArray = byteArrayOf(0,0,0,0,0,0,0,0)

) {

    private var desObject: FeistelStructure? = null
    private var dealObject: DealEncryptionAndDecryption? = null
    private var tripleDesObject: TripleDesEncryptionAndDecryption? = null
    //private var rijndaelObject: RijndaelEncryptionAndDecryption? = null

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
                val dealRoundFunction = DealRoundFunction(mode, endian, indexBase, randomDelta, vectorInit)
                dealObject = DealEncryptionAndDecryption(dealRoundFunction, dealRoundKeys, keyLength)

            }
            Algorithm.TripleDes -> {

                val tripleDesMode = when (encryptionKey.size) {

                    8 -> TripleDesMode.oneKey
                    16 -> TripleDesMode.twoKeys
                    24 -> TripleDesMode.threeKeys
                    else -> throw Exception("Invalid key length size, key should be 8 byte, 16 byte or 24 byte")

                }
                TripleDesEncryptionAndDecryption(encryptionKey, mode, paddingType, endian, indexBase, randomDelta, vectorInit, tripleDesMode)

            }

        }

    }

    private val blockCipherSize = when (algorithm) {

        Algorithm.DEAL -> 16
        Algorithm.DES -> 8
        Algorithm.TripleDes -> 8
        /*Algorithm.Rijndael -> {

            when (blockSizeRijndael) {

                RijndaelBlockSize.r128 -> 128
                RijndaelBlockSize.r192 -> 192
                RijndaelBlockSize.r256 -> 256*/

        }


    suspend fun sender(chunk: ByteArray, cipherOrDecipher: CipherOrDecipher, countForCTR_RandomDelta: Long): ByteArray {

        return when (algorithm) {

            Algorithm.DES -> {

                val realSize = chunk.size
                val newChunk = if (realSize < 8 && isStreamMode()) {
                    val full = ByteArray(8)
                    chunk.copyInto(full)
                    full
                }
                else if (realSize < 8 && !isStreamMode()) {
                    val padded = ByteArray(8)
                    chunk.copyInto(padded)
                    padded
                }
                else chunk

                val modesObj = Modes(newChunk, mode, cipherOrDecipher, desObject!!, vectorInit, realSize, endian, chunk, randomDelta, countForCTR_RandomDelta)
                return modesObj.modes()

            }
            Algorithm.DEAL -> { chunk

                //if (cipherOrDecipher == CipherOrDecipher.Encryption) dealContext.encryptionAlgorithm(chunk)
                //else dealContext.decryptionAlgorithm(chunk)

            }
            Algorithm.TripleDes -> {

                if (cipherOrDecipher == CipherOrDecipher.Encryption) tripleDesObject!!.encryptionAlgorithm(chunk)
                else tripleDesObject!!.decryptionAlgorithm(chunk)

            }

        }

    }

    private fun isStreamMode() =
        mode == EncryptionMode.CFB ||
                mode == EncryptionMode.OFB ||
                mode == EncryptionMode.CTR ||
                mode == EncryptionMode.RandomDelta

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

            val buffer = ByteArray(blockCipherSize)
            var countForCTR_RandomDelta: Long = 0L

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
                                val processed = sender(chunk, cipherOrDecipher, countForCTR_RandomDelta)
                                outChannel.write(ByteBuffer.wrap(processed))

                            }
                            else {

                                if (bytesRead < blockCipherSize && !isStreamMode()) chunk += ByteArray(blockCipherSize - bytesRead) { 0 }
                                val processed = sender(chunk, cipherOrDecipher, countForCTR_RandomDelta)

                                if (isStreamMode()) outChannel.write(ByteBuffer.wrap(processed, 0, bytesRead))
                                else outChannel.write(ByteBuffer.wrap(processed))

                            }

                            position += bytesRead
                            totalBytesProcessed += bytesRead

                        }

                        if (cipherOrDecipher == CipherOrDecipher.Decryption && isStreamMode()) outFile.setLength(
                            totalBytesProcessed
                        )


                    } else {

                        val jobs = mutableListOf<Deferred<Triple<Long, ByteArray, Int>>>()

                        while (true) {

                            val bytesRead = inChannel.read(ByteBuffer.wrap(buffer))
                            if (bytesRead == -1) break

                            var chunk = buffer.copyOf(bytesRead)
                            val pos = position

                            if (bytesRead < blockCipherSize) chunk = paddingAdd(chunk, paddingType, blockCipherSize)
                            else chunk += ByteArray(blockCipherSize - bytesRead) { 0 }

                            val job = async(dispatcher) {

                                val processed = sender(chunk, cipherOrDecipher, countForCTR_RandomDelta)
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

                    countForCTR_RandomDelta++
                    if (tripleDesObject != null) tripleDesObject!!.countForCTR_RandomDelta++

                }

            }

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

            countForCTR_RandomDelta = 0L
            if (tripleDesObject != null) tripleDesObject!!.countForCTR_RandomDelta = 0L

        }
        catch(e: Exception) {

            e.printStackTrace()
            e.stackTrace.forEach { println(it.toString()) }
            throw e

        }
    }

}