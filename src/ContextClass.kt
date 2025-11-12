import kotlinx.coroutines.*
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import Enums.*
import Padding.*

class ContextCypherAlgorithm(

    private val encryptionKey: ByteArray,
    private val mode: EncryptionMode,
    private val paddingType: Padding,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private var randomDelta: ByteArray = byteArrayOf(0,0,0,0,0,0,0,0),
    private var vectorInit: ByteArray = byteArrayOf(0,0,0,0,0,0,0,0),
    private val desContext: DesContext = DesContext(encryptionKey, mode, endian, indexBase, randomDelta, vectorInit)

) {

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

        desContext.isFirst = true
        desContext.cBlock = vectorInit.copyOf()
        desContext.pBlock = ByteArray(8)
        desContext.shiftRegister = vectorInit.copyOf()
        desContext.stream = vectorInit.copyOf()
        desContext.countForCTR_RandomDelta = 0

        val buffer = ByteArray(8)

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

                        if (bytesRead < 8 && (mode == EncryptionMode.CBC || mode == EncryptionMode.PCBC)) {

                            chunk = paddingAdd(chunk, paddingType)
                            val processed = desContext.enDeCryption(chunk, cipherOrDecipher)
                            outChannel.write(ByteBuffer.wrap(processed))

                        }

                        else {

                            if (bytesRead < 8 && !desContext.isStreamMode()) chunk += ByteArray(8 - bytesRead) { 0 }
                            val processed = desContext.enDeCryption(chunk, cipherOrDecipher)

                            if (desContext.isStreamMode()) outChannel.write(ByteBuffer.wrap(processed, 0, bytesRead))
                            else outChannel.write(ByteBuffer.wrap(processed))

                        }

                        position += bytesRead
                        totalBytesProcessed += bytesRead

                    }

                    if (cipherOrDecipher == CipherOrDecipher.Decryption && desContext.isStreamMode()) outFile.setLength(totalBytesProcessed)


                }
                else {

                    val jobs = mutableListOf<Deferred<Triple<Long, ByteArray, Int>>>()

                    while (true) {

                        val bytesRead = inChannel.read(ByteBuffer.wrap(buffer))
                        if (bytesRead == -1) break

                        var chunk = buffer.copyOf(bytesRead)
                        val pos = position

                        if (bytesRead < 8) chunk = paddingAdd(chunk, paddingType)

                        else chunk += ByteArray(8 - bytesRead) { 0 }

                        val job = async(dispatcher) {

                            val processed = desContext.enDeCryption(chunk, cipherOrDecipher, desContext.countForCTR_RandomDelta, randomDelta)
                            Triple(pos, processed, bytesRead)

                        }

                        desContext.countForCTR_RandomDelta++
                        jobs.add(job)
                        position += bytesRead

                    }

                    val results = jobs.awaitAll().sortedBy { it.first }

                    for ((_, bytes, originalSize) in results) {

                        if (originalSize < 8 && desContext.isStreamMode())
                            outChannel.write(ByteBuffer.wrap(bytes, 0, originalSize))
                        else
                            outChannel.write(ByteBuffer.wrap(bytes))

                    }

                }

            }

        }

        if (cipherOrDecipher == CipherOrDecipher.Decryption && !desContext.isStreamMode()) {

            RandomAccessFile(output, "rw").use { raf ->
                if (raf.length() >= 0L) {
                    val data = ByteArray(raf.length().toInt())
                    raf.seek(0)
                    raf.readFully(data)

                    val dePadded = paddingRemove(data, paddingType)

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

}