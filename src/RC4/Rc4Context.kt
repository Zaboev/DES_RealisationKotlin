package RC4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.io.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class Rc4ClassContext() {

    fun cipherDecipher(inputFile: File, outputFile: File, key: ByteArray, endian: ByteOrder = ByteOrder.BIG_ENDIAN) = runBlocking {

        FileInputStream(inputFile).use { input ->

            FileOutputStream(outputFile).use { output ->

                rc4EncryptionStream(input, output, key, endian)

            }

        }

    }

    suspend private fun rc4EncryptionStream(

        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        endian: ByteOrder

    ) = withContext(Dispatchers.IO) {

        val rc4 = RC4(key)
        val buffer = ByteArray(1)
        val endianBuffer = ByteBuffer.allocate(1).order(endian)

        while (true) {

            val bytesRead = inputStream.read(buffer)
            if (bytesRead == -1) break

            endianBuffer.clear()
            endianBuffer.put(buffer[0])
            endianBuffer.flip()
            val byteToProcess = endianBuffer.get()

            val encryptedByte = rc4.processByte(byteToProcess)

            outputStream.write(byteArrayOf(encryptedByte))

        }

        outputStream.flush()

    }

}