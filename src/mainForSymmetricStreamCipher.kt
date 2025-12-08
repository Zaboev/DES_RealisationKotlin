import RC4.*
import java.io.File

fun _filesEqualFast(f1: File, f2: File): Boolean {
    if (f1.length() != f2.length()) return false

    f1.inputStream().use { s1 ->
        f2.inputStream().use { s2 ->
            val b1 = ByteArray(8192)
            val b2 = ByteArray(8192)

            while (true) {
                val r1 = s1.read(b1)
                val r2 = s2.read(b2)

                if (r1 != r2) return false
                if (r1 == -1) return true
                if (!b1.copyOf(r1).contentEquals(b2.copyOf(r2))) return false
            }
        }
    }
}

fun main() {

    try {

        var isSuccess = true

        val obj = Rc4ClassContext()

        val originalFile = File("C:\\Users\\Zaboev\\Desktop\\ExamplesForEncryption\\text.txt")
        val cipheredFile = File("C:\\Users\\Zaboev\\Desktop\\ExamplesForEncryption\\Rc4Demonstration\\rc4Encryption.txt")
        val decipheredFile = File("C:\\Users\\Zaboev\\Desktop\\ExamplesForEncryption\\Rc4Demonstration\\rc4Decryption.txt")

        obj.cipherDecipher(originalFile, cipheredFile, byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8))
        obj.cipherDecipher(cipheredFile, decipheredFile, byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8))


        if (!_filesEqualFast(originalFile, decipheredFile))
            isSuccess = false

        if (isSuccess) println("Encryption and decryption were successful!")
        else println("Encryption and decryption failed...")

    }
    catch (e: Exception) {

        println(e.message)

    }

}