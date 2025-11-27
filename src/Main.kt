import DEAL.KeyLength
import Enums.*
import java.io.File

fun filesEqualFast(f1: File, f2: File): Boolean {
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

        for (j in 1 .. 7) {

            var mode: EncryptionMode = EncryptionMode.ECB

            when (j) {

                1 -> mode = EncryptionMode.ECB
                2 -> mode = EncryptionMode.CBC
                3 -> mode = EncryptionMode.PCBC
                4 -> mode = EncryptionMode.OFB
                5 -> mode = EncryptionMode.CFB
                6 -> mode = EncryptionMode.RandomDelta
                7 -> mode = EncryptionMode.CTR

            }

            for (i in 1..4) {

                var padding: Padding = Padding.Zeros

                when (i) {

                    1 -> padding = Padding.PKCS7
                    2 -> padding = Padding.ISO10126
                    3 -> padding = Padding.ANSI_X923
                    4 -> padding = Padding.Zeros

                }

                val obj = ContextCypherAlgorithm(
                    Algorithm.DEAL,
                    byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8),
                    mode,
                    padding,
                    Endian.BIG_ENDIAN,
                    IndexBase.ONE_INDEX,
                    byteArrayOf(8, 7, 6, 5, 4, 3, 2, 1, 2, 4, 6, 8, 1, 3, 5, 7), // random delta
                    byteArrayOf(2, 4, 6, 8, 1, 3, 5, 7, 2, 4, 6, 8, 1, 3, 5, 7) // vector init
                )

                obj.cipherStart(
                    "C:\\Users\\Zaboev\\Desktop\\ExamplesForEncryption\\text.txt",
                    "C:\\Users\\Zaboev\\Desktop\\ExamplesForEncryption\\Encryption_${mode}\\cipheredWith${padding}.txt",
                    CipherOrDecipher.Encryption,
                    5
                )

                obj.cipherStart(
                    "C:\\Users\\Zaboev\\Desktop\\ExamplesForEncryption\\Encryption_${mode}\\cipheredWith${padding}.txt",
                    "C:\\Users\\Zaboev\\Desktop\\ExamplesForEncryption\\Encryption_${mode}\\deCipheredWith${padding}.txt",
                    CipherOrDecipher.Decryption,
                    5
                )

                if (!filesEqualFast(File("C:\\Users\\Zaboev\\Desktop\\ExamplesForEncryption\\text.txt"),
                        File("C:\\Users\\Zaboev\\Desktop\\ExamplesForEncryption\\Encryption_${mode}\\deCipheredWith${padding}.txt"))) {

                    println("Encryption mode $mode with padding $padding is incorrect")
                    isSuccess = false

                }

            }

        }

        if (isSuccess) println("Encryption and decryption were successful!")
        else {
            println("\n---------------------------------------------------------\n")
            println("Encryption and decryption failed...")
        }
    }
    catch (e: Exception) {

        println(e.message)

    }
}