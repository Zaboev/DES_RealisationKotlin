package Rijndael
import DES.IRoundKeysGenerator
import Enums.*

class RijndaelRoundKeysGenerator(

    private val endian: Endian,
    private val rijndaelKeySize: Int,
    private val rijndaelBlockSize: Int

): IRoundKeysGenerator<ByteArray> {

    suspend fun subBytesCreating(): RijndaelSubBytes = RijndaelSubBytes(endian)

    suspend fun rotWord(key: ByteArray): ByteArray {

        return byteArrayOf(key[1], key[2], key[3], key[0])

    }

    suspend fun subBytes(key: ByteArray): ByteArray {

        val subBytesObject = subBytesCreating()
        return subBytesObject.subBytes(key)

    }

    suspend fun computeRcon(n: Int): UByte {

        require (n >= 1)

        var rc = 0x01

        if (n == 1) return rc.toUByte()

        for (i in 2..n) {

            rc = rc shl 1

            if (rc and 0x100 != 0) rc = (rc xor 0x11B) and 0xFF

        }

        return rc.toUByte()

    }

    suspend fun xor(convertedKey: ByteArray, originalKey: ByteArray, numRound: Int = 0): ByteArray {

        if (numRound == 0) return ByteArray(4) { i -> (convertedKey[i].toInt() xor originalKey[i].toInt()).toByte() }
        else {

            val rc = computeRcon(numRound)
            val rcByteArray = byteArrayOf(rc.toByte(), 0x00, 0x00, 0x00)

            return ByteArray(4) {

                i -> (convertedKey[i].toInt() xor originalKey[i].toInt() xor rcByteArray[i].toInt()).toByte()

            }

        }

    }

    override suspend fun rKeysGenerator(entryKey: ByteArray): ArrayList<ByteArray> {

        val result = ArrayList<ByteArray>()
        val Nk = rijndaelKeySize / 4
        val Nb = rijndaelBlockSize / 4

        val roundsCount = maxOf(Nk, Nb) + 6
        val totalWords = Nb * (roundsCount + 1)

        val words = ArrayList<ByteArray>()
        for (i in 0 until Nk) {

            words.add(entryKey.copyOfRange(i * 4, (i + 1) * 4))

        }

        var i = Nk

        while (i < totalWords) {

            var temp = words[i - 1].copyOf()

            if (i % Nk == 0) {

                temp = rotWord(temp)
                temp = subBytes(temp)
                temp = xor(temp, ByteArray(4){0}, i / Nk)

            }
            else if (Nk == 8 && i % Nk == 4) {

                temp = subBytes(temp)

            }

            val newWord = xor(temp, words[i - Nk])
            words.add(newWord)
            i++

        }

        for (j in 0 .. roundsCount) {

            val roundKey = ByteArray(Nb * 4)
            for (k in 0 until Nb) {

                val word = words[j * Nb + k]
                System.arraycopy(word, 0, roundKey, k * 4, 4)

            }

            result.add(roundKey)

        }

        return result

    }

}