package Rijndael
import DES.IRoundKeysGenerator
import Enums.*

class RijndaelRoundKeysGenerator(

    private val endian: Endian,
    private val rijndaelKeySize: RijndaelKeySize,
    private val rijndaelBlockSize: RijndaelBlockSize

): IRoundKeysGenerator<ByteArray> {

    private val roundsCount = when (rijndaelKeySize) {

        RijndaelKeySize.rK128 -> when (rijndaelBlockSize) {

            RijndaelBlockSize.r128 -> 10
            RijndaelBlockSize.r192 -> 12
            RijndaelBlockSize.r256 -> 14

        }
        RijndaelKeySize.rK192 -> when (rijndaelBlockSize) {

            RijndaelBlockSize.r128 -> 12
            RijndaelBlockSize.r192 -> 12
            RijndaelBlockSize.r256 -> 14

        }
        RijndaelKeySize.rK256 -> 14

    }

    private val subBytesObject = RijndaelSubBytes(endian)

    suspend fun rotWord(key: ByteArray): ByteArray {

        return byteArrayOf(key[1], key[2], key[3], key[0])

    }

    suspend fun subBytes(key: ByteArray): ByteArray {

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

        var rounds = 1

        while (rounds <= roundsCount) {

            var roundKey = ByteArray(0)

            roundKey += xor(subBytes(rotWord(entryKey.copyOfRange(12, 16))), entryKey.copyOfRange(0, 4), rounds)
            roundKey += xor(roundKey, entryKey.copyOfRange(4, 8))
            roundKey += xor(roundKey.copyOfRange(4, 8), entryKey.copyOfRange(8, 12))
            roundKey += xor(roundKey.copyOfRange(8, 12), entryKey.copyOfRange(12, 16))

            result.add(roundKey)

            rounds++

        }


        return result

    }

}