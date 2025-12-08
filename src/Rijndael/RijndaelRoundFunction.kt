package Rijndael
import DES.IRoundFunction
import Enums.*

class RijndaelRoundFunction (

    private val endian: Endian

): IRoundFunction {

    fun subBytesCreating(): RijndaelSubBytes = RijndaelSubBytes(endian)

    fun iSubBytes(state: ByteArray): ByteArray {

        val subBytesObject = subBytesCreating()
        return subBytesObject.inverseSubBytes(state)

    }

    fun subBytes(state: ByteArray): ByteArray {

        val subBytesObject = subBytesCreating()
        return subBytesObject.subBytes(state)

    }

    fun shiftRows(state: ByteArray): ByteArray {

        val blockSize = state.size
        val rows = 4
        val columns = blockSize / rows
        val shifts = when (blockSize) {

            16 -> intArrayOf(0, 1, 2, 3)
            24 -> intArrayOf(0, 1, 2, 4)
            32 -> intArrayOf(0, 1, 3, 4)
            else -> throw Exception("State size should be 16 || 24 || 32")

        }

        val result = ByteArray(blockSize)

        for (i in 0 until rows) {

            for (j in 0 until columns) {

                val fromIndex = i + ((j + shifts[i]) % columns) * rows
                val toIndex = i + j * rows
                result[toIndex] = state[fromIndex]

            }

        }

        return result

    }

    fun iShiftRows(state: ByteArray): ByteArray {

        val blockSize = state.size
        val rows = 4
        val columns = blockSize / rows
        val shifts = when (blockSize) {

            16 -> intArrayOf(0, 1, 2, 3)
            24 -> intArrayOf(0, 1, 2, 4)
            32 -> intArrayOf(0, 1, 3, 4)
            else -> throw Exception("State size should be 16 || 24 || 32")

        }

        val result = ByteArray(blockSize)

        for (i in 0 until rows) {

            for (j in 0 until columns) {

                val fromIndex = i + ((j - shifts[i] + columns) % columns) * rows
                val toIndex = i + j * rows
                result[toIndex] = state[fromIndex]

            }

        }

        return result

    }

    fun iMixCoulumns(state: ByteArray): ByteArray {

        val mc = RijndaelMixColumns()
        val result = ByteArray(state.size)

        for (i in 0 until 4) {

            val j = i * 4

            val a0 = state[j]
            val a1 = state[j + 1]
            val a2 = state[j + 2]
            val a3 = state[j + 3]

            val r0 = (mc.multiply0E(a0).toInt() xor mc.multiply0B(a1).toInt() xor mc.multiply0D(a2).toInt() xor mc.multiply09(a3).toInt()).toByte()
            val r1 = (mc.multiply09(a0).toInt() xor mc.multiply0E(a1).toInt() xor mc.multiply0B(a2).toInt() xor mc.multiply0D(a3).toInt()).toByte()
            val r2 = (mc.multiply0D(a0).toInt() xor mc.multiply09(a1).toInt() xor mc.multiply0E(a2).toInt() xor mc.multiply0B(a3).toInt()).toByte()
            val r3 = (mc.multiply0B(a0).toInt() xor mc.multiply0D(a1).toInt() xor mc.multiply09(a2).toInt() xor mc.multiply0E(a3).toInt()).toByte()

            result[j] = r0
            result[j + 1] = r1
            result[j + 2] = r2
            result[j + 3] = r3

        }

        return result

    }

    suspend fun mixColumns(state: ByteArray): ByteArray {

        val mc = RijndaelMixColumns()
        val result = ByteArray(state.size)

        for (i in 0 until 4) {

            val j = i * 4

            val a0 = state[j]
            val a1 = state[j + 1]
            val a2 = state[j + 2]
            val a3 = state[j + 3]

            val r0 = (mc.multiply02(a0).toInt() xor mc.multiply03(a1).toInt() xor (a2.toInt() and 0xFF) xor (a3.toInt() and 0xFF)).toByte()
            val r1 = ((a0.toInt() and 0xFF) xor mc.multiply02(a1).toInt() xor mc.multiply03(a2).toInt() xor (a3.toInt() and 0xFF)).toByte()
            val r2 = ((a0.toInt() and 0xFF) xor (a1.toInt() and 0xFF) xor mc.multiply02(a2).toInt() xor mc.multiply03(a3).toInt()).toByte()
            val r3 = (mc.multiply03(a0).toInt() xor (a1.toInt() and 0xFF) xor (a2.toInt() and 0xFF) xor mc.multiply02(a3).toInt()).toByte()

            result[j] = r0
            result[j + 1] = r1
            result[j + 2] = r2
            result[j + 3] = r3

        }

        return result

    }

    fun addRoundKey(state: ByteArray, roundKey: ByteArray): ByteArray {

        return ByteArray(state.size) { i ->

            (state[i].toInt() xor roundKey[i].toInt()).toByte()

        }

    }

    override suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray {

        var temp = subBytes(block)
        temp = shiftRows(temp)
        temp = mixColumns(temp)
        return addRoundKey(temp, roundKey)

    }

    override suspend fun lastEncryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray {

        var temp = subBytes(block)
        temp = shiftRows(temp)
        return addRoundKey(temp, roundKey)

    }

    override suspend fun decryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray {

        var temp = iShiftRows(block)
        temp = iSubBytes(temp)
        temp = addRoundKey(temp, roundKey)
        return iMixCoulumns(temp)

    }

    override suspend fun lastDecryptionTransformation(block: ByteArray, roundKey: ByteArray): ByteArray {

        var temp = iShiftRows(block)
        temp = iSubBytes(temp)
        return addRoundKey(temp, roundKey)

    }

}