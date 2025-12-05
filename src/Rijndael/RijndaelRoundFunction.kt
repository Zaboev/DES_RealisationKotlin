package Rijndael
import DES.IRoundFunction
import Enums.*

class RijndaelRoundFunction (

    private val endian: Endian,
    private val indexBase: IndexBase,
    private val numberOfRound: Int,
    private val rijndaelBlockSize: RijndaelBlockSize

): IRoundFunction {

    private var countOfRound: Int = 0

    private val subBytesObject = RijndaelSubBytes(endian)

    suspend fun subBytes(state: ByteArray): ByteArray {

        return subBytesObject.subBytes(state)

    }

    suspend fun shiftRows(state: ByteArray): ByteArray {

        var thirdShiftRow: Int
        var fourthShiftRow: Int
        when (rijndaelBlockSize) {

            RijndaelBlockSize.r128 -> {

                thirdShiftRow = 2
                fourthShiftRow = 3

            }
            RijndaelBlockSize.r192 -> {

                thirdShiftRow = 2
                fourthShiftRow = 4

            }
            RijndaelBlockSize.r256 -> {

                thirdShiftRow = 3
                fourthShiftRow = 4

            }

        }

        val temp =



    }

    suspend fun iShiftRows(state: ByteArray): ByteArray {

        return state

    }

    suspend fun mixColumns(state: ByteArray): ByteArray { return state

    }

    suspend fun addRoundKey(state: ByteArray, roundKey: ByteArray): ByteArray {

        return ByteArray(16) { i ->

            (state[i].toInt() xor roundKey[i].toInt()).toByte()

        }

    }

    override suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray {

        return block

    }

    override suspend fun decryptionTransformation(block: ByteArray, roundKey: ByteArray) : ByteArray {

        return block

    }

}