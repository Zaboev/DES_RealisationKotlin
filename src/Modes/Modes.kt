package Modes
import DES.FeistelStructure
import Enums.*
import java.nio.ByteBuffer
import java.nio.ByteOrder

class Modes (

    var block: ByteArray,
    private val mode: EncryptionMode,
    var cipherOrDecipher: CipherOrDecipher,
    private val structureDeFeistel: FeistelStructure,
    private var vectorInit: ByteArray,
    private val realSize: Int,
    private val endian: Endian,
    private val _block: ByteArray, // неполный блок
    private val randomDelta: ByteArray,
    private var counterForCTR_RandomDelta: Long

) {
    
    private val blockSize = block.size

    private var cBlock = vectorInit.copyOf()
    private var pBlock = ByteArray(blockSize)
    private var isFirst = true
    private var shiftRegister = vectorInit.copyOf()
    private var stream = vectorInit.copyOf()

    private fun shiftRegisterAppend(old: ByteArray, tail: ByteArray): ByteArray {
        val shift = tail.size
        val out = ByteArray(blockSize)
        for (i in 0 until blockSize - shift) out[i] = old[i + shift]
        for (j in 0 until shift) out[blockSize - shift + j] = tail[j]
        return out
    }

    suspend fun modes(): ByteArray {

        return when (mode) {
            EncryptionMode.ECB -> {
                if (cipherOrDecipher == CipherOrDecipher.Encryption) structureDeFeistel.encryptionAlgorithm(block)
                else structureDeFeistel.decryptionAlgorithm(block)
            }

            EncryptionMode.CBC -> {
                if (cipherOrDecipher == CipherOrDecipher.Encryption) {
                    val newBlock = ByteArray(blockSize) { i ->
                        (block[i].toInt() xor cBlock[i].toInt()).toByte()
                    }
                    cBlock = structureDeFeistel.encryptionAlgorithm(newBlock)
                    cBlock
                } else {
                    val outputBlock = structureDeFeistel.decryptionAlgorithm(block)
                    val result = ByteArray(blockSize) { i -> (outputBlock[i].toInt() xor cBlock[i].toInt()).toByte() }
                    cBlock = block
                    result
                }
            }

            EncryptionMode.PCBC -> {
                if (cipherOrDecipher == CipherOrDecipher.Encryption) {
                    var newBlock = ByteArray(blockSize)
                    if (isFirst) {
                        pBlock = block
                        newBlock = ByteArray(blockSize) { i ->
                            (block[i].toInt() xor cBlock[i].toInt()).toByte()
                        }
                        isFirst = false
                    } else {
                        newBlock = ByteArray(blockSize) { i ->
                            (block[i].toInt() xor cBlock[i].toInt() xor pBlock[i].toInt()).toByte()
                        }
                        pBlock = block
                    }
                    cBlock = structureDeFeistel.encryptionAlgorithm(newBlock)
                    cBlock
                } else {
                    val newBlock = structureDeFeistel.decryptionAlgorithm(block)
                    if (isFirst) {
                        pBlock = ByteArray(blockSize) { i -> (cBlock[i].toInt() xor newBlock[i].toInt()).toByte() }
                        cBlock = block
                        isFirst = false
                    } else {
                        pBlock =
                            ByteArray(blockSize) { i -> (newBlock[i].toInt() xor cBlock[i].toInt() xor pBlock[i].toInt()).toByte() }
                        cBlock = block
                    }
                    pBlock
                }
            }

            EncryptionMode.CFB -> {
                val enShiftRegister = structureDeFeistel.encryptionAlgorithm(shiftRegister)
                if (cipherOrDecipher == CipherOrDecipher.Encryption) {
                    val cipherBytes = ByteArray(realSize) { i ->
                        (_block[i].toInt() xor enShiftRegister[i].toInt()).toByte()
                    }
                    shiftRegister = shiftRegisterAppend(shiftRegister, cipherBytes)
                    cipherBytes
                } else {
                    val plainBytes = ByteArray(realSize) { i ->
                        (_block[i].toInt() xor enShiftRegister[i].toInt()).toByte()
                    }
                    shiftRegister = shiftRegisterAppend(shiftRegister, _block)
                    plainBytes
                }
            }

            EncryptionMode.OFB -> {
                stream = structureDeFeistel.encryptionAlgorithm(stream)
                ByteArray(realSize) { i ->
                    (block[i].toInt() xor stream[i].toInt()).toByte()
                }
            }

            EncryptionMode.CTR -> {
                val counterBlock = shiftRegister.copyOf()
                val counterBytes = ByteBuffer
                    .allocate(blockSize)
                    .order(if (endian == Endian.BIG_ENDIAN) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN)
                    .putLong(counterForCTR_RandomDelta)
                    .array()
                for (i in 0 until blockSize) counterBlock[i] = (counterBlock[i].toInt() xor counterBytes[i].toInt()).toByte()
                val outputBlock = structureDeFeistel.encryptionAlgorithm(counterBlock)
                ByteArray(realSize) { i -> (block[i].toInt() xor outputBlock[i].toInt()).toByte() }
            }

            EncryptionMode.RandomDelta -> {
                val localIV = shiftRegister.copyOf()
                val delta = ByteArray(blockSize)
                val counterBytes = ByteBuffer
                    .allocate(blockSize)
                    .order(if (endian == Endian.BIG_ENDIAN) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN)
                    .putLong(counterForCTR_RandomDelta)
                    .array()
                val RD = randomDelta
                for (i in 0 until blockSize) delta[i] =
                    (localIV[i].toInt() xor (RD[i].toInt() * counterBytes[i].toInt())).toByte()
                val outputBlock = structureDeFeistel.encryptionAlgorithm(delta)
                ByteArray(realSize) { i -> (block[i].toInt() xor outputBlock[i].toInt()).toByte() }
            }
        }
    }

}