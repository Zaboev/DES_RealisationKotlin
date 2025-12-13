package Modes
import DEAL.DealEncryptionAndDecryption
import DES.FeistelStructure
import Enums.*
import IdeaEncryptionAndDecryption
import Rijndael.RijndaelEncryptionAndDecryption
import TripleDES.TripleDesEncryptionAndDecryption
import java.nio.ByteBuffer
import java.nio.ByteOrder

class Modes (

    private val block: ByteArray,
    private val blockForCFB: ByteArray,
    private val realSize: Int,
    private val algorithm: Algorithm,
    private val mode: EncryptionMode,
    private val cipherOrDecipher: CipherOrDecipher,
    private var vectorInit: ByteArray,
    private val endian: Endian,
    private val randomDelta: ByteArray,
    private var countForCTR_RandomDelta: Long,
    private val desObject: FeistelStructure?,
    private val dealObject: DealEncryptionAndDecryption?,
    private val tripleDesObject: TripleDesEncryptionAndDecryption?,
    private val rijndaelObject: RijndaelEncryptionAndDecryption?,
    private val ideaObject: IdeaEncryptionAndDecryption?

    ) {

    private val blockFullSize = when (algorithm) {

        Algorithm.DES -> 8
        Algorithm.DEAL -> 16
        Algorithm.TripleDes -> 8
        Algorithm.Rijndael -> vectorInit.size
        Algorithm.IDEA -> 8

    }
    private var cBlock = vectorInit.copyOf()
    private var pBlock = ByteArray(blockFullSize)
    private var isFirst = true
    private var shiftRegister = vectorInit.copyOf()
    private var stream = vectorInit.copyOf()

    private suspend fun encryption (_block: ByteArray): ByteArray {

        return when (algorithm) {

            Algorithm.DES -> desObject!!.encryptionAlgorithm(_block)
            Algorithm.DEAL -> dealObject!!.encryptionAlgorithm(_block)
            Algorithm.TripleDes -> tripleDesObject!!.encryptionAlgorithm(_block)
            Algorithm.Rijndael -> rijndaelObject!!.encryptionAlgorithm(_block)
            Algorithm.IDEA -> ideaObject!!.encryptionAlgorithm(_block)
        }

    }

    private suspend fun decryption (_block: ByteArray): ByteArray {

        return when (algorithm) {

            Algorithm.DES -> desObject!!.decryptionAlgorithm(_block)
            Algorithm.DEAL -> dealObject!!.decryptionAlgorithm(_block)
            Algorithm.TripleDes -> tripleDesObject!!.decryptionAlgorithm(_block)
            Algorithm.Rijndael -> rijndaelObject!!.decryptionAlgorithm(_block)
            Algorithm.IDEA -> ideaObject!!.decryptionAlgorithm(_block)

        }

    }

    private fun shiftRegisterAppend(old: ByteArray, tail: ByteArray): ByteArray {
        val shift = tail.size
        val out = ByteArray(blockFullSize)
        for (i in 0 until blockFullSize - shift) out[i] = old[i + shift]
        for (j in 0 until shift) out[blockFullSize - shift + j] = tail[j]
        return out
    }

    suspend fun modes(): ByteArray {

        return when (mode) {
            EncryptionMode.ECB -> {

                if (cipherOrDecipher == CipherOrDecipher.Encryption) encryption(block)
                else decryption(block)
            }

            EncryptionMode.CBC -> {
                if (cipherOrDecipher == CipherOrDecipher.Encryption) {
                    val newBlock = ByteArray(blockFullSize) { i ->
                        (block[i].toInt() xor cBlock[i].toInt()).toByte()
                    }
                    cBlock = encryption(newBlock)
                    cBlock
                }
                else {
                    val outputBlock = decryption(block)
                    val result = ByteArray(blockFullSize) { i -> (outputBlock[i].toInt() xor cBlock[i].toInt()).toByte() }
                    cBlock = block
                    result
                }
            }

            EncryptionMode.PCBC -> {
                if (cipherOrDecipher == CipherOrDecipher.Encryption) {
                    var newBlock = ByteArray(blockFullSize)
                    if (isFirst) {
                        pBlock = block
                        newBlock = ByteArray(blockFullSize) { i ->
                            (block[i].toInt() xor cBlock[i].toInt()).toByte()
                        }
                        isFirst = false
                    }
                    else {
                        newBlock = ByteArray(blockFullSize) { i ->
                            (block[i].toInt() xor cBlock[i].toInt() xor pBlock[i].toInt()).toByte()
                        }
                        pBlock = block
                    }
                    cBlock = encryption(newBlock)
                    cBlock
                }
                else {
                    val newBlock = decryption(block)
                    if (isFirst) {
                        pBlock = ByteArray(blockFullSize) { i -> (cBlock[i].toInt() xor newBlock[i].toInt()).toByte() }
                        cBlock = block
                        isFirst = false
                    } else {
                        pBlock =
                            ByteArray(blockFullSize) { i -> (newBlock[i].toInt() xor cBlock[i].toInt() xor pBlock[i].toInt()).toByte() }
                        cBlock = block
                    }
                    pBlock
                }
            }

            EncryptionMode.CFB -> {
                val enShiftRegister = encryption(shiftRegister)
                if (cipherOrDecipher == CipherOrDecipher.Encryption) {
                    val cipherBytes = ByteArray(realSize) { i ->
                        (blockForCFB[i].toInt() xor enShiftRegister[i].toInt()).toByte()
                    }
                    shiftRegister = shiftRegisterAppend(shiftRegister, cipherBytes)
                    cipherBytes
                }
                else {
                    val plainBytes = ByteArray(realSize) { i ->
                        (blockForCFB[i].toInt() xor enShiftRegister[i].toInt()).toByte()
                    }
                    shiftRegister = shiftRegisterAppend(shiftRegister, blockForCFB)
                    plainBytes
                }
            }

            EncryptionMode.OFB -> {
                stream = encryption(stream)
                ByteArray(realSize) { i ->
                    (block[i].toInt() xor stream[i].toInt()).toByte()
                }
            }

            EncryptionMode.CTR -> {
                val counterBlock = shiftRegister.copyOf()
                val counterBytes = ByteBuffer
                    .allocate(blockFullSize)
                    .order(if (endian == Endian.BIG_ENDIAN) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN)
                    .putLong(countForCTR_RandomDelta)
                    .array()
                for (i in 0 until blockFullSize) counterBlock[i] = (counterBlock[i].toInt() xor counterBytes[i].toInt()).toByte()
                val outputBlock = encryption(counterBlock)
                ByteArray(realSize) { i -> (block[i].toInt() xor outputBlock[i].toInt()).toByte() }
            }

            EncryptionMode.RandomDelta -> {
                val localIV = shiftRegister.copyOf()
                val delta = ByteArray(blockFullSize)
                val counterBytes = ByteBuffer
                    .allocate(blockFullSize)
                    .order(if (endian == Endian.BIG_ENDIAN) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN)
                    .putLong(countForCTR_RandomDelta)
                    .array()
                val RD = randomDelta
                for (i in 0 until blockFullSize) delta[i] =
                    (localIV[i].toInt() xor (RD[i].toInt() * counterBytes[i].toInt())).toByte()
                val outputBlock = encryption(delta)
                ByteArray(realSize) { i -> (block[i].toInt() xor outputBlock[i].toInt()).toByte() }
            }
        }
    }

}