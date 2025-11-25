package TripleDES
import DES.FeistelStructure
import DES.IEncrDecr
import DES.RoundFunction
import DES.RoundKeysGenerator
import Enums.*
import Modes.Modes

class TripleDesEncryptionAndDecryption (

    private val encryptionKey: ByteArray,
    private val mode: EncryptionMode,
    private val paddingType: Padding,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private val randomDelta: ByteArray = byteArrayOf(0,0,0,0,0,0,0,0),
    private val vectorInit: ByteArray = byteArrayOf(0,0,0,0,0,0,0,0),
    private val tripleDesMode: TripleDesMode

) {

    var countForCTR_RandomDelta: Long = 0L

    private fun desObjectCreating(): FeistelStructure {

        val roundKeys = RoundKeysGenerator(endian, indexBase)
        val roundFunction = RoundFunction(endian, indexBase)
        return FeistelStructure(roundFunction, roundKeys, endian, indexBase, encryptionKey.copyOfRange(0, 8))

    }

    private fun isStreamMode() =
        mode == EncryptionMode.CFB ||
                mode == EncryptionMode.OFB ||
                mode == EncryptionMode.CTR ||
                mode == EncryptionMode.RandomDelta

    private fun blockConverterToNormalSize(block: ByteArray): ByteArray {

        val realSize = block.size
        val fullBlock = if (realSize < 8 && isStreamMode()) {
            val full = ByteArray(8)
            block.copyInto(full)
            full
        }
        else if (realSize < 8 && !isStreamMode()) {
            val padded = ByteArray(8)
            block.copyInto(padded)
            padded
        }
        else block

        return fullBlock

    }

    suspend fun encryptionAlgorithm(block: ByteArray): ByteArray {

        val fullBlock = blockConverterToNormalSize(block)
        val desObject = desObjectCreating()

        val modesObject = Modes(fullBlock, mode, CipherOrDecipher.Encryption,
            desObject, vectorInit, block.size, endian, block, randomDelta, countForCTR_RandomDelta)

        return when (tripleDesMode) {

            TripleDesMode.oneKey -> {

                val first = modesObject.modes()
                modesObject.cipherOrDecipher = CipherOrDecipher.Decryption

                val second = modesObject.modes


                desContext.enDeCryption (
                    desContext.enDeCryption(
                        desContext.enDeCryption(block, CipherOrDecipher.Encryption), CipherOrDecipher.Decryption), CipherOrDecipher.Encryption)

            }
            TripleDesMode.twoKeys -> {

                val firstCipher = desContext.enDeCryption(block, CipherOrDecipher.Encryption)
                desContext.encryptionKey = encryptionKey.copyOfRange(8, 16)

                val secondDeCipher = desContext.enDeCryption(firstCipher, CipherOrDecipher.Decryption)
                desContext.encryptionKey = encryptionKey.copyOfRange(0, 8)

                desContext.enDeCryption(secondDeCipher, CipherOrDecipher.Encryption)

            }
            TripleDesMode.threeKeys -> {

                val firstCipher = desContext.enDeCryption(block, CipherOrDecipher.Encryption)
                desContext.encryptionKey = encryptionKey.copyOfRange(8, 16)

                val secondDeCipher = desContext.enDeCryption(firstCipher, CipherOrDecipher.Decryption)
                desContext.encryptionKey = encryptionKey.copyOfRange(16, 24)

                desContext.enDeCryption(secondDeCipher, CipherOrDecipher.Encryption)

            }

        }

    }

    suspend fun decryptionAlgorithm(block: ByteArray): ByteArray {

        desContext.countForCTR_RandomDelta = countForCTR_RandomDelta
        return when (tripleDesMode) {

            TripleDesMode.oneKey -> {

                desContext.enDeCryption (
                    desContext.enDeCryption(
                        desContext.enDeCryption(block, CipherOrDecipher.Decryption), CipherOrDecipher.Encryption), CipherOrDecipher.Decryption)

            }
            TripleDesMode.twoKeys -> {

                val firstCipher = desContext.enDeCryption(block, CipherOrDecipher.Decryption)
                desContext.encryptionKey = encryptionKey.copyOfRange(8, 16)

                val secondDeCipher = desContext.enDeCryption(firstCipher, CipherOrDecipher.Encryption)
                desContext.encryptionKey = encryptionKey.copyOfRange(0, 8)

                desContext.enDeCryption(secondDeCipher, CipherOrDecipher.Decryption)

            }
            TripleDesMode.threeKeys -> {

                val firstCipher = desContext.enDeCryption(block, CipherOrDecipher.Decryption)
                desContext.encryptionKey = encryptionKey.copyOfRange(8, 16)

                val secondDeCipher = desContext.enDeCryption(firstCipher, CipherOrDecipher.Encryption)
                desContext.encryptionKey = encryptionKey.copyOfRange(16, 24)

                desContext.enDeCryption(secondDeCipher, CipherOrDecipher.Decryption)

            }

        }

    }



}