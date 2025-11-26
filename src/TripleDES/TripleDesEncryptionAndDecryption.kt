package TripleDES
import DES.FeistelStructure
import DES.RoundFunction
import DES.RoundKeysGenerator
import Enums.*

class TripleDesEncryptionAndDecryption (

    private val encryptionKey: ByteArray,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private val tripleDesMode: TripleDesMode

) {

    private fun desObjectCreating(): FeistelStructure {

        val roundKeys = RoundKeysGenerator(endian, indexBase)
        val roundFunction = RoundFunction(endian, indexBase)
        return FeistelStructure(roundFunction, roundKeys, endian, indexBase, encryptionKey.copyOfRange(0, 8))

    }

    suspend fun encryptionAlgorithm(block: ByteArray): ByteArray {

        val desObject = desObjectCreating()

        return when (tripleDesMode) {

            TripleDesMode.oneKey -> {

                val firstCipher = desObject.encryptionAlgorithm(block)
                val secondDeCipher = desObject.decryptionAlgorithm(firstCipher)
                desObject.encryptionAlgorithm(secondDeCipher)

            }
            TripleDesMode.twoKeys -> {

                val firstCipher = desObject.encryptionAlgorithm(block)
                desObject.entryKey = encryptionKey.copyOfRange(8, 16)

                val secondDeCipher = desObject.decryptionAlgorithm(firstCipher)
                desObject.entryKey = encryptionKey.copyOfRange(0, 8)

                desObject.encryptionAlgorithm(secondDeCipher)

            }
            TripleDesMode.threeKeys -> {

                val firstCipher = desObject.encryptionAlgorithm(block)
                desObject.entryKey = encryptionKey.copyOfRange(8, 16)

                val secondDeCipher = desObject.decryptionAlgorithm(firstCipher)
                desObject.entryKey = encryptionKey.copyOfRange(16, 24)

                desObject.encryptionAlgorithm(secondDeCipher)

            }

        }

    }

    suspend fun decryptionAlgorithm(block: ByteArray): ByteArray {

        val desObject = desObjectCreating()

        return when (tripleDesMode) {

            TripleDesMode.oneKey -> {

                val firstCipher = desObject.decryptionAlgorithm(block)
                val secondDeCipher = desObject.encryptionAlgorithm(firstCipher)
                desObject.decryptionAlgorithm(secondDeCipher)

            }
            TripleDesMode.twoKeys -> {

                val firstCipher = desObject.decryptionAlgorithm(block)
                desObject.entryKey = encryptionKey.copyOfRange(8, 16)

                val secondDeCipher = desObject.encryptionAlgorithm(firstCipher)
                desObject.entryKey = encryptionKey.copyOfRange(0, 8)

                desObject.decryptionAlgorithm(secondDeCipher)

            }
            TripleDesMode.threeKeys -> {

                val firstCipher = desObject.decryptionAlgorithm(block)
                desObject.entryKey = encryptionKey.copyOfRange(8, 16)

                val secondDeCipher = desObject.encryptionAlgorithm(firstCipher)
                desObject.entryKey = encryptionKey.copyOfRange(16, 24)

                desObject.decryptionAlgorithm(secondDeCipher)

            }

        }

    }



}