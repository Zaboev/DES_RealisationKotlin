package DEAL
import DES.*
import Enums.*

class DealRoundKeysGenerator (
    private val keys: ByteArray,
    private val keyLength: KeyLength,
    private val desObject: FeistelStructure
) : IRoundKeysGenerator<ArrayList<ByteArray>> {

    private val roundKeys = ArrayList<ByteArray>()

    private var k1 = ByteArray(8)
    private var k2 = ByteArray(8)
    private var k3 = ByteArray(8)
    private var k4 = ByteArray(8)

    private fun initialization() {

        when (keyLength) {

            KeyLength.k128 -> {

                k1 = keys.copyOfRange(0, 8)
                k2 = keys.copyOfRange(8, 16)

            }

            KeyLength.k192 -> {

                k1 = keys.copyOfRange(0, 8)
                k2 = keys.copyOfRange(8, 16)
                k3 = keys.copyOfRange(16, 24)

            }

            KeyLength.k256 -> {

                k1 = keys.copyOfRange(0, 8)
                k2 = keys.copyOfRange(8, 16)
                k3 = keys.copyOfRange(16, 24)
                k4 = keys.copyOfRange(24, 32)

            }


        }

    }

    suspend override fun rKeysGenerator(entryKey: ArrayList<ByteArray>): ArrayList<ByteArray> { // Неиспользуемый entryKey

        initialization()

        val encrKeys = listOf(k1, k2, k3, k4)

        when (keyLength) {

            KeyLength.k128 -> {

                roundKeys.add(desContext.enDeCryption(encrKeys[0], CipherOrDecipher.Encryption))

                var xorResult = ByteArray(8) { i ->

                    ((encrKeys[1][i].toInt() xor roundKeys[0][i].toInt()).toByte())

                }
                roundKeys.add(desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption))

                for (i in 2 .. 5) {

                    if (i % 2 == 0) {

                        xorResult = ByteArray(8) { j ->

                            ((encrKeys[0][j].toInt() xor roundKeys[i - 1][j].toInt() xor (i - 1)).toByte())

                        }
                        roundKeys.add(desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption))

                    }
                    else {

                        xorResult = ByteArray(8) { j ->

                            ((encrKeys[1][j].toInt() xor roundKeys[i - 1][j].toInt() xor (i - 1)).toByte())

                        }
                        roundKeys.add(desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption))

                    }

                }

            }

            KeyLength.k192 -> {

                roundKeys.add(desContext.enDeCryption(encrKeys[0], CipherOrDecipher.Encryption))

                var xorResult: ByteArray

                for (i in 1 .. 2) {

                    xorResult = ByteArray(8) { j ->

                        ((encrKeys[i][j].toInt() xor roundKeys[i - 1][j].toInt()).toByte())

                    }
                    roundKeys.add(desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption))

                }

                for (i in 3 .. 5) {

                    xorResult = ByteArray(8) { j ->

                        ((encrKeys[i - 3][j].toInt() xor roundKeys[i - 1][j].toInt() xor (i - 2)).toByte())

                    }
                    roundKeys.add(desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption))

                }

            }

            KeyLength.k256 -> {

                roundKeys.add(desContext.enDeCryption(encrKeys[0], CipherOrDecipher.Encryption))

                var xorResult: ByteArray

                for (i in 1 .. 3) {

                    xorResult = ByteArray(8) { j ->

                        ((encrKeys[i][j].toInt() xor roundKeys[i - 1][j].toInt()).toByte())

                    }
                    roundKeys.add(desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption))

                }

                for (i in 4 .. 7) {

                    xorResult = ByteArray(8) { j ->

                        ((encrKeys[i - 4][j].toInt() xor roundKeys[i - 1][j].toInt() xor (i - 3)).toByte())

                    }
                    roundKeys.add(desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption))

                }

            }

        }

        return roundKeys

    }

}