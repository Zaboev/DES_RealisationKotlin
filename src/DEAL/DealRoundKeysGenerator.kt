package DEAL
import DES.*
import DesContext
import Enums.*

class DealRoundKeysGenerator (
    private val keys: List<ByteArray>,
    private val keyLength: KeyLength,
    private val desContext: DesContext,
    private val counterForCTR_RandomDelta: Long = 0,
    private val randomDelta: ByteArray = ByteArray(8)
) : IRoundKeysGenerator<ArrayList<ByteArray>> {

    private val roundKeys = ArrayList<ByteArray>()

    private var k1 = ByteArray(8)
    private var k2 = ByteArray(8)
    private var k3 = ByteArray(8)
    private var k4 = ByteArray(8)

    private fun initialization() {

        when (keyLength) {

            KeyLength.k128 -> {

                k1 = keys[0]
                k2 = keys[1]

            }

            KeyLength.k192 -> {

                k1 = keys[0]
                k2 = keys[1]
                k3 = keys[2]

            }

            KeyLength.k256 -> {

                k1 = keys[0]
                k2 = keys[1]
                k3 = keys[2]
                k4 = keys[3]

            }


        }

    }

    suspend override fun rKeysGenerator(entryKey: ArrayList<ByteArray>): ArrayList<ByteArray> {

        initialization()

        val encrKeys = listOf(k1, k2, k3, k4)

        when (keyLength) {

            KeyLength.k128 -> {

                roundKeys[0] = desContext.enDeCryption(encrKeys[0], CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

                var xorResult = ByteArray(8) { i ->

                    ((encrKeys[1][i].toInt() xor roundKeys[0][i].toInt()).toByte())

                }
                roundKeys[1] = desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

                for (i in 2 .. 5) {

                    if (i % 2 == 0) {

                        xorResult = ByteArray(8) { j ->

                            ((encrKeys[0][j].toInt() xor roundKeys[i - 1][j].toInt() xor (i - 1)).toByte())

                        }
                        roundKeys[i] = desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

                    }
                    else {

                        xorResult = ByteArray(8) { j ->

                            ((encrKeys[1][j].toInt() xor roundKeys[i - 1][j].toInt() xor (i - 1)).toByte())

                        }
                        roundKeys[i] = desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

                    }

                }

            }

            KeyLength.k192 -> {

                roundKeys[0] = desContext.enDeCryption(encrKeys[0], CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

                var xorResult: ByteArray

                for (i in 1 .. 2) {

                    xorResult = ByteArray(8) { j ->

                        ((encrKeys[i][j].toInt() xor roundKeys[i - 1][j].toInt()).toByte())

                    }
                    roundKeys[i] = desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

                }

                for (i in 3 .. 5) {

                    xorResult = ByteArray(8) { j ->

                        ((encrKeys[i - 3][j].toInt() xor roundKeys[i - 1][j].toInt() xor (i - 2)).toByte())

                    }
                    roundKeys[i] = desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

                }

            }

            KeyLength.k256 -> {

                roundKeys[0] = desContext.enDeCryption(encrKeys[0], CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

                var xorResult: ByteArray

                for (i in 1 .. 3) {

                    xorResult = ByteArray(8) { j ->

                        ((encrKeys[i][j].toInt() xor roundKeys[i - 1][j].toInt()).toByte())

                    }
                    roundKeys[i] = desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

                }

                for (i in 4 .. 7) {

                    xorResult = ByteArray(8) { j ->

                        ((encrKeys[i - 4][j].toInt() xor roundKeys[i - 1][j].toInt() xor (i - 3)).toByte())

                    }
                    roundKeys[i] = desContext.enDeCryption(xorResult, CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

                }

            }

        }

        return roundKeys

    }

}