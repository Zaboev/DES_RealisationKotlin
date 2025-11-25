package DEAL
import DES.*
import Enums.CipherOrDecipher
import Enums.EncryptionMode
import Enums.Endian
import Enums.IndexBase
import Modes.Modes

class DealRoundFunction (
    private val mode: EncryptionMode,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private val randomDelta: ByteArray = ByteArray(8),
    private var vectorInit: ByteArray
) : IRoundFunction {

    override var countForCTR_RandomDelta: Long = 0

    suspend fun desObjectCreating(block: ByteArray, roundKey: ByteArray): Modes {

        val roundKeys = RoundKeysGenerator(endian, indexBase)
        val roundFunction = RoundFunction(endian, indexBase)
        val desObject = FeistelStructure(roundFunction, roundKeys, endian, indexBase, roundKey)


        Modes(block, mode, cipherOrDecipher, desObject, vectorInit, block.size, endian, block, randomDelta, countForCTR_RandomDelta)

    }

    override suspend fun encryptionTransformation(block: ByteArray, roundKey: ByteArray): ByteArray {

        val desModedObject = De(roundKey, mode, endian, indexBase, randomDelta, vectorInit)
        desContext.countForCTR_RandomDelta = countForCTR_RandomDelta

        val tempLeft = ByteArray(8) { i -> block[i] }
        val oldRight = ByteArray(8) { i -> block[i + 8] }

        val tempRight = desContext.enDeCryption(oldRight, CipherOrDecipher.Encryption)

        val rightBlock = ByteArray(8) { i ->

            ((tempLeft[i].toInt() xor tempRight[i].toInt()).toByte())

        }

        val result = oldRight + rightBlock

        return result

    }

}