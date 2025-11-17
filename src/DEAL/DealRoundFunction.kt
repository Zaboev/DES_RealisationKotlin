package DEAL
import DES.*
import DesContext
import Enums.CipherOrDecipher
import Enums.EncryptionMode
import Enums.Endian
import Enums.IndexBase

class DealRoundFunction (
    private val mode: EncryptionMode,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private val counterForCTR_RandomDelta: Long = 0,
    private val randomDelta: ByteArray = ByteArray(8),
    private var vectorInit: ByteArray
) : IRoundFunction<ArrayList<ByteArray>> {

    override suspend fun encryptionTransformation(block: ArrayList<ByteArray>, roundKey: ByteArray): ArrayList<ByteArray> {

        val desContext = DesContext(roundKey, mode, endian, indexBase, randomDelta, vectorInit)

        var tempLeft = block[0]
        var tempRight = desContext.enDeCryption(block[1], CipherOrDecipher.Encryption, counterForCTR_RandomDelta, randomDelta)

        var rightBlock = ByteArray(8) { i ->

            ((tempLeft[i].toInt() xor tempRight[i].toInt()).toByte())

        }

        val result = arrayListOf(block[1], rightBlock)

        return result

    }

}