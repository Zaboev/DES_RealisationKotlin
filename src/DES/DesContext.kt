/*import Enums.*
import DES.*
import Modes.Modes


class DesContext (
    var encryptionKey: ByteArray,
    private val mode: EncryptionMode,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private var randomDelta: ByteArray,
    private var vectorInit: ByteArray
) {

    var countForCTR_RandomDelta: Long = 0

    private fun objectCreating(): FeistelStructure {
        val roundKeys = RoundKeysGenerator(endian, indexBase)
        val roundFunction = RoundFunction(endian, indexBase)
        return FeistelStructure(roundFunction, roundKeys, endian, indexBase, encryptionKey)
    }

    fun isStreamMode() =
        mode == EncryptionMode.CFB ||
                mode == EncryptionMode.OFB ||
                mode == EncryptionMode.CTR ||
                mode == EncryptionMode.RandomDelta

    suspend fun enDeCryption(
        _block: ByteArray,
        cipherOrDecipher: CipherOrDecipher,
    ): ByteArray {
        val realSize = _block.size
        val block = if (realSize < 8 && isStreamMode()) {
            val full = ByteArray(8)
            _block.copyInto(full)
            full
        }
        else if (realSize < 8 && !isStreamMode()) {
            val padded = ByteArray(8)
            _block.copyInto(padded)
            padded
        }
        else _block

        val structureDeFeistel = objectCreating()

        val modesObj = Modes(block, mode, cipherOrDecipher, structureDeFeistel, vectorInit, realSize, endian, _block, randomDelta, countForCTR_RandomDelta)

        return modesObj.modes()

    }
}*/