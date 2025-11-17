package DEAL
import DES.IEncrDecr
import DES.IRoundFunction
import DES.IRoundKeysGenerator
import DesContext
import Enums.EncryptionMode
import Enums.Endian
import Enums.IndexBase

class DealEncryptionAndDecryption(

    private val roundFunction: IRoundFunction<ArrayList<ByteArray>>,
    private val roundKeyGenerator: IRoundKeysGenerator<ArrayList<ByteArray>>,
    private val mode: EncryptionMode,
    private val endian: Endian,
    private val indexBase: IndexBase,
    private val counterForCTR_RandomDelta: Long = 0,
    private val randomDelta: ByteArray = ByteArray(8),
    private var vectorInit: ByteArray,
    private val keyLength: KeyLength

) : IEncrDecr<ArrayList<ByteArray>> {

    private var roundKeys = ArrayList<ByteArray>()

    override suspend fun encryptionAlgorithm(enBlock: ArrayList<ByteArray>): ArrayList<ByteArray> {

        var result: ArrayList<ByteArray>

        if (keyLength != KeyLength.k256) {

            result = roundFunction.encryptionTransformation(enBlock, roundKeys[0])

            for (i in 1 .. 5) {

                result = roundFunction.encryptionTransformation(result, roundKeys[i])

            }

            return result

        }
        else {

            result = roundFunction.encryptionTransformation(enBlock, roundKeys[0])

            for (i in 1 .. 7) {

                result = roundFunction.encryptionTransformation(result, roundKeys[i])

            }

            return result

        }

    }

    override suspend fun decryptionAlgorithm(deBlock: ArrayList<ByteArray>): ArrayList<ByteArray> {

        var result: ArrayList<ByteArray>

        if (keyLength != KeyLength.k256) {

            result = roundFunction.encryptionTransformation(deBlock, roundKeys[5])

            for (i in 4 downTo 0) {

                result = roundFunction.encryptionTransformation(result, roundKeys[i])

            }

            return result

        }
        else {

            result = roundFunction.encryptionTransformation(deBlock, roundKeys[7])

            for (i in 6 downTo 0) {

                result = roundFunction.encryptionTransformation(result, roundKeys[i])

            }

            return result

        }

    }

    override suspend fun setRoundKeys(key: ArrayList<ByteArray>) {

        val fixedKey = "0123456789abcdef".chunked(2).map{ it.toInt(16).toByte() }.toByteArray() //переместить
        val desContext = DesContext(fixedKey, mode, endian, indexBase, randomDelta, vectorInit) // переместить

        roundKeys = roundKeyGenerator.rKeysGenerator(key)

    }


}