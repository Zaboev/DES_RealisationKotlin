package DEAL
import DES.IEncryptionAndDecryption
import DES.IRoundFunction
import DES.IRoundKeysGenerator


class DealEncryptionAndDecryption (

    val roundFunction: IRoundFunction,
    private val roundKeyGenerator: IRoundKeysGenerator<ArrayList<ByteArray>>,
    private val keyLength: KeyLength

) : IEncryptionAndDecryption<ArrayList<ByteArray>> {

    private var roundKeys = ArrayList<ByteArray>()

    override suspend fun encryptionAlgorithm(enBlock: ByteArray): ByteArray {

        var result: ByteArray
        setRoundKeys(roundKeys) // roundKeys просто заглушка, функция не использует входные параметры, но в интерфейсе они нужны

        if (keyLength != KeyLength.k256) {

            result = roundFunction.encryptionTransformation(enBlock, roundKeys[0])

            for (i in 1 .. 5) {

                result = roundFunction.encryptionTransformation(result, roundKeys[i])

            }

            val right = result.copyOfRange(0, 8)
            val left = result.copyOfRange(8, 16)
            result = left + right

            return result

        }
        else {

            result = roundFunction.encryptionTransformation(enBlock, roundKeys[0])

            for (i in 1 .. 7) {

                result = roundFunction.encryptionTransformation(result, roundKeys[i])

            }

            val right = result.copyOfRange(0, 8)
            val left = result.copyOfRange(8, 16)
            result = left + right

            return result

        }

    }

    override suspend fun decryptionAlgorithm(deBlock: ByteArray): ByteArray {

        var result: ByteArray
        setRoundKeys(roundKeys)

        if (keyLength != KeyLength.k256) {

            result = roundFunction.encryptionTransformation(deBlock, roundKeys[5])

            for (i in 4 downTo 0) {


                result = roundFunction.encryptionTransformation(result, roundKeys[i])

            }

            val right = result.copyOfRange(0, 8)
            val left = result.copyOfRange(8, 16)
            result = left + right

            return result

        }
        else {

            result = roundFunction.encryptionTransformation(deBlock, roundKeys[7])

            for (i in 6 downTo 0) {

                result = roundFunction.encryptionTransformation(result, roundKeys[i])

            }

            val right = result.copyOfRange(0, 8)
            val left = result.copyOfRange(8, 16)
            result = left + right

            return result

        }

    }

    override suspend fun setRoundKeys(key: ArrayList<ByteArray>) {

        roundKeys = roundKeyGenerator.rKeysGenerator(key)

    }


}