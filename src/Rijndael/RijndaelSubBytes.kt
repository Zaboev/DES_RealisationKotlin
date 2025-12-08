package Rijndael
import Enums.*

class RijndaelSubBytes(private val endian: Endian) {

    fun subBytes(input: ByteArray): ByteArray = process(input, false)

    fun inverseSubBytes(input: ByteArray): ByteArray = process(input, true)

    private fun process(input: ByteArray, inverse: Boolean): ByteArray {

        val out = ByteArray(input.size)

        val indices = when (endian) {
            Endian.BIG_ENDIAN -> input.indices
            Endian.LTL_ENDIAN -> input.indices.reversed()
        }

        for ((outIndex, i) in indices.withIndex()) {

            val x = input[i].toUByte().toInt()

            val inv = if (!inverse) gf256Inverse(x)
            else {

                val a = inverseAffineTransform(x)
                gf256Inverse(a)

            }

            val result = if (!inverse) affineTransform(inv)
            else inv

            out[outIndex] = result.toByte()

        }

        return out
    }

    private fun gf256Mul(a: Int, b: Int): Int {

        var res = 0
        var x = a
        var y = b

        repeat(8) {

            if ((y and 1) != 0) res = res xor x
            val hi = x and 0x80
            x = (x shl 1) and 0xFF
            if (hi != 0) x = x xor 0x1B
            y = y ushr 1

        }

        return res
    }

    private fun gf256Inverse(x: Int): Int {

        if (x == 0) return 0
        var y = x
        repeat(253) { y = gf256Mul(y, x) }
        return y

    }

    private fun affineTransform(x: Int): Int {

        var out = 0
        val c = 0x63

        for (i in 0 until 8) {

            val bit =
                ((x shr i) and 1) xor
                        ((x shr ((i + 4) and 7)) and 1) xor
                        ((x shr ((i + 5) and 7)) and 1) xor
                        ((x shr ((i + 6) and 7)) and 1) xor
                        ((x shr ((i + 7) and 7)) and 1) xor
                        ((c shr i) and 1)

            out = out or (bit shl i)

        }

        return out

    }

    private fun inverseAffineTransform(x: Int): Int {

        var out = 0
        val cInv = 0x05

        for (i in 0 until 8) {

            val bit =
                ((x shr ((i + 2) and 7)) and 1) xor
                        ((x shr ((i + 5) and 7)) and 1) xor
                        ((x shr ((i + 7) and 7)) and 1) xor
                        ((cInv shr i) and 1)

            out = out or (bit shl i)

        }

        return out

    }

}
