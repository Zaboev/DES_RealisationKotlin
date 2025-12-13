import DES.*

class IdeaRoundFunction : IRoundFunction<IntArray> {

    private fun mul(a: Int, b: Int): Int {
        val x = a and 0xFFFF
        val y = b and 0xFFFF
        if (x == 0) return (1 - y) and 0xFFFF
        if (y == 0) return (1 - x) and 0xFFFF
        val p = x * y
        val low = p and 0xFFFF
        val high = p ushr 16
        return (low - high + if (low < high) 1 else 0) and 0xFFFF
    }

    override suspend fun encryptionTransformation(block: ByteArray, roundKey: IntArray): ByteArray {

        fun getWord(i: Int) =
            ((block[i].toInt() and 0xFF) shl 8) or
                    (block[i + 1].toInt() and 0xFF)

        fun putWord(i: Int, v: Int) {
            block[i] = (v ushr 8).toByte()
            block[i + 1] = v.toByte()
        }

        var x1 = getWord(0)
        var x2 = getWord(2)
        var x3 = getWord(4)
        var x4 = getWord(6)

        var k = 0
        repeat(8) {
            x1 = mul(x1, roundKey[k++])
            x2 = (x2 + roundKey[k++]) and 0xFFFF
            x3 = (x3 + roundKey[k++]) and 0xFFFF
            x4 = mul(x4, roundKey[k++])

            val s3 = x3
            x3 = mul(x3 xor x1, roundKey[k++])

            val s2 = x2
            x2 = mul((x2 xor x4) + x3, roundKey[k++]) and 0xFFFF
            x3 = (x3 + x2) and 0xFFFF

            x1 = x1 xor x2
            x4 = x4 xor x3
            x2 = x2 xor s3
            x3 = x3 xor s2
        }

        x1 = mul(x1, roundKey[k++])
        x3 = (x3 + roundKey[k++]) and 0xFFFF
        x2 = (x2 + roundKey[k++]) and 0xFFFF
        x4 = mul(x4, roundKey[k])

        putWord(0, x1)
        putWord(2, x3)
        putWord(4, x2)
        putWord(6, x4)

        return block
    }

}
