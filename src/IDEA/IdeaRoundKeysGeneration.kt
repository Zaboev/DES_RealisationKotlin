import DES.*

class IdeaRoundKeysGenerator : IRoundKeysGenerator<ByteArray, IntArray> {

    companion object {

        private const val IDEAROUNDS = 8
        private const val IDEAKEYLEN = 6 * IDEAROUNDS + 4

    }

    override suspend fun rKeysGenerator(entryKey: ByteArray): IntArray {

        val ek = IntArray(IDEAKEYLEN)
        expandKey(entryKey, ek)
        return ek

    }

    override suspend fun rKeysGeneratorDecryptionForIdea(entryKey: ByteArray): IntArray {

        val ek = IntArray(IDEAKEYLEN)
        val dk = IntArray(IDEAKEYLEN)
        expandKey(entryKey, ek)
        invertKey(ek, dk)
        return dk

    }

    private fun expandKey(userKey: ByteArray, EK: IntArray) {
        var j = 0
        var idx = 0

        while (j < 8) {
            EK[j] =
                ((userKey[idx].toInt() and 0xFF) shl 8) or
                        (userKey[idx + 1].toInt() and 0xFF)
            idx += 2
            j++
        }

        var i = 0
        while (j < IDEAKEYLEN) {
            i++
            EK[i + 7] =
                ((EK[i and 7] shl 9) or
                        (EK[(i + 1) and 7] ushr 7)) and 0xFFFF
            if ((i and 8) != 0) {
                for (k in 0 until 8) {
                    EK[k] = EK[k + 8]
                }
            }
            i = i and 7
            j++
        }
    }

    private fun invertKey(EK: IntArray, DK: IntArray) {
        val temp = IntArray(IDEAKEYLEN)
        var p = IDEAKEYLEN
        var idx = 0

        fun mulInv(x: Int): Int {
            var v = x and 0xFFFF
            if (v <= 1) return v
            var t0 = 1
            var t1 = 0x10001 / v
            var y = 0x10001 % v
            while (y != 1) {
                val q = v / y
                v %= y
                t0 += q * t1
                if (v == 1) return t0 and 0xFFFF
                val q2 = y / v
                y %= v
                t1 += q2 * t0
            }
            return (1 - t1) and 0xFFFF
        }
        fun addInv(x: Int): Int = (-x) and 0xFFFF

        var t1 = mulInv(EK[idx++])
        var t2 = addInv(EK[idx++])
        var t3 = addInv(EK[idx++])

        temp[--p] = mulInv(EK[idx++])
        temp[--p] = t3
        temp[--p] = t2
        temp[--p] = t1

        repeat(IDEAROUNDS - 1) {
            t1 = EK[idx++]
            temp[--p] = EK[idx++]
            temp[--p] = t1

            t1 = mulInv(EK[idx++])
            t2 = addInv(EK[idx++])
            t3 = addInv(EK[idx++])

            temp[--p] = mulInv(EK[idx++])
            temp[--p] = t2
            temp[--p] = t3
            temp[--p] = t1
        }

        t1 = EK[idx++]
        temp[--p] = EK[idx++]
        temp[--p] = t1

        t1 = mulInv(EK[idx++])
        t2 = addInv(EK[idx++])
        t3 = addInv(EK[idx++])

        temp[--p] = mulInv(EK[idx])
        temp[--p] = t3
        temp[--p] = t2
        temp[--p] = t1

        for (i in DK.indices) DK[i] = temp[i]
    }

}
