package RC4

class RC4(private val key: ByteArray) {

    private val s = ByteArray(256) { it.toByte() }
    private var i = 0
    private var j = 0
    private val keySize = key.size

    init {

        var j = 0
        for ( i in 0 until 256) {

            j = (j + (s[i].toInt() and 0xFF) + (key[i%keySize].toInt() and 0xFF)) % 256
            val temp = s[i]
            s[i] = s[j]
            s[j] = temp

        }

    }

    private fun keyStreamByte() : Byte {

        i = (i + 1) % 256
        j = (j + (s[i].toInt() and 0xFF)) % 256
        val temp = s[i]
        s[i] = s[j]
        s[j] = temp
        val t = ((s[i].toInt() and 0xFF) + (s[j].toInt() and 0xFF)) % 256
        return s[t]

    }

    fun processByte(input: Byte) : Byte {

        val k = keyStreamByte()
        return (input.toInt() xor (k.toInt() and 0xFF)).toByte()

    }

}