package Rijndael

class RijndaelMixColumns {

    fun gfMultiply(x: Byte): Byte {

        val b = x.toInt() and 0xFF
        val shifted = (b shl 1) and 0xFF
        return if ((b and 0x80) != 0) (shifted xor 0x1B).toByte()
        else shifted.toByte()

    }

    fun multiply02(x: Byte): Byte = gfMultiply(x)

    fun multiply03(x: Byte): Byte = (gfMultiply(x).toInt() xor (x.toInt() and 0xFF)).toByte()

    fun multiply09(x: Byte): Byte {

        val x2 = gfMultiply(x)
        val x4 = gfMultiply(x2)
        val x8 = gfMultiply(x4)
        return (x8.toInt() xor (x.toInt() and 0xFF)).toByte()

    }

    fun multiply0B(x: Byte): Byte {

        val x2 = gfMultiply(x)
        val x4 = gfMultiply(x2)
        val x8 = gfMultiply(x4)
        return ((x8.toInt() xor x2.toInt() xor (x.toInt() and 0xFF)) and 0xFF).toByte()

    }

    fun multiply0D(x: Byte): Byte {

        val x2 = gfMultiply(x)
        val x4 = gfMultiply(x2)
        val x8 = gfMultiply(x4)
        return ((x8.toInt() xor x4.toInt() xor (x.toInt() and 0xFF)) and 0xFF).toByte()

    }

    fun multiply0E(x: Byte): Byte {

        val x2 = gfMultiply(x)
        val x4 = gfMultiply(x2)
        val x8 = gfMultiply(x4)
        return (x8.toInt() xor x4.toInt() xor x2.toInt() and 0xFF).toByte()

    }

}