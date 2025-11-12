package Padding
import Enums.Padding
import java.security.SecureRandom

fun paddingAdd(block: ByteArray, paddingType: Padding): ByteArray {

    val paddingLength = 8 - (block.size.takeIf { it != 0 } ?: 8)

    return when (paddingType) {

        Padding.Zeros -> block + ByteArray(paddingLength) { 0 }
        Padding.ANSI_X923 -> block + ByteArray(paddingLength - 1) { 0 } + byteArrayOf(paddingLength.toByte())
        Padding.PKCS7 -> block + ByteArray(paddingLength) { paddingLength.toByte() }
        Padding.ISO10126 -> {

            val random = SecureRandom()
            val randomBytes = ByteArray(paddingLength - 1).also { random.nextBytes(it) }
            block + randomBytes + byteArrayOf(paddingLength.toByte())

        }

    }

}

fun paddingRemove(block: ByteArray, paddingType: Padding): ByteArray {

    return when (paddingType) {

        Padding.Zeros -> block.dropLastWhile { it == 0.toByte() }.toByteArray()
        else -> {

            val last = block.last().toInt() and 0xFF

            if (last < 1 || last > 8) return block

            if (last > block.size) return block
            block.dropLast(last).toByteArray()

        }

    }

}