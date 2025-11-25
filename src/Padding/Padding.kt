package Padding
import Enums.Padding
import java.security.SecureRandom

fun paddingAdd(block: ByteArray, paddingType: Padding, blockSize: Int): ByteArray {

    if (blockSize == block.size) return block

    val paddingLength = blockSize - (block.size.takeIf { it != 0 } ?: blockSize)

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

fun paddingRemove(block: ByteArray, paddingType: Padding, blockSize: Int): ByteArray {

    return when (paddingType) {

        Padding.Zeros -> block.dropLastWhile { it == 0.toByte() }.toByteArray()
        else -> {

            val last = block.last().toInt() and 0xFF

            if (last < 1 || last > blockSize) return block

            if (last > block.size) return block
            block.dropLast(last).toByteArray()

        }

    }

}