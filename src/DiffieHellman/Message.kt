package DiffieHellman
import java.math.BigInteger

sealed class Message {

    data class Params(val p: BigInteger, val g: BigInteger) : Message()
    data class PublicKey(val value: BigInteger) : Message()

}