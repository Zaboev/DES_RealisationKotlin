package DiffieHellman
import java.math.BigInteger
import java.util.concurrent.BlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference

class Member(
    private val name: String,
    private val initiator: Boolean,
    private val inbox: BlockingQueue<Message>,
    private val outbox: BlockingQueue<Message>,
    private val resultKey: AtomicReference<ByteArray>,
    private val done: CountDownLatch
) : Runnable {

    override fun run() {

        var params: DiffieHellman.Params? = null
        var myKeyPair: DiffieHellman.KeyPair? = null
        var otherPublic: BigInteger? = null

        fun log(s: String) = println("$name $s")

        try {

            if (initiator) {

                params = DiffieHellman.GROUP14_2048
                myKeyPair = DiffieHellman.generateKeyPair(params)

                outbox.put(Message.Params(params.p, params.g))
                outbox.put(Message.PublicKey(myKeyPair.publicKey))

            }

            while (true) {

                val msg = inbox.take()

                when (msg) {

                    is Message.Params -> {

                        if (params == null) {

                            params = DiffieHellman.Params(msg.p, msg.g)
                            myKeyPair = DiffieHellman.generateKeyPair(params)
                            outbox.put(Message.PublicKey(myKeyPair.publicKey))

                        }

                    }

                    is Message.PublicKey -> {

                        otherPublic = msg.value

                    }

                }

                if (params != null && myKeyPair != null && otherPublic != null) {

                    val secret = DiffieHellman.computeSharedSecret(params, myKeyPair.privateKey, otherPublic)
                    val key = DiffieHellman.deriveKeySha256(secret)
                    resultKey.set(key)
                    log("derived key prefix = ${DiffieHellman.hexPrefix(key)}")
                    done.countDown()
                    return

                }

            }

        }
        catch (e: Exception) {

            log("${e.message}")
            done.countDown()

        }
    }
}