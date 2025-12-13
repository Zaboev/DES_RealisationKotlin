import DiffieHellman.*
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference

fun main() {

    val aInbox = LinkedBlockingQueue<Message>()
    val bInbox = LinkedBlockingQueue<Message>()

    val latch = CountDownLatch(2)

    val aKey = AtomicReference<ByteArray>()
    val bKey = AtomicReference<ByteArray>()

    val alice = Thread(
        Member(
            name = "Alice",
            initiator = true,
            inbox = aInbox,
            outbox = bInbox,
            resultKey = aKey,
            done = latch
        ),
        "AliceThread"
    )

    val bob = Thread(
        Member(
            name = "Bob",
            initiator = false,
            inbox = bInbox,
            outbox = aInbox,
            resultKey = bKey,
            done = latch
        ),
        "BobThread"
    )

    bob.start()
    alice.start()

    latch.await()

    val k1 = aKey.get()
    val k2 = bKey.get()

    if (k1 != null && k2 != null && k1.contentEquals(k2)) println("\nSuccess (prefix=${DiffieHellman.hexPrefix(k1)})")
    else println("\nFailure")

    alice.join()
    bob.join()

}