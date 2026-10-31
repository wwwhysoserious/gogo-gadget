package app.gogogadget

import javax.net.ssl.SSLContext

/**
 * libadb-android keeps ONE SSLContext for the whole process (`SslUtils.sslContext`), built around the first key pair
 * it ever saw, and hands it to every later pairing and TLS connect, whatever key that call brings. With several
 * identities (this phone, the shared key, one per network device) and keys that are deleted and made again, a handshake would present the wrong
 * certificate: a connect right after pairing is then refused, or it silently authenticates with a key the user
 * deleted. Dropping the cached context before every handshake makes the library build a new one around the key pair
 * of the call at hand. Callers hold the ADB lock, so no handshake is running while this happens.
 */
object LibAdbTls {
    private const val CLASS_NAME = "io.github.muntashirakon.adb.SslUtils"
    private const val FIELD_NAME = "sslContext"

    /** True when the library has no cached context any more (also when it had none). */
    fun reset(): Boolean = try {
        field().set(null, null)
        true
    } catch (e: Exception) {
        false
    } catch (e: LinkageError) {
        false
    }

    /** The context the library holds right now, for tests. */
    internal fun cached(): SSLContext? = field().get(null) as SSLContext?

    private fun field() = Class.forName(CLASS_NAME).getDeclaredField(FIELD_NAME).apply { isAccessible = true }
}
