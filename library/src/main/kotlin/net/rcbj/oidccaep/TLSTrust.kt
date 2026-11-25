// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Extra certificates to trust for the provider's TLS connections: a private CA's root (a trust anchor), or a full
 * chain (leaf, intermediates and root). Every certificate given counts as a trust anchor, so a chain may be given
 * whole or in part. The host name is still checked.
 *
 * Use it for an identity provider whose certificate is issued by a private CA (a self-signed test iya-sts),
 * instead of turning verification off with `InsecureSkipTLSVerification`.
 */
public class TLSTrust(
    /** The certificates, DER encoded. */
    public val certificates: List<ByteArray>,
    /** Whether the system's trusted roots still count. With `false`, only [certificates] are trusted. */
    public val includeSystemRoots: Boolean = true,
) {
    override fun equals(other: Any?): Boolean = other is TLSTrust && other.includeSystemRoots == includeSystemRoots &&
        other.certificates.size == certificates.size && other.certificates.zip(certificates).all { (a, b) -> a.contentEquals(b) }

    override fun hashCode(): Int = certificates.fold(includeSystemRoots.hashCode()) { h, c -> 31 * h + c.contentHashCode() }

    /** A trust manager accepting chains that lead to one of [certificates], or (when allowed) to a system root. */
    internal fun trustManager(): X509TrustManager {
        val factory = CertificateFactory.getInstance("X.509")
        val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
        certificates.forEachIndexed { i, der ->
            anchors.setCertificateEntry("trusted-$i", factory.generateCertificate(der.inputStream()))
        }
        val custom = managerFor(anchors)
        val system = if (includeSystemRoots) managerFor(null) else null
        return object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                throw CertificateException("Client certificates are not checked here")
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
                try {
                    custom.checkServerTrusted(chain, authType)
                } catch (e: CertificateException) {
                    // A chain whose leaf (or an intermediate) was itself given counts as trusted.
                    if (chain.any { c -> certificates.any { it.contentEquals(c.encoded) } }) return
                    system?.checkServerTrusted(chain, authType) ?: throw e
                }
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = custom.acceptedIssuers + (system?.acceptedIssuers ?: emptyArray())
        }
    }

    private fun managerFor(store: KeyStore?): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(store)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    public companion object {
        /** From PEM text (one or more `CERTIFICATE` blocks) or DER data, each entry a file's contents. */
        public fun fromPemOrDer(entries: List<ByteArray>, includeSystemRoots: Boolean = true): TLSTrust {
            val certs = mutableListOf<ByteArray>()
            for (entry in entries) {
                val text = entry.decodeToString()
                when {
                    text.contains("-----BEGIN CERTIFICATE-----") -> certs += parsePEM(text)
                    entry.isNotEmpty() && entry[0] == 0x30.toByte() -> certs += entry // DER: a SEQUENCE
                    else -> throw OIDCError.usage("A trusted certificate is neither PEM nor DER")
                }
            }
            if (certs.isEmpty()) throw OIDCError.usage("No certificates were found in the trusted certificates given")
            return TLSTrust(certs, includeSystemRoots)
        }

        internal fun parsePEM(text: String): List<ByteArray> {
            val out = mutableListOf<ByteArray>()
            var rest = text
            while (true) {
                val begin = rest.indexOf("-----BEGIN CERTIFICATE-----")
                if (begin < 0) break
                val start = begin + "-----BEGIN CERTIFICATE-----".length
                val end = rest.indexOf("-----END CERTIFICATE-----", start)
                if (end < 0) throw OIDCError.usage("A PEM certificate has no END line")
                val body = rest.substring(start, end).filterNot(Char::isWhitespace)
                out += try { Base64.getDecoder().decode(body) } catch (e: IllegalArgumentException) {
                    throw OIDCError.usage("A PEM certificate is not valid base64")
                }
                rest = rest.substring(end + "-----END CERTIFICATE-----".length)
            }
            return out
        }
    }
}
