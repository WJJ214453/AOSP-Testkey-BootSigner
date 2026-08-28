package com.wjj.bootsigner.signer

import org.bouncycastle.util.io.pem.PemReader
import java.io.InputStream
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.math.BigInteger

object CryptoUtils {

    /**
     * Parse PEM private key stream into PrivateKey object
     */
    fun loadPrivateKeyFromPem(inputStream: InputStream): RSAPrivateCrtKey {
        PemReader(InputStreamReader(inputStream)).use { reader ->
            val pemObject = reader.readPemObject() ?: throw IllegalArgumentException("Invalid PEM key file")
            val keyBytes = pemObject.content

            return try {
                // Try PKCS#8 format first
                val keySpec = PKCS8EncodedKeySpec(keyBytes)
                val kf = KeyFactory.getInstance("RSA")
                kf.generatePrivate(keySpec) as RSAPrivateCrtKey
            } catch (e: Exception) {
                // Fallback to PKCS#1 parser for RSA private key
                parsePkcs1RsaPrivateKey(keyBytes)
            }
        }
    }

    private fun parsePkcs1RsaPrivateKey(bytes: ByteArray): RSAPrivateCrtKey {
        // Parse ASN.1 DER sequence for PKCS#1 RSA Private Key
        val seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(bytes)
        val modulus = (seq.getObjectAt(1) as org.bouncycastle.asn1.ASN1Integer).value
        val publicExp = (seq.getObjectAt(2) as org.bouncycastle.asn1.ASN1Integer).value
        val privateExp = (seq.getObjectAt(3) as org.bouncycastle.asn1.ASN1Integer).value
        val prime1 = (seq.getObjectAt(4) as org.bouncycastle.asn1.ASN1Integer).value
        val prime2 = (seq.getObjectAt(5) as org.bouncycastle.asn1.ASN1Integer).value
        val exp1 = (seq.getObjectAt(6) as org.bouncycastle.asn1.ASN1Integer).value
        val exp2 = (seq.getObjectAt(7) as org.bouncycastle.asn1.ASN1Integer).value
        val crtCoef = (seq.getObjectAt(8) as org.bouncycastle.asn1.ASN1Integer).value

        val keySpec = RSAPrivateCrtKeySpec(
            modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef
        )
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec) as RSAPrivateCrtKey
    }

    /**
     * Sign data with SHA256withRSA (PKCS#1 v1.5 padding)
     */
    fun signSha256Rsa(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey)
        signer.update(data)
        return signer.sign()
    }
}
