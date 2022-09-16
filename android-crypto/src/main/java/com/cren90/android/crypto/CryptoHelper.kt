package com.cren90.android.crypto

import com.cren90.android.logging.Logger
import com.cren90.kotlin.common.extensions.fromBase64
import com.cren90.kotlin.common.extensions.toBase64String
import java.security.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

object CryptoHelper {

    fun encrypt(algorithm: String, text: String, key: Key): EncryptOutputs? = try {
        val cipher = Cipher.getInstance(algorithm)

        cipher.init(Cipher.ENCRYPT_MODE, key)

        val bytes = text.toByteArray(Charsets.UTF_8)

        val cipherText = cipher.doFinal(bytes)

        EncryptOutputs(
            cipherText.toBase64String(),
            cipher.iv.toBase64String()
        )

    } catch (exception: GeneralSecurityException) {
        //Timber.e(exception, "Encrypt failed with exception")

        null
    }

    fun decrypt(algorithm: String, cipherText: String, key: Key, iv: String): String? = try {
        val cipher = Cipher.getInstance(algorithm)

        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv.fromBase64()))

        val decryptedBytes = cipher.doFinal(cipherText.fromBase64())

        decryptedBytes.toString(Charsets.UTF_8)

    } catch (exception: GeneralSecurityException) {
        //Timber.e(exception, "Decrypt failed with exception")
        null
    }

    fun sign(algorithm: String, data: ByteArray, key: PrivateKey): ByteArray {
        return Signature.getInstance(algorithm).run {
            initSign(key)
            update(data)
            sign()
        }
    }

    fun verify(algorithm: String, data: ByteArray, signature: ByteArray, key: PublicKey): Boolean {
        return Signature.getInstance(algorithm).run {
            initVerify(key)
            update(data)
            verify(signature)
        }
    }
}