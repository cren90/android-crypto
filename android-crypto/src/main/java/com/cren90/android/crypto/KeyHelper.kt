package com.cren90.android.crypto

import android.security.keystore.KeyGenParameterSpec
import java.math.BigInteger
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

object KeyHelper {
    fun getSymmetricKey(
        keystoreName: String,
        alias: String,
        algorithm: String,
        padding: String,
        blockMode: String,
        purposes: Int
    ): SecretKey {
        val keystore = initKeystore(keystoreName)

        if (!keystore.containsAlias(alias)) {
            val keyGenerator = KeyGenerator.getInstance(algorithm, keystoreName)

            val keyGenParameterSpec = KeyGenParameterSpec.Builder(alias, purposes)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(padding)
                .build()

            keyGenerator.init(keyGenParameterSpec)

            return keyGenerator.generateKey()

        } else {

            return keystore.getKey(alias, null) as SecretKey
        }
    }

    @Suppress("MemberVisibilityCanBePrivate", "unused")
    fun getAsymmetricPrivateKey(
        keystoreName: String,
        alias: String,
        certSubject: String,
        algorithm: String,
        paddings: String
    ): PrivateKey = getAsymmetricKeys(
        keystoreName,
        alias,
        certSubject,
        algorithm,
        paddings
    ).private

    @Suppress("MemberVisibilityCanBePrivate", "unused")
    fun getAsymmetricPublicKey(
        keystoreName: String,
        alias: String,
        certSubject: String,
        algorithm: String,
        paddings: String
    ): PublicKey = getAsymmetricKeys(
        keystoreName,
        alias,
        certSubject,
        algorithm,
        paddings
    ).public

    @Suppress("MemberVisibilityCanBePrivate", "unused")
    fun getAsymmetricKeys(
        keystoreName: String,
        alias: String,
        certSubject: String,
        algorithm: String,
        paddings: String
    ): KeyPair {
        val keystore = initKeystore(keystoreName)

        if (!keystore.containsAlias(alias)) {
            val start = Calendar.getInstance()
            val end = Calendar.getInstance()
            end.add(Calendar.YEAR, 1)

            val spec: AlgorithmParameterSpec = KeyGenParameterSpec.Builder(
                alias,
                PURPOSE_ENCRYPT or PURPOSE_DECRYPT
            )
                .setCertificateSubject(X500Principal(certSubject))
                .setCertificateSerialNumber(BigInteger.ONE)
                .setKeyValidityStart(start.time)
                .setKeyValidityEnd(end.time)
                .setEncryptionPaddings(paddings)
                .build()

            val generator = KeyPairGenerator.getInstance(algorithm, keystoreName)
            generator.initialize(spec)
            return generator.generateKeyPair()
        } else {
            val privateKey = keystore.getKey(alias, null) as PrivateKey
            val publicKey = keystore.getCertificate(alias).publicKey
            return KeyPair(publicKey, privateKey)
        }
    }

    @Suppress("unused")
    fun getECPrivateKey(
        keystoreName: String,
        alias: String
    ) = getECKeyPair(keystoreName, alias).private

    @Suppress("unused")
    fun getECPublicKey(
        keystoreName: String,
        alias: String
    ) = getECKeyPair(keystoreName, alias).public

    fun getECKeyPair(keystoreName: String, alias: String): KeyPair {
        val keystore = initKeystore(keystoreName)

        if (!keystore.containsAlias(alias)) {
            val generator = KeyPairGenerator.getInstance(EC, keystoreName)
            val parameterSpec =
                KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN or PURPOSE_VERIFY)
                    .setDigests(SHA256)
                    .setUserAuthenticationRequired(false)
                    .build()

            generator.initialize(parameterSpec)
            return generator.generateKeyPair()
        } else {
            val privateKey = keystore.getKey(alias, null) as PrivateKey

            val publicKey = keystore.getCertificate(alias).publicKey as PublicKey
            return KeyPair(publicKey, privateKey)
        }
    }

    private fun initKeystore(keystoreName: String): KeyStore {
        val keystore = KeyStore.getInstance(keystoreName)
        keystore.load(null)
        return keystore
    }

    fun deleteKey(keystoreName: String, alias: String) {
        val keystore = KeyStore.getInstance(keystoreName)
        keystore.load(null)
        if (keystore.containsAlias(alias)) {
            keystore.deleteEntry(alias)
        }
    }
}