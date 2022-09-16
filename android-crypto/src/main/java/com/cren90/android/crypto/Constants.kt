package com.cren90.android.crypto

import android.security.keystore.KeyProperties

const val ANDROID_KEYSTORE = "AndroidKeyStore"
const val RSA = KeyProperties.KEY_ALGORITHM_RSA
const val AES = KeyProperties.KEY_ALGORITHM_AES
const val EC = KeyProperties.KEY_ALGORITHM_EC
const val CBC = KeyProperties.BLOCK_MODE_CBC
const val ECB = KeyProperties.BLOCK_MODE_ECB
const val PKCS1 = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
const val SHA256 = KeyProperties.DIGEST_SHA256
const val SHA512 = KeyProperties.DIGEST_SHA512
const val PKCS5 = "PKCS5Padding"
const val PKCS7 = KeyProperties.ENCRYPTION_PADDING_PKCS7
const val AES_CBC_PKCS5 = "$AES/$CBC/$PKCS5"
const val AES_CBC_PKCS7 = "$AES/$CBC/$PKCS7"
const val AES_ECB_PKCS5 = "$AES/$ECB/$PKCS5"
const val AES_ECB_PKCS7 = "$AES/$ECB/$PKCS7"
const val SHA256_ECDSA = "SHA256withECDSA"
const val PURPOSE_ENCRYPT = KeyProperties.PURPOSE_ENCRYPT
const val PURPOSE_DECRYPT = KeyProperties.PURPOSE_DECRYPT
const val PURPOSE_SIGN = KeyProperties.PURPOSE_SIGN
const val PURPOSE_VERIFY = KeyProperties.PURPOSE_VERIFY