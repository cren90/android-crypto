@file:Suppress("unused")

package com.cren90.android.crypto.extension

import java.math.BigInteger
import java.security.interfaces.ECPublicKey

fun ECPublicKey.toByteArray(): ByteArray {
    val keyLengthBytes = this.params.order.bitLength()

    val publicKeyBytes = ByteArray(2 * keyLengthBytes)

    var offset = 0

    val x: BigInteger = this.w.affineX
    val xba: ByteArray = x.toByteArray()
    check(
        !(xba.size > keyLengthBytes + 1 || xba.size == keyLengthBytes + 1
                && xba[0] != 0.toByte())
    ) { "X coordinate of EC public key has wrong size" }

    if (xba.size == keyLengthBytes + 1) {
        System.arraycopy(xba, 1, publicKeyBytes, offset, keyLengthBytes)
    } else {
        System.arraycopy(
            xba, 0, publicKeyBytes, offset + keyLengthBytes
                    - xba.size, xba.size
        )
    }
    offset += keyLengthBytes

    val y: BigInteger = this.w.affineY
    val yba: ByteArray = y.toByteArray()
    check(
        !(yba.size > keyLengthBytes + 1 || yba.size == keyLengthBytes + 1
                && yba[0] != 0.toByte())
    ) { "Y coordinate of EC public key has wrong size" }

    if (yba.size == keyLengthBytes + 1) {
        System.arraycopy(yba, 1, publicKeyBytes, offset, keyLengthBytes)
    } else {
        System.arraycopy(
            yba, 0, publicKeyBytes, offset + keyLengthBytes
                    - yba.size, yba.size
        )
    }

    return publicKeyBytes
}