package com.wjj.bootsigner.signer

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * AVB (Android Verified Boot) 2.0 Data Structures and Encoders
 */
object AvbFooter {
    const val AVB_MAGIC = "AVB0"
    const val AVB_FOOTER_MAGIC = "AVBf"
    const val AVB_FOOTER_SIZE = 64
    const val AVB_HEADER_SIZE = 256
    const val AVB_VERSION_MAJOR = 1
    const val AVB_VERSION_MINOR = 0

    const val AVB_DESCRIPTOR_TAG_HASH: Long = 1
    const val AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: Long = 4

    const val AVB_ALGORITHM_TYPE_NONE = 0
    const val AVB_ALGORITHM_TYPE_SHA256_RSA2048 = 1
    const val AVB_ALGORITHM_TYPE_SHA256_RSA4096 = 2

    /**
     * Create 64-byte AVB Footer
     */
    fun createFooter(
        originalImageSize: Long,
        vbmetaOffset: Long,
        vbmetaSize: Long
    ): ByteArray {
        val buffer = ByteBuffer.allocate(AVB_FOOTER_SIZE).order(ByteOrder.BIG_ENDIAN)
        buffer.put(AVB_FOOTER_MAGIC.toByteArray(Charsets.US_ASCII)) // 4 bytes magic
        buffer.putInt(AVB_VERSION_MAJOR) // 4 bytes major version
        buffer.putInt(AVB_VERSION_MINOR) // 4 bytes minor version
        buffer.putLong(originalImageSize) // 8 bytes original image size
        buffer.putLong(vbmetaOffset) // 8 bytes vbmeta offset
        buffer.putLong(vbmetaSize) // 8 bytes vbmeta size
        buffer.put(ByteArray(28)) // 28 bytes reserved
        return buffer.array()
    }

    /**
     * Create AVB Hash Descriptor
     */
    fun createHashDescriptor(
        imageSize: Long,
        partitionName: String,
        digest: ByteArray,
        salt: ByteArray = ByteArray(0)
    ): ByteArray {
        val nameBytes = partitionName.toByteArray(Charsets.UTF_8)
        val numBytesFollowing = 8L + 8L + 4L + 4L + 4L + 4L + (4L * 4L) +
                nameBytes.size + salt.size + digest.size

        // Total descriptor size must be multiple of 8 bytes
        val totalSize = 16 + numBytesFollowing.toInt()
        val paddedSize = (totalSize + 7) and 7.inv()
        val paddingSize = paddedSize - totalSize

        val buffer = ByteBuffer.allocate(paddedSize).order(ByteOrder.BIG_ENDIAN)
        buffer.putLong(AVB_DESCRIPTOR_TAG_HASH) // tag (8 bytes)
        buffer.putLong(numBytesFollowing + paddingSize) // num_bytes_following (8 bytes)
        buffer.putLong(imageSize) // image_size (8 bytes)
        buffer.put(ByteArray(8)) // digest_size placeholder / reserved (8 bytes)
        buffer.putInt(nameBytes.size) // partition_name_len (4 bytes)
        buffer.putInt(salt.size) // salt_len (4 bytes)
        buffer.putInt(digest.size) // digest_len (4 bytes)
        buffer.putInt(0) // flags (4 bytes)
        buffer.put(ByteArray(16)) // reserved (16 bytes)
        buffer.put(nameBytes) // partition name
        buffer.put(salt) // salt
        buffer.put(digest) // digest
        if (paddingSize > 0) {
            buffer.put(ByteArray(paddingSize))
        }

        return buffer.array()
    }
}
