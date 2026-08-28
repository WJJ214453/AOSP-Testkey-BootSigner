package com.wjj.bootsigner.signer

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateCrtKey

class AvbSigner(
    private val logCallback: (String) -> Unit
) {

    data class SignConfig(
        val partitionName: String = "boot",
        val isChainedMode: Boolean = true,
        val keyPemStream: InputStream,
        val keyBitSize: Int = 2048
    )

    fun signBootImage(
        sourceFile: File,
        outputFile: File,
        config: SignConfig
    ) {
        logCallback("🚀 开始解析镜像文件: ${sourceFile.name} (${sourceFile.length()} 字节)")

        val rawImageBytes = sourceFile.readBytes()
        var actualImageLength = rawImageBytes.size

        // Check if existing image already has an AVB footer
        if (actualImageLength >= 64) {
            val potentialFooter = rawImageBytes.copyOfRange(actualImageLength - 64, actualImageLength)
            val magic = String(potentialFooter.copyOfRange(0, 4), Charsets.US_ASCII)
            if (magic == AvbFooter.AVB_FOOTER_MAGIC) {
                logCallback("⚠️ 检测到原镜像已有 AVB Footer，正在剥离旧签名...")
                val footerBuffer = ByteBuffer.wrap(potentialFooter).order(ByteOrder.BIG_ENDIAN)
                footerBuffer.position(8) // Skip magic + versions
                val originalSize = footerBuffer.long
                if (originalSize in 1 until actualImageLength) {
                    actualImageLength = originalSize.toInt()
                    logCallback("ℹ️ 还原原镜像大小: $actualImageLength 字节")
                }
            }
        }

        val cleanImageBytes = rawImageBytes.copyOfRange(0, actualImageLength)

        // 1. Calculate SHA-256 of image
        logCallback("🔍 正在计算镜像哈希 (SHA-256)...")
        val md = MessageDigest.getInstance("SHA-256")
        val imageDigest = md.digest(cleanImageBytes)
        logCallback("✅ 镜像哈希: ${imageDigest.joinToString("") { "%02x".format(it) }}")

        // 2. Load RSA Private Key
        logCallback("🔑 正在加载 AOSP TestKey (${config.keyBitSize}-bit RSA)...")
        val privateKey: RSAPrivateCrtKey = CryptoUtils.loadPrivateKeyFromPem(config.keyPemStream)

        // 3. Build Descriptors
        val hashDescriptor = AvbFooter.createHashDescriptor(
            imageSize = cleanImageBytes.size.toLong(),
            partitionName = config.partitionName,
            digest = imageDigest
        )

        // 4. Build Auxiliary Block (Public Key + Descriptors)
        val auxStream = ByteArrayOutputStream()
        // Export public key in standard AVB format
        val modulusBytes = privateKey.modulus.toByteArray().let {
            if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it
        }
        val keyBlock = createAvbPublicKeyBlock(modulusBytes, privateKey.publicExponent.toLong(), config.keyBitSize)
        auxStream.write(keyBlock)
        auxStream.write(hashDescriptor)
        val auxData = auxStream.toByteArray()

        // 5. Build Auth Block (Signature)
        val authDataLength = config.keyBitSize / 8
        val hashForSign = md.digest(auxData)
        val signature = CryptoUtils.signSha256Rsa(hashForSign, privateKey)
        val authData = ByteBuffer.allocate(authDataLength).apply {
            put(signature)
        }.array()

        // 6. Build Vbmeta Header (256 bytes)
        val vbmetaHeader = ByteBuffer.allocate(AvbFooter.AVB_HEADER_SIZE).order(ByteOrder.BIG_ENDIAN)
        vbmetaHeader.put(AvbFooter.AVB_MAGIC.toByteArray(Charsets.US_ASCII)) // 4 bytes
        vbmetaHeader.putInt(AvbFooter.AVB_VERSION_MAJOR) // 4 bytes
        vbmetaHeader.putInt(AvbFooter.AVB_VERSION_MINOR) // 4 bytes
        vbmetaHeader.putLong(authData.size.toLong()) // 8 bytes auth_data_block_size
        vbmetaHeader.putLong(auxData.size.toLong()) // 8 bytes aux_data_block_size
        vbmetaHeader.putInt(if (config.keyBitSize == 4096) AvbFooter.AVB_ALGORITHM_TYPE_SHA256_RSA4096 else AvbFooter.AVB_ALGORITHM_TYPE_SHA256_RSA2048)
        vbmetaHeader.putInt(0) // hash_offset
        vbmetaHeader.putInt(authDataLength) // hash_size
        vbmetaHeader.putInt(0) // signature_offset
        vbmetaHeader.putInt(authDataLength) // signature_size
        vbmetaHeader.putInt(0) // public_key_offset
        vbmetaHeader.putInt(keyBlock.size) // public_key_size
        vbmetaHeader.putInt(keyBlock.size) // descriptors_offset
        vbmetaHeader.putInt(hashDescriptor.size) // descriptors_size

        val vbmetaStream = ByteArrayOutputStream()
        vbmetaStream.write(vbmetaHeader.array())
        vbmetaStream.write(authData)
        vbmetaStream.write(auxData)
        val vbmetaBytes = vbmetaStream.toByteArray()

        // 7. Align Image to 4096 bytes
        val outStream = FileOutputStream(outputFile)
        outStream.write(cleanImageBytes)

        val paddingSize = (4096 - (cleanImageBytes.size % 4096)) % 4096
        if (paddingSize > 0) {
            outStream.write(ByteArray(paddingSize))
        }

        val vbmetaOffset = cleanImageBytes.size + paddingSize.toLong()
        outStream.write(vbmetaBytes)

        val vbmetaPad = (4096 - (vbmetaBytes.size % 4096)) % 4096
        if (vbmetaPad > 0) {
            outStream.write(ByteArray(vbmetaPad))
        }

        // 8. Create & Append AVB Footer (64 bytes)
        val footer = AvbFooter.createFooter(
            originalImageSize = cleanImageBytes.size.toLong(),
            vbmetaOffset = vbmetaOffset,
            vbmetaSize = vbmetaBytes.size.toLong()
        )
        outStream.write(footer)
        outStream.flush()
        outStream.close()

        logCallback("✨ AVB Header & Footer 重建完成！")
        logCallback("📦 输出镜像大小: ${outputFile.length()} 字节 (原始: ${cleanImageBytes.size})")
        logCallback("🎉 签名成功！可直接导出刷写至设备。")
    }

    private fun createAvbPublicKeyBlock(modulus: ByteArray, exponent: Long, keyBitSize: Int): ByteArray {
        val buffer = ByteBuffer.allocate(8 + modulus.size).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(keyBitSize)
        buffer.putInt(exponent.toInt())
        buffer.put(modulus)
        return buffer.array()
    }
}
