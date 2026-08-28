package com.wjj.bootsigner

import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wjj.bootsigner.databinding.ActivityMainBinding
import com.wjj.bootsigner.signer.AvbSigner
import com.wjj.bootsigner.utils.FileUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var selectedFileUri: Uri? = null
    private var signedTempFile: File? = null

    private val selectFileLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            selectedFileUri = uri
            binding.tvSelectedFile.text = uri.lastPathSegment ?: uri.toString()
            binding.btnSign.enabled(true)
            log("📁 已选择文件: ${binding.tvSelectedFile.text}")
        }
    }

    private val saveFileLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        if (uri != null && signedTempFile != null && signedTempFile!!.exists()) {
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    FileUtils.copyFileToUri(this@MainActivity, signedTempFile!!, uri)
                    withContext(Dispatchers.Main) {
                        log("💾 成功保存至: $uri")
                        Toast.makeText(this@MainActivity, "文件保存成功！", Toast.LENGTH_LONG).show()
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        log("❌ 保存失败: ${e.message}")
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        initViews()
    }

    private fun initViews() {
        binding.btnSelectFile.setOnClickListener {
            selectFileLauncher.launch("*/*")
        }

        binding.btnSign.setOnClickListener {
            startSigning()
        }

        binding.btnSave.setOnClickListener {
            val partition = binding.etPartitionName.text.toString().trim().ifEmpty { "boot" }
            saveFileLauncher.launch("${partition}_signed.img")
        }
    }

    private fun startSigning() {
        val uri = selectedFileUri ?: return
        binding.btnSign.enabled(false)
        binding.btnSave.enabled(false)

        val partitionName = binding.etPartitionName.text.toString().trim().ifEmpty { "boot" }
        val isRsa4096 = binding.rbKey4096.isChecked
        val isChained = binding.rbModeChained.isChecked
        val keyAssetPath = if (isRsa4096) "keys/testkey_rsa4096.pem" else "keys/testkey_rsa2048.pem"
        val keyBits = if (isRsa4096) 4096 else 2048

        log("----------------------------------------")
        log("⚙️ 开始任务: 分区[$partitionName] 模式[${if (isChained) "Chained" else "Standard"}] 密钥[RSA-$keyBits]")

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val cacheDir = applicationContext.cacheDir
                val inputTemp = File(cacheDir, "input_boot.img")
                val outputTemp = File(cacheDir, "signed_boot.img")

                log("📥 正在读取所选文件...")
                FileUtils.copyUriToFile(this@MainActivity, uri, inputTemp)

                val signer = AvbSigner { msg ->
                    runOnUiThread { log(msg) }
                }

                val keyStream = assets.open(keyAssetPath)
                val config = AvbSigner.SignConfig(
                    partitionName = partitionName,
                    isChainedMode = isChained,
                    keyPemStream = keyStream,
                    keyBitSize = keyBits
                )

                signer.signBootImage(inputTemp, outputTemp, config)
                signedTempFile = outputTemp

                withContext(Dispatchers.Main) {
                    binding.btnSign.enabled(true)
                    binding.btnSave.enabled(true)
                    Toast.makeText(this@MainActivity, "签名完成，请点击保存！", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    log("❌ 签名过程出错: ${e.message}")
                    e.printStackTrace()
                    binding.btnSign.enabled(true)
                }
            }
        }
    }

    private fun log(message: String) {
        val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        val currentText = binding.tvConsole.text.toString()
        binding.tvConsole.text = "$currentText\n[$time] $message"
    }

    private fun com.google.android.material.button.MaterialButton.enabled(enabled: Boolean) {
        this.isEnabled = enabled
        this.alpha = if (enabled) 1.0f else 0.5f
    }
}
