# AOSP-Testkey-BootSigner (Android App 版)

将原电脑端 Python 重签脚本（AOSP-Testkey-BootSigner）移植并封装为原生 Android APP，支持直接在手机端导入 `boot.img`、`init_boot.img` 或 `vendor_boot.img` 并使用 AOSP 公共测试密钥（RSA-2048 / RSA-4096）进行 AVB 2.0 重构签名。

---

## ✨ 核心特性

- 📱 **纯手机端运行**：无需电脑环境、无需 Root 权限、无需 Termux，直接在 Android 设备上完成签名。
- 🔐 **AOSP TestKey 签名**：内置 AOSP 官方测试私钥（支持 RSA-2048 与 RSA-4096），自动生成标准 AVB Header、Hash Descriptor 与 64 字节 AVB Footer。
- 🔄 **自动识别与剥离**：自动检测原镜像是否包含历史 AVB Footer，并安全还原真实镜像体积后再签名。
- 📑 **实时控制台**：直观展示 SHA-256 计算、签名数据打包、对齐与输出日志。
- ⚡ **GitHub Actions 自动构建**：仓库自带 CI 工作流，代码推送后自动在云端编译生成 APK。

---

## 🛠️ 编译与使用方法

### 方式一：GitHub Actions 在线编译（最简便）
1. 将此项目文件夹内的所有内容上传/推送到您的 GitHub 仓库。
2. 进入 GitHub 仓库的 **Actions** 标签页。
3. 触发 **Build Android APK** 工作流（或推送代码自动触发）。
4. 构建完成后在 **Artifacts** 处下载 `AOSP-BootSigner-Debug-APK` 即可。

### 方式二：使用 Android Studio 本地编译
1. 打开 Android Studio，选择 **Open** 并定位到本工程目录。
2. 等待 Gradle 同步完成。
3. 点击顶部菜单 **Build -> Build Bundle(s) / APK(s) -> Build APK(s)**。
4. 编译完成后的 APK 位于 `app/build/outputs/apk/debug/`。

---

## 📂 项目结构说明

```text
AOSP-Testkey-BootSigner-App/
├── .github/workflows/
│   └── build-apk.yml               # GitHub Actions 云端自动编译 APK 配置
├── app/
│   ├── build.gradle.kts           # App 模块依赖与打包配置
│   ├── src/main/
│   │   ├── AndroidManifest.xml    # 应用清单文件
│   │   ├── assets/keys/           # 内置 AOSP 测试私钥 (RSA-2048 / RSA-4096)
│   │   ├── java/com/wjj/bootsigner/
│   │   │   ├── MainActivity.kt    # 主界面交互与协程调度
│   │   │   ├── signer/
│   │   │   │   ├── AvbSigner.kt   # AVB 重构与签名核心算法引擎
│   │   │   │   ├── AvbFooter.kt   # AVB 2.0 Header/Footer/Descriptor 结构
│   │   │   │   └── CryptoUtils.kt # RSA 签名与密钥解析工具
│   │   │   └── utils/
│   │   │       └── FileUtils.kt   # SAF 文件读写与流处理
│   │   └── res/                   # 界面布局与样式资源
├── gradle/
│   ├── libs.versions.toml         # 版本目录管理
│   └── wrapper/                   # Gradle Wrapper
├── build.gradle.kts               # 顶层构建配置
└── settings.gradle.kts            # 项目配置
```
