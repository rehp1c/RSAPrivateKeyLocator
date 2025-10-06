# RSAPrivateKeyLocator

RSAPrivateKeyLocator 用于在指定目录中查找与给定公钥匹配的私钥文件，并提供RSA解密功能。方便快速定位加密公钥对应私钥文件。

## 功能特点

- 🔍 **自动私钥查找**：在指定目录中递归搜索与公钥匹配的私钥文件
- 🔑 **手动私钥导入**：支持直接导入私钥文件进行解密操作
- 🔓 **RSA解密功能**：使用找到的私钥解密加密数据
- 📦 **多种填充方案支持**：支持OAEP-SHA-256、OAEP-SHA-1、PKCS#1 v1.5等多种填充方案
- 📄 **多种输入格式**：支持Base64和Hex格式的密文输入
- 📁 **文件导入/导出**：支持从文件导入密文和导出解密结果
- 📊 **进度显示**：搜索过程中显示进度条，提供直观的反馈
- 🎨 **现代化UI**：美观、直观的用户界面，提供良好的用户体验

## 安装指南

### 安装步骤

1. 克隆仓库：

```
git clone https://github.com/rehp1c/RSAPrivateKeyLocator.git
cd RSAPrivateKeyLocator
```

2. 安装依赖：

```
pip install -r requirements.txt
```

3. 运行应用程序：

```
python RSAPrivateKeyLocator.py
```

或直接在[Releases](https://github.com/rehp1c/RSAPrivateKeyLocator/releases)使用

## 使用说明

### 自动查找私钥(通过公钥）

1. 在"通过公钥查找私钥"选项卡中
2. 选择公钥文件
3. 选择私钥搜索目录
4. 设置私钥文件扩展名（默认为pem, key）
5. 点击"搜索私钥文件"按钮
6. 从搜索结果中选择私钥文件
7. 点击"使用选中私钥解密"打开解密窗口
   
### 自动查找私钥(通过加密文件）

1. 在"通过加密文件查找私钥"选项卡中
2. 选择公钥文件
3. 选择私钥搜索目录
4. 设置私钥文件扩展名（默认为pem, key）
5. 点击"尝试解密文件"按钮
6. 从搜索结果中查看正确的解密内容

### 手动导入私钥

1. 切换到"手动导入私钥"选项卡
2. 点击"浏览..."按钮选择私钥文件
3. 点击"使用此私钥解密"打开解密窗口

### 解密操作

1. 在解密窗口中输入密文或从文件导入
2. 选择密文格式（Base64或Hex）
3. 选择填充方案
4. 点击"解密"按钮查看结果
5. 对于二进制数据，使用"保存解密结果"按钮保存到文件

## 致谢

- [PyQt5](https://pypi.org/project/PyQt5/)- 用于创建GUI界面
- [cryptography](https://pypi.org/project/cryptography/)- 提供加密功能

- 所有贡献者和用户
