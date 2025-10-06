from os import walk, path
from sys import exit, argv
from base64 import b64decode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from hashlib import md5
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QLineEdit, QTextEdit, QFileDialog, QComboBox,
                             QGroupBox, QCheckBox, QListWidget, QMessageBox, QProgressBar,
                             QTabWidget, QDesktopWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QPalette, QColor, QFont, QIcon


# 常见文件类型的魔数（Magic Number）
FILE_SIGNATURES = {
    "ZIP": b"PK\x03\x04",
    "JPG": b"\xFF\xD8\xFF\xE0",
    "PNG": b"\x89PNG\r\n\x1a\n",
    "GIF": b"GIF89a",
    "PDF": b"%PDF",
    "MP3": b"ID3",
    "MP4": b"\x00\x00\x00\x18ftyp",
    "EXE": b"MZ",
    "DOC": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",  # DOC/OLE2
    "DOCX": b"PK\x03\x04",  # DOCX is a ZIP file
    "XLS": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",  # XLS/OLE2
    "XLSX": b"PK\x03\x04",  # XLSX is a ZIP file
    "PPT": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",  # PPT/OLE2
    "PPTX": b"PK\x03\x04",  # PPTX is a ZIP file
    "7Z": b"7z\xBC\xAF\x27\x1C",
    "RAR": b"Rar!\x1A\x07\x00",
    "BMP": b"BM",
    "TIFF": b"II*\x00"  # Little-endian TIFF
}


class KeySearchThread(QThread):
    """后台搜索私钥的线程"""
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(list)
    error_signal = pyqtSignal(str)

    def __init__(self, public_key_path, search_dir, extensions):
        super().__init__()
        self.public_key_path = public_key_path
        self.search_dir = search_dir
        self.extensions = extensions

    def run(self):
        try:
            # 获取公钥模数的MD5
            target_md5 = self.get_public_key_modulus_md5(self.public_key_path)
            self.progress_signal.emit(10)
            # 遍历目录查找匹配的私钥
            matches = []
            total_files = 0
            scanned_files = 0
            # 先计算总文件数
            for root, _, files in walk(self.search_dir):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in self.extensions):
                        total_files += 1
            if total_files == 0:
                self.error_signal.emit("在指定目录中未找到任何私钥文件")
                return
            # 开始搜索
            for root, _, files in walk(self.search_dir):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in self.extensions):
                        private_key_path = path.join(root, file)
                        try:
                            private_md5 = self.get_private_key_modulus_md5(
                                private_key_path)
                            if private_md5 == target_md5:
                                matches.append(private_key_path)
                        except Exception:
                            continue
                        scanned_files += 1
                        progress = 10 + int(90 * scanned_files / total_files)
                        self.progress_signal.emit(progress)
            self.result_signal.emit(matches)
        except Exception as e:
            self.error_signal.emit(str(e))

    def get_public_key_modulus_md5(self, public_key_path):
        """提取公钥文件的模数并计算其MD5指纹"""
        try:
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            # 获取模数并计算MD5
            modulus = public_key.public_numbers().n
            modulus_bytes = modulus.to_bytes(
                (modulus.bit_length() + 7) // 8, 'big')
            return md5(modulus_bytes).hexdigest()
        except Exception as e:
            raise ValueError(f"公钥解析失败: {e}")

    def get_private_key_modulus_md5(self, private_key_path):
        """提取私钥文件的模数并计算其MD5指纹"""
        try:
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            # 私钥模数与公钥模数相同
            modulus = private_key.private_numbers().public_numbers.n
            modulus_bytes = modulus.to_bytes(
                (modulus.bit_length() + 7) // 8, 'big')
            return md5(modulus_bytes).hexdigest()
        except Exception as e:
            raise ValueError(f"私钥解析失败 ({private_key_path}): {e}")


class DecryptFileThread(QThread):
    """后台尝试解密文件的线程"""
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(str, str, str)  # 私钥路径、解密结果、文件类型
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, encrypted_file_path, private_key_path, file_format):
        super().__init__()
        self.encrypted_file_path = encrypted_file_path
        self.private_key_path = private_key_path
        self.file_format = file_format

    def run(self):
        try:
            # 读取加密文件内容
            with open(self.encrypted_file_path, "rb") as enc_file:
                file_content = enc_file.read()

            # 根据文件格式转换数据
            if self.file_format == "Base64":
                # 尝试解码Base64内容
                try:
                    encrypted_data = b64decode(file_content)
                except Exception:
                    # 如果解码失败，尝试直接使用二进制数据
                    encrypted_data = file_content
            elif self.file_format == "Hex":
                # 尝试解码Hex内容
                try:
                    encrypted_data = bytes.fromhex(
                        file_content.decode('utf-8'))
                except Exception:
                    # 如果解码失败，尝试直接使用二进制数据
                    encrypted_data = file_content
            else:  # 二进制格式
                encrypted_data = file_content

            # 加载私钥
            with open(self.private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )

            self.progress_signal.emit(30)

            # 尝试所有支持的填充方案
            padding_schemes = self.get_all_padding_schemes()
            decrypted_data = None
            used_padding = None

            for name, scheme in padding_schemes:
                try:
                    # 检查是否需要分块解密
                    max_decrypt_size = private_key.key_size // 8
                    if len(encrypted_data) > max_decrypt_size:
                        # 对于大量数据，进行分块解密
                        decrypted_chunks = []
                        total_chunks = (len(encrypted_data) +
                                        max_decrypt_size - 1) // max_decrypt_size
                        for i in range(0, len(encrypted_data), max_decrypt_size):
                            chunk = encrypted_data[i:i + max_decrypt_size]
                            decrypted_chunk = private_key.decrypt(
                                chunk, scheme)
                            decrypted_chunks.append(decrypted_chunk)
                            progress = 30 + \
                                int(70 * (i // max_decrypt_size) / total_chunks)
                            self.progress_signal.emit(progress)
                        # 合并所有块
                        decrypted_data = b''.join(decrypted_chunks)
                    else:
                        # 小量数据直接解密
                        decrypted_data = private_key.decrypt(
                            encrypted_data, scheme)
                        self.progress_signal.emit(100)

                    # 如果解密成功，记录使用的填充方案并退出循环
                    used_padding = name
                    break
                except Exception:
                    # 当前填充方案失败，尝试下一个
                    continue

            if decrypted_data is None:
                self.error_signal.emit(
                    f"使用私钥 {self.private_key_path} 解密失败: 所有填充方案均失败")
                return

            # 检测文件类型
            file_type = self.detect_file_type(decrypted_data)

            # 尝试UTF-8解码
            try:
                result_str = decrypted_data.decode('utf-8')
                result_output = f"✅ 解密成功! (填充方案: {used_padding})\n文件类型: {file_type}\n{result_str}"
            except UnicodeDecodeError:
                # 如果不能解码为UTF-8，则显示二进制信息
                hex_data = decrypted_data.hex()
                preview = hex_data[:32] + \
                    "..." if len(hex_data) > 32 else hex_data
                result_output = (
                    f"✅ 解密成功! (填充方案: {used_padding})\n"
                    f"文件类型: {file_type}\n"
                    f"结果为二进制数据:\n"
                    f"前16字节: {decrypted_data[:16]}\n"
                    f"十六进制预览: {preview}\n"
                    f"总长度: {len(decrypted_data)} 字节"
                )
            self.result_signal.emit(
                self.private_key_path, result_output, file_type)

        except Exception as e:
            self.error_signal.emit(f"使用私钥 {self.private_key_path} 解密失败: {e}")
        finally:
            self.finished_signal.emit()

    def get_all_padding_schemes(self):
        """返回所有支持的填充方案"""
        return [
            ("OAEP-SHA-256", padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )),
            ("OAEP-SHA-256 with MGF1-SHA-1", padding.OAEP(
                mgf=padding.MGF1(hashes.SHA1()),
                algorithm=hashes.SHA256(),
                label=None
            )),
            ("OAEP-SHA-1", padding.OAEP(
                mgf=padding.MGF1(hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )),
            ("OAEP-SHA-1 with MGF1-SHA-256", padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA1(),
                label=None
            )),
            ("PKCS#1 v1.5", padding.PKCS1v15())
        ]

    def detect_file_type(self, data):
        """检测文件类型基于文件头（Magic Number）"""
        if len(data) < 8:
            return "未知 (数据太短)"

        # 检查常见文件类型
        for file_type, signature in FILE_SIGNATURES.items():
            if data.startswith(signature):
                return file_type

        # 检查是否为文本文件
        try:
            # 尝试解码为UTF-8
            data.decode('utf-8')
            return "文本文件 (UTF-8)"
        except UnicodeDecodeError:
            pass

        # 检查是否为ASCII文本
        if all(32 <= byte <= 126 or byte in (9, 10, 13) for byte in data[:128]):
            return "文本文件 (ASCII)"

        return "未知文件类型"


class DecryptionWindow(QWidget):
    """解密窗口"""

    def __init__(self, private_key_path, parent=None):
        super().__init__(parent)
        self.private_key_path = private_key_path
        self.decrypted_data = None
        self.setWindowFlags(Qt.Window)
        self.init_ui()

    def center(self):
        """居中窗口"""
        screen = QDesktopWidget().screenGeometry()
        size = self.geometry()
        new_left = (screen.width() - size.width()) / 2
        new_top = (screen.height() - size.height()) / 2
        self.move(int(new_left), int(new_top))

    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("RSA解密工具")
        self.setWindowIcon(QIcon.fromTheme("document-decrypt"))
        self.resize(800, 600)
        self.center()
        # 设置窗口背景色
        self.setAutoFillBackground(True)
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(245, 245, 245))
        self.setPalette(palette)
        # 主布局
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        # 私钥信息区域
        key_group = self.create_key_info_group()
        main_layout.addWidget(key_group)
        # 密文输入区域
        cipher_group = self.create_cipher_input_group()
        main_layout.addWidget(cipher_group)
        # 解密按钮
        decrypt_btn = QPushButton("解密")
        decrypt_btn.setObjectName("decryptButton")
        decrypt_btn.clicked.connect(self.decrypt)
        main_layout.addWidget(decrypt_btn)
        # 结果区域
        result_group = self.create_result_group()
        main_layout.addWidget(result_group)
        self.setLayout(main_layout)
        self.apply_styles()

    def create_key_info_group(self):
        """创建私钥信息区域"""
        group = QGroupBox("私钥信息")
        group.setObjectName("keyInfoGroup")
        layout = QVBoxLayout()
        key_label = QLabel(f"私钥路径: {self.private_key_path}")
        key_label.setWordWrap(True)
        key_label.setStyleSheet("font-weight: normal;")
        layout.addWidget(key_label)
        group.setLayout(layout)
        return group

    def create_cipher_input_group(self):
        """创建密文输入区域"""
        group = QGroupBox("密文输入")
        group.setObjectName("cipherInputGroup")
        layout = QVBoxLayout()
        # 格式选择
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("密文格式:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["Base64", "Hex", "二进制"])
        format_layout.addWidget(self.format_combo)
        format_layout.addStretch()
        layout.addLayout(format_layout)
        # 输入框和按钮
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("密文:"))
        self.cipher_text = QTextEdit()
        self.cipher_text.setPlaceholderText("请输入要解密的密文内容...")
        self.cipher_text.setMinimumHeight(100)
        input_layout.addWidget(self.cipher_text)
        file_btn = QPushButton("从文件导入")
        file_btn.setObjectName("importButton")
        file_btn.clicked.connect(self.import_from_file)
        input_layout.addWidget(file_btn)
        layout.addLayout(input_layout)
        group.setLayout(layout)
        return group

    def create_result_group(self):
        """创建结果区域"""
        group = QGroupBox("解密结果")
        group.setObjectName("resultGroup")
        layout = QVBoxLayout()
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setPlaceholderText("解密结果将显示在这里...")
        self.result_text.setMinimumHeight(150)
        layout.addWidget(self.result_text)
        # 保存按钮
        save_btn = QPushButton("保存解密结果")
        save_btn.setObjectName("saveButton")
        save_btn.clicked.connect(self.save_result)
        layout.addWidget(save_btn)
        group.setLayout(layout)
        return group

    def apply_styles(self):
        """应用样式"""
        self.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                border: 1px solid #d0d0d0;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 15px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
            }
            
            QPushButton {
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            
            QPushButton#decryptButton {
                background-color: #4CAF50;
                color: white;
                font-size: 14px;
                min-height: 35px;
            }
            
            QPushButton#importButton, QPushButton#saveButton {
                background-color: #2196F3;
                color: white;
            }
            
            QPushButton:hover {
                background-color: #45a049;
            }
            
            QPushButton#importButton:hover, QPushButton#saveButton:hover {
                background-color: #0b7dda;
            }
            
            QPushButton:pressed {
                background-color: #367c39;
            }
            
            QPushButton#importButton:pressed, QPushButton#saveButton:pressed {
                background-color: #0a6ebd;
            }
            
            QTextEdit, QLineEdit, QComboBox {
                border: 1px solid #d0d0d0;
                border-radius: 3px;
                padding: 5px;
            }
            
            QProgressBar {
                border: 1px solid #d0d0d0;
                border-radius: 3px;
                text-align: center;
            }
            
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
            }
            
            QListWidget {
                border: 1px solid #d0d0d0;
                border-radius: 3px;
            }
        """)

    def import_from_file(self):
        """从文件导入密文"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择密文文件",
            "",
            "所有文件 (*);;文本文件 (*.txt)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                self.cipher_text.setPlainText(content)
            except Exception as e:
                QMessageBox.critical(self, "错误", f"读取文件失败: {e}")

    def get_all_padding_schemes(self):
        """返回所有支持的填充方案"""
        return [
            ("OAEP-SHA-256", padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )),
            ("OAEP-SHA-256 with MGF1-SHA-1", padding.OAEP(
                mgf=padding.MGF1(hashes.SHA1()),
                algorithm=hashes.SHA256(),
                label=None
            )),
            ("OAEP-SHA-1", padding.OAEP(
                mgf=padding.MGF1(hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )),
            ("OAEP-SHA-1 with MGF1-SHA-256", padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA1(),
                label=None
            )),
            ("PKCS#1 v1.5", padding.PKCS1v15())
        ]

    def detect_file_type(self, data):
        """检测文件类型基于文件头（Magic Number）"""
        if len(data) < 8:
            return "未知 (数据太短)"

        # 检查常见文件类型
        for file_type, signature in FILE_SIGNATURES.items():
            if data.startswith(signature):
                return file_type

        # 检查是否为文本文件
        try:
            # 尝试解码为UTF-8
            data.decode('utf-8')
            return "文本文件 (UTF-8)"
        except UnicodeDecodeError:
            pass

        # 检查是否为ASCII文本
        if all(32 <= byte <= 126 or byte in (9, 10, 13) for byte in data[:128]):
            return "文本文件 (ASCII)"

        return "未知文件类型"

    def decrypt(self):
        """执行解密操作"""
        cipher_text = self.cipher_text.toPlainText().strip()
        if not cipher_text:
            QMessageBox.warning(self, "警告", "请输入要解密的密文")
            return
        format_type = self.format_combo.currentText()
        try:
            # 转换密文格式
            if format_type == "Base64":
                encrypted_data = b64decode(cipher_text)
            elif format_type == "Hex":
                encrypted_data = bytes.fromhex(cipher_text)
            else:  # 二进制格式
                encrypted_data = cipher_text.encode('utf-8')

            # 加载私钥
            with open(self.private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )

            # 尝试所有填充方案
            padding_schemes = self.get_all_padding_schemes()
            decrypted_data = None
            used_padding = None

            for name, scheme in padding_schemes:
                try:
                    # 检查是否需要分块解密
                    max_decrypt_size = private_key.key_size // 8
                    if len(encrypted_data) > max_decrypt_size:
                        # 对于大量数据，进行分块解密
                        decrypted_chunks = []
                        for i in range(0, len(encrypted_data), max_decrypt_size):
                            chunk = encrypted_data[i:i + max_decrypt_size]
                            decrypted_chunk = private_key.decrypt(
                                chunk, scheme)
                            decrypted_chunks.append(decrypted_chunk)
                        # 合并所有块
                        decrypted_data = b''.join(decrypted_chunks)
                    else:
                        # 小量数据直接解密
                        decrypted_data = private_key.decrypt(
                            encrypted_data, scheme)

                    # 如果解密成功，记录使用的填充方案并退出循环
                    used_padding = name
                    break
                except Exception:
                    # 当前填充方案失败，尝试下一个
                    continue

            if decrypted_data is None:
                QMessageBox.critical(self, "解密失败", "所有填充方案均失败")
                return

            # 检测文件类型
            file_type = self.detect_file_type(decrypted_data)

            # 保存解密结果
            self.decrypted_data = decrypted_data
            # 尝试UTF-8解码
            try:
                result_str = decrypted_data.decode('utf-8')
                self.result_text.setPlainText(
                    f"✅ 解密成功! (填充方案: {used_padding})\n"
                    f"文件类型: {file_type}\n"
                    f"{result_str}"
                )
            except UnicodeDecodeError:
                # 如果不能解码为UTF-8，则显示二进制信息
                hex_data = decrypted_data.hex()
                preview = hex_data[:32] + \
                    "..." if len(hex_data) > 32 else hex_data
                self.result_text.setPlainText(
                    f"✅ 解密成功! (填充方案: {used_padding})\n"
                    f"文件类型: {file_type}\n"
                    f"结果为二进制数据:\n"
                    f"前16字节: {decrypted_data[:16]}\n"
                    f"十六进制预览: {preview}\n"
                    f"总长度: {len(decrypted_data)} 字节\n"
                    f"使用下方按钮保存完整数据"
                )

        except Exception as e:
            QMessageBox.critical(self, "解密失败", f"解密过程中发生错误:\n{e}")

    def save_result(self):
        """保存解密结果到文件"""
        if self.decrypted_data is None:
            QMessageBox.warning(self, "警告", "没有可保存的解密结果")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存解密结果",
            "",
            "所有文件 (*);;文本文件 (*.txt)"
        )
        if file_path:
            try:
                with open(file_path, 'wb') as f:
                    f.write(self.decrypted_data)
                QMessageBox.information(self, "成功", "解密结果已保存")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"保存文件失败:\n{e}")


class MainWindow(QMainWindow):
    """主窗口"""

    def __init__(self):
        super().__init__()
        self.init_ui()
        self.search_thread = None
        self.matched_keys = []
        self.decrypt_threads = []
        self.decrypt_results = []  # 存储解密结果
        self.best_key = None  # 最佳私钥路径

    def center(self):
        """居中窗口"""
        screen = QDesktopWidget().screenGeometry()
        size = self.geometry()
        new_left = (screen.width() - size.width()) / 2
        new_top = (screen.height() - size.height()) / 2
        self.move(int(new_left), int(new_top))

    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("RSA私钥查找与解密工具")
        self.setWindowIcon(QIcon.fromTheme("security-high"))
        self.resize(900, 700)
        self.center()
        # 设置主窗口背景色
        self.setAutoFillBackground(True)
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(245, 245, 245))
        self.setPalette(palette)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        # 创建选项卡
        self.tab_widget = QTabWidget()
        self.tab_widget.setObjectName("mainTabs")
        main_layout.addWidget(self.tab_widget)
        # 创建三个选项卡
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()  # 通过加密文件查找私钥的选项卡

        self.tab_widget.addTab(self.tab1, "通过公钥查找私钥")
        self.tab_widget.addTab(self.tab3, "通过加密文件查找私钥")
        self.tab_widget.addTab(self.tab2, "手动导入私钥")

        # 设置第一个选项卡（自动查找私钥）
        self.setup_auto_tab()
        # 设置第二个选项卡（手动导入私钥）
        self.setup_manual_tab()
        # 设置第三个选项卡（通过加密文件查找私钥）
        self.setup_decrypt_file_tab()

        central_widget.setLayout(main_layout)
        self.apply_styles()

    def apply_styles(self):
        """应用样式"""
        self.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #d0d0d0;
                border-radius: 5px;
                padding: 10px;
            }
            
            QTabBar::tab {
                background: #f0f0f0;
                border: 1px solid #d0d0d0;
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                padding: 8px 16px;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected {
                background: #ffffff;
                border-bottom: 1px solid white;
            }
            
            QTabBar::tab:hover {
                background: #e0e0e0;
            }
            
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                border: 1px solid #d0d0d0;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 15px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
            }
            
            QPushButton {
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            
            QPushButton#searchButton {
                background-color: #2196F3;
                color: white;
                font-size: 14px;
                min-height: 35px;
            }
            
            QPushButton#decryptButton, QPushButton#manualDecryptButton, QPushButton#decryptFileButton {
                background-color: #4CAF50;
                color: white;
            }
            
            QPushButton:hover {
                background-color: #0b7dda;
            }
            
            QPushButton#decryptButton:hover, QPushButton#manualDecryptButton:hover, QPushButton#decryptFileButton:hover {
                background-color: #45a049;
            }
            
            QPushButton:pressed {
                background-color: #0a6ebd;
            }
            
            QPushButton#decryptButton:pressed, QPushButton#manualDecryptButton:pressed, QPushButton#decryptFileButton:pressed {
                background-color: #367c39;
            }
            
            QTextEdit, QLineEdit, QComboBox {
                border: 1px solid #d0d0d0;
                border-radius: 3px;
                padding: 5px;
            }
            
            QProgressBar {
                border: 1px solid #d0d0d0;
                border-radius: 3px;
                text-align: center;
            }
            
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
            }
            
            QListWidget {
                border: 1px solid #d0d0d0;
                border-radius: 3px;
            }
        """)

    def setup_auto_tab(self):
        """设置自动查找私钥选项卡"""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        # 公钥选择
        pubkey_group = self.create_file_group(
            "公钥文件", "pubkey_path", self.select_public_key)
        layout.addWidget(pubkey_group)
        # 私钥目录选择
        privdir_group = self.create_file_group(
            "私钥搜索目录", "privdir_path", self.select_private_dir, is_dir=True)
        layout.addWidget(privdir_group)
        # 文件扩展名设置
        ext_group = QGroupBox("私钥文件扩展名")
        ext_group.setObjectName("extGroup")
        ext_layout = QHBoxLayout()
        self.ext_input = QLineEdit("pem, key")
        self.ext_input.setPlaceholderText("例如: pem, key")
        ext_layout.addWidget(QLabel("扩展名(逗号分隔):"))
        ext_layout.addWidget(self.ext_input)
        ext_group.setLayout(ext_layout)
        layout.addWidget(ext_group)
        # 递归搜索选项
        self.recursive_check = QCheckBox("递归搜索子目录")
        self.recursive_check.setChecked(True)
        layout.addWidget(self.recursive_check)
        # 搜索按钮
        search_btn = QPushButton("搜索私钥文件")
        search_btn.setObjectName("searchButton")
        search_btn.clicked.connect(self.start_search)
        layout.addWidget(search_btn)
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        # 搜索结果
        result_group = QGroupBox("搜索结果")
        result_group.setObjectName("resultGroup")
        result_layout = QVBoxLayout()
        self.result_list = QListWidget()
        self.result_list.setMinimumHeight(150)
        result_layout.addWidget(self.result_list)
        # 解密按钮
        decrypt_btn = QPushButton("使用选中私钥解密")
        decrypt_btn.setObjectName("decryptButton")
        decrypt_btn.clicked.connect(self.open_decryption_window)
        result_layout.addWidget(decrypt_btn)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)
        self.tab1.setLayout(layout)

    def setup_manual_tab(self):
        """设置手动导入私钥选项卡"""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        privkey_group = self.create_file_group(
            "私钥文件", "manual_privkey_path", self.select_manual_private_key)
        layout.addWidget(privkey_group)
        note_label = QLabel("提示: 在此选项卡中，您可以直接导入私钥文件进行解密，无需公钥匹配过程。")
        note_label.setWordWrap(True)
        note_label.setStyleSheet(
            "color: #666666; font-style: italic; padding: 10px;")
        layout.addWidget(note_label)
        decrypt_btn = QPushButton("使用此私钥解密")
        decrypt_btn.setObjectName("manualDecryptButton")
        decrypt_btn.clicked.connect(self.open_decryption_with_manual_key)
        layout.addWidget(decrypt_btn)

        self.tab2.setLayout(layout)

    def setup_decrypt_file_tab(self):
        """设置通过加密文件查找私钥选项卡"""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)

        # 加密文件选择
        encfile_group = self.create_file_group(
            "加密文件", "encfile_path", self.select_encrypted_file)
        layout.addWidget(encfile_group)

        # 文件格式选择
        format_group = QGroupBox("加密文件格式")
        format_group.setObjectName("formatGroup")
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("文件格式:"))
        self.file_format_combo = QComboBox()
        self.file_format_combo.addItems(["Base64", "Hex", "二进制"])
        format_layout.addWidget(self.file_format_combo)
        format_group.setLayout(format_layout)
        layout.addWidget(format_group)

        # 私钥目录选择
        privdir_group = self.create_file_group(
            "私钥搜索目录", "decrypt_privdir_path", self.select_decrypt_private_dir, is_dir=True)
        layout.addWidget(privdir_group)

        # 文件扩展名设置
        ext_group = QGroupBox("私钥文件扩展名")
        ext_group.setObjectName("extGroup")
        ext_layout = QHBoxLayout()
        self.decrypt_ext_input = QLineEdit("pem, key")
        self.decrypt_ext_input.setPlaceholderText("例如: pem, key")
        ext_layout.addWidget(QLabel("扩展名(逗号分隔):"))
        ext_layout.addWidget(self.decrypt_ext_input)
        ext_group.setLayout(ext_layout)
        layout.addWidget(ext_group)

        # 搜索按钮
        decrypt_file_btn = QPushButton("尝试解密文件")
        decrypt_file_btn.setObjectName("decryptFileButton")
        decrypt_file_btn.clicked.connect(self.start_decrypt_file)
        layout.addWidget(decrypt_file_btn)

        # 进度条
        self.decrypt_progress_bar = QProgressBar()
        self.decrypt_progress_bar.setVisible(False)
        layout.addWidget(self.decrypt_progress_bar)

        # 状态标签
        self.decrypt_status_label = QLabel("准备就绪")
        self.decrypt_status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.decrypt_status_label)

        # 结果区域
        result_group = QGroupBox("解密结果")
        result_group.setObjectName("resultGroup")
        result_layout = QVBoxLayout()
        self.decrypt_result_text = QTextEdit()
        self.decrypt_result_text.setReadOnly(True)
        self.decrypt_result_text.setPlaceholderText("解密结果将显示在这里...")
        self.decrypt_result_text.setMinimumHeight(150)
        result_layout.addWidget(self.decrypt_result_text)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        self.tab3.setLayout(layout)

    def create_file_group(self, title, attribute_name, callback, is_dir=False):
        """创建文件/目录选择组"""
        group = QGroupBox(title)
        group.setObjectName(f"{attribute_name}Group")
        layout = QHBoxLayout()
        if not hasattr(self, attribute_name):
            setattr(self, attribute_name, QLineEdit())
        line_edit = getattr(self, attribute_name)
        line_edit.setPlaceholderText(
            f"请选择{title}..." if not is_dir else "请选择目录...")
        layout.addWidget(line_edit)
        browse_btn = QPushButton("浏览...")
        browse_btn.setObjectName(f"{attribute_name}Browse")
        browse_btn.clicked.connect(callback)
        layout.addWidget(browse_btn)
        group.setLayout(layout)
        return group

    def select_public_key(self):
        """选择公钥文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择公钥文件",
            "",
            "PEM文件 (*.pem *.pub);;所有文件 (*)"
        )
        if file_path:
            self.pubkey_path.setText(file_path)

    def select_private_dir(self):
        """选择私钥搜索目录"""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "选择私钥搜索目录"
        )
        if dir_path:
            self.privdir_path.setText(dir_path)

    def select_manual_private_key(self):
        """选择手动导入的私钥文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择私钥文件",
            "",
            "PEM文件 (*.pem *.key);;所有文件 (*)"
        )
        if file_path:
            self.manual_privkey_path.setText(file_path)

    def select_encrypted_file(self):
        """选择加密文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择加密文件",
            "",
            "所有文件 (*)"
        )
        if file_path:
            self.encfile_path.setText(file_path)

    def select_decrypt_private_dir(self):
        """选择私钥搜索目录（解密选项卡）"""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "选择私钥搜索目录"
        )
        if dir_path:
            self.decrypt_privdir_path.setText(dir_path)

    def start_search(self):
        """开始搜索私钥"""
        pubkey_path = self.pubkey_path.text().strip()
        privdir_path = self.privdir_path.text().strip()
        ext_text = self.ext_input.text().strip()
        if not pubkey_path:
            QMessageBox.warning(self, "警告", "请选择公钥文件")
            return
        if not privdir_path:
            QMessageBox.warning(self, "警告", "请选择私钥搜索目录")
            return
        if not path.exists(pubkey_path):
            QMessageBox.warning(self, "警告", "公钥文件不存在")
            return
        if not path.exists(privdir_path):
            QMessageBox.warning(self, "警告", "私钥搜索目录不存在")
            return
        extensions = [
            f".{ext.strip().lstrip('.')}" for ext in ext_text.split(",")]
        extensions = [ext for ext in extensions if ext != "."]
        if not extensions:
            QMessageBox.warning(self, "警告", "请指定有效的文件扩展名")
            return
        self.result_list.clear()
        self.matched_keys = []
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.search_thread = KeySearchThread(
            pubkey_path, privdir_path, extensions)
        self.search_thread.progress_signal.connect(self.update_progress)
        self.search_thread.result_signal.connect(self.search_completed)
        self.search_thread.error_signal.connect(self.search_error)
        self.search_thread.start()

    def start_decrypt_file(self):
        """开始尝试解密文件"""
        encfile_path = self.encfile_path.text().strip()
        privdir_path = self.decrypt_privdir_path.text().strip()
        ext_text = self.decrypt_ext_input.text().strip()
        file_format = self.file_format_combo.currentText()

        if not encfile_path:
            QMessageBox.warning(self, "警告", "请选择加密文件")
            return
        if not privdir_path:
            QMessageBox.warning(self, "警告", "请选择私钥搜索目录")
            return
        if not path.exists(encfile_path):
            QMessageBox.warning(self, "警告", "加密文件不存在")
            return
        if not path.exists(privdir_path):
            QMessageBox.warning(self, "警告", "私钥搜索目录不存在")
            return
        extensions = [
            f".{ext.strip().lstrip('.')}" for ext in ext_text.split(",")]
        extensions = [ext for ext in extensions if ext != "."]
        if not extensions:
            QMessageBox.warning(self, "警告", "请指定有效的文件扩展名")
            return

        # 遍历目录查找所有可能的私钥
        private_key_paths = []
        for root, _, files in walk(privdir_path):
            for file in files:
                if any(file.lower().endswith(ext) for ext in extensions):
                    private_key_paths.append(path.join(root, file))

        if not private_key_paths:
            self.decrypt_status_label.setText("未找到任何私钥文件")
            self.decrypt_progress_bar.setVisible(False)
            QMessageBox.information(self, "完成", "在指定目录中未找到任何私钥文件")
            return

        self.decrypt_status_label.setText(
            f"找到 {len(private_key_paths)} 个私钥文件，正在尝试解密...")
        self.decrypt_progress_bar.setVisible(True)
        self.decrypt_progress_bar.setValue(0)
        self.decrypt_result_text.clear()
        self.decrypt_results = []  # 清空之前的结果
        self.best_key = None  # 重置最佳私钥

        # 清空之前的解密线程
        for thread in self.decrypt_threads:
            if thread.isRunning():
                thread.terminate()
        self.decrypt_threads = []

        # 为每个私钥创建解密线程
        for private_key_path in private_key_paths:
            thread = DecryptFileThread(
                encfile_path, private_key_path, file_format)
            thread.progress_signal.connect(self.update_decrypt_progress)
            thread.result_signal.connect(self.on_decrypt_result)
            thread.error_signal.connect(self.on_decrypt_error)
            thread.finished_signal.connect(self.on_decrypt_finished)
            self.decrypt_threads.append(thread)
            thread.start()

    def on_decrypt_result(self, private_key_path, result_output, file_type):
        """处理解密结果"""
        # 存储结果
        self.decrypt_results.append({
            "private_key_path": private_key_path,
            "result_output": result_output,
            "file_type": file_type
        })

        # 在结果文本框中显示
        self.decrypt_result_text.append(f"使用私钥: {private_key_path}\n")
        self.decrypt_result_text.append(f"{result_output}\n")
        self.decrypt_result_text.append("-" * 50 + "\n")

        # 尝试确定最佳私钥（根据文件类型匹配程度）
        self.determine_best_key()

    def determine_best_key(self):
        """根据文件类型匹配程度确定最佳私钥"""
        if not self.decrypt_results:
            return

        # 优先选择匹配到已知文件类型的结果
        best_result = None
        for result in self.decrypt_results:
            file_type = result["file_type"]
            # 如果文件类型不是"未知"，则优先选择
            if "未知" not in file_type:
                best_result = result
                break

        # 如果没有找到已知文件类型，则选择第一个结果
        if best_result is None:
            best_result = self.decrypt_results[0]

        self.best_key = best_result["private_key_path"]
        self.best_file_type = best_result["file_type"]
        # self.decrypt_status_label.setText(f"最佳匹配私钥: {self.best_key}, 文件类型: {best_result['file_type']}")

    def on_decrypt_error(self, error_msg):
        """处理解密错误"""
        self.decrypt_result_text.append(f"错误: {error_msg}\n")
        self.decrypt_result_text.append("-" * 50 + "\n")

    def on_decrypt_finished(self):
        """所有解密线程完成"""
        all_finished = all(not thread.isRunning()
                           for thread in self.decrypt_threads)
        if all_finished:
            self.decrypt_status_label.setText("解密尝试完成")
            self.decrypt_progress_bar.setVisible(False)

            # 显示最佳私钥
            if self.best_key:
                self.decrypt_result_text.append(
                    f"最佳匹配私钥: {self.best_key}, 文件类型: {self.best_file_type}")

    def update_progress(self, value):
        """更新进度条"""
        self.progress_bar.setValue(value)

    def update_decrypt_progress(self, value):
        """更新解密进度条"""
        self.decrypt_progress_bar.setValue(value)

    def search_completed(self, matches):
        """搜索完成处理"""
        self.progress_bar.setVisible(False)
        self.matched_keys = matches

        if matches:
            self.result_list.addItems(matches)
            QMessageBox.information(self, "完成", f"找到 {len(matches)} 个匹配的私钥")
        else:
            QMessageBox.information(self, "完成", "未找到匹配的私钥")

    def search_error(self, error_msg):
        """搜索错误处理"""
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "错误", error_msg)

    def open_decryption_window(self):
        """打开解密窗口（使用自动查找的私钥）"""
        if not self.matched_keys:
            QMessageBox.warning(self, "警告", "没有可用的私钥文件")
            return
        selected_items = self.result_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "警告", "请先选择一个私钥文件")
            return
        private_key_path = selected_items[0].text()
        self.decryption_window = DecryptionWindow(private_key_path, self)
        self.decryption_window.show()

    def open_decryption_with_manual_key(self):
        """打开解密窗口（使用手动导入的私钥）"""
        private_key_path = self.manual_privkey_path.text().strip()
        if not private_key_path:
            QMessageBox.warning(self, "警告", "请先选择私钥文件")
            return
        if not path.exists(private_key_path):
            QMessageBox.warning(self, "警告", "私钥文件不存在")
            return
        try:
            with open(private_key_path, "rb") as key_file:
                serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        except Exception as e:
            QMessageBox.critical(self, "错误", f"无效的私钥文件:\n{e}")
            return
        self.decryption_window = DecryptionWindow(private_key_path, self)
        self.decryption_window.show()


if __name__ == "__main__":
    app = QApplication(argv)
    app.setStyle('Fusion')
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    window = MainWindow()
    window.show()
    exit(app.exec_())
