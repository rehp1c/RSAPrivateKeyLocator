import os
import argparse
import base64
import binascii
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import hashlib
import platform


def clear_screen():
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')


def get_public_key_modulus_md5(public_key_path):
    """提取公钥文件的模数并计算其MD5指纹"""
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        modulus = public_key.public_numbers().n
        modulus_bytes = modulus.to_bytes((modulus.bit_length() + 7) // 8, 'big')
        return hashlib.md5(modulus_bytes).hexdigest()
    except Exception as e:
        raise ValueError(f"公钥解析失败: {e}")

def get_private_key_modulus_md5(private_key_path):
    """提取私钥文件的模数并计算其MD5指纹"""
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        modulus = private_key.private_numbers().public_numbers.n
        modulus_bytes = modulus.to_bytes((modulus.bit_length() + 7) // 8, 'big')
        return hashlib.md5(modulus_bytes).hexdigest()
    except Exception as e:
        raise ValueError(f"私钥解析失败 ({private_key_path}): {e}")

def find_matching_private_key(public_key_path, search_dir, extensions=("pem", "key")):
    """在目录中递归查找匹配的私钥文件"""
    target_md5 = get_public_key_modulus_md5(public_key_path)
    print(f"目标公钥指纹: {target_md5}\n搜索目录: {search_dir}")

    matches = []
    for root, _, files in os.walk(search_dir):
        for file in files:
            if file.lower().endswith(extensions):
                private_key_path = os.path.join(root, file)
                try:
                    private_md5 = get_private_key_modulus_md5(private_key_path)
                    if private_md5 == target_md5:
                        matches.append(private_key_path)
                except ValueError:
                    continue  # 跳过无效文件

    return matches

def select_padding_scheme():
    """让用户选择填充方案"""
    clear_screen()
    print("请选择填充(padding)方案:")
    print("1. OAEP-SHA-256")
    print("2. OAEP-SHA-1") 
    print("3. OAEP-SHA-256 with MGF1-SHA-1")
    print("4. OAEP-SHA-1 with MGF1-SHA-256")
    print("5. PKCS#1 v1.5")
    print("6. 返回")
    
    while True:
        choice = input("请输入选择 (1-6): ").strip()
        if choice == "1":
            return "oaep_sha256"
        elif choice == "2":
            return "oaep_sha1"
        elif choice == "3":
            return "oaep_sha256_mgf1_sha1"
        elif choice == "4":
            return "oaep_sha1_mgf1_sha256"
        elif choice == "5":
            return "pkcs1v15"
        elif choice == "6":
            return 0
        else:
            print("❌ 无效选择，请重新输入")

def get_padding_scheme(padding_type):
    """根据类型返回相应的填充方案"""
    if padding_type == "oaep_sha256":
        return padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    elif padding_type == "oaep_sha256_mgf1_sha1":
        return padding.OAEP(
            mgf=padding.MGF1(hashes.SHA1()),
            algorithm=hashes.SHA256(),
            label=None
        )
    elif padding_type == "oaep_sha1":
        return padding.OAEP(
            mgf=padding.MGF1(hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    elif padding_type == "oaep_sha1_mgf1_sha256":
        return padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA1(),
            label=None
        )
    elif padding_type == "pkcs1v15":
        return padding.PKCS1v15()
    else:
        # 默认使用 OAEP SHA-256
        return padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

def get_encrypted_data_input():
    """获取加密数据输入方式"""
    clear_screen()
    print("请选择输入方式:")
    print("1. 直接输入 (终端输入)")
    print("2. 从文件读取")
    
    while True:
        choice = input("请输入选择 (1-2): ").strip()
        if choice == "1":
            return "terminal"
        elif choice == "2":
            return "file"
        else:
            print("❌ 无效选择，请重新输入")

def get_input_format():
    """获取输入格式"""
    clear_screen()
    print("请选择输入格式:")
    print("1. base64")
    print("2. hex")
    
    while True:
        choice = input("请输入选择 (1-2): ").strip()
        if choice == "1":
            return "base64"
        elif choice == "2":
            return "hex"
        else:
            print("❌ 无效选择，请重新输入")

def decrypt_string_with_private_key(private_key_path, encrypted_data, padding_type):
    """使用私钥解密字符串数据"""
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        
        # 获取填充方案
        pad_scheme = get_padding_scheme(padding_type)
        
        # 检查是否需要分块解密
        max_decrypt_size = private_key.key_size // 8
        if len(encrypted_data) > max_decrypt_size:
            # 对于大量数据，进行分块解密
            decrypted_chunks = []
            for i in range(0, len(encrypted_data), max_decrypt_size):
                chunk = encrypted_data[i:i + max_decrypt_size]
                decrypted_chunk = private_key.decrypt(chunk, pad_scheme)
                decrypted_chunks.append(decrypted_chunk)
            
            # 合并所有块
            decrypted_data = b''.join(decrypted_chunks)
        else:
            # 小量数据直接解密
            decrypted_data = private_key.decrypt(encrypted_data, pad_scheme)
        
        # 改进：先尝试UTF-8解码，如果失败则返回原始二进制数据
        try:
            return decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            # 如果不能解码为UTF-8，则返回原始字节数据（以十六进制形式显示）
            return decrypted_data
    except Exception as e:
        raise ValueError(f"解密失败: {e}")

def decrypt_file_with_private_key(private_key_path, encrypted_file_path, output_file_path, padding_type):
    """使用私钥解密文件"""
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        
        # 读取加密的文件内容
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # 获取填充方案
        pad_scheme = get_padding_scheme(padding_type)
        
        # 检查是否需要分块解密
        max_decrypt_size = private_key.key_size // 8
        if len(encrypted_data) > max_decrypt_size:
            # 对于大量数据，进行分块解密
            decrypted_chunks = []
            for i in range(0, len(encrypted_data), max_decrypt_size):
                chunk = encrypted_data[i:i + max_decrypt_size]
                decrypted_chunk = private_key.decrypt(chunk, pad_scheme)
                decrypted_chunks.append(decrypted_chunk)
            
            # 合并所有块
            decrypted_data = b''.join(decrypted_chunks)
        else:
            # 小量数据直接解密
            decrypted_data = private_key.decrypt(encrypted_data, pad_scheme)
        
        with open(output_file_path, 'wb') as f:
            f.write(decrypted_data)
            
        return True
    except Exception as e:
        raise ValueError(f"文件解密失败: {e}")

def get_encrypted_data_from_terminal(input_format):
    """从终端获取加密数据"""
    encrypted_input = input(f"请输入要解密的字符串 ({input_format}格式): ").strip()
    
    if input_format == "base64":
        return base64.b64decode(encrypted_input)
    elif input_format == "hex":
        return bytes.fromhex(encrypted_input)

def get_encrypted_data_from_file(file_path, input_format):
    """从文件获取加密数据"""
    try:
        with open(file_path, 'r') as f:
            data = f.read()
        if input_format == "base64":
            return base64.b64decode(data)
        elif input_format == "hex":
            return bytes.fromhex(data)
    except Exception as e:
        raise ValueError(f"读取文件失败: {e}")

def show_menu_and_decrypt(matches):
    """显示菜单并执行解密操作"""
    if not matches:
        print("未找到匹配的私钥文件")
        return
    
    # 选择一个私钥（这里选择第一个匹配的私钥）
    private_key_path = matches[0]
    while True:
        clear_screen()
        print(f"✅ 匹配到私钥文件: {private_key_path}")
        print("\n请选择解密类型(如果文件内部为hex或base64，请使用1。):")
        print("1. 解密字符串")
        print("2. 解密文件")
        print("3. 退出")
        
        choice = input("请输入选择 (1-3): ").strip()
        
        if choice == "1":
            # 解密字符串
            padding_type = select_padding_scheme()
            if padding_type == 0:
                continue
            
            input_method = get_encrypted_data_input()
            input_format = get_input_format()
            
            try:
                if input_method == "terminal":
                    encrypted_data = get_encrypted_data_from_terminal(input_format)
                else:
                    file_path = input("请输入加密数据文件路径: ").strip()
                    encrypted_data = get_encrypted_data_from_file(file_path, input_format)
                
                decrypted_text = decrypt_string_with_private_key(private_key_path, encrypted_data, padding_type)
                clear_screen()
                print(f"✅ 解密成功!")
                
                # 检查解密结果是否为二进制数据
                if isinstance(decrypted_text, bytes):
                    # 如果是二进制数据，询问是否保存到文件
                    print(f"解密结果为二进制数据")
                    print(f"文件头(bytes)为：{decrypted_text[:16]}")
                    print(f"文件头(hex)为：{decrypted_text[:16].hex()}")
                    save_file = input("解密结果为二进制数据，是否保存到文件? (Y/n): ").strip().lower()
                    if save_file == 'n':
                        print("解密结果为二进制数据，未保存到文件")
                    else:
                        output_file = input("请输入输出文件路径: ").strip()
                        with open(output_file, 'wb') as f:
                            f.write(decrypted_text)
                        print(f"✅ 二进制数据已保存到: {output_file}")
                        os.system("pause")
                else:
                    print(f"解密结果: {decrypted_text}")
                    
                    os.system("pause")
            except Exception as e:
                print(f"❌ 解密失败: {e}")
                
        elif choice == "2":
            # 解密文件
            padding_type = select_padding_scheme()
            encrypted_file = input("请输入要解密的文件路径: ").strip()
            if not os.path.exists(encrypted_file):
                print("❌ 文件不存在")
                continue
                
            output_file = input("请输入输出文件路径: ").strip()
            try:
                decrypt_file_with_private_key(private_key_path, encrypted_file, output_file, padding_type)
                print(f"✅ 文件解密成功! 结果已保存到: {output_file}")
            except Exception as e:
                print(f"❌ 文件解密失败: {e}")
                
        elif choice == "3":
            print("退出程序")
            break
        else:
            print("❌ 无效选择，请重新输入")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="查找与公钥匹配的私钥文件，并可进行解密操作")
    parser.add_argument("public_key", help="公钥文件路径 (.pem/.pub)")
    parser.add_argument("search_dir", help="要搜索的目录")
    parser.add_argument("--ext", nargs="+", default=["pem", "key"], 
                        help="私钥文件扩展名，如 pem key (默认: pem key)")
    args = parser.parse_args()

    try:
        result = find_matching_private_key(
            args.public_key,
            args.search_dir,
            tuple("." + e.strip(".").lower() for e in args.ext)
        )

        if result:
            print("✅ 找到匹配的私钥文件:")
            for path in result:
                print(f"  - {path}")
            # 显示菜单并进行解密操作
            show_menu_and_decrypt(result)
        else:
            print("❌ 未找到匹配的私钥文件")
    except Exception as e:
        print(f"❌ 错误: {e}")
