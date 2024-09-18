import unittest
import subprocess
import os

class TestEncryptionApp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # 在测试类运行之前，编译并生成可执行文件
        result = subprocess.run(['make'], cwd=os.path.join(os.path.dirname(__file__), '../build'), capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Build failed with error: {result.stderr}")

    def test_encryption_functionality(self):
        # 假设您有一个输入和预期的输出
        test_input = "Hello, World!"
        expected_output = "Encrypted_Hello_World!"  # 这是一个示例输出

        # 运行可执行文件并获取输出
        result = subprocess.run(['./EncryptionApp'], input=test_input, capture_output=True, text=True, cwd='../build')

        self.assertEqual(result.stdout.strip(), expected_output)

    def test_decryption_functionality(self):
        # 假设您有要解密的输入和预期输出
        test_input = "Encrypted_Hello_World!"
        expected_output = "Hello, World!"

        # 运行可执行文件并获取输出
        result = subprocess.run(['./EncryptionApp', 'decrypt'], input=test_input, capture_output=True, text=True, cwd='../build')

        self.assertEqual(result.stdout.strip(), expected_output)

    @classmethod
    def tearDownClass(cls):
        # 清理可执行文件
        os.remove(os.path.join(os.path.dirname(__file__), '../build/EncryptionApp'))

if __name__ == '__main__':
    unittest.main()
