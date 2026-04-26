import unittest
from magma import transformation, g, expand_key, magma_encrypt_block, magma_decrypt_block


class TestMagmaCipher(unittest.TestCase):
    def test_transformation_t(self):
        """Тест A.2.1: Проверка преобразования t"""
        test_cases = [
            (0xfdb97531, 0x2a196f34),
            (0x2a196f34, 0xebd9f03a),
            (0xebd9f03a, 0xb039bb3d),
            (0xb039bb3d, 0x68695433)
        ]
        for inp, expected in test_cases:
            with self.subTest(value=inp):
                self.assertEqual(transformation(inp), expected)
        print("✅ Тест преобразования t успешно пройден!")

    def test_transformation_g(self):
        """Тест A.2.2: Проверка преобразования g"""
        test_cases = [
            (0x87654321, 0xfedcba98, 0xfdcbc20c),
            (0xfdcbc20c, 0x87654321, 0x7e791a4b),
            (0x7e791a4b, 0xfdcbc20c, 0xc76549ec),
            (0xc76549ec, 0x7e791a4b, 0x9791c849)
        ]
        for k, a, expected in test_cases:
            with self.subTest(k=k, a=a):
                self.assertEqual(g(k, a), expected)
        print("✅ Тест преобразования g успешно пройден!")

    def test_key_expansion(self):
        """Тест A.2.3: Проверка развертывания ключа"""
        master_key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        expanded_keys = expand_key(master_key)

        expected_keys = [
            0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
            0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
            0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
            0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
            0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
            0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
            0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3,
            0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc
        ]
        self.assertEqual(expanded_keys, expected_keys)
        print("✅ Тест развертывания ключа успешно пройден!")

    def test_encryption(self):
        """Тест A.2.4: Проверка алгоритма зашифрования"""
        plaintext = bytes.fromhex("fedcba9876543210")
        master_key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        expected_ciphertext = bytes.fromhex("4ee901e5c2d8ca3d")

        round_keys = expand_key(master_key)
        ciphertext = magma_encrypt_block(plaintext, round_keys)

        self.assertEqual(ciphertext, expected_ciphertext)
        print("✅ Тест алгоритма зашифрования успешно пройден!")

    def test_decryption(self):
        """Тест A.2.5: Проверка алгоритма расшифрования"""
        ciphertext = bytes.fromhex("4ee901e5c2d8ca3d")
        master_key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        expected_plaintext = bytes.fromhex("fedcba9876543210")

        round_keys = expand_key(master_key)
        decrypted_text = magma_decrypt_block(ciphertext, round_keys)

        self.assertEqual(decrypted_text, expected_plaintext)
        print("✅ Тест алгоритма расшифрования успешно пройден!")


if __name__ == "__main__":
    unittest.main()
