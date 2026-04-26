import unittest
from gost_34_13_2015 import ecb_encrypt, ecb_decrypt, ctr_encrypt_decrypt, ofb_encrypt_decrypt, cbc_encrypt, \
    cbc_decrypt, cfb_encrypt, cfb_decrypt, mac


class TestGOSTModes(unittest.TestCase):
    def test_ecb_mode(self):
        """Тестирование шифрования в режиме ECB."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # Открытый текст (четыре 64-битных блока)
        plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Эталонный шифртекст
        expected_ciphertext = bytes.fromhex("2B073F0494F372A0DE70E715D3556E4811D8D9E9EACFBC1E7C68260996C67EFB")

        # Шифруем открытый текст
        ciphertext = ecb_encrypt(plaintext, key)

        # Проверяем, что полученный шифртекст совпадает с эталонным
        self.assertEqual(ciphertext, expected_ciphertext, "Шифртекст не совпадает с эталонным!")

        # Выводим сообщение об успешном прохождении теста
        print("✅ Тест шифрования с режимом ECB прошел успешно!")

    def test_ecb_decrypt(self):
        """Тестирование расшифрования в режиме ECB."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # Эталонный шифртекст (четыре 64-битных блока)
        ciphertext = bytes.fromhex("2B073F0494F372A0DE70E715D3556E4811D8D9E9EACFBC1E7C68260996C67EFB")

        # Исходный открытый текст
        expected_plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Расшифровываем шифртекст
        decrypted_data = ecb_decrypt(ciphertext, key)

        # Проверяем, что полученный открытый текст совпадает с эталонным
        self.assertEqual(decrypted_data, expected_plaintext,
                         "Открытый текст после расшифрования не совпадает с исходным!")

        # Выводим сообщение об успешной расшифровке
        print("✅ Тест расшифрования с режимом ECB прошел успешно!")

    def test_ctr_encrypt(self):
        """Тестирование шифрования в режиме CTR."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # IV (4 байта)
        iv = bytes.fromhex("12345678")

        # Открытый текст (четыре 64-битных блока)
        plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Эталонный шифртекст
        expected_ciphertext = bytes.fromhex("4E98110C97B7B93C3E250D93D6E85D69136D868807B2DBEF568EB680AB52A12D")

        # Шифруем открытый текст
        encrypted_data = ctr_encrypt_decrypt(plaintext, key, iv)

        # Проверяем, что полученный шифртекст совпадает с эталонным
        self.assertEqual(encrypted_data, expected_ciphertext, "Шифртекст не совпадает с эталонным!")
        print("✅ Тест шифрования в режиме CTR прошел успешно!")

    def test_ctr_decrypt(self):
        """Тестирование расшифрования в режиме CTR."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # IV (4 байта)
        iv = bytes.fromhex("12345678")

        # Шифртекст
        ciphertext = bytes.fromhex("4E98110C97B7B93C3E250D93D6E85D69136D868807B2DBEF568EB680AB52A12D")

        # Исходный открытый текст
        expected_plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Расшифровываем шифртекст
        decrypted_data = ctr_encrypt_decrypt(ciphertext, key, iv)

        # Проверяем, что полученный открытый текст совпадает с исходным
        self.assertEqual(decrypted_data, expected_plaintext,
                         "Открытый текст после расшифрования не совпадает с исходным!")
        print("✅ Тест расшифрования в режиме CTR прошел успешно!")

    def test_ofb_encrypt(self):
        """Тестирование шифрования в режиме OFB."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # IV (16 байт)
        iv = bytes.fromhex("1234567890abcdef234567890abcdef1")

        # Открытый текст (четыре 64-битных блока)
        plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Эталонный шифртекст
        expected_ciphertext = bytes.fromhex("DB37E0E266903C830D46644C1F9A089CA0F83062430E327EC824EFB8BD4FDB05")

        # Шифруем открытый текст
        encrypted_data = ofb_encrypt_decrypt(plaintext, key, iv)

        # Проверяем, что полученный шифртекст совпадает с эталонным
        self.assertEqual(encrypted_data, expected_ciphertext, "Шифртекст не совпадает с эталонным!")
        print("✅ Тест шифрования в режиме OFB прошел успешно!")

    def test_ofb_decrypt(self):
        """Тестирование расшифрования в режиме OFB."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # IV (16 байт)
        iv = bytes.fromhex("1234567890abcdef234567890abcdef1")

        # Шифртекст
        ciphertext = bytes.fromhex("DB37E0E266903C830D46644C1F9A089CA0F83062430E327EC824EFB8BD4FDB05")

        # Исходный открытый текст
        expected_plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Расшифровываем шифртекст
        decrypted_data = ofb_encrypt_decrypt(ciphertext, key, iv)

        # Проверяем, что полученный открытый текст совпадает с исходным
        self.assertEqual(decrypted_data, expected_plaintext,
                         "Открытый текст после расшифрования не совпадает с исходным!")
        print("✅ Тест расшифрования в режиме OFB прошел успешно!")

    def test_cbc_encrypt(self):
        """Тестирование шифрования в режиме CBC."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # IV (24 байта)
        iv = bytes.fromhex("1234567890abcdef234567890abcdef134567890abcdef12")

        # Открытый текст (четыре 64-битных блока)
        plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Эталонный шифртекст
        expected_ciphertext = bytes.fromhex("96D1B05EEA683919AFF76129ABB937B95058B4A1C4BC001920B78B1A7CD7E667")

        # Шифруем открытый текст
        encrypted_data = cbc_encrypt(plaintext, key, iv)

        # Проверяем, что полученный шифртекст совпадает с эталонным
        self.assertEqual(encrypted_data, expected_ciphertext, "Шифртекст не совпадает с эталонным!")
        print("✅ Тест шифрования в режиме CBC прошел успешно!")

    def test_cbc_decrypt(self):
        """Тестирование расшифрования в режиме CBC."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # IV (24 байта)
        iv = bytes.fromhex("1234567890abcdef234567890abcdef134567890abcdef12")

        # Шифртекст
        ciphertext = bytes.fromhex("96D1B05EEA683919AFF76129ABB937B95058B4A1C4BC001920B78B1A7CD7E667")

        # Исходный открытый текст
        expected_plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Расшифровываем шифртекст
        decrypted_data = cbc_decrypt(ciphertext, key, iv)

        # Проверяем, что полученный открытый текст совпадает с исходным
        self.assertEqual(decrypted_data, expected_plaintext,
                         "Открытый текст после расшифрования не совпадает с исходным!")
        print("✅ Тест расшифрования в режиме CBC прошел успешно!")

    def test_cfb_encrypt(self):
        """Тестирование шифрования в режиме CFB."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # IV (16 байт)
        iv = bytes.fromhex("1234567890abcdef234567890abcdef1")

        # Открытый текст (четыре 64-битных блока)
        plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Эталонный шифртекст
        expected_ciphertext = bytes.fromhex("DB37E0E266903C830D46644C1F9A089C24BDD2035315D38BBCC0321421075505")

        # Шифруем открытый текст
        encrypted_data = cfb_encrypt(plaintext, key, iv)

        # Проверяем, что полученный шифртекст совпадает с эталонным
        self.assertEqual(encrypted_data, expected_ciphertext, "Шифртекст не совпадает с эталонным!")
        print("✅ Тест шифрования в режиме CFB прошел успешно!")

    def test_cfb_decrypt(self):
        """Тестирование расшифрования в режиме CFB."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # IV (16 байт)
        iv = bytes.fromhex("1234567890abcdef234567890abcdef1")

        # Шифртекст
        ciphertext = bytes.fromhex("DB37E0E266903C830D46644C1F9A089C24BDD2035315D38BBCC0321421075505")

        # Исходный открытый текст
        expected_plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Расшифровываем шифртекст
        decrypted_data = cfb_decrypt(ciphertext, key, iv)

        # Проверяем, что полученный открытый текст совпадает с исходным
        self.assertEqual(decrypted_data, expected_plaintext,
                         "Открытый текст после расшифрования не совпадает с исходным!")
        print("✅ Тест расшифрования в режиме CFB прошел успешно!")

    def test_mac(self):
        """Тестирование вычисления MAC."""
        # Ключ
        key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        # Открытый текст (четыре 64-битных блока)
        plaintext = bytes.fromhex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")

        # Эталонный MAC
        expected_mac = bytes.fromhex("154E7210")

        # Вычисляем MAC
        calculated_mac = mac(plaintext, key)

        # Проверяем, что полученный MAC совпадает с эталонным
        self.assertEqual(calculated_mac, expected_mac, "MAC не совпадает с эталонным!")
        print(f"✅ Тест MAC прошел успешно! Рассчитанный MAC: {calculated_mac.hex().upper()}")


if __name__ == "__main__":
    unittest.main()
