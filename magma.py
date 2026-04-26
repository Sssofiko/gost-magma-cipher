import os
import base64
import binascii

# Таблица S-блоков (ГОСТ Р 34.12-2015)
SBOX = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
]


def sbox_substitution(value: int) -> int:
    """Применяет S-блоки к 32-битному числу."""
    assert 0 <= value <= 0xFFFFFFFF, "Число должно быть 32-битным!"

    result = 0
    for i in range(8):  # 8 групп по 4 бита
        nibble = (value >> (4 * i)) & 0xF  # Извлекаем 4 бита
        substituted = SBOX[i][nibble]  # Подставляем значение из S-блока
        result |= substituted << (4 * i)  # Записываем обратно

    return result


def transformation(value: int) -> int:
    """Применяет преобразование t к 32-битному числу."""
    return sbox_substitution(value)


def g(k: int, a: int) -> int:
    """Выполняет операцию g[k](a) = (t(Vec32(Int32(a) ⊞ Int32(k)))) << 11."""
    # Преобразуем входные значения в десятичные
    a_decimal = a
    k_decimal = k

    # Сложение чисел a и k по модулю 2^32
    sum_result = a_decimal + k_decimal
    sum_mod = sum_result % (2 ** 32)  # Приведение по модулю 2^32

    # Применяем преобразование t (с использованием S-блоков)
    t_result = sbox_substitution(sum_mod)

    # Переводим t_result в двоичный формат (по символам)
    t_result_hex = f"{t_result:08X}"
    t_result_bin = ''.join(f"{int(ch, 16):04b}" for ch in t_result_hex)

    # Перемещаем первые 11 бит в конец
    shifted_result_bin = t_result_bin[11:] + t_result_bin[:11]

    # Переводим результат обратно в целое число
    final_result = int(shifted_result_bin, 2)

    # Возвращаем результат в шестнадцатеричной форме
    return final_result


def expand_key(master_key: bytes) -> list[int]:
    """Разворачивает 256-битный ключ в 32 раундовых ключа."""
    assert len(master_key) == 32, "Ошибка: ключ должен быть 256 бит (32 байта)."

    # Разбиваем 256-битный ключ на 8 частей по 32 бита (4 байта каждая)
    key_parts = [int.from_bytes(master_key[i:i + 4], 'big') for i in range(0, 32, 4)]

    # Формируем 32 раундовых ключа: 24 ключа в прямом порядке + 8 в обратном
    round_keys = key_parts * 3 + key_parts[::-1]

    return round_keys


def feistel_round(x1: int, x0: int, k: int) -> tuple[int, int]:
    """Один раунд сети Фейстеля: X₁, X₀ = X₀, X₁ ⊕ g(X₀, K)."""
    return x0, x1 ^ g(k, x0)  # Обновляем X₁ и меняем местами X₁ и X₀


def magma_encrypt_block(block: bytes, round_keys: list[int]) -> bytes:
    """Шифрует 64-битный блок Магма."""
    assert len(block) == 8, "Блок должен быть 64 бита (8 байт)."

    # Разбиваем 64-битный блок на две 32-битные половины
    x1 = int.from_bytes(block[:4], 'big')
    x0 = int.from_bytes(block[4:], 'big')

    # 32 раунда Фейстеля
    for i in range(31):  # 31 раунд с обменом мест
        x1, x0 = feistel_round(x1, x0, round_keys[i])

    # Финальный раунд без обмена мест
    x1 ^= g(round_keys[31], x0)

    # Соединяем X₁ и X₀ обратно в 64-битный блок
    return x1.to_bytes(4, 'big') + x0.to_bytes(4, 'big')


def magma_decrypt_block(block: bytes, round_keys: list[int]) -> bytes:
    """Расшифровывает 64-битный блок алгоритмом Магма."""
    assert len(block) == 8, "Блок должен быть 64 бита (8 байт)."

    # Разбиваем 64-битный блок на две 32-битные половины
    x1 = int.from_bytes(block[:4], 'big')
    x0 = int.from_bytes(block[4:], 'big')

    # 32 раунда Фейстеля (ключи идут в ОБРАТНОМ порядке)
    for i in range(31, 0, -1):  # 31 раунд с обменом мест
        x1, x0 = feistel_round(x1, x0, round_keys[i])

    # Финальный раунд без обмена мест
    x1 ^= g(round_keys[0], x0)

    # Соединяем X₁ и X₀ обратно в 64-битный блок
    return x1.to_bytes(4, 'big') + x0.to_bytes(4, 'big')


def add_padding(data: bytes, block_size: int = 8) -> bytes:
    """Добавляет PKCS7-паддинг, чтобы размер данных был кратен block_size."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def encrypt_file(input_path: str, output_path: str, key: bytes):
    """Читает файл, шифрует его и сохраняет в output_path."""
    assert os.path.exists(input_path), "Файл не найден!"

    # Читаем данные из файла
    with open(input_path, "rb") as f:
        data = f.read()

    # Добавляем PKCS7-паддинг
    prepared_data = add_padding(data)

    # Выводим HEX открытого текста перед шифрованием
    print(f"🔍 HEX открытого текста: {prepared_data.hex()}")

    # Генерируем 32 раундовых ключа
    round_keys = expand_key(key)

    # Шифруем данные блоками по 8 байт
    encrypted_data = b""
    for i in range(0, len(prepared_data), 8):
        block = prepared_data[i:i + 8]
        encrypted_data += magma_encrypt_block(block, round_keys)

    # Кодируем зашифрованные данные в Base64
    encoded_data = base64.b64encode(encrypted_data)

    # Записываем зашифрованные данные в новый файл
    with open(output_path, "wb") as f:
        f.write(encoded_data)

    print(f"✅ Файл зашифрован и сохранён как: {output_path}")


def remove_padding(data: bytes) -> bytes:
    """Удаляет PKCS7-паддинг. Проверяет корректность перед удалением."""
    if not data:
        return b""

    padding_len = data[-1]  # Последний байт указывает, сколько байтов было добавлено
    if padding_len < 1 or padding_len > 8:
        raise ValueError("❌ Ошибка: неверный PKCS7-паддинг!")

    return data[:-padding_len]  # Убираем паддинг


def decrypt_file(input_path: str, output_path: str, key: bytes):
    """Читает зашифрованный файл, расшифровывает его и сохраняет в output_path."""
    if not os.path.exists(input_path):
        print(f"❌ Ошибка: файл '{input_path}' не найден!")
        return

    # Читаем закодированные в Base64 данные
    with open(input_path, "rb") as f:
        encoded_data = f.read()

    # Декодируем из Base64 обратно в байты
    try:
        data = base64.b64decode(encoded_data)
    except binascii.Error:
        print("❌ Ошибка: файл не является корректным Base64-кодированным текстом!")
        return

    # Проверяем, что размер данных кратен 8 байтам (64 бита)
    if len(data) % 8 != 0:
        print(
            f"❌ Ошибка: размер файла после Base64-декодирования ({len(data)} байт) не кратен 8! Возможно, файл повреждён.")
        return

    # Генерируем 32 раундовых ключа
    round_keys = expand_key(key)

    # Расшифровываем данные блоками по 8 байт
    decrypted_data = b""
    for i in range(0, len(data), 8):
        block = data[i:i + 8]
        decrypted_data += magma_decrypt_block(block, round_keys)

    # Выводим расшифрованные байты в HEX для отладки
    print(f"🔍 HEX расшифрованных данных: {decrypted_data.hex()}")

    # Удаляем паддинг PKCS7
    try:
        decrypted_data = remove_padding(decrypted_data)
    except ValueError:
        print("❌ Ошибка при удалении паддинга! Возможно, файл повреждён.")
        return

    # Сохраняем расшифрованные данные
    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    print(f"✅ Файл расшифрован и сохранён как: {output_path}")


def get_user_choice():
    """Запрашивает у пользователя выбор операции (шифрование или расшифрование)."""
    print("\nВыберите операцию:")
    print("  1) 🔒 Зашифровать файл")
    print("  2) 🔓 Расшифровать файл")

    while True:
        choice = input("Введите 1 или 2: ").strip()
        if choice in ["1", "2"]:
            return choice
        print("❌ Ошибка: введите 1 для шифрования или 2 для расшифрования.")


def get_file_path():
    """Запрашивает у пользователя путь к файлу и проверяет его существование."""
    while True:
        file_path = input("Введите путь к файлу: ").strip()
        if os.path.exists(file_path):
            return file_path
        print("❌ Ошибка: файл не найден, попробуйте еще раз.")


def get_key():
    """Запрашивает у пользователя ключ (16cc, текст или файл)."""
    print("\nВыберите способ ввода ключа:")
    print("  1) 📝 Ввести вручную")
    print("  2) 📄 Загрузить из файла")

    while True:
        method = input("Введите 1 или 2: ").strip()
        if method == "1":
            return get_key_from_console()
        elif method == "2":
            return get_key_from_file()
        else:
            print("❌ Ошибка: введите 1 или 2.")


def get_key_from_console():
    """Запрашивает ключ вручную (16cc или текст)."""
    print("\nВыберите формат ввода ключа:")
    print("  1) 🔢 Шестнадцатеричный (16cc)")
    print("  2) 🔡 Слово/текст")

    while True:
        key_format = input("Введите 1 или 2: ").strip()
        if key_format == "1":
            key_hex = input("Введите 32-байтовый ключ в 16сс: ").strip()
            try:
                key = bytes.fromhex(key_hex)
                if len(key) == 32:
                    return key
                else:
                    print("❌ Ошибка: ключ должен быть ровно 32 байта (64 символа в 16сс).")
            except ValueError:
                print("❌ Ошибка: введите корректный шестнадцатеричный ключ.")
        elif key_format == "2":
            key_text = input("Введите ключ (слово/текст): ").strip().encode('utf-8')
            return key_text.ljust(32, b'\0')[:32]  # Дополняем нулями или обрезаем
        else:
            print("❌ Ошибка: введите 1 или 2.")


def get_key_from_file():
    """Загружает ключ из файла (16cc или текст)."""
    file_path = get_file_path()

    with open(file_path, "r", encoding="utf-8") as f:
        key_content = f.read().strip()

    print("\nВыберите формат ключа в файле:")
    print("  1) 🔢 Шестнадцатеричный (16cc)")
    print("  2) 🔡 Слово/текст")

    while True:
        key_format = input("Введите 1 или 2: ").strip()
        if key_format == "1":
            try:
                key = bytes.fromhex(key_content)
                if len(key) == 32:
                    return key
                else:
                    print("❌ Ошибка: ключ должен быть ровно 32 байта (64 символа в 16сс).")
            except ValueError:
                print("❌ Ошибка: некорректный шестнадцатеричный ключ в файле.")
        elif key_format == "2":
            key = key_content.encode('utf-8')
            return key.ljust(32, b'\0')[:32]  # Дополняем нулями или обрезаем
        else:
            print("❌ Ошибка: введите 1 или 2.")


def get_output_filename(default_name: str) -> str:
    """Позволяет пользователю выбрать стандартное или задать свое имя файла."""
    print(f"\nВыберите название выходного файла:")
    print(f"  1) 📄 Использовать стандартное ({default_name})")
    print("  2) ✏️ Ввести своё название")

    while True:
        choice = input("Введите 1 или 2: ").strip()
        if choice == "1":
            return default_name
        elif choice == "2":
            custom_name = input("Введите имя выходного файла (с расширением): ").strip()
            return custom_name if custom_name else default_name
        else:
            print("❌ Ошибка: введите 1 или 2.")


def view_file_content(file_path: str):
    """Предлагает пользователю посмотреть содержимое файла."""
    print("\nХотите посмотреть содержимое файла?")
    print("  1) 👀 Да, показать")
    print("  2) ❌ Нет, завершить")

    while True:
        choice = input("Введите 1 или 2: ").strip()
        if choice == "1":
            with open(file_path, "rb") as f:
                content = f.read(256)  # Ограничиваем вывод 256 байтами
            print("\n🔹 Содержимое файла:")
            print(content.decode("utf-8", errors="replace"))  # Показываем текст
            break
        elif choice == "2":
            print("🚀 Готово! Завершаем работу.")
            break
        else:
            print("❌ Ошибка: введите 1 или 2.")


def get_mode_choice():
    """Запрашивает у пользователя выбор режима шифрования."""
    print("\nВыберите режим работы:")
    print("  1) ECB (Electronic Codebook)")
    print("  2) CTR (Counter Mode)")
    print("  3) OFB (Output Feedback Mode)")
    print("  4) CBC (Cipher Block Chaining)")
    print("  5) CFB (Cipher Feedback Mode)")
    print("  6) MAC (Message Authentication Code)")

    while True:
        choice = input("Введите номер режима (1-6): ").strip()
        if choice in ["1", "2", "3", "4", "5", "6"]:
            return int(choice)
        print("❌ Ошибка: введите число от 1 до 6.")


def encrypt_data(data: bytes, key: bytes, mode: int, iv: bytes = None) -> bytes:
    """Шифрует данные в выбранном режиме."""
    from gost_34_13_2015 import ecb_encrypt, ctr_encrypt_decrypt, ofb_encrypt_decrypt, cbc_encrypt, cfb_encrypt, mac

    if mode == 1:  # ECB
        data = add_padding(data)
        return ecb_encrypt(data, key)
    elif mode == 2:  # CTR
        assert iv is not None and len(iv) == 4, "CTR требует 4-байтовый IV."
        return ctr_encrypt_decrypt(data, key, iv)
    elif mode == 3:  # OFB
        assert iv is not None and len(iv) == 16, "OFB требует 16-байтовый IV."
        return ofb_encrypt_decrypt(data, key, iv)
    elif mode == 4:  # CBC
        assert iv is not None and len(iv) == 24, "CBC требует 24-байтовый IV."
        data = add_padding(data)
        return cbc_encrypt(data, key, iv)
    elif mode == 5:  # CFB
        assert iv is not None and len(iv) == 16, "CFB требует 16-байтовый IV."
        data = add_padding(data)
        return cfb_encrypt(data, key, iv)
    elif mode == 6:  # MAC
        mac_result = mac(data, key)
        return mac_result.hex().encode()
    else:
        raise ValueError("Неподдерживаемый режим!")


def decrypt_data(data: bytes, key: bytes, mode: int, iv: bytes = None) -> bytes:
    """Расшифровывает данные в выбранном режиме."""
    from gost_34_13_2015 import ecb_decrypt, ctr_encrypt_decrypt, ofb_encrypt_decrypt, cbc_decrypt, cfb_decrypt

    if mode == 1:  # ECB
        plaintext = ecb_decrypt(data, key)
        return remove_padding(plaintext)
    elif mode == 2:  # CTR
        assert iv is not None and len(iv) == 4, "CTR требует 4-байтовый IV."
        return ctr_encrypt_decrypt(data, key, iv)
    elif mode == 3:  # OFB
        assert iv is not None and len(iv) == 16, "OFB требует 16-байтовый IV."
        return ofb_encrypt_decrypt(data, key, iv)
    elif mode == 4:  # CBC
        assert iv is not None and len(iv) == 24, "CBC требует 24-байтовый IV."
        plaintext = cbc_decrypt(data, key, iv)
        return remove_padding(plaintext)
    elif mode == 5:  # CFB
        assert iv is not None and len(iv) == 16, "CFB требует 16-байтовый IV."
        plaintext = cfb_decrypt(data, key, iv)
        return remove_padding(plaintext)
    elif mode == 6:  # MAC
        raise ValueError("MAC не поддерживает расшифрование!")
    else:
        raise ValueError("Неподдерживаемый режим!")


def get_iv_from_user(iv_length: int) -> bytes:
    """Запрашивает IV у пользователя."""
    print(f"\nВведите {iv_length}-байтовый IV (в шестнадцатеричном формате):")

    while True:
        iv_hex = input("IV: ").strip()
        try:
            iv = bytes.fromhex(iv_hex)
            if len(iv) == iv_length:
                print(f"🔑 Введенный IV ({iv_length} байт): {iv.hex()}")
                return iv
            else:
                print(f"❌ Ошибка: IV должен быть ровно {iv_length} байт!")
        except ValueError:
            print("❌ Ошибка: введите корректный шестнадцатеричный IV.")


def get_iv_choice(iv_length: int) -> bytes:
    """Позволяет пользователю выбрать способ получения IV."""
    print(f"\nВыберите способ задания IV ({iv_length}-байтовый):")
    print("  1) 📝 Ввести вручную")
    print("  2) 🔄 Сгенерировать автоматически")

    while True:
        choice = input("Введите 1 или 2: ").strip()
        if choice == "1":
            return get_iv_from_user(iv_length)
        elif choice == "2":
            iv = os.urandom(iv_length)
            print(f"🔑 Сгенерированный IV ({iv_length} байт): {iv.hex()}")
            return iv
        else:
            print("❌ Ошибка: введите 1 или 2.")


if __name__ == "__main__":
    print("=== 🛡 Блочный шифр Магма (ГОСТ Р 34.12-2015) 🛡 ===")

    choice = get_user_choice()  # Выбор операции (шифрование/расшифрование)
    file_path = get_file_path()  # Получение пути к файлу
    key = get_key()  # Получение ключа

    mode = get_mode_choice()  # Выбор режима работы
    iv = None

    if mode in [2, 3, 4, 5]:  # Режимы, требующие IV
        iv_length = {2: 4, 3: 16, 4: 24, 5: 16}[mode]

        if choice == "1":  # Шифрование
            # Для шифрования даем выбор: ввести IV или сгенерировать автоматически
            print(f"\nВыберите способ задания IV ({iv_length}-байтовый):")
            print("  1) 📝 Ввести вручную")
            print("  2) 🔄 Сгенерировать автоматически")

            while True:
                iv_choice = input("Введите 1 или 2: ").strip()
                if iv_choice == "1":
                    iv = get_iv_from_user(iv_length)  # Пользователь вводит IV
                    break
                elif iv_choice == "2":
                    iv = os.urandom(iv_length)  # Генерация случайного IV
                    print(f"🔑 Сгенерированный IV ({iv_length} байт): {iv.hex()}")
                    break
                else:
                    print("❌ Ошибка: введите 1 или 2.")
        else:  # Расшифрование
            # Для расшифрования всегда запрашиваем IV у пользователя
            iv = get_iv_from_user(iv_length)

    if choice == "1":  # Шифрование
        output_file = get_output_filename("encrypted_text.txt")
        with open(file_path, "rb") as f:
            data = f.read()

        encrypted_data = encrypt_data(data, key, mode, iv)
        if mode != 6:  # Если это не MAC
            encrypted_data = base64.b64encode(encrypted_data)

        with open(output_file, "wb") as f:
            f.write(encrypted_data)

        print(f"✅ Файл зашифрован: {output_file}")
        view_file_content(output_file)

    else:  # Расшифрование
        output_file = get_output_filename("decrypted_text.txt")

        with open(file_path, "rb") as f:
            data = f.read()

        if mode != 6:  # Если это не MAC
            data = base64.b64decode(data)

        decrypted_data = decrypt_data(data, key, mode, iv)

        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        print(f"✅ Файл расшифрован: {output_file}")
        view_file_content(output_file)

    print("\n🚀 Готово!")
