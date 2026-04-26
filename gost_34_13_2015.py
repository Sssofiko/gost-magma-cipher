from magma import magma_encrypt_block, magma_decrypt_block, expand_key


def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Шифрует данные в режиме ECB."""
    assert len(plaintext) % 8 == 0, "Длина данных должна быть кратна 8 байтам (64 бит)"

    round_keys = expand_key(key)
    ciphertext = b""

    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i + 8]
        ciphertext += magma_encrypt_block(block, round_keys)

    return ciphertext


def ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Расшифровывает данные в режиме ECB."""
    assert len(ciphertext) % 8 == 0, "Длина данных должна быть кратна 8 байтам (64 бит)"

    round_keys = expand_key(key)
    plaintext = b""

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i + 8]
        plaintext += magma_decrypt_block(block, round_keys)

    return plaintext


def xor_blocks(block1: bytes, block2: bytes) -> bytes:
    """Выполняет XOR двух 64-битных блоков."""
    return bytes(a ^ b for a, b in zip(block1, block2))


def int_to_bytes(value: int, length: int) -> bytes:
    """Преобразует целое число в байтовое представление фиксированной длины."""
    return value.to_bytes(length, byteorder="big")


def ctr_encrypt_decrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Режим гаммирования (CTR) для Магма (используется одинаково для шифрования и дешифрования)."""
    assert len(iv) == 4, "IV должен быть 4 байта (половина блока)"

    round_keys = expand_key(key)
    ciphertext = b""
    counter = 0

    for i in range(0, len(plaintext), 8):
        # Формируем блок счетчика: IV (4 байта) + счетчик (4 байта)
        counter_block = iv + int_to_bytes(counter, 4)

        # Шифруем блок счетчика
        keystream_block = magma_encrypt_block(counter_block, round_keys)

        # XOR с очередным блоком данных
        block = plaintext[i:i + 8]
        ciphertext += bytes(a ^ b for a, b in zip(block, keystream_block))

        counter += 1  # Увеличиваем счетчик

    return ciphertext


def ofb_encrypt_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Режим гаммирования с обратной связью по выходу (OFB) для Магма.
    Используется одинаково для шифрования и дешифрования.

    :param data: Открытый или зашифрованный текст
    :param key: 256-битный ключ
    :param iv: 128-битный вектор инициализации
    :return: Результат преобразования
    """
    assert len(iv) == 16, "IV должен быть 128 бит (16 байт)"
    assert len(data) % 8 == 0, "Длина данных должна быть кратна 8 байтам (64 бит)"

    round_keys = expand_key(key)
    r = [iv[i:i + 8] for i in range(0, len(iv), 8)]  # Разбиваем IV на два 64-битных блока
    result = []

    for i in range(0, len(data), 8):
        r = [r[1], magma_encrypt_block(r[0], round_keys)]  # Сдвигаем и шифруем
        result.append(xor_blocks(r[-1], data[i:i + 8]))  # XOR с текущим блоком данных

    return b"".join(result)


def cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Режим CBC для шифрования.

    :param data: Открытый текст (уже с паддингом)
    :param key: 256-битный ключ
    :param iv: 192-битный вектор инициализации
    :return: Зашифрованный текст
    """
    assert len(data) % 8 == 0, "Открытый текст должен быть кратен 8 байтам (64 бит)"
    assert len(iv) == 24, "IV должен быть 192 бита (24 байта)"

    round_keys = expand_key(key)
    r = [iv[i:i + 8] for i in range(0, len(iv), 8)]  # Разбиваем IV на три 64-битных блока
    ciphertext = []

    for i in range(0, len(data), 8):
        block = xor_blocks(r[0], data[i:i + 8])  # XOR с первым блоком IV
        encrypted_block = magma_encrypt_block(block, round_keys)
        ciphertext.append(encrypted_block)
        r = r[1:] + [encrypted_block]  # Сдвиг IV

    return b"".join(ciphertext)


def cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Режим CBC для расшифрования.

    :param data: Зашифрованный текст
    :param key: 256-битный ключ
    :param iv: 192-битный вектор инициализации
    :return: Расшифрованный текст
    """
    assert len(data) % 8 == 0, "Шифртекст должен быть кратен 8 байтам (64 бит)"
    assert len(iv) == 24, "IV должен быть 192 бита (24 байта)"

    round_keys = expand_key(key)
    r = [iv[i:i + 8] for i in range(0, len(iv), 8)]  # Разбиваем IV на три 64-битных блока
    plaintext = []

    for i in range(0, len(data), 8):
        block = data[i:i + 8]
        decrypted_block = magma_decrypt_block(block, round_keys)
        plaintext.append(xor_blocks(r[0], decrypted_block))  # XOR с первым блоком IV
        r = r[1:] + [block]  # Сдвиг IV

    return b"".join(plaintext)


def cfb_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Режим CFB для шифрования.

    :param data: Открытый текст
    :param key: 256-битный ключ
    :param iv: 128-битный вектор инициализации
    :return: Зашифрованный текст
    """
    assert len(iv) == 16, "IV должен быть 128 бит (16 байт)"
    assert len(data) % 8 == 0, "Открытый текст должен быть кратен 8 байтам (64 бит)"

    round_keys = expand_key(key)
    r = [iv[i:i + 8] for i in range(0, len(iv), 8)]  # Разбиваем IV на два 64-битных блока
    ciphertext = []

    for i in range(0, len(data), 8):
        encrypted_r0 = magma_encrypt_block(r[0], round_keys)  # Шифруем первый блок IV
        ct_block = xor_blocks(encrypted_r0, data[i:i + 8])  # XOR с данными
        ciphertext.append(ct_block)
        r = r[1:] + [ct_block]  # Сдвигаем IV

    return b"".join(ciphertext)


def cfb_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Режим CFB для расшифрования.

    :param data: Зашифрованный текст
    :param key: 256-битный ключ
    :param iv: 128-битный вектор инициализации
    :return: Расшифрованный текст
    """
    assert len(iv) == 16, "IV должен быть 128 бит (16 байт)"
    assert len(data) % 8 == 0, "Шифртекст должен быть кратен 8 байтам (64 бит)"

    round_keys = expand_key(key)
    r = [iv[i:i + 8] for i in range(0, len(iv), 8)]  # Разбиваем IV на два 64-битных блока
    plaintext = []

    for i in range(0, len(data), 8):
        encrypted_r0 = magma_encrypt_block(r[0], round_keys)  # Шифруем первый блок IV
        pt_block = xor_blocks(encrypted_r0, data[i:i + 8])  # XOR с шифртекстом
        plaintext.append(pt_block)
        r = r[1:] + [data[i:i + 8]]  # Сдвигаем IV

    return b"".join(plaintext)


def mac_shift(data: bytes, xor_lsb: int, bs: int) -> bytes:
    """Выполняет сдвиг влево и XOR последнего бита."""
    num = int.from_bytes(data, 'big') << 1  # Сдвиг влево
    num ^= xor_lsb  # XOR с последним битом

    # Проверяем, что число помещается в допустимый диапазон
    max_value = (1 << (bs * 8)) - 1  # Максимальное значение для bs байтов
    if num > max_value:
        num = num & max_value  # Обрезаем до максимально допустимого значения

    return num.to_bytes(bs, 'big')[-bs:]

def mac_ks(encrypter, bs: int) -> tuple[bytes, bytes]:
    """Генерирует ключи K1 и K2 для CMAC."""
    Rb = 0b10000111 if bs == 16 else 0b11011  # Константы для GF(2^128) и GF(2^64)
    L = encrypter(bytes(bs))  # Шифруем нулевой блок
    k1 = mac_shift(L, Rb, bs) if L[0] & 0x80 else mac_shift(L, 0, bs)
    k2 = mac_shift(k1, Rb, bs) if k1[0] & 0x80 else mac_shift(k1, 0, bs)
    return k1, k2


def mac(data: bytes, key: bytes, bs: int = 8) -> bytes:
    """Генерирует MAC (CMAC, OMAC1).

    :param data: Данные для аутентификации
    :param key: 256-битный ключ
    :param bs: Размер блока (64 бита = 8 байт)
    :return: 32-битный MAC (согласно ГОСТ Р 34.13-2015)
    """
    assert len(data) > 0, "Данные не должны быть пустыми!"

    round_keys = expand_key(key)
    encrypter = lambda block: magma_encrypt_block(block, round_keys)

    k1, k2 = mac_ks(encrypter, bs)

    if len(data) % bs == 0:
        tail_offset = len(data) - bs
    else:
        tail_offset = len(data) - (len(data) % bs)

    prev = bytes(bs)
    for i in range(0, tail_offset, bs):
        prev = encrypter(bytes(a ^ b for a, b in zip(data[i:i + bs], prev)))

    tail = data[tail_offset:]
    padded_tail = tail.ljust(bs, b'\x00')  # PKCS3-паддинг (дополняем нулями)
    last_block = bytes(a ^ b for a, b in zip(padded_tail, prev))

    if len(tail) == bs:
        last_block = bytes(a ^ b for a, b in zip(last_block, k1))
    else:
        last_block = bytes(a ^ b for a, b in zip(last_block, k2))

    return encrypter(last_block)[:4]  # Возвращаем только 32 бита (4 байта) MAC
