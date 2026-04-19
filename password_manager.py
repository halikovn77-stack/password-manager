import os
import base64
import random
import string
import sqlite3
import datetime
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ========== КОНСТАНТЫ ==========
SALT_FILE = 'salt.bin'              # Файл с солью (нужен для создания ключа из пароля)
DB_FILE = 'passwords.db'            # Временная незашифрованная база данных
ENCRYPTED_DB_FILE = 'passwords.enc' # Зашифрованная база данных (хранится постоянно)

# ========== ЛОГИРОВАНИЕ ==========
def write_log(action, details=""):
    """
    Записывает действие пользователя в файл лога с временной меткой.
    
    Аргументы:
        action: str - название действия (например, "ДОБАВЛЕН ПАРОЛЬ")
        details: str - подробности (например, "google/user@gmail.com")
    
    Файл лога: password_manager.log
    Режим: 'a' (append) - добавляем в конец, не перезаписываем
    """

    log_file = 'password_manager.log'
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {action}: {details}\n")

# ========== ШИФРОВАНИЕ (МАСТЕР-ПАРОЛЬ) ==========
def derive_key_from_password(password: str, salt: bytes = None):
    """
    Превращает мастер-пароль в ключ шифрования для Fernet.
    
    Как работает:
        1. Если соль не передана - генерируем новую (16 случайных байт)
        2. PBKDF2 "прогоняет" пароль через хеширование 100 000 раз с добавлением соли
        3. Получаем 32 байта (нужно для Fernet)
        4. Кодируем в base64 (Fernet требует такой формат)
    
    Аргументы:
        password: str - мастер-пароль пользователя
        salt: bytes - соль (если None - генерируем новую)
    
    Возвращает:
        key: bytes - ключ в формате base64 (готов для Fernet)
        salt: bytes - соль (нужно сохранить)
    """
    if salt is None:
        salt = os.urandom(16) # 16 случайных байт = соль
        print('Сгенерирована новая соль')

    # Настройка преобразователя пароля в ключ
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),    # алгоритм хеширования
        length=32,                    # длина ключа (32 байта)
        salt=salt,                    # соль (уникальная добавка)
        iterations=100000,            # 100 тысяч повторений (для защиты от подбора)
    )

    # Создаём ключ из пароля
    key_bytes = kdf.derive(password.encode())
    # Fernet требует ключ в формате base64
    key = base64.urlsafe_b64encode(key_bytes)

    return key, salt

def initialize_cipher():
    """
    Запрашивает мастер-пароль и создаёт объект для шифрования/расшифровки.
    
    При первом запуске:
        - Просит придумать пароль (дважды для подтверждения)
        - Генерирует соль и сохраняет её в salt.bin
        - Создаёт ключ из пароля
    
    При следующих запусках:
        - Загружает соль из salt.bin
        - Просит ввести мастер-пароль
        - Создаёт ключ из пароля + соли
    
    Возвращает:
        cipher: Fernet - объект для шифрования/расшифровки
    """

    if os.path.exists(SALT_FILE):
        # НЕ первый запуск: соль уже есть
        print('Загружаю существующую соль...')
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()

        password = getpass('Введите мастер-пароль: ')
        key, _ = derive_key_from_password(password, salt)
        print('Ключ создан из мастер-пароля')
        write_log("ВХОД В СИСТЕМУ", "Мастер-пароль введён")
    else:
        # ПЕРВЫЙ запуск: создаём новый мастер-пароль
        print("ПЕРВЫЙ ЗАПУСК! Создаю новый мастер-пароль.\n")
        password = getpass('Придумайте мастер-пароль: ')
        password_confirm = getpass('Повторите мастер-пароль: ')

        if password != password_confirm:
            print('Пароли не совпадают!')
            write_log("ОШИБКА", "Пароли не совпадают при создании")
            exit(1)

        key, salt = derive_key_from_password(password)

        # Сохраняем ТОЛЬКО соль (пароль и ключ НЕ сохраняем!)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
        print("\nСоль сохранена. ЗАПОМНИТЕ МАСТЕР-ПАРОЛЬ! Без него данные не восстановить.\n")
        write_log("СОЗДАНИЕ МАСТЕР-ПАРОЛЯ", "Новый мастер-пароль создан")

    return Fernet(key)

# ========== РАБОТА С ЗАШИФРОВАННОЙ БАЗОЙ ДАННЫХ ==========
def decrypt_db(cipher):
    """
    Расшифровывает passwords.enc во временный passwords.db.
    
    Алгоритм:
        1. Читаем зашифрованный файл passwords.enc
        2. Расшифровываем с помощью переданного cipher
        3. Сохраняем расшифрованные данные как passwords.db
    
    Аргументы:
        cipher: Fernet - объект для расшифровки
    
    Возвращает:
        bool - True если расшифровка успешна, False если файла нет или ошибка
    """
    if not os.path.exists(ENCRYPTED_DB_FILE):
        print("Зашифрованный файл не найден. Будет создана новая БД.")
        return False
    
    print('Расшифровываю базу данных...')

    try:
        with open(ENCRYPTED_DB_FILE, 'rb') as enc_file:
            encrypted_data = enc_file.read()

        decrypted_data = cipher.decrypt(encrypted_data)

        with open(DB_FILE, 'wb') as db_file:
            db_file.write(decrypted_data)
        
        print('База данных расшифрована')
        return True
    except Exception as e:
        # Неправильный мастер-пароль вызовет ошибку расшифровки
        print(f"Ошибка расшифровки! Неправильный мастер-пароль {e}")
        return False
    
def encrypt_db(cipher):
    """
    Шифрует passwords.db обратно в passwords.enc.
    
    Алгоритм:
        1. Читаем временный файл passwords.db
        2. Шифруем с помощью переданного cipher
        3. Сохраняем зашифрованные данные как passwords.enc
    
    Аргументы:
        cipher: Fernet - объект для шифрования
    """
    if not os.path.exists(DB_FILE):
        print("Нет файла БД для шифрования")
        return
    
    print('Шифрую базу данных...')

    with open(DB_FILE, 'rb') as db_file:
        db_data = db_file.read()

    encrypted_data = cipher.encrypt(db_data)

    with open(ENCRYPTED_DB_FILE, 'wb') as enc_file:
        enc_file.write(encrypted_data)

    print('База данных зашифрована')

def create_new_database():
    """
    Создаёт новую пустую базу данных SQLite с таблицей accounts.
    
    Таблица имеет поля:
        - id: INTEGER PRIMARY KEY AUTOINCREMENT (уникальный номер)
        - service: TEXT NOT NULL (название сервиса, не может быть пустым)
        - username: TEXT (логин/почта)
        - password: TEXT (пароль)
    """
    print('Создаю новую базу данных...')
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT,
            password TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print('Новая БД создана')

# ========== ФУНКЦИИ ДЛЯ РАБОТЫ С ПАРОЛЯМИ ==========
def add_password():
    """
    Добавляет новый пароль в базу данных.
    
    Защита:
        - Проверка на пустые поля
        - Проверка на дубликаты (сервис + логин)
        - Предупреждение при пустом пароле
    """
    print('\nДОБАВЛЕНИЕ НОВОГО ПАРОЛЯ')
    print('-' * 30)

    # Ввод названия сервиса (не может быть пустым)
    while True:
        service = input("Введите название сервиса: ").strip()
        if service:
            break
        print('Название сервиса не должно быть пустым!')

    # Ввод логина (не может быть пустым)
    while True:
        username = input("Введите логин/почту/телефон: ").strip()
        if username:
            break
        print('Логин не должен быть пустым!')
    
    # Ввод пароля (может быть пустым, но с предупреждением)
    password = input("Введите пароль: ").strip()
    if not password:
        print('ПРЕДУПРЕЖДЕНИЕ: пароль пустой!')
        confirm = input('Продолжить? (y/n): ')
        if confirm.lower() != 'y':
            print('Действие отменено')
            write_log("ДОБАВЛЕНИЕ ОТМЕНЕНО", f"{service}/{username} (пустой пароль)")
            return
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Проверка на существование такого же аккаунта
    cursor.execute(
        'SELECT * FROM accounts WHERE service = ? AND username = ?',
        (service, username)
    )
    if cursor.fetchone():
        print(f"\nАккаунт '{username}' для сервиса '{service}' УЖЕ СУЩЕСТВУЕТ!")
        print('Чтобы изменить пароль, используйте опцию 4 - Обновить пароль')
        write_log("ДОБАВЛЕНИЕ ОТМЕНЕНО", f"{service}/{username} (уже существует)")
        conn.close()
        return
    
    # Добавляем новую запись
    cursor.execute(
        'INSERT INTO accounts (service, username, password) VALUES (?, ?, ?)',
        (service, username, password)
    )

    conn.commit()
    conn.close()
    print(f"Пароль для '{service}' ({username}) ДОБАВЛЕН!")
    write_log("ДОБАВЛЕН ПАРОЛЬ", f"{service}/{username}")

def find_password():
    """
    Ищет пароль по названию сервиса.
    
    Показывает ВСЕ аккаунты, связанные с этим сервисом.
    (потому что у одного сервиса может быть несколько логинов)
    """
    print('\nПОИСК ПАРОЛЯ')
    print('-' * 30)

    service = input("Введите название сервиса: ").strip()

    if not service:
        print('Название сервиса не должно быть пустым!')
        return
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Ищем все аккаунты этого сервиса, сортируем по логину
    cursor.execute(
        'SELECT username, password FROM accounts WHERE service = ? ORDER BY username',
        (service,)
    )

    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print(f"Сервис '{service}' НЕ НАЙДЕН!")
        write_log("ПОИСК НЕ УДАЛСЯ", f"{service} (не найден)")
        return
    
    print(f"\nНайдено аккаунтов для '{service}': {len(rows)}")
    print('=' * 40)
    for i, (username, password) in enumerate(rows, 1):
        print(f"  {i}. Логин: {username}")
        print(f"     Пароль: {password}")
        print()
    print("=" * 40)
    write_log("ПОИСК ПАРОЛЯ", f"{service} (найдено {len(rows)} аккаунтов)")

def show_all_services():
    """
    Показывает список всех сервисов с количеством аккаунтов.
    
    Группирует записи по полю service и считает количество.
    Правильно склоняет слово "аккаунт" в зависимости от числа.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT service, COUNT(*) as count 
        FROM accounts 
        GROUP BY service 
        ORDER BY service
    ''')
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print('\nНЕТ СОХРАНЕННЫХ ПАРОЛЕЙ')
    else:
        print('\nСПИСОК СЕРВИСОВ')
        print('-' * 40)
        for service, count in rows:
            # Склонение слова "аккаунт" по правилам русского языка
            if count == 1:
                word = 'аккаунт'
            elif 2 <= count <= 4:
                word = 'аккаунта'
            else:
                word = 'аккаунтов'
            print(f"  {service}: {count} {word}")
        print('-' * 40)

def update_password():
    """
    Обновляет пароль для существующего аккаунта.
    
    Алгоритм:
        1. Найти все аккаунты по названию сервиса
        2. Показать их пользователю
        3. Пользователь выбирает номер
        4. Вводит новый пароль
        5. Подтверждает изменение
    """
    print('\nОБНОВЛЕНИЕ ПАРОЛЯ')
    print('-' * 30)

    service = input("Введите название сервиса: ").strip()

    if not service:
        print('Название сервиса не должно быть пустым!')
        return
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Получаем все аккаунты этого сервиса
    cursor.execute(
        'SELECT id, username FROM accounts WHERE service = ? ORDER BY username',
        (service,)
    )
    accounts = cursor.fetchall()

    if not accounts:
        print(f"Сервис '{service}' НЕ НАЙДЕН!")
        write_log("ОБНОВЛЕНИЕ НЕ УДАЛОСЬ", f"{service} (не найден)")
        conn.close()
        return
    
    # Показываем список найденных аккаунтов
    print(f"\nНайдено аккаунтов для '{service}': {len(accounts)}")
    for i, (acc_id, username) in enumerate(accounts, 1):
        print(f"  {i}. {username}")
    
    try:
        choice = int(input('\nВыберите номер аккаунта для обновления (0 - отмена): '))
        if choice == 0:
            print('Обновление омтменено')
            conn.close()
            return
        elif 1 <= choice <= len(accounts):
            account_id, username = accounts[choice - 1]

            new_password = input(f"\nВведите новый пароль для '{username}': ").strip()
            if not new_password:
                print("Пароль не может быть пустым!")
                conn.close()
                return
            
            confirm = input(f"Изменить пароль для '{username}'? (y/n): ")
            if confirm.lower() == 'y':
                # SQL-запрос UPDATE - обновляет существующую запись
                cursor.execute(
                    'UPDATE accounts SET password = ? WHERE id = ?',
                    (new_password, account_id)
                )
                conn.commit()
                print(f"\nПароль для '{service}' ({username}) ОБНОВЛЕН!")
                write_log("ОБНОВЛЁН ПАРОЛЬ", f"{service}/{username}")
            else:
                print('Обновление отменено')
        else:
            print('Неверный номер')
    except ValueError:
        print('Введите ЧИСЛО')

    conn.close()

def delete_password():
    """
    Удаляет пароль с двойным подтверждением.
    
    Защита от случайного удаления:
        1. Пользователь выбирает аккаунт
        2. Первое подтверждение (y/n)
        3. Второе подтверждение (нужно ввести 'yes')
    """
    print('\nУДАЛЕНИЕ ПАРОЛЯ')
    print('-' * 30)

    service = input("Введите название сервиса: ").strip()
    if not service:
        print('Название сервиса не должно быть пустым!')
        return
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        'SELECT id, username FROM accounts WHERE service = ? ORDER BY username',
        (service,)
    )
    accounts = cursor.fetchall()

    if not accounts:
        print(f"Сервис '{service}' НЕ НАЙДЕН!")
        write_log("УДАЛЕНИЕ НЕ УДАЛОСЬ", f"{service} (не найден)")
        conn.close()
        return
    
    print(f"\nНайдено аккаунтов для '{service}': {len(accounts)}")
    for i, (acc_id, username) in enumerate(accounts, 1):
        print(f"  {i}. {username}")
    
    try:
        choice = int(input('\nВыберите номер аккаунта для удаления (0 - отмена): '))
        if choice == 0:
            print('Удаление омтменено')
            conn.close()
            return
        elif 1 <= choice <= len(accounts):
            account_id, username = accounts[choice - 1]

            print(f"\nВНИМАНИЕ! Вы собираетесь УДАЛИТЬ аккаунт '{username}' для сервиса '{service}'")
            confirm = input("Это действие НЕЛЬЗЯ отменить. Удалить? (y/n): ")

            if confirm.lower() == 'y':
                # Второе подтверждение (защита от случайного нажатия)
                confirm2 = input(f"Ещё раз ПОДТВЕРДИТЕ удаление (введите 'yes'): ")
                if confirm2.lower() == 'yes':
                    cursor.execute('DELETE FROM accounts WHERE id = ?',(account_id,))
                    conn.commit()
                    print(f"\nАккаунт '{username}' УДАЛЕН!")
                    write_log("УДАЛЁН ПАРОЛЬ", f"{service}/{username}")
                else:
                    print("Удаление отменено")
            else:
                print("Удаление отменено")
        else:
            print("Неверный номер")
    except ValueError:
        print('Ведите ЧИСЛО')

    conn.close()

def generate_password():
    """
    Генерирует надёжный случайный пароль с настройками пользователя.
    
    Возможности:
        - Настройка длины (по умолчанию 16)
        - Выбор типа символов (буквы/цифры/спецсимволы)
        - Сохранение сгенерированного пароля сразу в базу
    """
    print('\nГЕНЕРАТОР ПАРОЛЕЙ')
    print('-' * 30)

    # Запрашиваем длину пароля
    try:
        length_input = input("Введите длину пароля (по умолчанию 16): ").strip()
        if length_input:
            length = int(length_input)
            # Ограничение по безопасности
            if length < 4:
                print("Пароль слишком короткий! Минимум 4 символа. Будет использована длина 8")
                length = 8
            elif length > 100:
                print("Пароль слишком длинный! Максимум 100 символов. Будет использована длина 32")
                length = 32
        else:
            length = 16
    except ValueError:
        print("Некорректный ввод! Использую длину 16")
        length = 16

    # Запрашиваем тип символов
    print('\nКакие символы использовать?')
    print("  1. Только буквы (a-z)")
    print("  2. Буквы + цифры")
    print("  3. Буквы + цифры + спецсимволы (рекомендуется)")
    print("  4. Только цифры")

    choice = input("Выберите тип (1-4, по умолчанию 3): ").strip()

    # Настраиваем набор символов в зависимости от выбора
    if choice == '1':
        chars = string.ascii_letters  # a-z и A-Z
        type_name = 'буквы'
    elif choice == '2':
        chars = string.ascii_letters + string.digits # буквы + цифры
        type_name = 'буквы и цифры'
    elif choice == '4':
        chars = string.digits # только цифры
        type_name = "цифры"
    else:
        chars = string.ascii_letters + string.digits + "!@#$%^&*"  # всё
        type_name = "буквы, цифры и спецсимволы"

    # Генерируем пароль (случайный выбор символов из набора)
    password = ''.join(random.choice(chars) for _ in range(length))

    # Результат
    print('\n' + '=' * 50)
    print(f"СГЕНЕРИРОВАН ПАРОЛЬ ({type_name}, {length}) символов:")
    print(f"\n   {password}\n")
    print('=' * 50)

    # Предлагаем сохранить пароль
    save = input("\nСохранить этот пароль для сервиса? (y/n): ").strip().lower()

    if save == 'y':
        service = input("Введите название сервиса: ").strip()
        if not service:
            print("Название сервиса не может быть пустым!")
            write_log("ГЕНЕРАЦИЯ ПАРОЛЯ", "Сохранение отменено (пустой сервис)")
            return
        
        username = input("Введите логин/почту/телефон: ").strip()
        if not username:
            print("Логин не может быть пустым!")
            write_log("ГЕНЕРАЦИЯ ПАРОЛЯ", "Сохранение отменено (пустой логин)")
            return
        
        # Проверяем, не существует ли уже такой аккаунт
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute(
            'SELECT * FROM accounts WHERE service = ? AND username = ?',
            (service, username)
        )
        if cursor.fetchone:
            print(f"\nАккаунт '{username}' для сервиса '{service}' УЖЕ СУЩЕСТВУЕТ!")
            write_log("ГЕНЕРАЦИЯ ПАРОЛЯ", f"Сохранение отменено {service}/{username} (уже существует)")
            conn.close()
            return
        
        # Сохраняем
        cursor.execute(
            'INSERT INTO accounts (service, username, password) VALUES (?, ?, ?)',
            (service, username, password)
        )
        conn.commit()
        conn.close()

        print(f"\nПароль для '{service}' ({username}) СОХРАНЁН!")
        write_log("СОХРАНЁН СГЕНЕРИРОВАННЫЙ ПАРОЛЬ", f"{service}/{username}")
    else:
        print("\nПароль НЕ сохранён. Вы можете скопировать его и использовать вручную.")
        write_log("ГЕНЕРАЦИЯ ПАРОЛЯ", "Пароль сгенерирован, но не сохранён")
        
# ========== ГЛАВНАЯ ФУНКЦИЯ (МЕНЮ) ==========
def main():
    """
    Главная функция - запускает меню и управляет всем приложением.
    
    Порядок работы:
        1. Логируем запуск
        2. Инициализируем шифрование (мастер-пароль)
        3. Расшифровываем БД или создаём новую
        4. Бесконечный цикл с меню
        5. При выходе: шифруем БД и удаляем временный файл
    """
    write_log("ЗАПУСК ПРОГРАММЫ", "=" * 40)
    cipher = initialize_cipher()

    if not decrypt_db(cipher):
        create_new_database()
        write_log("СОЗДАНИЕ БД", "Создана новая пустая база данных")

    # Бесконечный цикл меню
    while True:
        print("\n" + "=" * 50)
        print("           МЕНЕДЖЕР ПАРОЛЕЙ")
        print("=" * 50)
        print("  1. 🔐 ДОБАВИТЬ пароль")
        print("  2. 🔍 НАЙТИ пароль")
        print("  3. 📋 СПИСОК сервисов")
        print("  4. 🔄 ОБНОВИТЬ пароль")
        print("  5. 🗑️  УДАЛИТЬ пароль")
        print("  6. 🎲 СГЕНЕРИРОВАТЬ пароль")
        print("  7. 🚪 ВЫЙТИ")
        print("=" * 50)

        choice = input("  Введите номер действия (1-7): ")

        if choice == '1':
            add_password()
        elif choice == '2':
            find_password()
        elif choice == '3':
            show_all_services()
        elif choice == '4':
            update_password()
        elif choice == '5':
            delete_password()
        elif choice == '6':
            generate_password()
        elif choice == '7':
            print("\nСохраняю изменения и выхожу...")
            write_log("ЗАВЕРШЕНИЕ ПРОГРАММЫ", "Пользователь вышел")
            break
        else:
            print("НЕВЕРНЫЙ ВЫБОР! Введите число от 1 до 7.")
    
    # Шифруем БД обратно
    encrypt_db(cipher)

    # Удаляем временный файл
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print('Временный файл удалён')

    print("\nДО СВИДАНИЯ! База данных зашифрована.")

# ========== ЗАПУСК ПРОГРАММЫ ==========
if __name__ == '__main__':
    main()