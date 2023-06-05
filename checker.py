"""
Реализация класса проверки приложений
"""
import os
import re
import subprocess

import r2pipe
import zipfile
import plistlib
from bs4 import BeautifulSoup


class FileChecker:
    """
    Класс проверки приложений
    """
    def __init__(self):
        self.ipa_file_path = ""
        self.code_dir_path = ""
        self.extract_dir = ""

    def choose_ipa_file(self, file_path):
        """
        Выбирает файл .ipa для проверки.

        Args:
            file_path (str): Путь к файлу .ipa.
        """
        self.ipa_file_path = file_path

    def choose_code_dir(self, dir_path):
        """
        Выбирает папку с кодом для проверки.

        Args:
            dir_path (str): Путь к папке с кодом.
        """
        self.code_dir_path = dir_path

    def extract_files(self):
        """
        Разархивирует файл .ipa.

        Returns:
            bool: True, если разархивация прошла успешно, иначе False.
        """
        if not self.ipa_file_path:
            return False

        extract_dir = os.path.join(os.getcwd(), "extracted_files")
        os.makedirs(extract_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(self.ipa_file_path, 'r') as ipa_zip:
                ipa_zip.extractall(extract_dir)
            self.extract_dir = extract_dir
            return True
        except Exception as e:
            raise Exception(f"Ошибка при разархивации файлов: {e}")

    def find_info_plist_CFBundleExecutable(self):
        """
        Находит исполняемый файл в файле Info.plist.

        Returns:
            str or None: Имя исполняемого файла или None, если не найден.
        """
        if not self.ipa_file_path:
            return None

        with zipfile.ZipFile(self.ipa_file_path, 'r') as ipa_file:
            for file_name in ipa_file.namelist():
                if file_name.endswith('.app/Info.plist'):
                    plist_data = ipa_file.read(file_name)
                    info_plist = plistlib.loads(plist_data)
                    executable = info_plist.get('CFBundleExecutable')
                    if executable:
                        return executable

        return None

    def find_file_by_name(self, file_name, directory):
        """
         Находит файл по имени в заданной директории.

         Args:
             file_name (str): Имя файла.
             directory (str): Путь к директории.

         Returns:
             str or None: Полный путь к файлу или None, если файл не найден.
         """
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file == file_name:
                    return os.path.join(root, file)
        return None

    def get_import_names(self, executable_path):
        """
        Получает список имен импортируемых модулей из исполняемого файла.

        Args:
            executable_path (str): Путь к исполняемому файлу.

        Returns:
            list: Список имен импортируемых модулей.
        """
        r = r2pipe.open(executable_path)
        raw_print = r.cmd('ii')
        import_records = raw_print.split("\r\n")[3:]
        import_names = [i[41:] for i in import_records]
        return import_names

    def check_file_crypt(self):
        """
        Проверяет наличие импорта криптографических функций.

        Returns:
            tuple: Кортеж с двумя значениями:
                - bool: True, если импорт криптографических функций обнаружен, иначе False.
                - bool: True, если импорт "kSecAttrAccessibleAlways" обнаружен, иначе False.
        """
        if not self.extract_dir:
            raise Exception("Сначала разархивируйте файл .ipa")

        executable_path = self.find_file_by_name(self.find_info_plist_CFBundleExecutable(), self.extract_dir)
        import_names = self.get_import_names(executable_path)
        is_found = any(name in import_names for name in ["CCCrypt", "CCCryptorCreate", "CCCryptorCreate","CCryptorCreateFromData","CCCryptorRelease",
      "CCCryptorUpdate","CCCryptorFinal", "CCCryptorGetOutputLength", "CCCryptorReset", "CCCrypt", "'CC_SHA256", "CC_MD5", "CC_SHA1", "SecKeyDecrypt",
      "SecKeyEncrypt", "SecKeychainAddGenericPassword", "SecKeychainFindGenericPassword", "SecKeychainItemModifyContent", "SecKeyGeneratePair", 
      "SecCertificateCreateWithData", "SecKeyEncrypt", "SecCertificateCopyCommonName", "SecTrustEvaluateWithError", "SecDigestTransformFinal",
      "SecDigestTransformUpdate", "SecDigestTransformCreate", "SecKeyRawVerify", "SecKeyRawSign", "SecKeyCopyPublicKey", "SecKeyCreateRandomKey"])
        is_found_sec = any("kSecAttrAccessibleAlways" in name for name in import_names)
        return is_found, is_found_sec

    def check_keywords_in_plist_files(self):
        """
        Проверяет наличие конфиденциальных данных в файлах .plist.

        Returns:
            bool: True, если конфиденциальные данные обнаружены, иначе False.
        """
        if not self.extract_dir:
            raise Exception("Сначала разархивируйте файл .ipa")

        has_confidential_data = False
        keywords = ['username', 'password', 'token', 'secret', 'key']

        for root, dirs, files in os.walk(self.extract_dir):
            for file in files:
                if file.endswith('.plist'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'rb') as plist_file:
                            plist_data = plistlib.load(plist_file)
                            found_keywords = [keyword for keyword in keywords if keyword in plist_data]
                            if found_keywords:
                                has_confidential_data = True
                    except (plistlib.InvalidFileException, OSError):
                        pass

        return has_confidential_data

    def check_permissions(self):
        """
        Проверяет разрешения в файле .ipa.

        Returns:
            tuple: Кортеж с двумя значениями:
                - list: Список разрешений.
                - list: Список степеней важности (1 - не критично, 2 - критично).
        """
        if not self.ipa_file_path:
            raise Exception("Сначала выберите файл .ipa")

        info_plist_files = []
        with zipfile.ZipFile(self.ipa_file_path) as ipa:
            for file_name in ipa.namelist():
                if 'Info.plist' in file_name:
                    info_plist_files.append(file_name)

        # Список разрешений Apple и соответствующие им степени важности
        apple_permissions = {
            "NSAppleMusicUsageDescription": 1,
            # Доступ к библиотеке мультимедиа Apple (Этот ключ требуется, если ваше приложение использует медиатеку пользователя.)
            "NSBluetoothAlwaysUsageDescription": 2,
            # Доступ к Bluetooth всегда (Этот ключ требуется, если ваше приложение использует интерфейс Bluetooth устройства.)
            "NSBluetoothPeripheralUsageDescription": 1,
            # Доступ к Bluetooth (Этот ключ требуется, если ваше приложение использует интерфейс Bluetooth устройства.) (Apple рекоммендует его использоватеть для iOS<13, для  iOS >=13 используется NSBluetoothAlwaysUsageDescription)
            "NSCalendarsUsageDescription": 1,
            # Доступ к календарю (Этот ключ необходим, если ваше приложение использует API-интерфейсы для доступа к данным календаря пользователя.)
            "NSCameraUsageDescription": 2,
            # Доступ к камере (Этот ключ необходим, если ваше приложение использует API для доступа к камере устройства.)
            "NSContactsUsageDescription": 2,
            # Доступ к контактам (Этот ключ необходим, если ваше приложение использует API для доступа к контактам пользователя.)
            "NSFaceIDUsageDescription": 2,
            # Доступ к распознаванию лица Face ID (Этот ключ необходим, если ваше приложение использует API для доступа к Face ID.)
            "NSHealthShareUsageDescription": 1,
            # Доступ на чтение к данным о здоровье (Этот ключ необходим, если ваше приложение использует API-интерфейсы для доступа к данным о здоровье пользователя.)
            "NSHealthUpdateUsageDescription": 1,
            # Доступ на запись к данным о здоровье (Этот ключ необходим, если ваше приложение использует API, которые обновляют данные о состоянии здоровья пользователя.)
            "NSHomeKitUsageDescription": 1,
            # Доступ к устройствам HomeKit (Этот ключ необходим, если ваше приложение использует API-интерфейсы, которые получают доступ к данным конфигурации HomeKit пользователя.)
            "NSLocationAlwaysAndWhenInUseUsageDescription": 2,
            # Доступ к местоположению всегда и при использовании (Этот ключ необходим, если ваше приложение для iOS использует API, которые постоянно получают доступ к информации о местоположении пользователя.)
            "NSLocationAlwaysUsageDescription": 2,
            # Доступ к местоположению всегда (Этот ключ требуется, если ваше приложение для iOS использует API-интерфейсы, которые постоянно обращаются к местоположению пользователя и развертываются на устройствах, предшествующих iOS 11.)
            "NSLocationWhenInUseUsageDescription": 1,
            # Доступ к местоположению во время использования приложения (Этот ключ требуется, если ваше приложение для iOS использует API-интерфейсы, которые получают доступ к информации о местоположении пользователя во время использования приложения.)
            "NSMicrophoneUsageDescription": 2,
            # Доступ к микрофону (Этот ключ требуется, если ваше приложение использует API-интерфейсы для доступа к микрофону устройства.)
            "NSMotionUsageDescription": 1,
            # Доступ к данным о движении (Этот ключ требуется, если ваше приложение использует API-интерфейсы для доступа к данным о движении устройства, включая CMSensorRecorder, CMPedometer, CMMotionActivityManager и CMMovementDisorderManager.)
            "NSPhotoLibraryAddUsageDescription": 1,
            # Доступ к добавлению фотографий в библиотеку (Этот ключ необходим, если ваше приложение использует API-интерфейсы, которые имеют доступ на запись к библиотеке фотографий пользователя.)
            "NSPhotoLibraryUsageDescription": 1,
            # Доступ к фотографиям (Этот ключ требуется, если ваше приложение использует API-интерфейсы, которые имеют доступ для чтения или записи к библиотеке фотографий пользователя.)
            "NSRemindersUsageDescription": 1,
            # Доступ к напоминаниям (Этот ключ необходим, если ваше приложение использует API-интерфейсы для доступа к напоминаниям пользователя.)
            "NSSpeechRecognitionUsageDescription": 2,
            # Доступ к распознаванию речи (Этот ключ необходим, если ваше приложение использует API-интерфейсы, которые отправляют пользовательские данные на серверы распознавания речи Apple.)
            "NSVideoSubscriberAccountUsageDescription": 1
            # Доступ к аккаунтам видеопровайдеров (Этот ключ необходим, если ваше приложение использует API-интерфейсы, которые обращаются к учетной записи поставщика услуг телевидения пользователя.)
        }

        # Проверка наличия разрешений в каждом файле Info.plist
        permissions = []
        importance_levels = []
        for info_plist_file in info_plist_files:
            with zipfile.ZipFile(self.ipa_file_path) as ipa:
                info_plist_data = ipa.read(info_plist_file)
                info_plist = plistlib.loads(info_plist_data)

            for permission, importance in apple_permissions.items():
                if permission in info_plist:
                    permissions.append(permission)
                    importance_levels.append(importance)

        return permissions, importance_levels

    def check_http_usage(self):
        """
        Проверяет использование HTTP в коде.

        Returns:
            tuple: Кортеж с двумя значениями:
                - bool: True, если обнаружено использование HTTP, иначе False.
                - list: Список файлов, в которых обнаружено использование HTTP.
        """
        if not self.code_dir_path:
            raise Exception("Сначала выберите папку с кодом")

        http_pattern = r"(http:\/\/)"
        is_found = False
        files_found = []

        if os.path.isdir(self.code_dir_path):
            for root, dirs, files in os.walk(self.code_dir_path):
                for file in files:
                    if file.endswith('.swift'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if re.search(http_pattern, content):
                                is_found = True
                                files_found.append(file_path)

        return is_found, files_found

    def find_package_swift(self):
        """
        Находит файл "Package.swift" в папке с кодом.

        Returns:
            str or None: Путь к файлу "Package.swift" или None, если файл не найден.
        """
        if not self.code_dir_path:
            raise Exception("Сначала выберите папку с кодом")

        for root, dirs, files in os.walk(self.code_dir_path):
            if "Package.swift" in files:
                package_path = os.path.join(root, "Package.swift")
                return package_path

        return None

    def run_dependency_check(self, package_path, destination_folder):
        """
        Запускает проверку зависимостей с помощью инструмента dependency-check.

        Args:
            package_path (str): Путь к файлу "Package.swift".
            destination_folder (str): Путь к папке, в которой будет сохранен результат проверки.

        Returns:
            bool: True, если проверка завершена успешно, иначе False.
        """


        #cmd = f'dependency-check.bat --project "package.swift" --enableExperimental --scan "{package_path}" --out "{destination_folder}"'
        cmd = f'dependency-check.bat --project "package.swift" --enableExperimental --prettyPrint ' \
              f'--disableNodeAuditCache --scan "{package_path}" --out "{destination_folder}" '
        try:
            subprocess.run(cmd, shell=True, check=True)
            return True
        except subprocess.CalledProcessError as error:
            print(error)
            return False

    def check_vulnerable_dependencies(self, html_file):
        # Открываем файл .html и считываем его содержимое
        with open(html_file, 'r') as file:
            html_code = file.read()

        # Создаем объект BeautifulSoup для анализа HTML-кода
        soup = BeautifulSoup(html_code, 'html.parser')

        # Ищем элемент с id "vulnerableCount" и получаем его текстовое содержимое
        vulnerable_dependencies = int(soup.find(id='vulnerableCount').get_text(strip=True))

        # Проверяем, что значение Vulnerable Dependencies больше нуля
        if vulnerable_dependencies > 0:
            return True
        else:
            return False