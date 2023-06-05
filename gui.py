"""
GUI для приложения
"""

import os
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import font

# локальные файлы
from checker import FileChecker
from messages import kSecAttrAccessibleAlways_message, info_text


class Application(tk.Tk):
    """
    Класс реализации GUI для приложения
    """
    def __init__(self):
        """
        Инициализация
        """
        super().__init__()
        self.title("Проверка безопасности iOS приложения")
        # Получаем размеры экрана
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        # Определяем центральные координаты окна
        window_width = 820  # Ширина окна
        window_height = 520  # Высота окна
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2

        # Устанавливаем положение окна по центру
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # Инициализируем класс проверки файлов
        self.file_checker = FileChecker()

        # Шрифт для окон
        self.font_bold = font.Font(weight='bold', size=12)

        # Уровни важности (2 тест)
        self.importance_levels_dict = {1: 'Не критично', 2: 'Критично'}

        # Подгружаем фотографии
        self.success_image = tk.PhotoImage(file="pictures/success.png")
        self.error_image = tk.PhotoImage(file="pictures/error.png")
        self.exception_image = tk.PhotoImage(file="pictures/exception.png")

        # Создание вкладок
        self.tabControl = ttk.Notebook(self)
        self.mainTab = ttk.Frame(self.tabControl)
        self.check1Tab = ttk.Frame(self.tabControl)
        self.check2Tab = ttk.Frame(self.tabControl)
        self.check3Tab = ttk.Frame(self.tabControl)
        self.check4Tab = ttk.Frame(self.tabControl)
        self.infoTab = ttk.Frame(self.tabControl)

        # Добавляем на окно
        self.tabControl.add(self.mainTab, text="Главная")
        self.tabControl.add(self.check1Tab, text="Проверка 1")
        self.tabControl.add(self.check2Tab, text="Проверка 2")
        self.tabControl.add(self.check3Tab, text="Проверка 3")
        self.tabControl.add(self.check4Tab, text="Проверка 4")
        self.tabControl.add(self.infoTab, text="Инфо")

        # Добавление содержимого на вкладки, инициализация
        self.create_main_tab()
        self.create_check1_tab()
        self.create_check2_tab()
        self.create_check3_tab()
        self.create_check4_tab()
        self.create_info_tab()  # Добавление содержимого на вкладку "Инфо"

        self.tabControl.pack(expand=True, fill="both")

    def create_main_tab(self):
        """
        Создает содержимое вкладки "Главная".
        """
        # Содержимое главной вкладки
        self.file1_label = ttk.Label(self.mainTab, text="")
        self.file1_label.pack(padx=10, pady=10)
        self.file2_label = ttk.Label(self.mainTab, text="")
        self.file2_label.pack(padx=10, pady=10)

        add_file1_button = ttk.Button(self.mainTab, text="Выбрать .ipa файл", command=self.choose_ipa_file)
        add_file1_button.pack(padx=10, pady=10)

        add_file2_button = ttk.Button(self.mainTab, text="Выбрать папку с кодом", command=self.choose_code_dir)
        add_file2_button.pack(padx=10, pady=10)

        extract_button = ttk.Button(self.mainTab, text="Разархивировать файлы", command=self.extract_files)
        extract_button.pack(padx=10, pady=10)

        self.extract_path_label = ttk.Label(self.mainTab, text="")
        self.extract_path_label.pack(padx=10, pady=10)

        self.run_all_button = ttk.Button(self.mainTab, text="Запустить все проверки", command=self.run_all_checks)
        self.run_all_button.pack(padx=10, pady=10)
        self.run_all_button['state'] = 'disabled'

    def create_info_tab(self):
        """
        Создает содержимое вкладки "Инфо".
        """

        label = ttk.Label(self.infoTab, text="Информация о проверках", font=self.font_bold)
        label.pack(padx=10, pady=10)

        # Информационный текст

        info_label = ttk.Label(self.infoTab, text=info_text)
        info_label.pack(padx=10, pady=10)

    def choose_ipa_file(self):
        """
        Открывает диалоговое окно для выбора файла .ipa.
        """
        filetypes = [("IPA Files", "*.ipa")]
        file_path = filedialog.askopenfilename(filetypes=filetypes)
        if file_path:
            self.file1_label.configure(text="Выбранный .ipa файл: " + file_path)
            self.file_checker.choose_ipa_file(file_path)

    def choose_code_dir(self):
        """
        Открывает диалоговое окно для выбора папки с кодом.
        """
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.file2_label.configure(text="Выбрана папка с кодом: " + dir_path)
            self.file_checker.choose_code_dir(dir_path)
            self.run_all_button['state'] = True

    def extract_files(self):
        """
        Разархивирует файлы из выбранного .ipa файла.
        """
        try:
            success = self.file_checker.extract_files()
            if success:
                self.extract_path_label.configure(text=f"Файлы разархивированы"
                                                       f" в папку: {self.file_checker.extract_dir}")
                self.run_all_button['state'] = True
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def create_check1_tab(self):
        """
        Создает содержимое вкладки "Проверка 1".
        """

        label = ttk.Label(self.check1Tab,
                          text="Проверка на использование незащищенного хранения данныхй", font=self.font_bold)
        label.pack(padx=10, pady=10)

        # Создание метки для отображения изображения
        self.image_label_1 = ttk.Label(self.check1Tab, image=None)
        self.image_label_1.pack(padx=5, pady=5)

        check_button = ttk.Button(self.check1Tab, text="Проверить", command=self.run_check1)
        check_button.pack(padx=10, pady=10)

        self.check1_result_label = ttk.Label(self.check1Tab, text="")
        self.check1_result_label.pack(padx=10, pady=10)

    def run_check1(self):
        """
         Запускает проверку на использование незащищенного хранения данных.
        """
        try:
            # Крипто
            is_found, is_found_sec = self.file_checker.check_file_crypt()
            # .plist
            is_found_keywords = self.file_checker.check_keywords_in_plist_files()
            print(f'Проверка 1: {is_found}; {is_found_keywords}')

            if is_found is True and is_found_keywords is False:
                self.check1_result_label.configure(text="Проверка на использование незащищенного хранения данных "
                                                        "прошла успешно")
                self.image_label_1.configure(image=self.success_image)
            elif is_found is False and is_found_keywords is False:
                self.check1_result_label.configure(text="В .plist не найдены конфиденциальные данные\nв проекте не найдено использование функций шифрования")
                self.image_label_1.configure(image=self.error_image)
            elif is_found is True and is_found_keywords is True:
                self.check1_result_label.configure(text="В .plist найдены конфиденциальные данные")
                self.image_label_1.configure(image=self.error_image)
            else:
                self.check1_result_label.configure(text="Проверка на использование незащищенного хранения провалилась")
                self.image_label_1.configure(image=self.error_image)

            # Если аттрибут kSec найден
            if is_found_sec is True:
                text = self.check1_result_label.cget("text") + "\n\n" + kSecAttrAccessibleAlways_message
                self.check1_result_label.configure(text=text)
        except Exception as e:
            self.image_label_1.configure(image=self.exception_image)
            self.check1_result_label.configure(text=f"Ошибка: {e}")
            messagebox.showerror("Ошибка", str(e))

    def create_check2_tab(self):
        """
        Создает содержимое вкладки "Проверка 2".
        """
        label = ttk.Label(self.check2Tab, text="Проверка разрешений приложения", font=self.font_bold)
        label.pack(padx=10, pady=10)

        # Создание метки для отображения изображения
        self.image_label_2 = ttk.Label(self.check2Tab, image=None)
        self.image_label_2.pack(padx=5, pady=5)

        check_button = ttk.Button(self.check2Tab, text="Проверить", command=self.run_check2)
        check_button.pack(padx=10, pady=10)

        self.check2_result_label = ttk.Label(self.check2Tab, text="")
        self.check2_result_label.pack(padx=10, pady=10)

        # Создание виджета Treeview для вывода таблицы
        self.treeview = ttk.Treeview(self.check2Tab)
        self.treeview.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Определение колонок таблицы
        self.treeview["columns"] = ("Permission", "Importance")
        self.treeview.column("#0", width=0, stretch=tk.NO)  # Скрытие первой колонки
        self.treeview.column("Permission", anchor=tk.W, width=300)
        self.treeview.column("Importance", anchor=tk.W, width=150)

        # Определение заголовков колонок
        self.treeview.heading("Permission", text="Разрешение")
        self.treeview.heading("Importance", text="Степень важности")

        # Создание кнопок для оценки проверки
        self.success_button = ttk.Button(self.check2Tab, text="Успешно", command=lambda: self.set_check2_status(True))
        self.success_button.pack(padx=10, pady=10)

        self.failure_button = ttk.Button(self.check2Tab, text="Неуспешно", command=lambda: self.set_check2_status(False))
        self.failure_button.pack(padx=10, pady=10)

    def run_check2(self):
        """
        Запускает проверку разрешений приложения.
        """
        try:
            # Получение разрешений
            permissions, importance_levels = self.file_checker.check_permissions()

            # Очистить предыдущие результаты
            self.treeview.delete(*self.treeview.get_children())

            # Вывести новые результаты
            for permission, importance in zip(permissions, importance_levels):
                self.treeview.insert("", tk.END, values=(permission, self.importance_levels_dict.get(importance, None)))
            messagebox.showwarning("Предупреждение", "Проверьте в окне 'Проверка 2', является ли список запрашиваемых разрешений "
                                                     "минимально\nвозможным,самостоятельно заполните статус "
                                                     "проверки.")
            print(f'Проверка 2: {permissions};')
        except Exception as e:
            self.image_label_2.configure(image=self.exception_image)
            self.check2_result_label.pack()  # Показать изображение при ошибке
            self.check2_result_label.configure(text=f"Ошибка: {e}")
            messagebox.showerror("Ошибка", str(e))

    def set_check2_status(self, success):
        """
        Установка изображения
        :param success: True - все хорошо, иначе False
        """
        if success is True:
            self.image_label_2.configure(image=self.success_image)
        else:
            self.image_label_2.configure(image=self.error_image)

    def create_check3_tab(self):
        """
        Создает содержимое вкладки "Проверка 3".
        """
        label = ttk.Label(self.check3Tab, text="Проверка использования HTTP", font=self.font_bold)
        label.pack(padx=10, pady=10)

        # Создание метки для отображения изображения
        self.image_label_3 = ttk.Label(self.check3Tab, image=None)
        self.image_label_3.pack(padx=5, pady=5)

        check_button = ttk.Button(self.check3Tab, text="Проверить", command=self.run_check3)
        check_button.pack(padx=10, pady=10)

        self.check3_result_label = ttk.Label(self.check3Tab, text="")
        self.check3_result_label.pack(padx=10, pady=10)

    def run_check3(self):
        """
        Запускает проверку использования небезопасного протокола HTTP.
        """
        try:
            # Поиск по файлам
            is_found, pathes = self.file_checker.check_http_usage()
            if is_found:
                # Получаем список файлов в строковом формате, разделенные переносом строки
                files = '\n'.join([f'{_}. {path}' for _, path in enumerate(pathes, start=1)])

                self.check3_result_label.configure(text=f"Обнаружено использование небезопасного протокола HTTP в "
                                                        f"файлах:\n{files}")
                self.image_label_3.configure(image=self.error_image)
            else:
                self.check3_result_label.configure(text="Не обнаружено использование небезопасного протокола HTTP")
                self.image_label_3.configure(image=self.success_image)
            print(f'Проверка 3: {is_found}; {pathes[0]}')
        except Exception as e:
            self.image_label_3.configure(image=self.exception_image)
            self.check3_result_label.configure(text=f"Ошибка: {e}")
            messagebox.showerror("Ошибка", str(e))

    def create_check4_tab(self):
        """
        Создает содержимое вкладки "Проверка 4".
        """
        label = ttk.Label(self.check4Tab, text="Анализ зависимостей Package.swift", font=self.font_bold)
        label.pack(padx=10, pady=10)

        # Создание метки для отображения изображения
        self.image_label_4 = ttk.Label(self.check4Tab, image=None)
        self.image_label_4.pack(padx=5, pady=5)

        check_button = ttk.Button(self.check4Tab, text="Проверить", command=self.run_check4)
        check_button.pack(padx=10, pady=10)

        self.check4_result_label = ttk.Label(self.check4Tab, text="")
        self.check4_result_label.pack(padx=10, pady=10)

    def run_check4(self):
        """
        Запускает анализ зависимостей из файла Package.swift.
        """
        try:
            package_path = self.file_checker.find_package_swift()
            if package_path:
                report_path = os.getcwd()
                success = self.file_checker.run_dependency_check(package_path.replace('/', '\\'),
                                                                 report_path)
                if success:
                    result = self.file_checker.check_vulnerable_dependencies(report_path +
                                                                             '\\' + 'dependency-check-report.html')
                    if result is True:
                        self.image_label_4.configure(image=self.error_image)
                        self.check4_result_label.configure(text=f"Приложение использует зависимости с найденными уязвимостями.\nДля получения более подробной информации просмотрите\nотчет dependency-check.html")
                    else:
                        self.image_label_4.configure(image=self.success_image)
                        self.check4_result_label.configure(text="Файл не содержит уязвимости")
                    return
                else:
                    self.image_label_4.configure(image=self.error_image)
                    self.check4_result_label.configure(text="Ошибка при выполнении команды dependency-check.bat")
                print(f'Проверка 4: {package_path}; {success}')
            else:
                self.image_label_4.configure(image=self.exception_image)
                self.check4_result_label.configure(text="Файл Package.swift не найден")
                print(f'Проверка 4: {package_path};')

        except Exception as e:
            self.image_label_4.configure(image=self.exception_image)
            self.check4_result_label.configure(text=f"Ошибка: {e}")
            messagebox.showerror("Ошибка", str(e))

    def run_all_checks(self):
        """
        Запускает все проверки.
        """
        try:
            self.run_check1()
            self.run_check2()
            self.run_check3()
            self.run_check4()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))


if __name__ == "__main__":
    app = Application()
    app.mainloop()

