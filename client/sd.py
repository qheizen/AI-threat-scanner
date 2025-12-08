# app.py
import sys
import os
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication, QDialog, QLineEdit, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
    QWidget, QMainWindow, QFileDialog, QSplitter, QTableWidget, QTableWidgetItem,
    QMessageBox, QProgressDialog, QSizePolicy, QSpacerItem
)


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Вход")
        self.setModal(True)
        self.resize(320, 150)

        self.login_edit = QLineEdit()
        self.login_edit.setPlaceholderText("Логин")

        self.pass_edit = QLineEdit()
        self.pass_edit.setPlaceholderText("Пароль")
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)

        self.ok_btn = QPushButton("Войти")
        self.cancel_btn = QPushButton("Отмена")

        self.ok_btn.clicked.connect(self.try_login)
        self.cancel_btn.clicked.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Введите пользователя"))
        layout.addWidget(self.login_edit)
        layout.addWidget(self.pass_edit)

        btns = QHBoxLayout()
        btns.addWidget(self.ok_btn)
        btns.addWidget(self.cancel_btn)
        layout.addLayout(btns)

        self.setLayout(layout)

    def try_login(self):
        login = self.login_edit.text().strip()
        pwd = self.pass_edit.text().strip()
        # Простая политика: принимаем, если оба поля не пустые.
        if not login or not pwd:
            QMessageBox.warning(self, "Ошибка", "Заполните логин и пароль.")
            return
        # Если нужна реальная проверка — замените этот блок на проверку БД/файла/LDAP и т.п.
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Главное окно — Аналог .NET интерфейса")
        self.resize(900, 550)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # Разделитель: левая панель — управление, правая — таблица
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Левая панель
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(8, 8, 8, 8)
        left_layout.setSpacing(10)

        # Поле для указания папки и кнопка обзора
        folder_label = QLabel("Папка для сканирования:")
        self.folder_edit = QLineEdit()
        self.folder_edit.setPlaceholderText("Выберите папку...")
        browse_btn = QPushButton("Обзор")
        browse_btn.clicked.connect(self.browse_folder)

        folder_h = QHBoxLayout()
        folder_h.addWidget(self.folder_edit)
        folder_h.addWidget(browse_btn)

        left_layout.addWidget(folder_label)
        left_layout.addLayout(folder_h)

        # Кнопка начать сканирование
        self.scan_btn = QPushButton("Начать сканирование")
        self.scan_btn.clicked.connect(self.start_scan)
        left_layout.addWidget(self.scan_btn)

        # Разделитель/отступ
        left_layout.addItem(QSpacerItem(20, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed))

        # Получить данные для тренировки и Перетренировать модель
        self.get_data_btn = QPushButton("Получить данные для тренировки")
        self.get_data_btn.clicked.connect(self.get_training_data)

        self.retrain_btn = QPushButton("Перетренировать модель")
        self.retrain_btn.clicked.connect(self.retrain_model)

        left_layout.addWidget(self.get_data_btn)
        left_layout.addWidget(self.retrain_btn)

        # Ниже — можно добавить дополнительные элементы
        left_layout.addStretch(1)

        # Правая панель — таблица, занимает половину пространства
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(8, 8, 8, 8)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Файл", "Тип", "Тип угрозы", "Вердикт"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(self.table.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(self.table.EditTrigger.NoEditTriggers)

        right_layout.addWidget(self.table)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)

        # Сделаем размеры примерно 1:1 (половина окна — таблица)
        splitter.setSizes([300, 600])

        main_layout.addWidget(splitter)

        # Статусбар
        self.status = self.statusBar()
        self.status.showMessage("Готово")

    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку для сканирования", str(Path.home()))
        if folder:
            self.folder_edit.setText(folder)

    def start_scan(self):
        folder = self.folder_edit.text().strip()
        if not folder:
            QMessageBox.warning(self, "Ошибка", "Укажите папку для сканирования.")
            return
        if not os.path.isdir(folder):
            QMessageBox.warning(self, "Ошибка", "Папка не найдена.")
            return

        # Очистим таблицу
        self.table.setRowCount(0)
        self.status.showMessage("Сканирование...")

        # Простая синхронная имитация сканирования: перечислим файлы в указанной папке (только верхний уровень)
        try:
            files = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать папку:\n{e}")
            self.status.showMessage("Ошибка при сканировании")
            return

        # Заполняем таблицу: файл, тип (расширение), тип угрозы (placeholder), вердикт (placeholder)
        for filename in files:
            row = self.table.rowCount()
            self.table.insertRow(row)

            filepath = os.path.join(folder, filename)
            ext = Path(filename).suffix.lower().lstrip(".") or "—"

            item_file = QTableWidgetItem(filename)
            item_type = QTableWidgetItem(ext)
            item_threat = QTableWidgetItem("неизвестно")   # сюда вписывается результат детектора угроз
            item_verdict = QTableWidgetItem("необработан")

            self.table.setItem(row, 0, item_file)
            self.table.setItem(row, 1, item_type)
            self.table.setItem(row, 2, item_threat)
            self.table.setItem(row, 3, item_verdict)

        self.status.showMessage(f"Сканирование завершено: {len(files)} файлов")
        QMessageBox.information(self, "Сканирование", f"Найдено {len(files)} файлов в папке.")

    def get_training_data(self):
        # Демонстрационная логика: диалог-уведомление.
        # Здесь можно сделать скачивание/сбор данных, подготовку выборки и т.д.
        QMessageBox.information(self, "Данные", "Данные для тренировки получены (демо).")
        self.status.showMessage("Данные для тренировки получены")

    def retrain_model(self):
        # Демонстрация процесса обучения с прогресс-диалогом.
        dlg = QProgressDialog("Перетренировка модели...", "Отмена", 0, 100, self)
        dlg.setWindowTitle("Перетренировка")
        dlg.setWindowModality(Qt.WindowModality.WindowModal)
        dlg.setMinimumDuration(200)
        dlg.show()

        # Симулируем прогресс с помощью таймера
        self._progress = 0

        def update_progress():
            if dlg.wasCanceled():
                timer.stop()
                self.status.showMessage("Перетренировка отменена")
                return
            self._progress += 5
            dlg.setValue(self._progress)
            if self._progress >= 100:
                timer.stop()
                dlg.close()
                QMessageBox.information(self, "Готово", "Перетренировка завершена (демо).")
                self.status.showMessage("Перетренировка завершена")

        timer = QTimer(self)
        timer.timeout.connect(update_progress)
        timer.start(150)  # каждые 150 ms — обновление

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Demo .NET-like UI in Python")

    login = LoginDialog()
    if login.exec() == QDialog.DialogCode.Accepted:
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    else:
        # пользователь отменил логин
        sys.exit(0)


if __name__ == "__main__":
    main()
