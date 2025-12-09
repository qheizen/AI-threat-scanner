import sys
import ast
import traceback
from functools import partial
from typing import List, Dict, Any
from PySide6 import QtCore, QtGui, QtWidgets

from .model_controller import ModelController
from .user_controller import UserController


class Worker(QtCore.QThread):
    finished = QtCore.Signal(object)
    error = QtCore.Signal(str)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            print("Worker started!")
            result = self.func(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            tb = traceback.format_exc()
            self.error.emit(f"{e}\n{tb}")
            

class CreateFiletypeDialog(QtWidgets.QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Создание: Тип файла")
        self.setModal(True)
        self.setFixedSize(360, 140)

        vbox = QtWidgets.QVBoxLayout(self)
        self.name_edit = QtWidgets.QLineEdit()
        self.name_edit.setPlaceholderText(
            "Наименование (например: executable)")
        self.ext_edit = QtWidgets.QLineEdit()
        self.ext_edit.setPlaceholderText("Расширение (например: .exe)")

        vbox.addWidget(self.name_edit)
        vbox.addWidget(self.ext_edit)
        vbox.addStretch()
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel,
            QtCore.Qt.Horizontal, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        vbox.addWidget(buttons)

        self.name_edit.returnPressed.connect(self.ext_edit.setFocus)
        self.ext_edit.returnPressed.connect(
            buttons.button(QtWidgets.QDialogButtonBox.Ok).click)

        self.name_edit.setFocus()

    def get_data(self):
        name = self.name_edit.text().strip()
        ext = self.ext_edit.text().strip()
        return name, ext
    

class RegisterDialog(QtWidgets.QDialog):
    def __init__(self, user_controller, parent=None):
        super().__init__(parent)
        self.user_controller = user_controller
        self.setWindowTitle("Регистрация")
        self.setModal(True)
        self.setFixedSize(360, 170)

        self.name = QtWidgets.QLineEdit()
        self.login = QtWidgets.QLineEdit()
        self.pwd = QtWidgets.QLineEdit()
        self.pwd.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.email = QtWidgets.QLineEdit()

        form = QtWidgets.QFormLayout()
        form.addRow("Имя", self.name)
        form.addRow("Логин", self.login)
        form.addRow("Пароль", self.pwd)
        form.addRow("Email", self.email)

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok |
            QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )

        btns.accepted.connect(self.on_ok)
        btns.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(btns)

    def validate(self):
        if not self.name.text().strip():
            return "Введите имя"
        if not self.login.text().strip():
            return "Введите логин"
        if len(self.pwd.text()) < 4:
            return "Пароль должен быть минимум 4 символа"
        if "@" not in self.email.text():
            return "Некорректный email"
        return None

    def on_ok(self):
        err = self.validate()
        if err:
            QtWidgets.QMessageBox.warning(self, "Ошибка", err)
            return

        try:
            self.user_controller.registration(
                self.name.text(),
                self.login.text(),
                self.pwd.text(),
                self.email.text()
            )
            QtWidgets.QMessageBox.information(self, "OK", "Успешная регистрация")
            self.accept()

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка", str(e))


class CreateThreattypeDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Создание: Тип угрозы")
        self.setModal(True)
        self.setFixedSize(480, 300)

        vbox = QtWidgets.QVBoxLayout(self)

        self.name_edit = QtWidgets.QLineEdit()
        self.name_edit.setPlaceholderText("Наименование (например: CVE2025)")
        self.desc_edit = QtWidgets.QPlainTextEdit()
        self.desc_edit.setPlaceholderText("Описание")

        vbox.addWidget(self.name_edit)
        vbox.addWidget(self.desc_edit)
        vbox.addStretch()
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel,
            QtCore.Qt.Horizontal, self
        )

        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        vbox.addWidget(buttons)

        self.name_edit.returnPressed.connect(self.desc_edit.setFocus)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Return"), self).activated.connect(
            buttons.button(QtWidgets.QDialogButtonBox.Ok).click
        )
        self.name_edit.setFocus()

    def get_data(self):
        name = self.name_edit.text().strip()
        desc = self.desc_edit.toPlainText().strip()
        return name, desc
    

class LoginDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Вход в систему")
        self.setModal(True)
        self.setFixedSize(360, 150)

        layout = QtWidgets.QVBoxLayout(self)

        self.login_edit = QtWidgets.QLineEdit()
        self.login_edit.setPlaceholderText("Логин")

        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setPlaceholderText("Пароль")
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.Password)

        layout.addWidget(self.login_edit)
        layout.addWidget(self.password_edit)
        layout.addStretch()

        btns = QtWidgets.QHBoxLayout()
        self.login_btn = QtWidgets.QPushButton("Войти")
        self.register_btn = QtWidgets.QPushButton("Регистрация")
        self.exit_btn = QtWidgets.QPushButton("Выйти")

        btns.addWidget(self.login_btn)
        btns.addWidget(self.register_btn)
        btns.addWidget(self.exit_btn)
        layout.addLayout(btns)

        self.status = QtWidgets.QLabel("Добро пожаловать!")
        layout.addWidget(self.status)

        self.login_edit.returnPressed.connect(self.password_edit.setFocus)
        self.password_edit.returnPressed.connect(self.login_btn.click)
        self.exit_btn.clicked.connect(self.reject)
        self.login_edit.setFocus()

    def show_error(self, text: str):
        self.status.setText(f"<span style='color:red'>{text}</span>")
        

class ExtendedDialog(QtWidgets.QDialog):
    def __init__(self, user_controller: UserController, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Управление базой данных")
        self.resize(900, 300)
        self.user_controller = user_controller

        main = QtWidgets.QVBoxLayout(self)

        self.table = QtWidgets.QTableWidget()
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        main.addWidget(self.table, 3)

        lower = QtWidgets.QHBoxLayout()
        self.text_edit = QtWidgets.QPlainTextEdit()
        self.text_edit.setPlaceholderText(
            "Введите запрос в следующем виде: {'id': 'name'}; tablename")
        lower.addWidget(self.text_edit, 4)

        btn_col = QtWidgets.QVBoxLayout()
        self.create_btn = QtWidgets.QPushButton("Создать")
        self.update_btn = QtWidgets.QPushButton("Редактировать")
        self.delete_btn = QtWidgets.QPushButton("Удалить")
        self.search_btn = QtWidgets.QPushButton("Поиск по фильтру")

        btn_col.addWidget(self.create_btn)
        btn_col.addWidget(self.update_btn)
        btn_col.addWidget(self.delete_btn)
        btn_col.addWidget(self.search_btn)

        btn_col.addStretch()
        lower.addLayout(btn_col, 1)

        main.addLayout(lower, 2)

        self.create_btn.clicked.connect(partial(self.perform_action, 'create'))
        self.update_btn.clicked.connect(partial(self.perform_action, 'update'))
        self.delete_btn.clicked.connect(partial(self.perform_action, 'delete'))
        self.search_btn.clicked.connect(partial(self.perform_action, 'search'))

    def perform_action(self, action: str):
        text = self.text_edit.toPlainText().strip()
        if not text:
            QtWidgets.QMessageBox.warning(
                self, "Ошибка ввода", "Введите запрос в следующем виде: {'id': 'name'}; tablename")
            return
        try:
            if ';' in text:
                dict_part, table_part = text.rsplit(';', 1)
            else:
                QtWidgets.QMessageBox.warning(
                    self, "Ошибка ввода", "В запросе отсутствует ';tablename'. Добавьте таблицу для обращения")
                return
            data = ast.literal_eval(dict_part.strip())
            table = table_part.strip()
            if not isinstance(data, (dict, list)):
                raise ValueError(
                    "Ошибка ввода: структура не соответствует формату словаря")
        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self, "Ошибка обработки", f"Невозможно обработать словарь: {e}")
            return

        try:
            if action == 'create':
                resp = self.user_controller.create(data, table)
            elif action == 'update':
                resp = self.user_controller.update(data, table)
            elif action == 'search':
                resp = self.user_controller.search(data, table)
            else:
                resp = self.user_controller.delete(data, table)
        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self, "Ошибка", f"Запрос к базе данных сброшен: {e}")
            return

        to_display = []
        if resp is False or resp is None:
            QtWidgets.QMessageBox.information(
                self, "Результат", "Операция возвратила None / False")
            return
        elif isinstance(resp, dict):
            to_display = [resp]
        elif isinstance(resp, list):
            to_display = resp
        else:
            QtWidgets.QMessageBox.information(self, "Результат", str(resp))
            return

        self.populate_table_with_dicts(to_display)

    def populate_table_with_dicts(self, rows: List[Dict[str, Any]]):
        keys = []
        for r in rows:
            for k in r.keys():
                if k not in keys:
                    keys.append(k)
        self.table.setColumnCount(len(keys))
        self.table.setRowCount(len(rows))
        self.table.setHorizontalHeaderLabels(keys)

        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        for i, r in enumerate(rows):
            for j, k in enumerate(keys):
                val = r.get(k, '')
                item = QtWidgets.QTableWidgetItem(str(val))
                self.table.setItem(i, j, item)
                
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, user_controller: UserController, model_controller_cls=ModelController):
        super().__init__()
        self.setWindowTitle("Шерлок")
        self.resize(1200, 700)
        self.user_controller = user_controller
        self.model_controller_cls = model_controller_cls
        self.model_controller = None
        
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QHBoxLayout(central)
        
        left = QtWidgets.QVBoxLayout()
        layout.addLayout(left, 1)
        
        self._scan_worker = None
        self._get_train_worker = None
        self._choose_train_worker = None
        
        self.scan_btn = QtWidgets.QPushButton("Начать сканирование (выбрать директорию)")
        self.scan_progress = QtWidgets.QProgressBar()
        self.scan_progress.setVisible(False)
        left.addWidget(self.scan_btn)
        left.addWidget(self.scan_progress)
        
        self.get_train_btn = QtWidgets.QPushButton("Получить данные для тренировки")
        self.get_train_progress = QtWidgets.QProgressBar()
        self.get_train_progress.setVisible(False)
        left.addWidget(self.get_train_btn)
        left.addWidget(self.get_train_progress)
        
        self.choose_train_btn = QtWidgets.QPushButton("Указать файл тренировки (файл)")
        self.choose_train_progress = QtWidgets.QProgressBar()
        self.choose_train_progress.setVisible(False)
        left.addWidget(self.choose_train_btn)
        left.addWidget(self.choose_train_progress)
        left.addStretch()
        
        self.extended_btn = QtWidgets.QPushButton("Управление")
        left.addWidget(self.extended_btn)
        
        self.create_filetype_btn = QtWidgets.QPushButton("Создание типа файла")
        self.create_threattype_btn = QtWidgets.QPushButton("Создание типа угрозы")
        left.addWidget(self.create_filetype_btn)
        left.addWidget(self.create_threattype_btn)

        right = QtWidgets.QVBoxLayout()
        layout.addLayout(right, 4)
        
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Название", "Хэш SHA256", "Вердикт", "Тип угрозы", "Тип файла"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        right.addWidget(self.table)
        
        self.scan_btn.clicked.connect(self.on_scan)
        self.get_train_btn.clicked.connect(self.on_get_train)
        self.choose_train_btn.clicked.connect(self.on_choose_train)
        self.extended_btn.clicked.connect(self.on_extended)
        self.create_filetype_btn.clicked.connect(self.on_create_filetype)
        self.create_threattype_btn.clicked.connect(self.on_create_threattype)
        
        self.extended_window = None
        
    def ensure_model_controller(self):
        if self.model_controller is None:
            try:
                client = self.user_controller.client
            except Exception:
                client = None
            model_dir = './model_dir'
            self.model_controller = self.model_controller_cls(model_dir, client)
            
    def on_scan(self):
        self.ensure_model_controller()
        dir_path = QtWidgets.QFileDialog.getExistingDirectory(self, "Выберите целевую директорию")
        if not dir_path:
            return

        self.scan_progress.setVisible(True)
        self.scan_progress.setRange(0, 0)
        self.scan_btn.setEnabled(False)

        self._scan_worker = Worker(self.model_controller.predict_with_list, dir_path)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.finished.connect(self._cleanup_scan_worker)
        self._scan_worker.error.connect(lambda e: (self._on_worker_error(e, 'Сканирование'), self._cleanup_scan_worker()))
        self._scan_worker.start()
    
    def _cleanup_scan_worker(self, *args):
        if self._scan_worker is None:
            return
        try:
            self._scan_worker.deleteLater()
        except Exception:
            pass
        self._scan_worker = None
        
    def _on_scan_finished(self, result):
        self.scan_btn.setEnabled(True)
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setValue(100)
        
        if result is False or result is None:
            QtWidgets.QMessageBox.warning(self, "Сканирование", "Сканирование не удалось")
            return
        rows = []
        for r in result:
            try:
                row = {
                    'Название': getattr(r, 'file_name', getattr(r, 'fileName', '')),
                    'Хэш SHA256': getattr(r, 'sha256', getattr(r, 'sha', '')),
                    'Вердикт': getattr(r, 'file_verdict', getattr(r, 'fileVerdict', '')),
                    'Тип угрозы': getattr(r, 'threat_type', getattr(r, 'threatType', '')),
                    'Тип файла': getattr(r, 'file_type', getattr(r, 'fileType', '')),
                }
            except Exception:
                row = {'file_name': str(r)}
            rows.append(row)
        self.populate_table(rows)
        
    def populate_table(self, rows: List[Dict[str, Any]]):
        self.table.clearContents()
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.table.setItem(i, 0, QtWidgets.QTableWidgetItem(str(r.get('Название', ''))))
            self.table.setItem(i, 1, QtWidgets.QTableWidgetItem(str(r.get('Хэш SHA256', ''))))
            self.table.setItem(i, 2, QtWidgets.QTableWidgetItem(str(r.get('Вердикт', ''))))
            self.table.setItem(i, 3, QtWidgets.QTableWidgetItem(str(r.get('Тип угрозы', ''))))
            self.table.setItem(i, 4, QtWidgets.QTableWidgetItem(str(r.get('Тип файла', ''))))
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        
    def on_get_train(self):
        self.ensure_model_controller()
        self.get_train_progress.setVisible(True)
        self.get_train_progress.setRange(0, 0)
        self.get_train_btn.setEnabled(False)

        self._get_train_worker = Worker(self.model_controller.train_model_with_server)
        self._get_train_worker.finished.connect(self._on_get_train_finished)
        self._get_train_worker.finished.connect(self._cleanup_get_train_worker)
        self._get_train_worker.error.connect(lambda e: (self._on_worker_error(e, 'GetTrain'), self._cleanup_get_train_worker()))
        self._get_train_worker.start()
        
    def _cleanup_get_train_worker(self, *args):
        if self._get_train_worker is None:
            return
        try:
            self._get_train_worker.deleteLater()
        except Exception:
            pass
        self._get_train_worker = None
        
    def _on_get_train_finished(self, result):
        self.get_train_btn.setEnabled(True)
        self.get_train_progress.setRange(0, 100)
        self.get_train_progress.setValue(100)
        if result is True:
            QtWidgets.QMessageBox.information(
                self, "Тренировка", "Тренировка корректно завершена")
        else:
            QtWidgets.QMessageBox.warning(
                self, "Тренировка", f"Тренировка не удалась: {result}")

    def on_choose_train(self):
        self.ensure_model_controller()
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select training file")
        if not file_path:
            return
        self.choose_train_btn.setEnabled(False)
        self.choose_train_progress.setVisible(True)
        self.choose_train_progress.setRange(0, 0)

        self._choose_train_worker = Worker(self.model_controller.train_model_with_file, file_path)
        self._choose_train_worker.finished.connect(self._on_choose_train_finished)
        self._choose_train_worker.finished.connect(self._cleanup_choose_train_worker)
        self._choose_train_worker.error.connect(lambda e: (self._on_worker_error(e, 'ChooseTrain'), self._cleanup_choose_train_worker()))
        self._choose_train_worker.start()

    def _cleanup_choose_train_worker(self, *args):
        if self._choose_train_worker is None:
            return
        try:
            self._choose_train_worker.deleteLater()
        except Exception:
            pass
        self._choose_train_worker = None
    
    def _on_choose_train_finished(self, result):
        self.choose_train_btn.setEnabled(True)
        self.choose_train_progress.setRange(0, 100)
        self.choose_train_progress.setValue(100)
        if result is True:
            QtWidgets.QMessageBox.information(
                self, "Тренировка", "Тренировка корректно завершена")
        else:
            QtWidgets.QMessageBox.warning(
                self, "Тренировка", f"Тренировка не удалась: {result}")

    def _on_worker_error(self, error_str: str, context: str):
        QtWidgets.QMessageBox.critical(self, f"{context} error", error_str)
        self.scan_btn.setEnabled(True)
        self.get_train_btn.setEnabled(True)
        self.choose_train_btn.setEnabled(True)
        self.scan_progress.setVisible(False)
        self.get_train_progress.setVisible(False)
        self.choose_train_progress.setVisible(False)

    def on_extended(self):
        if self.extended_window is None:
            self.extended_window = ExtendedDialog(self.user_controller, self)
        self.extended_window.show()
        self.extended_window.raise_()

    def on_create_filetype(self):
        dlg = CreateFiletypeDialog(self)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            name, ext = dlg.get_data()

            if not name:
                name = "None"
                QtWidgets.QMessageBox.warning(
                    self, "Validation", "Именование файла не может быть пустым.")
                return

            if not ext:
                ext = "None"
                QtWidgets.QMessageBox.warning(
                    self, "Validation", "Расширение файла не может быть пустым.")
                return

            if not ext.startswith('.'):
                ext = '.' + ext

            try:
                self.user_controller.create_new_filetype(name, ext)
                QtWidgets.QMessageBox.information(
                    self, "Успешно", "Создание типа файла успешно завершено")
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Ошибка", str(e))

    def on_create_threattype(self):
        dlg = CreateThreattypeDialog(self)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            name, desc = dlg.get_data()

            if not name:
                QtWidgets.QMessageBox.warning(
                    self, "Validation", "Name cannot be empty.")
                return

            try:
                self.user_controller.create_new_threattype(name, desc)
                QtWidgets.QMessageBox.information(
                    self, "Успешно", "Создание типа угрозы успешно завершено")
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Ошибка", str(e))
                

def main():
    app = QtWidgets.QApplication(sys.argv)
    try:
        QtWidgets.QApplication.setStyle('Fusion')
    except Exception:
        pass
    
    user_controller = UserController()
    login = LoginDialog()
    
    def do_login():
        login_text = login.login_edit.text().strip()
        pwd_text = login.password_edit.text().strip()
        if not login_text or not pwd_text:
            login.show_error('Введите логин и пароль')
            return
        try:
            ok = user_controller.authorization(login_text, pwd_text)
        except Exception as e:
            login.show_error(str(e))
            return
        if ok:
            login.accept()
        else:
            login.show_error('Авторизация не удалась')
            
    def do_register():
        dlg = RegisterDialog(user_controller)
        if dlg.exec():
            login.accept()

    login.login_btn.clicked.connect(do_login)
    login.register_btn.clicked.connect(do_register)
    
    if login.exec() != QtWidgets.QDialog.Accepted:
        sys.exit(0)
        
    w = MainWindow(user_controller)
    w.show()
    sys.exit(app.exec())
    

if __name__ == '__main__':
    main()