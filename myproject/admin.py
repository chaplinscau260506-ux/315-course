import sqlite3
import sys
from PyQt5.QtWidgets import QApplication, QMessageBox, QMainWindow, QLineEdit
import re
from datetime import datetime
from designer.vhod import Ui_vhod
from designer.reg import Ui_reg
from glawwin import Home
import hashlib

class Database:
    def __init__(self, db_name='cafe_base.db'):
        self.conn = sqlite3.connect(db_name)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.conn.row_factory = sqlite3.Row

    def get_user_by_username(self, user_name):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM admin_us WHERE user_name = ?", (user_name,))
        return cursor.fetchone()

    def get_admin_by_email(self, email):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE email = ?", (email,))
        return cursor.fetchone()

    def insert_admin(self, last_name, first_name, dob, number, email, user_name):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO admin (last_name, first_name, dob, number, email, user_name) VALUES (?, ?, ?, ?, ?, ?)",
            (last_name, first_name, dob, number, email, user_name)
        )
        self.conn.commit()
        return cursor.lastrowid

    def insert_admin_user(self, user_name, password_hash, admin_id):
        self.conn.execute(
            "INSERT INTO admin_us (user_name, password_hash, admin_id) VALUES (?, ?, ?)",
            (user_name, password_hash, admin_id)
        )
        self.conn.commit()

    def close(self):
        self.conn.close()

def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode('utf-8')).hexdigest()

class VhodWin(QMainWindow, Ui_vhod):
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.vhod)
        self.pushButton_2.clicked.connect(self.open_second)
        self.password.setEchoMode(QLineEdit.Password)

    def vhod(self):
        try:
            user_name = self.user_name.text()
            password = self.password.text()

            if not user_name or not password:
                QMessageBox.warning(self, "Ошибка", "Введите логин и пароль")
                return

            user_record = self.db.get_user_by_username(user_name)
            if user_record is None:
                QMessageBox.warning(self, "Ошибка", "Неверный логин или пароль")
                return

            if user_record["password_hash"] == hash_password(password):
                # Успешный вход
                user_id = user_record["id"]  # предполагается, что в базе есть поле id
                self.open_main(user_id)
            else:
                QMessageBox.warning(self, "Ошибка", "Неверный логин или пароль")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", str(e))

    def open_second(self):
        self.close()
        self.reg_window = RegWin()
        self.reg_window.show()

    def open_main(self, user_id):
        self.close()
        self.main = Home()
        self.main.set_current_user(user_id)
        self.main.show()

class RegWin(QMainWindow, Ui_reg):
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.setupUi(self)
        self.password.setEchoMode(QLineEdit.Password)
        self.password_p.setEchoMode(QLineEdit.Password)

        self.pushButton.clicked.connect(self.open)
        self.pushButton_2.clicked.connect(self.reg)

    def reg(self):
        try:
            last_name = self.last_name.text()
            first_name = self.first_name.text()
            dob = self.dob.text()
            number = self.number.text()
            email = self.email.text()
            user_name = self.user_name.text()
            password = self.password.text()
            password_p = self.password_p.text()

            if len(user_name) < 3:
                QMessageBox.warning(self, "Ошибка", "Логин должен содержать не менее 3 символов")
                return
            if len(password) < 6:
                QMessageBox.warning(self, "Ошибка", "Пароль должен содержать не менее 6 символов")
                return

            if not all([last_name, first_name, dob, number, email, user_name, password, password_p]):
                QMessageBox.warning(self, "Ошибка", "Введите все данные")
                return
            if password != password_p:
                QMessageBox.warning(self, "Ошибка", "Пароли не совпадают")
                return

            try:
                datetime.strptime(dob, "%Y-%m-%d")
            except ValueError:
                QMessageBox.warning(self, "Ошибка", "Некорректный формат даты. Используйте ГГГГ-ММ-ДД.")
                return

            email_pattern = r"[^@]+@[^@]+\.[^@]+"
            if not re.match(email_pattern, email):
                QMessageBox.warning(self, "Ошибка", "Некорректный формат email")
                return

            # Проверка существования логина
            if self.db.get_user_by_username(user_name) is not None:
                QMessageBox.warning(self, "Ошибка", "Этот логин уже занят")
                return

            # Проверка существования email
            if self.db.get_admin_by_email(email) is not None:
                QMessageBox.warning(self, "Ошибка", "Этот email уже зарегистрирован")
                return

            # Создаем администратора
            admin_id = self.db.insert_admin(last_name, first_name, dob, number, email, user_name)

            # Вставляем пользователя
            self.db.insert_admin_user(user_name, hash_password(password), admin_id)

            QMessageBox.information(self, "Успех", "Вы успешно зарегистрировались")
            self.open()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка регистрации: {e}")

    def open(self):
        self.close()
        self.reg_window = VhodWin()
        self.reg_window.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = VhodWin()
    main_window.show()
    sys.exit(app.exec_())