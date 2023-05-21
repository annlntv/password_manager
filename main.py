import sys #для выхода из python
from PyQt5.QtCore import Qt #импортируем нужные модули
from PyQt5.QtWidgets import QApplication, QHBoxLayout, QDialog, QWidget, QLabel, QLineEdit, QTextEdit, QPushButton, QVBoxLayout, QMessageBox
from cryptography.fernet import Fernet #для создания ключа шифрования

#создаём окно отображения сохраненных паролей
class PasswordDialog(QDialog):
    def __init__(self, decrypted_passwords):
        super().__init__()
        self.setWindowTitle('Сохраненные пароли')
        layout = QVBoxLayout()
        self.password_box = QTextEdit()
        self.password_box.setReadOnly(True)
        self.password_box.setText(decrypted_passwords)
        layout.addWidget(self.password_box)
        self.setLayout(layout)

#Основное окно менеджера паролей
class PasswordManager(QWidget):

    #инициализируем приложение
    def __init__(self):
        super().__init__()
        self.init_ui() #рисуем интерфейс
        self.load_key() #получаем ключ для расшифровки

    def init_ui(self):
        self.setWindowTitle('Password Manager')
        self.resize(400, 100)
        self.service_label = QLabel('Сервис:')
        self.password_label = QLabel('Пароль:')

        self.service_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.save_button = QPushButton('Сохранить')
        self.save_button.clicked.connect(self.save_password)

        self.view_button = QPushButton('Посмотреть пароли')
        self.view_button.clicked.connect(self.view_passwords)

        layout = QHBoxLayout()
        layout2 = QHBoxLayout()

        main_line = QVBoxLayout()

        layout.addWidget(self.service_label)
        layout.addWidget(self.service_input)
        layout2.addWidget(self.password_label)
        layout2.addWidget(self.password_input)
        main_line.addLayout(layout)
        main_line.addLayout(layout2)
        main_line.addWidget(self.save_button, alignment=Qt.AlignCenter)
        main_line.addWidget(self.view_button, alignment=Qt.AlignCenter)

        self.setLayout(main_line)

    #метод для прочтения уникального ключа шифрования в файле key.key, который создается автоматически
    def load_key(self):
        try:
            with open('key.key', 'rb') as file:
                self.key = file.read()
        except FileNotFoundError:
            self.generate_key()
            self.load_key()

    #генерация ключа и запись в новый файл
    def generate_key(self):
        self.key = Fernet.generate_key()
        with open('key.key', 'wb') as file:
            file.write(self.key)

    #шифрование пароля
    def encrypt_password(self, password):
        cipher_suite = Fernet(self.key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        return encrypted_password

    #расшифровка пароля
    def decrypt_password(self, encrypted_password):
        cipher_suite = Fernet(self.key)
        decrypted_password = cipher_suite.decrypt(encrypted_password)
        return decrypted_password.decode()

    #сохранение пароля в файле passwords.txt в виде "сервис: (зашифрованный пароль)"
    def save_password(self):
        service = self.service_input.text()
        password = self.password_input.text()

        if service and password:
            encrypted_password = self.encrypt_password(password)
            with open('passwords.txt', 'ab') as file:
                file.write(f'{service}:'.encode() + encrypted_password + b'\n')
            QMessageBox.information(self, 'Успешно', 'Пароль сохранен.')
            self.service_input.clear()
            self.password_input.clear()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Сервис и пароль не могут быть пустыми.')

    #просмотр сохраненных паролей, дешифрование
    def view_passwords(self):
        try:
            with open('passwords.txt', 'rb') as file:
                passwords = file.read()
        except FileNotFoundError:
            passwords = b''

        if passwords:
            decrypted_passwords = ''
            lines = passwords.split(b'\n')
            for line in lines:
                if line:
                    service, encrypted_password = line.split(b':')
                    decrypted_password = self.decrypt_password(encrypted_password.strip())
                    decrypted_passwords += f'{service.decode()}: {decrypted_password}\n'

            password_dialog = PasswordDialog(decrypted_passwords)
            password_dialog.exec_()
        else:
            QMessageBox.warning(self, 'Ошибка', 'Пароли еще не были сохранены.')

#запуск программы
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec_())
