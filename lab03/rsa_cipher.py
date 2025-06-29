import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.rsa import Ui_MainWindow
import requests

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
<<<<<<< HEAD
        self.ui.btn_gen_keys.clicked.connect(self.call_api_gen_keys)
=======
        self.ui.btn_generatekey.clicked.connect(self.call_api_gen_keys)
>>>>>>> 52e3cee (add lab03 all)
        self.ui.btn_encrypt.clicked.connect(self.call_api_encrypt)
        self.ui.btn_decrypt.clicked.connect(self.call_api_decrypt)
        self.ui.btn_sign.clicked.connect(self.call_api_sign)
        self.ui.btn_verify.clicked.connect(self.call_api_verify)
    
    def call_api_gen_keys(self):
        url = "http://127.0.0.1:5000/api/rsa/generate_keys"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText(data["message"])
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e.message)
    
    def call_api_encrypt(self):
        url = "http://127.0.0.1:5000/api/rsa/encrypt"
        payload = {
<<<<<<< HEAD
            "message": self.ui.txt_plain_text.toPlainText(),
=======
            "message": self.ui.txt_plaintext.toPlainText(),
>>>>>>> 52e3cee (add lab03 all)
            "key_type": "public"
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
<<<<<<< HEAD
                self.ui.txt_cipher_text.setText(data["encrypted_message"])
=======
                self.ui.txt_ciphertext.setText(data["encrypted_message"])
>>>>>>> 52e3cee (add lab03 all)

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Encrypted Successfully")
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e.message)
    
    def call_api_decrypt(self):
        url = "http://127.0.0.1:5000/api/rsa/decrypt"
        payload = {
<<<<<<< HEAD
            "ciphertext": self.ui.txt_cipher_text.toPlainText(),
=======
            "ciphertext": self.ui.txt_ciphertext.toPlainText(),
>>>>>>> 52e3cee (add lab03 all)
            "key_type": "private"
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
<<<<<<< HEAD
                self.ui.txt_plain_text.setText(data["decrypted_message"])
=======
                self.ui.txt_plaintext.setText(data["decrypted_message"])
>>>>>>> 52e3cee (add lab03 all)

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Decrypted Successfully")
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e.message)

    def call_api_sign(self):
        url = "http://127.0.0.1:5000/api/rsa/sign"
        payload = {
<<<<<<< HEAD
            "message": self.ui.txt_info.toPlainText(),
=======
            "message": self.ui.txt_information.toPlainText(),
>>>>>>> 52e3cee (add lab03 all)
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
<<<<<<< HEAD
                self.ui.txt_sign.setText(data["signature"])
=======
                self.ui.txt_signature.setText(data["signature"])
>>>>>>> 52e3cee (add lab03 all)

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Signed Successfully")
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e.message)
    
    def call_api_verify(self):
        url = "http://127.0.0.1:5000/api/rsa/verify"
        payload = {
<<<<<<< HEAD
            "message": self.ui.txt_info.toPlainText(),
            "signature": self.ui.txt_sign.toPlainText()
=======
            "message": self.ui.txt_information.toPlainText(),
            "signature": self.ui.txt_signature.toPlainText()
>>>>>>> 52e3cee (add lab03 all)
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if (data["is_verified"]):
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Information)
                    msg.setText("Verified Successfully")
                    msg.exec_()
                else:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Information)
                    msg.setText("Verified Fail")
                    msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print("Error: %s" % e.message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())