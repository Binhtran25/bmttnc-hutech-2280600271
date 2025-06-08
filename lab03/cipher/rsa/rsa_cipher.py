import rsa
import os

# Tạo thư mục chứa khóa nếu chưa tồn tại
if not os.path.exists('cipher/rsa/keys'):
    os.makedirs('cipher/rsa/keys')


class RSACipher:
    def __init__(self):
        pass

    def generate_keys(self):
        (public_key, private_key) = rsa.newkeys(1024)
        with open('cipher/rsa/keys/publicKey.pem', 'wb') as p:
            p.write(public_key.save_pkcs1('PEM'))
        with open('cipher/rsa/keys/privateKey.pem', 'wb') as p:
            p.write(private_key.save_pkcs1('PEM'))

    def load_keys(self):
        with open('cipher/rsa/keys/publicKey.pem', 'rb') as p:
            public_key = rsa.PublicKey.load_pkcs1(p.read())
        with open('cipher/rsa/keys/privateKey.pem', 'rb') as p:
            private_key = rsa.PrivateKey.load_pkcs1(p.read())
        return private_key, public_key

    def encrypt(self, message, key):
        return rsa.encrypt(message.encode('ascii'), key)

    def decrypt(self, ciphertext, key):
        try:
            return rsa.decrypt(ciphertext, key).decode('ascii')
        except:
            return False

    def sign(self, message, key):
        return rsa.sign(message.encode('ascii'), key, 'SHA-1')

    def verify(self, message, signature, key):
        try:
            rsa.verify(message.encode('ascii'), signature, key)
            return True
        except:
            return False


# Phần kiểm tra chương trình
if __name__ == '__main__':
    rsa_cipher = RSACipher()

    print("=== Tạo và lưu khóa RSA ===")
    rsa_cipher.generate_keys()

    print("=== Tải khóa lên ===")
    private_key, public_key = rsa_cipher.load_keys()

    message = "Hello RSA"

    print("\n=== Mã hóa ===")
    ciphertext = rsa_cipher.encrypt(message, public_key)
    print("Ciphertext:", ciphertext)

    print("\n=== Giải mã ===")
    plaintext = rsa_cipher.decrypt(ciphertext, private_key)
    print("Plaintext:", plaintext)

    print("\n=== Ký ===")
    signature = rsa_cipher.sign(message, private_key)
    print("Signature:", signature)

    print("\n=== Xác minh chữ ký ===")
    verified = rsa_cipher.verify(message, signature, public_key)
    print("Verified:", verified)
