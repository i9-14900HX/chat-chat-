#pip install pycryptodome
from Crypto.Cipher import AES
#pip install py-diffie-hellman
from diffiehellman import DiffieHellman


class Cipher:
    def __init__(self, key, nonce):
        """
        Initialize the cipher with a key and nonce
        """

        self.key = key
        self.nonce = nonce

    def aes_encrypt(self, txt):
        """
        Encrypt the provided text using AES encryption and return the ciphertext.
        """
        cipher = AES.new(self.key, AES.MODE_EAX,  nonce=self.nonce)
        ciphertext, tag = cipher.encrypt_and_digest(txt)
        return ciphertext

    def aes_decrypt(self, cipher_text):
        """
        Decrypt the provided ciphertext using AES decryption and return the original text.        
        """
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        msg = cipher.decrypt(cipher_text)
        return msg

    @staticmethod
    def get_dh_public_key():
        """
        returns the private key (dh) and the public key (pk) for Diffie-Hellman key exchange        
        """
        dh = DiffieHellman(group=14, key_bits=540)
        pk = dh.get_public_key()
        return dh, pk

    @staticmethod
    def get_dh_shared_key(dh_1, pk_2, lngth=32):
        """
        returns a shared key of the specified length (default 32 bytes) using the provided Diffie-Hellman private key and the other party's public key.
        """
        dh_shared = dh_1.generate_shared_key(pk_2)
        return dh_shared[:lngth]


if __name__ == "__main__":

    
    text = b"hello world 1234567"
    PUBLIC_KEY = b"it is my secret password"
    NONCE = b"better to try than not try"

    c1 = Cipher(PUBLIC_KEY, NONCE)
    encrypted_text = c1.aes_encrypt(text)
    c2 = Cipher(PUBLIC_KEY, NONCE)
    message = c2.aes_decrypt(encrypted_text)

    dh1, dh1_public = Cipher.get_dh_public_key()
    dh2, dh2_public = Cipher.get_dh_public_key()

    sk1 = Cipher.get_dh_shared_key(dh1, dh2_public)
    sk2 = Cipher.get_dh_shared_key(dh2, dh1_public)
