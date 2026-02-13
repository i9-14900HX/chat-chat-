import os
import hashlib
import hmac

class HashPasswords:
    def hash_new_password(self, password):
        """
        Hash the provided password with a randomly-generated salt and return the
        salt and hash to store in the database.
        """
        salt = os.urandom(16)
        pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt, pw_hash

    def is_correct_password(self, salt , pw_hash, password):
        """
        Given a previously-stored salt and hash, and a password provided by a user
        trying to log in, check whether the password is correct.
        """
        return hmac.compare_digest(
            pw_hash,
            hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        )

if __name__=='__main__':
    hash_passwords=HashPasswords()
    salt, pw_hash = hash_passwords.hash_new_password('correct horse battery staple')
    salt2, pw_hash2 = hash_passwords.hash_new_password('password2')
    print(hash_passwords.is_correct_password(salt, pw_hash, 'correct horse battery staple'))
    print(hash_passwords.is_correct_password(salt2, pw_hash2, 'password2'))
    print(hash_passwords.is_correct_password(salt, pw_hash, 'rosebud'))
    