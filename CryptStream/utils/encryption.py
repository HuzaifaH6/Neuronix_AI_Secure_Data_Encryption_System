from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

class EncryptionManager:
    
    @staticmethod
    def generate_fernet_key():
        """Generate a new Fernet key"""
        return Fernet.generate_key().decode('utf-8')
    
    @staticmethod
    def encrypt_fernet(text: str, key: str) -> str:
        """Encrypt using Fernet (symmetric encryption)"""
        try:
            f = Fernet(key.encode())
            encrypted = f.encrypt(text.encode())
            return encrypted.decode('utf-8')
        except Exception as e:
            raise Exception(f"Fernet encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_fernet(encrypted_text: str, key: str) -> str:
        """Decrypt using Fernet"""
        try:
            f = Fernet(key.encode())
            decrypted = f.decrypt(encrypted_text.encode())
            return decrypted.decode('utf-8')
        except Exception as e:
            raise Exception(f"Fernet decryption failed: {str(e)}")
    
    @staticmethod
    def encrypt_aes(text: str, password: str) -> tuple[str, str]:
        """Encrypt using AES-256"""
        try:
            # Generate key from password
            key = hashlib.sha256(password.encode()).digest()
            
            # Generate random IV
            cipher = AES.new(key, AES.MODE_CBC)
            iv = cipher.iv
            
            # Encrypt
            ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
            
            # Combine IV and ciphertext
            encrypted = base64.b64encode(iv + ct_bytes).decode('utf-8')
            
            return encrypted, base64.b64encode(key).decode('utf-8')
        except Exception as e:
            raise Exception(f"AES encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_aes(encrypted_text: str, password: str) -> str:
        """Decrypt using AES-256"""
        try:
            # Generate key from password
            key = hashlib.sha256(password.encode()).digest()
            
            # Decode the encrypted data
            encrypted_data = base64.b64decode(encrypted_text)
            
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ct = encrypted_data[16:]
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ct), AES.block_size)
            
            return decrypted.decode('utf-8')
        except Exception as e:
            raise Exception(f"AES decryption failed: {str(e)}")
    
    @staticmethod
    def encrypt_base64(text: str) -> str:
        """Encode using Base64 (not secure, just encoding)"""
        return base64.b64encode(text.encode()).decode('utf-8')
    
    @staticmethod
    def decrypt_base64(encoded_text: str) -> str:
        """Decode Base64"""
        try:
            return base64.b64decode(encoded_text).decode('utf-8')
        except Exception as e:
            raise Exception(f"Base64 decoding failed: {str(e)}")
    
    @staticmethod
    def encrypt_caesar(text: str, shift: int = 3) -> str:
        """Caesar cipher (demo/educational purpose)"""
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    @staticmethod
    def decrypt_caesar(text: str, shift: int = 3) -> str:
        """Decrypt Caesar cipher"""
        
        # Check 3: Reject Fernet pattern
        if text.startswith('gAAAAA'):
            raise Exception("Fernet encrypted text detected - use Fernet decryption!")

        # Check 4: Reject Base64 characters (Fernet/AES/Base64)
        if any(c in text for c in ['+', '/', '=']):
            raise Exception("Contains Base64 characters - Base64! or AES")
        
        decrypted = EncryptionManager.encrypt_caesar(text, -shift)
        return decrypted