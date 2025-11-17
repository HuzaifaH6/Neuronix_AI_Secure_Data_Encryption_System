import bcrypt
import json
import os
from pathlib import Path

class AuthManager:
    def __init__(self, users_file='data/users.json'):
        self.users_file = users_file
        self._ensure_data_folder()
    
    def _ensure_data_folder(self):
        """Create data folder if it doesn't exist"""
        Path('data').mkdir(exist_ok=True)
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump({}, f)

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    def load_users(self) -> dict:
        """Load users from JSON file"""
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def save_users(self, users: dict):
        """Save users to JSON file"""
        with open(self.users_file, 'w') as f:
            json.dump(users, f, indent=2)
    
    def register_user(self, username: str, password: str) -> tuple[bool, str]:
        """Register new user"""
        users = self.load_users()
        
        if username in users:
            return False, "Username already exists"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters"
        
        users[username] = {
            'password': AuthManager.hash_password(password),
            'created_at': str(Path(self.users_file).stat().st_mtime)
        }
        
        self.save_users(users)
        return True, "Registration successful"
    
    def login_user(self, username: str, password: str) -> tuple[bool, str]:
        """Authenticate user"""
        users = self.load_users()
        
        if username not in users:
            return False, "Invalid username or password"
        
        if AuthManager.verify_password(password, users[username]['password']):
            return True, "Login successful"
        
        return False, "Invalid username or password"