class AIRecommender:
    
    @staticmethod
    def recommend_encryption(text: str, context: str = "") -> dict:
        """
        Recommend encryption algorithm based on input analysis
        Returns: {algorithm, reason, security_level}
        """
        
        text_length = len(text)
        has_sensitive_keywords = any(keyword in text.lower() for keyword in 
            ['password', 'credit card', 'ssn', 'confidential', 'secret', 'private'])
        
        if has_sensitive_keywords or text_length > 500:
            return {
                'algorithm': 'AES',
                'reason': 'Detected sensitive content or large text. AES-256 provides military-grade security.',
                'security_level': 'High',
                'color': 'red'
            }
        
        elif text_length > 100:
            return {
                'algorithm': 'Fernet',
                'reason': 'Medium-length text detected. Fernet offers strong encryption with ease of use.',
                'security_level': 'Medium-High',
                'color': 'orange'
            }
        
        elif any(keyword in context.lower() for keyword in ['demo', 'test', 'example', 'learn']):
            return {
                'algorithm': 'Caesar',
                'reason': 'Learning/demo context detected. Caesar cipher is great for understanding encryption basics.',
                'security_level': 'Low (Educational)',
                'color': 'blue'
            }
        
        else:
            return {
                'algorithm': 'Fernet',
                'reason': 'General purpose encryption. Fernet is secure and efficient for most use cases.',
                'security_level': 'Medium-High',
                'color': 'green'
            }
    
    @staticmethod
    def get_algorithm_info(algorithm: str) -> dict:
        """Get detailed information about an algorithm"""
        
        info = {
            'Fernet': {
                'full_name': 'Fernet (Symmetric Encryption)',
                'description': 'Built on AES in CBC mode with HMAC for authentication',
                'use_cases': 'General purpose, API tokens, session data',
                'pros': 'Simple, secure, authenticated encryption',
                'cons': 'Same key for encrypt/decrypt must be kept secret'
            },
            'AES': {
                'full_name': 'AES-256 (Advanced Encryption Standard)',
                'description': 'Military-grade symmetric encryption with 256-bit keys',
                'use_cases': 'Highly sensitive data, financial records, medical data',
                'pros': 'Extremely secure, industry standard, fast',
                'cons': 'Requires secure key management'
            },
            'Base64': {
                'full_name': 'Base64 Encoding',
                'description': 'NOT encryption! Just encodes binary data to ASCII',
                'use_cases': 'Encoding binary data for transmission, NOT for security',
                'pros': 'Universal, simple, reversible',
                'cons': 'NO SECURITY - anyone can decode it'
            },
            'Caesar': {
                'full_name': 'Caesar Cipher',
                'description': 'Ancient substitution cipher, shifts letters by N positions',
                'use_cases': 'Educational purposes, puzzle games',
                'pros': 'Simple to understand, good for learning',
                'cons': 'NOT SECURE - easily broken by frequency analysis'
            }
        }
        
        return info.get(algorithm, {})