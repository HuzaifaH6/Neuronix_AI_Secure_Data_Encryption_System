import streamlit as st
from utils.auth import AuthManager
from utils.encryption import EncryptionManager
from utils.ai_recommender import AIRecommender

# Page config
st.set_page_config(
    page_title="Secure Data Encryption System",
    page_icon="🔒",
    layout="wide" 
)

# Initialize managers
auth_manager = AuthManager()
encryption_manager = EncryptionManager()
ai_recommender = AIRecommender()

# Session state initialization
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'page' not in st.session_state:
    st.session_state.page = 'login'

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        text-align: center;
        margin-bottom: 2rem;
        color: #1f1f1f;
    }
    .success-box {
        padding: 1rem;
        background-color: #d4edda;
        border-left: 5px solid #28a745;
        margin: 1rem 0;
        border-radius: 5px;
    }
    .error-box {
        padding: 1rem;
        background-color: #f8d7da;
        border-left: 5px solid #dc3545;
        margin: 1rem 0;
        border-radius: 5px;
    }
    .info-box {
        padding: 1rem;
        background-color: #d1ecf1;
        border-left: 5px solid #17a2b8;
        margin: 1rem 0;
        border-radius: 5px;
    }
    .stButton>button {
        width: 100%;
        background-color: #4CAF50;
        color: white;
        padding: 0.5rem;
        font-size: 1rem;
        border-radius: 5px;
        border: none;
        cursor: pointer;
    }
    .stButton>button:hover {
        background-color: #45a049;  
    }
</style>
""", unsafe_allow_html=True)

def login_page():
    """Login and Registration Page"""
    st.markdown('<h1 class="main-header">🔒 Secure Data Encryption System</h1>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        tab1, tab2 = st.tabs(["Login", "Sign Up"])
        
        with tab1:
            st.subheader("Login to your account")
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            
            if st.button("Login", key="login_btn"):
                if username and password:
                    success, message = auth_manager.login_user(username, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)
                else:
                    st.warning("Please enter both username and password")
        
        with tab2:
            st.subheader("Create new account")
            new_username = st.text_input("Username", key="signup_username")
            new_password = st.text_input("Password", type="password", key="signup_password"  )
            confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
            
            if st.button("Sign Up", key="signup_btn"):
                if new_username and new_password and confirm_password:
                    if new_password != confirm_password:
                        st.error("Passwords don't match")
                    else:
                        success, message = auth_manager.register_user(new_username, new_password)
                        if success:
                            st.success(message + " - You can now login!")
                        else:
                            st.error(message)
                else:
                    st.warning("Please fill all fields")

def encryption_page():
    """Main Encryption/Decryption Page"""
    
    # Header with logout
    col1, col2 = st.columns([6, 1])
    with col1:
        st.markdown('<h1 class="main-header">🔐 Encryption Dashboard</h1>', unsafe_allow_html=True)
        st.markdown(f"**Welcome, {st.session_state.username}!**")
    with col2:
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.rerun()
    
    # Sidebar Navigation
    st.sidebar.title("Navigation")
    action = st.sidebar.radio("Select an action:", ["Encrypt", "Decrypt"])
    
    if action == "Encrypt":
        encrypt_section()
    else:
        decrypt_section()

def clear_state():
    """Clears the encryption/decryption data from session state."""
    st.session_state.encrypted_text = ""
    st.session_state.encryption_algorithm = "Fernet"
    st.session_state.encryption_key = ""
    st.session_state.input_text = ""


def encrypt_section():
    """Encryption Section"""
    st.subheader("🔒 Encrypt Your Data")
    
    # Text input
    input_text = st.text_area("Enter the text to encrypt:", height=150, 
                            placeholder="Type your secret message here...")
    
    st.button("Use AI to Encrypt")
    
    if input_text:
        # AI Recommendation
        st.markdown("---")
        st.subheader("🤖 AI Recommendation")
        
        recommendation = ai_recommender.recommend_encryption(input_text)
        
        st.markdown(f"""
        <div class="info-box">
            <strong>Recommended Algorithm:</strong> {recommendation['algorithm']}<br>
            <strong>Security Level:</strong> {recommendation['security_level']}<br>
            <strong>Reason:</strong> {recommendation['reason']}
        </div>
        """, unsafe_allow_html=True)
        
        # Algorithm selection
        st.markdown("---")
        st.subheader("Select Encryption Algorithm")
        
        col1, col2 = st.columns(2)
        
        with col1:
            algorithm = st.selectbox(
                "Encryption Method:",
                ["Fernet", "AES", "Base64", "Caesar"],
                index=["Fernet", "AES", "Base64", "Caesar"].index(recommendation['algorithm']) 
                    if recommendation['algorithm'] in ["Fernet", "AES", "Base64", "Caesar"] else 0
            )
        
        with col2:
            # Show algorithm info
            info = ai_recommender.get_algorithm_info(algorithm)
            if info:
                st.markdown('<div style="margin-top: 28px;"></div>', unsafe_allow_html=True)
                with st.expander("ℹ️ Algorithm Information", expanded=False):
                    st.write(f"**{info.get('full_name', '')}**")
                    st.write(f"*{info.get('description', '')}*")
                    st.write(f"**Use Cases:** {info.get('use_cases', '')}")

        
        # Encryption key/password input
        if algorithm == "Fernet":
                encryption_key = encryption_manager.generate_fernet_key()
                st.info("Auto-generated key (save this for decryption!)")
        
        elif algorithm == "AES":
            encryption_key = st.text_input("Encryption Password:", type="password", 
                                        help="Enter a strong password for AES encryption")
        
        elif algorithm == "Caesar":
            encryption_key = st.slider("Shift Value:", 1, 25, 3)
        
        else:  # Base64
            encryption_key = None
            st.warning("⚠️ Base64 is NOT encryption! Anyone can decode it.")
        
        # Encrypt button
        if st.button("🔒 Encrypt Text", type="primary"):
            try:
                if algorithm == "Fernet":
                    if not encryption_key:
                        st.error("Please provide an encryption key")
                        return
                    encrypted_text = encryption_manager.encrypt_fernet(input_text, encryption_key)
                    key_to_show = encryption_key
                
                elif algorithm == "AES":
                    if not encryption_key:
                        st.error("Please provide an encryption password")
                        return
                    encrypted_text, key_to_show = encryption_manager.encrypt_aes(input_text, encryption_key)
                
                elif algorithm == "Base64":
                    encrypted_text = encryption_manager.encrypt_base64(input_text)
                    key_to_show = "None (Base64 is just encoding)"
                
                else:  # Caesar
                    encrypted_text = encryption_manager.encrypt_caesar(input_text, encryption_key)
                    key_to_show = f"Shift: {encryption_key}"
                
                # Store results in session state to pass to decrypt page
                st.session_state.encrypted_text = encrypted_text
                st.session_state.encryption_algorithm = algorithm
                st.session_state.encryption_key = key_to_show if algorithm == "Fernet" else ""

                # Display results
                st.markdown("---")
                st.success("✅ Encryption Successful!")
                
                st.subheader("Encrypted Text:")
                st.code(encrypted_text, language="text")
                
                st.subheader("Encryption Key:")
                st.code(key_to_show, language="text")
                
                st.warning("⚠️ **IMPORTANT:** Save both the encrypted text and the key. You need both for decryption!")
                
                # Download button
                st.download_button(
                    label="📥 Download Encrypted Text",
                    data=f"Encrypted Text:\n{encrypted_text}\n\nEncryption Key:\n{key_to_show}\n\nAlgorithm: {algorithm}",
                    file_name="encrypted_data.txt",
                    mime="text/plain"
                )
                
            except Exception as e:
                st.error(f"Encryption failed: {str(e)}")

def decrypt_section():
    """Decryption Section"""
    st.subheader("🔓 Decrypt Your Data")
    
    # Encrypted text input
    encrypted_input = st.text_area("Enter the encrypted text:",
                                value=st.session_state.encrypted_text,
                                height=150,
                                placeholder="Paste your encrypted text here...",
                                key="decrypt_text_area")
    st.session_state.encrypted_text = encrypted_input # Keep session state synced
    
    if encrypted_input:
        # Algorithm selection
        algo_list = ["Fernet", "AES", "Base64", "Caesar"]
        default_index = algo_list.index(st.session_state.encryption_algorithm) if st.session_state.encryption_algorithm in algo_list else 0
        algorithm = st.selectbox(
            "Select Decryption Algorithm:",
            algo_list,
            index=default_index
        )
        
        # Key input based on algorithm
        if algorithm == "Fernet":
            decryption_key = st.text_input("Enter Fernet Key:", value=st.session_state.encryption_key, type="password")
        
        elif algorithm == "AES":
            decryption_key = st.text_input("Enter Encryption Password:", type="password")
        
        elif algorithm == "Caesar":
            decryption_key = st.slider("Shift Value:", 1, 25, 3) # Cannot pre-fill this securely
        
        else:  # Base64
            decryption_key = None
        
        # Decrypt button
        if st.button("🔓 Decrypt Text", type="primary"):
            try:
                if algorithm == "Fernet":
                    if not decryption_key:
                        st.error("Please provide the decryption key")
                        return
                    decrypted_text = encryption_manager.decrypt_fernet(encrypted_input, decryption_key)
                
                elif algorithm == "AES":
                    if not decryption_key:
                        st.error("Please provide the decryption password")
                        return
                    decrypted_text = encryption_manager.decrypt_aes(encrypted_input, decryption_key)
                
                elif algorithm == "Base64":
                    decrypted_text = encryption_manager.decrypt_base64(encrypted_input)
                
                else:  # Caesar
                    decrypted_text = encryption_manager.decrypt_caesar(encrypted_input, decryption_key)
                
                # Display result
                st.markdown("---")
                st.success("✅ Decryption Successful!")
                
                st.subheader("Decrypted Text:")
                st.text_area("Your original text:", value=decrypted_text, height=150)
                # Optionally clear state after successful decryption
                clear_state()
                
            except Exception as e:
                st.error(f"❌ Decryption failed: {str(e)}\n\nPossible reasons:\n- Wrong key/password\n- Wrong algorithm\n- Corrupted encrypted text")

# Main app logic
def main():
    if not st.session_state.logged_in:
        login_page()
    else:
        encryption_page()

if __name__ == "__main__":
    main()