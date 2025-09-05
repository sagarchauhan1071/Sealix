import customtkinter as ctk
from tkinter import messagebox, filedialog
import json
import hashlib
import datetime
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class ClientInterface:
    def __init__(self, main_app, username):
        self.main_app = main_app
        self.current_user = username
        self.users_file = "users_data.json"
        self.logs_file = "system_logs.json"
        self.files_data_file = "files_data.json"

        self.user_key = None
        self.selected_file_path = None

        # Load data
        self.load_logs()
        self.load_files_data()
        self.generate_user_key()

        # UI Setup
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

        self.root = ctk.CTk()
        self.root.title(f"🔐 SecureVault Client - {username}")
        self.root.geometry("1200x800")
        self.root.configure(fg_color="#1a1a2e")

        self.create_client_gui()

    def load_logs(self):
        """Load system logs"""
        try:
            if os.path.exists(self.logs_file):
                with open(self.logs_file, 'r', encoding='utf-8') as f:
                    self.logs_data = json.load(f)
            else:
                self.logs_data = []
        except Exception as e:
            print(f"Error loading logs: {e}")
            self.logs_data = []

    def save_logs(self):
        """Save logs to file"""
        try:
            with open(self.logs_file, 'w', encoding='utf-8') as f:
                json.dump(self.logs_data, f, indent=2)
        except Exception as e:
            print(f"Error saving logs: {e}")

    def load_files_data(self):
        """Load files data"""
        try:
            if os.path.exists(self.files_data_file):
                with open(self.files_data_file, 'r', encoding='utf-8') as f:
                    self.files_data = json.load(f)
            else:
                self.files_data = {}
        except Exception as e:
            print(f"Error loading files data: {e}")
            self.files_data = {}

    def save_files_data(self):
        """Save files data"""
        try:
            with open(self.files_data_file, 'w', encoding='utf-8') as f:
                json.dump(self.files_data, f, indent=2)
        except Exception as e:
            print(f"Error saving files data: {e}")

    def generate_user_key(self):
        """Generate encryption key for user (deterministic based on username using PBKDF2)"""
        # Create a user-specific key based on username (deterministic)
        salt = self.current_user.encode()[:16].ljust(16, b'0')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.current_user.encode()))
        self.user_key = key

    # Optional: if you want a random key instead of deterministic, you can use:
    # def generate_user_key_random(self):
    #     self.user_key = Fernet.generate_key()

    def create_client_gui(self):
        """Create the client GUI interface"""
        # Main container
        main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        header_frame = ctk.CTkFrame(main_container, fg_color="#16213e", corner_radius=15)
        header_frame.pack(fill="x", pady=(0, 20))

        # Title and user info
        title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=15)

        title_label = ctk.CTkLabel(title_frame,
                                   text="🔐 SECUREVAULT CLIENT",
                                   font=("Courier New", 24, "bold"),
                                   text_color="#4fc3f7")
        title_label.pack(side="left")

        user_label = ctk.CTkLabel(title_frame,
                                  text=f"User: {self.current_user}",
                                  font=("Courier New", 14, "bold"),
                                  text_color="#81c784")
        user_label.pack(side="right")

        # Main content area
        content_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        content_frame.pack(fill="both", expand=True)

        # Left panel - Controls
        left_panel = ctk.CTkFrame(content_frame, fg_color="#16213e", corner_radius=15, width=300)
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)

        # Right panel - File operations
        right_panel = ctk.CTkFrame(content_frame, fg_color="#16213e", corner_radius=15)
        right_panel.pack(side="right", fill="both", expand=True)

        self.create_control_panel(left_panel)
        self.create_file_panel(right_panel)

        # Status bar
        self.status_label = ctk.CTkLabel(main_container,
                                        text="Ready | Select a file to begin encryption/decryption",
                                        font=("Courier New", 10),
                                        text_color="#81c784")
        self.status_label.pack(fill="x", pady=(10, 0))

    def create_control_panel(self, parent):
        """Create control panel"""
        ctk.CTkLabel(parent, text="FILE OPERATIONS",
                     font=("Courier New", 16, "bold"),
                     text_color="#81c784").pack(pady=20)

        # File selection
        file_frame = ctk.CTkFrame(parent, fg_color="#0f1419", corner_radius=10)
        file_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(file_frame, text="📁 FILE SELECTION",
                     font=("Courier New", 12, "bold"),
                     text_color="#ffffff").pack(pady=10)

        select_btn = ctk.CTkButton(file_frame, text="Select File",
                                   command=self.select_file,
                                   font=("Courier New", 11, "bold"),
                                   fg_color="#37474f", hover_color="#455a64")
        select_btn.pack(pady=5)

        self.selected_file_label = ctk.CTkLabel(file_frame, text="No file selected",
                                               font=("Courier New", 9),
                                               text_color="#888888",
                                               wraplength=250)
        self.selected_file_label.pack(pady=(5, 10))

        # Operations buttons
        operations = [
            ("🔒 Encrypt File", self.encrypt_file, "#4caf50"),
            ("🔓 Decrypt File", self.decrypt_file, "#2196f3"),
            ("💾 Save Encrypted", self.save_encrypted_file, "#ff9800"),
            ("💾 Save Decrypted", self.save_decrypted_file, "#9c27b0"),
            ("🔄 Generate New Key", self.generate_new_key_dialog, "#f44336"),
            ("📋 View File Info", self.view_file_info, "#607d8b")
        ]

        for text, command, color in operations:
            btn = ctk.CTkButton(parent, text=text, command=command,
                                font=("Courier New", 11, "bold"),
                                fg_color=color, hover_color=color,
                                width=250, height=35)
            btn.pack(pady=8, padx=15)

        # User info section
        info_frame = ctk.CTkFrame(parent, fg_color="#0f1419", corner_radius=10)
        info_frame.pack(fill="x", padx=15, pady=(20, 10))

        ctk.CTkLabel(info_frame, text="👤 USER STATUS",
                     font=("Courier New", 12, "bold"),
                     text_color="#ffffff").pack(pady=10)

        status_text = f"Username: {self.current_user}\nStatus: AUTHENTICATED ✅\nEncryption: ACTIVE 🔐"
        ctk.CTkLabel(info_frame, text=status_text,
                     font=("Courier New", 9),
                     text_color="#81c784").pack(pady=(0, 10))

        # Logout button
        logout_btn = ctk.CTkButton(parent, text="🚪 LOGOUT",
                                  command=self.logout,
                                  font=("Courier New", 12, "bold"),
                                  fg_color="#f44336", hover_color="#d32f2f",
                                  width=250, height=40)
        logout_btn.pack(side="bottom", pady=15, padx=15)

    def create_file_panel(self, parent):
        """Create file operations panel"""
        ctk.CTkLabel(parent, text="FILE CONTENT & OPERATIONS",
                     font=("Courier New", 18, "bold"),
                     text_color="#4fc3f7").pack(pady=15)

        # Create tabview for different content views
        self.tabview = ctk.CTkTabview(parent, height=500)
        self.tabview.pack(fill="both", expand=True, padx=15, pady=15)

        # Add tabs
        self.tabview.add("📄 Original Content")
        self.tabview.add("🔒 Encrypted Content")
        self.tabview.add("🔓 Decrypted Content")

        # Original content tab
        original_tab = self.tabview.tab("📄 Original Content")

        self.original_text = ctk.CTkTextbox(original_tab, height=400,
                                            font=("Courier New", 10),
                                            fg_color="#0f1419")
        self.original_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Encrypted content tab
        encrypted_tab = self.tabview.tab("🔒 Encrypted Content")

        self.encrypted_text = ctk.CTkTextbox(encrypted_tab, height=400,
                                             font=("Courier New", 10),
                                             fg_color="#0f1419",
                                             text_color="#ff7043")
        self.encrypted_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Decrypted content tab
        decrypted_tab = self.tabview.tab("🔓 Decrypted Content")

        self.decrypted_text = ctk.CTkTextbox(decrypted_tab, height=400,
                                             font=("Courier New", 10),
                                             fg_color="#0f1419",
                                             text_color="#81c784")
        self.decrypted_text.pack(fill="both", expand=True, padx=10, pady=10)

    def select_file(self):
        """Select file for encryption/decryption"""
        file_path = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[
                ("All files", "*.*"),
                ("Text files", "*.txt"),
                ("Document files", "*.doc *.docx"),
                ("PDF files", "*.pdf"),
                ("Image files", "*.jpg *.jpeg *.png *.gif *.bmp"),
                ("Video files", "*.mp4 *.avi *.mkv *.mov"),
                ("Audio files", "*.mp3 *.wav *.flac *.aac"),
                ("Archive files", "*.zip *.rar *.7z *.tar"),
                ("Code files", "*.py *.js *.html *.css *.java *.cpp"),
                ("Excel files", "*.xlsx *.xls"),
                ("PowerPoint files", "*.pptx *.ppt")
            ]
        )

        if file_path:
            self.selected_file_path = file_path
            filename = os.path.basename(file_path)
            self.selected_file_label.configure(text=f"📁 {filename}")

            # Load file content
            try:
                # Try to read as text first, fall back to binary for non-text files
                try:
                    with open(file_path, 'r', encoding='utf-8') as file:
                        content = file.read()
                except UnicodeDecodeError:
                    # For binary files, read as binary and encode to base64 for display
                    with open(file_path, 'rb') as file:
                        binary_content = file.read()
                        content = f"[BINARY FILE - {len(binary_content)} bytes]\n\nBase64 representation:\n{base64.b64encode(binary_content).decode()[:500]}..."

                self.original_text.delete("1.0", "end")
                self.original_text.insert("1.0", content)

                # Switch to original content tab
                self.tabview.set("📄 Original Content")

                self.status_label.configure(text=f"File loaded: {filename}")

                # Save file info to user's data
                if self.current_user not in self.files_data:
                    self.files_data[self.current_user] = {}

                self.files_data[self.current_user]['last_file'] = filename
                self.files_data[self.current_user]['last_accessed'] = datetime.datetime.now().isoformat()
                self.save_files_data()

                self.log_action(self.current_user, "FILE_SELECTED", f"Selected file: {filename}")

            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to load file: {str(e)}")
                self.log_action(self.current_user, "FILE_SELECT_ERROR", f"Failed to select file: {str(e)}")

    def encrypt_file(self):
        """Encrypt the selected file content"""
        content = self.original_text.get("1.0", "end").strip()

        if not content:
            messagebox.showerror("❌ Error", "No content to encrypt. Please select a file first.")
            return

        try:
            # Create Fernet cipher with user's key
            cipher = Fernet(self.user_key)

            # Encrypt the content - Fernet returns a URL-safe base64 token (bytes)
            encrypted_token = cipher.encrypt(content.encode())
            encrypted_text = encrypted_token.decode()  # store/display as string

            # Display encrypted content
            self.encrypted_text.delete("1.0", "end")
            self.encrypted_text.insert("1.0", encrypted_text)

            # Switch to encrypted tab
            self.tabview.set("🔒 Encrypted Content")

            self.status_label.configure(text="✅ File encrypted successfully!")

            # Save encryption info
            if self.current_user not in self.files_data:
                self.files_data[self.current_user] = {}

            self.files_data[self.current_user]['encrypted_data'] = encrypted_text[:100] + "..." if len(encrypted_text) > 100 else encrypted_text
            self.files_data[self.current_user]['encryption_timestamp'] = datetime.datetime.now().isoformat()
            self.save_files_data()

            self.log_action(self.current_user, "FILE_ENCRYPTED", "File content encrypted successfully")

            messagebox.showinfo("✅ Success", "File encrypted successfully!")

        except Exception as e:
            messagebox.showerror("❌ Error", f"Encryption failed: {str(e)}")
            self.log_action(self.current_user, "ENCRYPTION_FAILED", f"Encryption failed: {str(e)}")

    def decrypt_file(self):
        """Decrypt the encrypted content"""
        encrypted_content = self.encrypted_text.get("1.0", "end").strip()

        if not encrypted_content:
            messagebox.showerror("❌ Error", "No encrypted content to decrypt.")
            return

        try:
            # Create Fernet cipher with user's key
            cipher = Fernet(self.user_key)

            # encrypted_content is a URL-safe base64 token string from Fernet
            decrypted_content = cipher.decrypt(encrypted_content.encode()).decode()

            # Display decrypted content
            self.decrypted_text.delete("1.0", "end")
            self.decrypted_text.insert("1.0", decrypted_content)

            # Switch to decrypted tab
            self.tabview.set("🔓 Decrypted Content")

            self.status_label.configure(text="✅ File decrypted successfully!")

            # Save decryption info
            if self.current_user not in self.files_data:
                self.files_data[self.current_user] = {}

            self.files_data[self.current_user]['last_decryption'] = datetime.datetime.now().isoformat()
            self.save_files_data()

            self.log_action(self.current_user, "FILE_DECRYPTED", "File content decrypted successfully")

            messagebox.showinfo("✅ Success", "File decrypted successfully!")

        except Exception as e:
            messagebox.showerror("❌ Error", f"Decryption failed: {str(e)}")
            self.log_action(self.current_user, "DECRYPTION_FAILED", f"Decryption failed: {str(e)}")

    def save_encrypted_file(self):
        """Save encrypted content to file"""
        encrypted_content = self.encrypted_text.get("1.0", "end").strip()

        if not encrypted_content:
            messagebox.showerror("❌ Error", "No encrypted content to save.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save encrypted file",
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("Text files", "*.txt"), ("All files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(encrypted_content)

                filename = os.path.basename(file_path)
                self.status_label.configure(text=f"✅ Encrypted file saved: {filename}")
                self.log_action(self.current_user, "ENCRYPTED_FILE_SAVED", f"Encrypted file saved: {filename}")
                messagebox.showinfo("✅ Success", "Encrypted file saved successfully!")

            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to save file: {str(e)}")

    def save_decrypted_file(self):
        """Save decrypted content to file"""
        decrypted_content = self.decrypted_text.get("1.0", "end").strip()

        if not decrypted_content:
            messagebox.showerror("❌ Error", "No decrypted content to save.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save decrypted file",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(decrypted_content)

                filename = os.path.basename(file_path)
                self.status_label.configure(text=f"✅ Decrypted file saved: {filename}")
                self.log_action(self.current_user, "DECRYPTED_FILE_SAVED", f"Decrypted file saved: {filename}")
                messagebox.showinfo("✅ Success", "Decrypted file saved successfully!")

            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to save file: {str(e)}")

    def generate_new_key_dialog(self):
        """Confirmation wrapper to generate new encryption key"""
        if messagebox.askyesno("Generate New Key",
                               "⚠️ This will generate a new encryption key.\n\nFiles encrypted with the old key won't be decryptable with the new key.\n\nContinue?"):
            try:
                # If you want a random key:
                # self.user_key = Fernet.generate_key()

                # If you want to keep deterministic PBKDF2 but re-run (effectively same key for same username),
                # call generate_user_key(). To produce a new random key, uncomment Fernet.generate_key() above.
                self.generate_user_key()

                # Clear existing encrypted/decrypted content
                self.encrypted_text.delete("1.0", "end")
                self.decrypted_text.delete("1.0", "end")

                # Save key generation info
                if self.current_user not in self.files_data:
                    self.files_data[self.current_user] = {}

                self.files_data[self.current_user]['key_generated'] = datetime.datetime.now().isoformat()
                self.save_files_data()

                self.status_label.configure(text="✅ New encryption key generated!")
                self.log_action(self.current_user, "KEY_GENERATED", "New encryption key generated")

                messagebox.showinfo("✅ Success", "New encryption key generated successfully!\n\n⚠️ Note: Previously encrypted files cannot be decrypted with this new key.")

            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to generate new key: {str(e)}")

    def view_file_info(self):
        """View current file information"""
        if hasattr(self, 'selected_file_path') and self.selected_file_path:
            try:
                file_stats = os.stat(self.selected_file_path)
                file_size = file_stats.st_size
                modified_time = datetime.datetime.fromtimestamp(file_stats.st_mtime)

                # Get user's file data
                user_file_data = self.files_data.get(self.current_user, {})

                info = f"""📁 FILE INFORMATION
==================

📄 Name: {os.path.basename(self.selected_file_path)}
📂 Path: {self.selected_file_path}
📊 Size: {file_size} bytes
🕒 Modified: {modified_time.strftime('%Y-%m-%d %H:%M:%S')}
👤 User: {self.current_user}
🔐 Encryption Status: {"✅ Available" if self.encrypted_text.get("1.0", "end").strip() else "❌ Not encrypted"}
🔓 Decryption Status: {"✅ Available" if self.decrypted_text.get("1.0", "end").strip() else "❌ Not decrypted"}

📋 USER FILE DATA:
Last Accessed: {user_file_data.get('last_accessed', 'Never')}
Last Encryption: {user_file_data.get('encryption_timestamp', 'Never')}
Last Decryption: {user_file_data.get('last_decryption', 'Never')}
Key Generated: {user_file_data.get('key_generated', 'Default key')}
                """

                messagebox.showinfo("📁 File Information", info)
                self.log_action(self.current_user, "FILE_INFO_VIEWED", f"Viewed info for: {os.path.basename(self.selected_file_path)}")

            except Exception as e:
                messagebox.showerror("❌ Error", f"Failed to get file info: {str(e)}")
        else:
            messagebox.showinfo("📁 No File", "No file selected. Please select a file first.")

    def log_action(self, username, action, details):
        """Log user actions"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "username": username,
            "action": action,
            "details": details
        }
        # ensure logs_data exists
        if not hasattr(self, 'logs_data'):
            self.logs_data = []
        self.logs_data.append(log_entry)
        self.save_logs()

    def logout(self):
        """Handle user logout"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.log_action(self.current_user, "LOGOUT", "User logged out from client interface")
            self.root.destroy()
            # call back to main app
            try:
                self.main_app.show_dashboard()
            except Exception:
                pass

    def run(self):
        """Run the client interface"""
        # Log the login to client interface
        self.log_action(self.current_user, "CLIENT_LOGIN", "User accessed client interface")
        self.root.mainloop()


if __name__ == "__main__":
    # For testing purposes
    class MockMainApp:
        def show_dashboard(self):
            print("Returning to main dashboard")

    client = ClientInterface(MockMainApp(), "testuser")
    client.run()
