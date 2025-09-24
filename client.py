import customtkinter as ctk
from tkinter import messagebox, filedialog
import json
import hashlib
import datetime
import os
import base64
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class ClientInterface:
    def __init__(self, main_app, username):
        self.main_app = main_app
        self.current_user = username
        self.users_file = "users_data.json"
        self.logs_file = "system_logs.json"
        self.files_data_file = "files_data.json"

        # RSA keys and password
        self.public_key = None
        self.private_key = None
        self.private_key_password = None
        self.selected_file_path = None
        self.encrypted_files = []
        self.decryption_files = []

        # Load data
        self.load_logs()
        self.load_files_data()

        # UI Setup
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

        self.root = ctk.CTk()
        self.root.title(f"SecureVault Client v2.0 - {username}")
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
        """Save logs to file with proper error handling"""
        try:
            # Ensure logs_data is a list
            if not isinstance(self.logs_data, list):
                self.logs_data = []
            
            # Create backup of existing logs before writing
            if os.path.exists(self.logs_file):
                backup_file = self.logs_file + ".backup"
                with open(self.logs_file, 'r', encoding='utf-8') as f:
                    backup_data = f.read()
                with open(backup_file, 'w', encoding='utf-8') as f:
                    f.write(backup_data)
            
            # Write logs with proper formatting
            with open(self.logs_file, 'w', encoding='utf-8') as f:
                json.dump(self.logs_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print(f"Error saving logs: {e}")
            # Try to restore from backup if write failed
            backup_file = self.logs_file + ".backup"
            if os.path.exists(backup_file):
                try:
                    with open(backup_file, 'r', encoding='utf-8') as f:
                        backup_data = json.load(f)
                    with open(self.logs_file, 'w', encoding='utf-8') as f:
                        json.dump(backup_data, f, indent=2, ensure_ascii=False)
                except Exception:
                    pass

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
                json.dump(self.files_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving files data: {e}")

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
                                   text="SECUREVAULT CLIENT v2.0",
                                   font=("Courier New", 24, "bold"),
                                   text_color="#4fc3f7")
        title_label.pack(side="left")

        user_label = ctk.CTkLabel(title_frame,
                                  text=f"User: {self.current_user} | RSA+AES Hybrid",
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
                                        text="Ready | Generate or load RSA keys to begin",
                                        font=("Courier New", 10),
                                        text_color="#81c784")
        self.status_label.pack(fill="x", pady=(10, 0))

    def create_control_panel(self, parent):
        """Create control panel"""
        ctk.CTkLabel(parent, text="RSA+AES ENCRYPTION",
                     font=("Courier New", 16, "bold"),
                     text_color="#81c784").pack(pady=20)

        # Key Management Section
        key_frame = ctk.CTkFrame(parent, fg_color="#0f1419", corner_radius=10)
        key_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(key_frame, text="KEY MANAGEMENT",
                     font=("Courier New", 12, "bold"),
                     text_color="#ffffff").pack(pady=10)

        # Password entry for private key
        ctk.CTkLabel(key_frame, text="Private Key Password:",
                     font=("Courier New", 10),
                     text_color="#ffffff").pack(pady=(5, 0))
        
        self.password_entry = ctk.CTkEntry(key_frame, show="*", height=30,
                                          font=("Courier New", 10))
        self.password_entry.pack(fill="x", padx=10, pady=5)

        # Key operation buttons
        key_buttons = [
            ("Generate Key Pair", self.generate_key_pair, "#4caf50"),
            ("Load Public Key", self.load_public_key, "#2196f3"),
            ("Load Private Key", self.load_private_key, "#ff9800")
        ]

        for text, command, color in key_buttons:
            btn = ctk.CTkButton(key_frame, text=text, command=command,
                               font=("Courier New", 9, "bold"),
                               fg_color=color, hover_color=color,
                               width=250, height=30)
            btn.pack(pady=3, padx=10)

        # Key status
        self.key_status_label = ctk.CTkLabel(key_frame, 
                                            text="No keys loaded",
                                            font=("Courier New", 9),
                                            text_color="#f44336")
        self.key_status_label.pack(pady=(5, 10))

        # File selection
        file_frame = ctk.CTkFrame(parent, fg_color="#0f1419", corner_radius=10)
        file_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(file_frame, text="FILE SELECTION",
                     font=("Courier New", 12, "bold"),
                     text_color="#ffffff").pack(pady=10)

        select_btn = ctk.CTkButton(file_frame, text="Select File to Encrypt",
                                   command=self.select_file,
                                   font=("Courier New", 10, "bold"),
                                   fg_color="#37474f", hover_color="#455a64")
        select_btn.pack(pady=5)

        select_locked_btn = ctk.CTkButton(file_frame, text="Select .locked File",
                                         command=self.select_locked_file,
                                         font=("Courier New", 10, "bold"),
                                         fg_color="#37474f", hover_color="#455a64")
        select_locked_btn.pack(pady=5)

        self.selected_file_label = ctk.CTkLabel(file_frame, text="No file selected",
                                               font=("Courier New", 9),
                                               text_color="#888888",
                                               wraplength=250)
        self.selected_file_label.pack(pady=(5, 10))

        # Operations buttons
        operations = [
            ("Encrypt File", self.encrypt_file, "#4caf50"),
            ("Decrypt File", self.decrypt_file, "#2196f3"),
            ("Save Encrypted", self.save_encrypted_file, "#ff9800"),
            ("Save Decrypted", self.save_decrypted_file, "#9c27b0"),
            ("Clear Lists", self.clear_lists, "#f44336"),
            ("View File Info", self.view_file_info, "#607d8b")
        ]

        for text, command, color in operations:
            btn = ctk.CTkButton(parent, text=text, command=command,
                                font=("Courier New", 11, "bold"),
                                fg_color=color, hover_color=color,
                                width=250, height=35)
            btn.pack(pady=6, padx=15)

        # User info section
        info_frame = ctk.CTkFrame(parent, fg_color="#0f1419", corner_radius=10)
        info_frame.pack(fill="x", padx=15, pady=(20, 10))

        ctk.CTkLabel(info_frame, text="USER STATUS",
                     font=("Courier New", 12, "bold"),
                     text_color="#ffffff").pack(pady=10)

        status_text = f"Username: {self.current_user}\nStatus: AUTHENTICATED\nEncryption: RSA+AES Hybrid"
        ctk.CTkLabel(info_frame, text=status_text,
                     font=("Courier New", 9),
                     text_color="#81c784").pack(pady=(0, 10))

        # Logout button
        logout_btn = ctk.CTkButton(parent, text="LOGOUT",
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
        self.tabview.add("Original Content")
        self.tabview.add("Encrypted Content") 
        self.tabview.add("Decrypted Content")

        # Original content tab
        original_tab = self.tabview.tab("Original Content")

        self.original_text = ctk.CTkTextbox(original_tab, height=400,
                                            font=("Courier New", 10),
                                            fg_color="#0f1419")
        self.original_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Encrypted content tab
        encrypted_tab = self.tabview.tab("Encrypted Content")

        self.encrypted_text = ctk.CTkTextbox(encrypted_tab, height=400,
                                             font=("Courier New", 10),
                                             fg_color="#0f1419",
                                             text_color="#ff7043")
        self.encrypted_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Decrypted content tab
        decrypted_tab = self.tabview.tab("Decrypted Content")

        self.decrypted_text = ctk.CTkTextbox(decrypted_tab, height=400,
                                             font=("Courier New", 10),
                                             fg_color="#0f1419",
                                             text_color="#81c784")
        self.decrypted_text.pack(fill="both", expand=True, padx=10, pady=10)

    def generate_key_pair(self):
        """Generate RSA key pair and save with password protection"""
        if not self.password_entry.get():
            messagebox.showwarning("Missing Password", "Enter a password to protect the private key.")
            return

        try:
            self.log_action(self.current_user, "KEY_GENERATION_STARTED", "Started RSA key pair generation process")
            
            # Generate 2048-bit RSA key pair
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            # Save private key
            priv_path = filedialog.asksaveasfilename(
                defaultextension=".key",
                filetypes=[("Private Key", "*.key"), ("All files", "*.*")],
                title="Save Private Key"
            )
            if not priv_path:
                self.log_action(self.current_user, "KEY_GENERATION_CANCELLED", "User cancelled private key save dialog")
                return

            with open(priv_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        self.password_entry.get().encode()
                    )
                ))

            # Save public key
            pub_path = filedialog.asksaveasfilename(
                defaultextension=".pub",
                filetypes=[("Public Key", "*.pub"), ("All files", "*.*")],
                title="Save Public Key"
            )
            if not pub_path:
                self.log_action(self.current_user, "KEY_GENERATION_CANCELLED", "User cancelled public key save dialog")
                return

            with open(pub_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            # Store keys and password
            self.private_key = private_key
            self.public_key = public_key
            self.private_key_password = self.password_entry.get()

            # Update status
            self.key_status_label.configure(text="Key pair generated & loaded", text_color="#4caf50")
            self.status_label.configure(text="RSA key pair generated successfully!")

            # Log action with detailed information
            self.log_action(self.current_user, "KEY_PAIR_GENERATED", 
                          f"Successfully generated 2048-bit RSA key pair - Private: {os.path.basename(priv_path)}, Public: {os.path.basename(pub_path)}")

            # Save to files data
            if self.current_user not in self.files_data:
                self.files_data[self.current_user] = {}
            self.files_data[self.current_user]['key_generated'] = datetime.datetime.now().isoformat()
            self.files_data[self.current_user]['private_key_file'] = os.path.basename(priv_path)
            self.files_data[self.current_user]['public_key_file'] = os.path.basename(pub_path)
            self.files_data[self.current_user]['key_size'] = "2048-bit RSA"
            self.save_files_data()

            messagebox.showinfo("Success", 
                              f"RSA key pair generated successfully!\n\nPrivate key: {os.path.basename(priv_path)}\nPublic key: {os.path.basename(pub_path)}")

        except Exception as e:
            error_msg = f"Key generation failed: {str(e)}"
            messagebox.showerror("Error", f"Failed to generate key pair: {str(e)}")
            self.log_action(self.current_user, "KEY_GENERATION_FAILED", error_msg)

    def load_public_key(self):
        """Load public key from file"""
        path = filedialog.askopenfilename(
            title="Select Public Key",
            filetypes=[("Public Key", "*.pub"), ("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if path:
            try:
                self.log_action(self.current_user, "PUBLIC_KEY_LOAD_ATTEMPT", f"Attempting to load public key: {os.path.basename(path)}")
                
                with open(path, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(f.read())
                
                self.update_key_status()
                self.status_label.configure(text=f"Public key loaded: {os.path.basename(path)}")
                
                # Get key info for logging
                key_size = self.public_key.key_size
                self.log_action(self.current_user, "PUBLIC_KEY_LOADED", f"Successfully loaded {key_size}-bit public key: {os.path.basename(path)}")
                
                # Save to files data
                if self.current_user not in self.files_data:
                    self.files_data[self.current_user] = {}
                self.files_data[self.current_user]['public_key_loaded'] = datetime.datetime.now().isoformat()
                self.files_data[self.current_user]['public_key_file'] = os.path.basename(path)
                self.save_files_data()
                
                messagebox.showinfo("Success", f"Public key loaded successfully!\nKey size: {key_size} bits")
                
            except Exception as e:
                error_msg = f"Failed to load public key: {str(e)}"
                messagebox.showerror("Error", error_msg)
                self.log_action(self.current_user, "PUBLIC_KEY_LOAD_FAILED", error_msg)

    def load_private_key(self):
        """Load private key from file with password"""
        if not self.password_entry.get():
            messagebox.showwarning("Missing Password", "Enter the password for the private key.")
            return

        path = filedialog.askopenfilename(
            title="Select Private Key",
            filetypes=[("Private Key", "*.key"), ("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if path:
            try:
                self.log_action(self.current_user, "PRIVATE_KEY_LOAD_ATTEMPT", f"Attempting to load private key: {os.path.basename(path)}")
                
                with open(path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=self.password_entry.get().encode()
                    )
                
                self.private_key_password = self.password_entry.get()
                self.update_key_status()
                self.status_label.configure(text=f"Private key loaded: {os.path.basename(path)}")
                
                # Get key info for logging
                key_size = self.private_key.key_size
                self.log_action(self.current_user, "PRIVATE_KEY_LOADED", f"Successfully loaded {key_size}-bit private key: {os.path.basename(path)}")
                
                # Save to files data
                if self.current_user not in self.files_data:
                    self.files_data[self.current_user] = {}
                self.files_data[self.current_user]['private_key_loaded'] = datetime.datetime.now().isoformat()
                self.files_data[self.current_user]['private_key_file'] = os.path.basename(path)
                self.save_files_data()
                
                messagebox.showinfo("Success", f"Private key loaded successfully!\nKey size: {key_size} bits")
                
            except Exception as e:
                error_msg = f"Failed to load private key: {str(e)}"
                messagebox.showerror("Error", error_msg)
                self.log_action(self.current_user, "PRIVATE_KEY_LOAD_FAILED", error_msg)

    def update_key_status(self):
        """Update key status display"""
        if self.public_key and self.private_key:
            self.key_status_label.configure(text="Both keys loaded", text_color="#4caf50")
        elif self.public_key:
            self.key_status_label.configure(text="Public key only", text_color="#ff9800")
        elif self.private_key:
            self.key_status_label.configure(text="Private key only", text_color="#ff9800")
        else:
            self.key_status_label.configure(text="No keys loaded", text_color="#f44336")

    def select_file(self):
        """Select file for encryption"""
        file_path = filedialog.askopenfilename(
            title="Select file to encrypt",
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
            self.selected_file_label.configure(text=f"Selected: {filename}")

            # Get file info for logging
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(filename)[1] if '.' in filename else 'no extension'
            
            # Load and display file content
            self.load_file_content(file_path)
            self.status_label.configure(text=f"File selected: {filename}")
            self.log_action(self.current_user, "FILE_SELECTED_ENCRYPT", 
                          f"Selected file for encryption: {filename} ({file_size:,} bytes, {file_ext})")

    def select_locked_file(self):
        """Select .locked file for decryption"""
        file_path = filedialog.askopenfilename(
            title="Select .locked file to decrypt",
            filetypes=[("Encrypted files", "*.locked"), ("All files", "*.*")]
        )

        if file_path:
            self.selected_file_path = file_path
            filename = os.path.basename(file_path)
            self.selected_file_label.configure(text=f"Encrypted: {filename}")

            # Get file info for logging
            file_size = os.path.getsize(file_path)
            
            # Load encrypted file preview
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                    preview = f"[ENCRYPTED FILE - {len(data)} bytes]\n\nBase64 preview (first 500 chars):\n{base64.b64encode(data[:200]).decode()}..."
                    
                self.original_text.delete("1.0", "end")
                self.original_text.insert("1.0", preview)
                self.tabview.set("Original Content")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load encrypted file: {str(e)}")

            self.status_label.configure(text=f"Encrypted file selected: {filename}")
            self.log_action(self.current_user, "FILE_SELECTED_DECRYPT", 
                          f"Selected encrypted file: {filename} ({file_size:,} bytes)")

    def load_file_content(self, file_path):
        """Load and display file content in original tab"""
        try:
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Try to read as text first
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                content_type = "text"
            except UnicodeDecodeError:
                # For binary files, show info and base64 preview
                with open(file_path, 'rb') as file:
                    binary_content = file.read()
                    content = f"[BINARY FILE - {len(binary_content)} bytes]\n\nBase64 representation (first 500 chars):\n{base64.b64encode(binary_content[:200]).decode()}..."
                content_type = "binary"

            self.original_text.delete("1.0", "end")
            self.original_text.insert("1.0", content)
            self.tabview.set("Original Content")

            # Save file info with detailed logging
            if self.current_user not in self.files_data:
                self.files_data[self.current_user] = {}
            self.files_data[self.current_user]['last_file'] = filename
            self.files_data[self.current_user]['last_file_size'] = file_size
            self.files_data[self.current_user]['last_file_type'] = content_type
            self.files_data[self.current_user]['last_accessed'] = datetime.datetime.now().isoformat()
            self.save_files_data()
            
            self.log_action(self.current_user, "FILE_CONTENT_LOADED", 
                          f"Loaded {content_type} content from {filename} ({file_size:,} bytes)")

        except Exception as e:
            error_msg = f"Failed to load file content: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_action(self.current_user, "FILE_LOAD_FAILED", error_msg)

    def encrypt_file(self):
        """Encrypt the selected file using RSA+AES hybrid encryption"""
        if not self.selected_file_path:
            messagebox.showerror("Error", "No file selected. Please select a file first.")
            return

        if not self.public_key:
            messagebox.showerror("Error", "No public key loaded. Please load or generate a public key first.")
            return

        try:
            filename = os.path.basename(self.selected_file_path)
            self.log_action(self.current_user, "ENCRYPTION_STARTED", f"Started encryption process for: {filename}")
            
            # Read file in binary mode
            with open(self.selected_file_path, 'rb') as f:
                file_data = f.read()

            original_size = len(file_data)
            
            # Generate random AES key and IV
            aes_key = secrets.token_bytes(32)  # AES-256
            iv = secrets.token_bytes(16)       # 128-bit IV

            # Encrypt file data with AES-CFB
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()

            # Encrypt AES key with RSA
            encrypted_aes_key = self.public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Combine: IV + encrypted_aes_key + "::" + encrypted_data
            final_content = iv + encrypted_aes_key + b"::" + encrypted_data
            encrypted_size = len(final_content)

            # Save as .locked file
            locked_file_path = self.selected_file_path + ".locked"
            with open(locked_file_path, 'wb') as f:
                f.write(final_content)

            # Display encrypted content preview
            encrypted_preview = f"[ENCRYPTED FILE - {len(final_content)} bytes]\n\nBase64 preview (first 500 chars):\n{base64.b64encode(final_content[:200]).decode()}..."
            self.encrypted_text.delete("1.0", "end")
            self.encrypted_text.insert("1.0", encrypted_preview)
            self.tabview.set("Encrypted Content")

            self.status_label.configure(text=f"File encrypted: {os.path.basename(locked_file_path)}")
            
            # Log detailed encryption success
            compression_ratio = (encrypted_size / original_size) * 100 if original_size > 0 else 0
            self.log_action(self.current_user, "FILE_ENCRYPTED", 
                          f"Successfully encrypted {filename} using RSA-OAEP+AES-256-CFB | Original: {original_size:,} bytes -> Encrypted: {encrypted_size:,} bytes ({compression_ratio:.1f}% of original)")

            # Save encryption info with detailed metadata
            if self.current_user not in self.files_data:
                self.files_data[self.current_user] = {}
            self.files_data[self.current_user]['encryption_timestamp'] = datetime.datetime.now().isoformat()
            self.files_data[self.current_user]['encrypted_file'] = os.path.basename(locked_file_path)
            self.files_data[self.current_user]['original_file_size'] = original_size
            self.files_data[self.current_user]['encrypted_file_size'] = encrypted_size
            self.files_data[self.current_user]['encryption_algorithm'] = "RSA-OAEP + AES-256-CFB"
            self.files_data[self.current_user]['last_operation'] = "encrypt"
            self.save_files_data()

            messagebox.showinfo("Success", f"File encrypted successfully!\n\nOriginal: {original_size:,} bytes\nEncrypted: {encrypted_size:,} bytes\nSaved as: {os.path.basename(locked_file_path)}")

        except Exception as e:
            error_msg = f"Encryption failed: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_action(self.current_user, "ENCRYPTION_FAILED", f"Encryption failed for {filename}: {str(e)}")

    def decrypt_file(self):
        """Decrypt the selected .locked file using RSA+AES hybrid decryption"""
        if not self.selected_file_path:
            messagebox.showerror("Error", "No file selected. Please select a .locked file first.")
            return

        if not self.private_key:
            messagebox.showerror("Error", "No private key loaded. Please load the private key first.")
            return

        if not self.selected_file_path.endswith('.locked'):
            messagebox.showerror("Error", "Please select a .locked file for decryption.")
            return

        try:
            filename = os.path.basename(self.selected_file_path)
            self.log_action(self.current_user, "DECRYPTION_STARTED", f"Started decryption process for: {filename}")
            
            # Read encrypted file
            with open(self.selected_file_path, 'rb') as f:
                encrypted_content = f.read()

            encrypted_size = len(encrypted_content)
            
            # Extract IV (first 16 bytes)
            iv = encrypted_content[:16]
            rest = encrypted_content[16:]

            # Split encrypted AES key and encrypted data
            encrypted_aes_key, encrypted_data = rest.split(b"::", 1)

            # Decrypt AES key with RSA private key
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt file data with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            original_size = len(decrypted_data)
            
            # Save decrypted file (remove .locked extension)
            original_filename = self.selected_file_path.replace('.locked', '')
            decrypted_file_path = filedialog.asksaveasfilename(
                title="Save decrypted file as",
                initialfile=os.path.basename(original_filename)
            )

            if decrypted_file_path:
                with open(decrypted_file_path, 'wb') as f:
                    f.write(decrypted_data)

                # Display decrypted content preview
                try:
                    # Try to display as text
                    content_preview = decrypted_data.decode('utf-8')
                    if len(content_preview) > 1000:
                        content_preview = content_preview[:1000] + "\n\n... [Content truncated]"
                    content_type = "text"
                except UnicodeDecodeError:
                    # Binary file
                    content_preview = f"[BINARY FILE DECRYPTED - {len(decrypted_data)} bytes]\n\nBase64 preview (first 500 chars):\n{base64.b64encode(decrypted_data[:200]).decode()}..."
                    content_type = "binary"

                self.decrypted_text.delete("1.0", "end")
                self.decrypted_text.insert("1.0", content_preview)
                self.tabview.set("Decrypted Content")

                self.status_label.configure(text=f"File decrypted: {os.path.basename(decrypted_file_path)}")

                # Log detailed decryption success
                compression_ratio = (encrypted_size / original_size) * 100 if original_size > 0 else 0
                self.log_action(self.current_user, "FILE_DECRYPTED", 
                              f"Successfully decrypted {filename} using RSA-OAEP+AES-256-CFB | Encrypted: {encrypted_size:,} bytes -> Decrypted: {original_size:,} bytes | Content type: {content_type}")

                # Save decryption info with detailed metadata
                if self.current_user not in self.files_data:
                    self.files_data[self.current_user] = {}
                self.files_data[self.current_user]['last_decryption'] = datetime.datetime.now().isoformat()
                self.files_data[self.current_user]['decrypted_file'] = os.path.basename(decrypted_file_path)
                self.files_data[self.current_user]['decrypted_file_size'] = original_size
                self.files_data[self.current_user]['decryption_source'] = filename
                self.files_data[self.current_user]['decrypted_content_type'] = content_type
                self.files_data[self.current_user]['last_operation'] = "decrypt"
                self.save_files_data()

                messagebox.showinfo("Success", f"File decrypted successfully!\n\nEncrypted: {encrypted_size:,} bytes\nDecrypted: {original_size:,} bytes\nContent type: {content_type}\nSaved as: {os.path.basename(decrypted_file_path)}")

        except Exception as e:
            error_msg = f"Decryption failed: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_action(self.current_user, "DECRYPTION_FAILED", f"Decryption failed for {filename}: {str(e)}")

    def save_encrypted_file(self):
        """Save encrypted content to file (if available in preview)"""
        encrypted_content = self.encrypted_text.get("1.0", "end").strip()

        if not encrypted_content or "[ENCRYPTED FILE" not in encrypted_content:
            messagebox.showerror("Error", "No encrypted content available to save.")
            self.log_action(self.current_user, "SAVE_ENCRYPTED_FAILED", "No encrypted content available to save")
            return

        self.log_action(self.current_user, "SAVE_ENCRYPTED_INFO_SHOWN", "User viewed info about encrypted file saving")
        messagebox.showinfo("Info", "Encrypted files are automatically saved with .locked extension during encryption process.")

    def save_decrypted_file(self):
        """Save decrypted content to file"""
        decrypted_content = self.decrypted_text.get("1.0", "end").strip()

        if not decrypted_content:
            messagebox.showerror("Error", "No decrypted content to save.")
            self.log_action(self.current_user, "SAVE_DECRYPTED_FAILED", "No decrypted content available to save")
            return

        if "[BINARY FILE DECRYPTED" in decrypted_content:
            self.log_action(self.current_user, "SAVE_DECRYPTED_INFO_SHOWN", "User viewed info about binary file saving")
            messagebox.showinfo("Info", "Binary files are automatically saved during the decryption process.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save decrypted content",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(decrypted_content)

                filename = os.path.basename(file_path)
                file_size = len(decrypted_content.encode('utf-8'))
                self.status_label.configure(text=f"Decrypted content saved: {filename}")
                
                self.log_action(self.current_user, "DECRYPTED_CONTENT_SAVED", 
                              f"Saved decrypted text content: {filename} ({file_size:,} bytes)")
                
                # Update files data
                if self.current_user not in self.files_data:
                    self.files_data[self.current_user] = {}
                self.files_data[self.current_user]['manual_save_timestamp'] = datetime.datetime.now().isoformat()
                self.files_data[self.current_user]['manual_save_file'] = filename
                self.save_files_data()
                
                messagebox.showinfo("Success", f"Decrypted content saved successfully!\nFile: {filename}\nSize: {file_size:,} bytes")

            except Exception as e:
                error_msg = f"Failed to save decrypted content: {str(e)}"
                messagebox.showerror("Error", error_msg)
                self.log_action(self.current_user, "SAVE_DECRYPTED_FAILED", error_msg)

    def clear_lists(self):
        """Clear all file lists and reset content views"""
        self.log_action(self.current_user, "CLEAR_LISTS_STARTED", "User initiated clearing of all lists and content")
        
        self.encrypted_files.clear()
        self.decryption_files.clear()
        self.selected_file_path = None
        
        # Clear all text boxes
        self.original_text.delete("1.0", "end")
        self.encrypted_text.delete("1.0", "end")
        self.decrypted_text.delete("1.0", "end")
        
        # Reset file selection label
        self.selected_file_label.configure(text="No file selected")
        
        # Switch to original content tab
        self.tabview.set("Original Content")
        
        self.status_label.configure(text="Lists cleared, ready for new operations")
        self.log_action(self.current_user, "LISTS_CLEARED", "Successfully cleared all file lists, content views, and reset interface")

    def view_file_info(self):
        """View current file information"""
        if not self.selected_file_path:
            messagebox.showinfo("No File", "No file selected. Please select a file first.")
            self.log_action(self.current_user, "FILE_INFO_NO_FILE", "User attempted to view file info with no file selected")
            return

        try:
            file_stats = os.stat(self.selected_file_path)
            file_size = file_stats.st_size
            modified_time = datetime.datetime.fromtimestamp(file_stats.st_mtime)
            created_time = datetime.datetime.fromtimestamp(file_stats.st_ctime)

            # Get user's file data
            user_file_data = self.files_data.get(self.current_user, {})

            # Determine file type
            file_type = "Encrypted (.locked)" if self.selected_file_path.endswith('.locked') else "Original"
            file_ext = os.path.splitext(self.selected_file_path)[1] if '.' in self.selected_file_path else 'no extension'
            
            # Key status
            key_status = ""
            if self.public_key and self.private_key:
                pub_key_size = self.public_key.key_size
                priv_key_size = self.private_key.key_size
                key_status = f"Both keys available ({pub_key_size}-bit) - Encrypt & Decrypt ready"
            elif self.public_key:
                key_size = self.public_key.key_size
                key_status = f"Public key only ({key_size}-bit) - Encrypt only"
            elif self.private_key:
                key_size = self.private_key.key_size
                key_status = f"Private key only ({key_size}-bit) - Decrypt only"
            else:
                key_status = "No keys loaded"

            info = f"""FILE INFORMATION
==================

Name: {os.path.basename(self.selected_file_path)}
Path: {self.selected_file_path}
Size: {file_size:,} bytes ({file_size/1024:.1f} KB)
Extension: {file_ext}
Type: {file_type}
Modified: {modified_time.strftime('%Y-%m-%d %H:%M:%S')}
Created: {created_time.strftime('%Y-%m-%d %H:%M:%S')}
User: {self.current_user}

ENCRYPTION STATUS:
{key_status}
Encrypted Content: {"Available" if self.encrypted_text.get("1.0", "end").strip() else "Not available"}
Decrypted Content: {"Available" if self.decrypted_text.get("1.0", "end").strip() else "Not available"}

USER ACTIVITY LOG:
Last Accessed: {user_file_data.get('last_accessed', 'Never')}
Last Encryption: {user_file_data.get('encryption_timestamp', 'Never')}
Last Decryption: {user_file_data.get('last_decryption', 'Never')}
Key Generated: {user_file_data.get('key_generated', 'Never')}
Public Key Loaded: {user_file_data.get('public_key_loaded', 'Never')}
Private Key Loaded: {user_file_data.get('private_key_loaded', 'Never')}

RECENT OPERATIONS:
Last Operation: {user_file_data.get('last_operation', 'None')}
Last Encrypted File: {user_file_data.get('encrypted_file', 'None')}
Last Decrypted File: {user_file_data.get('decrypted_file', 'None')}
Manual Save: {user_file_data.get('manual_save_timestamp', 'Never')}

FILE SIZE HISTORY:
Original File Size: {user_file_data.get('original_file_size', 'N/A')} bytes
Encrypted File Size: {user_file_data.get('encrypted_file_size', 'N/A')} bytes
Decrypted File Size: {user_file_data.get('decrypted_file_size', 'N/A')} bytes

ENCRYPTION METHOD:
Algorithm: {user_file_data.get('encryption_algorithm', 'RSA-OAEP + AES-256-CFB')}
Key Exchange: RSA-OAEP with SHA-256
Symmetric: AES-256 in CFB mode with random IV
Content Type: {user_file_data.get('last_file_type', 'Unknown')}
"""

            # Create a new window for file info
            info_window = ctk.CTkToplevel(self.root)
            info_window.title("File Information")
            info_window.geometry("700x600")
            info_window.configure(fg_color="#1a1a2e")

            # Make window stay on top
            info_window.attributes('-topmost', True)

            # Info text
            info_textbox = ctk.CTkTextbox(info_window, height=550, 
                                         font=("Courier New", 11),
                                         fg_color="#16213e")
            info_textbox.pack(fill="both", expand=True, padx=20, pady=20)
            info_textbox.insert("1.0", info)
            info_textbox.configure(state="disabled")

            self.log_action(self.current_user, "FILE_INFO_VIEWED", 
                          f"Viewed detailed info for: {os.path.basename(self.selected_file_path)} ({file_size:,} bytes, {file_type})")

        except Exception as e:
            error_msg = f"Failed to get file info: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_action(self.current_user, "FILE_INFO_ERROR", error_msg)

    def log_action(self, username, action, details):
        """Log user actions with timestamp and enhanced metadata"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "username": username,
            "action": action,
            "details": details,
            "client_version": "v2.0_RSA+AES_Enhanced",
            "session_id": f"client_{username}_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}",
            "log_level": self.get_log_level(action)
        }
        
        # Ensure logs_data exists and is a list
        if not hasattr(self, 'logs_data') or not isinstance(self.logs_data, list):
            self.logs_data = []
            
        self.logs_data.append(log_entry)
        self.save_logs()

    def get_log_level(self, action):
        """Determine log level based on action type"""
        high_priority_actions = [
            "KEY_PAIR_GENERATED", "KEY_GENERATION_FAILED", "FILE_ENCRYPTED", "FILE_DECRYPTED",
            "ENCRYPTION_FAILED", "DECRYPTION_FAILED", "CLIENT_LOGIN_V2"
        ]
        medium_priority_actions = [
            "PUBLIC_KEY_LOADED", "PRIVATE_KEY_LOADED", "FILE_SELECTED_ENCRYPT", "FILE_SELECTED_DECRYPT",
            "FILE_CONTENT_LOADED"
        ]
        
        if action in high_priority_actions:
            return "HIGH"
        elif action in medium_priority_actions:
            return "MEDIUM"
        else:
            return "LOW"

    def logout(self):
        """Handle user logout"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            # Log logout with session summary
            session_duration = "Unknown"
            user_data = self.files_data.get(self.current_user, {})
            if 'session_start' in user_data:
                try:
                    start_time = datetime.datetime.fromisoformat(user_data['session_start'])
                    duration = datetime.datetime.now() - start_time
                    session_duration = f"{duration.total_seconds():.0f} seconds"
                except:
                    pass
            
            self.log_action(self.current_user, "LOGOUT", 
                          f"User logged out from client interface v2.0 | Session duration: {session_duration}")
            
            self.root.destroy()
            # Call back to main app
            try:
                self.main_app.show_dashboard()
            except Exception:
                pass

    def run(self):
        """Run the client interface"""
        # Log the login to client interface with session info
        session_start = datetime.datetime.now().isoformat()
        if self.current_user not in self.files_data:
            self.files_data[self.current_user] = {}
        self.files_data[self.current_user]['session_start'] = session_start
        self.save_files_data()
        
        self.log_action(self.current_user, "CLIENT_LOGIN_V2", 
                      f"User accessed client interface v2.0 (RSA+AES Enhanced) | Session started at {session_start}")
        self.root.mainloop()


if __name__ == "__main__":
    # For testing purposes
    class MockMainApp:
        def show_dashboard(self):
            print("Returning to main dashboard")

    client = ClientInterface(MockMainApp(), "testuser")
    client.run()