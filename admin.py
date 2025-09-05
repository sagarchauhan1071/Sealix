import customtkinter as ctk
from tkinter import messagebox, scrolledtext
import json
import hashlib
import datetime
import os
import base64
from cryptography.fernet import Fernet

class AdminInterface:
    def __init__(self, main_app):
        self.main_app = main_app
        self.users_file = "users_data.json"
        self.logs_file = "system_logs.json"
        self.files_data_file = "files_data.json"
        
        # Load data
        self.load_logs()
        self.load_files_data()
        
        # UI Setup
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")
        
        self.root = ctk.CTk()
        self.root.title("🛡️ SecureVault Admin Dashboard")
        self.root.geometry("1400x900")
        self.root.configure(fg_color="#0a0a0a")
        
        self.create_admin_gui()
        
    def load_logs(self):
        """Load system logs from file"""
        try:
            if os.path.exists(self.logs_file):
                with open(self.logs_file, 'r') as f:
                    self.logs_data = json.load(f)
            else:
                self.logs_data = []
        except Exception as e:
            print(f"Error loading logs: {e}")
            self.logs_data = []
    
    def save_logs(self):
        """Save logs to file"""
        try:
            with open(self.logs_file, 'w') as f:
                json.dump(self.logs_data, f, indent=2)
        except Exception as e:
            print(f"Error saving logs: {e}")
    
    def load_files_data(self):
        """Load files data from file"""
        try:
            if os.path.exists(self.files_data_file):
                with open(self.files_data_file, 'r') as f:
                    self.files_data = json.load(f)
            else:
                self.files_data = {}
        except Exception as e:
            print(f"Error loading files data: {e}")
            self.files_data = {}
    
    def save_files_data(self):
        """Save files data to file"""
        try:
            with open(self.files_data_file, 'w') as f:
                json.dump(self.files_data, f, indent=2)
        except Exception as e:
            print(f"Error saving files data: {e}")
    
    def create_admin_gui(self):
        """Create the admin GUI interface"""
        # Main container
        main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ctk.CTkFrame(main_container, fg_color="#1a1a1a", corner_radius=15)
        header_frame.pack(fill="x", pady=(0, 20))
        
        title_label = ctk.CTkLabel(header_frame, 
                                 text="🛡️ SECUREVAULT ADMIN DASHBOARD", 
                                 font=("Courier New", 28, "bold"),
                                 text_color="#ff4444")
        title_label.pack(pady=15)
        
        subtitle_label = ctk.CTkLabel(header_frame, 
                                    text="» System Administration & Security Monitoring «", 
                                    font=("Courier New", 14),
                                    text_color="#888888")
        subtitle_label.pack(pady=(0, 15))
        
        # Content area with tabs
        self.tabview = ctk.CTkTabview(main_container, height=600)
        self.tabview.pack(fill="both", expand=True)
        
        # Create tabs
        self.tabview.add("📊 Dashboard")
        self.tabview.add("👥 Users Data")
        self.tabview.add("📋 System Logs")
        self.tabview.add("📁 Files Data")
        
        # Setup tabs
        self.setup_dashboard_tab()
        self.setup_users_tab()
        self.setup_logs_tab()
        self.setup_files_tab()
        
        # Control buttons at bottom
        controls_frame = ctk.CTkFrame(main_container, fg_color="#1a1a1a", corner_radius=15)
        controls_frame.pack(fill="x", pady=(20, 0))
        
        buttons_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        buttons_frame.pack(pady=15)
        
        refresh_btn = ctk.CTkButton(buttons_frame, text="🔄 Refresh All Data", 
                                  command=self.refresh_all_data,
                                  font=("Courier New", 12, "bold"),
                                  fg_color="#2196f3", hover_color="#1976d2")
        refresh_btn.pack(side="left", padx=10)
        
        export_btn = ctk.CTkButton(buttons_frame, text="📤 Export Data", 
                                 command=self.export_data,
                                 font=("Courier New", 12, "bold"),
                                 fg_color="#ff9800", hover_color="#f57c00")
        export_btn.pack(side="left", padx=10)
        
        clear_logs_btn = ctk.CTkButton(buttons_frame, text="🧹 Clear Logs", 
                                     command=self.clear_logs,
                                     font=("Courier New", 12, "bold"),
                                     fg_color="#f44336", hover_color="#d32f2f")
        clear_logs_btn.pack(side="left", padx=10)
        
        back_btn = ctk.CTkButton(buttons_frame, text="🔙 Back to Main", 
                               command=self.back_to_main,
                               font=("Courier New", 12, "bold"),
                               fg_color="#6c757d", hover_color="#5a6268")
        back_btn.pack(side="right", padx=10)
    
    def setup_dashboard_tab(self):
        """Setup dashboard tab"""
        dashboard_tab = self.tabview.tab("📊 Dashboard")
        
        # Stats frame
        stats_frame = ctk.CTkFrame(dashboard_tab, fg_color="#1a1a1a")
        stats_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(stats_frame, text="SYSTEM STATISTICS", 
                   font=("Courier New", 18, "bold"),
                   text_color="#00ff41").pack(pady=15)
        
        # Stats grid
        stats_grid = ctk.CTkFrame(stats_frame, fg_color="transparent")
        stats_grid.pack(fill="x", padx=20, pady=10)
        
        # Total users
        users_frame = ctk.CTkFrame(stats_grid, fg_color="#4ecdc4", corner_radius=10)
        users_frame.pack(side="left", fill="x", expand=True, padx=5)
        
        ctk.CTkLabel(users_frame, text="Total Users", 
                   font=("Courier New", 14, "bold"),
                   text_color="#000000").pack(pady=5)
        
        self.total_users_label = ctk.CTkLabel(users_frame, text="0", 
                                            font=("Courier New", 24, "bold"),
                                            text_color="#000000")
        self.total_users_label.pack(pady=5)
        
        # Active sessions
        sessions_frame = ctk.CTkFrame(stats_grid, fg_color="#ffe66d", corner_radius=10)
        sessions_frame.pack(side="left", fill="x", expand=True, padx=5)
        
        ctk.CTkLabel(sessions_frame, text="Active Sessions", 
                   font=("Courier New", 14, "bold"),
                   text_color="#000000").pack(pady=5)
        
        self.active_sessions_label = ctk.CTkLabel(sessions_frame, text="1", 
                                                font=("Courier New", 24, "bold"),
                                                text_color="#000000")
        self.active_sessions_label.pack(pady=5)
        
        # Total logs
        logs_frame = ctk.CTkFrame(stats_grid, fg_color="#ff6b6b", corner_radius=10)
        logs_frame.pack(side="left", fill="x", expand=True, padx=5)
        
        ctk.CTkLabel(logs_frame, text="Total Logs", 
                   font=("Courier New", 14, "bold"),
                   text_color="#000000").pack(pady=5)
        
        self.total_logs_label = ctk.CTkLabel(logs_frame, text="0", 
                                           font=("Courier New", 24, "bold"),
                                           text_color="#000000")
        self.total_logs_label.pack(pady=5)
        
        # Recent activity
        activity_frame = ctk.CTkFrame(dashboard_tab, fg_color="#1a1a1a")
        activity_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        ctk.CTkLabel(activity_frame, text="RECENT SYSTEM ACTIVITY", 
                   font=("Courier New", 16, "bold"),
                   text_color="#00ff41").pack(pady=15)
        
        self.activity_text = ctk.CTkTextbox(activity_frame, height=300,
                                          font=("Courier New", 10),
                                          fg_color="#0a0a0a")
        self.activity_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
    
    def setup_users_tab(self):
        """Setup users data tab"""
        users_tab = self.tabview.tab("👥 Users Data")
        
        ctk.CTkLabel(users_tab, text="REGISTERED USERS DATA", 
                   font=("Courier New", 18, "bold"),
                   text_color="#00ff41").pack(pady=15)
        
        # Users display
        self.users_text = ctk.CTkTextbox(users_tab, height=500,
                                       font=("Courier New", 10),
                                       fg_color="#0a0a0a")
        self.users_text.pack(fill="both", expand=True, padx=20, pady=20)
    
    def setup_logs_tab(self):
        """Setup system logs tab"""
        logs_tab = self.tabview.tab("📋 System Logs")
        
        ctk.CTkLabel(logs_tab, text="SYSTEM ACTIVITY LOGS", 
                   font=("Courier New", 18, "bold"),
                   text_color="#00ff41").pack(pady=15)
        
        # Logs display
        self.logs_text = ctk.CTkTextbox(logs_tab, height=500,
                                      font=("Courier New", 10),
                                      fg_color="#0a0a0a")
        self.logs_text.pack(fill="both", expand=True, padx=20, pady=20)
    
    def setup_files_tab(self):
        """Setup files data tab"""
        files_tab = self.tabview.tab("📁 Files Data")
        
        ctk.CTkLabel(files_tab, text="USER FILES & ENCRYPTION DATA", 
                   font=("Courier New", 18, "bold"),
                   text_color="#00ff41").pack(pady=15)
        
        # Files display
        self.files_text = ctk.CTkTextbox(files_tab, height=500,
                                       font=("Courier New", 10),
                                       fg_color="#0a0a0a")
        self.files_text.pack(fill="both", expand=True, padx=20, pady=20)
    
    def load_users_data(self):
        """Load and display users data"""
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    users_data = json.load(f)
                
                self.users_text.delete("1.0", "end")
                
                header = "=" * 80 + "\n"
                header += "USERS DATABASE - ADMIN VIEW (INCLUDING PASSWORD HASHES)\n"
                header += "=" * 80 + "\n\n"
                self.users_text.insert("end", header)
                
                for username, user_info in users_data.items():
                    user_display = f"USERNAME: {username}\n"
                    user_display += f"ROLE: {user_info.get('role', 'user').upper()}\n"
                    user_display += f"PASSWORD HASH: {user_info.get('password', 'N/A')}\n"
                    user_display += f"REGISTERED: {user_info.get('timestamp', 'N/A')}\n"
                    user_display += "-" * 60 + "\n\n"
                    self.users_text.insert("end", user_display)
                
                return len(users_data)
            else:
                self.users_text.delete("1.0", "end")
                self.users_text.insert("end", "No users data file found.")
                return 0
        except Exception as e:
            self.users_text.delete("1.0", "end")
            self.users_text.insert("end", f"Error loading users data: {str(e)}")
            return 0
    
    def load_logs_display(self):
        """Load and display system logs"""
        self.logs_text.delete("1.0", "end")
        
        if not self.logs_data:
            self.logs_text.insert("end", "No system logs available.")
            return 0
        
        header = "=" * 80 + "\n"
        header += "SYSTEM ACTIVITY LOGS\n"
        header += "=" * 80 + "\n\n"
        self.logs_text.insert("end", header)
        
        # Sort logs by timestamp (newest first)
        sorted_logs = sorted(self.logs_data, key=lambda x: x.get('timestamp', ''), reverse=True)
        
        for log in sorted_logs:
            log_display = f"[{log.get('timestamp', 'N/A')}] "
            log_display += f"{log.get('username', 'SYSTEM')} - "
            log_display += f"{log.get('action', 'UNKNOWN')}: "
            log_display += f"{log.get('details', 'No details')}\n"
            self.logs_text.insert("end", log_display)
        
        return len(self.logs_data)
    
    def load_files_display(self):
        """Load and display files data"""
        self.files_text.delete("1.0", "end")
        
        if not self.files_data:
            self.files_text.insert("end", "No files data available.")
            return 0
        
        header = "=" * 80 + "\n"
        header += "USER FILES & ENCRYPTION DATA\n"
        header += "=" * 80 + "\n\n"
        self.files_text.insert("end", header)
        
        for username, files_info in self.files_data.items():
            user_section = f"USER: {username}\n"
            user_section += "-" * 40 + "\n"
            
            if isinstance(files_info, dict):
                for key, value in files_info.items():
                    user_section += f"{key.upper()}: {value}\n"
            else:
                user_section += f"DATA: {files_info}\n"
            
            user_section += "\n"
            self.files_text.insert("end", user_section)
        
        return len(self.files_data)
    
    def update_dashboard_stats(self):
        """Update dashboard statistics"""
        # Update user count
        total_users = self.load_users_data()
        self.total_users_label.configure(text=str(total_users))
        
        # Update logs count
        total_logs = len(self.logs_data)
        self.total_logs_label.configure(text=str(total_logs))
        
        # Update recent activity
        self.activity_text.delete("1.0", "end")
        
        activity_header = "=== RECENT SYSTEM ACTIVITY ===\n\n"
        self.activity_text.insert("end", activity_header)
        
        if self.logs_data:
            # Show last 10 logs
            recent_logs = sorted(self.logs_data, key=lambda x: x.get('timestamp', ''), reverse=True)[:10]
            
            for log in recent_logs:
                activity_line = f"[{log.get('timestamp', 'N/A')}] "
                activity_line += f"{log.get('username', 'SYSTEM')} - "
                activity_line += f"{log.get('action', 'UNKNOWN')}: "
                activity_line += f"{log.get('details', 'No details')}\n"
                self.activity_text.insert("end", activity_line)
        else:
            self.activity_text.insert("end", "No recent activity recorded.")
    
    def log_action(self, username, action, details):
        """Log system actions"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "username": username,
            "action": action,
            "details": details
        }
        self.logs_data.append(log_entry)
        self.save_logs()
    
    def refresh_all_data(self):
        """Refresh all data"""
        self.load_logs()
        self.load_files_data()
        self.update_dashboard_stats()
        self.load_logs_display()
        self.load_files_display()
        messagebox.showinfo("✅ Success", "All data refreshed successfully!")
        self.log_action("ADMIN", "DATA_REFRESH", "Admin refreshed all system data")
    
    def clear_logs(self):
        """Clear system logs"""
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear all system logs?"):
            self.logs_data = []
            self.save_logs()
            self.load_logs_display()
            self.update_dashboard_stats()
            messagebox.showinfo("✅ Success", "System logs cleared successfully!")
            self.log_action("ADMIN", "LOGS_CLEARED", "Admin cleared all system logs")
    
    def export_data(self):
        """Export system data"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Load current users data
            users_data = {}
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    users_data = json.load(f)
            
            export_data = {
                "export_timestamp": datetime.datetime.now().isoformat(),
                "users": users_data,
                "logs": self.logs_data,
                "files": self.files_data
            }
            
            export_filename = f"admin_export_{timestamp}.json"
            with open(export_filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            messagebox.showinfo("✅ Export Complete", f"Data exported successfully to:\n{export_filename}")
            self.log_action("ADMIN", "DATA_EXPORT", f"Admin exported system data to {export_filename}")
            
        except Exception as e:
            messagebox.showerror("❌ Export Error", f"Failed to export data: {str(e)}")
    
    def back_to_main(self):
        """Return to main application"""
        self.root.destroy()
        self.main_app.show_dashboard()
    
    def run(self):
        """Run the admin interface"""
        # Initial data load
        self.refresh_all_data()
        self.root.mainloop()

if __name__ == "__main__":
    # For testing purposes
    class MockMainApp:
        def show_dashboard(self):
            print("Returning to main dashboard")
    
    admin = AdminInterface(MockMainApp())
    admin.run()