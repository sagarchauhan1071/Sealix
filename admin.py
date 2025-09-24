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
                json.dump(self.logs_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving logs: {e}")
    
    def load_files_data(self):
        """Load files data from file"""
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
        """Save files data to file"""
        try:
            with open(self.files_data_file, 'w', encoding='utf-8') as f:
                json.dump(self.files_data, f, indent=2, ensure_ascii=False)
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
        
        ctk.CTkLabel(activity_frame, text="RECENT SYSTEM ACTIVITY (Last 10 Actions)", 
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
        
        # Header with controls
        logs_header = ctk.CTkFrame(logs_tab, fg_color="transparent")
        logs_header.pack(fill="x", padx=20, pady=(15, 10))
        
        ctk.CTkLabel(logs_header, text="SYSTEM ACTIVITY LOGS", 
                   font=("Courier New", 18, "bold"),
                   text_color="#00ff41").pack(side="left")
        
        # Log filtering options
        filter_frame = ctk.CTkFrame(logs_header, fg_color="#1a1a1a", corner_radius=10)
        filter_frame.pack(side="right", padx=(20, 0))
        
        ctk.CTkLabel(filter_frame, text="Filter:", 
                   font=("Courier New", 10, "bold"),
                   text_color="#ffffff").pack(side="left", padx=(10, 5))
        
        self.log_filter_var = ctk.StringVar(value="ALL")
        filter_options = ["ALL", "LOGIN", "LOGOUT", "ENCRYPTION", "DECRYPTION", "KEY_OPERATIONS", "ERRORS"]
        
        self.log_filter_dropdown = ctk.CTkOptionMenu(filter_frame, 
                                                   values=filter_options,
                                                   variable=self.log_filter_var,
                                                   command=self.filter_logs,
                                                   font=("Courier New", 9),
                                                   width=120)
        self.log_filter_dropdown.pack(side="left", padx=(0, 10), pady=5)
        
        # Logs display
        self.logs_text = ctk.CTkTextbox(logs_tab, height=480,
                                      font=("Courier New", 10),
                                      fg_color="#0a0a0a")
        self.logs_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
    
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
                with open(self.users_file, 'r', encoding='utf-8') as f:
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
                    
                    # Add user activity summary from logs
                    user_logs = [log for log in self.logs_data if log.get('username') == username]
                    if user_logs:
                        last_activity = max(user_logs, key=lambda x: x.get('timestamp', ''))
                        user_display += f"LAST ACTIVITY: {last_activity.get('timestamp', 'N/A')} - {last_activity.get('action', 'N/A')}\n"
                        user_display += f"TOTAL ACTIONS: {len(user_logs)}\n"
                    else:
                        user_display += f"LAST ACTIVITY: No activity recorded\n"
                        user_display += f"TOTAL ACTIONS: 0\n"
                    
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
    
    def load_logs_display(self, filter_type="ALL"):
        """Load and display system logs with optional filtering"""
        self.logs_text.delete("1.0", "end")
        
        if not self.logs_data:
            self.logs_text.insert("end", "No system logs available.")
            return 0
        
        # Filter logs based on selected filter
        filtered_logs = self.logs_data
        if filter_type != "ALL":
            if filter_type == "LOGIN":
                filtered_logs = [log for log in self.logs_data if "LOGIN" in log.get('action', '').upper()]
            elif filter_type == "LOGOUT":
                filtered_logs = [log for log in self.logs_data if "LOGOUT" in log.get('action', '').upper()]
            elif filter_type == "ENCRYPTION":
                filtered_logs = [log for log in self.logs_data if "ENCRYPT" in log.get('action', '').upper()]
            elif filter_type == "DECRYPTION":
                filtered_logs = [log for log in self.logs_data if "DECRYPT" in log.get('action', '').upper()]
            elif filter_type == "KEY_OPERATIONS":
                filtered_logs = [log for log in self.logs_data if "KEY" in log.get('action', '').upper()]
            elif filter_type == "ERRORS":
                filtered_logs = [log for log in self.logs_data if "FAILED" in log.get('action', '').upper() or "ERROR" in log.get('action', '').upper()]
        
        header = "=" * 80 + "\n"
        header += f"SYSTEM ACTIVITY LOGS - FILTER: {filter_type}\n"
        header += f"Showing {len(filtered_logs)} of {len(self.logs_data)} total logs\n"
        header += "=" * 80 + "\n\n"
        self.logs_text.insert("end", header)
        
        # Sort logs by timestamp (newest first)
        sorted_logs = sorted(filtered_logs, key=lambda x: x.get('timestamp', ''), reverse=True)
        
        for log in sorted_logs:
            # Enhanced log display with color coding based on action type
            timestamp = log.get('timestamp', 'N/A')
            username = log.get('username', 'SYSTEM')
            action = log.get('action', 'UNKNOWN')
            details = log.get('details', 'No details')
            
            # Add session info if available
            session_info = log.get('session_info', '')
            client_version = log.get('client_version', '')
            
            log_display = f"[{timestamp}] {username} - {action}\n"
            log_display += f"  Details: {details}\n"
            
            if session_info:
                log_display += f"  Session: {session_info}\n"
            if client_version:
                log_display += f"  Version: {client_version}\n"
            
            log_display += "-" * 60 + "\n\n"
            self.logs_text.insert("end", log_display)
        
        return len(filtered_logs)
    
    def filter_logs(self, selected_filter):
        """Handle log filtering when dropdown changes"""
        self.load_logs_display(selected_filter)
    
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
                    # Format timestamps for better readability
                    if key.endswith('_timestamp') or key.endswith('_accessed') or key.endswith('_loaded') or key.endswith('_generated'):
                        try:
                            if isinstance(value, str) and 'T' in value:
                                # ISO format timestamp
                                dt = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                                formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                                user_section += f"{key.upper().replace('_', ' ')}: {formatted_time}\n"
                            else:
                                user_section += f"{key.upper().replace('_', ' ')}: {value}\n"
                        except:
                            user_section += f"{key.upper().replace('_', ' ')}: {value}\n"
                    else:
                        user_section += f"{key.upper().replace('_', ' ')}: {value}\n"
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
        
        # Calculate active sessions (users who logged in within last 24 hours)
        current_time = datetime.datetime.now()
        active_sessions = 0
        
        for log in self.logs_data:
            if "LOGIN" in log.get('action', '').upper():
                try:
                    log_time = datetime.datetime.strptime(log.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
                    if (current_time - log_time).days == 0:  # Same day
                        active_sessions += 1
                except:
                    pass
        
        # Ensure at least 1 if admin is currently active
        if active_sessions == 0:
            active_sessions = 1
            
        self.active_sessions_label.configure(text=str(active_sessions))
        
        # Update recent activity (last 10 activities)
        self.update_recent_activity()
    
    def update_recent_activity(self):
        """Update the recent activity display on dashboard"""
        self.activity_text.delete("1.0", "end")
        
        activity_header = "=== RECENT SYSTEM ACTIVITY (Last 10 Actions) ===\n\n"
        self.activity_text.insert("end", activity_header)
        
        if self.logs_data:
            # Show last 10 logs, sorted by timestamp (newest first)
            recent_logs = sorted(self.logs_data, key=lambda x: x.get('timestamp', ''), reverse=True)[:10]
            
            for i, log in enumerate(recent_logs, 1):
                timestamp = log.get('timestamp', 'N/A')
                username = log.get('username', 'SYSTEM')
                action = log.get('action', 'UNKNOWN')
                details = log.get('details', 'No details')
                
                # Truncate long details for dashboard view
                if len(details) > 60:
                    details = details[:57] + "..."
                
                activity_line = f"{i:2d}. [{timestamp}] {username}\n"
                activity_line += f"    Action: {action}\n"
                activity_line += f"    Details: {details}\n\n"
                
                self.activity_text.insert("end", activity_line)
        else:
            self.activity_text.insert("end", "No recent activity recorded.")
    
    def log_action(self, username, action, details):
        """Log system actions with enhanced information"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "username": username,
            "action": action,
            "details": details,
            "source": "ADMIN_INTERFACE",
            "session_info": "Admin Dashboard"
        }
        self.logs_data.append(log_entry)
        self.save_logs()
    
    def refresh_all_data(self):
        """Refresh all data"""
        self.log_action("ADMIN", "DATA_REFRESH_START", "Admin initiated full data refresh")
        
        try:
            # Reload data from files
            self.load_logs()
            self.load_files_data()
            
            # Update all displays
            self.update_dashboard_stats()
            self.load_logs_display(self.log_filter_var.get())
            self.load_files_display()
            
            # Log successful refresh
            self.log_action("ADMIN", "DATA_REFRESH_SUCCESS", 
                          f"All data refreshed successfully - {len(self.logs_data)} logs, {len(self.files_data)} user files")
            
            messagebox.showinfo("✅ Success", "All data refreshed successfully!")
            
        except Exception as e:
            self.log_action("ADMIN", "DATA_REFRESH_FAILED", f"Data refresh failed: {str(e)}")
            messagebox.showerror("❌ Error", f"Failed to refresh data: {str(e)}")
    
    def clear_logs(self):
        """Clear system logs with confirmation"""
        if messagebox.askyesno("Clear Logs", 
                              f"Are you sure you want to clear all {len(self.logs_data)} system logs?\n\nThis action cannot be undone."):
            
            # Log the clear action before clearing
            old_count = len(self.logs_data)
            self.log_action("ADMIN", "LOGS_CLEAR_INITIATED", 
                          f"Admin initiated clearing of {old_count} system logs")
            
            # Clear logs but keep the clear action log
            clear_log = self.logs_data[-1]  # Keep the last log entry (the clear action)
            self.logs_data = [clear_log]
            
            self.save_logs()
            self.load_logs_display(self.log_filter_var.get())
            self.update_dashboard_stats()
            
            messagebox.showinfo("✅ Success", f"System logs cleared successfully!\nCleared {old_count} log entries.")
    
    def export_data(self):
        """Export system data with enhanced information"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Load current users data
            users_data = {}
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    users_data = json.load(f)
            
            # Create comprehensive export data
            export_data = {
                "export_info": {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "exported_by": "ADMIN",
                    "total_users": len(users_data),
                    "total_logs": len(self.logs_data),
                    "total_file_records": len(self.files_data)
                },
                "users": users_data,
                "logs": self.logs_data,
                "files": self.files_data,
                "statistics": {
                    "most_active_user": self.get_most_active_user(),
                    "recent_activity_count": len([log for log in self.logs_data 
                                                if self.is_recent_activity(log.get('timestamp', ''))]),
                    "encryption_operations": len([log for log in self.logs_data 
                                               if 'ENCRYPT' in log.get('action', '').upper()]),
                    "decryption_operations": len([log for log in self.logs_data 
                                               if 'DECRYPT' in log.get('action', '').upper()])
                }
            }
            
            export_filename = f"securevault_admin_export_{timestamp}.json"
            with open(export_filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            self.log_action("ADMIN", "DATA_EXPORT_SUCCESS", 
                          f"System data exported to {export_filename} - {len(users_data)} users, {len(self.logs_data)} logs")
            
            messagebox.showinfo("✅ Export Complete", 
                              f"Data exported successfully to:\n{export_filename}\n\nExport includes:\n• {len(users_data)} users\n• {len(self.logs_data)} log entries\n• {len(self.files_data)} file records")
            
        except Exception as e:
            self.log_action("ADMIN", "DATA_EXPORT_FAILED", f"Export failed: {str(e)}")
            messagebox.showerror("❌ Export Error", f"Failed to export data: {str(e)}")
    
    def get_most_active_user(self):
        """Get the most active user from logs"""
        user_activity = {}
        for log in self.logs_data:
            username = log.get('username', 'UNKNOWN')
            if username != 'ADMIN' and username != 'SYSTEM':
                user_activity[username] = user_activity.get(username, 0) + 1
        
        if user_activity:
            return max(user_activity.items(), key=lambda x: x[1])
        return ("No user activity", 0)
    
    def is_recent_activity(self, timestamp_str):
        """Check if activity is within last 24 hours"""
        try:
            log_time = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            current_time = datetime.datetime.now()
            return (current_time - log_time).days == 0
        except:
            return False
    
    def back_to_main(self):
        """Return to main application"""
        self.log_action("ADMIN", "ADMIN_SESSION_END", "Admin logged out from dashboard")
        self.root.destroy()
        self.main_app.show_dashboard()
    
    def run(self):
        """Run the admin interface"""
        # Log admin session start
        self.log_action("ADMIN", "ADMIN_SESSION_START", 
                       f"Admin dashboard accessed at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
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