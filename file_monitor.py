import os
import hashlib
from datetime import datetime
import mysql.connector
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# MySQL Database setup
def setup_database():
    conn = mysql.connector.connect(
        host="localhost",
        user="file_user",
        password="password",
        database="file_monitor"
    )
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS file_changes (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        file_path TEXT,
                        change_type VARCHAR(20),
                        hash TEXT,
                        timestamp DATETIME
                      )''')
    conn.commit()
    conn.close()

# Log file changes to the database
def log_change(file_path, change_type, file_hash):
    conn = mysql.connector.connect(
        host="localhost",
        user="file_user",
        password="password",
        database="file_monitor"
    )
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO file_changes (file_path, change_type, hash, timestamp) 
                      VALUES (%s, %s, %s, %s)''', (file_path, change_type, file_hash, datetime.now()))
    conn.commit()
    conn.close()

# Calculate file hash
def calculate_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

# File system event handler class
class FileIntegrityHandler(FileSystemEventHandler):
    def __init__(self, app):
        self.app = app

    def on_modified(self, event):
        if not event.is_directory:
            file_hash = calculate_hash(event.src_path)
            log_change(event.src_path, "Modified", file_hash)
            self.app.add_log(event.src_path, "Modified", file_hash)

    def on_created(self, event):
        if not event.is_directory:
            file_hash = calculate_hash(event.src_path)
            log_change(event.src_path, "Created", file_hash)
            self.app.add_log(event.src_path, "Created", file_hash)

    def on_deleted(self, event):
        if not event.is_directory:
            log_change(event.src_path, "Deleted", None)
            self.app.add_log(event.src_path, "Deleted", None)

# Main application class
class FileMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitor")

        self.observer = None

        # UI setup
        self.setup_ui()

        # Initialize database
        setup_database()

    def setup_ui(self):
        # Directory selection
        frame = ttk.Frame(self.root)
        frame.pack(padx=10, pady=10, fill="x")

        self.dir_path = tk.StringVar()

        ttk.Label(frame, text="Directory:").pack(side="left", padx=(0, 5))
        ttk.Entry(frame, textvariable=self.dir_path, width=50).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(frame, text="Browse", command=self.browse_directory).pack(side="left")

        # Start/Stop buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(padx=10, pady=(0, 10), fill="x")

        self.start_button = ttk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side="left", padx=(0, 5))

        self.stop_button = ttk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, state="disabled")
        self.stop_button.pack(side="left")

        # Logs display
        self.tree = ttk.Treeview(self.root, columns=("File Path", "Change Type", "Hash", "Timestamp"), show="headings")
        self.tree.heading("File Path", text="File Path")
        self.tree.heading("Change Type", text="Change Type")
        self.tree.heading("Hash", text="Hash")
        self.tree.heading("Timestamp", text="Timestamp")

        self.tree.column("File Path", width=300)
        self.tree.column("Change Type", width=100)
        self.tree.column("Hash", width=200)
        self.tree.column("Timestamp", width=150)

        self.tree.pack(padx=10, pady=(0, 10), fill="both", expand=True)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_path.set(directory)

    def start_monitoring(self):
        path_to_monitor = self.dir_path.get()

        if not os.path.exists(path_to_monitor):
            messagebox.showerror("Error", "The specified path does not exist.")
            return

        self.event_handler = FileIntegrityHandler(self)
        self.observer = Observer()
        self.observer.schedule(self.event_handler, path_to_monitor, recursive=True)
        self.observer.start()

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        messagebox.showinfo("Monitoring Started", f"Monitoring changes in: {path_to_monitor}")

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None

        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

        messagebox.showinfo("Monitoring Stopped", "File monitoring has been stopped.")

    def add_log(self, file_path, change_type, file_hash):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.tree.insert("", "end", values=(file_path, change_type, file_hash, timestamp))

# Run the application
def main():
    root = tk.Tk()
    app = FileMonitorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
