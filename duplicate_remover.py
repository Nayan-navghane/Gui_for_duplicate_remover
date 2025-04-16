import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Function to hash file contents
def hash_file(path):
    hasher = hashlib.sha1()
    try:
        with open(path, 'rb') as file:
            buf = file.read(65536)
            while buf:
                hasher.update(buf)
                buf = file.read(65536)
        return hasher.hexdigest()
    except:
        return None

# Function to scan for duplicates
def find_duplicates(folder):
    hashes = {}
    duplicates = []

    for dirpath, _, filenames in os.walk(folder):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            file_hash = hash_file(full_path)
            if file_hash:
                if file_hash in hashes:
                    duplicates.append((filename, full_path))
                else:
                    hashes[file_hash] = full_path
    return duplicates

# GUI setup
class DuplicateFinderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Duplicate File Finder")
        self.root.geometry("700x500")

        self.path = tk.StringVar()

        # Folder selection
        frame = tk.Frame(root)
        frame.pack(pady=10)

        tk.Label(frame, text="Select Folder:").pack(side=tk.LEFT, padx=5)
        tk.Entry(frame, textvariable=self.path, width=50).pack(side=tk.LEFT, padx=5)
        tk.Button(frame, text="Browse", command=self.browse_folder).pack(side=tk.LEFT)

        # Scan Button
        tk.Button(root, text="Scan for Duplicates", command=self.scan).pack(pady=10)

        # Treeview for results
        self.tree = ttk.Treeview(root, columns=("Filename", "Path"), show='headings', height=15)
        self.tree.heading("Filename", text="Filename")
        self.tree.heading("Path", text="Full Path")
        self.tree.column("Filename", width=150)
        self.tree.column("Path", width=500)
        self.tree.pack(padx=10, pady=10)

        # Delete button
        tk.Button(root, text="Delete Selected", command=self.delete_selected).pack(pady=10)

    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        self.path.set(folder_selected)

    def scan(self):
        folder = self.path.get()
        if not folder:
            messagebox.showwarning("Warning", "Please select a folder.")
            return

        self.tree.delete(*self.tree.get_children())  # Clear previous results

        duplicates = find_duplicates(folder)

        for filename, filepath in duplicates:
            self.tree.insert("", "end", values=(filename, filepath))

        if not duplicates:
            messagebox.showinfo("Done", "No duplicate files found.")
        else:
            messagebox.showinfo("Done", f"Found {len(duplicates)} duplicate files.")

    def delete_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Delete", "No file selected.")
            return

        confirm = messagebox.askyesno("Confirm", "Are you sure you want to delete the selected files?")
        if confirm:
            for item in selected:
                filepath = self.tree.item(item)['values'][1]
                try:
                    os.remove(filepath)
                except Exception as e:
                    messagebox.showerror("Error", f"Could not delete {filepath}: {e}")
                self.tree.delete(item)
            messagebox.showinfo("Deleted", "Selected files deleted successfully.")

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateFinderApp(root)
    root.mainloop()
