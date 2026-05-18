import os
import sys
import struct
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Ensure we can import our core tool
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import save_repair_tool as srt
except ImportError:
    messagebox.showerror("Error", "Could not import save_repair_tool.py")
    sys.exit(1)

class DXHRSaveEditor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Deus Ex: HR Director's Cut - Save Editor/Forensics")
        self.geometry("800x600")
        self.current_file = None
        self.buf = None
        
        self.create_widgets()

    def create_widgets(self):
        # Toolbar
        toolbar = tk.Frame(self, bd=1, relief=tk.RAISED)
        toolbar.pack(side=tk.TOP, fill=tk.X)
        
        tk.Button(toolbar, text="Load Save", command=self.load_save).pack(side=tk.LEFT, padx=2, pady=2)
        tk.Button(toolbar, text="Save As...", command=self.save_as).pack(side=tk.LEFT, padx=2, pady=2)
        tk.Button(toolbar, text="Unpack to Raw (.dec)", command=self.unpack_save).pack(side=tk.LEFT, padx=2, pady=2)
        tk.Button(toolbar, text="Pack from Raw (.dec)", command=self.pack_save).pack(side=tk.LEFT, padx=2, pady=2)
        
        # Main content
        main_pane = tk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        
        # Left side: basic stats
        left_frame = tk.Frame(main_pane)
        main_pane.add(left_frame, minsize=250)
        
        tk.Label(left_frame, text="Progression Stats", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        self.stats_tree = ttk.Treeview(left_frame, columns=("Value",), show="tree headings", height=5)
        self.stats_tree.heading("#0", text="Field")
        self.stats_tree.heading("Value", text="Value")
        self.stats_tree.column("#0", width=120)
        self.stats_tree.column("Value", width=100)
        self.stats_tree.pack(fill=tk.X)
        
        # Right side: inventory
        right_frame = tk.Frame(main_pane)
        main_pane.add(right_frame, minsize=400)
        
        tk.Label(right_frame, text="Inventory Items (Detected)", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        cols = ("Name", "ID", "Count", "X", "Y", "Offset")
        self.inv_tree = ttk.Treeview(right_frame, columns=cols, show="headings")
        for c in cols:
            self.inv_tree.heading(c, text=c)
        self.inv_tree.column("Name", width=180)
        self.inv_tree.column("ID", width=80)
        self.inv_tree.column("Count", width=60, anchor=tk.E)
        self.inv_tree.column("X", width=50, anchor=tk.E)
        self.inv_tree.column("Y", width=50, anchor=tk.E)
        self.inv_tree.column("Offset", width=80)
        
        scrollbar = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.inv_tree.yview)
        self.inv_tree.configure(yscroll=scrollbar.set)
        
        self.inv_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready.")
        status_bar = tk.Label(self, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def load_save(self):
        path = filedialog.askopenfilename(title="Select DXHRDC Save File")
        if not path:
            return
            
        try:
            self.buf = srt.read_save(path)
            self.current_file = path
            self.status_var.set(f"Loaded: {os.path.basename(path)} ({len(self.buf):,} bytes decompressed)")
            self.refresh_ui()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load save:\n{e}")

    def save_as(self):
        if not self.buf:
            messagebox.showwarning("Warning", "No save file loaded.")
            return
            
        path = filedialog.asksaveasfilename(title="Save As", initialfile=os.path.basename(self.current_file) + "_mod")
        if not path:
            return
            
        try:
            srt.write_save(path, self.buf)
            self.status_var.set(f"Saved successfully to {os.path.basename(path)}")
            messagebox.showinfo("Success", "Save written successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save:\n{e}")

    def unpack_save(self):
        path = filedialog.askopenfilename(title="Select DXHRDC Save File to Unpack")
        if not path:
            return
        
        out_path = filedialog.asksaveasfilename(title="Save Raw Binary (.dec)", initialfile=os.path.basename(path) + ".dec")
        if not out_path:
            return
            
        try:
            buf = srt.read_save(path)
            with open(out_path, "wb") as f:
                f.write(buf)
            self.status_var.set(f"Unpacked to {os.path.basename(out_path)}")
            messagebox.showinfo("Success", f"Unpacked {len(buf):,} bytes to:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unpack:\n{e}")

    def pack_save(self):
        path = filedialog.askopenfilename(title="Select Raw Binary (.dec) to Pack")
        if not path:
            return
            
        out_path = filedialog.asksaveasfilename(title="Save As Packed Save", initialfile=os.path.basename(path).replace(".dec", ""))
        if not out_path:
            return
            
        try:
            with open(path, "rb") as f:
                buf = f.read()
            srt.write_save(out_path, buf)
            self.status_var.set(f"Packed from {os.path.basename(path)}")
            messagebox.showinfo("Success", f"Packed and saved to:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to pack:\n{e}")

    def refresh_ui(self):
        # Clear trees
        for item in self.stats_tree.get_children():
            self.stats_tree.delete(item)
        for item in self.inv_tree.get_children():
            self.inv_tree.delete(item)
            
        if not self.buf:
            return
            
        prog = srt.read_progression(self.buf)
        
        # Populate Stats
        if prog["snapshots"]:
            snap = prog["snapshots"][0] # Just show the first one
            self.stats_tree.insert("", tk.END, text="XP", values=(snap.get("xp", "N/A"),))
            self.stats_tree.insert("", tk.END, text="Praxis", values=(snap.get("praxis", "N/A"),))
            
        # Populate Inventory
        for item in prog["items"]:
            if item["status"] != "abs":
                x = "?"
                y = "?"
                if item["status"].startswith("Pos("):
                    parts = item["status"][4:-1].split(",")
                    x = parts[0]
                    y = parts[1]
                
                self.inv_tree.insert("", tk.END, values=(
                    item["name"], 
                    item["id"], 
                    item["count"], 
                    x, 
                    y, 
                    hex(item["off"]) if item["off"] else ""
                ))

if __name__ == "__main__":
    app = DXHRSaveEditor()
    app.mainloop()
