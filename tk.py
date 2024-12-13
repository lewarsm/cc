import tkinter as tk
from tkinter import ttk

# Define colors
colors = {
    "background": "#1E4BC3",  # Deep blue
    "foreground": "#E2E2E2",  # Light gray
    "highlight": "#F9B612",   # Golden yellow
    "header": "#F9B612",      # Same as highlight
    "button": "#F9B612",      # Golden yellow
    "invert_button": "#FF0000",  # Bright red for inverse actions
    "table_odd": "#304CB2",   # Slightly darker blue for table rows
    "table_even": "#1E4BC3"   # Base blue for table rows
}

# Initialize the root window
root = tk.Tk()
root.title("Colored Tkinter App")
root.geometry("600x400")
root.configure(bg=colors["background"])

# Apply styling using ttk.Style
style = ttk.Style()
style.theme_use("clam")  # Use a modern theme

# Configure styles for different widgets
style.configure("TFrame", background=colors["background"])
style.configure("TLabel", background=colors["background"], foreground=colors["foreground"])
style.configure("TButton", background=colors["button"], foreground=colors["foreground"])
style.map("TButton", background=[("active", colors["highlight"])])
style.configure("Treeview", background=colors["background"], foreground=colors["foreground"], fieldbackground=colors["background"])
style.configure("Treeview.Heading", background=colors["header"], foreground=colors["foreground"])
style.configure("TMenu", background=colors["background"], foreground=colors["foreground"])

# Create a menu bar
menu_bar = tk.Menu(root, bg=colors["background"], fg=colors["foreground"])
file_menu = tk.Menu(menu_bar, tearoff=0, bg=colors["background"], fg=colors["foreground"])
file_menu.add_command(label="New")
file_menu.add_command(label="Open")
file_menu.add_command(label="Exit", command=root.quit)
menu_bar.add_cascade(label="File", menu=file_menu)
root.config(menu=menu_bar)

# Create a toolbar
toolbar = ttk.Frame(root, padding=5, style="TFrame")
toolbar.pack(side=tk.TOP, fill=tk.X)
btn1 = ttk.Button(toolbar, text="Action 1")
btn2 = ttk.Button(toolbar, text="Action 2")
btn1.pack(side=tk.LEFT, padx=5, pady=5)
btn2.pack(side=tk.LEFT, padx=5, pady=5)

# Create a table (Treeview)
frame = ttk.Frame(root, style="TFrame")
frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

columns = ("Column1", "Column2", "Column3")
tree = ttk.Treeview(frame, columns=columns, show="headings", style="Treeview")

# Set column headings
for col in columns:
    tree.heading(col, text=col, anchor="center")
    tree.column(col, width=100, anchor="center")

# Add rows with alternating colors
for i in range(10):
    row_color = colors["table_odd"] if i % 2 == 0 else colors["table_even"]
    tree.insert("", "end", values=(f"Row {i} Col 1", f"Row {i} Col 2", f"Row {i} Col 3"), tags=(row_color,))
    tree.tag_configure(row_color, background=row_color, foreground=colors["foreground"])

tree.pack(fill=tk.BOTH, expand=True)

# Run the application
root.mainloop()

