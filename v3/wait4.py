import tkinter as tk
from tkinter import ttk
import threading
import queue
import time
import requests
import socket

# Worker class to make an HTTP request to www.google.com and get the status code and response time
class Worker1(threading.Thread):
    def __init__(self, q):
        super().__init__()
        self.queue = q
    
    def run(self):
        try:
            start_time = time.time()
            response = requests.get("http://www.google.com")
            total_time = time.time() - start_time
            status_code = response.status_code
            result = [("HTTP Status", status_code), ("Response Time", f"{total_time:.3f} seconds")]
        except requests.RequestException as e:
            result = [("Error", str(e))]
        
        # Put result into the queue
        self.queue.put(('worker_1', result))
        self.queue.put(None)  # Signal completion

# Worker class to perform DNS lookup of mail.yahoo.com and return DNS records
class Worker2(threading.Thread):
    def __init__(self, q):
        super().__init__()
        self.queue = q
    
    def run(self):
        try:
            dns_records = socket.getaddrinfo("mail.yahoo.com", None)
            result = [("DNS Record", f"{record}") for record in dns_records]
        except socket.gaierror as e:
            result = [("Error", str(e))]
        
        # Put result into the queue
        self.queue.put(('worker_2', result))
        self.queue.put(None)  # Signal completion

# Function to update the GUI with the queue data
def update_gui(q, treeview1, treeview2):
    try:
        while True:
            msg = q.get_nowait()  # Get a message from the queue
            if msg is None:
                break  # Exit the loop when signal is received
            
            worker_type, result = msg
            
            if worker_type == 'worker_1':
                update_treeview(treeview1, result)
            elif worker_type == 'worker_2':
                update_treeview(treeview2, result)

    except queue.Empty:
        pass
    
    # Schedule the next check for the queue
    root.after(100, update_gui, q, treeview1, treeview2)

# Function to update a Treeview widget with data
def update_treeview(treeview, result):
    # Clear the existing rows
    for row in treeview.get_children():
        treeview.delete(row)
    
    # Insert new rows
    for row in result:
        treeview.insert('', 'end', values=row)

# Create the main window
root = tk.Tk()
root.title("Tkinter with Threading and Queue")

# Apply the 'clam' theme
style = ttk.Style()
style.theme_use("clam")

# Set custom background colors for each widget using the style
style.configure("Treeview1.Treeview", background="lightblue", fieldbackground="lightblue")
style.configure("Treeview2.Treeview", background="lightgreen", fieldbackground="lightgreen")
style.configure("TButton", background="lightgray")

# Create two Treeview widgets for the two tables
frame1 = ttk.Frame(root)
frame1.pack(pady=10, padx=10)

treeview1 = ttk.Treeview(frame1, columns=("Name", "Value"), show="headings", style="Treeview1.Treeview")
treeview1.heading("Name", text="Name")
treeview1.heading("Value", text="Value")
treeview1.pack()

frame2 = ttk.Frame(root)
frame2.pack(pady=10, padx=10)

treeview2 = ttk.Treeview(frame2, columns=("Name", "Value"), show="headings", style="Treeview2.Treeview")
treeview2.heading("Name", text="Name")
treeview2.heading("Value", text="Value")
treeview2.pack()

# Create a queue to communicate between threads and the main thread
q = queue.Queue()

# Start the worker threads
worker1 = Worker1(q)
worker1.start()

worker2 = Worker2(q)
worker2.start()

# Start the periodic update function to check the queue
root.after(100, update_gui, q, treeview1, treeview2)

# Run the Tkinter event loop
root.mainloop()

