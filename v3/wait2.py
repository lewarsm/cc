import tkinter as tk
from tkinter import ttk
import threading
import queue
import time
import requests
import socket

# Worker function to make an HTTP request to www.google.com and get the status code and response time
def worker_1(q):
    try:
        start_time = time.time()
        response = requests.get("http://www.google.com")
        total_time = time.time() - start_time
        status_code = response.status_code
        result = f"HTTP Status: {status_code}, Response Time: {total_time:.3f} seconds"
    except requests.RequestException as e:
        result = f"HTTP Error: {str(e)}"
    
    q.put(result)
    q.put(None)  # Signal completion

# Worker function to perform DNS lookup of mail.yahoo.com and return DNS records
def worker_2(q):
    try:
        dns_records = socket.getaddrinfo("mail.yahoo.com", None)
        result = f"DNS Records for mail.yahoo.com:\n"
        for record in dns_records:
            result += f"{record}\n"
    except socket.gaierror as e:
        result = f"DNS Lookup Error: {str(e)}"
    
    q.put(result)
    q.put(None)  # Signal completion

# Function to update the GUI with the queue data
def update_gui(q, label1, label2):
    try:
        while True:
            msg = q.get_nowait()  # Get a message from the queue
            if msg is None:
                break  # Exit the loop when signal is received
            if "HTTP" in msg:
                label1.config(text=msg)
            elif "DNS" in msg:
                label2.config(text=msg)
    except queue.Empty:
        pass
    root.after(100, update_gui, q, label1, label2)

# Create the main window
root = tk.Tk()
root.title("Tkinter with Threading and Queue")

# Create two labels for the two widgets
label1 = ttk.Label(root, text="Worker 1: Waiting...")
label1.pack(pady=10)

label2 = ttk.Label(root, text="Worker 2: Waiting...")
label2.pack(pady=10)

# Create a queue to communicate between threads and the main thread
q = queue.Queue()

# Start the worker threads
thread1 = threading.Thread(target=worker_1, args=(q,))
thread1.start()

thread2 = threading.Thread(target=worker_2, args=(q,))
thread2.start()

# Start the periodic update function to check the queue
root.after(100, update_gui, q, label1, label2)

# Run the Tkinter event loop
root.mainloop()

