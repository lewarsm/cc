import tkinter as tk
from tkinter import ttk
import threading
import queue
import time

# Worker function to simulate long-running tasks in a separate thread
def worker_1(q):
    for i in range(5):
        time.sleep(1)  # Simulate work
        q.put(f"Worker 1: {i}")
    q.put(None)  # Signal completion

def worker_2(q):
    for i in range(5):
        time.sleep(1.5)  # Simulate work
        q.put(f"Worker 2: {i}")
    q.put(None)  # Signal completion

# Function to update the GUI with the queue data
def update_gui(q, label1, label2):
    try:
        while True:
            msg = q.get_nowait()  # Get a message from the queue
            if msg is None:
                break  # Exit the loop when signal is received
            if "Worker 1" in msg:
                label1.config(text=msg)
            elif "Worker 2" in msg:
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

