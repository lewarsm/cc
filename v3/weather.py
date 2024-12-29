import tkinter as tk
from tkinter import ttk
import threading
import queue
import time
import requests
from datetime import datetime

# Function to get weather data from Open-Meteo
def get_weather(city):
    if city == "New York":
        latitude, longitude = 40.7128, -74.0060
    elif city == "Dallas":
        latitude, longitude = 32.7767, -96.7970
    else:
        return "Unknown city"

    url = f"https://api.open-meteo.com/v1/forecast?latitude={latitude}&longitude={longitude}&current_weather=true"
    response = requests.get(url)
    data = response.json()
    weather = data["current_weather"]["weathercode"]
    temperature = data["current_weather"]["temperature"]
    return f"Weather: {weather}, Temp: {temperature}°C"

# Function to update the widget with weather and time
def update_widget(city, label, queue):
    while True:
        weather = get_weather(city)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        queue.put((label, f"{city}\n{weather}\n{current_time}"))
        time.sleep(120)  # Refresh every 2 minutes

# Function to process the queue and update the labels
def process_queue(queue):
    while True:
        try:
            label, text = queue.get_nowait()
            label.config(text=text)
        except queue.Empty:  # Catch the correct exception class
            pass
        time.sleep(1)

# Create the main window
root = tk.Tk()
root.title("Weather and Time")

# Create a queue for inter-thread communication
q = queue.Queue()

# Create a grid layout
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

# Create labels for New York and Dallas
ny_label = ttk.Label(root, text="Loading...", font=("Arial", 14), anchor="center")
ny_label.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

dallas_label = ttk.Label(root, text="Loading...", font=("Arial", 14), anchor="center")
dallas_label.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

# Start threads to update the widgets
ny_thread = threading.Thread(target=update_widget, args=("New York", ny_label, q))
dallas_thread = threading.Thread(target=update_widget, args=("Dallas", dallas_label, q))

ny_thread.daemon = True
dallas_thread.daemon = True

ny_thread.start()
dallas_thread.start()

# Start a thread to process the queue
queue_thread = threading.Thread(target=process_queue, args=(q,))
queue_thread.daemon = True
queue_thread.start()

# Run the application
root.mainloop()

