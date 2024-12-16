# oauth_debugger.py

import tkinter as tk
from tkinter import ttk
import base64
import json
import os
from datetime import datetime
import aiohttp
import asyncio

# Default themes
NORD_STYLES = {
    "standard": {
        "background": "#304CB2",
        "foreground": "#D8DEE9",
        "highlight": "#88C0D0",
        "error": "#BF616A",
        "header": "#4C566A",
        "row_odd": "#3B4252",
        "row_even": "#434C5E",
        "button": "#FFCA4F",
        "invert_button": "#BF616A"
    },
    "frost": {
        "background": "#8FBCBB",
        "foreground": "#2E3440",
        "highlight": "#88C0D0",
        "error": "#BF616A",
        "header": "#4C566A",
        "row_odd": "#A3BE8C",
        "row_even": "#EBCB8B",
        "button": "#5E81AC",
        "invert_button": "#D08770"
    },
    "aurora": {
        "background": "#A3BE8C",
        "foreground": "#2E3440",
        "highlight": "#88C0D0",
        "error": "#BF616A",
        "header": "#4C566A",
        "row_odd": "#B48EAD",
        "row_even": "#D08770",
        "button": "#5E81AC",
        "invert_button": "#88C0D0"
    }
}

# Load custom themes if customtheme.json exists
if os.path.exists("customtheme.json"):
    with open("customtheme.json", "r") as file:
        custom_themes = json.load(file)
        NORD_STYLES.update(custom_themes)

class OAuthDebugger:
    def __init__(self, master, theme):
        self.master = master
        self.theme = theme
        self.setup_ui()

    def setup_ui(self):
        oauth_window = tk.Toplevel(self.master)
        oauth_window.title("OAuth Debugger")
        oauth_window.geometry("1200x600")

        frame = ttk.Frame(oauth_window)
        frame.pack(fill=tk.BOTH, expand=True)

        well_known_entry = self.create_labeled_entry(frame, "OAuth Well-Known Endpoint:", 1, 0)
        token_endpoint_entry = self.create_labeled_entry(frame, "Token Endpoint:", 3, 0)
        client_id_entry = self.create_labeled_entry(frame, "Client ID:", 5, 0)
        client_secret_entry = self.create_labeled_entry(frame, "Client Secret:", 7, 0)
        scopes_entry = self.create_labeled_entry(frame, "Scopes (space-separated):", 9, 0)

        result_text = self.create_scrollable_text(frame, 15, 60, self.theme, 11, 0, 2)

        well_known_table_frame = ttk.Frame(frame)
        well_known_table_frame.grid(row=0, column=3, rowspan=12, padx=10, pady=10, sticky="nsew")

        well_known_table = CustomTable(well_known_table_frame, ("Key", "Value"), 0, 0)

        well_known_urls = [
            'https://server/.well-known/openid-configuration',
            'https://server1/.well-known/openid-configuration'
        ]

        def on_well_known_select(event):
            selected_url = well_known_combobox.get()
            well_known_entry.delete(0, tk.END)
            well_known_entry.insert(0, selected_url)

        well_known_combobox = ttk.Combobox(frame, values=well_known_urls, state="readonly")
        well_known_combobox.grid(row=1, column=1, padx=5, pady=5)
        well_known_combobox.bind("<<ComboboxSelected>>", on_well_known_select)

        ttk.Button(frame, text="Fetch Well-Known OAuth", command=self.fetch_well_known_oauth).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Get Tokens", command=self.get_oauth_tokens).grid(row=10, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Show Certificate Details", command=self.show_cert_details).grid(row=0, column=0, padx=5, pady=5, sticky="e")
        ttk.Button(frame, text="Close", command=oauth_window.destroy).grid(row=12, column=1, padx=5, pady=5, sticky="e")

    def apply_theme(self):
        selected_theme = self.theme_combobox.get()
        if selected_theme in NORD_STYLES:
            self.theme = selected_theme
            self.master.configure(bg=NORD_STYLES[self.theme]["background"])
            for widget in self.master.winfo_children():
                widget.configure(bg=NORD_STYLES[self.theme]["background"], fg=NORD_STYLES[self.theme]["foreground"])

    def create_labeled_entry(self, parent, label_text, row, col, width=30):
        label = ttk.Label(parent, text=label_text)
        label.grid(row=row, column=col, padx=5, pady=5, sticky="w")
        entry = ttk.Entry(parent, width=width)
        entry.grid(row=row, column=col + 1, padx=5, pady=5, sticky="w")
        return entry

    def create_scrollable_text(self, parent, height, width, theme, row, col, colspan):
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=col, columnspan=colspan, padx=5, pady=5, sticky="nsew")
        text_widget = tk.Text(frame, height=height, width=width, wrap=tk.WORD)
        text_widget.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")
        return text_widget

    async def fetch_well_known_oauth(self):
        well_known_url = self.well_known_entry.get().strip()
        if not well_known_url:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Please enter a Well-Known Endpoint URL.")
            return

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(well_known_url, ssl=False) as response:
                    response.raise_for_status()
                    well_known_data = await response.json()
                    token_endpoint = well_known_data.get("token_endpoint", "")
                    self.token_endpoint_entry.delete(0, tk.END)
                    self.token_endpoint_entry.insert(0, token_endpoint)
                    self.result_text.insert(tk.END, "Well-Known Endpoint fetched successfully.\n")
                    
                    self.well_known_table.clear_table()
                    for key, value in well_known_data.items():
                        self.well_known_table.insert_row((key, value))
        except Exception as e:
            self.result_text.insert(tk.END, f"Error fetching Well-Known Endpoint: {e}")
            log_error("Error fetching Well-Known Endpoint in OAuth", e)

    async def get_oauth_tokens(self):
        token_endpoint = self.token_endpoint_entry.get().strip()
        client_id = self.client_id_entry.get().strip()
        client_secret = self.client_secret_entry.get().strip()
        scopes = self.scopes_entry.get().strip()

        if not all([token_endpoint, client_id, client_secret, scopes]):
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Please fill in all fields to get tokens.")
            return

        self.result_text.delete(1.0, tk.END)
        try:
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'client_credentials',
                'scope': scopes
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(token_endpoint, data=data, ssl=False) as response:
                    response.raise_for_status()
                    token_data = await response.json()
                    access_token = token_data.get('access_token')
                    self.result_text.insert(tk.END, f"Access Token:\n{access_token}\n\n")
                    self.result_text.insert(tk.END, f"Token Type:\n{token_data.get('token_type')}\n\n")
                    self.result_text.insert(tk.END, f"Expires In:\n{token_data.get('expires_in')}\n\n")

                    if access_token:
                        decoded_token = self.decode_jwt(access_token)
                        self.result_text.insert(tk.END, f"Decoded Access Token:\n{decoded_token}\n\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error retrieving OAuth tokens: {e}")
            log_error("Error retrieving OAuth token", e)

    def show_cert_details(self):
        show_certificate_details()

    def decode_jwt(self, token):
        try:
            header, payload, signature = token.split('.')
            header_decoded = base64.urlsafe_b64decode(header + '==').decode('utf-8')
            payload_decoded = base64.urlsafe_b64decode(payload + '==').decode('utf-8')
            
            header_json = json.loads(header_decoded)
            payload_json = json.loads(payload_decoded)
            
            # Convert Unix timestamps to UTC time
            for time_field in ['iat', 'exp', 'nbf']:
                if time_field in payload_json:
                    payload_json[time_field] = f"{payload_json[time_field]} ({datetime.utcfromtimestamp(payload_json[time_field]).strftime('%Y-%m-%d %H:%M:%S UTC')})"
            
            decoded = {
                "header": header_json,
                "payload": payload_json,
                "signature": signature
            }
            return json.dumps(decoded, indent=4)
        except Exception as e:
            log_error("Error decoding JWT", e)
            return f"Error decoding JWT: {e}"

# Example usage
if __name__ == "__main__":
    root = tk.Tk()
    app = OAuthDebugger(root, theme="default")
    root.mainloop()