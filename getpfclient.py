import json
import os
import tkinter as tk
from tkinter import ttk, messagebox, colorchooser
import requests
from requests.auth import HTTPBasicAuth

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

class PingFederateClientApp:
    def __init__(self, master, theme=None):
        self.master = master
        self.theme = theme or "standard"
        self.apply_theme(self.theme)
        self.create_toolbar()
        self.create_widgets()
        self.master.grid_rowconfigure(6, weight=1)
        self.master.grid_columnconfigure(1, weight=1)

    def apply_theme(self, theme_name):
        theme = NORD_STYLES.get(theme_name, NORD_STYLES["standard"])
        self.master.configure(bg=theme["background"])
        # Apply other theme settings as needed

    def create_toolbar(self):
        toolbar = ttk.Frame(self.master)
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew")

        theme_var = tk.StringVar(value=self.theme)
        ttk.Label(toolbar, text="Choose Theme:").grid(row=0, column=0, padx=5, pady=5)
        for i, theme_name in enumerate(NORD_STYLES.keys()):
            ttk.Radiobutton(toolbar, text=theme_name.capitalize(), variable=theme_var, value=theme_name, command=lambda: self.apply_theme(theme_var.get())).grid(row=0, column=i+1, padx=5, pady=5)

        ttk.Button(toolbar, text="Customize Theme", command=self.open_customize_theme_window).grid(row=0, column=i+2, padx=5, pady=5)

    def create_widgets(self):
        self.base_url_entry = tk.Entry(self.master)
        self.base_url_entry.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.user_id_entry = tk.Entry(self.master)
        self.user_id_entry.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.password_entry = tk.Entry(self.master, show="*")
        self.password_entry.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.ignore_cert_var = tk.IntVar()
        self.ignore_cert_check = tk.Checkbutton(self.master, text="Ignore SSL Cert", variable=self.ignore_cert_var)
        self.ignore_cert_check.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        tk.Button(self.master, text="Fetch Clients", command=self.fetch_clients).grid(row=5, column=0, columnspan=2, padx=5, pady=5)

        self.client_listbox = tk.Listbox(self.master, selectmode=tk.SINGLE)
        self.client_listbox.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        tk.Button(self.master, text="Get Client Info", command=self.get_client_info).grid(row=7, column=0, columnspan=2, padx=5, pady=5)

        self.result_frame = tk.Frame(self.master)
        self.result_frame.grid(row=8, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        self.result_text = tk.Text(self.result_frame, wrap=tk.NONE)
        self.result_text.grid(row=0, column=0, sticky="nsew")

        self.scroll_x = tk.Scrollbar(self.result_frame, orient=tk.HORIZONTAL, command=self.result_text.xview)
        self.scroll_x.grid(row=1, column=0, sticky="ew")

        self.scroll_y = tk.Scrollbar(self.result_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        self.scroll_y.grid(row=0, column=1, sticky="ns")

        self.result_text.configure(xscrollcommand=self.scroll_x.set, yscrollcommand=self.scroll_y.set)

        self.result_frame.grid_rowconfigure(0, weight=1)
        self.result_frame.grid_columnconfigure(0, weight=1)

    def open_customize_theme_window(self):
        customizer = CustomizeThemeWindow(self.master, self.theme)
        self.master.wait_window(customizer.top)
        self.apply_theme(self.theme)

    def fetch_clients(self):
        base_url = self.base_url_entry.get()
        clients_url = f"{base_url}/pf-admin-api/v1/oauth/clients"
        user_id = self.user_id_entry.get()
        password = self.password_entry.get()
        verify_ssl = not self.ignore_cert_var.get()
        
        
        response = requests.get(clients_url, auth=HTTPBasicAuth(user_id, password), headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"}, verify=verify_ssl)
        if response.status_code == 200:
            clients = response.json().get("items", [])
            self.client_listbox.delete(0, tk.END)
            for client in clients:
                self.client_listbox.insert(tk.END, client["clientId"])
        else:
            messagebox.showerror("Error", f"Failed to fetch clients: {response.status_code}")
            
    def get_client_info(self):
        selected_client_index = self.client_listbox.curselection()
        if not selected_client_index:
            messagebox.showerror("Error", "Please select a client from the list")
            return
        
        selected_client = self.client_listbox.get(selected_client_index)
        base_url = self.base_url_entry.get()
        client_info_url = f"{base_url}/pf-admin-api/v1/oauth/clients/{selected_client}"
        user_id = self.user_id_entry.get()
        password = self.password_entry.get()
        verify_ssl = not self.ignore_cert_var.get()


        client_info_response = requests.get(client_info_url, auth=HTTPBasicAuth(user_id, password), headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"}, verify=verify_ssl)
        if client_info_response.status_code == 200:
            client_info = client_info_response.json()
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Client Information:\n")
            self.result_text.insert(tk.END, json.dumps(client_info, indent=4))
            access_token_manager_id = client_info.get("defaultAccessTokenManagerRef",{}).get("id") 
            access_token_manager_url = f"{base_url}/pf-admin-api/v1/oauth/accessTokenManagers/{access_token_manager_id}"
            access_token_manager_response = requests.get(access_token_manager_url, auth=HTTPBasicAuth(user_id, password), headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"}, verify=verify_ssl)
            policy_group = client_info.get("oidcPolicy", {}).get("policyGroup", {})
            policy_group_id = policy_group.get("id")
            policy_group_location = policy_group.get("location")
            #print(f"Policy Group ID: {policy_group_id}")
            #print(f"Policy Group Location: {policy_group_location}")
            if access_token_manager_response.status_code == 200:
                access_token_manager_info = access_token_manager_response.json()
                self.result_text.insert(tk.END, "\n\nAccess Token Manager Information:\n")
                self.result_text.insert(tk.END, json.dumps(access_token_manager_info, indent=4))
                try:
                    policy_group_data = self.fetch_policy_group_location(policy_group_location, base_url, user_id, password)
                    if policy_group_data:
                        self.result_text.insert(tk.END, "\n\nOpenID Policy Information:\n")
                        self.result_text.insert(tk.END, json.dumps(policy_group_data, indent=4))
                    else:
                        self.result_text.insert(tk.END, "\n\nOpenID Policy Information Missing.\n")
                except Exception as e:
                    self.result_text.insert(tk.END, f"\n\nError fetching OpenID Policy Information: {e}\n")
            else:
                messagebox.showerror("Error", f"Failed to fetch access token manager info: {access_token_manager_response.status_code}")
        else:
            messagebox.showerror("Error", f"Failed to fetch client info: {client_info_response.status_code}")

    def get_default_openid(self, base_url, user_id, password):
        url = f"{base_url}/pf-admin-api/v1/oauth/openIdConnect/policies"
        response = requests.get(url, auth=HTTPBasicAuth(user_id, password), verify=False, headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"})
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        
        default_openid = None
        for item in data.get("items", []):
            access_token_manager_ref = item.get("accessTokenManagerRef", {})
            if access_token_manager_ref.get("id") == "default":
                default_openid = access_token_manager_ref.get("location")
                break
        
        return default_openid

    def fetch_policy_group_location(self, policy_group_location, base_url, user_id, password):
        if policy_group_location:
            response = requests.get(policy_group_location, auth=HTTPBasicAuth(user_id, password), verify=False, headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"})
            response.raise_for_status()  # Raise an exception for HTTP errors
            policy_group_data = response.json()
            return policy_group_data
        else:
            policy_group_location = self.get_default_openid(base_url, user_id, password)
            if policy_group_location:
                response = requests.get(policy_group_location, auth=HTTPBasicAuth(user_id, password), verify=False, headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"})
                response.raise_for_status()  # Raise an exception for HTTP errors
                policy_group_data = response.json()
                return policy_group_data
            else:
                return None

class CustomizeThemeWindow:
    def __init__(self, master, theme_name):
        self.top = tk.Toplevel(master)
        self.top.title("Customize Theme")
        self.theme_name = theme_name
        self.theme = NORD_STYLES.get(theme_name, NORD_STYLES["standard"])

        for i, key in enumerate(self.theme.keys()):
            ttk.Label(self.top, text=key.capitalize()).grid(row=i, column=0, padx=5, pady=5)
            ttk.Button(self.top, text=f"Choose {key} color", command=lambda k=key: self.choose_color(k)).grid(row=i, column=1, padx=5, pady=5)

        ttk.Button(self.top, text="Save Theme", command=self.save_custom_theme).grid(row=i+1, column=0, columnspan=2, padx=5, pady=5)

    def choose_color(self, key):
        color = colorchooser.askcolor(title=f"Choose {key} color", initialcolor=self.theme[key])[1]
        if color:
            self.theme[key] = color

    def save_custom_theme(self):
        NORD_STYLES[self.theme_name] = self.theme
        with open("customtheme.json", "w") as file:
            json.dump(NORD_STYLES, file, indent=4)
        messagebox.showinfo("Success", "Theme saved successfully!")
        self.top.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PingFederateClientApp(root)
    root.mainloop()
