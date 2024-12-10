import tkinter as tk
from tkinter import ttk, messagebox
import requests
from requests.auth import HTTPBasicAuth
import json

class PingFederateClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PingFederate Client App")
        
        self.base_urls = [
            'https://localhost:9999',
            'https://console.fed.prod.aws.swacorp.com',
            'https://console.fed.qa.aws.swacorp.com',
            'https://console.fed.dev.aws.swacorp.com'
        ]
        
        self.setup_ui()
        
    def setup_ui(self):
        tk.Label(self.root, text="User ID").grid(row=0, column=0)
        self.user_id_entry = tk.Entry(self.root)
        self.user_id_entry.grid(row=0, column=1)
        
        tk.Label(self.root, text="Password").grid(row=1, column=0)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.grid(row=1, column=1)
        
        tk.Label(self.root, text="Console URL").grid(row=2, column=0)
        self.url_var = tk.StringVar(self.root)
        self.url_var.set(self.base_urls[0])
        self.url_dropdown = ttk.Combobox(self.root, textvariable=self.url_var, values=self.base_urls, state="readonly")
        self.url_dropdown.grid(row=2, column=1)
        
        tk.Label(self.root, text="Base URL").grid(row=3, column=0)
        self.base_url_entry = tk.Entry(self.root)
        self.base_url_entry.grid(row=3, column=1)
        self.base_url_entry.insert(0, self.url_var.get().replace("/.well-known/openid-configuration", "").replace("9031", "9999"))

        self.ignore_cert_var = tk.BooleanVar()
        self.ignore_cert_checkbutton = tk.Checkbutton(self.root, text="Ignore Self-Signed Certificates", variable=self.ignore_cert_var)
        self.ignore_cert_checkbutton.grid(row=4, column=0, columnspan=2)

        tk.Button(self.root, text="Fetch Clients", command=self.fetch_clients).grid(row=5, column=0, columnspan=2)
        
        self.client_listbox = tk.Listbox(self.root, selectmode=tk.SINGLE)
        self.client_listbox.grid(row=6, column=0, columnspan=2, sticky="nsew")
        
        tk.Button(self.root, text="Get Client Info", command=self.get_client_info).grid(row=7, column=0, columnspan=2)

        self.result_frame = tk.Frame(self.root)
        self.result_frame.grid(row=8, column=0, columnspan=2, sticky="nsew")

        self.result_text = tk.Text(self.result_frame, wrap=tk.NONE)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scroll_x = tk.Scrollbar(self.result_frame, orient=tk.HORIZONTAL, command=self.result_text.xview)
        self.scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        self.scroll_y = tk.Scrollbar(self.result_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        self.scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        self.result_text.configure(xscrollcommand=self.scroll_x.set, yscrollcommand=self.scroll_y.set)

        self.root.grid_rowconfigure(6, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        
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

if __name__ == "__main__":
    root = tk.Tk()
    app = PingFederateClientApp(root)
    root.mainloop()
