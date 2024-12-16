
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

class OIDCDebugger:
    def __init__(self, master, theme):
        self.master = master
        self.theme = theme
        self.window = tk.Toplevel()
        self.window.title("OIDC Debugger")
        self.window.geometry("1400x600")
        self.server_port = 4443
        self.setup_ui()


    def apply_theme(self):
        style = ttk.Style(self.window)
        colors = NORD_STYLES[self.theme]
        style.configure("TFrame", background=colors["background"])
        style.configure("TLabel", background=colors["background"], foreground=colors["foreground"])
        style.configure("TButton", background=colors["button"], foreground=colors["foreground"])
        style.map("TButton", background=[("active", colors["highlight"])])
        style.configure("TEntry", background=colors["background"], foreground=colors["foreground"], fieldbackground=colors["background"])
        style.configure("TText", background=colors["background"], foreground=colors["foreground"])

    def setup_ui(self):
        self.frame = ttk.Frame(self.window, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.endpoint_label = ttk.Label(self.frame, text="Select or enter well-known endpoint URL:")
        self.endpoint_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.well_known_var = tk.StringVar()
        self.well_known_dropdown = ttk.Combobox(self.frame, textvariable=self.well_known_var)

        self.well_known_dropdown['values'] = [
            'https://server/.well-known/openid-configuration',
            'https://server1/.well-known/openid-configuration'
        ]
        self.well_known_dropdown.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        # Bind the selection event to a function
        self.well_known_dropdown.bind("<<ComboboxSelected>>", self.update_endpoint_entry)

        self.endpoint_entry = ttk.Entry(self.frame, width=50)
        self.endpoint_entry.grid(row=2, column=0, padx=5, pady=5)
        self.endpoint_entry.insert(0, "Enter well-known endpoint URL")

        self.server_name_label = ttk.Label(self.frame, text="Enter server name for redirect URL(optional):")
        self.server_name_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")

        self.server_name_entry = ttk.Entry(self.frame, width=50)
        self.server_name_entry.grid(row=4, column=0, padx=5, pady=5)
        self.server_name_entry.insert(0, "localhost")

        self.client_id_entry = ttk.Entry(self.frame, width=50)
        self.client_id_entry.grid(row=5, column=0, padx=5, pady=5)
        self.client_id_entry.insert(0, "Enter Client ID")

        self.client_secret_entry = ttk.Entry(self.frame, width=50, show="*")
        self.client_secret_entry.grid(row=6, column=0, padx=5, pady=5)
        self.client_secret_entry.insert(0, "Enter Client Secret")

        self.scope_entry = ttk.Entry(self.frame, width=50)
        self.scope_entry.grid(row=7, column=0, padx=5, pady=5)
        self.scope_entry.insert(0, "Enter Scopes (e.g., openid profile email)")

        self.use_pkce = tk.BooleanVar()
        ttk.Checkbutton(self.frame, text="Use PKCE", variable=self.use_pkce).grid(row=8, column=0, padx=5, pady=5)

        self.auth_method = tk.StringVar(value="client_secret_post")
        ttk.Radiobutton(self.frame, text="Client Secret Post", variable=self.auth_method, value="client_secret_post").grid(row=0, column=1, padx=1, pady=1, sticky="w")
        ttk.Radiobutton(self.frame, text="Client Secret Basic", variable=self.auth_method, value="client_secret_basic").grid(row=1, column=1, padx=1, pady=1, sticky="w")

        self.generate_request_btn = ttk.Button(self.frame, text="Generate Auth Request", command=self.generate_auth_request)
        self.generate_request_btn.grid(row=9, column=0, padx=5, pady=5)

        self.auth_url_text = tk.Text(self.frame, height=5, width=80)
        self.auth_url_text.grid(row=10, column=0, padx=5, pady=5, sticky="ew")
        auth_url_scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.auth_url_text.yview)
        self.auth_url_text.configure(yscrollcommand=auth_url_scrollbar.set)
        auth_url_scrollbar.grid(row=10, column=1, sticky="ns")

        self.submit_btn = ttk.Button(self.frame, text="Submit Auth Request", command=self.submit_auth_request)
        self.submit_btn.grid(row=11, column=0, padx=5, pady=5)

        self.clear_text_checkbox = tk.BooleanVar()
        ttk.Checkbutton(self.frame, text="Clear response text\n before next request", variable=self.clear_text_checkbox).grid(row=12, column=0, padx=5, pady=5, sticky="w")
        self.log_oidc_process = tk.BooleanVar()
        ttk.Checkbutton(self.frame, text="Log OIDC process\n in separate window", variable=self.log_oidc_process).grid(row=12, column=1, padx=5, pady=5, sticky="w")
        
        self.response_table_frame = ttk.Frame(self.frame)
        self.response_table_frame.grid(row=0, column=2, rowspan=9, padx=5, pady=5, sticky="nsew")

        table_scrollbar_y = ttk.Scrollbar(self.response_table_frame, orient="vertical")
        table_scrollbar_x = ttk.Scrollbar(self.response_table_frame, orient="horizontal")

        self.response_table = ttk.Treeview(self.response_table_frame, columns=("Key", "Value"), show="headings", yscrollcommand=table_scrollbar_y.set, xscrollcommand=table_scrollbar_x.set)
        self.response_table.heading("Key", text="Key")
        self.response_table.heading("Value", text="Value")

        # Set column widths
        self.response_table.column("Key", width=200)
        self.response_table.column("Value", width=600)

        table_scrollbar_y.config(command=self.response_table.yview)
        table_scrollbar_x.config(command=self.response_table.xview)

        self.response_table.grid(row=0, column=1, sticky="nsew")
        table_scrollbar_y.grid(row=0, column=2, sticky="ns")
        table_scrollbar_x.grid(row=1, column=1, sticky="ew")

        self.response_text = tk.Text(self.frame, height=30, width=100)
        self.response_text.grid(row=13, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        response_text_scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.response_text.yview)
        self.response_text.configure(yscrollcommand=response_text_scrollbar.set)
        response_text_scrollbar.grid(row=13, column=2, sticky="ns")

        self.certificate_btn = ttk.Button(self.frame, text="Show Certificate", command=self.show_certificate)
        self.certificate_btn.grid(row=14, column=0, padx=5, pady=5)

        self.replace_certificate_btn = ttk.Button(self.frame, text="Replace Certificate", command=self.replace_certificate)
        self.replace_certificate_btn.grid(row=15, column=0, padx=5, pady=5)

        self.oidc_log_window = None
        #Draw the screen and start network operations after UI is fully rendered 
        self.window.update_idletasks() 
        #self.window.after(100, self.after_ui_setup)
        
   # def after_ui_setup(self):
        # Start any initial network operations here, like nslookup or HTTP requests
   #     self.generate_self_signed_cert()
   #     self.start_https_server()

    def open_oidc_log_window(self):
        oidc_log_window = tk.Toplevel(self.window)
        oidc_log_window.title("OIDC Log")
        oidc_log_window.geometry("800x600")

        frame = ttk.Frame(oidc_log_window)
        frame.pack(fill=tk.BOTH, expand=True)

        # Create a Text widget with scrollbars
        self.oidc_log_text = tk.Text(frame, wrap=tk.NONE)
        self.oidc_log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.oidc_log_text.yview)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.oidc_log_text.configure(yscrollcommand=scrollbar_y.set)

        scrollbar_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.oidc_log_text.xview)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.oidc_log_text.configure(xscrollcommand=scrollbar_x.set)

        ttk.Button(frame, text="Close", command=oidc_log_window.destroy).pack(pady=5)

    def update_endpoint_entry(self, event):
        selected_value = self.well_known_var.get()
        if selected_value:
            self.endpoint_entry.delete(0, tk.END)
            self.endpoint_entry.insert(0, selected_value)
        else:
            self.endpoint_entry.delete(0, tk.END)
            self.endpoint_entry.insert(0, "Enter well-known endpoint URL")


    def copy_item_to_clipboard(self, event):
        selected_item = self.response_table.selection()
        if selected_item:
            item = selected_item[0]
            column = self.response_table.identify_column(event.x)
            value = self.response_table.item(item, "values")[int(column[1:]) - 1]
            self.window.clipboard_clear()
            self.window.clipboard_append(value)
            self.window.update()  # Keep the clipboard updated
            messagebox.showinfo("Copied", f"Copied to clipboard:\n{value}")

    def generate_auth_request(self):
        if self.log_oidc_process.get():
            self.open_oidc_log_window()

        well_known_url = self.endpoint_entry.get().strip()


        client_id = self.client_id_entry.get().strip()
        client_secret = self.client_secret_entry.get().strip()
        scopes = self.scope_entry.get().strip()
        server_name = self.server_name_entry.get().strip()
        if not server_name:
            server_name = "localhost"

        if not well_known_url or not client_id:
            self.response_text.insert(tk.END, "Please enter the well-known endpoint and client credentials.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, "Please enter the well-known endpoint and client credentials.\n")
            return

        try:
            response = requests.get(well_known_url, verify=False)
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error fetching well-known configuration: {response.status_code}\n")
                log_error("Unable to query Well-known Endpoint",f"{response.status_code}")
                return

            config = response.json()
            self.display_well_known_response(config)
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Well-known configuration response:\n{json.dumps(config, indent=4)}\n")


            auth_endpoint = config.get("authorization_endpoint")
            token_endpoint = config.get("token_endpoint")
            introspection_endpoint = config.get("introspection_endpoint")
            userinfo_endpoint = config.get("userinfo_endpoint")

            if not auth_endpoint or not token_endpoint:
                self.response_text.insert(tk.END, "Error: Unable to find authorization or token endpoint in the configuration.\n")
                log_error("Missing data in OIDC Well-Known Endpoint", "Error in configuration")
                return

            state = self.generate_state()
            nonce = self.generate_nonce()
            params = {
                "client_id": client_id,
                "redirect_uri": f"https://{server_name}:{self.server_port}/callback",
                "response_type": "code",
                "scope": scopes,
                "state": state,
                "nonce": nonce
            }

            if self.use_pkce.get():
                code_verifier, code_challenge = self.generate_pkce()
                params.update({
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256"
                })
                self.code_verifier = code_verifier
            else:
                self.code_verifier = None

            auth_url = f"{auth_endpoint}?{self.encode_params(params)}"
            self.auth_url_text.delete(1.0, tk.END)
            self.auth_url_text.insert(tk.END, auth_url)
            self.state = state
            self.token_endpoint = token_endpoint
            self.client_id = client_id
            self.client_secret = client_secret
            self.introspect_endpoint = introspection_endpoint
            self.userinfo_endpoint = userinfo_endpoint
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Authorization URL: {auth_url}\n")
        except Exception as e:
            self.response_text.insert(tk.END, f"Error generating auth request: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error generating auth request: {e}\n")
            log_error("Error create OIDC Auth Request",e)

        try:
        # Generate the self-signed certificate
            self.generate_self_signed_cert() 
        # Start the HTTPS server after the certificate is created
            self.start_https_server()
        except Exception as e:
            self.response_text.insert(tk.END, "Web server failed.\n")


    def generate_state(self):
        return base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8').rstrip('=')

    def generate_nonce(self):
        return base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8').rstrip('=')

    def generate_pkce(self):
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge

    def encode_params(self, params):
        return '&'.join([f"{k}={requests.utils.quote(v)}" for k, v in params.items()])

    def submit_auth_request(self):
        auth_url = self.auth_url_text.get(1.0, tk.END).strip()
        if not auth_url:
            self.response_text.insert(tk.END, "Please generate an authentication request URL first.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, "Authorization URL is empty. Generate the auth request first.\n")
      
            return
        webbrowser.open(auth_url)
        self.response_text.insert(tk.END, "Please complete the authentication in your browser.\n")
        if self.log_oidc_process.get():
            self.oidc_log_text.insert(tk.END, f"Opened Authorization URL: {auth_url}\n")

        self.response_text.insert(tk.END, f"Opened Authorization URL: {auth_url}\n")


    def generate_self_signed_cert(self):
        server_name = self.server_name_entry.get().strip()
        if not server_name:
            server_name = "localhost"
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State`"
        cert.get_subject().L = "City"
        cert.get_subject().O = "MyCompany"
        cert.get_subject().OU = "IT"
        cert.get_subject().CN = server_name
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        with open("server.crt", "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
        with open("server.key", "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8'))
        self.cert = cert

    def show_certificate(self):
        # Show the public certificate
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, self.cert).decode('utf-8')
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())

        # Display the certificate details
        cert_details = f"Public Certificate:\n{cert_pem}\n\n"
        cert_details += f"Issuer: {cert.issuer.rfc4514_string()}\n"
        cert_details += f"Subject: {cert.subject.rfc4514_string()}\n"
        cert_details += f"Serial Number: {cert.serial_number}\n"
        cert_details += f"Not Before: {cert.not_valid_before}\n"
        cert_details += f"Not After: {cert.not_valid_after}\n"

        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, cert_details)

    def replace_certificate(self):
        cert_file_path = tk.filedialog.askopenfilename(title="Select Certificate File", filetypes=[("Certificate Files", "*.crt *.pem")])
        key_file_path = tk.filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key *.pem")])

        if cert_file_path and key_file_path:
            with open(cert_file_path, "r") as cert_file:
                self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
            with open(key_file_path, "r") as key_file:
                self.key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(tk.END, "Certificate and key replaced successfully.\n")
        else:
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(tk.END, "Certificate or key file not selected.\n")

    def start_https_server(self):
        global https_server, https_server_thread

        server_name = self.server_name_entry.get().strip()
        if not server_name:
            server_name = "localhost"
        # Check if the server name resolves
        try:
            socket.gethostbyname(server_name)
        except socket.error:
            self.response_text.insert(tk.END, f"Server name '{server_name}' does not resolve. Using 127.0.0.1 instead.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Server name '{server_name}' does not resolve. Using 127.0.0.1 instead.\n")
            server_name = "localhost"
            
        if https_server is not None: 
            self.response_text.insert(tk.END, "HTTPS server is already running.\n")
            return

        handler = self.create_https_handler()
        https_server = socketserver.TCPServer((server_name, self.server_port), handler)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        https_server.socket = context.wrap_socket(https_server.socket, server_side=True)

        https_server_thread = threading.Thread(target=https_server.serve_forever)
        https_server_thread.daemon = True
        try:
            https_server_thread.start()
            self.response_text.insert(tk.END, f"HTTPS server started on https://{server_name}:{self.server_port}/callback\n\n")
            self.response_text.insert(tk.END, f"Please confirm {self.client_id} has the redirect uri:  https://{server_name}:{self.server_port}/callback\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"HTTPS server started on https://{server_name}:{self.server_port}/callback\n\n")
                self.oidc_log_text.insert(tk.END, f"Please confirm {self.client_id} has the redirect uri:  https://{server_name}:{self.server_port}/callback\n")
                self.add_horizontal_rule()

        except Exception as e:
            self.response_text.insert(tk.END, f"HTTPS server https://{server_name}:{self.server_port} Failed.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"HTTPS server https://{server_name}:{self.server_port} Failed.: {e}\n")
                self.add_horizontal_rule()
            log_error("HTTPS server Failed.", e)
    
    def add_horizontal_rule(self):
            self.response_text.insert(tk.END, f"---------------------------------------------------\n\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"---------------------------------------------------\n\n")

    
    def create_https_handler(self):
        parent = self

        class HTTPSHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith('/callback'):
                    query = self.path.split('?')[-1]
                    params = {k: v for k, v in (item.split('=') for item in query.split('&'))}
                    code = params.get('code')
                    parent.response_text.insert(tk.END, f"Received code: {code}\n")
                    if parent.log_oidc_process.get():
                        parent.oidc_log_text.insert(tk.END, f"Received authorization code: {code}\n")
                    parent.exchange_code_for_tokens(code)
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Authorization code received. You can close this window.")

                else:
                    self.send_error(404, "Not Found")

            def do_POST(self):
                if self.path == '/kill_server':
                    threading.Thread(target=shutdown_https_server).start()
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Server shutdown initiated.")
                if parent.log_oidc_process.get():
                    parent.oidc_log_text.insert(tk.END, "Server shutdown initiated.\n")
        return HTTPSHandler   


    def exchange_code_for_tokens(self, code):
        server_name = self.server_name_entry.get().strip()
        if not server_name:
            server_name = "localhost"
        try:
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": f"https://{server_name}:{self.server_port}/callback",
                "client_id": self.client_id,
            }
            headers = {}
            if self.code_verifier:
                data["code_verifier"] = self.code_verifier
            if self.auth_method.get() == "client_secret_post":
                data["client_secret"] = self.client_secret
            elif self.auth_method.get() == "client_secret_basic":
                basic_auth = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
                headers["Authorization"] = f"Basic {basic_auth}"
            elif self.auth_method.get() == "client_secret_jwt":
                now = int(time.time())
                payload = {
                    "iss": self.client_id,
                    "sub": self.client_id,
                    "aud": self.token_endpoint,
                    "exp": now + 300,  # Token expires in 5 minutes
                    "iat": now
                }

                def base64url_encode(input):
                    return base64.urlsafe_b64encode(input).decode('utf-8').rstrip('=')

                encoded_header = base64url_encode(json.dumps(headers).encode('utf-8'))
                encoded_payload = base64url_encode(json.dumps(payload).encode('utf-8'))
                signature = base64.urlsafe_b64encode(
                    hmac.new(self.client_secret.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'), hashlib.sha256).digest()
                ).decode('utf-8').rstrip('=')

                client_assertion = f"{encoded_header}.{encoded_payload}.{signature}"
                data["client_assertion"] = client_assertion
                data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Token Exchange Request Data: {json.dumps(data, indent=4)}\n")
                self.add_horizontal_rule()


            response = requests.post(self.token_endpoint, data=data, headers=headers, verify=False)
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error fetching tokens: {response.status_code}\n")
                if self.log_oidc_process.get():
                    self.oidc_log_text.insert(tk.END, f"Error fetching tokens: {response.status_code}\n")
                    self.add_horizontal_rule()


                return

            tokens = response.json()
            self.display_tokens(tokens)
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Token Exchange Response: {json.dumps(tokens, indent=4)}\n")
                self.add_horizontal_rule()

            
        except Exception as e:
            self.response_text.insert(tk.END, f"Error exchanging code for tokens: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error exchanging code for tokens: {e}\n")
                self.add_horizontal_rule()

            log_error("Error exchanging code for tokens", e)

    def stop_https_server(self): 
        shutdown_https_server() 
        self.response_text.insert(tk.END, "HTTPS server stopped.\n")

    def display_tokens(self, tokens):
        try:
        # Clear the response text if the checkbox is checked 
            if self.clear_text_checkbox.get(): 
                self.response_text.delete(1.0, tk.END)
            #self.response_text.delete(1.0, tk.END)
            
            self.response_text.insert(tk.END, f"Display Tokens:\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, "Display Tokens:\n")
                self.add_horizontal_rule()

            for key, value in tokens.items():
                self.response_text.insert(tk.END, f"{key}: {value}\n")
                if self.log_oidc_process.get():
                    self.oidc_log_text.insert(tk.END, f"{key}: {value}\n")
                    self.add_horizontal_rule()


            if "id_token" in tokens:
                self.decode_jwt(tokens["id_token"])
            if "access_token" in tokens:
                self.userinfo_query(tokens["access_token"], "access")
            if "access_token" in tokens:
                self.introspect_token(tokens["access_token"], "access")
            if "refresh_token" in tokens:
                self.introspect_token(tokens["refresh_token"], "refresh")
        except Exception as e:
            self.response_text.insert(tk.END, f"Error displaying tokens: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error displaying tokens: {e}\n")
                self.add_horizontal_rule()
            log_error("Error displaying tokens", e)


    def decode_jwt(self, token):
        try:
            header, payload, signature = token.split('.')
            header_decoded = base64.urlsafe_b64decode(header + '==').decode('utf-8')
            payload_decoded = base64.urlsafe_b64decode(payload + '==').decode('utf-8')
            decoded = {
                "header": json.loads(header_decoded),
                "payload": json.loads(payload_decoded),
                "signature": signature
            }
            self.response_text.insert(tk.END, f"Decoded ID Token: {json.dumps(decoded, indent=4)}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Decoded ID Token: {json.dumps(decoded, indent=4)}\n")
                self.add_horizontal_rule()

        except Exception as e:
            self.response_text.insert(tk.END, f"Error decoding JWT: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error decoding JWT: {e}\n")
                self.add_horizontal_rule()


    def userinfo_query(self, token, token_type):
        try:
            headers = {
                'Authorization': f'Bearer {token}'
            }
            response = requests.get(f"{self.userinfo_endpoint}", headers=headers, verify=False)
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error userinfo {token_type} token: {response.status_code}\n")
                if self.log_oidc_process.get():
                    self.oidc_log_text.insert(tk.END, f"Error userinfo {token_type} token: {response.status_code}\n")
                    self.add_horizontal_rule()

                return

            userinfo = response.json()
            self.response_text.insert(tk.END, f"UserInfo {token_type.capitalize()} Token: {json.dumps(userinfo, indent=4)}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"UserInfo {token_type.capitalize()} Token: {json.dumps(userinfo, indent=4)}\n")
                self.add_horizontal_rule()
        except Exception as e:
            self.response_text.insert(tk.END, f"Error calling UserInfo: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error calling UserInfo: {e}\n")
                self.add_horizontal_rule()


    def introspect_token(self, token, token_type):
        try:
            data = {
                "token": token,
                "token_type_hint": token_type,
                "client_id": self.client_id,
            }
            headers = {}
            if self.auth_method.get() == "client_secret_post":
                data["client_secret"] = self.client_secret
            elif self.auth_method.get() == "client_secret_basic":
                basic_auth = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
                headers["Authorization"] = f"Basic {basic_auth}"
            elif self.auth_method.get() == "client_secret_jwt":
                now = int(time.time())
                payload = {
                    "iss": self.client_id,
                    "sub": self.client_id,
                    "aud": self.introspect_endpoint,
                    "exp": now + 300,  # Token expires in 5 minutes
                    "iat": now
                }
                client_assertion = base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')
                data["client_assertion"] = client_assertion
                data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

            response = requests.post(self.introspect_endpoint, data=data, headers=headers, verify=False)
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error introspecting {token_type} token: {response.status_code}\n")
                if self.log_oidc_process.get():
                    self.oidc_log_text.insert(tk.END, f"Error introspecting {token_type} token: {response.status_code}\n")
                    self.add_horizontal_rule()
                return

            introspection = response.json()
            self.response_text.insert(tk.END, f"Introspected {token_type.capitalize()} Token: {json.dumps(introspection, indent=4)}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Introspected {token_type.capitalize()} Token: {json.dumps(introspection, indent=4)}\n")
                self.add_horizontal_rule()
        except Exception as e:
            self.response_text.insert(tk.END, f"Error introspecting {token_type} token: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error introspecting {token_type} token: {e}\n")
                self.add_horizontal_rule()
            log_error("Error introspecting token", e)

    def display_well_known_response(self, config):
        # Clear only the treeview items instead of destroying all widgets
        if hasattr(self, 'response_table'):
            self.response_table.delete(*self.response_table.get_children())
        else:
            # Add scrollbars
            table_scrollbar_y = ttk.Scrollbar(self.response_table_frame, orient="vertical")
            table_scrollbar_x = ttk.Scrollbar(self.response_table_frame, orient="horizontal")

            columns = ("Key", "Value")
            self.response_table = ttk.Treeview(self.response_table_frame, columns=columns, show="headings", yscrollcommand=table_scrollbar_y.set, xscrollcommand=table_scrollbar_x.set)
            self.response_table.heading("Key", text="Key")
            self.response_table.heading("Value", text="Value")

            # Set column widths
            self.response_table.column("Key", width=200)
            self.response_table.column("Value", width=600)

            # Attach scrollbars to the table
            table_scrollbar_y.config(command=self.response_table.yview)
            table_scrollbar_x.config(command=self.response_table.xview)

            self.response_table.grid(row=1, column=1, sticky="nsew")
            table_scrollbar_y.grid(row=1, column=0, sticky="ns")
            table_scrollbar_x.grid(row=0, column=1, sticky="ew")

            # Increase the row height
            style = ttk.Style()
            style.configure("Treeview", rowheight=30)

            # Bind double-click event
            self.response_table.bind("<Double-1>", self.on_item_double_click)

        for key, value in config.items():
            self.response_table.insert("", "end", values=(key, value))

    def on_item_double_click(self, event):
        item = event.widget.selection()[0]
        column = event.widget.identify_column(event.x)
        value = event.widget.item(item, "values")[int(column[1:]) - 1]
        self.master.clipboard_clear()
        self.master.clipboard_append(value)
        self.master.update()  # Keep the clipboard updated
        tk.messagebox.showinfo("Copied", f"Copied to clipboard:\n{value}")
