```

def backup_data(NSLookup, HTTPRequest):
    try:
        data = {}
        environments = ["production", "qa", "development"]

        for env in environments:
            # Get Lookup Table
            try:
                with open(f"{env}_domains.json", "r") as file:
                    nslookup_data = json.load(file)
            except FileNotFoundError:
                nslookup_data = ["server1"]

            # Get HTTP Table
            try:
                with open(f"{env}_urls.json", "r") as file:
                    http_data = json.load(file)
            except FileNotFoundError:
                http_data = [{"url": "server1", "regex": "ok"}]

            # Store data for the environment
            data[env] = {
                "nslookup": nslookup_data,
                "httprequest": http_data
            }

        # Add theme information
        data["theme"] = ttk.Style().theme_use()

        # Create backup file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"backup_{timestamp}.json"
        with open(filename, "w") as file:
            json.dump(data, file)

        messagebox.showinfo("Backup Completed", f"The Backup File {filename} was created.")
        print(f"Backup created: {filename}")
    except Exception as e:
        print(f"Error creating backup: {e}")
        log_error("Error creating backup file", e)

def restore_data():
    filename = filedialog.askopenfilename(title="Select Backup File", filetypes=[("JSON files", "*.json")])
    if filename:
        try:
            with open(filename, "r") as file:
                data = json.load(file)

            environments = ["production", "qa", "development"]

            for env in environments:
                with open(f"{env}_domains.json", "w") as ns_file:
                    json.dump(data.get(env, {}).get("nslookup", []), ns_file)
                with open(f"{env}_urls.json", "w") as http_file:
                    json.dump(data.get(env, {}).get("httprequest", []), http_file)

            ttk.Style().theme_use(data.get("theme", "clam"))
            print(f"Data restored from {filename}")
        except Exception as e:
            print(f"Error restoring data: {e}")
            log_error("Restore failed", e)
```
