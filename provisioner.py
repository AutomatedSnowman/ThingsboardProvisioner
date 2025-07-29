import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import requests
import re
import serial.tools.list_ports
import os
import shutil
import subprocess
import tempfile

DEVICE_TYPES = ["default", "default1", "default2"]
PLATFORMIO_PROJECT_DIR = tempfile.mkdtemp(prefix="tbprovisioner_")

class ThingsBoardProvisioner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Thingsboard Device Provisioner")
        self.geometry("600x620")
        self.resizable(False, False)

        self.token = None
        self.headers = None
        self.ino_path = None

        # UI
        ttk.Label(self, text="Thingsboard Dashboard URL:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.tb_url_var = tk.StringVar(value="http://localhost")
        ttk.Entry(self, textvariable=self.tb_url_var, width=55).grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(self, text="Tenant Username:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.user_var = tk.StringVar(value="tenant@thingsboard.org")
        ttk.Entry(self, textvariable=self.user_var, width=55).grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(self, text="Tenant Password:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.pass_var = tk.StringVar(value="tenant")
        ttk.Entry(self, textvariable=self.pass_var, show="*", width=55).grid(row=2, column=1, padx=10, pady=5)

        ttk.Label(self, text="New Customer Name:").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.customer_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.customer_var, width=55).grid(row=3, column=1, padx=10, pady=5)

        ttk.Label(self, text="Device Type:").grid(row=4, column=0, sticky="w", padx=10, pady=5)
        self.device_type_var = tk.StringVar(value=DEVICE_TYPES[0])
        cb = ttk.Combobox(self, textvariable=self.device_type_var, values=DEVICE_TYPES, state="readonly", width=52)
        cb.grid(row=4, column=1, padx=10, pady=5)
        cb.bind("<<ComboboxSelected>>", self.on_device_type_change)

        ttk.Label(self, text="New Device Name:").grid(row=5, column=0, sticky="w", padx=10, pady=5)
        self.device_var = tk.StringVar()
        self.device_entry = ttk.Entry(self, textvariable=self.device_var, width=55, state='readonly')
        self.device_entry.grid(row=5, column=1, padx=10, pady=5)

        ttk.Label(self, text="Select .ino File:").grid(row=6, column=0, sticky="w", padx=10, pady=5)
        self.file_btn = ttk.Button(self, text="Browse", command=self.select_ino)
        self.file_btn.grid(row=6, column=1, sticky="w", padx=10, pady=5)

        ttk.Label(self, text="COM Port:").grid(row=7, column=0, sticky="w", padx=10, pady=5)
        self.com_var = tk.StringVar()
        self.com_dropdown = ttk.Combobox(self, textvariable=self.com_var, width=52)
        self.com_dropdown.grid(row=7, column=1, padx=10, pady=5)
        self.refresh_com_ports()

        self.provision_btn = ttk.Button(self, text="Provision + Upload", command=self.provision)
        self.provision_btn.grid(row=8, column=0, columnspan=2, pady=15)

        ttk.Label(self, text="Log Output:").grid(row=9, column=0, sticky="nw", padx=10, pady=5)
        self.log_text = tk.Text(self, height=15, width=72, state="disabled", wrap="word")
        self.log_text.grid(row=10, column=0, columnspan=2, padx=10, pady=5)

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def refresh_com_ports(self):
        ports = serial.tools.list_ports.comports()
        self.com_dropdown["values"] = [port.device for port in ports]
        if ports:
            self.com_var.set(ports[0].device)

    def select_ino(self):
        path = filedialog.askopenfilename(filetypes=[("INO files", "*.ino")])
        if path:
            self.ino_path = path
            self.log(f"Selected .ino: {os.path.basename(path)}")

    def on_device_type_change(self, event=None):
        device_type = self.device_type_var.get()
        if device_type == "default":
            self.device_var.set("")
            return
        threading.Thread(target=self.autoname_device, args=(device_type,), daemon=True).start()

    def autoname_device(self, device_type):
        try:
            if not self.token:
                self.token = self.login(self.tb_url_var.get(), self.user_var.get(), self.pass_var.get())
                self.headers = {"X-Authorization": f"Bearer {self.token}"}
            prefix = "CPU" if "CPU" in device_type else "Micro" if "Micro" in device_type else "DEV"
            highest_index = 0
            page = 0
            while True:
                url = f"{self.tb_url_var.get()}/api/tenant/devices?pageSize=100&page={page}"
                resp = requests.get(url, headers=self.headers)
                devices = resp.json().get("data", [])
                if not devices: break
                for d in devices:
                    if d.get("type") != device_type: continue
                    m = re.match(r"^(\d{4})" + re.escape(prefix) + r"$", d.get("name", ""))
                    if m: highest_index = max(highest_index, int(m.group(1)))
                if not resp.json().get("hasNext", False): break
                page += 1
            next_name = f"{highest_index+1:04d}{prefix}"
            self.device_var.set(next_name)
            self.log(f"Auto-generated device name: {next_name}")
        except Exception as e:
            self.log(f"Auto-naming error: {e}")

    def provision(self):
        self.provision_btn.config(state="disabled")
        threading.Thread(target=self._provision_thread, daemon=True).start()

    def _provision_thread(self):
        try:
            url, user, pw = self.tb_url_var.get(), self.user_var.get(), self.pass_var.get()
            customer_name = self.customer_var.get()
            device_name = self.device_var.get()
            device_type = self.device_type_var.get()
            com_port = self.com_var.get()

            if not all([url, user, pw, customer_name, device_name, device_type, com_port, self.ino_path]):
                messagebox.showerror("Missing Fields", "Please fill in all fields and select a .ino file.")
                return

            self.log("Logging into ThingsBoard...")
            token = self.login(url, user, pw)
            headers = {"X-Authorization": f"Bearer {token}"}
            self.log("Login successful.")

            self.log(f"Creating customer '{customer_name}'...")
            customer_id = self.create_customer(url, headers, customer_name)["id"]["id"]
            self.log(f"Customer ID: {customer_id}")

            self.log(f"Creating device '{device_name}'...")
            device_id = self.create_device(url, headers, device_name, device_type)["id"]["id"]
            self.log(f"Device ID: {device_id}")

            self.log("Assigning device to customer...")
            self.assign_device_to_customer(url, headers, customer_id, device_id)

            access_token = self.get_device_credentials(url, headers, device_id)["credentialsId"]
            self.log(f"Access Token: {access_token}")

            self.prepare_platformio_project(access_token)
            self.log("Uploading via PlatformIO...")
            subprocess.run(["platformio", "run", "-t", "upload"], cwd=PLATFORMIO_PROJECT_DIR, check=True)
            self.log("Upload successful!")

            messagebox.showinfo("Success", f"Provisioning complete.\nAccess Token: {access_token}")
        except Exception as e:
            self.log(f"Provisioning failed: {e}")
            messagebox.showerror("Failed", str(e))
        finally:
            self.provision_btn.config(state="normal")

    def login(self, url, username, password):
        resp = requests.post(f"{url}/api/auth/login", json={"username": username, "password": password})
        resp.raise_for_status()
        return resp.json()["token"]

    def create_customer(self, url, headers, name):
        resp = requests.post(f"{url}/api/customer", headers=headers, json={"title": name})
        resp.raise_for_status()
        return resp.json()

    def create_device(self, url, headers, name, device_type):
        resp = requests.post(f"{url}/api/device", headers=headers, json={"name": name, "type": device_type})
        resp.raise_for_status()
        return resp.json()

    def assign_device_to_customer(self, url, headers, customer_id, device_id):
        resp = requests.post(f"{url}/api/customer/{customer_id}/device/{device_id}", headers=headers)
        resp.raise_for_status()

    def get_device_credentials(self, url, headers, device_id):
        resp = requests.get(f"{url}/api/device/{device_id}/credentials", headers=headers)
        resp.raise_for_status()
        return resp.json()

    def prepare_platformio_project(self, token):
        if os.path.exists(PLATFORMIO_PROJECT_DIR):
            shutil.rmtree(PLATFORMIO_PROJECT_DIR)
        os.makedirs(os.path.join(PLATFORMIO_PROJECT_DIR, "src"))

        with open(self.ino_path, "r") as f:
            code = f.read()

        # Inject or replace token define
        code = re.sub(r'#define\s+TOKEN\s+".*"', f'#define TOKEN "{token}"', code)
        if "TOKEN" not in code:
            code = f'#define TOKEN "{token}"\n' + code

        with open(os.path.join(PLATFORMIO_PROJECT_DIR, "src", "main.ino"), "w") as f:
            f.write(code)

        with open(os.path.join(PLATFORMIO_PROJECT_DIR, "platformio.ini"), "w") as f:
            f.write("""[env:seeed_xiao_esp32c6]
platform = https://github.com/pioarduino/platform-espressif32/releases/download/stable/platform-espressif32.zip
board = seeed_xiao_esp32c6
framework = arduino
monitor_speed = 115200
upload_speed = 921600
upload_port = COM3
""")

if __name__ == "__main__":
    app = ThingsBoardProvisioner()
    app.mainloop()
