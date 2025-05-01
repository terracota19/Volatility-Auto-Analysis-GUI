#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import subprocess
import shutil
import Tkinter as tk
import ttk
import tkFileDialog as filedialog
import tkMessageBox as messagebox
import ScrolledText as scrolledtext
import threading

class VolatilityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Volatility GUI")
        self.memfile = ""
        self.profile = ""
        self.outdir = ""
        self.is_running = False

        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Load", command=self.load_file)
        menubar.add_cascade(label="File", menu=filemenu)
        root.config(menu=menubar)

        self.text = scrolledtext.ScrolledText(root, width=100, height=20)
        self.text.pack(padx=10, pady=10)

        self.profile_label = tk.Label(root, text="Select Profile:")
        self.profile_label.pack(padx=10, pady=5)
        self.profile_combobox = ttk.Combobox(root, state="readonly")
        self.profile_combobox.pack(padx=10, pady=5)
        self.profile_combobox.bind("<<ComboboxSelected>>", self.on_profile_select)

        self.button = tk.Button(root, text="Run Full Analysis", command=self.run_analysis)
        self.button.pack(pady=10)
        self.button.config(state=tk.DISABLED)

        self.stop_button = tk.Button(root, text="Stop Analysis", command=self.stop_analysis)
        self.stop_button.pack(pady=10)
        self.stop_button.config(state=tk.DISABLED)

    def load_file(self):
        filepath = filedialog.askopenfilename(
            title="Select RAM dump",
            filetypes=[("Memory files", "*.raw *.mem *.dmp"), ("All files", "*.*")]
        )

        if filepath and filepath.lower().endswith(('.raw', '.mem', '.dmp')):
            self.memfile = filepath
            self.text.insert(tk.END, "[+] File loaded: {}\n".format(self.memfile))
            self.run_imageinfo()
            self.button.config(state=tk.NORMAL)
        else:
            messagebox.showerror("Error", "Invalid file type. Please select a .raw, .mem, or .dmp file.")

    def get_volatility_path(self):
        try:
            vol_path = subprocess.check_output("which vol.py", shell=True).decode().strip()
            if vol_path:
                return vol_path
            else:
                raise Exception("Volatility script (vol.py) not found in the PATH.")
        except subprocess.CalledProcessError as e:
            self.text.insert(tk.END, "[!] Error finding vol.py: {}\n".format(e))
            return None

    def run_imageinfo(self):
        self.text.insert(tk.END, "[*] Running imageinfo...\n")
        self.text.insert(tk.END, "[*] Executing vol.py with command: python2 vol.py -f {} imageinfo\n".format(self.memfile))
        self.root.update()  # Actualiza la interfaz para mostrar el mensaje de "Ejecutando..."

        vol_script_path = self.get_volatility_path()
        if not vol_script_path:
            return

        try:
            cmd = ["python2", vol_script_path, "-f", self.memfile, "imageinfo"]

            # Mostrar que el proceso está en ejecución
            self.text.insert(tk.END, "[*] Ejecutando el comando... Por favor, espere.\n")
            self.root.update()  # Refresca la interfaz para que se vea el mensaje.

            # Ejecuta el proceso sin esperar un timeout usando un bucle simple.
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()  # Sin timeout, simplemente espera a que termine

            if stderr:
                self.text.insert(tk.END, "[!] Error: {}\n".format(stderr.decode("utf-8")))

            decoded_output = stdout.decode("utf-8", errors="replace")
            self.text.insert(tk.END, decoded_output + "\n")

            profiles = []
            for line in decoded_output.splitlines():
                if "Suggested Profile(s)" in line:
                    profiles = line.split(":")[1].split(",")
                    profiles = [p.strip() for p in profiles]
                    self.text.insert(tk.END, "[+] Suggested profiles: {}\n".format(", ".join(profiles)))
                    break

            self.profile_combobox['values'] = profiles
            if profiles:
                self.profile_combobox.set(profiles[0])

        except subprocess.CalledProcessError as e:
            self.text.insert(tk.END, "[!] Error ejecutando imageinfo: {}\n".format(str(e)))
        except Exception as e:
            self.text.insert(tk.END, "[!] Error ejecutando imageinfo: {}\n".format(str(e)))

    def on_profile_select(self, event):
        self.profile = self.profile_combobox.get()
        self.text.insert(tk.END, "[+] Profile selected: {}\n".format(self.profile))

    def run_analysis(self):
        if not self.profile:
            messagebox.showerror("Error", "No valid profile selected.")
            return

        self.outdir = filedialog.askdirectory(title="Select Output Folder")
        if not self.outdir:
            return

        filename = os.path.basename(self.memfile)
        name = os.path.splitext(filename)[0]
        self.outdir = os.path.join(self.outdir, "case-{}-{}".format(self.profile, name))
        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)

        plugins = ["pslist", "pstree", "psscan", "netscan", "filescan", "dlllist", "cmdscan", "consoles", "hivelist", "malfind"]

        self.is_running = True
        self.button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        threading.Thread(target=self.run_plugins, args=(plugins,)).start()

    def run_plugins(self, plugins):
        self.text.insert(tk.END, "[*] Starting analysis with profile {}...\n".format(self.profile))
        self.root.update()

        log_file = os.path.join(self.outdir, "log.txt")
        with open(log_file, "w") as log:
            for plugin in plugins:
                if not self.is_running:
                    break
                self.text.insert(tk.END, "[*] Running {}...\n".format(plugin))
                self.root.update()
                log.write("[*] Running {}\n".format(plugin))

                try:
                    plugin_out = os.path.join(self.outdir, "{}.txt".format(plugin))
                    cmd = ["python2", self.get_volatility_path(), "-f", self.memfile, "--profile={}".format(self.profile), plugin]

                    self.text.insert(tk.END, "[*] Running plugin command: {}\n".format(" ".join(cmd)))

                    with open(plugin_out, "w") as f:
                        subprocess.call(cmd, stdout=f, stderr=open(os.devnull, 'w'))
                except Exception as e:
                    self.text.insert(tk.END, "[!] Error running {}: {}\n".format(plugin, str(e)))
                    log.write("[!] Error running {}: {}\n".format(plugin, str(e)))

        self.text.insert(tk.END, "[+] Analysis complete. Results in: {}\n".format(self.outdir))
        self.root.update()
        self.stop_button.config(state=tk.DISABLED)

    def stop_analysis(self):
        self.is_running = False
        self.text.insert(tk.END, "[!] Analysis stopped.\n")
        self.root.update()
        self.stop_button.config(state=tk.DISABLED)
        self.button.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = VolatilityGUI(root)
    root.mainloop()
