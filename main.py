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
        self.root.title("Volatility 2.6.1 Graphic User Interface")
        self.memfile = ""
        self.profile = ""
        self.outdir = ""
        self.is_running = False

        
        menubar = tk.Menu(root)

        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Load", command=self.load_file)
        menubar.add_cascade(label="File", menu=filemenu)

        procdump_menu = tk.Menu(menubar, tearoff=0)
        procdump_menu.add_command(label="Run ProcDump", command=self.run_procdump)
        menubar.add_cascade(label="ProcDump", menu=procdump_menu)

        dumpfiles_menu = tk.Menu(menubar, tearoff=0)
        dumpfiles_menu.add_command(label="Run DumpFiles", command=self.run_dumpfiles)
        menubar.add_cascade(label="DumpFiles", menu=dumpfiles_menu)

        root.config(menu=menubar)

        self.text = scrolledtext.ScrolledText(root, width=100, height=25)
        self.text.pack(padx=10, pady=10)

        self.text.tag_config("info", foreground="blue")
        self.text.tag_config("success", foreground="green")
        self.text.tag_config("error", foreground="red")
        self.text.tag_config("init", foreground="purple")
        self.insert_text("[+] Please load RAM memory file...to continue\n", "init")

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

    def insert_text(self, message, tag="info"):
        self.text.insert(tk.END, message, tag)
        self.text.see(tk.END)
        self.root.update()

    def load_file(self):
        filepath = filedialog.askopenfilename(
            title="Select RAM dump",
            filetypes=[("Memory files", "*.raw *.mem *.dmp"), ("All files", "*.*")]
        )

        if filepath and filepath.lower().endswith(('.raw', '.mem', '.dmp')):
            self.memfile = filepath
            self.insert_text("[+] File loaded: {}\n".format(self.memfile), "success")
            self.run_imageinfo()
            self.button.config(state=tk.NORMAL)
        else:
            messagebox.showerror("Error", "Invalid file type. Please select a .raw, .mem, or .dmp file.")

    def get_volatility_path(self):
        try:
            vol_path = subprocess.check_output("which vol.py", shell=True).strip()
            if vol_path:
                return vol_path
            else:
                raise Exception("Volatility script (vol.py) not found in the PATH.")
        except subprocess.CalledProcessError as e:
            self.insert_text("[!] Error finding vol.py: {}\n".format(e), "error")
            return None

    def run_imageinfo(self):
        self.insert_text("[*] Running imageinfo...\n", "info")
        self.insert_text("[*] Executing vol.py with command: python2 vol.py -f {} imageinfo\n".format(self.memfile), "info")

        vol_script_path = self.get_volatility_path()
        if not vol_script_path:
            return

        try:
            cmd = ["python2", vol_script_path, "-f", self.memfile, "imageinfo"]
            self.insert_text("[*] Executing the command... Please wait.\n", "info")
            self.root.update()

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if stderr:
                self.insert_text("[!] Error: {}\n".format(stderr.decode("utf-8")), "error")

            decoded_output = stdout.decode("utf-8", errors="replace")
            self.insert_text(decoded_output + "\n", "info")

            profiles = []
            for line in decoded_output.splitlines():
                if "Suggested Profile(s)" in line:
                    profiles = line.split(":")[1].split(",")
                    profiles = [p.strip() for p in profiles]
                    self.insert_text("[+] Suggested profiles: {}\n".format(", ".join(profiles)), "success")
                    break

            self.profile_combobox['values'] = profiles
            if profiles:
                self.profile_combobox.set(profiles[0])  
                self.profile = profiles[0]
                self.insert_text("[+] Profile selected: {}\n".format(self.profile), "success")

        except Exception as e:
            self.insert_text("[!] Error executing imageinfo: {}\n".format(str(e)), "error")

    def on_profile_select(self, event):
        self.profile = self.profile_combobox.get()
        self.insert_text("[+] Profile selected: {}\n".format(self.profile), "success")

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
        self.insert_text("[*] Starting analysis with profile {}...\n".format(self.profile), "info")
        self.root.update()

        log_file = os.path.join(self.outdir, "log.txt")
        with open(log_file, "w") as log:
            for plugin in plugins:
                if not self.is_running:
                    break
                self.insert_text("[*] Running {}...\n".format(plugin), "info")
                self.root.update()
                log.write("[*] Running {}\n".format(plugin))

                try:
                    plugin_out = os.path.join(self.outdir, "{}.txt".format(plugin))
                    cmd = ["python2", self.get_volatility_path(), "-f", self.memfile, "--profile={}".format(self.profile), plugin]

                    command_string = " ".join(cmd)
                    self.insert_text("[*] Running command: {}\n".format(command_string), "info")

                    with open(plugin_out, "w") as f:
                        subprocess.call(cmd, stdout=f, stderr=open(os.devnull, 'w'))

                    if os.path.getsize(plugin_out) == 0:
                        self.insert_text("[!] No data returned for plugin {}. You might want to try a different profile or dismiss this alert.\n".format(plugin), "error")

                except Exception as e:
                    self.insert_text("[!] Error running {}: {}\n".format(plugin, str(e)), "error")
                    log.write("[!] Error running {}: {}\n".format(plugin, str(e)))

        self.insert_text("[+] Analysis complete. Results in: {}\n".format(self.outdir), "success")
        self.root.update()
        self.stop_button.config(state=tk.DISABLED)



    def stop_analysis(self):
        self.is_running = False
        self.insert_text("[!] Analysis stopped.\n", "error")
        self.root.update()
        self.stop_button.config(state=tk.DISABLED)
        self.button.config(state=tk.NORMAL)

    def run_procdump(self):
        if not self.memfile:
            messagebox.showerror("Error", "No RAM dump file loaded.")
            return

        cmd = ["procdump", "-Q", "0x000000003ecec2b0", "-u", "-n", "-D", "."]
        self.insert_text("[*] Running ProcDump...\n", "info")
        try:
            subprocess.call(cmd)
            self.insert_text("[+] ProcDump completed successfully.\n", "success")
        except Exception as e:
            self.insert_text("[!] Error running ProcDump: {}\n".format(str(e)), "error")

    def run_dumpfiles(self):
        if not self.memfile:
            messagebox.showerror("Error", "No RAM dump file loaded.")
            return

        cmd = ["dumpfiles", "-Q", "0x000000003ecec2b0", "-u", "-n", "-D", "."]
        self.insert_text("[*] Running DumpFiles...\n", "info")
        try:
            subprocess.call(cmd)
            self.insert_text("[+] DumpFiles completed successfully.\n", "success")
        except Exception as e:
            self.insert_text("[!] Error running DumpFiles: {}\n".format(str(e)), "error")

if __name__ == "__main__":
    root = tk.Tk()
    app = VolatilityGUI(root)
    root.mainloop()
