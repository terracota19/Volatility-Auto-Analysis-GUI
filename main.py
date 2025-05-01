import os
import subprocess
import Tkinter as tk
from Tkinter import filedialog, messagebox, scrolledtext, ttk
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
        filepath = filedialog.askopenfilename(title="Select RAM dump", filetypes=[("Memory files", "*.raw;*.mem;*.dmp")])
        if filepath:
            self.memfile = filepath
            self.text.insert(tk.END, f"[+] File loaded: {self.memfile}\n")
            self.run_imageinfo()
            self.button.config(state=tk.NORMAL)

    def run_imageinfo(self):
        self.text.insert(tk.END, "[*] Running imageinfo...\n")
        try:
            process = subprocess.Popen(["volatility", "-f", self.memfile, "imageinfo"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            decoded_output = stdout.decode("utf-8") if isinstance(stdout, str) else stdout
            self.text.insert(tk.END, decoded_output + "\n")

            profiles = []
            for line in decoded_output.splitlines():
                if "Suggested Profile(s)" in line:
                    profiles = line.split(":")[1].split(",")
                    profiles = [p.strip() for p in profiles]
                    self.text.insert(tk.END, f"[+] Suggested profiles: {', '.join(profiles)}\n")
                    break

            self.profile_combobox['values'] = profiles
            self.profile_combobox.set(profiles[0])
        except subprocess.CalledProcessError as e:
            self.text.insert(tk.END, f"[!] Error running imageinfo: {e.output.decode()}\n")
        except Exception as e:
            self.text.insert(tk.END, f"[!] Unexpected error: {str(e)}\n")

    def on_profile_select(self, event):
        self.profile = self.profile_combobox.get()
        self.text.insert(tk.END, f"[+] Profile selected: {self.profile}\n")

    def run_analysis(self):
        if not self.profile:
            messagebox.showerror("Error", "No valid profile selected.")
            return

        self.outdir = filedialog.askdirectory(title="Select Output Folder")
        if not self.outdir:
            return

        filename = os.path.basename(self.memfile)
        name = os.path.splitext(filename)[0]
        self.outdir = os.path.join(self.outdir, f"case-{self.profile}-{name}")
        os.makedirs(self.outdir, exist_ok=True)

        plugins = ["pslist", "pstree", "psscan", "netscan", "filescan", "dlllist", "cmdscan", "consoles", "hivelist", "malfind"]

        self.is_running = True
        self.button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        threading.Thread(target=self.run_plugins, args=(plugins,)).start()

    def run_plugins(self, plugins):
        self.text.insert(tk.END, f"[*] Starting analysis with profile {self.profile}...\n")
        self.root.update()

        log_file = os.path.join(self.outdir, "log.txt")
        with open(log_file, "w") as log:
            for plugin in plugins:
                if not self.is_running:
                    break
                self.text.insert(tk.END, f"[*] Running {plugin}...\n")
                self.root.update()
                log.write(f"[*] Running {plugin}\n")

                try:
                    with open(f"{self.outdir}/{plugin}.txt", "w") as f:
                        subprocess.run(["volatility", "-f", self.memfile, "--profile=" + self.profile, plugin], stdout=f, stderr=subprocess.DEVNULL)
                except Exception as e:
                    self.text.insert(tk.END, f"[!] Error running {plugin}: {str(e)}\n")
                    log.write(f"[!] Error running {plugin}: {str(e)}\n")

        self.text.insert(tk.END, f"[+] Analysis complete. Results in: {self.outdir}\n")
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
