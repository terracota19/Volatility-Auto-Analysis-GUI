import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

class VolatilityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Volatility GUI")
        self.memfile = ""
        self.profile = ""

        # Menú
        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Load", command=self.load_file)
        menubar.add_cascade(label="File", menu=filemenu)
        root.config(menu=menubar)

        # Área de texto
        self.text = scrolledtext.ScrolledText(root, width=100, height=20)
        self.text.pack(padx=10, pady=10)

        # Lista desplegable para elegir el perfil
        self.profile_label = tk.Label(root, text="Select Profile:")
        self.profile_label.pack(padx=10, pady=5)
        self.profile_combobox = ttk.Combobox(root, state="readonly")
        self.profile_combobox.pack(padx=10, pady=5)
        self.profile_combobox.bind("<<ComboboxSelected>>", self.on_profile_select)

        # Botón para análisis completo
        self.button = tk.Button(root, text="Run Full Analysis", command=self.run_analysis)
        self.button.pack(pady=10)
        self.button.config(state=tk.DISABLED)

    def load_file(self):
        filepath = filedialog.askopenfilename(title="Select RAM dump")
        if filepath:
            self.memfile = filepath
            self.text.insert(tk.END, f"[+] File loaded: {self.memfile}\n")
            self.run_imageinfo()
            self.button.config(state=tk.NORMAL)

    def run_imageinfo(self):
        self.text.insert(tk.END, "[*] Running imageinfo...\n")
        try:
            output = subprocess.check_output(["volatility", "-f", self.memfile, "imageinfo"], stderr=subprocess.STDOUT)
            decoded_output = output.decode("utf-8")
            self.text.insert(tk.END, decoded_output + "\n")

            # Extract suggested profiles
            profiles = []
            for line in decoded_output.splitlines():
                if "Suggested Profile(s)" in line:
                    profiles = line.split(":")[1].split(",")
                    profiles = [p.strip() for p in profiles]
                    self.text.insert(tk.END, f"[+] Suggested profiles: {', '.join(profiles)}\n")
                    break

            # Populate combobox with suggested profiles
            self.profile_combobox['values'] = profiles
            self.profile_combobox.set(profiles[0])  # Default to the first profile
        except subprocess.CalledProcessError as e:
            self.text.insert(tk.END, f"[!] Error running imageinfo: {e.output.decode()}\n")

    def on_profile_select(self, event):
        self.profile = self.profile_combobox.get()
        self.text.insert(tk.END, f"[+] Profile selected: {self.profile}\n")

    def run_analysis(self):
        if not self.profile:
            messagebox.showerror("Error", "No valid profile selected.")
            return

        filename = os.path.basename(self.memfile)
        name = os.path.splitext(filename)[0]
        outdir = f"case-{self.profile}-{name}"
        os.makedirs(outdir, exist_ok=True)

        plugins = ["pslist", "pstree", "psscan", "netscan", "filescan", "dlllist", "cmdscan", "consoles", "hivelist", "malfind"]

        self.text.insert(tk.END, f"[*] Starting analysis with profile {self.profile}...\n")
        self.root.update()

        for plugin in plugins:
            self.text.insert(tk.END, f"[*] Running {plugin}...\n")
            self.root.update()
            try:
                with open(f"{outdir}/{plugin}.txt", "w") as f:
                    subprocess.run(["volatility", "-f", self.memfile, "--profile=" + self.profile, plugin], stdout=f, stderr=subprocess.DEVNULL)
            except Exception as e:
                self.text.insert(tk.END, f"[!] Error running {plugin}: {str(e)}\n")

        self.text.insert(tk.END, f"[+] Analysis complete. Results in: {outdir}\n")

# Start the app
if __name__ == "__main__":
    root = tk.Tk()
    app = VolatilityGUI(root)
    root.mainloop()
