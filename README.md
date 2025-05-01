# Volatility-Auto-Analysis-GUI 
A Python2 GUI tool to automate memory dump analysis using Volatility 2.6.1  [Volatility Framework](https://www.volatilityfoundation.org/).
It allows users to load memory files, automatically detects the correct profile with imageinfo, and runs common forensic commands. Results are organized into case folders for easy review.

![image](https://github.com/user-attachments/assets/9e7e69a5-404d-4e2e-af52-32b5624f2f19)

## Features

- Load memory dump files (`.raw`, `.mem`, `.dmp`)
- Automatically runs `imageinfo` to suggest valid profiles
- Automatically selects the first suggested profile
- Supports popular Volatility plugins (pslist, pstree, dlllist, netscan, malfind, etc.)
- Real-time log output with colored messages for readability
- Option to stop analysis at any time
- Saves results per plugin in an organized output directory

## Requirements

- Python **2.7** (not compatible with Python 3.x)
- Volatility Framework (legacy version using `vol.py`)
- Unix Operation System.

### Python Dependencies

Install Python dependencies:

```bash
pip2 install -r requirements.txt
```

On Linux systems, you might need to install Tkinter using your package manager:
```bash
sudo apt-get install python-tk
```

## How to Use

1. Run the application with Python 2.7:

   ```bash
   python2 volatility_gui.py
   ```
2. Go to File > Load to select a memory dump file (.raw, .mem, .dmp).

  The GUI will automatically run imageinfo and suggest valid profiles.
  
  The first suggested profile will be automatically selected.
3. Click Run Full Analysis to start running a set of Volatility plugins.

  You can stop the analysis at any time using the Stop Analysis button.

All plugin results will be saved in a dedicated subdirectory inside your selected output folder.  
