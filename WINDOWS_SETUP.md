# Windows Setup Guide — NetScope.ai

This guide details how to configure, build, and run the NetScope.ai application on Windows systems.

We support two ways to run the project:
1.  **AI Web Application (FastAPI + JS Frontend)** — Recommended.
2.  **C++ DPI Engine Command-Line Tool** — Historical reference.

---

## Part 1: Running the AI Web Application (FastAPI)

### Step 1: Install Python
1.  Download **Python 3.10 or higher** (e.g., Python 3.11/3.12) from the official website:
    - [Python Downloads](https://www.python.org/downloads/windows/)
2.  Run the installer executable.
3.  **CRITICAL:** Check the box at the bottom that says **"Add python.exe to PATH"** before clicking "Install Now".
    
    ![Add Python to PATH](https://docs.python.org/3/_images/win_installer.png)

### Step 2: Configure Virtual Environment
Open **PowerShell** or **Command Prompt** in the project directory (`d:\CS\Projects\Packet_analyzer`):

```powershell
# Create a virtual environment named .venv_pcap
python -m venv .venv_pcap

# Activate the environment in PowerShell
.\.venv_pcap\Scripts\Activate.ps1
# OR activate in Command Prompt (cmd)
.\.venv_pcap\Scripts\activate.bat
```

### Step 3: Install Python Dependencies
With the virtual environment active (you will see `(.venv_pcap)` in your shell prompt), install the requirements:
```powershell
pip install -r requirements.txt
```

### Step 4: Run the Application
1.  **Option A: Running with local API key configuration**
    Start the FastAPI server directly:
    ```powershell
    python -m uvicorn backend.main:app --port 8000
    ```
    Open `http://localhost:8000/` and paste your `GEMINI_API_KEY` in the sidebar to activate the AI Chat assistant.

2.  **Option B: Running with pre-configured Environment Variable**
    Set the environment variable in your terminal before running:
    ```powershell
    # In PowerShell:
    $env:GEMINI_API_KEY="your_api_key_here"
    python -m uvicorn backend.main:app --port 8000
    
    # In Command Prompt:
    set GEMINI_API_KEY=your_api_key_here
    python -m uvicorn backend.main:app --port 8000
    ```

---

## Part 2: Building the C++ DPI CLI Tool (Optional)

If you'd like to compile the core C++ CLI engine directly on Windows:

### Step 1: Install Visual Studio Build Tools
1.  Download **Visual Studio 2022 Community** (free):
    - [Visual Studio Downloads](https://visualstudio.microsoft.com/downloads/)
2.  Run the installer and select the workload: **Desktop development with C++**.
3.  Complete the installation (takes 10-15 minutes).

### Step 2: Compile the Engine
Open **Developer Command Prompt for VS 2022** (search in your Start Menu), navigate to the folder, and run:

```cmd
cd d:\CS\Projects\Packet_analyzer

cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_engine.exe ^
    src\dpi_mt.cpp ^
    src\pcap_reader.cpp ^
    src\packet_parser.cpp ^
    src\sni_extractor.cpp ^
    src\types.cpp
```

This creates the executable `dpi_engine.exe`.

### Step 3: Run the CLI tool
Execute with an input and output PCAP name:
```cmd
dpi_engine.exe test_dpi.pcap filtered_output.pcap
```

---

## Troubleshooting on Windows

### 1. Script Execution Policy Error (PowerShell)
If you get an error like *“running scripts is disabled on this system”* when executing the activation script:
Run PowerShell **as Administrator** and enter:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Then retry activating the virtual environment.

### 2. 'python' or 'pip' is not recognized
**Cause:** Python was installed without checking "Add python.exe to PATH".
**Fix:** Re-run the python installer, choose "Modify", and check "Add to PATH". Alternatively, manually add Python's installation folder and its `Scripts/` subdirectory to your system's Environment Variables.
