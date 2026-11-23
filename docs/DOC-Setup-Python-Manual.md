# Net-monit V12.4 — Python setup (run it yourself, step by step)

Use this when you do not want the Windows installer, when you are on Linux or macOS for a test, or when you are developing. Net-monit then runs in a terminal window; closing the window stops it. To keep it running all the time, see "Run it as a service" at the end.

## 1. Check Python
Net-monit needs **Python 3.9 or newer** (3.11 is what the installer uses).

Windows (Command Prompt or PowerShell):
```
python --version
```
Linux / macOS:
```
python3 --version
```
If you get an error or an old version, install Python from python.org (Windows: tick **Add python.exe to PATH**). On Windows, a `python` that opens the Microsoft Store is not a real install.

## 2. Open a terminal in the project folder
Extract the zip (or clone the repository), then:
```
cd path\to\Net-monit-V12.4          (Windows)
cd path/to/Net-monit-V12.4          (Linux / macOS)
```
You should see `app.py` and `requirements.txt` when you list the folder.

## 3. Create a private Python environment (called a venv)
Windows:
```
python -m venv venv
venv\Scripts\activate
```
Linux / macOS:
```
python3 -m venv venv
source venv/bin/activate
```
Your prompt now starts with `(venv)`. Every time you open a new terminal, activate it again before step 5.

## 4. Install what Net-monit needs
```
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```
This takes 1–3 minutes. `pywin32` is only installed on Windows. If an error mentions "Microsoft Visual C++" or "gcc", install the C build tools for your system and repeat the command.

## 5. Start it
```
python app.py
```
The first start creates the database in the `data` folder and prints a box like this:
```
FIRST-RUN DEFAULT ADMIN CREATED
Email : admin@email.com
Token : <a random token>
```
Copy the token now (it is also saved in `data/FIRST-RUN-ADMIN-TOKEN.txt` until you log in).

## 6. Open the dashboard
In a browser go to `http://localhost:5050`. Log in with `admin@email.com` and the token, change the password in the Admin Panel, then choose **Start a trial** on the Activation screen.

## 7. Add something to monitor
Devices page > add a device (for example a router's IP address with the *Ping* method), or the Sites page for a website. Within one polling interval (30 seconds by default) it appears on the dashboard as **Healthy**, **Warning**, **Critical** or **Offline**.

## Stop it
Press **Ctrl+C** in the terminal.

## Useful options (set before `python app.py`)
| Setting | Windows (Command Prompt) | Linux / macOS |
|---|---|---|
| Different port | `set NETMON_PORT=51000` | `export NETMON_PORT=51000` |
| Sessions survive restarts | `set NETMON_SECRET=<long random text>` | `export NETMON_SECRET=<long random text>` |
| HTTPS | `set NETMON_SSL_CERT=C:\cert.pem` and `set NETMON_SSL_KEY=C:\key.pem` | `export NETMON_SSL_CERT=/path/cert.pem NETMON_SSL_KEY=/path/key.pem` |

`.env.example` lists every option. The app does **not** read a `.env` file by itself; you must set these in the terminal or in your service manager.

## Run it as a service (stays on after you log out)
- **Windows:** open Command Prompt **as administrator** in the folder, with the venv activated, and run `python install_service.py install`. Then `python install_service.py status`.
- **Linux:** `sudo bash setup.sh` installs it as a systemd service (`netmonit-v124`) and starts it.

## Common problems
| What you see | What to do |
|---|---|
| `ModuleNotFoundError` | The venv is not active. Run the activate command from step 3, then step 4 again. |
| `Address already in use` | Another program uses port 5050. Set `NETMON_PORT` to another number. |
| Browser can't connect from another PC | Allow the port in the firewall and use the host PC's IP address, not `localhost`. |
| Lost the first-run token | Stop the app, delete `data/monitor.db`, start again for a **new** admin token. This also deletes your monitors and history. |
