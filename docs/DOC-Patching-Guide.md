# Net-monit — Updating with a patch (no reinstall)

A **patch** is a small zip that contains only the files that changed. You apply it to the Net-monit you already have. Your monitors, history, settings, users and license stay exactly as they are. The port and the Windows Service name do **not** change.

Use a patch for bug fixes and small features. A new full release (new folder, new port, new service) is only needed when the release notes say so.

## Before you start
- You need the patch zip made for **your version** (for example `Net-monit-V11.3-patch-01.zip` is for V12.0).
- Patches go in order: apply 01 before 02.
- You need Python (Net-monit already uses it) and permission to run as administrator.

## Windows, step by step
1. **Extract** the patch zip anywhere (Desktop is fine). You get a folder with `Apply-Patch.bat`, `apply_patch.py`, `PATCH-README.txt` and a `files` folder.
2. Open `PATCH-README.txt` and read the list of files it will change.
3. **Right-click `Apply-Patch.bat` > Run as administrator.** Click Yes.
4. When it asks **Install folder**, type your Net-monit folder (for example `C:\NetMonit-V12.4`) and press Enter. If you installed to a different folder, type that one.
5. The script: checks the folder is the right version, **backs up every file it will replace** (in `patch_backups` inside your install folder), stops the service, copies the files, checks them, and starts the service again.
6. When it says `DONE`, open the dashboard in the browser, press **Ctrl+F5**, then open **About**. **Patches applied** should show the patch number.

If your service has a custom name (you changed it in the wizard), run in Command Prompt as administrator, from the patch folder:
```
python apply_patch.py --target "C:\NetMonit-V12.4" --service Your_Service_Name
```

## Linux
```
sudo bash apply_patch.sh /opt/netmonit-v124
```

## See what it will do first
```
python apply_patch.py --target "C:\NetMonit-V12.4" --dry-run
```
Nothing is changed; it only lists the files.

## If it stops with a message
| Message | Meaning and what to do |
|---|---|
| "this patch is for V12.4 but the folder is V…" | Wrong patch for this install. Use the patch made for your version. |
| "needs patch 01 first" | Apply the earlier patch first. |
| "already applied" | Nothing to do. |
| Conflicts: "was edited on this machine" | Someone changed that file by hand. Keep a copy of it, then re-run with `--force` (the file is backed up first). |
| "damaged (checksum mismatch)" | The zip is incomplete. Download it again. |
| "could not stop it" | Stop the service yourself (`services.msc`), run the patch again with `--no-restart`, then start the service. |

## Undo a patch
The last lines of the output show a command ending in `--rollback "...patch_backups\..."`. Run it, in the patch folder, as administrator. Every replaced file is put back and the patch is removed from the "Patches applied" list.

## What a patch never touches
`data/` (your database), `logs/`, `config.yaml`, `secret.key`, `.env`, `venv/`, and the license. A patch that tries to touch them is refused.

## For the person who maintains the GitHub repository
- **Update the repo from a patch:** extract the patch zip, then
  ```
  python apply_patch.py --target <your repo folder> --repo
  ```
  This also updates `tests/`, `site/`, `README.md` and the docs (installs skip those).
- **Make a patch** between the previous and the new folder (same layout):
  ```
  python tools/make_patch.py OLD_FOLDER NEW_FOLDER --patch 2 --base-version 11.3 --summary "What changed, in one sentence" --out out
  ```
  The result, `out/Net-monit-V11.3-patch-02.zip`, contains only the added, changed and deleted files, each with a checksum.


---

# Upgrading V11.8 (V11.3 + patches 01-08) or V12.0/V12.1 to V12.4

Package: **Net-monit-V11.8-to-V12.4-Upgrade**. Needs Python on the PC (any 3.9+; the installed Net-monit already has it). Works in place: same folder, same service, **same port**.

1. Make sure V11 patch 08 is installed (About page lists patches). If not, the upgrade stops and says so (`--force` skips this check; the package contains all of patches 01–08 anyway).
2. Extract the package. Right-click **Upgrade-to-V12.4.bat** → **Run as administrator**. Type the install folder (for example `C:\NetMonit-V11.3`).
3. The upgrader prints: the service it found, **how it detected the port** (config.yaml, service environment, active_port.txt, old app.py default) and `The upgraded app will keep port 50113`. If the port shown is wrong, stop (Ctrl+C) and run with `--port <your port>`.
4. It then: backs up every file it replaces to `patch_backups\V12.4-upgrade-<time>`, stops the service, copies V12.4 files (never `data\`, `logs\`, `venv\`, `config.yaml`, `secret.key`, `.env`), pins the old port into `app.py`/`install_service.py`, installs the new Python packages (scapy, maxminddb, psutil…), runs the Npcap helper (optional), starts the service and waits up to 60 s for the dashboard on the same port.
5. Success message: `DONE. Dashboard answers on http://localhost:<port>`. Open **About**: version **12.2**.
6. If the dashboard does not answer, it prints the last lines of `logs\service.log` and **rolls back automatically**; the old version runs again.
7. Manual undo any time: `python upgrade_to_v124.py --target "<folder>" --rollback "<backup folder>"`.

Options: `--dry-run` (shows what would change), `--no-restart`, `--skip-pip`, `--no-npcap`, `--no-auto-rollback`, `--port N`, `--service NAME`, `--force`.
After the upgrade the **Traffic** menu appears. Existing firewall rules stay valid because the port did not change. Allow UDP 2055 only if you use NetFlow.


## Already upgraded with the first V12.2 upgrade package?
Your install may say "V12.2" on the About page while the sidebar still says "V11.3", and the upgrader used to answer "STOPPED: already V12.2". Run the **V12.4** upgrade package on the same folder (for example `C:\\NetMonit-V11.3`): it upgrades V12.0–V12.3 installs too, keeps the port (50113), and refreshes the files. After it finishes press Ctrl+F5: the sidebar, title and footers say V12.4 and About lists the version, the port in use and the patches.
If the upgrader cannot tell which Windows service is yours it lists the Net-monit services and asks, or you pass `--service <name>` (find it with `sc query state= all | findstr /i monit`).
