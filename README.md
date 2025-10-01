# DonutSMP Minecraft Ban Checker Bot

Hey! This is a tool that tries to log into Minecraft accounts and join the DonutSMP server (`donutsmp.net`). It tells you if the account is banned, unbanned, or if something else happened. You can use proxies, run a bunch of bots at once, and all your results get saved in a folder for you.

---

## What does it do?

- Logs in with Microsoft (Minecraft) accounts
- Tries to join DonutSMP (`donutsmp.net`)
- Tells you if the account is unbanned, banned, or if there was an error
- Works with proxies (HTTP/S, SOCKS4, SOCKS5, or auto-scrape)
- Runs multiple bots at the same time (multi-threaded)
- Saves everything in a `results/` folder

---

## What do you need?

- Python 3.8 or newer
- Minecraft Java Edition account credentials (Microsoft)
- The stuff in `requirements.txt` (see below)

---

## How do you set it up?

1. Make sure you have Python 3.8+ installed.
2. Open a terminal and run:
   ```sh
   pip install -r requirements.txt
   ```

---

## How do you use it?

1. Make a combo file (just a text file) with each line like this:
   ```
   email@example.com:password
   ```
2. Run the bot:
   ```sh
   python DonutChkr.py
   ```
3. Answer the questions it asks (combo file, proxy type, number of bots).

---

## Proxy Types

- `[1]` HTTP/S
- `[2]` SOCKS4
- `[3]` SOCKS5
- `[4]` None (proxyless, not recommended for big lists)
- `[5]` Auto Scraper (gets fresh proxies for you)

---

## Where do the results go?

- Everything is saved in `results/<combo_file_name>/`
- You’ll see files like: `Unbanned.txt`, `Banned.txt`, `Bad.txt`, `Capture.txt`

---

## Credits

- Inspired by MSMC
- Made by @minex00 AKA Minex13

---

**Heads up:**  
This tool does NOT check if Minecraft accounts are valid.  
It ONLY checks if a valid account is banned or unbanned on DonutSMP.  
Don’t use it for combo-checking Minecraft accounts.  
Use responsibly and for fun/education only and Creator is not responsible for anything you do with this!
!!!!!!YOU ACCEPT IT BY DOWNLOADING IT!!!!!!

<img width="935" height="755" alt="{A99DC289-AC4F-4E95-B620-0B4365C449B2}" src="https://github.com/user-attachments/assets/c1338496-a41f-4cc4-9d55-f4a9b1f23155" />

