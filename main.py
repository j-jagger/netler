import psutil
import tkinter as tk
import webbrowser
import re
import socket
import pyperclip
import sv_ttk
from tkinter import Menu, ttk
import threading
import logging
import subprocess
import requests

logging.basicConfig(level=logging.INFO)

self_info = {
    "version": "v1.0-B"
}

patterns = {
    "Netgear DDNS": re.compile(r"([a-zA-Z0-9-]+\.mynetgear\.com)"),
    "AWS EC2": re.compile(r"(ec2-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.compute-\d+\.amazonaws\.com)"),
    "AWS ELB": re.compile(r"([a-z0-9-]+\.elb\.amazonaws\.com)"),
    "AWS S3": re.compile(r"([a-z0-9.-]+\.s3\.[a-z0-9-]+\.amazonaws\.com)"),
    "AWS RDS": re.compile(r"([a-z0-9-]+\.rds\.[a-z0-9-]+\.amazonaws\.com)"),
    "AWS Global Accelerator": re.compile(r"([a-z0-9-]+\.awsglobalaccelerator\.com)"),
    "AWS CloudFront": re.compile(r"([a-zA-Z0-9]+\.cloudfront\.net)"),
    "AWS API Gateway": re.compile(r"([a-z0-9-]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com)"),
    "Azure Blob Storage": re.compile(r"([a-z0-9-]+\.blob\.core\.windows\.net)"),
    "Azure File Storage": re.compile(r"([a-z0-9-]+\.file\.core\.windows\.net)"),
    "Azure App Service": re.compile(r"([a-z0-9-]+\.azurewebsites\.net|[a-z0-9-]+\.cloudapp\.net)"),
    "Azure API Management": re.compile(r"([a-z0-9-]+\.azure-api\.net)"),
    "Azure Database": re.compile(r"([a-z0-9-]+\.database\.windows\.net)"),
    "Azure Virtual Network": re.compile(r"([a-z0-9-]+\.vpn\.core\.windows\.net)"),
    "YourServer": re.compile(r"([a-z0-9-]+\.your-server\.de)"),
    "Akamai CDN": re.compile(r"([a-zA-Z0-9.-]+\.akamaiedge\.net|[a-zA-Z0-9.-]+\.akamai\.net|[a-zA-Z0-9.-]+\.akamaitechnologies\.com)"),


    "Steam Content Servers": re.compile(r"(cm[a-z0-9-]+\.cs[a-z0-9-]+\.steamcontent\.com)"),  # Steam content delivery
    "Steam Community": re.compile(r"([a-z0-9-]+\.steamcommunity\.com)"),  # Steam community
    "Steam Powered": re.compile(r"([a-z0-9-]+\.steampowered\.com)"),  # Steam main website
    "Steam Storefront": re.compile(r"(store\.steampowered\.com)"),  # Steam store


    "Google APIs": re.compile(r"([a-z0-9-]+\.googleapis\.com)"),  # Google API services
    "Google Cloud Storage": re.compile(r"([a-z0-9-]+\.storage\.googleapis\.com)"),  # Google Cloud Storage
    "Dropbox": re.compile(r"([a-z0-9-]+\.dropboxusercontent\.com|[a-z0-9-]+\.dropbox\.com)"),  # Dropbox URLs
    "Microsoft Office": re.compile(r"([a-z0-9-]+\.office365\.com|[a-z0-9-]+\.office\.com)"),  # Microsoft Office 365
    "Fastly CDN": re.compile(r"([a-z0-9-]+\.fastly\.net)"),  # Fastly CDN service
    "Cloudflare": re.compile(r"([a-z0-9-]+\.cloudflare\.com)"),  # Cloudflare services
}


def parse_cloud_endpoint(endpoint):    
    for provider, pattern in patterns.items():
        match = pattern.search(endpoint)
        if match:
            return {
                "provider": provider,
                "service": match.group(1)
            }
    
    return {
        "provider": "None",
        "service": "None",
        "location": "N/A"
    }


def get_domain_name(ip, callback):
    global hostname
    try:
        callback("Resolving hostname...")
        ip = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+', r'\1', ip)
        hostname = socket.gethostbyaddr(ip)[0]
        callback(hostname)
    except (socket.herror, socket.gaierror):
        callback(f"No domain name found for {ip}")
        hostname = "None"
    except Exception as e:
        callback(f"Error resolving {ip}: {str(e)}")
        hostname = "Error"

def ipinfo_lookup(ip, callback=None):
    try:
        if ip[:3] in ("192", "127"):
            if callback:
                callback("Error: Cannot ipinfo query a local IP.")
            return
        print(ip)
        webbrowser.open_new_tab(f"https://ipinfo.io/{ip}")
    except Exception as e:
        if callback:
            callback(f"Error opening browser: {str(e)}")

def show_ip_inf(ip):
    logging.info(f"Showing more info for IP: {ip}")
    info_pane = tk.Toplevel()
    info_pane.title("Netler Info")
    info_pane.geometry("300x230")
    ttk.Label(info_pane, text="Netler", font=("Segoe UI", 24)).pack(pady=10)
    ttk.Label(info_pane, text="Because other programs cost money.").pack(pady=10)
    btn = ttk.Button(info_pane, text="GitHub", command=lambda: webbrowser.open_new_tab("https://github.com/j-jagger/netler"))
    btn.pack(pady=10)
    button = ttk.Button(info_pane, text="Close", command=info_pane.destroy)
    button.pack(pady=10)

def launch_nmap(ip):
    logging.info(f"Launching nmap on IP: {ip}")
    subprocess.Popen(f"cmd.exe /K nmap -A {ip}", shell=True)

def info_pane():
    info_pane = tk.Toplevel()
    info_pane.title("Netler Info")
    info_pane.geometry("500x230")
    info_pane.resizable(False,False)
    ttk.Label(info_pane, text="Netler", font=("Segoe UI", 24)).place(x=10,y=10)
    ttk.Label(info_pane, text="Because other programs cost money.").place(x=10,y=60)
    btn = ttk.Button(info_pane, text="GitHub", command=lambda: webbrowser.open_new_tab("https://github.com/j-jagger/netler"))
    btn.place(x=10,y=90)

    ttk.Label(info_pane,text="Debug Info").place(x=10,y=150)
    ttk.Label(info_pane,text=f"Local IP: {socket.gethostbyname(socket.gethostname())}").place(x=10,y=180)
    ttk.Label(info_pane,text=f"External IP: {requests.get('https://api.ipify.org').text}").place(x=10,y=200)

def tk_gui():
    global autorefresh, connid, localscan, hostname
    autorefresh = True
    connid = 0
    localscan = True
    root = tk.Tk()
    root.geometry("1000x700")
    root.resizable(False,False)
    root.title("Netler")

    def toggle_localscan():
        global localscan
        if localscan:
            localconn_button.configure(text="Enable Local Connections")
        else:
            localconn_button.configure(text="Disable Local Connections")
        localscan = not localscan

    def toggle_autorefresh():
        global autorefresh
        if autorefresh:
            refresh_button.configure(text="Resume Scan")
        else:
            refresh_button.configure(text="Pause Scan")
        autorefresh = not autorefresh


    def update():
        if not autorefresh:
            root.after(1, update)  # Slightly increase delay to reduce load
            return

        try:
            # Store the currently selected index
            selected_index = mainlist.curselection()

            # Clear and repopulate the list
            mainlist.delete(0, tk.END)
            connections = psutil.net_connections()
            
            for conn in connections:
                global connid
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                connid += 1

                if raddr == 'N/A':
                    conn_type = 'Local'
                elif raddr.startswith("192.") or raddr.startswith("127."):
                    conn_type = 'Local'
                else:
                    conn_type = 'External'

                # Skipping local connections if localscan is disabled
                if conn_type == 'Local' and not localscan:
                    continue

                connection_info = f"({connid}) Type: {conn_type} Connection | Status: {conn.status} | Local: {laddr} | Remote: {raddr}"

                if filter_box.get() not in connection_info:
                    continue

                mainlist.insert(tk.END, connection_info)

            # Re-select the previously selected index if it still exists
            if selected_index:
                try:
                    mainlist.select_set(selected_index)
                except:
                    pass  # Ignore if selection is out of bounds

            mainlist.yview_moveto(1)

        except Exception as e:
            logging.error(f"Error updating entries: {e}")

        # Increase the refresh interval
        root.after(2000, update)


    mainlist = tk.Listbox(root, width=160, height=20)
    mainlist.place(x=10, y=10)

    scrollbar = ttk.Scrollbar(root, orient="vertical", command=mainlist.yview)
    scrollbar.place(x=960, y=10, height=330)
    mainlist.configure(yscrollcommand=scrollbar.set)

    refresh_button = ttk.Button(root, text="Pause Scan", command=toggle_autorefresh)
    refresh_button.place(x=10, y=340)

    localconn_button = ttk.Button(root, text="Disable Local Connections", command=toggle_localscan)
    localconn_button.place(x=120, y=340)

    filter_box = ttk.Entry(root);ttk.Label(text="Filter:").place(x=10,y=390)
    filter_box.place(x=50,y=385)

    context_menu = Menu(root, tearoff=0)
    
    noticebox = ttk.Label(root, text="Monitoring...", font=("Segoe UI", 16))
    noticebox.place(x=100, y=660)

    ipane = ttk.LabelFrame(root, width=460, height=220, text="IP Information")
    ipane.place(x=500, y=340)

    iplabel = ttk.Label(ipane, text="IP: ")
    iplabel.place(x=10, y=10)

    hostlabel = ttk.Label(ipane, text="Hostname: ")
    hostlabel.place(x=10, y=30)

    servicelabel = ttk.Label(ipane, text="Service: ")
    servicelabel.place(x=10, y=50)

    def copy_ip():
        global ip_
        try:
            pyperclip.copy(ip_)
        except:
            print()

    def copy_hn():
        global hostname
        try:
            pyperclip.copy(hostname)
        except:
            print()

    copyhn = ttk.Button(ipane,text="Copy Hostname",command=copy_hn)
    copyhn.place(x=10,y=160)

    copyip = ttk.Button(ipane,text="Copy IP",command=copy_ip)
    copyip.place(x=150,y=160)

    info_btn = ttk.Button(root, text="Info 🛈", command=info_pane)
    info_btn.place(x=10, y=660)



    def edit_noticebox(text):
        noticebox.configure(text=text)

    def show_context_menu(event):
        try:
            context_menu.post(event.x_root, event.y_root)
        except Exception as e:
            logging.error(f"Error showing context menu: {e}")

    def on_select(event):
        try:
            selected_index = mainlist.curselection()
            if not selected_index:
                return

            entry = mainlist.get(selected_index)
            ip_match = re.search(r"Remote: ((?:(?:\d{1,3}\.){3}\d{1,3})|(?:[a-fA-F0-9:]+)):([0-9]+)", entry)            
            if not ip_match:
                edit_noticebox("Error: Could not extract IP")
                return
                
            ip = ip_match.group(1)
            context_menu.delete(0, tk.END)
            context_menu.add_command(label="Run IP Info Lookup", command=lambda: ipinfo_lookup(ip, edit_noticebox))
            context_menu.add_command(label="Show More", command=lambda: show_ip_inf(ip))
            context_menu.add_command(label="Launch Nmap", command=lambda: launch_nmap(ip))
            
            threading.Thread(target=get_domain_name, args=(ip, edit_noticebox), daemon=True).start()
            global hostname, ip_

            ip_ = ip
            service_info = parse_cloud_endpoint(hostname) if hostname else None
            service = service_info.get("provider", "Unknown") if service_info else "None"            
            iplabel.configure(text=f"IP: {ip}")
            hostlabel.configure(text=f"Hostname: {hostname}")
            servicelabel.configure(text=f"Service: {service}")

        except Exception as e:
            logging.error(f"Error in selection: {e}")

    mainlist.bind("<Button-3>", show_context_menu)
    mainlist.bind("<ButtonRelease-1>", on_select)

    sv_ttk.set_theme("dark")
    root.after(1000, update)
    root.mainloop()

tk_gui()
