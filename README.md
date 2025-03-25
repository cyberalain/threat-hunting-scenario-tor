<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cyberalain/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched  the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “alinolab” downloaded a tor installer, did something that resulted in  many tor-related files being copied to the desktop and the creation of a file call “Onlymy-list.txt” on the desktop at  2025-03-20T14:30:13.7002402Z. These events began at: 2025-03-20T13:34:57.1663781Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "alino-vm-test"
| where InitiatingProcessAccountName == "alinolab"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-20T13:34:57.1663781Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
![image](https://github.com/user-attachments/assets/1003ab14-8627-4905-840f-6dd7a1e25993)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.0.7.exe” Based on the logs retumed, At 2025-03-20T13:34:57.1663781Z, on the device named alino-vm-test, the user alinolab initiated the execution of the file tor-browser-windows-x86_64-portable-14.0.7.exe located in the Downloads folder.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "alino-vm-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/b18cde9e-2ccb-4b92-b4d9-30d6825a255f)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “alinolab” actually opened the tor browser. There was evidence that they did open it at : 2025-03-20T13:41:36.4732496Z
There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "alino-vm-test"
| where FileName has_any ("tor.exe", "firefox.exe", "torbrowser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/2e54655d-fea1-42ed-a66c-b54d8340537a)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched  the DeviceNetwork Events table for any indication the tor browser was used to establish a connection using any of the known tor ports. On 2025-03-20T13:42:20.5974479Z, on the device named alino-vm-test, the user alinolab attempted to establish a network connection using the application firefox.exe. This attempt resulted in a ConnectionFailed event while trying to connect to the IP address 127.0.0.1 on port 9150.​ In the context of the Tor Browser, firefox.exe is often utilized as the browser component, and it typically communicates with the Tor network through a local proxy. By default, the Tor Browser is configured to route its traffic through 127.0.0.1 (localhost) on port 9150, which serves as the SOCKS proxy for anonymizing web traffic. ​ Therefore, this event likely indicates that the Tor Browser's Firefox component attempted to connect to the Tor network via its local SOCKS proxy but encountered a connection failure. This could be due to the Tor service not running, misconfiguration, or network restrictions preventing the connection. There were a few other connections.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName  == "alino-vm-test"
| where InitiatingProcessAccountName != "system"
| where RemotePort  in ("9001","9030","9051","9150", "86","443")
| project Timestamp, DeviceName, InitiatingProcessAccountDomain, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/8652147d-0467-4d8e-ac3e-4689b1b8017e)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
