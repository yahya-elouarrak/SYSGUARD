# SYSGUARD

<h3>SYSGUARD - System & Authentification Logs Analyzer & Security Monitor</h3>

A single-file Bash Script designed to monitor system logs, detect suspicious activities, and generate security reports. It analyzes SSH attempts, sudo abuse, authentication failures, and unusual login patterns, providing real-time alerts via email and detailed reports.

![image](https://github.com/user-attachments/assets/02a94113-59ec-494f-b024-9a303015719d)


<h3>Features</h3>

✅ Real-Time Monitoring: Track log files continuously with configurable intervals.

✅ Multi-Log Analysis: Analyze default logs (auth.log, syslog) or custom files.

✅ Security Alerts: Detect and classify threats by severity (High, Medium, Low).

✅ Email Notifications: Send alerts via Gmail (supports filtering by severity).

✅ Excel Reports: Generate structured XLSX reports using Python and pandas.

✅ User-Friendly Output: Color-coded terminal output and session logs.

✅ Parallel Processing: Fork or thread modes for efficient log parsing.

</br>

<h3>Installation</h3>

1. Clone the repository:

```
git clone https://github.com/yahya-elouarrak/SYSGUARD.git
cd SYSGUARD
```


3. Make the sysguard.sh script executable:

```
sudo chmod +x ./sysguard.sh
```

</br>

<h3>Usage</h3>

**⚠️ Important: Run the script with admin privileges using sudo to ensure proper permissions.**

**Basic Analysis**

```
sudo ./sysguard.sh /var/log/auth.log /var/log/syslog
```

**Real-Time Monitoring**

```
sudo ./sysguard.sh --realtime -m your-email@example.com
```

**Generate Excel Report**

```
sudo ./sysguard.sh -e -o /path/to/reports /var/log/auth.log
```

</br>

**Full Options**


`-h, --help`

Show help message.

`-f, --fork`

Analyze logs in parallel processes.

`-t, --thread`

Use threads for detection rules.

`-o, --output <DIR>`

Specify output directory (default:  `./sysguard_reports`).

`-e, --excel`

Generate Excel report.

`-m, --email <EMAIL>`

Send alerts to the specified email.

`--realtime`

Enable real-time monitoring.

`--realtime-interval`

Set check interval in seconds (default: 2).

</br>

<h3>Output Structure 📂</h3>


Reports are saved in the specified output directory (default:  `sysguard_reports`):


sysguard_reports/

├── alerts-<TIMESTAMP>.log       # All alerts sorted by severity

├── sysguard-<TIMESTAMP>.log     # Full session log

├── sysguard-summary-<TIMESTAMP>.txt  # Summary of findings

└── sysguard-report-<TIMESTAMP>.xlsx  # Excel report (if enabled)

