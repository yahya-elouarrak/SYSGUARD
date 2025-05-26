# SYSGUARD - System & Authentification Logs Analyzer & Security Monitor

**SYSGUARD** is a Bash-based tool designed to monitor system logs, detect suspicious activities, and generate security reports. It analyzes SSH attempts, sudo abuse, authentication failures, and unusual login patterns, providing real-time alerts via email and detailed reports.

</br>

<h3>Features</h3>

✅ Real-Time Monitoring: Track log files continuously with configurable intervals.

✅ Multi-Log Analysis: Analyze default logs (auth.log, syslog) or custom files.

✅ Security Alerts: Detect and classify threats by severity (High, Medium, Low).

✅ Email Notifications: Send alerts via Gmail (supports filtering by severity).

✅ Excel Reports: Generate structured XLSX reports using Python and pandas.

✅ User-Friendly Output: Color-coded terminal output and session logs.

✅ Parallel Processing: Fork or thread modes for efficient log parsing.

</br>

<h3>Usage</h3>

**Basic Analysis**

```
./sysguard.sh /var/log/auth.log /var/log/syslog
```

**Real-Time Monitoring**

```
./sysguard.sh --realtime -m your-email@example.com
```

**Generate Excel Report**

```
./sysguard.sh -e -o /path/to/reports /var/log/auth.log
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

