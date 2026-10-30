# SentinelSOC

### Security Monitoring & Threat Detection Platform

SentinelSOC is a Python-based cybersecurity project designed to
analyze security logs, identify suspicious activity, and generate
security alerts.

## Project Overview

The goal of SentinelSOC is to simulate a lightweight Security
Operations Center (SOC) monitoring environment.

The application is being developed to analyze authentication
and network activity and identify potential security threats.

## Planned Features

- Security log analysis
- Brute-force login detection
- Port scanning detection
- Threat severity classification
- Risk scoring
- Security event database
- Web-based monitoring dashboard
- Security alert visualization

## Technologies

- Python
- Flask
- SQLite
- Git & GitHub
- Linux
- HTML/CSS/JavaScript

## Current Progress

**Day 2 of 10 — Security Log Analysis**

Completed:
- Python development environment
- GitHub repository setup
- Application initialization
- Security log parser
- Authentication event analysis
- IP-based activity statistics
- Invalid log handling
- Automated parser tests

### Current Capabilities

SentinelSOC can currently:

1. Read simulated authentication log files.
2. Extract timestamps, usernames, event types, and IP addresses.
3. Validate authentication events.
4. Count successful and failed login attempts.
5. Calculate authentication statistics for individual IP addresses.
6. Identify unique source IP addresses.
7. Report invalid log entries.

## Running the Application

Clone the repository and navigate to the project directory.

Create a Python virtual environment:

```bash
python -m venv .venv
```

Activate the environment and run:

```bash
python -m app/main.py
```

## Disclaimer

SentinelSOC is an educational cybersecurity project.

All included sample security logs are fictional.
Testing should only be performed in environments
where authorization has been granted.

## Development Status

Under active development.

## Testing

Run the automated parser tests:

```bash
python -m unittest discover -s tests -v
```