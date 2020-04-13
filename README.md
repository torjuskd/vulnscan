# vulnscan

A simple batteries included, non-intrusive, large scale vulnerability scanner.

## Setup and dependencies
To be able to run this application, you must have some dependencies installed and
on your `PATH` for non-interactive shells.
This usually means that: To make your PATH entries available to /bin/sh scripts run by a specific user,
add the PATH entry to the ~/.profile file or ~/.bash_profile or ~/.bash_login.

### dependencies
- `postgresql` - install on eg. Ubuntu with `sudo apt install postgresql postgresql-contrib`, already installed on Kali.
- [subjack](https://github.com/haccer/subjack)
- [meg](https://github.com/tomnomnom/meg)
- [nmap](https://nmap.org/)
- [ripgrep](https://github.com/BurntSushi/ripgrep)
- [s3scanner](https://github.com/sa7mon/S3Scanner)
- [gittools](https://github.com/internetwache/GitTools)
- [SimplyEmail](https://simplysecurity.github.io/SimplyEmail/)

## Run
Run with
```console
java -jar vulnscan-1.0-SNAPSHOT.jar
```

## Output
Results will be written to files currently specified in the class `VulnScan`.
Output from searching for `.env` files will be in the `out/` directory.

## Current source directory structure
```
.
├── main
│   ├── java
│   │   └── no
│   │       └── uio
│   │           └── ifi
│   │               └── vulnscan
│   │                   ├── Application.java
│   │                   ├── BashCommand.java
│   │                   ├── FileOverWriter.java
│   │                   ├── FileParser.java
│   │                   ├── tasks
│   │                   │   ├── ScanForEnvFiles.java
│   │                   │   ├── ScanGit.java
│   │                   │   ├── ScanHeartbleed.java
│   │                   │   ├── ScanS3.java
│   │                   │   ├── ScanSubdomains.java
│   │                   │   └── ScanTask.java
│   │                   └── VulnScan.java
│   └── resources
│       └── log4j2.xml
└── test
    └── java
```
