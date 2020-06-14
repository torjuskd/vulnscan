# vulnscan

A simple non-intrusive, large scale vulnerability scanner.

![Java CI with Maven](https://github.com/torjuskd/vulnscan/workflows/Java%20CI%20with%20Maven/badge.svg?branch=master)

## Setup and dependencies
To be able to run this application, you must have some dependencies installed and
on your `PATH` for non-interactive shells.
This usually means that: To make your PATH entries available to /bin/sh scripts run by a specific user,
add the PATH entry to the `~/.profile` file or `~/.bash_profile` or `~/.bash_login`.

### Dependencies
- `postgresql` - install on eg. Ubuntu with `sudo apt install postgresql postgresql-contrib`, installed by default on Kali.
- [subjack](https://github.com/haccer/subjack)
- [meg](https://github.com/tomnomnom/meg)
- [nmap](https://nmap.org/)
- [ripgrep](https://github.com/BurntSushi/ripgrep)
- [s3scanner](https://github.com/sa7mon/S3Scanner) and an S3-account
- [gittools](https://github.com/internetwache/GitTools)
- [SimplyEmail](https://simplysecurity.github.io/SimplyEmail/)
- Shodan user/api key with query credit
- Google custom search engine, and api key to use it

If there are any of the scans that you don't want to run, you can set its flag to `false` in the config-file.

## Run
Run with
```console
java -jar vulnscan-1.0.jar
```

## Output
Results will be written to files currently specified in the class `VulnScan`.
Output from searching for `.env` files will be in the `out/` directory.

## Source directory structure
```
src
├── main
│   ├── java
│   │   └── no
│   │       └── uio
│   │           └── ifi
│   │               └── vulnscan
│   │                   ├── Application.java
│   │                   ├── tasks
│   │                   │   ├── ScanEmail.java
│   │                   │   ├── ScanForEnvFiles.java
│   │                   │   ├── ScanGit.java
│   │                   │   ├── ScanGoogle.java
│   │                   │   ├── ScanHeartbleed.java
│   │                   │   ├── ScanS3.java
│   │                   │   ├── ScanShodan.java
│   │                   │   ├── ScanSubdomains.java
│   │                   │   └── ScanTask.java
│   │                   ├── util
│   │                   │   ├── BashCommand.java
│   │                   │   └── io
│   │                   │       ├── FileOverWriter.java
│   │                   │       └── FileParser.java
│   │                   └── VulnScan.java
│   └── resources
│       └── log4j2.xml
└── test
    └── java
```
