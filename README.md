# vulnscan

A simple batteries included, non-intrusive, large scale vulnerability scanner.

## Setup and dependencies
To be able to run this application, you must have some dependencies installed and
on your `PATH` for non-interactive shells.
- postgesql
- subjack
- meg
- nmap
- ripgrep
- s3scanner
- gittools

This usually means that: To make your PATH entries available to /bin/sh scripts run by a specific user, 
add the PATH entry to the ~/.profile file or ~/.bash_profile or ~/.bash_login.

## Run
Run with
```console
java -jar vulnscan-1.0-SNAPSHOT.jar
```
