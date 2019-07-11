---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: diablodale

---

## Description

Please provide a clear and concise description of your issue.

## Setup

* Description of your computer hardware
* Version of your Operating System and any patches/updates
* Version of gpg
* Version of pinentry-wsl-ps1.sh
* Version of the (optional) davotronic5000/PowerShell_Credential_Manager
* Describe how you installed `pinentry-wsl-ps1.sh` on your computer
* Detail any options you changed inside the `pinentry-wsl-ps1.sh` file

## Steps to reproduce

1. Edit your `~/.gnupg/gpg-agent.conf` file and include the following settings. Replace `username` or the whole path to a location you want to create the log file.
   ```conf
   debug 1024
   debug-pinentry
   log-file /home/username/agent.log
   ```
2. Kill and restart gpg-agent
3. Reproduce your issue and detail every step

## Actual Result

* What result did you *actually* get? Please provide screenshots when helpful.
* Review (and edit to remove any confidential information) the `agent.log` file that has been created.
* Copy/paste the whole log file into the dedicated section below

## Expected Result

* What result did you *expect* to get?

## Workarounds

* Did you discover any workarounds? What are they?

## GPG-agent log file

```
Please copy and paste the log file here. Remember to remove any confidential information.
```
