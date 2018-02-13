# pinentry-wsl-ps1

GUI for GPG within Windows WSL for passwords, pins, etc.  
Optional persistence of passwords into Windows Credential Manager

(c) 2018 Dale Phurrough  
Licensed under the Mozilla Public License 2.0

## Features

* Allows GnuPG to prompt and read passphrases by the pinentry protocol
with a GUI when running within WSL (Windows Subsystem for Linux)
* Works for all keys managed by gpg-agent (GPG, SSH, etc)
* Drop-in replacement GUI to pinentry-curses, pinentry-gtk-2, etc.

## Setup

1. Save the `pinentry-wsl-ps1.sh` script and set its permissions to be executable
2. Configure gpg-agent to use this script for pinentry using
   one of the following methods
   * Set pinentry-program within ~/.gnupg/gpg-agent.conf to the script's path, e.g.  
     `pinentry-program /mnt/c/repos/pinentry-wsl-ps1/pinentry-wsl-ps1.sh`
   * ... or, set the path to this script when you launch gpg-agent, e.g.  
     `gpg-agent --pinentry-program /mnt/c/repos/pinentry-wsl-ps1/pinentry-wsl-ps1.sh`
3. Optionally enable persistence of passwords.  
   1. Follow instructions https://github.com/davotronic5000/PowerShell_Credential_Manager
   to install the needed module from the Powershell Gallery or GitHub.  
   2. Note security perspectives like https://security.stackexchange.com/questions/119765/how-secure-is-the-windows-credential-manager  
   3. Edit the script and set `PERSISTENCE` to one of the values:
      * `""` no persistence
      * `"Session"` persists the password only for the current Windows login session
      * `"LocalMachine"` persists the password for the current Windows login on the local Windows computer
      * `"Enterprise"` persists the password for the current Windows login and requests Windows Credential Manager to synchronize it across Windows computers for that same Windows login

## References

* https://www.gnupg.org/software/pinentry/index.html
* https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html
* https://github.com/GPGTools/pinentry/blob/master/doc/pinentry.texi
* https://gist.github.com/mdeguzis/05d1f284f931223624834788da045c65
* https://github.com/GPGTools/pinentry/blob/master/pinentry/pinentry.c
