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
* Works well with [WSLgit](https://github.com/andy-5/wslgit). Enables your Git and GPG configuration/processing in WSL while access/using it from Windows apps like VS Code. Easy-breezy GPG signing of Git commits. 🙂📝

## Requirements

* Windows 10 Fall Creators Update (build 16299) or newer. You can check the version by `winver.exe`
* WSL with Ubuntu 16.04 or newer. You can check the release version by `cat /etc/lsb-release`
* GPG v2.1.11 or later. Earlier versions of 2.x (aka GPG2) or 1.x (aka GPG) have not been tested and are not recommended. You can check the version by `gpg2 --version`

## Setup

1. Save the `pinentry-wsl-ps1.sh` script and set its permissions to be readable and executable, e.g.  
   `chmod ug=rx pinentry-wsl-ps1.sh`
2. Configure gpg-agent to use this script for pinentry using
   one of the following methods  
    1. Set pinentry-program within ~/.gnupg/gpg-agent.conf to the script's path, e.g.  
     `pinentry-program /mnt/c/repos/pinentry-wsl-ps1/pinentry-wsl-ps1.sh`
    2. Or, set the path to this script when you launch gpg-agent, e.g.  
     `gpg-agent --pinentry-program /mnt/c/repos/pinentry-wsl-ps1/pinentry-wsl-ps1.sh`
    3. Or, more portable, set pinentry-program within ~/.gnupg/gpg-agent.conf to a [custom pin-entry script](https://a3nm.net/git/mybin/file/my-pinentry.html) 
       checking for a case `wsl); exec /mnt/c/repos/pinentry-wsl-ps1/pinentry-wsl-ps1.sh "$@";;`, and 
       add the line `[ -z ${WSLENV+x} ] || PINENTRY_USER_DATA=wsl` to `~/.profile`
    4. Or,  on supporting distributions (such as [Opensuse](https://obs.smar.fi/package/view_file/SUSE:SLE-15:Update/pinentry/pinentry?expand=0)),
       add `[ -z ${WSLENV+x} ] || PINENTRY_BINARY=/mnt/c/repos/pinentry-wsl-ps1/pinentry-wsl-ps1.sh` in `~/.profile`
3. Optionally _enable_ persistence of passwords.  
    1. Follow instructions <https://github.com/davotronic5000/PowerShell_Credential_Manager>
   to install the needed module from the Powershell Gallery or GitHub.
    2. Note security perspectives like <https://security.stackexchange.com/questions/119765/how-secure-is-the-windows-credential-manager>
    3. Edit the script and near the beginning of the file set `PERSISTENCE` to one of the values:
        * `""` no persistence
        * `"Session"` persists the password only for the current Windows login session
        * `"LocalMachine"` persists the password for the current Windows login on the local Windows computer
        * `"Enterprise"` persists the password for the current Windows login and requests Windows Credential Manager to synchronize it across Windows computers for that same Windows login
4. Optionally _disable_ toast notification of password retrieval from Credential Manager. By default, this code notifies you with a toast notification every time gpg-agent retrieves a password from the Windows Credential Manager. Gpg-agent caches passwords by default (see gpg-agent settings like [`max-cache-ttl`](https://gnupg.org/documentation/manuals/gnupg/Agent-Options.html#Agent-Options)) so you may not see the notification with every usage.
    * Disable: edit the script, near the top, set `NOTIFY` to the value `"0"`
    * Enable: edit the script, near the top, set `NOTIFY` to the value `"1"`


## Troubleshooting Ideas

1. Run `gpg2 --version` and `gpg-agent --version`. If you don't have version 2.1.11 or newer for both versions, you may have unknown problems.
2. I recommend you have a fully working GPG2 and GPG-agent setup using the default GPG2 configuration. Try two tests.  If these both don't work, you first need to troubleshoot your install.  
    1. `gpg2 --clearsign myfile.zip`. Your entire console window should clear and present you an isolated password entry field in a crudely drawn box. Type in your key's password and it should return to your normal console with no error. You should now have the newly signed `myfile.zip.asc` file.
    2. If you are using the SSH-compatibility feature of GPG-agent, ensure you are not running `ssh-agent`. Try `ssh-add ...` to add your SSH key for your favorite host. Then remove and stash in a protected location this ssh key file from your `~/.ssh` directory to ensure ssh isn't using that file instead of the agent. Now try to ssh to this host. It should automatically retrieve the private host key from gpg-agent.
3. I discovered that there are many ways for gpg-agent to be started silently. The options passed to it are inconsistent across the methods (and across gpg versions). On my computer, I explicitly start gpg-agent.  Below is the method I use in my `.profile`. Please be aware that `.profile` is not always run for all *nix shell scenarios and `.bashrc` may be better for your setup. The details on this are written in the [BASH man page](https://linux.die.net/man/1/bash) in the INVOCATION section.
4. Configuration of GPG can become complicated if you diverge from what the GPG team considers a standard setup. You may need to read the [official GPG documentation](https://gnupg.org/documentation/index.html) to configure it for your specific computer setup.
5. GIT uses `gpg` by default. To instruct GIT to use `gpg2`, you can easily configure it with `git config --global gpg.program gpg2`
6. Enable a gpg-agent log file. Edit your `~/.gnupg/gpg-agent.conf` file and insert the following lines. Your user must have permission to write to this file path. Restart gpg-agent after you save this configuration.
    ```crmsh
    debug 1024
    debug-pinentry
    log-file /home/username/agent.log 
    ```
7. Enable a log file specific to this pinentry code. Edit the script, near the top, set `DEBUGLOG` to a file path, e.g. `"$HOME/pintrace.log"`. Your user must have permission to write to this file path. Restart gpg-agent after you save this configuration.

## Example configuration files

Below are some examples from my configuration files. If you have a working GPG2 and gpg-agent setup, the only config change likely needed is the `pinentry-program` line from setup step 2.

#### Part of my ~/.profile

```bash
if [ -z "$(pgrep gpg-agent)" ]; then
    gpgconf --launch gpg-agent
    # I use the above method because the following method
    # doesn't set GPG_AGENT_INFO or GPG_TTY and has a bug
    # setting SSH_AUTH_SOCK if you use socket redirection:
    #   eval $(gpg-agent --homedir $HOME/.gnupg --daemon) 
fi
if [ -z "$(pgrep dirmngr)" ]; then
    dirmngr --homedir $HOME/.gnupg --daemon >/dev/null 2>&1
    # I use the above method to consistently set vars in .bashrc
    # rather than the following:
    #   eval $(dirmngr --homedir $HOME/.gnupg --daemon) 
fi
```

#### Part of my ~/.bashrc

```bash
export GPGKEY=12345678 # set prefered gpg signing key
PIDFOUND=$(pgrep gpg-agent)
if [ -n "$PIDFOUND" ]; then
    export GPG_AGENT_INFO="$HOME/.gnupg/S.gpg-agent:$PIDFOUND:1"
    export GPG_TTY=$(tty)
    export SSH_AUTH_SOCK="$HOME/.gnupg/S.gpg-agent.ssh"
    unset SSH_AGENT_PID
fi
PIDFOUND=$(pgrep dirmngr)
if [ -n "$PIDFOUND" ]; then
    export DIRMNGR_INFO="$HOME/.gnupg/S.dirmngr:$PIDFOUND:1"
fi
unset PIDFOUND
```

#### My ~/.gnupg/gpg-agent.conf

```
enable-ssh-support
disable-scdaemon
pinentry-program /mnt/c/repos/pinentry-wsl-ps1/pinentry-wsl-ps1.sh
```

## References

* <https://www.gnupg.org/software/pinentry/index.html>
* <https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html>
* <https://github.com/GPGTools/pinentry/blob/master/doc/pinentry.texi>
* <https://gist.github.com/mdeguzis/05d1f284f931223624834788da045c65>
* <https://github.com/GPGTools/pinentry/blob/master/pinentry/pinentry.c>
