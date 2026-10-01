#!/usr/bin/env bash

# pinentry-wsl-ps1
#
# (c) 2018 Dale Phurrough
# Licensed under the Mozilla Public License 2.0
#
# Allows GnuPG to prompt and read passphrases by the pinentry standard
# with a GUI when running within WSL (Windows Subsystem for Linux).
# Works for all keys managed by gpg-agent (GPG, SSH, etc).
# This is a drop-in GUI alternative to pinentry-curses, pinentry-gtk-2, etc.
# https://www.gnupg.org/software/pinentry/index.html
#
# Setup:
# 1. Save this script and set its permissions to be executable
# 2. Configure gpg-agent to use this script for pinentry using
#    one of the following methods:
#    a) Set pinentry-program within ~/.gnupg/gpg-agent.conf
#       pinentry-program /mnt/c/repos/pinentry-wsl-ps1/pinentry-wsl-ps1.sh
#    b) Set the path to this script when you launch gpg-agent
#       gpg-agent --pinentry-program /mnt/c/repos/pinentry-wsl-ps1/pinentry-wsl-ps1.sh
# 3. Optionally enable persistence of passwords.
#    Requires https://github.com/davotronic5000/PowerShell_Credential_Manager
#    Please follow instructions there to install from the Gallery or GitHub.
#    Note security perspectives like https://security.stackexchange.com/questions/119765/how-secure-is-the-windows-credential-manager
#    Possible values for PERSISTENCE are: "", "Session", "LocalMachine", or "Enterprise"
# 4. Optionally disable toast notification of password retrieval from Credential Manager.
#    By default, this code notifies you with a toast notification every time gpg-agent
#    retrieves a password from the Windows Credential Manager. Gpg-agent caches passwords
#    by default (see gpg-agent settings like max-cache-ttl) so you may not see the notification
#    with every usage.
#    * Disable: edit the script, near the top, set NOTIFY to the value "0"
#    * Enable: edit the script, near the top, set NOTIFY to the value "1"
PERSISTENCE=""
NOTIFY="1"
DEBUGLOG=""
POWERSHELL="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"

# run a powershell command; strip Windows CR so output is clean for Assuan
runps() {
    "$POWERSHELL" -nologo -noprofile -noninteractive -command "$1" | tr -d '\r'
}

# Do not casually edit the below values
VERSION="0.2.1"
TIMEOUT="0"
DESCRIPTION="Enter password for GPG key"
PROMPT="Password:"
TITLE="GPG Key Credentials"
CACHEPREFIX="gpgcache:"
CACHEUSER=""
KEYINFO=""
OKBUTTON="&OK"
CANCELBUTTON="&Cancel"
NOTOKBUTTON="&Do not do this"
PINERROR=""
EXTPASSCACHE="0"
REPEATPASSWORD="0"
REPEATDESCRIPTION="Confirm password for GPG key"
REPEATERROR="Error: Passwords did not match."
GRABKEYBOARD="0"

# convert Assuan protocol error into an ERR number, e.g. echo -n $(( (5 << 24) | $1 ))
assuan_result() {
    case $1 in
        0)
            echo -n "ERR 0 no error"
            ;;
        62)
            echo -n "ERR 83886142 timeout"
            ;;
        99)
            echo -n "ERR 83886179 cancelled"
            ;;
        114)
            echo -n "ERR 83886194 not confirmed"
            ;;
        174)
            echo -n "ERR 83886254 invalid option"
            ;;
        257)
            echo -n "ERR 83886337 general error"
            ;;
        261)
            echo -n "ERR 83886341 invalid value"
            ;;
        275)
            echo -n "ERR 83886355 unknown command"
            ;;
    esac
}

# WinForms password dialog; $1 = description text
# ($Host.ui.PromptForCredential fails with "Access is denied" when powershell
#  has no console window, e.g. when gpg-agent runs under systemd)
passworddialog() {
    cat <<-DLM
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        [System.Windows.Forms.Application]::EnableVisualStyles()
        \$form = New-Object System.Windows.Forms.Form
        \$form.Text = "$TITLE"
        \$form.FormBorderStyle = "FixedDialog"
        \$form.StartPosition = "CenterScreen"
        \$form.MinimizeBox = \$false
        \$form.MaximizeBox = \$false
        \$form.TopMost = \$true
        \$desc = New-Object System.Windows.Forms.Label
        \$desc.Text = "$1"
        \$desc.AutoSize = \$true
        \$desc.MaximumSize = New-Object System.Drawing.Size(400, 0)
        \$desc.Location = New-Object System.Drawing.Point(12, 12)
        \$form.Controls.Add(\$desc)
        \$y = 24 + \$desc.GetPreferredSize((New-Object System.Drawing.Size(400, 0))).Height
        \$prompt = New-Object System.Windows.Forms.Label
        \$prompt.Text = "$PROMPT"
        \$prompt.AutoSize = \$true
        \$prompt.Location = New-Object System.Drawing.Point(12, (\$y + 3))
        \$form.Controls.Add(\$prompt)
        \$pw = New-Object System.Windows.Forms.TextBox
        \$pw.UseSystemPasswordChar = \$true
        \$pw.Location = New-Object System.Drawing.Point(100, \$y)
        \$pw.Width = 312
        \$form.Controls.Add(\$pw)
        # editing shortcuts; Ctrl+Backspace/Delete remove everything before/after the
        # caret rather than one word, so they don't reveal word boundaries
        \$pw.Add_KeyDown({
            param(\$sender, \$e)
            if (-not \$e.Control) { return }
            \$start = \$pw.SelectionStart
            switch (\$e.KeyCode) {
                "A" { \$pw.SelectAll() }
                "U" { \$pw.Clear() }
                "Back" {
                    if (\$pw.SelectionLength -gt 0) { \$pw.SelectedText = "" }
                    else { \$pw.Text = \$pw.Text.Substring(\$start); \$pw.SelectionStart = 0 }
                }
                "Delete" {
                    if (\$pw.SelectionLength -gt 0) { \$pw.SelectedText = "" }
                    else { \$pw.Text = \$pw.Text.Substring(0, \$start); \$pw.SelectionStart = \$start }
                }
                default { return }
            }
            \$e.SuppressKeyPress = \$true
        })
        \$ok = New-Object System.Windows.Forms.Button
        \$ok.Text = "$OKBUTTON"
        \$ok.DialogResult = "OK"
        \$ok.Location = New-Object System.Drawing.Point(256, (\$y + 36))
        \$form.Controls.Add(\$ok)
        \$cancel = New-Object System.Windows.Forms.Button
        \$cancel.Text = "$CANCELBUTTON"
        \$cancel.DialogResult = "Cancel"
        \$cancel.Location = New-Object System.Drawing.Point(337, (\$y + 36))
        \$form.Controls.Add(\$cancel)
        \$form.AcceptButton = \$ok
        \$form.CancelButton = \$cancel
        \$form.ClientSize = New-Object System.Drawing.Size(424, (\$y + 72))
        \$form.Add_Shown({ \$form.Activate(); \$pw.Focus() })
        if (\$form.ShowDialog() -eq "OK" -and \$pw.Text) {
            # write raw UTF-8 bytes so non-ASCII passwords survive the console codepage
            \$bytes = [System.Text.Encoding]::UTF8.GetBytes(\$pw.Text)
            \$out = [Console]::OpenStandardOutput()
            \$out.Write(\$bytes, 0, \$bytes.Length)
            \$out.Flush()
        }
DLM
}

# GUI dialogs for passwords; text is dynamically set by gpg-agent via protocol
getpassword() {
    if [ -n "$CACHEUSER" ]; then
        local creduser="$CACHEUSER"
    else
        if [ -n "$KEYINFO" ]; then
            local creduser="$KEYINFO"
        else
            local creduser="--not yet defined--"
        fi
    fi
    local cmd_prompt="$(passworddialog "$PINERROR$DESCRIPTION")"
    local cmd_repeat="$(passworddialog "$REPEATDESCRIPTION")"
    local cmd_lookup=$(cat <<-DLM
        \$cred = Get-StoredCredential -Target "$CACHEPREFIX$KEYINFO" -Type GENERIC
        if (\$cred) {
            Write-Output \$cred.GetNetworkCredential().Password
        }
DLM
    )
    local cmd_store=$(cat <<-DLM
        \$pw = \$Input | Select-Object -First 1
        \$securepw = ConvertTo-SecureString \$pw -AsPlainText -Force
        New-StoredCredential -Target "$CACHEPREFIX$KEYINFO" -Type GENERIC -UserName "$creduser" -SecurePassword \$securepw -Persist $PERSISTENCE |
        out-null
DLM
    )
    # idea from http://thewindowscollege.com/display-toast-notifications-windows-10.html
    # alt1: https://gist.github.com/loge5/7ec41e2e2f0e0293fdcc5155499e9072
    # alt2: https://gist.github.com/Windos/9aa6a684ac583e0d38a8fa68196bc2dc
    local cmd_toast=$(cat <<-DLM
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        [reflection.assembly]::loadwithpartialname("System.Drawing")
        \$notify = new-object system.windows.forms.notifyicon
        \$notify.icon = [System.Drawing.SystemIcons]::Information
        \$notify.visible = \$true
        \$notify.showballoontip(10, "GPG pinentry-wsl-ps1", "GPG password retrieved from Windows Credential Manager", [system.windows.forms.tooltipicon]::Info)
DLM
    )
    local credpassword
    local credpasswordrepeat
    local passwordfromcache=0
    if [ -z "$PINERROR" ]; then
        if [ "$REPEATPASSWORD" == "0" ]; then
            if [ "$EXTPASSCACHE" == "1" ]; then
                if [ -n "$KEYINFO" ]; then
                    credpassword="$(runps "$cmd_lookup")"
                    if [ -n "$credpassword" ]; then
                        printf 'S PASSWORD_FROM_CACHE\nD %s\nOK\n' "${credpassword//%/%25}"
                        if [ "$NOTIFY" == "1" ]; then
                            runps "$cmd_toast" > /dev/null
                        fi
                        return
                    fi
                fi
            fi
        fi
    fi
    PINERROR=""
    credpassword="$(runps "$cmd_prompt")"
    if [ -n "$credpassword" ]; then
        if [ "$REPEATPASSWORD" == "1" ]; then
            credpasswordrepeat="$(runps "$cmd_repeat")"
            if [ "$credpassword" == "$credpasswordrepeat" ]; then
                printf 'S PIN_REPEATED\nD %s\nOK\n' "${credpassword//%/%25}"
            else
                message "$REPEATERROR" > /dev/null
                echo "$(assuan_result 114)" # unsure this is the correct error
                return
            fi
        else
            printf 'D %s\nOK\n' "${credpassword//%/%25}"
        fi
        if [ "$EXTPASSCACHE" == "1" ]; then
            if [ -n "$KEYINFO" ]; then
                # avoid setting password on visible param
                # alt is to always save on the single or last-of-repeat dialog. And if the repeat fails, then immediately delete it from the cred store
                printf '%s' "$credpassword" | runps "$cmd_store"
            fi
        fi
    else
        echo "$(assuan_result 99)"
    fi
}

# remove password from persistent store
removepassword() {
    if [ -z "$1" ]; then
        echo "$(assuan_result 261)"
        return
    fi
    local cmd_remove=$(cat <<-DLM
        try {
            Remove-StoredCredential -Target "$CACHEPREFIX$1" -Type GENERIC -ErrorAction Stop
        }
        catch {
            Write-Output "$(assuan_result 261)"
            return
        }
        Write-Output "OK"
DLM
    )
    if [ "$EXTPASSCACHE" == "1" ]; then
        echo "$(runps "$cmd_remove")"
    else
        echo "OK"
    fi
}

# GUI dialog box with simple message and one OK button
message() {
    local desc
    if [ -n "$1" ]; then
        desc="$1"
    else
        desc="$DESCRIPTION"
    fi
    local cmd=$(cat <<-DLM
        \$wshShell = New-Object -ComObject WScript.Shell
        \$options = 0x0 + 0x40 + 0x2000 + 0x10000 # 1 + 16 + 8192 + 65536
        \$result = \$wshShell.Popup("$desc", $TIMEOUT, "$TITLE", \$options)
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject(\$wshShell) | Out-Null
DLM
    )
    local result="$(runps "$cmd")" #> /dev/null
    echo "OK"
}

# GUI dialog box with test and two buttons: OK, Cancel
confirm() {
    PINERROR=""
    if [ "$1" == "--one-button" ]; then
        message
        return
    fi
    local cmd=$(cat <<-DLM
        \$wshShell = New-Object -ComObject WScript.Shell
        \$options = 0x1 + 0x30 + 0x2000 + 0x10000 # 1 + 16 + 8192 + 65536
        \$result = \$wshShell.Popup("$DESCRIPTION", $TIMEOUT, "$TITLE", \$options)
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject(\$wshShell) | Out-Null
        if (\$result) {
            switch(\$result) {
                1 { Write-Output "OK" }
                2 { Write-Output "$(assuan_result 99)" }
                default { Write-Output "$(assuan_result 114)" }
            }
        }
        else {
            Write-Output "$(assuan_result 114)"
        }
DLM
    )
    local result="$(runps "$cmd")"
    echo "$result"
}

# set a timeout value in seconds after which prompts/dialogs are automatically cancelled
# limited functionality in current codebase
# potential improvements at https://stackoverflow.com/questions/21176487/adding-a-timeout-to-batch-powershell
settimeout() {
    TIMEOUT="$1"
    echo "OK"
}

# helper function for decoding strings from gpg-agent into Windows-compatible format
decodegpgagentstr() {
    local decode="${1//%0A/%0D%0A}"  # convert hex LF into hex Windows CRLF
    decode="${decode//%/\\x}"        # convert hex encoding style
    decode="$(echo -en "$decode")"   # decode hex
    echo -n "${decode//\"/\`\"}"     # escape double quotes for powershell
}

# commonly used to set main text in GUI dialog boxes
# also parses for key ids to display in GUI prompts
setdescription() {
    DESCRIPTION="$(decodegpgagentstr "$1")"
    local searchfor='ID ([[:xdigit:]]{16})'  # hack to search for first gpg key id in description
    if [[ "$1" =~ $searchfor ]]; then
        CACHEUSER="${BASH_REMATCH[1]}"
    fi
    local searchfor='(([[:xdigit:]][[:xdigit:]]:){15}[[:xdigit:]][[:xdigit:]])'  # hack to search for ssh fingerprint in description
    if [[ "$1" =~ $searchfor ]]; then
        CACHEUSER="${BASH_REMATCH[1]}"
    fi
    echo "OK"
}

setprompt() {
    PROMPT="$1"
    echo "OK"
}

settitle() {
    TITLE="$1"
    echo "OK"
}

setpinerror() {
    PINERROR="$(decodegpgagentstr "** $1 **")"$'\r'$'\n' # decode and add CRLF to separate line
    echo "OK"
}

setkeyinfo() {
    if [ "$1" == "--clear" ]; then
        KEYINFO=""
    else
        KEYINFO="$1"
    fi
    echo "OK"
}

setrepeatpassword() {
    REPEATPASSWORD="1"
    REPEATDESCRIPTION="$(decodegpgagentstr "$1")"
    echo "OK"
}

setrepeaterror () {
    REPEATERROR="$(decodegpgagentstr "$1")"
    echo "OK"
}

setokbutton() {
    OKBUTTON="${1//_/\&}"
    echo "OK"
}

setcancelbutton() {
    CANCELBUTTON="${1//_/\&}"
    echo "OK"
}

setnotokbutton() {
    NOTOKBUTTON="${1//_/\&}"
    echo "OK"
}

getinfo() {
    if [ "$1" == "version" ]; then
        echo -e "D $VERSION\nOK"
    elif [ "$1" == "pid" ]; then
        echo -e "D $BASHPID\nOK"
    else
        echo "$(assuan_result 275)"
    fi
}

# often called by gpg-agent to set default values
setoption() {
    local key="$(echo "$1" | cut -d'=' -f1)"
    local value="$(echo "$1" | cut -d'=' -s -f2-)"
    case $key in
        allow-external-password-cache)
            if [ -n "$PERSISTENCE" ]; then
                EXTPASSCACHE=1
            fi
            echo "OK"
            ;;
        default-ok)
            setokbutton "$value"
            ;;
        default-cancel)
            setcancelbutton "$value"
            ;;
        default-notok)
            setnotokbutton "$value"
            ;;
        default-prompt)
            setprompt "$value"
            ;;
        grab)
            GRABKEYBOARD="1"
            echo "OK"
            ;;
        no-grab)
            GRABKEYBOARD="0"
            echo "OK"
            ;;
        *)
            echo "OK"
            ;;
    esac
}

# check that we are running within WSL
if ! cat /proc/sys/kernel/osrelease | grep -q -i Microsoft; then
    echo "$(assuan_result 257)"
    exit 1
fi

# main loop to read stdin and respond
echo "OK Your orders please"
while IFS= read -r line; do
    if [ -n "$DEBUGLOG" ]; then
        echo "$line" >> "$DEBUGLOG"
    fi
    action="$(echo $line | cut -d' ' -f1)"
    args="$(echo $line | cut -d' ' -s -f2-)"
    case $action in
        BYE)
            echo "OK closing connection"
            exit 0
            ;;
        GETPIN)
            getpassword
            ;;
        SETTIMEOUT)
            settimeout "$args"
            ;;
        SETDESC)
            setdescription "$args"
            ;;
        SETPROMPT)
            setprompt "$args"
            ;;
        SETTITLE)
            settitle "$args"
            ;;
        SETKEYINFO)
            setkeyinfo "$args"
            ;;
        SETOK)
            setokbutton "$args"
            ;;
        SETCANCEL)
            setcancelbutton "$args"
            ;;
        SETNOTOK)
            setnotokbutton "$args"
            ;;
        CONFIRM)
            confirm "$args"
            ;;
        MESSAGE)
            message "$args"
            ;;
        SETERROR)
            setpinerror "$args"
            ;;
        GETINFO)
            getinfo "$args"
            ;;
        OPTION)
            setoption "$args"
            ;;
        SETREPEAT)
            setrepeatpassword "$args"
            ;;
        SETREPEATERROR)
            setrepeaterror "$args"
            ;;
        CLEARPASSPHRASE)
            removepassword "$args"
            ;;
        RESET)
            echo "OK"
            ;;
        *)
            echo "OK"
            ;;
    esac
done
