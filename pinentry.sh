#/bin/bash

VERSION="0.1.0"
TIMEOUT="0"
DESCRIPTION="Enter password for GPG key"
PROMPT="Password:"
TITLE="GPG Key Credentials"
CREDENTIALPREFIX="gpgkey://"
KEYINFO=""
OKBUTTON="&OK"
CANCELBUTTON="&Cancel"
NOTOKBUTTON="&Do not do this"
PINERROR=""
EXTPASSCACHE=0
REPEATPASSWORD=0
REPEATDESCRIPTION="Confirm password for GPG key"
REPEATERROR="Error: Passwords did not match."

assuan_result() {
    #echo -n $(( (5 << 24) | $1 ))
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

getpassword() {
    local cmd_prompt=$(cat <<-DLM
        \$cred = \$Host.ui.PromptForCredential("$TITLE",
            "$PINERROR$DESCRIPTION",
            "$KEYINFO",
            "gpgkey://$KEYINFO",
            "Generic",
            "None,ReadOnlyUserName")
        if (\$cred) {
            Write-Output \$cred.GetNetworkCredential().Password
        }
DLM
    )
    local cmd_repeat=$(cat <<-DLM
        \$cred = \$Host.ui.PromptForCredential("$TITLE",
            "$REPEATDESCRIPTION",
            "$KEYINFO",
            "gpgkey://$KEYINFO",
            "Generic",
            "None,ReadOnlyUserName")
        if (\$cred) {
            Write-Output \$cred.GetNetworkCredential().Password
        }
DLM
    )
    local cmd_lookup=$(cat <<-DLM
        \$cred = Get-StoredCredential -Target "$CREDENTIALPREFIX$KEYINFO" -Type GENERIC
        if (\$cred) {
            Write-Output \$cred.GetNetworkCredential().Password
        }
DLM
    )
    local cmd_store=$(cat <<-DLM
        \$pw = \$Input | Select-Object -First 1
        \$securepw = ConvertTo-SecureString \$pw -AsPlainText -Force
        New-StoredCredential -Target "$CREDENTIALPREFIX$KEYINFO" -Type GENERIC -UserName "$KEYINFO" -SecurePassword \$securepw -Persist LocalMachine |
        out-null
DLM
    )
    PINERROR=""
    local credpassword
    local credpasswordrepeat
    local passwordfromcache=0
    if [ "$REPEATPASSWORD" -eq "0" ]; then
        if [ "$EXTPASSCACHE" -eq "1" ]; then
            if [ -n "$KEYINFO" ]; then
                credpassword="$(powershell.exe -nologo -noprofile -noninteractive -command "$cmd_lookup")"
                if [ -n "$credpassword" ]; then
                    echo -e "S PASSWORD_FROM_CACHE\nD $credpassword\nOK"
                    return
                fi
            fi
        fi
    fi
    credpassword="$(powershell.exe -nologo -noprofile -noninteractive -command "$cmd_prompt")"
    if [ -n "$credpassword" ]; then
        if [ "$REPEATPASSWORD" -eq "1" ]; then
            credpasswordrepeat="$(powershell.exe -nologo -noprofile -noninteractive -command "$cmd_repeat")"
            if [ "$credpassword" == "$credpasswordrepeat" ]; then
                echo -e "S PIN_REPEATED\nD $credpassword\nOK"
            else
                message "$REPEATERROR" > /dev/null
                echo "$(assuan_result 114)" # unsure this is the correct error
                return
            fi
        else
            echo -e "D $credpassword\nOK"
        fi
        if [ "$EXTPASSCACHE" -eq "1" ]; then
            if [ -n "$KEYINFO" ]; then
                # avoid setting password on visible param
                # alt is to always save on the single or last-of-repeat dialog. And if the repeat fails, then immediately delete it from the cred store
                builtin echo -n "$credpassword" | powershell.exe -nologo -noprofile -noninteractive -command "$cmd_store"
            fi
        fi
    else
        echo "$(assuan_result 99)"
    fi
}

removepassword() {
    if [ -z "$1" ]; then
        echo "$(assuan_result 261)"
        return
    fi
    local cmd_remove=$(cat <<-DLM
        try {
            Remove-StoredCredential -Target "$CREDENTIALPREFIX$1" -Type GENERIC -ErrorAction Stop
        }
        catch {
            Write-Output "$(assuan_result 261)"
            return
        }
        Write-Output "OK"
DLM
    )
    echo "$(powershell.exe -nologo -noprofile -noninteractive -command "$cmd_remove")"
}

message() {
    local desc
    if [ -n "$1" ]; then
        desc="$1"
    else
        desc="$DESCRIPTION"
    fi
    local cmd=$(cat <<-DLM
        \$options = [System.Management.Automation.Host.ChoiceDescription[]] @("$OKBUTTON")
        [int]\$defaultchoice = 0
        \$result = \$host.UI.PromptForChoice("$TITLE",
            "$desc",
            \$options,
            \$defaultchoice)
DLM
    )
    echo "$cmd"
    local result="$(powershell.exe -nologo -noprofile -command "$cmd")" #> /dev/null
    echo "OK"
}

confirm() {
    PINERROR=""
    if [ "$1" == "--one-button" ]; then
        message
        return
    fi
    local cmd=$(cat <<-DLM
        \$options = [System.Management.Automation.Host.ChoiceDescription[]] @("$OKBUTTON", "$CANCELBUTTON")
        [int]\$defaultchoice = 0
        \$result = \$host.UI.PromptForChoice("$TITLE",
            "$DESCRIPTION",
            \$options,
            \$defaultchoice)
        if (\$result) {
            switch(\$result)
            {
                0 { Write-Output "OK"}
                1 { Write-Output "$(assuan_result 99)"}
                2 { Write-Output "$(assuan_result 114)"}
            }
        }
        else {
            Write-Output "$(assuan_result 114)"
        }
DLM
    )
    local result="$(powershell.exe -nologo -noprofile -noninteractive -command "$cmd")"
    echo "$result"
}

settimeout() {
    # https://stackoverflow.com/questions/21176487/adding-a-timeout-to-batch-powershell
    TIMEOUT="$1"
    echo "OK"
}

setdescription() {
    DESCRIPTION="$1"
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
    PINERROR="** $1 ** "
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
    REPEATPASSWORD=1
    REPEATDESCRIPTION="$1"
    echo "OK"
}

setrepeaterror () {
    REPEATERROR="$1"
    echo "OK"
}

setokbutton() {
    OKBUTTON="${$1//_/&}"
    echo "OK"
}

setcancelbutton() {
    CANCELBUTTON="${$1//_/&}"
    echo "OK"
}

setnotokbutton() {
    NOTOKBUTTON="${$1//_/&}"
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

setoption() {
    local key="$(echo "$1" | cut -d'=' -f1)"
    local value="$(echo "$1" | cut -d'=' -s -f2-)"
    case $key in
        allow-external-password-cache)
            EXTPASSCACHE=1
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
        *)
            echo "OK"
            ;;
    esac
}

echo "OK Your orders please"
while IFS= read -r line; do
    #echo "$line" >> /home/dalep/tracepin.txt
    action="$(echo $line | cut -d' ' -f1)"
    args="$(echo $line | cut -d' ' -s -f2-)"
    #echo "action:$action:"
    #echo "args:$args:"
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
