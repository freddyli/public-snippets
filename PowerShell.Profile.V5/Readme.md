# Configuration

## KeePass Integration -- KeePassHTTP Plugin

In options dialog (`KeePass Main Window/Tools Menu/KeePassHTTP Options`):
    - Required:
        - Tick: `Advanced/Search in all opened databases ...`
    - Recommended:
        - Tick: `General/Request for unlocking ...`
        - Untick: `General/Show a notification ...`

# Other Stuff

### Creating symlink to the profile

Execute this command with **administrative privileges** using `cmd` and NOT `powershell`:

```powershell
C:\Users\...\Documents\WindowsPowerShell>
    mklink Microsoft.PowerShell_profile.ps1 infrastructure\PowerShell.Profile.V5\Microsoft.PowerShell_profile.ps1
```

### Known Issues -- KeePass

1) If KeePass is running, but the wrong KeePass database file is active / selected, the PowerShell integration does not work.
