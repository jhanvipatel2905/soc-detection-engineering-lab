# SPL Queries
## Process Creation Monitoring

```spl
index=* Sysmon EventCode=1
| table _time Image ParentImage CommandLine User
```


## PowerShell Execution Detection
```spl
index=* Sysmon Image="*powershell.exe"
| table _time Image ParentImage CommandLine User
```


## Encoded PowerShell Detection
```spl
index=* Sysmon CommandLine="*-EncodedCommand*"
| table _time Image ParentImage CommandLine User
```


## Suspicious Parent-Child Process Detection
```spl
index=* Sysmon ParentImage="*cmd.exe" Image="*powershell.exe"
| table _time ParentImage Image CommandLine
```


## LOLBin (Certutil) Detection
```spl
index=* Sysmon Image="*certutil.exe"
| table _time Image ParentImage CommandLine
```
