# Persistask
A BOF that uses a COM object to interact with Scheduled Tasks to create a logon task. This is great for persistence, and should be more OPSEC safe than conventional methods as it doesn't use the task scheduler binary.

# Installation
Simply browse to the directory of the BOF and use `make`.

# Usage
Load the CNA via the script loader in Cobalt Strike, then use with:
`persistask [add / remove] [taskname] [command to run]`
