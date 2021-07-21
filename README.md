# HiveNightmare-Checker
A PowerShell script that checks for dangerous ACLs on system hives and shadows

It does the following:
1. Check for dangerous ACLs on the hive files
2. Ask the user if they want to change them and then uses icacls to change them according to Microsoft's suggestion workarounds
3. Checks shadow copies to see if any have dangerous ACLs on the hive files
4. If any shadow copies are found it asks you if you want to delete them.
