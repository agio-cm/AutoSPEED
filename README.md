# AutoSPEED
Automating the intro things on client pentests.

## Current Capabilities
Nmap TCP/UDP/Egress scans on a provided scope with the ability to add an exclusion list.
Parsing of the Nmap results into separate text files for use by other tools.
CrackMapExec to generate a list of hosts that do not have SMB Signing enabled and SMBv1.
Metasploit RDP NLA checking with a file created with a list of hosts that do not have NLA enabled.
Metasploit IPMI scanning to automatically dump hashes of IPMI hosts if vulnerable.
Eyewitness scanning of http/https hosts.
