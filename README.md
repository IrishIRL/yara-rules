# Yara Rules by IrishIRL
## AsyncRAT Yara Detection Rule
### Sources
Used official builder: https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp

### Possible limitations
To create the rule, investigated only two files built from the officially released builder. As the project is open source, source code could be modified and some of the detectables could be removed.

## NjRAT Yara Detection Rule
### Sources
To create a rule, 16 different builders were used to create malware sampes.<br>
Builder sources: https://github.com/cve0day/RAT<br>
Also used got some strings from https://github.com/Yara-Rules/rules/blob/master/malware/RAT_Njrat.yar

### Possible limitations
Some of the NjRAT builders create files with random 9-10 chars long names. As it is impossible to predict them, I have added the next wildcard: /[a-z]{9,10}.exe/, which can provide additional false-positive results.
