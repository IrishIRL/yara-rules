# NjRAT YARA RULE
## Task
Create a Yara rule to detect a NjRAT malware.

## Sources
To create a rule, 16 different builders were used to create malware sampes. Builder sources: https://github.com/cve0day/RAT <br>
Also used got some strings from https://github.com/Yara-Rules/rules/blob/master/malware/RAT_Njrat.yar

## Issues with YARA
* The current yara rule was tested on small amount of files, so it is could provide many false-positives.
* Some of the NjRAT builders create files with random 9-10 chars long names. As it is impossible to guess such name, I am using a wildcard: /[a-z]{9,10}.exe/, which can provide additional false-positive results.