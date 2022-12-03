/*
   YARA Rule Set
   Author: IrishIRL
   Date: 2022-12-03
   Identifier: malware
*/

rule AsyncRAT: RAT
{
   meta:
      description = "AsyncRAT v0.5.7B - Remote Administration Tool, became popular across hackforums members"
      author = "IrishIRL"
      reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
      date = "2022-12-03"
      hash1 = "42b647e06beb09787a9ef602cac06caeacc44ca14b4cceb69520f9dcbb946854"

   strings:
      $magic = "MZ"

      $required01 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide
      $required02 = "START \"\" \"" fullword wide
      $required03 = "DEL \"" fullword wide
      // $required04 = "Stub.exe" fullword wide // official builder requires Stub.exe. However, other builders could easily change to another name.

      $imports01 = "System.Drawing.Imaging" fullword ascii
      $imports02 = "System.Net.Sockets" fullword ascii
      $imports03 = "System.Security.Cryptography" fullword ascii

      $suspicious01 = "HWID" fullword wide
      $suspicious02 = "Pastebin" fullword wide
      $suspicious03 = "Antivirus" fullword wide
      $suspicious04 = "R\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
      $suspicious05 = "Select * from Win32_ComputerSystem" fullword wide
      $suspicious06 = "timeout 3 > NUL" fullword wide

      $antivm01 = "vmware" fullword wide
      $antivm02 = "VirtualBox" fullword wide
      $antivm03 = "SbieDll.dll" fullword wide
      $antivm04 = "VIRTUAL" fullword wide

   condition:
      $magic at 0 and
      all of ($required*) and all of ($imports*) and
      (all of ($suspicious*) or all of ($antivm*) or
      (3 of ($suspicious*) and 2 of ($antivm*)))
}