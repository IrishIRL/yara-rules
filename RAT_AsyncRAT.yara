/*
   YARA Rule Set
   Author: IrishIRL
   Date: 2022-12-03
   Reference: "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
   Identifier: malware
*/

rule AsyncRAT: RAT
{
   meta:
      description = "AsyncRAT v0.5.7B - Remote Administration Tool, became popular across hackforums members"
      author = "IrishIRL"
      hash1 = "42b647e06beb09787a9ef602cac06caeacc44ca14b4cceb69520f9dcbb946854"
      hash2 = "02e5b0b06e775d758396cca84532c6e0e21beff8ff55ccf095b1708597feeaf7"
   strings:
      $magic = "MZ"

      $required1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide
      $required2 = "Stub.exe" fullword wide

      $imports01 = "System.Drawing.Imaging" fullword ascii
      $imports02 = "System.Net.Sockets" fullword ascii
      $imports03 = "System.Security.Cryptography" fullword ascii

      $suspicious01 = "HWID" fullword wide
      $suspicious02 = "Pastebin" fullword wide
      $suspicious03 = "Antivirus" fullword wide
      $suspicious04 = "R\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
      $suspicious05 = "Select * from Win32_ComputerSystem" fullword wide

      $antivm01 = "vmware" fullword wide
      $antivm02 = "VirtualBox" fullword wide
      $antivm03 = "SbieDll.dll" fullword wide

   condition:
      $magic at 0 and
      all of ($required*) and all of ($imports*) and
      (all of ($suspicious*) or all of ($antivm*) or
      (3 of ($suspicious*) and 2 of ($antivm*)))
}
