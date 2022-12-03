/*
   YARA Rule Set
   Author: IrishIRL
   Date: 2022-12-03
   Reference1: https://github.com/Yara-Rules/rules/blob/master/malware/RAT_Njrat.yar
   Reference2: https://github.com/cve0day/RAT
   Identifier: malware
*/

rule NjRat: RAT
{
   meta:
      author = "IrishIRL"
      description = "NjRat - Remote Access Trojan"
      comment = "Combined from personal collected strings and some data from the reference"
      hash1 = "71aba8ec37ab3ceea5e4609be93e40085608f0f45ac74166c850308866677733"
      hash2 = "d1ae188fa0e8c51c24617c8ce67e27561444a22ac26a92ea2a85f0606780f11b"
      hash3 = "b3a507bbe1dad3081643e9e34e997f69f71441cb0baa1a4f74f3bf5fea145f10"
      hash4 = "64ea7858a04295ddf1b7da477f1a18c2a116d0775acca61086a69f5acd189690"
      hash5 = "e62255d702115eb2f24f3633b18d49674f2407eee8bff6dc9aa922d650be52b9"
      hash6 = "0236cb99962a77995fc4cbc43ff50166acdec56c9e85c9046885a83ebab1850f"
      hash7 = "7a52f4c721579adde4d4bba8df744a9138f849dd95d4fc4078f07ddf87c635cf"
      hash8 = "f53a75d2509244fd5af4523566f04c54e778a23d7c2b35cb24b8499534d34674"
      hash9 = "69935c5ce0e0ff9ac17353022761bdb6e61f1df6072545c6504ecb9c0e8f4553"
      hash10 = "4816fdc2d09085b3593bb2c4cdf8497f13a4a60baf60773648698ce1612ddced"
      hash11 = "739db7173fa7c10ce344acc5390d556ac3f3eab74fd9a53bb2fb6bdc7c0ac36c"
      hash12 = "894d9967789e922e85f58ee64322eec7738c05d71603ec5cce347c9c5c6c78b3"
      hash13 = "242b76fd11d62170e6011d0f3819116905272537fe9e461443689eae6fe63981"
      hash14 = "71ef653202fbf4aaf0450f26c6ee5eb5cb4dddbf0ece0c1f600608482bb4fcad"
      hash15 = "53e566aa0e9a539962d4da8169827ede25cd9af09b065740a32839359bf8aeb3"
      hash16 = "2d0a29715ca94be9f2333f55b59290f8a2b93fd660c76696271713bc225af12d"

   strings:
      $magic = "MZ"

      /* NjRat must have */
      $must01 = "WebClient"

      /* every NjRat scanned had one of the following ping command */
      $cmd01 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide /* found in Server.exe */
      $cmd02 = "md.exe /k ping 0 & del" wide /* NjRat example from online */
      $cmd03 = "cmd.exe /c ping" wide /* NjRat example from online */
      $cmd04 = "cmd.exe /c ping 127.0.0.1 & del \"" fullword wide

      /* some usually gotten items by NjRat */
      $machine_info01 = "get_Location"
      $machine_info02 = "get_Registry"
      $machine_info03 = "get_CurrentUser"
      $machine_info04 = "get_MachineName"
      $machine_info05 = "get_UserName"
      $machine_info06 = "get_LastWriteTime"
      $machine_info07 = "get_FullName"
      $machine_info08 = "get_Keyboard"
      $machine_info09 = "get_PrimaryScreen"
      $machine_info10 = "get_Position"
      $machine_info11 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" /*fullword ascii*/
      $machine_info12 = "netsh firewall add allowedprogram \"" /*fullword wide*/

      /* detect embedded files */
      /* there are version that create files with random 9-10 chars long names */
      /* not detecting these files as searching for random names will provide many false-positives */
      $embedded01 = "j.exe" fullword ascii
      $embedded02 = "Stub.exe" fullword ascii
      $embedded03 = "w.exe" fullword ascii
      $embedded04 = "Programme.exe" fullword ascii
      $embedded05 = "ClassLibrary1.exe" fullword ascii
      $embedded06 = "Trojan.exe" fullword ascii
      $embedded07 = "Hack facebook.exe" fullword ascii
      $embedded08 = "Microsoft.exe" fullword ascii
      $embedded09 = "java_update.exe" fullword ascii
      $embedded10 = "java update.exe" fullword ascii

      $wildembedded = /[a-z]{9,10}.exe/
   condition:
      $magic at 0 and
      (1 of ($cmd*) and 1 of ($embedded*) and 5 of ($machine_info*) and all of ($must*)) or
      /* Second one could be removed, but RATs with rnd named embedded files will be undetected */
      (1 of ($cmd*) and $wildembedded and 6 of ($machine_info*) and all of ($must*))
}
