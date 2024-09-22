rule Detected_WannaCry {
   meta:
      author = "Oguzhan YALCIN"
      description = "Detects WannaCry Ransomware"
      hash = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa" //sha256

   strings:
      $s1 = "TaskStart" nocase wide ascii
      $s2 = "GetNativeSystemInfo" nocase wide ascii
      $s3 = "cmd.exe /c \"%s\"" nocase wide ascii
      $s4 = "MsWinZonesCacheCounterMutexA" nocase wide ascii
      $s5 = "OpenServiceA" nocase wide ascii
      $s6 = "CreateServiceA" nocase wide ascii
      $s7 = "StartServiceA" nocase wide ascii

      $o1 = "Microsoft Enhanced RSA and AES" nocase wide ascii
      $o2 = "WNcry@2ol7" nocase wide ascii
      $o3 = "WANACRY!" nocase wide ascii  			//O.M.G

      $h1 = { ff d6 68 ?? f? 40 00 }  //GetProcAddress ile CryptAcquireContextA, CryptImportKey, CryptDestroyKey, CryptEncrypt ve CryptDEcrypt kullanımı

      $h2 = { 68 fc f4 40 00 e8 72 ef ff ff } //bir fonkisyon "icacls . /grant Everyone:F /T /C /Q" parmetresi ile call ediliyor.

      $h3 = { 68 10 e0 40 00 ff 15 18 81 40 00 } // c.wnry dosyasını aciyor (fopen())

      $h4 = { 68 d8 f4 40 00 ff 15 84 80 40 00 } // get path tasksche.exe

   condition:
      uint16(0) == 0x5a4d
      and 4 of ($s*)
      and 1 of ($o*)
      and all of ($h*)
}