
import "hash"
import "pe"
import "dotnet"

rule INDICATOR_SUSPICIOUS_EXE_ASEP_REG_Reverse {
    meta:
        author = "ditekSHen"
        description = "Detects file containing reversed ASEP Autorun registry keys"
        threat = "UDS:ASEP.Autorun"
    strings:
        $s1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s2 = "ecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s3 = "secivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s4 = "xEecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s5 = "ecnOsecivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s6 = "yfitoN\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s7 = "tiniresU\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s8 = "nuR\\rerolpxE\\seiciloP\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s9 = "stnenopmoC dellatsnI\\puteS evitcA\\tfosorciM" ascii wide nocase
        $s10 = "sLLD_tinIppA\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s11 = "snoitpO noitucexE eliF egamI\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s12 = "llehS\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s13 = "daol\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s14 = "daoLyaleDtcejbOecivreSllehS\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s15 = "nuRotuA\\rossecorP\\dnammoC\\tfosorciM" ascii wide nocase
        $s16 = "putratS\\sredloF llehS resU\\rerolpxE\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s17 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\teSlortnoCtnerruC\\metsyS" ascii wide nocase
        $s18 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\100teSlortnoC\\metsyS" ascii wide nocase
        $s19 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\erawtfoS" ascii wide nocase
        $s20 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\edoN2346woW\\erawtfoS" ascii wide nocase
    condition:
        1 of them and filesize < 2000KB
}

rule DotNet_EmbeddedPE
{
   meta:

    author = "Malware Utkonos"
    date = "2021-01-18"
    description = "This detects a PE embedded in a .NET executable."
    namespace = "DotNet_EmbeddedPE"
    threat = "SUSPECIOUS:DotNET.Loader"


   condition:

    for any str in dotnet.user_strings : ( str matches
/^4\x00[dD]\x005\x00[aA]\x00.{186,}/ )
}


rule agent_tesla
{
    meta:

        description = "Detecting HTML strings used by Agent Tesla malware"
        author = "Stormshield"
        version = "1.0"
        reference = "https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/"
        namespace = "agent_tesla"
        threat = "Tesla:Agent"

    strings:

        $html_username    = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_pc_name     = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_os_name     = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_clipboard   = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

    condition:

        3 of them
}


rule Agent_Tesla : Agent_Tesla
{
    meta:

        author = "LastLine"
        reference = "https://www.lastline.com/labsblog/surge-of-agent-tesla-threat-report/"
        namespace = "Agent_Tesla"
        threat = "Agent:Tesla"


    strings:

        $pass = "amp4Z0wpKzJ5Cg0GDT5sJD0sMw0IDAsaGQ1Afik6NwXr6rrSEQE=" fullword ascii wide nocase
        $salt = "aGQ1Afik6NampDT5sJEQE4Z0wpsMw0IDAD06rrSswXrKzJ5Cg0G=" fullword ascii wide nocase
 
    condition:

        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and all of them
}

rule AgentTesla
{
    meta:

        author = "InQuest Labs"
        source = "http://blog.inquest.net/blog/2018/05/22/field-notes-agent-tesla-open-directory/"
        created = "05/18/2018"
        TLP = "WHITE"
        namespace = "AgentTesla"
        threat = "Agent.Tesla"

    strings:

        $s0 = "SecretId1" ascii
        $s1 = "#GUID" ascii
        $s2 = "#Strings" ascii
        $s3 = "#Blob" ascii
        $s4 = "get_URL" ascii
        $s5 = "set_URL" ascii
        $s6 = "DecryptIePassword" ascii
        $s8 = "GetURLHashString" ascii
        $s9 = "DoesURLMatchWithHash" ascii

        $f0 = "GetSavedPasswords" ascii
        $f1 = "IESecretHeader" ascii
        $f2 = "RecoveredBrowserAccount" ascii
        $f4 = "PasswordDerivedBytes" ascii
        $f5 = "get_ASCII" ascii
        $f6 = "get_ComputerName" ascii
        $f7 = "get_WebServices" ascii
        $f8 = "get_UserName" ascii
        $f9 = "get_OSFullName" ascii
        $f10 = "ComputerInfo" ascii
        $f11 = "set_Sendwebcam" ascii
        $f12 = "get_Clipboard" ascii
        $f13 = "get_TotalFreeSpace" ascii
        $f14 = "get_IsAttached" ascii

        $x0 = "IELibrary.dll" ascii wide
        $x1 = "webpanel" ascii wide nocase
        $x2 = "smtp" ascii wide nocase
        
        $v5 = "vmware" ascii wide nocase
        $v6 = "VirtualBox" ascii wide nocase
        $v7 = "vbox" ascii wide nocase
        $v9 = "avghookx.dll" ascii wide nocase

        $pdb = "IELibrary.pdb" ascii

    condition:

        (
            (
                5 of ($s*) or 
                7 of ($f*)
            ) and
            all of ($x*) and 
            all of ($v*) and
            $pdb
        )

}

rule AdwareDownloaderA
{
	meta:
		Description  = "Adware.Downloader.A.vb"
		ThreatLevel  = "5"
        namespace = "AdwareDownloaderA"
        threat = "Adware:Downloader.A"

	strings:

		$ = "odiassi" ascii wide
		$ = "stavers" ascii wide
		$ = "trollimog" ascii wide
		$ = "diapause" ascii wide
		$ = "UserControl1" ascii wide
		$ = "listboxmod01" ascii wide

	condition:
		all of them
}

rule Win32_Downloader_dlMarlboro : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "DLMARLBORO"
        description         = "Yara rule that detects dlMarlboro downloader."

        tc_detection_type   = "Downloader"
        tc_detection_name   = "dlMarlboro"
        tc_detection_factor = 3
        namespace           = "Win32_Downloader_dlMarlboro"
        threat              = "Trojan:dlMarlboro.Downloader"

    strings:

        $ping_apnic = {
            55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 6A ?? 8D 85 ?? ?? ?? ?? C7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 0F 57 
            C0 F3 0F 7F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 6A ?? FF 15 ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 
            85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 
            8D 85 ?? ?? ?? ?? 50 6A ?? FF 15 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 
            B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $download_bin_1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 89 65 ?? 8B F2 8B C1 89 85 ?? 
            ?? ?? ?? 8B 7D ?? 68 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? 50 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 68 ?? ?? 
            ?? ?? 83 EC ?? 8B CC 6A ?? 6A ?? C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? 56 C6 01 
            ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 
            E8 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? F6 84 
            05 ?? ?? ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? FF 50 ?? 8D 4D ?? 51 8B 
            C8 E8 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B D7 8B C8 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D6 8B C8 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C8 E8 
            ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 8D ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 8D 55 
            ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 8D 55 ?? C6 
            45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? F6 84 05 ?? ?? 
            ?? ?? ?? 74 ?? 83 EC ?? 8D 45 ?? 8D 4D ?? 50 E8 ?? ?? ?? ?? C6 45 ?? ?? BA ?? ?? ?? 
            ?? 8B C8 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 74 ?? B3 ?? EB ?? 32 DB
        }

        $download_bin_2 = { 
            C7 45 ?? ?? ?? ?? ?? F6 85 ?? ?? ?? ?? ?? 74 ?? 83 7D ?? ?? 72 ?? FF 75 ?? E8 ?? ?? 
            ?? ?? 83 C4 ?? 84 DB 74 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? 50 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 ?? 8D 80 ?? ?? ?? ?? 89 
            85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B 40 ?? 03 
            C8 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 50 C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 83 
            C4 ?? 8B 8D ?? ?? ?? ?? 8B F0 85 C9 74 ?? 8B 01 FF 50 ?? 85 C0 74 ?? 8B 10 8B C8 6A 
            ?? FF 12 8B 06 8B CE 6A ?? 8B 40 ?? FF D0 50 8D 55 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8B 5D ?? 83 C4 ?? 8B 7D ?? 8B 08 8B 49 ?? F6 44 01 ?? ?? 75 ?? 8B 75 ?? 8D 4D ?? 
            83 FB ?? B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 0F 43 CF 3B F0 0F 42 C6 50 E8 ?? ?? ?? ?? 83 
            C4 ?? 85 C0 75 ?? 83 FE ?? 73 ?? 83 C8 ?? EB ?? 33 C0 83 FE ?? 0F 95 C0 85 C0 0F 94 
            C0 84 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 
            E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? 
            ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 56 E8 ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 FB ?? 72 ?? 57 E8 ?? ?? ?? ?? 83 C4 
            ?? 83 7D ?? ?? 72 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 72 ?? FF 75 ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B C6 EB ?? 8B 8D ?? ?? ?? 
            ?? 8B 01 FF 50 ?? 8B 8D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? C3 8B 85 ?? ?? 
            ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 
            5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and $ping_apnic and $download_bin_1 and $download_bin_2
}


rule Windows_PUP_MediaArena_a9e3b4a1 {

    meta:

        author = "Elastic Security"
        id = "a9e3b4a1-fd87-4f8f-a9d4-d93f9c018270"
        fingerprint = "0535228889b1d2a7c317a7ce939621d3d20e2a454ec6d31915c25884931d62b9"
        creation_date = "2023-06-02"
        last_modified = "2023-06-13"
        threat_name = "Windows.PUP.MediaArena"
        reference_sample = "c071e0b67e4c105c87b876183900f97a4e8bc1a7c18e61c028dee59ce690b1ac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
        namespace = "Windows_PUP_MediaArena_a9e3b4a1"
        threat = "PUP:MediaArena"

    strings:

        $a1 = "Going to change default browser to be MS Edge ..." wide
        $a2 = "https://www.searcharchiver.com/eula" wide
        $a3 = "Current default browser is unchanged!" wide
        $a4 = "You can terminate your use of the Search Technology and Search Technology services"
        $a5 = "The software may also offer to change your current web navigation access points"
        $a6 = "{{BRAND_NAME}} may have various version compatible with different platform,"
        $a7 = "{{BRAND_NAME}} is a powerful search tool" wide

    condition:

        2 of them
}


rule Windows_PUP_Generic_198b73aa {

    meta:

        author = "Elastic Security"
        id = "198b73aa-d7dd-4f28-bf1c-02672a03d031"
        fingerprint = "23c11df4ce2ec2d30b1916b73fc94a84b6a817c1686905fd69fa7a6528798d5f"
        creation_date = "2023-07-27"
        last_modified = "2023-09-20"
        threat_name = "Windows.PUP.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
        namespace = "Windows_PUP_Generic_198b73aa"
        threat = "PUP:GenericWin"

    strings:

        $a1 = "[%i.%i]av=[error]" fullword
        $a2 = "not_defined" fullword
        $a3 = "osver=%d.%d-ServicePack %d" fullword

    condition:

        all of them

}


rule Windows_Hacktool_CpuLocker_73b41444 {

    meta:

        author = "Elastic Security"
        id = "73b41444-4c17-4fea-b440-fe7b0a086a7f"
        fingerprint = "3f90517fbeafdccd37e4b8ab0316a91dd18a911cb1f4ffcd4686ab912a0feab4"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.Hacktool.CpuLocker"
        reference_sample = "dbfc90fa2c5dc57899cc75ccb9dc7b102cb4556509cdfecde75b36f602d7da66"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
        namespace = "Windows_Hacktool_CpuLocker_73b41444"
        threat = "Hacktool:CpuLocker.Maldrv"

    strings:

        $str1 = "\\CPULocker.pdb"
    condition:

        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
        
}


rule Windows_Exploit_Log4j_dbac7698 {

    meta:

        author = "Elastic Security"
        id = "dbac7698-906c-44a2-9795-f04ec07d7fcc"
        fingerprint = "cd06db6f5bebf0412d056017259b5451184d5ba5b2976efd18fa8f96dba6a159"
        creation_date = "2021-12-13"
        last_modified = "2022-01-13"
        threat_name = "Windows.Exploit.Log4j"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
        namespace = "Windows_Exploit_Log4j_dbac7698"
        threat = "EXPLOIT:Win.Log4j"

    strings:

        $jndi1 = "jndi.ldap.LdapCtx.c_lookup"
        $jndi2 = "logging.log4j.core.lookup.JndiLookup.lookup"
        $jndi3 = "com.sun.jndi.url.ldap.ldapURLContext.lookup"
        $exp1 = "Basic/Command/Base64/"
        $exp2 = "java.lang.ClassCastException: Exploit"
        $exp3 = "WEB-INF/classes/Exploit"
        $exp4 = "Exploit.java"

    condition:

        2 of ($jndi*) and 1 of ($exp*)

}

rule Multi_Ransomware_Luna_8614d3d7 {

    meta:

        author = "Elastic Security"
        id = "8614d3d7-7fd2-4cf9-aa97-48a8d9333f38"
        fingerprint = "90c97ecfce451e1373af0d7538cf12991cc844d05c99ee18570e176143ccd899"
        creation_date = "2022-08-02"
        last_modified = "2022-08-16"
        threat_name = "Multi.Ransomware.Luna"
        reference_sample = "1cbbf108f44c8f4babde546d26425ca5340dccf878d306b90eb0fbec2f83ab51"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
        namespace = "Multi_Ransomware_Luna_8614d3d7"
        threat = "MULTI:Ransom.Luna"

    strings:

        $str_extensions = ".ini.exe.dll.lnk"
        $str_ransomnote_bs64 = "W1dIQVQgSEFQUEVORUQ/XQ0KDQpBbGwgeW91ciBmaWxlcyB3ZXJlIG1vdmVkIHRvIHNlY3VyZSBzdG9yYWdlLg0KTm9ib"
        $str_path = "/home/username/"
        $str_error1 = "Error while writing encrypted data to:"
        $str_error2 = "Error while writing public key to:"
        $str_error3 = "Error while renaming file:"
        $chunk_calculation0 = { 48 8D ?? 00 00 48 F4 48 B9 8B 3D 10 B6 9A 5A B4 36 48 F7 E1 48 }
        $chunk_calculation1 = { 48 C1 EA 12 48 89 D0 48 C1 E0 05 48 29 D0 48 29 D0 48 3D C4 EA 00 00 }

    condition:

        5 of ($str_*) or all of ($chunk_*)

}


rule Windows_Trojan_SnakeKeylogger_af3faa65 {

    meta:

        author = "Elastic Security"
        id = "af3faa65-b19d-4267-ac02-1a3b50cdc700"
        fingerprint = "15f4ef2a03c6f5c6284ea6a9013007e4ea7dc90a1ba9c81a53a1c7407d85890d"
        creation_date = "2021-04-06"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.SnakeKeylogger"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
        namespace = "Windows_Trojan_SnakeKeylogger_af3faa65"
        threat = "Trojan:SnakeKeylogger"

    strings:

        $a1 = "get_encryptedPassword" ascii fullword
        $a2 = "get_encryptedUsername" ascii fullword
        $a3 = "get_timePasswordChanged" ascii fullword
        $a4 = "get_passwordField" ascii fullword
        $a5 = "set_encryptedPassword" ascii fullword
        $a6 = "get_passwords" ascii fullword
        $a7 = "get_logins" ascii fullword
        $a8 = "GetOutlookPasswords" ascii fullword
        $a9 = "StartKeylogger" ascii fullword
        $a10 = "KeyLoggerEventArgs" ascii fullword
        $a11 = "KeyLoggerEventArgsEventHandler" ascii fullword
        $a12 = "GetDataPassword" ascii fullword
        $a13 = "_encryptedPassword" ascii fullword
        $b1 = "----------------S--------N--------A--------K--------E----------------"
        $c1 = "SNAKE-KEYLOGGER" ascii fullword

    condition:

        8 of ($a*) or #b1 > 5 or #c1 > 5
}


rule Windows_Trojan_XtremeRAT_cd5b60be {

    meta:

        author = "Elastic Security"
        id = "cd5b60be-4685-425a-8fe1-8366c0e5b84a"
        fingerprint = "2ee35d7c34374e9f5cffceb36fe1912932288ea4e8211a8b77430b98a9d41fb2"
        creation_date = "2022-03-15"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.XtremeRAT"
        reference_sample = "735f7bf255bdc5ce8e69259c8e24164e5364aeac3ee78782b7b5275c1d793da8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
        namespace = "Windows_Trojan_XtremeRAT_cd5b60be"
        threat = "Win32:Nimnul.a"

    strings:

        $s01 = "SOFTWARE\\XtremeRAT" wide fullword
        $s02 = "XTREME" wide fullword
        $s03 = "STARTSERVERBUFFER" wide fullword
        $s04 = "ENDSERVERBUFFER" wide fullword
        $s05 = "ServerKeyloggerU" ascii fullword
        $s06 = "TServerKeylogger" ascii fullword
        $s07 = "XtremeKeylogger" wide fullword
        $s08 = "XTREMEBINDER" wide fullword
        $s09 = "UnitInjectServer" ascii fullword
        $s10 = "shellexecute=" wide fullword

    condition:

        7 of ($s*)

}

rule Windows_Trojan_Zeus_e51c60d7 {

    meta:
        author = "Elastic Security"
        id = "e51c60d7-3afa-4cf5-91d8-7782e5026e46"
        fingerprint = "813e2ee2447fcffdde6519dc6c52369a5d06c668b76c63bb8b65809805ecefba"
        creation_date = "2021-02-07"
        last_modified = "2021-10-04"
        description = "Detects strings used in Zeus web injects. Many other malware families are built on Zeus and may hit on this signature."
        threat_name = "Windows.Trojan.Zeus"
        reference = "https://www.virusbulletin.com/virusbulletin/2014/10/paper-evolution-webinjects"
        reference_sample = "d7e9cb60674e0a05ad17eb96f8796d9f23844a33f83aba5e207b81979d0f2bf3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
        namespace = "Windows_Trojan_Zeus_e51c60d7"
        threat = "Trojan:Zeus.Agent"
        
    strings:

        $a1 = "name=%s&port=%u" ascii fullword
        $a2 = "data_inject" ascii wide fullword
        $a3 = "keylog.txt" ascii fullword
        $a4 = "User-agent: %s]]]" ascii fullword
        $a5 = "%s\\%02d.bmp" ascii fullword

    condition:
        all of them
}

rule Windows_Ransomware_WannaCry_d9855102 {

    meta:

        author = "Elastic Security"
        id = "d9855102-56dc-4e4c-9599-82fa52922b95"
        fingerprint = "f96f2f0eb3cdf6e882adcad06ad10e375412dec99687b3d38d4dbe9bdde52db5"
        creation_date = "2022-08-29"
        last_modified = "2022-09-29"
        threat_name = "Windows.Ransomware.WannaCry"
        reference_sample = "0b7878babbaf7c63d808f3ce32c7306cb785fdfb1ceb73be07fb48fdd091fdfb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
        namespace = "Windows_Ransomware_WannaCry_d9855102"
        threat = "Ransom:Wannacry"

    strings:

        $a1 = "@WanaDecryptor@.exe" wide fullword
        $a2 = ".WNCRY" wide fullword
        $a3 = "$%d worth of bitcoin" fullword
        $a4 = "%d%d.bat" fullword
        $a5 = "This folder protects against ransomware. Modifying it will reduce protection" wide fullword
        $b1 = { 53 55 56 57 FF 15 D0 70 00 10 8B E8 A1 8C DD 00 10 85 C0 75 6A 68 B8 0B 00 00 FF 15 70 70 00 10 }
        $b2 = { A1 90 DD 00 10 53 56 57 85 C0 75 3E 8B 1D 60 71 00 10 8B 3D 70 70 00 10 6A 00 FF D3 83 C4 04 A3 }
        $b3 = { 56 8B 74 24 08 57 8B 3D 70 70 00 10 56 E8 2E FF FF FF 83 C4 04 A3 8C DD 00 10 85 C0 75 09 68 88 }

    condition:

        5 of ($a*) or 1 of ($b*)
}

rule Windows_Hacktool_CheatEngine_fedac96d {

    meta:

        author = "Elastic Security"
        id = "fedac96d-4c23-4c8d-8476-4c89fd610441"
        fingerprint = "94d375ddab90c27ef22dd18b98952d0ec8a4d911151970d5b9f59654a8e3d7db"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Subject: Cheat Engine"
        threat_name = "Windows.Hacktool.CheatEngine"
        reference_sample = "b20b339a7b61dc7dbc9a36c45492ba9654a8b8a7c8cbc202ed1dfed427cfd799"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
        namespace = "Windows_Hacktool_CheatEngine_fedac96d"
        threat = "PUA:Hacktool.CheatEngine"


    strings:

        $subject_name = { 06 03 55 04 03 [2] 43 68 65 61 74 20 45 6E 67 69 6E 65 }

    condition:

        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

rule Win32_Ransomware_CryptoLocker : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "CRYPTOLOCKER"
        description         = "Yara rule that detects CryptoLocker ransomware."
        namespace           = "Win32_Ransomware_CryptoLocker"
        threat              = "YARA:Win32.CryptoLocker"
        tc_detection_type   = "Ransomware"
        tc_detection_name   = "CryptoLocker"
        tc_detection_factor = 5

    strings:

        $file_loop_1 = {
            55 8B EC 83 EC ?? 53 56 8B D9 57 89 5D ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 32 C9 83 7D ?? ?? 88 4D ?? 0F 86 45 01 
            00 00 8B 5D ?? 0F 57 C0 66 0F 13 45 ?? 84 C9 74 08 6A ?? FF 15 ?? ?? ?? ?? 6A ?? 6A ?? FF 75 ?? FF 75 ?? FF 33 FF 15 ?? 
            ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 FF 33 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? 8B 75 ?? 
            6A ?? 8B 49 ?? 6A ?? 52 56 8B 01 6A ?? 89 55 ?? 8B 00 FF D0 84 C0 0F 84 E6 00 00 00 FF 15 ?? ?? ?? ?? 8B 7D ?? 33 D2 89 
            45 ?? 8B D8 85 FF 72 18 77 08 81 FE ?? ?? ?? ?? 76 0E B8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB 05 8B C6 89 7D ?? 3B D0 73 
            0F 8B 45 ?? 8D 0C 13 8B 40 ?? 88 0C 02 42 EB CC 8B 5D ?? 85 FF 8B FE 75 04 85 F6 74 6B 85 DB 77 0E 72 08 81 FF ?? ?? ?? 
            ?? 73 04 8B F7 EB 05 BE ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 8B 45 ?? 56 FF 70 ?? 8B 45 ?? FF 30 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 
            39 75 ?? 75 ?? 8B 45 ?? 2B FE 8B 55 ?? 83 DB ?? 2B D7 8B 48 ?? 8B 45 ?? 1B C3 50 8B 31 52 FF 75 ?? FF 75 ?? 8B 06 6A ?? 
            FF D0 84 C0 74 34 85 DB 77 AD 72 04 85 FF 75 95 8B 5D ?? FF 33 FF 15 ?? ?? ?? ?? 8A 4D ?? FE C1 0F B6 C1 88 4D ?? 3B 45 
            ?? 0F 82 C6 FE FF FF B0 ?? 5F 5E 5B 8B E5 5D C2
        }

        $file_loop_2 = {
            55 8B EC 83 EC ?? 53 56 8B D9 57 89 5D ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 32 C9 83 7D ?? ?? 88 4D ?? 0F 86 50 01 
            00 00 8B 5D ?? 0F 57 C0 66 0F 13 45 ?? 84 C9 74 08 6A ?? FF 15 ?? ?? ?? ?? 6A ?? 6A ?? FF 75 ?? FF 75 ?? FF 33 FF 15 ?? 
            ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 FF 33 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? 8B 49 ?? 
            8B 75 ?? 8B 01 6A ?? 8B 00 6A ?? 52 56 6A ?? 89 55 ?? FF D0 84 C0 0F 84 F1 00 00 00 FF 15 ?? ?? ?? ?? 8B 7D ?? 89 45 ?? 
            33 D2 8B D8 85 FF 72 18 77 08 81 FE ?? ?? ?? ?? 76 0E B8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB 05 8B C6 89 7D ?? 3B D0 73 
            10 8B 45 ?? 8D 0C 13 8B 40 ?? 42 88 4C 02 ?? EB CB 8B 5D ?? 85 FF 8B FE 75 04 85 F6 74 75 85 DB 77 11 72 08 81 FF ?? ?? 
            ?? ?? 73 07 8B F7 89 5D ?? EB 0C BE ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 8B 45 ?? 56 FF 70 ?? 8B 45 ?? FF 
            30 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 39 75 ?? 75 ?? 8B 45 ?? 8B 55 ?? 8B 48 ?? 8B 45 ?? 2B FE 8B 31 83 DB ?? 2B D7 1B C3 50 
            8B 06 52 FF 75 ?? FF 75 ?? 6A ?? FF D0 84 C0 74 34 85 DB 77 A6 72 04 85 FF 75 8B 8B 5D ?? FF 33 FF 15 ?? ?? ?? ?? 8A 4D 
            ?? FE C1 0F B6 C1 88 4D ?? 3B 45 ?? 0F 82 BB FE FF FF B0 ?? 5F 5E 5B 8B E5 5D C2
        }

        $file_loop_3 = {
            55 8B EC 83 EC ?? 53 56 8B C1 57 89 45 ?? E8 ?? ?? ?? ?? 84 C0 0F 84 62 01 00 00 8B 5D ?? 32 C0 0F 57 C0 88 45 ?? 66 0F 
            13 45 ?? EB 03 8D 49 ?? 84 C0 74 08 6A ?? FF 15 ?? ?? ?? ?? 6A ?? 6A ?? FF 75 ?? FF 75 ?? FF 33 FF 15 ?? ?? ?? ?? 85 C0 
            0F 84 27 01 00 00 8D 45 ?? 50 FF 33 FF 15 ?? ?? ?? ?? 85 C0 0F 84 13 01 00 00 8B 4D ?? 8B 55 ?? 8B 49 ?? 8B 75 ?? 8B 01 
            6A ?? 8B 00 6A ?? 52 56 6A ?? 89 55 ?? FF D0 84 C0 0F 84 EE 00 00 00 FF 15 ?? ?? ?? ?? 8B 7D ?? 89 45 ?? 33 D2 8B D8 90 
            85 FF 72 18 77 08 81 FE ?? ?? ?? ?? 76 0E B8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB 05 8B C6 89 7D ?? 3B D0 73 10 8B 45 ?? 
            8D 0C 13 8B 40 ?? 42 88 4C 02 ?? EB CB 8B 5D ?? 85 FF 8B FE 75 04 85 F6 74 75 85 DB 77 11 72 08 81 FF ?? ?? ?? ?? 73 07 
            8B F7 89 5D ?? EB 0C BE ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 8B 45 ?? 56 FF 70 ?? 8B 45 ?? FF 30 FF 15 ?? 
            ?? ?? ?? 85 C0 74 5E 39 75 ?? 75 59 8B 45 ?? 8B 55 ?? 8B 48 ?? 8B 45 ?? 2B FE 8B 31 83 DB ?? 2B D7 1B C3 50 8B 06 52 FF 
            75 ?? FF 75 ?? 6A ?? FF D0 84 C0 74 30 85 DB 77 A6 72 04 85 FF 75 8B 8B 5D ?? FF 33 FF 15 ?? ?? ?? ?? 8A 45 ?? FE C0 88 
            45 ?? 3C ?? 0F 82 BE FE FF FF B0 ?? 5F 5E 5B 8B E5 5D C2
        }

        $encrypt_data_1 = {
            55 8B EC 56 8B 75 ?? 57 8B F9 39 75 ?? 73 09 5F 83 C8 ?? 5E 5D C2 ?? ?? 8B 07 53 85 C0 74 58 48 83 F8 ?? 77 48 8B 5D ?? 
            8B 45 ?? 3B D8 74 0B 56 50 53 E8 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? 8D 45 ?? 89 75 ?? 50 8B 45 ?? 53 6A ?? 0F B6 C0 50 6A ?? 
            FF 77 ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 83 CA ?? 85 C0 5B 0F 44 CA 5F 8B C1 5E 5D C2 ?? ?? 5B 5F 83 C8 ?? 5E 5D C2 ?? ?? 8B 
            47 ?? 33 D2 89 45 ?? 8B 47 ?? 85 F6 74 26 8B 7D ?? 8B DE 8B 4D ?? 8B F0 2B F9 8A 04 0F 8D 49 ?? 32 04 32 88 41 ?? 8D 42 
            ?? 33 D2 F7 75 ?? 4B 75 E9 8B 75 ?? 5B 5F 8B C6 5E 5D C2
        }

        $encrypt_data_2 = {
            55 8B EC 56 8B 75 ?? 57 8B F9 39 75 ?? 73 09 5F 83 C8 ?? 5E 5D C2 ?? ?? 8B 07 53 85 C0 74 56 48 83 F8 ?? 77 46 8B 5D ?? 
            8B 45 ?? 3B D8 74 0B 56 50 53 E8 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? 8D 45 ?? 50 0F B6 45 ?? 53 6A ?? 50 6A ?? FF 77 ?? 89 75 
            ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 83 CA ?? 85 C0 5B 0F 44 CA 5F 8B C1 5E 5D C2 ?? ?? 5B 5F 83 C8 ?? 5E 5D C2 ?? ?? 8B 47 ?? 
            33 D2 89 45 ?? 8B 47 ?? 85 F6 74 26 8B 4D ?? 8B 7D ?? 8B DE 2B F9 8B F0 8A 04 0F 32 04 32 8D 49 ?? 88 41 ?? 8D 42 ?? 33 
            D2 F7 75 ?? 4B 75 E9 8B 75 ?? 5B 5F 8B C6 5E 5D C2
        }

        $encrypt_data_3 = {
            55 8B EC 53 56 8B 75 ?? 8B D9 39 75 ?? 72 4C 83 3B ?? 77 47 8B 45 ?? 57 8B 7D ?? 3B F8 74 0B 56 50 57 E8 ?? ?? ?? ?? 83 
            C4 ?? FF 75 ?? 8D 45 ?? 50 0F B6 45 ?? 57 6A ?? 50 6A ?? FF 73 ?? 89 75 ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 83 CA ?? 85 C0 5F 
            0F 44 CA 5E 8B C1 5B 5D C2 ?? ?? 5E 83 C8 ?? 5B 5D C2
        }

        $decrypt_data_1 = {
            55 8B EC 53 56 57 8B F9 8B 07 85 C0 74 53 48 83 F8 ?? 77 55 8B 75 ?? 39 75 ?? 72 4D 8B 5D ?? 8B 45 ?? 3B D8 74 0B 56 50 
            53 E8 ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 89 75 ?? 50 8B 45 ?? 53 6A ?? 0F B6 C0 50 6A ?? FF 77 ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 
            83 CA ?? 85 C0 5F 0F 44 CA 5E 8B C1 5B 5D C2 ?? ?? 8B 75 ?? 39 75 ?? 73 0A 5F 5E 83 C8 ?? 5B 5D C2 ?? ?? 8B 47 ?? 33 D2 
            89 45 ?? 8B 47 ?? 85 F6 74 28 8B 7D ?? 8B DE 8B 4D ?? 8B F0 2B F9 8B FF 8A 04 0F 8D 49 ?? 32 04 32 88 41 ?? 8D 42 ?? 33 
            D2 F7 75 ?? 4B 75 E9 8B 75 ?? 5F 8B C6 5E 5B 5D C2
        }

        $decrypt_data_2 = {
            55 8B EC 53 56 57 8B F9 8B 07 85 C0 74 51 48 83 F8 ?? 77 53 8B 75 ?? 39 75 ?? 72 4B 8B 5D ?? 8B 45 ?? 3B D8 74 0B 56 50 
            53 E8 ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 50 0F B6 45 ?? 53 6A ?? 50 6A ?? FF 77 ?? 89 75 ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 83 CA 
            ?? 85 C0 5F 0F 44 CA 5E 8B C1 5B 5D C2 ?? ?? 8B 75 ?? 39 75 ?? 73 0A 5F 5E 83 C8 ?? 5B 5D C2 ?? ?? 8B 47 ?? 33 D2 89 45 
            ?? 8B 47 ?? 85 F6 74 2A 8B 4D ?? 8B 7D ?? 8B DE 2B F9 8B F0 8D 64 24 ?? 8A 04 0F 32 04 32 8D 49 ?? 88 41 ?? 8D 42 ?? 33 
            D2 F7 75 ?? 4B 75 E9 8B 75 ?? 5F 8B C6 5E 5B 5D C2 
        }

        $decrypt_data_3 = {
            55 8B EC 53 8B D9 83 3B ?? 77 56 56 8B 75 ?? 39 75 ?? 73 09 5E 83 C8 ?? 5B 5D C2 ?? ?? 8B 45 ?? 57 8B 7D ?? 3B F8 74 0B 
            56 50 57 E8 ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 50 0F B6 45 ?? 57 6A ?? 50 6A ?? FF 73 ?? 89 75 ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 
            83 CA ?? 85 C0 5F 0F 44 CA 5E 8B C1 5B 5D C2 ?? ?? 83 C8 ?? 5B 5D C2
        }

        $decrypt_strings_1 = {
            55 8B EC 53 56 8B D9 8B F2 57 33 C9 33 FF 2B DE 8B 45 ?? 8D 14 31 8A 04 07 02 C1 32 04 13 88 02 8D 47 ?? 33 D2 F7 75 ?? 
            8B FA F6 C1 ?? 75 0B 8B C1 D1 E8 66 83 3C 46 ?? 74 03 41 EB D3 D1 E9 5F 5E 5B 8D 41 ?? 5D C3 
        }

        $decrypt_strings_2 = {
            55 8B EC 53 56 8B D9 57 8B F2 33 C9 33 FF 2B DE 8B 45 ?? 8D 14 31 8A 04 07 02 C1 32 04 13 88 02 8D 47 ?? 33 D2 F7 75 ?? 
            8B FA F6 C1 ?? 75 0B 8B C1 D1 E8 66 83 3C 46 ?? 74 03 41 EB D3 5F D1 E9 5E 8D 41 ?? 5B 5D C3
        }

        $decrypt_1 = {
            A1 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 8C B7 00 00 00 33 D2 8B 0C 95 ?? ?? ?? ?? 33 0C 95 ?? ?? ?? ?? 81 E1 ?? ?? ?? ?? 33 0C 
            95 ?? ?? ?? ?? 8B C1 D1 E9 83 E0 ?? 33 0C 85 ?? ?? ?? ?? 33 0C 95 ?? ?? ?? ?? 89 0C 95 ?? ?? ?? ?? 42 81 FA ?? ?? ?? ?? 
            7C C0 81 FA ?? ?? ?? ?? 7D 39 56 8D 34 95 ?? ?? ?? ?? 8B 0E 33 4E ?? 81 E1 ?? ?? ?? ?? 33 0E 8B C1 D1 E9 83 E0 ?? 8B 04 
            85 ?? ?? ?? ?? 33 86 ?? ?? ?? ?? 33 C1 89 06 83 C6 ?? 81 FE ?? ?? ?? ?? 7C D0 5E 8B 0D ?? ?? ?? ?? 33 0D ?? ?? ?? ?? 81 
            E1 ?? ?? ?? ?? 33 0D ?? ?? ?? ?? 8B C1 D1 E9 83 E0 ?? 33 0C 85 ?? ?? ?? ?? 33 0D ?? ?? ?? ?? 33 C0 89 0D ?? ?? ?? ?? 8B 
            0C 85 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 8B C1 C1 E8 ?? 33 C8 8B C1 25 ?? ?? ?? ?? C1 E0 ?? 33 C8 8B C1 25 ?? ?? ?? ?? C1 E0 
            ?? 33 C8 8B C1 C1 E8 ?? 33 C1 C3
        }

        $decrypt_2 = {
            A1 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 8C C7 00 00 00 33 D2 EB 0C 8D A4 24 ?? ?? ?? ?? EB 03 8D 49 ?? 8B 0C 95 ?? ?? ?? ?? 33 
            0C 95 ?? ?? ?? ?? 42 81 E1 ?? ?? ?? ?? 33 0C 95 ?? ?? ?? ?? 8B C1 83 E0 ?? D1 E9 33 0C 85 ?? ?? ?? ?? 33 0C 95 ?? ?? ?? 
            ?? 89 0C 95 ?? ?? ?? ?? 81 FA ?? ?? ?? ?? 7C C0 81 FA ?? ?? ?? ?? 7D 3B 56 8D 34 95 ?? ?? ?? ?? 8B 0E 33 4E ?? 83 C6 ?? 
            81 E1 ?? ?? ?? ?? 33 4E ?? 8B C1 83 E0 ?? D1 E9 8B 04 85 ?? ?? ?? ?? 33 86 ?? ?? ?? ?? 33 C1 89 46 ?? 81 FE ?? ?? ?? ?? 
            7C CE 5E 8B 0D ?? ?? ?? ?? 33 0D ?? ?? ?? ?? 81 E1 ?? ?? ?? ?? 33 0D ?? ?? ?? ?? 8B C1 83 E0 ?? D1 E9 33 0C 85 ?? ?? ?? 
            ?? 33 0D ?? ?? ?? ?? 33 C0 89 0D ?? ?? ?? ?? 8B 0C 85 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 8B C1 C1 E8 ?? 33 C8 8B C1 25 ?? ?? 
            ?? ?? C1 E0 ?? 33 C8 8B C1 25 ?? ?? ?? ?? C1 E0 ?? 33 C8 8B C1 C1 E8 ?? 33 C1 C3
        }

        $decrypt_3 = {
            A1 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 8C C7 00 00 00 33 D2 EB 0C 8D A4 24 ?? ?? ?? ?? EB 03 8D 49 ?? 8B 0C 95 ?? ?? ?? ?? 33 
            0C 95 ?? ?? ?? ?? 42 81 E1 ?? ?? ?? ?? 33 0C 95 ?? ?? ?? ?? 8B C1 83 E0 ?? D1 E9 33 0C 85 ?? ?? ?? ?? 33 0C 95 ?? ?? ?? 
            ?? 89 0C 95 ?? ?? ?? ?? 81 FA ?? ?? ?? ?? 7C C0 81 FA ?? ?? ?? ?? 7D 3B 56 8D 34 95 ?? ?? ?? ?? 8B 0E 33 4E ?? 83 C6 ?? 
            81 E1 ?? ?? ?? ?? 33 4E ?? 8B C1 83 E0 ?? D1 E9 8B 04 85 ?? ?? ?? ?? 33 86 ?? ?? ?? ?? 33 C1 89 46 ?? 81 FE ?? ?? ?? ?? 
            7C CE 5E 8B 0D ?? ?? ?? ?? 33 0D ?? ?? ?? ?? 81 E1 ?? ?? ?? ?? 33 0D ?? ?? ?? ?? 8B C1 83 E0 ?? D1 E9 33 0C 85 ?? ?? ?? 
            ?? 33 0D ?? ?? ?? ?? 33 C0 89 0D ?? ?? ?? ?? 8B 0C 85 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 8B C1 C1 E8 ?? 33 C8 8B C1 25 ?? ?? 
            ?? ?? C1 E0 ?? 33 C8 8B C1 25 ?? ?? ?? ?? C1 E0 ?? 33 C8 8B C1 C1 E8 ?? 33 C1 C3
        }

        $entrypoint_all = {
            83 EC ?? E8 ?? ?? ?? ?? 50 FF 15
        }

    condition:
        uint16(0) == 0x5A4D and ((($file_loop_1 and $encrypt_data_1 and $decrypt_data_1 and $decrypt_strings_1 and $decrypt_1) or
        ($file_loop_2 and $encrypt_data_2 and $decrypt_data_2 and $decrypt_strings_2 and $decrypt_2) or
        ($file_loop_3 and $encrypt_data_3 and $decrypt_data_3 and $decrypt_3)) and
        ($entrypoint_all at pe.entry_point))
}

rule potential_python_keylogger  {

    meta:
        author          = "Movalabs"

        threat          = "Potential:PythonKeylogger"
        namespace       = "potential_python_keylogger"

    strings:

        $s1 = "def OnKeyboardEvent" fullword ascii
        $s2 = "legal disclaimer: Usage of this keylogger for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program."
        $s3 = "file_log = 'C:\\Program Files\\keylogger\\log.txt'" fullword ascii
        $s4 = "hooks_manager = pyHook.HookManager()" fullword ascii
        $s5 = "hooks_manager.KeyDown = OnKeyboardEvent" fullword ascii

    condition:
        2 of them
}

rule eicar_av_test {
    /*
       Per standard, match only if entire file is EICAR string plus optional trailing whitespace.
       The raw EICAR string to be matched is:
       X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
       Threat level: 1-5
    */

    meta:
        description             = "This is a standard AV test, intended to verify that BinaryAlert is working correctly."
        threat                  = "Mal:EicarTestFile"
        author                  = "Austin Byers | Airbnb CSIRT"
        reference               = "http://www.eicar.org/86-0-Intended-use.html"
        Threat_level            = "5"
        md5_1                   = "44d88612fea8a8f36de82e1278abb02f"
        md5_2                   = "d069649f87bcb2945498c35ae973bf70"
        namespace               = "eicar_av_test"

    strings:
        $eicar_regex = /^X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*\s*$/

    condition:
        all of them
}

rule eicar_substring {
    /*
       More generic - match just the embedded EICAR string (e.g. in packed executables, PDFs, etc)
    */

    meta:
        description = "Standard AV test, checking for an EICAR substring"
        threat = "Mal:EicarTestFile"
        author = "Austin Byers | Airbnb CSIRT"
        Threat_level = "5"
        namespace = "eicar_substring"

    strings:
        $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

    condition:
        
        all of them
}

rule potential_python__file_encryption {
    /*
        A python ransomware teste signature
    */
    meta:
        description = "Python file encryption substring detection"
        threat = "Potential:PythonRansomware [Generic]"
        author = "Movalabs"
        Threat_level = "5"
        namespace = "potential_python__file_encryption"

    strings:

        $import_string = "from cryptography.fernet import Fernet" fullword ascii

    condition:
        all of them

}

rule is__Mirai_gen7 {
        meta:
                description = "Generic detection for MiraiX version 7"
                reference = "http://blog.malwaremustdie.org/2016/08/mmd-0056-2016-linuxmirai-just.html"
                author = "unixfreaxjp"
                org = "MalwareMustDie"
                date = "2018-01-05"
                threat = "MiraiX:Generic"
                namespace = "is__Mirai_gen7"

        strings:
                $st01 = "/bin/busybox rm" fullword nocase wide ascii
                $st02 = "/bin/busybox echo" fullword nocase wide ascii
                $st03 = "/bin/busybox wget" fullword nocase wide ascii
                $st04 = "/bin/busybox tftp" fullword nocase wide ascii
                $st05 = "/bin/busybox cp" fullword nocase wide ascii
                $st06 = "/bin/busybox chmod" fullword nocase wide ascii
                $st07 = "/bin/busybox cat" fullword nocase wide ascii

        condition:
                5 of them
}

rule PE_File_pyinstaller
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect PE file produced by pyinstaller"
        reference = "https://isc.sans.edu/diary/21057"
        namespace = "PE_File_pyinstaller"
        threat = "not-a-virus:PYInstaller:Generic"

    strings:

        $a = "pyi-windows-manifest-filename"

    condition:
        pe.number_of_resources > 0 and $a
}

rule MALW_FakePyPI
{
    meta:
        description = "Identifies fake PyPI Packages."
        author = "@bartblaze"
        reference = "http://www.nbu.gov.sk/skcsirt-sa-20170909-pypi/"
        date = "2017-09"
        tlp = "white"
        namespace = "MALW_FakePyPI"
        threat = "Mal:FakePyPI.Package"

    strings:	
        $ = "# Welcome Here! :)"
        $ = "# just toy, no harm :)"
        $ = "[0x76,0x21,0xfe,0xcc,0xee]"

    condition:
        all of them
}

rule MachO_File_pyinstaller
{
    meta:
        author = "KatsuragiCSL (https://katsuragicsl.github.io)"
        description = "Detect Mach-O file produced by pyinstaller"
        namespace = "MachO_File_pyinstaller"
        threat = "Mal:PYInstaller.Mach-O"

    strings:
        $a = "pyi-runtime-tmpdir"
        $b = "pyi-bootloader-ignore-signals"

    condition:
        any of them
}


rule Petya_Ransomware {

	meta:

		description = "Detects Petya Ransomware"
		author = "Florian Roth"
		reference = "http://www.heise.de/newsticker/meldung/Erpressungs-Trojaner-Petya-riegelt-den-gesamten-Rechner-ab-3150917.html"
		date = "2016-03-24"
		hash = "26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739"
        namespace = "Petya_Ransomware"
        threat = "Ransom:Petya.Ransomware [Trj]"


	strings:

		$a1 = "<description>WinRAR SFX module</description>" fullword ascii

		$s1 = "BX-Proxy-Manual-Auth" fullword wide
		$s2 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
		$s3 = "X-HTTP-Attempts" fullword wide
		$s4 = "@CommandLineMode" fullword wide
		$s5 = "X-Retry-After" fullword wide

	condition:

		uint16(0) == 0x5a4d and filesize < 500KB and $a1 and 3 of ($s*)
}

rule Ransom_Petya {

    meta:
        description = "Regla para detectar Ransom.Petya con md5 AF2379CC4D607A45AC44D62135FB7015"
        author = "CCN-CERT"
        version = "1.0"
        namespace = "Petya_Ransomware"
        threat = "Win32:Ransom.Petya [Trj]"

    strings:

        $a1 = { C1 C8 14 2B F0 03 F0 2B F0 03 F0 C1 C0 14 03 C2 }
        $a2 = { 46 F7 D8 81 EA 5A 93 F0 12 F7 DF C1 CB 10 81 F6 }
        $a3 = { 0C 88 B9 07 87 C6 C1 C3 01 03 C5 48 81 C3 A3 01 00 00 }

    condition:
        all of them
}

rule Win32_Ransomware_Petya : tc_detection malicious
{
    
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "PETYA"
        description         = "Yara rule that detects Petya ransomware."
        namespace = "Win32_Ransomware_Petya"
        threat = "Ransom:Win32.Petya [Trj]"

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Petya"
        tc_detection_factor = 5

    strings:
        $entry_point = {
            55 8B EC 56 8B 75 ?? 57 83 FE ?? 75 ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? 56 FF 75 ?? E8 ?? ?? ?? ?? 8B F8 85 F6 75 ?? E8 ?? 
            ?? ?? ?? 8B C7 5F 5E 5D C2 
        }

        $shutdown_pattern = {
            55 8B EC 83 EC ?? 8D 45 ?? 56 50 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 
            75 ?? 33 C0 EB ?? 8D 45 ?? 33 F6 50 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 56 56 56 8D 
            45 ?? C7 45 ?? ?? ?? ?? ?? 50 56 FF 75 ?? C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 
            15 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 50 FF 15 
            ?? ?? ?? ?? 8D 4D ?? 51 6A ?? 56 56 56 68 ?? ?? ?? ?? FF D0 33 C0 83 C4 ?? 40 5E 8B 
            E5 5D C3 
        }

        $sectionxxxx_pattern = {
            83 EC ?? 53 55 8B C2 89 4C 24 ?? 56 57 8B C8 89 44 24 ?? 33 D2 E8 ?? ?? ?? ?? 85 C0 
            74 ?? 0F B7 48 ?? 8B FA 83 C1 ?? 03 C8 0F B7 40 ?? 89 44 24 ?? 85 C0 74 ?? BE ?? ?? 
            ?? ?? 2B F1 80 39 ?? 8D 59 ?? 6A ?? 5D 75 ?? 85 ED 74 ?? 0F BE 2C 1E 0F BE 03 43 3B 
            E8 74 ?? 83 C1 ?? 83 EE ?? 47 3B 7C 24 ?? 72 ?? 8B CA 85 C9 74 ?? 8B 51 ?? 8B 5C 24 
            ?? 8B FB 03 54 24 ?? 8B F2 8B 4A ?? A5 83 C1 ?? 03 CA 89 4B ?? A5 A5 8B 43 ?? 8D 72 
            ?? 89 43 ?? 8B 43 ?? 89 43 ?? B8 ?? ?? ?? ?? 89 73 ?? 66 39 01 74 ?? 8B 7A ?? 8B 2A 
            03 7A ?? 74 ?? 33 DB 43 2B DE 33 D2 8D 0C 33 8B C5 F7 F1 30 16 46 4F 75 ?? B2 ?? 5F 
            5E 5D 0F B6 C2 5B 83 C4 ?? C3 
        }

        $crypt_gen_pattern = {
            55 8B EC 53 57 8B 7D ?? 8D 45 ?? 68 ?? ?? ?? ?? 6A ?? 33 DB 53 53 50 89 1F FF 15 ?? 
            ?? ?? ?? 85 C0 75 ?? 6A ?? 58 EB ?? 56 FF 75 ?? 8B 75 ?? 56 FF 75 ?? FF 15 ?? ?? ?? 
            ?? 85 C0 75 ?? 6A ?? 58 EB ?? 53 FF 75 ?? FF 15 ?? ?? ?? ?? 89 37 33 C0 5E 5F 5B 5D 
            C3 
        }

    condition:
        uint16(0) == 0x5A4D and ($entry_point at pe.entry_point) and $shutdown_pattern and $sectionxxxx_pattern and $crypt_gen_pattern
            
}


rule Win32_Ransomware_WannaCry : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "WANNACRY"
        description         = "Yara rule that detects WannaCry ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "WannaCry"
        tc_detection_factor = 5
        namespace = "Win32_Ransomware_WannaCry"
        threat = "Ransom.WannaCrypt"

    strings:
        $main_1 = {
            A0 ?? ?? ?? ?? 56 57 6A ?? 88 85 ?? ?? ?? ?? 59 33 C0 8D BD ?? ?? ?? ?? F3 AB 66 AB 
            AA 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 6A ?? 50 FF D6 59 85 C0 59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 
            18 59 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 53 53 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 85 
            C0 74 ?? 8D 45 ?? 8D 8D ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 89 5D
        }
        
        $main_2 = {
            68 ?? ?? ?? ?? 33 DB 50 53 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 FF 15 
            ?? ?? ?? ?? 83 38 ?? 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 00 FF 70 ?? E8 ?? ?? 
            ?? ?? 59 85 C0 59 75 ?? 53 E8 ?? ?? ?? ?? 85 C0 59 74 ?? BE ?? ?? ?? ?? 53 8D 85 ?? 
            ?? ?? ?? 56 50 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 83 F8 ?? 74 ?? E8 ?? ?? ?? ?? 
            85 C0 0F 85 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 85 C0 
            59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 18 59 8D 85 ?? ?? ?? ?? 50 FF 15 ?? 
            ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            53 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 53 68 ?? ?? ?? ?? E8
        }
        
        $main_3 = {
            83 EC ?? 56 57 B9 ?? ?? ?? ?? BE ?? ?? ?? ?? 8D 7C 24 ?? 33 C0 F3 A5 A4 89 44 24 ?? 
            89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 66 89 44 24 ?? 50 50 50 6A ?? 50 88 
            44 24 ?? FF 15 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 8D 4C 24 ?? 8B F0 6A ?? 51 56 
            FF 15 ?? ?? ?? ?? 8B F8 56 8B 35 ?? ?? ?? ?? 85 FF 75 ?? FF D6 6A ?? FF D6 E8
        }
        
        $start_service_3 = {
            83 EC ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 
            38 ?? 7D ?? E8 ?? ?? ?? ?? 83 C4 ?? C3 57 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? 
            ?? 8B F8 85 FF 74 ?? 53 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 8B 1D 
            ?? ?? ?? ?? 8B F0 85 F6 74 ?? 6A ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 56 FF D3 57 FF D3 5E 
            5B 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? 
            ?? ?? C7 44 24 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 5F 83 C4 ?? C3 
        }
        
        $main_4 = {
            83 EC ?? 57 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F8 85 FF 74 ?? 53 56 68 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 85 F6 74 ?? 
            6A ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 56 FF D3 57 FF D3 5E 5B 8D 44 24 ?? C7 44 24 ?? ?? 
            ?? ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 
            FF 15 ?? ?? ?? ?? 33 C0 5F 83 C4 ?? C2 
        }
        
        $main_5 = {
            68 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 
            FF D6 59 85 C0 59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 18 59 8D 85 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 53 53 53 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 85 C0 74 ?? 8D 45 ?? 8D 
            8D ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 89 5D ?? E8 ?? ?? ?? ?? 3B C3 74 ?? FF 75 ?? 50 E8 
            ?? ?? ?? ?? 59 3B C3 59 74 ?? 68 ?? ?? ?? ?? 50 E8
        }
        
        $main_6 = {
            FF 74 24 ?? FF 74 24 ?? FF 74 24 ?? FF 74 24 ?? E8 ?? ?? ?? ?? C2
        }
        
        $set_reg_key_6 = {
            68 ?? ?? ?? ?? F3 AB 66 AB AA 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 
            ?? 8B 2D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 ?? 33 FF 89 7C 24 ?? 85 FF 75 ?? 8D 4C 
            24 ?? 8D 54 24 ?? 51 52 68 ?? ?? ?? ?? EB ?? 8D 44 24 ?? 8D 4C 24 ?? 50 51 68 ?? ?? 
            ?? ?? FF 15 ?? ?? ?? ?? 8B 44 24 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 85 
            C9 74 ?? 8D 94 24 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? FF D5 8D BC 24 ?? ?? ?? ?? 83 C9 ?? 
            33 C0 F2 AE F7 D1 8D 84 24 ?? ?? ?? ?? 51 8B 4C 24 ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? 
            51 FF D3 8B 7C 24 ?? 8B F0 F7 DE 1B F6 46 EB ?? 8D 54 24 ?? 8D 8C 24 ?? ?? ?? ?? 52 
            51 6A ?? 6A ?? 68 ?? ?? ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? FF 15 
        }
        
        $download_tor_6 = {
            81 EC ?? ?? ?? ?? 53 55 56 57 E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? A0 ?? ?? ?? ?? 
            B9 ?? ?? ?? ?? 88 44 24 ?? 33 C0 8D 7C 24 ?? 8B 35 ?? ?? ?? ?? F3 AB 68 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 66 AB 68 ?? ?? ?? ?? 8D 4C 24 ?? 33 ED 68 ?? ?? ?? ?? 51 89 2D ?? ?? 
            ?? ?? 89 2D ?? ?? ?? ?? AA FF D6 8B 1D ?? ?? ?? ?? 83 C4 ?? 8D 54 24 ?? 52 FF D3 83 
            F8 ?? 0F 85 ?? ?? ?? ?? 55 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 84 
            C0 75 ?? 5F 5E 5D 5B 81 C4 ?? ?? ?? ?? C3 A0 ?? ?? ?? ?? B9 ?? ?? ?? ?? 88 84 24 ?? 
            ?? ?? ?? 33 C0 8D BC 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? F3 AB 66 AB 68 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 AA FF D6 83 C4 ?? 8D 94 24 ?? ?? ?? 
            ?? 52 FF D3 83 F8 ?? 75 ?? 5F 5E 5D 32 C0 5B 81 C4 ?? ?? ?? ?? C3 
        }
        
        $main_7 = {
            68 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 
            FF D6 59 85 C0 59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 18 59 8D 85 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 53 53 53 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 85 C0 74 ?? 8D 45 ?? 8D 
            8D ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 53 8F 45 ?? E8 ?? ?? ?? ?? 39 44 24 ?? 74 ?? 89 44 
            24 ?? 83 EC ?? 2B C3 58 74 ?? FF 75 ?? 50 E8 ?? ?? ?? ?? 59 89 44 24 ?? 83 EC ?? 2B 
            C3 58 59 74 ?? 68 ?? ?? ?? ?? 50 E8 
        }
        
        $main_8 = {
            68 ?? ?? ?? ?? F3 AB 66 AB AA 8D 44 24 ?? 50 6A ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? 
            ?? 8D 4C 24 ?? 6A ?? 51 FF D6 83 C4 ?? 85 C0 74 ?? 8D 54 24 ?? 6A ?? 52 FF D6 83 C4 
            ?? C6 00 ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 8C 24 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 
            5E 85 C0 74 ?? 8D 4C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 51 68 ?? ?? ?? ?? 8D 8C 24 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 54 24 ?? 52 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 
            ?? 68 ?? ?? ?? ?? 50 E8 
        }

        $entrypoint_all = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? 
            ?? 83 EC ?? 53 56 57 89 65 ?? 33 DB 89 5D ?? 6A ?? FF 15 ?? ?? ?? ?? 59 83 0D ?? ?? 
            ?? ?? ?? 83 0D ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 08 FF 15 ?? ?? 
            ?? ?? 8B 0D ?? ?? ?? ?? 89 08 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 39 
            1D ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 59 E8 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 45 ?? 8D 45 ?? 50 FF 35 ?? ?? ?? 
            ?? 8D 45 ?? 50 8D 45 ?? 50 8D 45 ?? 50 FF 15 
        }

    condition:
        uint16(0) == 0x5A4D and 
        ($entrypoint_all at pe.entry_point) and 
        ($main_1 or $main_2 or ($main_3 and $start_service_3) or $main_4 or $main_5 or ($main_6 and ($set_reg_key_6 or $download_tor_6)) or $main_7 or $main_8)
}


rule INDICATOR_SUSPICIOUS_GENRansomware {

    meta:

        description = "detects command variations typically used by ransomware"
        author = "ditekSHen"
        namespace = "INDICATOR_SUSPICIOUS_GENRansomware"
        threat = "BehavesLike.GenRansomware"


    strings:

        $cmd1 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii wide nocase
        $cmd2 = "vssadmin.exe Delete Shadows /all" ascii wide nocase
        $cmd3 = "Delete Shadows /all" ascii wide nocase
        $cmd4 = "} recoveryenabled no" ascii wide nocase
        $cmd5 = "} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd6 = "wmic SHADOWCOPY DELETE" ascii wide nocase
        $cmd7 = "\\Microsoft\\Windows\\SystemRestore\\SR\" /disable" ascii wide nocase
        $cmd8 = "resize shadowstorage /for=c: /on=c: /maxsize=" ascii wide nocase
        $cmd9 = "shadowcopy where \"ID='%s'\" delete" ascii wide nocase
        $cmd10 = "wmic.exe SHADOWCOPY /nointeractive" ascii wide nocase
        $cmd11 = "WMIC.exe shadowcopy delete" ascii wide nocase
        $cmd12 = "Win32_Shadowcopy | ForEach-Object {$_.Delete();}" ascii wide nocase
        $delr = /del \/s \/f \/q(( [A-Za-z]:\\(\*\.|[Bb]ackup))(VHD|bac|bak|wbcat|bkf)?)+/ ascii wide
        $wp1 = "delete catalog -quiet" ascii wide nocase
        $wp2 = "wbadmin delete backup" ascii wide nocase
        $wp3 = "delete systemstatebackup" ascii wide nocase

    condition:

        (uint16(0) == 0x5a4d and 2 of ($cmd*) or (1 of ($cmd*) and 1 of ($wp*)) or #delr > 4) or (4 of them)
}



rule WannaCry_Ransomware {

   meta:

      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (Nextron Systems) (with the help of binar.ly)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
      namespace = "WannaCry_Ransomware"
      threat = "Trojan.Ransom.WannaCryptor.A"

   strings:

      $x1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $x2 = "taskdl.exe" fullword ascii
      $x3 = "tasksche.exe" fullword ascii
      $x4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
      $x5 = "WNcry@2ol7" fullword ascii
      $x6 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
      $x7 = "mssecsvc.exe" fullword ascii
      $x8 = "C:\\%s\\qeriuwjhrf" fullword ascii
      $x9 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii

      $s1 = "C:\\%s\\%s" fullword ascii
      $s2 = "<!-- Windows 10 --> " fullword ascii
      $s3 = "cmd.exe /c \"%s\"" fullword ascii
      $s4 = "msg/m_portuguese.wnry" fullword ascii
      $s5 = "\\\\192.168.56.20\\IPC$" fullword wide
      $s6 = "\\\\172.16.99.5\\IPC$" fullword wide

      $op1 = { 10 ac 72 0d 3d ff ff 1f ac 77 06 b8 01 00 00 00 }
      $op2 = { 44 24 64 8a c6 44 24 65 0e c6 44 24 66 80 c6 44 }
      $op3 = { 18 df 6c 24 14 dc 64 24 2c dc 6c 24 5c dc 15 88 }
      $op4 = { 09 ff 76 30 50 ff 56 2c 59 59 47 3b 7e 0c 7c }
      $op5 = { c1 ea 1d c1 ee 1e 83 e2 01 83 e6 01 8d 14 56 }
      $op6 = { 8d 48 ff f7 d1 8d 44 10 ff 23 f1 23 c1 }

   condition:

      uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) and 1 of ($s*) or 3 of ($op*) )
}

rule WannaCry_Ransomware_Gen {

   meta:

      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (Nextron Systems) (based on rule by US CERT)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-132A"
      date = "2017-05-12"
      hash1 = "9fe91d542952e145f2244572f314632d93eb1e8657621087b2ca7f7df2b0cb05"
      hash2 = "8e5b5841a3fe81cade259ce2a678ccb4451725bba71f6662d0cc1f08148da8df"
      hash3 = "4384bf4530fb2e35449a8e01c7e0ad94e3a25811ba94f7847c1e6612bbb45359"
      namespace = "WannaCry_Ransomware_Gen"
      threat = "Trojan.Ransom.WannaCryptor"


   strings:

      $s1 = "__TREEID__PLACEHOLDER__" ascii
      $s2 = "__USERID__PLACEHOLDER__" ascii
      $s3 = "Windows for Workgroups 3.1a" fullword ascii
      $s4 = "PC NETWORK PROGRAM 1.0" fullword ascii
      $s5 = "LANMAN1.0" fullword ascii

   condition:

      uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule WannCry_m_vbs {

   meta:

      description = "Detects WannaCry Ransomware VBS"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"
      namespace = "WannCry_m_vbs"
      threat = "Trojan-Ransom.BAT"

   strings:

      $x1 = ".TargetPath = \"C:\\@" ascii
      $x2 = ".CreateShortcut(\"C:\\@" ascii
      $s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii

   condition:

      ( uint16(0) == 0x4553 and filesize < 1KB and all of them )
}

rule WannCry_BAT {

   meta:

      description = "Detects WannaCry Ransomware BATCH File"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "f01b7f52e3cb64f01ddc248eb6ae871775ef7cb4297eba5d230d0345af9a5077"
      namespace = "WannCry_BAT"
      threat = "BAT/Trojan-Ransom:Wannacry"
      

   strings:

      $s1 = "@.exe\">> m.vbs" ascii
      $s2 = "cscript.exe //nologo m.vbs" fullword ascii
      $s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
      $s4 = "echo om.Save>> m.vbs" fullword ascii

   condition:

      ( uint16(0) == 0x6540 and filesize < 1KB and 1 of them )
}

rule WannaCry_RansomNote {

   meta:

      description = "Detects WannaCry Ransomware Note"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"
      namespace = "WannaCry_RansomNote"
      threat = "Trojan.RansomNote"


   strings:

      $s1 = "A:  Don't worry about decryption." fullword ascii
      $s2 = "Q:  What's wrong with my files?" fullword ascii

   condition:

      ( uint16(0) == 0x3a51 and filesize < 2KB and all of them )
}

/* Kaspersky Rule */

rule APT_lazaruswannacry {

   meta:

      description = "Rule based on shared code between Feb 2017 Wannacry sample and Lazarus backdoor from Feb 2015 discovered by Neel Mehta"
      date = "2017-05-15"
      reference = "https://twitter.com/neelmehta/status/864164081116225536"
      author = "Costin G. Raiu, Kaspersky Lab"
      version = "1.0"
      hash = "9c7c7149387a1c79679a87dd1ba755bc"
      hash = "ac21c8ad899727137c4b94458d7aa8d8"
      namespace = "APT_lazaruswannacry"
      threat = "Trojan.Win32.WannaCryptor"


   strings:

      $a1 = { 51 53 55 8B 6C 24 10 56 57 6A 20 8B 45 00 8D 75
         04 24 01 0C 01 46 89 45 00 C6 46 FF 03 C6 06 01 46
         56 E8 }
      $a2 = { 03 00 04 00 05 00 06 00 08 00 09 00 0A 00 0D 00
         10 00 11 00 12 00 13 00 14 00 15 00 16 00 2F 00
         30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00
         38 00 39 00 3C 00 3D 00 3E 00 3F 00 40 00 41 00
         44 00 45 00 46 00 62 00 63 00 64 00 66 00 67 00
         68 00 69 00 6A 00 6B 00 84 00 87 00 88 00 96 00
         FF 00 01 C0 02 C0 03 C0 04 C0 05 C0 06 C0 07 C0
         08 C0 09 C0 0A C0 0B C0 0C C0 0D C0 0E C0 0F C0
         10 C0 11 C0 12 C0 13 C0 14 C0 23 C0 24 C0 27 C0
         2B C0 2C C0 FF FE }

   condition:

      uint16(0) == 0x5A4D and filesize < 15000000 and all of them
}

rule MALW_cobaltrike
{
    meta:
    
        description = "Rule to detect CobaltStrike beacon"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-07-19"
        rule_version = "v1"
        malware_type = "backdoor"
        malware_family = "Backdoor:W32/CobaltStrike"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash1 = "f47a627880bfa4a117fec8be74ab206690e5eb0e9050331292e032cd22883f5b"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
        threat = "Backdoor:W32/CobaltStrike"
        namespace = "MALW_cobaltrike"

    strings:

        $pattern_0 = { e9???????? eb0a b801000000 e9???????? }
        $pattern_1 = { 3bc7 750d ff15???????? 3d33270000 }
        $pattern_2 = { 8bd0 e8???????? 85c0 7e0e }
        $pattern_3 = { 50 8d8d24efffff 51 e8???????? }
        $pattern_4 = { 03b5d4eeffff 89b5c8eeffff 3bf7 72bd 3bf7 }
        $pattern_5 = { 8b450c 8945f4 8d45f4 50 }
        $pattern_6 = { 33c5 8945fc 8b4508 53 56 ff750c 33db }
        $pattern_7 = { e8???????? e9???????? 833d????????01 7505 e8???????? }
        $pattern_8 = { 53 53 8d85f4faffff 50 }
        $pattern_9 = { 68???????? 53 50 e8???????? 83c424 }
        $pattern_10 = { 488b4c2420 8b0401 8b4c2408 33c8 8bc1 89442408 }
        $pattern_11 = { 488d4d97 e8???????? 4c8d9c24d0000000 418bc7 498b5b20 498b7328 498b7b30 }
        $pattern_12 = { bd08000000 85d2 7459 ffcf 4d85ed }
        $pattern_13 = { 4183c9ff 33d2 ff15???????? 4c63c0 4983f8ff }
        $pattern_14 = { 49c1e002 e8???????? 03f3 4d8d349e 3bf5 7d13 }
        $pattern_15 = { 752c 4c8d45af 488d55af 488d4d27 }
   
    condition:

        7 of them and filesize < 696320
}

rule downloader_darkmegi_pdb {

	 meta:

		 description = "Rule to detect DarkMegi downloader based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-03-06"
		 rule_version = "v1"
         malware_type = "downloader"
         malware_family = "Downloader:W32/DarkMegi"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkmegi" 
		 hash = "bf849b1e8f170142176d2a3b4f0f34b40c16d0870833569824809b5c65b99fc1"
		 threat = "Downloader:W32/DarkMegi"
		 namespace = "downloader_darkmegi_pdb"
		 


 	strings:

 		$pdb = "\\RKTDOW~1\\RKTDRI~1\\RKTDRI~1\\objchk\\i386\\RktDriver.pdb"

 	condition:

 		uint16(0) == 0x5a4d and
	 	filesize > 20000KB and
	 	any of them
}

rule screenlocker_5h311_1nj3c706 {

   meta:

      description = "Rule to detect the screenlocker 5h311_1nj3c706"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-08-07"
      rule_version = "v1"
      malware_type = "screenlocker"
      malware_family = "ScreenLocker:W32/5h311_1nj3c706"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://twitter.com/demonslay335/status/1038060120461266944"
      hash = "016ee638bd4fccd5ca438c2e0abddc4b070f59269c08f11c5313ba9c37190718"
      threat = "ScreenLocker:W32/5h311_1nj3c706"
      namespace = "screenlocker_5h311_1nj3c706"


   strings:

      $s1 = "C:\\Users\\Hoang Nam\\source\\repos\\WindowsApp22\\WindowsApp22\\obj\\Debug\\WindowsApp22.pdb" fullword ascii
      $s2 = "cmd.exe /cREG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop /v NoChangingWallPaper /t REG_DWOR" wide
      $s3 = "C:\\Users\\file1.txt" fullword wide
      $s4 = "C:\\Users\\file2.txt" fullword wide
      $s5 = "C:\\Users\\file.txt" fullword wide
      $s6 = " /v Wallpaper /t REG_SZ /d %temp%\\IMG.jpg /f" fullword wide
      $s7 = " /v DisableAntiSpyware /t REG_DWORD /d 1 /f" fullword wide
      $s8 = "All your file has been locked. You must pay money to have a key." fullword wide
      $s9 = "After we receive Bitcoin from you. We will send key to your email." fullword wide
   
   condition:

      uint16(0) == 0x5a4d and
      filesize < 200KB and
      all of them 
}

rule NionSpy
{

	meta:

		description = "Triggers on old and new variants of W32/NionSpy file infector"
		rule_version = "v1"
	    malware_type = "fileinfector"
	    malware_family = "FileInfector:W32/NionSpy"
	    actor_type = "Cybercrime"
	    actor_group = "Unknown"
		reference = "https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector"
		threat = "FileInfector:W32/NionSpy"
		namespace = "NionSpy"


	strings:

		$variant2015_infmarker = "aCfG92KXpcSo4Y94BnUrFmnNk27EhW6CqP5EnT"
		$variant2013_infmarker = "ad6af8bd5835d19cc7fdc4c62fdf02a1"
		$variant2013_string = "%s?cstorage=shell&comp=%s"

	condition:

		uint16(0) == 0x5A4D and 
		uint32(uint32(0x3C)) == 0x00004550 and
		1 of ($variant*)
}

rule MINER_monero_mining_detection {

   meta:

      description = "Monero mining software"
      author = "Trellix ATR team"
      date = "2018-04-05"
      rule_version = "v1"
      malware_type = "miner"
      malware_family = "Ransom:W32/MoneroMiner"
      actor_type = "Cybercrime"
      actor_group = "Unknown"   
      
      namespace = "MINER_monero_mining_detection"


   strings:

      $1 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
      $2 = "--cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
      $3 = "* THREADS:      %d, %s, av=%d, %sdonate=%d%%%s" fullword ascii
      $4 = "--user-agent         set custom user-agent string for pool" fullword ascii
      $5 = "-O, --userpass=U:P       username:password pair for mining server" fullword ascii
      $6 = "--cpu-priority       set process priority (0 idle, 2 normal to 5 highest)" fullword ascii
      $7 = "-p, --pass=PASSWORD      password for mining server" fullword ascii
      $8 = "* VERSIONS:     XMRig/%s libuv/%s%s" fullword ascii
      $9 = "-k, --keepalive          send keepalived for prevent timeout (need pool support)" fullword ascii
      $10 = "--max-cpu-usage=N    maximum CPU usage for automatic threads mode (default 75)" fullword ascii
      $11 = "--nicehash           enable nicehash/xmrig-proxy support" fullword ascii
      $12 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
      $13 = "* CPU:          %s (%d) %sx64 %sAES-NI" fullword ascii
      $14 = "-r, --retries=N          number of times to retry before switch to backup server (default: 5)" fullword ascii
      $15 = "-B, --background         run the miner in the background" fullword ascii
      $16 = "* API PORT:     %d" fullword ascii
      $17 = "--api-access-token=T access token for API" fullword ascii
      $18 = "-t, --threads=N          number of miner threads" fullword ascii
      $19 = "--print-time=N       print hashrate report every N seconds" fullword ascii
      $20 = "-u, --user=USERNAME      username for mining server" fullword ascii
   
   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 4000KB and
      ( 8 of them )) or
      ( all of them )
}

rule Trojan_CoinMiner {
   meta:
      description = "Rule to detect Coinminer malware"
      author = "Trellix ATR"
      date = "2021-07-22"
      version = "v1"
      hash1 = "3bdac08131ba5138bcb5abaf781d6dc7421272ce926bc37fa27ca3eeddcec3c2"
      hash2 = "d60766c4e6e77de0818e59f687810f54a4e08505561a6bcc93c4180adb0f67e7"
      threat = "Win.Trojan.Coinminer"

   strings:
  
      $seq0 = { df 75 ab 7b 80 bf 83 c1 48 b3 18 74 70 01 24 5c }
      $seq1 = { 08 37 4e 6e 0f 50 0b 11 d0 98 0f a8 b8 27 47 4e }
      $seq2 = { bf 17 5a 08 09 ab 80 2f a1 b0 b1 da 47 9f e1 61 }
      $seq3 = { 53 36 34 b2 94 01 cc 05 8c 36 aa 8a 07 ff 06 1f }
      $seq4 = { 25 30 ae c4 44 d1 97 82 a5 06 05 63 07 02 28 3a }
      $seq5 = { 01 69 8e 1c 39 7b 11 56 38 0f 43 c8 5f a8 62 d0 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "e4290fa6afc89d56616f34ebbd0b1f2c" and 3 of ($seq*)
      ) 
}

rule STEALER_credstealesy
{
	
	 meta:

		description = "Generic Rule to detect the CredStealer Malware"
		author = "IsecG – McAfee Labs"
		date = "2015-05-08"
		rule_version = "v1"
        malware_type = "stealer"
        malware_family = "Stealer:W32/CredStealer"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/when-hackers-get-hacked-the-malware-servers-of-a-data-stealing-campaign/"

	strings:

		$my_hex_string = "CurrentControlSet\\Control\\Keyboard Layouts\\" wide //malware trying to get keyboard layout
		$my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8} //specific decryption module

	condition:

		$my_hex_string and $my_hex_string2
}

rule STEALER_emirates_statement 
{
	meta:

		description = "Credentials Stealing Attack"
		author = "Christiaan Beek | McAfee ATR Team"
		date = "2013-06-30"
		rule_version = "v1"
        malware_type = "stealer"
        malware_family = "Stealer:W32/DarkSide"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash = "7cf757e0943b0a6598795156c156cb90feb7d87d4a22c01044499c4e1619ac57"
	
	strings:

		$string0 = "msn.klm"
		$string1 = "wmsn.klm"
		$string2 = "bms.klm"
	
	condition:
	
		all of them
}

rule STEALER_Lokibot
 {
   meta:

      description = "Rule to detect Lokibot stealer"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-09-23"
      rule_version = "v1"
      malware_type = "stealer"
      malware_family = "Ransomware:W32/Lokibot"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash1 = "0e40f4fdd77e1f90279c585cfc787942b8474e5216ff4d324d952ef6b74f25d2"
      hash2 = "3ad36afad12d8cf245904285c21a8db43f9ed9c82304fdc2f27c4dd1438e4a1d"
      hash3 = "26fbdd516b3c1bfa36784ef35d6bc216baeb0ef2d0c0ba036ff9296da2ce2c84"

    strings:

        $sq1 = { 55 8B EC 56 8B 75 08 57 56 E8 ?? ?? ?? ?? 8B F8 59 85 FF 75 04 33 C0 EB 20 56 6A 00 57 E8 ?? ?? ?? ?? 6A 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 E5 83 60 08 00 89 38 89 70 04 5F 5E 5D C3 }
        $sq2 = { 55 8B EC 83 EC 0C 53 56 57 33 DB BE ?? ?? ?? ?? 53 53 56 6A 09 E8 ?? ?? ?? ?? 6A 10 6A 01 53 53 8D 4D F8 51 FF D0 53 53 56 6A 09 E8 ?? ?? ?? ?? 6A 08 6A 01 53 53 8D 4D F8 51 FF D0 85 C0 0F 84 2B 01 00 00 6A 24 E8 ?? ?? ?? ?? 59 8B D8 33 C0 6A 09 59 8B FB F3 AB 66 8B 4D 24 B8 03 66 00 00 C7 03 08 02 00 00 66 85 C9 74 03 0F B7 C1 8B 4D 08 33 D2 0F B7 C0 89 43 04 89 53 08 85 C9 74 12 C7 43 08 08 00 00 00 8B 01 89 43 0C 8B 41 04 89 43 10 8B 4D 0C 85 C9 74 0F 83 43 08 08 8B 01 89 43 14 8B 41 04 89 43 18 8B 4D 10 85 C9 74 0F 83 43 08 08 8B 01 89 43 1C 8B 41 04 89 43 20 8B 7B 08 8B 75 F8 83 C7 0C 52 52 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 8D 4D FC 51 6A 00 6A 00 57 53 56 FF D0 85 C0 74 75 8B 75 FC 33 C0 40 83 7D 20 00 0F 45 45 20 33 FF 57 57 68 ?? ?? ?? ?? 6A 09 89 45 F4 E8 ?? ?? ?? ?? 57 8D 4D F4 51 6A 04 56 FF D0 85 C0 74 3B 39 7D 14 74 1A 8B 75 FC 57 57 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 57 FF 75 14 6A 01 56 FF D0 8B 55 18 8B 4D FC 53 89 0A 8B 55 1C 8B 4D F8 89 0A E8 ?? ?? ?? ?? 33 C0 59 40 EB 21 FF 75 FC E8 BF FB FF FF 59 EB 02 33 FF 53 E8 ?? ?? ?? ?? 57 FF 75 F8 E8 6B FB FF FF 83 C4 0C 33 C0 5F 5E 5B 8B E5 5D C3 }
        $sq3 = { 55 8B EC 83 EC 0C 53 8B 5D 0C 56 57 6A 10 33 F6 89 75 F8 89 75 FC 58 89 45 F4 85 DB 75 0E FF 75 08 E8 ?? ?? ?? ?? 8B D8 8B 45 F4 59 50 E8 ?? ?? ?? ?? 8B F8 59 85 FF 0F 84 B6 00 00 00 FF 75 F4 56 57 E8 C4 ?? ?? ?? 83 C4 0C 56 56 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 68 00 00 00 F0 6A 01 56 56 8D 4D F8 51 FF D0 85 C0 0F 84 84 00 00 00 8B 75 F8 6A 00 6A 00 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 8D 4D FC 51 6A 00 6A 00 68 03 80 00 00 56 FF D0 85 C0 74 51 6A 00 53 FF 75 08 FF 75 FC E8 7F FD FF FF 83 C4 10 85 C0 74 3C 8B 75 FC 6A 00 6A 00 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 6A 00 8D 4D F4 51 57 6A 02 56 FF D0 85 C0 74 19 FF 75 FC E8 16 FD FF FF 6A 00 FF 75 F8 E8 26 FD FF FF 83 C4 0C 8B C7 EB 0E 6A 00 FF 75 F8 E8 15 FD FF FF 59 59 33 C0 5F 5E 5B 8B E5 5D C3 }
        $sq4 = { 55 8B EC 83 7D 10 00 56 57 8B 7D 0C 57 74 0E E8 ?? ?? ?? ?? 8B F0 33 C0 03 F6 40 EB 09 E8 ?? ?? ?? ?? 8B F0 33 C0 83 7D 14 00 59 75 24 50 FF 75 08 E8 2C 00 00 00 59 59 83 F8 01 74 04 33 C0 EB 1D 56 FF 75 08 E8 C5 FE FF FF 59 59 83 F8 01 75 EC 56 57 FF 75 08 E8 CA FE FF FF 83 C4 0C 5F 5E 5D C3 }
        $sq5 = { 55 8B EC 53 56 8B 75 0C 57 85 F6 75 0B FF 75 08 E8 ?? ?? ?? ?? 59 8B F0 6B C6 03 89 45 0C 8D 58 01 53 E8 ?? ?? ?? ?? 8B F8 59 85 FF 74 42 53 6A 00 57 E8 ?? ?? ?? ?? 83 C4 0C 33 D2 85 F6 74 27 8B 45 08 0F B6 0C 02 8B C1 83 E1 0F C1 E8 04 8A 80 ?? ?? ?? ?? 88 04 57 8A 81 ?? ?? ?? ?? 88 44 57 01 42 3B D6 72 D9 8B 45 0C C6 04 07 00 8B C7 5F 5E 5B 5D C3 }
        $sq6 = { 55 8B EC 53 56 57 FF 75 08 E8 ?? ?? ?? ?? 33 C9 6A 02 5B 8D B8 A0 1F 00 00 8B C7 F7 E3 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 74 6F 8D 0C 3F 51 6A 00 56 E8 ?? ?? ?? ?? 8D 45 0C 50 FF 75 08 56 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B F8 83 C4 1C 85 FF 74 40 33 C9 8D 47 02 F7 E3 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B D8 59 85 DB 74 25 8D 0C 7D 02 00 00 00 51 6A 00 53 E8 ?? ?? ?? ?? 57 56 53 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 1C 8B C3 EB 09 56 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5B 5D C3 }
        $sq7 = { 55 8B EC 81 EC 80 00 00 00 56 57 E8 ?? ?? ?? ?? 6A 1F 59 BE ?? ?? ?? ?? 8D 7D 80 F3 A5 33 C9 6A 02 5A 66 A5 8B 7D 08 8D 47 01 F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B F0 59 85 F6 74 4D 8D 04 7D 02 00 00 00 4F 89 45 08 53 50 6A 00 56 E8 ?? ?? ?? ?? 83 C4 0C 33 DB 85 FF 74 1C E8 ?? ?? ?? ?? 33 D2 6A 7E 59 F7 F1 D1 EA 66 8B 44 55 80 66 89 04 5E 43 3B DF 72 E4 56 E8 ?? ?? ?? ?? 3B F8 8B 45 08 59 77 C4 8B C6 5B EB 02 33 C0 5F 5E 8B E5 5D C3 }
        $sq8 = { 55 8B EC 81 EC 50 02 00 00 53 56 57 6A 0A E8 ?? ?? ?? ?? 59 33 DB 6A 2E 5E 39 5D 14 0F 84 13 01 00 00 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 0F 84 F7 00 00 00 53 53 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 56 FF D0 8B D8 83 FB FF 0F 84 CC 00 00 00 F6 85 B0 FD FF FF 10 0F 84 97 00 00 00 83 7D 1C 00 74 2E 8D 85 DC FD FF FF 68 ?? ?? ?? ?? 50 E8 0A ?? ?? ?? 59 59 85 C0 75 7A 8D 85 DC FD FF FF 68 ?? ?? ?? ?? 50 E8 F3 ?? ?? ?? 59 59 85 C0 75 63 8D 85 DC FD FF FF 50 E8 ?? ?? ?? ?? 59 83 F8 03 73 0C 6A 2E 58 66 39 85 DC FD FF FF 74 45 8D 85 DC FD FF FF 50 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 89 45 14 85 C0 74 27 6A 01 6A 00 6A 01 FF 75 10 FF 75 0C 50 E8 14 FF FF FF FF 75 14 8B F8 E8 ?? ?? ?? ?? 83 C4 1C 85 FF 0F 85 EE 00 00 00 33 C0 50 50 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 53 FF D0 85 C0 0F 85 3B FF FF FF 53 E8 ?? ?? ?? ?? 59 56 E8 ?? ?? ?? ?? 59 33 DB 6A 2E 5E FF 75 0C FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 83 C4 0C 85 FF 0F 84 CF 00 00 00 53 53 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 57 FF D0 8B D8 83 FB FF 0F 84 A6 00 00 00 8D 85 DC FD FF FF 50 E8 ?? ?? ?? ?? 59 83 F8 03 73 09 66 39 B5 DC FD FF FF 74 3E 83 BD B0 FD FF FF 10 75 06 83 7D 18 00 74 2F 8D 85 DC FD FF FF 50 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 83 C4 0C 85 F6 74 12 83 7D 10 00 74 40 56 FF 55 10 56 E8 ?? ?? ?? ?? 59 59 33 C0 50 50 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 53 FF D0 85 C0 74 29 6A 2E 5E EB 85 56 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8B C7 EB 22 57 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8B C6 EB 10 53 E8 ?? ?? ?? ?? 59 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5B 8B E5 5D C3 }
        $sq9 = { 83 3D 14 ?? ?? ?? ?? 56 74 0A 8B 35 20 ?? ?? ?? 85 F6 75 66 53 57 BB E0 01 00 00 33 FF 53 89 3D 14 ?? ?? ?? E8 F0 F8 FF FF 33 F6 A3 14 ?? ?? ?? 46 59 85 C0 74 12 6A 78 57 50 89 35 20 ?? ?? ?? E8 A6 F8 FF FF 83 C4 0C 53 89 3D 18 ?? ?? ?? E8 C5 F8 FF FF A3 18 ?? ?? ?? 59 85 C0 74 14 6A 78 57 50 89 35 20 ?? ?? ?? E8 7E F8 FF FF 83 C4 0C EB 06 8B 35 20 ?? ?? ?? 5F 5B 8B C6 5E C3 }
        $sq10 = { 55 8B EC 51 51 83 65 FC 00 53 56 57 64 A1 30 00 00 00 89 45 FC 8B 45 FC 8B 40 0C 8B 58 0C 8B F3 8B 46 18 FF 76 28 89 45 F8 E8 CE FA FF FF 8B F8 59 85 FF 74 1F 6A 00 57 E8 32 01 00 00 57 E8 ?? ?? ?? ?? 03 C0 50 57 E8 71 FA FF FF 83 C4 14 39 45 08 74 11 8B 36 3B DE 75 C6 33 C0 5F 5E 5B 8B E5 5D C2 04 00 8B 45 F8 EB F2 }
        $sq11 = { A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 33 C0 A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? C3 }
        $sq12 = { 55 8B EC 56 8B 75 0C 57 85 F6 74 48 56 E8 ?? ?? ?? ?? 59 85 C0 74 3D 56 E8 ?? ?? ?? ?? 59 85 C0 74 32 83 65 0C 00 8D 45 0C 6A 01 50 56 E8 ?? ?? ?? ?? 8B F8 83 C4 0C 85 FF 74 19 8B 45 0C 85 C0 74 12 83 7D 14 00 74 12 39 45 14 73 0D 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5D C3 83 7D 10 00 74 1A 6A 00 6A 01 56 E8 ?? ?? ?? ?? 59 50 FF 75 08 E8 1F 00 00 00 8B 45 0C 83 C4 10 50 57 FF 75 08 E8 FF FE FF FF 57 8B F0 E8 ?? ?? ?? ?? 83 C4 10 8B C6 EB C3 }
        $sq13 = { 55 8B EC 83 EC 18 56 FF 75 08 E8 ?? ?? ?? ?? 50 89 45 F0 E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 0F 84 C0 00 00 00 53 8B 5D 0C 33 C9 57 6A 04 5A 8B C3 F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 83 65 F4 00 8B F8 83 65 FC 00 59 85 DB 74 6D 8B 45 10 83 C0 FC FF 75 F0 83 C0 04 89 45 E8 6A 00 56 8B 00 89 45 EC E8 ?? ?? ?? ?? FF 75 F0 FF 75 08 56 E8 ?? ?? ?? ?? 83 65 F8 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 20 EB 1F FF 75 EC 50 E8 ?? ?? ?? ?? 59 59 85 C0 75 32 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? FF 45 F8 59 59 85 C0 75 DD 8B 45 FC 40 89 45 FC 3B C3 8B 45 E8 72 99 56 E8 ?? ?? ?? ?? 59 39 5D F4 75 12 8B C7 EB 17 8B 45 FC 8B 4D F8 FF 45 F4 89 0C 87 EB D7 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5B 5E 8B E5 5D C3 }
        $sq14 = { 55 8B EC 8B 45 0C 53 56 8B 75 08 57 8B 4E 04 03 C1 8D 3C 09 3B F8 77 06 8D B8 F4 01 00 00 33 C9 8B C7 6A 04 5A F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B D8 59 85 DB 74 26 57 6A 00 53 E8 ?? ?? ?? ?? FF 76 08 FF 36 53 E8 ?? ?? ?? ?? FF 36 E8 ?? ?? ?? ?? 33 C0 89 1E 83 C4 1C 89 7E 04 40 5F 5E 5B 5D C3 }
        $sq15 = { 55 8B EC 83 7D 0C 00 57 74 39 8B 7D 10 85 FF 74 32 56 8B 75 08 8B 46 08 03 C7 3B 46 04 76 09 57 56 E8 3F FF FF FF 59 59 8B 46 08 03 06 57 FF 75 0C 50 E8 ?? ?? ?? ?? 01 7E 08 83 C4 0C 33 C0 40 5E EB 02 33 C0 5F 5D C3 }

    condition:

       uint16(0) == 0x5a4d and
       any of them 
}

rule BadBunny {
   
   meta:

      description = "Bad Rabbit Ransomware"
      author = "Christiaan Beek"
      date = "2017-10-24"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/BadRabbit"
      actor_type = "Cybercrime"
      actor_group = "Unknown"    
      hash1 = "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"
   
   strings:

      $x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
      $x2 = "need to do is submit the payment and get the decryption password." fullword ascii
      $s3 = "If you have already got the password, please enter it below." fullword ascii
      $s4 = "dispci.exe" fullword wide
      $s5 = "\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" fullword wide
      $s6 = "Run DECRYPT app at your desktop after system boot" fullword ascii
      $s7 = "Enter password#1: " fullword wide
      $s8 = "Enter password#2: " fullword wide
      $s9 = "C:\\Windows\\cscc.dat" fullword wide
      $s10 = "schtasks /Delete /F /TN %ws" fullword wide
      $s11 = "Password#1: " fullword ascii
      $s12 = "\\AppData" fullword wide
      $s13 = "Disk decryption completed" fullword wide
      $s14 = "Files decryption completed" fullword wide
      $s15 = "http://diskcryptor.net/" fullword wide
      $s16 = "Your personal installation key#1:" fullword ascii
      $s17 = ".3ds.7z.accdb.ai.asm.asp.aspx.avhd.back.bak.bmp.brw.c.cab.cc.cer.cfg.conf.cpp.crt.cs.ctl.cxx.dbf.der.dib.disk.djvu.doc.docx.dwg." wide
      $s18 = "Disable your anti-virus and anti-malware programs" fullword wide
      $s19 = "bootable partition not mounted" fullword ascii
   
   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 400KB and 
      pe.imphash() == "94f57453c539227031b918edd52fc7f1" and 
      ( 1 of ($x*) or
      4 of them )) or
      ( all of them )
}

rule badrabbit_ransomware {
   
   meta:

      description = "Rule to detect Bad Rabbit Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/BadRabbit"
      actor_type = "Cybercrime"
      actor_group = "Unknown" 
      reference = "https://securelist.com/bad-rabbit-ransomware/82851/"

   strings:
   
      $s1 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\" -id %u && exit\"" fullword wide
      $s2 = "C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\" fullword wide
      $s3 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
      $s4 = "need to do is submit the payment and get the decryption password." fullword wide
      $s5 = "schtasks /Create /SC once /TN drogon /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
      $s6 = "rundll32 %s,#2 %s" fullword ascii
      $s7 = " \\\"C:\\Windows\\%s\\\" #1 " fullword wide
      $s8 = "Readme.txt" fullword wide
      $s9 = "wbem\\wmic.exe" fullword wide
      $s10 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide

      $og1 = { 39 74 24 34 74 0a 39 74 24 20 0f 84 9f }
      $og2 = { 74 0c c7 46 18 98 dd 00 10 e9 34 f0 ff ff 8b 43 }
      $og3 = { 8b 3d 34 d0 00 10 8d 44 24 28 50 6a 04 8d 44 24 }

      $oh1 = { 39 5d fc 0f 84 03 01 00 00 89 45 c8 6a 34 8d 45 }
      $oh2 = { e8 14 13 00 00 b8 ff ff ff 7f eb 5b 8b 4d 0c 85 }
      $oh3 = { e8 7b ec ff ff 59 59 8b 75 08 8d 34 f5 48 b9 40 }

      $oj4 = { e8 30 14 00 00 b8 ff ff ff 7f 48 83 c4 28 c3 48 }
      $oj5 = { ff d0 48 89 45 e0 48 85 c0 0f 84 68 ff ff ff 4c }
      $oj6 = { 85 db 75 09 48 8b 0e ff 15 34 8f 00 00 48 8b 6c }

      $ok1 = { 74 0c c7 46 18 c8 4a 40 00 e9 34 f0 ff ff 8b 43 }
      $ok2 = { 68 f8 6c 40 00 8d 95 e4 f9 ff ff 52 ff 15 34 40 }
      $ok3 = { e9 ef 05 00 00 6a 10 58 3b f8 73 30 8b 45 f8 85 }


   condition:

      uint16(0) == 0x5a4d and
      filesize < 1000KB and
      (all of ($s*) and
      all of ($og*)) or
      all of ($oh*) or
      all of ($oj*) or
      all of ($ok*)
}

rule Ransom_AvosLocker {
   meta:
      description = "Rule to detect Avoslocker Ransomware"
      author = "CB @ ATR"
      date = "2021-07-22"
      Version = "v1"
      DetectionName = "Ransom_Win_Avoslocker"
      hash1 = "fb544e1f74ce02937c3a3657be8d125d5953996115f65697b7d39e237020706f"
      hash2 = "43b7a60c0ef8b4af001f45a0c57410b7374b1d75a6811e0dfc86e4d60f503856"
   strings:

      $v1 = "CryptImportPublicKeyInfo failed. error: %d" fullword ascii
      $v2 = "CryptStringToBinary failed. Err: %d" fullword ascii
      $v3 = "encrypting %ls failed" fullword wide
      $v4 = "CryptDecodeObjectEx 1 failed. Err: %p" fullword ascii
      $v5 = "operator co_await" fullword ascii
      $v6 = "drive %s took %f seconds" fullword ascii

      $seq0 = { 8d 4e 04 5e e9 b1 ff ff ff 55 8b ec ff 75 08 ff }
      $seq1 = { 33 c0 80 fb 2d 0f 94 c0 05 ff ff ff 7f eb 02 f7 }
      $seq2 = { 8b 40 0c 89 85 1c ff ff ff 8b 40 0c 89 85 18 ff }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and pe.imphash() == "a24c2b5bf84a5465eb75f1e6aa8c1eec" and ( 5 of them ) and all of ($seq*)
      ) or ( all of them )
}

rule wannaren_ransomware {

    meta:

        description = "Rule to detect WannaRen Ransomware"
        author = "McAfee ATR Team"
        date = "2020-04-25"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/WannaRen"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://blog.360totalsecurity.com/en/attention-you-may-have-become-a-susceptible-group-of-wannaren-ransomware/"
        hash = "7b364f1c854e6891c8d09766bcc9a49420e0b5b4084d74aa331ae94e2cfb7e1d"
        
    strings:

        $sq0 = { 92 93 a91c2ea521 59 334826 }
        $sq1 = { d0ce 6641 c1e9c0 41 80f652 49 c1f94d }
        $sq2 = { 80f8b5 4d 63c9 f9 4d 03d9 41 }
        $sq3 = { 34b7 d2ea 660fbafa56 0f99c2 32d8 660fbafaed 99 }
        $sq4 = { f9 f7c70012355f 35c01f5226 f9 8d8056c800b0 f6c4b2 f9 }
        $sq5 = { f5 f9 44 3aeb 45 33cd 41 }
        $sq6 = { 890f c0ff12 44 b4a3 ee 2b4e70 7361 }
        $sq7 = { 81c502000000 6689542500 6681d97a1e 660fabe1 660fbae1a5 8b0f 8dbf04000000 }
        $sq8 = { 8d13 de11 d7 677846 f1 0d8cd45f87 bb34b98f33 }
        $sq9 = { 1440 4b 41 e8???????? 397c0847 }

    condition:

        uint16(0) == 0x5a4d and
        filesize < 21000KB and
        7 of them
}

rule RANSOM_wastedlocker
{
    meta:
    
        description = "Rule to detect unpacked samples of WastedLocker"
        author = "McAfee ATR Team"
        date = "2020-07-27"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/WastedLocker"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash1 = "ae255679f487e2e9075ffd5e8c7836dd425229c1e3bd40cfc46fbbceceec7cf4"
    
    strings:

        $pattern_0 = { 8d45fc 50 53 53 6a19 ff75f8 }
        $pattern_1 = { 66833b00 8bf3 0f8485000000 8b7d10 8b472c 85c0 7410 }
        $pattern_2 = { e8???????? 8b4d08 8b4518 8d0441 6683600200 83c40c 837d1400 }
        $pattern_3 = { 8701 e9???????? 8bc7 5f 5e 5b }
        $pattern_4 = { 8bf8 3bfb 742f 53 8d45fc 50 56 }
        $pattern_5 = { 6a10 8d45f0 6a00 50 e8???????? 83c40c 5e }
        $pattern_6 = { 5f 5d c20800 55 8bec }
        $pattern_7 = { 8d7e04 ff15???????? 85c0 8945e8 740e 2b4510 }
        $pattern_8 = { ff15???????? 8b45dc 8b4dbc 69c00d661900 055ff36e3c 8945dc }
        $pattern_9 = { 8b4d08 8b19 03d8 f7d0 c1c60f 03f2 0bc6 }
   
    condition:

        7 of them and
        filesize < 1806288
}

rule Ransom_Win_BlackCat
{
  meta:
  description = "Detecting variants of Windows BlackCat malware"
  author = " Trellix ATR"
  date = "2022-01-06"
  malware_type = "Ransomware"
  detection_name = "Ransom_Win_BlackCat"
  malware_family = "Ransom:W32/BlackCat"
  actor_group = "Unknown"

strings:

 $URL1 = "zujgzbu5y64xbmvc42addp4lxkoosb4tslf5mehnh7pvqjpwxn5gokyd.onion" ascii wide
 $URL2 = "mu75ltv3lxd24dbyu6gtvmnwybecigs5auki7fces437xvvflzva2nqd.onion" ascii wide

 $API = { 3a 7c d8 3f }

 condition:
  uint16(0) == 0x5a4d and
  filesize < 3500KB and
  1 of ($URL*) and
  $API
}

rule installer_coronavirus {

   meta:
   
      description = "Rule to detect the Corona Virus Installer"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-03-25"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/CoronaVirus"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://twitter.com/malwrhunterteam/status/1238056503493505024"
      hash = "5987a6e42c3412086b7c9067dc25f1aaa659b2b123581899e9df92cb7907a3ed"

   strings:

      //achellies@hotmail.com
      $s1 = { 61 63 68 65 6C 6C 69 65 73 40 68 6F 74 6D 61 69 6C 2E 63 6F 6D }

      //tojen.me@gmail.com
      $s2 = { 74 6F 6A 65 6E 2E 6D 65 40 67 6D 61 69 6C 2E 63 6F 6D }

      //wangchyz@gmail.com
      $s4 = { 77 61 6E 67 63 68 79 7A 40 67 6D 61 69 6C 2E 63 6F 6D }

      //Todos los tipos de imagen|*.bmp;*.cur;*.dib;*.emf;*.ico;*.wmf|Mapas de bits (*.bmp;*.dib)|*.bmp;*.dib|Iconos/cursores (*.ico;*.cur)|*.ico;*.cur|Metaarchivos (*.wmf;*.emf)|*.wmf;*.emf|Todos los archivos (*.*)|*.*||
      $s5 = { 54 00 6F 00 64 00 6F 00 73 00 20 00 6C 00 6F 00 73 00 20 00 74 00 69 00 70 00 6F 00 73 00 20 00 64 00 65 00 20 00 69 00 6D 00 61 00 67 00 65 00 6E 00 7C 00 2A 00 2E 00 62 00 6D 00 70 00 3B 00 2A 00 2E 00 63 00 75 00 72 00 3B 00 2A 00 2E 00 64 00 69 00 62 00 3B 00 2A 00 2E 00 65 00 6D 00 66 00 3B 00 2A 00 2E 00 69 00 63 00 6F 00 3B 00 2A 00 2E 00 77 00 6D 00 66 00 7C 00 4D 00 61 00 70 00 61 00 73 00 20 00 64 00 65 00 20 00 62 00 69 00 74 00 73 00 20 00 28 00 2A 00 2E 00 62 00 6D 00 70 00 3B 00 2A 00 2E 00 64 00 69 00 62 00 29 00 7C 00 2A 00 2E 00 62 00 6D 00 70 00 3B 00 2A 00 2E 00 64 00 69 00 62 00 7C 00 49 00 63 00 6F 00 6E 00 6F 00 73 00 2F 00 63 00 75 00 72 00 73 00 6F 00 72 00 65 00 73 00 20 00 28 00 2A 00 2E 00 69 00 63 00 6F 00 3B 00 2A 00 2E 00 63 00 75 00 72 00 29 00 7C 00 2A 00 2E 00 69 00 63 00 6F 00 3B 00 2A 00 2E 00 63 00 75 00 72 00 7C 00 4D 00 65 00 74 00 61 00 61 00 72 00 63 00 68 00 69 00 76 00 6F 00 73 00 20 00 28 00 2A 00 2E 00 77 00 6D 00 66 00 3B 00 2A 00 2E 00 65 00 6D 00 66 00 29 00 7C 00 2A 00 2E 00 77 00 6D 00 66 00 3B 00 2A 00 2E 00 65 00 6D 00 66 00 7C 00 54 00 6F 00 64 00 6F 00 73 00 20 00 6C 00 6F 00 73 00 20 00 61 00 72 00 63 00 68 00 69 00 76 00 6F 00 73 00 20 00 28 00 2A 00 2E 00 2A 00 29 00 7C 00 2A 00 2E 00 2A 00 7C 00 7C 00 }

      //HTML_IMG#IDR_HTM_IMAGES_LI_CAPTION_HOVER_PNG)IDR_HTM_IMAGES_SB_H_SCROLL_PREV_HOVER_PNG1IDR_HTM_IMG_PAGE_TITLE_ICON_MENU_ORANGE_CLOSE_PNG2IDR_HTM_IMG_PAGE_TITLE_ICON_MENU_PAID_SETTINGS_PNG
      $s6 = { 48 00 54 00 4D 00 4C 00 5F 00 49 00 4D 00 47 00 23 00 49 00 44 00 52 00 5F 00 48 00 54 00 4D 00 5F 00 49 00 4D 00 41 00 47 00 45 00 53 00 5F 00 4C 00 49 00 5F 00 43 00 41 00 50 00 54 00 49 00 4F 00 4E 00 5F 00 48 00 4F 00 56 00 45 00 52 00 5F 00 50 00 4E 00 47 00 29 00 49 00 44 00 52 00 5F 00 48 00 54 00 4D 00 5F 00 49 00 4D 00 41 00 47 00 45 00 53 00 5F 00 53 00 42 00 5F 00 48 00 5F 00 53 00 43 00 52 00 4F 00 4C 00 4C 00 5F 00 50 00 52 00 45 00 56 00 5F 00 48 00 4F 00 56 00 45 00 52 00 5F 00 50 00 4E 00 47 00 31 00 49 00 44 00 52 00 5F 00 48 00 54 00 4D 00 5F 00 49 00 4D 00 47 00 5F 00 50 00 41 00 47 00 45 00 5F 00 54 00 49 00 54 00 4C 00 45 00 5F 00 49 00 43 00 4F 00 4E 00 5F 00 4D 00 45 00 4E 00 55 00 5F 00 4F 00 52 00 41 00 4E 00 47 00 45 00 5F 00 43 00 4C 00 4F 00 53 00 45 00 5F 00 50 00 4E 00 47 00 32 00 49 00 44 00 52 00 5F 00 48 00 54 00 4D 00 5F 00 49 00 4D 00 47 00 5F 00 50 00 41 00 47 00 45 00 5F 00 54 00 49 00 54 00 4C 00 45 00 5F 00 49 00 43 00 4F 00 4E 00 5F 00 4D 00 45 00 4E 00 55 00 5F 00 50 00 41 00 49 00 44 00 5F 00 53 00 45 00 54 00 54 00 49 00 4E 00 47 00 53 00 5F 00 50 00 4E 00 47 00 }

      //%s\log_%04d%02d%02d_%d.log
      $s7 = { 25 73 5C 6C 6F 67 5F 25 30 34 64 25 30 32 64 25 30 32 64 5F 25 64 2E 6C 6F 67 }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 3000KB and
      all of them
}

rule ransomware_coronavirus {

   meta:
   
      description = "Rule to detect the Corona Virus ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-03-25"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/CoronaVirus"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://twitter.com/malwrhunterteam/status/1238056503493505024"
      hash = "3299f07bc0711b3587fe8a1c6bf3ee6bcbc14cb775f64b28a61d72ebcb8968d3"
   
   strings:

      //%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s
      $s1 = { 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 }

      //%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s
      $s2 = { 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 25 00 73 00 }
      
      ///upload/%s_%d_%s
      $s3 = { 2F 00 75 00 70 00 6C 00 6F 00 61 00 64 00 2F 00 25 00 73 00 5F 00 25 00 64 00 5F 00 25 00 73 00 }
      
      //SYSTEM\CurrentControlSet\Control\Session Manager
      $s4 = { 53 59 53 54 45 4D 5C 43 75 72 72 65 6E 74 43 6F 6E 74 72 6F 6C 53 65 74 5C 43 6F 6E 74 72 6F 6C 5C 53 65 73 73 69 6F 6E 20 4D 61 6E 61 67 65 72 }
      
      //\\.\PhysicalDrive%d
      $s5 = { 5C 5C 2E 5C 50 68 79 73 69 63 61 6C 44 72 69 76 65 25 64 }
         
   condition:

      uint16(0) == 0x5a4d and 
      filesize < 100KB and 
      all of them
}

rule VPNFilter {
   
   meta:
      
      description = "Filter for 2nd stage malware used in VPNfilter attack"
      author = "Christiaan Beek @ McAfee Advanced Threat Research"
      date = "2018-05-23"
      rule_version = "v1"
      malware_type = "backdoor"
      malware_family = "Backdoor:W32/VPNfilter"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://blog.talosintelligence.com/2018/05/VPNFilter.html"
      hash = "9eb6c779dbad1b717caa462d8e040852759436ed79cc2172692339bc62432387"
   
   strings:

      $s1 = "id-at-postalAddress" fullword ascii
      $s2 = "/bin/shell" fullword ascii
      $s3 = "/DZrtenNLQNiTrM9AM+vdqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQAB" fullword ascii
      $s4 = "Usage does not match the keyUsage extension" fullword ascii
      $s5 = "id-at-postalCode" fullword ascii
      $s6 = "vTeY4KZMaUrveEel5tWZC94RSMKgxR6cyE1nBXyTQnDOGbfpNNgBKxyKbINWoOJU" fullword ascii
      $s7 = "id-ce-extKeyUsage" fullword ascii
      $s8 = "/f8wYwYDVR0jBFwwWoAUtFrkpbPe0lL2udWmlQ/rPrzH/f+hP6Q9MDsxCzAJBgNV" fullword ascii
      $s9 = "/etc/config/hosts" fullword ascii
      $s10 = "%s%-18s: %d bits" fullword ascii
      $s11 = "id-ce-keyUsage" fullword ascii
      $s12 = "Machine is not on the network" fullword ascii
      $s13 = "No XENIX semaphores available" fullword ascii
      $s14 = "No CSI structure available" fullword ascii
      $s15 = "Name not unique on network" fullword ascii
   
   condition:

      ( uint16(0) == 0x457f and
      filesize < 500KB and
      ( 8 of them )) or
      ( all of them )
}

rule vbs_mykins_botnet {

   meta:

      description = "Rule to detect the VBS files used in Mykins botnet"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-01-24"
      rule_version = "v1"
      malware_type = "botnet"
      malware_family = "Botnet:W32/MyKins"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://blog.netlab.360.com/mykings-the-botnet-behind-multiple-active-spreading-botnets/"
      
   strings:

      $s1 = "fso.DeleteFile(WScript.ScriptFullName)" fullword ascii
      $s2 = "Set ws = CreateObject(\"Wscript.Shell\")" fullword ascii
      $s3 = "Set fso = CreateObject(\"Scripting.Filesystemobject\")" fullword ascii
      $r = /Windows\\ime|web|inf|\\c[0-9].bat/

   condition:

      uint16(0) == 0x6553 and
      filesize < 1KB 
      and any of ($s*) and
      $r  
      
}

rule MALW_emotet
{
    meta:
    
        description = "Rule to detect unpacked Emotet"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-07-21"
        rule_version = "v1"
        malware_type = "financial"
        malware_family = "Backdoor:W32/Emotet"
        actor_type = "Cybercrime"
        hash1 = "a6621c093047446e0e8ae104769af93a5a8ed147ab8865afaafbbd22adbd052d"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
    
    strings:

        $pattern_0 = { 8b45fc 8be5 5d c3 55 8bec }
        $pattern_1 = { 3c39 7e13 3c61 7c04 3c7a 7e0b 3c41 }
        $pattern_2 = { 7c04 3c39 7e13 3c61 7c04 3c7a 7e0b }
        $pattern_3 = { 5f 8bc6 5e 5b 8be5 }
        $pattern_4 = { 5f 668906 5e 5b }
        $pattern_5 = { 3c30 7c04 3c39 7e13 3c61 7c04 }
        $pattern_6 = { 53 56 57 8bfa 8bf1 }
        $pattern_7 = { 3c39 7e13 3c61 7c04 3c7a 7e0b }
        $pattern_8 = { 55 8bec 83ec14 53 }
        $pattern_9 = { 5e 8be5 5d c3 55 8bec }
   
    condition:

        7 of them and filesize < 180224
}

rule dropper_demekaf_pdb {
	 
	 meta:

		 description = "Rule to detect Demekaf dropper based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2011-03-26"
		 rule_version = "v1"
         malware_type = "dropper"
         malware_family = "Dropper:W32/Demekaf"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://v.virscan.org/Trojan-Dropper.Win32.Demekaf.html"
		 hash = "fab320fceb38ba2c5398debdc828a413a41672ce9745afc0d348a0e96c5de56e"
	 
 	 strings:

 		$pdb = "\\vc\\res\\fake1.19-jpg\\fake\\Release\\fake.pdb"

 	 condition:

	 	 uint16(0) == 0x5a4d and
		 filesize < 150KB and
		 any of them
}

rule Dridex_P2P_pdb
{
	 meta:

		 description = "Rule to detect Dridex P2P based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2014-11-29"
		 rule_version = "v1"
         malware_type = "backdoor"
         malware_family = "Backdoor:W32/Dridex"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.us-cert.gov/ncas/alerts/aa19-339a" 
		 hash = "5345a9405212f3b8ef565d5d793e407ae8db964865a85c97e096295ba3f39a78"

	 strings:

	 	$pdb = "\\c0da\\j.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 400KB and
	 	any of them
}

rule malw_browser_fox_adware {
	 
	 meta:

		 description = "Rule to detect Browser Fox Adware based on the PDB reference"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2015-01-15"
		 rule_version = "v1"
         malware_type = "adware"
         malware_family = "Adware:W32/BrowserFox"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.sophos.com/en-us/threat-center/threat-analyses/adware-and-puas/Browse%20Fox.aspx"
		 hash = "c6f3d6024339940896dd18f32064c0773d51f0261ecbee8b0534fdd9a149ac64"
	 
	 strings:

	 	$pdb = "\\Utilities\\130ijkfv.o4g\\Desktop\\Desktop.OptChecker\\bin\\Release\\ BooZaka.Opt"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 800KB and
	 	any of them
}

rule rtf_bluetea_builder {

    meta:

	    description = "Rule to detect the RTF files created to distribute BlueTea trojan"
	    author = "Marc Rivero | McAfee ATR Team"
	    date = "2020-04-21"
	    rule_version = "v1"
        malware_type = "maldoc"
        malware_family = "Maldoc:W32/BlueTea"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
	    reference = "https://blog.360totalsecurity.com/en/bluetea-action-drive-the-life-trojan-update-email-worm-module-and-spread-through-covid-19-outbreak/"
	    hash = "4a3eeaed22342967a95302a4f087b25f50d61314facc6791f756dcd113d4f277"

    strings:

      /*

		  7B5C727466315C616465666C616E67313032355C616E73695C616E73696370673933365C7563325C616465666633313530375C64656666305C73747368666462636833313530355C73747368666C6F636833313530365C73747368666869636833313530365C73747368666269305C6465666C616E67313033335C6465666C616E676665323035325C7468656D656C616E67313033335C7468656D656C616E676665323035325C7468656D656C616E676373307B5C666F6E7474626C7B5C66305C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D0D0A7B5C6631335C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D5C2763625C2763655C2763635C2765357B5C2A5C66616C742053696D53756E7D3B7D7B5C6633345C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323034303530333035303430363033303230347D43616D62726961204D6174683B7D0D0A7B5C6633375C6662696469205C6673776973735C6663686172736574305C66707271327B5C2A5C70616E6F73652030323066303530323032303230343033303230347D43616C696272693B7D7B5C6633385C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D405C2763625C2763655C2763635C2765353B7D0D0A7B5C666C6F6D616A6F725C6633313530305C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D7B5C6664626D616A6F725C6633313530315C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D5C2763625C2763655C2763635C2765357B5C2A5C66616C742053696D53756E7D3B7D0D0A7B5C6668696D616A6F725C6633313530325C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323034303530333035303430363033303230347D43616D627269613B7D7B5C6662696D616A6F725C6633313530335C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D0D0A7B5C666C6F6D696E6F725C6633313530345C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D7B5C6664626D696E6F725C6633313530355C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D5C2763625C2763655C2763635C2765357B5C2A5C66616C742053696D53756E7D3B7D0D0A7B5C6668696D696E6F725C6633313530365C6662696469205C6673776973735C6663686172736574305C66707271327B5C2A5C70616E6F73652030323066303530323032303230343033303230347D43616C696272693B7D7B5C6662696D696E6F725C6633313530375C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D7B5C6634305C6662696469205C66726F6D616E5C66636861727365743233385C66707271322054696D6573204E657720526F6D616E2043453B7D0D0A7B5C6634315C6662696469205C66726F6D616E5C66636861727365743230345C66707271322054696D6573204E657720526F6D616E204379723B7D7B5C6634335C6662696469205C66726F6D616E5C66636861727365743136315C66707271322054696D6573204E657720526F6D616E20477265656B3B7D7B5C6634345C6662696469205C66726F6D616E5C66636861727365743136325C66707271322054696D6573204E657720526F6D616E205475723B7D7B5C6634355C6662696469205C66726F6D616E5C66636861727365743137375C66707271322054696D6573204E657720526F6D616E2028486562726577293B7D0D0A7B5C6634365C6662696469205C66726F6D616E5C66636861727365743137385C66707271322054696D6573204E657720526F6D616E2028417261626963293B7D7B5C6634375C6662696469205C66726F6D616E5C66636861727365743138365C66707271322054696D6573204E657720526F6D616E2042616C7469633B7D7B5C6634385C6662696469205C66726F6D616E5C66636861727365743136335C66707271322054696D6573204E657720526F6D616E2028566965746E616D657365293B7D0D0A7B5C663137325C6662696469205C666E696C5C6663686172736574305C66707271322053696D53756E205765737465726E7B5C2A5C66616C742053696D53756E7D3B7D7B5C663338305C6662696469205C66726F6D616E5C66636861727365743233385C66707271322043616D62726961204D6174682043453B7D7B5C663338315C6662696469205C66726F6D616E5C66636861727365743230345C66707271322043616D62726961204D617468204379723B7D7B5C663338335C6662696469205C66726F6D616E5C66636861727365743136315C66707271322043616D62726961204D61746820477265656B3B7D0D0A7B5C663338345C6662696469205C66726F6D616E5C66636861727365743136325C66707271322043616D62726961204D617468205475723B7D7B5C663338375C6662696469205C66726F6D616E5C66636861727365743138365C66707271322043616D62726961204D6174682042616C7469633B7D7B5C663338385C6662696469205C66726F6D616E5C66636861727365743136335C66707271322043616D62726961204D6174682028566965746E616D657365293B7D7B5C663431305C6662696469205C6673776973735C66636861727365743233385C66707271322043616C696272692043453B7D0D0A7B5C663431315C6662696469205C6673776973735C66636861727365743230345C66707271322043616C69627269204379723B7D7B5C663431335C6662696469205C6673776973735C66636861727365743136315C66707271322043616C6962726920477265656B3B7D7B5C663431345C6662696469205C6673776973735C66636861727365743136325C66707271322043616C69627269205475723B7D7B5C663431375C6662696469205C6673776973735C66636861727365743138365C66707271322043616C696272692042616C7469633B7D0D0A7B5C663431385C6662696469205C6673776973735C66636861727365743136335C66707271322043616C696272692028566965746E616D657365293B7D7B5C663432325C6662696469205C666E696C5C6663686172736574305C667072713220405C2763625C2763655C2763635C276535205765737465726E3B7D7B5C666C6F6D616A6F725C6633313530385C6662696469205C66726F6D616E5C66636861727365743233385C66707271322054696D6573204E657720526F6D616E2043453B7D0D0A7B5C666C6F6D616A6F725C6633313530395C6662696469205C66726F6D616E5C66636861727365743230345C66707271322054696D6573204E657720526F6D616E204379723B7D7B5C666C6F6D616A6F725C6633313531315C6662696469205C66726F6D616E5C66636861727365743136315C66707271322054696D6573204E657720526F6D616E20477265656B3B7D7B5C666C6F6D616A6F725C6633313531325C6662696469205C66726F6D616E5C66636861727365743136325C66707271322054696D6573204E657720526F6D616E205475723B7D0D0A7B5C666C6F6D616A6F725C6633313531335C6662696469205C66726F6D616E5C66636861727365743137375C66707271322054696D6573204E657720526F6D616E2028486562726577293B7D7B5C666C6F6D616A6F725C6633313531345C6662696469205C66726F6D616E5C66636861727365743137385C66707271322054696D6573204E657720526F6D616E2028417261626963293B7D7B5C666C6F6D616A6F725C6633313531355C6662696469205C66726F6D616E5C66636861727365743138365C66707271322054696D6573204E657720526F6D616E2042616C7469633B7D0D0A7B5C666C6F6D616A6F725C6633313531365C6662696469205C66726F6D616E5C66636861727365743136335C66707271322054696D6573204E657720526F6D616E2028566965746E616D657365293B7D7B5C6664626D616A6F725C6633313532305C6662696469205C666E696C5C6663686172736574305C66707271322053696D53756E205765737465726E7B5C2A5C66616C742053696D53756E7D3B7D7B5C6668696D616A6F725C6633313532385C6662696469205C66726F6D616E5C66636861727365743233385C66707271322043616D627269612043453B7D0D0A7B5C6668696D616A6F725C6633313532395C6662696469205C66726F6D616E5C66636861727365743230345C66707271322043616D62726961204379723B7D7B5C6668696D616A6F725C6633313533315C6662696469205C66726F6D616E5C66636861727365743136315C66707271322043616D6272696120477265656B3B7D7B5C6668696D616A6F725C6633313533325C6662696469205C66726F6D616E5C66636861727365743136325C66707271322043616D62726961205475723B7D0D0A7B5C6668696D616A6F725C6633313533355C6662696469205C66726F6D616E5C66636861727365743138365C66707271322043616D627269612042616C7469633B7D7B5C6668696D616A6F

		  */
      $sequence = { 7B??72??6631??????65666C616E6731??32??????????69??????????????67????36??75??32??????656666????35????????656666????????73??666462????33??35????????74??68????????68????????36??73??73??66??????68????????36??73??73??6662????5C646566??616E6731??33??5C646566??616E67666532??35????????656D656C616E6731??33??5C74??656D656C616E67666532??35????????656D656C616E6763????7B??666F6E74??62??????6630??????69??????????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??32??3630??30??????????30??30??30????????????73??4E6577??526F6D616E3B????0A????6631??5C6662????69??????????6C5C6663????72??6574??33????6670??71??7B??2A??????6E6F73??20??32??31??3630??30??30??30??30??30??30??7D??2763????2763????2763????276535????????66616C74??5369????????????7D??5C6633????6662????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??34??35????????30????3630??30??30????????????72??6120????74??3B????0A????6633??5C6662????69??????????69????????????6172??6574??5C6670??71??7B??2A??????6E6F73??20??32??6630??????????30??30????33??32??34??43616C69????????????5C6633??5C6662????69??????????6C5C6663????72??6574??33????6670??71??7B??2A??????6E6F73??20??32??31??3630??30??30??30??30??30??30??7D??5C2763????2763????2763????276535????????7B??666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??32??3630??30??????????30??30??30????????????73??4E6577??526F6D616E3B????5C666462????6A??72??6633??35????????62????69??????????6C5C6663????72??6574??33????6670??71??7B??2A??????6E6F73??20??32??31??3630??30??30??30??30??30??30??7D??2763????2763????2763????276535????????66616C74??5369????????????7D??0A????66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??34??35????????30????3630??30??30????????????72??613B????5C6662????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??32??3630??30??????????30??30??30????????????73??4E6577??526F6D616E3B????0A????666C6F6D69????????????31??????????62????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??32??3630??30??????????30??30??30????????????73??4E6577??526F6D616E3B????5C666462????6E6F72??6633??35????????62????69??????????6C5C6663????72??6574??33????6670??71??7B??2A??????6E6F73??20??32??31??3630??30??30??30??30??30??30??7D??2763????2763????2763????276535????????66616C74??5369????????????7D??0A????66??????69????????????31??????????62????69??????????69????????????6172??6574??5C6670??71??7B??2A??????6E6F73??20??32??6630??????????30??30????33??32??34??43616C69????????????5C6662????69????????????31??????????62????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??32??3630??30??????????30??30??30????????????73??4E6577??526F6D616E3B????5C6634??5C6662????69??????????6D616E5C6663????72??6574??33??5C6670??71??20??????6573??4E6577??526F6D616E20????3B????0A????6634??5C6662????69??????????6D616E5C6663????72??6574??30????6670??71??20??????6573??4E6577??526F6D616E20????72??7D??5C6634??5C6662????69??????????6D616E5C6663????72??6574??3631??????72??32??5469????????????77??526F6D616E20????6565??????7B??6634??5C6662????69??????????6D616E5C6663????72??6574??3632??????72??32??5469????????????77??526F6D616E20??????3B????5C6634??5C6662????69??????????6D616E5C6663????72??6574??37375C6670??71??20??????6573??4E6577??526F6D616E20??486562????77??3B????0A????6634??5C6662????69??????????6D616E5C6663????72??6574??3738??????72??32??5469????????????77??526F6D616E20??4172??62????29??7D??5C6634??5C6662????69??????????6D616E5C6663????72??6574??38??5C6670??71??20??????6573??4E6577??526F6D616E20????6C74??63??7D??5C6634??5C6662????69??????????6D616E5C6663????72??6574??3633??????72??32??5469????????????77??526F6D616E20??5669????????????73??29??7D??0A????6631??32??????69??????????????6C5C6663????72??6574??5C6670??71??20????6D5375??20????73??6572??7B??2A??????6C74??5369????????????7D??5C6633??30??????69??????????????6D616E5C6663????72??6574??33??5C6670??71??20????6D62????6120????74??20????3B????5C6633??31??????69??????????????6D616E5C6663????72??6574??30????6670??71??20????6D62????6120????74??20????72??7D??5C6633??33??????69??????????????6D616E5C6663????72??6574??3631??????72??32??43616D62????6120????74??20????6565??????0D????????33??34??6662????69??????????6D616E5C6663????72??6574??3632??????72??32??43616D62????6120????74??20??????3B????5C6633??375C6662????69??????????6D616E5C6663????72??6574??38??5C6670??71??20????6D62????6120????74??20????6C74??63??7D??5C6633??38??????69??????????????6D616E5C6663????72??6574??3633??????72??32??43616D62????6120????74??20??5669????????????73??29??7D??5C6634??30??????69??????????????69????????????6172??6574??33??5C6670??71??20????6C69????????????3B????0A????6634??31??????69??????????????69????????????6172??6574??30????6670??71??20????6C69????????????72??7D??5C6634??33??????69??????????????69????????????6172??6574??3631??????72??32??43616C69????????????6565??????7B??6634??34??6662????69??????????69????????????6172??6574??3632??????72??32??43616C69????????????72??7D??5C6634??375C6662????69??????????69????????????6172??6574??38??5C6670??71??20????6C69????????????6C74??63??7D??0A????6634??38??????69??????????????69????????????6172??6574??3633??????72??32??43616C69????????????69????????????73??29??7D??5C6634??32??????69??????????????6C5C6663????72??6574??5C6670??71??20????2763????2763????2763????276535????????74??72??3B????5C666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??33??5C6670??71??20??????6573??4E6577??526F6D616E20????3B????0A????666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??30????6670??71??20??????6573??4E6577??526F6D616E20????72??7D??5C666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3631??????72??32??5469????????????77??526F6D616E20????6565??????7B??666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3632??????72??32??5469????????????77??526F6D616E20??????3B????0A????666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??37375C6670??71??20??????6573??4E6577??526F6D616E20??486562????77??3B????5C666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3738??????72??32??5469????????????77??526F6D616E20??4172??62????29??7D??5C666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??38??5C6670??71??20??????6573??4E6577??526F6D616E20????6C74??63??7D??0A????666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3633??????72??32??5469????????????77??526F6D616E20??5669????????????73??29??7D??5C666462????6A??72??6633??35????????62????69??????????6C5C6663????72??6574??5C6670??71??20????6D5375??20????73??6572??7B??2A??????6C74??5369????????????7D??5C66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??33??5C6670??71??20????6D62????6120????3B????0A????66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??30????6670??71??20????6D62????6120????72??7D??5C66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3631??????72??32??43616D62????6120????6565??????7B??66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3632??????72??32??43616D62????6120??????3B????0A????66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??38??5C6670??71??20????6D62????6120????6C74??63??7D??5C66??????616A?? }

    condition:

      uint16(0) == 0x5c7b and
		  filesize < 100KB and
		  all of them
}

rule jatboss {
        
        meta:

            description = "Rule to detect PDF files from Jatboss campaign and MSG files that contained those attachents"
            author = "Marc Rivero | McAfee ATR Team"
            date = "2019-12-04"
            rule_version = "v1"
            malware_type = "phishing"
            malware_family = "Phishing:W32/Jatboss"
            actor_type = "Cybercrime"
            actor_group = "Unknown"
            reference = "https://exchange.xforce.ibmcloud.com/collection/JATBOSS-Phishing-Kit-17c74b38860de5cb9fc727e6c0b6d5b5"           
            hash = "b81fb37dc48812f6ad61984ecf2a8dbbfe581120257cb4becad5375a12e755bb"
            
        strings:

            //<</Author(JAT) /Creator( string    
            $jat = { 3C 3C 2F 41 75 74 68 6F 72 28 4A 41 54 29 20 2F 43 72 65 61 74 6F 72 28 }

          	//<</Author(jatboss) /Creator(
          	$jatboss = { 3C 3C 2F 41 75 74 68 6F 72 28 4A 41 54 29 20 2F 43 72 65 61 74 6F 72 28 }

          	//SPAM MSG file:
            $spam = { 54 00 68 00 69 00 73 00 20 00 65 00 2D 00 6D 00 61 00 69 00 6C 00 20 00 61 00 6E 00 64 00 20 00 61 00 6E 00 79 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 6D 00 65 00 6E 00 74 00 20 00 61 00 72 00 65 00 20 00 43 00 6F 00 6E 00 66 00 69 00 64 00 65 00 6E 00 74 00 69 00 61 00 6C 00 2E 00 }

      condition:

        	(uint16(0) == 0x5025 and
          filesize < 1000KB and
          ($jat or
          $jatboss)) or
          (uint16(0) == 0xcfd0 and 
          $spam and 
          any of ($jat*)) 
}

rule CryptoLocker_set1
{

	meta:

		description = "Detection of Cryptolocker Samples"
		author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
		date = "2014-04-13"
		rule_version = "v1"
	    malware_type = "ransomware"
	    malware_family = "Ransom:W32/Cryptolocker"
	    actor_type = "Cybercrime"
	    actor_group = "Unknown"
		
		
	strings:

		$string0 = "static"
		$string1 = " kscdS"
		$string2 = "Romantic"
		$string3 = "CompanyName" wide
		$string4 = "ProductVersion" wide
		$string5 = "9%9R9f9q9"
		$string6 = "IDR_VERSION1" wide
		$string7 = "  </trustInfo>"
		$string8 = "LookFor" wide
		$string9 = ":n;t;y;"
		$string10 = "        <requestedExecutionLevel level"
		$string11 = "VS_VERSION_INFO" wide
		$string12 = "2.0.1.0" wide
		$string13 = "<assembly xmlns"
		$string14 = "  <trustInfo xmlns"
		$string15 = "srtWd@@"
		$string16 = "515]5z5"
		$string17 = "C:\\lZbvnoVe.exe" wide

	condition:

		12 of ($string*)
}

rule CryptoLocker_rule2
{

	meta:

		description = "Detection of CryptoLocker Variants"
		author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
		date = "2014-04-14"
		rule_version = "v1"
	    malware_type = "ransomware"
	    malware_family = "Ransom:W32/Cryptolocker"
	    actor_type = "Cybercrime"
	    actor_group = "Unknown"

	strings:

		$string0 = "2.0.1.7" wide
		$string1 = "    <security>"
		$string2 = "Romantic"
		$string3 = "ProductVersion" wide
		$string4 = "9%9R9f9q9"
		$string5 = "IDR_VERSION1" wide
		$string6 = "button"
		$string7 = "    </security>"
		$string8 = "VFileInfo" wide
		$string9 = "LookFor" wide
		$string10 = "      </requestedPrivileges>"
		$string11 = " uiAccess"
		$string12 = "  <trustInfo xmlns"
		$string13 = "last.inf"
		$string14 = " manifestVersion"
		$string15 = "FFFF04E3" wide
		$string16 = "3,31363H3P3m3u3z3"

	condition:

		12 of ($string*)
}

rule RANSOM_darkside
{
    meta:
    
        description = "Rule to detect packed and unpacked samples of DarkSide"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-08-11"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/DarkSide"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash1 = "9cee5522a7ca2bfca7cd3d9daba23e9a30deb6205f56c12045839075f7627297"
    
    strings:

        $pattern_0 = { CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC558BEC5053515256570FEFC0660FEFC033DB8B7D088B450C33D2B910000000F7F185C0740B0F110783C7104885C075F585D27502EB5892B908000000F7F185C0740B0F7F0783C7084885C075F585D27502EB3B92B904000000F7F185C0740A891F83C7044885C075F685D27502EB1F92B902000000F7F185C0740B66891F83C7024885C075F585D27502EB02881F5F5E5A595B585DC20800558BEC5053515256578B750C8B7D088B451033D2B910000000F7F185C074110F10060F110783C61083C7104885C075EF85D27502EB6892B908000000F7F185C074110F6F060F7F0783C60883C7084885C075EF85D27502EB4592B904000000F7F185C0740F8B1E891F83C60483C7044885C075F185D27502EB2492B902000000F7F185C0740E66891F83C60283C7024885C075F285D27502EB048A1E881F5F5E5A595B585DC20C00558BEC53515256578B4D0C8B75088B7D1033C033DBAC8AD8C0E80480E30F3C0072063C09770204303C0A72063C0F7702045780FB00720880FB09770380C33080FB0A720880FB0F770380C35766AB8AC366AB4985C975BE6633C066AB5F5E5A595B5DC20C00558BEC53515256578B75088B7D0C55FCB2808A0683C601880783C701BB0200000002D275058A164612D273E602D275058A164612D2734F33C002D275058A164612D20F83DB00000002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C074068BDF2BD88A03880747BB02000000EB9BB80100000002D275058A164612D213C002D275058A164612D272EA2BC3BB010000007528B90100000002D275058A164612D213C902D275058A164612D272EA568BF72BF5F3A45EE94FFFFFFF48C1E0088A06468BE8B90100000002D275058A164612D213C902D275058A164612D272EA3D007D000083D9FF3D0005000083D9FF3D8000000083D1003D8000000083D100568BF72BF0F3A45EE9FEFEFFFF8A064633C9C0E801741783D1028BE8568BF72BF0F3A45EBB01000000E9DDFEFFFF5D2B7D0C8BC75F5E5A595B5DC20800558BEC53515256578B7D088B450CB9FF00000033D2F7F185C074188BD868FF00000057E8AD00000081C7FF0000004B85DB75EA85D274075257E8970000005F5E5A595B5DC20800558BEC5351525657B9F0000000BEB2B640008B45088B108B58048B78088B400C89540E0C89440E08895C0E04893C0E81EA101010102D1010101081EB1010101081EF1010101083E91079D533D233C98B750C33DB8B7D108A81B2B6400002141E02D08AA2B2B64000438882B2B6400088A1B2B640003BDF7306FEC175DAEB0633DBFEC175D25F5E5A595B5DC20C00558BEC535152565733C0A3C2B84000A3C6B84000B9400000008D35B2B640008D3DB2B74000F3A58B7D088B15C2B840008B4D0C8B1DC6B840004F33C0029AB3B740008A82B3B740008AABB2B740008883B2B7400088AAB3B7400002C5478A80B2B74000FEC23007FEC975D18915C2B84000891DC6B840005F5E5A595B5DC2080053515256578D35047040008D3DCAB84000FF76FC56E891FEFFFF56E8864500008BD8FF76FC56E888FBFFFF8B46FC8D3406B915000000E85C010000AD5056E868FEFFFF56E85D4500008BD8FF76FC56E85FFBFFFF8B46FC8D3406B93D000000E833010000AD5056E83FFEFFFF5256E8334500008BD85AFF76FC56E834FBFFFF8B46FC8D3406B915000000E808010000AD5056E814FEFFFF5256E8084500008BD85AFF76FC56E809FBFFFF8B46FC8D3406B904000000E8DD000000AD5056E8E9FDFFFF5256E8DD4400008BD85AFF76FC56E8DEFAFFFF8B46FC8D3406B906000000E8B2000000AD5056E8BEFDFFFF5256E8B24400008BD85AFF76FC56E8B3FAFFFF8B46FC8D3406B901000000E887000000AD5056E893FDFFFF5256E8874400008BD85AFF76FC56E888FAFFFF8B46FC8D3406B903000000E85C000000AD5056E868FDFFFF5256E85C4400008BD85AFF76FC56E85DFAFFFF8B46FC8D3406B901000000E831000000AD5056E83DFDFFFF5256E8314400008BD85AFF76FC56E832FAFFFF8B46FC8D3406B902000000E8060000005F5E5A595BC3ADFF76FC56E80AFDFFFF515653E8F743000059ABFF76FC56E8FFF9FFFF8B46FC8D34064985C975D8C3558BEC81EC1401000053515256578D85ECFEFFFF50FF1516B940008BB5F0FEFFFF8BBDF4FEFFFF83FE05750583FF01720583FE057313B8000000005F5E5A595B8BE55DC3E9DA00000083FE05751883FF017513B8330000005F5E5A595B8BE55DC3E9BD00000083FE05751883FF027513B8340000005F5E5A595B8BE55DC3E9A000000083FE06751785FF7513B83C0000005F5E5A595B8BE55DC3E98400000083FE06751583FF017510B83D0000005F5E5A595B8BE55DC3EB6A83FE06751583FF027510B83E0000005F5E5A595B8BE55DC3EB5083FE06751583FF037510B83F0000005F5E5A595B8BE55DC3EB3683FE0A751485FF7510B8640000005F5E5A595B8BE55DC3EB1D83FE0A750583FF00770583FE0A760EB8FFFFFF7F5F5E5A595B8BE55DC3B8FFFFFFFF5F5E5A595B8BE55DC3558BEC83C4F853515256576A0068800000006A026A006A006800000040FF7508FF1526B940008945FC837DFCFF74226A008D45F850FF7510FF750CFF75FCFF1536B9400085C07409FF75FCFF153EB940005F5E5A595B8BE55DC20C008BFF558BEC5351525657837D0C0074728D3DAABA4000837D100075086A1057E842F8FFFFFF750CFF750868EFBEADDEFF15F6B84000FF750CFF750850FF15F6B840003107FF750CFF750850FF15F6B84000314704FF750CFF750850FF15F6B84000314708FF750CFF750850FF15F6B8400031470CB8AABA40005F5E5A595B5DC20C00B8000000005F5E5A595B5DC20C00558BEC5351525657FF7508FF15DEB8400083C4048BD88D045D02000000506A00FF35AEB64000FF15BEB940008BF085F67434FF750856FF15CEB8400083C4088D43016A006A0050FF75086AFF566A006A00FF1506BA4000566A00FF35AEB64000FF15C6B940008BC35F5E5A595B5DC2040053515657833DBABA400000750B68BABA4000FF15F2B8400068BABA4000FF15F2B840008BD15F5E595BC3558BEC5351525657BB080000008B7508E8C1FFFFFF83FB05750433C033D28944DEFC8954DEF84B85DB75E55F5E5A595B5DC204008D4000558BEC81EC0001000053515256578D45B083C00F83E0F089850CFFFFFF8D8560FFFFFF83C00F83E0F0898508FFFFFF8D8510FFFFFF83C00F83E0F0898504FFFFFF837D14000F84750300008BB504FFFFFF0F57C00F11060F1146100F1146200F1146308B75088BBD0CFFFFFF0F10060F104E100F1056200F105E300F11070F114F100F1157200F115F30837D1440732A8B4510898500FFFFFF8B9504FFFFFF8BFA8B750C8B4D148A440EFF88440FFF4985C975F389550C8955108BB50CFFFFFF8BBD08FFFFFF0F10060F104E100F1056200F105E300F11070F114F100F1157200F115F305556BD0A0000008B078B5F108B4F208B57308BF003F2C1C60733DE8BF303F0C1C60933CE8BF103F3C1C60D33D68BF203F1C1C61233C68907895F10894F208957308B47148B5F248B4F348B57048BF003F2C1C60733DE8BF303F0C1C60933CE8BF103F3C1C60D33D68BF203F1C1C61233C6894714895F24894F348957048B47288B5F388B4F088B57188BF003F2C1C60733DE8BF303F0C1C60933CE8BF103F3C1C60D33D68BF203F1C1C61233C6894728895F38894F088957188B473C8B5F0C8B4F1C8B572C8BF003F2C1C60733DE8BF303F0C1C60933CE8BF103F3C1C60D33D68BF203F1C1C61233C689473C }
        $pattern_1 = { 70211F3B6E97C50000473D000000A000004602003EBBFF1F92CC558BEC5053515256570FEFC0660333DBFBFFEDFF8B7D088B450C33D2B9100000F7F185C0740B0F110783C710480A692EFB7F75F585D27502EB5892B9081C7F08B60F592E3B040A891F38049B641979F61F02661CD6FEBFEC023802881F5F5E5A595B585DC25D977E20634F8B750C9110110F1006252383FD94C61097EF6819AC59BA226F7F089DEFD8EE0119450F8B1E82C604A23E033232F1240EC602B9EC91C1A5F2048A1EA70CA12CCBD9A64D757D42E9FEFFBFAC8AD8C0E80480E30F3C0072063C09770204303C0A090FB66F6DBB5780FB140804150380C3300C0ADADFFE790F5766AB8AC3034985C975BE6646FF252CD6096564610C55FCB2806FDF86DB8A069701887801BBAD0299058A164FD62EFB4612D273E60A4F430C0F83DB7F2A7B602613C00A74068BDF2BD821EC63DB8A03644762EB9BB80142900BFBFB72EA2BC3BB1C7528B923C96F7FFB1F568BF72BF5F3A45EE94D01D248C1E008C3468BE8DE1EC26E0C0449303D007D4B83D9FF0DD93CD907058000D100BDB01BF250F04C33C974017417B1D8B0B61902561B96204B06E1C25D2B398BC75208111AEE18EDB9FF2660F4F8EFDDF7188BD8680E579B03D981C70B4B85DB75EAEE94CD5EFE7407521546B9F0256F7F6BB7BE02A6B24D50108B58048B7807400C895FF7FFDB540E03440E08895C0E04893C0E81EA10002D048168ED9FB1EB05EF83E91079D57EC0DFFFFDE4EC80108A814A02141E02D08AA20A436BFFBFDF88820688A1053BDF7306FEC175DAEB062C076E0B29A3D227F8A327A8C27DFBEDFE04C6B940998D35378D3D05A7B2F3A57DBC8FF7F31520B41D242A9A1BFB8DDD1CB38A8205AB28888305AA11D88DFFFE02C5478A800EFEC23007FEA0D189402F9684D8893D0D7C6BF07BF8CF6004A8CAFF76FC5630040549FF33FFDBAC59109C0C8B46FC8D3406B9150F477291BD05F0AD50283D52C252D961295A532A02B902BB04550608B902B90103E10843260299C3AD8615B2BF2751565333F959AB329FE0EEF874D8C33F81EC1468C885ECFE7777DFF0FFFF50FF4FA9168BB5F00C8BBDF40583FE055877F74BA483FF017205097313B86D00695BF36DFA8BE55DC36C073C2118751C3300D21C210234DF04D2FD06751785FF1B3C1555109AC11EC8B83DEB6A19023EA419644250033FC866DE2636690A75141864FECDEE4C1DDE00770A760EB8FFFFFF7F1B927C490DFF3083C4AEFD7A84F82D6A0068976A02080AFE8FB07509405A083B268945FC837DFCFF7422916D73DF188D45F85072020C1DFC34ECB0AE3672090C3E59746B43DACC8BFFCE3C0D7472E1AD44FB51AAAA0B04576A1057BC67BF3F16470868EFBEADDE3FA8F6105090BDB0670C31070E47040F92F50EC9080CB8624E071B5913D85CD6A8DE6D1FDF6AF9E4D88D045D6D50DAFF58F78F7D63AEC6BE8BF085F6743429562ADDDCE1CBCE088D430119FDBDFF56B027ECEF0A1AAA065639C68BC37077FB9C630484FAF4BAF10B6807A31DB0B14CF20A8BD12DE09A3871989ABBFD24E84013CB376608A783FB048DD2D90317B87FDEFC87DEF8C4E55D49C628308D17EE000DC32FF145B083C027E0F089850CE3FD202387B960051108102B99FE37040B7D14000F8475C41E0FA6DBC5F60F571C119846100320ED17EF8930B1BD4EB0104E17D32CDBCB1056105E3026074F57CDE6E26E5F304840732AE457008B6FF017BF954D8BFAFB4D148A3FFF88447B6DFBD30FFFA3F389550C02106E5359FDF0A964085556BD0A14078B5F6FFFDFBE354F208B5792F003F2C1C60733DE8BF303F0080933CEED2FFFF28BF103F30D33D68BF203F11233C68907892ECBB26D96898947143A243404CBD612202F3B24342CCBB22C0428380818CBB25C802838081820CBB22C3C0C1C2CDFB22C173C0C1C2CED0463476063760CED04750C53606363ED187510ED18D80863637510ED2C6424ED3036C2142C6524ED30234C818D6538ED3065386DA30DFC4D85ED0F851B975E5DF30702CBE5726BC80357105F1867206FB6022F972877307F380F0C024EE572B9DC1EFE56FE5EFE66FE6EA6D996CBFE76FE7E7F3D7F7F94A6699A7F7F7F7F7F9AE5C8708D6B5757575D8C966B57BED8FE2011BFE4B834118B9DA7274320837B2086F1B195000824E977EF1866C335DB32C500E4B2BD154E8B55BA338942200524B5655BFA24EB16831940030C6D370297C0237485CAFC86C21297EE1A818880308D7D80F3B920B16FE21DF2F3ABB900DF518D7580F810CD33E7FED1168D7604E2F92175128B06194DA6ECED078D7F17F473181911C9600933C441290CD5BB0A5B5B59F033E476B05505E00CEDAA9BBDB266E03AA5D908A6BFB960DDDFFCDD4FE0C64580018BA98F7EF05D0C81C379B981A849B1BE07D84150F8510851FC8DAB8360115F547B8D626FADBB1D508D3B50E874D3815240D3E0BF6563F02203740F9908199BBB4B1961646306AE9B780C830627307DC7E63041B73BDB06F8410ECB8A369391B8D51A68A41F000B8278E2C406CE1F0926023676729008AA12F80C1A24446B4B22170E54206317F226F8C37EF45B18B8C3F8EF238B71C65E4E62F475F8F46A0514066C737F01CE04EB43EB3F3D310A1B1CB5D84CD837C2EBC60D2C5A839117A1C12C4468F7BBA5196AD2C86AD6616CDBD8288E2E33ED3CAD1D14C3999178FF733C02CA74D72E71A1A14402EBFC1C332275D4565858CA5D4F846D35570F06E6AC62895FE9BF454B183B480875278D1F30AABEC220586C3BEA0F2C3A0E186BD5E850C63826070017E40793C5F30C0262CC0D776B110D6F68081017F4FDDD58B2C77568040110976256A3D8B3C4B2CC11D3D23DE2DB4636F677FC57FB571F34102048BC03A1088DA3ADD5456CD8C2BE227A30C3A3B18D922A9B1C2C6A9BDB095B62106E38E18B5E12C37BD86CB0403753132F6E56A573B367B10FBC59A8EE97CD409E848530675464A1183064849F924030C31A2C72E1248313F88D1DCF6C125B166CECFC53EC531BB519E4027936286BC0D263936C0F6A245FD4C70B24B15766738C09E89B4A2C585392A89C53325426816407AA7E5111040C8D9913E810EF52A937B527344930AA660C5E017648727CC960E3F07304ADA50B27ACDB8F2D60F0B5833EAF15107A641F05D019EBCCCBACDD2578763D4FA9744A4A0FFC0618E9E3147A6517C1293AECB517D9F88B122E0146336C2CD67D7C5224760B1D0E08506FC8096E7ACA96504FB6B1B1463FD3A6521911F424E1FC5A0142A91AD9A722EC3EEE6B18B26B1C3D7DB1D75EAFFC8D7531831C8535BF8E68EB803FAA5219367958D984534FBE3C1B690664B0B03CCC09209966A401B44050C83336C9ECA29D0004D88465B109215A244576CF58C96AF0346AF4AE9D3DB360BC0E3989C005A9247508F153A7A564036F644553F675A3D4253BAC3956120C5AEBE66EC682D922722568F4C058B36FD730DAEDB57D14450DAA0BD716168151969EAE69921D76C8D85E08626E130C9C11C00D07C160C7846481EDFF72C8A1BDE3DF9F813C18DEADBEEF980340EBF2C631F9EC4E04136DA456A4A1FC8EAC7E73C8C1E0068BD82373CCBB46C6DE01B16A1630408086A44CB2810B2C2F3616500A17F3DE5F0BAB8EAEA556561FFBE5B2F6150A374D358D83E6070A67B303593A5A56223D5A89E4C8254EB60FE492B3D95E56223D5E4FD9EC447286176256223D223972C96250561FB9E46C766656223D6641363B911C26276A56223D488E5C726A51F62E72362B90C7223D6E9D488E5C52C6367256472E399B223D724B963E9CCD4E247656223D7627922397537E427A56964BCE66223D7A545890672269727E72CCA759E47E0AC8A912678203C11A01B23557FBC2E08A53D968243106BE91ACB86472A8C319698152773D833C038C907C420BB3345B061008091C095EE251887010EBDE251B5A160CE0FD66B80904A10B9566ABE74C161266A4D19EE614ECA72DE3F8DC0F84A129461DF421D89E3DE828139F83DA062D4FEEF350ECD3AEFCF6EB6399F833D285D255B390DB6BFDC90530940107A842EB14BB162E2CC12B8B1BD4CB4D33C9192BFFAE400830040E4183F9080E04AC5F713904576A57014C7042E2C8681122C63664F381D8ED9E70B470B8182C883DA58E0EFFE62C080B5B180C256C469348D2C1B408AC1CEC840704300A44AA0EBBB6044381DC0C4BA62EEA1D487CDA4AE10E58D4DC194871F43A5F5DB37064FBF086F034798B83C9A26B096057B0571E7F83172666FD47FE5CFA66C704475C00D565F15702444702D9EB3D62598B151A11EA0B3531B614F06592BA0E46348A5D3932DAC81B1A386C90410C03802C26E0B1CCCD19502B1B035C4379AA3ACD09D534968523BBEB6953CCECBFEC511DB68B27C8F4CB75EC39326FD94ED2820BEB1E27F41821E12E7548293B02750759AC12C23B9616FF57C6082997A5EC1C846C4EC80C6D026D0630968DE46D06251CA43358A41AF84F9CD06CEBA91B5C107EDA562CE1F7C049A5AE83702B0CCB523367A364CD46000B08DD35AD8C91877A08E63C5798CC25C3AC9C86AD927DC615A3A3DC53E7CA217946B6431A1010E864489E911414F0183891906718F8A44D6148561EEBA0D3363ACC9DD08BC8C45110BA36D092BA42CE140510960626A37C49D0736C658C67F0524156E89E609103 }
   
    condition:

        $pattern_0 or $pattern_1 and filesize < 5831344
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EventViewer {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using eventvwr.exe"
        author = "ditekSHen"
        threat = "BehavesLike:UACBypass/Evenvwr"
    strings:
        $s1 = "\\Classes\\mscfile\\shell\\open\\command" ascii wide nocase
        $s2 = "eventvwr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CleanMgr {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using cleanmgr.exe"
        author = "ditekSHen"
        threat = "BehavesLike:UACBypass/cleanmgr"
    strings:
        $s1 = "\\Enviroment\\windir" ascii wide nocase
        $s2 = "\\system32\\cleanmgr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_DisableWinDefender {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing artifcats associated with disabling Widnows Defender"
        threat = "BehavesLike:DefenderDisabler"
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
        $reg2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
        $s1 = "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true" ascii wide nocase
        $s2 = "Set-MpPreference -DisableArchiveScanning $true" ascii wide nocase
        $s3 = "Set-MpPreference -DisableIntrusionPreventionSystem $true" ascii wide nocase
        $s4 = "Set-MpPreference -DisableScriptScanning $true" ascii wide nocase
        $s5 = "Set-MpPreference -SubmitSamplesConsent 2" ascii wide nocase
        $s6 = "Set-MpPreference -MAPSReporting 0" ascii wide nocase
        $s7 = "Set-MpPreference -HighThreatDefaultAction 6" ascii wide nocase
        $s8 = "Set-MpPreference -ModerateThreatDefaultAction 6" ascii wide nocase
        $s9 = "Set-MpPreference -LowThreatDefaultAction 6" ascii wide nocase
        $s10 = "Set-MpPreference -SevereThreatDefaultAction 6" ascii wide nocase
        $s11 = "Set-MpPreference -EnableControlledFolderAccess Disabled" ascii wide nocase
        $pdb = "\\Disable-Windows-Defender\\obj\\Debug\\Disable-Windows-Defender.pdb" ascii
        $e1 = "Microsoft\\Windows Defender\\Exclusions\\Paths" ascii wide nocase
        $e2 = "Add-MpPreference -Exclusion" ascii wide nocase
        $c1 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($reg*) and 1 of ($s*)) or ($pdb) or all of ($e*) or #c1 > 1)
}

rule INDICATOR_SUSPICIOUS_AMSI_Bypass {
    meta:
        author = "ditekSHen"
        description = "Detects AMSI bypass pattern"
        threat = "BehavesLike:AMSIBypasser"
    strings:
        $v1_1 = "[Ref].Assembly.GetType(" ascii nocase
        $v1_2 = "System.Management.Automation.AmsiUtils" ascii
        $v1_3 = "GetField(" ascii nocase
        $v1_4 = "amsiInitFailed" ascii
        $v1_5 = "NonPublic,Static" ascii
        $v1_6 = "SetValue(" ascii nocase
    condition:
        5 of them and filesize < 2000KB
}

rule Windows_Trojan_Asyncrat_11a11ba1 {
    meta:
        author = "Elastic Security"
        id = "11a11ba1-c178-4415-9c09-45030b500f50"
        fingerprint = "715ede969076cd413cebdfcf0cdda44e3a6feb5343558f18e656f740883b41b8"
        creation_date = "2021-08-05"
        last_modified = "2021-10-04"
        threat = "Windows.Trojan.Asyncrat"
        reference_sample = "fe09cd1d13b87c5e970d3cbc1ebc02b1523c0a939f961fc02c1395707af1c6d1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" wide fullword
        $a2 = "Stub.exe" wide fullword
        $a3 = "get_ActivatePong" ascii fullword
        $a4 = "vmware" wide fullword
        $a5 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide fullword
        $a6 = "get_SslClient" ascii fullword
    condition:
        all of them
}

rule RANSOM_Exorcist
{
    meta:
       
        description = "Rule to detect Exorcist"
        author = "McAfee ATR Team"
        date = "2020-09-01"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransomware:W32/Exorcist"
        actor_type = "Cybercrime"
        hash1 = "793dcc731fa2c6f7406fd52c7ac43926ac23e39badce09677128cce0192e19b0"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
    
    strings:

        $sq1 = { 48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 55 41 56 41 57 48 8D 68 A1 48 81 EC 90 00 00 00 49 8B F1 49 8B F8 4C 8B FA 48 8B D9 E8 ?? ?? ?? ?? 45 33 E4 85 C0 0F 85 B1 00 00 00 48 8B D7 48 8B CB E8 9E 02 00 00 85 C0 0F 85 9E 00 00 00 33 D2 48 8B CB E8 ?? ?? ?? ?? 45 33 C0 48 8D 15 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 45 8D 44 24 01 48 8B D7 48 8B C8 E8 ?? ?? ?? ?? 48 8B D0 48 8B CB 48 8B F8 FF 15 ?? ?? ?? ?? 4C 89 64 24 30 45 33 C9 C7 44 24 28 80 00 00 E8 45 33 C0 BA 00 00 00 C0 C7 44 24 20 03 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 4C 8B F0 48 8D 48 FF 48 83 F9 FD 77 25 48 8D 55 2F 48 8B C8 FF 15 ?? ?? ?? ?? 4C 39 65 2F 75 3B 49 8B CE FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? 48 8B CF E8 ?? ?? ?? ?? 4C 8D 9C 24 90 00 00 00 49 8B 5B 20 49 8B 73 28 49 8B 7B 30 4D 8B 63 38 49 8B E3 41 5F 41 5E 5D C3 48 8D 45 FB 4C 89 65 1F 4C 8D 4D FF 48 89 44 24 20 4C 8B C6 4C 89 65 07 48 8D 55 07 4C 89 65 FF 48 8D 4D 1F 44 89 65 FB E8 ?? ?? ?? ?? 45 33 C9 4C 8D 05 3C F5 FF FF 49 8B D7 49 8B CE FF 15 ?? ?? ?? ?? 48 8D 55 17 49 8B CE FF 15 ?? ?? ?? ?? 49 8B CE 44 89 65 F7 E8 ?? ?? ?? ?? 49 8B F4 4C 89 65 0F 4C 39 65 17 0F 8E 9D 00 00 00 C1 E0 10 44 8B F8 F0 FF 45 F7 B9 50 00 00 00 E8 ?? ?? ?? ?? 8B 4D 13 48 8B D8 89 48 14 89 70 10 4C 89 60 18 44 89 60 28 4C 89 70 30 48 8B 4D 07 48 89 48 48 48 8D 45 F7 B9 00 00 01 00 48 89 43 40 E8 ?? ?? ?? ?? 33 D2 48 89 43 20 41 B8 00 00 01 00 48 8B C8 E8 ?? ?? ?? ?? 48 8B 53 20 4C 8D 4B 38 41 B8 00 00 01 00 48 89 5C 24 20 49 8B CE FF 15 ?? ?? ?? ?? EB 08 33 C9 FF 15 ?? ?? ?? ?? 8B 45 F7 3D E8 03 00 00 77 EE 49 03 F7 48 89 75 0F 48 3B 75 17 0F 8C 6B FF FF FF EB 03 8B 45 F7 85 C0 74 0E 33 C9 FF 15 ?? ?? ?? ?? 44 39 65 F7 77 F2 48 8B 4D 07 E8 ?? ?? ?? ?? 48 8B 4D 1F 33 D2 E8 ?? ?? ?? ?? 49 8B CE FF 15 ?? ?? ?? ?? 4C 89 64 24 30 45 33 C9 C7 44 24 28 80 00 00 00 45 33 C0 BA 00 00 00 C0 C7 44 24 20 03 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 48 8B D8 48 8D 48 FF 48 83 F9 FD 77 51 48 8D 55 37 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B 55 37 45 33 C9 45 33 C0 48 8B CB FF 15 ?? ?? ?? ?? 44 8B 45 FB 4C 8D 4D 27 48 8B 55 FF 48 8B CB 4C 89 64 24 20 FF 15 ?? ?? ?? ?? 48 8B 4D FF E8 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? E9 14 FE FF FF 48 8B CF E8 ?? ?? ?? ?? 48 8B 4D FF E9 06 FE FF FF }          
        $sq2 = { 48 8B C4 48 81 EC 38 01 00 00 48 8D 50 08 C7 40 08 04 01 00 00 48 8D 4C 24 20 FF 15 ?? ?? ?? ?? 48 8D 4C 24 20 E8 ?? ?? ?? ?? 48 81 C4 38 01 00 00 C3 } 

    condition:

        uint16(0) == 0x5a4d and
         any of them 
}

rule crime_ransomware_windows_GPGQwerty

{
	meta:

		description = "Detect GPGQwerty ransomware"
		author = "McAfee Labs"
		date = "2018-03-21"
		rule_version = "v1"
	    malware_type = "ransomware"
	    malware_family = "Ransom:W32/GPGQwerty"
	    actor_type = "Cybercrime"
	    actor_group = "Unknown"	
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/"
		
	strings:

		$a = "gpg.exe –recipient qwerty  -o"
		$b = "%s%s.%d.qwerty"
		$c = "del /Q /F /S %s$recycle.bin"
		$d = "cryz1@protonmail.com"

	condition:

		all of them
}

rule jeff_dev_ransomware {

   meta:
   
      description = "Rule to detect Jeff Dev Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-08-26"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Jeff"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
      hash = "386d4617046790f7f1fcf37505be4ffe51d165ba7cbd42324aed723288ca7e0a"
      
   strings:

      $s1 = "C:\\Users\\Umut\\Desktop\\takemeon" fullword wide
      $s2 = "C:\\Users\\Umut\\Desktop\\" fullword ascii
      $s3 = "PRESS HERE TO STOP THIS CREEPY SOUND AND VIEW WHAT HAPPENED TO YOUR COMPUTER" fullword wide
      $s4 = "WHAT YOU DO TO MY COMPUTER??!??!!!" fullword wide

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 5000KB ) and
      all of them
}

rule ransom_Linux_HelloKitty_0721 {
   meta:
      description = "rule to detect Linux variant of the Hello Kitty Ransomware"
      author = "Christiaan @ ATR"
      date = "2021-07-19"
      Rule_Version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:Linux/HelloKitty"
      hash1 = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
      hash2 = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"

   strings:
      $v1 = "esxcli vm process kill -t=force -w=%d" fullword ascii
      $v2 = "esxcli vm process kill -t=hard -w=%d" fullword ascii
      $v3 = "esxcli vm process kill -t=soft -w=%d" fullword ascii
      $v4 = "error encrypt: %s rename back:%s" fullword ascii
      $v5 = "esxcli vm process list" fullword ascii
      $v6 = "Total VM run on host:" fullword ascii
      $v7 = "error lock_exclusively:%s owner pid:%d" fullword ascii
      $v8 = "Error open %s in try_lock_exclusively" fullword ascii
      $v9 = "Mode:%d  Verbose:%d Daemon:%d AESNI:%d RDRAND:%d " fullword ascii
      $v10 = "pthread_cond_signal() error" fullword ascii
      $v11 = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>" fullword ascii

   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule locdoor_ransomware {

   meta:

      description = "Rule to detect Locdoor/DryCry"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-09-02"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Locdoor"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://twitter.com/leotpsc/status/1036180615744376832"     
      hash = "0000c55f7cdbbad9bacba0e79637696f3bfeb95a5f71dfa0b398bc77a207eb41"

   strings:

      $s1 = "copy \"Locdoor.exe\" \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\temp00000000.exe\"" fullword ascii
      $s2 = "copy wscript.vbs C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\wscript.vbs" fullword ascii
      $s3 = "!! Your computer's important files have been encrypted! Your computer's important files have been encrypted!" fullword ascii
      $s4 = "echo CreateObject(\"SAPI.SpVoice\").Speak \"Your computer's important files have been encrypted! " fullword ascii    
      $s5 = "! Your computer's important files have been encrypted! " fullword ascii
      $s7 = "This program is not supported on your operating system." fullword ascii
      $s8 = "echo Your computer's files have been encrypted to Locdoor Ransomware! To make a recovery go to localbitcoins.com and create a wa" ascii
      $s9 = "Please enter the password." fullword ascii

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 600KB ) and
      all of them 
}

rule Lockbit2_Jul21 {
   meta:
      description = "simple rule to detect latest Lockbit ransomware Jul 2021"
      author = "CB @ ATR"
      date = "2021-07-28"
      version = "v1"
      threat = "Ransom:Win32/Lockbit"
      hash1 = "f32e9fb8b1ea73f0a71f3edaebb7f2b242e72d2a4826d6b2744ad3d830671202"
      hash2 = "dd8fe3966ab4d2d6215c63b3ac7abf4673d9c19f2d9f35a6bf247922c642ec2d"

   strings:
      $seq1 = " /C ping 127.0.0.7 -n 3 > Nul & fsutil file setZeroData offset=0 length=524288 \"%s\" & Del /f /q \"%s\"" fullword wide
      $seq2 = "\"C:\\Windows\\system32\\mshta.exe\" \"%s\"" fullword wide
      $p1 = "C:\\windows\\system32\\%X%X%X.ico" fullword wide
      $p2 = "\\??\\C:\\windows\\system32\\%X%X%X.ico" fullword wide
      $p3 = "\\Registry\\Machine\\Software\\Classes\\Lockbit\\shell\\Open\\Command" fullword wide
      $p4 = "use ToxID: 3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" fullword wide
      $p5 = "https://tox.chat/download.html" fullword wide
      $p6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration" fullword wide
      $p7 = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" fullword wide
      $p8 = "\\LockBit_Ransomware.hta" fullword wide
     
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($seq*) and 4 of them )
      ) or ( all of them )
}

rule LockerGogaRansomware {
   
   meta:

      description = "LockerGoga Ransomware"
      author = "Christiaan Beek - McAfee ATR team"
      date = "2019-03-20"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/LockerGoga"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash = "ba15c27f26265f4b063b65654e9d7c248d0d651919fafb68cb4765d1e057f93f"

   strings:

      $1 = "boost::interprocess::spin_recursive_mutex recursive lock overflow" fullword ascii
      $2 = ".?AU?$error_info_injector@Usync_queue_is_closed@concurrent@boost@@@exception_detail@boost@@" fullword ascii
      $3 = ".?AV?$CipherModeFinalTemplate_CipherHolder@V?$BlockCipherFinal@$00VDec@RC6@CryptoPP@@@CryptoPP@@VCBC_Decryption@2@@CryptoPP@@" fullword ascii
      $4 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $5 = "cipher.exe" fullword ascii
      $6 = ".?AU?$placement_destroy@Utrace_queue@@@ipcdetail@interprocess@boost@@" fullword ascii
      $7 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $8 = "CreateProcess failed" fullword ascii
      $9 = "boost::dll::shared_library::load() failed" fullword ascii
      $op1 = { 8b df 83 cb 0f 81 fb ff ff ff 7f 76 07 bb ff ff }
      $op2 = { 8b df 83 cb 0f 81 fb ff ff ff 7f 76 07 bb ff ff }

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 2000KB and
      ( 6 of them ) and
      all of ($op*)) or
      ( all of them )
}

rule loocipher_ransomware {

   meta:

      description = "Rule to detect Loocipher ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-12-05"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Loocipher"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/analysis-of-loocipher-a-new-ransomware-family-observed-this-year/"
      hash = "7720aa6eb206e589493e440fec8690ceef9e70b5e6712a9fec9208c03cac7ff0"
      
   strings:

      $x1 = "c:\\users\\usuario\\desktop\\cryptolib\\gfpcrypt.h" fullword ascii
      $x2 = "c:\\users\\usuario\\desktop\\cryptolib\\eccrypto.h" fullword ascii
      $s3 = "c:\\users\\usuario\\desktop\\cryptolib\\gf2n.h" fullword ascii
      $s4 = "c:\\users\\usuario\\desktop\\cryptolib\\queue.h" fullword ascii
      $s5 = "ThreadUserTimer: GetThreadTimes failed with error " fullword ascii
      $s6 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::operator *" fullword wide
      $s7 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::operator +=" fullword wide
      $s8 = "std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class std::allocator<unsigned short> >::operator []" fullword wide
      $s9 = "std::vector<struct CryptoPP::ProjectivePoint,class std::allocator<struct CryptoPP::ProjectivePoint> >::operator []" fullword wide
      $s10 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::operator *" fullword wide
      $s11 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::operator +=" fullword wide
      $s12 = "std::vector<struct CryptoPP::WindowSlider,class std::allocator<struct CryptoPP::WindowSlider> >::operator []" fullword wide
      $s13 = "std::istreambuf_iterator<char,struct std::char_traits<char> >::operator ++" fullword wide
      $s14 = "std::istreambuf_iterator<char,struct std::char_traits<char> >::operator *" fullword wide
      $s15 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::_Compat" fullword wide
      $s16 = "std::vector<class CryptoPP::PolynomialMod2,class std::allocator<class CryptoPP::PolynomialMod2> >::operator []" fullword wide
      $s17 = "DL_ElgamalLikeSignatureAlgorithm: this signature scheme does not support message recovery" fullword ascii
      $s18 = "std::vector<struct CryptoPP::ECPPoint,class std::allocator<struct CryptoPP::ECPPoint> >::operator []" fullword wide
      $s19 = "std::vector<struct CryptoPP::EC2NPoint,class std::allocator<struct CryptoPP::EC2NPoint> >::operator []" fullword wide
      $s20 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::_Compat" fullword wide

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 17000KB and
      ( 1 of ($x*) and
      4 of them ) ) or
      ( all of them )
}

rule RANSOM_makop
{
    meta:
    
        description = "Rule to detect the unpacked Makop ransomware samples"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-07-19"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/Makop"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash = "008e4c327875110b96deef1dd8ef65cefa201fef60ca1cbb9ab51b5304e66fe1"
    
    strings:

        $pattern_0 = { 50 8d7c2420 e8???????? 84c0 0f84a6020000 8b742460 ba???????? }
        $pattern_1 = { 51 52 53 ffd5 85c0 746d 8b4c240c }
        $pattern_2 = { 7521 68000000f0 6a18 6a00 6a00 56 ff15???????? }
        $pattern_3 = { 83c40c 8d4e0c 51 66c7060802 66c746041066 c6460820 }
        $pattern_4 = { 51 ffd3 50 ffd7 8b4628 85c0 }
        $pattern_5 = { 85c9 741e 8b4508 8b4d0c 8a11 }
        $pattern_6 = { 83c002 6685c9 75f5 2bc6 d1f8 66390c46 8d3446 }
        $pattern_7 = { 895a2c 8b7f04 85ff 0f85f7feffff 55 6a00 }
        $pattern_8 = { 8b3d???????? 6a01 6a00 ffd7 50 ff15???????? }
        $pattern_9 = { 85c0 7407 50 ff15???????? }
   
    condition:

        7 of them and
        filesize < 237568
}

rule Ransom_Maze {
   
   meta:
   
      description = "Detecting MAZE Ransomware"
      author = "McAfee ATR"
      date = "2020-04-19"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Maze"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash = "5badaf28bde6dcf77448b919e2290f95cd8d4e709ef2d699aae21f7bae68a76c"

   strings:

      $x1 = "process call create \"cmd /c start %s\"" fullword wide
      $s1 = "%spagefile.sys" fullword wide
      $s2 = "%sswapfile.sys" fullword wide
      $s3 = "%shiberfil.sys" fullword wide
      $s4 = "\\wbem\\wmic.exe" fullword wide
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko" fullword ascii
      $s6 = "NO MUTEX | " fullword wide
      $s7 = "--nomutex" fullword wide
      $s8 = ".Logging enabled | Maze" fullword wide
      $s9 = "DECRYPT-FILES.txt" fullword wide

      $op0 = { 85 db 0f 85 07 ff ff ff 31 c0 44 44 44 44 5e 5f }
      $op1 = { 66 90 89 df 39 ef 89 fb 0f 85 64 ff ff ff eb 5a }
      $op2 = { 56 e8 34 ca ff ff 83 c4 08 55 e8 0b ca ff ff 83 }

   condition:
      ( uint16(0) == 0x5a4d and
      filesize < 500KB and
      ( 1 of ($x*) and
      4 of them ) and
      all of ($op*)) or
      ( all of them )
}

rule megacortex_signed {

    meta:

        description = "Rule to detect MegaCortex samples digitally signed"
        author = "Marc Rivero | McAfee ATR Team"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/MegaCortex"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://blog.malwarebytes.com/detections/ransom-megacortex/"
        
    condition:

      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "/C=GB/L=ROMFORD/O=3AN LIMITED/CN=3AN LIMITED"  and
         pe.signatures[i].serial == "04:c7:cd:cc:16:98:e2:5b:49:3e:b4:33:8d:5e:2f:8b" or
         pe.signatures[i].subject contains "/C=GB/postalCode=RM6 4DE/ST=ROMFORD/L=ROMFORD/street=8 Quarles Park Road/O=3AN LIMITED/CN=3AN LIMITED"  and
         pe.signatures[i].serial == "53:cc:4c:69:e5:6a:7d:bc:36:67:d5:ff:d5:24:aa:4b" or
         pe.signatures[i].subject contains "/C=GB/postalCode=RM6 4DE/ST=ROMFORD/L=ROMFORD/street=8 Quarles Park Road/O=3AN LIMITED/CN=3AN LIMITED" or
         pe.signatures[i].serial == "00:ad:72:9a:65:f1:78:47:ac:b8:f8:49:6a:76:80:ff:1e")
}

rule ransom_mespinoza {
   meta:
      description = "rule to detect Mespinoza ransomware"
      author = "Christiaan Beek @ McAfee ATR"
      date = "2020-11-24"
      malware_family = "Ransom:W32/Mespinoza"
      hash1 = "e9662b468135f758a9487a1be50159ef57f3050b753de2915763b4ed78839ead"
      hash2 = "48355bd2a57d92e017bdada911a4b31aa7225c0b12231c9cbda6717616abaea3"
      hash3 = "e4287e9708a73ce6a9b7a3e7c72462b01f7cc3c595d972cf2984185ac1a3a4a8"
  
   strings:
      $s1 = "update.bat" fullword ascii
      $s2 = "protonmail.com" fullword ascii
      $s3 = "Every byte on any types of your devices was encrypted." fullword ascii
      $s4 = "To get all your data back contact us:" fullword ascii
      $s5 = "What to do to get all data back?" fullword ascii
      $s6 = "Don't try to use backups because it were encrypted too." fullword ascii

      $op0 = { 83 f8 4b 75 9e 0f be 46 ff 8d 4d e0 ff 34 85 50 }
      $op1 = { c6 05 34 9b 47 00 00 e8 1f 0c 03 00 59 c3 cc cc }
      $op2 = { e8 ef c5 fe ff b8 ff ff ff 7f eb 76 8b 4d 0c 85 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and pe.imphash() == "b5e8bd2552848bb7bf2f28228d014742" and ( 8 of them ) and 2 of ($op*)
      ) or ( all of them )
}

rule ransom_monglock {
   
   meta:

      description = "Ransomware encrypting Mongo Databases "
      author = "Christiaan Beek - McAfee ATR team"
      date = "2019-04-25"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/MongLock"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash5 = "c4de2d485ec862b308d00face6b98a7801ce4329a8fc10c63cf695af537194a8"

   strings:

      $x1 = "C:\\Windows\\system32\\cmd.exe" fullword wide
      $s1 = "and a Proof of Payment together will be ignored. We will drop the backup after 24 hours. You are welcome! " fullword ascii
      $s2 = "Your File and DataBase is downloaded and backed up on our secured servers. To recover your lost data : Send 0.1 BTC to our BitCoin" ascii
      $s3 = "No valid port number in connect to host string (%s)" fullword ascii
      $s4 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii
      $s5 = "# https://curl.haxx.se/docs/http-cookies.html" fullword ascii
      $s6 = "Connection closure while negotiating auth (HTTP 1.0?)" fullword ascii
      $s7 = "detail may be available in the Windows System event log." fullword ascii
      $s8 = "Found bundle for host %s: %p [%s]" fullword ascii
      $s9 = "No valid port number in proxy string (%s)" fullword ascii


      $op0 = { 50 8d 85 78 f6 ff ff 50 ff b5 70 f6 ff ff ff 15 }
      $op1 = { 83 fb 01 75 45 83 7e 14 08 72 34 8b 0e 66 8b 45 }
      $op2 = { c7 41 0c df ff ff ff c7 41 10 }

   condition:
      ( uint16(0) == 0x5a4d and
      filesize < 2000KB and
      ( 1 of ($x*) and
      4 of them ) and
      all of ($op*)
      ) or
      ( all of them )
}

rule RANSOM_mountlocker
{
   meta:

      description = "Rule to detect Mount Locker ransomware"
      author = "McAfee ATR Team"
      date = "2020-09-25"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransomware:W32/MountLocker"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash1 = "4b917b60f4df6d6d08e895d179a22dcb7c38c6a6a6f39c96c3ded10368d86273"
      hash2 = "f570d5b17671e6f3e56eae6ad87be3a6bbfac46c677e478618afd9f59bf35963"
    
    strings:

        $s1 = {63 69 64 3d 25 43 4c 49 45 4e 54 5f 49 44}
        $s2 = {7a 73 61 33 77 78 76 62 62 37 67 76 36 35 77 6e 6c 37 6c 65 72 73 6c 65 65 33 63 37 69 32 37 6e 64 71 67 68 71 6d 36 6a 74 32 70 72 69 76 61 32 71 63 64 70 6f 6e 61 64 2e 6f 6e 69 6f 6e}
        $s3 = {36 6d 6c 7a 61 68 6b 63 37 76 65 6a 79 74 70 70 62 71 68 71 6a 6f 75 34 69 70 66 74 67 73 33 67 69 7a 6f 66 32 78 34 7a 6b 6c 62 6c 6c 69 61 79 68 73 71 62 33 77 61 64 2e 6f 6e 69 6f 6e}


    condition:

        uint16(0) == 0x5a4d and
        filesize < 300KB and
        ($s1 and
        $s2) or
        ($s1 and
        $s3) or
        $s1 
}

rule nefilim_ransomware {

   meta:

      description = "Rule to detect Nefilim ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-03-17"
      last_update = "2020-04-03"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Nefilim"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.bleepingcomputer.com/news/security/new-nefilim-ransomware-threatens-to-release-victims-data/"
      hash = "5ab834f599c6ad35fcd0a168d93c52c399c6de7d1c20f33e25cb1fdb25aec9c6"

   strings:

      $s1 = "C:\\Users\\Administrator\\Desktop\\New folder\\Release\\NEFILIM.pdb" fullword ascii
      $s2 = "oh how i did it??? bypass sofos hah" fullword ascii
      $s3 = " /c timeout /t 3 /nobreak && del \"" fullword wide
      $s4 = "NEFILIM-DECRYPT.txt" fullword wide

      $op0 = { db ff ff ff 55 8b ec 83 ec 24 53 56 57 89 55 f4 }
      $op1 = { 60 be 00 d0 40 00 8d be 00 40 ff ff 57 eb 0b 90 }
      $op2 = { 84 e0 40 00 90 d1 40 00 08 }

      /*

      BYTES:

      558BEC83EC245356578955F4294DF46A048D72038D79015A8BC78955DC8A5EFD8858FF8B5DF48A1C0388188A5EFF8858018A1E88580203F203C2FF4DDC75DE8955F48D51038D42108D59028945F8894DF0297DF0895DEC297DEC8955E8297DE88D470C8D7902894DE4297DE48955DC297DDC8B7DF8894DE02955E08D7102F645F4038B5DEC8A1C038B4DF08A14018A08885DFA8B5DE88A1C03885DFB753B0FB6DB8A9B803040000FB6C98855FF8A91803040000FB64DFA8A8980304000885DFA0FB65DFF8A9B80304000885DFB8B5DF4C1EB023293803240008B5DE48A1C3332DA8B55E0881C178A50F432D18850048A0E324DFA83C004884E108B4DDC8A0C31324DFBFF45F4880F83C60483C704837DF42C0F8266FFFFFF5F5E5BC9C3558BEC560FB6C057C1E0040345086A045F6A045E8A10301140414E75F74F75F15F5E5DC356576A045F6A048BC15E0FB6108A9280304000881083C0044E75EF414F75E65F5EC38A50058A48018850018A50098850058A500D8850098A500A88480D8A48028850028A500E88480A8A48068850068A500F88480E8A48038850038A500B88500F8A500788500B884807C3558BEC5153566A0483C1025E8A410132018A51FE8A59FF8845FD32C232C38845FF8855FE32D38AC2C0E807B31BF6EB02D232C23245FE8A51FF3245FF32118841FE8AC2C0E807F6EB02D232C23241FF8A55FD3245FF8841FF8AC2C0E807F6EB02D232C232018A51013245FF3255FE88018AC2C0E807F6EB02D232C232410183C1043245FF4E8841FD75825E5BC9C3558BEC53FF75088BCE32C0E8D3FEFFFF59B3018BCEE8EDFEFFFF8BC6E808FFFFFF8BCEE84AFFFFFFFF75088BCE8AC3E8AFFEFFFFFEC35980FB0A72D78BCEE8C4FEFFFF8BC6E8DFFEFFFF5B8BCEB00A5DE98EFEFFFF558BEC81ECC000000053568D8D40FFFFFFE85BFDFFFF33DB6A1059395D0C764D5783F91075358B75108D7DF0A5A5A58D8540FFFFFFA5508D75F0E86CFFFFFF596A0F588B4D108D1408803AFF750848C6020079EFEB03FE040833C98A540DF08B450830141843413B5D0C72B55F8B45148B4D106A102BC85E8A14018810404E75F75E5BC9C3558BEC81EC1C02000053FF75088D85E4FDFFFF50FF155C304000688C3240008D85E4FDFFFF50FF155030400033DB53536A02535368000000408D85E4FDFFFF50FF15343040008945F03BC30F849600000056578D45FC5053BE6038400056895DFCFF15083040005056E8C809000083C41085C0750753FF1500304000FF75FC8B3D2430400053FFD750FF15103040008D4DFC5150568945F8FF15083040005056E89109000083C41085C074C98B45FC8945F48D45F450FF75F8E8C909000059595385C074B18D45EC50FF75FCFF75F8FF75F0FF1528304000FF75F853FFD750FF15183040005F5E5BC9C3558BEC83E4F881EC64060000535657FF75088D84246C04000050FF155C3040008B1D5030400068B83240008D84246C04000050FFD38D442410508D84246C04000050FF15043040008944240C83F8FF0F84580300008B354C30400068C03240008D44244050FFD685C00F841D03000068C43240008D44244050FFD685C00F840903000068CC3240008D44244050FFD685C00F84F502000068D43240008D44244050FFD685C00F84E102000068E43240008D44244050FFD685C00F84CD02000068003340008D44244050FFD685C00F84B902000068083340008D44244050FFD685C00F84A502000068103340008D44244050FFD685C00F8491020000682C3340008D44244050FFD685C00F847D02000068383340008D44244050FFD685C00F8469020000684C3340008D44244050FFD685C00F8455020000685C3340008D44244050FFD685C00F844102000068703340008D44244050FFD685C00F842D020000688C3340008D44244050FFD685C00F841902000068A43340008D44244050FFD685C00F840502000068BC3340008D44244050FFD685C00F84F101000068D43340008D44244050FFD685C00F84DD01000068E83340008D44244050FFD685C00F84C901000068043440008D44244050FFD685C00F84B501000068143440008D44244050FFD685C00F84A1010000682C3440008D44244050FFD685C00F848D010000683C3440008D44244050FFD685C00F847901000068583440008D44244050FFD685C00F8465010000F644241010FF75088D842464020000507436FF155C3040008D44243C508D84246402000050FFD368803440008D84246402000050FFD38D84246002000050E896FDFFFFE91C010000FF155C3040008D44243C508D84246402000050FFD38D44243C50E8F60500008BF8C704248434400057FFD685C00F84EA000000689034400057FFD685C00F84DA000000689C34400057FFD685C00F84CA00000068A834400057FFD685C00F84BA00000068B434400057FFD685C00F84AA00000068C034400057FFD685C00F849A00000068CC34400057FFD685C00F848A00000068D834400057FFD685C0747E68E434400057FFD685C0747268F034400057FFD685C0746668FC34400057FFD685C0745A680835400057FFD685C0744E681435400057FFD685C07442682035400057FFD685C07436683435400057FFD685C0742A684035400057FFD685C0741E688C3240008D44244050FFD685C0740E8D84246002000050E829000000598D44241050FF742410FF155430400085C00F85B8FCFFFFFF74240CFF15483040005F5E5B8BE55DC3558BEC81EC4802000053565768843F4000FF15083040008B35243040005033FF57FFD68B1D1030400050FFD368843F40008945E8FF15083040008945F4B8843F4000397DF474138B4DE82BC88A10FF4DF488140140397DF475F257576A03575768000000C0FF7508FF15343040008945F83BC70F845F0300008D4DDC5150FF15383040006A1057FFD650FFD36A10578945F4FFD650FFD3FF75F48945F0E8B2040000FF75F0E8AA0400005959680001000057FFD650FFD36800010000578945CCFFD650FFD3FF75CC8B55F48945C8E8990E0000FF75C88B55F0E88E0E00008B1D1430400059595757FF75E0FF75DCFF75F8FFD357FF1540304000578D45D0506800010000FF75CCFF75F8FF1528304000FF153C30400083F8060F84B9020000FF153C30400083F8130F84AA0200008B45DC8B4DE05705000100005713CF5150FF75F8FFD3578D45D0506800010000FF75C8FF75F8FF15283040008B45DC8B4DE05705000200005713CF5150FF75F8FFD3578D45D05068843F4000FF150830400050FF75E8FF75F8FF15283040008B45E08B4DDC3BC70F8C660100007F0C81F90090D0030F86E5000000897DD4897DD83BC70F8CBC0100007F0D3BCF0F86B2010000EB038B4DDC2B4DD41B45D88945E80F889E0100007F0C81F990D003000F82900100006848E8010057FFD650FF15103040005757FF75D88945E8FF75D4FF75F8FFD3578D45C4506848E80100FF75E8FF75F8FF1530304000FF75F08B55F4FF75F06848E80100FF75E8E8AFF8FFFF83C4105757FF75D8FF75D4FF75F8FFD3578D45D0506848E80100FF75E8FF75F8FF1528304000FFD6FF75E85750FF15183040008145D490D003008B45E0117DD83945D80F8C4CFFFFFF0F8FF60000008B4DDC394DD40F823DFFFFFFE9E50000003BC77C6F7F0881F9804F1200766568C027090057FFD650FF1510304000575733C98945E85133C050FF75F8FFD3578D45C45068C0270900FF75E8FF75F8FF1530304000FF75F08B55F4FF75F068C0270900FF75E8E8F6F7FFFF83C410575733C05050FF75F8FFD3578D45D05068C0270900EB595157FFD650FF1510304000575733C98945E85133C050FF75F8FFD3578D45C450FF75DCFF75E8FF75F8FF1530304000FF75F08B55F4FF75F0FF75DCFF75E8E899F7FFFF83C410575733C05050FF75F8FFD3578D45D050FF75DCFF75E8FF75F8FF1528304000FF75E857FFD650FF1518304000FF75F8FF1558304000FF75CC57FFD68B1D1830400050FFD3FF75C8

      */

      $bp = { 558B??83????53565789????29????6A??8D????8D????5A8B??89????8A????88????8B????8A????88??8A????88????8A??88????03??03??FF????75??89????8D????8D????8D????89????89????29????89????29????89????29????8D????8D????89????29????89????29????8B????89????29????8D????F6??????8B????8A????8B????8A????8A??88????8B????8A????88????75??0FB6??8A??????????0FB6??88????8A??????????0FB6????8A??????????88????0FB6????8A??????????88????8B????C1????32??????????8B????8A????32??8B????88????8A????32??88????8A??32????83????88????8B????8A????32????FF????88??83????83????83??????0F82????????5F5E5BC9C3558B??560FB6??57C1????03????6A??5F6A??5E8A??30??40414E75??4F75??5F5E5DC356576A??5F6A??8B??5E0FB6??8A??????????88??83????4E75??414F75??5F5EC38A????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????88????C3558B??5153566A??83????5E8A????32??8A????8A????88????32??32??88????88????32??8A??C0????B3??F6??02??32??32????8A????32????32??88????8A??C0????F6??02??32??32????8A????32????88????8A??C0????F6??02??32??32??8A????32????32????88??8A??C0????F6??02??32??32????83????32????4E88????75??5E5BC9C3558B??53FF????8B??32??E8????????59B3??8B??E8????????8B??E8????????8B??E8????????FF????8B??8A??E8????????FE??5980????72??8B??E8????????8B??E8????????5B8B??B0??5DE9????????558B??81??????????53568D??????????E8????????33??6A??5939????76??5783????75??8B????8D????A5A5A58D??????????A5508D????E8????????596A??588B????8D????80????75??48C6????79??EB??FE????33??8A??????8B????30????43413B????72??5F8B????8B????6A??2B??5E8A????88??404E75??5E5BC9C3558B??81??????????53FF????8D??????????50FF??????????68????????8D??????????50FF??????????33??53536A??535368????????8D??????????50FF??????????89????3B??0F84????????56578D????5053BE????????5689????FF??????????5056E8????????83????85??75??53FF??????????FF????8B??????????53FF??50FF??????????8D????51505689????FF??????????5056E8????????83????85??74??8B????89????8D????50FF????E8????????59595385??74??8D????50FF????FF????FF????FF??????????FF????53FF??50FF??????????5F5E5BC9C3558B??83????81??????????535657FF????8D????????????50FF??????????8B??????????68????????8D????????????50FF??8D??????508D????????????50FF??????????89??????83????0F84????????8B??????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????F6????????FF????8D????????????5074??FF??????????8D??????508D????????????50FF??68????????8D????????????50FF??8D????????????50E8????????E9????????FF??????????8D??????508D????????????50FF??8D??????50E8????????8B??C7????????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????8D??????50FF??85??74??8D????????????50E8????????598D??????50FF??????FF??????????85??0F85????????FF??????FF??????????5F5E5B8B??5DC3558B??81??????????53565768????????FF??????????8B??????????5033??57FF??8B??????????50FF??68????????89????FF??????????89????B8????????39????74??8B????2B??8A??FF????88????4039????75??57576A??575768????????FF????FF??????????89????3B??0F84????????8D????5150FF??????????6A??57FF??50FF??6A??5789????FF??50FF??FF????89????E8????????FF????E8????????595968????????57FF??50FF??68????????5789????FF??50FF??FF????8B????89????E8????????FF????8B????E8????????8B??????????59595757FF????FF????FF????FF??57FF??????????578D????5068????????FF????FF????FF??????????FF??????????83????0F84????????FF??????????83????0F84????????8B????8B????5705????????5713??5150FF????FF??578D????5068????????FF????FF????FF??????????8B????8B????5705????????5713??5150FF????FF??578D????5068????????FF??????????50FF????FF????FF??????????8B????8B????3B??0F8C????????7F??81??????????0F86????????89????89????3B??0F8C????????7F??3B??0F86????????EB??8B????2B????1B????89????0F88????????7F??81??????????0F82????????68????????57FF??50FF??????????5757FF????89????FF????FF????FF??578D????5068????????FF????FF????FF??????????FF????8B????FF????68????????FF????E8????????83????5757FF????FF????FF????FF??578D????5068????????FF????FF????FF??????????FF??FF????5750FF??????????81????????????8B????11????39????0F8C????????0F8F????????8B????39????0F82????????E9????????3B??7C??7F??81??????????76??68????????57FF??50FF??????????575733??89????5133??50FF????FF??578D????5068????????FF????FF????FF??????????FF????8B????FF????68????????FF????E8????????83????575733??5050FF????FF??578D????5068????????EB??5157FF??50FF??????????575733??89????5133??50FF????FF??578D????50FF????FF????FF????FF??????????FF????8B????FF????FF????FF????E8????????83????575733??5050FF????FF??578D????50FF????FF????FF????FF??????????FF????57FF??50FF??????????FF????FF??????????FF????57FF??8B??????????50FF??FF???? }

      
   condition:

      uint16(0) == 0x5a4d and
      filesize < 200KB and
      all of ($s*) or
      all of ($op*) or 
      $bp
}

rule nefilim_signed {

    meta:

        description = "Rule to detect Nefilim samples digitally signed"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-04-02"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/Nefilim"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://www.bleepingcomputer.com/news/security/new-nefilim-ransomware-threatens-to-release-victims-data/"
        hash = "353ee5805bc5c7a98fb5d522b15743055484dc47144535628d102a4098532cd5"
        
    condition:

      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "Red GmbH/CN=Red GmbH"  and
         pe.signatures[i].serial == "00:b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a" or
         pe.signatures[i].thumbprint == "5b:19:58:8b:78:74:0a:4c:5d:08:41:99:dc:0f:52:a6:1f:38:00:99")
}

rule RANSOM_nefilim_go
{
    meta:

        description = "Rule to detect the new Nefilim written in GO"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-07-13"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/Nefilim"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://www.bleepingcomputer.com/news/security/new-nefilim-ransomware-threatens-to-release-victims-data/"
        hash = "a51fec27e478a1908fc58c96eb14f3719608ed925f1b44eb67bbcc67bd4c4099"

    strings:

        $pattern = { FF20476F206275696C642049443A20226A744368374D37436A4A5732634C5F636633374A2F49625946794336635A64735F4D796A56633461642F486B6D36694A4D39327847785F4F2D65746744692F664E37434C43622D59716E374D795947565A686F220A20FFCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108766B83EC0CC744241400000000C7442418000000008B4424108400890424E88D0200008B44240485C0740789C183F8FF7514C744241400000000C74424180000000083C40CC3894C24088B44241083C004890424E8570200008B4424048B4C2408894C24148944241883C40CC3E8AE5A0400E979FFFFFFCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B61080F86EC00000083EC108B44241885C00F84C30000008B4424148400890424E8FD0100008B44240485C0742E89C183F8FF74E38B44241839C10F85800000008B44241C894424048B44241483C004890424E88B12000083C410C3E8620303008B442414890424C744240400000000C7442408FFFFFFFFE8A61200000FB644240C84C07507E868030300EB8B8B44241C894424048B4424148D4804890C24E83F1200008B442418894424048B442414890424E82B120000E83603030083C410C38D05408E4E008904248D05B8CC510089442404E8DA3F02000F0B8D05408E4E008904248D05B0CC510089442404E8C03F02000F0BE899590400E9F4FEFFFFCCCCCCCCE90B000000CCCCCCCCCCCCCCCCCCCCCC8B6C24048B4424088B4C240CF00FB14D000F94442410C3CCCCCCCCCCCCCCCCCCE9DBFFFFFFCCCCCCCCCCCCCCCCCCCCCC8B6C2404F7C50700000074068B05000000008B4424088B54240C8B5C24108B4C2414F00FC74D000F94442418C3CCCCCCE90B000000CCCCCCCCCCCCCCCCCCCCCC8B6C24048B44240889C1F00FC1450001C1894C240CC3CCCCCCCCCCCCCCCCCCCC8B6C2404F7C50700000074068B05000000008B7424088B7C240C8B45008B550489C389D101F311F9F00FC74D0075F1895C2410894C2414C3CCCCCCCCCCCCCCCC8B4424048B0089442408C3CCCCCCCCCC8B442404A90700000074068B05000000000F6F000F7F4424080F77C3CCCCCCCCE9CBFFFFFFCCCCCCCCCCCCCCCCCCCCCCE9BBFFFFFFCCCCCCCCCCCCCCCCCCCCCC8B6C24048B442408874500C3CCCCCCCCE9EBFFFFFFCCCCCCCCCCCCCCCCCCCCCC8B4424040FBCC074058944240CC38B4424080FBCC0740883C0208944240CC3C744240C40000000C3CCCCCCCCCCCCCCCC8B4424048B0089442408C3CCCCCCCCCC8B4424048B0089442408C3CCCCCCCCCC83EC208B4424248B088B54242889CB01D1894C241C8B6804890424895C2404896C2408894C240C8B5C242C11DD896C2418896C2410E8160100000FB644241484C074C08B44241C894424308B4424188944243483C420C3CCCCCCCCCCCCCCCCCC83EC208B4424248B08894C24188B50048954241C890424894C2404895424088B5C2428895C240C8B6C242C896C2410E8BC0000000FB644241484C074C68B442418894424308B44241C8944243483C420C3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC8B5C24048B4424088B4C240CF00FB10B0F94442410C3CCCCCCCCCCCCCCCCCCCCE9DBFFFFFFCCCCCCCCCCCCCCCCCCCCCCE9EBFEFFFFCCCCCCCCCCCCCCCCCCCCCCE9DBFEFFFFCCCCCCCCCCCCCCCCCCCCCCE9DB000000CCCCCCCCCCCCCCCCCCCCCCE97B000000CCCCCCCCCCCCCCCCCCCCCCE9CB000000CCCCCCCCCCCCCCCCCCCCCCE9BBFEFFFFCCCCCCCCCCCCCCCCCCCCCC8B6C2404F7C50700000074068B2D000000008B4424088B54240C8B5C24108B4C2414F00FC74D000F94442418C3CCCCCC8B5C24048B4424088B4C240CF00FB10B0F94442410C3CCCCCCCCCCCCCCCCCCCC8B5C24048B44240889C1F00FC10301C88944240CC3CCCCCCCCCCCCCCCCCCCCCC8B5C24048B44240887038944240CC3CCE9EBFFFFFFCCCCCCCCCCCCCCCCCCCCCC8B5C24048B4424088703C3CCCCCCCCCC8B5C24048B4424088703C3CCCCCCCCCC8B442404A90700000074068B05000000008D5C24080F6F000F7F030F77C3CCCC8B442404A90700000074068B05000000000F6F4424080F7F000F77B800000000F00FC10424C3CCCCCCCCCCCCCCCCCCCC8B4424048A5C2408F00818C3CCCCCCCC8B4424048A5C2408F02018C3CCCCCCCC648B0D140000008B89000000003B610876098B4424088944240CC3E860550400EBDECCCCCCCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108762B83EC108B4424148904248B44241889442404C744240801000000E8AF4400008B44240C8944241C83C410C3E80E550400EBBCCCCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108762B83EC108B4424148904248B44241889442404C744240802000000E85F4400008B44240C8944241C83C410C3E8BE540400EBBCCCCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108762B83EC108B4424148904248B44241889442404C744240810000000E80F4400008B44240C8944241C83C410C3E86E540400EBBCCCCCCCCCCCCCCCCCCCCCCCCC83EC108D42048B008B4C2414890C248B4C2418894C240489442408E8D04300008B44240C8944241C83C410C3CCCCCCCC648B0D140000008B89000000003B6108762C83EC108B4424148B088B400489442408890C248B44241889442404E88E4300008B44240C8944241C83C410C3E8ED530400EBBBCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B61080F86B600000083EC108B442414F30F10000F57C90F2EC175060F8B860000000F2EC075027B5B648B05140000008B80000000008B40188B88940000008B909800000089909400000089CBC1E11131D989D331CAC1E90731D189DAC1EB1031CB8998980000008D041A8B4C241831C835A98E7FAA69C0CD76BAC28944241C83C410C38904248B44241889442404C744240804000000E8C74200008B44240C8944241C83C410C38B44241835A98E7FAA69C0CD76BAC28944241C83C410C3E80F530400E92AFFFFFFCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B61080F86B800000083EC108B442414F20F10000F57C9660F2EC175060F8B87000000660F2EC075027B5B648B05140000008B80000000008B40188B88940000008B909800000089909400000089CBC1E11131D989D331CAC1E90731D189DAC1EB1031CB8998980000008D041A8B4C241831C835A98E7FAA69C0CD76BAC28944241C83C410C38904248B44241889442404C744240808000000E8E54100008B44240C8944241C83C410C38B44241835A98E7FAA69C0CD76BAC28944241C83C410C3E82D520400E928FFFFFFCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108763C83EC0C8B44241084008904248B4C2414894C2404E815FEFFFF8B44241083C0048B4C2408890424894C2404E8FEFDFFFF8B4424088944241883C40CC3E8CD510400EBABCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108763C83EC0C8B44241084008904248B4C2414894C2404E895FEFFFF8B44241083C0088B4C2408890424894C2404E87EFEFFFF8B4424088944241883C40CC3E86D510400EBABCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B61080F86F200000083EC248B4424288B0885C974678B49048B59108B1385D274670FB6490FF6C120742983C0048904248B44242C35A98E7FAA894424048B02FFD08B44240869C0CD76BAC28944243083C424C38B40048904248B44242C35A98E7FAA894424048B02FFD08B44240869C0CD76BAC28944243083C424C38B44242C8944243083C424C3890C24E8B2FA03008B4424088B4C2404C70424000000008D15A279500089542404C744240818000000894C240C89442410E8F46603008B4424188B4C2414894C241C894424208D05C0D24E008904248D44241C89442404E81E8E00008B44240C8B4C2408890C2489442404E87A3602000F0BE853500400E9EEFEFFFFCCCCCCCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B61080F86EF00000083EC248B4424288B0885C974648B59108B1385D274670FB6490FF6C120742983C0048904248B44242C35A98E7FAA894424048B02FFD08B44240869C0CD76BAC28944243083C424C38B40048904248B44242C35A98E7FAA894424048B02FFD08B44240869C0CD76BAC28944243083C424C38B44242C8944243083C424C3890C24E895F903008B4424088B4C2404C70424000000008D15A279500089542404C744240818000000894C240C89442410E8D76503008B4424188B4C2414894C241C894424208D05C0D24E008904248D44241C89442404E8018D00008B44240C8B4C2408890C2489442404E85D3502000F0BE8364F0400E9F1FEFFFFCC648B0D140000008B89000000003B61087606C644240C01C3 }

    condition:
    
        uint16(0) == 0x5a4d and
        filesize < 8000KB and
        all of them
}

rule Robbinhood_ransomware {

   meta:

      description = "Robbinhood GoLang ransowmare"
      author = "Christiaan Beek | McAfee ATR"
      date = "2019-05-10"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Robbinhood"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash = "9977ba861016edef0c3fb38517a8a68dbf7d3c17de07266cfa515b750b0d249e"
 
   strings:

      $s1 = ".enc_robbinhood" nocase
      $s2 = "sc.exe stop SQLAgent$SQLEXPRESS" nocase
      $s3 = "pub.key" nocase
      $s4 = "main.EnableShadowFucks" nocase
      $s5 = "main.EnableRecoveryFCK" nocase
      $s6 = "main.EnableLogLaunders" nocase
      $s7 = "main.EnableServiceFuck" nocase
     

      $op0 = { 8d 05 2d 98 51 00 89 44 24 30 c7 44 24 34 1d }
      $op1 = { 8b 5f 10 01 c3 8b 47 04 81 c3 b5 bc b0 34 8b 4f }
      $op2 = { 0f b6 34 18 8d 7e d0 97 80 f8 09 97 77 39 81 fd }

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 3000KB and
      ( 1 of ($s*) ) and
      all of ($op*)) or 
      ( all of them )
}

rule snake_ransomware {
	
	meta:

		description = "Rule to detect Snake ransomware"
		author = "McAfee ATR Team"
		date = "2020-02-20"
		rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/EKANS"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
		reference = "https://dragos.com/blog/industry-news/ekans-ransomware-and-ics-operations/"
		hash = "e5262db186c97bbe533f0a674b08ecdafa3798ea7bc17c705df526419c168b60"
		
	strings:

		$snake = { 43 3A 2F 55 73 ?? 72 ?? 2F 57 49 4E 31 2F 67 6F 2F 73 ?? 63 2F 6A 6F 62 6E 68 62 67 6E 6E 69 66 70 6F 64 68 68 70 ?? 6D 66 2F 6E 66 64 6C 68 6F 70 68 6B 65 69 6A 61 64 67 66 64 64 69 6D 2F 6E 66 64 6C 68 6F 70 68 6B 65 69 6A 61 64 67 66 64 64 69 6D 2F 76 74 5F 73 74 ?? 69 6E 67 2E 67 6F 00 }
	
	condition:

		 ( uint16(0) == 0x5a4d and
		 filesize < 11000KB ) and
		 all of them
	
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCOM {
    meta:
        description = "Detects Windows exceutables bypassing UAC using CMSTP COM interfaces. MITRE (T1218.003)"
        author = "ditekSHen"
        threat = "BehavesLike:UACBypasser/CMSTP"
    strings:
        // CMSTPLUA
        $guid1 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide nocase
        // CMLUAUTIL
        $guid2 = "{3E000D72-A845-4CD9-BD83-80C07C3B881F}" ascii wide nocase
        // Connection Manager LUA Host Object
        $guid3 = "{BA126F01-2166-11D1-B1D0-00805FC1270E}" ascii wide nocase
        $s1 = "CoGetObject" fullword ascii wide
        $s2 = "Elevation:Administrator!new:" fullword ascii wide
    condition:
       uint16(0) == 0x5a4d and (1 of ($guid*) and 1 of ($s*))
}

rule Ransom_TunderX {
   meta:
      description = "Rule to detect tthe ThunderX ransomware family"
      author = "McAfee ATR team"
      date = "2020-09-14"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransomware:W32/ThunderX"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash1 = "7bab5dedef124803668580a59b6bf3c53cc31150d19591567397bbc131b9ccb6"
      hash2 = "0fbfdb8340108fafaca4c5ff4d3c9f9a2296efeb9ae89fcd9210e3d4c7239666"
      hash3 = "7527459500109b3bb48665236c5c5cb2ec71ba789867ad2b6417b38b9a46615e"
   
   strings:
   
      $pattern1 = "626364656469742E657865202F736574207B64656661756C747D20626F6F74737461747573706F6C6963792069676E6F7265616C6C6661696C75726573" 
     
      $s3 = "776261646D696E2044454C4554452053595354454D53544154454241434B5550202D64656C6574654F6C64657374" ascii
      $s4 = "626364656469742E657865202F736574207B64656661756C747D207265636F76657279656E61626C6564204E6F" ascii 
      $s5 = "776261646D696E2044454C4554452053595354454D53544154454241434B5550" ascii 
      $s6 = "433A5C50726F6772616D2046696C65732028783836295C4D6963726F736F66742053514C20536572766572" ascii 
      $s7 = "476C6F62616C5C33353335354641352D303745392D343238422D423541352D314338384341423242343838" ascii 
      $s8 = "433A5C50726F6772616D2046696C65735C4D6963726F736F66742053514C20536572766572" ascii 
      $s9 = "76737361646D696E2E6578652044656C65746520536861646F7773202F416C6C202F5175696574" ascii 
      $s10 = "776D69632E65786520534841444F57434F5059202F6E6F696E746572616374697665" ascii 
      $s11 = "534F4654574152455C4D6963726F736F66745C45524944" ascii 
      $s12 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s13 = "7B5041545445524E5F49447D" ascii 
      $s14 = "726561646D652E747874" ascii 
      $s15 = "226E6574776F726B223A22" ascii 
      $s16 = "227375626964223A22" ascii 
      $s17 = "226C616E67223A22" ascii 
      $s18 = "22657874223A22" ascii 
      $s19 = "69642E6B6579" ascii 
      $s20 = "7B5549447D" ascii 

      $seq0 = { eb 34 66 0f 12 0d 10 c4 41 00 f2 0f 59 c1 ba cc }
      $seq1 = { 6a 07 50 e8 51 ff ff ff 8d 86 d0 }
      $seq2 = { ff 15 34 81 41 00 eb 15 83 f8 fc 75 10 8b 45 f4 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "ea7e408cd2a264fd13492973e97d8d70" and $pattern1 and 4 of them ) and all of ($seq*) or ( all of them )
}



rule MALWARE_Win_zgRAT {
    meta:
        author = "ditekSHen"
        description = "Detects zgRAT"
        threat = "BehavesLike:Trojan.MSIL.zgRAT"
    strings:
        $s1 = "file:///" fullword wide
        $s2 = "{11111-22222-10009-11112}" fullword wide
        $s3 = "{11111-22222-50001-00000}" fullword wide
        $s4 = "get_Module" fullword ascii
        $s5 = "Reverse" fullword ascii
        $s6 = "BlockCopy" fullword ascii
        $s7 = "ReadByte" fullword ascii
        $s8 = { 4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00
                00 0b 46 00 69 00 6e 00 64 00 20 00 00 13 52 00
                65 00 73 00 6f 00 75 00 72 00 63 00 65 00 41 00
                00 11 56 00 69 00 72 00 74 00 75 00 61 00 6c 00
                20 00 00 0b 41 00 6c 00 6c 00 6f 00 63 00 00 0d
                57 00 72 00 69 00 74 00 65 00 20 00 00 11 50 00
                72 00 6f 00 63 00 65 00 73 00 73 00 20 00 00 0d
                4d 00 65 00 6d 00 6f 00 72 00 79 00 00 0f 50 00
                72 00 6f 00 74 00 65 00 63 00 74 00 00 0b 4f 00
                70 00 65 00 6e 00 20 00 00 0f 50 00 72 00 6f 00
                63 00 65 00 73 00 73 00 00 0d 43 00 6c 00 6f 00
                73 00 65 00 20 00 00 0d 48 00 61 00 6e 00 64 00
                6c 00 65 00 00 0f 6b 00 65 00 72 00 6e 00 65 00
                6c 00 20 00 00 0d 33 00 32 00 2e 00 64 00 6c 00
                6c }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule MALWARE_Win_Nitro {
    meta:
        author = "ditekSHen"
        description = "Detects Nitro Ransomware"
        threat = "Ransom:W32/Nitro"
    strings:
        $x1 = ".givemenitro" wide
        $x2 = "Nitro Ransomware" ascii wide
        $x3 = "\\NitroRansomware.pdb" ascii
        $x4 = "NitroRansomware" ascii wide nocase
        $s1 = "Valid nitro code was received" wide
        $s2 = "discord nitro" ascii wide nocase
        $s3 = "Starting file encryption" wide
        $s4 = "NR_decrypt.txt" wide
        $s5 = "open it unless you have the decryption key." ascii
        $s6 = "<EncryptAll>b__" ascii
        $s7 = "<DecryptAll>b__" ascii
        $s8 = "DECRYPT_PASSWORD" fullword ascii
        $s9 = "IsEncrypted" fullword ascii
        $s10 = "CmdProcess_OutputDataReceived" fullword ascii
        $s11 = "encryptedFileLog" fullword ascii
        $s12 = "Encrypting:" fullword wide
        $s13 = "decryption key. If you do so, your files may get corrupted" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or (3 of ($s*) and 1 of ($x*)) or (7 of ($s*)))
}

rule INDICATOR_EXE_Packed_ConfuserEx {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod"
        snort2_sid = "930016-930018"
        snort3_sid = "930005-930006"
        threat = "BehavesLike:ConfuserExMOD"
    strings:
        $s1 = "ConfuserEx " ascii
        $s2 = "ConfusedByAttribute" fullword ascii
        $c1 = "Confuser.Core " ascii wide
        $u1 = "Confu v" fullword ascii
        $u2 = "ConfuByAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($c*) or all of ($u*))
}

rule SUSP_INDICATOR_RTF_MalVer_Objects { //phns-1666275333
   meta:
      description = "Detects RTF documents with non-standard version and embedding one of the object mostly observed in exploit (e.g. CVE-2017-11882) documents."
      author = "ditekSHen"
      reference = "https://github.com/ditekshen/detection"
      date = "2022-10-20"
      score = 65
      hash1 = "43812ca7f583e40b3e3e92ae90a7e935c87108fa863702aa9623c6b7dc3697a2"
      hash2 = "a31da6c6a8a340901f764586a28bd5f11f6d2a60a38bf60acd844c906a0d44b1"
      threat = "BehavesLike:Exploit/Rtf"
   strings:
      // Embedded Objects
      $obj1 = "\\objhtml" ascii
      $obj2 = "\\objdata" ascii
      $obj3 = "\\objupdate" ascii
      $obj4 = "\\objemb" ascii
      $obj5 = "\\objautlink" ascii
      $obj6 = "\\objlink" ascii
   condition:
      uint32(0) == 0x74725c7b and (
         // missing 'f' after '{\rt' and missing '1' (version) after 'rtf' and no char-set set ('\' missing at pos 6)
         // https://www.biblioscape.com/rtf15_spec.htm#Heading6
         (not uint8(4) == 0x66 or not uint8(5) == 0x31 or not uint8(6) == 0x5c) 
         and 1 of ($obj*)
      )
}

rule SmokeLoader
{
    meta:
        author = "kevoreilly"
        description = "SmokeLoader Payload"
        cape_options = "bp0=$gate+19,action0=DumpSectionViews,count=1"
    strings:
        $gate = {68 [2] 00 00 50 E8 [4] 8B 45 ?? 89 F1 8B 55 ?? 9A [2] 40 00 33 00 89 F9 89 FA 81 C1 [2] 00 00 81 C2 [2] 00 00 89 0A 8B 46 ?? 03 45 ?? 8B 4D ?? 8B 55 ?? 9A [2] 40 00 33 00}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Suspicious_PowerShell_WebDownload_1 : HIGHVOL FILE {
   meta:
      description = "Detects suspicious PowerShell code that downloads from web sites"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "Internal Research"
      date = "2017-02-22"
      modified = "2022-07-27"
      nodeepdive = 1
      threat = "Trojan:Download.PShell"
   strings:
      $s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
      $s2 = "System.Net.WebClient).DownloadString('http" ascii nocase
      $s3 = "system.net.webclient).downloadfile('http" ascii nocase
      $s4 = "system.net.webclient).downloadfile(\"http" ascii nocase
      $s5 = "GetString([Convert]::FromBase64String(" ascii nocase

      $fp1 = "NuGet.exe" ascii fullword
      $fp2 = "chocolatey.org" ascii
      $fp3 = " GET /"
      $fp4 = " POST /"
      $fp5 = ".DownloadFile('https://aka.ms/installazurecliwindows', 'AzureCLI.msi')" ascii
      $fp6 = " 404 " /* in web server logs */
      $fp7 = "# RemoteSSHConfigurationScript" ascii /* \.vscode\extensions\ms-vscode-remote.remote-ssh */
      $fp8 = "<helpItems" ascii fullword
      $fp9 = "DownloadFile(\"https://codecov.io/bash" ascii
   condition:
      1 of ($s*) and not 1 of ($fp*)
}

rule MALWARE_Win_SnakeKeylogger {
    meta:
        author = "ditekSHen"
        description = "Detects Snake Keylogger"
        clamav_sig = "MALWARE.Win.Trojan.SnakeKeylogger"
        threat = "Windows.Trojan.SnakeKeylogger"
    strings:
        $id1 = "SNAKE-KEYLOGGER" fullword ascii
        $id2 = "----------------S--------N--------A--------K--------E----------------" ascii
        $s1 = "_KPPlogS" fullword ascii
        $s2 = "_Scrlogtimerrr" fullword ascii
        $s3 = "_Clpreptimerr" fullword ascii
        $s4 = "_clprEPs" fullword ascii
        $s5 = "_kLLTIm" fullword ascii
        $s6 = "_TPSSends" fullword ascii
        $s7 = "_ProHfutimer" fullword ascii
        $s8 = "GrabbedClp" fullword ascii
        $s9 = "StartKeylogger" fullword ascii
        // Snake Keylogger Stub New
        $x1 = "$%SMTPDV$" wide
        $x2 = "$#TheHashHere%&" wide
        $x3 = "%FTPDV$" wide
        $x4 = "$%TelegramDv$" wide
        $x5 = "KeyLoggerEventArgs" ascii
        $m1 = "| Snake Keylogger" ascii wide
        $m2 = /(Screenshot|Clipboard|keystroke) Logs ID/ ascii wide
        $m3 = "SnakePW" ascii wide
        $m4 = "\\SnakeKeylogger\\" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (all of ($id*) or 6 of ($s*) or (1 of ($id*) and 3 of ($s*)) or 4 of ($x*))) or (2 of ($m*))
}

rule Ryuk_Ransomware {

   meta:

      description = "Ryuk Ransomware hunting rule"
      author = "Christiaan Beek - McAfee ATR team"
      date = "2019-04-25"
      rule_version = "v2"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Ryuk"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/ryuk-ransomware-attack-rush-to-attribution-misses-the-point/"
      
   
   strings:

      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "\\System32\\cmd.exe" fullword wide
      $s1 = "C:\\Users\\Admin\\Documents\\Visual Studio 2015\\Projects\\ConsoleApplication54new crypted" ascii
      $s2 = "fg4tgf4f3.dll" fullword wide
      $s3 = "lsaas.exe" fullword wide
      $s4 = "\\Documents and Settings\\Default User\\sys" fullword wide
      $s5 = "\\Documents and Settings\\Default User\\finish" fullword wide
      $s6 = "\\users\\Public\\sys" fullword wide
      $s7 = "\\users\\Public\\finish" fullword wide
      $s8 = "You will receive btc address for payment in the reply letter" fullword ascii
      $s9 = "hrmlog" fullword wide
      $s10 = "No system is safe" fullword ascii
      $s11 = "keystorage2" fullword wide
      $s12 = "klnagent" fullword wide
      $s13 = "sqbcoreservice" fullword wide
      $s14 = "tbirdconfig" fullword wide
      $s15 = "taskkill" fullword wide

      $op0 = { 8b 40 10 89 44 24 34 c7 84 24 c4 }
      $op1 = { c7 44 24 34 00 40 00 00 c7 44 24 38 01 }
    
   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 1 of ($x*) and
      4 of them ) and
      all of ($op*)) or
      ( all of them )
}

rule Ransom_Ryuk_sept2020 {
   meta:
      description = "Detecting latest Ryuk samples"
      author = "McAfe ATR"
      date = "2020-10-13"
       malware_type = "ransomware"
      malware_family = "Ransom:W32/Ryuk"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash1 = "cfdc2cb47ef3d2396307c487fc3c9fe55b3802b2e570bee9aea4ab1e4ed2ec28"
   strings:
      $x1 = "\" /TR \"C:\\Windows\\System32\\cmd.exe /c for /l %x in (1,1,50) do start wordpad.exe /p " fullword ascii
      $x2 = "cmd.exe /c \"bcdedit /set {default} recoveryenabled No & bcdedit /set {default}\"" fullword ascii
      $x3 = "cmd.exe /c \"bootstatuspolicy ignoreallfailures\"" fullword ascii
      $x4 = "cmd.exe /c \"vssadmin.exe Delete Shadows /all /quiet\"" fullword ascii
      $x5 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x6 = "cmd.exe /c \"WMIC.exe shadowcopy delete\"" fullword ascii
      $x7 = "/C REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"EV\" /t REG_SZ /d \"" fullword wide
      $x8 = "W/C REG DELETE \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"EV\" /f" fullword wide
      $x9 = "\\System32\\cmd.exe" fullword wide
      $s10 = "Ncsrss.exe" fullword wide
      $s11 = "lsaas.exe" fullword wide
      $s12 = "lan.exe" fullword wide
      $s13 = "$WGetCurrentProcess" fullword ascii
      $s14 = "\\Documents and Settings\\Default User\\sys" fullword wide
      $s15 = "Ws2_32.dll" fullword ascii
      $s16 = " explorer.exe" fullword wide
      $s17 = "e\\Documents and Settings\\Default User\\" fullword wide
      $s18 = "\\users\\Public\\" fullword ascii
      $s19 = "\\users\\Public\\sys" fullword wide
      $s20 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii

      $seq0 = { 2b c7 50 e8 30 d3 ff ff ff b6 8c }
      $seq1 = { d1 e0 8b 4d fc 8b 14 01 89 95 34 ff ff ff c7 45 }
      $seq2 = { d1 e0 8b 4d fc 8b 14 01 89 95 34 ff ff ff c7 45 }
   condition:
      ( uint16(0) == 0x5a4d and 
      filesize < 400KB and 
      ( 1 of ($x*) and 5 of them ) and 
      all of ($seq*)) or ( all of them )
}

rule RANSOM_RYUK_May2021 : ransomware
{
	meta:
		description = "Rule to detect latest May 2021 compiled Ryuk variant"
		author = "Marc Elias | McAfee ATR Team"
		date = "2021-05-21"
		hash = "8f368b029a3a5517cb133529274834585d087a2d3a5875d03ea38e5774019c8a"
		version = "0.1"

	strings:
		$ryuk_filemarker = "RYUKTM" fullword wide ascii
		
		$sleep_constants = { 68 F0 49 02 00 FF (15|D1) [0-4] 68 ?? ?? ?? ?? 6A 01 }
		$icmp_echo_constants = { 68 A4 06 00 00 6A 44 8D [1-6] 5? 6A 00 6A 20 [5-20] FF 15 }
		
	condition:
		uint16(0) == 0x5a4d
		and uint32(uint32(0x3C)) == 0x00004550
		and filesize < 200KB
		and ( $ryuk_filemarker
		or ( $sleep_constants 
		and $icmp_echo_constants ))
}

rule nemty_ransomware {

   meta:

      description = "Rule to detect Nemty Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-02-23"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Nemty"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/nemty-ransomware-learning-by-doing/"
      hash = "73bf76533eb0bcc4afb5c72dcb8e7306471ae971212d05d0ff272f171b94b2d4"

   strings:

      $x1 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default}" fullword ascii
      $s2 = "https://pbs.twimg.com/media/Dn4vwaRW0AY-tUu.jpg:large :D" fullword ascii
      $s3 = "MSDOS.SYS" fullword wide
      $s4 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} " ascii
      $s5 = "recoveryenabled no & wbadmin delete catalog -quiet & wmic shadowcopy delete" fullword ascii
      $s6 = "DECRYPT.txt" fullword ascii
      $s7 = "pv3mi+NQplLqkkJpTNmji/M6mL4NGe5IHsRFJirV6HSyx8mC8goskf5lXH2d57vh52iqhhEc5maLcSrIKbukcnmUwym+In1OnvHp070=" fullword ascii
      $s8 = "\\NEMTY-DECRYPT.txt\"" fullword ascii
      $s9 = "rfyPvccxgVaLvW9OOY2J090Mq987N9lif/RoIDP89luS9Ouv9gUImpgCTVGWvJzrqiS8hQ5El02LdEvKcJ+7dn3DxiXSNG1PwLrY59KzGs/gUvXnYcmT6t34qfZmr8g8" ascii
      $s10 = "IO.SYS" fullword wide
      $s11 = "QgzjKXcD1Jh/cOLBh1OMb+rWxUbToys2ArG9laNWAWk0rNIv2dnIDpc+mSbp91E8qVN8Mv8K5jC3EBr4TB8jh5Ns/onBhPZ9rLXR7wIkaXGeTZi/4/XOtO3DFiad4+vf" ascii
      $s12 = "NEMTY-DECRYPT.txt" fullword wide
      $s13 = "pvXmjPQRoUmjj0g9QZ24wvEqyvcJVvFWXc0LL2XL5DWmz8me5wElh/48FHKcpbnq8C2kwQ==" fullword ascii
      $s14 = "a/QRAGlNLvqNuONkUWCQTNfoW45DFkZVjUPn0t3tJQnHWPhJR2HWttXqYpQQIMpn" fullword ascii
      $s15 = "KeoJrLFoTgXaTKTIr+v/ObwtC5BKtMitXq8aaDT8apz98QQvQgMbncLSJWJG+bHvaMhG" fullword ascii
      $s16 = "pu/hj6YerUnqlUM9A8i+i/UhnvsIE+9XTYs=" fullword ascii
      $s17 = "grQkLxaGvL0IBGGCRlJ8Q4qQP/midozZSBhFGEDpNElwvWXhba6kTH1LoX8VYNOCZTDzLe82kUD1TSAoZ/fz+8QN7pLqol5+f9QnCLB9QKOi0OmpIS1DLlngr9YH99vt" ascii
      $s18 = "BOOTSECT.BAK" fullword wide
      $s19 = "bbVU/9TycwPO+5MgkokSHkAbUSRTwcbYy5tmDXAU1lcF7d36BTpfvzaV5/VI6ARRt2ypsxHGlnOJQUTH6Ya//Eu0jPi/6s2MmOk67csw/msiaaxuHXDostsSCC+kolVX" ascii
      $s20 = "puh4wXjVYWJzFN6aIgnClL4W/1/5Eg6bm5uEv6Dru0pfOvhmbF1SY3zav4RQVQTYMfZxAsaBYfJ+Gx+6gDEmKggypl1VcVXWRbxAuDIXaByh9aP4B2QvhLnJxZLe+AG5" ascii

   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 1 of ($x*) and
      4 of them ))
}

rule nemty_ransomware_2_6 {

   meta:

      description = "Rule to detect Nemty Ransomware version 2.6"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-04-06"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Nemty"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/nemty-ransomware-learning-by-doing/"
      hash = "52b7d20d358d1774a360bb3897a889e14d416c3b2dff26156a506ff199c3388d"

   strings:

   	  /*

		BYTES:

		558BEC83EC245356578955F4294DF46A048D72038D79015A8BC78955DC8A5EFD8858FF8B5DF48A1C0388188A5EFF8858018A1E88580203F203C2FF4DDC75DE8955F48D51038D42108D59028945F8894DF0297DF0895DEC297DEC8955E8297DE88D470C8D7902894DE4297DE48955DC297DDC8B7DF8894DE02955E08D7102F645F4038B5DEC8A1C038B4DF08A14018A08885DFA8B5DE88A1C03885DFB753B0FB6DB8A9B281241000FB6C98855FF8A91281241000FB64DFA8A8928124100885DFA0FB65DFF8A9B28124100885DFB8B5DF4C1EB023293281441008B5DE48A1C3332DA8B55E0881C178A50F432D18850048A0E324DFA83C004884E108B4DDC8A0C31324DFBFF45F4880F83C60483C704837DF42C0F8266FFFFFF5F5E5BC9C3558BEC560FB6C057C1E0040345086A045F6A045E8A10301140414E75F74F75F15F5E5DC356576A045F6A048BC15E0FB6108A9228124100881083C0044E75EF414F75E65F5EC38A50058A48018850018A50098850058A500D8850098A500A88480D8A48028850028A500E88480A8A48068850068A500F88480E8A48038850038A500B88500F8A500788500B884807C3558BEC5153566A0483C1025E8A410132018A51FE8A59FF8845FD32C232C38845FF8855FE32D38AC2C0E807B31BF6EB02D232C23245FE8A51FF3245FF32118841FE8AC2C0E807F6EB02D232C23241FF8A55FD3245FF8841FF8AC2C0E807F6EB02D232C232018A51013245FF3255FE88018AC2C0E807F6EB02D232C232410183C1043245FF4E8841FD75825E5BC9C3558BEC53FF75088BCE32C0E8D3FEFFFF59B3018BCEE8EDFEFFFF8BC6E808FFFFFF8BCEE84AFFFFFFFF75088BCE8AC3E8AFFEFFFFFEC35980FB0A72D78BCEE8C4FEFFFF8BC6E8DFFEFFFF5B8BCEB00A5DE98EFEFFFF558BEC81ECC8000000A18440410033C58945FC8B4508578D8D3CFFFFFF898538FFFFFFE849FDFFFF33FF6A1058397D0C764F5683F8107534508D45EC5350E88E6000008D853CFFFFFF508D75ECE859FFFFFF83C4106A0F58803C03FF7509C60403004879F3EB03FE041833C08A4C05EC8BB538FFFFFF300C3E47403B7D0C72B35E8B4DFC33CD5FE835600000C9C3558BEC51515333C05633F632DB8945FC39450C0F8682000000578B7DFC8B55088A14178BFE83EF0074504F74374F755D217DF80FB6FB0FB6F283E70F8BDEC1EB06C1E7020BFB8A9F6811410083E63F881C088A9E681141008B75F8885C080183C002EB290FB6FB0FB6DA83E7036A02C1E704C1EB045E0BFBEB0933F60FB6FA46C1EF028A9F68114100881C0840FF45FC8ADA8B55FC3B550C72805F4E741D4E75360FB6D383E20F8A149568114100881408C64408013D83C002EB1C0FB6D383E203C1E2048A926811410088140866C74408013D3D83C0035EC60408005BC9C3558BEC33C0F6450C0375775733FF39450C766E8B4D088A0C0F80F93D746380F92B7C5C80F97A7F570FB6C98A89A811410080F9FF74498BD783E20383EA0074314A741D4A74094A752E080C3040EB288AD1C0EA0280E20F08143040C0E106EB148AD1C0EA0480E20308143040C0E104EB03C0E102880C30473B7D0C7296EB0233C05F5DC3558BEC518B0B85C974298B4304568BF18945FC3BF07413576A0133FFE81E00000083C61C3B75FC75EF5FFF33E84A630000595E33C08903894304894308C9C3558BEC807D08007420837E1410721A538B1E85FF740B575356E8835E000083C40C53E815630000595BC746140F000000897E10C60437005DC20400C701C0F24000E9E5630000558BEC568BF1C706C0F24000E8D4630000F6450801740756E8D9620000598BC65E5DC20400558BEC83E4F881ECEC020000A18440410033C4898424E80200005356578D4508508D742450E89915000068341441008D842488000000E8AE1500006A075F33C083EC1C668944244C8D45088BF433DB50897C2464895C2460E866150000E8CC0E000033C066894424308B8424B00000000344247883C41C8D4C2414897C2428895C2424E8BA1E0000538D4424505083C8FF8D74241CE8D8200000538D8424880000005083C8FFE8C72000008BDE8D442430E8A61500006A0133FFE87F160000837C2444088B44243073048D4424308D8C24A00000005150FF15DCF040008944241083F8FF0F842E0500008B3598F04000683C1441008D8424D000000050FFD685C00F84ED04000068401441008D8424D000000050FFD685C00F84D604000068481441008D8424D000000050FFD685C00F84BF04000068501441008D8424D000000050FFD685C00F84A804000068601441008D8424D000000050FFD685C00F8491040000687C1441008D8424D000000050FFD685C00F847A04000068841441008D8424D000000050FFD685C00F846304000068A01441008D8424D000000050FFD685C00F844C04000068AC1441008D8424D000000050FFD685C00F843504000068C01441008D8424D000000050FFD685C00F841E04000068D01441008D8424D000000050FFD685C00F840704000068E41441008D8424D000000050FFD685C00F84F003000068001541008D8424D000000050FFD685C00F84D903000068181541008D8424D000000050FFD685C00F84C203000068301541008D8424D000000050FFD685C00F84AB03000068481541008D8424D000000050FFD685C00F8494030000685C1541008D8424D000000050FFD685C00F847D03000068781541008D8424D000000050FFD685C00F846603000068881541008D8424D000000050FFD685C00F844F03000068A01541008D8424D000000050FFD685C00F843803000068B01541008D8424D000000050FFD685C00F842103000068CC1541008D8424D000000050FFD685C00F840A03000068F41541008D8424D000000050FFD685C00F84F302000068081641008D8424D000000050FFD685C00F84DC020000F68424A0000000108D8424CC000000508D4C246C8D4424507450E8441A0000598D4C241451E88F1A00008BD8598D442430E80E1300006A0133FF8D742418E8E31300006A018D74246CE8D813000083EC1C8D44244C8BF450E84E120000E886FCFFFF83C41CE972020000E8F41900008BD8598D442430E8C91200006A0133FF8D74246CE89E1300008D8424CC00000050FF15ACF14000508D442418E8311200008B4424146A085F397C242873048D4424148B3598F04000681816410050FFD685C00F84080200008B442414397C242873048D442414682416410050FFD685C00F84EA0100008B442414397C242873048D442414683016410050FFD685C00F84CC0100008B442414397C242873048D442414683C16410050FFD685C00F84AE0100008B442414397C242873048D442414684816410050FFD685C00F84900100008B442414397C242873048D442414685416410050FFD685C00F84720100008B442414397C242873048D442414686016410050FFD685C00F84540100008B442414397C242873048D442414686C16410050FFD685C00F84360100008B442414397C242873048D442414687816410050FFD685C00F84180100008B442414397C242873048D442414688416410050FFD685C00F84FA0000008B442414397C242873048D442414689016410050FFD685C00F84DC0000008B442414397C242873048D442414689C16410050FFD685C00F84BE0000008B442414397C242873048D44241468A816410050FFD685C00F84A00000008B442414397C242873048D44241468B416410050FFD685C00F84820000008B442414397C242873048D44241468C816410050FFD685C074688B442414397C242873048D44241468D416410050FFD685C0744E83EC1C8BC468E0164100E84110000083EC1C8D8C24040100008BC451E82F100000E83456000083C43885C075218B4C2430397C244473048D4C243083EC1C8BC451E80A100000E8CE0A000083C41C6A0133FF8D742418E84A1100008D8424A000000050FF742414FF1594F0400085C00F85DCFAFFFFFF742410FF15A0F0400033DB435333FF8D742434

		*/
         
      $pattern = { 558B??83????53565789????29????6A??8D????8D????5A8B??89????8A????88????8B????8A????88??8A????88????8A??88????03??03??FF????75??89????8D????8D????8D????89????89????29????89????29????89????29????8D????8D????89????29????89????29????8B????89????29????8D????F6??????8B????8A????8B????8A????8A??88????8B????8A????88????75??0FB6??8A??????????0FB6??88????8A??????????0FB6????8A??????????88????0FB6????8A??????????88????8B????C1????32??????????8B????8A????32??8B????88????8A????32??88????8A??32????83????88????8B????8A????32????FF????88??83????83????83??????0F82????????5F5E5BC9C3558B??560FB6??57C1????03????6A??5F6A??5E8A??30??40414E75??4F75??5F5E5DC356576A??5F6A??8B??5E0FB6??8A??????????88??83????4E75??414F75??5F5EC38A????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????88????C3558B??5153566A??83????5E8A????32??8A????8A????88????32??32??88????88????32??8A??C0????B3??F6??02??32??32????8A????32????32??88????8A??C0????F6??02??32??32????8A????32????88????8A??C0????F6??02??32??32??8A????32????32????88??8A??C0????F6??02??32??32????83????32????4E88????75??5E5BC9C3558B??53FF????8B??32??E8????????59B3??8B??E8????????8B??E8????????8B??E8????????FF????8B??8A??E8????????FE??5980????72??8B??E8????????8B??E8????????5B8B??B0??5DE9????????558B??81??????????A1????????33??89????8B????578D??????????89??????????E8????????33??6A??5839????76??5683????75??508D????5350E8????????8D??????????508D????E8????????83????6A??5880??????75??C6??????4879??EB??FE????33??8A??????8B??????????30????47403B????72??5E8B????33??5FE8????????C9C3558B??51515333??5633??32??89????39????0F86????????578B????8B????8A????8B??83????74??4F74??4F75??21????0FB6??0FB6??83????8B??C1????C1????0B??8A??????????83????88????8A??????????8B????88??????83????EB??0FB6??0FB6??83????6A??C1????C1????5E0B??EB??33??0FB6??46C1????8A??????????88????40FF????8A??8B????3B????72??5F4E74??4E75??0FB6??83????8A????????????88????C6????????83????EB??0FB6??83????C1????8A??????????88????66????????????83????5EC6??????5BC9C3558B??33??F6??????75??5733??39????76??8B????8A????80????74??80????7C??80????7F??0FB6??8A??????????80????74??8B??83????83????74??4A74??4A74??4A75??08????40EB??8A??C0????80????08????40C0????EB??8A??C0????80????08????40C0????EB??C0????88????473B????72??EB??33??5F5DC3558B??518B??85??74??8B????568B??89????3B??74??576A??33??E8????????83????3B????75??5FFF??E8????????595E33??89??89????89????C9C3558B??80??????74??83??????72??538B??85??74??575356E8????????83????53E8????????595BC7????????????89????C6??????5DC2????C7??????????E9????????558B??568B??C7??????????E8????????F6??????74??56E8????????598B??5E5DC2????558B??83????81??????????A1????????33??89????????????5356578D????508D??????E8????????68????????8D????????????E8????????6A??5F33??83????66????????8D????8B??33??5089??????89??????E8????????E8????????33??66????????8B????????????03??????83????8D??????89??????89??????E8????????538D??????5083????8D??????E8????????538D????????????5083????E8????????8B??8D??????E8????????6A??33??E8????????83????????8B??????73??8D??????8D????????????5150FF??????????89??????83????0F84????????8B??????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????F6??????????????8D????????????508D??????8D??????74??E8????????598D??????51E8????????8B??598D??????E8????????6A??33??8D??????E8????????6A??8D??????E8????????83????8D??????8B??50E8????????E8????????83????E9????????E8????????8B??598D??????E8????????6A??33??8D??????E8????????8D????????????50FF??????????508D??????E8????????8B??????6A??5F39??????73??8D??????8B??????????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??74??8B??????39??????73??8D??????68????????50FF??85??74??83????8B??68????????E8????????83????8D????????????8B??51E8????????E8????????83????85??75??8B??????39??????73??8D??????83????8B??51E8????????E8????????83????6A??33??8D??????E8????????8D????????????50FF??????FF??????????85??0F85????????FF??????FF??????????33??435333??8D?????? }


   condition:
   
      uint16(0) == 0x5a4d and
      filesize < 1500KB and
      $pattern
}

rule clop_ransom_note {

   meta:

      description = "Rule to detect Clop Ransomware Note"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-08-01"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Clop"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/clop-ransomware/"
      
   strings:

      $s1 = "If you want to restore your files write to emails" fullword ascii
      $s2 = "All files on each host in the network have been encrypted with a strong algorithm." fullword ascii
      $s3 = "Shadow copies also removed, so F8 or any other methods may damage encrypted data but not recover." fullword ascii
      $s4 = "You will receive decrypted samples and our conditions how to get the decoder." fullword ascii
      $s5 = "DO NOT RENAME OR MOVE the encrypted and readme files." fullword ascii
      $s6 = "(Less than 6 Mb each, non-archived and your files should not contain valuable information" fullword ascii
      $s7 = "We exclusively have decryption software for your situation" fullword ascii
      $s8 = "Do not rename encrypted files." fullword ascii
      $s9 = "DO NOT DELETE readme files." fullword ascii
      $s10 = "Nothing personal just business" fullword ascii
      $s11 = "eqaltech.su" fullword ascii

   condition:

      ( uint16(0) == 0x6f59) and 
      filesize < 10KB and
      all of them
}
