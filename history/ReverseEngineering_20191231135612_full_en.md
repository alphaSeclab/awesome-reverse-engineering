# Other Resource Collection Projects:
- [All open source security tools I collected: sec-tool-list](https://github.com/alphaSeclab/sec-tool-list/blob/master/Readme_en.md): More than 18K. Both Markdown and Json format.
- [Reverse Engineering Resources For All Platforms: awesome-reverse-engineering](https://github.com/alphaSeclab/awesome-reverse-engineering/blob/master/Readme_en.md): 
    - Windows: PE/DLL/DLL-Injection/Dll-Hijack/Dll-Load/UAC-Bypass/Sysmon/AppLocker/ETW/WSL/.NET/Process-Injection/Code-Injection/DEP/Kernel/...
    - Linux: ELF/...
    - macOS/iXxx: Mach-O/越狱/LLDB/XCode/...
    - Android: HotFix/XPosed/Pack/Unpack/Emulator/Obfuscate
    - Famous Tools: IDA/Ghidra/x64dbg/OllDbg/WinDBG/CuckooSandbox/Radare2/BinaryNinja/DynamoRIO/IntelPin/Frida/QEMU/...
- [Network Related Resources: awesome-network-stuff](https://github.com/alphaSeclab/awesome-network-stuff/blob/master/Readme_en.md):
    - Network Communication: Proxy/SS/V2ray/GFW/ReverseProxy/Tunnel/VPN/Tor/I2P/...
    - Network Attack: MiTM/PortKnocking/...
    - Network Analysis: Sniff/Protocol-Analysis/Network-Visualization/Network-Diagnostic/...
- [Offensive Security Resources: awesome-cyber-security](https://github.com/alphaSeclab/awesome-cyber-security/blob/master/Readme_en.md): Vulnerability/Pentest/IoTSecurity/DataExfiltration/Metasploit/BurpSuite/KaliLinux/C&C/OWASP/AntiVirus/CobaltStrike/Recon/OSINT/SocialEnginneringAttack/Password/Credential/ThreatHunting/Payload/WifiHacking/PostExploitation/PrivilegeEscalation/UACBypass/...
- [open source RAT and malicious RAT analysis reports: awesome-rat](https://github.com/alphaSeclab/awesome-rat/blob/master/Readme_en.md): RAT for all platforms: Windows/Linux/macOS/Android; malicious RAT analysis reports
- [Webshell Resource Collection: awesome-webshell](https://github.com/alphaSeclab/awesome-webshell/blob/master/Readme_en.md): Almost 150 open source tools, and 200 blog posts about webhsell.
- [Forensics Resource Collection: awesome-forensics](https://github.com/alphaSeclab/awesome-forensics/blob/master/Readme_en.md): Almost 300 open source forensics tools, and 600 blog posts about forensics.




# ReverseEngineering


- Reverse Engineering Resource Collection. 3500+ open source tools, 2300+ blog posts.
- This page only contains limited tools and posts. [Read Full Version](https://github.com/alphaSeclab/awesome-reverse-engineering/blob/master/Readme_full_en.md)


# PS
[中文版本](https://github.com/alphaSeclab/awesome-reverse-engineering/blob/master/Readme.md)


# Directory
- [Windows](#2f81493de610f9b796656b269380b2de)
    - [PE](#620af0d32e6ac1f4a3e97385d4d3efc0)
        - [(68) Tool](#574db8bbaafbee72eeb30e28e2799458)
        - [(324) Post](#7e890d391fa32df27beb1377a371518b)
    - [DLL](#89f963773ee87e2af6f9170ee60a7fb2)
        - [DLL Injection](#3b4617e54405a32290224b729ff9f2b3)
            - [(67) Tools](#b0d50ee42d53b1f88b32988d34787137)
            - [(70) Post](#1a0b0dab4cdbab08bbdc759bab70dbb6)
        - [DLL Hijack](#f39e40e340f61ae168b67424baac5cc6)
            - [(60) Post](#01e95333e07439ac8326253aa8950b4f)
            - [(18) Tools](#c9cdcc6f4acbeda6c8ac8f4a1ba1ea6b)
        - [Recent Add](#4dcfd9135aa5321b7fa65a88155256f9)
            - [(16) Post](#b05f4c5cdfe64e1dde2a3c8556e85827)
            - [(107) Tools](#9753a9d52e19c69dc119bf03e9d7c3d2)
    - [UAC](#40fd1488e4a26ebf908f44fdcedd9675)
        - [(29) Tools](#02517eda8c2519c564a19219e97d6237)
        - [(123) Post](#90d7d5feb7fd506dc8fd6ee0d7e98285)
    - [Sysmon](#0fed6a96b28f339611e7b111b8f42c23)
        - [(12) Tools](#d48f038b58dc921660be221b4e302f70)
        - [(131) Post](#2c8cb7fdf765b9d930569f7c64042d62)
    - [ETW](#ac43a3ce5a889d8b18cf22acb6c31a72)
        - [(64) Post](#11c4c804569626c1eb02140ba557bb85)
        - [(35) Tools](#0af4bd8ca0fd27c9381a2d1fa8b71a1f)
    - [AppLocker](#184bbacd8b9e08c30cc9ffcee9513f44)
        - [(11) Tools](#8f1876dff78e80b60d00de25994276d9)
        - [(93) Post](#286317d6d7c1a0578d8f5db940201320)
    - [Tools](#b478e9a9a324c963da11437d18f04998)
        - [(213) Other](#1afda3039b4ab9a3a1f60b179ccb3e76)
        - [(10) .NET](#d90b60dc79837e06d8ba2a7ee1f109d3)
        - [Recent Add](#f9fad1d4d1f0e871a174f67f63f319d8)
        - [(5) Environment Setup](#6d2fe834b7662ecdd48c17163f732daf)
        - [Process Injection](#8bfd27b42bb75956984994b3419fb582)
        - [Code Injection](#1c6069610d73eb4246b58d78c64c9f44)
        - [Memory Module](#7c1541a69da4c025a89b0571d8ce73d2)
        - [(6) VT&&Hypbervisor](#19cfd3ea4bd01d440efb9d4dd97a64d0)
        - [(8) Kernel&&Driver](#c3cda3278305549f4c21df25cbf638a4)
        - [(3) Registry](#920b69cea1fc334bbc21a957dd0d9f6f)
        - [(4) SystemCall](#d295182c016bd9c2d5479fe0e98a75df)
        - [(3) Procmon](#518d80dfb8e9dda028d18ace1d3f3981)
    - [Posts&&Videos](#3939f5e83ca091402022cb58e0349ab8)
        - [Recent Add](#8e1344cae6e5f9a33e4e5718a012e292)
        - [(5) Procmon](#af06263e9a92f6036dc5d4c4b28b9d8c)
        - [(68) DEP](#fa89526db1f9373c57ea4ffa1ac8c39f)
- [Linux](#dc664c913dc63ec6b98b47fcced4fdf0)
    - [ELF](#a63015576552ded272a242064f3fe8c9)
        - [(59) Tools](#929786b8490456eedfb975a41ca9da07)
        - [(102) Post](#72d101d0f32d5521d5d305e7e653fdd3)
    - [Tools](#89e277bca2740d737c1aeac3192f374c)
        - [(99) Recent Add](#203d00ef3396d68f5277c90279f4ebf3)
    - [Post&&Videos](#f6d78e82c3e5f67d13d9f00c602c92f0)
        - [Recent Add](#bdf33f0b1200cabea9c6815697d9e5aa)
- [Apple&&iOS&&iXxx](#069664f347ae73b1370c4f5a2ec9da9f)
    - [Mach-O](#830f40713cef05f0665180d840d56f45)
        - [(28) Tools](#9b0f5682dc818c93c4de3f46fc3f43d0)
        - [(24) Post](#750700dcc62fbd83e659226db595b5cc)
    - [JailBreak](#bba00652bff1672ab1012abd35ac9968)
        - [(96) Tools](#ff19d5d94315d035bbcb3ef0c348c75b)
        - [(14) Post](#cbb847a025d426a412c7cd5d8a2332b5)
    - [LLDB](#004d0b9e325af207df8e1ca61af7b721)
        - [(11) Tools](#c20772abc204dfe23f3e946f8c73dfda)
        - [(17) Post](#86eca88f321a86712cc0a66df5d72e56)
    - [XCode](#977cef2fc942ac125fa395254ab70eea)
        - [(18) Tools](#7037d96c1017978276cb920f65be2297)
        - [(49) Post](#a2d228a68b40162953d3d482ce009d4e)
    - [Tools](#58cd9084afafd3cd293564c1d615dd7f)
        - [(319) Recent Add](#d0108e91e6863289f89084ff09df39d0)
    - [Posts&&Videos](#c97bbe32bbd26c72ceccb43400e15bf1)
        - [Recent Add](#d4425fc7c360c2ff324be718cf3b7a78)
- [Android](#11a59671b467a8cdbdd4ea9d5e5d9b51)
    - [Tools](#2110ded2aa5637fa933cc674bc33bf21)
        - [(183) Recent Add1](#883a4e0dd67c6482d28a7a14228cd942)
        - [(4) HotFix](#fa49f65b8d3c71b36c6924ce51c2ca0c)
        - [(1) Package](#ec395c8f974c75963d88a9829af12a90)
        - [(2) Collection](#767078c52aca04c452c095f49ad73956)
        - [(1) App](#17408290519e1ca7745233afea62c43c)
        - [(30) Xposed](#7f353b27e45b5de6b0e6ac472b02cbf1)
        - [(19) Pack&&Unpack](#50f63dce18786069de2ec637630ff167)
        - [(12) HOOK](#596b6cf8fd36bc4c819335f12850a915)
        - [(9) Emulator](#5afa336e229e4c38ad378644c484734a)
        - [(6) IDA](#0a668d220ce74e11ed2738c4e3ae3c9e)
        - [(11) Debug](#bb9f8e636857320abf0502c19af6c763)
        - [(34) Malware](#f975a85510f714ec3cc2551e868e75b8)
        - [(5) Obfuscate](#1d83ca6d8b02950be10ac8e4b8a2d976)
        - [(15) Reverse Engineering](#6d2b758b3269bac7d69a2d2c8b45194c)
        - [(319) Recent Add](#63fd2c592145914e99f837cecdc5a67c)
    - [(2) Posts&&Videos](#f0493b259e1169b5ddd269b13cfd30e6)
- [IDA](#08e59e476824a221f6e4a69c0bba7d63)
    - [Tools](#f11ab1ff46aa300cc3e86528b8a98ad7)
        - [(97) No Category](#c39a6d8598dde6abfeef43faf931beb5)
        - [Structure&&Class](#fb4f0c061a72fc38656691746e7c45ce)
            - [(6) No Category](#fa5ede9a4f58d4efd98585d3158be4fb)
            - [(8) C++ Class&&Virtual Table](#4900b1626f10791748b20630af6d6123)
        - [(3) Collection](#a7dac37cd93b8bb42c7d6aedccb751b3)
        - [(9) Skin&&Theme](#fabf03b862a776bbd8bcc4574943a65a)
        - [(4) Firmware&&Embed Device](#a8f5db3ab4bc7bc3d6ca772b3b9b0b1e)
        - [Signature(FLIRT...)&&Diff&&Match](#02088f4884be6c9effb0f1e9a3795e58)
            - [(17) No Category](#cf04b98ea9da0056c055e2050da980c1)
            - [FLIRT](#19360afa4287236abe47166154bc1ece)
                - [(3) FLIRT Signature Collection](#1c9d8dfef3c651480661f98418c49197)
                - [(2) FLIRT Signature Generate](#a9a63d23d32c6c789ca4d2e146c9b6d0)
            - [(11) Diff&&Match](#161e5a3437461dc8959cc923e6a18ef7)
            - [(7) Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a)
        - [(6) IDB](#5e91b280aab7f242cbc37d64ddbff82f)
        - [(5) Collaborative RE](#206ca17fc949b8e0ae62731d9bb244cb)
        - [(9) Sync With Debugger](#f7d311685152ac005cfce5753c006e4b)
        - [Import Export&&Sync With Other Tools](#6fb7e41786c49cc3811305c520dfe9a1)
            - [(13) No Category](#8ad723b704b044e664970b11ce103c09)
            - [(5) Ghidra](#c7066b0c388cd447e980bf0eb38f39ab)
            - [(3) BinNavi](#11139e7d6db4c1cef22718868f29fe12)
            - [(3) BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a)
            - [(2) Radare2](#21ed198ae5a974877d7a635a4b039ae3)
            - [(4) Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd)
            - [(2) IntelPin](#dd0332da5a1482df414658250e6357f8)
        - [Specific Target](#004c199e1dbf71769fbafcd8e58d1ead)
            - [(26) No Category](#5578c56ca09a5804433524047840980e)
            - [(2) GoLang](#1b17ac638aaa09852966306760fda46b)
            - [(4) Windows Driver](#4c158ccc5aee04383755851844fdd137)
            - [(4) PS3&&PS4](#315b1b8b41c67ae91b841fce1d4190b5)
            - [(33) Loader&Processor](#cb59d84840e41330a7b5e275c0b81725)
            - [(4) PDB](#f5e51763bb09d8fd47ee575a98bedca1)
            - [(2) Flash&&SWF](#7d0681efba2cf3adaba2780330cd923a)
            - [(4) Malware Family](#841d605300beba45c3be131988514a03)
            - [(1) CTF](#ad44205b2d943cfa2fa805b2643f4595)
        - [IDAPython](#ad68872e14f70db53e8d9519213ec039)
            - [(8) No Category](#2299bc16945c25652e5ad4d48eae8eca)
            - [(1) Cheatsheets](#c42137cf98d6042372b1fd43c3635135)
        - [(6) Instruction Reference&&Doc](#846eebe73bef533041d74fc711cafb43)
        - [Script Writting](#c08ebe5b7eec9fc96f8eff36d1d5cc7d)
            - [(9) No Category](#45fd7cfce682c7c25b4f3fbc4c461ba2)
            - [(3) Qt](#1a56a5b726aaa55ec5b7a5087d6c8968)
            - [(3) Console&&GUI](#1721c09501e4defed9eaa78b8d708361)
            - [(2) Template](#227fbff77e3a13569ef7b007344d5d2e)
            - [(2) Other Lang](#8b19bb8cf9a5bc9e6ab045f3b4fabf6a)
        - [(16) Ancient](#dc35a2b02780cdaa8effcae2b6ce623e)
        - [Debug&&Dynamic Data](#e3e7030efc3b4de3b5b8750b7d93e6dd)
            - [(10) No Category](#2944dda5289f494e5e636089db0d6a6a)
            - [(10) DBI Data](#0fbd352f703b507853c610a664f024d1)
            - [(4) Debugger Data](#b31acf6c84a9506066d497af4e702bf5)
        - [(14) Decompiler&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9)
        - [(7) DeObfuscate](#7199e8787c0de5b428f50263f965fda7)
        - [Nav&&Quick Access&&Graph&&Image](#fcf75a0881617d1f684bc8b359c684d7)
            - [(15) No Category](#c5b120e1779b928d860ad64ff8d23264)
            - [(9) GUI Enhencement](#03fac5b3abdbd56974894a261ce4e25f)
            - [(3) Graph](#3b1dba00630ce81cba525eea8fcdae08)
            - [(3) Search](#8f9468e9ab26128567f4be87ead108d7)
        - [(7) Android](#66052f824f5054aa0f70785a2389a478)
        - [Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O](#2adc0044b2703fb010b3bf73b1f1ea4a)
            - [(5) No Category](#8530752bacfb388f3726555dc121cb1a)
            - [(3) Kernel Cache](#82d0fa2d6934ce29794a651513934384)
            - [(3) Mach-O](#d249a8d09a3f25d75bb7ba8b32bd9ec5)
            - [(3) Swift](#1c698e298f6112a86c12881fbd8173c7)
        - [(9) ELF](#e5e403123c70ddae7bd904d3a3005dbb)
        - [(5) Microcode](#7a2977533ccdac70ee6e58a7853b756b)
        - [(6) Emulator](#b38dab81610be087bd5bc7785269b8cc)
        - [(4) Recent Add](#c39dbae63d6a3302c4df8073b4d1cdc8)
        - [(4) Part Of Other Tool](#83de90385d03ac8ef27360bfcdc1ab48)
        - [Vul](#1ded622dca60b67288a591351de16f8b)
            - [(7) No Category](#385d6777d0747e79cccab0a19fa90e7e)
            - [(2) ROP](#cf2efa7e3edb24975b92d2e26ca825d2)
        - [(7) Patch](#7d557bc3d677d206ef6c5a35ca8b3a14)
        - [(3) Other](#7dfd8abad50c14cd6bdc8d8b79b6f595)
        - [Function](#90bf5d31a3897400ac07e15545d4be02)
            - [(4) No Category](#347a2158bdd92b00cd3d4ba9a0be00ae)
            - [(6) Rename&&Prefix&&Tag](#73813456eeb8212fd45e0ea347bec349)
            - [(5) Nav&&Search](#e4616c414c24b58626f834e1be079ebc)
            - [(2) demangle](#cadae88b91a57345d266c68383eb05c5)
        - [(3) Taint Analysis&&Symbolic Execution](#34ac84853604a7741c61670f2a075d20)
        - [(8) string](#9dcc6c7dd980bec1f92d0cc9a2209a24)
        - [(3) encrypt&&decrypt](#06d2caabef97cf663bd29af2b1fe270c)
    - [Video&&Post](#18c6a45392d6b383ea24b363d2f3e76b)
        - [(6) Series-Labeless Introduction](#04cba8dbb72e95d9c721fe16a3b48783)
        - [(24) Series-Reversing With IDA From Scrach](#1a2e56040cfc42c11c5b4fa86978cc19)
        - [Series-Using IDAPython To Make Your Life Easier](#e838a1ecdcf3d068547dd0d7b5c446c6)
            - [(6) Original](#7163f7c92c9443e17f3f76cc16c2d796)
            - [(5) ZH](#fc62c644a450f3e977af313edd5ab124)
        - [Tool&&Plugin&&Script](#3d3bc775abd7f254ff9ff90d669017c9)
            - [(51) No Category](#cd66794473ea90aa6241af01718c3a7d)
            - [(3) Loader&&Processor](#43a4761e949187bf737e378819752c3b)
            - [(1) With Other Tools](#c7483f3b20296ac68084a8c866230e15)
        - [(10) Tips&&Tricks](#a4bd25d3dc2f0be840e39674be67d66b)
        - [(125) No Category](#4187e477ebc45d1721f045da62dbf4e8)
        - [(5) Translate-The IDA Pro Book](#ea11818602eb33e8b165eb18d3710965)
        - [(2) Translate-Reverse Engineering Code With IDA Pro](#ec5f7b9ed06500c537aa25851a3f2d3a)
        - [(5) Series-Reversing C Code With IDA](#8433dd5df40aaf302b179b1fda1d2863)
        - [REPractice](#d8e48eb05d72db3ac1e050d8ebc546e1)
            - [(11) No Category](#374c6336120363a5c9d9a27d7d669bf3)
            - [(15) Malware](#0b3e1936ad7c4ccc10642e994c653159)
            - [(2) Vuln Analysis&&Vuln Hunting](#03465020d4140590326ae12c9601ecfd)
        - [(27) Recent Add](#37634a992983db427ce41b37dd9a98c2)
        - [(4) IDASelf](#2120fe5420607a363ae87f5d2fed459f)
        - [(1) Microcode](#e9ce398c2c43170e69c95fe9ad8d22fc)
        - [(1) AgainstIDA](#9c0ec56f402a2b9938417f6ecbaeaa72)
- [Ghidra](#319821036a3319d3ade5805f384d3165)
    - [Plugins&&Scripts](#fa45b20f6f043af1549b92f7c46c9719)
        - [(12) Recent Add](#ce70b8d45be0a3d29705763564623aca)
        - [Specific Target](#69dc4207618a2977fe8cd919e7903fa5)
            - [(4) No Category](#da5d2b05da13f8e65aa26d6a1c95a8d0)
            - [(18) Loader&&Processor](#058bb9893323f337ad1773725d61f689)
            - [(2) Xbox](#51a2c42c6d339be24badf52acb995455)
        - [With Other Tools](#99e3b02da53f1dbe59e0e277ef894687)
            - [(2) Radare2](#e1cc732d1388084530b066c26e24887b)
            - [No Category](#5923db547e1f04f708272543021701d2)
            - [(5) IDA](#d832a81018c188bf585fcefa3ae23062)
            - [(1) DBI](#60e86981b2c98f727587e7de927e0519)
            - [(1) Debugger](#e81053b03a859e8ac72f7fe79e80341a)
        - [(1) Skin&&Theme](#cccbd06c6b9b03152d07a4072152ae27)
        - [(4) Ghidra](#2ae406afda6602c8f02d73678b2ff040)
        - [Script Writting](#45910c8ea12447df9cdde2bea425f23f)
            - [(1) Other](#c12ccb8e11ba94184f8f24767eb64212)
            - [(1) Lang](#b24e162720cffd2d2456488571c1a136)
    - [Post&&Videos](#273df546f1145fbed92bb554a327b87a)
        - [(30) Recent Add](#ce49901b4914f3688ef54585c8f9df1a)
        - [(4) Vuln](#b7fb955b670df2babc67e5942297444d)
        - [Vuln Analysis](#dd0d49a5e6bd34b372d9bbf4475e8024)
            - [(3) Vuln Analysis&&Vuln Hunting](#375c75af4fa078633150415eec7c867d)
            - [(9) No Category](#f0ab053d7a282ab520c3a327fc91ba2e)
            - [(9) Malware](#4e3f53845efe99da287b2cea1bdda97c)
        - [Other](#92f60c044ed13b3ffde631794edd2756)
        - [Tips&&Tricks](#4bfa6dcf708b3f896870c9d3638c0cde)
        - [(5) Script Writting](#0d086cf7980f65da8f7112b901fecdc1)
        - [(15) RecentAdd1](#8962bde3fbfb1d1130879684bdf3eed0)
- [x64dbg](#b1a6c053e88e86ce01bbd78c54c63a7c)
    - [Plugins&&Scripts](#b4a856db286f9f29b5a32d477d6b3f3a)
        - [(63) Recent Add](#da5688c7823802e734c39b539aa39df7)
        - [(1) x64dbg](#353ea40f2346191ecb828210a685f9db)
    - [(21) Post&&Videos](#22894d6f2255dc43d82dd46bdbc20ba1)
- [OllyDbg](#37e37e665eac00de3f55a13dcfd47320)
    - [Plugins&&Scripts](#7834e399e48e6c64255a1a0fdb6b88f5)
        - [(13) Recent Add](#92c44f98ff5ad8f8b0f5e10367262f9b)
    - [(122) Post&&Videos](#8dd3e63c4e1811973288ea8f1581dfdb)
- [WinDBG](#0a506e6fb2252626add375f884c9095e)
    - [Plugins&&Scripts](#37eea2c2e8885eb435987ccf3f467122)
        - [(67) Recent Add](#2ef75ae7852daa9862b2217dca252cc3)
    - [(155) Post&&Videos](#6d8bac8bfb5cda00c7e3bd38d64cbce3)
- [Radare2](#86cb7d8f548ca76534b5828cb5b0abce)
    - [Plugins&&Scripts](#0e08f9478ed8388319f267e75e2ef1eb)
        - [(76) Recent Add](#6922457cb0d4b6b87a34caf39aa31dfe)
        - [(1) Radare2](#ec3f0b5c2cf36004c4dd3d162b94b91a)
        - [With Other Tools](#1a6652a1cb16324ab56589cb1333576f)
            - [(4) No Category](#dfe53924d678f9225fc5ece9413b890f)
            - [(3) IDA](#1cfe869820ecc97204a350a3361b31a7)
        - [GUI](#f7778a5392b90b03a3e23ef94a0cc3c6)
            - [(4) GUI](#8f151d828263d3bc038f75f8d6418758)
            - [(5) Cutter](#df45c3c60bd074e21d650266aa85c241)
    - [Posts&&Videos](#95fdc7692c4eda74f7ca590bb3f12982)
        - [(167) 未分类](#a4debf888d112b91e56c90136f513ec0)
        - [(5) Cutter](#d86e19280510aee0bcf2599f139cfbf7)
- [Cuckoo](#0ae4ddb81ff126789a7e08b0768bd693)
    - [Tools](#5830a8f8fb3af1a336053d84dd7330a1)
        - [(40) Recent Add](#f2b5c44c2107db2cec6c60477c6aa1d0)
    - [(62) Post&&Videos](#ec0a441206d9a2fe1625dce0a679d466)
- [BinaryNinja](#afb7259851922935643857c543c4b0c2)
    - [Plugins&&Scripts](#3034389f5aaa9d7b0be6fa7322340aab)
        - [(58) Recent Add](#a750ac8156aa0ff337a8639649415ef1)
        - [With Other Tools](#bba1171ac550958141dfcb0027716f41)
            - [(2) No Category](#c2f94ad158b96c928ee51461823aa953)
            - [(3) IDA](#713fb1c0075947956651cc21a833e074)
    - [(12) Posts&&Videos](#2d24dd6f0c01a084e88580ad22ce5b3c)
- [DBI](#7ab3a7005d6aa699562b3a0a0c6f2cff)
    - [DynamoRIO](#c8cdb0e30f24e9b7394fcd5681f2e419)
        - [Tools](#6c4841dd91cb173093ea2c8d0b557e71)
            - [(8) Recent Add](#ff0abe26a37095f6575195950e0b7f94)
            - [(2) DynamoRIO](#3a577a5b4730a1b5b3b325269509bb0a)
            - [(3) With Other Tools](#928642a55eff34b6b52622c6862addd2)
        - [(15) Posts&&Videos](#9479ce9f475e4b9faa4497924a2e40fc)
    - [IntelPin](#7b8a493ca344f41887792fcc008573e7)
        - [Tools](#fe5a6d7f16890542c9e60857706edfde)
            - [(18) Recent Add](#78a2edf9aa41eb321436cb150ea70a54)
            - [With Other Tools](#e6a829abd8bbc5ad2e5885396e3eec04)
                - [(8) No Category](#e129288dfadc2ab0890667109f93a76d)
        - [Posts&&Videos](#226190bea6ceb98ee5e2b939a6515fac)
    - [Frida](#f24f1235fd45a1aa8d280eff1f03af7e)
        - [Tools](#a5336a0f9e8e55111bda45c8d74924c1)
            - [(100) Recent Add](#54836a155de0c15b56f43634cd9cfecf)
            - [With Other Tools](#74fa0c52c6104fd5656c93c08fd1ba86)
                - [(1) No Category](#00a86c65a84e58397ee54e85ed57feaf)
                - [(3) IDA](#d628ec92c9eea0c4b016831e1f6852b3)
                - [(2) Binary Ninja](#f9008a00e2bbc7535c88602aa79c8fd8)
                - [(2) Radare2](#ac053c4da818ca587d57711d2ff66278)
            - [(1) Frida](#6d3c24e43835420063f9ca50ba805f15)
        - [(92) Posts&&Videos](#a1a7e3dd7091b47384c75dba8f279caf)
    - [QBDI](#b2fca17481b109a9b3b0bc290a1a1381)
        - [(1) Tools](#e72b766bcd3b868c438a372bc365221e)
        - [(6) Post](#2cf79f93baf02a24d95d227a0a3049d8)
    - [Other](#5a9974bfcf7cdf9b05fe7a7dc5272213)
        - [(4) Tools](#104bc99e36692f133ba70475ebc8825f)
        - [(1) Post](#8f1b9c5c2737493524809684b934d49a)
- [Other](#d3690e0b19c784e104273fe4d64b2362)
    - [Post-Recent Add](#9162e3507d24e58e9e944dd3f6066c0e)
    - [(284) Tool-Recent Add](#1d9dec1320a5d774dc8e0e7604edfcd3)
    - [(3) Tool-Other](#bc2b78af683e7ba983205592de8c3a7a)
    - [angr](#4fe330ae3e5ce0b39735b1bfea4528af)
        - [(27) Tool](#1ede5ade1e55074922eb4b6386f5ca65)
        - [(4) Post](#042ef9d415350eeb97ac2539c2fa530e)
    - [Debug](#324874bb7c3ead94eae6f1fa1af4fb68)
        - [(116) Tool](#d22bd989b2fdaeda14b64343b472dfb6)
        - [Post](#136c41f2d05739a74c6ec7d8a84df1e8)
    - [BAP](#9f8d3f2c9e46fbe6c25c22285c8226df)
        - [(26) Tool](#f10e9553770db6f98e8619dcd74166ef)
        - [Post](#e111826dde8fa44c575ce979fd54755d)
    - [BinNavi](#2683839f170250822916534f1db22eeb)
        - [(3) Tool](#2e4980c95871eae4ec0e76c42cc5c32f)
        - [(5) Post](#ff4dc5c746cb398d41fb69a4f8dfd497)
    - [Decompiler](#0971f295b0f67dc31b7aa45caf3f588f)
        - [(73) Tool](#e67c18b4b682ceb6716388522f9a1417)
        - [Post](#a748b79105651a8fd8ae856a7dc2b1de)
    - [Disassemble](#2df6d3d07e56381e1101097d013746a0)
        - [(30) Tool](#59f472c7575951c57d298aef21e7d73c)
        - [Post](#a6eb5a22deb33fc1919eaa073aa29ab5)
    - [GDB](#975d9f08e2771fccc112d9670eae1ed1)
        - [(80) Tool](#5f4381b0a90d88dd2296c2936f7e7f70)
        - [(102) Post](#37b17362d72f9c8793973bc4704893a2)
    - [Monitor](#70e64e3147675c9bcd48d4f475396e7f)
        - [(29) Tools](#cd76e644d8ddbd385939bb17fceab205)
- [TODO](#35f8efcff18d0449029e9d3157ac0899)


# <a id="35f8efcff18d0449029e9d3157ac0899"></a>TODO


- Add more tools and posts


# <a id="08e59e476824a221f6e4a69c0bba7d63"></a>IDA


***


## <a id="f11ab1ff46aa300cc3e86528b8a98ad7"></a>Tools


- Mainly from Github


### <a id="c39dbae63d6a3302c4df8073b4d1cdc8"></a>Recent Add


- [**111**Star][1m] [firmianay/security-paper](https://github.com/firmianay/security-paper) （与本人兴趣强相关的）各种安全or计算机资料收集
- [**4**Star][1y] [Py] [bitshifter123/arpwn](https://github.com/bitshifter123/arpwn) Analysis tools and exploit sample scripts for Adobe Reader 10/11 and Acrobat Reader DC
- [**4**Star][25d] [Py] [socraticbliss/ps4_ioctl_nabber_script](https://github.com/socraticbliss/ps4_ioctl_nabber_script) PS4 IOCTL Nabber / IDA 7.0-7.2
- [**2**Star][10m] [enusbaum/mbbsdasm.ida](https://github.com/enusbaum/mbbsdasm.ida) MBBSDASM Hex-Rays IDA IDS/IDT Files for MajorBBS/Worldgroup Modules


### <a id="c39a6d8598dde6abfeef43faf931beb5"></a>No Category


- [**1058**Star][17d] [Py] [fireeye/flare-ida](https://github.com/fireeye/flare-ida) Multiple IDA plugins and IDAPython scripts
    - [StackStrings](https://github.com/fireeye/flare-ida/blob/master/plugins/stackstrings_plugin.py) recovery of manually constructed strings described [here](http://www.fireeye.com/blog/threat-research/2014/08/flare-ida-pro-script-series-automatic-recovery-of-constructed-strings-in-malware.html)
    - [Struct Typer](https://github.com/fireeye/flare-ida/blob/master/plugins/struct_typer_plugin.py) implements the struct typing described [here](https://www.mandiant.com/blog/applying-function-types-structure-fields-ida/)
    - [ApplyCalleeType](https://github.com/fireeye/flare-ida/blob/master/python/flare/apply_callee_type.py) specify or choose a function type for indirect calls as described [here](https://www.fireeye.com/blog/threat-research/2015/04/flare_ida_pro_script.html)
    - [argtracker](https://github.com/fireeye/flare-ida/blob/master/python/flare/argtracker.py) identify static arguments to functions used within a program
    - [idb2pat](https://github.com/fireeye/flare-ida/blob/master/python/flare/idb2pat.py) generate function patterns from an existing IDB database that can then be turned into FLIRT signatures to help identify similar functions in new files. [more info](https://www.fireeye.com/blog/threat-research/2015/01/flare_ida_pro_script.html)
    - [objc2_analyzer](https://github.com/fireeye/flare-ida/blob/master/python/flare/objc2_analyzer.py) creates cross-references between selector references and their implementations as defined in the Objective-C runtime related sections of the target Mach-O executable
    - [MSDN Annotations](https://github.com/fireeye/flare-ida/tree/master/python/flare/IDB_MSDN_Annotator) adds MSDN information from a XML file to the IDB database. [more info](https://www.fireeye.com/blog/threat-research/2014/09/flare-ida-pro-script-series-msdn-annotations-ida-pro-for-malware-analysis.html)
    - [ironstrings](https://github.com/fireeye/flare-ida/tree/master/python/flare/ironstrings) uses code emulation to recover constructed strings (stackstrings) from malware
    - [Shellcode Hashes](https://github.com/fireeye/flare-ida/tree/master/shellcode_hashes) create the database for hash search described in [here](https://www.mandiant.com/blog/precalculated-string-hashes-reverse-engineering-shellcode/)
- [**737**Star][7m] [Py] [devttys0/ida](https://github.com/devttys0/ida) Collection of IDA Python plugins/scripts/modules.


    - [wpsearch](https://github.com/devttys0/ida/blob/master/scripts/wpsearch.py) Searches for immediate values commonly founds in MIPS WPS checksum implementations.
    - [md5hash](https://github.com/devttys0/ida/tree/master/modules/md5hash) A sample implementation of MD5 in pure Python
    - [alleycat](https://github.com/devttys0/ida/tree/master/plugins/alleycat) Finds paths to a given code block inside a function; Finds paths between two or more functions; Generates interactive call graphs
    - [codatify](https://github.com/devttys0/ida/tree/master/plugins/codatify) Defines ASCII-strings/functions/code that IDA's auto analysis missed; Converts all undefined bytes in the data segment into DWORDs
    - [fluorescence](https://github.com/devttys0/ida/tree/master/plugins/fluorescence) Un/highlights function call instructions
    - [leafblower](https://github.com/devttys0/ida/tree/master/plugins/leafblower) Assists in identifying standard POSIX functions in MIPS/ARM code.
    - [localxrefs](https://github.com/devttys0/ida/tree/master/plugins/localxrefs) Finds references to any selected text from within the current function
    - [mipslocalvars](https://github.com/devttys0/ida/tree/master/plugins/mipslocalvars) Names stack variables used by the compiler for storing registers on the stack, simplifying stack data analysis (MIPS only)
    - [mipsrop](https://github.com/devttys0/ida/tree/master/plugins/mipsrop) Allows you to search for suitable ROP gadgets in MIPS executable code; Built-in methods to search for common ROP gadgets
    - [rizzo](https://github.com/devttys0/ida/tree/master/plugins/rizzo) Identifies and re-names functions between two or more IDBs
- [**318**Star][2m] [C] [ohjeongwook/darungrim](https://github.com/ohjeongwook/darungrim) A patch analysis tool 
    - [IDA插件](https://github.com/ohjeongwook/darungrim/tree/master/Src/IDAPlugin) 
    - [DGEngine](https://github.com/ohjeongwook/darungrim/tree/master/Src/DGEngine) 
- [**312**Star][1y] [C++] [nevermoe/unity_metadata_loader](https://github.com/nevermoe/unity_metadata_loader)  load strings and method/class names in global-metadata.dat to IDA
- [**277**Star][4m] [Py] [jpcertcc/aa-tools](https://github.com/jpcertcc/aa-tools) Multiple RE plugins and scripts
    - [apt17scan.py](https://github.com/jpcertcc/aa-tools/blob/master/apt17scan.py) Volatility plugin for detecting APT17 related malware and extracting its config
    - [emdivi_postdata_decoder](https://github.com/jpcertcc/aa-tools/blob/master/emdivi_postdata_decoder.py) Python script for decoding Emdivi's post data
    - [emdivi_string_decryptor](https://github.com/jpcertcc/aa-tools/blob/master/emdivi_string_decryptor.py) IDAPython script for decrypting strings inside Emdivi
    - [citadel_decryptor](https://github.com/jpcertcc/aa-tools/tree/master/citadel_decryptor) Data decryption tool for Citadel
    - [adwind_string_decoder](https://github.com/jpcertcc/aa-tools/blob/master/adwind_string_decoder.py) Python script for decoding strings inside Adwind
    - [redleavesscan](https://github.com/jpcertcc/aa-tools/blob/master/redleavesscan.py) Volatility plugin for detecting RedLeaves and extracting its config
    - [datper_splunk](https://github.com/jpcertcc/aa-tools/blob/master/datper_splunk.py) Python script for detects Datper communication and adds result field to Splunk index
    - [datper_elk](https://github.com/jpcertcc/aa-tools/blob/master/datper_elk.py) Python script for detects Datper communication and adds result field to Elasticsearch index
    - [tscookie_decode](https://github.com/jpcertcc/aa-tools/blob/master/tscookie_decode.py) Python script for decrypting and parsing TSCookie configure data
    - [wellmess_cookie_decode](https://github.com/jpcertcc/aa-tools/blob/master/wellmess_cookie_decode.py) Python script for decoding WellMess's cookie data (support Python2)
    - [cobaltstrikescan](https://github.com/jpcertcc/aa-tools/blob/master/cobaltstrikescan.py) Volatility plugin for detecting Cobalt Strike Beacon and extracting its config
    - [tscookie_data_decode](https://github.com/jpcertcc/aa-tools/blob/master/tscookie_data_decode.py) Python script for decrypting and parsing TSCookie configure data
- [**114**Star][1y] [Py] [vallejocc/reverse-engineering-arsenal](https://github.com/vallejocc/Reverse-Engineering-Arsenal) Useful Scripts for helping in reverse engeenering
    - [WinDbg](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/WinDbg) WinDBG script collection
    - [IDA-set_symbols_for_addresses](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/IDA/set_symbols_for_addresses.py) asks you for a file containing pairs address - symbol. It walks all segments searching for DWORDs matching the addresses of the given file of pairs address - symbols, and it will name the variable containing the address with the symbol name
    - [IDA-stack_strings_deobfuscator_1](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/IDA/stack_strings_deobfuscator_1.py) Some malware families construct strings into the stack
    - [RevealPE](https://github.com/vallejocc/Reverse-Engineering-Arsenal/tree/master/Standalone/RevealPE) 
- [**80**Star][4m] [Py] [takahiroharuyama/ida_haru](https://github.com/takahiroharuyama/ida_haru) scripts for IDA Pro
    - [bindiff](https://github.com/takahiroharuyama/ida_haru/blob/master/bindiff/README.org) BinDiff wrapper script for multiple binary diffing
    - [eset_crackme](https://github.com/takahiroharuyama/ida_haru/blob/master/eset_crackme/README.org) IDA Pro loader/processor modules for ESET CrackMe driver VM
    - [fn_fuzzy](https://github.com/takahiroharuyama/ida_haru/blob/master/fn_fuzzy/README.org) IDAPython script for fast multiple binary diffing triage
    - [stackstring_static](https://github.com/takahiroharuyama/ida_haru/blob/master/stackstring_static/README.org) IDAPython script statically-recovering strings constructed in stack
- [**75**Star][10m] [Py] [secrary/ida-scripts](https://github.com/secrary/ida-scripts) IDAPro scripts/plugins
    - [dumpDyn](https://github.com/secrary/ida-scripts/blob/master/dumpDyn/README.md) IDAPython plugin(script) which saves comments, names, breakpoints, functions from one execution to another.
    - [idenLib](https://github.com/secrary/ida-scripts/blob/master/idenLib/README.md) Library Function Identification
    - [IOCTL_decode](https://github.com/secrary/ida-scripts/blob/master/IOCTL_decode.py) Windows Device IO Control Code
    - [XORCheck](https://github.com/secrary/ida-scripts/blob/master/XORCheck.py) check xor
- [**60**Star][2y] [Py] [tmr232/idabuddy](https://github.com/tmr232/idabuddy)  a reverse-engineer's best friend. Designed to be everything Clippy the Office Assistant was, and more!
- [**59**Star][2y] [C++] [alexhude/loadprocconfig](https://github.com/alexhude/loadprocconfig) IDA Plugin to load processor configuration files.
- [**59**Star][2m] [Py] [williballenthin/idawilli](https://github.com/williballenthin/idawilli) IDA Pro resources, scripts, and configurations
    - [hint_calls](https://github.com/williballenthin/idawilli/blob/master/plugins/hint_calls/readme.md) IDA plugin to display the calls and strings referenced by a function as hints.
    - [dynamic_hints](https://github.com/williballenthin/idawilli/blob/master/plugins/dynamic_hints/readme.md) an example plugin that demonstrates how to provide custom hints with dynamic data.
    - [add_segment](https://github.com/williballenthin/idawilli/tree/master/scripts/add_segment) IDAPython plugin that adds the contents of a file as a new segment in an existing idb
    - [color](https://github.com/williballenthin/idawilli/tree/master/scripts/color) IDAPython script that colors instructions
    - [find_ptrs](https://github.com/williballenthin/idawilli/tree/master/scripts/find_ptrs) IDAPython script that scans through the .text section for values that could be pointers (32-bit).
    - [yara_fn](https://github.com/williballenthin/idawilli/tree/master/scripts/yara_fn) IDAPython script that generates a YARA rule to match against the basic blocks of the current function
    - [idawilli](https://github.com/williballenthin/idawilli/tree/master/idawilli) a python module that contains utilities for working with the idapython scripting interface.
    - [themes](https://github.com/williballenthin/idawilli/tree/master/themes) colors and skins
- [**58**Star][20d] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA tools and scripts collection
    - Also In Section: [IDA->Tools->Import Export->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |[DBI->Frida->Tools->Recent Add](#54836a155de0c15b56f43634cd9cfecf) |
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor scripts
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida Scripts
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA Scripts
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) When there is chinese unicode character in programe, due to python's shortage, ida could not recongnized them correctly, it's what my script just do
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py)  When you deal with macho file with ida, you'll find out that it's not easy to find Objc-Class member function's caller and callee, (because it use msgSend instead of direct calling  convention), so we need to make some connection between the selector names and member function  pointers, it's what my script just do
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) When you debug android with IDA and gdbserver, you'd find that the module list and segment is empy, while we can read info from /proc/[pid]/,
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) this script is to trace instruction stream in one run 
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) this script is to detect ollvm and fix it in some extent, apply to android and ios
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) this script is used to analysis block structure exist in macho file, target NSConcreteStackBlock/NSConcreteGlobalBlock currently, also contain some wonderful skills
- [**54**Star][1y] [Py] [zardus/idalink](https://github.com/zardus/idalink) idalink arose of the need to easily use IDA's API for analysis without wanting to be stuck in the IDA interface
- [**52**Star][3y] [C++] [sektioneins/wwcd](https://github.com/sektioneins/wwcd) Capstone powered IDA view
- [**51**Star][2y] [Py] [cseagle/ida_clemency](https://github.com/cseagle/ida_clemency) IDA cLEMENCy Tools
    - [clemency_ldr](https://github.com/cseagle/ida_clemency/blob/master/clemency_ldr.py) IDA loader module to create the basic memory layout and handle the loading of 9-bit, middle-endian, cLEMENCy executables.
    - [clemency_proc](https://github.com/cseagle/ida_clemency/blob/master/clemency_proc.py) IDA processor module to handle disassembly and assembly tasks
    - [clemency_dump](https://github.com/cseagle/ida_clemency/blob/master/clemency_dump.py) IDA plugin to allow for dumping modified database content back to a packed 9-bit, middle-endian file 
    - [clemency_fix](https://github.com/cseagle/ida_clemency/blob/master/clemency_fix.py)  IDA plugin to assist with fixing up poorly disassembled functions that might branch/call into regions that continue to be marked as data blocks.
- [**49**Star][12m] [Py] [agustingianni/utilities](https://github.com/agustingianni/utilities) Uncategorized utilities
    - [DumpFunctionBytes](https://github.com/agustingianni/utilities/blob/master/DumpFunctionBytes.py)  dumps the current function (you need to position the cursor on the start of the function) as a shellcode. It does a very limited analysis of the function in order to let you know that you need to fix call sites to functions
    - [func_references](https://github.com/agustingianni/utilities/blob/master/func_references.py) print all the function calls to a given function. This is generally used to look for calls to malloc like function
    - [arm_frequency](https://github.com/agustingianni/utilities/blob/master/arm_frequency.py) takes as input the output of objdump on an ARM binary. It will show the ammount of times every instruction was used, sorted by the most used ones.
    - [struct_hint](https://github.com/agustingianni/utilities/blob/master/struct_hint.py) infer what's the underlying structure used by a function. Highly heuristic. Don't trust it blindly, just try to use what it gives you and work from that.
    - [string_finder](https://github.com/agustingianni/utilities/blob/master/string_finder.py) Utility to find all the strings inside an ill formed IDA Database
    - [simple_jack](https://github.com/agustingianni/utilities/blob/master/simple_jack.py) Simple Jack symbol porting tool by goose
    - [renamer](https://github.com/agustingianni/utilities/blob/master/renamer.py) Rename files in a directory to its sha1 sum plus an extension.
    - [prolog_finder](https://github.com/agustingianni/utilities/blob/master/prolog_finder.py) Find potential ARM procedures prolog
    - [minset](https://github.com/agustingianni/utilities/blob/master/minset.py) Tool to calculate the minimum set of files that have approximatelly the best coverage.
    - [mark_interesting](https://github.com/agustingianni/utilities/blob/master/mark_interesting.py) Small idapython script that finds all the signed comparisions and marks them with a color.
    - [machofinder](https://github.com/agustingianni/utilities/blob/master/machofinder.py) Hacky script to gather all the mach-o file (and fat).
    - [find_hardref](https://github.com/agustingianni/utilities/blob/master/find_hardref.py) Script to find hardcoded references inside an IDA database.
- [**47**Star][4y] [Py] [jjo-sec/idataco](https://github.com/jjo-sec/idataco) IDATACO IDA Pro Plugin
- [**46**Star][7y] [Py] [carlosgprado/milf](https://github.com/carlosgprado/milf) An IDA Pro swiss army knife 
    - [milf](https://github.com/carlosgprado/MILF/blob/master/milf.py) Some useful methods in vulnerability discovery
- [**42**Star][4y] [C++] [nihilus/guid-finder](https://github.com/nihilus/guid-finder) find GUID/UUIDs
- [**40**Star][7m] [Visual Basic .NET] [dzzie/re_plugins](https://github.com/dzzie/re_plugins) misc reverse engineering plugins
    - [IDASrvr](https://github.com/dzzie/re_plugins/tree/master/IDASrvr) wm_copydata IPC server running in IDA. allows you to send commands to IDA from another   process to query data and control interface display
    - [IDA_JScript](https://github.com/dzzie/re_plugins/tree/master/IDA_JScript) Script IDA in Javascript
    - [IDA_JScript_w_DukDbg](https://github.com/dzzie/re_plugins/tree/master/IDA_JScript_w_DukDbg) same as IDA_JScript, but using the dukdbg.ocx as full on javascript debugger
    - [IDASrvr2](https://github.com/dzzie/re_plugins/tree/master/IDASrvr2) support x64
    - [IdaUdpBridge](https://github.com/dzzie/re_plugins/tree/master/IdaUdpBridge) this replaces the udp command socket in idavbscript which was crashy
    - [IdaVbScript](https://github.com/dzzie/re_plugins/tree/master/IdaVbScript)  ton of small tools for IDA all thrown into one interface
    - [OllySrvr](https://github.com/dzzie/re_plugins/tree/master/OllySrvr)  wm_copydata IPC server running in olly
    - [Olly_hittrace](https://github.com/dzzie/re_plugins/tree/master/Olly_hittrace) You set breakpoints in the UI and it will then run   the app automating it and logging which ones were hit.
    - [Olly_module_bpx](https://github.com/dzzie/re_plugins/tree/master/Olly_module_bpx)    allow you to set breakpoints within modules which have not yet been loaded.
    - [Olly_vbscript](https://github.com/dzzie/re_plugins/tree/master/Olly_vbscript) vbscript automation capability for olly including working across breakpoint events.
    - [PyIDAServer](https://github.com/dzzie/re_plugins/tree/master/PyIDAServer) experiment to test a python based IPC server running in IDA that remote process clients can control and query IDA with.
    - [Wingraph32](https://github.com/dzzie/re_plugins/tree/master/Wingraph32) This is another experiment at a wingraph32 replacement for ida. This one has more features to hide nodes, and can also navigate IDA to the selected function when you click on it in the graph. 
    - [rabc_gui](https://github.com/dzzie/re_plugins/tree/master/flash_tools/rabc_gui) this is a GUI front end for RABCDAsm to disasm, reasm, and reinsert  modified script blocks back into flash files.
    - [swfdump_gui](https://github.com/dzzie/re_plugins/tree/master/flash_tools/swfdump_gui) when run against a target swf, it will create a decompressed version of the swf and a .txt disasm log file these files will be cached and used on subsequent loads. if you wish to start over from scratch use the tools->delete cached * options.
    - [gleegraph](https://github.com/dzzie/re_plugins/tree/master/gleegraph) a quick Wingraph32/qwingraph replacement that has some extra features such as being able to navigate IDA to the selected nodes when they are clicked on in graph view, as well as being able to rename the selected node from the  graph, or adding a prefix to all child nodes below it.
    - [hidden_strings](https://github.com/dzzie/re_plugins/tree/master/misc_tools/hidden_strings) scans for strings being build up in char arrays at runtime to hide from traditional strings output
    - [memdump_conglomerate](https://github.com/dzzie/re_plugins/tree/master/misc_tools/memdump_conglomerate) reads a folder full of memory dumps and puts them  all into a single dll husk so they will disassemble at the proper offsets.
    - [memdump_embedder](https://github.com/dzzie/re_plugins/tree/master/misc_tools/memdump_embedder) takes a memory dump and embeds it into a dummy dll husk so that you can disassemble it at the target base address without having to manually reset it everytime
    - [rtf_hexconvert](https://github.com/dzzie/re_plugins/tree/master/misc_tools/rtf_hexconvert) small tool to extract hex strings from a rtf document and show them in a listview. click on listitem to see decoded data in a hexeditor pane where you can save it
    - [uGrapher](https://github.com/dzzie/re_plugins/tree/master/uGrapher) rename real wingraph32.exe to _wingraph.exe and put this one in its place.
    - [wininet_hooks](https://github.com/dzzie/re_plugins/tree/master/wininet_hooks) httpsendhook.dll hooks the following wininet api calls:HttpOpenRequest,InternetConnect,InternetReadFile,InternetCrackUrl,HttpSendRequest
- [**40**Star][2y] [Py] [mxmssh/idametrics](https://github.com/mxmssh/idametrics)  static software complexity metrics collection
- [**38**Star][2y] [Py] [saelo/ida_scripts](https://github.com/saelo/ida_scripts) Collection of IDA scripts
    - [kernelcache](https://github.com/saelo/ida_scripts/blob/master/kernelcache.py) Identify and rename function stubs (plt entries) in an iOS kernelcache. ARM64 only.
    - [ssdt](https://github.com/saelo/ida_scripts/blob/master/ssdt.py) Resolve syscall table entries in the Windows kernel.
- [**34**Star][4y] [Py] [madsc13ntist/idapython](https://github.com/madsc13ntist/idapython) My collection of IDAPython scripts.(No Documentation)
- [**32**Star][5y] [Py] [iphelix/ida-pomidor](https://github.com/iphelix/ida-pomidor) a productivity plugin for Hex-Ray's IDA Pro disassembler.
- [**28**Star][1y] [Py] [xyzz/vita-ida-physdump](https://github.com/xyzz/vita-ida-physdump) help with physical memory dump reversing
- [**27**Star][1y] [Py] [daniel_plohmann/simplifire.idascope](https://bitbucket.org/daniel_plohmann/simplifire.idascope)  An IDA Pro extension for easier (malware) reverse engineering
- [**27**Star][6m] [Py] [enovella/re-scripts](https://github.com/enovella/re-scripts) IDA, Ghidra and Radare2 scripts(no documentation)
- [**26**Star][5y] [Py] [bastkerg/recomp](https://github.com/bastkerg/recomp) IDA recompiler（No Documentation）
- [**26**Star][8m] [C++] [offlinej/ida-rpc](https://github.com/offlinej/ida-rpc) Discord rich presence plugin for IDA Pro 7.0
- [**25**Star][3y] [Py] [zyantific/continuum](https://github.com/zyantific/continuum) Plugin adding multi-binary project support to IDA Pro (WIP)
- [**23**Star][3m] [Py] [rceninja/re-scripts](https://github.com/rceninja/re-scripts) 
    - [Hyperv-Scripts](https://github.com/rceninja/re-scripts/tree/master/scripts/Hyperv-Scripts) 
    - [IA32-MSR-Decoder](https://github.com/rceninja/re-scripts/tree/master/scripts/IA32-MSR-Decoder) an IDA script which helps you to find and decode all MSR codes inside binary files
    - [IA32-VMX-Helper](https://github.com/rceninja/re-scripts/tree/master/scripts/IA32-VMX-Helper) an IDA script (Updated IA32 MSR Decoder) which helps you to find and decode all MSR/VMCS codes inside binary files
- [**23**Star][10m] [C++] [trojancyborg/ida_jni_rename](https://github.com/trojancyborg/ida_jni_rename) IDA JNI clal rename
- [**22**Star][5y] [Py] [nihilus/idascope](https://github.com/nihilus/idascope)  An IDA Pro extension for easier (malware) reverse engineering（Bitbucket has newer version）
- [**22**Star][4m] [Py] [nlitsme/idascripts](https://github.com/nlitsme/idascripts) IDApro idc and idapython script collection
    - [enumerators](https://github.com/nlitsme/idascripts/blob/master/enumerators.py) Enumeration utilities for idapython
- [**22**Star][4y] [Py] [onethawt/idapyscripts](https://github.com/onethawt/idapyscripts) IDAPython scripts
    - [DataXrefCounter ](https://github.com/onethawt/idapyscripts/blob/master/dataxrefcounter.py)  A small IDAPython plugin which enumerates all of the the x-references in a specific segment and counts the frequency of usage
- [**22**Star][3y] [C++] [patois/idaplugins](https://github.com/patois/idaplugins) Random IDA scripts, plugins, example code (some of it may be old and not working anymore)
- [**20**Star][1y] [Py] [hyuunnn/ida_python_scripts](https://github.com/hyuunnn/ida_python_scripts) IDAPython scripts(No Documentation)
    - [IDA_comment](https://github.com/hyuunnn/ida_python_scripts/blob/master/IDA_comment.py) 
    - [ida_function_rename](https://github.com/hyuunnn/ida_python_scripts/blob/master/ida_function_rename.py) 
    - [variable_finder](https://github.com/hyuunnn/ida_python_scripts/blob/master/variable_finder.py) 
    - [assembler_disassembler](https://github.com/hyuunnn/ida_python_scripts/blob/master/assembler_disassembler.py) 
    - [api_visualization](https://github.com/hyuunnn/ida_python_scripts/tree/master/api_visualization) 
    - [Decoder](https://github.com/hyuunnn/ida_python_scripts/tree/master/Decoder) Multiple malware decoders
- [**20**Star][2y] [C#] [zoebear/radia](https://github.com/zoebear/radia) create an interactive and immerse environment to visualize code, and to augment the task of reverse engineering binaries
- [**20**Star][3y] [Py] [ztrix/idascript](https://github.com/ztrix/idascript) Full functional idascript with stdin/stdout handled
- [**20**Star][1y] [Py] [hyuunnn/ida_python_scripts](https://github.com/hyuunnn/ida_python_scripts) ida python scripts
- [**20**Star][2m] [Py] [mephi42/ida-kallsyms](https://github.com/mephi42/ida-kallsyms) (No Doc)
- [**19**Star][1y] [Py] [a1ext/ida-embed-arch-disasm](https://github.com/a1ext/ida-embed-arch-disasm) Allows you to disassemble x86-64 code (like inlined WOW64 one) while you using 32-bit IDA database
- [**19**Star][9m] [Py] [yellowbyte/reverse-engineering-playground](https://github.com/yellowbyte/reverse-engineering-playground) Scripts I made to aid me in everyday reversing or just for fun.
    - [idapython-scripts](https://github.com/yellowbyte/reverse-engineering-playground/tree/master/idapython) 
    - [IDA-ARMdetect](https://github.com/yellowbyte/reverse-engineering-playground/blob/master/idapython/ARMdetect.py) Identifies all sections in a ARM binary that is setting up (writing to) a pin, reading a pin (using the pin as input pin), or interfacing with other devices on the board using I2C
    - [IDA-CCCheck](https://github.com/yellowbyte/reverse-engineering-playground/blob/master/idapython/CCCheck.py) The 0xCC byte is the byte representing int 3, or software breakpoint. When you make a software breakpoint on an instruction, the debugger replaces the first byte of the instruction to 0xCC.
    - [IDA-Deobfuscate](https://github.com/yellowbyte/reverse-engineering-playground/blob/master/idapython/Deobfuscate.py) directly patch the bytes in IDA so IDA will show the correct deobfuscated listing rather than writing the deobfuscated listing to a separate file
    - [IDA-FindMain](https://github.com/yellowbyte/reverse-engineering-playground/blob/master/idapython/FindMain.py) automatically find and rename main as "main" and then move cursor position in IDA's disassembly listing to beginning of main.(In a stripped ELF executable, IDA will not be able to identify main)
    - [IDA-intCheck](https://github.com/yellowbyte/reverse-engineering-playground/blob/master/idapython/intCheck.py) Interrupts are either generated by external sources, such as I/O devices, or by processor-detected exceptions in the running code
    - [IDA-JccFlip](https://github.com/yellowbyte/reverse-engineering-playground/blob/master/idapython/JccFlip.py) Changes a jcc instruction to its opposite representation.
    - [IDA-LocFuncAnalyzer](https://github.com/yellowbyte/reverse-engineering-playground/blob/master/idapython/LocFuncAnalyzer.py) In a stripped ELF binary, local functions are deprived of its original name. This is why local functions are not usually the starting point when doing analysis since without its original name, all local functions look exactly the same as one another. This script aims to change that
    - [IDA-MalCheck](https://github.com/yellowbyte/reverse-engineering-playground/blob/master/idapython/MalCheck.py) Checks an executable for usage of API that has a high chance of being used maliciously or for anti-reversing purposes such as IsDebuggerPresent
    - [IDA-NopSled](https://github.com/yellowbyte/reverse-engineering-playground/blob/master/idapython/NopSled.py) Either convert the instructions that user select/highlight or the instruction that the mouse cursor is on to NOPs
    - [IDA-RdtscCheck](https://github.com/yellowbyte/reverse-engineering-playground/blob/master/idapython/RdtscCheck.py) rdtsc instruction puts the number of ticks since the last system reboot in EDX:EAX
    - [file_format_hacks](https://github.com/yellowbyte/reverse-engineering-playground/tree/master/file_format_hacks) File Format Hacks
    - [file_analysis](https://github.com/yellowbyte/reverse-engineering-playground/tree/master/file_analysis) 
    - [shellcode_analysis](https://github.com/yellowbyte/reverse-engineering-playground/tree/master/shellcode_analysis) Shellcode Analysis
- [**17**Star][1y] [Py] [honeybadger1613/etm_displayer](https://github.com/honeybadger1613/etm_displayer) IDA Pro плагин для отображения результата Coresight ETM трассировки perf'а
- [**16**Star][5y] [fabi/idacsharp](https://github.com/fabi/idacsharp) C# 'Scripts' for IDA 6.6+ based on
- [**15**Star][8m] [CMake] [google/idaidle](https://github.com/google/idaidle) a plugin for the commercial IDA Pro disassembler that warns users if they leave their instance idling for too long
- [**14**Star][4y] [C++] [nihilus/fast_idb2sig_and_loadmap_ida_plugins](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins) ida plugins
    - [LoadMap](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins/tree/master/LoadMap)  An IDA plugin, which loads a VC/Borland/Dede map file into IDA 4.5
    - [idb2sig](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins/blob/master/idb2sig/ReadMe.txt) 
- [**13**Star][2y] [Py] [cisco-talos/pdata_check](https://github.com/cisco-talos/pdata_check) identify unusual runtimes based on the pdata section and the last instruction of the runtime function
- [**13**Star][1y] [C++] [nihilus/graphslick](https://github.com/nihilus/graphslick) IDA Plugin - GraphSlick
- [**13**Star][1y] [Py] [cxm95/ida_wrapper](https://github.com/cxm95/ida_wrapper) An IDA_Wrapper for linux, shipped with an Function Identifier. It works well with Driller on static linked binaries.
- [**12**Star][1y] [Assembly] [gabrielravier/cave-story-decompilation](https://github.com/gabrielravier/cave-story-decompilation) Decompilation of Cave Story. Can be opened with IDA Pro (freeware and pro version).
- [**11**Star][2y] [Py] [0xddaa/iddaa](https://github.com/0xddaa/iddaa) idapython scripts
- [**11**Star][5y] [Py] [dshikashio/idarest](https://github.com/dshikashio/idarest) Expose some basic IDA Pro interactions through a REST API for JSONP
- [**11**Star][10m] [C++] [ecx86/ida7-supportlib](https://github.com/ecx86/ida7-supportlib) IDA-SupportLib library by sirmabus, ported to IDA 7
- [**10**Star][4y] [C++] [revel8n/spu3dbg](https://github.com/revel8n/spu3dbg) Ida Pro debugger module for the anergistic SPU emulator.
- [**9**Star][4y] [Py] [nfarrar/ida-colorschemes](https://github.com/nfarrar/ida-colorschemes) A .clr colorscheme generator for IDA Pro 6.4+.
- [**9**Star][2m] [C++] [nlitsme/idcinternals](https://github.com/nlitsme/idcinternals) investigate the internals of IDA
- [**9**Star][5y] [Ruby] [rogwfu/plympton](https://github.com/rogwfu/plympton) Library to work with yaml exported IDA Pro information and run statistics
- [**9**Star][9m] [Py] [0xcpu/relieve](https://github.com/0xcpu/relieve) Scripts used for reverse engineering, malware analysis.
    - [elfie](https://github.com/0xcpu/relieve/blob/master/elfie.py)  display (basic) info about an ELF, similar to readelf.
    - [elforensics](https://github.com/0xcpu/relieve/blob/master/elforensics.py)  check ELF for entry point hooks, RWX sections, CTORS & GOT & PLT hooks, function prologue trampolines.
    - [dololi](https://github.com/0xcpu/relieve/tree/master/dololi) unfinished, the idea is to automatically generate an executable that calls exports from DLL(s).
- [**8**Star][5y] [Py] [daniel_plohmann/idapatchwork](https://bitbucket.org/daniel_plohmann/idapatchwork) Stitching against malware families with IDA Pro
- [**8**Star][2y] [C++] [ecx86/ida7-segmentselect](https://github.com/ecx86/ida7-segmentselect) IDA-SegmentSelect library by sirmabus, ported to IDA 7
- [**8**Star][2y] [Py] [fireundubh/ida7-alleycat](https://github.com/fireundubh/ida7-alleycat) Alleycat plugin by devttys0, ported to IDA 7
- [**8**Star][2m] [Py] [lanhikari22/gba-ida-pseudo-terminal](https://github.com/lanhikari22/gba-ida-pseudo-terminal) IDAPython tools to aid with analysis, disassembly and data extraction using IDA python commands, tailored for the GBA architecture at some parts
- [**8**Star][3y] [Py] [pwnslinger/ibt](https://github.com/pwnslinger/ibt) IDA Pro Back Tracer - Initial project toward automatic customized protocols structure extraction
- [**8**Star][2y] [C++] [shazar14/idadump](https://github.com/shazar14/idadump) An IDA Pro script to verify binaries found in a sample and write them to disk
- [**7**Star][2y] [Py] [swackhamer/ida_scripts](https://github.com/swackhamer/ida_scripts) IDAPython scripts（No Doc）
- [**7**Star][10m] [Py] [techbliss/ida_pro_http_ip_geolocator](https://github.com/techbliss/ida_pro_http_ip_geolocator) look up web addresses and resolve it to a ip and look it via google maps
- [**7**Star][5y] [Py] [techbliss/processor-changer](https://github.com/techbliss/processor-changer) change processor inside ida, No need to Reopen Ida Pro
- [**7**Star][1y] [C++] [tenable/mida](https://github.com/tenable/mida) an IDA plugin which extracts RPC interfaces and recreates the associated IDL file
- [**7**Star][1y] [C++] [ecx86/ida7-hexrays-invertif](https://github.com/ecx86/ida7-hexrays-invertif) Hex-Rays Invert if statement plugin for IDA 7.0
- [**6**Star][2y] [CMake] [elemecca/cmake-ida](https://github.com/elemecca/cmake-ida) This project provides CMake support for building IDA Pro modules.
- [**6**Star][9m] [Py] [geosn0w/dumpanywhere64](https://github.com/geosn0w/dumpanywhere64) An IDA (Interactive Disassembler) script that can save a chunk of binary from an address.
- [**5**Star][3y] [Py] [andreafioraldi/idavshelp](https://github.com/andreafioraldi/idavshelp) IDAPython plugin to integrate Visual Studio Help Viewer in IDA Pro >= 6.8.
- [**5**Star][5m] [Py] [fdiskyou/ida-plugins](https://github.com/fdiskyou/ida-plugins) IDAPython scripts（No Documentation）
    - [banned_functions](https://github.com/fdiskyou/ida-plugins/blob/master/banned_functions.py) 
- [**5**Star][3y] [Py] [gh0st3rs/idassldump](https://github.com/gh0st3rs/idassldump) Simple IDAPython script for dump ssl traffic to file
- [**5**Star][1y] [C++] [lab313ru/m68k_fixer](https://github.com/lab313ru/m68k_fixer) IDA Pro plugin fixer for m68k
- [**5**Star][5y] [C#] [npetrovski/ida-smartpatcher](https://github.com/npetrovski/ida-smartpatcher) IDA apply patch GUI
- [**5**Star][4y] [Py] [tmr232/tarkus](https://github.com/tmr232/tarkus) Plugin Manager for IDA Pro
- [**5**Star][2y] [abarbatei/ida-utils](https://github.com/abarbatei/ida-utils) links, information and helper scripts for IDA Pro
- [**4**Star][3m] [Py] [gitmirar/idaextapi](https://github.com/gitmirar/idaextapi) IDA API utlitites
- [**4**Star][3y] [Py] [hustlelabs/joseph](https://github.com/hustlelabs/joseph) IDA Viewer Plugins
- [**4**Star][1y] [savagedd/samp-server-idb](https://github.com/savagedd/samp-server-idb) 
- [**4**Star][3m] [Py] [spigwitmer/golang_struct_builder](https://github.com/spigwitmer/golang_struct_builder) IDA 7.0+ script that auto-generates structs and interfaces from runtime metadata found in golang binaries
- [**3**Star][10m] [Py] [gdataadvancedanalytics/ida-python](https://github.com/gdataadvancedanalytics/ida-python) Random assembly of IDA Python scripts
    - [defineIAT](https://github.com/gdataadvancedanalytics/ida-python/blob/master/Trickbot/defineIAT.py) written for the Trickbot sample with sha256 8F590AC32A7C7C0DDFBFA7A70E33EC0EE6EB8D88846DEFBDA6144FADCC23663A
    - [stringDecryption](https://github.com/gdataadvancedanalytics/ida-python/blob/master/Trickbot/stringDecryption.py) written for the Trickbot sample with sha256 8F590AC32A7C7C0DDFBFA7A70E33EC0EE6EB8D88846DEFBDA6144FADCC23663A
- [**3**Star][5y] [C++] [nihilus/ida-x86emu](https://github.com/nihilus/ida-x86emu) x86 emulator
- [**3**Star][2y] [Py] [ypcrts/ida-pro-segments](https://github.com/ypcrts/ida-pro-segments) It's very hard to load multiple files in the IDA GUI without it exploding. This makes it easy.
- [**2**Star][2y] [C++] [ecx86/ida7-oggplayer](https://github.com/ecx86/ida7-oggplayer) IDA-OggPlayer library by sirmabus, ported to IDA 7
- [**2**Star][2y] [Py] [mayl8822/ida](https://github.com/mayl8822/ida) SearchGoogle
- [**2**Star][4y] [Py] [nihilus/idapatchwork](https://github.com/nihilus/idapatchwork) Stitching against malware families with IDA Pro
- [**2**Star][2y] [Py] [sbouber/idaplugins](https://github.com/sbouber/idaplugins) 
- [**2**Star][2m] [Py] [psxvoid/idapython-debugging-dynamic-enrichment](https://github.com/psxvoid/idapython-debugging-dynamic-enrichment) 
- [**1**Star][2y] [Py] [andreafioraldi/idamsdnhelp](https://github.com/andreafioraldi/idamsdnhelp) IdaPython plugin to open MSDN Search page
- [**1**Star][1y] [Py] [farzonl/idapropluginlab4](https://github.com/farzonl/idapropluginlab4) An ida pro plugin that tracks def use chains of a given x86 binary.
- [**1**Star][3m] [Py] [voidsec/ida-helpers](https://github.com/voidsec/ida-helpers) Collection of IDA helpers
- [**0**Star][3y] [Py] [kcufid/my_ida_python](https://github.com/kcufid/my_ida_python) My idapython decode data
- [**0**Star][1y] [Py] [ruipin/idapy](https://github.com/ruipin/idapy) Various IDAPython libraries and scripts
- [**0**Star][9m] [Py] [tkmru/idapython-scripts](https://github.com/tkmru/idapython-scripts) IDAPro scripts


### <a id="fb4f0c061a72fc38656691746e7c45ce"></a>Structure&&Class


#### <a id="fa5ede9a4f58d4efd98585d3158be4fb"></a>No Category


- [**931**Star][25d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) a static Binary Code Analysis Toolkit, designed to help reverse engineers, directly from IDA or using Python for automation.
    - Also In Section: [IDA->Tools->Taint Analysis](#34ac84853604a7741c61670f2a075d20) |
- [**664**Star][27d] [Py] [igogo-x86/hexrayspytools](https://github.com/igogo-x86/hexrayspytools) assists in the creation of classes/structures and detection of virtual tables
- [**168**Star][1y] [Py] [bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) An IDA Toolkit for analyzing iOS kernelcaches
    - Also In Section: [IDA->Tools->Apple->Kernel Cache](#82d0fa2d6934ce29794a651513934384) |
- [**140**Star][4y] [C++] [nihilus/hexrays_tools](https://github.com/nihilus/hexrays_tools) Assist in creation of new structure definitions / virtual calls detection
- [**103**Star][4m] [Py] [lucasg/findrpc](https://github.com/lucasg/findrpc) Ida script to extract RPC interface from binaries
- [**4**Star][3y] [C#] [andreafioraldi/idagrabstrings](https://github.com/andreafioraldi/idagrabstrings) IDAPython plugin to manipulate strings in a specified range of addresses
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |


#### <a id="4900b1626f10791748b20630af6d6123"></a>C++ Class&&Virtual Table


- [**607**Star][3m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) IDAPython tool for C++ vtables reconstruction
    - Also In Section: [IDA->Tools->Debug->Debugger Data](#b31acf6c84a9506066d497af4e702bf5) |
        <details>
        <summary>View Details</summary>


        ## 静态部分: 
        - 检测非直接调用
        - 利用条件断点, Hook非直接调用的值赋值过程
        
        ## 动态 部分
        - 创建虚表结构
        - 重命名函数和虚表地址
        - 给反汇编非直接调用添加结构偏移
        - 给非直接调用到虚表之间添加交叉引用
        
        ## 使用
        - File -> Script File -> Main.py(设置断点) -> IDA调试器执行
        </details>


- [**171**Star][10m] [C++] [ecx86/classinformer-ida7](https://github.com/ecx86/classinformer-ida7) ClassInformer backported for IDA Pro 7.0
- [**130**Star][2y] [Py] [nccgroup/susanrtti](https://github.com/nccgroup/SusanRTTI) Another RTTI Parsing IDA plugin
- [**90**Star][1y] [C++] [rub-syssec/marx](https://github.com/rub-syssec/marx) Uncovering Class Hierarchies in C++ Programs
    - [IDA导出](https://github.com/rub-syssec/marx/blob/master/ida_export/export.py) 
    - [IDA导入插件](https://github.com/rub-syssec/marx/tree/master/ida_import) 
    - [core](https://github.com/rub-syssec/marx/tree/master/src) 
- [**69**Star][7y] [C] [nektra/vtbl-ida-pro-plugin](https://github.com/nektra/vtbl-ida-pro-plugin) Identifying Virtual Table Functions using VTBL IDA Pro Plugin + Deviare Hooking Engine
- [**35**Star][5y] [C++] [nihilus/ida_classinformer](https://github.com/nihilus/ida_classinformer) IDA ClassInformer PlugIn
- [**32**Star][2y] [Py] [krystalgamer/dec2struct](https://github.com/krystalgamer/dec2struct) Python plugin to easily setup vtables in IDA using declaration files
- [**16**Star][2y] [C++] [mwl4/ida_gcc_rtti](https://github.com/mwl4/ida_gcc_rtti) Class informer plugin for IDA which supports parsing GCC RTTI




### <a id="a7dac37cd93b8bb42c7d6aedccb751b3"></a>Collection


- [**1771**Star][10d] [onethawt/idaplugins-list](https://github.com/onethawt/idaplugins-list) A list of IDA Plugins
- [**363**Star][9m] [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) Awesome IDA, x64DBG & OllyDBG plugin
    - Also In Section: [x64dbg->Plugins->Recent Add](#da5688c7823802e734c39b539aa39df7) |
- [**10**Star][1y] [Py] [ecx86/ida-scripts](https://github.com/ecx86/ida-scripts) Collection of my IDA Pro/Hex-Rays scripts and plugins


### <a id="fabf03b862a776bbd8bcc4574943a65a"></a>Skin&&Theme


- [**723**Star][7m] [Py] [zyantific/idaskins](https://github.com/zyantific/idaskins) Plugin providing advanced skinning support for IDA Pro utilizing Qt stylesheets, similar to CSS.
- [**258**Star][7y] [eugeneching/ida-consonance](https://github.com/eugeneching/ida-consonance) Consonance, a dark color theme for IDA.
- [**106**Star][6m] [CSS] [0xitx/ida_nightfall](https://github.com/0xitx/ida_nightfall) A dark color theme for IDA Pro
- [**58**Star][7y] [gynophage/solarized_ida](https://github.com/gynophage/solarized_ida) "Solarized Dark" color scheme for IDA Pro.
- [**10**Star][7y] [Py] [luismiras/ida-color-scripts](https://github.com/luismiras/ida-color-scripts) a collection of color scripts for IDA Pro. They deal with import and export of color themes.
- [**9**Star][2y] [CSS] [gbps/x64dbg-consonance-theme](https://github.com/gbps/x64dbg-consonance-theme) dark x64dbg color theme based on IDA Consonance
- [**6**Star][5y] [Py] [techbliss/ida-styler](https://github.com/techbliss/ida-styler) Small Plugin to change the style off Ida Pro
- [**3**Star][3m] [rootbsd/ida_pro_zinzolin_theme](https://github.com/rootbsd/ida_pro_zinzolin_theme) IDA Pro zinzolin theme
- [**1**Star][1y] [C] [albertzsigovits/idc-dark](https://github.com/albertzsigovits/idc-dark) A dark-mode color scheme for Hex-Rays IDA using idc


### <a id="a8f5db3ab4bc7bc3d6ca772b3b9b0b1e"></a>Firmware&&Embed Device


- [**5228**Star][2m] [Py] [refirmlabs/binwalk](https://github.com/ReFirmLabs/binwalk) a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.
    - [IDA插件](https://github.com/ReFirmLabs/binwalk/tree/master/src/scripts) 
    - [binwalk](https://github.com/ReFirmLabs/binwalk/tree/master/src/binwalk) 
- [**492**Star][5m] [Py] [maddiestone/idapythonembeddedtoolkit](https://github.com/maddiestone/idapythonembeddedtoolkit) a set of script to automate many of the steps associated with statically analyzing, or reverse engineering, the firmware of embedded devices in IDA Pro.
- [**177**Star][2y] [Py] [duo-labs/idapython](https://github.com/duo-labs/idapython)  a few Python modules developed for use with IDA Pro from the researchers at Duo Labs.
    - Also In Section: [IDA->Tools->Apple->No Category](#8530752bacfb388f3726555dc121cb1a) |
    - [cortex_m_firmware](https://github.com/duo-labs/idapython/blob/master/cortex_m_firmware.py) grooms an IDA Pro database containing firmware from an ARM Cortex M microcontroller.
    - [amnesia](https://github.com/duo-labs/idapython/blob/master/amnesia.py)  an IDAPython module designed to use byte level heuristics to find ARM thumb instructions in undefined bytes in an IDA Pro database
    - [REobjc](https://github.com/duo-labs/idapython/blob/master/reobjc.py)  an IDAPython module designed to make proper cross references between calling functions and called functions in Objective-C methods
- [**101**Star][1m] [Py] [pagalaxylab/vxhunter](https://github.com/PAGalaxyLab/vxhunter) A ToolSet for VxWorks Based Embedded Device Analyses.
    - [R2](https://github.com/PAGalaxyLab/vxhunter/blob/master/firmware_tools/vxhunter_r2_py2.py) 
    - [IDA插件](https://github.com/PAGalaxyLab/vxhunter/blob/master/firmware_tools/vxhunter_ida.py) 
    - [Ghidra插件](https://github.com/PAGalaxyLab/vxhunter/tree/master/firmware_tools/ghidra) 


### <a id="02088f4884be6c9effb0f1e9a3795e58"></a>Signature(FLIRT...)&&Diff&&Match


#### <a id="cf04b98ea9da0056c055e2050da980c1"></a>No Category


- [**421**Star][1m] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) a scalable assembly management and analysis platform
    - Also In Section: [IDA->Tools->Part Of Other Tool](#83de90385d03ac8ef27360bfcdc1ab48) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 
- [**149**Star][1y] [C++] [ajkhoury/sigmaker-x64](https://github.com/ajkhoury/SigMaker-x64) IDA Pro 7.0 compatible SigMaker plugin
- [**131**Star][1y] [Py] [cisco-talos/bass](https://github.com/cisco-talos/bass) a framework designed to automatically generate antivirus signatures from samples belonging to previously generated malware clusters
- [**71**Star][4y] [Py] [icewall/bindifffilter](https://github.com/icewall/bindifffilter) IDA Pro plugin making easier work on BinDiff results
- [**69**Star][5y] [Py] [arvinddoraiswamy/slid](https://github.com/arvinddoraiswamy/slid) detect static lib
- [**51**Star][3m] [Py] [vrtadmin/first-plugin-ida](https://github.com/vrtadmin/first-plugin-ida) Function Identification and Recovery Signature Tool
- [**45**Star][1y] [Py] [l4ys/idasignsrch](https://github.com/l4ys/idasignsrch) IDAPython Plugin for searching signatures, use xml signature database from IDA_Signsrch
- [**33**Star][3y] [Py] [g4hsean/binauthor](https://github.com/g4hsean/binauthor) an IDA pro plugin developped through research at concordia in the area of binary authorship identification
- [**31**Star][1y] [Py] [cisco-talos/casc](https://github.com/cisco-talos/casc)  IDA Pro plug-in to generate signatures
- [**25**Star][2y] [LLVM] [syreal17/cardinal](https://github.com/syreal17/cardinal) Similarity Analysis to Defeat Malware Compiler Variations
- [**24**Star][6m] [Py] [xorpd/fcatalog_server](https://github.com/xorpd/fcatalog_server) Functions Catalog
- [**21**Star][3y] [Py] [xorpd/fcatalog_client](https://github.com/xorpd/fcatalog_client) fcatalog idapython client
- [**18**Star][5y] [Py] [zaironne/snippetdetector](https://github.com/zaironne/snippetdetector) IDA Python scripts project for snippets detection
- [**17**Star][8y] [C++] [alexander-pick/idb2pat](https://github.com/alexander-pick/idb2pat) idb2pat plugin, fixed to work with IDA 6.2
- [**14**Star][8y] [Standard ML] [letsunlockiphone/iphone-baseband-ida-pro-signature-files](https://github.com/letsunlockiphone/iphone-baseband-ida-pro-signature-files) IDA Pro Signature Files iPhone Baseband Reversing
    - Also In Section: [IDA->Tools->Apple->No Category](#8530752bacfb388f3726555dc121cb1a) |
- [**3**Star][4y] [Py] [ayuto/discover_win](https://github.com/ayuto/discover_win) compare linux and windows binary, rename windows binary functions
    - Also In Section: [IDA->Tools->Function->Rename](#73813456eeb8212fd45e0ea347bec349) |
- [**0**Star][1y] [Py] [gh0st3rs/idaprotosync](https://github.com/gh0st3rs/idaprotosync) IDAPython plugin for identifies functions prototypes between two or more IDBs


#### <a id="19360afa4287236abe47166154bc1ece"></a>FLIRT


##### <a id="1c9d8dfef3c651480661f98418c49197"></a>FLIRT Signature Collection


- [**605**Star][2m] [Max] [maktm/flirtdb](https://github.com/Maktm/FLIRTDB) A community driven collection of IDA FLIRT signature files
- [**321**Star][5m] [push0ebp/sig-database](https://github.com/push0ebp/sig-database) IDA FLIRT Signature Database
- [**4**Star][9m] [cloudwindby/ida-pro-sig](https://github.com/cloudwindby/ida-pro-sig) IDA PRO FLIRT signature files MSVC2017的sig文件


##### <a id="a9a63d23d32c6c789ca4d2e146c9b6d0"></a>FLIRT Signature Generate


- [**62**Star][11m] [Py] [push0ebp/allirt](https://github.com/push0ebp/allirt) Tool that converts All of libc to signatures for IDA Pro FLIRT Plugin. and utility make sig with FLAIR easily
- [**54**Star][9m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - Also In Section: [IDA->Tools->Import Export->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[Ghidra->Plugins->With Other Tools->IDA](#d832a81018c188bf585fcefa3ae23062) |




#### <a id="161e5a3437461dc8959cc923e6a18ef7"></a>Diff&&Match


- [**1554**Star][13d] [Py] [joxeankoret/diaphora](https://github.com/joxeankoret/diaphora) program diffing
- [**360**Star][1m] [Py] [checkpointsw/karta](https://github.com/checkpointsw/karta) source code assisted fast binary matching plugin for IDA
- [**332**Star][1y] [Py] [joxeankoret/pigaios](https://github.com/joxeankoret/pigaios) A tool for matching and diffing source codes directly against binaries.
- [**135**Star][1y] [Py] [nirizr/rematch](https://github.com/nirizr/rematch) REmatch, a complete binary diffing framework that is free and strives to be open source and community driven.
- [**95**Star][7m] [Visual Basic .NET] [dzzie/idacompare](https://github.com/dzzie/idacompare) a plugin for IDA which is designed to help you  line up functions across two separate disassemblies
- [**73**Star][4y] [C] [nihilus/ida_signsrch](https://github.com/nihilus/ida_signsrch) IDA Pro plug-in conversion of Luigi Auriemma's signsrch signature matching tool.
- [**72**Star][5y] [Py] [binsigma/binsourcerer](https://github.com/binsigma/binsourcerer) Assembly to Source Code Matching Framework for IDA Pro.
- [**72**Star][3y] [vrtadmin/first](https://github.com/vrtadmin/first) Function Identification and Recovery Signature Tool
- [**52**Star][5y] [C++] [filcab/patchdiff2](https://github.com/filcab/patchdiff2) IDA binary differ. Since code.google.com/p/patchdiff2/ seemed abandoned, I did the obvious thing…
- [**14**Star][3y] [Py] [0x00ach/idadiff](https://github.com/0x00ach/idadiff) The script uses the @Heurs MACHOC algorithm (https://github.com/ANSSI-FR/polichombr) in order to build tiny CFG hashes of a source binary sample in IDA PRO
- [**14**Star][5y] [C++] [binsigma/binclone](https://github.com/binsigma/binclone) detecting code clones in malware


#### <a id="46c9dfc585ae59fe5e6f7ddf542fb31a"></a>Yara


- [**449**Star][2m] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) IDA pro plugin to find crypto constants (and more)
    - Also In Section: [IDA->Tools->encrypt](#06d2caabef97cf663bd29af2b1fe270c) |
- [**92**Star][2m] [Py] [hyuunnn/hyara](https://github.com/hyuunnn/Hyara) IDA Plugin that provides convenience when writing yararule.
    - [IDA插件](https://github.com/hy00un/hyara/tree/master/IDA%20Plugin) 
    - [BinaryNinja插件](https://github.com/hy00un/hyara/tree/master/BinaryNinja%20Plugin) 
- [**92**Star][2m] [Py] [hyuunnn/hyara](https://github.com/hyuunnn/hyara) Yara rule making tool (IDA Pro & Binary Ninja Plugin)
- [**83**Star][1y] [Py] [oalabs/findyara](https://github.com/oalabs/findyara) IDA python plugin to scan your binary with yara rules
- [**16**Star][11m] [Py] [bnbdr/ida-yara-processor](https://github.com/bnbdr/ida-yara-processor) Loader and processor for YARA's compiled rule format
    - Also In Section: [IDA->Tools->Specific Target->Loader](#cb59d84840e41330a7b5e275c0b81725) |
- [**14**Star][1y] [Py] [alexander-hanel/ida_yara](https://github.com/alexander-hanel/ida_yara) scan data within in an IDB using Yara
- [**14**Star][1y] [Py] [souhailhammou/idaray-plugin](https://github.com/souhailhammou/idaray-plugin) IDARay is an IDA Pro plugin that matches the database against multiple YARA files which themselves may contain multiple rules.




### <a id="5e91b280aab7f242cbc37d64ddbff82f"></a>IDB


- [**316**Star][6m] [Py] [williballenthin/python-idb](https://github.com/williballenthin/python-idb)  a library for accessing the contents of IDA Pro databases
- [**151**Star][2m] [Py] [nccgroup/idahunt](https://github.com/nccgroup/idahunt) a framework to analyze binaries with IDA Pro and hunt for things in IDA Pro
- [**87**Star][6m] [C++] [nlitsme/idbutil](https://github.com/nlitsme/idbutil) extracting information from IDA databases
- [**81**Star][4m] [Py] [nlitsme/pyidbutil](https://github.com/nlitsme/pyidbutil) extracting information from IDA databases
- [**18**Star][1y] [Py] [kkhaike/tinyidb](https://github.com/kkhaike/tinyidb) export userdata from huge idb
- [**0**Star][4y] [C] [hugues92/idaextrapassplugin](https://github.com/hugues92/idaextrapassplugin) idb fix and clean


### <a id="206ca17fc949b8e0ae62731d9bb244cb"></a>Collaborative RE


- [**508**Star][11m] [Py] [idarlingteam/idarling](https://github.com/IDArlingTeam/IDArling) a collaborative reverse engineering plugin for IDA Pro and Hex-Rays
- [**258**Star][1y] [C++] [dga-mi-ssi/yaco](https://github.com/dga-mi-ssi/yaco) a Hex-Rays IDA plugin enabling collaborative reverse-engineering on IDA databases for multiple users
- [**88**Star][5y] [Py] [cubicalabs/idasynergy](https://github.com/cubicalabs/idasynergy) IDA Plugin with svn integerted
- [**71**Star][2m] [C++] [cseagle/collabreate](https://github.com/cseagle/collabreate) IDA Pro Collaboration/Synchronization Plugin
- [**4**Star][2y] [Py] [argussecurity/psida](https://bitbucket.org/socialauth/login/atlassianid/?next=%2Fargussecurity%2Fpsida) Python Scripts for IDA [by the Argus Research Team]


### <a id="f7d311685152ac005cfce5753c006e4b"></a>Sync With Debugger


- [**471**Star][13d] [C] [bootleg/ret-sync](https://github.com/bootleg/ret-sync) a set of plugins that help to synchronize a debugging session (WinDbg/GDB/LLDB/OllyDbg/OllyDbg2/x64dbg) with IDA/Ghidra disassemblers
    - Also In Section: [x64dbg->Plugins->Recent Add](#da5688c7823802e734c39b539aa39df7) |
    - [GDB插件](https://github.com/bootleg/ret-sync/tree/master/ext_gdb) 
    - [Ghidra插件](https://github.com/bootleg/ret-sync/tree/master/ext_ghidra) 
    - [IDA插件](https://github.com/bootleg/ret-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/bootleg/ret-sync/tree/master/ext_lldb) 
    - [OD](https://github.com/bootleg/ret-sync/tree/master/ext_olly1) 
    - [OD2](https://github.com/bootleg/ret-sync/tree/master/ext_olly2) 
    - [WinDgb](https://github.com/bootleg/ret-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/bootleg/ret-sync/tree/master/ext_x64dbg) 
- [**292**Star][11m] [C] [a1ext/labeless](https://github.com/a1ext/labeless) Seamless synchronization of labels, function names, comments and global variables (w/wo demangling); Dynamic dumping of debugged process memory regions
    - [IDA插件](https://github.com/a1ext/labeless/tree/master/labeless_ida) 
    - [OD](https://github.com/a1ext/labeless/tree/master/labeless_olly) 
    - [OD2](https://github.com/a1ext/labeless/tree/master/labeless_olly2) 
    - [x64dbg](https://github.com/a1ext/labeless/tree/master/labeless_x64dbg) 
- [**179**Star][1y] [Py] [andreafioraldi/idangr](https://github.com/andreafioraldi/idangr) Use angr in the IDA Pro debugger generating a state from the current debug session
- [**132**Star][2y] [Py] [comsecuris/gdbida](https://github.com/comsecuris/gdbida) a visual bridge between a GDB session and IDA Pro's disassembler
    - [IDA插件](https://github.com/comsecuris/gdbida/blob/master/ida_gdb_bridge.py) 
    - [GDB脚本](https://github.com/comsecuris/gdbida/blob/master/gdb_ida_bridge_client.py) 
- [**97**Star][4y] [C++] [quarkslab/qb-sync](https://github.com/quarkslab/qb-sync) add some helpful glue between IDA Pro and Windbg
    - [GDB插件](https://github.com/quarkslab/qb-sync/tree/master/ext_gdb) 
    - [IDA插件](https://github.com/quarkslab/qb-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/quarkslab/qb-sync/tree/master/ext_lldb) 
    - [OD2](https://github.com/quarkslab/qb-sync/tree/master/ext_olly2) 
    - [WinDbg](https://github.com/quarkslab/qb-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/quarkslab/qb-sync/tree/master/ext_x64dbg) 
- [**46**Star][4m] [JS] [sinakarvandi/windbg2ida](https://github.com/sinakarvandi/windbg2ida) dump each step in Windbg then shows these steps in IDA Windbg2ida
    - [Windbg脚本](https://github.com/sinakarvandi/windbg2ida/blob/master/windbg2ida.js) JavaScript
    - [IDA脚本](https://github.com/sinakarvandi/windbg2ida/blob/master/IDAScript.py) 
- [**36**Star][10m] [Py] [anic/ida2pwntools](https://github.com/anic/ida2pwntools) a IDA 7.0 plugins that helps to attach process created by pwntools and debug pwn
- [**29**Star][2y] [Py] [iweizime/dbghider](https://github.com/iweizime/dbghider) hide IDA Winddows debugger from processes.
- [**19**Star][7y] [Py] [rmadair/windbg2ida](https://github.com/rmadair/windbg2ida) Import debugging traces from WinDBG into IDA. Color the graph, fill in the value of all operands, etc.


### <a id="6fb7e41786c49cc3811305c520dfe9a1"></a>Import Export&&Sync With Other Tools


#### <a id="8ad723b704b044e664970b11ce103c09"></a>No Category


- [**163**Star][2m] [Py] [x64dbg/x64dbgida](https://github.com/x64dbg/x64dbgida) Official x64dbg plugin for IDA Pro.
    - Also In Section: [x64dbg->Plugins->Recent Add](#da5688c7823802e734c39b539aa39df7) |
- [**148**Star][2m] [C++] [alschwalm/dwarfexport](https://github.com/alschwalm/dwarfexport) Export dwarf debug information from IDA Pro
- [**96**Star][2y] [Py] [robindavid/idasec](https://github.com/robindavid/idasec) IDA plugin for reverse-engineering and dynamic interactions with the Binsec platform
- [**67**Star][1y] [Py] [lucasg/idamagnum](https://github.com/lucasg/idamagnum)  a plugin for integrating MagnumDB requests within IDA
- [**59**Star][2m] [Py] [binaryanalysisplatform/bap-ida-python](https://github.com/binaryanalysisplatform/bap-ida-python) interoperatibility between BAP and IDA Pro
- [**35**Star][5y] [Py] [siberas/ida2sym](https://github.com/siberas/ida2sym) IDAScript to create Symbol file which can be loaded in WinDbg via AddSyntheticSymbol
- [**28**Star][6y] [C++] [oct0xor/deci3dbg](https://github.com/oct0xor/deci3dbg) Ida Pro debugger module for Playstation 3
    - Also In Section: [IDA->Tools->Specific Target->PS3](#315b1b8b41c67ae91b841fce1d4190b5) |
- [**28**Star][5m] [C++] [thalium/idatag](https://github.com/thalium/idatag) IDA plugin to explore and browse tags
- [**19**Star][2y] [Py] [brandon-everhart/angryida](https://github.com/brandon-everhart/angryida) Python based angr plug in for IDA Pro.
    - Also In Section: [Other->angr->Tool](#1ede5ade1e55074922eb4b6386f5ca65) |
- [**16**Star][4y] [C++] [m417z/mapimp](https://github.com/m417z/mapimp) an OllyDbg plugin which will help you to import map files exported by IDA, Dede, IDR, Microsoft and Borland linkers.
- [**16**Star][5y] [Py] [danielmgmi/virusbattle-ida-plugin](https://github.com/danielmgmi/virusbattle-ida-plugin) The plugin is an integration of Virus Battle API to the well known IDA Disassembler.
- [**8**Star][7y] [C++] [patois/madnes](https://github.com/patois/madnes) IDA plugin to export symbols and names from IDA db so they can be loaded into FCEUXD SP
- [**3**Star][1y] [Py] [r00tus3r/differential_debugging](https://github.com/r00tus3r/differential_debugging) Differential debugging using IDA Python and GDB


#### <a id="c7066b0c388cd447e980bf0eb38f39ab"></a>Ghidra


- [**299**Star][4m] [Py] [cisco-talos/ghida](https://github.com/cisco-talos/ghida) an IDA Pro plugin that integrates the Ghidra decompiler in IDA.
    - Also In Section: [Ghidra->Plugins->With Other Tools->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**238**Star][9m] [Py] [daenerys-sre/source](https://github.com/daenerys-sre/source)  A framework for interoperability between IDA and Ghidra
    - Also In Section: [Ghidra->Plugins->With Other Tools->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**88**Star][4m] [Py] [cisco-talos/ghidraaas](https://github.com/cisco-talos/ghidraaas) a simple web server that exposes Ghidra analysis through REST APIs
    - Also In Section: [Ghidra->Plugins->With Other Tools->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**54**Star][9m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->FLIRT->FLIRT Signature Generate](#a9a63d23d32c6c789ca4d2e146c9b6d0) |[Ghidra->Plugins->With Other Tools->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**47**Star][2m] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
    - Also In Section: [Ghidra->Plugins->With Other Tools->IDA](#d832a81018c188bf585fcefa3ae23062) |[x64dbg->Plugins->Recent Add](#da5688c7823802e734c39b539aa39df7) |


#### <a id="11139e7d6db4c1cef22718868f29fe12"></a>BinNavi


- [**382**Star][26d] [C++] [google/binexport](https://github.com/google/binexport) Export disassemblies into Protocol Buffers and to BinNavi databases
    - Also In Section: [Other->BinNavi->Tool](#2e4980c95871eae4ec0e76c42cc5c32f) |
- [**213**Star][4y] [PLpgSQL] [cseagle/freedom](https://github.com/cseagle/freedom) capstone based disassembler for extracting to binnavi
    - Also In Section: [Other->BinNavi->Tool](#2e4980c95871eae4ec0e76c42cc5c32f) |
- [**25**Star][7y] [Py] [tosanjay/bopfunctionrecognition](https://github.com/tosanjay/bopfunctionrecognition) plugin to BinNavi tool to analyze a x86 binanry file to find buffer overflow prone functions. Such functions are important for vulnerability analysis.
    - Also In Section: [Other->BinNavi->Tool](#2e4980c95871eae4ec0e76c42cc5c32f) |


#### <a id="d1ff64bee76f6749aef6100d72bfbe3a"></a>BinaryNinja


- [**68**Star][9m] [Py] [lunixbochs/revsync](https://github.com/lunixbochs/revsync) realtime cross-tool collaborative reverse engineering
    - Also In Section: [BinaryNinja->Plugins->With Other Tools->IDA](#713fb1c0075947956651cc21a833e074) |
- [**61**Star][6m] [Py] [zznop/bnida](https://github.com/zznop/bnida) Suite of plugins that provide the ability to transfer analysis data between Binary Ninja and IDA
    - Also In Section: [BinaryNinja->Plugins->With Other Tools->IDA](#713fb1c0075947956651cc21a833e074) |
    - [ida_export](https://github.com/zznop/bnida/blob/master/ida/ida_export.py) 将数据从IDA中导入
    - [ida_import](https://github.com/zznop/bnida/blob/master/ida/ida_import.py) 将数据导入到IDA
    - [binja_export](https://github.com/zznop/bnida/blob/master/binja_export.py) 将数据从BinaryNinja中导出
    - [binja_import](https://github.com/zznop/bnida/blob/master/binja_import.py) 将数据导入到BinaryNinja
- [**14**Star][6m] [Py] [cryptogenic/idc_importer](https://github.com/cryptogenic/idc_importer) A Binary Ninja plugin for importing IDC database dumps from IDA.
    - Also In Section: [BinaryNinja->Plugins->With Other Tools->IDA](#713fb1c0075947956651cc21a833e074) |


#### <a id="21ed198ae5a974877d7a635a4b039ae3"></a>Radare2


- [**125**Star][8m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->Function->No Category](#347a2158bdd92b00cd3d4ba9a0be00ae) |[Radare2->Plugins->With Other Tools->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**123**Star][2m] [Py] [radare/radare2ida](https://github.com/radare/radare2ida) Tools, documentation and scripts to move projects from IDA to R2 and viceversa
    - Also In Section: [Radare2->Plugins->With Other Tools->IDA](#1cfe869820ecc97204a350a3361b31a7) |


#### <a id="a1cf7f7f849b4ca2101bd31449c2a0fd"></a>Frida


- [**128**Star][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) a reverse engineering framework created to simplify dynamic instrumentation with Frida
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |[DBI->Frida->Tools->With Other Tools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**83**Star][5y] [Py] [techbliss/frida_for_ida_pro](https://github.com/techbliss/frida_for_ida_pro) plugin for ida pro thar uses the Frida api
    - Also In Section: [DBI->Frida->Tools->With Other Tools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
- [**58**Star][20d] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA tools and scripts collection
    - Also In Section: [IDA->Tools->No Category](#c39a6d8598dde6abfeef43faf931beb5) |[DBI->Frida->Tools->Recent Add](#54836a155de0c15b56f43634cd9cfecf) |
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor scripts
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida Scripts
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA Scripts
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) When there is chinese unicode character in programe, due to python's shortage, ida could not recongnized them correctly, it's what my script just do
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py)  When you deal with macho file with ida, you'll find out that it's not easy to find Objc-Class member function's caller and callee, (because it use msgSend instead of direct calling  convention), so we need to make some connection between the selector names and member function  pointers, it's what my script just do
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) When you debug android with IDA and gdbserver, you'd find that the module list and segment is empy, while we can read info from /proc/[pid]/,
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) this script is to trace instruction stream in one run 
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) this script is to detect ollvm and fix it in some extent, apply to android and ios
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) this script is used to analysis block structure exist in macho file, target NSConcreteStackBlock/NSConcreteGlobalBlock currently, also contain some wonderful skills
- [**40**Star][2y] [Py] [agustingianni/memrepl](https://github.com/agustingianni/memrepl) a frida based script that aims to help a researcher in the task of exploitation of memory corruption related bugs
    - Also In Section: [DBI->Frida->Tools->Recent Add](#54836a155de0c15b56f43634cd9cfecf) |


#### <a id="dd0332da5a1482df414658250e6357f8"></a>IntelPin


- [**134**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |[IDA->Tools->Vul->No Category](#385d6777d0747e79cccab0a19fa90e7e) |[DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**44**Star][3y] [Batchfile] [maldiohead/idapin](https://github.com/maldiohead/idapin) plugin of ida with pin
    - Also In Section: [DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |




### <a id="004c199e1dbf71769fbafcd8e58d1ead"></a>Specific Target


#### <a id="5578c56ca09a5804433524047840980e"></a>No Category


- [**542**Star][2y] [Py] [anatolikalysch/vmattack](https://github.com/anatolikalysch/vmattack) static and dynamic virtualization-based packed analysis and deobfuscation.
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**199**Star][4y] [Py] [f8left/decllvm](https://github.com/f8left/decllvm) IDA plugin for OLLVM analysis
- [**117**Star][1y] [Py] [xerub/idastuff](https://github.com/xerub/idastuff) IDA Pro/Hexrays plugins, mainly targeted at ARM processors
- [**101**Star][12d] [Py] [fboldewin/com-code-helper](https://github.com/fboldewin/com-code-helper) Two IDAPython Scripts help you to reconstruct Microsoft COM (Component Object Model) Code
- [**93**Star][4m] [Py] [themadinventor/ida-xtensa](https://github.com/themadinventor/ida-xtensa) IDAPython plugin for Tensilica Xtensa (as seen in ESP8266)
- [**82**Star][4y] [C++] [wjp/idados](https://github.com/wjp/idados) Eric Fry's IDA/DOSBox debugger plugin
    - Also In Section: [IDA->Tools->Debug->No Category](#2944dda5289f494e5e636089db0d6a6a) |
- [**75**Star][3m] [Py] [coldzer0/ida-for-delphi](https://github.com/coldzer0/ida-for-delphi) IDA Python Script to Get All function names from Event Constructor (VCL)
- [**59**Star][2y] [Py] [isra17/nrs](https://github.com/isra17/nrs) NSIS Reversing Suite with IDA Plugins
- [**59**Star][6m] [C++] [troybowman/dtxmsg](https://github.com/troybowman/dtxmsg) an IDA plugin that helped me reverse-engineer the DTXConnectionServices framework.
- [**57**Star][4m] [Py] [giantbranch/mipsaudit](https://github.com/giantbranch/mipsaudit) IDA script to assist in MIPS static scan
- [**50**Star][10m] [C] [lab313ru/smd_ida_tools](https://github.com/lab313ru/smd_ida_tools) Special IDA Pro tools for the Sega Genesis/Megadrive romhackers
- [**47**Star][2y] [C++] [antid0tecom/aarch64_armv81extension](https://github.com/antid0tecom/aarch64_armv81extension) IDA AArch64 processor extender extension: Adding support for ARMv8.1 opcodes
- [**33**Star][3y] [Py] [sam-b/windows_syscalls_dumper](https://github.com/sam-b/windows_syscalls_dumper) A dirty IDAPython script to dump windows system call number/name pairs as JSON
- [**24**Star][3y] [C++] [sektioneins/aarch64_cryptoextension](https://github.com/sektioneins/aarch64_cryptoextension) IDA AArch64 processor extender extension: Adding crypto extension instructions (AES/SHA1/SHA256)
- [**23**Star][12m] [Py] [howmp/comfinder](https://github.com/howmp/comfinder) IDA plugin for COM
    - Also In Section: [IDA->Tools->Function->Rename](#73813456eeb8212fd45e0ea347bec349) |
- [**23**Star][3y] [Py] [pfalcon/ida-xtensa2](https://github.com/pfalcon/ida-xtensa2) IDAPython plugin for Tensilica Xtensa (as seen in ESP8266), version 2
- [**20**Star][5y] [Py] [digitalbond/ibal](https://github.com/digitalbond/ibal) IDA Pro Bootrom Analysis Library, which contains a number of useful functions for analyzing embedded ROMs
- [**19**Star][2y] [C] [andywhittaker/idaproboschme7x](https://github.com/andywhittaker/idaproboschme7x) IDA Pro Bosch ME7x C16x Disassembler Helper
- [**16**Star][3y] [Py] [0xdeva/ida-cpu-risc-v](https://github.com/0xdeva/ida-cpu-risc-v) RISCV-V disassembler for IDA Pro
- [**15**Star][5y] [Py] [dolphin-emu/gcdsp-ida](https://github.com/dolphin-emu/gcdsp-ida) An IDA plugin for GC DSP reverse engineering
- [**11**Star][2y] [C++] [hyperiris/gekkops](https://github.com/hyperiris/gekkops) Nintendo GameCube Gekko CPU Extension plug-in for IDA Pro 5.2
- [**4**Star][3y] [Py] [neogeodev/idaneogeo](https://github.com/neogeodev/idaneogeo) NeoGeo binary loader & helper for the Interactive Disassembler
- [**3**Star][5m] [C] [extremlapin/glua_c_headers_for_ida](https://github.com/extremlapin/glua_c_headers_for_ida) Glua module C headers for IDA
- [**2**Star][6m] [Py] [lucienmp/idapro_m68k](https://github.com/lucienmp/idapro_m68k) Extends existing support in IDA for the m68k by adding gdb step-over and type information support
- [**0**Star][9m] [C] [0xd0cf11e/idcscripts](https://github.com/0xd0cf11e/idcscripts) Scripts used when analyzing files in IDA
    - [emotet-decode](https://github.com/0xd0cf11e/idcscripts/blob/master/emotet/emotet-decode.idc) 解码emotet
- [**0**Star][3m] [C++] [marakew/emuppc](https://github.com/marakew/emuppc) simple PowerPC emulator for unpack into IDAPro some PowerPC binary


#### <a id="cb59d84840e41330a7b5e275c0b81725"></a>Loader&Processor


- [**205**Star][1y] [Py] [fireeye/idawasm](https://github.com/fireeye/idawasm) IDA Pro loader and processor modules for WebAssembly
- [**161**Star][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |[Android->Tools->Recent Add](#63fd2c592145914e99f837cecdc5a67c) |
- [**155**Star][2y] [Py] [crytic/ida-evm](https://github.com/crytic/ida-evm) IDA Processor Module for the Ethereum Virtual Machine (EVM)
- [**146**Star][29d] [Py] [argp/iboot64helper](https://github.com/argp/iboot64helper) IDAPython loader to help with AArch64 iBoot, iBEC, and SecureROM reverse engineering
- [**131**Star][2y] [C] [gsmk/hexagon](https://github.com/gsmk/hexagon) IDA processor module for the hexagon (QDSP6) processor
- [**112**Star][1y] [pgarba/switchidaproloader](https://github.com/pgarba/switchidaproloader) Loader for IDA Pro to support the Nintendo Switch NRO binaries
- [**79**Star][9m] [Py] [reswitched/loaders](https://github.com/reswitched/loaders) IDA Loaders for Switch binaries(NSO / NRO)
- [**72**Star][2y] [Py] [embedi/meloader](https://github.com/embedi/meloader) Intel Management Engine firmware loader plugin for IDA
- [**55**Star][7m] [C++] [mefistotelis/ida-pro-loadmap](https://github.com/mefistotelis/ida-pro-loadmap) Plugin for IDA Pro disassembler which allows loading .map files.
- [**37**Star][1y] [C++] [patois/nesldr](https://github.com/patois/nesldr) Nintendo Entertainment System (NES) ROM loader module for IDA Pro
- [**35**Star][1y] [Py] [bnbdr/ida-bpf-processor](https://github.com/bnbdr/ida-bpf-processor) BPF Processor for IDA Python
- [**33**Star][2y] [C++] [teammolecule/toshiba-mep-idp](https://github.com/TeamMolecule/toshiba-mep-idp) IDA Pro module for Toshiba MeP processors
- [**32**Star][5y] [Py] [0xebfe/3dsx-ida-pro-loader](https://github.com/0xebfe/3dsx-ida-pro-loader) IDA PRO Loader for 3DSX files
- [**28**Star][4y] [C] [gdbinit/teloader](https://github.com/gdbinit/teloader) A TE executable format loader for IDA
- [**27**Star][4m] [Py] [ghassani/mclf-ida-loader](https://github.com/ghassani/mclf-ida-loader) An IDA file loader for Mobicore trustlet and driver binaries
- [**27**Star][3y] [Py] [w4kfu/ida_loader](https://github.com/w4kfu/ida_loader) Some loader module for IDA
- [**23**Star][2y] [C++] [balika011/belf](https://github.com/balika011/belf) Balika011's PlayStation 4 ELF loader for IDA Pro 7.0/7.1
- [**23**Star][6y] [vtsingaras/qcom-mbn-ida-loader](https://github.com/vtsingaras/qcom-mbn-ida-loader) IDA loader plugin for Qualcomm Bootloader Stages
- [**20**Star][3y] [C++] [patois/ndsldr](https://github.com/patois/ndsldr) Nintendo DS ROM loader module for IDA Pro
- [**18**Star][8y] [Py] [rpw/flsloader](https://github.com/rpw/flsloader) IDA Pro loader module for Infineon/Intel-based iPhone baseband firmwares
- [**17**Star][9m] [C++] [gocha/ida-snes-ldr](https://github.com/gocha/ida-snes-ldr) SNES ROM Cartridge File Loader for IDA (Interactive Disassembler) 6.x
- [**16**Star][11m] [Py] [bnbdr/ida-yara-processor](https://github.com/bnbdr/ida-yara-processor) Loader and processor for YARA's compiled rule format
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |
- [**16**Star][9m] [C++] [gocha/ida-65816-module](https://github.com/gocha/ida-65816-module) SNES 65816 processor plugin for IDA (Interactive Disassembler) 6.x
- [**16**Star][1y] [Py] [lcq2/riscv-ida](https://github.com/lcq2/riscv-ida) RISC-V ISA processor module for IDAPro 7.x
- [**16**Star][1y] [Py] [ptresearch/nios2](https://github.com/ptresearch/nios2) IDA Pro processor module for Altera Nios II Classic/Gen2 microprocessor architecture
- [**14**Star][2y] [Py] [patois/necromancer](https://github.com/patois/necromancer) IDA Pro V850 Processor Module Extension
- [**13**Star][1y] [Py] [rolfrolles/hiddenbeeloader](https://github.com/rolfrolles/hiddenbeeloader) IDA loader module for Hidden Bee's custom executable file format
- [**10**Star][4y] [C++] [areidz/nds_loader](https://github.com/areidz/nds_loader) Nintendo DS loader module for IDA Pro 6.1
- [**10**Star][6y] [Py] [cycad/mbn_loader](https://github.com/cycad/mbn_loader) IDA Pro Loader Plugin for Samsung Galaxy S4 ROMs
- [**7**Star][1y] [C++] [fail0verflow/rl78-ida-proc](https://github.com/fail0verflow/rl78-ida-proc) Renesas RL78 processor module for IDA
- [**5**Star][9m] [C++] [gocha/ida-spc700-module](https://github.com/gocha/ida-spc700-module) SNES SPC700 processor plugin for IDA (Interactive Disassembler)
- [**3**Star][9m] [C++] [gocha/ida-snes_spc-ldr](https://github.com/gocha/ida-snes_spc-ldr) SNES-SPC700 Sound File Loader for IDA (Interactive Disassembler)
- [**2**Star][3m] [C] [cisco-talos/ida_tilegx](https://github.com/cisco-talos/ida_tilegx) This is an IDA processor module for the Tile-GX processor architecture


#### <a id="1b17ac638aaa09852966306760fda46b"></a>GoLang


- [**376**Star][9m] [Py] [sibears/idagolanghelper](https://github.com/sibears/idagolanghelper) Set of IDA Pro scripts for parsing GoLang types information stored in compiled binary
- [**297**Star][2m] [Py] [strazzere/golang_loader_assist](https://github.com/strazzere/golang_loader_assist) Making GO reversing easier in IDA Pro


#### <a id="4c158ccc5aee04383755851844fdd137"></a>Windows Driver


- [**306**Star][1y] [Py] [fsecurelabs/win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) A tool to help when dealing with Windows IOCTL codes or reversing Windows drivers.
- [**218**Star][1y] [Py] [nccgroup/driverbuddy](https://github.com/nccgroup/driverbuddy) IDA Python script to assist with the reverse engineering of Windows kernel drivers.
- [**74**Star][5y] [Py] [tandasat/winioctldecoder](https://github.com/tandasat/winioctldecoder) IDA Plugin which decodes Windows Device I/O control code into DeviceType, FunctionCode, AccessType and MethodType.
- [**23**Star][1y] [C] [ioactive/kmdf_re](https://github.com/ioactive/kmdf_re) Helper idapython code for reversing kmdf drivers


#### <a id="315b1b8b41c67ae91b841fce1d4190b5"></a>PS3&&PS4


- [**69**Star][3m] [C] [aerosoul94/ida_gel](https://github.com/aerosoul94/ida_gel) A collection of IDA loaders for various game console ELF's. (PS3, PSVita, WiiU)
- [**55**Star][7y] [C++] [kakaroto/ps3ida](https://github.com/kakaroto/ps3ida) IDA scripts and plugins for PS3
- [**44**Star][2y] [C] [aerosoul94/dynlib](https://github.com/aerosoul94/dynlib) IDA Pro plugin to aid PS4 user mode ELF reverse engineering.
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
- [**28**Star][6y] [C++] [oct0xor/deci3dbg](https://github.com/oct0xor/deci3dbg) Ida Pro debugger module for Playstation 3
    - Also In Section: [IDA->Tools->Import Export->No Category](#8ad723b704b044e664970b11ce103c09) |


#### <a id="f5e51763bb09d8fd47ee575a98bedca1"></a>PDB


- [**98**Star][5m] [C++] [mixaill/fakepdb](https://github.com/mixaill/fakepdb) 通过IDA数据库生成PDB文件
- [**39**Star][1y] [Py] [ax330d/ida_pdb_loader](https://github.com/ax330d/ida_pdb_loader) IDA PDB Loader
- [**14**Star][1y] [CMake] [gdataadvancedanalytics/bindifflib](https://github.com/gdataadvancedanalytics/bindifflib) Automated library compilation and PDB annotation with CMake and IDA Pro
- [**2**Star][6m] [Py] [clarkb7/annotate_lineinfo](https://github.com/clarkb7/annotate_lineinfo) Annotate IDA with source and line number information from a PDB


#### <a id="7d0681efba2cf3adaba2780330cd923a"></a>Flash&&SWF


- [**34**Star][1y] [Py] [kasperskylab/actionscript3](https://github.com/kasperskylab/actionscript3) Tools for static and dynamic analysis of ActionScript3 SWF files.
- [**27**Star][4y] [C++] [nihilus/ida-pro-swf](https://github.com/nihilus/ida-pro-swf) SWF Process


#### <a id="841d605300beba45c3be131988514a03"></a>Malware Family


- [**9**Star][2y] [Py] [d00rt/easy_way_nymaim](https://github.com/d00rt/easy_way_nymaim) An IDA Pro script for creating a clearer idb for nymaim malware
- [**8**Star][3y] [Py] [thngkaiyuan/mynaim](https://github.com/thngkaiyuan/mynaim) IDAPython Deobfuscation Scripts for Nymaim Samples
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**4**Star][2y] [Py] [immortalp0ny/fyvmdisassembler](https://github.com/immortalp0ny/fyvmdisassembler) IDAPython scripts for devirtualization/disassembly FinSpy VM
- [**4**Star][8m] [C] [lacike/gandcrab_string_decryptor](https://github.com/lacike/gandcrab_string_decryptor) IDC script for decrypting strings in the GandCrab v5.1-5.3
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |


#### <a id="ad44205b2d943cfa2fa805b2643f4595"></a>CTF


- [**132**Star][2y] [Py] [pwning/defcon25-public](https://github.com/pwning/defcon25-public) Publicly released tools/plugins from PPP for DEFCON 25 CTF Finals




### <a id="ad68872e14f70db53e8d9519213ec039"></a>IDAPython


#### <a id="2299bc16945c25652e5ad4d48eae8eca"></a>No Category


- [**720**Star][15d] [Py] [idapython/src](https://github.com/idapython/src) IDAPython project for Hex-Ray's IDA Pro
- [**373**Star][3m] [Py] [tmr232/sark](https://github.com/tmr232/sark) IDAPython Made Easy
- [**248**Star][2y] [Py] [intezer/docker-ida](https://github.com/intezer/docker-ida) Run IDA Pro disassembler in Docker containers for automating, scaling and distributing the use of IDAPython scripts.
- [**82**Star][4y] [idapython/bin](https://github.com/idapython/bin) IDAPython binaries
- [**69**Star][2y] [Py] [alexander-hanel/idapython6to7](https://github.com/alexander-hanel/idapython6to7) 
- [**43**Star][1y] [Py] [nirizr/pytest-idapro](https://github.com/nirizr/pytest-idapro) A pytest module for The Interactive Disassembler and IDAPython; Record and Replay IDAPython API, execute inside IDA or use mockups of IDAPython API.
- [**29**Star][3y] [Py] [kerrigan29a/idapython_virtualenv](https://github.com/kerrigan29a/idapython_virtualenv) Enable Virtualenv or Conda in IDAPython
- [**23**Star][3y] [Py] [devttys0/idascript](https://github.com/devttys0/idascript) a wrapper around IDA Pro that makes it easy to automate the execution of IDA scripts  against target files from the command line


#### <a id="c42137cf98d6042372b1fd43c3635135"></a>Cheatsheets


- [**258**Star][28d] [Py] [inforion/idapython-cheatsheet](https://github.com/inforion/idapython-cheatsheet) Scripts and cheatsheets for IDAPython




### <a id="846eebe73bef533041d74fc711cafb43"></a>Instruction Reference&&Doc


- [**497**Star][1y] [PLpgSQL] [nologic/idaref](https://github.com/nologic/idaref) IDA Pro Instruction Reference Plugin
- [**449**Star][4m] [C++] [alexhude/friend](https://github.com/alexhude/friend) Flexible Register/Instruction Extender aNd Documentation
    - Also In Section: [IDA->Tools->Nav->No Category](#c5b120e1779b928d860ad64ff8d23264) |
- [**250**Star][2y] [Py] [gdelugre/ida-arm-system-highlight](https://github.com/gdelugre/ida-arm-system-highlight) IDA script for highlighting and decoding ARM system instructions
- [**106**Star][2m] [Py] [neatmonster/amie](https://github.com/neatmonster/amie) A Minimalist Instruction Extender for the ARM architecture and IDA Pro
- [**45**Star][8y] [Py] [zynamics/msdn-plugin-ida](https://github.com/zynamics/msdn-plugin-ida) Imports MSDN documentation into IDA Pro
- [**24**Star][3y] [AutoIt] [yaseralnajjar/ida-msdn-helper](https://github.com/yaseralnajjar/IDA-MSDN-helper) IDA Pro MSDN Helper


### <a id="c08ebe5b7eec9fc96f8eff36d1d5cc7d"></a>Script Writting


#### <a id="45fd7cfce682c7c25b4f3fbc4c461ba2"></a>No Category


- [**393**Star][3y] [Py] [36hours/idaemu](https://github.com/36hours/idaemu) an IDA Pro Plugin use for emulating code in IDA Pro.
    - Also In Section: [IDA->Tools->Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**282**Star][2m] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) marries a supported binary analysis framework, such as IDA Pro or Radare2, with Unicorn’s emulation framework to provide the user with an easy to use and flexible interface for scripting emulation tasks
    - Also In Section: [IDA->Tools->Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**137**Star][26d] [Py] [arizvisa/ida-minsc](https://github.com/arizvisa/ida-minsc) a plugin for IDA Pro that assists a user with scripting the IDAPython plugin that is bundled with the disassembler.
- [**104**Star][1m] [Py] [patois/idapyhelper](https://github.com/patois/idapyhelper) IDAPyHelper is a script for the Interactive Disassembler that helps writing IDAPython scripts and plugins.
- [**74**Star][5m] [C++] [0xeb/ida-qscripts](https://github.com/0xeb/ida-qscripts) An IDA plugin to increase productivity when developing scripts for IDA
    - Also In Section: [IDA->Tools->Nav->No Category](#c5b120e1779b928d860ad64ff8d23264) |
- [**42**Star][6m] [C++] [0xeb/ida-climacros](https://github.com/0xeb/ida-climacros) Create and use macros in IDA's CLIs
- [**32**Star][2y] [CMake] [zyantific/ida-cmake](https://github.com/zyantific/ida-cmake) IDA plugin CMake build-script
- [**22**Star][1y] [Py] [nirizr/idasix](https://github.com/nirizr/idasix) IDAPython compatibility library. idasix aims to create a smooth ida development process and allow a single codebase to function with multiple IDA/IDAPython versions
- [**4**Star][8m] [inndy/idapython-cheatsheet](https://github.com/inndy/idapython-cheatsheet) scripting IDA like a Pro


#### <a id="1a56a5b726aaa55ec5b7a5087d6c8968"></a>Qt


- [**25**Star][1y] [techbliss/ida_pro_ultimate_qt_build_guide](https://github.com/techbliss/ida_pro_ultimate_qt_build_guide) Ida Pro Ultimate Qt Build Guide
- [**13**Star][3m] [Py] [tmr232/cute](https://github.com/tmr232/cute) Cross-Qt compatibility module for IDAPython.
- [**9**Star][3y] [Py] [techbliss/ida_pro_screen_recorder](https://github.com/techbliss/ida_pro_screen_recorder) PyQt plugin for Ida Pro for Screen recording.


#### <a id="1721c09501e4defed9eaa78b8d708361"></a>Console&&GUI


- [**269**Star][1m] [Py] [eset/ipyida](https://github.com/eset/ipyida) IPython console integration for IDA Pro
- [**232**Star][2y] [Jupyter Notebook] [james91b/ida_ipython](https://github.com/james91b/ida_ipython) An IDA Pro Plugin for embedding an IPython Kernel
- [**175**Star][5m] [Py] [techbliss/python_editor](https://github.com/techbliss/python_editor) Better CodeEditor for Ida Pro.


#### <a id="227fbff77e3a13569ef7b007344d5d2e"></a>Template


- [**5**Star][2y] [C++] [patois/ida_vs2017](https://github.com/patois/ida_vs2017) IDA 7.x VisualStudio 2017 Sample Project for IDA and HexRays plugins (works with Community Edition)
- [**4**Star][5y] [JS] [nihilus/ida-pro-plugin-wizard-for-vs2013](https://github.com/nihilus/ida-pro-plugin-wizard-for-vs2013) IDA Pro plugin wizard for VisualStudio 2013


#### <a id="8b19bb8cf9a5bc9e6ab045f3b4fabf6a"></a>Other Lang


- [**22**Star][3y] [Java] [cblichmann/idajava](https://github.com/cblichmann/idajava) Java integration for Hex-Rays IDA Pro
- [**8**Star][3y] [C++] [nlitsme/idaperl](https://github.com/nlitsme/idaperl) perl scripting support for IDApro




### <a id="dc35a2b02780cdaa8effcae2b6ce623e"></a>Ancient


- [**162**Star][4y] [Py] [osirislab/fentanyl](https://github.com/osirislab/Fentanyl) an IDAPython script that makes patching significantly easier
- [**127**Star][6y] [C++] [crowdstrike/crowddetox](https://github.com/crowdstrike/crowddetox) CrowdStrike CrowdDetox Plugin for Hex-Rays，automatically removes junk code and variables from Hex-Rays function decompilation
- [**95**Star][5y] [Py] [nihilus/ida-idc-scripts](https://github.com/nihilus/ida-idc-scripts) Varoius IDC-scripts I've collected during the years.
- [**82**Star][6y] [Py] [einstein-/hexrays-python](https://github.com/einstein-/hexrays-python) Python bindings for the Hexrays Decompiler
- [**76**Star][5y] [PHP] [v0s/plus22](https://github.com/v0s/plus22) Tool to analyze 64-bit binaries with 32-bit Hex-Rays Decompiler
- [**63**Star][5y] [C] [nihilus/idastealth](https://github.com/nihilus/idastealth) 
- [**40**Star][6y] [C++] [wirepair/idapinlogger](https://github.com/wirepair/idapinlogger) Logs instruction hits to a file which can be fed into IDA Pro to highlight which instructions were called.
- [**39**Star][10y] [izsh/ida-python-scripts](https://github.com/izsh/ida-python-scripts) IDA Python Scripts
- [**39**Star][8y] [Py] [zynamics/bincrowd-plugin-ida](https://github.com/zynamics/bincrowd-plugin-ida) BinCrowd Plugin for IDA Pro
- [**35**Star][8y] [Py] [zynamics/ida2sql-plugin-ida](https://github.com/zynamics/ida2sql-plugin-ida) 
- [**27**Star][4y] [C++] [luorui110120/idaplugins](https://github.com/luorui110120/idaplugins) IDA plugins, No Doc
- [**21**Star][10y] [C++] [sporst/ida-pro-plugins](https://github.com/sporst/ida-pro-plugins) Collection of IDA Pro plugins I wrote over the years
- [**18**Star][10y] [Py] [binrapt/ida](https://github.com/binrapt/ida) Python script which extracts procedures from IDA Win32 LST files and converts them to correctly dynamically linked compilable Visual C++ inline assembly.
- [**16**Star][7y] [Py] [nihilus/optimice](https://github.com/nihilus/optimice) 
- [**10**Star][10y] [jeads-sec/etherannotate_ida](https://github.com/jeads-sec/etherannotate_ida) EtherAnnotate IDA Pro Plugin - Parse EtherAnnotate trace files and markup IDA disassemblies with runtime values
- [**6**Star][10y] [C] [jeads-sec/etherannotate_xen](https://github.com/jeads-sec/etherannotate_xen) EtherAnnotate Xen Ether Modification - Adds a feature to Ether that pulls register values and potential string values at each instruction during an instruction trace.


### <a id="e3e7030efc3b4de3b5b8750b7d93e6dd"></a>Debug&&Dynamic Data


#### <a id="2944dda5289f494e5e636089db0d6a6a"></a>No Category


- [**395**Star][1y] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) Debugger plugin for IDA Pro backed by the Unicorn Engine
    - Also In Section: [IDA->Tools->Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**187**Star][5y] [C++] [nihilus/scyllahide](https://github.com/nihilus/scyllahide) an x64/x86 usermode Anti-Anti-Debug library
- [**107**Star][23d] [Py] [danielplohmann/apiscout](https://github.com/danielplohmann/apiscout) simplifying Windows API import recovery on arbitrary memory dumps
- [**82**Star][4y] [C++] [wjp/idados](https://github.com/wjp/idados) Eric Fry's IDA/DOSBox debugger plugin
    - Also In Section: [IDA->Tools->Specific Target->No Category](#5578c56ca09a5804433524047840980e) |
- [**57**Star][8y] [Py] [cr4sh/ida-vmware-gdb](https://github.com/cr4sh/ida-vmware-gdb) Helper script for Windows kernel debugging with IDA Pro on VMware + GDB stub
- [**42**Star][5y] [Py] [nihilus/idasimulator](https://github.com/nihilus/idasimulator) a plugin that extends IDA's conditional breakpoint support, making it easy to augment / replace complex executable code inside a debugged process with Python code.
- [**39**Star][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) some idapython scripts for android debugging.
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**22**Star][5y] [Py] [techbliss/scylladumper](https://github.com/techbliss/scylladumper) Ida Plugin to Use the Awsome Scylla plugin
- [**14**Star][5y] [Py] [techbliss/free_the_debuggers](https://github.com/techbliss/free_the_debuggers) Free_the_Debuggers
- [**0**Star][2y] [Py] [benh11235/ida-windbglue](https://github.com/benh11235/ida-windbglue) Humble suite of scripts to assist with remote debugging using IDA pro client and winDBG server.


#### <a id="0fbd352f703b507853c610a664f024d1"></a>DBI Data


- [**943**Star][1y] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) Code Coverage Explorer for IDA Pro & Binary Ninja
    - Also In Section: [DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->Tools->With Other Tools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |[DBI->Frida->Tools->With Other Tools->Binary Ninja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**134**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [IDA->Tools->Import Export->IntelPin](#dd0332da5a1482df414658250e6357f8) |[IDA->Tools->Vul->No Category](#385d6777d0747e79cccab0a19fa90e7e) |[DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**128**Star][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) a reverse engineering framework created to simplify dynamic instrumentation with Frida
    - Also In Section: [IDA->Tools->Import Export->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |[DBI->Frida->Tools->With Other Tools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**122**Star][5y] [C++] [zachriggle/ida-splode](https://github.com/zachriggle/ida-splode) Augmenting Static Reverse Engineering with Dynamic Analysis and Instrumentation
    - Also In Section: [DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/zachriggle/ida-splode/tree/master/py) 
    - [PinTool](https://github.com/zachriggle/ida-splode/tree/master/src) 
- [**117**Star][2y] [C++] [0xphoenix/mazewalker](https://github.com/0xphoenix/mazewalker) Toolkit for enriching and speeding up static malware analysis
    - Also In Section: [DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |
    - [mazeui](https://github.com/0xphoenix/mazewalker/blob/master/MazeUI/mazeui.py) 在IDA中显示界面
    - [PyScripts](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/PyScripts) Python脚本，处理收集到的数据
    - [PinClient](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/src) 
- [**89**Star][8y] [C] [neuroo/runtime-tracer](https://github.com/neuroo/runtime-tracer) Dynamic tracing for binary applications (using PIN), IDA plugin to visualize and interact with the traces
    - Also In Section: [DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |
    - [PinTool](https://github.com/neuroo/runtime-tracer/tree/master/tracer) 
    - [IDA插件](https://github.com/neuroo/runtime-tracer/tree/master/ida-pin) 
- [**80**Star][3y] [Py] [davidkorczynski/repeconstruct](https://github.com/davidkorczynski/repeconstruct)  automatically unpacking binaries and rebuild the binaries in a manner well-suited for further analysis, specially focused on further manual analysis in IDA pro.
- [**52**Star][12m] [Py] [cisco-talos/dyndataresolver](https://github.com/cisco-talos/dyndataresolver) Dynamic Data Resolver (DDR) IDA Pro Plug-in
    - Also In Section: [DBI->DynamoRIO->Tools->With Other Tools](#928642a55eff34b6b52622c6862addd2) |
    - [DDR](https://github.com/cisco-talos/dyndataresolver/blob/master/VS_project/ddr/ddr.sln) 基于DyRIO的Client
    - [IDA插件](https://github.com/cisco-talos/dyndataresolver/tree/master/IDAplugin) 
- [**20**Star][9m] [C++] [secrary/findloop](https://github.com/secrary/findloop) find possible encryption/decryption or compression/decompression code
    - Also In Section: [DBI->DynamoRIO->Tools->With Other Tools](#928642a55eff34b6b52622c6862addd2) |
- [**15**Star][1y] [C++] [agustingianni/instrumentation](https://github.com/agustingianni/instrumentation) Collection of tools implemented using pintools aimed to help in the task of reverse engineering.
    - Also In Section: [DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |
    - [CodeCoverage](https://github.com/agustingianni/instrumentation/tree/master/CodeCoverage) 
    - [Pinnacle](https://github.com/agustingianni/instrumentation/tree/master/Pinnacle) 
    - [Recoverer](https://github.com/agustingianni/instrumentation/tree/master/Recoverer) 
    - [Resolver](https://github.com/agustingianni/instrumentation/tree/master/Resolver) 


#### <a id="b31acf6c84a9506066d497af4e702bf5"></a>Debugger Data


- [**607**Star][3m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) IDAPython tool for C++ vtables reconstruction
    - Also In Section: [IDA->Tools->Structure->C++ Class](#4900b1626f10791748b20630af6d6123) |
        <details>
        <summary>View Details</summary>


        ## 静态部分: 
        - 检测非直接调用
        - 利用条件断点, Hook非直接调用的值赋值过程
        
        ## 动态 部分
        - 创建虚表结构
        - 重命名函数和虚表地址
        - 给反汇编非直接调用添加结构偏移
        - 给非直接调用到虚表之间添加交叉引用
        
        ## 使用
        - File -> Script File -> Main.py(设置断点) -> IDA调试器执行
        </details>


- [**386**Star][5m] [Py] [ynvb/die](https://github.com/ynvb/die)  an IDA python plugin designed to enrich IDA`s static analysis with dynamic data
- [**380**Star][4y] [Py] [deresz/funcap](https://github.com/deresz/funcap) IDA Pro script to add some useful runtime info to static analysis
- [**104**Star][3y] [Py] [c0demap/codemap](https://github.com/c0demap/codemap) a binary analysis tool for "run-trace visualization" provided as IDA plugin.
    - [IDA插件](https://github.com/c0demap/codemap/blob/master/idapythonrc.py) 
    - [Web服务器](https://github.com/c0demap/codemap/tree/master/codemap/server) 




### <a id="d2166f4dac4eab7fadfe0fd06467fbc9"></a>Decompiler&&AST


- [**1672**Star][7m] [C++] [yegord/snowman](https://github.com/yegord/snowman)  a native code to C/C++ decompiler, supporting x86, AMD64, and ARM architectures
    - Also In Section: [x64dbg->Plugins->Recent Add](#da5688c7823802e734c39b539aa39df7) |
    - [IDA插件](https://github.com/yegord/snowman/tree/master/src/ida-plugin) 
    - [snowman](https://github.com/yegord/snowman/tree/master/src/snowman) QT界面
    - [nocode](https://github.com/yegord/snowman/tree/master/src/nocode) 命令行工具
    - [nc](https://github.com/yegord/snowman/tree/master/src/nc) 核心代码，可作为库使用
- [**1329**Star][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) Hex-Rays Decompiler plugin for better code navigation
    - Also In Section: [IDA->Tools->Nav->No Category](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>View Details</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**467**Star][4y] [Py] [einstein-/decompiler](https://github.com/EiNSTeiN-/decompiler) A decompiler with multiple backend support, written in Python. Works with IDA and Capstone.
- [**418**Star][3m] [C++] [avast/retdec-idaplugin](https://github.com/avast/retdec-idaplugin) RetDec plugin for IDA
- [**293**Star][5y] [C++] [smartdec/smartdec](https://github.com/smartdec/smartdec) SmartDec decompiler
    - [IDA插件](https://github.com/smartdec/smartdec/tree/master/src/ida-plugin) 
    - [nocode](https://github.com/smartdec/smartdec/tree/master/src/nocode) 命令行反编译器
    - [smartdec](https://github.com/smartdec/smartdec/tree/master/src/smartdec) 带GUI界面的反编译器
    - [nc](https://github.com/smartdec/smartdec/tree/master/src/nc) 反编译器的核心代码
- [**286**Star][5y] [Py] [aaronportnoy/toolbag](https://github.com/aaronportnoy/toolbag) The IDA Toolbag is a plugin providing supplemental functionality to Hex-Rays IDA Pro disassembler.
- [**235**Star][7m] [Py] [patois/dsync](https://github.com/patois/dsync) IDAPython plugin that synchronizes disassembler and decompiler views
    - Also In Section: [IDA->Tools->Nav->No Category](#c5b120e1779b928d860ad64ff8d23264) |
- [**180**Star][29d] [Py] [fireeye/fidl](https://github.com/fireeye/fidl) A sane API for IDA Pro's decompiler. Useful for malware RE and vulnerability research
- [**167**Star][1y] [Py] [tintinweb/ida-batch_decompile](https://github.com/tintinweb/ida-batch_decompile) IDA Batch Decompile plugin and script for Hex-Ray's IDA Pro that adds the ability to batch decompile multiple files and their imports with additional annotations (xref, stack var size) to the pseudocode .c file
- [**150**Star][1y] [Py] [ax330d/hrdev](https://github.com/ax330d/hrdev) Hex-Rays Decompiler Enhanced View
    - Also In Section: [IDA->Tools->Nav->GUI Enhencement](#03fac5b3abdbd56974894a261ce4e25f) |
- [**103**Star][13d] [Py] [sibears/hrast](https://github.com/sibears/hrast) PoC of modifying HexRays AST
- [**90**Star][6m] [Py] [patois/hrdevhelper](https://github.com/patois/hrdevhelper) HexRays decompiler plugin that visualizes the ctree of decompiled functions.
    - Also In Section: [IDA->Tools->Nav->GUI Enhencement](#03fac5b3abdbd56974894a261ce4e25f) |
- [**70**Star][13d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) An IDAPython decompiler script that helps auditing calls to the memcpy() and memmove() functions.
    - Also In Section: [IDA->Tools->Vul->No Category](#385d6777d0747e79cccab0a19fa90e7e) |
- [**25**Star][2y] [C++] [dougallj/dj_ida_plugins](https://github.com/dougallj/dj_ida_plugins) Plugins for IDA Pro and Hex-Rays


### <a id="7199e8787c0de5b428f50263f965fda7"></a>DeObfuscate


- [**1365**Star][3m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) Automatically extract obfuscated strings from malware.
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**542**Star][2y] [Py] [anatolikalysch/vmattack](https://github.com/anatolikalysch/vmattack) static and dynamic virtualization-based packed analysis and deobfuscation.
    - Also In Section: [IDA->Tools->Specific Target->No Category](#5578c56ca09a5804433524047840980e) |
- [**304**Star][4m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) Hex-Rays microcode API plugin for breaking an obfuscating compiler
    - Also In Section: [IDA->Tools->Microcode](#7a2977533ccdac70ee6e58a7853b756b) |
- [**202**Star][2y] [Py] [tkmru/nao](https://github.com/tkmru/nao) Simple No-meaning Assembly Omitter for IDA Pro (CURRENTLY UNDER DEVELOPMENT)
    - Also In Section: [IDA->Tools->Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**47**Star][2y] [Py] [riscure/drop-ida-plugin](https://github.com/riscure/drop-ida-plugin) Experimental opaque predicate detection for IDA Pro
- [**23**Star][5m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
    - Also In Section: [IDA->Tools->Taint Analysis](#34ac84853604a7741c61670f2a075d20) |
- [**8**Star][3y] [Py] [thngkaiyuan/mynaim](https://github.com/thngkaiyuan/mynaim) IDAPython Deobfuscation Scripts for Nymaim Samples
    - Also In Section: [IDA->Tools->Specific Target->Malware Family](#841d605300beba45c3be131988514a03) |


### <a id="fcf75a0881617d1f684bc8b359c684d7"></a>Nav&&Quick Access&&Graph&&Image


#### <a id="c5b120e1779b928d860ad64ff8d23264"></a>No Category


- [**1329**Star][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) Hex-Rays Decompiler plugin for better code navigation
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
        <details>
        <summary>View Details</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**449**Star][4m] [C++] [alexhude/friend](https://github.com/alexhude/friend) Flexible Register/Instruction Extender aNd Documentation
    - Also In Section: [IDA->Tools->Instruction Reference](#846eebe73bef533041d74fc711cafb43) |
- [**372**Star][3m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) Make your IDA Lazy!
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->Tools->Vul->No Category](#385d6777d0747e79cccab0a19fa90e7e) |
        <details>
        <summary>View Details</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**329**Star][4m] [Py] [pfalcon/scratchabit](https://github.com/pfalcon/scratchabit) Easily retargetable and hackable interactive disassembler with IDAPython-compatible plugin API
- [**235**Star][7m] [Py] [patois/dsync](https://github.com/patois/dsync) IDAPython plugin that synchronizes disassembler and decompiler views
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**192**Star][2m] [Py] [danigargu/dereferencing](https://github.com/danigargu/dereferencing) IDA Pro plugin that implements more user-friendly register and stack views
- [**130**Star][2y] [Py] [comsecuris/ida_strcluster](https://github.com/comsecuris/ida_strcluster) extending IDA's string navigation capabilities
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
- [**99**Star][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) IDAPython plugin for finding function strings recursively
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->Tools->Function->Nav](#e4616c414c24b58626f834e1be079ebc) |
- [**81**Star][15d] [Py] [ax330d/functions-plus](https://github.com/ax330d/functions-plus) IDA Pro plugin to show functions in a tree view
    - Also In Section: [IDA->Tools->Function->Nav](#e4616c414c24b58626f834e1be079ebc) |
- [**74**Star][5m] [C++] [0xeb/ida-qscripts](https://github.com/0xeb/ida-qscripts) An IDA plugin to increase productivity when developing scripts for IDA
    - Also In Section: [IDA->Tools->Script Writting->No Category](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**48**Star][8d] [C++] [jinmo/ifred](https://github.com/jinmo/ifred) IDA command palette & more (Ctrl+Shift+P, Ctrl+P)
- [**40**Star][5m] [Py] [tmr232/brutal-ida](https://github.com/tmr232/brutal-ida) Block Redo & Undo To Achieve Legacy IDA
- [**23**Star][7y] [C++] [cr4sh/ida-ubigraph](https://github.com/cr4sh/ida-ubigraph) IDA Pro plug-in and tools for displaying 3D graphs of procedures using UbiGraph
- [**17**Star][2y] [Py] [tmr232/graphgrabber](https://github.com/tmr232/graphgrabber) grab full-resolution images of IDA graphs.
- [**5**Star][2y] [Py] [handsomematt/ida_func_ptr](https://github.com/handsomematt/ida_func_ptr) Easily create and copy function pointers to functions in IDA.


#### <a id="03fac5b3abdbd56974894a261ce4e25f"></a>GUI Enhencement


- [**208**Star][1m] [Py] [patois/idacyber](https://github.com/patois/idacyber) Data Visualization Plugin for IDA Pro
- [**150**Star][1y] [Py] [ax330d/hrdev](https://github.com/ax330d/hrdev) Hex-Rays Decompiler Enhanced View
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**105**Star][2y] [Py] [danigargu/idatropy](https://github.com/danigargu/idatropy) a plugin for Hex-Ray's IDA Pro designed to generate charts of entropy and histograms using the power of idapython and matplotlib.
- [**90**Star][6m] [Py] [patois/hrdevhelper](https://github.com/patois/hrdevhelper) HexRays decompiler plugin that visualizes the ctree of decompiled functions.
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**52**Star][1m] [Py] [patois/xray](https://github.com/patois/xray) Hexrays decompiler plugin that colorizes and filters the decompiler's output based on regular expressions
- [**20**Star][4m] [C++] [revspbird/hightlight](https://github.com/revspbird/hightlight) a plugin for ida of version 7.2 to help know F5 window codes better
- [**5**Star][3y] [Py] [oct0xor/ida_pro_graph_styling](https://github.com/oct0xor/ida_pro_graph_styling) Advanced Ida Pro Instruction Highlighting
- [**5**Star][2y] [C] [teppay/ida](https://github.com/teppay/ida) my files related to IDA
- [**3**Star][2y] [Py] [andreafioraldi/idaretaddr](https://github.com/andreafioraldi/idaretaddr) Highlight the return address of a function in the Ida Pro debugger
    - Also In Section: [IDA->Tools->Function->No Category](#347a2158bdd92b00cd3d4ba9a0be00ae) |


#### <a id="3b1dba00630ce81cba525eea8fcdae08"></a>Graph


- [**2569**Star][6m] [Java] [google/binnavi](https://github.com/google/binnavi) a binary analysis IDE that allows to inspect, navigate, edit and annotate control flow graphs and call graphs of disassembled code.
- [**231**Star][2y] [C++] [fireeye/simplifygraph](https://github.com/fireeye/simplifygraph) IDA Pro plugin to assist with complex graphs
- [**40**Star][9m] [Py] [rr-/ida-images](https://github.com/rr-/ida-images) Image preview plugin for IDA disassembler.


#### <a id="8f9468e9ab26128567f4be87ead108d7"></a>Search


- [**150**Star][15d] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) Fuzzy search tool for IDA Pro.
    - Also In Section: [IDA->Tools->Function->Nav](#e4616c414c24b58626f834e1be079ebc) |
- [**64**Star][3y] [Py] [xorpd/idsearch](https://github.com/xorpd/idsearch) A search tool for IDA
- [**23**Star][6m] [Py] [alexander-hanel/hansel](https://github.com/alexander-hanel/hansel) a simple but flexible search for IDA




### <a id="66052f824f5054aa0f70785a2389a478"></a>Android


- [**246**Star][28d] [C++] [strazzere/android-scripts](https://github.com/strazzere/android-scripts) Collection of Android reverse engineering scripts
    - Also In Section: [Android->Tools->Reverse Engineering](#6d2b758b3269bac7d69a2d2c8b45194c) |
- [**161**Star][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->Specific Target->Loader](#cb59d84840e41330a7b5e275c0b81725) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |[Android->Tools->Recent Add](#63fd2c592145914e99f837cecdc5a67c) |
- [**118**Star][4y] [Py] [cvvt/dumpdex](https://github.com/cvvt/dumpdex) IDA python script to dynamically dump DEX in memory
    - Also In Section: [Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**83**Star][2y] [Py] [zhkl0228/androidattacher](https://github.com/zhkl0228/androidattacher) IDA debugging plugin for android armv7 so
    - Also In Section: [Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**39**Star][5y] [Py] [techbliss/adb_helper_qt_super_version](https://github.com/techbliss/adb_helper_qt_super_version) All You Need For Ida Pro And Android Debugging
    - Also In Section: [Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**39**Star][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) some idapython scripts for android debugging.
    - Also In Section: [IDA->Tools->Debug->No Category](#2944dda5289f494e5e636089db0d6a6a) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**16**Star][7y] [C++] [strazzere/dalvik-header-plugin](https://github.com/strazzere/dalvik-header-plugin) Dalvik Header Plugin for IDA Pro
    - Also In Section: [Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |


### <a id="2adc0044b2703fb010b3bf73b1f1ea4a"></a>Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O


#### <a id="8530752bacfb388f3726555dc121cb1a"></a>No Category


- [**177**Star][2y] [Py] [duo-labs/idapython](https://github.com/duo-labs/idapython)  a few Python modules developed for use with IDA Pro from the researchers at Duo Labs.
    - Also In Section: [IDA->Tools->Firmware](#a8f5db3ab4bc7bc3d6ca772b3b9b0b1e) |
    - [cortex_m_firmware](https://github.com/duo-labs/idapython/blob/master/cortex_m_firmware.py) grooms an IDA Pro database containing firmware from an ARM Cortex M microcontroller.
    - [amnesia](https://github.com/duo-labs/idapython/blob/master/amnesia.py)  an IDAPython module designed to use byte level heuristics to find ARM thumb instructions in undefined bytes in an IDA Pro database
    - [REobjc](https://github.com/duo-labs/idapython/blob/master/reobjc.py)  an IDAPython module designed to make proper cross references between calling functions and called functions in Objective-C methods
- [**167**Star][8y] [Py] [zynamics/objc-helper-plugin-ida](https://github.com/zynamics/objc-helper-plugin-ida) Simplifies working with Objective-C binaries in IDA Pro
- [**21**Star][3y] [aozhimin/ios-monitor-resources](https://github.com/aozhimin/ios-monitor-resources) 对各厂商的 iOS SDK 性能监控方案的整理和收集后的资源
- [**17**Star][9y] [C++] [alexander-pick/patchdiff2_ida6](https://github.com/alexander-pick/patchdiff2_ida6) patched up patchdiff2 to compile and work with IDA 6 on OSX
- [**14**Star][8y] [Standard ML] [letsunlockiphone/iphone-baseband-ida-pro-signature-files](https://github.com/letsunlockiphone/iphone-baseband-ida-pro-signature-files) IDA Pro Signature Files iPhone Baseband Reversing
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->No Category](#cf04b98ea9da0056c055e2050da980c1) |


#### <a id="82d0fa2d6934ce29794a651513934384"></a>Kernel Cache


- [**168**Star][1y] [Py] [bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) An IDA Toolkit for analyzing iOS kernelcaches
    - Also In Section: [IDA->Tools->Structure->No Category](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**140**Star][8y] [stefanesser/ida-ios-toolkit](https://github.com/stefanesser/ida-ios-toolkit) Collection of idapython scripts for dealing with the iOS kernelcache
- [**50**Star][1y] [Py] [synacktiv-contrib/kernelcache-laundering](https://github.com/Synacktiv-contrib/kernelcache-laundering) load iOS12 kernelcaches and PAC code in IDA


#### <a id="d249a8d09a3f25d75bb7ba8b32bd9ec5"></a>Mach-O


- [**47**Star][8m] [C] [gdbinit/extractmacho](https://github.com/gdbinit/extractmacho) IDA plugin to extract Mach-O binaries located in the disassembly or data
- [**18**Star][3y] [C] [cocoahuke/iosdumpkernelfix](https://github.com/cocoahuke/iosdumpkernelfix) This tool will help to fix the Mach-O header of iOS kernel which dump from the memory. So that IDA or function symbol-related tools can loaded function symbols of ios kernel correctly
- [**17**Star][8y] [C] [gdbinit/machoplugin](https://github.com/gdbinit/machoplugin) IDA plugin to Display Mach-O headers


#### <a id="1c698e298f6112a86c12881fbd8173c7"></a>Swift


- [**52**Star][3y] [Py] [tobefuturer/ida-swift-demangle](https://github.com/tobefuturer/ida-swift-demangle) A tool to demangle Swift function names in IDA.
- [**17**Star][3y] [Py] [tylerha97/swiftdemang](https://github.com/0xtyh/swiftdemang) Demangle Swift
- [**17**Star][4y] [Py] [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle) An IDA plugin to demangle Swift function names
    - Also In Section: [IDA->Tools->Function->demangle](#cadae88b91a57345d266c68383eb05c5) |




### <a id="e5e403123c70ddae7bd904d3a3005dbb"></a>ELF


- [**525**Star][2y] [C] [lunixbochs/patchkit](https://github.com/lunixbochs/patchkit) binary patching from Python
    - Also In Section: [IDA->Tools->Patch](#7d557bc3d677d206ef6c5a35ca8b3a14) |
    - [IDA插件](https://github.com/lunixbochs/patchkit/tree/master/ida) 
    - [patchkit](https://github.com/lunixbochs/patchkit/tree/master/core) 
- [**206**Star][6y] [C] [snare/ida-efiutils](https://github.com/snare/ida-efiutils) Some scripts for IDA Pro to assist with reverse engineering EFI binaries
- [**161**Star][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->Tools->Specific Target->Loader](#cb59d84840e41330a7b5e275c0b81725) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |[Android->Tools->Recent Add](#63fd2c592145914e99f837cecdc5a67c) |
- [**125**Star][8m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [IDA->Tools->Import Export->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[IDA->Tools->Function->No Category](#347a2158bdd92b00cd3d4ba9a0be00ae) |[Radare2->Plugins->With Other Tools->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**92**Star][3y] [C++] [gdbinit/efiswissknife](https://github.com/gdbinit/efiswissknife) An IDA plugin to improve (U)EFI reversing
- [**84**Star][19d] [Py] [yeggor/uefi_retool](https://github.com/yeggor/uefi_retool) finding proprietary protocols in UEFI firmware and UEFI modules analysing
- [**44**Star][2y] [C] [aerosoul94/dynlib](https://github.com/aerosoul94/dynlib) IDA Pro plugin to aid PS4 user mode ELF reverse engineering.
    - Also In Section: [IDA->Tools->Specific Target->PS3](#315b1b8b41c67ae91b841fce1d4190b5) |
- [**44**Star][4y] [Py] [danse-macabre/ida-efitools](https://github.com/danse-macabre/ida-efitools) Some scripts for IDA Pro to assist with reverse engineering EFI binaries
- [**43**Star][4y] [Py] [strazzere/idant-wanna](https://github.com/strazzere/idant-wanna) ELF header abuse


### <a id="7a2977533ccdac70ee6e58a7853b756b"></a>Microcode


- [**304**Star][4m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) Hex-Rays microcode API plugin for breaking an obfuscating compiler
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**185**Star][5m] [C++] [chrisps/hexext](https://github.com/chrisps/Hexext) a plugin to improve the output of the hexrays decompiler through microcode manipulation.
- [**65**Star][1m] [Py] [patois/genmc](https://github.com/patois/genmc) Display Hex-Rays Microcode
- [**54**Star][3m] [Py] [idapython/pyhexraysdeob](https://github.com/idapython/pyhexraysdeob) A port of Rolf Rolles hexraysdeob
- [**19**Star][9m] [Py] [neatmonster/mcexplorer](https://github.com/neatmonster/mcexplorer) Python portage of the Microcode Explorer plugin


### <a id="b38dab81610be087bd5bc7785269b8cc"></a>Emulator


- [**504**Star][20d] [Py] [alexhude/uemu](https://github.com/alexhude/uemu) Tiny cute emulator plugin for IDA based on unicorn.
- [**395**Star][1y] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) Debugger plugin for IDA Pro backed by the Unicorn Engine
    - Also In Section: [IDA->Tools->Debug->No Category](#2944dda5289f494e5e636089db0d6a6a) |
- [**393**Star][3y] [Py] [36hours/idaemu](https://github.com/36hours/idaemu) an IDA Pro Plugin use for emulating code in IDA Pro.
    - Also In Section: [IDA->Tools->Script Writting->No Category](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**282**Star][2m] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) marries a supported binary analysis framework, such as IDA Pro or Radare2, with Unicorn’s emulation framework to provide the user with an easy to use and flexible interface for scripting emulation tasks
    - Also In Section: [IDA->Tools->Script Writting->No Category](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**202**Star][2y] [Py] [tkmru/nao](https://github.com/tkmru/nao) Simple No-meaning Assembly Omitter for IDA Pro (CURRENTLY UNDER DEVELOPMENT)
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**126**Star][3y] [Py] [codypierce/pyemu](https://github.com/codypierce/pyemu) x86 Emulator in Python


### <a id="83de90385d03ac8ef27360bfcdc1ab48"></a>Part Of Other Tool


- [**1542**Star][28d] [Py] [lifting-bits/mcsema](https://github.com/lifting-bits/mcsema) Framework for lifting x86, amd64, and aarch64 program binaries to LLVM bitcode
    - [IDA7插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida7) 用于反汇编二进制文件并生成控制流程图
    - [IDA插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida) 用于反汇编二进制文件并生成控制流程图
    - [Binja插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/binja) 用于反汇编二进制文件并生成控制流程图
    - [mcsema](https://github.com/lifting-bits/mcsema/tree/master/mcsema) 
- [**421**Star][1m] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) a scalable assembly management and analysis platform
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->No Category](#cf04b98ea9da0056c055e2050da980c1) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 
- [**27**Star][4y] [Scheme] [yifanlu/cgen](https://github.com/yifanlu/cgen) CGEN with support for generating IDA Pro IDP modules
- [**23**Star][2y] [Py] [tintinweb/unbox](https://github.com/tintinweb/unbox) a convenient one-click unpack and decompiler tool that wraps existing 3rd party applications like IDA Pro, JD-Cli, Dex2Src, and others to provide a convenient archiver liker command line interfaces to unpack and decompile various types of files


### <a id="1ded622dca60b67288a591351de16f8b"></a>Vul


#### <a id="385d6777d0747e79cccab0a19fa90e7e"></a>No Category


- [**492**Star][7m] [Py] [danigargu/heap-viewer](https://github.com/danigargu/heap-viewer) An IDA Pro plugin to examine the glibc heap, focused on exploit development
- [**376**Star][2y] [Py] [1111joe1111/ida_ea](https://github.com/1111joe1111/ida_ea) A set of exploitation/reversing aids for IDA
- [**372**Star][3m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) Make your IDA Lazy!
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->Tools->Nav->No Category](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>View Details</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**138**Star][8m] [Py] [iphelix/ida-sploiter](https://github.com/iphelix/ida-sploiter) a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's capabilities as an exploit development and vulnerability research tool.
- [**134**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [IDA->Tools->Import Export->IntelPin](#dd0332da5a1482df414658250e6357f8) |[IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**70**Star][13d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) An IDAPython decompiler script that helps auditing calls to the memcpy() and memmove() functions.
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**32**Star][6y] [Py] [coldheat/quicksec](https://github.com/coldheat/quicksec) IDAPython script for quick vulnerability analysis


#### <a id="cf2efa7e3edb24975b92d2e26ca825d2"></a>ROP


- [**54**Star][3y] [Py] [patois/drgadget](https://github.com/patois/drgadget) IDAPython plugin for the Interactive Disassembler 
- [**19**Star][2y] [Py] [lucasg/idarop](https://github.com/lucasg/idarop) ROP database plugin for IDA




### <a id="7d557bc3d677d206ef6c5a35ca8b3a14"></a>Patch


- [**727**Star][1y] [Py] [keystone-engine/keypatch](https://github.com/keystone-engine/keypatch) Multi-architecture assembler for IDA Pro. Powered by Keystone Engine.
- [**525**Star][2y] [C] [lunixbochs/patchkit](https://github.com/lunixbochs/patchkit) binary patching from Python
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
    - [IDA插件](https://github.com/lunixbochs/patchkit/tree/master/ida) 
    - [patchkit](https://github.com/lunixbochs/patchkit/tree/master/core) 
- [**89**Star][5y] [Py] [iphelix/ida-patcher](https://github.com/iphelix/ida-patcher) a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's ability to patch binary files and memory.
- [**42**Star][3y] [C++] [mrexodia/idapatch](https://github.com/mrexodia/idapatch) IDA plugin to patch IDA Pro in memory.
- [**31**Star][4m] [Py] [scottmudge/debugautopatch](https://github.com/scottmudge/debugautopatch) Patching system improvement plugin for IDA.
- [**16**Star][8y] [C++] [jkoppel/reprogram](https://github.com/jkoppel/reprogram) Patch binaries at load-time
- [**0**Star][8m] [Py] [tkmru/genpatch](https://github.com/tkmru/genpatch) IDA plugin that generates a python script for patch


### <a id="7dfd8abad50c14cd6bdc8d8b79b6f595"></a>Other


- [**123**Star][2y] [Shell] [feicong/ida_for_mac_green](https://github.com/feicong/ida_for_mac_green) IDAPro for macOS
- [**34**Star][6m] [angelkitty/ida7.0](https://github.com/angelkitty/ida7.0) 
- [**16**Star][2y] [jas502n/ida7.0-pro](https://github.com/jas502n/ida7.0-pro) IDA7.0  download


### <a id="90bf5d31a3897400ac07e15545d4be02"></a>Function


#### <a id="347a2158bdd92b00cd3d4ba9a0be00ae"></a>No Category


- [**125**Star][8m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->Import Export->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[Radare2->Plugins->With Other Tools->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**11**Star][2y] [C++] [fireundubh/ida7-functionstringassociate](https://github.com/fireundubh/ida7-functionstringassociate) FunctionStringAssociate plugin by sirmabus, ported to IDA 7
- [**3**Star][2y] [Py] [andreafioraldi/idaretaddr](https://github.com/andreafioraldi/idaretaddr) Highlight the return address of a function in the Ida Pro debugger
    - Also In Section: [IDA->Tools->Nav->GUI Enhencement](#03fac5b3abdbd56974894a261ce4e25f) |
- [**2**Star][5m] [Py] [farzonl/idapropluginlab3](https://github.com/farzonl/idapropluginlab3) An Ida plugin that does static analysis to describe what malware is doing.


#### <a id="73813456eeb8212fd45e0ea347bec349"></a>Rename&&Prefix&&Tag


- [**291**Star][3m] [Py] [a1ext/auto_re](https://github.com/a1ext/auto_re) IDA PRO auto-renaming plugin with tagging support
- [**119**Star][5y] [C++] [zyantific/retypedef](https://github.com/zyantific/retypedef) Name substitution plugin for IDA Pro
- [**95**Star][2y] [Py] [gaasedelen/prefix](https://github.com/gaasedelen/prefix) Function Prefixing for IDA Pro
- [**48**Star][3y] [Py] [alessandrogario/ida-function-tagger](https://github.com/alessandrogario/ida-function-tagger) This IDAPython script tags subroutines according to their use of imported functions
- [**23**Star][12m] [Py] [howmp/comfinder](https://github.com/howmp/comfinder) IDA plugin for COM
    - Also In Section: [IDA->Tools->Specific Target->No Category](#5578c56ca09a5804433524047840980e) |
- [**3**Star][4y] [Py] [ayuto/discover_win](https://github.com/ayuto/discover_win) compare linux and windows binary, rename windows binary functions
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->No Category](#cf04b98ea9da0056c055e2050da980c1) |


#### <a id="e4616c414c24b58626f834e1be079ebc"></a>Nav&&Search


- [**180**Star][6m] [Py] [hasherezade/ida_ifl](https://github.com/hasherezade/ida_ifl) IFL - Interactive Functions List (plugin for IDA Pro)
- [**150**Star][15d] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) Fuzzy search tool for IDA Pro.
    - Also In Section: [IDA->Tools->Nav->Search](#8f9468e9ab26128567f4be87ead108d7) |
- [**99**Star][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) IDAPython plugin for finding function strings recursively
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->Tools->Nav->No Category](#c5b120e1779b928d860ad64ff8d23264) |
- [**81**Star][15d] [Py] [ax330d/functions-plus](https://github.com/ax330d/functions-plus) IDA Pro plugin to show functions in a tree view
    - Also In Section: [IDA->Tools->Nav->No Category](#c5b120e1779b928d860ad64ff8d23264) |
- [**34**Star][3y] [Py] [darx0r/reef](https://github.com/darx0r/reef) IDAPython plugin for finding Xrefs from a function


#### <a id="cadae88b91a57345d266c68383eb05c5"></a>demangle


- [**17**Star][4y] [Py] [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle) An IDA plugin to demangle Swift function names
    - Also In Section: [IDA->Tools->Apple->Swift](#1c698e298f6112a86c12881fbd8173c7) |
- [**14**Star][1y] [Py] [ax330d/exports-plus](https://github.com/ax330d/exports-plus) IDA Pro plugin to view Exports




### <a id="34ac84853604a7741c61670f2a075d20"></a>Taint Analysis&&Symbolic Execution


- [**931**Star][25d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) a static Binary Code Analysis Toolkit, designed to help reverse engineers, directly from IDA or using Python for automation.
    - Also In Section: [IDA->Tools->Structure->No Category](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**868**Star][2y] [C++] [illera88/ponce](https://github.com/illera88/ponce) Symbolic Execution just one-click away!
- [**23**Star][5m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |


### <a id="9dcc6c7dd980bec1f92d0cc9a2209a24"></a>string


- [**1365**Star][3m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) Automatically extract obfuscated strings from malware.
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**372**Star][3m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) Make your IDA Lazy!
    - Also In Section: [IDA->Tools->Nav->No Category](#c5b120e1779b928d860ad64ff8d23264) |[IDA->Tools->Vul->No Category](#385d6777d0747e79cccab0a19fa90e7e) |
        <details>
        <summary>View Details</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**181**Star][2m] [Py] [joxeankoret/idamagicstrings](https://github.com/joxeankoret/idamagicstrings) An IDA Python script to extract information from string constants.
- [**130**Star][2y] [Py] [comsecuris/ida_strcluster](https://github.com/comsecuris/ida_strcluster) extending IDA's string navigation capabilities
    - Also In Section: [IDA->Tools->Nav->No Category](#c5b120e1779b928d860ad64ff8d23264) |
- [**99**Star][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) IDAPython plugin for finding function strings recursively
    - Also In Section: [IDA->Tools->Nav->No Category](#c5b120e1779b928d860ad64ff8d23264) |[IDA->Tools->Function->Nav](#e4616c414c24b58626f834e1be079ebc) |
- [**45**Star][5y] [Py] [kyrus/ida-translator](https://github.com/kyrus/ida-translator) A plugin for IDA Pro that assists in decoding arbitrary character sets in an IDA Pro database into Unicode, then automatically invoking a web-based translation service (currently Google Translate) to translate that foreign text into English.
- [**4**Star][3y] [C#] [andreafioraldi/idagrabstrings](https://github.com/andreafioraldi/idagrabstrings) IDAPython plugin to manipulate strings in a specified range of addresses
    - Also In Section: [IDA->Tools->Structure->No Category](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**4**Star][8m] [C] [lacike/gandcrab_string_decryptor](https://github.com/lacike/gandcrab_string_decryptor) IDC script for decrypting strings in the GandCrab v5.1-5.3
    - Also In Section: [IDA->Tools->Specific Target->Malware Family](#841d605300beba45c3be131988514a03) |


### <a id="06d2caabef97cf663bd29af2b1fe270c"></a>encrypt&&decrypt


- [**449**Star][2m] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) IDA pro plugin to find crypto constants (and more)
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |
- [**136**Star][25d] [Py] [you0708/ida](https://github.com/you0708/ida) A Python implementation of FindCrypt plugin.
    - [IDA主题](https://github.com/you0708/ida/tree/master/theme) 
    - [findcrypt](https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt) IDA FindCrypt/FindCrypt2 插件的Python版本
- [**42**Star][7y] [C++] [vlad902/findcrypt2-with-mmx](https://github.com/vlad902/findcrypt2-with-mmx) IDA Pro findcrypt2 plug-in with MMX AES instruction finding support




***


## <a id="18c6a45392d6b383ea24b363d2f3e76b"></a>Video&&Post


### <a id="37634a992983db427ce41b37dd9a98c2"></a>Recent Add


- 2019.12 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P27)](https://medium.com/p/5fa5c173547c)
- 2019.12 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P26)](https://medium.com/p/f3fc8d187258)
- 2019.12 [knownsec] [使用 IDA 处理 U-Boot 二进制流文件](https://blog.knownsec.com/2019/12/%e4%bd%bf%e7%94%a8-ida-%e5%a4%84%e7%90%86-u-boot-%e4%ba%8c%e8%bf%9b%e5%88%b6%e6%b5%81%e6%96%87%e4%bb%b6/)
- 2019.12 [venus] [使用 IDA 处理 U-Boot 二进制流文件](https://paper.seebug.org/1090/)
- 2019.11 [hexblog] [Extending IDA processor modules for GDB debugging](http://www.hexblog.com/?p=1371)
- 2019.11 [0x48] [使用IDA处理U-Boot二进制流文件](https://nobb.site/2019/11/29/0x57/)
- 2019.11 [aliyun] [使用IDA microcode去除ollvm混淆(上)](https://xz.aliyun.com/t/6749)
- 2019.10 [cisco] [New IDA Pro plugin provides TileGX support](https://blogs.cisco.com/security/talos/new-ida-pro-plugin-provides-tilegx-support)
- 2019.09 [cisco] [GhIDA: Ghidra decompiler for IDA Pro](https://blogs.cisco.com/security/talos/ghida-ghidra-decompiler-for-ida-pro)
- 2019.09 [cn0xroot] [Fix IDA Crash bug on osx 10.14](https://cn0xroot.com/2019/09/02/fix-ida-crash-bug-on-osx-10-14/)
- 2019.08 [hexblog] [IDA 7.4: IDAPython and Python 3](http://www.hexblog.com/?p=1355)
- 2019.08 [hexblog] [IDA 7.4: Turning off IDA 6.x compatibility in IDAPython by default](http://www.hexblog.com/?p=1352)
- 2019.06 [hitbsecconf] [#HITB2019AMS D1T2 - fn_fuzzy: Fast Multiple Binary Diffing Triage With IDA - Takahiro Haruyama](https://www.youtube.com/watch?v=kkvNebE9amY)
- 2019.05 [aliyun] [欺骗IDA F5参数识别](https://xz.aliyun.com/t/5186)
- 2019.05 [aliyun] [混淆IDA F5的一个小技巧-x64](https://xz.aliyun.com/t/4994)
- 2018.11 [4hou] [使用IDAPython自动映射二进制文件替换默认函数名](http://www.4hou.com/technology/14149.html)
- 2018.10 [WarrantyVoider] [Ida Pro Tutorial -  Compare Reverse Engineering](https://www.youtube.com/watch?v=7-OytQJRwtE)
- 2018.06 [freebuf] [MindshaRE：如何利用IDA Python浏览WINDOWS内核](http://www.freebuf.com/articles/system/173269.html)
- 2018.05 [WarrantyVoider] [Tutorial - Debugging In Source Code With IDA Pro](https://www.youtube.com/watch?v=Jgb3KTVg-rY)
- 2018.03 [BinaryAdventure] [x86 In-Depth 4: Labeling Structs Properly in IDA Pro](https://www.youtube.com/watch?v=X3xCwNt2ZVY)
- 2017.12 [BinaryAdventure] [Understanding the IDAPython API Docs](https://www.youtube.com/watch?v=QwOOzSx5g3w)
- 2016.01 [freebuf] [适用于IDA Pro的CGEN框架介绍](http://www.freebuf.com/articles/security-management/92938.html)
- 2015.12 [] [某公司泄露版IDA pro6.8去除局域网检测](http://www.91ri.org/14891.html)
- 2015.10 [pediy] [[原创]基于IDA Python的Dex Dump](https://bbs.pediy.com/thread-205316.htm)
- 2012.11 [pediy] [[原创]分享一个QuickTime静态分析IDAPython脚本](https://bbs.pediy.com/thread-158687.htm)
- 2009.03 [pediy] [[原创]如何将idc脚本移植成IDA plugin程序](https://bbs.pediy.com/thread-84527.htm)
- 2006.11 [pediy] [[翻译]008使用IDA PRO的跟踪特性](https://bbs.pediy.com/thread-35253.htm)


### <a id="4187e477ebc45d1721f045da62dbf4e8"></a>No Category


- 2018.05 [tradahacking] [So sánh binary bằng IDA và các công cụ bổ trợ](https://medium.com/p/651e62117695)
- 2018.04 [pediy] [[翻译]IDAPython-Book（Alexander Hanel）](https://bbs.pediy.com/thread-225920.htm)
- 2018.03 [hexblog] [IDA on non-OS X/Retina Hi-DPI displays](http://www.hexblog.com/?p=1180)
- 2018.03 [pediy] [[翻译]IDA v6.5 文本执行](https://bbs.pediy.com/thread-225514.htm)
- 2018.02 [pediy] [[原创]逆向技术之熟悉IDA工具](https://bbs.pediy.com/thread-224499.htm)
- 2018.01 [pediy] [[原创]ARM Linux下搭建IDA Pro远程调试环境](https://bbs.pediy.com/thread-224337.htm)
- 2018.01 [pediy] [[翻译]对抗IDA Pro调试器ARM反汇编的技巧](https://bbs.pediy.com/thread-223894.htm)
- 2017.12 [OALabs] [Debugging shellcode using BlobRunner and IDA Pro](https://www.youtube.com/watch?v=q9q8dy-2Jeg)
- 2017.12 [pediy] [[原创]IDA7.0 Mac 插件编译指南](https://bbs.pediy.com/thread-223211.htm)
- 2017.12 [pediy] [[原创]IDA 插件- FRIEND 的安装和使用](https://bbs.pediy.com/thread-223156.htm)
- 2017.12 [BinaryAdventure] [IDAPython Tutorial with example script](https://www.youtube.com/watch?v=5ehI2wgcSGo)
- 2017.11 [OALabs] [How To Defeat Anti-VM and Anti-Debug Packers With IDA Pro](https://www.youtube.com/watch?v=WlE8abc8V-4)
- 2017.11 [pediy] [[原创]IDAPython脚本分享 - 自动在JNI_OnLoad下断点](https://bbs.pediy.com/thread-222998.htm)
- 2017.11 [pediy] [[求助]IDA Pro调试so，附加完毕，跳到目标so基址，但是内容都是DCB伪指令？](https://bbs.pediy.com/thread-222646.htm)
- 2017.11 [OALabs] [IDA Pro Malware Analysis Tips](https://www.youtube.com/watch?v=qCQRKLaz2nQ)
- 2017.10 [hexblog] [IDA and common Python issues](http://www.hexblog.com/?p=1132)
- 2017.10 [pediy] [[分享]IDA + VMware 调试win7 x64](https://bbs.pediy.com/thread-221884.htm)
- 2017.06 [pediy] [[翻译]IDA Hex-Rays反编译器使用的一些小技巧](https://bbs.pediy.com/thread-218780.htm)
- 2017.06 [qmemcpy] [IDA series, part 2: debugging a .NET executable](https://qmemcpy.io/post/ida-series-2-debugging-net)
- 2017.06 [qmemcpy] [IDA series, part 1: the Hex-Rays decompiler](https://qmemcpy.io/post/ida-series-1-hex-rays)
- 2017.05 [3gstudent] [逆向分析——使用IDA动态调试WanaCrypt0r中的tasksche.exe](https://3gstudent.github.io/3gstudent.github.io/%E9%80%86%E5%90%91%E5%88%86%E6%9E%90-%E4%BD%BF%E7%94%A8IDA%E5%8A%A8%E6%80%81%E8%B0%83%E8%AF%95WanaCrypt0r%E4%B8%AD%E7%9A%84tasksche.exe/)
- 2017.05 [pediy] [[原创] IDA导入Jni.h](https://bbs.pediy.com/thread-217701.htm)
- 2017.05 [oct0xor] [Advanced Ida Pro Instruction Highlighting](http://oct0xor.github.io/2017/05/03/ida_coloring/)
- 2017.05 [repret] [Improving Coverage Guided Fuzzing, Using Static Analysis](https://repret.wordpress.com/2017/05/01/improving-coverage-guided-fuzzing-using-static-analysis/)
- 2017.04 [osandamalith] [Executing Shellcode Directly](https://osandamalith.com/2017/04/11/executing-shellcode-directly/)
- 2017.04 [hexacorn] [IDA, hotpatched functions and signatures that don’t work…](http://www.hexacorn.com/blog/2017/04/07/ida-hotpatched-functions-and-signatures-that-dont-work/)
- 2017.04 [] [Remote debugging in IDA Pro by http tunnelling](https://0xec.blogspot.com/2017/04/remote-debugging-in-ida-pro-by-http.html)
- 2017.03 [pediy] [[翻译]如何让 IDA Pro 使用我们提供的 Python 版本以及如何在 Chroot 的环境中运行 IDA Pro](https://bbs.pediy.com/thread-216643.htm)
- 2017.01 [kudelskisecurity] [SANS Holiday Hack Challenge 2016](https://research.kudelskisecurity.com/2017/01/06/sans-holiday-hack-challenge-2016/)
- 2016.12 [adelmas] [API Hooking with IDA Pro](http://adelmas.com/blog/ida_api_hooking.php)
- 2016.12 [hexacorn] [IDA, function alignment and signatures that don’t work…](http://www.hexacorn.com/blog/2016/12/27/ida-function-alignment-and-signatures-that-dont-work/)
- 2016.10 [] [Build IDA Pro KeyPatch for Fedora Linux](https://www.0x90.se/build-ida-pro-keypatch-for-fedora-linux/)
- 2016.05 [lucasg] [Do not load dll from System32 directly into IDA](http://lucasg.github.io/2016/05/30/Do-not-load-dll-from-System32-directly-into-IDA/)
- 2016.04 [hexacorn] [Creating IDT/IDS files for IDA from MS libraries with symbols](http://www.hexacorn.com/blog/2016/04/22/creating-idtids-files-for-ida-from-ms-libraries-with-symbols/)
- 2016.02 [pediy] [[原创]翻译，IDA调试Dalvik](https://bbs.pediy.com/thread-207891.htm)
- 2016.01 [pediy] [[原创]Android 5.0 + IDA 6.8 调试经验分享](https://bbs.pediy.com/thread-207548.htm)
- 2016.01 [insinuator] [Dynamic IDA Enrichment (aka. DIE)](https://insinuator.net/2016/01/die/)
- 2016.01 [360] [在OSX上编译非osx ida pro插件](https://www.anquanke.com/post/id/83385/)
- 2016.01 [adventuresincyberchallenges] [SANS Holiday Hack Quest 2015](https://adventuresincyberchallenges.blogspot.com/2016/01/holiday-hack-quest.html)
- 2015.12 [yifan] [CGEN for IDA Pro](http://yifan.lu/2015/12/29/cgen-for-ida-pro/)
- 2015.12 [pediy] [调试篇---安卓arm/x86平台之IDA or GDB长驱直入](https://bbs.pediy.com/thread-206654.htm)
- 2015.12 [hexacorn] [IDAPython – making strings decompiler-friendly](http://www.hexacorn.com/blog/2015/12/21/idapython-making-strings-decompiler-friendly/)
- 2015.12 [pediy] [[原创]IDA Pro 6.8 安装密码爆破的可行性分析](https://bbs.pediy.com/thread-206346.htm)
- 2015.11 [govolution] [Very first steps with IDA](https://govolution.wordpress.com/2015/11/06/very-first-steps-with-ida/)
- 2015.08 [pediy] [[原创]一步步搭建ida pro动态调试SO环境。](https://bbs.pediy.com/thread-203080.htm)
- 2015.07 [hexblog] [Hack of the day #0: Somewhat-automating pseudocode HTML generation, with IDAPython.](http://www.hexblog.com/?p=921)
- 2015.06 [msreverseengineering] [Transparent Deobfuscation with IDA Processor Module Extensions](http://www.msreverseengineering.com/blog/2015/6/29/transparent-deobfuscation-with-ida-processor-module-extensions)
- 2015.02 [pediy] [[原创]使用IDA PRO+OllyDbg+PEview 追踪windows API 动态链接库函数的调用过程。](https://bbs.pediy.com/thread-197829.htm)
- 2014.12 [hexblog] [Augmenting IDA UI with your own actions.](http://www.hexblog.com/?p=886)
- 2014.10 [vexillium] [SECURE 2014 slide deck and Hex-Rays IDA Pro advisories published](https://j00ru.vexillium.org/2014/10/secure-2014-slide-deck-and-hex-rays-ida-pro-advisories-published/)
- 2014.10 [pediy] [[原创]解决IDA的F5(hexray 1.5)不能用于FPU栈用满的情况](https://bbs.pediy.com/thread-193414.htm)
- 2014.08 [3xp10it] [ida插件使用备忘录](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/27/ida%E6%8F%92%E4%BB%B6%E4%BD%BF%E7%94%A8%E5%A4%87%E5%BF%98%E5%BD%95/)
- 2014.08 [3xp10it] [ida通过usb调试ios下的app](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/25/ida%E9%80%9A%E8%BF%87usb%E8%B0%83%E8%AF%95ios%E4%B8%8B%E7%9A%84app/)
- 2014.08 [3xp10it] [ida批量下断点追踪函数调用](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/12/21/ida%E6%89%B9%E9%87%8F%E4%B8%8B%E6%96%AD%E7%82%B9%E8%BF%BD%E8%B8%AA%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8/)
- 2014.08 [3xp10it] [ida插件使用备忘录](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/27/ida%E6%8F%92%E4%BB%B6%E4%BD%BF%E7%94%A8%E5%A4%87%E5%BF%98%E5%BD%95/)
- 2014.08 [3xp10it] [ida插件mynav](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/01/22/ida%E6%8F%92%E4%BB%B6mynav/)
- 2014.08 [3xp10it] [ida通过usb调试ios下的app](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/25/ida%E9%80%9A%E8%BF%87usb%E8%B0%83%E8%AF%95ios%E4%B8%8B%E7%9A%84app/)
- 2014.08 [3xp10it] [ida批量下断点追踪函数调用](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/12/21/ida%E6%89%B9%E9%87%8F%E4%B8%8B%E6%96%AD%E7%82%B9%E8%BF%BD%E8%B8%AA%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8/)
- 2014.07 [hexblog] [IDA Dalvik debugger: tips and tricks](http://www.hexblog.com/?p=809)
- 2014.04 [hexblog] [Extending IDAPython in IDA 6.5: Be careful about the GIL](http://www.hexblog.com/?p=788)
- 2014.03 [zdziarski] [The Importance of Forensic Tools Validation](https://www.zdziarski.com/blog/?p=3112)
- 2014.03 [evilsocket] [Programmatically Identifying and Isolating Functions Inside Executables Like IDA Does.](https://www.evilsocket.net/2014/03/11/programmatically-identifying-and-isolating-functions-inside-executables-like-ida-does/)
- 2014.02 [silentsignal] [From Read to Domain Admin – Abusing Symantec Backup Exec with Frida](https://blog.silentsignal.eu/2014/02/27/from-read-to-domain-admin-abusing-symantec-backup-exec-with-frida/)
- 2013.12 [hexblog] [Interacting with IDA through IPC channels](http://www.hexblog.com/?p=773)
- 2013.06 [trustwave] [Debugging Android Libraries using IDA](https://www.trustwave.com/Resources/SpiderLabs-Blog/Debugging-Android-Libraries-using-IDA/)
- 2013.05 [v0ids3curity] [Defeating anti-debugging techniques using IDA and x86 emulator plugin](https://www.voidsecurity.in/2013/05/defeating-anti-debugging-techniques.html)
- 2013.05 [hexblog] [Loading your own modules from your IDAPython scripts with idaapi.require()](http://www.hexblog.com/?p=749)
- 2013.04 [hexblog] [Installing PIP packages, and using them from IDA on a 64-bit machine](http://www.hexblog.com/?p=726)
- 2013.03 [pediy] [[原创]IDA Demo6.4破解笔记](https://bbs.pediy.com/thread-167109.htm)
- 2012.11 [redplait] [pyside for ida pro 6.3 - part 2](http://redplait.blogspot.com/2012/11/pyside-for-ida-pro-63-part-2.html)
- 2012.10 [redplait] [AVX/XOP instructions processor extender for IDA Pro](http://redplait.blogspot.com/2012/10/avxxop-instructions-processor-extender.html)
- 2012.10 [redplait] [IDA Pro 6.3 SDK is broken ?](http://redplait.blogspot.com/2012/10/ida-pro-63-sdk-is-broken.html)
- 2012.10 [redplait] [pyside for ida pro 6.3](http://redplait.blogspot.com/2012/10/pyside-for-ida-pro-63.html)
- 2012.09 [redplait] [IDA loader of .dcu files from XE3](http://redplait.blogspot.com/2012/09/ida-loader-of-dcu-files-from-xe3.html)
- 2012.08 [tencent] [浅谈IDA脚本在漏洞挖掘中的应用](https://security.tencent.com/index.php/blog/msg/4)
- 2012.07 [cr4] [VMware + GDB stub + IDA](http://blog.cr4.sh/2012/07/vmware-gdb-stub-ida.html)
- 2012.06 [pediy] [[原创]PRX loader for IDA](https://bbs.pediy.com/thread-152647.htm)
- 2012.06 [pediy] [[翻译]API Call Tracing - PEfile, PyDbg and IDAPython](https://bbs.pediy.com/thread-151870.htm)
- 2012.05 [redplait] [dcu files loader for ida pro v2](http://redplait.blogspot.com/2012/05/dcu-files-loader-for-ida-pro-v2.html)
- 2012.05 [redplait] [dcu files loader for ida pro](http://redplait.blogspot.com/2012/05/dcu-files-loader-for-ida-pro.html)
- 2012.03 [redplait] [updated perl binding for IDA Pro](http://redplait.blogspot.com/2012/03/updated-perl-binding-for-ida-pro.html)
- 2012.03 [pediy] [[原创]IDA批量模式](https://bbs.pediy.com/thread-147777.htm)
- 2012.02 [pediy] [[原创]IDA Android Remote Debug](https://bbs.pediy.com/thread-146721.htm)
- 2012.01 [pediy] [[原创]IDA 6.1 bool 及 默认对齐 sizeof 设置永久修复](https://bbs.pediy.com/thread-145188.htm)
- 2011.12 [redplait] [IDA 5.60 PICode analyzer plugin for win64](http://redplait.blogspot.com/2011/12/ida-560-picode-analyzer-plugin-for.html)
- 2011.10 [reverse] [How to create IDA C/C++ plugins with Xcode](https://reverse.put.as/2011/10/31/how-to-create-ida-cc-plugins-with-xcode/)
- 2011.10 [pediy] [[转帖]IDA PRO 6.1 远程调试 Android](https://bbs.pediy.com/thread-141739.htm)
- 2011.09 [pediy] [[推荐]IDA sp-analysis failed 不能F5的 解决方案之(一)](https://bbs.pediy.com/thread-140002.htm)
- 2011.08 [pediy] [[原创]用IDA Pro + OD 来分析扫雷](https://bbs.pediy.com/thread-138855.htm)
- 2011.08 [pediy] [[原创]IDA + GDBServer实现iPhone程序远程调试](https://bbs.pediy.com/thread-138472.htm)
- 2011.08 [redplait] [perl inside IDA Pro](http://redplait.blogspot.com/2011/08/perl-inside-ida-pro.html)
- 2011.07 [redplait] [несколько pdb в ida pro](http://redplait.blogspot.com/2011/07/pdb-ida-pro.html)
- 2011.07 [pediy] [[原创]IDA + Debug 插件 实现64Bit Exe脱壳](https://bbs.pediy.com/thread-137416.htm)
- 2011.06 [pediy] [[翻译]使用VMWare GDB和IDA调试Windows内核](https://bbs.pediy.com/thread-135229.htm)
- 2011.05 [pediy] [[分享]IDA 6.1 版本不能F5的解决办法](https://bbs.pediy.com/thread-134363.htm)
- 2011.05 [pediy] [[原创]IDAPython+OdbgScript动态获取程序执行流程](https://bbs.pediy.com/thread-134171.htm)
- 2011.03 [pediy] [[原创]Ida Pro Advanced 6.0 中木马分析](https://bbs.pediy.com/thread-131195.htm)
- 2011.03 [pediy] [[原创]IDA SDK合并jmp乱序插件代码示例阅读](https://bbs.pediy.com/thread-131016.htm)
- 2011.01 [hexblog] [IDA & Qt: Under the hood](http://www.hexblog.com/?p=250)
- 2010.12 [pediy] [[原创]ida 静态分析 破除时间限制](https://bbs.pediy.com/thread-126668.htm)
- 2010.10 [pediy] [[下载]IDA pro代码破解揭秘的随书例子下载](https://bbs.pediy.com/thread-123432.htm)
- 2010.10 [hexblog] [Calculating API hashes with IDA Pro](http://www.hexblog.com/?p=193)
- 2010.09 [publicintelligence] [(U//FOUO) FBI Warning: Extremists Likely to Retaliate Against Florida Group’s Planned “International Burn A Koran Day”](https://publicintelligence.net/ufouo-fbi-warning-extremists-likely-to-retaliate-against-florida-group%e2%80%99s-planned-%e2%80%9cinternational-burn-a-koran-day%e2%80%9d/)
- 2010.08 [mattoh] [Exporting IDA function for IDC Script Usage](https://mattoh.wordpress.com/2010/08/06/exporting-ida-function-for-idc-script-usage/)
- 2010.07 [hexblog] [Implementing command completion for IDAPython](http://www.hexblog.com/?p=129)
- 2010.07 [hexblog] [Running scripts from the command line with idascript](http://www.hexblog.com/?p=128)
- 2010.06 [hexblog] [Extending IDC and IDAPython](http://www.hexblog.com/?p=126)
- 2010.04 [hexblog] [Kernel debugging with IDA Pro / Windbg plugin and VirtualKd](http://www.hexblog.com/?p=123)
- 2010.03 [hexblog] [Using custom viewers from IDAPython](http://www.hexblog.com/?p=119)
- 2010.01 [hexblog] [Debugging ARM code snippets in IDA Pro 5.6 using QEMU emulator](http://www.hexblog.com/?p=111)
- 2009.12 [pediy] [[原创]Symbian_Remote_Debugger_With_IDA](https://bbs.pediy.com/thread-103934.htm)
- 2009.10 [pediy] [[原创]IDA学习笔记](https://bbs.pediy.com/thread-99560.htm)
- 2009.09 [hexblog] [Develop your master boot record and debug it with IDA Pro and the Bochs debugger plugin](http://www.hexblog.com/?p=103)
- 2009.02 [hexblog] [Advanced Windows Kernel Debugging with VMWare and IDA’s GDB debugger](http://www.hexblog.com/?p=94)
- 2008.10 [evilcodecave] [IDA Pro Enhances Hostile Code Analysis Support](https://evilcodecave.wordpress.com/2008/10/04/ida-pro-enhances-hostile-code-analysis-support/)
- 2008.09 [pediy] [[原创]ShellCode Locator for IDA 5.2](https://bbs.pediy.com/thread-72947.htm)
- 2008.08 [evilcodecave] [IDA Debugger Malformed SEH Causes Crash](https://evilcodecave.wordpress.com/2008/08/31/ida-debugger-malformed-seh-causes-crash/)
- 2008.04 [pediy] [[原创]idb_2_pat for ida pro V5.2](https://bbs.pediy.com/thread-62825.htm)
- 2007.08 [pediy] [[原创]基于 ida 的反汇编转换 Obj 的可行性 笔记(1)](https://bbs.pediy.com/thread-49910.htm)
- 2007.04 [pediy] [[翻译]Pinczakko的AwardBIOS逆向工程指导](https://bbs.pediy.com/thread-42166.htm)
- 2007.02 [pediy] [IDA Plugin 编写基础](https://bbs.pediy.com/thread-38900.htm)
- 2006.09 [pediy] [[翻译]Using IDA Pro's Debugger](https://bbs.pediy.com/thread-31667.htm)
- 2006.09 [pediy] [[翻译]Customizing IDA Pro](https://bbs.pediy.com/thread-31658.htm)
- 2006.08 [msreverseengineering] [Defeating HyperUnpackMe2 with an IDA Processor Module](http://www.msreverseengineering.com/blog/2014/8/5/defeating-hyperunpackme2-with-an-ida-processor-module)
- 2004.11 [pediy] [又说 IDA 边界修改插件](https://bbs.pediy.com/thread-7150.htm)


### <a id="a4bd25d3dc2f0be840e39674be67d66b"></a>Tips&&Tricks


- 2019.07 [kienbigmummy] [Cách export data trong IDA](https://medium.com/p/d4c8128704f)
- 2019.07 [hexacorn] [Batch decompilation with IDA / Hex-Rays Decompiler](http://www.hexacorn.com/blog/2019/07/04/batch-decompilation-with-ida-hex-rays-decompiler/)
- 2019.06 [openanalysis] [Disable ASLR for Easier Malware Debugging With x64dbg and IDA Pro](https://oalabs.openanalysis.net/2019/06/12/disable-aslr-for-easier-malware-debugging/)
- 2019.06 [OALabs] [Disable ASLR For Easier Malware Debugging With x64dbg and IDA Pro](https://www.youtube.com/watch?v=DGX7oZvdmT0)
- 2019.06 [openanalysis] [Reverse Engineering C++ Malware With IDA Pro: Classes, Constructors, and Structs](https://oalabs.openanalysis.net/2019/06/03/reverse-engineering-c-with-ida-pro-classes-constructors-and-structs/)
- 2019.06 [OALabs] [Reverse Engineering C++ Malware With IDA Pro](https://www.youtube.com/watch?v=o-FFGIloxvE)
- 2019.03 [aliyun] [IDA Pro7.0使用技巧总结](https://xz.aliyun.com/t/4205)
- 2018.06 [checkpoint] [Scriptable Remote Debugging with Windbg and IDA Pro](https://research.checkpoint.com/scriptable-remote-debugging-windbg-ida-pro/)
- 2015.07 [djmanilaice] [Pycharm for your IDA development](http://djmanilaice.blogspot.com/2015/07/pycharm-for-your-ida-development.html)
- 2015.07 [djmanilaice] [Auto open dlls and exe in current directory for IDA](http://djmanilaice.blogspot.com/2015/07/auto-open-dlls-and-exe-in-current.html)


### <a id="04cba8dbb72e95d9c721fe16a3b48783"></a>Series-Labeless Introduction


- 2018.10 [checkpoint] [Labeless Part 6: How to Resolve Obfuscated API Calls in the Ngioweb Proxy Malware - Check Point Research](https://research.checkpoint.com/labeless-part-6-how-to-resolve-obfuscated-api-calls-in-the-ngioweb-proxy-malware/)
- 2018.10 [checkpoint] [Labeless Part 5: How to Decrypt Strings in Boleto Banking Malware Without Reconstructing Decryption Algorithm. - Check Point Research](https://research.checkpoint.com/labeless-part-5-how-to-decrypt-strings-in-boleto-banking-malware-without-reconstructing-decryption-algorithm/)
- 2018.10 [checkpoint] [Labeless Part 4: Scripting - Check Point Research](https://research.checkpoint.com/labeless-part-4-scripting/)
- 2018.08 [checkpoint] [Labeless Part 3: How to Dump and Auto-Resolve WinAPI Calls in LockPos Point-of-Sale Malware - Check Point Research](https://research.checkpoint.com/19558-2/)
- 2018.08 [checkpoint] [Labeless Part 2: Installation - Check Point Research](https://research.checkpoint.com/installing-labeless/)
- 2018.08 [checkpoint] [Labeless Part 1: An Introduction - Check Point Research](https://research.checkpoint.com/labeless-an-introduction/)


### <a id="1a2e56040cfc42c11c5b4fa86978cc19"></a>Series-Reversing With IDA From Scrach


- 2019.11 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P25)](https://medium.com/p/304110bdf635)
- 2019.10 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P24)](https://medium.com/p/66451e50163e)
- 2019.10 [tradahacking] [REVERSING WITH IDA FROM SCRATCH (P23)](https://medium.com/p/a03897f960be)
- 2019.09 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P21)](https://medium.com/p/17ce2ee804af)
- 2019.08 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P20)](https://medium.com/p/adc2bad58cc3)
- 2019.08 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P19)](https://medium.com/p/b8a5ccc0efbc)
- 2019.07 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P18)](https://medium.com/p/b9b5987eea22)
- 2019.07 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P17)](https://medium.com/p/13aae3c33824)
- 2019.06 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P16)](https://medium.com/p/66c697636724)
- 2019.06 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P15)](https://medium.com/p/9bb2bbdf6fbc)
- 2019.05 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P14)](https://medium.com/p/fd20c144c844)
- 2019.05 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P13)](https://medium.com/p/adc88403c295)
- 2019.04 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P12)](https://medium.com/p/6b19df3db60e)
- 2019.04 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P11)](https://medium.com/p/34e6214132d6)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P10)](https://medium.com/p/f054072cc4cd)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P9)](https://medium.com/p/3ead456499d2)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P8)](https://medium.com/p/c627c70b5efd)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P7)](https://medium.com/p/986cb6c09405)
- 2019.03 [tradahacking] [REVERSING WITH IDA FROM SCRATCH (P6)](https://medium.com/p/ec232b87a091)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P5)](https://medium.com/p/f153835b4ffc)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P4)](https://medium.com/p/3a7e726e197b)
- 2019.02 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P3)](https://medium.com/p/181f78a4fac7)
- 2019.02 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P2)](https://medium.com/p/971d62a4c94a)
- 2019.02 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P1)](https://medium.com/p/a0360893d2d5)


### <a id="e838a1ecdcf3d068547dd0d7b5c446c6"></a>Series-Using IDAPython To Make Your Life Easier


#### <a id="7163f7c92c9443e17f3f76cc16c2d796"></a>Original


- 2016.06 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/unit42-using-idapython-to-make-your-life-easier-part-6/)
- 2016.01 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-5/)
- 2016.01 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-4/)
- 2016.01 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-3/)
- 2015.12 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-2/)
- 2015.12 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-1/)


#### <a id="fc62c644a450f3e977af313edd5ab124"></a>ZH


- 2016.01 [freebuf] [IDAPython：让你的生活更美好（五）](http://www.freebuf.com/articles/system/93440.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（四）](http://www.freebuf.com/articles/system/92505.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（三）](http://www.freebuf.com/articles/system/92488.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（二）](http://www.freebuf.com/sectool/92168.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（一）](http://www.freebuf.com/sectool/92107.html)




### <a id="8433dd5df40aaf302b179b1fda1d2863"></a>Series-Reversing C Code With IDA


- 2019.01 [ly0n] [Reversing C code with IDA part V](https://paumunoz.tech/2019/01/12/reversing-c-code-with-ida-part-v/)
- 2019.01 [ly0n] [Reversing C code with IDA part IV](https://paumunoz.tech/2019/01/07/reversing-c-code-with-ida-part-iv/)
- 2019.01 [ly0n] [Reversing C code with IDA part III](https://paumunoz.tech/2019/01/02/reversing-c-code-with-ida-part-iii/)
- 2018.12 [ly0n] [Reversing C code with IDA part II](https://paumunoz.tech/2018/12/31/reversing-c-code-with-ida-part-ii/)
- 2018.01 [ly0n] [Reversing C code with IDA part I](https://paumunoz.tech/2018/01/11/reversing-c-code-with-ida-part-i/)


### <a id="3d3bc775abd7f254ff9ff90d669017c9"></a>Tool&&Plugin&&Script


#### <a id="cd66794473ea90aa6241af01718c3a7d"></a>No Category


- 2019.10 [vmray] [VMRay IDA Plugin v1.1: Streamlining Deep-Dive Malware Analysis](https://www.vmray.com/cyber-security-blog/vmray-ida-plugin-v1-1-streamlining-deep-dive-malware-analysis/)
- 2019.10 [talosintelligence] [New IDA Pro plugin provides TileGX support](https://blog.talosintelligence.com/2019/10/new-ida-pro-plugin-provides-tilegx.html)
- 2019.09 [talosintelligence] [GhIDA: Ghidra decompiler for IDA Pro](https://blog.talosintelligence.com/2019/09/ghida.html)
- 2019.05 [carbonblack] [fn_fuzzy: Fast Multiple Binary Diffing Triage with IDA](https://www.carbonblack.com/2019/05/09/fn_fuzzy-fast-multiple-binary-diffing-triage-with-ida/)
- 2019.04 [] [climacros – IDA productivity tool](http://0xeb.net/2019/04/climacros-ida-productivity-tool/)
- 2019.04 [] [QScripts – IDA Scripting productivity tool](http://0xeb.net/2019/04/ida-qscripts/)
- 2019.03 [] [Daenerys: IDA Pro and Ghidra interoperability framework](http://0xeb.net/2019/03/daenerys-ida-pro-and-ghidra-interoperability-framework/)
- 2019.03 [freebuf] [Ponce：一键即可实现符号执行（IDA插件）](https://www.freebuf.com/sectool/197708.html)
- 2019.01 [talosintelligence] [Dynamic Data Resolver (DDR) - IDA Plugin](https://blog.talosintelligence.com/2019/01/ddr.html)
- 2018.11 [4hou] [FLARE脚本系列：使用idawasm IDA Pro插件逆向WebAssembly（Wasm）模块](http://www.4hou.com/reverse/13935.html)
- 2018.10 [aliyun] [用idawasm IDA Pro逆向WebAssembly模块](https://xz.aliyun.com/t/2854)
- 2018.10 [fireeye] [FLARE Script Series: Reverse Engineering WebAssembly Modules Using the
idawasm IDA Pro Plugin](https://www.fireeye.com/blog/threat-research/2018/10/reverse-engineering-webassembly-modules-using-the-idawasm-ida-pro-plugin.html)
- 2018.10 [vmray] [Introducing the IDA Plugin for VMRay Analyzer](https://www.vmray.com/cyber-security-blog/ida-plugin-vmray-analyzer/)
- 2018.10 [aliyun] [IDA-minsc在Hex-Rays插件大赛中获得第二名（2）](https://xz.aliyun.com/t/2842)
- 2018.10 [aliyun] [IDA-minsc在Hex-Rays插件大赛中获得第二名（1）](https://xz.aliyun.com/t/2841)
- 2018.10 [aliyun] [通过两个IDAPython插件支持A12 PAC指令和iOS12 kernelcache 重定位](https://xz.aliyun.com/t/2839)
- 2018.09 [ptsecurity] [How we developed the NIOS II processor module for IDA Pro](http://blog.ptsecurity.com/2018/09/how-we-developed-nios-ii-processor.html)
- 2018.09 [talosintelligence] [IDA-minsc Wins Second Place in Hex-Rays Plugins Contest](https://blog.talosintelligence.com/2018/09/ida-minsc.html)
- 2018.09 [cisco] [IDA-minsc Wins Second Place in Hex-Rays Plugins Contest](https://blogs.cisco.com/security/talos/ida-minsc-wins-second-place-in-hex-rays-plugins-contest)
- 2018.09 [msreverseengineering] [Weekend Project: A Custom IDA Loader Module for the Hidden Bee Malware Family](http://www.msreverseengineering.com/blog/2018/9/2/weekend-project-a-custom-ida-loader-module-for-the-hidden-bee-malware-family)
- 2018.06 [dougallj] [Writing a Hex-Rays Plugin: VMX Intrinsics](https://dougallj.wordpress.com/2018/06/04/writing-a-hex-rays-plugin-vmx-intrinsics/)
- 2018.05 [hexblog] [IDAPython: wrappers are only wrappers](http://www.hexblog.com/?p=1219)
- 2018.05 [freebuf] [HeapViewer：一款专注于漏洞利用开发的IDA Pro插件](http://www.freebuf.com/sectool/171632.html)
- 2018.03 [pediy] [[翻译]使用 IDAPython 写一个简单的x86模拟器](https://bbs.pediy.com/thread-225091.htm)
- 2018.03 [] [Using Z3 with IDA to simplify arithmetic operations in functions](http://0xeb.net/2018/03/using-z3-with-ida-to-simplify-arithmetic-operations-in-functions/)
- 2018.02 [] [Writing a simple x86 emulator with IDAPython](http://0xeb.net/2018/02/writing-a-simple-x86-emulator-with-idapython/)
- 2018.01 [fireeye] [FLARE IDA Pro Script Series: Simplifying Graphs in IDA](https://www.fireeye.com/blog/threat-research/2018/01/simplifying-graphs-in-ida.html)
- 2017.12 [ret2] [What's New in Lighthouse v0.7](http://blog.ret2.io/2017/12/07/lighthouse-v0.7/)
- 2017.12 [OALabs] [Using Yara Rules With IDA Pro - New Tool!](https://www.youtube.com/watch?v=zAKi9KWYyfM)
- 2017.11 [hasherezade] [IFL - Interactive Functions List - a plugin for IDA Pro](https://www.youtube.com/watch?v=L6sROW_MivE)
- 2017.06 [reverse] [EFI Swiss Knife – An IDA plugin to improve (U)EFI reversing](https://reverse.put.as/2017/06/13/efi-swiss-knife-an-ida-plugin-to-improve-uefi-reversing/)
- 2017.04 [redplait] [etwex - ida plugin for Etw traces IIDs searching](http://redplait.blogspot.com/2017/04/etwex-ida-plugin-for-etw-traces-iids.html)
- 2017.04 [360] [IDAPython：一个可以解放双手的 IDA 插件](https://www.anquanke.com/post/id/85890/)
- 2017.03 [duksctf] [Make IDA Pro Great Again](http://duksctf.github.io/2017/03/15/Make-IDA-Pro-Great-Again.html)
- 2017.03 [redplait] [ida plugin for RFG fixups processing](http://redplait.blogspot.com/2017/03/ida-plugin-for-rfg-fixups-processing.html)
- 2017.02 [argus] [Collaborative Reverse Engineering with PSIDA - Argus Cyber Security](https://argus-sec.com/collaborative-reverse-engineering-psida/)
- 2016.01 [eugenekolo] [A walk through the binary with IDA](https://eugenekolo.com/blog/a-walk-through-the-binary-with-ida/)
- 2015.12 [360] [适用于IDA Pro的CGEN框架](https://www.anquanke.com/post/id/83210/)
- 2015.12 [freebuf] [FLARE IDA Pro的脚本系列：自动化提取函数参数](http://www.freebuf.com/sectool/89273.html)
- 2015.04 [nul] [VMProtect + IDA Pro　做一回强悍的加密](http://www.nul.pw/2015/04/29/86.html)
- 2015.03 [joxeankoret] [Diaphora, a program diffing plugin for IDA Pro](http://joxeankoret.com/blog/2015/03/13/diaphora-a-program-diffing-plugin-for-ida-pro/)
- 2014.10 [devttys0] [A Code Signature Plugin for IDA](http://www.devttys0.com/2014/10/a-code-signature-plugin-for-ida/)
- 2014.09 [freebuf] [火眼（FireEye）实验室FLARE IDA Pro脚本系列：MSDN注释插件](http://www.freebuf.com/sectool/43334.html)
- 2014.08 [3xp10it] [ida插件mynav](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/01/22/ida%E6%8F%92%E4%BB%B6mynav/)
- 2014.05 [oct0xor] [Deci3dbg - Ida Pro Debugger Module for Playstation 3](http://oct0xor.github.io/2014/05/30/deci3dbg/)
- 2013.11 [quarkslab] [IDA processor module](https://blog.quarkslab.com/ida-processor-module.html)
- 2013.06 [redplait] [IDA loader of .dcu files from XE4](http://redplait.blogspot.com/2013/06/ida-loader-of-dcu-files-from-xe4.html)
- 2012.07 [reverse] [ExtractMachO: an IDA plugin to extract Mach-O binaries from disassembly](https://reverse.put.as/2012/07/30/extractmacho-an-ida-plugin-to-extract-mach-o-binaries-from-disassembly/)
- 2011.11 [reverse] [Display Mach-O headers plugin for IDA](https://reverse.put.as/2011/11/03/display-mach-o-headers-plugin-for-ida/)
- 2011.04 [hexblog] [VirusTotal plugin for IDA Pro](http://www.hexblog.com/?p=324)
- 2010.05 [joxeankoret] [MyNav, a python plugin for IDA Pro](http://joxeankoret.com/blog/2010/05/02/mynav-a-python-plugin-for-ida-pro/)


#### <a id="43a4761e949187bf737e378819752c3b"></a>Loader&&Processor


- 2019.03 [360] [为CHIP-8编写IDA processor module](https://www.anquanke.com/post/id/172217/)
- 2018.10 [ptsecurity] [Modernizing IDA Pro: how to make processor module glitches go away](http://blog.ptsecurity.com/2018/10/modernizing-ida-pro-how-to-make.html)
- 2018.08 [360] [Lua程序逆向之为Luac编写IDA Pro处理器模块](https://www.anquanke.com/post/id/153699/)


#### <a id="c7483f3b20296ac68084a8c866230e15"></a>With Other Tools


- 2018.09 [dustri] [IDAPython vs. r2pipe](https://dustri.org/b/idapython-vs-r2pipe.html)




### <a id="ea11818602eb33e8b165eb18d3710965"></a>Translate-The IDA Pro Book


- 2008.10 [pediy] [[翻译]The IDA Pro Book 第六章](https://bbs.pediy.com/thread-75632.htm)
- 2008.10 [pediy] [[翻译]（20081030更新）The IDA Pro Book 第12章：使用FLIRT签名识别库](https://bbs.pediy.com/thread-75422.htm)
- 2008.10 [pediy] [[翻译]The IDA Pro Book(第二章)](https://bbs.pediy.com/thread-74943.htm)
- 2008.10 [pediy] [[翻译]The IDA Pro book 第5章---IDA DATA DISPLAY](https://bbs.pediy.com/thread-74838.htm)
- 2008.10 [pediy] [[翻译]The IDA Pro Book(第一章)](https://bbs.pediy.com/thread-74564.htm)


### <a id="ec5f7b9ed06500c537aa25851a3f2d3a"></a>Translate-Reverse Engineering Code With IDA Pro


- 2009.01 [pediy] [[原创]Reverse Engineering Code with IDA Pro第七章中文译稿](https://bbs.pediy.com/thread-80580.htm)
- 2008.06 [pediy] [[翻译]Reverse Engineering Code with IDA Pro(第一、二章)](https://bbs.pediy.com/thread-66010.htm)


### <a id="2120fe5420607a363ae87f5d2fed459f"></a>IDASelf


- 2019.01 [pediy] [[原创]IDA7.2安装包分析](https://bbs.pediy.com/thread-248989.htm)
- 2019.01 [pediy] [[原创]IDA 在解析 IA64 中的 brl 指令时存在一个 Bug](https://bbs.pediy.com/thread-248983.htm)
- 2018.11 [hexblog] [IDA 7.2 – The Mac Rundown](http://www.hexblog.com/?p=1300)
- 2018.10 [pediy] [[原创] 修复 IDA Pro 7.0在macOS Mojave崩溃的问题](https://bbs.pediy.com/thread-247334.htm)


### <a id="d8e48eb05d72db3ac1e050d8ebc546e1"></a>REPractice


#### <a id="374c6336120363a5c9d9a27d7d669bf3"></a>No Category


- 2019.11 [4hou] [反作弊游戏如何破解，看看《黑色沙漠》逆向分析过程：使用 IDAPython 和 FLIRT 签名恢复 IAT](https://www.4hou.com/web/21806.html)
- 2019.11 [aliyun] [使用IDA microcode去除ollvm混淆(下)](https://xz.aliyun.com/t/6795)
- 2019.06 [devco] [破密行動: 以不尋常的角度破解 IDA Pro 偽隨機數](https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way/)
- 2019.05 [360] [IDAPython实战项目——DES算法识别](https://www.anquanke.com/post/id/177808/)
- 2019.04 [venus] [使用 IDA Pro 的 REobjc 模块逆向 Objective-C 二进制文件](https://paper.seebug.org/887/)
- 2019.01 [ly0n] [Cracking with IDA (redh@wk 2.5 crackme)](https://paumunoz.tech/2019/01/05/cracking-with-ida-redhwk-2-5-crackme/)
- 2018.11 [somersetrecon] [Introduction to IDAPython for Vulnerability Hunting - Part 2](http://www.somersetrecon.com/blog/2018/8/2/idapython-part-2)
- 2018.11 [pediy] [[原创]IDA动态调试ELF](https://bbs.pediy.com/thread-247830.htm)
- 2018.06 [pediy] [[翻译]在IDA中使用Python Z3库来简化函数中的算术运算](https://bbs.pediy.com/thread-228688.htm)
- 2018.03 [duo] [Reversing Objective-C Binaries With the REobjc Module for IDA Pro](https://duo.com/blog/reversing-objective-c-binaries-with-the-reobjc-module-for-ida-pro)
- 2006.05 [pediy] [Themida v1008 驱动程序分析,去除花指令的 IDA 文件](https://bbs.pediy.com/thread-25836.htm)


#### <a id="0b3e1936ad7c4ccc10642e994c653159"></a>Malware


- 2019.04 [360] [两种姿势批量解密恶意驱动中的上百条字串](https://www.anquanke.com/post/id/175964/)
- 2019.03 [cyber] [Using IDA Python to analyze Trickbot](https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/)
- 2019.01 [OALabs] [Lazy String Decryption Tips With IDA PRO and Shade Ransomware Unpacked!](https://www.youtube.com/watch?v=RfnuMhosxuQ)
- 2018.09 [4hou] [Hidden Bee恶意软件家族的定制IDA装载模块开发](http://www.4hou.com/technology/13438.html)
- 2018.09 [4hou] [用IDAPython解密Gootkit中的字符串](http://www.4hou.com/technology/13209.html)
- 2018.05 [OALabs] [Unpacking Gootkit Part 2 - Debugging Anti-Analysis Tricks With IDA Pro and x64dbg](https://www.youtube.com/watch?v=QgUlPvEE4aw)
- 2018.04 [OALabs] [Unpacking VB6 Packers With IDA Pro and API Hooks (Re-Upload)](https://www.youtube.com/watch?v=ylWInOcQy2s)
- 2018.03 [OALabs] [Unpacking Gootkit Malware With IDA Pro and X64dbg - Subscriber Request](https://www.youtube.com/watch?v=242Tn0IL2jE)
- 2018.01 [OALabs] [Unpacking Pykspa Malware With Python and IDA Pro - Subscriber Request Part 1](https://www.youtube.com/watch?v=HfSQlC76_s4)
- 2017.11 [OALabs] [Unpacking Process Injection Malware With IDA PRO (Part 2)](https://www.youtube.com/watch?v=kdNQhfgoQoU)
- 2017.11 [OALabs] [Unpacking Process Injection Malware With IDA PRO (Part 1)](https://www.youtube.com/watch?v=ScBB-Hi7NxQ)
- 2017.06 [hackers] [Reverse Engineering Malware, Part 3:  IDA Pro Introduction](https://www.hackers-arise.com/single-post/2017/06/22/Reverse-Engineering-Malware-Part-3-IDA-Pro-Introduction)
- 2017.05 [4hou] [逆向分析——使用IDA动态调试WanaCrypt0r中的tasksche.exe](http://www.4hou.com/technology/4832.html)
- 2017.05 [3gstudent] [逆向分析——使用IDA动态调试WanaCrypt0r中的tasksche.exe](https://3gstudent.github.io/3gstudent.github.io/%E9%80%86%E5%90%91%E5%88%86%E6%9E%90-%E4%BD%BF%E7%94%A8IDA%E5%8A%A8%E6%80%81%E8%B0%83%E8%AF%95WanaCrypt0r%E4%B8%AD%E7%9A%84tasksche.exe/)
- 2012.06 [trustwave] [Defeating Flame String Obfuscation with IDAPython](https://www.trustwave.com/Resources/SpiderLabs-Blog/Defeating-Flame-String-Obfuscation-with-IDAPython/)


#### <a id="03465020d4140590326ae12c9601ecfd"></a>Vuln Analysis&&Vuln Hunting


- 2018.07 [360] [如何使用 IDAPython 寻找漏洞](https://www.anquanke.com/post/id/151898/)
- 2018.07 [somersetrecon] [Introduction to IDAPython for Vulnerability Hunting](http://www.somersetrecon.com/blog/2018/7/6/introduction-to-idapython-for-vulnerability-hunting)




### <a id="e9ce398c2c43170e69c95fe9ad8d22fc"></a>Microcode


- 2019.10 [amossys] [Exploring Hex-Rays microcode](https://blog.amossys.fr/stage-2019-hexraysmicrocode.html)


### <a id="9c0ec56f402a2b9938417f6ecbaeaa72"></a>AgainstIDA


- 2019.05 [aliyun] [混淆IDA F5的一个小技巧-x86](https://xz.aliyun.com/t/5062)




# <a id="319821036a3319d3ade5805f384d3165"></a>Ghidra


***


## <a id="fa45b20f6f043af1549b92f7c46c9719"></a>Plugins&&Scripts


### <a id="2ae406afda6602c8f02d73678b2ff040"></a>Ghidra


- [**18649**Star][10d] [Java] [nationalsecurityagency/ghidra](https://github.com/nationalsecurityagency/ghidra) Ghidra is a software reverse engineering (SRE) framework
- [**59**Star][9m] [nationalsecurityagency/ghidra-data](https://github.com/nationalsecurityagency/ghidra-data) a companion repository to the Ghidra source code repository, as a place to put data sets that improve Ghidra
- [**49**Star][2m] [Shell] [bkerler/ghidra_installer](https://github.com/bkerler/ghidra_installer) Helper scripts to set up OpenJDK 11 and scale Ghidra for 4K on Ubuntu 18.04 / 18.10
- [**27**Star][3m] [Dockerfile] [dukebarman/ghidra-builder](https://github.com/dukebarman/ghidra-builder) Docker image for building ghidra RE framework from source


### <a id="ce70b8d45be0a3d29705763564623aca"></a>Recent Add


- [**455**Star][9m] [YARA] [ghidraninja/ghidra_scripts](https://github.com/ghidraninja/ghidra_scripts) Scripts for the Ghidra software reverse engineering suite.
    - [binwalk](https://github.com/ghidraninja/ghidra_scripts/blob/master/binwalk.py) Runs binwalk on the current program and bookmarks the findings
    - [yara](https://github.com/ghidraninja/ghidra_scripts/blob/master/yara.py) Automatically find crypto constants in the loaded program - allows to very quickly identify crypto code.
    - [swift_demangler](https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py) Automatically demangle swift function names
    - [golang_renamer](https://github.com/ghidraninja/ghidra_scripts/blob/master/golang_renamer.py) Restores function names from a stripped Go binary
- [**204**Star][8m] [Java] [rolfrolles/ghidrapal](https://github.com/rolfrolles/ghidrapal) Ghidra Program Analysis Library(No Doc)
- [**83**Star][16d] [allsafecybersecurity/awesome-ghidra](https://github.com/allsafecybersecurity/awesome-ghidra) A curated list of awesome Ghidra materials
- [**53**Star][9m] [aldelaro5/ghidra-gekko-broadway-lang](https://github.com/aldelaro5/ghidra-gekko-broadway-lang) Ghidra language definition for the Gekko and Broadway CPU variant used in the Nintendo GameCube and Nintendo Wii respectively
- [**51**Star][2m] [Makefile] [blacktop/docker-ghidra](https://github.com/blacktop/docker-ghidra) Ghidra Client/Server Docker Image
- [**36**Star][2m] [Java] [ayrx/jnianalyzer](https://github.com/ayrx/jnianalyzer) Analysis scripts for Ghidra to work with Android NDK libraries.
- [**34**Star][2m] [Py] [pagalaxylab/ghidra_scripts](https://github.com/pagalaxylab/ghidra_scripts) Scripts for the Ghidra.
    - [AnalyzeOCMsgSend](https://github.com/pagalaxylab/ghidra_scripts/blob/master/AnalyzeOCMsgSend.py) 
    - [trace_function_call_parm_value](https://github.com/pagalaxylab/ghidra_scripts/blob/master/trace_function_call_parm_value.py) 
- [**19**Star][9m] [Java] [kant2002/ghidra](https://github.com/kant2002/ghidra) As it is obvious from the name this is version of NSA Ghidra which actually could be built from sources
- [**18**Star][2m] [Java] [threatrack/ghidra-patchdiff-correlator](https://github.com/threatrack/ghidra-patchdiff-correlator) This project tries to provide additional Ghidra Version Tracking Correlators suitable for patch diffing.
- [**16**Star][5m] [hedgeberg/rl78_sleigh](https://github.com/hedgeberg/rl78_sleigh) An implementation of the RL78 ISA for Ghidra SRE
- [**12**Star][3m] [Java] [threatrack/ghidra-fid-generator](https://github.com/threatrack/ghidra-fid-generator) Code for generating Ghidra FidDb files (currently only for static libraries available in the CentOS repositories)
- [**5**Star][8m] [Py] [0xd0cf11e/ghidra](https://github.com/0xd0cf11e/ghidra) Anything related to Ghidra


### <a id="69dc4207618a2977fe8cd919e7903fa5"></a>Specific Target


#### <a id="da5d2b05da13f8e65aa26d6a1c95a8d0"></a>No Category


- [**123**Star][11d] [Java] [al3xtjames/ghidra-firmware-utils](https://github.com/al3xtjames/ghidra-firmware-utils) Ghidra utilities for analyzing PC firmware
- [**108**Star][1m] [Java] [astrelsky/ghidra-cpp-class-analyzer](https://github.com/astrelsky/ghidra-cpp-class-analyzer) Ghidra C++ Class and Run Time Type Information Analyzer
- [**94**Star][7m] [Java] [felberj/gotools](https://github.com/felberj/gotools) Plugin for Ghidra to assist reversing Golang binaries
- [**42**Star][2m] [Py] [kc0bfv/pcode-emulator](https://github.com/kc0bfv/pcode-emulator) A PCode Emulator for Ghidra.


#### <a id="058bb9893323f337ad1773725d61f689"></a>Loader&&Processor


- [**90**Star][3m] [Java] [adubbz/ghidra-switch-loader](https://github.com/adubbz/ghidra-switch-loader) Nintendo Switch loader for Ghidra
- [**79**Star][2m] [Py] [leveldown-security/svd-loader-ghidra](https://github.com/leveldown-security/svd-loader-ghidra) 
- [**65**Star][24d] [Java] [beardypig/ghidra-emotionengine](https://github.com/beardypig/ghidra-emotionengine) Ghidra Processor for the Play Station 2's Emotion Engine MIPS based CPU
- [**56**Star][5m] [Assembly] [xyzz/ghidra-mep](https://github.com/xyzz/ghidra-mep) Toshiba MeP processor module for GHIDRA
- [**54**Star][1m] [Java] [cuyler36/ghidra-gamecube-loader](https://github.com/cuyler36/ghidra-gamecube-loader) A Nintendo GameCube binary loader for Ghidra
- [**53**Star][10m] [Java] [jogolden/ghidraps4loader](https://github.com/jogolden/ghidraps4loader) A Ghidra loader for PlayStation 4 binaries.
- [**44**Star][3m] [Java] [nalen98/ebpf-for-ghidra](https://github.com/nalen98/ebpf-for-ghidra) eBPF Processor for Ghidra
- [**34**Star][6m] [Java] [idl3r/ghidravmlinuxloader](https://github.com/idl3r/ghidravmlinuxloader) 
- [**32**Star][9d] [Java] [zerokilo/n64loaderwv](https://github.com/zerokilo/n64loaderwv) Ghidra Loader Module for N64 ROMs
- [**30**Star][5m] [cturt/gameboy_ghidrasleigh](https://github.com/cturt/gameboy_ghidrasleigh) Ghidra Processor support for Nintendo Game Boy
- [**28**Star][9d] [Java] [zerokilo/xexloaderwv](https://github.com/zerokilo/xexloaderwv) Ghidra Loader Module for X360 XEX Files
- [**27**Star][2m] [vgkintsugi/ghidra-segasaturn-processor](https://github.com/vgkintsugi/ghidra-segasaturn-processor) A Ghidra processor module for the Sega Saturn (SuperH SH-2)
- [**25**Star][9m] [Assembly] [thog/ghidra_falcon](https://github.com/thog/ghidra_falcon) Support of Nvidia Falcon processors for Ghidra (WIP)
- [**19**Star][7m] [guedou/ghidra-processor-mep](https://github.com/guedou/ghidra-processor-mep) Toshiba MeP-c4 for Ghidra
- [**15**Star][2m] [Java] [neatmonster/mclf-ghidra-loader](https://github.com/neatmonster/mclf-ghidra-loader) Ghidra loader module for the Mobicore trustlet and driver binaries
- [**7**Star][4m] [Java] [ballon-rouge/rx-proc-ghidra](https://github.com/ballon-rouge/rx-proc-ghidra) Renesas RX processor module for Ghidra
- [**5**Star][6m] [CSS] [lcq2/griscv](https://github.com/lcq2/griscv) RISC-V processor plugin for Ghidra
- [**5**Star][9d] [Java] [zerokilo/c64loaderwv](https://github.com/zerokilo/c64loaderwv) Ghidra Loader Module for C64 programs


#### <a id="51a2c42c6d339be24badf52acb995455"></a>Xbox


- [**24**Star][9m] [Java] [jonas-schievink/ghidraxbe](https://github.com/jonas-schievink/ghidraxbe) A Ghidra extension for loading Xbox Executables (.xbe files)
- [**18**Star][10m] [Java] [jayfoxrox/ghidra-xbox-extensions](https://github.com/jayfoxrox/ghidra-xbox-extensions) Tools to analyze original Xbox files in the Ghidra SRE framework




### <a id="99e3b02da53f1dbe59e0e277ef894687"></a>With Other Tools


#### <a id="5923db547e1f04f708272543021701d2"></a>No Category




#### <a id="e1cc732d1388084530b066c26e24887b"></a>Radare2


- [**175**Star][14d] [C++] [radareorg/r2ghidra-dec](https://github.com/radareorg/r2ghidra-dec) Deep ghidra decompiler integration for radare2
    - Also In Section: [Radare2->Plugins->With Other Tools->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**36**Star][5m] [Java] [radare/ghidra-r2web](https://github.com/radare/ghidra-r2web) Ghidra plugin to start an r2 webserver to let r2 interact with it


#### <a id="d832a81018c188bf585fcefa3ae23062"></a>IDA


- [**299**Star][4m] [Py] [cisco-talos/ghida](https://github.com/cisco-talos/ghida) an IDA Pro plugin that integrates the Ghidra decompiler in IDA.
    - Also In Section: [IDA->Tools->Import Export->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |
- [**238**Star][9m] [Py] [daenerys-sre/source](https://github.com/daenerys-sre/source)  A framework for interoperability between IDA and Ghidra
    - Also In Section: [IDA->Tools->Import Export->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |
- [**88**Star][4m] [Py] [cisco-talos/ghidraaas](https://github.com/cisco-talos/ghidraaas) a simple web server that exposes Ghidra analysis through REST APIs
    - Also In Section: [IDA->Tools->Import Export->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |
- [**54**Star][9m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - Also In Section: [IDA->Tools->Import Export->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[IDA->Tools->Signature(FLIRT...)->FLIRT->FLIRT Signature Generate](#a9a63d23d32c6c789ca4d2e146c9b6d0) |
- [**47**Star][2m] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
    - Also In Section: [IDA->Tools->Import Export->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[x64dbg->Plugins->Recent Add](#da5688c7823802e734c39b539aa39df7) |


#### <a id="60e86981b2c98f727587e7de927e0519"></a>DBI


- [**102**Star][4m] [Java] [0ffffffffh/dragondance](https://github.com/0ffffffffh/dragondance) Binary code coverage visualizer plugin for Ghidra
    - Also In Section: [DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |
    - [Ghidra插件](https://github.com/0ffffffffh/dragondance/blob/master/README.md) 
    - [coverage-pin](https://github.com/0ffffffffh/dragondance/blob/master/coveragetools/README.md) 使用Pin收集信息


#### <a id="e81053b03a859e8ac72f7fe79e80341a"></a>Debugger


- [**42**Star][2m] [Java] [revolver-ocelot-saa/ghidrax64dbg](https://github.com/revolver-ocelot-saa/ghidrax64dbg) Extract annoations from Ghidra into an X32/X64 dbg database
    - Also In Section: [x64dbg->Plugins->Recent Add](#da5688c7823802e734c39b539aa39df7) |




### <a id="cccbd06c6b9b03152d07a4072152ae27"></a>Skin&&Theme


- [**78**Star][10m] [Py] [elliiot/ghidra_darknight](https://github.com/elliiot/ghidra_darknight) DarkNight theme for Ghidra


### <a id="45910c8ea12447df9cdde2bea425f23f"></a>Script Writting


#### <a id="c12ccb8e11ba94184f8f24767eb64212"></a>Other


- [**40**Star][27d] [Py] [vdoo-connected-trust/ghidra-pyi-generator](https://github.com/vdoo-connected-trust/ghidra-pyi-generator) Generates `.pyi` type stubs for the entire Ghidra API


#### <a id="b24e162720cffd2d2456488571c1a136"></a>Lang


- [**19**Star][5m] [Java] [edmcman/ghidra-scala-loader](https://github.com/edmcman/ghidra-scala-loader) An extension to load Ghidra scripts written in Scala






***


## <a id="273df546f1145fbed92bb554a327b87a"></a>Post&&Videos


### <a id="8962bde3fbfb1d1130879684bdf3eed0"></a>RecentAdd1


- 2019.12 [shogunlab] [Here Be Dragons: Reverse Engineering with Ghidra - Part 1 [Data, Functions & Scripts]](https://www.shogunlab.com/blog/2019/12/22/here-be-dragons-ghidra-1.html)
- 2019.11 [freebuf] [使用Ghidra分析phpStudy后门](https://www.freebuf.com/sectool/217560.html)
- 2019.10 [4hou] [使用 Ghidra 分析 phpStudy 后门](https://www.4hou.com/technology/21097.html)
- 2019.10 [knownsec] [使用 Ghidra 分析 phpStudy 后门](https://blog.knownsec.com/2019/10/%e4%bd%bf%e7%94%a8-ghidra-%e5%88%86%e6%9e%90-phpstudy-%e5%90%8e%e9%97%a8/)
- 2019.10 [venus] [使用 Ghidra 分析 phpStudy 后门](https://paper.seebug.org/1058/)
- 2019.10 [WarrantyVoider] [C64LoaderWV - Loading C64 programs into Ghidra](https://www.youtube.com/watch?v=thl6VciaUzg)
- 2019.08 [pentestpartners] [CVE-2019-12103 – Analysis of a Pre-Auth RCE on the TP-Link M7350, with Ghidra!](https://www.pentestpartners.com/security-blog/cve-2019-12103-analysis-of-a-pre-auth-rce-on-the-tp-link-m7350-with-ghidra/)
- 2019.08 [xpnsec] [Analysing RPC With Ghidra and Neo4j](https://blog.xpnsec.com/analysing-rpc-with-ghidra-neo4j/)
- 2019.04 [X0x6d696368] [ghidra_scripts: GoogleSearch.py (to lookup function names via Google)](https://www.youtube.com/watch?v=BMmNg35Cjqo)
- 2019.04 [X0x6d696368] [ghidra_scripts: SimpleStackStrings.py (to reassemble "stack strings")](https://www.youtube.com/watch?v=K_2khlMATew)
- 2019.04 [X0x6d696368] [ghidra_scripts: colorCallGraphCallsTo.py (using SetBackroundColor and traversing the call graph)](https://www.youtube.com/watch?v=SHNO1ZrIQB8)
- 2019.04 [4hou] [利用GHIDRA逆向Tytera MD380的固件](https://www.4hou.com/reverse/17464.html)
- 2019.04 [jeanmichel] [First steps with Ghidra: crackme01](https://medium.com/p/319827a2e80b)
- 2019.03 [GynvaelEN] [Hacking Livestream #74: Ghidra](https://www.youtube.com/watch?v=tXxiuHzjm34)
- 2019.01 [sans] [How to Train Your Dragon:  Ghidra Basics](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1574103618.pdf)


### <a id="ce49901b4914f3688ef54585c8f9df1a"></a>Recent Add


- 2019.09 [dustri] [Radare2, IDA Pro, and Binary ninja, a metaphoric comparison](https://dustri.org/b/radare2-ida-pro-and-binary-ninja-a-metaphoric-comparison.html)
- 2019.05 [vimeo] [Three Heads are Better Than One: Mastering Ghidra - Alexei Bulazel, Jeremy Blackthorne - INFILTRATE 2019](https://vimeo.com/335158460)
- 2019.04 [X0x6d696368] [Ghidra: Stack Depth (to detect stack manipulation)](https://www.youtube.com/watch?v=hP9FQrD61tk)
- 2019.04 [X0x6d696368] [Ghidra: Version Tracking](https://www.youtube.com/watch?v=K83T7iVla5s)
- 2019.04 [X0x6d696368] [Ghidra: Export Symbols and Load External Libraries (to resolve imported function names)](https://www.youtube.com/watch?v=Avn8s7iW3Rc)
- 2019.04 [X0x6d696368] [Ghidra: Data Type Manager / Archives and Parse C Source... (resolve function signatures)](https://www.youtube.com/watch?v=u15-r5Erfnw)
- 2019.04 [X0x6d696368] [Ghidra: Generate Checksum... (to extract hashes of embedded malware artifacts)](https://www.youtube.com/watch?v=vLG7c5Eae0s)
- 2019.04 [msreverseengineering] [An Abstract Interpretation-Based Deobfuscation Plugin for Ghidra](https://www.msreverseengineering.com/blog/2019/4/17/an-abstract-interpretation-based-deobfuscation-plugin-for-ghidra)
- 2019.04 [X0x6d696368] [Ghidra: FunctionID (to identify libraries and code reuse)](https://www.youtube.com/watch?v=P8Ul2K7pEfU)
- 2019.04 [X0x6d696368] [Ghidra: Server / Shared Projects (using ghidra-server.org)](https://www.youtube.com/watch?v=ka4vGxLmr4w)
- 2019.04 [X0x6d696368] [Ghidra: Bytes View (to patch binary and export to a working PE file)](https://www.youtube.com/watch?v=utUqAbfURko)
- 2019.04 [X0x6d696368] [Ghidra: Fixing Bugs (Fixing PE section import size alignment)](https://www.youtube.com/watch?v=vpt7-Hn-Uhg)
- 2019.04 [X0x6d696368] [Ghidra: Clear Flow and Repair, and Patch Instruction (to defeat anti-disassembly)](https://www.youtube.com/watch?v=H9DyLQ2iuyE)
- 2019.04 [X0x6d696368] [Ghidra: Scripting (Python) (a quick introduction by implementing pipeDecoder.py)](https://www.youtube.com/watch?v=WLXlq3lvUGs)
- 2019.04 [X0x6d696368] [Ghidra: Decompile and compile (to quickly reimplement malware decoding functions)](https://www.youtube.com/watch?v=YuwOgBDt_b4)
- 2019.04 [X0x6d696368] [Ghidra: EditBytesScript (to fix/manipulate PE header to load ShadowHammer setup.exe sample)](https://www.youtube.com/watch?v=7__tiVMPIEE)
- 2019.04 [X0x6d696368] [Ghidra: Extract and Import ... (to extract resources from PE binaries)](https://www.youtube.com/watch?v=M19ZSTAgubI)
- 2019.04 [X0x6d696368] [Ghidra: YaraGhidraGUIScript (to generate a YARA signature for threat/retro hunting)](https://www.youtube.com/watch?v=tBvxVkJrkh0)
- 2019.04 [X0x6d696368] [Ghidra: XORMemoryScript (to XOR decode strings)](https://www.youtube.com/watch?v=vPqs7E_nhdQ)
- 2019.04 [yoroi] [Ghidra SRE: The AZORult Field Test](https://blog.yoroi.company/research/ghidra-sre-the-azorult-field-test/)
- 2019.03 [nsfocus] [Ghidra Software Reverse Engineering Framework逆向工具分析](http://blog.nsfocus.net/ghidra-software-reverse-engineering-framework/)
- 2019.03 [sans] [Tip: Ghidra & ZIP Files](https://isc.sans.edu/forums/diary/Tip+Ghidra+ZIP+Files/24732/)
- 2019.03 [cybersecpolitics] [Ghidra: A meta changer?](https://cybersecpolitics.blogspot.com/2019/03/ghidra-meta-changer.html)
- 2019.03 [freecodecamp] [How I solved a simple CrackMe challenge with the NSA’s Ghidra](https://medium.com/p/d7e793c5acd2)
- 2019.03 [] [Ghidra: A quick overview for the curious](http://0xeb.net/2019/03/ghidra-a-quick-overview/)
- 2019.03 [freebuf] [RSA 2019丨NSA内部开源反汇编工具集Ghidra](https://www.freebuf.com/news/197482.html)
- 2019.03 [n0where] [NSA Software Reverse Engineering Framework: Ghidra](https://n0where.net/nsa-software-reverse-engineering-framework-ghidra)
- 2019.03 [malwaretech] [Video: First Look at Ghidra (NSA Reverse Engineering Tool)](https://www.malwaretech.com/2019/03/video-first-look-at-ghidra-nsa-reverse-engineering-tool.html)
- 2019.03 [MalwareTech] [First Look at Ghidra (NSA Reverse Engineering Tool)](https://www.youtube.com/watch?v=285b_DEmvHY)
- 2019.01 [linuxjournal] [GitHub Announces that Free Accounts Now Can Create Private Repositories, Bash-5.0 Released, iPhone Apps Linked to Golduck Malware, Godot Game Engine Reaches 3.1 Beta, NSA to Open-Source Its GHIDRA Reverse-Engineering Tool](https://www.linuxjournal.com/content/github-announces-free-accounts-now-can-create-private-repositories-bash-50-released-iphone)


### <a id="b7fb955b670df2babc67e5942297444d"></a>Vuln


- 2019.10 [securityaffairs] [Researchers discovered a code execution flaw in NSA GHIDRA](https://securityaffairs.co/wordpress/92280/hacking/ghidra-code-execution-flaw.html)
- 2019.10 [4hou] [CVE-2019-16941: NSA Ghidra工具RCE漏洞](https://www.4hou.com/info/news/20698.html)
- 2019.03 [venus] [Ghidra 从 XXE 到 RCE](https://paper.seebug.org/861/)
- 2019.03 [tencent] [Ghidra 从 XXE 到 RCE](https://xlab.tencent.com/cn/2019/03/18/ghidra-from-xxe-to-rce/)


### <a id="dd0d49a5e6bd34b372d9bbf4475e8024"></a>Vuln Analysis


#### <a id="f0ab053d7a282ab520c3a327fc91ba2e"></a>No Category


- 2019.09 [venus] [使用 Ghidra 对 iOS 应用进行 msgSend 分析](https://paper.seebug.org/1037/)
- 2019.09 [4hou] [使用Ghidra对iOS应用进行msgSend分析](https://www.4hou.com/system/20326.html)
- 2019.09 [WarrantyVoider] [X360 XEX Decompiling With Ghidra](https://www.youtube.com/watch?v=coGz0f7hHTM)
- 2019.08 [WarrantyVoider] [N64 ROM Decompiling With Ghidra - N64LoaderWV](https://www.youtube.com/watch?v=3d3a39LuCwc)
- 2019.08 [4hou] [基于Ghidra和Neo4j的RPC分析技术](https://www.4hou.com/technology/19730.html)
- 2019.04 [X0x6d696368] [Ghidra: Search Program Text... (to find XOR decoding functions in malware)](https://www.youtube.com/watch?v=MaxwIxrmrWY)
- 2019.04 [shogunlab] [Here Be Dragons: Reverse Engineering with Ghidra - Part 0 [Main Windows & CrackMe]](https://www.shogunlab.com/blog/2019/04/12/here-be-dragons-ghidra-0.html)
- 2019.03 [GhidraNinja] [Reverse engineering with #Ghidra: Breaking an embedded firmware encryption scheme](https://www.youtube.com/watch?v=4urMITJKQQs)
- 2019.03 [GhidraNinja] [Ghidra quickstart & tutorial: Solving a simple crackme](https://www.youtube.com/watch?v=fTGTnrgjuGA)


#### <a id="375c75af4fa078633150415eec7c867d"></a>Vuln Analysis&&Vuln Hunting


- 2019.11 [4hou] [使用Ghidra对WhatsApp VOIP Stack 溢出漏洞的补丁对比分析](https://www.4hou.com/vulnerable/21141.html)
- 2019.09 [4hou] [利用Ghidra分析TP-link M7350 4G随身WiFi的RCE漏洞](https://www.4hou.com/vulnerable/20267.html)
- 2019.08 [aliyun] [CVE-2019-12103  使用Ghidra分析TP-Link M7350上的预认证RCE](https://xz.aliyun.com/t/6017)


#### <a id="4e3f53845efe99da287b2cea1bdda97c"></a>Malware


- 2019.06 [dawidgolak] [IcedID aka #Bokbot Analysis with Ghidra.](https://medium.com/p/560e3eccb766)
- 2019.04 [aliyun] [利用Ghidra分析恶意软件Emotet](https://xz.aliyun.com/t/4931)
- 2019.04 [X0x6d696368] [Ghidra: Shadow Hammer (Stage 1: Setup.exe) complete static Analysis](https://www.youtube.com/watch?v=gI0nZR4z7_M)
- 2019.04 [X0xd0cf11e] [Analyzing Emotet with Ghidra — Part 2](https://medium.com/p/9efbea374b14)
- 2019.04 [X0x6d696368] [Ghidra: Android APK (it's basically dex2jar with a .dex decompiler)](https://www.youtube.com/watch?v=At_T6riSb9A)
- 2019.04 [X0xd0cf11e] [Analyzing Emotet with Ghidra — Part 1](https://medium.com/p/4da71a5c8d69)
- 2019.03 [GhidraNinja] [Reversing WannaCry Part 1 - Finding the killswitch and unpacking the malware in #Ghidra](https://www.youtube.com/watch?v=Sv8yu12y5zM)
- 2019.03 [HackerSploit] [Malware Analysis With Ghidra - Stuxnet Analysis](https://www.youtube.com/watch?v=TJhfnItRVOA)
- 2019.03 [sans] [Analysing meterpreter payload with Ghidra](https://isc.sans.edu/forums/diary/Analysing+meterpreter+payload+with+Ghidra/24722/)




### <a id="92f60c044ed13b3ffde631794edd2756"></a>Other




### <a id="4bfa6dcf708b3f896870c9d3638c0cde"></a>Tips&&Tricks




### <a id="0d086cf7980f65da8f7112b901fecdc1"></a>Script Writting


- 2019.11 [deadc0de] [Scripting Ghidra with Python](https://deadc0de.re/articles/ghidra-scripting-python.html)
- 2019.04 [X0x6d696368] [ghidra_scripts: RC4Decryptor.py](https://www.youtube.com/watch?v=kXaHrPyZtGs)
- 2019.04 [aliyun] [如何开发用于漏洞研究的Ghidra插件，Part 1](https://xz.aliyun.com/t/4723)
- 2019.04 [somersetrecon] [Ghidra Plugin Development for Vulnerability Research - Part-1](https://www.somersetrecon.com/blog/2019/ghidra-plugin-development-for-vulnerability-research-part-1)
- 2019.03 [wololo] [PS4 release: GhidraPS4Loader and Playstation 4 Flash tool](http://wololo.net/2019/03/18/ps4-release-ghidraps4loader-and-playstation-4-flash-tool/)




# <a id="b1a6c053e88e86ce01bbd78c54c63a7c"></a>x64dbg


***


## <a id="b4a856db286f9f29b5a32d477d6b3f3a"></a>Plugins&&Scripts


### <a id="353ea40f2346191ecb828210a685f9db"></a>x64dbg


- [**34576**Star][1m] [C++] [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) An open-source x64/x32 debugger for windows.


### <a id="da5688c7823802e734c39b539aa39df7"></a>Recent Add


- [**1672**Star][7m] [C++] [yegord/snowman](https://github.com/yegord/snowman)  a native code to C/C++ decompiler, supporting x86, AMD64, and ARM architectures
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
    - [IDA插件](https://github.com/yegord/snowman/tree/master/src/ida-plugin) 
    - [snowman](https://github.com/yegord/snowman/tree/master/src/snowman) QT界面
    - [nocode](https://github.com/yegord/snowman/tree/master/src/nocode) 命令行工具
    - [nc](https://github.com/yegord/snowman/tree/master/src/nc) 核心代码，可作为库使用
- [**1341**Star][1m] [C] [x64dbg/x64dbgpy](https://github.com/x64dbg/x64dbgpy) Automating x64dbg using Python, Snapshots:
- [**1133**Star][2y] [C++] [x64dbg/gleebug](https://github.com/x64dbg/gleebug) Debugging Framework for Windows.
- [**972**Star][2m] [Py] [x64dbg/docs](https://github.com/x64dbg/docs) x64dbg Documentation
- [**471**Star][13d] [C] [bootleg/ret-sync](https://github.com/bootleg/ret-sync) a set of plugins that help to synchronize a debugging session (WinDbg/GDB/LLDB/OllyDbg/OllyDbg2/x64dbg) with IDA/Ghidra disassemblers
    - Also In Section: [IDA->Tools->Sync With Debugger](#f7d311685152ac005cfce5753c006e4b) |
    - [GDB插件](https://github.com/bootleg/ret-sync/tree/master/ext_gdb) 
    - [Ghidra插件](https://github.com/bootleg/ret-sync/tree/master/ext_ghidra) 
    - [IDA插件](https://github.com/bootleg/ret-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/bootleg/ret-sync/tree/master/ext_lldb) 
    - [OD](https://github.com/bootleg/ret-sync/tree/master/ext_olly1) 
    - [OD2](https://github.com/bootleg/ret-sync/tree/master/ext_olly2) 
    - [WinDgb](https://github.com/bootleg/ret-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/bootleg/ret-sync/tree/master/ext_x64dbg) 
- [**363**Star][9m] [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) Awesome IDA, x64DBG & OllyDBG plugin
    - Also In Section: [IDA->Tools->Collection](#a7dac37cd93b8bb42c7d6aedccb751b3) |
- [**163**Star][2m] [Py] [x64dbg/x64dbgida](https://github.com/x64dbg/x64dbgida) Official x64dbg plugin for IDA Pro.
    - Also In Section: [IDA->Tools->Import Export->No Category](#8ad723b704b044e664970b11ce103c09) |
- [**78**Star][12d] [C] [horsicq/nfdx64dbg](https://github.com/horsicq/nfdx64dbg) Plugin for x64dbg Linker/Compiler/Tool detector.
- [**77**Star][3m] [C] [ahmadmansoor/advancedscript](https://github.com/ahmadmansoor/advancedscript) Add More Features for x64dbg Script System,with some Functions which will help Plugin Coder
- [**75**Star][4y] [C++] [x64dbg/xedparse](https://github.com/x64dbg/xedparse)  A MASM-like, single-line plaintext assembler
- [**72**Star][2y] [C] [0ffffffffh/api-break-for-x64dbg](https://github.com/0ffffffffh/api-break-for-x64dbg) x64dbg plugin to set breakpoints automatically to Win32/64 APIs
- [**71**Star][2y] [Py] [x64dbg/mona](https://github.com/x64dbg/mona) Fork of mona.py with x64dbg support
- [**70**Star][12d] [C] [horsicq/stringsx64dbg](https://github.com/horsicq/stringsx64dbg) Strings plugin for x64dbg
- [**47**Star][2m] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
    - Also In Section: [IDA->Tools->Import Export->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[Ghidra->Plugins->With Other Tools->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**43**Star][7m] [YARA] [x64dbg/yarasigs](https://github.com/x64dbg/yarasigs) Various Yara signatures (possibly to be included in a release later).
- [**42**Star][2m] [Java] [revolver-ocelot-saa/ghidrax64dbg](https://github.com/revolver-ocelot-saa/ghidrax64dbg) Extract annoations from Ghidra into an X32/X64 dbg database
    - Also In Section: [Ghidra->Plugins->With Other Tools->Debugger](#e81053b03a859e8ac72f7fe79e80341a) |
- [**41**Star][12d] [C] [horsicq/pex64dbg](https://github.com/horsicq/pex64dbg) pe viewer
- [**40**Star][3y] [C++] [x64dbg/interobfu](https://github.com/x64dbg/interobfu) Intermediate x86 instruction representation for use in obfuscation/deobfuscation.
- [**38**Star][3y] [C] [changeofpace/force-page-protection](https://github.com/changeofpace/force-page-protection) This x64dbg plugin sets the page protection for memory mapped views in scenarios which cause NtProtectVirtualMemory to fail.
- [**38**Star][3y] [C++] [kurapicabs/x64_tracer](https://github.com/kurapicabs/x64_tracer) x64dbg conditional branches logger [Plugin]
- [**38**Star][3y] [CSS] [thundercls/x64dbg_vs_dark](https://github.com/thundercls/x64dbg_vs_dark) x64dbg stylesheet like visual studio dark theme
- [**37**Star][3y] [C] [changeofpace/pe-header-dump-utilities](https://github.com/changeofpace/pe-header-dump-utilities) This x64dbg plugin adds several commands for dumping PE header information by address.
- [**29**Star][1y] [Assembly] [mrfearless/apiinfo-plugin-x86](https://github.com/mrfearless/apiinfo-plugin-x86) APIInfo Plugin (x86) - A Plugin For x64dbg
- [**29**Star][3y] [Py] [x64dbg/x64dbgbinja](https://github.com/x64dbg/x64dbgbinja) Official x64dbg plugin for Binary Ninja
- [**28**Star][2y] [C] [x64dbg/plugintemplate](https://github.com/x64dbg/plugintemplate) Plugin template for x64dbg. Releases:
- [**28**Star][2y] [C] [x64dbg/slothbp](https://github.com/x64dbg/slothbp) Collaborative Breakpoint Manager for x64dbg.
- [**27**Star][2y] [atom0s/ceautoasm-x64dbg](https://github.com/atom0s/ceautoasm-x64dbg) An x64dbg plugin that allows users to execute Cheat Engine auto assembler scripts within x64dbg.
- [**25**Star][1y] [Assembly] [mrfearless/apisearch-plugin-x86](https://github.com/mrfearless/apisearch-plugin-x86) APISearch Plugin (x86) - A Plugin For x64dbg
- [**24**Star][3y] [C++] [chausner/1337patch](https://github.com/chausner/1337patch) Simple command-line tool to apply patches exported by x64dbg to running processes
- [**20**Star][2y] [Py] [techbliss/x64dbg_script_editor](https://github.com/techbliss/x64dbg_script_editor) x64dbg Script editor v2.0
- [**19**Star][5y] [C] [x64dbg/staticanalysis](https://github.com/x64dbg/staticanalysis) Static analysis plugin for x64dbg (now deprecated).
- [**17**Star][2y] [C#] [thundercls/xhotspots](https://github.com/thundercls/xhotspots) xHotSpots plugin for x64dbg
- [**16**Star][11m] [C] [mrfearless/x64dbg-plugin-template-for-visual-studio](https://github.com/mrfearless/x64dbg-plugin-template-for-visual-studio) x64dbg plugin template for visual studio
- [**15**Star][4y] [C] [realgam3/x64dbg-python](https://github.com/realgam3/x64dbg-python) Automating x64dbg using Python
- [**13**Star][8m] [C] [mrexodia/driver_unpacking](https://github.com/mrexodia/driver_unpacking) Source code for the "Kernel driver unpacking with x64dbg" blog post.
- [**13**Star][1y] [Assembly] [mrfearless/x64dbg-plugin-sdk-for-x64-assembler](https://github.com/mrfearless/x64dbg-plugin-sdk-for-x64-assembler) x64dbg Plugin SDK For x64 Assembler
- [**12**Star][2y] [C] [blaquee/slothemu](https://github.com/blaquee/slothemu) unicorn emulator for x64dbg
- [**12**Star][1y] [Assembly] [mrfearless/apisearch-plugin-x64](https://github.com/mrfearless/apisearch-plugin-x64) APISearch Plugin (x64) - A Plugin For x64dbg
- [**12**Star][1y] [Assembly] [mrfearless/copytoasm-plugin-x86](https://github.com/mrfearless/copytoasm-plugin-x86) CopyToAsm (x86) - A Plugin For x64dbg
- [**12**Star][2y] [C] [thundercls/magicpoints](https://github.com/thundercls/magicpoints) MagicPoints plugin for x64dbg
- [**12**Star][3y] [C] [x64dbg/capstone_wrapper](https://github.com/x64dbg/capstone_wrapper) C++ wrapper for capstone (x86 only)
- [**12**Star][2m] [C] [x64dbg/qtplugin](https://github.com/x64dbg/qtplugin) Plugin demonstrating how to link with Qt.
- [**12**Star][3y] [C] [x64dbg/testplugin](https://github.com/x64dbg/testplugin) Example plugin for x64dbg.
- [**11**Star][1y] [Assembly] [mrfearless/x64dbg-plugin-sdk-for-x86-assembler](https://github.com/mrfearless/x64dbg-plugin-sdk-for-x86-assembler) x64dbg Plugin SDK For x86 Assembler
- [**9**Star][3y] [C++] [jdavidberger/chaiscriptplugin](https://github.com/jdavidberger/chaiscriptplugin) Plugin which enables chai scripts to run inside of x64dbg
- [**9**Star][1y] [Assembly] [mrfearless/today-plugin-x64](https://github.com/mrfearless/today-plugin-x64) Today Plugin (x64) - A Plugin For x64dbg
- [**4**Star][3y] [C] [mrexodia/traceplugin](https://github.com/mrexodia/traceplugin) Very simple trace plugin example for x64dbg.
- [**4**Star][1y] [Assembly] [mrfearless/autocmdline-plugin-x86](https://github.com/mrfearless/autocmdline-plugin-x86) AutoCmdLine Plugin (x86) - A Plugin For x64dbg
- [**4**Star][1y] [Assembly] [mrfearless/copytoasm-plugin-x64](https://github.com/mrfearless/copytoasm-plugin-x64) CopyToAsm (x64) - A Plugin For x64dbg
- [**4**Star][1y] [Assembly] [mrfearless/today-plugin-x86](https://github.com/mrfearless/today-plugin-x86) Today Plugin (x86) - A Plugin For x64dbg
- [**4**Star][2y] [thomasthelen/upxunpacker](https://github.com/thomasthelen/upxunpacker) Scripts for x64dbg to find the OEP of exe files packed with UPX
- [**4**Star][1y] [CSS] [x64dbg/blog](https://github.com/x64dbg/blog) Blog for x64dbg.
- [**3**Star][1y] [Assembly] [mrfearless/autocmdline-plugin-x64](https://github.com/mrfearless/autocmdline-plugin-x64) AutoCmdLine Plugin (x64) - A Plugin For x64dbg
- [**3**Star][3y] [stonedreamforest/x64dbg_theme_relaxyoureyes](https://github.com/stonedreamforest/x64dbg_theme_relaxyoureyes) Relax Your Eyes
- [**3**Star][2y] [C#] [x64dbg/pluginmanager](https://github.com/x64dbg/pluginmanager) Plugin manager plugin for x64dbg.
- [**2**Star][1y] [Assembly] [mrfearless/codeshot-plugin-x86](https://github.com/mrfearless/codeshot-plugin-x86) CodeShot Plugin (x86) - A Plugin For x64dbg
- [**2**Star][1y] [Assembly] [mrfearless/stepint3-plugin-x86](https://github.com/mrfearless/stepint3-plugin-x86) StepInt3 Plugin (x86) - A Plugin For x64dbg
- [**2**Star][1y] [C] [phidelpark/x64dbgplugins](https://github.com/phidelpark/x64dbgplugins) 디버거 x64dbg 플러그인
- [**2**Star][2y] [C] [x64dbg/dbgit](https://github.com/x64dbg/dbgit) Simple plugin to automatically add x64dbg databases to version control.
- [**1**Star][2y] [C++] [lllshamanlll/x64dbg_cpp_template](https://github.com/lllshamanlll/x64dbg_cpp_template) Simple, easy to use template plugin for x64dbg
- [**1**Star][1y] [Assembly] [mrfearless/stepint3-plugin-x64](https://github.com/mrfearless/stepint3-plugin-x64) StepInt3 Plugin (x64) - A Plugin For x64dbg
- [**1**Star][2y] [C++] [x64dbg/snowmandummy](https://github.com/x64dbg/snowmandummy) Dummy DLL for snowman.
- [**0**Star][2y] [C] [x64dbg/getcharabcwidthsi_cache](https://github.com/x64dbg/getcharabcwidthsi_cache) Plugin to improve performance of QWindowsFontEngine::getGlyphBearings.




***


## <a id="22894d6f2255dc43d82dd46bdbc20ba1"></a>Post&&Videos


- 2019.02 [freebuf] [使用x64dbg分析微信并获取所有联系人信息](https://www.freebuf.com/articles/terminal/195774.html)
- 2018.03 [freebuf] [使用x64dbg分析微信聊天函数并实现发信息](http://www.freebuf.com/sectool/164988.html)
- 2018.03 [360] [使用x64dbg脱壳之开源壳upx](https://www.anquanke.com/post/id/99750/)
- 2018.02 [360] [使用x64dbg分析微信防多开功能](https://www.anquanke.com/post/id/98825/)
- 2018.02 [360] [使用x64dbg 分析 TIM2.0 QQ撤销功能](https://www.anquanke.com/post/id/98498/)
- 2018.02 [KirbiflintCracking] [Patching a Keygenme with x64dbg [Learning Cracking]](https://www.youtube.com/watch?v=tkHW-VNBBQo)
- 2018.01 [KirbiflintCracking] [Cracking & Keygen a crackme with x64dbg [Learning Cracking]](https://www.youtube.com/watch?v=6JsYRg8_yeY)
- 2018.01 [KirbiflintCracking] [Cracking the new Steam Stub drm with x64dbg [Learning Cracking]](https://www.youtube.com/watch?v=yrrcL8xGPoE)
- 2018.01 [KirbiflintCracking] [Cracking a simple crackme & bypassing Anti-debugger protection with x64dbg [Learning Cracking]](https://www.youtube.com/watch?v=Sal3xbSJdJA)
- 2017.12 [KirbiflintCracking] [Cracking some Crackmes with x64dbg [Learning Cracking]](https://www.youtube.com/watch?v=E1zD4Lp7b1g)
- 2017.12 [KirbiflintCracking] [Cracking a simple Crackme with x64dbg [Learning cracking]](https://www.youtube.com/watch?v=MHw8Xu9Od_c)
- 2017.10 [x64dbg] [Limitations in x64dbg](https://x64dbg.com/blog/2017/10/06/Limitations-in-x64dbg.html)
- 2017.09 [pediy] [[翻译]消息断点在x64dbg中的应用 by lantie@15PB](https://bbs.pediy.com/thread-221551.htm)
- 2017.07 [pediy] [[原创]使用x64dbg+VS2015 Spy++去除WinRAR5.40(64位)广告弹框](https://bbs.pediy.com/thread-219435.htm)
- 2017.06 [seowhistleblower] [Channel Update + Let's Hack: Sniper Elite 4 (Cheat Engine and x64dbg Tutorial)](https://www.youtube.com/watch?v=KCHsOmebYo4)
- 2016.10 [x64dbg] [Architecture of x64dbg](https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html)
- 2016.07 [x64dbg] [x64dbg plugin SDK](https://x64dbg.com/blog/2016/07/30/x64dbg-plugin-sdk.html)
- 2016.07 [adelmas] [Introducing x64dbg and Pizzacrypts Ransomware Unpacking](http://adelmas.com/blog/x64dbg_pizzacrypts.php)
- 2015.12 [pediy] [[原创]源码编译x64dbg](https://bbs.pediy.com/thread-206431.htm)
- 2015.10 [pediy] [[原创]win7X64DBGPORT移位数据](https://bbs.pediy.com/thread-205123.htm)
- 2015.01 [reverseengineeringtips] [An Introduction To x64dbg](http://reverseengineeringtips.blogspot.com/2015/01/an-introduction-to-x64dbg.html)


# <a id="37e37e665eac00de3f55a13dcfd47320"></a>OllyDbg


***


## <a id="7834e399e48e6c64255a1a0fdb6b88f5"></a>Plugins&&Scripts


### <a id="92c44f98ff5ad8f8b0f5e10367262f9b"></a>Recent Add


- [**75**Star][5y] [C++] [quangnh89/ollycapstone](https://github.com/quangnh89/ollycapstone) This is a plugin for OllyDbg 1.10 to replace the old disasm engine by Capstone disassembly/disassembler framework.
- [**48**Star][8y] [C] [stephenfewer/ollysockettrace](https://github.com/stephenfewer/ollysockettrace) OllySocketTrace is a plugin for OllyDbg to trace the socket operations being performed by a process.
- [**45**Star][7m] [thomasthelen/ollydbg-scripts](https://github.com/thomasthelen/ollydbg-scripts) Unpacking scripts for Ollydbg.
- [**41**Star][1y] [Batchfile] [romanzaikin/ollydbg-v1.10-with-best-plugins-and-immunity-debugger-theme-](https://github.com/romanzaikin/ollydbg-v1.10-with-best-plugins-and-immunity-debugger-theme-) Make OllyDbg v1.10 Look like Immunity Debugger & Best Plugins
- [**41**Star][8y] [C] [stephenfewer/ollyheaptrace](https://github.com/stephenfewer/ollyheaptrace) OllyHeapTrace is a plugin for OllyDbg to trace the heap operations being performed by a process.
- [**38**Star][8y] [C] [stephenfewer/ollycalltrace](https://github.com/stephenfewer/ollycalltrace) OllyCallTrace is a plugin for OllyDbg to trace the call chain of a thread.
- [**24**Star][6y] [C++] [epsylon3/odbgscript](https://github.com/epsylon3/odbgscript) OllyDBG Script Engine
- [**22**Star][3y] [Py] [ehabhussein/ollydbg-binary-execution-visualizer](https://github.com/ehabhussein/ollydbg-binary-execution-visualizer) reverse engineering, visual binary analysis
- [**21**Star][5y] [C++] [lynnux/holyshit](https://github.com/lynnux/holyshit) ollydbg plugin, the goal is to make life easier. The project is DEAD!
- [**15**Star][8y] [C] [zynamics/ollydbg-immunitydbg-exporter](https://github.com/zynamics/ollydbg-immunitydbg-exporter) Exporters for OllyDbg and ImmunityDbg for use with zynamics BinNavi <= 3.0
- [**14**Star][5y] [C++] [sinsoul/ollight](https://github.com/sinsoul/ollight) A Code highlighting plugin for OllyDbg 2.01.
- [**9**Star][2y] [Assembly] [dentrax/dll-injection-with-assembly](https://github.com/dentrax/dll-injection-with-assembly) DLL Injection to Exe with Assembly using OllyDbg
- [**1**Star][2y] [Assembly] [infocus7/assembly-simple-keygen](https://github.com/infocus7/assembly-simple-keygen) First time using Ollydbg for Reverse Engineering




***


## <a id="8dd3e63c4e1811973288ea8f1581dfdb"></a>Post&&Videos


- 2019.04 [freebuf] [缓冲区溢出实战教程系列（三）：利用OllyDbg了解程序运行机制](https://www.freebuf.com/articles/system/198149.html)
- 2018.10 [pediy] [[原创]使用“PE文件加区段工具”、“LordPE”、“WinHex”、“OllyDbg”为PE文件添加section、dll（API）](https://bbs.pediy.com/thread-247370.htm)
- 2018.10 [pediy] [[原创]Ollydbg插件的编写流程](https://bbs.pediy.com/thread-247331.htm)
- 2018.03 [pediy] [[原创]业余时间开发的类IDA静态反汇编工具(仿Ollydbg界面)(内有传送门)](https://bbs.pediy.com/thread-225396.htm)
- 2018.01 [kienbigmummy] [OllyDbg_tut32](https://medium.com/p/345972799c44)
- 2018.01 [pediy] [如何实现自己的ollydbg调试器 (1) 界面的实现](https://bbs.pediy.com/thread-224157.htm)
- 2017.12 [hackers] [Reverse Engineering Malware, Part 5: OllyDbg Basics](https://www.hackers-arise.com/single-post/2017/10/03/Reverse-Engineering-Malware-Part-5-OllyDbg-Basics)
- 2017.10 [4hou] [工具推荐：逆向破解利器OllyDbg](http://www.4hou.com/tools/7890.html)
- 2017.07 [ColinHardy] [Three and a half ways to unpack malware using Ollydbg](https://www.youtube.com/watch?v=n_gxtaFX8Ao)
- 2016.12 [360] [利用OllyDbg跟踪分析Process Hollowing](https://www.anquanke.com/post/id/85124/)
- 2016.12 [airbuscybersecurity] [Following Process Hollowing in OllyDbg](http://blog.airbuscybersecurity.com/post/2016/06/Following-Process-Hollowing-in-OllyDbg)
- 2015.11 [pediy] [[原创][开源]OllyDbg 2.x插件编写教程](https://bbs.pediy.com/thread-206175.htm)
- 2015.11 [pediy] [[原创]科普文之如何编写ollydbg插件](https://bbs.pediy.com/thread-206064.htm)
- 2015.11 [pediy] [[翻译]Ollydbg2.0X版本帮助手册中文翻译](https://bbs.pediy.com/thread-205870.htm)
- 2015.08 [pediy] [[原创]《使用OllyDbg从零开始Cracking》第14课练习完整解答](https://bbs.pediy.com/thread-203152.htm)
- 2015.01 [pediy] [[翻译]使用OllyDbg从零开始Cracking 第五十八章-EXECryptor v2.2.50.h脱壳](https://bbs.pediy.com/thread-196797.htm)
- 2014.11 [reversec0de] [OllyDbg Plugin Converter v0.1b](https://reversec0de.wordpress.com/2014/11/09/ollydbg-plugin-converter-v0-1b/)
- 2014.10 [pediy] [[翻译]使用OllyDbg从零开始Cracking 第四十四章-ACProtect V1.09脱壳(修复AntiDump)](https://bbs.pediy.com/thread-193537.htm)
- 2014.10 [pediy] [[翻译]使用OllyDbg从零开始Cracking 第四十三章-ACProtect V1.09脱壳(编写脚本修复IAT)](https://bbs.pediy.com/thread-193467.htm)
- 2014.10 [pediy] [使用OllyDbg从零开始Cracking 第四十二章-ACProtect V1.09脱壳(寻找OEP,绕过硬件断点的检测,修复Stolen code)](https://bbs.pediy.com/thread-193405.htm)
- 2014.08 [pediy] [[求助]旧帖新读之OllyDBG入门系列(五)CrackMe算法分析](https://bbs.pediy.com/thread-190696.htm)
- 2014.07 [pediy] [[原创]OllyDbg命令栏插件缓冲区溢出](https://bbs.pediy.com/thread-189758.htm)
- 2014.05 [pediy] [[原创]Android平台的ollydbg即将到来，求gikdbg.art内测伙伴！](https://bbs.pediy.com/thread-188241.htm)
- 2014.04 [pediy] [使用OllyDbg从零开始Cracking 第十章-断点](https://bbs.pediy.com/thread-187118.htm)
- 2014.04 [pediy] [使用OllyDbg从零开始Cracking 第九章-基本概念](https://bbs.pediy.com/thread-187023.htm)
- 2014.04 [pediy] [[开源]OllyDbg 2.01 的代码即时高亮插件](https://bbs.pediy.com/thread-186755.htm)
- 2014.04 [zairon] [My new Ollydbg plugin: Sequential Dumper](https://zairon.wordpress.com/2014/04/03/my-new-ollydbg-plugin-sequential-dumper/)
- 2014.03 [zairon] [Ollydbg plugin development: Findmemory needs Listmemory?](https://zairon.wordpress.com/2014/03/28/ollydbg-plugin-development-findmemory-needs-listmemory/)
- 2014.03 [pediy] [[原创]iOS平台的ollydbg即将到来，求gikdbg内测伙伴！](https://bbs.pediy.com/thread-185733.htm)
- 2014.02 [pediy] [使用OllyDbg从零开始Cracking第八章](https://bbs.pediy.com/thread-184873.htm)
- 2014.02 [sans] [Is OllyDbg Version 2 Ready for Malware Analysis?](https://digital-forensics.sans.org/blog/2014/02/20/ollydbg-version-2-for-malware-analysis)
- 2014.02 [pediy] [[翻译]使用OllyDbg从零开始Cracking 第七章-call,ret](https://bbs.pediy.com/thread-184699.htm)
- 2014.02 [pediy] [使用OllyDbg从零开始Cracking(已完结)](https://bbs.pediy.com/thread-184679.htm)
- 2014.02 [pediy] [[翻译]使用OllyDbg从零开始Cracking 第六章-比较和条件跳转指令](https://bbs.pediy.com/thread-184658.htm)
- 2014.02 [pediy] [[翻译]使用OllyDbg从零开始Cracking 第五章-数学指令](https://bbs.pediy.com/thread-184589.htm)
- 2014.02 [pediy] [[翻译]使用OllyDbg从零开始Cracking 第四章-汇编指令](https://bbs.pediy.com/thread-184551.htm)
- 2013.09 [toolswatch] [New Tool for Visualizing Binaries With Ollydbg and Graphvis released](http://www.toolswatch.org/2013/09/new-tool-for-visualizing-binaries-with-ollydbg-and-graphvis-released/)
- 2013.09 [doar] [Pinpointing Heap-related Issues: OllyDbg2 Off-by-one Story](http://doar-e.github.io/blog/2013/09/09/pinpointing-heap-related-issues-ollydbg2-off-by-one-story/)
- 2013.08 [pediy] [[原创]基于VT技术的OllyDbg插件Ddvp](https://bbs.pediy.com/thread-177179.htm)
- 2013.05 [pediy] [[原创]公布过SafengineChallenge悬赏壳的脚本及OLLYDBG](https://bbs.pediy.com/thread-170845.htm)
- 2013.02 [pediy] [[原创]OllyDBG 数据转换和反汇编代码插件2013-3-10 更新 支持OD2.01h](https://bbs.pediy.com/thread-163152.htm)
- 2011.10 [pediy] [[原创]为OllyDbg增添“内存硬件条件断点”功能（1）](https://bbs.pediy.com/thread-141697.htm)
- 2011.09 [pediy] [[未收录]OllyDbg小改01](https://bbs.pediy.com/thread-140274.htm)
- 2011.08 [pediy] [[原创]让 OllyDbg 1.10 自动适应并创建 UDD 和 插件 路径](https://bbs.pediy.com/thread-138598.htm)
- 2011.03 [pediy] [[原创]逆向patch，突破ollydbg 32插件限制](https://bbs.pediy.com/thread-130518.htm)
- 2011.02 [pediy] [[分享]共享一个Ollydbg小插件带源码](https://bbs.pediy.com/thread-130050.htm)
- 2010.10 [pediy] [[原创]Ollydbg之SetUnhandledExceptionFilter调试](https://bbs.pediy.com/thread-121866.htm)
- 2010.08 [pediy] [[原创]一行代码检测程序是否使用OllyDBG启动](https://bbs.pediy.com/thread-119484.htm)
- 2010.05 [pediy] [[原创]使用OllyDbg调试源代码级C程序](https://bbs.pediy.com/thread-112457.htm)
- 2010.03 [pediy] [[分享]Ollydbg 硬件断点笔记](https://bbs.pediy.com/thread-108107.htm)
- 2009.10 [pediy] [[翻译]使用OllyDbg从零开始Cracking 第三章](https://bbs.pediy.com/thread-98776.htm)
- 2009.07 [pediy] [Anti OllyDbg](https://bbs.pediy.com/thread-93316.htm)
- 2009.07 [pediy] [[翻译]OllyDbg插件开发手册全部翻译件](https://bbs.pediy.com/thread-93305.htm)
- 2009.06 [pediy] [[翻译][原创]OllyDbg命令行插件帮助](https://bbs.pediy.com/thread-91880.htm)
- 2009.01 [gamelinux] [EDB : OllyDbg for Linux…  Im in *LOVE*](https://gamelinux.wordpress.com/2009/01/30/edb-ollydbg-for-linux-im-in-love/)
- 2009.01 [pediy] [[求助]自己做的加密函数导入表，少部分程序只在Ollydbg等调试器下正常运行，高手帮着分析一下为什么？](https://bbs.pediy.com/thread-80457.htm)
- 2009.01 [pediy] [[求助]OllyDBG的标题汉化问题[附带目前网上很少的非标汉化工具破解版]](https://bbs.pediy.com/thread-80292.htm)
- 2008.05 [pediy] [[原创]OllyDBG分析报告系列(5)---内存补丁](https://bbs.pediy.com/thread-65546.htm)
- 2008.05 [pediy] [[原创]OllyDBG分析报告系列(2)---内存断点](https://bbs.pediy.com/thread-65221.htm)
- 2008.03 [pediy] [[原创]给ollydbg自动添加注释的插件](https://bbs.pediy.com/thread-62158.htm)
- 2007.07 [pediy] [[下载]OllyDBG入门教程－－chm版（看雪论坛）](https://bbs.pediy.com/thread-48237.htm)
- 2007.06 [pediy] [[原创]关于《OllyDBG 入门系列（五）－消息断点及 RUN 跟踪》的补充](https://bbs.pediy.com/thread-46520.htm)
- 2007.06 [pelock] [Kaspersky Anti-Virus v6.0.2 vs OllyDbg](https://www.pelock.com/blog/2007/06/13/kaspersky-anti-virus-v602-vs-ollydbg/)
- 2007.04 [pediy] [用OllyDbg手脱RLPack V1.17加壳的DLL](https://bbs.pediy.com/thread-42043.htm)
- 2007.03 [pediy] [翻译 ollyDBG tutorial.原创](https://bbs.pediy.com/thread-40359.htm)
- 2007.02 [pediy] [[原创]OllyDBG (Condition) Log Hardware BreakPoint](https://bbs.pediy.com/thread-39645.htm)
- 2007.01 [pediy] [[初级]用实例讲解OllyICE（OllyDBG）破解一个商业时间限制软件[原创]](https://bbs.pediy.com/thread-38773.htm)
- 2006.12 [pediy] [兼容VC，Softice快捷键标准的ollydbg,F5,F8,F10,Ctrl+F5](https://bbs.pediy.com/thread-37114.htm)
- 2006.11 [pediy] [[原创]从Ollydbg说起-----WinDbg用户态调试教程{看雪学院2006金秋读书季}](https://bbs.pediy.com/thread-34379.htm)
- 2006.10 [pediy] [[分享]献给初学者---OllyDBG入门教程（收藏版）](https://bbs.pediy.com/thread-33399.htm)
- 2006.10 [pediy] [[分享]OllyDbg.Disassembler.for.Delphi](https://bbs.pediy.com/thread-33048.htm)
- 2006.09 [pediy] [OllyDBG1.1条件记录断点中传递命令到命令行插件功能的使用探索](https://bbs.pediy.com/thread-31790.htm)
- 2006.04 [pediy] [特定码――用OllyDBG手脱Enigma Protector V1.12加壳的试炼品](https://bbs.pediy.com/thread-24123.htm)
- 2006.04 [pediy] [[分享]给Ollydbg的增加实用的快捷键操作功能（4.25更新）](https://bbs.pediy.com/thread-24059.htm)
- 2006.04 [pediy] [[原创]OllyDBG 入门系列（七）－汇编功能](https://bbs.pediy.com/thread-23873.htm)
- 2006.03 [pediy] [解决ollydbg调试程序cpu应用率高达100%的问题](https://bbs.pediy.com/thread-23172.htm)
- 2006.02 [pediy] [[分享]打包OllyDBG 入门系列及一些基础精华（2006-05-10修正）](https://bbs.pediy.com/thread-21748.htm)
- 2006.02 [pediy] [[原创]OllyDBG 入门系列（五）－消息断点及 RUN 跟踪](https://bbs.pediy.com/thread-21532.htm)
- 2006.02 [pediy] [[原创]OllyDBG 入门系列（四）－内存断点](https://bbs.pediy.com/thread-21378.htm)
- 2006.02 [pediy] [[原创]OllyDBG 入门系列（三）－函数参考](https://bbs.pediy.com/thread-21330.htm)
- 2006.02 [pediy] [[原创]OllyDBG 入门系列（二）－字串参考](https://bbs.pediy.com/thread-21308.htm)
- 2006.02 [pediy] [[原创]OllyDBG 入门系列（一）－认识OllyDBG](https://bbs.pediy.com/thread-21284.htm)
- 2005.12 [pediy] [[分享]OllyDBG中快速定位VB按钮的处理程序](https://bbs.pediy.com/thread-19782.htm)
- 2005.12 [pediy] [用Ollydbg手脱SafeDisc V2.43.000加壳的DLL](https://bbs.pediy.com/thread-19721.htm)
- 2005.12 [pediy] [用Ollydbg手脱Armadillo加壳的DLL――Visual.Assist.X.V10.2.1437.0](https://bbs.pediy.com/thread-19368.htm)
- 2005.10 [pediy] [ExeCryptor 2.2.X 的 Anti Ollydbg 小结](https://bbs.pediy.com/thread-17826.htm)
- 2005.09 [pediy] [用Ollydbg手脱tElock V0.98加壳的DLL(菜鸟练习篇）](https://bbs.pediy.com/thread-17287.htm)
- 2005.09 [pediy] [OllyDbg + ASProtect SKE 2.X +代码变形](https://bbs.pediy.com/thread-16774.htm)
- 2005.08 [pediy] [藏好自己的 OllyDbg](https://bbs.pediy.com/thread-16371.htm)
- 2005.08 [pediy] [Diy OllyDbg's Loaddll.exe](https://bbs.pediy.com/thread-16140.htm)
- 2005.08 [pediy] [使用 OLLYDBG 咄入 Xprotector](https://bbs.pediy.com/thread-16126.htm)
- 2005.08 [pediy] [[分享]利用OllyDbg进行源码级调试(Win32汇编语言)](https://bbs.pediy.com/thread-15934.htm)
- 2005.07 [pediy] [关于调试的几个基础问题，是ollydbg的，有点不明白，在此虚心请教](https://bbs.pediy.com/thread-15065.htm)
- 2005.05 [pediy] [用Ollydbg手脱Armadillo加壳的DLL](https://bbs.pediy.com/thread-14098.htm)
- 2005.05 [pediy] [[原创]使用OllyDbg 分析 USB HID 设备接口协议](https://bbs.pediy.com/thread-13846.htm)
- 2005.03 [pediy] [用Ollydbg手脱Packman V0.0.0.1加壳的DLL](https://bbs.pediy.com/thread-11744.htm)
- 2005.02 [pediy] [[原创]OllyDbg增加填充Nop指令功能](https://bbs.pediy.com/thread-11357.htm)
- 2004.12 [pediy] [用Ollydbg手脱ACProtect V1.41加壳的DLL](https://bbs.pediy.com/thread-9161.htm)
- 2004.12 [pediy] [用Ollydbg手脱Petite V2.2加壳的DLL](https://bbs.pediy.com/thread-9018.htm)
- 2004.12 [pediy] [[圣诞贺礼]OllyDbg中文帮助文档](https://bbs.pediy.com/thread-8899.htm)
- 2004.12 [pediy] [ReloX修复DLL脱壳重定位表的简便方法――用Ollydbg手脱Neolite加壳的DLL](https://bbs.pediy.com/thread-8819.htm)
- 2004.12 [pediy] [[原创]打造自己喜欢的 Ollydbg](https://bbs.pediy.com/thread-7901.htm)
- 2004.11 [pediy] [用Ollydbg手脱PECompact双层加壳的DLL －－Psinthk.dll](https://bbs.pediy.com/thread-7609.htm)
- 2004.11 [pediy] [OllyDbg的help-怎样开始调试（翻译）](https://bbs.pediy.com/thread-7289.htm)
- 2004.11 [pediy] [用Ollydbg手脱Softlocx V5.0.0.6加壳的OCX](https://bbs.pediy.com/thread-6881.htm)
- 2004.10 [pediy] [用Ollydbg手脱Visual Protect V3.54加壳的DLL](https://bbs.pediy.com/thread-6365.htm)
- 2004.10 [pediy] [用OllyDbg手动脱DLL的tELock变形壳](https://bbs.pediy.com/thread-6298.htm)
- 2004.10 [pediy] [用OllyDbg 1.10 手脱 chap708.exe之Mission Impassable?](https://bbs.pediy.com/thread-5564.htm)
- 2004.08 [pediy] [[译]The other ways to detect OllyDbg 检测OllyDbg的另类方法](https://bbs.pediy.com/thread-4013.htm)
- 2004.08 [pediy] [用Ollydbg手脱CrypKey V5.7[Stealth]加壳的DLL――CKI32h.DLL](https://bbs.pediy.com/thread-3991.htm)
- 2004.07 [pediy] [转贴:OllyDbg Debugger消息格式串处理漏洞](https://bbs.pediy.com/thread-3395.htm)
- 2004.07 [pediy] [用Ollydbg手脱EncryptPE V1.2003.5.18加壳的DLL](https://bbs.pediy.com/thread-2614.htm)
- 2004.06 [pediy] [用Ollydbg手脱 SVK Protector V1.32 加壳的DLL](https://bbs.pediy.com/thread-1823.htm)
- 2004.06 [pediy] [用Ollydbg手脱 幻影 V2.33 加壳的DLL](https://bbs.pediy.com/thread-1727.htm)
- 2004.06 [pediy] [用Ollydbg手脱tElock V0.98加壳的DLL](https://bbs.pediy.com/thread-1595.htm)
- 2004.06 [pediy] [用Ollydbg手脱ASPack加壳的DLL](https://bbs.pediy.com/thread-1561.htm)
- 2004.06 [pediy] [用Ollydbg手脱ASProtect V1.23RC4加壳的DLL](https://bbs.pediy.com/thread-1545.htm)
- 2004.06 [pediy] [用Ollydbg手脱JDPack[铁甲] V1.01加壳的DLL](https://bbs.pediy.com/thread-1519.htm)
- 2004.05 [pediy] [用Ollydbg手脱UPX加壳的DLL](https://bbs.pediy.com/thread-1484.htm)
- 2004.05 [pediy] [用Ollydbg手脱Armadillo V3.60加壳的DLL](https://bbs.pediy.com/thread-1316.htm)
- 2004.05 [pediy] [用Ollydbg手脱PECompact加壳的DLL](https://bbs.pediy.com/thread-1248.htm)
- 2004.05 [pediy] [转载: 用其它方式检查出 OllyDbg](https://bbs.pediy.com/thread-507.htm)


# <a id="0a506e6fb2252626add375f884c9095e"></a>WinDBG


***


## <a id="37eea2c2e8885eb435987ccf3f467122"></a>Plugins&&Scripts


### <a id="2ef75ae7852daa9862b2217dca252cc3"></a>Recent Add


- [**946**Star][2y] [HTML] [chybeta/software-security-learning](https://github.com/chybeta/software-security-learning) Software-Security-Learning
- [**564**Star][6m] [C#] [fremag/memoscope.net](https://github.com/fremag/memoscope.net) Dump and analyze .Net applications memory ( a gui for WinDbg and ClrMd )
- [**389**Star][2y] [C++] [swwwolf/wdbgark](https://github.com/swwwolf/wdbgark) WinDBG Anti-RootKit Extension
- [**279**Star][1m] [Py] [hugsy/defcon_27_windbg_workshop](https://github.com/hugsy/defcon_27_windbg_workshop) DEFCON 27 workshop - Modern Debugging with WinDbg Preview
- [**230**Star][9m] [C++] [microsoft/windbg-samples](https://github.com/microsoft/windbg-samples) Sample extensions, scripts, and API uses for WinDbg.
- [**190**Star][8m] [Py] [corelan/windbglib](https://github.com/corelan/windbglib) Public repository for windbglib, a wrapper around pykd.pyd (for Windbg), used by mona.py
- [**157**Star][3y] [Py] [theevilbit/exploit_generator](https://github.com/theevilbit/exploit_generator) Automated Exploit generation with WinDBG
- [**141**Star][1y] [Py] [bruce30262/twindbg](https://github.com/bruce30262/twindbg) PEDA-like debugger UI for WinDbg
- [**136**Star][27d] [C#] [chrisnas/debuggingextensions](https://github.com/chrisnas/debuggingextensions) Host of debugging-related extensions such as post-mortem tools or WinDBG extensions
- [**135**Star][5y] [C] [goldshtn/windbg-extensions](https://github.com/goldshtn/windbg-extensions) Various extensions for WinDbg
- [**123**Star][18d] [JS] [0vercl0k/windbg-scripts](https://github.com/0vercl0k/windbg-scripts) A bunch of JavaScript extensions for WinDbg.
- [**97**Star][1m] [C++] [fdiskyou/iris](https://github.com/fdiskyou/iris) WinDbg extension to display Windows process mitigations
- [**89**Star][2y] [HTML] [sam-b/windbg-plugins](https://github.com/sam-b/windbg-plugins) Any useful windbg plugins I've written.
- [**79**Star][6y] [C++] [tandasat/findpg](https://github.com/tandasat/findpg) Windbg extension to find PatchGuard pages
- [**77**Star][3y] [HTML] [szimeus/evalyzer](https://github.com/szimeus/evalyzer) Using WinDBG to tap into JavaScript and help with deobfuscation and browser exploit detection
- [**72**Star][25d] [C++] [rodneyviana/netext](https://github.com/rodneyviana/netext) WinDbg extension for data mining managed heap. It also includes commands to list http request, wcf services, WIF tokens among others
- [**69**Star][2y] [C++] [lynnux/windbg_hilight](https://github.com/lynnux/windbg_hilight) A windbg plugin to hilight text in Disassembly and Command windows. Support x86 and x64.
- [**67**Star][3m] [davidfowl/windbgcheatsheet](https://github.com/davidfowl/windbgcheatsheet) This is a cheat sheet for windbg
- [**64**Star][1y] [vagnerpilar/windbgtree](https://github.com/vagnerpilar/windbgtree) A command tree based on commands and extensions for Windows Kernel Debugging.
- [**62**Star][2m] [JS] [hugsy/windbg_js_scripts](https://github.com/hugsy/windbg_js_scripts) Toy scripts for playing with WinDbg JS API
- [**60**Star][3m] [C++] [imugee/pegasus](https://github.com/imugee/pegasus) reverse engineering extension plugin for windbg
- [**59**Star][3y] [C++] [markhc/windbg_to_c](https://github.com/markhc/windbg_to_c) Translates WinDbg "dt" structure dump to a C structure
- [**58**Star][3y] [rehints/windbg](https://github.com/rehints/windbg) 
- [**51**Star][2y] [Py] [cisco-talos/dotnet_windbg](https://github.com/cisco-talos/dotnet_windbg) 
- [**51**Star][4y] [C++] [fishstiqz/poolinfo](https://github.com/fishstiqz/poolinfo) kernel pool windbg extension
- [**50**Star][2y] [C#] [zodiacon/windbgx](https://github.com/zodiacon/windbgx) An attempt to create a friendly version of WinDbg
- [**45**Star][2y] [Py] [kukfa/bindbg](https://github.com/kukfa/bindbg) Binary Ninja plugin that syncs WinDbg to Binary Ninja
- [**45**Star][4y] [C++] [pstolarz/dumpext](https://github.com/pstolarz/dumpext) WinDbg debugger extension library providing various tools to analyse, dump and fix (restore) Microsoft Portable Executable files for both 32 (PE) and 64-bit (PE+) platforms.
- [**43**Star][3y] [C++] [andreybazhan/dbgext](https://github.com/andreybazhan/dbgext) Debugger extension for the Debugging Tools for Windows (WinDbg, KD, CDB, NTSD).
- [**43**Star][1y] [bulentrahimkazanci/windbg-cheat-sheet](https://github.com/bulentrahimkazanci/windbg-cheat-sheet) A practical guide to analyze memory dumps of .Net applications by using Windbg
- [**40**Star][11m] [C#] [kevingosse/windbg-extensions](https://github.com/kevingosse/windbg-extensions) Extensions for the new WinDbg
- [**37**Star][2y] [C] [long123king/tokenext](https://github.com/long123king/tokenext) A windbg extension, extracting token related contents
- [**34**Star][7m] [C++] [seancline/pyext](https://github.com/seancline/pyext) WinDbg Extensions for Python
- [**31**Star][3y] [osandamalith/apimon](https://github.com/osandamalith/apimon) A simple API monitor for Windbg
- [**28**Star][7y] [C++] [cr4sh/dbgcb](https://github.com/cr4sh/dbgcb) Engine for communication with remote kernel debugger (KD, WinDbg) from drivers and applications
- [**28**Star][2y] [C++] [dshikashio/pybag](https://github.com/dshikashio/pybag) CPython module for Windbg's dbgeng plus additional wrappers.
- [**28**Star][2y] [C++] [fdfalcon/typeisolationdbg](https://github.com/fdfalcon/typeisolationdbg) A little WinDbg extension to help dump the state of Win32k Type Isolation structures.
- [**28**Star][3y] [long123king/grep](https://github.com/long123king/grep) Grep-like WinDbg extension
- [**27**Star][3m] [C++] [progmboy/win32kext](https://github.com/progmboy/win32kext) windbg plugin for win32k debugging
- [**22**Star][4m] [wangray/windbg-for-gdb-users](https://github.com/wangray/windbg-for-gdb-users) "Pwntools does not support Windows. Use a real OS ;)" — Zach Riggle, 2015
- [**21**Star][5y] [stolas/windbg-darktheme](https://github.com/stolas/windbg-darktheme) A dark theme for WinDBG.
- [**21**Star][5y] [Py] [windbgscripts/pykd](https://github.com/windbgscripts/pykd) This contains Helpful PYKD (Python Extension for Windbg) scripts
- [**18**Star][3y] [Py] [ajkhoury/windbg2struct](https://github.com/ajkhoury/windbg2struct) Takes a Windbg dumped structure (using the 'dt' command) and formats it into a C structure
- [**15**Star][6y] [pccq2002/windbg](https://github.com/pccq2002/windbg) windbg open source
- [**14**Star][3y] [C] [lowleveldesign/lldext](https://github.com/lowleveldesign/lldext) LLD WinDbg extension
- [**14**Star][1y] [JS] [osrdrivers/windbg-exts](https://github.com/osrdrivers/windbg-exts) Various WinDbg extensions and scripts
- [**13**Star][3y] [C++] [evandowning/windbg-trace](https://github.com/evandowning/windbg-trace) Use WinDBG to trace the Windows API calls of any Portable Executable file
- [**12**Star][1y] [Py] [wu-wenxiang/tool-windbg-pykd-scripts](https://github.com/wu-wenxiang/tool-windbg-pykd-scripts) Pykd scripts collection for Windbg
- [**11**Star][1y] [C] [0cch/luadbg](https://github.com/0cch/luadbg) Lua Extension for Windbg
- [**11**Star][6y] [baoqi/uni-trace](https://github.com/baoqi/uni-trace) Universal Trace Debugger Engine. Currently, only support windbg on Windows, but the long term goal is to also support GDB or LLDB
- [**10**Star][1y] [C++] [jkornev/cfgdump](https://github.com/jkornev/cfgdump) Windbg extension that allows you analyze Control Flow Guard map
- [**10**Star][3y] [C] [pstolarz/asprext](https://github.com/pstolarz/asprext) ASProtect reverse engineering & analysis WinDbg extension
- [**10**Star][4y] [C] [pstolarz/scriptext](https://github.com/pstolarz/scriptext) WinDbg scripting language utilities.
- [**9**Star][2y] [C#] [indy-singh/automateddumpanalysis](https://github.com/indy-singh/automateddumpanalysis) A simple tool that helps you run common diagnostics steps instead of battling with WinDbg.
- [**8**Star][2y] [abarbatei/windbg-info](https://github.com/abarbatei/windbg-info) collection of links related to using and improving windbg
- [**7**Star][8y] [C] [pcguru34/windbgshark](https://github.com/pcguru34/windbgshark) Automatically exported from code.google.com/p/windbgshark
- [**7**Star][10m] [C#] [xquintana/dumpreport](https://github.com/xquintana/dumpreport) Console application that creates an HTML report from a Windows user-mode dump file, using WinDBG or CDB debuggers. Although it's been mainly designed for crash dump analysis of Windows applications developed in C++, it can also be used to read hang dumps or .Net dumps.
- [**6**Star][5y] [lallousx86/windbg-scripts](https://github.com/lallousx86/windbg-scripts) Windbg scripts
- [**5**Star][6y] [Py] [bannedit/windbg](https://github.com/bannedit/windbg) 
- [**5**Star][5y] [C++] [dshikashio/pywindbg](https://github.com/dshikashio/pywindbg) Python Windbg extension
- [**5**Star][2m] [repnz/windbg-cheat-sheet](https://github.com/repnz/windbg-cheat-sheet) My personal cheat sheet for using WinDbg for kernel debugging
- [**5**Star][3y] [Py] [saaramar/nl_windbg](https://github.com/saaramar/nl_windbg) Base library for Windows kernel debugging
- [**5**Star][2y] [Py] [seancline/pythonsymbols](https://github.com/seancline/pythonsymbols) A WinDbg symbol server for all recent versions of CPython.
- [**2**Star][4y] [C] [tenpoku1000/windbg_logger](https://github.com/tenpoku1000/windbg_logger) カーネルデバッグ中の Visual Studio 内蔵 WinDbg の通信内容を記録するアプリケーションとデバイスドライバです。
- [**2**Star][2y] [C++] [vincentse/watchtrees](https://github.com/vincentse/watchtrees) Debugger extension for the Windows Debugging Tools (WinDBG, KD, CDB, NTSD). It add commands to manage watches.
- [**0**Star][10m] [C++] [kevingosse/lldb-loadmanaged](https://github.com/kevingosse/lldb-loadmanaged) LLDB plugin capable of executing plugins written for WinDbg/ClrMD
- [**0**Star][9m] [C++] [lomomike/nethelps](https://github.com/lomomike/nethelps) NetHelps - WinDbg extension, helps to view some .Net internals information




***


## <a id="6d8bac8bfb5cda00c7e3bd38d64cbce3"></a>Post&&Videos


- 2019.10 [freebuf] [Iris：一款可执行常见Windows漏洞利用检测的WinDbg扩展](https://www.freebuf.com/sectool/214276.html)
- 2019.08 [lowleveldesign] [Synthetic types and tracing syscalls in WinDbg](https://lowleveldesign.org/2019/08/27/synthetic-types-and-tracing-syscalls-in-windbg/)
- 2019.08 [benoit] [Portable WinDbg](https://medium.com/p/c0087e320ddc)
- 2019.07 [osr] [How L1 Terminal Fault (L1TF) Mitigation and WinDbg Wasted My Morning (a.k.a. Yak Shaving: WinDbg Edition)](https://www.osr.com/blog/2019/07/02/how-l1-terminal-fault-l1tf-mitigation-and-windbg-wasted-my-morning-a-k-a-yak-shaving-windbg-edition/)
- 2019.06 [360] [《Dive into Windbg系列》Explorer无法启动排查](https://www.anquanke.com/post/id/179748/)
- 2019.05 [nul] [一个Windbg/cdb极其缓慢的例子](http://www.nul.pw/2019/05/21/281.html)
- 2019.04 [360] [《Dive into Windbg系列》AudioSrv音频服务故障](https://www.anquanke.com/post/id/176343/)
- 2019.04 [freebuf] [如何为WinDbg编写ClrMD插件](https://www.freebuf.com/articles/network/198951.html)
- 2019.03 [aliyun] [为WinDbg和LLDB编写ClrMD扩展](https://xz.aliyun.com/t/4459)
- 2019.03 [offensive] [Development of a new Windows 10 KASLR Bypass (in One WinDBG Command)](https://www.offensive-security.com/vulndev/development-of-a-new-windows-10-kaslr-bypass-in-one-windbg-command/)
- 2019.02 [OALabs] [WinDbg Basics for Malware Analysis](https://www.youtube.com/watch?v=QuFJpH3My7A)
- 2019.01 [TheSourceLens] [Windows Internals - Processes Part 6 of 20 -  Process related windbg commands.](https://www.youtube.com/watch?v=Hg0xcpBc6R4)
- 2019.01 [TheSourceLens] [Introduction to Windbg Series 1 Part 23 - Time travellers tracing ( IDNA )](https://www.youtube.com/watch?v=Is8mZ5kklfw)
- 2018.09 [pediy] [[原创] 《软件调试》分页机制windbg例子分析（各种填坑）](https://bbs.pediy.com/thread-246768.htm)
- 2018.08 [pediy] [[翻译]WinDbg内核调试配置方法介绍](https://bbs.pediy.com/thread-246228.htm)
- 2018.06 [pediy] [[原创]让Windbg在驱动入口前断下来](https://bbs.pediy.com/thread-228575.htm)
- 2018.05 [criteo] [Extending the new WinDbg, Part 3 – Embedding a C# interpreter](http://labs.criteo.com/2018/05/extending-new-windbg-part-3-embedding-c-interpreter/)
- 2018.04 [whereisk0shl] [Windbg logviewer.exe缓冲区溢出漏洞](http://whereisk0shl.top/post/2018-04-26)
- 2018.04 [nettitude] [WinDbg: using pykd to dump private symbols](https://labs.nettitude.com/blog/windbg-using-pykd-to-dump-private-symbols/)
- 2018.02 [comae] [YARA scans in WinDbg](https://medium.com/p/b98851bf599b)
- 2018.01 [360] [《Dive into Windbg系列》Wireshark的卡死与崩溃](https://www.anquanke.com/post/id/95427/)
- 2018.01 [criteo] [Extending the new WinDbg, Part 2 – Tool windows and command output](http://labs.criteo.com/2018/01/extending-new-windbg-part-2-tool-windows-command-output/)
- 2018.01 [biosengineer] [紀錄一下WinDbg裡面比較常用到的指令集](http://biosengineer.blogspot.com/2018/01/windbg.html)
- 2017.12 [pediy] [[原创] 实现 windbg !vad 功能  ，也可以说成是内核枚举进程模块](https://bbs.pediy.com/thread-223321.htm)
- 2017.11 [nsfocus] [windbg jsprovider.dll的一个BUG](http://blog.nsfocus.net/windbg-jsprovider-dll-bug/)
- 2017.10 [pediy] [[讨论]WinDbg、IDA下都有哪些有用、好玩的插件？](https://bbs.pediy.com/thread-222203.htm)
- 2017.10 [ixiacom] [Debugging Malware with WinDbg](https://www.ixiacom.com/company/blog/debugging-malware-windbg)
- 2017.10 [Cooper] [Hack.lu 2017 Let’s Play with WinDBG & .NET by Paul Rascagneres](https://www.youtube.com/watch?v=0mVaSm9WBRA)
- 2017.10 [360] [利用WinDbg脚本对抗反调试技术](https://www.anquanke.com/post/id/86975/)
- 2017.09 [360] [利用WinDbg本地内核调试器攻陷 Windows 内核](https://www.anquanke.com/post/id/86928/)
- 2017.09 [criteo] [Extending the new WinDbg, Part 1 – Buttons and commands](http://labs.criteo.com/2017/09/extending-new-windbg-part-1-buttons-commands/)
- 2017.08 [4hou] [利用WinDbg和wscript.exe分析JavaScript脚本](http://www.4hou.com/technology/7261.html)
- 2017.08 [360] [如何使用windbg调试javascript](https://www.anquanke.com/post/id/86638/)
- 2017.08 [pediy] [[分享]基于WinDbg调试引擎编写的调试器，支持python](https://bbs.pediy.com/thread-220422.htm)
- 2017.08 [talosintelligence] [WinDBG and JavaScript Analysis](https://blog.talosintelligence.com/2017/08/windbg-and-javascript-analysis.html)
- 2017.07 [360] [使用Windbg分析.NET恶意软件](https://www.anquanke.com/post/id/86492/)
- 2017.07 [pediy] [[分享]VirtualKD+IDA+VM+Windbg调试无PDB内核驱动](https://bbs.pediy.com/thread-219728.htm)
- 2017.07 [talosintelligence] [Unravelling .NET with the Help of WinDBG](https://blog.talosintelligence.com/2017/07/unravelling-net-with-help-of-windbg.html)
- 2017.06 [criteo] [ClrMD Part 5 – How to use ClrMD to extend SOS in WinDBG](http://labs.criteo.com/2017/06/clrmd-part-5-how-to-use-clrmd-to-extend-sos-in-windbg/)
- 2017.06 [hasherezade] [Stealing an Access Token using WinDbg](https://www.youtube.com/watch?v=0kRPMvrARyI)
- 2017.05 [pediy] [[原创]OD_WINDBG 附加功能的区别（1）- 用户层](https://bbs.pediy.com/thread-217798.htm)
- 2017.05 [osr] [WinDbg, Debugger Objects, and JavaScript! Oh, My!](https://www.osr.com/blog/2017/05/18/windbg-debugger-objects-javascript-oh/)
- 2017.03 [welivesecurity] [How to configure WinDbg for kernel debugging](https://www.welivesecurity.com/2017/03/27/configure-windbg-kernel-debugging/)
- 2017.03 [nul] [02 - Machine to Machine - 自动化WinDBG分析过程](http://www.nul.pw/2017/03/27/213.html)
- 2017.03 [venus] [WinDbg 漏洞分析调试（三）之 CVE-2014-6332](https://paper.seebug.org/240/)
- 2017.02 [GynvaelEN] [Hacking Livestream #11: Challenge! Solve a crackme using only WinDbg](https://www.youtube.com/watch?v=v0-gCQgfKyI)
- 2017.01 [venus] [WinDbg 漏洞分析调试（二）](https://paper.seebug.org/182/)
- 2017.01 [venus] [WinDbg 漏洞分析调试（一）](https://paper.seebug.org/179/)
- 2016.10 [theevilbit] [Exploit generation and JavaScript analysis automation with WinDBG](http://theevilbit.blogspot.com/2016/10/exploit-generation-and-javascript.html)
- 2016.10 [Cooper] [Hack.lu 2016 Exploit generation and JavaScript analysis automation with WinDBG](https://www.youtube.com/watch?v=d42EBkolXqY)
- 2016.09 [securityintelligence] [Fighting Fire With WinDBG: Breaking URLZone’s Anti-VM Armor](https://securityintelligence.com/fighting-fire-with-windbg-breaking-urlzones-anti-vm-armor/)
- 2016.06 [lowleveldesign] [.natvis files and type templates in WinDbg](https://lowleveldesign.org/2016/06/30/natvis-files-and-type-templates-in-windbg/)
- 2016.06 [lowleveldesign] [!injectdll – a WinDbg extension for DLL injection](https://lowleveldesign.org/2016/06/22/injectdll-a-windbg-extension-for-dll-injection/)
- 2016.06 [thembits] [Loffice - Analyzing malicious documents using WinDbg](http://thembits.blogspot.com/2016/06/loffice-analyzing-malicious-documents.html)
- 2016.05 [freebuf] [使用Windbg和Python进行堆跟踪](http://www.freebuf.com/articles/system/103816.html)
- 2016.05 [PowerShellConferenceEU] [PowerShell in WinDbg (Staffan Gustafsson)](https://www.youtube.com/watch?v=oRZ4jPijwcg)
- 2016.04 [pediy] [[原创]Windbg和IDA脚本辅助分析](https://bbs.pediy.com/thread-209718.htm)
- 2016.03 [freebuf] [使用WinDbg调试Windows内核(二)](http://www.freebuf.com/articles/network/99856.html)
- 2016.03 [freebuf] [使用WinDbg调试Windows内核(一)](http://www.freebuf.com/articles/web/99512.html)
- 2016.03 [contextis] [An Introduction to Debugging the Windows Kernel with WinDbg](https://www.contextis.com/blog/introduction-debugging-windows-kernel-windbg)
- 2016.02 [govolution] [Memdumps, Volatility, Mimikatz, VMs – Part 3: WinDBG Mimikatz Extension](https://govolution.wordpress.com/2016/02/06/memdumps-volatility-mimikatz-vms-part-3-windbg-mimikatz-extension/)
- 2016.01 [freebuf] [Windbg入门实战讲解](http://www.freebuf.com/articles/system/92499.html)
- 2015.12 [djmanilaice] [windbg - Dumping a dll from a debugged process to disk](http://djmanilaice.blogspot.com/2015/12/windbg-dumping-dll-from-debugged.html)
- 2015.10 [pediy] [[原创]Windbg跟踪临界区的bug](https://bbs.pediy.com/thread-205210.htm)
- 2015.07 [djmanilaice] [PID of debugged process in windbg](http://djmanilaice.blogspot.com/2015/07/pid-of-debugged-process-in-windbg.html)
- 2015.07 [djmanilaice] [Forgetting Windbg commands?  Too lazy to type?  Use .cmdtree in windbg!](http://djmanilaice.blogspot.com/2015/07/forgetting-windbg-commands-too-lazy-to.html)
- 2015.07 [topsec] [隐藏在windbg下面的攻防对抗](http://blog.topsec.com.cn/ad_lab/%e9%9a%90%e8%97%8f%e5%9c%a8windbg%e4%b8%8b%e9%9d%a2%e7%9a%84%e6%94%bb%e9%98%b2%e5%af%b9%e6%8a%97/)
- 2015.06 [pediy] [[原创]windbg 脚本化扩展 xcwd](https://bbs.pediy.com/thread-201704.htm)
- 2015.01 [jlospinoso] [Tools for fixing symbols issues in WinDbg](https://lospi.net/developing/kernel%20mode/operating%20systems/software/software%20engineering/windows%20internals/2015/01/12/tools-for-fixing-symbols-issues-in-windbg.html)
- 2015.01 [jlospinoso] [Tools for fixing symbols issues in WinDbg](https://lospi.net/developing/kernel%20mode/operating%20systems/software/software%20engineering/windows%20internals/2015/01/12/tools-for-fixing-symbols-issues-in-windbg.html)
- 2015.01 [jlospinoso] [Tools for fixing symbols issues in WinDbg](https://jlospinoso.github.io/developing/kernel%20mode/operating%20systems/software/software%20engineering/windows%20internals/2015/01/12/tools-for-fixing-symbols-issues-in-windbg.html)
- 2014.12 [nul] [windbg 着色](http://www.nul.pw/2014/12/13/39.html)
- 2014.11 [codemachine] [WinDBG : A rodent killer](http://codemachine.com/article_poisonivy.html)
- 2014.08 [3xp10it] [windbg命令](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2016/12/02/windbg%E5%91%BD%E4%BB%A4/)
- 2014.08 [3xp10it] [windbg命令](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2016/12/02/windbg%E5%91%BD%E4%BB%A4/)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 19 - Conditional breakpoints](https://www.youtube.com/watch?v=4_ddicRWCVY)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 17 -  Command bu or breakpoint unresolved.](https://www.youtube.com/watch?v=e8cfu_q-BJc)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 15 - Command bp for giving breakpoints](https://www.youtube.com/watch?v=I7hlZGJFjwk)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 8 -  Commands k for callstack or stackback trace](https://www.youtube.com/watch?v=chLH3ISqrcU)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 21 - Exceptions And Events](https://www.youtube.com/watch?v=xl3xPWAe0As)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 7 - Physical Machine Kernel Debugging With Network Cable](https://www.youtube.com/watch?v=-ApELUcdCUc)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 3 -  Introduction To debug Symbols](https://www.youtube.com/watch?v=y4fc7rLyBz0)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 4 - Troubleshooting Symbols mismatch](https://www.youtube.com/watch?v=md8Z33XDK-k)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 9 - Commands r for register d for dump memory.](https://www.youtube.com/watch?v=V_q341zGPxc)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 13 - Unassemble code](https://www.youtube.com/watch?v=hv4iZkZR6B0)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 5 - Introduction to debugger Commands](https://www.youtube.com/watch?v=GXxsp830Jb0)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 11 -  Command dt - dump type](https://www.youtube.com/watch?v=xzn7qQKHW1I)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 20 - miscellaneous breakpoint related commands](https://www.youtube.com/watch?v=CS54jEeGBcQ)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 18 - Command ba or break on access](https://www.youtube.com/watch?v=Psr99yABYUE)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 14 - Command s or search memory](https://www.youtube.com/watch?v=nMLGrbwGSLg)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 6 - Kernel Debugging With VmPlayer](https://www.youtube.com/watch?v=yQQLIEM6qp8)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 1 - THE Debugger](https://www.youtube.com/watch?v=8zBpqc3HkSE)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 10 - Commands dv and .frame](https://www.youtube.com/watch?v=ZaYQ6YINIpA)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 12 - Command e - edit memory](https://www.youtube.com/watch?v=4LfWru4bJ6A)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 16 -  Command bm for break point](https://www.youtube.com/watch?v=su48ewn00UU)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 2 - Different Modes Of Operations of Windbg](https://www.youtube.com/watch?v=sbRGDEexZH8)
- 2014.06 [TheSourceLens] [Introduction to Windbg Series 1 Part 22 -  Miscellaneous Commands](https://www.youtube.com/watch?v=xNGRJzoNNMA)
- 2013.12 [pediy] [[原创]如何在VS2012中编写Windbg插件](https://bbs.pediy.com/thread-182206.htm)
- 2013.10 [pediy] [[分享][笔记]现学现用之windbg的高级玩法外篇二：干掉QQProtect.sys](https://bbs.pediy.com/thread-180088.htm)
- 2013.08 [pediy] [[原创]发一个WINDBG脚本](https://bbs.pediy.com/thread-178121.htm)
- 2013.08 [yiiyee] [Windbg调试命令详解](http://www.yiiyee.cn/Blog/windbg/)
- 2013.08 [yiiyee] [Windbg中查看计算机名](http://www.yiiyee.cn/Blog/computername/)
- 2013.07 [yiiyee] [初学Windbg，从主题布局开始](http://www.yiiyee.cn/Blog/windbg-theme/)
- 2013.04 [pediy] [[原创]过TesSafe反WinDbg双机调试](https://bbs.pediy.com/thread-170342.htm)
- 2013.04 [debasish] [Fuzzing Monitoring with WinDBG Console Debugger(cdb.exe)](http://www.debasish.in/2013/04/fuzzing-monitoring-with-windbg-console.html)
- 2013.04 [pediy] [[原创]获取系统热键链表windbg脚本 GetHotkeys windbg script](https://bbs.pediy.com/thread-167645.htm)
- 2013.04 [pediy] [[原创]利用 windbg 脚本动态调试代码](https://bbs.pediy.com/thread-167644.htm)
- 2013.03 [pediy] [[分享][下载]windbg的python扩展插件PYKD 0.2.0.19 (2013.3.28)](https://bbs.pediy.com/thread-167203.htm)
- 2013.01 [corelan] [Heap Layout Visualization with mona.py and WinDBG](https://www.corelan.be/index.php/2013/01/18/heap-layout-visualization-with-mona-py-and-windbg/)
- 2012.08 [pediy] [[分享]Windbg的各种符号服务器](https://bbs.pediy.com/thread-154231.htm)
- 2012.05 [pediy] [[原创]windbg查看E.KTHREAD,E.KPROCESS](https://bbs.pediy.com/thread-150274.htm)
- 2012.04 [pediy] [[原创]windbg下断辅助](https://bbs.pediy.com/thread-149361.htm)
- 2012.03 [toolswatch] [Blackhat Amsterdam 2012 : ToolsTube with Andrey Labunets on Windbgshark](http://www.toolswatch.org/2012/03/blackhat-amsterdam-2012-toolstube-with-andrey-labunets-on-windbgshark/)
- 2012.03 [toolswatch] [WinDBGShark v0.2.3 (Black Hat EU 2012 Edition) Released](http://www.toolswatch.org/2012/03/windbgshark-v0-2-3-black-hat-eu-2012-edition-released/)
- 2011.11 [pediy] [[原创]利用windbg脚本调试简单实例](https://bbs.pediy.com/thread-142841.htm)
- 2011.09 [pediy] [[原创]编写脚本增强windbg堆栈、内存窗口[有码有真相啊]](https://bbs.pediy.com/thread-139816.htm)
- 2011.07 [pediy] [[原创]再发几个好东西，windbg可编译源码](https://bbs.pediy.com/thread-137731.htm)
- 2011.05 [pediy] [[求助]HS+TMD 环境下怎么Windbg双机调试...](https://bbs.pediy.com/thread-133538.htm)
- 2010.11 [pediy] [[原创]小技巧大用处，让WINDBG跑起来](https://bbs.pediy.com/thread-125358.htm)
- 2010.10 [redplait] [windbg & rpc](http://redplait.blogspot.com/2010/10/windbg-rpc.html)
- 2010.08 [mattoh] [Dumping Kernel Service Table from Windbg](https://mattoh.wordpress.com/2010/08/06/dumping-kernel-service-table-from-windbg/)
- 2010.08 [mattoh] [Setting breakpoint on entry point with Windbg](https://mattoh.wordpress.com/2010/08/06/setting-breakpoint-on-entry-poin-with-windbg/)
- 2009.12 [pediy] [[求助]更新WINDBG 调试SYS 文件误用 INITCODE添加代码与图片](https://bbs.pediy.com/thread-102400.htm)
- 2009.07 [pediy] [[原创]WinDbg学习笔记（一）--认识WinDbg](https://bbs.pediy.com/thread-94457.htm)
- 2009.07 [pediy] [[原创]WinDbg学习笔记（二）--字符串访问断点](https://bbs.pediy.com/thread-94326.htm)
- 2009.01 [pediy] [[原创]winxp+vpc2007+win2003sp1+windbg](https://bbs.pediy.com/thread-80082.htm)
- 2008.12 [pediy] [[原创]Windows调试工具入门4 - WinDbg内核调试配置](https://bbs.pediy.com/thread-78912.htm)
- 2008.11 [kobyk] [Windbg 6.10.3.233 released](https://kobyk.wordpress.com/2008/11/21/windbg-6103233-released/)
- 2008.10 [pediy] [用 WinDbg 内核调试查找隐藏进程](https://bbs.pediy.com/thread-75698.htm)
- 2008.08 [rapid7] [Improved WinDBG opcode searching](https://blog.rapid7.com/2008/08/25/improved-windbg-opcode-searching/)
- 2008.08 [rapid7] [Byakugan WinDBG Plugin Released!](https://blog.rapid7.com/2008/08/20/byakugan-windbg-plugin-released/)
- 2008.06 [pediy] [[原创]Make a Windbg By Yourself(一)](https://bbs.pediy.com/thread-66218.htm)
- 2008.05 [pediy] [[原创]斗胆发一个辅助使用WinDbg获得内核数据结构的小工具](https://bbs.pediy.com/thread-65415.htm)
- 2008.05 [evilcodecave] [Disabling VS JIT and Prepairing WinDBG for Unknown Exceptions](https://evilcodecave.wordpress.com/2008/05/22/disabling-vs-jit-and-preparing-windbg-for-unknown-exceptions/)
- 2008.05 [kobyk] [Windbg 6.9.3.113 released](https://kobyk.wordpress.com/2008/05/03/windbg-693113-released/)
- 2008.05 [biosengineer] [WinDbg 查看Log](http://biosengineer.blogspot.com/2008/05/windbglog-stop-0x000000d1-0x00000080.html)
- 2007.08 [kobyk] [Windbg’s integrated managed debugging – an accidental feature?](https://kobyk.wordpress.com/2007/08/11/windbgs-integrated-managed-debugging-an-accidental-feature/)
- 2007.07 [kobyk] [How about some Windbg love?](https://kobyk.wordpress.com/2007/07/14/how-about-some-windbg-love/)
- 2007.06 [pediy] [[技巧]在 WinDbg 脚本中使用参数](https://bbs.pediy.com/thread-46016.htm)
- 2007.05 [pediy] [[分享]方便的 windbg 命令 - !list](https://bbs.pediy.com/thread-43835.htm)
- 2007.01 [pediy] [WinDbg插件编写――基础篇](https://bbs.pediy.com/thread-38729.htm)
- 2007.01 [pediy] [几个常用的 WinDbg 命令](https://bbs.pediy.com/thread-38641.htm)
- 2006.12 [pediy] [[翻译]Kernel Debugging with WinDbg](https://bbs.pediy.com/thread-36186.htm)
- 2006.12 [pediy] [WinDBG双机调试之Vista Boot Config 设置,高手勿进.](https://bbs.pediy.com/thread-36107.htm)
- 2006.11 [pediy] [[原创]Windbg核心调试之dump分析](https://bbs.pediy.com/thread-35044.htm)
- 2006.11 [pediy] [Windbg基本调试技术](https://bbs.pediy.com/thread-34958.htm)
- 2006.11 [pediy] [[原创]使用WinDBG进行双机内核调试](https://bbs.pediy.com/thread-34731.htm)
- 2006.10 [pediy] [写了个小的 WinDbg 脚本，可以显示 SSDT](https://bbs.pediy.com/thread-34018.htm)
- 2006.10 [pediy] [WinDbg 帮助文档翻译 - 数值表达式语法](https://bbs.pediy.com/thread-33989.htm)
- 2006.10 [pediy] [[原创]WINDBG Script简易教程{看雪学院2006金秋读书季}](https://bbs.pediy.com/thread-33663.htm)
- 2006.10 [pediy] [[分享]关于windbg进行双机调试的一些资料](https://bbs.pediy.com/thread-33178.htm)
- 2006.04 [pediy] [翻译：通往WinDbg的捷径（二）](https://bbs.pediy.com/thread-24119.htm)
- 2006.04 [pediy] [翻译：通往WinDbg的捷径（一）](https://bbs.pediy.com/thread-24077.htm)
- 2006.02 [debuginfo] [WinDbg the easy way](http://debuginfo.com/articles/easywindbg.html)
- 2006.02 [pediy] [[原创]用WinDbg动态脱Reflector](https://bbs.pediy.com/thread-20953.htm)


# <a id="11a59671b467a8cdbdd4ea9d5e5d9b51"></a>Android


***


## <a id="2110ded2aa5637fa933cc674bc33bf21"></a>Tools


### <a id="63fd2c592145914e99f837cecdc5a67c"></a>Recent Add


- [**6101**Star][3m] [Java] [google/android-classyshark](https://github.com/google/android-classyshark) Analyze any Android/Java based app or game
- [**6094**Star][5m] [Java] [qihoo360/replugin](https://github.com/qihoo360/replugin) RePlugin - A flexible, stable, easy-to-use Android Plug-in Framework
- [**5195**Star][19d] [Py] [mobsf/mobile-security-framework-mobsf](https://github.com/MobSF/Mobile-Security-Framework-MobSF) Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.
- [**5084**Star][15d] [HTML] [owasp/owasp-mstg](https://github.com/owasp/owasp-mstg) The Mobile Security Testing Guide (MSTG) is a comprehensive manual for mobile app security development, testing and reverse engineering.
- [**4882**Star][24d] [Java] [guardianproject/haven](https://github.com/guardianproject/haven) Haven is for people who need a way to protect their personal spaces and possessions without compromising their own privacy, through an Android app and on-device sensors
- [**4776**Star][12d] [C++] [facebook/redex](https://github.com/facebook/redex) A bytecode optimizer for Android apps
- [**4306**Star][15d] [Shell] [ashishb/android-security-awesome](https://github.com/ashishb/android-security-awesome) A collection of android security related resources
- [**3649**Star][2m] [C++] [anbox/anbox](https://github.com/anbox/anbox)  a container-based approach to boot a full Android system on a regular GNU/Linux system
- [**2314**Star][1y] [Java] [csploit/android](https://github.com/csploit/android) cSploit - The most complete and advanced IT security professional toolkit on Android.
- [**2120**Star][9m] [Py] [linkedin/qark](https://github.com/linkedin/qark) Tool to look for several security related Android application vulnerabilities
- [**2095**Star][10m] [jermic/android-crack-tool](https://github.com/jermic/android-crack-tool) 
- [**2051**Star][21d] [Py] [sensepost/objection](https://github.com/sensepost/objection)  runtimemobile exploration
- [**2011**Star][8m] [Py] [fsecurelabs/drozer](https://github.com/FSecureLABS/drozer) The Leading Security Assessment Framework for Android.
- [**1976**Star][9d] [Java] [kyson/androidgodeye](https://github.com/kyson/androidgodeye) AndroidGodEye:A performance monitor tool , like "Android Studio profiler" for Android , you can easily monitor the performance of your app real time in pc browser
- [**1925**Star][7m] [Java] [fuzion24/justtrustme](https://github.com/fuzion24/justtrustme) An xposed module that disables SSL certificate checking for the purposes of auditing an app with cert pinning
- [**1430**Star][11m] [Java] [aslody/legend](https://github.com/aslody/legend) A framework for hook java methods.
- [**1417**Star][1m] [Java] [chrisk44/hijacker](https://github.com/chrisk44/hijacker) Aircrack, Airodump, Aireplay, MDK3 and Reaver GUI Application for Android
- [**1366**Star][3y] [C++] [aslody/turbodex](https://github.com/aslody/turbodex) fast load dex in memory.
- [**1241**Star][3m] [Java] [whataa/pandora](https://github.com/whataa/pandora) an android library for debugging what we care about directly in app.
- [**1235**Star][2m] [Java] [find-sec-bugs/find-sec-bugs](https://github.com/find-sec-bugs/find-sec-bugs) The SpotBugs plugin for security audits of Java web applications and Android applications. (Also work with Kotlin, Groovy and Scala projects)
- [**1213**Star][2m] [JS] [megatronking/httpcanary](https://github.com/megatronking/httpcanary) A powerful capture and injection tool for the Android platform
- [**1208**Star][4m] [Java] [javiersantos/piracychecker](https://github.com/javiersantos/piracychecker) An Android library that prevents your app from being pirated / cracked using Google Play Licensing (LVL), APK signature protection and more. API 14+ required.
- [**1134**Star][1m] [Java] [huangyz0918/androidwm](https://github.com/huangyz0918/androidwm) An android image watermark library that supports invisible digital watermarks (steganography).
- [**968**Star][3y] [Java] [androidvts/android-vts](https://github.com/androidvts/android-vts) Android Vulnerability Test Suite - In the spirit of open data collection, and with the help of the community, let's take a pulse on the state of Android security. NowSecure presents an on-device app to test for recent device vulnerabilities.
- [**920**Star][7y] [designativedave/androrat](https://github.com/designativedave/androrat) Remote Administration Tool for Android devices
- [**903**Star][5y] [Java] [wszf/androrat](https://github.com/wszf/androrat) Remote Administration Tool for Android
- [**885**Star][2m] [C] [504ensicslabs/lime](https://github.com/504ensicslabs/lime) LiME (formerly DMD) is a Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, such as those powered by Android. The tool supports acquiring memory either to the file system of the device or over the network. LiME is unique in that it is the first tool that allows full memory captures f…
- [**833**Star][6y] [C] [madeye/gaeproxy](https://github.com/madeye/gaeproxy) GAEProxy for Android (Deprecated)
- [**820**Star][11d] [proxymanapp/proxyman](https://github.com/proxymanapp/proxyman) Modern and Delightful HTTP Debugging Proxy for macOS, iOS and Android
- [**810**Star][4m] [Scala] [antox/antox](https://github.com/antox/antox) Android client for Project Tox - Secure Peer to Peer Messaging
- [**800**Star][3m] [sh4hin/androl4b](https://github.com/sh4hin/androl4b) A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis
- [**769**Star][1y] [C] [ele7enxxh/android-inline-hook](https://github.com/ele7enxxh/android-inline-hook) thumb16 thumb32 arm32 inlineHook in Android
- [**735**Star][2y] [Java] [gcssloop/encrypt](https://github.com/gcssloop/encrypt) [暂停维护]Android 加密解密工具包。
- [**708**Star][4y] [Py] [androbugs/androbugs_framework](https://github.com/androbugs/androbugs_framework) AndroBugs Framework is an efficient Android vulnerability scanner that helps developers or hackers find potential security vulnerabilities in Android applications. No need to install on Windows.
- [**668**Star][2m] [doridori/android-security-reference](https://github.com/doridori/android-security-reference) A W.I.P Android Security Ref
- [**666**Star][7y] [Java] [honeynet/apkinspector](https://github.com/honeynet/apkinspector) APKinspector is a powerful GUI tool for analysts to analyze the Android applications.
- [**608**Star][7m] [JS] [vincentcox/stacoan](https://github.com/vincentcox/stacoan) StaCoAn is a crossplatform tool which aids developers, bugbounty hunters and ethical hackers performing static code analysis on mobile applications.
- [**585**Star][2y] [Java] [hypertrack/hyperlog-android](https://github.com/hypertrack/hyperlog-android) Utility logger library for storing logs into database and push them to remote server for debugging
- [**559**Star][14d] [Shell] [owasp/owasp-masvs](https://github.com/owasp/owasp-masvs) The Mobile Application Security Verification Standard (MASVS) is a standard for mobile app security.
- [**546**Star][2m] [nordicsemiconductor/android-nrf-connect](https://github.com/nordicsemiconductor/android-nrf-connect) Documentation and issue tracker for nRF Connect for Android.
- [**541**Star][1y] [Java] [jaredrummler/apkparser](https://github.com/jaredrummler/apkparser) APK parser for Android
- [**540**Star][7y] [Java] [moxie0/androidpinning](https://github.com/moxie0/androidpinning) A standalone library project for certificate pinning on Android.
- [**527**Star][4m] [JS] [wooyundota/droidsslunpinning](https://github.com/wooyundota/droidsslunpinning) Android certificate pinning disable tools
- [**518**Star][4m] [Java] [megatronking/stringfog](https://github.com/megatronking/stringfog) 一款自动对字节码中的字符串进行加密Android插件工具
- [**511**Star][9d] [Java] [happylishang/cacheemulatorchecker](https://github.com/happylishang/cacheemulatorchecker) Android模拟器检测，检测Android模拟器 ，获取相对真实的IMEI AndroidId 序列号 MAC地址等，作为DeviceID，应对防刷需求等
- [**488**Star][2y] [b-mueller/android_app_security_checklist](https://github.com/b-mueller/android_app_security_checklist) Android App Security Checklist
- [**482**Star][2m] [JS] [lyxhh/lxhtoolhttpdecrypt](https://github.com/lyxhh/lxhtoolhttpdecrypt) Simple Android/iOS protocol analysis and utilization tool
- [**471**Star][2y] [Smali] [sensepost/kwetza](https://github.com/sensepost/kwetza) Python script to inject existing Android applications with a Meterpreter payload.
- [**451**Star][3y] [C++] [vusec/drammer](https://github.com/vusec/drammer) Native binary for testing Android phones for the Rowhammer bug
- [**450**Star][12m] [Kotlin] [shadowsocks/kcptun-android](https://github.com/shadowsocks/kcptun-android) kcptun for Android.
- [**443**Star][1m] [TS] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
- [**431**Star][13d] [C] [guardianproject/orbot](https://github.com/guardianproject/orbot) The Github home of Orbot: Tor on Android (Also available on gitlab!)
- [**426**Star][19d] [Py] [thehackingsage/hacktronian](https://github.com/thehackingsage/hacktronian) All in One Hacking Tool for Linux & Android
- [**412**Star][4m] [Java] [megatronking/netbare](https://github.com/megatronking/netbare) Net packets capture & injection library designed for Android
- [**411**Star][3y] [Java] [fourbrother/kstools](https://github.com/fourbrother/kstools) Android中自动爆破签名工具
- [**409**Star][3m] [CSS] [angea/pocorgtfo](https://github.com/angea/pocorgtfo) a "Proof of Concept or GTFO" mirror with extra article index, direct links and clean PDFs.
- [**408**Star][1y] [Java] [testwhat/smaliex](https://github.com/testwhat/smaliex) A wrapper to get de-optimized dex from odex/oat/vdex.
- [**405**Star][3y] [Java] [ac-pm/sslunpinning_xposed](https://github.com/ac-pm/sslunpinning_xposed) Android Xposed Module to bypass SSL certificate validation (Certificate Pinning).
- [**403**Star][6y] [Java] [isecpartners/introspy-android](https://github.com/isecpartners/introspy-android) Security profiling for blackbox Android
- [**397**Star][2y] [Java] [routerkeygen/routerkeygenandroid](https://github.com/routerkeygen/routerkeygenandroid) Router Keygen generate default WPA/WEP keys for several routers.
- [**382**Star][2y] [Java] [davidbuchanan314/nxloader](https://github.com/davidbuchanan314/nxloader) My first Android app: Launch Fusée Gelée payloads from stock Android (CVE-2018-6242)
- [**379**Star][6m] [Makefile] [crifan/android_app_security_crack](https://github.com/crifan/android_app_security_crack) 安卓应用的安全和破解
- [**379**Star][1y] [CSS] [nowsecure/secure-mobile-development](https://github.com/nowsecure/secure-mobile-development) A Collection of Secure Mobile Development Best Practices
- [**378**Star][2y] [Java] [jaredrummler/androidshell](https://github.com/jaredrummler/androidshell) Execute shell commands on Android.
- [**373**Star][3y] [Py] [androidhooker/hooker](https://github.com/androidhooker/hooker) Hooker is an opensource project for dynamic analyses of Android applications. This project provides various tools and applications that can be use to automaticaly intercept and modify any API calls made by a targeted application.
- [**358**Star][5m] [b3nac/android-reports-and-resources](https://github.com/b3nac/android-reports-and-resources) A big list of Android Hackerone disclosed reports and other resources.
- [**358**Star][5m] [C] [the-cracker-technology/andrax-mobile-pentest](https://github.com/the-cracker-technology/andrax-mobile-pentest) ANDRAX The first and unique Penetration Testing platform for Android smartphones
- [**353**Star][3y] [ObjC] [naituw/hackingfacebook](https://github.com/naituw/hackingfacebook) Kill Facebook for iOS's SSL Pinning
- [**333**Star][25d] [Java] [datatheorem/trustkit-android](https://github.com/datatheorem/trustkit-android) Easy SSL pinning validation and reporting for Android.
- [**323**Star][2y] [Kotlin] [ollide/intellij-java2smali](https://github.com/ollide/intellij-java2smali) A plugin for IntelliJ IDEA & Android Studio to easily compile Java & Kotlin files to smali.
- [**287**Star][1y] [C] [freakishfox/xanso](https://github.com/freakishfox/xanso) Android So文件浏览修复工具
- [**285**Star][2y] [Java] [simbiose/encryption](https://github.com/simbiose/encryption) Encryption is a simple way to encrypt and decrypt strings on Android and Java project.
- [**284**Star][9m] [Py] [micropyramid/forex-python](https://github.com/micropyramid/forex-python) Foreign exchange rates, Bitcoin price index and currency conversion using ratesapi.io
- [**282**Star][4y] [Py] [fuzzing/mffa](https://github.com/fuzzing/mffa) Media Fuzzing Framework for Android
- [**274**Star][2y] [Java] [mateuszk87/badintent](https://github.com/mateuszk87/badintent) Intercept, modify, repeat and attack Android's Binder transactions using Burp Suite
- [**270**Star][2y] [Java] [reoky/android-crackme-challenge](https://github.com/reoky/android-crackme-challenge) A collection of reverse engineering challenges for learning about the Android operating system and mobile security.
- [**267**Star][4m] [Py] [amimo/dcc](https://github.com/amimo/dcc) DCC (Dex-to-C Compiler) is method-based aot compiler that can translate DEX code to C code.
- [**267**Star][4y] [C] [samsung/adbi](https://github.com/samsung/adbi) Android Dynamic Binary Instrumentation tool for tracing Android native layer
- [**267**Star][2y] [Kotlin] [temyco/security-workshop-sample](https://github.com/temyco/security-workshop-sample) This repository has been desired to show different Android Security Approach implementations using a simple sample project.
- [**265**Star][11d] [Py] [den4uk/andriller](https://github.com/den4uk/andriller) a collection of forensic tools for smartphones
- [**262**Star][2y] [Java] [maxcamillo/android-keystore-password-recover](https://github.com/maxcamillo/android-keystore-password-recover) Automatically exported from code.google.com/p/android-keystore-password-recover
- [**258**Star][3y] [Java] [flankerhqd/jaadas](https://github.com/flankerhqd/jaadas) Joint Advanced Defect assEsment for android applications
- [**258**Star][7y] [Java] [isecpartners/android-ssl-bypass](https://github.com/isecpartners/android-ssl-bypass) Black box tool to bypass SSL verification on Android, even when pinning is used.
- [**256**Star][3y] [C] [w-shackleton/android-netspoof](https://github.com/w-shackleton/android-netspoof) Network Spoofer
- [**254**Star][2y] [Java] [panhongwei/tracereader](https://github.com/panhongwei/tracereader) android小工具，通过读取trace文件，回溯整个整个程序执行调用树。
- [**251**Star][10m] [C] [chef-koch/android-vulnerabilities-overview](https://github.com/chef-koch/android-vulnerabilities-overview) An small overview of known Android vulnerabilities
- [**234**Star][3m] [C] [grant-h/qu1ckr00t](https://github.com/grant-h/qu1ckr00t) A PoC application demonstrating the power of an Android kernel arbitrary R/W.
- [**234**Star][1y] [Ruby] [hahwul/droid-hunter](https://github.com/hahwul/droid-hunter) (deprecated) Android application vulnerability analysis and Android pentest tool
- [**229**Star][8m] [Java] [jieyushi/luffy](https://github.com/jieyushi/luffy) Android字节码插件，编译期间动态修改代码，改造添加全埋点日志采集功能模块，对常见控件进行监听处理
- [**225**Star][3m] [Java] [virb3/trustmealready](https://github.com/virb3/trustmealready) Disable SSL verification and pinning on Android, system-wide
- [**208**Star][26d] [C] [derrekr/fastboot3ds](https://github.com/derrekr/fastboot3ds) A homebrew bootloader for the Nintendo 3DS that is similar to android's fastboot.
- [**202**Star][1y] [C#] [labo89/adbgui](https://github.com/labo89/adbgui) Wrapper for Android Debug Bridge (ADB) written in C#
- [**200**Star][2y] [Java] [ernw/androtickler](https://github.com/ernw/androtickler) Penetration testing and auditing toolkit for Android apps.
- [**194**Star][2y] [Java] [panhongwei/androidmethodhook](https://github.com/panhongwei/androidmethodhook) android art hook like Sophix
- [**183**Star][2y] [Smali] [sslab-gatech/avpass](https://github.com/sslab-gatech/avpass) Tool for leaking and bypassing Android malware detection system
- [**180**Star][3y] [C] [kriswebdev/android_aircrack](https://github.com/kriswebdev/android_aircrack) Aircrack-ng command-line for Android. Binaries & source.
- [**173**Star][2m] [Java] [calebfenton/apkfile](https://github.com/calebfenton/apkfile) Android app analysis and feature extraction library
- [**173**Star][7y] [Py] [trivio/common_crawl_index](https://github.com/trivio/common_crawl_index) billions of pages randomly crawled from the internet
- [**170**Star][10m] [thehackingsage/hackdroid](https://github.com/thehackingsage/hackdroid) Penetration Testing Apps for Android
- [**167**Star][24d] [Java] [pwittchen/reactivewifi](https://github.com/pwittchen/reactivewifi) Android library listening available WiFi Access Points and related information with RxJava Observables
- [**161**Star][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->Specific Target->Loader](#cb59d84840e41330a7b5e275c0b81725) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**161**Star][1y] [Java] [iqiyi/dexsplitter](https://github.com/iqiyi/dexsplitter) Analyze contribution rate of each module to the apk size
- [**160**Star][10m] [Py] [sch3m4/androidpatternlock](https://github.com/sch3m4/androidpatternlock) A little Python tool to crack the Pattern Lock on Android devices
- [**160**Star][4y] [Py] [appknox/afe](https://github.com/appknox/AFE) Android Framework for Exploitation, is a framework for exploiting android based devices
- [**158**Star][3y] [Java] [googlecloudplatform/endpoints-codelab-android](https://github.com/googlecloudplatform/endpoints-codelab-android) endpoints-codelab-android
- [**146**Star][4m] [PostScript] [guardianproject/orfox](https://github.com/guardianproject/orfox) UPDATE: Orfox is being replaced by Tor Browser for Android. All future work and comments will be handled by Tor Project.
- [**145**Star][3y] [Java] [zhouat/inject-hook](https://github.com/zhouat/inject-hook) for android
- [**142**Star][3m] [Py] [technicaldada/hackerpro](https://github.com/technicaldada/hackerpro) All in One Hacking Tool for Linux & Android (Termux). Hackers are welcome in our blog
- [**140**Star][4m] [Shell] [izzysoft/adebar](https://github.com/izzysoft/adebar) Android DEvice Backup And Report, using Bash and ADB
- [**137**Star][2y] [Java] [gnaixx/hidex-hack](https://github.com/gnaixx/hidex-hack) anti reverse by hack dex file
- [**137**Star][3y] [Java] [ysrc/anti-emulator](https://github.com/ysrc/anti-emulator) 基于文件特征的Android模拟器检测
- [**133**Star][3y] [C++] [chenenyu/androidsecurity](https://github.com/chenenyu/androidsecurity) Android安全实践
- [**130**Star][1y] [Java] [florent37/rxlifecycle](https://github.com/florent37/rxlifecycle) Rx binding of stock Android Activities & Fragment Lifecycle, avoiding memory leak
- [**130**Star][2m] [pouyadarabi/instagram_ssl_pinning](https://github.com/pouyadarabi/instagram_ssl_pinning) Bypassing SSL Pinning in Instagram Android App
- [**127**Star][4y] [C++] [chago/advmp](https://github.com/chago/advmp) 大自然的搬运工-Android虚拟机保护Demo
- [**125**Star][5y] [Ruby] [mttkay/replicant](https://github.com/mttkay/replicant) A REPL for the Android Debug Bridge (ADB)
- [**124**Star][2y] [Shell] [nccgroup/lazydroid](https://github.com/nccgroup/lazydroid) bash script to facilitate some aspects of an Android application assessment
- [**123**Star][5y] [jacobsoo/androidslides](https://github.com/jacobsoo/androidslides) 
- [**122**Star][3m] [Java] [aaronjwood/portauthority](https://github.com/aaronjwood/portauthority) A handy systems and security-focused tool, Port Authority is a very fast Android port scanner. Port Authority also allows you to quickly discover hosts on your network and will display useful network information about your device and other hosts.
- [**116**Star][1y] [C++] [melonwxd/elfhooker](https://github.com/melonwxd/elfhooker) 兼容Android 32位和64位。基于EFL文件格式Hook的demo，hook了SurfaceFlinger进程的eglSwapBuffers函数，替换为new_eglSwapBuffers
- [**114**Star][1m] [Java] [stringcare/androidlibrary](https://github.com/stringcare/androidlibrary) Android library to reveal or obfuscate strings and assets at runtime
- [**114**Star][2y] [wpvsyou/mprop](https://github.com/wpvsyou/mprop) 修改Android prop脚本工具
- [**113**Star][2y] [Py] [fsecurelabs/drozer-modules](https://github.com/FSecureLABS/drozer-modules) leading security testing framework for Android.
- [**112**Star][4y] [Py] [androidsecuritytools/lobotomy](https://github.com/androidsecuritytools/lobotomy) Android Security Toolkit
- [**108**Star][5y] [Py] [mspreitz/adel](https://github.com/mspreitz/adel) dumps all important SQLite Databases from a connected Android smartphone to the local disk and analyzes these files in a forensically accurate workflow
- [**104**Star][4m] [JS] [adelphes/android-dev-ext](https://github.com/adelphes/android-dev-ext) Android debugging support for VS Code
- [**104**Star][2y] [Kotlin] [heimashi/debug_view_kotlin](https://github.com/heimashi/debug_view_kotlin) 用kotlin实现的Android浮层调试控制台，实时的显示内存、FPS、文字log、app启动时间、Activity启动时间
- [**102**Star][6m] [Py] [vmavromatis/absolutely-proprietary](https://github.com/vmavromatis/absolutely-proprietary) Proprietary package detector for arch-based distros. Compares your installed packages against Parabola's package blacklist and then prints your Stallman Freedom Index (free/total).
- [**101**Star][9m] [Py] [zsdlove/apkvulcheck](https://github.com/zsdlove/apkvulcheck) This is a tool to help androidcoder to check the flaws in their projects.
- [**99**Star][4y] [Java] [odrin/droid-watcher](https://github.com/odrin/droid-watcher) [OUTDATED & UNSUPPORTED] Droid Watcher - Android Spy Application
- [**95**Star][4y] [Shell] [jlrodriguezf/whatspwn](https://github.com/jlrodriguezf/whatspwn) Linux tool used to extract sensitive data, inject backdoor or drop remote shells on android devices.
- [**94**Star][2y] [C++] [woxihuannisja/stormhook](https://github.com/woxihuannisja/stormhook) StormHook is a Android Hook Framework for Dalvik and Art
- [**93**Star][2y] [C++] [femto-dev/femto](https://github.com/femto-dev/femto) Sequence Indexing and Search
- [**93**Star][1y] [Py] [integrity-sa/droidstatx](https://github.com/integrity-sa/droidstatx) Python tool that generates an Xmind map with all the information gathered and any evidence of possible vulnerabilities identified via static analysis. The map itself is an Android Application Pentesting Methodology component, which assists Pentesters to cover all important areas during an assessment.
- [**90**Star][4y] [C] [rchiossi/dexterity](https://github.com/rchiossi/dexterity) Dex manipulation library
- [**90**Star][8m] [JS] [adonespitogo/adobot-io](https://github.com/adonespitogo/adobot-io) Android Spyware Server
- [**89**Star][2m] [pouyadarabi/facebook_ssl_pinning](https://github.com/pouyadarabi/facebook_ssl_pinning) Bypassing SSL Pinning in Facebook Android App
- [**87**Star][4y] [Py] [necst/aamo](https://github.com/necst/aamo) AAMO: Another Android Malware Obfuscator
- [**86**Star][5y] [Java] [sysdream/fino](https://github.com/sysdream/fino) Android small footprint inspection tool
- [**85**Star][2m] [Java] [rikkaapps/wadb](https://github.com/rikkaapps/wadb) A simple switch for adb (Android Debug Bridge) over network.
- [**83**Star][1y] [Kotlin] [pvasa/easycrypt](https://github.com/pvasa/easycrypt) Android cryptography library with SecureRandom patches.
- [**81**Star][2m] [Kotlin] [linkedin/dex-test-parser](https://github.com/linkedin/dex-test-parser) Find all test methods in an Android instrumentation APK
- [**79**Star][3y] [Py] [dancezarp/tbdex](https://github.com/dancezarp/tbdex) 
- [**76**Star][11d] [Py] [tp7309/ttdedroid](https://github.com/tp7309/ttdedroid) 一键反编译工具One key for quickly decompile apk/aar/dex/jar, support by jadx/dex2jar/enjarify/cfr.
- [**74**Star][3y] [wtsxdev/android-security-list](https://github.com/wtsxdev/android-security-list) Collection of Android security related resources
- [**73**Star][11d] [jawz101/mobileadtrackers](https://github.com/jawz101/mobileadtrackers) Taken from DNS logs while actively using Android apps over the years. Formatted in hostfile format.
- [**70**Star][2y] [Java] [yolosec/routerkeygenandroid](https://github.com/yolosec/routerkeygenandroid) Router Keygen generate default WPA/WEP keys for several routers.
- [**69**Star][2y] [Kotlin] [menjoo/android-ssl-pinning-webviews](https://github.com/menjoo/android-ssl-pinning-webviews) A simple demo app that demonstrates Certificate pinning and scheme/domain whitelisting in Android WebViews
- [**68**Star][1y] [Java] [fooock/phone-tracker](https://github.com/fooock/phone-tracker) Phone tracker is an Android library to gather environment signals, like cell towers, wifi access points and gps locations.
- [**66**Star][3y] [Py] [crange/crange](https://github.com/crange/crange) Crange is a tool to index and cross-reference C/C++ source code
- [**66**Star][3y] [Java] [fsecurelabs/drozer-agent](https://github.com/FSecureLABS/drozer-agent) The Android Agent for the Mercury Security Assessment Framework.
- [**65**Star][1y] [Py] [cryptax/dextools](https://github.com/cryptax/dextools) Miscellaenous DEX (Dalvik Executable) tools
- [**65**Star][2y] [Java] [isacan/andzu](https://github.com/isacan/andzu) In-App Android Debugging Tool With Enhanced Logging, Networking Info, Crash reporting And More.
- [**63**Star][4y] [Java] [ac-pm/proxyon](https://github.com/ac-pm/proxyon) Android Xposed Module to apply proxy for a specific app.
- [**63**Star][28d] [Py] [meituan-dianping/lyrebird-android](https://github.com/meituan-dianping/lyrebird-android) 本程序是一个Lyrebird的插件，用于支持获取Android设备信息。
- [**62**Star][1y] [pfalcon/awesome-linux-android-hacking](https://github.com/pfalcon/awesome-linux-android-hacking) List of hints and Q&As to get most of your Linux/Android device
- [**61**Star][7m] [Java] [ajnas/wifips](https://github.com/ajnas/wifips) WiFi Based Indoor Positioning System, A MVP android Application
- [**61**Star][6y] [Java] [isecpartners/android-killpermandsigchecks](https://github.com/isecpartners/android-killpermandsigchecks) Bypass signature and permission checks for IPCs
- [**61**Star][6y] [Java] [gat3way/airpirate](https://github.com/gat3way/airpirate) Android 802.11 pentesting tool
- [**60**Star][3m] [Java] [aagarwal1012/image-steganography-library-android](https://github.com/aagarwal1012/image-steganography-library-android) 
- [**60**Star][2y] [Java] [geeksonsecurity/android-overlay-malware-example](https://github.com/geeksonsecurity/android-overlay-malware-example) Harmless Android malware using the overlay technique to steal user credentials.
- [**60**Star][2y] [Java] [globalpolicy/phonemonitor](https://github.com/globalpolicy/phonemonitor) A Remote Administration Tool for Android devices
- [**59**Star][13d] [C] [watf-team/watf-bank](https://github.com/watf-team/watf-bank) WaTF Bank - What a Terrible Failure Mobile Banking Application for Android and iOS
- [**58**Star][2m] [Java] [lizhangqu/android-bundle-support](https://github.com/lizhangqu/android-bundle-support) 增强型apk analyzer，支持ap_, ap, aar, aab, jar, so, awb, aab, apks等zip文件使用apk analyzer打开, android studio插件
- [**56**Star][2y] [C] [mwpcheung/ssl-kill-switch2](https://github.com/mwpcheung/ssl-kill-switch2) Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and OS X Apps
- [**55**Star][3y] [C++] [stealth/crash](https://github.com/stealth/crash) crypted admin shell: SSH-like strong crypto remote admin shell for Linux, BSD, Android, Solaris and OSX
- [**54**Star][10m] [Py] [circl/potiron](https://github.com/circl/potiron) Potiron - Normalize, Index and Visualize Network Capture
- [**54**Star][5y] [Go] [hailocab/logslam](https://github.com/hailocab/logslam) A lightweight lumberjack protocol compliant logstash indexer
- [**54**Star][1y] [C] [shunix/tinyinjector](https://github.com/shunix/tinyinjector) Shared Library Injector on Android
- [**53**Star][2y] [Java] [zyrikby/fsquadra](https://github.com/zyrikby/fsquadra) Fast detection of repackaged Android applications based on the comparison of resource files included into the package.
- [**52**Star][2y] [Java] [owasp-ruhrpott/owasp-workshop-android-pentest](https://github.com/owasp-ruhrpott/owasp-workshop-android-pentest) Learning Penetration Testing of Android Applications
- [**52**Star][7m] [C++] [virgilsecurity/virgil-crypto](https://github.com/virgilsecurity/virgil-crypto) Virgil Crypto is a high-level cryptographic library that allows you to perform all necessary operations for secure storing and transferring data and everything required to become HIPAA and GDPR compliant. Crypto Library is written in C++, suitable for mobile and server platforms and supports bindings with: Swift, Obj-C, Java (Android), С#/.NET, …
- [**51**Star][2m] [C] [alainesp/hashsuitedroid](https://github.com/alainesp/hashsuitedroid) Hash Suite for Android
- [**51**Star][2m] [Java] [guardianproject/tor-android](https://github.com/guardianproject/tor-android) Tor binary and library for Android
- [**49**Star][3y] [Java] [necst/heldroid](https://github.com/necst/heldroid) Dissect Android Apps Looking for Ransomware Functionalities
- [**47**Star][5y] [C] [mobileforensicsresearch/mem](https://github.com/mobileforensicsresearch/mem) Tool used for dumping memory from Android devices
- [**47**Star][2y] [C] [shunix/androidgothook](https://github.com/shunix/androidgothook) GOT Hook implemented in Android
- [**46**Star][5y] [Java] [monstersb/hijackandroidpoweroff](https://github.com/monstersb/hijackandroidpoweroff) Android hijack power off
- [**44**Star][3y] [Java] [miracle963/zjdroid](https://github.com/miracle963/zjdroid) 基于Xposed Framewrok的动态逆向分析模块，逆向分析者可以通过ZjDroid完成以下工作： DEX文件的内存dump 基于Dalvik关键指针的内存BackSmali，有效破解加固应用 敏感API的动态监控 指定内存区域数据dump 获取应用加载DEX信息。 获取指定DEX文件加载类信息。 dump Dalvik java堆信息。 在目标进程动态运行lua脚本。
- [**43**Star][2y] [JS] [intoli/slice](https://github.com/intoli/slice) A JavaScript implementation of Python's negative indexing and extended slice syntax.
- [**42**Star][2y] [PHP] [paragonie/hpkp-builder](https://github.com/paragonie/hpkp-builder) Build HTTP Public-Key-Pinning headers from a JSON file (or build them programmatically)
- [**41**Star][2y] [Java] [alepacheco/androrw](https://github.com/alepacheco/androrw) PoC Ransomware for android
- [**40**Star][3y] [JS] [naman14/gnome-android-tool](https://github.com/naman14/gnome-android-tool) Gnome shell extension for adb tools
- [**39**Star][2y] [Java] [tiked/androrw](https://github.com/tiked/androrw) PoC Ransomware for android
- [**39**Star][19d] [C] [intel/kernelflinger](https://github.com/intel/kernelflinger)  the Intel UEFI bootloader for AndroidTM/BrilloTM
- [**39**Star][3m] [TS] [whid-injector/whid-mobile-connector](https://github.com/whid-injector/whid-mobile-connector) Android Mobile App for Controlling WHID Injector remotely.
- [**38**Star][2y] [Py] [aptnotes/tools](https://github.com/aptnotes/tools) Tools to interact with APTnotes reporting/index.
- [**38**Star][5y] [Py] [jakev/oat2dex-python](https://github.com/jakev/oat2dex-python) Extract DEX files from an ART ELF binary
- [**38**Star][2y] [HTML] [keenrivals/bugsite-index](https://github.com/keenrivals/bugsite-index) Index of websites publishing bugs along the lines of heartbleed.com
- [**36**Star][11m] [Py] [pilgun/acvtool](https://github.com/pilgun/acvtool) ACVTool is a novel tool for measuring black-box code coverage of Android applications.
- [**34**Star][8m] [Py] [claudiugeorgiu/riskindroid](https://github.com/claudiugeorgiu/riskindroid) A tool for quantitative risk analysis of Android applications based on machine learning techniques
- [**33**Star][7y] [C] [nwhusted/auditdandroid](https://github.com/nwhusted/auditdandroid) A Fork of Auditd geared specifically for running on the Android platform. Includes system applications, AOSP patches, and kernel patches to maximize the audit experience.
- [**33**Star][2y] [Xtend] [splondike/polipoid](https://github.com/splondike/polipoid) Android wrapper for the polipo proxy
- [**32**Star][2y] [amoghbl1/tor-browser](https://github.com/amoghbl1/tor-browser) Orfox - A Tor Browser for Android
- [**32**Star][5y] [Py] [jonmetz/androfuzz](https://github.com/jonmetz/androfuzz) A fuzzing utility for Android that focuses on reporting and delivery portions of the fuzzing process
- [**32**Star][2y] [knoobdev/bypass-facebook-ssl-pinning](https://github.com/knoobdev/bypass-facebook-ssl-pinning) Bypassing ssl pinning for facebook android app
- [**32**Star][3y] [Py] [mdegrazia/osx-quicklook-parser](https://github.com/mdegrazia/osx-quicklook-parser) Parse the Mac Quickook index.sqlite database
- [**32**Star][3y] [Shell] [mseclab/ahe17](https://github.com/mseclab/ahe17) Android Hacking Event 2017 Write-up
- [**32**Star][5y] [Py] [xurubin/aurasium](https://github.com/xurubin/aurasium) Practical security policy enforcement for Android apps via bytecode rewriting and in-place reference monitor
- [**31**Star][4y] [C] [ctxis/kgdb-android](https://github.com/ctxis/kgdb-android) Patches to the Nexus 6 (Shamu) kernel source to allow KGDB over serial debug cable
- [**31**Star][7m] [Java] [jehy/rutracker-free](https://github.com/jehy/rutracker-free) Android thin client for rutracker.org, using Tor to avoid block.
- [**29**Star][2y] [C] [wangyinuo/memdump](https://github.com/wangyinuo/memdump) android下的内存dump工具，可以dump so文件
- [**28**Star][6y] [MATLAB] [vedaldi/visualindex](https://github.com/vedaldi/visualindex) A simple demo of visual object matching using VLFeat
- [**28**Star][4m] [Go] [cs8425/go-adbbot](https://github.com/cs8425/go-adbbot) android bot based on adb and golang
- [**27**Star][2y] [Java] [coh7eiqu8thabu/slocker](https://github.com/coh7eiqu8thabu/slocker) Source code of the SLocker Android ransomware
- [**26**Star][3y] [Java] [whyalwaysmea/mobilesafe](https://github.com/whyalwaysmea/mobilesafe) 这是一个android版的手机卫士，包含一下功能：1.手机防盗 2. 黑名单设置 3.软件管理 4.进程管理 5.流量统计 6.缓存清理 7.手机杀毒 8.来电归属地显示 9.号码归属地查询 10.程序锁
- [**26**Star][24d] [fkie-cad/destroid](https://github.com/fkie-cad/destroid) Fighting String Encryption in Android Malware
- [**25**Star][3y] [Shell] [amoghbl1/orfox](https://github.com/amoghbl1/orfox) This is my repository for the orfox browser, a browser that uses tor to communicate and Firefox for Android as it's base.
- [**25**Star][3y] [Java] [calebfenton/androidemulatordetect](https://github.com/calebfenton/androidemulatordetect) Android Emulator Detection
- [**25**Star][5y] [Py] [fygrave/dnslyzer](https://github.com/fygrave/dnslyzer) DNS traffic indexer and analyzer
- [**25**Star][1y] [Java] [sryze/wirebug](https://github.com/sryze/wirebug) Toggle Wi-Fi debugging on Android without a USB cable (needs root)
- [**25**Star][5y] [wirelesscollege/securitytools](https://github.com/wirelesscollege/securitytools) android安全工具大全
- [**25**Star][29d] [victorkifer/clicker](https://github.com/victorkifer/clicker) Wireless Presenter for Android and iOS, supports Windows, Linux and OS X
- [**24**Star][8m] [appspector/android-sdk](https://github.com/appspector/android-sdk) AppSpector is a debugging service for mobile apps
- [**24**Star][5y] [Py] [burningcodes/dexconfuse](https://github.com/burningcodes/dexconfuse) 简易dex混淆器
- [**23**Star][3y] [Py] [skiddietech/hidaaf](https://github.com/skiddietech/hidaaf) Python - Human Interface Device Android Attack Framework
- [**22**Star][2y] [JS] [feedhenry/mobile-security](https://github.com/feedhenry/mobile-security) FeedHenry Mobile Security
- [**22**Star][1m] [Java] [orhun/k3pler](https://github.com/orhun/k3pler) Android network connection blocker and packet analyzer built on top of local HTTP proxy.
- [**22**Star][7y] [brycethomas/liber80211](https://github.com/brycethomas/liber80211) 802.11 monitor mode for Android without root.
- [**20**Star][2y] [C#] [vr-house/eazy-arcore-interface](https://github.com/vr-house/eazy-arcore-interface) Eazy ARCore Interface is a Unity3D plugin which makes development and debugging of ARCore projects easier. Specifically, it simulates how ARCore works in an Android device inside of Unity3D editor. Thus, it allows for faster development of ARCore apps, without the need to build and deploy to the device in order to test fuctionality
- [**20**Star][11m] [Kotlin] [hacker1024/android-wifi-qr-code-generator](https://github.com/hacker1024/android-wifi-qr-code-generator) An android app that generates QR codes from your saved wifi networks.
- [**19**Star][2y] [Java] [panagiotisdrakatos/t0rlib4android](https://github.com/panagiotisdrakatos/t0rlib4android) A minimal android controller library for Tor
- [**18**Star][3y] [Java] [open-android/leakcanarydemo](https://github.com/open-android/leakcanarydemo) 内存泄漏检测工具，支持android studio eclipse
- [**18**Star][1y] [Shell] [plowsec/android-ducky](https://github.com/plowsec/android-ducky) Rubber Ducky with Android
- [**16**Star][7m] [zyrikby/stadyna](https://github.com/zyrikby/stadyna) Addressing the Problem of Dynamic Code Updates in the Security Analysis of Android Applications
- [**15**Star][2y] [Kotlin] [ttymsd/traffic-monitor](https://github.com/ttymsd/traffic-monitor) traffic debugging library for android
- [**13**Star][1y] [C] [gtoad/android_inline_hook_arm_example](https://github.com/gtoad/android_inline_hook_arm_example) 
- [**13**Star][5y] [seattleandrew/digibrutedroid](https://github.com/seattleandrew/digibrutedroid) A 4-Digit PIN Brute Force attack for USB-OTG Android devices
- [**12**Star][2y] [Java] [1van/activityhijacker](https://github.com/1van/activityhijacker) Hijack and AntiHijack for Android activity.
- [**12**Star][12m] [C++] [vito11/camerahook](https://github.com/vito11/camerahook) An prototype to hook android camera preview data of third-party and system apps
- [**10**Star][1y] [C] [gtoad/android_inline_hook_thumb_example](https://github.com/gtoad/android_inline_hook_thumb_example) 
- [**10**Star][3m] [Rust] [timvisee/apbf](https://github.com/timvisee/apbf) Tool to brute force Android security pattern through TWRP recovery.
- [**10**Star][2y] [Java] [yesterselga/password-strength-checker-android](https://github.com/yesterselga/password-strength-checker-android) Check password strength (Weak, Medium, Strong, Very Strong). Setting optional requirements by required length, with at least 1 special character, numbers and letters in uppercase or lowercase.
- [**7**Star][5y] [Perl] [pentestpartners/android](https://github.com/pentestpartners/android) android
- [**7**Star][2m] [Rust] [superandroidanalyzer/abxml-rs](https://github.com/superandroidanalyzer/abxml-rs) Android binary XML decoding library in Rust.
- [**6**Star][4y] [Java] [cspf-founder/dodovulnerablebank](https://github.com/cspf-founder/dodovulnerablebank) Insecure Vulnerable Android Application that helps to learn hacing and securing apps
- [**6**Star][12m] [Py] [datadancer/hiafuzz](https://github.com/datadancer/hiafuzz) Hybrid Interface Aware Fuzz for Android Kernel Drivers
- [**6**Star][4y] [praveshagrawal/droid-toolkit](https://github.com/praveshagrawal/droid-toolkit) A complete toolkit for Android Hacking
- [**6**Star][1y] [Java] [nishchalraj/passwordstrengthbar](https://github.com/nishchalraj/passwordstrengthbar) An android library to show the password strength using four strength bars with colours set for each.
- [**5**Star][10m] [Java] [ioactive/aosp-downloadproviderheadersdumper](https://github.com/ioactive/aosp-downloadproviderheadersdumper) PoC Exploiting Headers Disclosure in Android's Download Provider (CVE-2018-9546)
- [**5**Star][6y] [Java] [lanrat/wifi_recovery](https://github.com/lanrat/wifi_recovery) A simple android application to retrieve saved WIFI passwords
- [**5**Star][2y] [TeX] [pietroborrello/android-malware-detection](https://github.com/pietroborrello/android-malware-detection) Detecting malicious android programs through ML techniques
- [**5**Star][2y] [rev-code/androidclient](https://github.com/rev-code/androidclient) Android remote administration client
- [**5**Star][8d] [YARA] [qeeqbox/analyzer](https://github.com/qeeqbox/analyzer) Threat intelligence framework for extracting artifacts and IoCs from Windows, Linux, Android, iPhone, Blackberry, macOS binaries and more
- [**4**Star][1y] [Py] [51j0/android-storage-extractor](https://github.com/51j0/android-storage-extractor) A tool to extract local data storage of an Android application in one click.
- [**4**Star][7y] [Java] [asudhak/android-malware](https://github.com/asudhak/android-malware) Android Malware POC for CSC591
- [**4**Star][2y] [Java] [flintx/airmanager](https://github.com/flintx/airmanager) 第九届全国大学生信息安全竞赛 参赛作品 Android部分
- [**4**Star][2y] [Java] [fooock/shodand](https://github.com/fooock/shodand) Console and Android native Shodan application. Developed using MVP architecture, RxJava, Butterknife, zxing and more! Looking for collaborators, join now!
- [**4**Star][2y] [TeX] [gelldur/msc-thesis](https://github.com/gelldur/msc-thesis) Master's Thesis: Decompiling Android OS applications
- [**4**Star][6y] [C] [lance0312/vulnapp](https://github.com/lance0312/vulnapp) A vulnerable Android app
- [**4**Star][4y] [C] [mono-man/kgdb-android](https://github.com/mono-man/kgdb-android) Patches to the Nexus 6 (Shamu) kernel source to allow KGDB over serial debug cable
- [**4**Star][8m] [Java] [netdex/android-hid-script](https://github.com/netdex/android-hid-script) An Android app that allows you to script HID emulation tasks.
- [**4**Star][3y] [OpenEdge ABL] [sp2014/android-malware-detector](https://github.com/sp2014/android-malware-detector) A machine learning based Android malware detection model.
- [**4**Star][3y] [Java] [b00sti/wifi-analyzer](https://github.com/b00sti/wifi-analyzer) Analyzer 802.11 networks - android app [to refactor]
- [**4**Star][6y] [Py] [sushant-hiray/android-malware-detection](https://github.com/sushant-hiray/android-malware-detection) Storehouse of scripts/code snippets corresponding to the current RnD project.
- [**3**Star][7y] [Java] [alaasalman/aids](https://github.com/alaasalman/aids) Proof of concept Android Intrusion Detection System.
- [**3**Star][2y] [Java] [alexeyzatsepin/cp-tester](https://github.com/alexeyzatsepin/cp-tester) Android application for finding vulnerabilities in all of content providers based on SQLite databases on your device with sql-injection
- [**3**Star][3y] [Kotlin] [alilotfi/virustotalclient](https://github.com/alilotfi/virustotalclient) VirusTotal for Android checks the applications installed in your Android phone against VirusTotal (
- [**3**Star][Py] [btx3/ipwebcam-destroyer](https://github.com/btx3/ipwebcam-destroyer) Android IP Webcam DoS Tool
- [**3**Star][10m] [d4wu/unity3d-android-reverse-demo](https://github.com/d4wu/unity3d-android-reverse-demo) 
- [**3**Star][6y] [C] [hiikezoe/libfb_mem_exploit](https://github.com/hiikezoe/libfb_mem_exploit) CVE-2013-2596 exploit for android
- [**3**Star][2y] [Java] [leetcodes/poc-android-malware](https://github.com/leetcodes/poc-android-malware) A simple andorid malware uploading basic info to remote server
- [**3**Star][5y] [Py] [niejuhu/pocs](https://github.com/niejuhu/pocs) Android漏洞验证程序
- [**3**Star][9m] [Java] [pangodream/claudioremote](https://github.com/pangodream/claudioremote) Simple android App to show Claudio remote configuration capabilities
- [**3**Star][3y] [prashantmi/android-h](https://github.com/prashantmi/android-h) Android Hacker is a software based on ADB (Android Debug Bridge) and can compromise any "Android Device"
- [**3**Star][1y] [Shell] [wazehell/android-usb-pwn](https://github.com/wazehell/android-usb-pwn) simple script to pwn android phone with physical access
- [**3**Star][2y] [Java] [threedr3am/ctf-android-writeup](https://github.com/xuanyonghao/ctf-android-writeup) 很久以前参加CTF比赛做出来的部分Android逆向题目wp（瞎写，自用记录）
- [**3**Star][6y] [zoobab/busybox-static-for-android](https://github.com/zoobab/busybox-static-for-android) A static busybox for android
- [**3**Star][3y] [Py] [zyrikby/fsquadra2](https://github.com/zyrikby/fsquadra2) Evaluation of Resource-based App Repackaging Detection in Android
- [**3**Star][12y] [C] [bcopeland/android_packetspammer](https://github.com/bcopeland/android_packetspammer) packetspammer for android
- [**3**Star][8m] [Visual Basic .NET] [pericena/apkdcx](https://github.com/pericena/apkdcx) Los programas nos ayudara a poder descomprimir o descompilar las aplicaciones que son desarrollada en Android, con la extensión”.apk “para poder modificar el código y mejorar la aplicación.
- [**2**Star][2y] [androidtamer/awesome_android_pentest](https://github.com/androidtamer/awesome_android_pentest) Awesome android Pentest tools collection
- [**2**Star][10m] [Shell] [b15mu7h/androidmalwarezoo](https://github.com/b15mu7h/androidmalwarezoo) A Collection of Android Malware
- [**2**Star][12m] [Java] [b3nac/injuredandroid](https://github.com/b3nac/injuredandroid) A vulnerable Android application that shows simple examples of vulnerabilities in a ctf style.
- [**2**Star][3y] [Py] [kr1shn4murt1/exploit-ms-17-010](https://github.com/kr1shn4murt1/exploit-ms-17-010) Exploit para vulnerabilidad ms17-010 desde android
- [**2**Star][5y] [Py] [lanninghuanxue/droidj](https://github.com/lanninghuanxue/droidj) A System for Android Malware Detection and Analysis
- [**2**Star][5y] [D] [monstersb/arpdetection](https://github.com/monstersb/arpdetection) Arp attack detection for android
- [**2**Star][2y] [TeX] [neutze/master-latex-thesis](https://github.com/neutze/master-latex-thesis) Master's Thesis "Analysis of Android Cracking Tools and Investigations in Counter Measurements for Developers" at Fakultät für Informatik of Technische Universität München
- [**2**Star][5y] [Java] [nodoraiz/latchhooks](https://github.com/nodoraiz/latchhooks) Hack for Android app hooking using latch
- [**2**Star][2y] [Py] [pypygeek/amiv](https://github.com/pypygeek/AMIV) Android Malware Info Visibility Tool
- [**2**Star][6y] [yangwenbo/resetpin](https://github.com/yangwenbo/resetpin) POC of Android Fragment Injection vulnerability, about reset PIN
- [**2**Star][2m] [C++] [bootak/touchlogger-android-client](https://github.com/BOOtak/touchlogger-android-client) Log all gestures on android phone without root permissions (developer options enabled required!)
- [**1**Star][1y] [Shell] [backtrackcroot/androidtoolbox](https://github.com/backtrackcroot/androidtoolbox) A android decompile tool set.
- [**1**Star][3y] [Java] [ctf/ctf-android](https://github.com/ctf/ctf-android) Source code for CTF's Android app
- [**1**Star][3y] [C++] [cvvt/challenge_for_ctf](https://github.com/cvvt/challenge_for_ctf) Source code of android challenges for capturing the flag
- [**1**Star][7y] [C] [gerasiov/abootimg-android](https://github.com/gerasiov/abootimg-android) Android build of abootimg
- [**1**Star][6y] [huyle333/androidmitllctf2013](https://github.com/huyle333/androidmitllctf2013) BUILDS Team 2 Android code from the MIT LL CTF 2013 for future reference. A list of APK files with different functions.
- [**1**Star][8y] [Java] [rajasaur/ctfdroid](https://github.com/rajasaur/ctfdroid) Android app for talking to Forge
- [**1**Star][4y] [Java] [sushanthikshwaku/antiv](https://github.com/sushanthikshwaku/antiv) Anti virus app for android using VirusTotal
- [**1**Star][2y] [Py] [tum-i22/localizing-android-malicious-behaviors](https://github.com/tum-i22/localizing-android-malicious-behaviors) Initial implementation of a method to localize malicious behaviors from API call traces of Android apps
- [**1**Star][8y] [utkanos/android_device_htc_rezound](https://github.com/utkanos/android_device_htc_rezound) working POC device for building bootable recovery
- [**1**Star][8y] [utkanos/android_device_htc_vigor](https://github.com/utkanos/android_device_htc_vigor) poc cwmr port for htc rezound
- [**1**Star][12m] [Java] [oxagast/ansvif_android](https://github.com/oxagast/ansvif_android) An Android frontend for ansvif fuzzing
- [**1**Star][4y] [C] [ru-faraon/pixiewps-android](https://github.com/ru-faraon/pixiewps-android) 
- [**1**Star][6y] [PHP] [akibsayyed/poc-android-malware-files](https://github.com/akibsayyed/poc-android-malware-files) PHP Files for Android malware
- [**0**Star][5y] [Java] [anonim1133/ctf](https://github.com/anonim1133/ctf) Simple Android app to play Caputre The Flag. By using GPS and wifi it allows you to "capture the flags".
- [**0**Star][3y] [Java] [artwyman/android_ctf](https://github.com/artwyman/android_ctf) 
- [**0**Star][2y] [Py] [bizdak/silverboxcc](https://github.com/bizdak/silverboxcc) Reverse engineered android malware, and this is a C&C server for it
- [**0**Star][7m] [Py] [brant-ruan/idf4apev](https://github.com/brant-ruan/idf4apev) Integrated Detection Framework for Android's Privilege Escalation Vulnerabilites
- [**0**Star][4y] [C] [c0d3st0rm/android_kernel_tesco_ht7s3](https://github.com/c0d3st0rm/android_kernel_tesco_ht7s3) Android kernel source for Tesco's first Hudl (HT7S3). This is here only for reference, as Tesco don't host kernel sources anymore, and is unbuildable - the kernel configs are missing and so are some of the essential parts of the kernel, eg WiFi drivers.
- [**0**Star][2y] [chicharitomu14/android-hover-attack-document](https://github.com/chicharitomu14/android-hover-attack-document) A document about Android Hover Attack in Chinese, organized from the paper “Using Hover to Compromise the Confidentiality of User Input on Android”
- [**0**Star][7y] [ctfk/cl.ctfk](https://github.com/ctfk/cl.ctfk) Android CTF Game
- [**0**Star][6y] [Java] [ctz/android-keystore](https://github.com/ctz/android-keystore) POC for Android keystore leak
- [**0**Star][5m] [Perl] [debos99/droidvenom](https://github.com/debos99/droidvenom) DroidVenom is simple perl script for creating custom payload for android
- [**0**Star][6y] [C] [enjens/android_kernel_sony_pollux_windy_stock](https://github.com/enjens/android_kernel_sony_pollux_windy_stock) Stock kernel with kexec patches for Sony Tablet Z WIFI
- [**0**Star][4y] [Py] [eward9/android-backdoor-factory](https://github.com/eward9/android-backdoor-factory) 
- [**0**Star][3y] [Java] [fathulkirom22/androidctf](https://github.com/fathulkirom22/androidctf) 
- [**0**Star][6y] [Groovy] [jhong01/ctfpro](https://github.com/jhong01/ctfpro) Android Capture the Flag Pro
- [**0**Star][5y] [Java] [kappaetakappa/robot-ctf-android](https://github.com/kappaetakappa/robot-ctf-android) Controller software for the Expo project
- [**0**Star][10m] [Smali] [moviet/space-ghost](https://github.com/moviet/space-ghost) A simple example source codes of an initial android app cloner
- [**0**Star][1y] [paradox5566/evihunter](https://github.com/paradox5566/evihunter) EviHunter is a static program analysis tool for parsing the evidentiary data from Android apps.
- [**0**Star][5y] [preethams2/m_analysis](https://github.com/preethams2/m_analysis) Android malware tuts
- [**0**Star][5y] [qwertgfdvgjh/xmanager](https://github.com/qwertgfdvgjh/xmanager) xManager-手机安全卫士/练手Android项目，自己独立开发
- [**0**Star][3y] [Java] [sanjeet990/android-antivirus-project](https://github.com/sanjeet990/android-antivirus-project) This is an Antivirus project for Android that I created for my college project.
- [**0**Star][3y] [serval-snt-uni-lu/hookranker](https://github.com/serval-snt-uni-lu/hookranker) Automatically Locating Malicious Payload in Piggybacked Android Apps (A Hook Ranking Approach)
- [**0**Star][2y] [Java] [toulousehackingconvention/bestpig-reverse-android-serial](https://github.com/toulousehackingconvention/bestpig-reverse-android-serial) THC CTF 2018 - Reverse - Android serial
- [**0**Star][7y] [C] [tvall43/android_kernel_grouper](https://github.com/tvall43/android_kernel_grouper) kernel for the Google Asus Nexus 7 (2012) Wifi (insane naming system, right?)
- [**0**Star][5y] [vaginessa/kali_launcher_android_app](https://github.com/vaginessa/kali_launcher_android_app) Android Application to launch Kali Android chroot.
- [**0**Star][6m] [C] [alex91ar/gdb-multiarch](https://github.com/alex91ar/gdb-multiarch) Patched GDB-Multiarch to debug android Kernels.


### <a id="883a4e0dd67c6482d28a7a14228cd942"></a>Recent Add1


- [**183**Star][30d] [Kotlin] [iammert/applocker](https://github.com/iammert/applocker) 
- [**157**Star][2m] [Java] [reddr/libscout](https://github.com/reddr/libscout) Third-party library detector for Java/Android apps
- [**154**Star][4m] [Java] [rednaga/axmlprinter](https://github.com/rednaga/axmlprinter) Library for parsing and printing compiled Android manifest files
- [**149**Star][2y] [Py] [mhelwig/apk-anal](https://github.com/mhelwig/apk-anal) Android APK analyzer based on radare2 and others.
    - Also In Section: [Radare2->Plugins->Recent Add](#6922457cb0d4b6b87a34caf39aa31dfe) |
- [**146**Star][10m] [Java] [lanchon/haystack](https://github.com/lanchon/haystack) Signature Spoofing Patcher for Android
- [**142**Star][2m] [Java] [joshjdevl/libsodium-jni](https://github.com/joshjdevl/libsodium-jni) (Android) Networking and Cryptography Library (NaCL) JNI binding. JNI is utilized for fastest access to native code. Accessible either in Android or Java application. Uses SWIG to generate Java JNI bindings. SWIG definitions are extensible to other languages.
- [**139**Star][3m] [nathanchance/android-kernel-clang](https://github.com/nathanchance/android-kernel-clang) Information on compiling Android kernels with Clang
- [**137**Star][9m] [Py] [ale5000-git/tingle](https://github.com/ale5000-git/tingle) Android patcher
- [**136**Star][3y] [Batchfile] [eliteandroidapps/whatsapp-key-db-extractor](https://github.com/eliteandroidapps/whatsapp-key-db-extractor) Allows WhatsApp users to extract their cipher key and databases on non-rooted Android devices.
- [**132**Star][5y] [C] [hiteshd/android-rootkit](https://github.com/hiteshd/android-rootkit) A rootkit for Android. Based on "Android platform based linux kernel rootkit" from Phrack Issue 68
- [**129**Star][3m] [Shell] [exalab/anlinux-resources](https://github.com/exalab/anlinux-resources) Image and Script for LinuxOnAndroid App
- [**127**Star][2m] [osm0sis/android-busybox-ndk](https://github.com/osm0sis/android-busybox-ndk) Keeping track of instructions and patches for building busybox with the Android NDK
- [**122**Star][4y] [irsl/adb-backup-apk-injection](https://github.com/irsl/adb-backup-apk-injection) Android ADB backup APK Injection POC
- [**121**Star][7y] [Py] [liato/android-market-api-py](https://github.com/liato/android-market-api-py) A Python port of the java Android Market API.
- [**120**Star][10m] [Java] [securityfirst/umbrella_android](https://github.com/securityfirst/umbrella_android) Digital and Physical Security Advice App
- [**120**Star][2m] [C++] [stealth/lophttpd](https://github.com/stealth/lophttpd) lots of performance (or lots of porn, if you prefer) httpd: Easy, chrooted, fast and simple to use HTTP server for static content. Runs on Linux, BSD, Android and OSX/Darwin. It's free but if you like it, consider donating to the EFF:
- [**119**Star][1m] [Kotlin] [babylonhealth/certificate-transparency-android](https://github.com/babylonhealth/certificate-transparency-android) Certificate transparency for Android and Java
- [**118**Star][4m] [Java] [andprox/andprox](https://github.com/andprox/andprox) Native Android Proxmark3 client (no root required)
- [**117**Star][2m] [Java] [auth0/lock.android](https://github.com/auth0/lock.android) Android Library to authenticate using Auth0 and with a Native Look & Feel
- [**117**Star][3y] [Java] [rafaeltoledo/android-security](https://github.com/rafaeltoledo/android-security) An app showcase of some techniques to improve Android app security
- [**114**Star][7m] [Py] [alexmyg/andropytool](https://github.com/alexmyg/andropytool) A framework for automated extraction of static and dynamic features from Android applications
- [**113**Star][4y] [Java] [evilsocket/pdusms](https://github.com/evilsocket/pdusms) PoC app for raw pdu manipulation on Android.
- [**109**Star][2y] [C] [pbatard/bootimg-tools](https://github.com/pbatard/bootimg-tools) Android boot.img creation and extraction tools [NOTE: This project is NO LONGER maintained]
- [**104**Star][19d] [Py] [virb3/apk-utilities](https://github.com/virb3/apk-utilities) Tools and scripts to manipulate Android APKs
- [**104**Star][12m] [Java] [varunon9/remote-control-pc](https://github.com/varunon9/remote-control-pc) Control Laptop using Android. Remote control PC consists of android as well as desktop app written in Java to control laptop using phone.
- [**103**Star][9m] [C++] [quarkslab/android-restriction-bypass](https://github.com/quarkslab/android-restriction-bypass) PoC to bypass Android restrictions
- [**99**Star][11m] [winterssy/miui-purify](https://github.com/winterssy/miui-purify) 个人兴趣项目存档，使用 apktool 魔改 MIUI ROM，去除 MIUI 系统新增的广告。
- [**97**Star][4y] [Java] [zencodex/hack-android](https://github.com/zencodex/hack-android) Collection tools for hack android, java
- [**95**Star][4m] [Java] [dexpatcher/dex2jar](https://github.com/dexpatcher/dex2jar) Unofficial dex2jar builds
- [**92**Star][18d] [Py] [imtiazkarimik23/atfuzzer](https://github.com/imtiazkarimik23/atfuzzer) "Opening Pandora's Box through ATFuzzer: Dynamic Analysis of AT Interface for Android Smartphones" ACSAC 2019
- [**91**Star][3y] [Java] [5gsd/aimsicdl](https://github.com/5gsd/aimsicdl) AIMSICD Lite (Android IMSI-Catcher Detector) - reloaded!
- [**90**Star][3y] [Java] [mingyuan-xia/patdroid](https://github.com/mingyuan-xia/patdroid) A Program Analysis Toolkit for Android
- [**90**Star][8y] [Java] [securitycompass/androidlabs](https://github.com/securitycompass/androidlabs) Android security labs
- [**88**Star][1y] [ObjC] [cmackay/google-analytics-plugin](https://github.com/cmackay/google-analytics-plugin) Cordova Google Analytics Plugin for Android & iOS
- [**88**Star][3m] [Scala] [rsertelon/android-keystore-recovery](https://github.com/rsertelon/android-keystore-recovery) A tool to recover your lost Android keystore password
- [**86**Star][3y] [Py] [ucsb-seclab/baredroid](https://github.com/ucsb-seclab/baredroid) bare-metal analysis on Android devices
- [**85**Star][7y] [Java] [thomascannon/android-sms-spoof](https://github.com/thomascannon/android-sms-spoof) PoC app which takes advantage of Android's SmsReceiverService being exported to fake an incoming SMS with no permissions.
- [**84**Star][2y] [Kotlin] [viktordegtyarev/callreclib](https://github.com/viktordegtyarev/callreclib) Call Recorder fix for Android 7 and Android 6
- [**81**Star][4y] [Py] [android-dtf/dtf](https://github.com/android-dtf/dtf) Android Device Testing Framework ("dtf")
- [**80**Star][12m] [Java] [thelinuxchoice/droidtracker](https://github.com/thelinuxchoice/droidtracker) Script to generate an Android App to track location in real time
- [**79**Star][3m] [Py] [sashs/filebytes](https://github.com/sashs/filebytes) Library to read and edit files in the following formats: Executable and Linking Format (ELF), Portable Executable (PE), MachO and OAT (Android Runtime)
- [**77**Star][8d] [HTML] [android-x86/android-x86.github.io](https://github.com/android-x86/android-x86.github.io) Official Website for Android-x86 Project
- [**77**Star][2y] [C++] [daizhongyin/securitysdk](https://github.com/daizhongyin/securitysdk) Android安全SDK，提供基础的安全防护能力，如安全webview、IPC安全通信、应用和插件安全更新、威胁情报搜集等等
- [**77**Star][19d] [Py] [nightwatchcybersecurity/truegaze](https://github.com/nightwatchcybersecurity/truegaze) Static analysis tool for Android/iOS apps focusing on security issues outside the source code
- [**76**Star][3y] [Py] [moosd/needle](https://github.com/moosd/needle) Android framework injection made easy
- [**75**Star][3y] [Java] [guardianproject/cacheword](https://github.com/guardianproject/cacheword) a password caching and management service for Android
- [**74**Star][3m] [Ruby] [devunwired/apktools](https://github.com/devunwired/apktools) Ruby library for reading/parsing APK resource data
- [**73**Star][2y] [C++] [vusec/guardion](https://github.com/vusec/guardion) Android GuardION patches to mitigate DMA-based Rowhammer attacks on ARM
- [**71**Star][4y] [Py] [programa-stic/marvin-django](https://github.com/programa-stic/marvin-django) Marvin-django is the UI/database part of the Marvin project. Marvin is a platform for security analysis of Android apps.
- [**70**Star][2y] [androidtamer/androidtamer](https://github.com/androidtamer/androidtamer) We Use Github Extensively and openly. So it becomes dificult to track what's what and what's where. This repository is a master repo to Help with that.
- [**69**Star][23d] [Java] [auth0/auth0.android](https://github.com/auth0/auth0.android) Android toolkit for Auth0 API
- [**68**Star][1y] [Shell] [kiyadesu/android](https://github.com/kiyadesu/Android) walk into Android security step by step
- [**66**Star][11m] [Py] [yelp/parcelgen](https://github.com/yelp/parcelgen) Helpful tool to make data objects easier for Android
- [**65**Star][5y] [Java] [guardianproject/trustedintents](https://github.com/guardianproject/trustedintents) library for flexible trusted interactions between Android apps
- [**65**Star][6y] [Java] [ibrahimbalic/androidrat](https://github.com/ibrahimbalic/androidrat) Android RAT
- [**65**Star][6y] [C++] [trevd/android_root](https://github.com/trevd/android_root) Got Root!
- [**65**Star][8y] [C] [robclemons/arpspoof](https://github.com/robclemons/Arpspoof) Android port of Arpspoof
- [**64**Star][3m] [Java] [flankerhqd/bindump4j](https://github.com/flankerhqd/bindump4j) A portable utility to locate android binder service
- [**64**Star][7y] [C] [hiikezoe/android_run_root_shell](https://github.com/hiikezoe/android_run_root_shell) 
- [**62**Star][2y] [C] [wlach/orangutan](https://github.com/wlach/orangutan) Simulate native events on Android-like devices
- [**61**Star][7y] [Java] [intrepidusgroup/iglogger](https://github.com/intrepidusgroup/iglogger) Class to help with adding logging function in smali output from 3rd party Android apps.
- [**58**Star][5y] [C] [poliva/dexinfo](https://github.com/poliva/dexinfo) A very rudimentary Android DEX file parser
- [**58**Star][2m] [Kotlin] [m1dr05/istheapp](https://github.com/m1dr05/istheapp) Open-source android spyware
- [**57**Star][2y] [Java] [amotzte/android-mock-location-for-development](https://github.com/amotzte/android-mock-location-for-development) allows to change mock location from command line on real devices
- [**56**Star][1y] [C] [jduck/canhazaxs](https://github.com/jduck/canhazaxs) A tool for enumerating the access to entries in the file system of an Android device.
- [**55**Star][1y] [JS] [enovella/androidtrainings](https://github.com/enovella/androidtrainings) Mobile security trainings based on android
- [**55**Star][6m] [Java] [pnfsoftware/jeb2-androsig](https://github.com/pnfsoftware/jeb2-androsig) Android Library Code Recognition
- [**55**Star][11d] [Java] [gedsh/invizible](https://github.com/gedsh/invizible) Android application for Internet privacy and security
- [**55**Star][3y] [Java] [giovannicolonna/msfvenom-backdoor-android](https://github.com/giovannicolonna/msfvenom-backdoor-android) Android backdoored app, improved source code of msfvenom android .apk
- [**53**Star][2y] [Java] [modzero/modjoda](https://github.com/modzero/modjoda) Java Object Deserialization on Android
- [**53**Star][2m] [Py] [nelenkov/android-device-check](https://github.com/nelenkov/android-device-check) Check Android device security settings
- [**53**Star][3y] [Shell] [nvssks/android-responder](https://github.com/nvssks/android-responder) Scripts for running Responder.py in an Android (rooted) device.
- [**53**Star][5y] [Java] [thuxnder/androiddevice.info](https://github.com/thuxnder/androiddevice.info) Android app collecting device information and submiting it to
- [**53**Star][1m] [Py] [ucsb-seclab/agrigento](https://github.com/ucsb-seclab/agrigento) Agrigento is a tool to identify privacy leaks in Android apps by performing black-box differential analysis on the network traffic.
- [**50**Star][5y] [Java] [retme7/broadanywhere_poc_by_retme_bug_17356824](https://github.com/retme7/broadanywhere_poc_by_retme_bug_17356824) a poc of Android bug 17356824
- [**48**Star][3y] [Shell] [osm0sis/apk-patcher](https://github.com/osm0sis/apk-patcher) Patch APKs on-the-fly from Android recovery (Proof of Concept)
- [**48**Star][5y] [C++] [sogeti-esec-lab/android-fde](https://github.com/sogeti-esec-lab/android-fde) Tools to work on Android Full Disk Encryption (FDE).
- [**48**Star][7y] [tias/android-busybox-ndk](https://github.com/tias/android-busybox-ndk) Keeping track of instructions and patches for building busybox with the android NDK
- [**47**Star][3y] [Py] [alessandroz/pupy](https://github.com/alessandroz/pupy) Pupy is an opensource, multi-platform (Windows, Linux, OSX, Android), multi function RAT (Remote Administration Tool) mainly written in python.
- [**47**Star][6m] [Java] [tlamb96/kgb_messenger](https://github.com/tlamb96/kgb_messenger) An Android CTF practice challenge
- [**46**Star][5m] [Py] [cryptax/angeapk](https://github.com/cryptax/angeapk) Encrypting a PNG into an Android application
- [**46**Star][1y] [Java] [kaushikravikumar/realtimetaxiandroiddemo](https://github.com/kaushikravikumar/realtimetaxiandroiddemo) PubNub Demo that uses a Publish/Subscribe model to implement a realtime map functionality similar to Lyft/Uber.
- [**44**Star][2y] [Java] [m301/rdroid](https://github.com/m301/rdroid) [Android RAT] Remotely manage your android phone using PHP Interface
- [**43**Star][11m] [Kotlin] [cbeuw/cloak-android](https://github.com/cbeuw/cloak-android) Android client of Cloak
- [**42**Star][3m] [Java] [nowsecure/cybertruckchallenge19](https://github.com/nowsecure/cybertruckchallenge19) Android security workshop material taught during the CyberTruck Challenge 2019 (Detroit USA).
- [**41**Star][4y] [C] [sesuperuser/super-bootimg](https://github.com/sesuperuser/super-bootimg) Tools to edit Android boot.img. NDK buildable, to be usable in an update.zip
- [**41**Star][2y] [Shell] [xtiankisutsa/twiga](https://github.com/xtiankisutsa/twiga) twiga：枚举 Android 设备，获取了解其内部部件和漏洞利用的信息
- [**40**Star][2y] [Java] [ivianuu/contributer](https://github.com/ivianuu/contributer) Inject all types like views or a conductor controllers with @ContributesAndroidInjector
- [**40**Star][7y] [C++] [taintdroid/android_platform_dalvik](https://github.com/taintdroid/android_platform_dalvik) Mirror of git://android.git.kernel.org/platform/dalvik.git with TaintDroid additions (mirror lags official Android)
- [**40**Star][5y] [Java] [tacixat/cfgscandroid](https://github.com/TACIXAT/CFGScanDroid) Control Flow Graph Scanning for Android
- [**40**Star][12m] [Java] [thelinuxchoice/droidcam](https://github.com/thelinuxchoice/droidcam) Script to generate an Android App to take photos from Cameras
- [**39**Star][5y] [C] [cyanogenmod/android_external_openssl](https://github.com/cyanogenmod/android_external_openssl) OpenSSL for Android
- [**39**Star][1y] [Py] [sundaysec/andspoilt](https://github.com/sundaysec/andspoilt) Run interactive android exploits in linux.
- [**38**Star][8m] [Java] [pnfsoftware/jnihelper](https://github.com/pnfsoftware/jnihelper) jeb-plugin-android-jni-helper
- [**37**Star][13d] [Java] [cliqz-oss/browser-android](https://github.com/cliqz-oss/browser-android) CLIQZ for Android
- [**37**Star][4y] [Java] [julianschuette/condroid](https://github.com/julianschuette/condroid) Symbolic/concolic execution of Android apps
- [**35**Star][6m] [Py] [bkerler/dump_avb_signature](https://github.com/bkerler/dump_avb_signature) Dump Android Verified Boot Signature
- [**35**Star][6y] [C#] [redth/android.signature.tool](https://github.com/redth/android.signature.tool) Simple GUI tool for Mac and Windows to help find the SHA1 and MD5 hashes of your Android keystore's and apk's
- [**35**Star][3y] [Java] [serval-snt-uni-lu/droidra](https://github.com/serval-snt-uni-lu/droidra) Taming Reflection to Support Whole-Program Analysis of Android Apps
- [**34**Star][2y] [hardenedlinux/armv7-nexus7-grsec](https://github.com/hardenedlinux/armv7-nexus7-grsec) Hardened PoC: PaX for Android
- [**34**Star][11m] [Kotlin] [cbeuw/goquiet-android](https://github.com/cbeuw/goquiet-android) GoQuiet plugin on android
- [**33**Star][1y] [C] [jp-bennett/fwknop2](https://github.com/jp-bennett/fwknop2) A replacement fwknop client for android.
- [**33**Star][3y] [Java] [riramar/pubkey-pin-android](https://github.com/riramar/pubkey-pin-android) Just another example for Android Public Key Pinning (based on OWASP example)
- [**33**Star][7m] [Shell] [robertohuertasm/apk-decompiler](https://github.com/robertohuertasm/apk-decompiler) Small Rust utility to decompile Android apks
- [**32**Star][2y] [dweinstein/dockerfile-androguard](https://github.com/dweinstein/dockerfile-androguard) docker file for use with androguard python android app analysis tool
- [**30**Star][4m] [Py] [azmatt/anaximander](https://github.com/azmatt/anaximander) Python Code to Map Cell Towers From a Cellebrite Android Dump
- [**30**Star][8m] [Java] [pnfsoftware/jeb2-plugin-oat](https://github.com/pnfsoftware/jeb2-plugin-oat) Android OAT Plugin for JEB
- [**30**Star][3y] [Java] [amitshekhariitbhu/applock](https://github.com/amitshekhariitbhu/applock) Android Application for app lock
- [**29**Star][1y] [C] [calebfenton/native-harness-target](https://github.com/calebfenton/native-harness-target) Android app for demonstrating native library harnessing
- [**29**Star][1m] [JS] [fsecurelabs/android-keystore-audit](https://github.com/fsecurelabs/android-keystore-audit) 
- [**28**Star][3y] [Java] [martinstyk/apkanalyzer](https://github.com/martinstyk/apkanalyzer) Java tool for analyzing Android APK files
- [**27**Star][4y] [C] [anarcheuz/android-pocs](https://github.com/anarcheuz/android-pocs) 
- [**27**Star][3m] [Py] [cryptax/droidlysis](https://github.com/cryptax/droidlysis) Property extractor for Android apps
- [**27**Star][3m] [grapheneos/os_issue_tracker](https://github.com/grapheneos/os_issue_tracker) Issue tracker for GrapheneOS Android Open Source Project hardening work. Standalone projects like Auditor, AttestationServer and hardened_malloc have their own dedicated trackers.
- [**26**Star][1y] [Ruby] [ajitsing/apktojava](https://github.com/ajitsing/apktojava) View android apk as java code in gui
- [**25**Star][3y] [zyrikby/android_permission_evolution](https://github.com/zyrikby/android_permission_evolution) Analysis of the evolution of Android permissions. This repository contains the results presented in the paper "Small Changes, Big Changes: An Updated View on the Android Permission System".
- [**25**Star][11m] [Visual Basic .NET] [modify24x7/ultimate-advanced-apktool](https://github.com/modify24x7/ultimate-advanced-apktool) v4.1
- [**24**Star][2y] [Java] [commonsguy/autofillfollies](https://github.com/commonsguy/autofillfollies) Demonstration of security issues with Android 8.0 autofill
- [**24**Star][1y] [C++] [zsshen/yadd](https://github.com/zsshen/yadd) Yet another Android Dex bytecode Disassembler: a static Android app disassembler for fast class and method signature extraction and code structure visualization.
- [**24**Star][4y] [Java] [stealthcopter/steganography](https://github.com/stealthcopter/steganography) Android Steganography Library
- [**24**Star][2m] [Java] [snail007/goproxy-ss-plugin-android](https://github.com/snail007/goproxy-ss-plugin-android) goproxy安卓全局代理，ss goproxy安卓插件, goproxy :
- [**22**Star][1m] [Smali] [aress31/sci](https://github.com/aress31/sci) Framework designed to automate the process of assembly code injection (trojanising) within Android applications.
- [**21**Star][7y] [C] [0xroot/whitesnow](https://github.com/0xroot/whitesnow) An experimental rootkit for Android
- [**21**Star][1y] [Smali] [dan7800/vulnerableandroidapporacle](https://github.com/dan7800/vulnerableandroidapporacle) 
- [**20**Star][10m] [Rust] [gamozolabs/slime_tree](https://github.com/gamozolabs/slime_tree) Worst Android kernel fuzzer
- [**20**Star][5y] [snifer/l4bsforandroid](https://github.com/snifer/l4bsforandroid) Repositorio de APK para Hacking y Seguridad
- [**19**Star][3m] [C] [cybersaxostiger/androiddump](https://github.com/cybersaxostiger/androiddump) A tool pulls loaded binaries ordered by memory regions
- [**19**Star][2m] [Java] [h3xstream/find-sec-bugs](https://github.com/h3xstream/find-sec-bugs) The FindBugs plugin for security audits of Java web applications and Android applications. (Also work with Scala and Groovy projects)
- [**19**Star][5y] [Java] [juxing/adoreforandroid](https://github.com/juxing/adoreforandroid) Transplant adore rootkit for Android platform.
- [**19**Star][5y] [C++] [trustonic/trustonic-tee-user-space](https://github.com/trustonic/trustonic-tee-user-space) Android user space components for the Trustonic Trusted Execution Environment
- [**18**Star][3y] [C] [freddierice/farm-root](https://github.com/freddierice/farm-root) Farm root is a root for android devices using the dirty cow vulnerability
- [**18**Star][7y] [Java] [jseidl/goldeneye-mobile](https://github.com/jseidl/goldeneye-mobile) GoldenEye Mobile Android Layer 7 HTTP DoS Test Tool
- [**18**Star][4y] [Java] [meleap/myo_andoridemg](https://github.com/meleap/myo_andoridemg) We got the Myo's EMG-data on Android by hacking bluetooth.
- [**18**Star][6y] [Java] [taufderl/whatsapp-sniffer-android-poc](https://github.com/taufderl/whatsapp-sniffer-android-poc) proof of concept app to show how to upload and decrypt WhatsApp backup database
- [**18**Star][30d] [jqorz/biquge_crack](https://github.com/jqorz/biquge_crack) 笔趣阁_Android_去广告修改版（免费看小说！无广告！秒开无等待！）反编译学习
- [**17**Star][3y] [bemre/bankbot-mazain](https://github.com/bemre/bankbot-mazain) 针对Android设备的开源手机银行木马BankBot / Mazain分析
- [**17**Star][6y] [Py] [thomascannon/android-fde-decryption](https://github.com/thomascannon/android-fde-decryption) Cracking and decrypting Android Full Device Encryption
- [**17**Star][6y] [Java] [fsecurelabs/mwr-android](https://github.com/FSecureLABS/mwr-android) A collection of utilities for Android applications.
- [**16**Star][2y] [androidtamer/tools](https://github.com/androidtamer/tools) This website will be holding list / details of each and every tool available via Android Tamer
- [**16**Star][4y] [lewisrhine/kotlin-for-android-developers-zh](https://github.com/lewisrhine/kotlin-for-android-developers-zh) Kotlin for android developers in chinese.
- [**15**Star][2y] [C++] [chenzhihui28/securitydemo](https://github.com/chenzhihui28/securitydemo) ndk进行简单的签名校验，密钥保护demo,android应用签名校验
- [**15**Star][4m] [hyrathon/hitcon2019](https://github.com/hyrathon/hitcon2019) Slides(In both CN and EN) & WP(outdated) of my topic in HITCON 2019 about bug hunting in Android NFC
- [**15**Star][7y] [Vim script] [jlarimer/android-stuff](https://github.com/jlarimer/android-stuff) Random scripts and files I use for Android reversing
- [**15**Star][2y] [Java] [tanprathan/sievepwn](https://github.com/tanprathan/sievepwn) An android application which exploits sieve through android components.
- [**13**Star][2y] [anelkaos/ada](https://github.com/anelkaos/ada) Android Automation Tool
- [**13**Star][2y] [Scala] [fschrofner/glassdoor](https://github.com/fschrofner/glassdoor) glassdoor is a modern, autonomous security framework for Android APKs. POC, unmaintained unfortunately.
- [**13**Star][6y] [Shell] [k3170makan/droidsploit](https://github.com/k3170makan/droidsploit) A collection of scripts to find common application vulnerabilities in Android Applications
- [**13**Star][5y] [Py] [lifeasageek/morula](https://github.com/lifeasageek/morula) Morula is a secure replacement of Zygote to fortify weakened ASLR on Android
- [**13**Star][1y] [Shell] [theyahya/android-decompile](https://github.com/theyahya/android-decompile) 
- [**12**Star][3m] [Py] [clviper/droidstatx](https://github.com/clviper/droidstatx) Python tool that generates an Xmind map with all the information gathered and any evidence of possible vulnerabilities identified via static analysis. The map itself is an Android Application Pentesting Methodology component, which assists Pentesters to cover all important areas during an assessment.
- [**12**Star][1y] [JS] [integrity-sa/android](https://github.com/integrity-sa/android) Repository with research related to Android
- [**12**Star][7y] [Java] [jeffers102/keystorecracker](https://github.com/jeffers102/keystorecracker) Helps retrieve forgotten keystore passwords using your commonly used segments. Great for those forgotten Android keystore passphrases, which is exactly why I created this tool in the first place!
- [**12**Star][3y] [Java] [miguelmarco/zcashpannel](https://github.com/miguelmarco/zcashpannel) An android front-end to the zcash wallet through onion services
- [**12**Star][5y] [Java] [poliva/radare-installer](https://github.com/poliva/radare-installer) Application to easily download and install radare2 on android devices
- [**12**Star][3y] [Py] [zyrikby/bboxtester](https://github.com/zyrikby/bboxtester) Tool to measure code coverage of Android applications when their source code is not available
- [**11**Star][7m] [Java] [radare/radare2-installer](https://github.com/radare/radare2-installer) Application to easily download and install radare2 on android devices
- [**11**Star][1y] [Java] [wishihab/wedefend-android](https://github.com/wishihab/wedefend-android) ⛔
- [**11**Star][1y] [Java] [zjsnowman/hackandroid](https://github.com/zjsnowman/hackandroid) Android安全之 Activity 劫持与反劫持
- [**11**Star][2y] [Java] [mandyonze/droidsentinel](https://github.com/Mandyonze/DroidSentinel) Analizador de tráfico para dispositivos Android potencialmente comprometidos como parte de una botnet orientado a detectar ataques DDoS.
- [**10**Star][5y] [C] [christianpapathanasiou/defcon-18-android-rootkit-mindtrick](https://github.com/christianpapathanasiou/defcon-18-android-rootkit-mindtrick) Worlds first Google Android kernel rootkit as featured at DEF CON 18
- [**10**Star][4y] [Java] [cyberscions/digitalbank](https://github.com/cyberscions/digitalbank) Android Digital Bank Vulnerable Mobile App
- [**9**Star][3y] [C++] [android-art-intel/nougat](https://github.com/android-art-intel/nougat) ART-Extension for Android Nougat
- [**9**Star][5y] [Shell] [bbqlinux/android-udev-rules](https://github.com/bbqlinux/android-udev-rules) 
- [**9**Star][2y] [Java] [djkovrik/comicser](https://github.com/djkovrik/comicser) Udacity Android Developer Nanodegree - Capstone project.
- [**9**Star][4y] [C] [ele7enxxh/fakeodex](https://github.com/ele7enxxh/fakeodex) modify field(modWhen, crc) in android odex file;安卓APP“寄生兽”漏洞
- [**9**Star][2y] [Java] [optimistanoop/android-developer-nanodegree](https://github.com/optimistanoop/android-developer-nanodegree) This repo contains all 8 Apps developed during Udacity Android Developer Nanodegree. These all Apps met expectation during code review process of Udacity Android Developer Nanodegree.
- [**9**Star][1y] [C#] [preemptive/protected-todoazureauth](https://github.com/preemptive/protected-todoazureauth) Example of protecting a Xamarin.Android app with Dotfuscator’s Root Check
- [**9**Star][7m] [Go] [shosta/androsectest](https://github.com/shosta/androsectest) Automate the setup of your Android Pentest and perform automatically static tests
- [**9**Star][1y] [Kotlin] [smartnsoft/android-monero-miner](https://github.com/smartnsoft/android-monero-miner) A minimal SDK that lets an integrator add a Monero Miner using the Javascript miner created by CoinHive. The Monero Miner can be used with any CoinHive address and is a proof of concept of an alternative to ad banners and interstitials for mobile app developers that want to get retributed for their work without spamming their users with bad adve…
- [**8**Star][7y] [Py] [agnivesh/aft](https://github.com/agnivesh/aft) [Deprecated] Android Forensic Toolkit
- [**8**Star][4y] [Java] [appknox/vulnerable-application](https://github.com/appknox/vulnerable-application) Test Android Application.
- [**8**Star][2y] [JS] [checkmarx/webviewgoat](https://github.com/checkmarx/webviewgoat) A deliberately vulnerable Android application to demonstrate exfiltration scenarios
- [**8**Star][11m] [C] [hcamael/android_kernel_pwn](https://github.com/hcamael/android_kernel_pwn) android kernel pwn
- [**8**Star][6y] [Java] [fsecurelabs/mwr-tls](https://github.com/FSecureLABS/mwr-tls) A collection of utilities for interacting with SSL and X509 Certificates on Android.
- [**7**Star][5y] [CSS] [dhirajongithub/owasp_kalp_mobile_project](https://github.com/dhirajongithub/owasp_kalp_mobile_project) OWASP KALP Mobile Project is an android application developed for users to view OWASP Top 10 (WEB and MOBILE) on mobile devices.
- [**7**Star][2y] [Py] [sathish09/xender2shell](https://github.com/sathish09/xender2shell) 利用 web.xender.com 入侵用户的 Android 手机
- [**7**Star][2m] [C++] [amrashraf/androshield](https://github.com/amrashraf/androshield) An ASP.NET web application that responsible of detecting and reporting vulnerabilities in android applications by static and dynamic analysis methodologies.
- [**6**Star][2y] [C#] [advancedhacker101/android-c-sharp-rat-server](https://github.com/advancedhacker101/android-c-sharp-rat-server) This is a plugin for the c# R.A.T server providing extension to android based phone systems
- [**6**Star][12m] [as0ler/android-examples](https://github.com/as0ler/android-examples) APK's used as example Apps for decompiling
- [**6**Star][5m] [Py] [h1nayoshi/smalien](https://github.com/h1nayoshi/smalien) Information flow analysis tool for Android applications
- [**6**Star][2y] [Py] [silentsignal/android-param-annotate](https://github.com/silentsignal/android-param-annotate) Android parameter annotator for Dalvik/Smali disassembly
- [**6**Star][3y] [Java] [theblixguy/scanlinks](https://github.com/theblixguy/scanlinks) Block unsafe and dangerous links on your Android device!
- [**6**Star][5y] [vaginessa/pwn-pad-arsenal-tools](https://github.com/vaginessa/pwn-pad-arsenal-tools) Penetration Testing Apps for Android Devices


### <a id="fa49f65b8d3c71b36c6924ce51c2ca0c"></a>HotFix


- [**14557**Star][13d] [Java] [tencent/tinker](https://github.com/tencent/tinker) Tinker is a hot-fix solution library for Android, it supports dex, library and resources update without reinstall apk.
- [**6684**Star][3y] [C++] [alibaba/andfix](https://github.com/alibaba/andfix) AndFix is a library that offer hot-fix for Android App.
- [**3462**Star][27d] [Java] [meituan-dianping/robust](https://github.com/meituan-dianping/robust) Robust is an Android HotFix solution with high compatibility and high stability. Robust can fix bugs immediately without a reboot.
- [**1117**Star][6m] [Java] [manbanggroup/phantom](https://github.com/manbanggroup/phantom)  唯一零 Hook 稳定占坑类 Android 热更新插件化方案


### <a id="ec395c8f974c75963d88a9829af12a90"></a>Package


- [**5080**Star][2m] [Java] [meituan-dianping/walle](https://github.com/meituan-dianping/walle) Android Signature V2 Scheme签名下的新一代渠道包打包神器


### <a id="767078c52aca04c452c095f49ad73956"></a>Collection


- [**1663**Star][2y] [Shell] [juude/droidreverse](https://github.com/juude/droidreverse) reverse engineering tools for android
- [**72**Star][9m] [wufengxue/android-reverse](https://github.com/wufengxue/android-reverse) 安卓逆向工具汇总


### <a id="17408290519e1ca7745233afea62c43c"></a>App


- [**12285**Star][11d] [Java] [signalapp/signal-android](https://github.com/signalapp/Signal-Android) A private messenger for Android.


### <a id="7f353b27e45b5de6b0e6ac472b02cbf1"></a>Xposed


- [**8756**Star][2m] [Java] [android-hacker/virtualxposed](https://github.com/android-hacker/virtualxposed) A simple app to use Xposed without root, unlock the bootloader or modify system image, etc.
- [**2559**Star][7m] [taichi-framework/taichi](https://github.com/taichi-framework/taichi) A framework to use Xposed module with or without Root/Unlock bootloader, supportting Android 5.0 ~ 10.0
- [**2034**Star][12d] [Java] [elderdrivers/edxposed](https://github.com/elderdrivers/edxposed) Elder driver Xposed Framework.
- [**1726**Star][1y] [Java] [ac-pm/inspeckage](https://github.com/ac-pm/inspeckage) Android Package Inspector - dynamic analysis with api hooks, start unexported activities and more. (Xposed Module)
- [**1655**Star][2m] [Java] [tiann/epic](https://github.com/tiann/epic) Dynamic java method AOP hook for Android(continution of Dexposed on ART), Supporting 4.0~10.0
- [**1494**Star][2y] [Kotlin] [gh0u1l5/wechatmagician](https://github.com/gh0u1l5/wechatmagician) WechatMagician is a Xposed module written in Kotlin, that allows you to completely control your Wechat.
- [**1296**Star][2m] [Java] [android-hacker/exposed](https://github.com/android-hacker/exposed) A library to use Xposed without root or recovery(or modify system image etc..).
- [**839**Star][5y] [halfkiss/zjdroid](https://github.com/halfkiss/zjdroid) Android app dynamic reverse tool based on Xposed framework.
- [**790**Star][8m] [Java] [blankeer/mdwechat](https://github.com/blankeer/mdwechat) 一个能让微信 Material Design 化的 Xposed 模块
- [**669**Star][12d] [Java] [ganyao114/sandhook](https://github.com/ganyao114/sandhook) Android ART Hook/Native Inline Hook/Single Instruction Hook - support 4.4 - 10.0 32/64 bit - Xposed API Compat
- [**478**Star][2m] [Java] [tornaco/x-apm](https://github.com/tornaco/x-apm) 应用管理 Xposed
- [**424**Star][3y] [Makefile] [mindmac/androideagleeye](https://github.com/mindmac/androideagleeye) An Xposed and adbi based module which is capable of hooking both Java and Native methods targeting Android OS.
- [**322**Star][1y] [C] [smartdone/dexdump](https://github.com/smartdone/dexdump) 快速脱一代壳的xposed插件
- [**309**Star][1m] [bigsinger/androididchanger](https://github.com/bigsinger/androididchanger) Xposed Module for Changing Android Device Info
- [**309**Star][13d] [Java] [ganyao114/sandvxposed](https://github.com/ganyao114/sandvxposed) Xposed environment without root (OS 5.0 - 10.0)
- [**283**Star][2y] [C++] [rovo89/android_art](https://github.com/rovo89/android_art) Android ART with modifications for the Xposed framework.
- [**214**Star][1y] [Kotlin] [paphonb/androidp-ify](https://github.com/paphonb/androidp-ify) [Xposed] Use features introduced in Android P on your O+ Device!
- [**204**Star][1y] [C] [gtoad/android_inline_hook](https://github.com/gtoad/android_inline_hook) Build an so file to automatically do the android_native_hook work. Supports thumb-2/arm32 and ARM64 ! With this, tools like Xposed can do android native hook.
- [**127**Star][2y] [Java] [bmax121/budhook](https://github.com/bmax121/budhook) An Android hook framework written like Xposed,based on YAHFA.
- [**120**Star][3y] [Java] [rastapasta/pokemon-go-xposed](https://github.com/rastapasta/pokemon-go-xposed) 
- [**79**Star][4m] [Go] [tillson/git-hound](https://github.com/tillson/git-hound) GitHound pinpoints exposed API keys on GitHub using pattern matching, commit history searching, and a unique result scoring system. A batch-catching, pattern-matching, patch-attacking secret snatcher.
- [**71**Star][1m] [Java] [lianglixin/sandvxposed](https://github.com/lianglixin/sandvxposed) Xposed environment without root (OS 5.0 - 10.0)
- [**64**Star][10m] [FreeMarker] [dvdandroid/xposedmoduletemplate](https://github.com/dvdandroid/xposedmoduletemplate) Easily create a Xposed Module with Android Studio
- [**64**Star][8d] [uniking/dingding](https://github.com/uniking/dingding) 免root远程钉钉打卡，支持wifi和gps定位，仅支持android系统。本项目出于学习目的，仅用于学习玩耍,请于24小时后自行删除。xposed, crack,package,dingtalk,remote control
- [**49**Star][11m] [Py] [hrkfdn/deckard](https://github.com/hrkfdn/deckard) Deckard performs static and dynamic binary analysis on Android APKs to extract Xposed hooks
- [**38**Star][10m] [Java] [egguncle/xposednavigationbar](https://github.com/egguncle/xposednavigationbar) Xposed导航栏功能拓展模块
- [**36**Star][8m] [Py] [anantshri/ds_store_crawler_parser](https://github.com/anantshri/ds_store_crawler_parser) a parser + crawler for .DS_Store files exposed publically
- [**34**Star][5y] [Java] [wooyundota/intentmonitor](https://github.com/wooyundota/intentmonitor) Tool based xposed can monitor the android intents
- [**28**Star][5y] [Java] [mindmac/xposedautomation](https://github.com/mindmac/xposedautomation) A demo to show how to install Xposed and enable Xposed based module automatically
- [**26**Star][5y] [Java] [twilightgod/malwarebuster](https://github.com/twilightgod/malwarebuster) This is a Xposed module. It helps to prevent malwares to register service/receiver which were disabled in My Android Tools before.


### <a id="50f63dce18786069de2ec637630ff167"></a>Pack&&Unpack


- [**1793**Star][8m] [C++] [wrbug/dumpdex](https://github.com/wrbug/dumpdex) Android unpack
- [**1620**Star][3y] [Makefile] [drizzlerisk/drizzledumper](https://github.com/drizzlerisk/drizzledumper) a memory-search-based Android unpack tool.
- [**1465**Star][3m] [C++] [vaibhavpandeyvpz/apkstudio](https://github.com/vaibhavpandeyvpz/apkstudio) Open-source, cross platform Qt based IDE for reverse-engineering Android application packages.
- [**1036**Star][3y] [C++] [zyq8709/dexhunter](https://github.com/zyq8709/dexhunter) General Automatic Unpacking Tool for Android Dex Files
- [**811**Star][4m] [C] [strazzere/android-unpacker](https://github.com/strazzere/android-unpacker) Android Unpacker presented at Defcon 22: Android Hacker Protection Level 0
- [**712**Star][2m] [YARA] [rednaga/apkid](https://github.com/rednaga/apkid) Android Application Identifier for Packers, Protectors, Obfuscators and Oddities - PEiD for Android
- [**366**Star][3m] [Java] [patrickfav/uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) A cli tool that helps signing and zip aligning single or multiple Android application packages (APKs) with either debug or provided release certificates. It supports v1, v2 and v3 Android signing scheme has an embedded debug keystore and auto verifies after signing.
- [**322**Star][6m] [Shell] [1n3/reverseapk](https://github.com/1n3/reverseapk) Quickly analyze and reverse engineer Android packages
- [**298**Star][2y] [Shell] [checkpointsw/android_unpacker](https://github.com/checkpointsw/android_unpacker) A (hopefully) generic unpacker for packed Android apps.
- [**189**Star][3y] [Py] [drizzlerisk/tunpacker](https://github.com/drizzlerisk/tunpacker) TUnpacker是一款Android脱壳工具
- [**187**Star][3y] [Py] [andy10101/apkdetecter](https://github.com/andy10101/apkdetecter) Android Apk查壳工具及源代码
- [**148**Star][3y] [Py] [drizzlerisk/bunpacker](https://github.com/drizzlerisk/bunpacker) BUnpacker是一款Android脱壳工具
- [**105**Star][4y] [Java] [liuyufei/sslkiller](https://github.com/liuyufei/sslkiller) SSLKiller is used for killing SSL verification functions on Android client side. With SSLKiller, You can intercept app's HTTPS communication packages between the client and server.
- [**104**Star][3y] [Java] [cvvt/apptroy](https://github.com/cvvt/apptroy) An Online Analysis System for Packed Android Malware
- [**89**Star][2y] [ObjC] [wooyundota/dumpdex](https://github.com/wooyundota/dumpdex) Android Unpack tool based on Cydia
- [**68**Star][5y] [Py] [ajinabraham/xenotix-apk-reverser](https://github.com/ajinabraham/xenotix-apk-reverser) Xenotix APK Reverser is an OpenSource Android Application Package (APK) decompiler and disassembler powered by dex2jar, baksmali and jd-core.
- [**30**Star][8m] [Java] [cristianturetta/mad-spy](https://github.com/cristianturetta/mad-spy) We developed a malware for educational purposes. In particular, our goal is to provide a PoC of what is known as a Repacking attack, a known technique widely used by malware cybercrooks to trojanize android apps. The answer to solve this particular goal boils down in the simplicity of APK decompiling and smali code injection.
- [**22**Star][13d] [Py] [botherder/snoopdroid](https://github.com/botherder/snoopdroid) Extract packages from an Android device
- [**10**Star][2y] [Shell] [nickdiego/docker-ollvm](https://github.com/nickdiego/docker-ollvm) Easily build and package Obfuscator-LLVM into Android NDK.


### <a id="596b6cf8fd36bc4c819335f12850a915"></a>HOOK


- [**1500**Star][27d] [C] [iqiyi/xhook](https://github.com/iqiyi/xhook) a PLT (Procedure Linkage Table) hook library for Android native ELF 
- [**1494**Star][9d] [C++] [jmpews/dobby](https://github.com/jmpews/Dobby) a lightweight, multi-platform, multi-architecture hook framework.
- [**804**Star][25d] [C++] [aslody/whale](https://github.com/aslody/whale) Hook Framework for Android/IOS/Linux/MacOS
- [**530**Star][7m] [Java] [aslody/andhook](https://github.com/asLody/AndHook) Android dynamic instrumentation framework
- [**400**Star][3y] [Java] [pqpo/inputmethodholder](https://github.com/pqpo/inputmethodholder) A keyboard listener for Android which by hooking the InputMethodManager. 
- [**361**Star][8m] [C] [turing-technician/fasthook](https://github.com/turing-technician/fasthook) Android ART Hook
- [**216**Star][3y] [Java] [zhengmin1989/wechatsportcheat](https://github.com/zhengmin1989/wechatsportcheat) 手把手教你当微信运动第一名 – 利用Android Hook进行微信运动作弊
- [**190**Star][4y] [C++] [aslody/elfhook](https://github.com/aslody/elfhook) modify PLT to hook api, supported android 5\6.
- [**123**Star][9m] [Java] [turing-technician/virtualfasthook](https://github.com/turing-technician/virtualfasthook) Android application hooking tool based on FastHook + VirtualApp
- [**58**Star][3y] [Java] [nightoftwelve/virtualhookex](https://github.com/nightoftwelve/virtualhookex) Android application hooking tool based on VirtualHook/VirtualApp
- [**54**Star][3y] [Rust] [nccgroup/assethook](https://github.com/nccgroup/assethook) LD_PRELOAD magic for Android's AssetManager
- [**36**Star][27d] [C++] [chickenhook/chickenhook](https://github.com/chickenhook/chickenhook) A linux / android / MacOS hooking framework


### <a id="5afa336e229e4c38ad378644c484734a"></a>Emulator


- [**1492**Star][1y] [C++] [f1xpl/openauto](https://github.com/f1xpl/openauto) AndroidAuto headunit emulator
- [**532**Star][7m] [Java] [limboemu/limbo](https://github.com/limboemu/limbo) Limbo is a QEMU-based emulator for Android. It currently supports PC & ARM emulation for Intel x86 and ARM architecture. See our wiki
- [**471**Star][3m] [Java] [strazzere/anti-emulator](https://github.com/strazzere/anti-emulator) Android Anti-Emulator
- [**428**Star][2y] [Py] [evilsocket/smali_emulator](https://github.com/evilsocket/smali_emulator) This software will emulate a smali source file generated by apktool.
- [**202**Star][3y] [Py] [mseclab/nathan](https://github.com/mseclab/nathan) Android Emulator for mobile security testing
- [**168**Star][12m] [Py] [mnkgrover08-zz/whatsapp_automation](https://github.com/mnkgrover08-zz/whatsapp_automation) Whatsapp Automation is a collection of APIs that interact with WhatsApp messenger running in an Android emulator, allowing developers to build projects that automate sending and receiving messages, adding new contacts and broadcasting messages multiple contacts.
- [**148**Star][5y] [C] [strazzere/android-lkms](https://github.com/strazzere/android-lkms) Android Loadable Kernel Modules - mostly used for reversing and debugging on controlled systems/emulators
- [**27**Star][2y] [Shell] [gustavosotnas/avd-launcher](https://github.com/gustavosotnas/avd-launcher) Front-end to Android Virtual Devices (AVDs) emulator from Google.
- [**16**Star][1y] [Py] [abhi-r3v0/droxes](https://github.com/abhi-r3v0/droxes) A simple script to turn an Android device/emulator into a test-ready box.


### <a id="0a668d220ce74e11ed2738c4e3ae3c9e"></a>IDA


- [**161**Star][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->Specific Target->Loader](#cb59d84840e41330a7b5e275c0b81725) |[Android->Tools->Recent Add](#63fd2c592145914e99f837cecdc5a67c) |
- [**118**Star][4y] [Py] [cvvt/dumpdex](https://github.com/cvvt/dumpdex) IDA python script to dynamically dump DEX in memory
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |
- [**83**Star][2y] [Py] [zhkl0228/androidattacher](https://github.com/zhkl0228/androidattacher) IDA debugging plugin for android armv7 so
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |
- [**39**Star][5y] [Py] [techbliss/adb_helper_qt_super_version](https://github.com/techbliss/adb_helper_qt_super_version) All You Need For Ida Pro And Android Debugging
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |
- [**39**Star][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) some idapython scripts for android debugging.
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->Tools->Debug->No Category](#2944dda5289f494e5e636089db0d6a6a) |
- [**16**Star][7y] [C++] [strazzere/dalvik-header-plugin](https://github.com/strazzere/dalvik-header-plugin) Dalvik Header Plugin for IDA Pro
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |


### <a id="bb9f8e636857320abf0502c19af6c763"></a>Debug


- [**10794**Star][1m] [Java] [konloch/bytecode-viewer](https://github.com/konloch/bytecode-viewer) A Java 8+ Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More)
- [**6762**Star][10m] [Java] [amitshekhariitbhu/android-debug-database](https://github.com/amitshekhariitbhu/android-debug-database) A library for debugging android databases and shared preferences - Make Debugging Great Again
- [**527**Star][5y] [Py] [swdunlop/andbug](https://github.com/swdunlop/andbug) Android Debugging Library
- [**468**Star][7y] [Shell] [kosborn/p2p-adb](https://github.com/kosborn/p2p-adb) Phone to Phone Android Debug Bridge - A project for "debugging" phones... from other phones.
- [**123**Star][3y] [C++] [cheetahsec/avmdbg](https://github.com/cheetahsec/avmdbg) a lightweight debugger for android virtual machine.
- [**106**Star][6y] [Java] [isecpartners/android-opendebug](https://github.com/isecpartners/android-opendebug) Make any application debuggable
- [**98**Star][4y] [Py] [cx9527/strongdb](https://github.com/cx9527/strongdb) gdb plugin for android debugging
- [**65**Star][6y] [Py] [anbc/andbug](https://github.com/anbc/andbug) Android Debugging Library
- [**57**Star][3y] [C] [gnaixx/anti-debug](https://github.com/gnaixx/anti-debug) Android detect debugger
- [**56**Star][5m] [Shell] [wuseman/wbruter](https://github.com/wuseman/wbruter) Crack your non-rooted android device pin code with 100% guarantee aslong as usb debugging has been enable. Wbruter also has support for parallel ssh brute forcing via pssh
- [**22**Star][1y] [C++] [gtoad/android_anti_debug](https://github.com/gtoad/android_anti_debug) An example of android anti-debug.


### <a id="f975a85510f714ec3cc2551e868e75b8"></a>Malware


- [**429**Star][4m] [Shell] [ashishb/android-malware](https://github.com/ashishb/android-malware) Collection of android malware samples
- [**347**Star][3m] [Java] [droidefense/engine](https://github.com/droidefense/engine) Droidefense: Advance Android Malware Analysis Framework
- [**192**Star][4y] [HTML] [faber03/androidmalwareevaluatingtools](https://github.com/faber03/androidmalwareevaluatingtools) Evaluation tools for malware Android
- [**123**Star][2y] [Java] [brompwnie/uitkyk](https://github.com/brompwnie/uitkyk) Android Frida库, 用于分析App查找恶意行为
    - Also In Section: [DBI->Frida->Tools->Recent Add](#54836a155de0c15b56f43634cd9cfecf) |
- [**117**Star][7y] [C] [secmobi/amatutor](https://github.com/secmobi/amatutor) Android恶意代码分析教程
- [**97**Star][2y] [Lua] [niallmcl/deep-android-malware-detection](https://github.com/niallmcl/deep-android-malware-detection) Code for Deep Android Malware Detection paper
- [**82**Star][5y] [Py] [maldroid/maldrolyzer](https://github.com/maldroid/maldrolyzer) Simple framework to extract "actionable" data from Android malware (C&Cs, phone numbers etc.)
- [**67**Star][10m] [dkhuuthe/madlira](https://github.com/dkhuuthe/madlira) Malware detection using learning and information retrieval for Android
- [**65**Star][1y] [Py] [mwleeds/android-malware-analysis](https://github.com/mwleeds/android-malware-analysis) This project seeks to apply machine learning algorithms to Android malware classification.
- [**65**Star][4y] [C++] [soarlab/maline](https://github.com/soarlab/maline) Android Malware Detection Framework
- [**59**Star][6m] [Py] [hgascon/adagio](https://github.com/hgascon/adagio) Structural Analysis and Detection of Android Malware
- [**49**Star][3y] [HTML] [mburakergenc/malware-detection-using-machine-learning](https://github.com/mburakergenc/malware-detection-using-machine-learning) Malware detection project on Android devices using machine learning classification algorithms.
- [**49**Star][2y] [java] [toufikairane/andromalware](https://github.com/tfairane/andromalware) Android Malware for educational purpose
- [**46**Star][1y] [Py] [maoqyhz/droidcc](https://github.com/maoqyhz/droidcc) Android malware detection using deep learning, contains android malware samples, papers, tools etc.
- [**40**Star][2y] [Java] [miwong/intellidroid](https://github.com/miwong/intellidroid) A targeted input generator for Android that improves the effectiveness of dynamic malware analysis.
- [**40**Star][1y] [traceflight/android-malware-datasets](https://github.com/traceflight/android-malware-datasets) Popular Android malware datasets
- [**33**Star][5y] [Shell] [vt-magnum-research/antimalware](https://github.com/vt-magnum-research/antimalware) Dynamic malware analysis for the Android platform
- [**29**Star][2y] [virqdroid/android_malware](https://github.com/virqdroid/android_malware) 
- [**27**Star][3y] [fouroctets/android-malware-samples](https://github.com/fouroctets/android-malware-samples) Android Malware Samples
- [**24**Star][3y] [Py] [bunseokbot/androtools](https://github.com/bunseokbot/androtools) Android malware static & dynamic analysis and automated action (deprecated)
- [**19**Star][2y] [Py] [namk12/malware-detection](https://github.com/namk12/malware-detection) Deep Learning Based Android Malware Detection Framework
- [**15**Star][3y] [Java] [darrylburke/androidmalwareexample](https://github.com/darrylburke/androidmalwareexample) Proof of Concept example of Android Malware used for Research Purposes
- [**13**Star][5y] [JS] [cheverebe/android-malware](https://github.com/cheverebe/android-malware) Injected malicious code into legitimate andoid applications. Converted a keyboard app into a keylogger and an MP3 downloader into an image thief.
- [**13**Star][6m] [HTML] [fmind/euphony](https://github.com/fmind/euphony) Harmonious Unification of Cacophonous Anti-Virus Vendor Labels for Android Malware
- [**13**Star][9m] [Py] [vinayakumarr/android-malware-detection](https://github.com/vinayakumarr/android-malware-detection) Android malware detection using static and dynamic analysis
- [**11**Star][3m] [Py] [jacobsoo/amtracker](https://github.com/jacobsoo/amtracker) Android Malware Tracker
- [**11**Star][2y] [Py] [tlatkdgus1/android-malware-analysis-system](https://github.com/tlatkdgus1/android-malware-analysis-system) Android Malware Detection based on Deep Learning
- [**9**Star][4y] [Java] [acprimer/malwaredetector](https://github.com/acprimer/malwaredetector) android malwarre detector
- [**9**Star][2y] [Py] [mldroid/csbd](https://github.com/mldroid/csbd) The repository contains the python implementation of the Android Malware Detection paper: "Empirical assessment of machine learning-based malware detectors for Android: Measuring the Gap between In-the-Lab and In-the-Wild Validation Scenarios"
- [**7**Star][3y] [Java] [waallen/http-sms-android-malware](https://github.com/waallen/http-sms-android-malware) HTTP and SMS spam testing application
- [**6**Star][7y] [Java] [ssesha/malwarescanner](https://github.com/ssesha/malwarescanner) Android app performing hash based malware detection
- [**6**Star][3y] [Py] [tuomao/android_malware_detection](https://github.com/tuomao/android_malware_detection) 
- [**6**Star][8y] [Java] [twitter-university/antimalware](https://github.com/twitter-university/antimalware) An Android Eclipse project demonstrating how to build a simple anti-malware application
- [**6**Star][1y] [Py] [aliemamalinezhad/machine-learning](https://github.com/aliemamalinezhad/machine-learning) android-malware-classification using machine learning algorithms


### <a id="1d83ca6d8b02950be10ac8e4b8a2d976"></a>Obfuscate


- [**3078**Star][2m] [Java] [calebfenton/simplify](https://github.com/calebfenton/simplify) Generic Android Deobfuscator
- [**294**Star][4m] [C] [shadowsocks/simple-obfs-android](https://github.com/shadowsocks/simple-obfs-android) A simple obfuscating tool for Android
- [**76**Star][4y] [Java] [enovella/jebscripts](https://github.com/enovella/jebscripts) A set of JEB Python/Java scripts for reverse engineering Android obfuscated code
- [**12**Star][1m] [Py] [omirzaei/androdet](https://github.com/omirzaei/androdet) AndrODet: An Adaptive Android Obfuscation Detector
- [**11**Star][1y] [Java] [miwong/tiro](https://github.com/miwong/tiro) TIRO - A hybrid iterative deobfuscation framework for Android applications


### <a id="6d2b758b3269bac7d69a2d2c8b45194c"></a>Reverse Engineering


- [**9285**Star][1m] [Java] [ibotpeaches/apktool](https://github.com/ibotpeaches/apktool) A tool for reverse engineering Android apk files
- [**2053**Star][1m] [Java] [genymobile/gnirehtet](https://github.com/genymobile/gnirehtet) Gnirehtet provides reverse tethering for Android
- [**585**Star][3m] [C++] [secrary/andromeda](https://github.com/secrary/andromeda) Andromeda - Interactive Reverse Engineering Tool for Android Applications [This project is not maintained anymore]
- [**554**Star][3y] [Java] [linchaolong/apktoolplus](https://github.com/linchaolong/apktoolplus) apk analysis tool
- [**545**Star][20d] [maddiestone/androidappre](https://github.com/maddiestone/androidappre) Android App Reverse Engineering Workshop
- [**331**Star][7y] [Java] [brutall/brut.apktool](https://github.com/brutall/brut.apktool) A tool for reverse engineering Android apk files
- [**267**Star][10m] [Dockerfile] [cryptax/androidre](https://github.com/cryptax/androidre) Reverse engineering Android
- [**246**Star][28d] [C++] [strazzere/android-scripts](https://github.com/strazzere/android-scripts) Collection of Android reverse engineering scripts
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |
- [**102**Star][3y] [feicong/android-app-sec](https://github.com/feicong/android-app-sec) ISC 2016安全训练营－安卓app逆向与安全防护 ppt
- [**54**Star][6m] [Smali] [hellohudi/androidreversenotes](https://github.com/hellohudi/androidreversenotes) Android逆向笔记---从入门到入土
- [**54**Star][9y] [Emacs Lisp] [nelhage/reverse-android](https://github.com/nelhage/reverse-android) Reverse-engineering tools for Android applications
- [**32**Star][3y] [nextco/android-decompiler](https://github.com/nextco/android-decompiler) A hight quality list of tools to reverse engineering code from android.
- [**16**Star][3m] [Smali] [freedom-wy/reverse_android](https://github.com/freedom-wy/reverse_android) 安卓从开发到逆向
- [**11**Star][2y] [Smali] [yifengyou/android-software-security-and-reverse-analysis](https://github.com/yifengyou/android-software-security-and-reverse-analysis) Android软件安全与逆向分析
- [**6**Star][2y] [CSS] [oscar0812/apktoolfx](https://github.com/oscar0812/apktoolfx) A GUI for Apktool to make reverse engineering of android apps a breeze.




***


## <a id="f0493b259e1169b5ddd269b13cfd30e6"></a>Posts&&Videos


- 2019.12 [aliyun] [Android智能终端系统的安全加固（上）](https://xz.aliyun.com/t/6852)
- 2019.11 [venus] [Android勒索病毒分析（上）](https://paper.seebug.org/1085/)


# <a id="069664f347ae73b1370c4f5a2ec9da9f"></a>Apple&&iOS&&iXxx


***


## <a id="830f40713cef05f0665180d840d56f45"></a>Mach-O


### <a id="9b0f5682dc818c93c4de3f46fc3f43d0"></a>Tools


- [**2540**Star][10m] [ObjC] [nygard/class-dump](https://github.com/nygard/class-dump) Generate Objective-C headers from Mach-O files.
- [**2389**Star][2y] [Py] [secretsquirrel/the-backdoor-factory](https://github.com/secretsquirrel/the-backdoor-factory) Patch PE, ELF, Mach-O binaries with shellcode (NOT Supported)
- [**2140**Star][2m] [Py] [jonathansalwan/ropgadget](https://github.com/jonathansalwan/ropgadget) This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation. ROPgadget supports ELF, PE and Mach-O format on x86, x64, ARM, ARM64, PowerPC, SPARC and MIPS architectures.
- [**1471**Star][3y] [ObjC] [polidea/ios-class-guard](https://github.com/polidea/ios-class-guard) Simple Objective-C obfuscator for Mach-O executables.
- [**856**Star][3y] [C++] [0vercl0k/rp](https://github.com/0vercl0k/rp) rp++ is a full-cpp written tool that aims to find ROP sequences in PE/Elf/Mach-O x86/x64 binaries. It is open-source and has been tested on several OS: Debian / Windows 8.1 / Mac OSX Lion (10.7.3). Moreover, it is x64 compatible and supports Intel syntax. Standalone executables can also be directly downloaded.
- [**399**Star][2m] [Logos] [limneos/classdump-dyld](https://github.com/limneos/classdump-dyld) Class-dump any Mach-o file without extracting it from dyld_shared_cache
- [**331**Star][3y] [C] [steakknife/unsign](https://github.com/steakknife/unsign) Remove code signatures from OSX Mach-O binaries (note: unsigned binaries cannot currently be re-codesign'ed. Patches welcome!)
- [**269**Star][5y] [C] [conradev/dumpdecrypted](https://github.com/conradev/dumpdecrypted) Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk. This tool is necessary for security researchers to be able to look under the hood of encryption.
- [**265**Star][8m] [ObjC] [devaukz/macho-kit](https://github.com/devaukz/macho-kit) A C/Objective-C library for parsing Mach-O files.
- [**238**Star][3y] [aidansteele/osx-abi-macho-file-format-reference](https://github.com/aidansteele/osx-abi-macho-file-format-reference) Mirror of OS X ABI Mach-O File Format Reference
- [**197**Star][2y] [ObjC] [alonemonkey/dumpdecrypted](https://github.com/alonemonkey/dumpdecrypted) Dumps decrypted mach-o files from encrypted applications、framework or app extensions.
- [**178**Star][4m] [ObjC] [yulingtianxia/apporderfiles](https://github.com/yulingtianxia/apporderfiles) The easiest way to generate order files for Mach-O using Clang. Improving App Performance.
- [**150**Star][2y] [C] [alexdenisov/bitcode_retriever](https://github.com/alexdenisov/bitcode_retriever) Retrieves Bitcode from Mach-O binaries
- [**148**Star][14d] [Rust] [m4b/faerie](https://github.com/m4b/faerie) Magical ELF and Mach-o object file writer backend
- [**137**Star][2y] [ObjC] [bluecocoa/class-dump](https://github.com/bluecocoa/class-dump) Generate Objective-C headers from Mach-O files.
- [**124**Star][8m] [Swift] [devaukz/macho-explorer](https://github.com/devaukz/macho-explorer) A graphical Mach-O viewer for macOS. Powered by Mach-O Kit.
- [**105**Star][2y] [C++] [tyilo/macho_edit](https://github.com/tyilo/macho_edit) Command line utility for modifying Mach-O binaries in various ways.
- [**100**Star][4y] [Py] [jonathansalwan/abf](https://github.com/jonathansalwan/abf) Abstract Binary Format Manipulation - ELF, PE and Mach-O format
- [**62**Star][7y] [C] [gdbinit/osx_boubou](https://github.com/gdbinit/osx_boubou) A PoC Mach-O infector via library injection
- [**48**Star][5m] [ObjC] [dcsch/macho-browser](https://github.com/dcsch/macho-browser) Mac browser for Mach-O binaries (macOS, iOS, watchOS, and tvOS)
- [**39**Star][5y] [C] [x43x61x69/codeunsign](https://github.com/x43x61x69/codeunsign) A Mach-O binary codesign remover.
- [**35**Star][3y] [Py] [airbus-seclab/elfesteem](https://github.com/airbus-seclab/elfesteem) ELF/PE/Mach-O parsing library
- [**31**Star][1m] [Rust] [flier/rust-macho](https://github.com/flier/rust-macho) Mach-O File Format Parser for Rust
- [**20**Star][3y] [Py] [njsmith/machomachomangler](https://github.com/njsmith/machomachomangler) Tools for mangling Mach-O and PE binaries
- [**20**Star][11m] [C] [geosn0w/machdump](https://github.com/geosn0w/machdump) A very basic C Mach-O Header Dump tool written for practicing purposes. Works With x86 and x86_64 binaries
- [**17**Star][4m] [JS] [indutny/macho](https://github.com/indutny/macho) Mach-O parser for node.js
- [**11**Star][7y] [C] [gdbinit/calcspace](https://github.com/gdbinit/calcspace) Small util to calculate available free space in mach-o binaries for code injection
- [**10**Star][4y] [OCaml] [m4b/bin2json](https://github.com/m4b/bin2json) Converts ELF, mach-o, or PE binaries to a JSON representation


### <a id="750700dcc62fbd83e659226db595b5cc"></a>Post


- 2017.11 [pnfsoftware] [Having Fun with Obfuscated Mach-O Files](https://www.pnfsoftware.com/blog/having-fun-with-obfuscated-mach-o-files/)
- 2017.03 [lse] [Playing with Mach-O binaries and dyld](https://blog.lse.epita.fr:443/articles/82-playing-with-mach-os-and-dyld.html)
- 2017.03 [lse] [Playing with Mach-O binaries and dyld](https://blog.lse.epita.fr/articles/82-playing-with-mach-os-and-dyld.html)
- 2017.02 [venus] [Mach-O 脱壳技巧一则](https://paper.seebug.org/202/)
- 2016.05 [turingh] [nlist-Mach-O文件重定向信息数据结构分析](http://turingh.github.io/2016/05/24/nlist-Mach-O%E6%96%87%E4%BB%B6%E9%87%8D%E5%AE%9A%E5%90%91%E4%BF%A1%E6%81%AF%E6%95%B0%E6%8D%AE%E7%BB%93%E6%9E%84%E5%88%86%E6%9E%90/)
- 2016.05 [pediy] [[原创]初探Mach-O学习小记(附源码)](https://bbs.pediy.com/thread-209957.htm)
- 2016.03 [turingh] [OSX内核加载mach-o流程分析](http://turingh.github.io/2016/03/30/OSX%E5%86%85%E6%A0%B8%E5%8A%A0%E8%BD%BDmach-o%E6%B5%81%E7%A8%8B%E5%88%86%E6%9E%90/)
- 2016.03 [pediy] [[原创]Mach-O动态连接的简单分析(延时绑定)](https://bbs.pediy.com/thread-208455.htm)
- 2016.03 [turingh] [Mach-O的动态链接相关知识](http://turingh.github.io/2016/03/10/Mach-O%E7%9A%84%E5%8A%A8%E6%80%81%E9%93%BE%E6%8E%A5/)
- 2016.03 [pediy] [[原创]Mach-O格式分析](https://bbs.pediy.com/thread-208357.htm)
- 2016.03 [turingh] [mach-o格式分析](http://turingh.github.io/2016/03/07/mach-o%E6%96%87%E4%BB%B6%E6%A0%BC%E5%BC%8F%E5%88%86%E6%9E%90/)
- 2016.03 [pediy] [[原创]dyld加载mach-o文件分析](https://bbs.pediy.com/thread-208255.htm)
- 2016.03 [turingh] [dyld中mach-o文件加载的简单分析](http://turingh.github.io/2016/03/01/dyld%E4%B8%ADmacho%E5%8A%A0%E8%BD%BD%E7%9A%84%E7%AE%80%E5%8D%95%E5%88%86%E6%9E%90/)
- 2014.09 [pediy] [[原创]mach-o文件格式学习记录](https://bbs.pediy.com/thread-192657.htm)
- 2014.09 [cerbero] [Stripping symbols from a Mach-O](http://cerbero-blog.com/?p=1483)
- 2014.08 [secureallthethings] [Patching the Mach-o Format the Simple and Easy Way](http://secureallthethings.blogspot.com/2014/08/patching-mach-o-format-simple-and-easy.html)
- 2013.06 [cerbero] [Mach-O support (including Universal Binaries and Apple Code Signatures)](http://cerbero-blog.com/?p=1139)
- 2013.05 [volatility] [MoVP II - 1.1 - Mach-O Address Space](https://volatility-labs.blogspot.com/2013/05/movp-ii-11-mach-o-address-space.html)
- 2013.03 [reverse] [OS.X/Boubou – Mach-O infector PoC source code](https://reverse.put.as/2013/03/05/os-xboubou-mach-o-infector-poc-source-code/)
- 2012.02 [reverse] [A little more fun with Mach-O headers: adding and spoofing a constructor](https://reverse.put.as/2012/02/06/a-little-more-fun-with-mach-o-headers-adding-and-spoofing-a-constructor/)
- 2012.02 [reverse] [Anti-disassembly & obfuscation #1: Apple doesn’t follow their own Mach-O specifications?](https://reverse.put.as/2012/02/02/anti-disassembly-obfuscation-1-apple-doesnt-follow-their-own-mach-o-specifications/)
- 2011.11 [thireus] [execve("/bin//sh", ["/bin//sh"], NULL) - MacOS mach-o-x86-64](https://blog.thireus.com/execvebinsh-binsh-null-macos-mach-o-x86-64/)
- 2010.01 [reverse] [A new util to process Mach-O binaries information (or a replacement to otool -l)](https://reverse.put.as/2010/01/05/a-new-util-to-process-mach-o-binaries-information-or-a-replacement-to-otool-l/)
- 2009.03 [reverse] [Mach-O binary offset calculator](https://reverse.put.as/2009/03/13/mach-o-binary-offset-calculator/)




***


## <a id="bba00652bff1672ab1012abd35ac9968"></a>JailBreak


### <a id="ff19d5d94315d035bbcb3ef0c348c75b"></a>Tools


- [**5451**Star][3m] [Py] [axi0mx/ipwndfu](https://github.com/axi0mx/ipwndfu) open-source jailbreaking tool for many iOS devices
- [**5390**Star][6m] [C] [pwn20wndstuff/undecimus](https://github.com/pwn20wndstuff/undecimus) unc0ver jailbreak for iOS 11.0 - 12.4
- [**4248**Star][8m] [ObjC] [alonemonkey/monkeydev](https://github.com/alonemonkey/monkeydev) CaptainHook Tweak、Logos Tweak and Command-line Tool、Patch iOS Apps, Without Jailbreak.
- [**3221**Star][5m] [ObjC] [naituw/ipapatch](https://github.com/naituw/ipapatch) Patch iOS Apps, The Easy Way, Without Jailbreak.
- [**2016**Star][3y] [Swift] [urinx/iosapphook](https://github.com/urinx/iosapphook) 专注于非越狱环境下iOS应用逆向研究，从dylib注入，应用重签名到App Hook
- [**1800**Star][3y] [ObjC] [kpwn/yalu102](https://github.com/kpwn/yalu102) incomplete iOS 10.2 jailbreak for 64 bit devices by qwertyoruiopz and marcograssi
- [**1193**Star][15d] [JS] [alonemonkey/frida-ios-dump](https://github.com/alonemonkey/frida-ios-dump) pull decrypted ipa from jailbreak device
    - Also In Section: [DBI->Frida->Tools->Recent Add](#54836a155de0c15b56f43634cd9cfecf) |
- [**642**Star][2y] [C] [coolstar/electra](https://github.com/coolstar/electra) Electra iOS 11.0 - 11.1.2 jailbreak toolkit based on async_awake
- [**482**Star][2y] [Objective-C++] [bishopfox/bfinject](https://github.com/bishopfox/bfinject) Dylib injection for iOS 11.0 - 11.1.2 with LiberiOS and Electra jailbreaks
- [**430**Star][2y] [ObjC] [jackrex/fakewechatloc](https://github.com/jackrex/fakewechatloc) 手把手教你制作一款iOS越狱App
- [**415**Star][2y] [zhengmin1989/greatiosjailbreakmaterial](https://github.com/zhengmin1989/greatiosjailbreakmaterial) Great iOS Jailbreak Material! - I read hundreds of papers and PPTs. Only list the most useful materials here!
- [**404**Star][1y] [C] [coalfire-research/ios-11.1.2-15b202-jailbreak](https://github.com/coalfire-research/ios-11.1.2-15b202-jailbreak) iOS 11.1.2 (15B202) Jailbreak
- [**386**Star][3y] [ObjC] [kpwn/yalu](https://github.com/kpwn/yalu) incomplete ios 8.4.1 jailbreak by Kim Jong Cracks (8.4.1 codesign & sandbox bypass w/ LPE to root & untether)
- [**384**Star][2y] [Assembly] [sgayou/kindle-5.6.5-jailbreak](https://github.com/sgayou/kindle-5.6.5-jailbreak) Kindle 5.6.5 exploitation tools.
- [**379**Star][2y] [ObjC] [codermjlee/mjapptools](https://github.com/codermjlee/mjapptools) 【越狱-逆向】处理iOS APP信息的命令行工具
- [**375**Star][6y] [C] [heardrwt/revealloader](https://github.com/heardrwt/revealloader) Reveal Loader dynamically loads libReveal.dylib (Reveal.app support) into iOS apps on jailbroken devices.
- [**365**Star][9y] [C] [psgroove/psgroove](https://github.com/psgroove/psgroove) PSGroove
- [**291**Star][4y] [Perl] [bishopfox/theos-jailed](https://github.com/bishopfox/theos-jailed) A version of Theos/CydiaSubstrate for non-jailbroken iOS devices
- [**287**Star][7m] [Shell] [0ki/mikrotik-tools](https://github.com/0ki/mikrotik-tools) Tools for Mikrotik devices -  universal jailbreak tool
- [**273**Star][2y] [C] [bishopfox/bfdecrypt](https://github.com/bishopfox/bfdecrypt) Utility to decrypt App Store apps on jailbroken iOS 11.x
- [**240**Star][2y] [ObjC] [sticktron/g0blin](https://github.com/sticktron/g0blin) a work-in-progress jailbreak for iOS 10.3.x (A7-A9)
- [**237**Star][11m] [C] [geosn0w/osirisjailbreak12](https://github.com/geosn0w/osirisjailbreak12) iOS 12.0 -> 12.1.2 Incomplete Osiris Jailbreak with CVE-2019-6225 by GeoSn0w (FCE365)
- [**200**Star][1y] [ObjC] [sunweiliang/neteasemusiccrack](https://github.com/sunweiliang/neteasemusiccrack) iOS网易云音乐 免VIP下载、去广告、去更新 无需越狱...
- [**199**Star][2y] [ObjC] [tihmstar/doubleh3lix](https://github.com/tihmstar/doubleh3lix) Jailbreak for iOS 10.x 64bit devices without KTRR
- [**193**Star][4y] [C++] [isecpartners/jailbreak](https://github.com/isecpartners/jailbreak) Jailbreak
- [**157**Star][9y] [C] [comex/star](https://github.com/comex/star) the code behind the second incarnation of jailbreakme.com
- [**146**Star][1y] [ObjC] [tihmstar/jelbrektime](https://github.com/tihmstar/jelbrektime) An developer jailbreak for Apple watch S3 watchOS 4.1
- [**145**Star][1y] [Shell] [kirovair/delectra](https://github.com/kirovair/delectra) An uninstaller script for Coolstars' Electra iOS 11.0 - 11.1.2 jailbreak.
- [**145**Star][1y] [ObjC] [psychotea/meridianjb](https://github.com/psychotea/meridianjb) An iOS 10.x Jailbreak for all 64-bit devices.
- [**144**Star][1y] [C] [geosn0w/osiris-jailbreak](https://github.com/geosn0w/osiris-jailbreak) An incomplete iOS 11.2 -> iOS 11.3.1 Jailbreak
- [**144**Star][3y] [ObjC] [project-imas/security-check](https://github.com/project-imas/security-check) Application level, attached debug detect and jailbreak checking
- [**128**Star][5y] [C] [stefanesser/opensource_taig](https://github.com/stefanesser/opensource_taig) Lets create an open source version of the latest TaiG jailbreak.
- [**111**Star][2y] [C] [openjailbreak/evasi0n6](https://github.com/openjailbreak/evasi0n6) Evasi0n6 Jailbreak by Evad3rs for iOS 6.0-6.1.2
- [**110**Star][2y] [ObjC] [rozbo/ios-pubgm-hack](https://github.com/rozbo/ios-pubgm-hack) iOS吃鸡辅助
- [**109**Star][10m] [ObjC] [devapple/yalu103](https://github.com/devapple/yalu103) incomplete iOS 10.3Betas jailbreak for 64 bit devices by qwertyoruiopz, marcograssi, and devapple (personal use)
- [**108**Star][10d] [HTML] [cj123/canijailbreak.com](https://github.com/cj123/canijailbreak.com) a website which tells you whether you can jailbreak your iOS device.
- [**100**Star][2y] [Objective-C++] [electrajailbreak/cydia](https://github.com/electrajailbreak/cydia) Cydia modified for iOS 11/Electra
- [**99**Star][2y] [ObjC] [geosn0w/yalu-jailbreak-ios-10.2](https://github.com/geosn0w/yalu-jailbreak-ios-10.2) My own fork of (Beta) Yalu Jailbreak for iOS 10.0 to 10.2 by
- [**96**Star][3y] [Py] [chaitin/pro](https://github.com/chaitin/pro) A crappy tool used in our private PS4 jailbreak
- [**93**Star][7y] [C] [planetbeing/ios-jailbreak-patchfinder](https://github.com/planetbeing/ios-jailbreak-patchfinder) Analyzes a binary iOS kernel to determine function offsets and where to apply the canonical jailbreak patches.
- [**89**Star][3y] [ObjC] [jamie72/ipapatch](https://github.com/jamie72/ipapatch) Patch iOS Apps, The Easy Way, Without Jailbreak.
- [**89**Star][3y] [Logos] [thomasfinch/priorityhub](https://github.com/thomasfinch/priorityhub) Sorted notifications jailbreak tweak
- [**83**Star][6m] [ObjC] [smilezxlee/zxhookdetection](https://github.com/smilezxlee/zxhookdetection) 【iOS应用安全】hook及越狱的基本防护与检测(动态库注入检测、hook检测与防护、越狱检测、签名校验)
- [**80**Star][2y] [C] [axi0mx/ios-kexec-utils](https://github.com/axi0mx/ios-kexec-utils) boot LLB/iBoot/iBSS/iBEC image from a jailbroken iOS kernel
- [**77**Star][1y] [JS] [mtjailed/jailbreakme](https://github.com/mtjailed/jailbreakme) A webbased jailbreak solution unifying existing jailbreak me solutions and new ones.
- [**72**Star][2y] [ObjC] [sunweiliang/baiduyuncrack](https://github.com/sunweiliang/baiduyuncrack) iOS百度云盘 破解速度限制、去广告、去更新 无需越狱~
- [**65**Star][3y] [ObjC] [zhengmin1989/yalu102](https://github.com/zhengmin1989/yalu102) incomplete iOS 10.2 jailbreak for 64 bit devices by qwertyoruiopz and marcograssi
- [**62**Star][2y] [ObjC] [rickhe/rhwechat](https://github.com/rickhe/rhwechat) iOS 无需越狱逆向微信：自动抢红包
- [**58**Star][2y] [C++] [openjailbreak/jailbreakme-1.0](https://github.com/openjailbreak/jailbreakme-1.0) The first publicly available userland jailbreak for iPhoneOS 1.0.2/1.1.1 by cmw and dre
- [**55**Star][1y] [JS] [userlandkernel/jailbreakme-unified](https://github.com/userlandkernel/jailbreakme-unified) Framework for iOS browser exploitation to kernel privileges and rootfs remount
- [**53**Star][5m] [Py] [n0fate/ichainbreaker](https://github.com/n0fate/ichainbreaker) Breaking the iCloud Keychain Artifacts
- [**52**Star][2y] [Shell] [alephsecurity/initroot](https://github.com/alephsecurity/initroot) Motorola Untethered Jailbreak: Exploiting CVE-2016-10277 for Secure Boot and Device Locking bypass
- [**51**Star][1y] [C] [pwn20wndstuff/osiris](https://github.com/pwn20wndstuff/osiris) Osiris developer jailbreak for iOS 11.0 - 11.4b3
- [**50**Star][9m] [Swift] [joncardasis/to-the-apples-core](https://github.com/joncardasis/to-the-apples-core) A collection of non-jailbroken code snippets on reverse-engineered iOS private apis
- [**49**Star][2y] [JS] [idan5x/switcheroo](https://github.com/idan5x/switcheroo) Exploiting CVE-2016-4657 to JailBreak the Nintendo Switch
- [**47**Star][7m] [Py] [ivrodriguezca/decrypt-ios-apps-script](https://github.com/ivrodriguezca/decrypt-ios-apps-script) Python script to SSH into your jailbroken device, decrypt an iOS App and transfer it to your local machine
- [**45**Star][2y] [C] [geosn0w/ios-10.1.1-project-0-exploit-fork](https://github.com/geosn0w/ios-10.1.1-project-0-exploit-fork) iOS 10.1.1 Project 0 Exploit Compatible with All arm64 devices for Jailbreak Development
- [**41**Star][3y] [kd1991/oxul103-jailbreak](https://github.com/KD1991/OXUL103-Jailbreak) A NEW 64-bit JAILBREAK FOR iOS 10.3,10.3.1,10.3.2,10.3.x. (Untethered).
- [**40**Star][1y] [C] [in7egral/taig8-ios-jailbreak-patchfinder](https://github.com/in7egral/taig8-ios-jailbreak-patchfinder) Analyzes a binary iOS kernel to determine function offsets and where to apply the canonical jailbreak patches.
- [**37**Star][6m] [C] [geosn0w/geofilza](https://github.com/geosn0w/geofilza) Filza No Jailbreak
- [**35**Star][4y] [ObjC] [billy-ellis/ios-file-explorer](https://github.com/billy-ellis/ios-file-explorer) No-jailbreak file explorer application for iOS
- [**34**Star][2y] [C] [mtjailed/purplesmoke](https://github.com/mtjailed/purplesmoke) A work-in-progress repository for breaking the security of iOS 11.2 up to 11.2.6
- [**33**Star][2y] [ObjC] [mtjailed/privateapimanager](https://github.com/mtjailed/privateapimanager) A project providing usefull classes for reverse engineering iOS Private APIs on-device
- [**32**Star][2y] [applebetas/mterminal-jailed](https://github.com/applebetas/mterminal-jailed) An iOS 11 compatible fork of MTerminal using Ian Beer's tfp0 exploit
- [**32**Star][2y] [ObjC] [lycajb/lycajb](https://github.com/lycajb/lycajb) LycaJB is a project that aims to fill the gap in iOS 11.0 - 11.3.1 jailbreaks. While this jailbreak is specifically aimed at developers it could be turned into a public stable jailbreak which includes Cydia. Right now we had to make the hard decision to remove Cydia from LycaJB as it caused our test devices to bootloop. We are working hard to ma…
- [**32**Star][2y] [ObjC] [mikaelbo/proxyswitcher](https://github.com/mikaelbo/proxyswitcher) Easily enable / disable WiFi proxy on a jailbroken iOS device
- [**29**Star][2y] [C] [jndok/of32](https://github.com/jndok/of32) A simple tool to find offsets needed in 32bit jailbreaks. Feel free to contribute.
- [**25**Star][8m] [Logos] [ruler225/jailbreaktweaks](https://github.com/ruler225/jailbreaktweaks) All of my open source jailbreak tweaks for iOS
- [**23**Star][2y] [C] [openjailbreak/absinthe](https://github.com/openjailbreak/absinthe) Absinthe Jailbreak. Most recent version I've maintained. Help split this up into reusable modules for future userland jailbreaks. This is archived for future generations
- [**22**Star][9m] [Logos] [leavez/runmario](https://github.com/leavez/runmario) iOS jailbreak tweak that allow playing SuperMarioRun on jailbreak device
- [**20**Star][4y] [C] [jonathanseals/ios-kexec-utils](https://github.com/jonathanseals/ios-kexec-utils) I'm taking a break, I swear
- [**20**Star][11m] [m4cs/ios-tweak-dev-tools](https://github.com/m4cs/ios-tweak-dev-tools) A collection of useful development tools and forks of tools that are geared towards iOS jailbreak developers.
- [**18**Star][1y] [C++] [jakeajames/kernelsymbolfinder](https://github.com/jakeajames/kernelsymbolfinder) Get kernel symbols on device. No jailbreak required (note: unslid addresses)
- [**17**Star][2y] [Roff] [mtjailed/mtjailed-native](https://github.com/mtjailed/mtjailed-native) A terminal emulator with remote shell for non-jailbroken iOS devices
- [**17**Star][1y] [C] [xerub/ios-kexec-utils](https://github.com/xerub/ios-kexec-utils) I'm taking a break, I swear
- [**16**Star][4y] [C#] [firecore/seas0npass-windows](https://github.com/firecore/seas0npass-windows) Windows version of the jailbreak tool for Apple TV 2G
- [**15**Star][2y] [C] [jailbreaks/empty_list](https://github.com/jailbreaks/empty_list) empty_list - exploit for p0 issue 1564 (CVE-2018-4243) iOS 11.0 - 11.3.1 kernel r/w
- [**14**Star][10m] [SourcePawn] [headline/gangs](https://github.com/headline/gangs) Gangs for Jailbreak Servers Running SourceMod
- [**11**Star][8y] [i0n1c/corona-a5-exploit](https://github.com/i0n1c/corona-a5-exploit) The Corona A5 exploit used in the Absinthe jailbreak.
- [**11**Star][3y] [ObjC] [openjailbreak/yalu102](https://github.com/openjailbreak/yalu102) incomplete iOS 10.2 jailbreak for 64 bit devices by qwertyoruiopz and marcograssi
- [**10**Star][2y] [Swift] [6ilent/electralyzed_ios](https://github.com/6ilent/electralyzed_ios) Install Jailbreak tweaks without the hassle (iOS Version, Electra [iOS 11 - 11.1.2] Jailbreak Toolkit)
- [**10**Star][2y] [ObjC] [elegantliar/wechathook](https://github.com/ElegantLiar/WeChatHook) iOS非越狱 逆向微信实现防撤回, 修改步数
- [**9**Star][2y] [TeX] [abhinashjain/jailbreakdetection](https://github.com/abhinashjain/jailbreakdetection) iOS Jailbreak detection analysis - Comparison of jailed and jailbroken iOS devices
- [**9**Star][4y] [Py] [b0n0n/ms-fitnessband-jailbreak](https://github.com/b0n0n/ms-fitnessband-jailbreak) simple scripts to parse and patch Microsoft fitness band firmware update file
- [**9**Star][2y] [proappleos/upgrade-from-any-jailbroken-device-to-ios-11.1.2-with-blobs](https://github.com/proappleos/upgrade-from-any-jailbroken-device-to-ios-11.1.2-with-blobs) How to Upgrade any Jailbroken Device to iOS 11.1.2 with Blobs
- [**8**Star][3y] [ObjC] [imokhles/boptionloader](https://github.com/imokhles/boptionloader) side load BOptionsPro for BBM to improve BBM app on iOS device ( first BBM tweak ever for non jailbroken devices )
- [**6**Star][11m] [C] [cryptiiiic/skybreak](https://github.com/cryptiiiic/skybreak) 8.4.1 Jailbreak using CVE-2016-4655 / CVE-2016-4656
- [**4**Star][4y] [luowenw/xiaohedoublepinyindict](https://github.com/luowenw/xiaohedoublepinyindict) Files that can be useful for XiaoHe double pinyin solution on non jailbreak IOS devices.
- [**4**Star][3y] [ObjC] [kd1991/ipapatch](https://github.com/KD1991/IPAPatch) Patch iOS Apps, The Easy Way, Without Jailbreak.
- [**3**Star][2y] [Logos] [artikushg/switcherxi](https://github.com/artikushg/switcherxi) The iOS 11 appswitcher for iOS 10 jailbreak.
- [**3**Star][5y] [ObjC] [martianz/shadowsocks-ios](https://github.com/martianz/shadowsocks-ios) shadowsocks client for OSX and non-jailbroken iPhone and iPad
- [**3**Star][3y] [ObjC] [openjailbreak/yalu](https://github.com/openjailbreak/yalu) incomplete ios 8.4.1 jailbreak by Kim Jong Cracks (8.4.1 codesign & sandbox bypass w/ LPE to root & untether)
- [**2**Star][7y] [felipefmmobile/ios-plist-encryptor](https://github.com/felipefmmobile/ios-plist-encryptor) IOS *.plist encryptor project. Protect your *.plist files from jailbroken
- [**2**Star][2y] [Ruby] [mtjailed/msf-webkit-10.3](https://github.com/mtjailed/msf-webkit-10.3) A metasploit module for webkit exploits and PoC's targeting devices running iOS 10+
- [**1**Star][4y] [Shell] [app174/xcodeghost-clean](https://github.com/app174/xcodeghost-clean) Check and clean app contains XCodeGhost on your jailbreaked iDevice.
- [**0**Star][3y] [ziki69/ios10jailbreak](https://github.com/ziki69/ios10jailbreak) iOS 10.1.1 jailbreak w/ support of iPhone 5s


### <a id="cbb847a025d426a412c7cd5d8a2332b5"></a>Post


- 2019.10 [talosintelligence] [Checkrain fake iOS jailbreak leads to click fraud](https://blog.talosintelligence.com/2019/10/checkrain-click-fraud.html)
- 2019.08 [elcomsoft] [Why iOS 12.4 Jailbreak Is a Big Deal for the Law Enforcement](https://blog.elcomsoft.com/2019/08/why-ios-12-4-jailbreak-is-a-big-deal-for-the-law-enforcement/)
- 2019.05 [elcomsoft] [Step by Step Guide to iOS Jailbreaking and Physical Acquisition](https://blog.elcomsoft.com/2019/05/step-by-step-guide-to-ios-jailbreaking-and-physical-acquisition/)
- 2019.02 [securityinnovation] [iOS 12 Jailbreak](https://blog.securityinnovation.com/jailbreak)
- 2019.02 [elcomsoft] [iOS 12 Rootless Jailbreak](https://blog.elcomsoft.com/2019/02/ios-12-rootless-jailbreak/)
- 2019.01 [] [IPC Voucher UaF Remote Jailbreak Stage 2](http://blogs.360.cn/post/IPC%20Voucher%20UaF%20Remote%20Jailbreak%20Stage%202.html)
- 2019.01 [] [IPC Voucher UaF Remote Jailbreak Stage 2 (EN)](http://blogs.360.cn/post/IPC%20Voucher%20UaF%20Remote%20Jailbreak%20Stage%202%20(EN).html)
- 2018.07 [elcomsoft] [Using iOS 11.2-11.3.1 Electra Jailbreak for iPhone Physical Acquisition](https://blog.elcomsoft.com/2018/07/electra-jailbreak-ios-11-2-11-3-1-iphone-physical-acquisition/)
- 2017.12 [venus] [GreatiOSJailbreakMaterial - Only List the Most Useful Materials Here!](https://paper.seebug.org/482/)
- 2015.10 [welivesecurity] [New YiSpecter malware attacks iOS devices without jailbreak](https://www.welivesecurity.com/2015/10/06/new-yispecter-malware-attacks-ios-devices-without-jailbreak/)
- 2011.07 [sans] [Jailbreakme Takes Advantage of 0-day PDF Vuln in Apple iOS Devices](https://isc.sans.edu/forums/diary/Jailbreakme+Takes+Advantage+of+0day+PDF+Vuln+in+Apple+iOS+Devices/11185/)
- 2010.09 [securelist] [iPhone Jailbreaking, Greenpois0n and SHAtter Trojans](https://securelist.com/iphone-jailbreaking-greenpois0n-and-shatter-trojans/29748/)
- 2010.08 [trendmicro] [The Security Implications of iOS Jailbreaking](https://blog.trendmicro.com/trendlabs-security-intelligence/the-security-implications-of-ios-jailbreaking/)
- 2010.08 [trendmicro] [Online iPhone Jailbreak Uses iOS Vulnerabilities](https://blog.trendmicro.com/trendlabs-security-intelligence/online-iphone-jailbreak-uses-ios-vulnerabilities/)




***


## <a id="004d0b9e325af207df8e1ca61af7b721"></a>LLDB


### <a id="c20772abc204dfe23f3e946f8c73dfda"></a>Tools


- [**8031**Star][3m] [Py] [facebook/chisel](https://github.com/facebook/chisel) Chisel is a collection of LLDB commands to assist debugging iOS apps.
- [**784**Star][3m] [C++] [nodejs/llnode](https://github.com/nodejs/llnode) An lldb plugin for Node.js and V8, which enables inspection of JavaScript states for insights into Node.js processes and their core dumps.
- [**636**Star][2m] [C++] [apple/swift-lldb](https://github.com/apple/swift-lldb) This is the version of LLDB that supports the Swift programming language & REPL.
- [**492**Star][28d] [Rust] [vadimcn/vscode-lldb](https://github.com/vadimcn/vscode-lldb) A native debugger extension for VSCode based on LLDB
- [**388**Star][2m] [C++] [llvm-mirror/lldb](https://github.com/llvm-mirror/lldb) Mirror of official lldb git repository located at
- [**242**Star][5y] [C++] [meeloo/xspray](https://github.com/meeloo/xspray) A front end for lldb on OS X for Mac and iOS targets, with a twist
- [**198**Star][2y] [proteas/native-lldb-for-ios](https://github.com/proteas/native-lldb-for-ios) native LLDB(v3.8) for iOS
- [**25**Star][3y] [Py] [bnagy/francis](https://github.com/bnagy/francis) LLDB engine based tool to instrument OSX apps and triage crashes
- [**20**Star][3y] [Py] [critiqjo/lldb.nvim](https://github.com/critiqjo/lldb.nvim) This repository was moved to
- [**16**Star][2m] [Py] [malor/cpython-lldb](https://github.com/malor/cpython-lldb) LLDB script for debugging of CPython processes
- [**12**Star][3y] [C++] [indutny/llnode](https://github.com/indutny/llnode) Node.js C++ lldb plugin


### <a id="86eca88f321a86712cc0a66df5d72e56"></a>Post


- 2019.11 [4hou] [一款实用的macOS内核调试工具——LLDBagility](https://www.4hou.com/tools/21472.html)
- 2019.11 [reverse] [How to make LLDB a real debugger](https://reverse.put.as/2019/11/19/how-to-make-lldb-a-real-debugger/)
- 2019.08 [trendmicro] [LLDBFuzzer: Debugging and Fuzzing the Apple Kernel with LLDB Script](https://blog.trendmicro.com/trendlabs-security-intelligence/lldbfuzzer-debugging-and-fuzzing-the-apple-kernel-with-lldb-script/)
- 2019.06 [quarkslab] [LLDBagility: practical macOS kernel debugging](https://blog.quarkslab.com/lldbagility-practical-macos-kernel-debugging.html)
- 2018.05 [freebuf] [如何在Electra越狱的设备上使用LLDB调试应用程序](http://www.freebuf.com/articles/terminal/173218.html)
- 2018.01 [reverse] [lldbinit - Improving LLDB](https://reverse.put.as/2018/01/15/lldbinit-improving-lldb/)
- 2017.10 [venus] [Native LLDB(v3.8) for iOS](https://paper.seebug.org/419/)
- 2017.10 [pediy] [[原创]4s的9.3.5尝试Proteas大神的Native lldb](https://bbs.pediy.com/thread-221926.htm)
- 2017.07 [pediy] [[分享]]编译mac下的lldb](https://bbs.pediy.com/thread-219717.htm)
- 2016.09 [pediy] [[原创]lldb使用方法(学习笔记)](https://bbs.pediy.com/thread-212731.htm)
- 2015.01 [pediy] [[原创]修正lldb-310及以后版本的Thumb反汇编问题](https://bbs.pediy.com/thread-196735.htm)
- 2014.08 [3xp10it] [lldb命令](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/25/lldb%E5%91%BD%E4%BB%A4/)
- 2014.08 [3xp10it] [lldb命令](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/25/lldb%E5%91%BD%E4%BB%A4/)
- 2014.05 [pediy] [[原创]gikdbg v1.1携手lldb震撼来袭，求内测伙伴！](https://bbs.pediy.com/thread-187657.htm)
- 2013.03 [it] [iTunes debugging disabling ptrace with LLDB](https://blog.it-securityguard.com/itunes-exploit-development/)
- 2005.08 [pediy] [[原创]借第一篇破文吹一下olldbg](https://bbs.pediy.com/thread-16177.htm)
- 2004.06 [pediy] [用olldbg破解，分析ocx控件](https://bbs.pediy.com/thread-2134.htm)




***


## <a id="977cef2fc942ac125fa395254ab70eea"></a>XCode


### <a id="7037d96c1017978276cb920f65be2297"></a>Tools


- [**6203**Star][3m] [ObjC] [johnno1962/injectionforxcode](https://github.com/johnno1962/injectionforxcode) Runtime Code Injection for Objective-C & Swift
- [**2057**Star][19d] [ObjC] [ios-control/ios-deploy](https://github.com/ios-control/ios-deploy) Install and debug iPhone apps from the command line, without using Xcode
- [**1606**Star][2m] [Swift] [indragiek/inappviewdebugger](https://github.com/indragiek/inappviewdebugger) A UIView debugger (like Reveal or Xcode) that can be embedded in an app for on-device view debugging
- [**1409**Star][1m] [Swift] [johnno1962/injectioniii](https://github.com/johnno1962/injectioniii) Re-write of Injection for Xcode in (mostly) Swift4
- [**572**Star][1m] [ObjC] [hdb-li/lldebugtool](https://github.com/hdb-li/lldebugtool) LLDebugTool is a debugging tool for developers and testers that can help you analyze and manipulate data in non-xcode situations.
- [**497**Star][7y] [C] [ghughes/fruitstrap](https://github.com/ghughes/fruitstrap) Install and debug iPhone apps from the command line, without using Xcode
- [**384**Star][3m] [JS] [johnno1962/xprobeplugin](https://github.com/johnno1962/xprobeplugin) Live Memory Browser for Apps & Xcode
- [**179**Star][4y] [ObjC] [x43x61x69/otx](https://github.com/x43x61x69/otx) The Mach-O disassembler. Now 64bit and Xcode 6 compatible.
- [**135**Star][1y] [Swift] [danleechina/mixplaintext](https://github.com/danleechina/mixplaintext) 可对 Xcode 项目工程所有的 objective-c 文件内包含的明文进行加密混淆，提高逆向分析难度。
- [**135**Star][1y] [Shell] [onmyway133/swiftsnippets](https://github.com/onmyway133/SwiftSnippets) A collection of Swift snippets to be used in Xcode 
- [**48**Star][2y] [C++] [tonyzesto/pubgprivxcode85](https://github.com/tonyzesto/pubgprivxcode85) Player ESP 3D Box ESP Nametag ESP Lightweight Code Secure Injection Dedicated Cheat Launcher Secured Against Battleye Chicken Dinner Every Day. Win more matches than ever before with CheatAutomation’s Playerunknown’s Battlegrounds cheat! Our stripped down, ESP only cheat gives you the key features you need to take out your opponents and be eatin…
- [**45**Star][7m] [Swift] [git-kevinchuang/potatso-swift5](https://github.com/git-kevinchuang/potatso-swift5) Potatso compiled with swift5 xcode 10.2.1 mojave 10.14.5
- [**44**Star][3y] [Shell] [vtky/resign](https://github.com/vtky/resign) XCode Project to resign .ipa files
- [**28**Star][1m] [Swift] [hdb-li/lldebugtoolswift](https://github.com/hdb-li/lldebugtoolswift) LLDebugTool is a debugging tool for developers and testers that can help you analyze and manipulate data in non-xcode situations.
- [**28**Star][2y] [Swift] [jeanshuang/potatso](https://github.com/jeanshuang/potatso) 适配Xcode9.3 iOS11.3 Swift3.3编译通过。 (unmaintained) Potatso is an iOS client that implements Shadowsocks proxy with the leverage of NetworkExtension framework in iOS 9.
- [**24**Star][12m] [Swift] [shoheiyokoyama/lldb-debugging](https://github.com/shoheiyokoyama/lldb-debugging) The LLDB Debugging in C, Swift, Objective-C, Python and Xcode
- [**17**Star][2y] [maxfong/obfuscatorxcplugin](https://github.com/maxfong/obfuscatorxcplugin) 逻辑混淆XCode插件
- [**1**Star][2y] [Swift] [wdg/webshell-builder](https://github.com/wdg/webshell-builder) A WebShell application builder (no use of Xcode)


### <a id="a2d228a68b40162953d3d482ce009d4e"></a>Post


- 2019.07 [pewpewthespells] [Using Xcode Targets](https://pewpewthespells.com/blog/using_xcode_targets.pdf)
- 2019.07 [pewpewthespells] [Xcode Build Locations](https://pewpewthespells.com/blog/xcode_build_locations.pdf)
- 2019.07 [pewpewthespells] [Migrating Code Signing Configurations to Xcode 8](https://pewpewthespells.com/blog/migrating_code_signing.pdf)
- 2019.06 [pewpewthespells] [Xcode SDKs](https://pewpewthespells.com/blog/sparse_sdks.pdf)
- 2019.04 [pewpewthespells] [Xcode Build Settings Reference](https://pewpewthespells.com/blog/buildsettings.pdf)
- 2019.03 [pewpewthespells] [Xcode DerivedData Hashes](https://pewpewthespells.com/blog/xcode_deriveddata_hashes.pdf)
- 2019.02 [pewpewthespells] [The Xcode Build System](https://pewpewthespells.com/blog/xcode_build_system.pdf)
- 2019.02 [pewpewthespells] [Managing Xcode](https://pewpewthespells.com/blog/managing_xcode.pdf)
- 2019.02 [hakin9] [Building an iOS App Without Xcode’s Build System by Vojta Stavik](https://hakin9.org/building-an-ios-app-without-xcodes-build-system/)
- 2018.11 [CodeColorist] [Xcode Instruments for iOS: reversing and abuse](https://medium.com/p/dd73d72d87e2)
- 2018.06 [applehelpwriter] [Xcode 10: where did snippets go?](https://applehelpwriter.com/2018/06/10/xcode-10-where-did-snippets-go/)
- 2018.05 [freecodecamp] [How to convert your Xcode plugins to Xcode extensions](https://medium.com/p/ac90f32ae0e3)
- 2017.07 [pediy] [[原创] iOSOpenDev修改版MonkeyDev，最新theos和Xcode 9测试通过!](https://bbs.pediy.com/thread-219003.htm)
- 2017.06 [alonemonkey] [0x01 Xcode调试一个LLVM Pass](http://www.alonemonkey.com/2017/06/02/writing-an-llvm-pass/)
- 2017.03 [360] [XcodeGhost或重出江湖，Google Play大量APP被植入恶意代码](https://www.anquanke.com/post/id/85636/)
- 2016.05 [rachelbythebay] [Go upgrade Xcode.  Fix your git security hole.](http://rachelbythebay.com/w/2016/05/05/xcode/)
- 2015.12 [metricpanda] [Compiling NASM Assembly with Xcode in a C/C++ Project](https://metricpanda.com/compiling-nasm-with-xcode-in-a-cpp-project)
- 2015.12 [360] [Xcode 7 Bitcode的工作流程及安全性评估](https://www.anquanke.com/post/id/83125/)
- 2015.12 [freebuf] [Xcode 7 Bitcode的工作流程及安全性评估](http://www.freebuf.com/articles/others-articles/89806.html)
- 2015.11 [freebuf] [XcodeGhost S：变种带来的又一波影响](http://www.freebuf.com/news/84064.html)
- 2015.10 [freebuf] [比XcodeGhost更邪恶的手段30年前就出现了](http://www.freebuf.com/news/81860.html)
- 2015.10 [topsec] [xcodeghost事件观察](http://blog.topsec.com.cn/ad_lab/xcodeghost%e4%ba%8b%e4%bb%b6%e8%a7%82%e5%af%9f/)
- 2015.10 [topsec] [xcodeghost事件观察](http://blog.topsec.com.cn/xcodeghost%e4%ba%8b%e4%bb%b6%e8%a7%82%e5%af%9f/)
- 2015.10 [alienvault] [XCodeGhost - pervasive hack of Apple’s Xcode developer toolkit](https://www.alienvault.com/blogs/security-essentials/xcodeghost-pervasive-hack-of-apples-xcode-developer-toolkit)
- 2015.10 [verisign] [Verisign iDefense Analysis of XcodeGhost](https://blog.verisign.com/security/verisign-idefense-analysis-of-xcodeghost/)
- 2015.10 [duo] [XcodeGhost: Resources for Developer and User Security](https://duo.com/blog/xcodeghost-resources-for-developer-and-user-security)
- 2015.09 [kaspersky] [Security Week 39: XcodeGhost, the leak of D-Link certificates, $1M for bugs in iOS9](https://www.kaspersky.com/blog/security-week-39/10016/)
- 2015.09 [elearnsecurity] [Apple App Store Compromised by XcodeGhost Vulnerability](https://blog.elearnsecurity.com/apple-app-store-compromised-by-xcodeghost-vulnerability.html)
- 2015.09 [] [青岛警方破获Xcode病毒案，技术手段似美情部门](http://www.91ri.org/14319.html)
- 2015.09 [freebuf] [苹果官方发布受XcodeGhost影响最大的25个App](http://www.freebuf.com/news/79799.html)
- 2015.09 [sec] [对几家专业安全公司xcodeGhost插入恶意代码事件的分析报告解读](https://www.sec-un.org/to-several-professional-security-company-xcodeghost-inserted-malicious-code-analysis-report-interpretation/)
- 2015.09 [freebuf] [XcodeGhost机读威胁情报IOC](http://www.freebuf.com/news/79787.html)
- 2015.09 [nsfocus] [XcodeGhost危害国内苹果应用市场](http://blog.nsfocus.net/xcodeghost-harm-third-party-appstore/)
- 2015.09 [mcafee] [XcodeGhost Pulled from App Store After a Good Scare: What to Know](https://securingtomorrow.mcafee.com/consumer/consumer-threat-notices/xcodeghost-malware-hits-app-store/)
- 2015.09 [trustlook] ["Reflections on Trusting Trust" – Some Thoughts on the XcodeGhost Incident](https://blog.trustlook.com/2015/09/23/some-thoughts-on-the-xcodeghost-incident/)
- 2015.09 [skycure] [How to Protect Against XcodeGhost iOS Malware?](https://www.skycure.com/blog/how-to-protect-against-xcodeghost-ios-malware/)
- 2015.09 [lookout] [Good news: Lookout can protect you from XcodeGhost](https://blog.lookout.com/xcodeghost-detection)
- 2015.09 [360] [你以为服务器关了这事就结束了？ - XcodeGhost截胡攻击和服务端的复现，以及UnityGhost预警](https://www.anquanke.com/post/id/82451/)
- 2015.09 [paloaltonetworks] [More Details on the XcodeGhost Malware and Affected](https://unit42.paloaltonetworks.com/more-details-on-the-xcodeghost-malware-and-affected-ios-apps/)
- 2015.09 [checkpoint] [XCodeGhost: The First Wide-Scale Attack on iOS Apps Arrives | Check Point Software Blog](https://blog.checkpoint.com/2015/09/21/xcodeghost-the-first-wide-scale-attack-on-ios-apps-arrives/)
- 2015.09 [trendmicro] [The XcodeGhost Plague – How Did It Happen?](https://blog.trendmicro.com/trendlabs-security-intelligence/the-xcodeghost-plague-how-did-it-happen/)
- 2015.09 [lookout] [Updated: XcodeGhost iOS malware: The list of affected apps and what you should do](https://blog.lookout.com/xcodeghost-apps)
- 2015.09 [malwarebytes] [XcodeGhost malware infiltrates App Store](https://blog.malwarebytes.com/cybercrime/2015/09/xcodeghost-malware-infiltrates-app-store/)
- 2015.09 [sans] [Detecting XCodeGhost Activity](https://isc.sans.edu/forums/diary/Detecting+XCodeGhost+Activity/20171/)
- 2015.09 [pediy] [[原创]XCodeGhost详细技术分析[XCodeGhost内幕暴料]](https://bbs.pediy.com/thread-204281.htm)
- 2015.09 [antiy] [Xcode非官方版本恶意代码污染事件（XcodeGhost）的分析与综述](http://www.antiy.com/response/xcodeghost.html)
- 2015.09 [sec] [XcodeGhost国人作者致歉，中情局笑了](https://www.sec-un.org/xcodeghost-cia/)
- 2015.09 [360] [涅槃团队：Xcode幽灵病毒存在恶意下发木马行为](https://www.anquanke.com/post/id/82438/)
- 2015.09 [tencent] [你以为这就是全部了？我们来告诉你完整的XCodeGhost事件](https://security.tencent.com/index.php/blog/msg/96)




***


## <a id="58cd9084afafd3cd293564c1d615dd7f"></a>Tools


### <a id="d0108e91e6863289f89084ff09df39d0"></a>Recent Add


- [**11025**Star][2y] [ObjC] [bang590/jspatch](https://github.com/bang590/jspatch) JSPatch bridge Objective-C and Javascript using the Objective-C runtime. You can call any Objective-C class and method in JavaScript by just including a small engine. JSPatch is generally used to hotfix iOS App.
- [**10966**Star][10d] [ObjC] [flipboard/flex](https://github.com/flipboard/flex) An in-app debugging and exploration tool for iOS
- [**5775**Star][4m] [ObjC] [square/ponydebugger](https://github.com/square/ponydebugger) Remote network and data debugging for your native iOS app using Chrome Developer Tools
- [**4663**Star][1m] [C] [google/ios-webkit-debug-proxy](https://github.com/google/ios-webkit-debug-proxy) A DevTools proxy (Chrome Remote Debugging Protocol) for iOS devices (Safari Remote Web Inspector).
- [**4397**Star][12d] [Swift] [signalapp/signal-ios](https://github.com/signalapp/Signal-iOS) A private messenger for iOS.
- [**3686**Star][4m] [C] [facebook/fishhook](https://github.com/facebook/fishhook) A library that enables dynamically rebinding symbols in Mach-O binaries running on iOS.
- [**3414**Star][2m] [icodesign/potatso](https://github.com/icodesign/Potatso) Potatso is an iOS client that implements different proxies with the leverage of NetworkExtension framework in iOS 10+.
- [**3327**Star][3m] [Swift] [yagiz/bagel](https://github.com/yagiz/bagel) a little native network debugging tool for iOS
- [**3071**Star][10m] [JS] [jipegit/osxauditor](https://github.com/jipegit/osxauditor) OS X Auditor is a free Mac OS X computer forensics tool
- [**2867**Star][12d] [ObjC] [facebook/idb](https://github.com/facebook/idb) idb is a flexible command line interface for automating iOS simulators and devices
- [**2795**Star][24d] [Swift] [kasketis/netfox](https://github.com/kasketis/netfox) A lightweight, one line setup, iOS / OSX network debugging library!
- [**2753**Star][1m] [Makefile] [theos/theos](https://github.com/theos/theos) A cross-platform suite of tools for building and deploying software for iOS and other platforms.
- [**2733**Star][26d] [ObjC] [dantheman827/ios-app-signer](https://github.com/dantheman827/ios-app-signer) This is an app for OS X that can (re)sign apps and bundle them into ipa files that are ready to be installed on an iOS device.
- [**2708**Star][2m] [ObjC] [kjcracks/clutch](https://github.com/kjcracks/clutch) Fast iOS executable dumper
- [**2345**Star][6y] [C] [stefanesser/dumpdecrypted](https://github.com/stefanesser/dumpdecrypted) Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk. This tool is necessary for security researchers to be able to look under the hood of encryption.
- [**1801**Star][1y] [aozhimin/ios-monitor-platform](https://github.com/aozhimin/ios-monitor-platform) 
- [**1774**Star][3y] [ObjC] [tapwork/heapinspector-for-ios](https://github.com/tapwork/heapinspector-for-ios) Find memory issues & leaks in your iOS app without instruments
- [**1695**Star][6m] [Py] [yelp/osxcollector](https://github.com/yelp/osxcollector) A forensic evidence collection & analysis toolkit for OS X
- [**1683**Star][2m] [Swift] [pmusolino/wormholy](https://github.com/pmusolino/wormholy) iOS network debugging, like a wizard 🧙‍♂️
- [**1642**Star][7m] [Objective-C++] [tencent/oomdetector](https://github.com/tencent/oomdetector) OOMDetector is a memory monitoring component for iOS which provides you with OOM monitoring, memory allocation monitoring, memory leak detection and other functions.
- [**1630**Star][1m] [ivrodriguezca/re-ios-apps](https://github.com/ivrodriguezca/re-ios-apps) A completely free, open source and online course about Reverse Engineering iOS Applications.
- [**1444**Star][5y] [C++] [gdbinit/machoview](https://github.com/gdbinit/machoview) MachOView fork
- [**1442**Star][28d] [ObjC] [nabla-c0d3/ssl-kill-switch2](https://github.com/nabla-c0d3/ssl-kill-switch2) Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and OS X Apps
- [**1299**Star][6m] [JS] [feross/spoof](https://github.com/feross/spoof) Easily spoof your MAC address in macOS, Windows, & Linux!
- [**1291**Star][1m] [JS] [icymind/vrouter](https://github.com/icymind/vrouter) 一个基于 VirtualBox 和 openwrt 构建的项目, 旨在实现 macOS / Windows 平台的透明代理.
- [**1253**Star][2m] [Vue] [chaitin/passionfruit](https://github.com/chaitin/passionfruit) [WIP] Crappy iOS app analyzer
- [**1252**Star][17d] [michalmalik/osx-re-101](https://github.com/michalmalik/osx-re-101) A collection of resources for OSX/iOS reverse engineering.
- [**1240**Star][2y] [ObjC] [krausefx/detect.location](https://github.com/krausefx/detect.location) An easy way to access the user's iOS location data without actually having access
- [**1239**Star][8d] [C] [datatheorem/trustkit](https://github.com/datatheorem/trustkit) Easy SSL pinning validation and reporting for iOS, macOS, tvOS and watchOS.
- [**1215**Star][16d] [YARA] [horsicq/detect-it-easy](https://github.com/horsicq/detect-it-easy) Program for determining types of files for Windows, Linux and MacOS.
- [**1199**Star][6y] [gdbinit/gdbinit](https://github.com/gdbinit/gdbinit) Gdbinit for OS X, iOS and others - x86, x86_64 and ARM
- [**1174**Star][5y] [Py] [hackappcom/ibrute](https://github.com/hackappcom/ibrute) AppleID bruteforce p0c
- [**1113**Star][1y] [ObjC] [neoneggplant/eggshell](https://github.com/neoneggplant/eggshell) iOS/macOS/Linux Remote Administration Tool
- [**1026**Star][2y] [ObjC] [zhengmin1989/ios_ice_and_fire](https://github.com/zhengmin1989/ios_ice_and_fire) iOS冰与火之歌
- [**1001**Star][2m] [ObjC] [lmirosevic/gbdeviceinfo](https://github.com/lmirosevic/gbdeviceinfo) Detects the hardware, software and display of the current iOS or Mac OS X device at runtime.
- [**985**Star][1y] [Py] [fsecurelabs/needle](https://github.com/FSecureLABS/needle) The iOS Security Testing Framework
- [**975**Star][3y] [Py] [synack/knockknock](https://github.com/synack/knockknock) displays persistent items (scripts, commands, binaries, etc.), that are set to execute automatically on OS X
- [**936**Star][3y] [C] [tyilo/insert_dylib](https://github.com/tyilo/insert_dylib) Command line utility for inserting a dylib load command into a Mach-O binary
- [**907**Star][4m] [ObjC] [ptoomey3/keychain-dumper](https://github.com/ptoomey3/keychain-dumper) A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken
- [**866**Star][16d] [ObjC] [meitu/mthawkeye](https://github.com/meitu/mthawkeye) Profiling / Debugging assist tools for iOS. (Memory Leak, OOM, ANR, Hard Stalling, Network, OpenGL, Time Profile ...)
- [**857**Star][3y] [Py] [hubert3/isniff-gps](https://github.com/hubert3/isniff-gps) Passive sniffing tool for capturing and visualising WiFi location data disclosed by iOS devices
- [**847**Star][2y] [Shell] [kpwn/iosre](https://github.com/kpwn/iosre) iOS Reverse Engineering
- [**840**Star][9d] [JS] [cypress-io/cypress-example-recipes](https://github.com/cypress-io/cypress-example-recipes) Various recipes for testing common scenarios with Cypress
- [**812**Star][5y] [ObjC] [isecpartners/ios-ssl-kill-switch](https://github.com/isecpartners/ios-ssl-kill-switch) Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS Apps
- [**807**Star][2y] [Ruby] [dmayer/idb](https://github.com/dmayer/idb) simplify some common tasks for iOS pentesting and research
- [**796**Star][13d] [Shell] [aqzt/kjyw](https://github.com/aqzt/kjyw) 快捷运维，代号kjyw，项目基于shell、python，运维脚本工具库，收集各类运维常用工具脚本，实现快速安装nginx、mysql、php、redis、nagios、运维经常使用的脚本等等...
- [**782**Star][3y] [Go] [summitroute/osxlockdown](https://github.com/summitroute/osxlockdown) [No longer maintained] Apple OS X tool to audit for, and remediate, security configuration settings.
- [**745**Star][5y] [ObjC] [kjcracks/yololib](https://github.com/kjcracks/yololib) dylib injector for mach-o binaries
- [**662**Star][1y] [Py] [deepzec/bad-pdf](https://github.com/deepzec/bad-pdf) create malicious PDF file to steal NTLM(NTLMv1/NTLMv2) Hashes from windows machines
- [**653**Star][3y] [C] [rentzsch/mach_inject](https://github.com/rentzsch/mach_inject) interprocess code injection for Mac OS X
- [**651**Star][9m] [ObjC] [chenxiancai/stcobfuscator](https://github.com/chenxiancai/stcobfuscator) iOS全局自动化 代码混淆 工具！支持cocoapod组件代码一并 混淆，完美避开hardcode方法、静态库方法和系统库方法！
- [**649**Star][3y] [ObjC] [isecpartners/introspy-ios](https://github.com/isecpartners/introspy-ios) Security profiling for blackbox iOS
- [**636**Star][1y] [Swift] [phynet/ios-url-schemes](https://github.com/phynet/ios-url-schemes) a github solution from my gist of iOS list for urls schemes
- [**621**Star][5y] [PHP] [pr0x13/idict](https://github.com/pr0x13/idict) iCloud Apple iD BruteForcer
- [**616**Star][3y] [ObjC] [macmade/keychaincracker](https://github.com/macmade/keychaincracker) macOS keychain cracking tool
- [**604**Star][2m] [siguza/ios-resources](https://github.com/siguza/ios-resources) Useful resources for iOS hacking
- [**583**Star][3y] [C++] [tobefuturer/app2dylib](https://github.com/tobefuturer/app2dylib) A reverse engineering tool to convert iOS app to dylib
- [**558**Star][3y] [advanced-threat-research/firmware-security-training](https://github.com/advanced-threat-research/firmware-security-training) materials for a hands-on training Security of BIOS/UEFI System Firmware from Attacker and Defender Perspectives
- [**530**Star][3y] [ObjC] [herzmut/shadowsocks-ios](https://github.com/herzmut/shadowsocks-ios) Fork of shadowsocks/shadowsocks-iOS
- [**526**Star][4y] [Py] [hackappcom/iloot](https://github.com/hackappcom/iloot) OpenSource tool for iCloud backup extraction
- [**522**Star][2y] [Shell] [seemoo-lab/mobisys2018_nexmon_software_defined_radio](https://github.com/seemoo-lab/mobisys2018_nexmon_software_defined_radio) Proof of concept project for operating Broadcom Wi-Fi chips as arbitrary signal transmitters similar to software-defined radios (SDRs)
- [**517**Star][3y] [ObjC] [pjebs/obfuscator-ios](https://github.com/pjebs/obfuscator-ios) Secure your app by obfuscating all the hard-coded security-sensitive strings.
- [**517**Star][5y] [Py] [project-imas/mdm-server](https://github.com/project-imas/mdm-server) Sample iOS MDM server
- [**500**Star][27d] [Swift] [google/science-journal-ios](https://github.com/google/science-journal-ios) Use the sensors in your mobile devices to perform science experiments. Science doesn’t just happen in the classroom or lab—tools like Science Journal let you see how the world works with just your phone.
- [**482**Star][1y] [Swift] [icepa/icepa](https://github.com/icepa/icepa) iOS system-wide VPN based Tor client
- [**478**Star][15d] [pixelcyber/thor](https://github.com/pixelcyber/thor) HTTP Sniffer/Capture on iOS for Network Debug & Inspect.
- [**471**Star][8m] [C++] [everettjf/machoexplorer](https://github.com/everettjf/machoexplorer) [WIP] Explore MachO File on macOS and Windows
- [**462**Star][15d] [Java] [dsheirer/sdrtrunk](https://github.com/dsheirer/sdrtrunk) A cross-platform java application for decoding, monitoring, recording and streaming trunked mobile and related radio protocols using Software Defined Radios (SDR). Website:
- [**432**Star][7y] [C] [juuso/keychaindump](https://github.com/juuso/keychaindump) A proof-of-concept tool for reading OS X keychain passwords
- [**430**Star][11m] [captainarash/the_holy_book_of_x86](https://github.com/captainarash/the_holy_book_of_x86) A simple guide to x86 architecture, assembly, memory management, paging, segmentation, SMM, BIOS....
- [**419**Star][4y] [ObjC] [asido/systemmonitor](https://github.com/asido/systemmonitor) iOS application providing you all information about your device - hardware, operating system, processor, memory, GPU, network interface, storage and battery, including OpenGL powered visual representation in real time.
- [**406**Star][5y] [ObjC] [mp0w/ios-headers](https://github.com/mp0w/ios-headers) iOS 5.0/5.1/6.0/6.1/7.0/7.1/8.0/8.1 Headers of All Frameworks (private and not) + SpringBoard
- [**396**Star][4m] [ansjdnakjdnajkd/ios](https://github.com/ansjdnakjdnajkd/ios) Most usable tools for iOS penetration testing
- [**393**Star][2y] [r0ysue/osg-translationteam](https://github.com/r0ysue/osg-translationteam) 看雪iOS安全小组的翻译团队作品集合，如有勘误，欢迎斧正！
- [**382**Star][11m] [C] [coolstar/electra1131](https://github.com/coolstar/electra1131) Electra for iOS 11.0 - 11.3.1
- [**375**Star][2y] [C++] [alonemonkey/iosrebook](https://github.com/alonemonkey/iosrebook) 《iOS应用逆向与安全》随书源码
- [**375**Star][29d] [Swift] [justeat/justlog](https://github.com/justeat/justlog) JustLog brings logging on iOS to the next level. It supports console, file and remote Logstash logging via TCP socket with no effort. Support for logz.io available.
- [**374**Star][2y] [C++] [breenmachine/rottenpotatong](https://github.com/breenmachine/rottenpotatong) New version of RottenPotato as a C++ DLL and standalone C++ binary - no need for meterpreter or other tools.
- [**371**Star][18d] [Shell] [matthewpierson/1033-ota-downgrader](https://github.com/matthewpierson/1033-ota-downgrader) First ever tool to downgrade ANY iPhone 5s, ANY iPad Air and (almost any) iPad Mini 2 to 10.3.3 with OTA blobs + checkm8!
- [**349**Star][19d] [C] [jedisct1/swift-sodium](https://github.com/jedisct1/swift-sodium) Safe and easy to use crypto for iOS and macOS
- [**346**Star][4m] [TS] [bacher09/pwgen-for-bios](https://github.com/bacher09/pwgen-for-bios) Password generator for BIOS
- [**340**Star][3m] [C] [trailofbits/cb-multios](https://github.com/trailofbits/cb-multios) DARPA Challenges Sets for Linux, Windows, and macOS
- [**332**Star][3y] [Logos] [bishopfox/ispy](https://github.com/bishopfox/ispy) A reverse engineering framework for iOS
- [**322**Star][2m] [ObjC] [auth0/simplekeychain](https://github.com/auth0/simplekeychain) A Keychain helper for iOS to make it very simple to store/obtain values from iOS Keychain
- [**310**Star][28d] [Swift] [securing/iossecuritysuite](https://github.com/securing/iossecuritysuite) iOS platform security & anti-tampering Swift library
- [**298**Star][2y] [krausefx/steal.password](https://github.com/krausefx/steal.password) Easily get the user's Apple ID password, just by asking
- [**292**Star][8y] [ObjC] [nst/spyphone](https://github.com/nst/spyphone) This project shows the kind of data a rogue iPhone application can collect.
- [**287**Star][1y] [Py] [manwhoami/mmetokendecrypt](https://github.com/manwhoami/mmetokendecrypt) Decrypts and extracts iCloud and MMe authorization tokens on Apple macOS / OS X. No user authentication needed. 🏅🌩
- [**283**Star][2y] [Swift] [krausefx/watch.user](https://github.com/krausefx/watch.user) Every iOS app you ever gave permission to use your camera can record you any time it runs - without notice
- [**263**Star][14d] [ObjC] [strongbox-password-safe/strongbox](https://github.com/strongbox-password-safe/strongbox) A KeePass/Password Safe Client for iOS and OS X
- [**247**Star][1m] [C++] [s0uthwest/futurerestore](https://github.com/s0uthwest/futurerestore) iOS upgrade and downgrade tool utilizing SHSH blobs
- [**244**Star][7m] [JS] [we11cheng/wcshadowrocket](https://github.com/we11cheng/wcshadowrocket) iOS Shadowrocket(砸壳重签,仅供参考,添加节点存在问题)。另一个fq项目potatso源码参见:
- [**241**Star][2y] [C] [limneos/mobileminer](https://github.com/limneos/mobileminer) CPU Miner for ARM64 iOS Devices
- [**239**Star][1y] [ObjC] [lmirosevic/gbping](https://github.com/lmirosevic/gbping) Highly accurate ICMP Ping controller for iOS
- [**238**Star][4m] [Swift] [shadowsocksr-live/ishadowsocksr](https://github.com/shadowsocksr-live/ishadowsocksr) ShadowsocksR for iOS, come from
- [**229**Star][3y] [Swift] [trailofbits/secureenclavecrypto](https://github.com/trailofbits/secureenclavecrypto) Demonstration library for using the Secure Enclave on iOS
- [**223**Star][12m] [AppleScript] [lifepillar/csvkeychain](https://github.com/lifepillar/csvkeychain) Import/export between Apple Keychain.app and plain CSV file.
- [**219**Star][6m] [ObjC] [rickyzhang82/tethering](https://github.com/rickyzhang82/tethering) Proxy and DNS Server on iOS
- [**213**Star][8m] [C] [owasp/igoat](https://github.com/owasp/igoat) OWASP iGoat - A Learning Tool for iOS App Pentesting and Security by Swaroop Yermalkar
- [**211**Star][13d] [TS] [bevry/getmac](https://github.com/bevry/getmac) Get the mac address of the current machine you are on via Node.js
- [**210**Star][2y] [C] [cheesecakeufo/saigon](https://github.com/cheesecakeufo/saigon) iOS 10.2.1 - Discontinued version
- [**203**Star][5m] [Py] [googleprojectzero/ios-messaging-tools](https://github.com/googleprojectzero/ios-messaging-tools) several tools Project Zero uses to test iPhone messaging
- [**200**Star][6m] [PS] [mkellerman/invoke-commandas](https://github.com/mkellerman/invoke-commandas) Invoke Command As System/Interactive/GMSA/User on Local/Remote machine & returns PSObjects.
- [**199**Star][1m] [ObjC] [everettjf/yolo](https://github.com/everettjf/yolo) Scripts or demo projects on iOS development or reverse engineering
- [**198**Star][27d] [Swift] [auth0/lock.swift](https://github.com/auth0/Lock.swift) A Swift & iOS framework to authenticate using Auth0 and with a Native Look & Feel
- [**195**Star][2m] [Logos] [creantan/lookinloader](https://github.com/creantan/lookinloader) Lookin - iOS UI Debugging Tweak LookinLoader,Compatible with iOS 8~13
- [**190**Star][13d] [Py] [ydkhatri/mac_apt](https://github.com/ydkhatri/mac_apt) macOS Artifact Parsing Tool
- [**182**Star][1m] [JS] [nowsecure/node-applesign](https://github.com/nowsecure/node-applesign) NodeJS module and commandline utility for re-signing iOS applications (IPA files).
- [**181**Star][4y] [ObjC] [iosre/hippocamphairsalon](https://github.com/iosre/hippocamphairsalon) A simple universal memory editor (game trainer) on OSX/iOS
- [**181**Star][12m] [zekesnider/nintendoswitchrestapi](https://github.com/zekesnider/nintendoswitchrestapi) Reverse engineered REST API used in the Nintendo Switch app for iOS. Includes documentation on Splatoon 2's API.
- [**180**Star][4m] [Py] [anssi-fr/secuml](https://github.com/anssi-fr/secuml) Machine Learning for Computer Security
- [**180**Star][8m] [Java] [yubico/ykneo-openpgp](https://github.com/yubico/ykneo-openpgp) OpenPGP applet for the YubiKey NEO
- [**174**Star][1y] [ObjC] [macmade/filevaultcracker](https://github.com/macmade/filevaultcracker) macOS FileVault cracking tool
- [**172**Star][23d] [C++] [samyk/frisky](https://github.com/samyk/frisky) Instruments to assist in binary application reversing and augmentation, geared towards walled gardens like iOS and macOS
- [**171**Star][2y] [Py] [3gstudent/worse-pdf](https://github.com/3gstudent/worse-pdf) Turn a normal PDF file into malicious.Use to steal Net-NTLM Hashes from windows machines.
- [**171**Star][10m] [Shell] [trustedsec/hardcidr](https://github.com/trustedsec/hardcidr) hardCIDR is a Linux Bash script, but also functions under macOS. Your mileage may vary on other distros. The script with no specified options will query ARIN and a pool of BGP route servers. The route server is selected at random at runtime.
- [**169**Star][7m] [C] [octomagon/davegrohl](https://github.com/octomagon/davegrohl) A Password Cracker for macOS
- [**166**Star][8m] [proteas/unstripped-ios-kernels](https://github.com/proteas/unstripped-ios-kernels) Unstripped iOS Kernels
- [**165**Star][2y] [C++] [google/pawn](https://github.com/google/pawn) 从基于 Intel 的工作站和笔记本电脑中提取 BIOS 固件
- [**165**Star][16d] [Swift] [ryasnoy/applocker](https://github.com/ryasnoy/applocker) AppLocker - simple lock screen for iOS Application ( Swift 4+, iOS 9.0+) Touch ID / Face ID
- [**163**Star][6y] [C] [gdbinit/readmem](https://github.com/gdbinit/readmem) A small OS X/iOS userland util to dump processes memory
- [**163**Star][9m] [C] [tboox/itrace](https://github.com/tboox/itrace) Trace objc method call for ios and mac
- [**162**Star][2y] [C++] [encounter/futurerestore](https://github.com/encounter/futurerestore) (unmaintained) iOS upgrade and downgrade tool utilizing SHSH blobs (unofficial fork supporting iOS 11 and newer devices)
- [**159**Star][2m] [smilezxlee/crackediosapps](https://github.com/smilezxlee/crackediosapps) iOS端破解版App集合，包含破解版QQ、破解版抖音、破解版百度网盘、破解版麻花、钉钉打卡助手、破解版墨墨背单词、破解版网易云音乐、破解版芒果TV
- [**157**Star][20d] [mac4n6/presentations](https://github.com/mac4n6/presentations) Presentation Archives for my macOS and iOS Related Research
- [**152**Star][7y] [Py] [intrepidusgroup/imdmtools](https://github.com/intrepidusgroup/imdmtools) Intrepidus Group's iOS MDM tools
- [**147**Star][3y] [Py] [biosbits/bits](https://github.com/biosbits/bits) BIOS Implementation Test Suite
- [**145**Star][2y] [Shell] [depoon/iosdylibinjectiondemo](https://github.com/depoon/iosdylibinjectiondemo) Using this Repository to demo how to inject dynamic libraries into cracked ipa files for jailed iOS devices
- [**144**Star][10m] [Py] [dlcowen/fseventsparser](https://github.com/dlcowen/fseventsparser) Parser for OSX/iOS FSEvents Logs
- [**144**Star][4y] [ObjC] [etsy/bughunt-ios](https://github.com/etsy/bughunt-ios) 
- [**143**Star][2y] [C] [rodionovd/liblorgnette](https://github.com/rodionovd/liblorgnette) Interprocess dlsym() for OS X & iOS
- [**140**Star][4m] [Go] [greenboxal/dns-heaven](https://github.com/greenboxal/dns-heaven) 通过/etc/resolv.conf 启用本地 DNS stack 来修复（愚蠢的） macOS DNS stack
- [**139**Star][3y] [Py] [google/tcp_killer](https://github.com/google/tcp_killer) 关闭 Linux或 MacOS 的 Tcp 端口
- [**139**Star][8m] [C++] [macmade/dyld_cache_extract](https://github.com/macmade/dyld_cache_extract) A macOS utility to extract dynamic libraries from the dyld_shared_cache of macOS and iOS.
- [**130**Star][4m] [Py] [apperian/ios-checkipa](https://github.com/apperian/ios-checkipa) Scans an IPA file and parses its Info.plist and embedded.mobileprovision files. Performs checks of expected key/value relationships and displays the results.
- [**129**Star][4y] [Go] [benjojo/dos_ssh](https://github.com/benjojo/dos_ssh) Use BIOS ram hacks to make a SSH server out of any INT 10 13h app (MS-DOS is one of those)
- [**129**Star][2m] [Py] [stratosphereips/stratospherelinuxips](https://github.com/stratosphereips/stratospherelinuxips) an intrusion prevention system that is based on behavioral detections and machine learning algorithms
- [**128**Star][2y] [Py] [unfetter-discover/unfetter-analytic](https://github.com/unfetter-discover/unfetter-analytic) a framework for collecting events (process creation, network connections, Window Event Logs, etc.) from a client machine (Windows 7) and performing CAR analytics to detect potential adversary activity
- [**126**Star][3m] [Py] [platomav/biosutilities](https://github.com/platomav/biosutilities) Various BIOS Utilities for Modding/Research
- [**126**Star][4y] [Py] [sektioneins/sandbox_toolkit](https://github.com/sektioneins/sandbox_toolkit) Toolkit for binary iOS / OS X sandbox profiles
- [**125**Star][16d] [C] [projecthorus/radiosonde_auto_rx](https://github.com/projecthorus/radiosonde_auto_rx) Automatically Track Radiosonde Launches using RTLSDR
- [**125**Star][3y] [JS] [vtky/swizzler2](https://github.com/vtky/swizzler2) Swizzler2 - Hacking iOS applications
- [**121**Star][2y] [Swift] [lxdcn/nepackettunnelvpndemo](https://github.com/lxdcn/nepackettunnelvpndemo) iOS VPN client implementation demo based on iOS9 NetworkExtension NETunnelProvider APIs
- [**119**Star][1y] [Py] [winheapexplorer/winheap-explorer](https://github.com/winheapexplorer/winheap-explorer) heap-based bugs detection in x86 machine code for Windows applications.
- [**113**Star][3y] [Objective-C++] [yonsm/ipafine](https://github.com/yonsm/ipafine) iOS IPA package refine and resign
- [**111**Star][5m] [C++] [danielcardeenas/audiostego](https://github.com/danielcardeenas/audiostego) Audio file steganography. Hides files or text inside audio files and retrieve them automatically
- [**110**Star][8m] [C] [siguza/imobax](https://github.com/siguza/imobax) iOS Mobile Backup Extractor
- [**106**Star][7y] [intrepidusgroup/trustme](https://github.com/intrepidusgroup/trustme) Disable certificate trust checks on iOS devices.
- [**99**Star][2y] [antid0tecom/ios-kerneldocs](https://github.com/Antid0teCom/ios-kerneldocs) Various files helping to better understand the iOS / WatchOS / tvOS kernels
- [**98**Star][2y] [Py] [google/legilimency](https://github.com/google/legilimency) A Memory Research Platform for iOS
- [**96**Star][7m] [Swift] [depoon/networkinterceptor](https://github.com/depoon/networkinterceptor) iOS URLRequest interception framework
- [**96**Star][2y] [Swift] [liruqi/mume-ios](https://github.com/liruqi/mume-ios) an iOS client that implements custom proxies with the leverage of Network Extension framework introduced by Apple since iOS 9
- [**95**Star][2y] [ObjC] [xslim/mobiledevicemanager](https://github.com/xslim/mobiledevicemanager) Manage iOS devices through iTunes lib
- [**93**Star][1y] [Jupyter Notebook] [positivetechnologies/seq2seq-web-attack-detection](https://github.com/positivetechnologies/seq2seq-web-attack-detection) The implementation of the Seq2Seq model for web attack detection. The Seq2Seq model is usually used in Neural Machine Translation. The main goal of this project is to demonstrate the relevance of the NLP approach for web security.
- [**90**Star][2y] [PS] [netbiosx/digital-signature-hijack](https://github.com/netbiosx/digital-signature-hijack) Binaries, PowerShell scripts and information about Digital Signature Hijacking.
- [**90**Star][5y] [ObjC] [project-imas/app-password](https://github.com/project-imas/app-password) Custom iOS user authentication mechanism (password with security questions for self reset)
- [**85**Star][4y] [Swift] [deniskr/keychainswiftapi](https://github.com/deniskr/keychainswiftapi) This Keychain Swift API library is a wrapper of iOS C Keychain Framework. It allows easily and securely storing sensitive data in secure keychain store.
- [**85**Star][2y] [ObjC] [siguza/phoenixnonce](https://github.com/siguza/phoenixnonce) 64-bit nonce setter for iOS 9.3.4-9.3.5
- [**84**Star][8m] [Py] [aaronst/macholibre](https://github.com/aaronst/macholibre) Mach-O & Universal Binary Parser
- [**83**Star][10m] [Shell] [trailofbits/ios-integrity-validator](https://github.com/trailofbits/ios-integrity-validator) Integrity validator for iOS devices
- [**79**Star][1y] [Swift] [aidevjoe/sandboxbrowser](https://github.com/aidevjoe/sandboxbrowser) A simple iOS sandbox file browser, you can share files through AirDrop
- [**79**Star][4y] [mi3security/su-a-cyder](https://github.com/mi3security/su-a-cyder) Home-Brewed iOS Malware PoC Generator (BlackHat ASIA 2016)
- [**79**Star][6y] [C] [peterfillmore/removepie](https://github.com/peterfillmore/removepie) removePIE changes the MH_PIE flag of the MACH-O header on iOS applications to disable ASLR on applications
- [**78**Star][1y] [Shell] [iaik/ios-analysis](https://github.com/iaik/ios-analysis) Automated Binary Analysis on iOS
- [**77**Star][2y] [ObjC] [cocoahuke/ioskextdump](https://github.com/cocoahuke/ioskextdump) Dump Kext information from iOS kernel cache. Applicable to the kernel which dump from memory
- [**75**Star][7m] [Py] [tribler/dispersy](https://github.com/tribler/dispersy) The elastic database system. A database designed for P2P-like scenarios, where potentially millions of computers send database updates around.
- [**74**Star][29d] [C] [certificate-helper/tls-inspector](https://github.com/certificate-helper/tls-inspector) Easily view and inspect X.509 certificates on your iOS device.
- [**72**Star][4m] [C++] [macmade/unicorn-bios](https://github.com/macmade/unicorn-bios) Basic BIOS emulator for Unicorn Engine.
- [**72**Star][6y] [Py] [piccimario/iphone-backup-analyzer-2](https://github.com/piccimario/iphone-backup-analyzer-2) iPBA, Qt version
- [**72**Star][3y] [C++] [razzile/liberation](https://github.com/razzile/liberation) A runtime patching library for iOS. Major rework on unfinished branch
- [**72**Star][30d] [Py] [ehco1996/aioshadowsocks](https://github.com/ehco1996/aioshadowsocks) 用 asyncio 重写 shadowsocks ~
- [**69**Star][3m] [C] [brandonplank/rootlessjb4](https://github.com/BrandonPlank/rootlessJB4) rootlessJB that supports iOS 12.0 - 12.2 & 12.4
- [**67**Star][22d] [Py] [guardianfirewall/grandmaster](https://github.com/guardianfirewall/grandmaster) A simplistic python tool that assists in automating iOS firmware decryption.
- [**65**Star][4y] [zhengmin1989/ios-10-decrypted-kernel-cache](https://github.com/zhengmin1989/ios-10-decrypted-kernel-cache) iOS 10 Decrypted Kernel Cache
- [**65**Star][5y] [ObjC] [project-imas/memory-security](https://github.com/project-imas/memory-security) Tools for securely clearing and validating iOS application memory
- [**63**Star][2y] [josephlhall/dc25-votingvillage-report](https://github.com/josephlhall/dc25-votingvillage-report) A report to synthesize findings from the Defcon 25 Voting Machine Hacking Village
- [**62**Star][8m] [C] [luoyanbei/testhookzz](https://github.com/luoyanbei/testhookzz) iOS逆向：使用HookZz框架hook游戏“我的战争”，进入上帝模式
- [**62**Star][5m] [C++] [meitu/mtgldebug](https://github.com/meitu/mtgldebug) An OpenGL debugging tool for iOS.
- [**61**Star][9y] [C] [chronic-dev/bootrom-dumper](https://github.com/chronic-dev/bootrom-dumper) Utility to Dump iPhone Bootrom
- [**61**Star][6m] [PS] [texhex/biossledgehammer](https://github.com/texhex/biossledgehammer) Automated BIOS, ME, TPM firmware update and BIOS settings for HP devices
- [**61**Star][11m] [ObjC] [tihmstar/v3ntex](https://github.com/tihmstar/v3ntex) getf tfp0 on iOS 12.0 - 12.1.2
- [**60**Star][4y] [shadowsocks/tun2socks-ios](https://github.com/shadowsocks/tun2socks-ios) tun2socks as a library for iOS apps
- [**58**Star][7m] [Perl] [dnsmichi/manubulon-snmp](https://github.com/dnsmichi/manubulon-snmp) Set of Icinga/Nagios plugins to check hosts and hardware wi the SNMP protocol.
- [**58**Star][4y] [HTML] [nccgroup/iodide](https://github.com/nccgroup/iodide) The Cisco IOS Debugger and Integrated Disassembler Environment
- [**58**Star][2y] [Shell] [tanprathan/fridpa](https://github.com/tanprathan/fridpa) An automated wrapper script for patching iOS applications (IPA files) and work on non-jailbroken device
- [**57**Star][ObjC] [jrock007/tob](https://github.com/jrock007/tob) Free, open-source and ad-less Tor web browser for iOS
- [**56**Star][11m] [ObjC] [geosn0w/chaos](https://github.com/geosn0w/chaos) Chaos iOS < 12.1.2 PoC by
- [**55**Star][2y] [jkpang/timliu-ios](https://github.com/jkpang/timliu-ios) iOS开发常用三方库、插件、知名博客等等
- [**55**Star][3y] [C++] [s-kanev/xiosim](https://github.com/s-kanev/xiosim) A detailed michroarchitectural x86 simulator
- [**55**Star][3y] [C] [synack/chaoticmarch](https://github.com/synack/chaoticmarch) A mechanism for automating input events on iOS
- [**52**Star][1y] [C] [bazad/threadexec](https://github.com/bazad/threadexec) A library to execute code in the context of other processes on iOS 11.
- [**52**Star][2y] [rehints/blackhat_2017](https://github.com/rehints/blackhat_2017) Betraying the BIOS: Where the Guardians of the BIOS are Failing
- [**52**Star][10m] [Logos] [zhaochengxiang/ioswechatfakelocation](https://github.com/zhaochengxiang/ioswechatfakelocation) A tweak that can fake location info in WeChat
- [**51**Star][3y] [HTML] [pwnsdx/ios-uri-schemes-abuse-poc](https://github.com/pwnsdx/ios-uri-schemes-abuse-poc) A set of URI schemes bugs that lead Safari to crash/freeze.
- [**49**Star][1y] [Swift] [sherlouk/swiftprovisioningprofile](https://github.com/sherlouk/swiftprovisioningprofile) Parse iOS mobile provisioning files into Swift models
- [**48**Star][2y] [Shell] [leanvel/iinject](https://github.com/leanvel/iinject) Tool to automate the process of embedding dynamic libraries into iOS applications from GNU/Linux
- [**48**Star][7m] [ObjC] [smilezxlee/zxhookutil](https://github.com/smilezxlee/zxhookutil) 【iOS逆向】Tweak工具函数集，基于theos、monkeyDev
- [**47**Star][2m] [ObjC] [ooni/probe-ios](https://github.com/ooni/probe-ios) OONI Probe iOS
- [**47**Star][4y] [Py] [ostorlab/jniostorlab](https://github.com/ostorlab/jniostorlab) JNI method enumeration in ELF files
- [**47**Star][3m] [ObjC] [smilezxlee/zxrequestblock](https://github.com/smilezxlee/zxrequestblock) 一句话实现iOS应用底层所有网络请求拦截(如ajax请求拦截)，包含http-dns解决方法，有效防止DNS劫持，用于分析http，https请求，禁用/允许代理，防抓包等
- [**47**Star][2m] [the-blockchain-bible/readme](https://github.com/the-blockchain-bible/readme) The Blockchain Bible,a collections for blockchain tech,bitcoin,ethereum,crypto currencies,cryptography,decentralized solutions,business scenarios,hyperledger tech,meetups,区块链,数字货币,加密货币,比特币,以太坊,密码学,去中心化,超级账本
- [**47**Star][5y] [PHP] [cloudsec/aioshell](https://github.com/cloudsec/aioshell) A php webshell run under linux based webservers. v0.05
- [**46**Star][2y] [C] [encounter/tsschecker](https://github.com/encounter/tsschecker) Check TSS signing status of iOS firmwares and save SHSH blobs
- [**46**Star][2y] [uefitech/resources](https://github.com/uefitech/resources) One-stop shop for UEFI/BIOS specifications/utilities by UEFI.Tech community
- [**46**Star][1y] [Go] [unixpickle/cve-2018-4407](https://github.com/unixpickle/cve-2018-4407) Crash macOS and iOS devices with one packet
- [**44**Star][4y] [C] [samdmarshall/machodiff](https://github.com/samdmarshall/machodiff) mach-o diffing tool
- [**43**Star][5y] [Shell] [netspi/heapdump-ios](https://github.com/netspi/heapdump-ios) Dump IOS application heap space from memory
- [**42**Star][1m] [ObjC] [dineshshetty/ios-sandbox-dumper](https://github.com/dineshshetty/ios-sandbox-dumper) SandBox-Dumper makes use of multiple private libraries to provide exact locations of the application sandbox, application bundle and some other interesting information
- [**42**Star][2y] [Py] [klsecservices/ios_mips_gdb](https://github.com/klsecservices/ios_mips_gdb) Cisco MIPS debugger
- [**40**Star][15d] [Swift] [fonta1n3/fullynoded](https://github.com/fonta1n3/fullynoded) A Bitcoin Core GUI for iOS devices. Allows you to connect to and control multiple nodes via Tor
- [**39**Star][3y] [Logos] [ahmadhashemi/immortal](https://github.com/ahmadhashemi/immortal) Prevent expiration of signed iOS applications & bypass 3 free signed applications per device limit
- [**39**Star][4m] [Py] [gh2o/rvi_capture](https://github.com/gh2o/rvi_capture) rvictl for Linux and Windows: capture packets sent/received by iOS devices
- [**39**Star][4y] [Pascal] [senjaxus/delphi_remote_access_pc](https://github.com/senjaxus/delphi_remote_access_pc) Remote access in Delphi 7 and Delphi XE5 (With sharer files, CHAT and Forms Inheritance) || Acesso Remoto em Delphi 7 e Delphi XE5 (Com Compartilhador de Arquivos, CHAT e Herança de Formulários)
- [**39**Star][27d] [Shell] [userlandkernel/plataoplomo](https://github.com/userlandkernel/plataoplomo) Collection of (at time of release) iOS bugs I found
- [**39**Star][3m] [Py] [meituan-dianping/lyrebird-ios](https://github.com/meituan-dianping/lyrebird-ios) 本程序是Lyrebird插件，您可以在插件中快速查看已连接iOS设备的详细设备信息，截取屏幕快照，以及查看已连接设备的应用信息。
- [**38**Star][4y] [C] [taichisocks/shadowsocks](https://github.com/taichisocks/shadowsocks) Lightweight shadowsocks client for iOS and Mac OSX base on shadowsocks-libev
- [**38**Star][1y] [ObjC] [xmartlabs/metalperformanceshadersproxy](https://github.com/xmartlabs/metalperformanceshadersproxy) A proxy for MetalPerformanceShaders which takes to a stub on a simulator and to the real implementation on iOS devices.
- [**37**Star][4m] [Ruby] [appspector/ios-sdk](https://github.com/appspector/ios-sdk) AppSpector is a debugging service for mobile apps
- [**36**Star][4y] [Objective-C++] [cyhe/iossecurity-attack](https://github.com/cyhe/iossecurity-attack) APP安全(逆向攻击篇)
- [**36**Star][3y] [PS] [machosec/mystique](https://github.com/machosec/mystique) PowerShell module to play with Kerberos S4U extensions
- [**35**Star][4y] [Py] [curehsu/ez-wave](https://github.com/curehsu/ez-wave) Tools for Evaluating and Exploiting Z-Wave Networks using Software-Defined Radios.
- [**35**Star][1y] [Swift] [vixentael/zka-example](https://github.com/vixentael/zka-example) Zero Knowledge Application example, iOS, notes sharing, Firebase backend
- [**33**Star][3y] [ObjC] [integrity-sa/introspy-ios](https://github.com/integrity-sa/introspy-ios) Security profiling for blackbox iOS
- [**33**Star][7y] [C] [mubix/fakenetbios](https://github.com/mubix/fakenetbios) See here:
- [**33**Star][10m] [Swift] [vixentael/ios-datasec-basics](https://github.com/vixentael/ios-datasec-basics) iOS data security basics: key management, workshop for iOS Con UK
- [**33**Star][2m] [ObjC] [proteas/ios13-sandbox-profile-format](https://github.com/proteas/ios13-sandbox-profile-format) Binary Format of iOS 13 Sandbox Profile Collection
- [**31**Star][3y] [Py] [as0ler/r2clutch](https://github.com/as0ler/r2clutch) r2-based tool to decrypt iOS applications
- [**31**Star][3y] [Assembly] [gyje/bios_rootkit](https://github.com/gyje/bios_rootkit) 来自Freebuf评论区,一个UEFI马.
- [**31**Star][2y] [proappleos/upgrade-from-10.3.x-to-ios-11.1.2-on-any-64bit-device-with-blobs](https://github.com/ProAppleOS/Upgrade-from-10.3.x-to-iOS-11.1.2-on-any-64Bit-device-with-Blobs) How to Upgrade any 64Bit Device from 10.3.x to 11.1.2 with Blobs
- [**30**Star][3y] [ObjC] [mtigas/iobfs](https://github.com/mtigas/iobfs) Building obfs4proxy for Tor-enabled iOS apps.
- [**30**Star][2y] [Shell] [pnptutorials/pnp-portablehackingmachine](https://github.com/pnptutorials/pnp-portablehackingmachine) This script will convert your Raspberry Pi 3 into a portable hacking machine.
- [**30**Star][8y] [Py] [hubert3/isniff](https://github.com/hubert3/isniff) SSL man-in-the-middle tool targeting iOS devices < 4.3.5
- [**29**Star][12m] [Py] [antid0tecom/ipad_accessory_research](https://github.com/antid0tecom/ipad_accessory_research) Research into Security of Apple Smart Keyboard and Apple Pencil
- [**29**Star][4y] [ObjC] [quellish/facebook-ios-internal-headers](https://github.com/quellish/facebook-ios-internal-headers) Headers generated by reverse engineering the Facebook iOS binary
- [**29**Star][8y] [sektioneins/.ipa-pie-scanner](https://github.com/sektioneins/.ipa-PIE-Scanner) Scans iPhone/iPad/iPod applications for PIE flags
- [**29**Star][4y] [C] [scallywag/nbtscan](https://github.com/scallywag/nbtscan) NetBIOS scanning tool. Currently segfaults!
- [**28**Star][2y] [ObjC] [dannagle/packetsender-ios](https://github.com/dannagle/packetsender-ios) Packet Sender for iOS, Send/Receive UDP/TCP
- [**28**Star][10m] [C] [mrmacete/r2-ios-kernelcache](https://github.com/mrmacete/r2-ios-kernelcache) Radare2 plugin to parse modern iOS 64-bit kernel caches
- [**28**Star][3y] [C] [salmg/audiospoof](https://github.com/salmg/audiospoof) Magnetic stripe spoofer implementing audio waves.
- [**28**Star][4y] [Swift] [urinx/device-9](https://github.com/urinx/device-9) 实时监测网速，IP，内存大小，温度等设备信息并显示在通知中心的 iOS App
- [**27**Star][1y] [alonemonkey/iosrebook-issues](https://github.com/alonemonkey/iosrebook-issues) 《iOS应用逆向与安全》 勘误
- [**27**Star][27d] [Perl] [hknutzen/netspoc](https://github.com/hknutzen/netspoc) A network security policy compiler. Netspoc is targeted at large environments with a large number of firewalls and admins. Firewall rules are derived from a single rule set. Supported are Cisco IOS, NX-OS, ASA and IPTables.
- [**27**Star][3m] [Rust] [marcograss/rust-kernelcache-extractor](https://github.com/marcograss/rust-kernelcache-extractor) Extract a decrypted iOS 64-bit kernelcache
- [**27**Star][8m] [Py] [qingxp9/cve-2019-6203-poc](https://github.com/qingxp9/cve-2019-6203-poc) PoC for CVE-2019-6203, works on < iOS 12.2, macOS < 10.14.4
- [**27**Star][5m] [Py] [mvelazc0/purplespray](https://github.com/mvelazc0/purplespray) PurpleSpray is an adversary simulation tool that executes password spray behavior under different scenarios and conditions with the purpose of generating attack telemetry in properly monitored Windows enterprise environments
- [**26**Star][2y] [C++] [cuitche/code-obfuscation](https://github.com/cuitche/code-obfuscation) 一款iOS代码混淆工具(A code obfuscation tool for iOS.)
- [**26**Star][5m] [HTML] [devnetsandbox/sbx_multi_ios](https://github.com/devnetsandbox/sbx_multi_ios) Sample code, examples, and resources for use with the DevNet Multi-IOS Sandbox
- [**26**Star][4y] [ObjC] [qiuyuzhou/shadowsocks-ios](https://github.com/qiuyuzhou/shadowsocks-ios) No maintaining. Try this
- [**26**Star][3y] [ObjC] [nabla-c0d3/ios-reversing](https://github.com/nabla-c0d3/ios-reversing) Some iOS tools and scripts from 2014 for iOS reversing.
- [**26**Star][5m] [Swift] [itsjohnye/lead-ios](https://github.com/itsjohnye/lead-ios) a featherweight iOS SS proxy client with interactive UI
- [**25**Star][2y] [C] [embedi/tcl_shellcode](https://github.com/embedi/tcl_shellcode) A template project for creating a shellcode for the Cisco IOS in the C language
- [**25**Star][1y] [HTML] [649/crash-ios-exploit](https://github.com/649/crash-ios-exploit) Repository dedicated to storing a multitude of iOS/macOS/OSX/watchOS crash bugs. Some samples need to be viewed as raw in order to see the Unicode. Please do not intentionally abuse these exploits.
- [**24**Star][6y] [ObjC] [samdmarshall/ios-internals](https://github.com/samdmarshall/ios-internals) iOS related code
- [**23**Star][5y] [Ruby] [claudijd/bnat](https://github.com/claudijd/bnat) "Broken NAT" - A suite of tools focused on detecting and interacting with publicly available BNAT scenerios
- [**23**Star][1y] [ObjC] [rpwnage/warri0r](https://github.com/RPwnage/Warri0r) ios 12 Sandbox escape POC
- [**22**Star][2y] [jasklabs/blackhat2017](https://github.com/jasklabs/blackhat2017) Data sets and examples for Jask Labs Blackhat 2017 Handout: Top 10 Machine Learning Cyber Security Use Cases
- [**22**Star][4y] [sunkehappy/ios-reverse-engineering-tools-backup](https://github.com/sunkehappy/ios-reverse-engineering-tools-backup) Some guys find the old lsof could not be downloaded. But I have it and I want to share it.
- [**22**Star][1y] [PHP] [svelizdonoso/asyrv](https://github.com/svelizdonoso/asyrv) ASYRV es una aplicación escrita en PHP/MySQL, con Servicios Web mal desarrollados(SOAP/REST/XML), esperando ayudar a los entusiastas de la seguridad informática a comprender esta tecnología tan utilizada hoy en día por las Organizaciones.
- [**21**Star][2y] [troydo42/awesome-pen-test](https://github.com/troydo42/awesome-pen-test) Experiment with penetration testing Guides and Tools for WordPress, iOS, MacOS, Wifi and Car
- [**20**Star][1y] [C] [downwithup/cve-2018-16712](https://github.com/downwithup/cve-2018-16712) PoC Code for CVE-2018-16712 (exploit by MmMapIoSpace)
- [**20**Star][1y] [Ruby] [martinvigo/ransombile](https://github.com/martinvigo/ransombile) Ransombile is a tool that can be used in different scenarios to compromise someone’s digital life when having physical access to a locked mobile device
- [**19**Star][3y] [Swift] [depoon/injectiblelocationspoofing](https://github.com/depoon/injectiblelocationspoofing) Location Spoofing codes for iOS Apps via Code Injection
- [**19**Star][1y] [ObjC] [frpccluster/frpc-ios](https://github.com/frpccluster/frpc-ios) IOS,苹果版frpc.一个快速反向代理，可帮助您将NAT或防火墙后面的本地服务器暴露给Internet。
- [**19**Star][6y] [Logos] [iosre/iosrelottery](https://github.com/iosre/iosrelottery) 
- [**18**Star][12d] [Py] [adafruit/adafruit_circuitpython_rfm9x](https://github.com/adafruit/adafruit_circuitpython_rfm9x) CircuitPython module for the RFM95/6/7/8 LoRa wireless 433/915mhz packet radios.
- [**16**Star][4y] [ashishb/ios-malware](https://github.com/ashishb/ios-malware) iOS malware samples
- [**16**Star][2y] [ObjC] [mikaelbo/updateproxysettings](https://github.com/mikaelbo/updateproxysettings) A simple iOS command line tool for updating proxy settings
- [**16**Star][1y] [Py] [r3dxpl0it/cve-2018-4407](https://github.com/r3dxpl0it/cve-2018-4407) IOS/MAC Denial-Of-Service [POC/EXPLOIT FOR MASSIVE ATTACK TO IOS/MAC IN NETWORK]
- [**15**Star][2y] [Objective-C++] [ay-kay/cda](https://github.com/ay-kay/cda) iOS command line tool to search for installed apps and list container paths (bundle, data, group)
- [**15**Star][2y] [Py] [mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) a list of BIOS/Firmware fixes adressing CVE-2017-5715, CVE-2017-5753, CVE-2017-5754
- [**15**Star][2y] [Swift] [vgmoose/nc-client](https://github.com/vgmoose/nc-client) [iOS] netcat gui app, for using the 10.1.x mach_portal root exploit on device
- [**15**Star][12m] [aliasrobotics/rctf](https://github.com/aliasrobotics/rctf) Scenarios of the Robotics CTF (RCTF), a playground to challenge robot security.
- [**14**Star][2m] [refractionpoint/limacharlie](https://github.com/refractionpoint/limacharlie) Old home of LimaCharlie, open source EDR
- [**14**Star][7y] [Py] [trotsky/insyde-tools](https://github.com/trotsky/insyde-tools) (Inactive) Tools for unpacking and modifying an InsydeH2O UEFI BIOS now merged into coreboot
- [**14**Star][5y] [C] [yifanlu/polipo-ios](https://github.com/yifanlu/polipo-ios) iOS port of Polipo caching HTTP proxy
- [**13**Star][1y] [ObjC] [omerporze/toothfairy](https://github.com/omerporze/toothfairy) CVE-2018-4330 POC for iOS
- [**13**Star][6y] [Py] [yuejd/ios_restriction_passcode_crack---python-version](https://github.com/yuejd/ios_restriction_passcode_crack---python-version) Crack ios Restriction PassCode in Python
- [**13**Star][2m] [Shell] [ewypych/icinga-domain-expiration-plugin](https://github.com/ewypych/icinga-domain-expiration-plugin) Icinga2/Nagios plugin for checking domain expiration
- [**12**Star][8y] [C] [akgood/iosbasicconstraintsworkaround](https://github.com/akgood/iosbasicconstraintsworkaround) Proof-of-Concept OpenSSL-based workaround for iOS basicConstraints SSL certificate validation vulnerability
- [**12**Star][10m] [Py] [wyatu/cve-2018-4407](https://github.com/wyatu/cve-2018-4407) CVE-2018-4407 IOS/macOS kernel crash
- [**11**Star][8m] [Swift] [sambadiallob/pubnubchat](https://github.com/sambadiallob/pubnubchat) An anonymous chat iOS app made using PubNub
- [**11**Star][3y] [ObjC] [flankerhqd/descriptor-describes-toctou](https://github.com/flankerhqd/descriptor-describes-toctou) POCs for IOMemoryDescriptor racing bugs in iOS/OSX kernels
- [**10**Star][1y] [Py] [zteeed/cve-2018-4407-ios](https://github.com/zteeed/cve-2018-4407-ios) POC: Heap buffer overflow in the networking code in the XNU operating system kernel
- [**9**Star][2y] [Logos] [asnowfish/ios-system](https://github.com/asnowfish/ios-system) iOS系统的逆向代码
- [**9**Star][4y] [C] [yigitcanyilmaz/iohideventsystemuserclient](https://github.com/yigitcanyilmaz/iohideventsystemuserclient) iOS Kernel Race Vulnerability (Patched on iOS 9.3.2,OSX 10.11.5,tvOS 9.2.1 by Apple)
- [**9**Star][2y] [C] [syst3ma/cisco_ios_research](https://github.com/syst3ma/cisco_ios_research) 
- [**9**Star][2m] [nemo-wq/privilege_escalation](https://github.com/nemo-wq/privilege_escalation) Lab exercises to practice privilege escalation scenarios in AWS IAM. These exercises and the slides go through the basics behind AWS IAM, common weaknesses in AWS deployments, specific to IAM, and how to exploit them manually. This was run as a workshop at BruCon 2019.
- [**9**Star][2y] [C] [syst3ma/cisco_ios_research](https://github.com/syst3ma/cisco_ios_research) 
- [**8**Star][6y] [C] [linusyang/sslpatch](https://github.com/linusyang/sslpatch) Patch iOS SSL vulnerability (CVE-2014-1266)
- [**8**Star][2y] [pinczakko/nsa_bios_backdoor_articles](https://github.com/pinczakko/nsa_bios_backdoor_articles) PDF files of my articles on NSA BIOS backdoor
- [**8**Star][2y] [JS] [ansjdnakjdnajkd/frinfo](https://github.com/ansjdnakjdnajkd/frinfo) Dump files, data, cookies, keychain and etc. from iOS device with one click.
- [**7**Star][7y] [ObjC] [hayaq/recodesign](https://github.com/hayaq/recodesign) Re-codesigning tool for iOS ipa file
- [**7**Star][11m] [Py] [shawarkhanethicalhacker/cve-2019-8389](https://github.com/shawarkhanethicalhacker/cve-2019-8389) [CVE-2019-8389] An exploit code for exploiting a local file read vulnerability in Musicloud v1.6 iOS Application
- [**7**Star][1y] [C] [ukern-developers/xnu-kernel-fuzzer](https://github.com/ukern-developers/xnu-kernel-fuzzer) Kernel Fuzzer for Apple's XNU, mainly meant for the iOS operating system
- [**6**Star][2y] [C] [jduncanator/isniff](https://github.com/jduncanator/isniff) Packet capture and network sniffer for Apple iOS devices (iPhone / iPod). An implementation of iOS 5+ Remote Virtual Interface service and pcapd.
- [**6**Star][6y] [Shell] [rawrly/juicejacking](https://github.com/rawrly/juicejacking) Several script and images used with the juice jacking kiosks
- [**6**Star][8y] [Ruby] [spiderlabs/bnat-suite](https://github.com/spiderlabs/bnat-suite) "Broken NAT" - A suite of tools focused on detecting/exploiting/fixing publicly available BNAT scenerios
- [**4**Star][12m] [anonymouz4/apple-remote-crash-tool-cve-2018-4407](https://github.com/anonymouz4/apple-remote-crash-tool-cve-2018-4407) Crashes any macOS High Sierra or iOS 11 device that is on the same WiFi network
- [**4**Star][2y] [C] [chibitronics/ltc-os](https://github.com/chibitronics/ltc-os) ChibiOS-based operating system for the Love-to-Code project
- [**4**Star][2y] [Swift] [crazyquark/keysafe](https://github.com/crazyquark/keysafe) A technical demo on how to use KeySecGeneratePair() with the secure enclave in iOS 9+
- [**4**Star][8y] [ObjC] [spiderlabs/twsl2011-007_ios_code_workaround](https://github.com/spiderlabs/twsl2011-007_ios_code_workaround) Workaround for the vulnerability identified by TWSL2011-007 or CVE-2008-0228 - iOS x509 Certificate Chain Validation Vulnerability
- [**3**Star][3y] [ObjC] [susnmos/xituhook](https://github.com/susnmos/xituhook) 逆向分析及修复稀土掘金iOS版客户端闪退bug
- [**3**Star][4y] [Py] [torque59/yso-mobile-security-framework](https://github.com/torque59/yso-mobile-security-framework) Mobile Security Framework is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static and dynamic analysis.
- [**3**Star][1y] [tthtlc/awesome_malware_techniques](https://github.com/tthtlc/awesome_malware_techniques) This will compile a list of Android, iOS, Linux malware techniques for attacking and detection purposes.
- [**3**Star][4y] [Py] [tudorthe1ntruder/rubber-ducky-ios-pincode-bruteforce](https://github.com/tudorthe1ntruder/rubber-ducky-ios-pincode-bruteforce) 
- [**2**Star][3y] [Py] [alexplaskett/needle](https://github.com/alexplaskett/needle) The iOS Security Testing Framework.
- [**2**Star][5y] [HTML] [dhirajongithub/owasp-kalp-mobile-project-ios-app](https://github.com/dhirajongithub/owasp-kalp-mobile-project-ios-app) OWASP KALP Mobile Project is an iOS application developed for users to view OWASP Top 10 (WEB and MOBILE) on mobile device.
- [**2**Star][2y] [C] [kigkrazy/hookzz](https://github.com/kigkrazy/hookzz) a cute hook framwork for arm/arm64/ios/android
- [**2**Star][4y] [C] [ohdarling/potatso-ios](https://github.com/ohdarling/potatso-ios) Potatso is an iOS client that implements Shadowsocks proxy with the leverage of NetworkExtension framework in iOS 9.
- [**2**Star][1y] [Py] [zeng9t/cve-2018-4407-ios-exploit](https://github.com/zeng9t/cve-2018-4407-ios-exploit) CVE-2018-4407,iOS exploit
- [**2**Star][2y] [nrollr/ios](https://github.com/nrollr/ios) Ivan Krstić - Black Hat 2016 presentation
- [**1**Star][10m] [Ruby] [hercules-team/augeasproviders_nagios](https://github.com/hercules-team/augeasproviders_nagios) Augeas-based nagios types and providers for Puppet
- [**1**Star][4y] [Go] [jordan2175/ios-passcode-crack](https://github.com/jordan2175/ios-passcode-crack) Tool for cracking the iOS restrictions passcode
- [**0**Star][2y] [ObjC] [joedaguy/exploit11.2](https://github.com/joedaguy/exploit11.2) Exploit iOS 11.2.x by ZIMPERIUM and semi-completed by me. Sandbox escapes on CVE-2018-4087.
- [**0**Star][3y] [C] [maximehip/extra_recipe](https://github.com/maximehip/extra_recipe) Ian Beer's exploit for CVE-2017-2370 (kernel memory r/w on iOS 10.2)
- [**0**Star][6y] [ObjC] [skycure/skycure_news](https://github.com/skycure/skycure_news) Sample news iOS application
- [**0**Star][2y] [Py] [tsunghowu/diskimagecreator](https://github.com/tsunghowu/diskimagecreator) A python utility to process the input raw disk image and sign MBR/partitions with given corresponding keys. This tool is designed to help people attack the machine with a secure chain-of-trust boot process in UEFI BIOS.
- [**0**Star][3y] [Swift] [jencisov/stackview](https://github.com/jencisov/StackView) POC project of StackViews on iOS
- [**0**Star][2m] [HTML] [dotnetnicaragua/example-xss-crosssitescripting](https://github.com/dotnetnicaragua/example-xss-crosssitescripting) Ejemplo de vulnerabilidad: A7 - Secuencia de Comandos en Sitios Cruzados (XSS) según OWASP TOP 10 2017




***


## <a id="c97bbe32bbd26c72ceccb43400e15bf1"></a>Posts&&Videos


### <a id="d4425fc7c360c2ff324be718cf3b7a78"></a>Recent Add






# <a id="0ae4ddb81ff126789a7e08b0768bd693"></a>Cuckoo


***


## <a id="5830a8f8fb3af1a336053d84dd7330a1"></a>Tools


### <a id="f2b5c44c2107db2cec6c60477c6aa1d0"></a>Recent Add


- [**4042**Star][3m] [JS] [cuckoosandbox/cuckoo](https://github.com/cuckoosandbox/cuckoo) Cuckoo Sandbox is an automated dynamic malware analysis system
- [**458**Star][2y] [Py] [idanr1986/cuckoo-droid](https://github.com/idanr1986/cuckoo-droid) Automated Android Malware Analysis with Cuckoo Sandbox.
- [**357**Star][3y] [Py] [spender-sandbox/cuckoo-modified](https://github.com/spender-sandbox/cuckoo-modified) Modified edition of cuckoo
- [**308**Star][2m] [Py] [hatching/vmcloak](https://github.com/hatching/vmcloak) Automated Virtual Machine Generation and Cloaking for Cuckoo Sandbox.
- [**248**Star][4y] [C] [begeekmyfriend/cuckoofilter](https://github.com/begeekmyfriend/cuckoofilter) Substitute for bloom filter.
- [**238**Star][7m] [Py] [cuckoosandbox/community](https://github.com/cuckoosandbox/community) Repository of modules and signatures contributed by the community
- [**236**Star][5y] [C] [conix-security/zer0m0n](https://github.com/conix-security/zer0m0n) zer0m0n driver for cuckoo sandbox
- [**236**Star][4m] [Py] [brad-sp/cuckoo-modified](https://github.com/brad-sp/cuckoo-modified) Modified edition of cuckoo
- [**225**Star][1y] [PHP] [cuckoosandbox/monitor](https://github.com/cuckoosandbox/monitor) The new Cuckoo Monitor.
- [**220**Star][4m] [Shell] [blacktop/docker-cuckoo](https://github.com/blacktop/docker-cuckoo) Cuckoo Sandbox Dockerfile
- [**202**Star][2y] [C] [david-reguera-garcia-dreg/anticuckoo](https://github.com/david-reguera-garcia-dreg/anticuckoo) A tool to detect and crash Cuckoo Sandbox
- [**151**Star][3y] [Shell] [buguroo/cuckooautoinstall](https://github.com/buguroo/cuckooautoinstall) Auto Installer Script for Cuckoo Sandbox
- [**124**Star][4y] [Py] [davidoren/cuckoosploit](https://github.com/davidoren/cuckoosploit) An environment for comprehensive, automated analysis of web-based exploits, based on Cuckoo sandbox.
- [**120**Star][4y] [C] [cuckoosandbox/cuckoomon](https://github.com/cuckoosandbox/cuckoomon) DEPRECATED - replaced with "monitor"
- [**117**Star][3y] [Py] [honeynet/cuckooml](https://github.com/honeynet/cuckooml) Machine Learning for Cuckoo Sandbox
- [**82**Star][2y] [Py] [idanr1986/cuckoodroid-2.0](https://github.com/idanr1986/cuckoodroid-2.0) Automated Android Malware Analysis with Cuckoo Sandbox.
- [**78**Star][5y] [Py] [idanr1986/cuckoo](https://github.com/idanr1986/cuckoo) A Cuckoo Sandbox Extension for Android
- [**70**Star][26d] [Py] [jpcertcc/malconfscan-with-cuckoo](https://github.com/jpcertcc/malconfscan-with-cuckoo) Cuckoo Sandbox plugin for extracts configuration data of known malware
- [**70**Star][4m] [PS] [nbeede/boombox](https://github.com/nbeede/boombox) Automatic deployment of Cuckoo Sandbox malware lab using Packer and Vagrant
- [**69**Star][3y] [C] [angelkillah/zer0m0n](https://github.com/angelkillah/zer0m0n) zer0m0n driver for cuckoo sandbox
- [**57**Star][8m] [Py] [hatching/sflock](https://github.com/hatching/sflock) Sample staging & detonation utility to be used in combination with Cuckoo Sandbox.
- [**55**Star][4y] [Py] [rodionovd/cuckoo-osx-analyzer](https://github.com/rodionovd/cuckoo-osx-analyzer) An OS X analyzer for Cuckoo Sandbox project
- [**52**Star][1y] [C] [phdphuc/mac-a-mal](https://github.com/phdphuc/mac-a-mal) 追踪macOS恶意软件的内核驱动, 与Cuckoo沙箱组合使用
- [**39**Star][7y] [Perl] [xme/cuckoomx](https://github.com/xme/cuckoomx) CuckooMX is a project to automate analysis of files transmitted over SMTP (using the Cuckoo sandbox)
- [**38**Star][3y] [C] [spender-sandbox/cuckoomon-modified](https://github.com/spender-sandbox/cuckoomon-modified) Modified edition of cuckoomon
- [**36**Star][6m] [ocatak/malware_api_class](https://github.com/ocatak/malware_api_class) Malware dataset for security researchers, data scientists. Public malware dataset generated by Cuckoo Sandbox based on Windows OS API calls analysis for cyber security researchers
- [**32**Star][2y] [Py] [phdphuc/mac-a-mal-cuckoo](https://github.com/phdphuc/mac-a-mal-cuckoo) extends the open-source Cuckoo Sandbox (legacy) with functionality for analyzing macOS malware in macOS guest VM(s).
- [**28**Star][3y] [Py] [0x71/cuckoo-linux](https://github.com/0x71/cuckoo-linux) Linux malware analysis based on Cuckoo Sandbox.
- [**19**Star][5y] [C] [zer0box/zer0m0n](https://github.com/zer0box/zer0m0n) zer0m0n driver for cuckoo sandbox
- [**16**Star][22d] [Py] [ryuchen/panda-sandbox](https://github.com/ryuchen/panda-sandbox) 这是一个基于 Cuckoo 开源版本的沙箱的修订版本, 该版本完全为了适配国内软件环境所打造
- [**12**Star][3y] [Py] [keithjjones/cuckoo-modified-api](https://github.com/keithjjones/cuckoo-modified-api) A Python library to interface with a cuckoo-modified instance
- [**10**Star][4y] [Py] [tribalchicken/postfix-cuckoolyse](https://github.com/tribalchicken/postfix-cuckoolyse) A Postfix filter which takes a piped message and submits it to Cuckoo Sandbox
- [**8**Star][2y] [Py] [kojibhy/cuckoo-yara-auto](https://github.com/kojibhy/cuckoo-yara-auto) simple python script to add yara rules in cuckoo sandbox
- [**8**Star][3y] [Py] [threatconnect-inc/cuckoo-reporting-module](https://github.com/threatconnect-inc/cuckoo-reporting-module) Cuckoo reporting module for version 1.2 stable
- [**7**Star][2y] [Ruby] [fyhertz/ansible-role-cuckoo](https://github.com/fyhertz/ansible-role-cuckoo) Automated installation of Cuckoo Sandbox with Ansible
- [**6**Star][3y] [Py] [xme/cuckoo](https://github.com/xme/cuckoo) Miscellaneous files related to Cuckoo sandbox
- [**4**Star][11m] [HTML] [hullgj/report-parser](https://github.com/hullgj/report-parser) Cuckoo Sandbox report parser into ransomware classifier
- [**2**Star][3y] [Shell] [harryr/cockatoo](https://github.com/harryr/cockatoo) Torified Cuckoo malware analyser in a Docker container with VirtualBox
- [**2**Star][7y] [Shell] [hiddenillusion/cuckoo3.2](https://github.com/hiddenillusion/cuckoo3.2) This repo contains patches for the 0.3.2 release of the cuckoo sandbox (
- [**1**Star][2y] [Py] [dc170/mbox-to-cuckoo](https://github.com/dc170/mbox-to-cuckoo) Simple python script to send all executable files extracted from linux postfix mailboxes to the cuckoo sandbox for further automated analysis




***


## <a id="ec0a441206d9a2fe1625dce0a679d466"></a>Post&&Videos


- 2019.04 [eforensicsmag] [How to Integrate RSA Malware Analysis with Cuckoo Sandbox | By Luiz Henrique Borges](https://eforensicsmag.com/how-to-integrate-rsa-malware-analysis-with-cuckoo-sandbox-by-luiz-henrique-borges/)
- 2019.02 [thehive] [Cortex-Analyzers 1.15.3 get ready for  URLhaus and Cuckoo](https://blog.thehive-project.org/2019/02/26/cortex-analyzers-1-15-3-get-ready-for-urlhaus-and-cuckoo/)
- 2018.07 [360] [一例IRC Bot针对Cuckoo沙箱的猥琐对抗分析](https://www.anquanke.com/post/id/152631/)
- 2018.05 [trustedsec] [Malware Analysis is for the (Cuckoo) Birds – Working with Proxmox](https://www.trustedsec.com/2018/05/working-with-proxmox/)
- 2018.05 [trustedsec] [Protected: Malware Analysis is for the (Cuckoo) Birds](https://www.trustedsec.com/2018/05/malware-cuckoo-1/)
- 2018.05 [trustedsec] [Protected: Malware Analysis is for the (Cuckoo) Birds – Cuckoo Installation Notes for Debian](https://www.trustedsec.com/2018/05/malware-cuckoo-2/)
- 2018.04 [ly0n] [Automating malware analysis, cuckoo api + postfix](https://paumunoz.tech/2018/04/25/automating-malware-analysis-cuckoo-api-postfix/)
- 2018.04 [ly0n] [Automating malware analysis, cuckoo api + postfix](http://ly0n.me/2018/04/25/automating-malware-analysis-cuckoo-api-postfix/)
- 2018.04 [nviso] [Painless Cuckoo Sandbox Installation](https://blog.nviso.be/2018/04/12/painless-cuckoo-sandbox-installation/)
- 2018.03 [rapid7] [Next Threat Intel Book Club 4/5: Recapping The Cuckoo’s Egg](https://blog.rapid7.com/2018/03/18/next-threat-intel-book-club-4-5-recapping-the-cuckoos-egg/)
- 2018.03 [ensurtec] [Cuckoo Sandbox Setup Tutorial](https://ensurtec.com/cuckoo-sandbox-setup-tutorial/)
- 2018.01 [fortinet] [Prevalent Threats Targeting Cuckoo Sandbox Detection and Our Mitigation](https://blog.fortinet.com/2018/01/03/prevalent-threats-targeting-cuckoo-sandbox-detection-and-our-mitigation)
- 2018.01 [fortinet] [Prevalent Threats Targeting Cuckoo Sandbox Detection and Our Mitigation](https://www.fortinet.com/blog/threat-research/prevalent-threats-targeting-cuckoo-sandbox-detection-and-our-mitigation.html)
- 2017.09 [360] [在细节中捕捉恶魔 ：提升Cuckoo沙箱捕获恶意Office样本行为的能力](https://www.anquanke.com/post/id/86826/)
- 2017.08 [trustwave] [Cuckoo & Linux Subsystem: Some Love for Windows 10](https://www.trustwave.com/Resources/SpiderLabs-Blog/Cuckoo--Linux-Subsystem--Some-Love-for-Windows-10/)
- 2017.08 [n0where] [Automated Android Malware Analysis: CuckooDroid](https://n0where.net/automated-android-malware-analysis-cuckoodroid)
- 2017.05 [robertputt] [Basic Malware Analysis with Cuckoo Sandbox](http://robertputt.co.uk/basic-malware-analysis-with-cuckoo-sandbox.html)
- 2017.05 [rastamouse] [Playing with Cuckoo](https://rastamouse.me/2017/05/playing-with-cuckoo/)
- 2017.04 [mcafee] [OpenDXL Case Study: Sandbox Mania featuring Cuckoo and Wildfire](https://securingtomorrow.mcafee.com/business/optimize-operations/opendxl-case-study-sandbox-mania-featuring-cuckoo-wildfire/)
- 2016.11 [tribalchicken] [Guide: Cuckoo Sandbox on FreeBSD](https://tribalchicken.io/guide-cuckoo-sandbox-on-freebsd/)
- 2016.11 [tribalchicken] [Guide: Cuckoo Sandbox on FreeBSD](https://tribalchicken.net/guide-cuckoo-sandbox-on-freebsd/)
- 2016.09 [cuckoo] [Analysis of nested archives with Cuckoo Sandbox: SFlock 0.1 release](https://cuckoo.sh/blog/sflock01.html)
- 2016.08 [alienvault] [One Flew Over the Cuckoo’s Test: Performing a Penetration Test with Methodology](https://www.alienvault.com/blogs/security-essentials/one-flew-over-the-cuckoos-test-performing-a-penetration-test-with-methodology)
- 2016.07 [freebuf] [自动化恶意软件分析系统Cuckoo安装、配置详解](http://www.freebuf.com/sectool/108533.html)
- 2016.02 [eugenekolo] [Installing and setting up Cuckoo Sandbox](https://eugenekolo.com/blog/installing-and-setting-up-cuckoo-sandbox/)
- 2016.01 [n0where] [Malware Analysis System: Cuckoo Sandbox](https://n0where.net/malware-analysis-system-cuckoo-sandbox)
- 2015.12 [eugenekolo] [Cuckoo Sandbox Notes](https://eugenekolo.com/blog/cuckoo-sandbox-notes/)
- 2015.11 [tribalchicken] [Automated Malware Analysis: mail server -> Cuckoo, V2.0](https://tribalchicken.io/automated-mail-server-cuckoo-analysis-v2-0/)
- 2015.11 [tribalchicken] [Automated Malware Analysis: mail server -> Cuckoo, V2.0](https://tribalchicken.net/automated-mail-server-cuckoo-analysis-v2-0/)
- 2015.11 [serializethoughts] [How Cuckoo Filter Can Improve Existing Approximate Matching Techniques](https://serializethoughts.com/2015/11/01/how-cuckoo-filter-can-improve-existing-approximate-matching-techniques/)
- 2015.10 [trendmicro] [Nigerian Cuckoo Miner Campaign Takes Over Legitimate Inboxes, Targets Banks](https://blog.trendmicro.com/trendlabs-security-intelligence/nigerian-cuckoo-miner-campaign-takes-over-legitimate-inboxes-targets-banks/)
- 2015.09 [acolyer] [Cuckoo Search via Lévy Flights](https://blog.acolyer.org/2015/09/25/cuckoo-search-via-levy-flights/)
- 2015.08 [malwarebytes] [Automatic Analysis Using Malheur And Cuckoo](https://blog.malwarebytes.com/threat-analysis/2015/08/automatic-analysis-using-malheur-and-cuckoo/)
- 2015.05 [alienvault] [There’s a Cuckoo in my Nest. Time to talk about security for the Internet of Things](https://www.alienvault.com/blogs/security-essentials/theres-a-cuckoo-in-my-nest-time-to-talk-about-security-for-the-internet-of-things)
- 2015.03 [checkpoint] [CuckooDroid – Fighting the Tide of Android Malware | Check Point Software Blog](https://blog.checkpoint.com/2015/03/24/cuckoodroid-fighting-tide-android-malware/)
- 2015.03 [arduino] [Encrypting messages with Cuckoo and Arduino Yún](https://blog.arduino.cc/2015/03/07/encrypting-messages-with-cuckoo-and-arduino-yun/)
- 2014.11 [eventbrite] [Brite Space Dublin: A Q&A With Mark Breen, Co-Founder, Cuckoo Events](https://www.eventbrite.co.uk/blog/brite-space-dublin-mark-breen-cuckoo-events-ds00/)
- 2014.10 [tribalchicken] [Automated malware analysis: Mail server -> Cuckoo](https://tribalchicken.io/automated-malware-analysis-mail-server-cuckoo/)
- 2014.10 [tribalchicken] [Automated malware analysis: Mail server -> Cuckoo](https://tribalchicken.net/automated-malware-analysis-mail-server-cuckoo/)
- 2014.05 [notanumber] [Cuckoo Byte Stuffing Algorithm](http://notanumber.net/archives/183/cuckoo-byte-stuffing-algorithm)
- 2014.05 [immunityproducts] [Connecting El Jefe 2.0 with the Cuckoo malware sandbox](https://immunityproducts.blogspot.com/2014/05/connecting-el-jefe-20-with-cuckoo.html)
- 2014.05 [toolswatch] [Cuckoo Sandbox v1.1 Released](http://www.toolswatch.org/2014/05/cuckoo-sandbox-v1-1-released/)
- 2014.04 [malwarebytes] [Automating Malware Analysis with Cuckoo Sandbox](https://blog.malwarebytes.com/threat-analysis/2014/04/automating-malware-analysis-with-cuckoo-sandbox/)
- 2013.09 [itgeekchronicles] [Python: Kippo 2 Cuckoo](https://itgeekchronicles.co.uk/2013/09/16/python-kippo-2-cuckoo/)
- 2013.06 [rapid7] [Cuckoo Sandbox approaching 1.0](https://blog.rapid7.com/2013/06/21/cuckoo-sandbox-approaching-10/)
- 2013.04 [toolswatch] [Cuckoo Sandbox v0.6 available](http://www.toolswatch.org/2013/04/cuckoo-sandbox-v0-6-available/)
- 2013.04 [rapid7] [Fooling malware like a boss with Cuckoo Sandbox](https://blog.rapid7.com/2013/04/16/fooling-malware-like-a-boss-with-cuckoo-sandbox/)
- 2013.01 [sans] [Cuckoo 0.5 is out and the world didn't end](https://isc.sans.edu/forums/diary/Cuckoo+05+is+out+and+the+world+didnt+end/14845/)
- 2012.12 [volatility] [What do Upclicker, Poison Ivy, Cuckoo, and Volatility Have in Common?](https://volatility-labs.blogspot.com/2012/12/what-do-upclicker-poison-ivy-cuckoo-and.html)
- 2012.12 [alienvault] [Hardening Cuckoo Sandbox against VM aware malware](https://www.alienvault.com/blogs/labs-research/hardening-cuckoo-sandbox-against-vm-aware-malware)
- 2012.11 [securityartwork] [Customizing “Cuckoo Sandbox”](https://www.securityartwork.es/2012/11/23/customizing-cuckoo-sandbox/)
- 2012.10 [toolswatch] [Cuckoo Sandbox v0.4.2 available (Support for VMware added)](http://www.toolswatch.org/2012/10/cuckoo-sandbox-v0-4-2-available-support-for-vmware-added/)
- 2012.08 [toolswatch] [Cuckoo Sandbox v0.4.1 The Malware Analysis Released](http://www.toolswatch.org/2012/08/cuckoo-sandbox-v0-4-1-the-malware-analysis-released/)
- 2012.07 [rapid7] [Cuckoo Sandbox 0.4 Simplifies Malware Analysis with KVM support, Signatures and Extended Modularity](https://blog.rapid7.com/2012/07/24/cuckoo-sandbox-04-is-here/)
- 2012.07 [hiddenillusion] [Customizing cuckoo to fit your needs](http://hiddenillusion.blogspot.com/2012/07/customizing-cukoo-to-fit-your-needs.html)
- 2012.05 [corelan] [HITB2012AMS Day 1 – One Flew Over The Cuckoos Nest](https://www.corelan.be/index.php/2012/05/24/hitb2012ams-day-1-one-flew-over-the-cuckoos-nest/)
- 2012.05 [toolswatch] [Cuckoo Sandbox v0.3.2 Released](http://www.toolswatch.org/2012/05/cuckoo-sandbox-v0-3-2-released/)
- 2012.01 [trustwave] [Cuckoo for Cuckoo Box](https://www.trustwave.com/Resources/SpiderLabs-Blog/Cuckoo-for-Cuckoo-Box/)
- 2011.02 [chuvakin] [The Honeynet Project Releases New Tool: Cuckoo](http://chuvakin.blogspot.com/2011/02/honeynet-project-releases-new-tool_24.html)
- 2007.09 [infosecblog] [Cuckoo’s Egg](https://www.infosecblog.org/2007/09/cuckoos-egg/)
- 2007.01 [infosecblog] [ISC: Cuckoo’s egg on the face](https://www.infosecblog.org/2007/01/isc-cuckoos-egg-on-the-face/)
- 2007.01 [sans] [Cuckoo's egg on the face](https://isc.sans.edu/forums/diary/Cuckoos+egg+on+the+face/1996/)


# <a id="7ab3a7005d6aa699562b3a0a0c6f2cff"></a>DBI


***


## <a id="c8cdb0e30f24e9b7394fcd5681f2e419"></a>DynamoRIO


### <a id="6c4841dd91cb173093ea2c8d0b557e71"></a>Tools


#### <a id="3a577a5b4730a1b5b3b325269509bb0a"></a>DynamoRIO


- [**1388**Star][12d] [C] [dynamorio/drmemory](https://github.com/dynamorio/drmemory) Memory Debugger for Windows, Linux, Mac, and Android
- [**1228**Star][12d] [C] [dynamorio/dynamorio](https://github.com/dynamorio/dynamorio) Dynamic Instrumentation Tool Platform


#### <a id="ff0abe26a37095f6575195950e0b7f94"></a>Recent Add


- [**1364**Star][3m] [C] [googleprojectzero/winafl](https://github.com/googleprojectzero/winafl) A fork of AFL for fuzzing Windows binaries
- [**249**Star][5m] [C] [ampotos/dynstruct](https://github.com/ampotos/dynstruct) Reverse engineering tool for automatic structure recovering and memory use analysis based on DynamoRIO and Capstone
- [**119**Star][5y] [C++] [breakingmalware/selfie](https://github.com/breakingmalware/selfie) A Tool to Unpack Self-Modifying Code using DynamoRIO
- [**119**Star][4m] [C++] [googleprojectzero/drsancov](https://github.com/googleprojectzero/drsancov) DynamoRIO plugin to get ASAN and SanitizerCoverage compatible output for closed-source executables
- [**53**Star][4y] [C] [lgeek/dynamorio_pin_escape](https://github.com/lgeek/dynamorio_pin_escape) 
- [**17**Star][26d] [C] [firodj/bbtrace](https://github.com/firodj/bbtrace) Basic Block Trace: DynamoRIO client
- [**14**Star][6m] [C++] [vanhauser-thc/afl-dynamorio](https://github.com/vanhauser-thc/afl-dynamorio) run AFL with dynamorio
- [**10**Star][2y] [C++] [atrosinenko/afl-dr](https://github.com/atrosinenko/afl-dr) Experiment in implementation of an instrumentation for American Fuzzy Lop using DynamoRIO


#### <a id="928642a55eff34b6b52622c6862addd2"></a>With Other Tools


- [**52**Star][12m] [Py] [cisco-talos/dyndataresolver](https://github.com/cisco-talos/dyndataresolver) Dynamic Data Resolver (DDR) IDA Pro Plug-in
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |
    - [DDR](https://github.com/cisco-talos/dyndataresolver/blob/master/VS_project/ddr/ddr.sln) 基于DyRIO的Client
    - [IDA插件](https://github.com/cisco-talos/dyndataresolver/tree/master/IDAplugin) 
- [**20**Star][9m] [C++] [secrary/findloop](https://github.com/secrary/findloop) find possible encryption/decryption or compression/decompression code
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |
- [**6**Star][2y] [C++] [ncatlin/drgat](https://github.com/ncatlin/drgat) The DynamoRIO client for rgat




### <a id="9479ce9f475e4b9faa4497924a2e40fc"></a>Posts&&Videos


- 2019.10 [freebuf] [DrSemu：基于动态行为的恶意软件检测与分类工具](https://www.freebuf.com/sectool/214277.html)
- 2019.06 [freebuf] [Functrace：使用DynamoRIO追踪函数调用](https://www.freebuf.com/sectool/205989.html)
- 2019.01 [360] [深入浅出——基于DynamoRIO的strace和ltrace](https://www.anquanke.com/post/id/169257/)
- 2018.08 [n0where] [Dynamic API Call Tracer for Windows and Linux Applications: Drltrace](https://n0where.net/dynamic-api-call-tracer-for-windows-and-linux-applications-drltrace)
- 2018.07 [topsec] [动态二进制修改(Dynamic Binary Instrumentation)入门：Pin、DynamoRIO、Frida](http://blog.topsec.com.cn/%e5%8a%a8%e6%80%81%e4%ba%8c%e8%bf%9b%e5%88%b6%e4%bf%ae%e6%94%b9dynamic-binary-instrumentation%e5%85%a5%e9%97%a8%ef%bc%9apin%e3%80%81dynamorio%e3%80%81frida/)
- 2017.11 [SECConsult] [The Art of Fuzzing - Demo 10: In-memory Fuzzing HashCalc using DynamoRio](https://www.youtube.com/watch?v=FEJGlgBeUJ8)
- 2017.11 [SECConsult] [The Art of Fuzzing - Demo 6: Extract Coverage Information using DynamoRio](https://www.youtube.com/watch?v=Ur_E9c2vX1A)
- 2017.04 [pediy] [[原创]通过Selife学习使用DynamoRIO动态插桩](https://bbs.pediy.com/thread-216970.htm)
- 2016.11 [360] [“Selfie”：利用DynamoRIO实现自修改代码自动脱壳的神器](https://www.anquanke.com/post/id/84999/)
- 2016.09 [securitygossip] [Practical Memory Checking With Dr. Memory](http://securitygossip.com/blog/2016/09/12/2016-09-12/)
- 2016.09 [sjtu] [Practical Memory Checking With Dr. Memory](https://loccs.sjtu.edu.cn/gossip/blog/2016/09/12/2016-09-12/)
- 2016.08 [n0where] [Dynamic Instrumentation Tool Platform: DynamoRIO](https://n0where.net/dynamic-instrumentation-tool-platform-dynamorio)
- 2014.01 [dustri] [Memory debugging under Windows with drmemory](https://dustri.org/b/memory-debugging-under-windows-with-drmemory.html)
- 2012.10 [redplait] [building dynamorio](http://redplait.blogspot.com/2012/10/building-dynamorio.html)
- 2011.06 [redplait] [dynamorio](http://redplait.blogspot.com/2011/06/dynamorio.html)




***


## <a id="7b8a493ca344f41887792fcc008573e7"></a>IntelPin


### <a id="fe5a6d7f16890542c9e60857706edfde"></a>Tools


#### <a id="78a2edf9aa41eb321436cb150ea70a54"></a>Recent Add


- [**424**Star][5y] [C++] [jonathansalwan/pintools](https://github.com/jonathansalwan/pintools) Pintool example and PoC for dynamic binary analysis
- [**299**Star][2m] [C] [vusec/vuzzer](https://github.com/vusec/vuzzer) depends heavily on a modeified version of DataTracker, which in turn depends on LibDFT pintool.
- [**148**Star][5y] [C++] [f-secure/sulo](https://github.com/f-secure/sulo) Dynamic instrumentation tool for Adobe Flash Player built on Intel Pin
- [**123**Star][6m] [C++] [hasherezade/tiny_tracer](https://github.com/hasherezade/tiny_tracer) A Pin Tool for tracing API calls etc
- [**65**Star][3y] [C++] [m000/dtracker](https://github.com/m000/dtracker) DataTracker: A Pin tool for collecting high-fidelity data provenance from unmodified programs.
- [**60**Star][2y] [C++] [hasherezade/mypintools](https://github.com/hasherezade/mypintools) Tools to run with Intel PIN
- [**48**Star][9m] [C++] [angorafuzzer/libdft64](https://github.com/angorafuzzer/libdft64) libdft for Intel Pin 3.x and 64 bit platform. (Dynamic taint tracking, taint analysis)
- [**48**Star][7y] [C++] [cr4sh/code-coverage-analysis-tools](https://github.com/cr4sh/code-coverage-analysis-tools) Code coverage analysis tools for the PIN Toolkit
- [**39**Star][4y] [C++] [corelan/pin](https://github.com/corelan/pin) Collection of pin tools
- [**36**Star][3y] [C++] [paulmehta/ablation](https://github.com/paulmehta/ablation) Augmenting Static Analysis Using Pintool: Ablation
- [**30**Star][4y] [C++] [0xddaa/pin](https://github.com/0xddaa/pin) Use Intel Pin tools to analysis binary.
- [**27**Star][1y] [C++] [fdiskyou/winalloctracer](https://github.com/fdiskyou/WinAllocTracer) Pintool that logs and tracks calls to RtlAllocateHeap, RtlReAllocateHeap, RtlFreeHeap, VirtualAllocEx, and VirtualFreeEx.
- [**26**Star][7y] [C++] [jingpu/pintools](https://github.com/jingpu/pintools) 
- [**25**Star][2m] [C++] [boegel/mica](https://github.com/boegel/mica) a Pin tool for collecting microarchitecture-independent workload characteristics
- [**22**Star][6y] [C++] [jbremer/pyn](https://github.com/jbremer/pyn) Awesome Python bindings for Pintool
- [**18**Star][1y] [bash-c/pin-in-ctf](https://github.com/bash-c/pin-in-ctf) 使用intel pin来求解一部分CTF challenge
- [**12**Star][3y] [C++] [netspi/pin](https://github.com/netspi/pin) Intel pin tools
- [**6**Star][2y] [C++] [spinpx/afl_pin_mode](https://github.com/spinpx/afl_pin_mode) Yet another AFL instrumentation tool implemented by Intel Pin.


#### <a id="e6a829abd8bbc5ad2e5885396e3eec04"></a>With Other Tools


##### <a id="e129288dfadc2ab0890667109f93a76d"></a>No Category


- [**943**Star][1y] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) Code Coverage Explorer for IDA Pro & Binary Ninja
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |[DBI->Frida->Tools->With Other Tools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |[DBI->Frida->Tools->With Other Tools->Binary Ninja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**134**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [IDA->Tools->Import Export->IntelPin](#dd0332da5a1482df414658250e6357f8) |[IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |[IDA->Tools->Vul->No Category](#385d6777d0747e79cccab0a19fa90e7e) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**122**Star][5y] [C++] [zachriggle/ida-splode](https://github.com/zachriggle/ida-splode) Augmenting Static Reverse Engineering with Dynamic Analysis and Instrumentation
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |
    - [IDA插件](https://github.com/zachriggle/ida-splode/tree/master/py) 
    - [PinTool](https://github.com/zachriggle/ida-splode/tree/master/src) 
- [**117**Star][2y] [C++] [0xphoenix/mazewalker](https://github.com/0xphoenix/mazewalker) Toolkit for enriching and speeding up static malware analysis
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |
    - [mazeui](https://github.com/0xphoenix/mazewalker/blob/master/MazeUI/mazeui.py) 在IDA中显示界面
    - [PyScripts](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/PyScripts) Python脚本，处理收集到的数据
    - [PinClient](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/src) 
- [**102**Star][4m] [Java] [0ffffffffh/dragondance](https://github.com/0ffffffffh/dragondance) Binary code coverage visualizer plugin for Ghidra
    - Also In Section: [Ghidra->Plugins->With Other Tools->DBI](#60e86981b2c98f727587e7de927e0519) |
    - [Ghidra插件](https://github.com/0ffffffffh/dragondance/blob/master/README.md) 
    - [coverage-pin](https://github.com/0ffffffffh/dragondance/blob/master/coveragetools/README.md) 使用Pin收集信息
- [**89**Star][8y] [C] [neuroo/runtime-tracer](https://github.com/neuroo/runtime-tracer) Dynamic tracing for binary applications (using PIN), IDA plugin to visualize and interact with the traces
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |
    - [PinTool](https://github.com/neuroo/runtime-tracer/tree/master/tracer) 
    - [IDA插件](https://github.com/neuroo/runtime-tracer/tree/master/ida-pin) 
- [**44**Star][3y] [Batchfile] [maldiohead/idapin](https://github.com/maldiohead/idapin) plugin of ida with pin
    - Also In Section: [IDA->Tools->Import Export->IntelPin](#dd0332da5a1482df414658250e6357f8) |
- [**15**Star][1y] [C++] [agustingianni/instrumentation](https://github.com/agustingianni/instrumentation) Collection of tools implemented using pintools aimed to help in the task of reverse engineering.
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |
    - [CodeCoverage](https://github.com/agustingianni/instrumentation/tree/master/CodeCoverage) 
    - [Pinnacle](https://github.com/agustingianni/instrumentation/tree/master/Pinnacle) 
    - [Recoverer](https://github.com/agustingianni/instrumentation/tree/master/Recoverer) 
    - [Resolver](https://github.com/agustingianni/instrumentation/tree/master/Resolver) 






### <a id="226190bea6ceb98ee5e2b939a6515fac"></a>Posts&&Videos






***


## <a id="f24f1235fd45a1aa8d280eff1f03af7e"></a>Frida


### <a id="a5336a0f9e8e55111bda45c8d74924c1"></a>Tools


#### <a id="6d3c24e43835420063f9ca50ba805f15"></a>Frida


- [**4516**Star][13d] [Makefile] [frida/frida](https://github.com/frida/frida) Clone this repo to build Frida


#### <a id="54836a155de0c15b56f43634cd9cfecf"></a>Recent Add


- [**1193**Star][15d] [JS] [alonemonkey/frida-ios-dump](https://github.com/alonemonkey/frida-ios-dump) pull decrypted ipa from jailbreak device
    - Also In Section: [Apple->JailBreak->Tools](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**895**Star][5m] [JS] [dpnishant/appmon](https://github.com/dpnishant/appmon) an automated framework for monitoring and tampering system API calls of native macOS, iOS and android apps. It is based on Frida.
- [**645**Star][16d] [Py] [igio90/dwarf](https://github.com/igio90/dwarf) Full featured multi arch/os debugger built on top of PyQt5 and frida
- [**559**Star][1m] [JS] [nccgroup/house](https://github.com/nccgroup/house) A runtime mobile application analysis toolkit with a Web GUI, powered by Frida, written in Python.
- [**513**Star][1m] [JS] [iddoeldor/frida-snippets](https://github.com/iddoeldor/frida-snippets) Hand-crafted Frida examples
- [**422**Star][1y] [Py] [dstmath/frida-unpack](https://github.com/dstmath/frida-unpack) unpack script based on frida
- [**420**Star][13d] [C] [frida/frida-python](https://github.com/frida/frida-python) Frida Python bindings
- [**407**Star][2y] [JS] [0xdea/frida-scripts](https://github.com/0xdea/frida-scripts) A collection of my Frida.re instrumentation scripts to facilitate reverse engineering of mobile apps.
- [**405**Star][1y] [C++] [vah13/extracttvpasswords](https://github.com/vah13/extracttvpasswords) tool to extract passwords from TeamViewer memory using Frida
- [**332**Star][15d] [JS] [chichou/bagbak](https://github.com/ChiChou/bagbak) Yet another frida based iOS dumpdecrypted, works on iOS 13 with checkra1n and supports decrypting app extensions
- [**321**Star][1m] [C] [frida/frida-core](https://github.com/frida/frida-core) Frida core library intended for static linking into bindings
- [**317**Star][5y] [C++] [frida/cryptoshark](https://github.com/frida/cryptoshark) Self-optimizing cross-platform code tracer based on dynamic recompilation
- [**308**Star][4m] [JS] [smartdone/frida-scripts](https://github.com/smartdone/frida-scripts) frida scripts
- [**283**Star][8m] [Py] [nightbringer21/fridump](https://github.com/nightbringer21/fridump) A universal memory dumper using Frida
- [**266**Star][2y] [Py] [antojoseph/frida-android-hooks](https://github.com/antojoseph/frida-android-hooks) Lets you hook Method Calls in Frida ( Android )
- [**250**Star][1y] [Py] [igio90/frick](https://github.com/igio90/frick) aka the first debugger built on top of frida
- [**243**Star][19d] [JS] [frenchyeti/dexcalibur](https://github.com/frenchyeti/dexcalibur) Dynamic binary instrumentation tool designed for Android application and powered by Frida. It disassembles dex, analyzes it statically, generates hooks, discovers reflected methods, stores intercepted data and does new things from it. Its aim is to be an all-in-one Android reverse engineering platform.
- [**228**Star][13d] [C] [frida/frida-gum](https://github.com/frida/frida-gum) Low-level code instrumentation library used by frida-core
- [**197**Star][28d] [JS] [xiaokanghub/frida-android-unpack](https://github.com/xiaokanghub/frida-android-unpack) this unpack script for Android O and Android P
- [**195**Star][5m] [C] [nowsecure/frida-cycript](https://github.com/nowsecure/frida-cycript) Cycript fork powered by Frida.
- [**173**Star][11d] [JS] [andreafioraldi/frida-fuzzer](https://github.com/andreafioraldi/frida-fuzzer) This experimetal fuzzer is meant to be used for API in-memory fuzzing.
- [**159**Star][3m] [JS] [interference-security/frida-scripts](https://github.com/interference-security/frida-scripts) Frida Scripts
- [**141**Star][19d] [TS] [chame1eon/jnitrace](https://github.com/chame1eon/jnitrace) A Frida based tool that traces usage of the JNI API in Android apps.
- [**138**Star][3y] [JS] [as0ler/frida-scripts](https://github.com/as0ler/frida-scripts) Repository including some useful frida script for iOS Reversing
- [**128**Star][8m] [enovella/r2frida-wiki](https://github.com/enovella/r2frida-wiki) This repo aims at providing practical examples on how to use r2frida
- [**124**Star][3y] [JS] [antojoseph/diff-gui](https://github.com/antojoseph/diff-gui) GUI for Frida -Scripts
- [**123**Star][2y] [Java] [brompwnie/uitkyk](https://github.com/brompwnie/uitkyk) Android Frida库, 用于分析App查找恶意行为
    - Also In Section: [Android->Tools->Malware](#f975a85510f714ec3cc2551e868e75b8) |
- [**121**Star][29d] [JS] [fuzzysecurity/fermion](https://github.com/fuzzysecurity/fermion) Fermion, an electron wrapper for Frida & Monaco.
- [**112**Star][2y] [C] [b-mueller/frida-detection-demo](https://github.com/b-mueller/frida-detection-demo) Some examples for detecting frida on Android
- [**112**Star][25d] [C++] [frida/frida-node](https://github.com/frida/frida-node) Frida Node.js bindings
- [**109**Star][9m] [Py] [rootbsd/fridump3](https://github.com/rootbsd/fridump3) A universal memory dumper using Frida for Python 3
- [**104**Star][1y] [JS] [thecjw/frida-android-scripts](https://github.com/thecjw/frida-android-scripts) Some frida scripts
- [**98**Star][2y] [Java] [piasy/fridaandroidtracer](https://github.com/piasy/fridaandroidtracer) A runnable jar that generate Javascript hook script to hook Android classes.
- [**97**Star][15d] [JS] [frida/frida-java-bridge](https://github.com/frida/frida-java-bridge) Java runtime interop from Frida
- [**90**Star][1y] [C] [grimm-co/notquite0dayfriday](https://github.com/grimm-co/notquite0dayfriday) This is a repo which documents real bugs in real software to illustrate trends, learn how to prevent or find them more quickly.
- [**90**Star][2m] [Py] [demantz/frizzer](https://github.com/demantz/frizzer) Frida-based general purpose fuzzer
- [**88**Star][2y] [Py] [mind0xp/frida-python-binding](https://github.com/mind0xp/frida-python-binding) Easy to use Frida python binding script
- [**86**Star][3y] [JS] [oalabs/frida-wshook](https://github.com/oalabs/frida-wshook) Script analysis tool based on Frida.re
- [**85**Star][4m] [TS] [nowsecure/airspy](https://github.com/nowsecure/airspy) AirSpy - Frida-based tool for exploring and tracking the evolution of Apple's AirDrop protocol implementation on i/macOS, from the server's perspective. Released during BH USA 2019 Training
- [**83**Star][3y] [JS] [oalabs/frida-extract](https://github.com/oalabs/frida-extract) Frida.re based RunPE (and MapViewOfSection) extraction tool
- [**81**Star][5m] [JS] [frida/frida-presentations](https://github.com/frida/frida-presentations) Public presentations given on Frida at conferences
- [**79**Star][4m] [C] [oleavr/ios-inject-custom](https://github.com/oleavr/ios-inject-custom) Example showing how to use Frida for standalone injection of a custom payload
- [**76**Star][1m] [JS] [andreafioraldi/frida-js-afl-instr](https://github.com/andreafioraldi/frida-js-afl-instr) An example on how to do performant in-memory fuzzing with AFL++ and Frida
- [**75**Star][4y] [Py] [antojoseph/diff-droid](https://github.com/antojoseph/diff-droid) Various Scripts for Mobile Pen-testing with Frida
- [**65**Star][3m] [Py] [hamz-a/jeb2frida](https://github.com/hamz-a/jeb2frida) Automated Frida hook generation with JEB
- [**58**Star][20d] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA tools and scripts collection
    - Also In Section: [IDA->Tools->No Category](#c39a6d8598dde6abfeef43faf931beb5) |[IDA->Tools->Import Export->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor scripts
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida Scripts
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA Scripts
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) When there is chinese unicode character in programe, due to python's shortage, ida could not recongnized them correctly, it's what my script just do
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py)  When you deal with macho file with ida, you'll find out that it's not easy to find Objc-Class member function's caller and callee, (because it use msgSend instead of direct calling  convention), so we need to make some connection between the selector names and member function  pointers, it's what my script just do
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) When you debug android with IDA and gdbserver, you'd find that the module list and segment is empy, while we can read info from /proc/[pid]/,
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) this script is to trace instruction stream in one run 
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) this script is to detect ollvm and fix it in some extent, apply to android and ios
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) this script is used to analysis block structure exist in macho file, target NSConcreteStackBlock/NSConcreteGlobalBlock currently, also contain some wonderful skills
- [**57**Star][8m] [JS] [hamz-a/frida-android-libbinder](https://github.com/hamz-a/frida-android-libbinder) PoC Frida script to view Android libbinder traffic
- [**53**Star][1m] [Py] [hamz-a/frida-android-helper](https://github.com/hamz-a/frida-android-helper) Frida Android utilities
- [**52**Star][1m] [Py] [frida/frida-tools](https://github.com/frida/frida-tools) Frida CLI tools
- [**50**Star][1y] [JS] [fortiguard-lion/frida-scripts](https://github.com/fortiguard-lion/frida-scripts) 
- [**49**Star][6m] [TS] [igio90/hooah-trace](https://github.com/igio90/hooah-trace) Instructions tracing powered by frida
- [**46**Star][1y] [JS] [maltek/swift-frida](https://github.com/maltek/swift-frida) Frida library for interacting with Swift programs.
- [**46**Star][5m] [JS] [nowsecure/frida-trace](https://github.com/nowsecure/frida-trace) Trace APIs declaratively through Frida.
- [**43**Star][8m] [C] [sensepost/frida-windows-playground](https://github.com/sensepost/frida-windows-playground) A collection of Frida hooks for experimentation on Windows platforms.
- [**42**Star][2y] [HTML] [digitalinterruption/fridaworkshop](https://github.com/digitalinterruption/fridaworkshop) Break Apps with Frida workshop material
- [**42**Star][4m] [Swift] [frida/frida-swift](https://github.com/frida/frida-swift) Frida Swift bindings
- [**40**Star][2y] [Py] [agustingianni/memrepl](https://github.com/agustingianni/memrepl) a frida based script that aims to help a researcher in the task of exploitation of memory corruption related bugs
    - Also In Section: [IDA->Tools->Import Export->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |
- [**39**Star][29d] [JS] [frida/frida-compile](https://github.com/frida/frida-compile) Compile a Frida script comprised of one or more Node.js modules
- [**39**Star][4m] [TS] [oleavr/frida-agent-example](https://github.com/oleavr/frida-agent-example) Example Frida agent written in TypeScript
- [**37**Star][9d] [CSS] [frida/frida-website](https://github.com/frida/frida-website) Frida's website
- [**34**Star][2m] [Py] [dmaasland/mcfridafee](https://github.com/dmaasland/mcfridafee) 
- [**29**Star][6m] [TS] [igio90/frida-onload](https://github.com/igio90/frida-onload) Frida module to hook module initializations on android
- [**28**Star][1y] [JS] [ioactive/bluecrawl](https://github.com/ioactive/bluecrawl) Frida (Android) Script for extracting bluetooth information
- [**28**Star][2y] [JS] [versprite/engage](https://github.com/versprite/engage) Tools and Materials for the Frida Engage Blog Series
- [**28**Star][5m] [Java] [dineshshetty/fridaloader](https://github.com/dineshshetty/fridaloader) A quick and dirty app to download and launch Frida on Genymotion
- [**28**Star][8m] [C++] [frida/v8](https://github.com/frida/v8) Frida depends on V8
- [**26**Star][2y] [Py] [androidtamer/frida-push](https://github.com/androidtamer/frida-push) Wrapper tool to identify the remote device and push device specific frida-server binary.
- [**26**Star][4m] [C++] [frida/frida-clr](https://github.com/frida/frida-clr) Frida .NET bindings
- [**26**Star][3m] [JS] [nowsecure/frida-uikit](https://github.com/nowsecure/frida-uikit) Inspect and manipulate UIKit-based GUIs through Frida.
- [**25**Star][10m] [TS] [woza-lab/woza](https://github.com/woza-lab/woza) [Deprecated]Dump application ipa from jailbroken iOS based on frida. (Node edition)
- [**20**Star][3y] [JS] [dweinstein/node-frida-contrib](https://github.com/dweinstein/node-frida-contrib) frida utility-belt
- [**20**Star][5m] [JS] [nowsecure/frida-uiwebview](https://github.com/nowsecure/frida-uiwebview) Inspect and manipulate UIWebView-hosted GUIs through Frida.
- [**19**Star][7m] [JS] [iddoeldor/mplus](https://github.com/iddoeldor/mplus) Intercept android apps based on unity3d (Mono) using Frida
- [**19**Star][2m] [Shell] [virb3/magisk-frida](https://github.com/virb3/magisk-frida) 
- [**19**Star][26d] [JS] [cynops/frida-hooks](https://github.com/cynops/frida-hooks) 
- [**18**Star][5y] [JS] [frida/aurora](https://github.com/frida/aurora) Proof-of-concept web app built on top of Frida
- [**18**Star][2y] [Py] [igio90/fridaandroidtracer](https://github.com/igio90/fridaandroidtracer) Android application tracer powered by Frida
- [**18**Star][2y] [Py] [notsosecure/dynamic-instrumentation-with-frida](https://github.com/notsosecure/dynamic-instrumentation-with-frida) Dynamic Instrumentation with Frida
- [**18**Star][5m] [JS] [nowsecure/frida-screenshot](https://github.com/nowsecure/frida-screenshot) Grab screenshots using Frida.
- [**16**Star][5m] [JS] [nowsecure/frida-fs](https://github.com/nowsecure/frida-fs) Create a stream from a filesystem resource.
- [**16**Star][5m] [JS] [freehuntx/frida-mono-api](https://github.com/freehuntx/frida-mono-api) All the mono c exports, ready to be used in frida!
- [**11**Star][5m] [JS] [nowsecure/mjolner](https://github.com/nowsecure/mjolner) Cycript backend powered by Frida.
- [**11**Star][3m] [JS] [freehuntx/frida-inject](https://github.com/freehuntx/frida-inject) This module allows you to easily inject javascript using frida and frida-load.
- [**10**Star][1y] [JS] [andreafioraldi/taint-with-frida](https://github.com/andreafioraldi/taint-with-frida) just an experiment
- [**10**Star][5y] [JS] [frida/cloudspy](https://github.com/frida/cloudspy) Proof-of-concept web app built on top of Frida
- [**9**Star][11m] [JS] [lmangani/node_ssl_logger](https://github.com/lmangani/node_ssl_logger) Decrypt and log process SSL traffic via Frida Injection
- [**9**Star][2y] [JS] [random-robbie/frida-docker](https://github.com/random-robbie/frida-docker) Dockerised Version of Frida
- [**9**Star][4m] [Py] [melisska/neomorph](https://github.com/melisska/neomorph) Frida Python Tool
- [**9**Star][10m] [JS] [rubaljain/frida-jb-bypass](https://github.com/rubaljain/frida-jb-bypass) Frida script to bypass the iOS application Jailbreak Detection
- [**6**Star][4m] [JS] [nowsecure/frida-panic](https://github.com/nowsecure/frida-panic) Easy crash-reporting for Frida-based applications.
- [**6**Star][10m] [JS] [eybisi/fridascripts](https://github.com/eybisi/fridascripts) 
- [**5**Star][2m] [TS] [nowsecure/frida-remote-stream](https://github.com/nowsecure/frida-remote-stream) Create an outbound stream over a message transport.
- [**4**Star][5m] [JS] [davuxcom/frida-scripts](https://github.com/davuxcom/frida-scripts) Inject JS and C# into Windows apps, call COM and WinRT APIs
- [**4**Star][2y] [JS] [frida/frida-load](https://github.com/frida/frida-load) Load a Frida script comprised of one or more Node.js modules
- [**4**Star][1m] [JS] [sipcapture/hepjack.js](https://github.com/sipcapture/hepjack.js) Elegantly Sniff Forward-Secrecy TLS/SIP to HEP at the source using Frida
- [**3**Star][5m] [JS] [nowsecure/frida-memory-stream](https://github.com/nowsecure/frida-memory-stream) Create a stream from one or more memory regions.
- [**3**Star][8d] [Py] [margular/frida-skeleton](https://github.com/margular/frida-skeleton) This repository is supposed to define infrastructure of frida on hook android including some useful functions
- [**3**Star][2y] [JS] [myzhan/frida-examples](https://github.com/myzhan/frida-examples) Examples of using frida.
- [**2**Star][1y] [rhofixxxx/kick-off-owasp_webapp_security_vulnerabilities](https://github.com/rhofixxxx/kick-off-OWASP_WebApp_Security_Vulnerabilities) Want to keep your Web application from getting hacked? Here's how to get serious about secure apps. So let's do it! Open Friday, Aug 2016 - Presentation Notes.
- [**1**Star][1y] [JS] [ddurando/frida-scripts](https://github.com/ddurando/frida-scripts) 


#### <a id="74fa0c52c6104fd5656c93c08fd1ba86"></a>With Other Tools


##### <a id="00a86c65a84e58397ee54e85ed57feaf"></a>No Category


- [**584**Star][1y] [Java] [federicodotta/brida](https://github.com/federicodotta/brida) The new bridge between Burp Suite and Frida!


##### <a id="d628ec92c9eea0c4b016831e1f6852b3"></a>IDA


- [**943**Star][1y] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) Code Coverage Explorer for IDA Pro & Binary Ninja
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->Tools->With Other Tools->Binary Ninja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**128**Star][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) a reverse engineering framework created to simplify dynamic instrumentation with Frida
    - Also In Section: [IDA->Tools->Import Export->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |[IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**83**Star][5y] [Py] [techbliss/frida_for_ida_pro](https://github.com/techbliss/frida_for_ida_pro) plugin for ida pro thar uses the Frida api
    - Also In Section: [IDA->Tools->Import Export->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |


##### <a id="f9008a00e2bbc7535c88602aa79c8fd8"></a>Binary Ninja


- [**943**Star][1y] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) Code Coverage Explorer for IDA Pro & Binary Ninja
    - Also In Section: [IDA->Tools->Debug->DBI Data](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->Tools->With Other Tools->No Category](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->Tools->With Other Tools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**8**Star][3m] [Py] [c3r34lk1ll3r/binrida](https://github.com/c3r34lk1ll3r/BinRida) Plugin for Frida in Binary Ninja
    - Also In Section: [BinaryNinja->Plugins->With Other Tools->No Category](#c2f94ad158b96c928ee51461823aa953) |


##### <a id="ac053c4da818ca587d57711d2ff66278"></a>Radare2


- [**378**Star][27d] [JS] [nowsecure/r2frida](https://github.com/nowsecure/r2frida) Radare2 and Frida better together.
    - Also In Section: [Radare2->Plugins->With Other Tools->No Category](#dfe53924d678f9225fc5ece9413b890f) |
- [**34**Star][12m] [CSS] [nowsecure/r2frida-book](https://github.com/nowsecure/r2frida-book) The radare2 + frida book for Mobile Application assessment
    - Also In Section: [Radare2->Plugins->With Other Tools->No Category](#dfe53924d678f9225fc5ece9413b890f) |






### <a id="a1a7e3dd7091b47384c75dba8f279caf"></a>Posts&&Videos


- 2019.12 [xakcop] [Cloning RSA tokens with Frida](https://xakcop.com/post/cloning-rsa/)
- 2019.09 [freebuf] [Dwarf：一款基于Pyqt5和Frida的逆向分析调试工具](https://www.freebuf.com/sectool/212123.html)
- 2019.06 [two06] [Fun With Frida](https://medium.com/p/5d0f55dd331a)
- 2019.05 [nsfocus] [基于Frida进行通信数据“解密”](http://blog.nsfocus.net/communication-data-decryption-based-on-frida/)
- 2019.05 [nsfocus] [Frida应用基础及 APP https证书验证破解](http://blog.nsfocus.net/frida%e5%ba%94%e7%94%a8%e5%9f%ba%e7%a1%80%e5%8f%8a-app-https%e8%af%81%e4%b9%a6%e9%aa%8c%e8%af%81%e7%a0%b4%e8%a7%a3/)
- 2019.05 [nsfocus] [Frida应用基础及 APP https证书验证破解](http://blog.nsfocus.net/frida-application-foundation-app-https-certificate-verification-cracking-2/)
- 2019.05 [nsfocus] [Frida应用基础及APP https证书验证破解](http://blog.nsfocus.net/frida-application-foundation-app-https-certificate-verification-cracking/)
- 2019.05 [CodeColorist] [Trace child process with frida on macOS](https://medium.com/p/3b8f0f953f3d)
- 2019.05 [360] [FRIDA脚本系列（四）更新篇：几个主要机制的大更新](https://www.anquanke.com/post/id/177597/)
- 2019.03 [360] [FRIDA脚本系列（三）超神篇：百度AI“调教”抖音AI](https://www.anquanke.com/post/id/175621/)
- 2019.03 [securityinnovation] [Setting up Frida Without Jailbreak on the Latest iOS 12.1.4 Device](https://blog.securityinnovation.com/frida)
- 2019.02 [nowsecure] [Frida 12.3 Debuts New Crash Reporting Feature](https://www.nowsecure.com/blog/2019/02/07/frida-12-3-debuts-new-crash-reporting-feature/)
- 2019.01 [fuzzysecurity] [Application Introspection & Hooking With Frida](http://fuzzysecurity.com/tutorials/29.html)
- 2019.01 [fuping] [安卓APP测试之HOOK大法-Frida篇](https://fuping.site/2019/01/25/Frida-Hook-SoulAPP/)
- 2019.01 [360] [FRIDA脚本系列（二）成长篇：动静态结合逆向WhatsApp](https://www.anquanke.com/post/id/169315/)
- 2019.01 [pediy] [[原创]介召几个frida在安卓逆向中使用的脚本以及延时Hook手法](https://bbs.pediy.com/thread-248848.htm)
- 2018.12 [360] [FRIDA脚本系列（一）入门篇：在安卓8.1上dump蓝牙接口和实例](https://www.anquanke.com/post/id/168152/)
- 2018.12 [pediy] [[原创]CVE-2017-4901 VMware虚拟机逃逸漏洞分析【Frida Windows实例】](https://bbs.pediy.com/thread-248384.htm)
- 2018.12 [freebuf] [一篇文章带你领悟Frida的精髓（基于安卓8.1）](https://www.freebuf.com/articles/system/190565.html)
- 2018.12 [pediy] [[原创] Frida操作手册-Android环境准备](https://bbs.pediy.com/thread-248293.htm)
- 2018.11 [4hou] [使用FRIDA为Android应用进行脱壳的操作指南](http://www.4hou.com/technology/14404.html)
- 2018.11 [pediy] [[原创]Frida Bypass Android SSL pinning example 1](https://bbs.pediy.com/thread-247967.htm)
- 2018.11 [BSidesCHS] [BSidesCHS 2018: "Hacking Mobile Apps with Frida" by David Coursey](https://www.youtube.com/watch?v=NRyHP9IJRMs)
- 2018.11 [freebuf] [Frida-Wshook：一款基于Frida.re的脚本分析工具](https://www.freebuf.com/sectool/188726.html)
- 2018.11 [360] [如何使用FRIDA搞定Android加壳应用](https://www.anquanke.com/post/id/163390/)
- 2018.11 [ioactive] [Extracting Bluetooth Metadata in an Object’s Memory Using Frida](https://ioactive.com/extracting-bluetooth-metadata-in-an-objects-memory-using-frida/)
- 2018.11 [fortinet] [How-to Guide: Defeating an Android Packer with FRIDA](https://www.fortinet.com/blog/threat-research/defeating-an-android-packer-with-frida.html)
- 2018.10 [PancakeNopcode] [r2con2018 - Analyzing Swift Apps With swift-frida and radare2 - by Malte Kraus](https://www.youtube.com/watch?v=yp6E9-h6yYQ)
- 2018.10 [serializethoughts] [Bypassing Android FLAG_SECURE using FRIDA](https://serializethoughts.com/2018/10/07/bypassing-android-flag_secure-using-frida/)
- 2018.09 [pediy] [[原创]使用frida来hook加固的Android应用的java层](https://bbs.pediy.com/thread-246767.htm)
- 2018.09 [freebuf] [Frida在爆破Windows程序中的应用](http://www.freebuf.com/articles/system/182112.html)
- 2018.08 [pediy] [[翻译]通过破解游戏学习Frida基础知识](https://bbs.pediy.com/thread-246272.htm)
- 2018.07 [pediy] [[原创]在windows搭建frida hook环境碰到问题](https://bbs.pediy.com/thread-230138.htm)
- 2018.07 [CodeColorist] [《基于 FRIDA 的全平台逆向分析》课件](https://medium.com/p/2918c2b8967d)
- 2018.07 [pediy] [[翻译]在未root的设备上使用frida](https://bbs.pediy.com/thread-229970.htm)
- 2018.07 [pediy] [[原创]进阶Frida--Android逆向之动态加载dex Hook（三）（下篇）](https://bbs.pediy.com/thread-229657.htm)
- 2018.07 [pediy] [[原创]进阶Frida--Android逆向之动态加载dex Hook（三）（上篇）](https://bbs.pediy.com/thread-229597.htm)
- 2018.06 [pediy] [[原创]frida源码阅读之frida-java](https://bbs.pediy.com/thread-229215.htm)
- 2018.06 [4hou] [利用Frida打造ELF解析器](http://www.4hou.com/technology/12197.html)
- 2018.06 [pediy] [[原创]关于android 微信 frida 使用技巧](https://bbs.pediy.com/thread-228746.htm)
- 2018.06 [pediy] [[原创]初识Frida--Android逆向之Java层hook (二)](https://bbs.pediy.com/thread-227233.htm)
- 2018.06 [pediy] [[原创]初识Frida--Android逆向之Java层hook (一)](https://bbs.pediy.com/thread-227232.htm)
- 2018.05 [pediy] [[原创]Frida从入门到入门—安卓逆向菜鸟的frida食用说明](https://bbs.pediy.com/thread-226846.htm)
- 2018.05 [aliyun] [Frida.Android.Practice (ssl unpinning)](https://xz.aliyun.com/t/2336)
- 2018.05 [infosecinstitute] [Frida](http://resources.infosecinstitute.com/frida/)
- 2018.03 [pediy] [[翻译]使用 Frida 逆向分析 Android 应用与 BLE 设备的通信](https://bbs.pediy.com/thread-224926.htm)
- 2018.03 [freebuf] [Frida之Pin码破解实验](http://www.freebuf.com/articles/terminal/163297.html)
- 2018.02 [pentestpartners] [Reverse Engineering BLE from Android apps with Frida](https://www.pentestpartners.com/security-blog/reverse-engineering-ble-from-android-apps-with-frida/)
- 2018.02 [BSidesLeeds] [Prototyping And Reverse Engineering With Frida by Jay Harris](https://www.youtube.com/watch?v=cLUl_jK59EM)
- 2018.02 [libnex] [Hunting for hidden parameters within PHP built-in functions (using frida)](http://www.libnex.org/blog/huntingforhiddenparameterswithinphpbuilt-infunctionsusingfrida)
- 2017.11 [pediy] [[翻译]Frida官方手册中文版](https://bbs.pediy.com/thread-222729.htm)
- 2017.10 [pediy] [[翻译]利用Frida绕过Certificate Pinning](https://bbs.pediy.com/thread-222427.htm)
- 2017.09 [PancakeNopcode] [r2con 2017 - Intro to Frida and Dynamic Machine Code Transformations by Ole Andre](https://www.youtube.com/watch?v=sBcLPLtqGYU)
- 2017.09 [PancakeNopcode] [r2con2017 - r2frida /by @mrmacete](https://www.youtube.com/watch?v=URyd4bcV-Ik)
- 2017.09 [pediy] [[原创] 如何构建一款像 frida 一样的框架](https://bbs.pediy.com/thread-220794.htm)
- 2017.08 [360] [如何利用Frida实现原生Android函数的插桩](https://www.anquanke.com/post/id/86653/)
- 2017.08 [notsosecure] [Instrumenting Native Android Functions using Frida](https://www.notsosecure.com/instrumenting-native-android-functions-using-frida/)
- 2017.08 [freebuf] [Brida：使用Frida进行移动应用渗透测试](http://www.freebuf.com/sectool/143360.html)
- 2017.08 [freebuf] [利用Frida从TeamViewer内存中提取密码](http://www.freebuf.com/sectool/142928.html)
- 2017.08 [360] [联合Frida和BurpSuite的强大扩展--Brida](https://www.anquanke.com/post/id/86567/)
- 2017.08 [4hou] [Brida:将frida与burp结合进行移动app渗透测试](http://www.4hou.com/penetration/6916.html)
- 2017.07 [mediaservice] [Brida: Advanced Mobile Application Penetration Testing with Frida](https://techblog.mediaservice.net/2017/07/brida-advanced-mobile-application-penetration-testing-with-frida/)
- 2017.07 [360] [使用Frida绕过Android SSL Re-Pinning](https://www.anquanke.com/post/id/86507/)
- 2017.07 [mediaservice] [Universal Android SSL Pinning bypass with Frida](https://techblog.mediaservice.net/2017/07/universal-android-ssl-pinning-bypass-with-frida/)
- 2017.07 [4hou] [objection - 基于 Frida 的 iOS APP Runtime 探测工具](http://www.4hou.com/tools/6333.html)
- 2017.06 [360] [利用FRIDA攻击Android应用程序（四）](https://www.anquanke.com/post/id/86201/)
- 2017.06 [fitblip] [Frida CodeShare: Building a Community of Giants](https://medium.com/p/e84695a16e10)
- 2017.05 [freebuf] [如何在iOS应用程序中用Frida来绕过“越狱检测”?](http://www.freebuf.com/articles/terminal/134111.html)
- 2017.05 [4hou] [Android APP破解利器Frida之反调试对抗](http://www.4hou.com/technology/4584.html)
- 2017.05 [360] [如何使用Frida绕过iOS应用的越狱检测](https://www.anquanke.com/post/id/86068/)
- 2017.05 [4hou] [Frida：一款可以绕过越狱检测的工具](http://www.4hou.com/technology/4675.html)
- 2017.05 [pediy] [[翻译]多种特征检测 Frida](https://bbs.pediy.com/thread-217482.htm)
- 2017.05 [attify] [Bypass Jailbreak Detection with Frida in iOS applications](http://blog.attify.com/2017/05/06/bypass-jailbreak-detection-frida-ios-applications/)
- 2017.05 [pediy] [[翻译]OWASP iOS crackme 的教程：使用Frida来解决](https://bbs.pediy.com/thread-217448.htm)
- 2017.05 [attify] [Bypass Jailbreak Detection with Frida in iOS applications](https://blog.attify.com/bypass-jailbreak-detection-frida-ios-applications/)
- 2017.05 [pediy] [[翻译]用Frida来hack 安卓应用III—— OWASP UNCRACKABLE 2](https://bbs.pediy.com/thread-217424.htm)
- 2017.05 [360] [利用FRIDA攻击Android应用程序（三）](https://www.anquanke.com/post/id/85996/)
- 2017.04 [codemetrix] [Hacking Android apps with FRIDA III - OWASP UnCrackable 2](https://codemetrix.net/hacking-android-apps-with-frida-3/)
- 2017.04 [4hou] [安卓APP破解利器Frida之破解实战](http://www.4hou.com/technology/4392.html)
- 2017.04 [4hou] [安卓APP破解利器之FRIDA](http://www.4hou.com/info/news/4113.html)
- 2017.04 [koz] [Using Frida on Android without root](https://koz.io/using-frida-on-android-without-root/)
- 2017.04 [pediy] [[翻译]使用Frida来hack安卓APP（二）-crackme](https://bbs.pediy.com/thread-216893.htm)
- 2017.04 [fuping] [Android HOOK 技术之Frida的初级使用](https://fuping.site/2017/04/01/Android-HOOK-%E6%8A%80%E6%9C%AF%E4%B9%8BFrida%E7%9A%84%E5%88%9D%E7%BA%A7%E4%BD%BF%E7%94%A8/)
- 2017.03 [pediy] [[翻译] 使用Frida来hack安卓APP（一）](https://bbs.pediy.com/thread-216645.htm)
- 2017.03 [360] [利用FRIDA攻击Android应用程序（二）](https://www.anquanke.com/post/id/85759/)
- 2017.03 [360] [利用FRIDA攻击Android应用程序（一）](https://www.anquanke.com/post/id/85758/)
- 2017.03 [notsosecure] [Pentesting Android Apps Using Frida](https://www.notsosecure.com/pentesting-android-apps-using-frida/)
- 2017.03 [codemetrix] [Hacking Android apps with FRIDA II - Crackme](https://codemetrix.net/hacking-android-apps-with-frida-2/)
- 2017.03 [codemetrix] [Hacking Android apps with FRIDA I](https://codemetrix.net/hacking-android-apps-with-frida-1/)
- 2017.01 [freebuf] [使用Frida配合Burp Suite追踪API调用](http://www.freebuf.com/articles/web/125260.html)
- 2016.09 [PancakeNopcode] [r2con 2016 -- oleavr - r2frida](https://www.youtube.com/watch?v=ivCucqeVeZI)
- 2016.09 [n0where] [RunPE Extraction Tool: FridaExtract](https://n0where.net/runpe-extraction-tool-fridaextract)




***


## <a id="b2fca17481b109a9b3b0bc290a1a1381"></a>QBDI


### <a id="e72b766bcd3b868c438a372bc365221e"></a>Tools


- [**578**Star][1y] [C++] [qbdi/qbdi](https://github.com/QBDI/QBDI) A Dynamic Binary Instrumentation framework based on LLVM.


### <a id="2cf79f93baf02a24d95d227a0a3049d8"></a>Post


- 2019.09 [quarkslab] [QBDI 0.7.0](https://blog.quarkslab.com/qbdi-070.html)
- 2019.07 [freebuf] [教你如何使用QBDI动态二进制检测框架](https://www.freebuf.com/sectool/207898.html)
- 2019.06 [quarkslab] [Android Native Library Analysis with QBDI](https://blog.quarkslab.com/android-native-library-analysis-with-qbdi.html)
- 2018.01 [quarkslab] [Slaying Dragons with QBDI](https://blog.quarkslab.com/slaying-dragons-with-qbdi.html)
- 2018.01 [pentesttoolz] [QBDI – QuarkslaB Dynamic binary Instrumentation](https://pentesttoolz.com/2018/01/13/qbdi-quarkslab-dynamic-binary-instrumentation/)
- 2018.01 [n0where] [QuarkslaB Dynamic binary Instrumentation: QBDI](https://n0where.net/quarkslab-dynamic-binary-instrumentation-qbdi)




***


## <a id="5a9974bfcf7cdf9b05fe7a7dc5272213"></a>Other


### <a id="104bc99e36692f133ba70475ebc8825f"></a>Tools


- [**171**Star][20d] [C] [beehive-lab/mambo](https://github.com/beehive-lab/mambo) ARM运行时二进制文件修改工具，低耗版。
- [**73**Star][3y] [Py] [carlosgprado/brundlefuzz](https://github.com/carlosgprado/brundlefuzz) BrundleFuzz is a distributed fuzzer for Windows and Linux using dynamic binary instrumentation.
- [**60**Star][1y] [C] [zhechkoz/pwin](https://github.com/zhechkoz/pwin) Security Evaluation of Dynamic Binary Instrumentation Engines
- [**6**Star][4y] [C++] [crackinglandia/exait-plugins](https://github.com/crackinglandia/exait-plugins) Anti-Dynamic binary instrumentation plugins for eXait (


### <a id="8f1b9c5c2737493524809684b934d49a"></a>Post


- 2018.08 [4hou] [动态二进制插桩的原理和基本实现过程（一）](http://www.4hou.com/binary/13026.html)




# <a id="d3690e0b19c784e104273fe4d64b2362"></a>Other


***


## <a id="9162e3507d24e58e9e944dd3f6066c0e"></a>Post-Recent Add




***


## <a id="1d9dec1320a5d774dc8e0e7604edfcd3"></a>Tool-Recent Add


- [**19766**Star][3m] [Jupyter Notebook] [camdavidsonpilon/probabilistic-programming-and-bayesian-methods-for-hackers](https://github.com/camdavidsonpilon/probabilistic-programming-and-bayesian-methods-for-hackers) aka "Bayesian Methods for Hackers": An introduction to Bayesian methods + probabilistic programming with a computation/understanding-first, mathematics-second point of view. All in pure Python ;)
- [**14349**Star][2m] [Py] [corentinj/real-time-voice-cloning](https://github.com/corentinj/real-time-voice-cloning) Clone a voice in 5 seconds to generate arbitrary speech in real-time
- [**11402**Star][10d] [Java] [oracle/graal](https://github.com/oracle/graal) Run Programs Faster Anywhere
- [**11213**Star][2m] [Jupyter Notebook] [selfteaching/the-craft-of-selfteaching](https://github.com/selfteaching/the-craft-of-selfteaching) One has no future if one couldn't teach themself.
- [**10378**Star][11d] [Go] [goharbor/harbor](https://github.com/goharbor/harbor) An open source trusted cloud native registry project that stores, signs, and scans content.
- [**7748**Star][10d] [Go] [git-lfs/git-lfs](https://github.com/git-lfs/git-lfs) Git extension for versioning large files
- [**7020**Star][14d] [Go] [nats-io/nats-server](https://github.com/nats-io/nats-server) High-Performance server for NATS, the cloud native messaging system.
- [**6894**Star][2m] [Go] [sqshq/sampler](https://github.com/sqshq/sampler) A tool for shell commands execution, visualization and alerting. Configured with a simple YAML file.
- [**6454**Star][9m] [HTML] [open-power-workgroup/hospital](https://github.com/open-power-workgroup/hospital) OpenPower工作组收集汇总的医院开放数据
- [**6353**Star][2m] [Py] [seatgeek/fuzzywuzzy](https://github.com/seatgeek/fuzzywuzzy) Fuzzy String Matching in Python
- [**6055**Star][7m] [JS] [haotian-wang/google-access-helper](https://github.com/haotian-wang/google-access-helper) 谷歌访问助手破解版
- [**5876**Star][3m] [Gnuplot] [nasa-jpl/open-source-rover](https://github.com/nasa-jpl/open-source-rover) A build-it-yourself, 6-wheel rover based on the rovers on Mars!
- [**5829**Star][7m] [JS] [sindresorhus/fkill-cli](https://github.com/sindresorhus/fkill-cli) Fabulously kill processes. Cross-platform.
- [**5753**Star][18d] [Go] [casbin/casbin](https://github.com/casbin/casbin) An authorization library that supports access control models like ACL, RBAC, ABAC in Golang
- [**5751**Star][9m] [C] [xoreaxeaxeax/movfuscator](https://github.com/xoreaxeaxeax/movfuscator) The single instruction C compiler
- [**5717**Star][28d] [JS] [swagger-api/swagger-editor](https://github.com/swagger-api/swagger-editor) Swagger Editor
- [**5420**Star][12d] [Py] [mlflow/mlflow](https://github.com/mlflow/mlflow) Open source platform for the machine learning lifecycle
- [**5229**Star][4m] [Py] [ytisf/thezoo](https://github.com/ytisf/thezoo) A repository of LIVE malwares for your own joy and pleasure. theZoo is a project created to make the possibility of malware analysis open and available to the public.
- [**5226**Star][13d] [Shell] [denisidoro/navi](https://github.com/denisidoro/navi) An interactive cheatsheet tool for the command-line
- [**5116**Star][11d] [ASP] [hq450/fancyss](https://github.com/hq450/fancyss) fancyss is a project providing tools to across the GFW on asuswrt/merlin based router.
- [**5007**Star][2m] [Py] [snare/voltron](https://github.com/snare/voltron) A hacky debugger UI for hackers
- [**4857**Star][13d] [Go] [gcla/termshark](https://github.com/gcla/termshark) A terminal UI for tshark, inspired by Wireshark
- [**4810**Star][8m] [Py] [10se1ucgo/disablewintracking](https://github.com/10se1ucgo/disablewintracking) Uses some known methods that attempt to minimize tracking in Windows 10
- [**4747**Star][8d] [C++] [paddlepaddle/paddle-lite](https://github.com/PaddlePaddle/Paddle-Lite) Multi-platform high performance deep learning inference engine (『飞桨』多平台高性能深度学习预测引擎）
- [**4651**Star][13d] [powershell/win32-openssh](https://github.com/powershell/win32-openssh) Win32 port of OpenSSH
- [**4610**Star][1y] [C] [upx/upx](https://github.com/upx/upx) UPX - the Ultimate Packer for eXecutables
- [**4600**Star][12m] [Py] [ecthros/uncaptcha2](https://github.com/ecthros/uncaptcha2) defeating the latest version of ReCaptcha with 91% accuracy
- [**4597**Star][12d] [C++] [mozilla/rr](https://github.com/mozilla/rr) Record and Replay Framework
- [**4541**Star][4m] [TS] [apis-guru/graphql-voyager](https://github.com/apis-guru/graphql-voyager) 
- [**4352**Star][1y] [Py] [lennylxx/ipv6-hosts](https://github.com/lennylxx/ipv6-hosts) Fork of
- [**4314**Star][15d] [Rust] [timvisee/ffsend](https://github.com/timvisee/ffsend) Easily and securely share files from the command line
- [**4258**Star][12m] [JS] [butterproject/butter-desktop](https://github.com/butterproject/butter-desktop) All the free parts of Popcorn Time
- [**4174**Star][2y] [forter/security-101-for-saas-startups](https://github.com/forter/security-101-for-saas-startups) security tips for startups
- [**4062**Star][3m] [Java] [jesusfreke/smali](https://github.com/jesusfreke/smali) smali/baksmali
- [**4060**Star][2m] [JS] [sigalor/whatsapp-web-reveng](https://github.com/sigalor/whatsapp-web-reveng) Reverse engineering WhatsApp Web.
- [**4003**Star][11d] [Go] [dexidp/dex](https://github.com/dexidp/dex) OpenID Connect Identity (OIDC) and OAuth 2.0 Provider with Pluggable Connectors
- [**3980**Star][1m] [Rust] [svenstaro/genact](https://github.com/svenstaro/genact) a nonsense activity generator
- [**3960**Star][11d] [Py] [angr/angr](https://github.com/angr/angr) A powerful and user-friendly binary analysis platform!
- [**3954**Star][16d] [Go] [eranyanay/1m-go-websockets](https://github.com/eranyanay/1m-go-websockets) handling 1M websockets connections in Go
- [**3939**Star][15d] [C] [aquynh/capstone](https://github.com/aquynh/capstone) Capstone disassembly/disassembler framework: Core (Arm, Arm64, BPF, EVM, M68K, M680X, MOS65xx, Mips, PPC, RISCV, Sparc, SystemZ, TMS320C64x, Web Assembly, X86, X86_64, XCore) + bindings.
- [**3908**Star][12d] [C++] [baldurk/renderdoc](https://github.com/baldurk/renderdoc) RenderDoc is a stand-alone graphics debugging tool.
- [**3844**Star][2m] [ObjC] [sveinbjornt/sloth](https://github.com/sveinbjornt/sloth) Mac app that shows all open files, directories and sockets in use by all running processes. Nice GUI for lsof.
- [**3773**Star][25d] [jjqqkk/chromium](https://github.com/jjqqkk/chromium) Chromium browser with SSL VPN. Use this browser to unblock websites.
- [**3768**Star][2m] [Go] [microsoft/ethr](https://github.com/microsoft/ethr) Ethr is a Network Performance Measurement Tool for TCP, UDP & HTTP.
- [**3749**Star][12d] [Go] [hashicorp/consul-template](https://github.com/hashicorp/consul-template) Template rendering, notifier, and supervisor for
- [**3690**Star][21d] [JS] [lesspass/lesspass](https://github.com/lesspass/lesspass) 
- [**3688**Star][29d] [HTML] [hamukazu/lets-get-arrested](https://github.com/hamukazu/lets-get-arrested) This project is intended to protest against the police in Japan
- [**3669**Star][1y] [Py] [misterch0c/shadowbroker](https://github.com/misterch0c/shadowbroker) The Shadow Brokers "Lost In Translation" leak
- [**3627**Star][26d] [HTML] [consensys/smart-contract-best-practices](https://github.com/consensys/smart-contract-best-practices) A guide to smart contract security best practices
- [**3608**Star][9d] [Pascal] [cheat-engine/cheat-engine](https://github.com/cheat-engine/cheat-engine) Cheat Engine. A development environment focused on modding
- [**3597**Star][2y] [C#] [nummer/destroy-windows-10-spying](https://github.com/nummer/destroy-windows-10-spying) Destroy Windows Spying tool
- [**3597**Star][3y] [Perl] [x0rz/eqgrp](https://github.com/x0rz/eqgrp) Decrypted content of eqgrp-auction-file.tar.xz
- [**3538**Star][5m] [Shell] [chengr28/revokechinacerts](https://github.com/chengr28/revokechinacerts) Revoke Chinese certificates.
- [**3505**Star][16d] [C] [cyan4973/xxhash](https://github.com/cyan4973/xxhash) Extremely fast non-cryptographic hash algorithm
- [**3451**Star][19d] [C] [mikebrady/shairport-sync](https://github.com/mikebrady/shairport-sync) AirPlay audio player. Shairport Sync adds multi-room capability with Audio Synchronisation
- [**3320**Star][2y] [scanate/ethlist](https://github.com/scanate/ethlist) The Comprehensive Ethereum Reading List
- [**3306**Star][19d] [C] [microsoft/windows-driver-samples](https://github.com/microsoft/windows-driver-samples) This repo contains driver samples prepared for use with Microsoft Visual Studio and the Windows Driver Kit (WDK). It contains both Universal Windows Driver and desktop-only driver samples.
- [**3295**Star][15d] [JS] [koenkk/zigbee2mqtt](https://github.com/koenkk/zigbee2mqtt) Zigbee
- [**3289**Star][15d] [C] [virustotal/yara](https://github.com/virustotal/yara) The pattern matching swiss knife
- [**3280**Star][29d] [Java] [oldmanpushcart/greys-anatomy](https://github.com/oldmanpushcart/greys-anatomy) Java诊断工具
- [**3259**Star][5y] [C++] [google/lmctfy](https://github.com/google/lmctfy) lmctfy is the open source version of Google’s container stack, which provides Linux application containers.
- [**3243**Star][14d] [Shell] [gfw-breaker/ssr-accounts](https://github.com/gfw-breaker/ssr-accounts) 一键部署Shadowsocks服务；免费Shadowsocks账号分享；免费SS账号分享; 翻墙；无界，自由门，SquirrelVPN
- [**3233**Star][25d] [C] [tmate-io/tmate](https://github.com/tmate-io/tmate) Instant Terminal Sharing
- [**3219**Star][2m] [TS] [google/incremental-dom](https://github.com/google/incremental-dom) An in-place DOM diffing library
- [**3202**Star][1y] [Shell] [toyodadoubi/doubi](https://github.com/toyodadoubi/doubi) 一个逗比写的各种逗比脚本~
- [**3188**Star][11d] [C] [meetecho/janus-gateway](https://github.com/meetecho/janus-gateway) Janus WebRTC Server
- [**3131**Star][2m] [CSS] [readthedocs/sphinx_rtd_theme](https://github.com/readthedocs/sphinx_rtd_theme) Sphinx theme for readthedocs.org
- [**3129**Star][13d] [C] [qemu/qemu](https://github.com/qemu/qemu) Official QEMU mirror. Please see
- [**3120**Star][11d] [Go] [tencent/bk-cmdb](https://github.com/tencent/bk-cmdb) 蓝鲸智云配置平台(BlueKing CMDB)
- [**3108**Star][1m] [C] [unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn) Unicorn CPU emulator framework (ARM, AArch64, M68K, Mips, Sparc, X86)
- [**3066**Star][1y] [Swift] [zhuhaow/spechtlite](https://github.com/zhuhaow/spechtlite) A rule-based proxy for macOS
- [**3052**Star][4m] [C++] [google/robotstxt](https://github.com/google/robotstxt) The repository contains Google's robots.txt parser and matcher as a C++ library (compliant to C++11).
- [**3010**Star][1y] [PHP] [owner888/phpspider](https://github.com/owner888/phpspider) 《我用爬虫一天时间“偷了”知乎一百万用户，只为证明PHP是世界上最好的语言 》所使用的程序
- [**2993**Star][18d] [Py] [quantaxis/quantaxis](https://github.com/quantaxis/quantaxis) QUANTAXIS 支持任务调度 分布式部署的 股票/期货/自定义市场 数据/回测/模拟/交易/可视化 纯本地PAAS量化解决方案
- [**2980**Star][14d] [ObjC] [google/santa](https://github.com/google/santa) A binary whitelisting/blacklisting system for macOS
- [**2948**Star][1m] [C] [libfuse/sshfs](https://github.com/libfuse/sshfs) A network filesystem client to connect to SSH servers
- [**2898**Star][8m] [C] [p-h-c/phc-winner-argon2](https://github.com/p-h-c/phc-winner-argon2) The password hash Argon2, winner of PHC
- [**2887**Star][4y] [ObjC] [maciekish/iresign](https://github.com/maciekish/iresign) iReSign allows iDevice app bundles (.ipa) files to be signed or resigned with a digital certificate from Apple for distribution. This tool is aimed at enterprises users, for enterprise deployment, when the person signing the app is different than the person(s) developing it.
- [**2872**Star][14d] [C] [lxc/lxc](https://github.com/lxc/lxc) LXC - Linux Containers
- [**2854**Star][1m] [Py] [espressif/esptool](https://github.com/espressif/esptool) ESP8266 and ESP32 serial bootloader utility
- [**2848**Star][6m] [Py] [instantbox/instantbox](https://github.com/instantbox/instantbox) Get a clean, ready-to-go Linux box in seconds.
- [**2833**Star][2m] [Assembly] [cirosantilli/x86-bare-metal-examples](https://github.com/cirosantilli/x86-bare-metal-examples) Dozens of minimal operating systems to learn x86 system programming. Tested on Ubuntu 17.10 host in QEMU 2.10 and real hardware. Userland cheat at:
- [**2815**Star][20d] [C] [processhacker/processhacker](https://github.com/processhacker/processhacker) A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware.
- [**2808**Star][10m] [Py] [plasma-disassembler/plasma](https://github.com/plasma-disassembler/plasma) Plasma is an interactive disassembler for x86/ARM/MIPS. It can generates indented pseudo-code with colored syntax.
- [**2789**Star][13d] [C++] [qtox/qtox](https://github.com/qtox/qtox) qTox is a chat, voice, video, and file transfer IM client using the encrypted peer-to-peer Tox protocol.
- [**2772**Star][2m] [JS] [trufflesuite/ganache-cli](https://github.com/trufflesuite/ganache-cli) Fast Ethereum RPC client for testing and development
- [**2760**Star][10d] [TS] [webhintio/hint](https://github.com/webhintio/hint) 
- [**2718**Star][3m] [Py] [drivendata/cookiecutter-data-science](https://github.com/drivendata/cookiecutter-data-science) A logical, reasonably standardized, but flexible project structure for doing and sharing data science work.
- [**2687**Star][11d] [Go] [adguardteam/adguardhome](https://github.com/adguardteam/adguardhome) Network-wide ads & trackers blocking DNS server
- [**2631**Star][8m] [leandromoreira/linux-network-performance-parameters](https://github.com/leandromoreira/linux-network-performance-parameters) Learn where some of the network sysctl variables fit into the Linux/Kernel network flow
- [**2627**Star][23d] [JS] [popcorn-official/popcorn-desktop](https://github.com/popcorn-official/popcorn-desktop) Popcorn Time is a multi-platform, free software BitTorrent client that includes an integrated media player. Desktop ( Windows / Mac / Linux ) a Butter-Project Fork
- [**2621**Star][2m] [pditommaso/awesome-pipeline](https://github.com/pditommaso/awesome-pipeline) A curated list of awesome pipeline toolkits inspired by Awesome Sysadmin
- [**2619**Star][2m] [Swift] [zhuhaow/nekit](https://github.com/zhuhaow/nekit) A toolkit for Network Extension Framework
- [**2615**Star][1m] [JS] [knownsec/kcon](https://github.com/knownsec/kcon) KCon is a famous Hacker Con powered by Knownsec Team.
- [**2587**Star][10d] [C] [esnet/iperf](https://github.com/esnet/iperf) A TCP, UDP, and SCTP network bandwidth measurement tool
- [**2580**Star][8y] [C] [id-software/quake](https://github.com/id-software/quake) Quake GPL Source Release
- [**2535**Star][3m] [Java] [jboss-javassist/javassist](https://github.com/jboss-javassist/javassist) Java bytecode engineering toolkit
- [**2478**Star][11m] [JS] [weixin/miaow](https://github.com/weixin/Miaow) A set of plugins for Sketch include drawing links & marks, UI Kit & Color sync, font & text replacing.
- [**2474**Star][25d] [JS] [vitaly-t/pg-promise](https://github.com/vitaly-t/pg-promise) PostgreSQL interface for Node.js
- [**2456**Star][3y] [Py] [google/enjarify](https://github.com/google/enjarify) a tool for translating Dalvik bytecode to equivalent Java bytecode.
- [**2395**Star][3y] [OCaml] [facebookarchive/pfff](https://github.com/facebookarchive/pfff) Tools for code analysis, visualizations, or style-preserving source transformation.
- [**2391**Star][21d] [Java] [mock-server/mockserver](https://github.com/mock-server/mockserver) MockServer enables easy mocking of any system you integrate with via HTTP or HTTPS with clients written in Java, JavaScript and Ruby. MockServer also includes a proxy that introspects all proxied traffic including encrypted SSL traffic and supports Port Forwarding, Web Proxying (i.e. HTTP proxy), HTTPS Tunneling Proxying (using HTTP CONNECT) and…
- [**2364**Star][10d] [C] [domoticz/domoticz](https://github.com/domoticz/domoticz) monitor and configure various devices like: Lights, Switches, various sensors/meters like Temperature, Rain, Wind, UV, Electra, Gas, Water and much more
- [**2345**Star][4m] [Go] [vuvuzela/vuvuzela](https://github.com/vuvuzela/vuvuzela) Private messaging system that hides metadata
- [**2344**Star][16d] [C] [tsl0922/ttyd](https://github.com/tsl0922/ttyd) Share your terminal over the web
- [**2340**Star][2m] [JS] [pa11y/pa11y](https://github.com/pa11y/pa11y) Pa11y is your automated accessibility testing pal
- [**2321**Star][5y] [C] [abrasive/shairport](https://github.com/abrasive/shairport) Airtunes emulator! Shairport is no longer maintained.
- [**2305**Star][2m] [C] [moby/hyperkit](https://github.com/moby/hyperkit) A toolkit for embedding hypervisor capabilities in your application
- [**2301**Star][3y] [Py] [lmacken/pyrasite](https://github.com/lmacken/pyrasite) Inject code into running Python processes
- [**2286**Star][1m] [JS] [talkingdata/inmap](https://github.com/talkingdata/inmap) 大数据地理可视化
- [**2260**Star][13d] [dumb-password-rules/dumb-password-rules](https://github.com/dumb-password-rules/dumb-password-rules) Shaming sites with dumb password rules.
- [**2217**Star][14d] [Go] [google/mtail](https://github.com/google/mtail) extract whitebox monitoring data from application logs for collection in a timeseries database
- [**2214**Star][18d] [getlantern/lantern-binaries](https://github.com/getlantern/lantern-binaries) Lantern installers binary downloads.
- [**2211**Star][1m] [C++] [google/bloaty](https://github.com/google/bloaty) Bloaty McBloatface: a size profiler for binaries
- [**2194**Star][13d] [C] [armmbed/mbedtls](https://github.com/armmbed/mbedtls) An open source, portable, easy to use, readable and flexible SSL library
- [**2137**Star][19d] [Assembly] [pret/pokered](https://github.com/pret/pokered) disassembly of Pokémon Red/Blue
- [**2132**Star][20d] [goq/telegram-list](https://github.com/goq/telegram-list) List of telegram groups, channels & bots // Список интересных групп, каналов и ботов телеграма // Список чатов для программистов
- [**2093**Star][10d] [C] [flatpak/flatpak](https://github.com/flatpak/flatpak) Linux application sandboxing and distribution framework
- [**2092**Star][26d] [swiftonsecurity/sysmon-config](https://github.com/swiftonsecurity/sysmon-config) Sysmon configuration file template with default high-quality event tracing
- [**2080**Star][2m] [Go] [theupdateframework/notary](https://github.com/theupdateframework/notary) Notary is a project that allows anyone to have trust over arbitrary collections of data
- [**2053**Star][4m] [Go] [maxmcd/webtty](https://github.com/maxmcd/webtty) Share a terminal session over WebRTC
- [**2053**Star][24d] [C#] [mathewsachin/captura](https://github.com/mathewsachin/captura) Capture Screen, Audio, Cursor, Mouse Clicks and Keystrokes
- [**2052**Star][13d] [C++] [openthread/openthread](https://github.com/openthread/openthread) OpenThread released by Google is an open-source implementation of the Thread networking protocol
- [**2031**Star][10m] [C] [dekunukem/nintendo_switch_reverse_engineering](https://github.com/dekunukem/nintendo_switch_reverse_engineering) A look at inner workings of Joycon and Nintendo Switch
- [**2005**Star][4y] [C] [probablycorey/wax](https://github.com/probablycorey/wax) Wax is now being maintained by alibaba
- [**2003**Star][2m] [C++] [asmjit/asmjit](https://github.com/asmjit/asmjit) Complete x86/x64 JIT and AOT Assembler for C++
- [**1998**Star][2m] [Swift] [github/softu2f](https://github.com/github/softu2f) Software U2F authenticator for macOS
- [**1955**Star][11d] [Go] [solo-io/gloo](https://github.com/solo-io/gloo) An Envoy-Powered API Gateway
- [**1949**Star][17d] [C] [microsoft/procdump-for-linux](https://github.com/microsoft/procdump-for-linux) A Linux version of the ProcDump Sysinternals tool
- [**1944**Star][3y] [C#] [lazocoder/windows-hacks](https://github.com/lazocoder/windows-hacks) Creative and unusual things that can be done with the Windows API.
- [**1930**Star][22d] [C++] [mhammond/pywin32](https://github.com/mhammond/pywin32) Python for Windows (pywin32) Extensions
- [**1907**Star][18d] [Go] [minishift/minishift](https://github.com/minishift/minishift) Run OpenShift 3.x locally
- [**1899**Star][25d] [C++] [acidanthera/lilu](https://github.com/acidanthera/Lilu) Arbitrary kext and process patching on macOS
- [**1893**Star][5y] [C++] [tum-vision/lsd_slam](https://github.com/tum-vision/lsd_slam) LSD-SLAM
- [**1877**Star][25d] [Java] [adoptopenjdk/jitwatch](https://github.com/adoptopenjdk/jitwatch) Log analyser / visualiser for Java HotSpot JIT compiler. Inspect inlining decisions, hot methods, bytecode, and assembly. View results in the JavaFX user interface.
- [**1864**Star][4y] [ObjC] [xcodeghostsource/xcodeghost](https://github.com/xcodeghostsource/xcodeghost) "XcodeGhost" Source
- [**1863**Star][10d] [C++] [pytorch/glow](https://github.com/pytorch/glow) Compiler for Neural Network hardware accelerators
- [**1859**Star][12m] [C++] [googlecreativelab/open-nsynth-super](https://github.com/googlecreativelab/open-nsynth-super) Open NSynth Super is an experimental physical interface for the NSynth algorithm
- [**1854**Star][19d] [C] [github/glb-director](https://github.com/github/glb-director) GitHub Load Balancer Director and supporting tooling.
- [**1852**Star][1y] [Py] [jinnlynn/genpac](https://github.com/jinnlynn/genpac) PAC/Dnsmasq/Wingy file Generator, working with gfwlist, support custom rules.
- [**1851**Star][1y] [Java] [yeriomin/yalpstore](https://github.com/yeriomin/yalpstore) Download apks from Google Play Store
- [**1848**Star][9m] [Py] [netflix-skunkworks/stethoscope](https://github.com/Netflix-Skunkworks/stethoscope) Personalized, user-focused recommendations for employee information security.
- [**1846**Star][3m] [C] [retroplasma/earth-reverse-engineering](https://github.com/retroplasma/earth-reverse-engineering) Reversing Google's 3D satellite mode
- [**1837**Star][3m] [Go] [influxdata/kapacitor](https://github.com/influxdata/kapacitor) Open source framework for processing, monitoring, and alerting on time series data
- [**1827**Star][13d] [Py] [trailofbits/manticore](https://github.com/trailofbits/manticore) Symbolic execution tool
- [**1816**Star][29d] [Go] [gdamore/tcell](https://github.com/gdamore/tcell) Tcell is an alternate terminal package, similar in some ways to termbox, but better in others.
- [**1786**Star][1m] [C++] [apitrace/apitrace](https://github.com/apitrace/apitrace) Tools for tracing OpenGL, Direct3D, and other graphics APIs
- [**1781**Star][26d] [PHP] [ezyang/htmlpurifier](https://github.com/ezyang/htmlpurifier) Standards compliant HTML filter written in PHP
- [**1779**Star][29d] [17mon/china_ip_list](https://github.com/17mon/china_ip_list) 
- [**1771**Star][3y] [ObjC] [alibaba/wax](https://github.com/alibaba/wax) Wax is a framework that lets you write native iPhone apps in Lua.
- [**1761**Star][1y] [JS] [puppeteer/examples](https://github.com/puppeteer/examples) Use case-driven examples for using Puppeteer and headless chrome
- [**1761**Star][13d] [C] [google/wuffs](https://github.com/google/wuffs) Wrangling Untrusted File Formats Safely
- [**1756**Star][16d] [PHP] [wordpress/wordpress-coding-standards](https://github.com/wordpress/wordpress-coding-standards) PHP_CodeSniffer rules (sniffs) to enforce WordPress coding conventions
- [**1727**Star][8d] [TSQL] [brentozarultd/sql-server-first-responder-kit](https://github.com/brentozarultd/sql-server-first-responder-kit) sp_Blitz, sp_BlitzCache, sp_BlitzFirst, sp_BlitzIndex, and other SQL Server scripts for health checks and performance tuning.
- [**1722**Star][4m] [Py] [anorov/cloudflare-scrape](https://github.com/anorov/cloudflare-scrape) A Python module to bypass Cloudflare's anti-bot page.
- [**1714**Star][1m] [Go] [hashicorp/memberlist](https://github.com/hashicorp/memberlist) Golang package for gossip based membership and failure detection
- [**1698**Star][21d] [C++] [microsoft/detours](https://github.com/microsoft/detours) Detours is a software package for monitoring and instrumenting API calls on Windows. It is distributed in source code form.
- [**1694**Star][3y] [CoffeeScript] [okturtles/dnschain](https://github.com/okturtles/dnschain) A blockchain-based DNS + HTTP server that fixes HTTPS security, and more!
- [**1676**Star][10d] [Java] [apache/geode](https://github.com/apache/geode) Apache Geode
- [**1672**Star][7m] [C] [easyhook/easyhook](https://github.com/easyhook/easyhook) The reinvention of Windows API Hooking
- [**1668**Star][3m] [Py] [boppreh/keyboard](https://github.com/boppreh/keyboard) Hook and simulate global keyboard events on Windows and Linux.
- [**1665**Star][4y] [Java] [dodola/hotfix](https://github.com/dodola/hotfix) 安卓App热补丁动态修复框架
- [**1659**Star][25d] [JS] [tylerbrock/mongo-hacker](https://github.com/tylerbrock/mongo-hacker) MongoDB Shell Enhancements for Hackers
- [**1650**Star][13d] [sarojaba/awesome-devblog](https://github.com/sarojaba/awesome-devblog) 어썸데브블로그. 국내 개발 블로그 모음(only 실명으로).
- [**1637**Star][12d] [JS] [efforg/privacybadger](https://github.com/efforg/privacybadger) Privacy Badger is a browser extension that automatically learns to block invisible trackers.
- [**1624**Star][9m] [JS] [localtunnel/server](https://github.com/localtunnel/server) server for localtunnel.me
- [**1620**Star][16d] [C++] [lief-project/lief](https://github.com/lief-project/lief) Library to Instrument Executable Formats
- [**1616**Star][2y] [JS] [addyosmani/a11y](https://github.com/addyosmani/a11y) Accessibility audit tooling for the web (beta)
- [**1592**Star][2m] [ObjC] [ealeksandrov/provisionql](https://github.com/ealeksandrov/provisionql) Quick Look plugin for apps and provisioning profile files
- [**1584**Star][1y] [C] [qihoo360/phptrace](https://github.com/qihoo360/phptrace) A tracing and troubleshooting tool for PHP scripts.
- [**1572**Star][1m] [C] [codahale/bcrypt-ruby](https://github.com/codahale/bcrypt-ruby)  Ruby binding for the OpenBSD bcrypt() password hashing algorithm, allowing you to easily store a secure hash of your users' passwords.
- [**1562**Star][1m] [C] [p-gen/smenu](https://github.com/p-gen/smenu) Terminal utility that reads words from standard input or from a file and creates an interactive selection window just below the cursor. The selected word(s) are sent to standard output for further processing.
- [**1562**Star][19d] [Java] [gchq/gaffer](https://github.com/gchq/Gaffer) A large-scale entity and relation database supporting aggregation of properties
- [**1540**Star][2y] [C++] [hteso/iaito](https://github.com/hteso/iaito) A Qt and C++ GUI for radare2 reverse engineering framework
- [**1015**Star][3y] [C++] [aguinet/wannakey](https://github.com/aguinet/wannakey) Wannacry in-memory key recovery
- [**966**Star][7m] [PHP] [jenssegers/optimus](https://github.com/jenssegers/optimus)  id transformation With this library, you can transform your internal id's to obfuscated integers based on Knuth's integer has和
- [**906**Star][7m] [C++] [dfhack/dfhack](https://github.com/DFHack/dfhack) Memory hacking library for Dwarf Fortress and a set of tools that use it
- [**895**Star][12m] [JS] [levskaya/jslinux-deobfuscated](https://github.com/levskaya/jslinux-deobfuscated) An old version of Mr. Bellard's JSLinux rewritten to be human readable, hand deobfuscated and annotated.
- [**706**Star][1y] [Jupyter Notebook] [anishathalye/obfuscated-gradients](https://github.com/anishathalye/obfuscated-gradients) Obfuscated Gradients Give a False Sense of Security: Circumventing Defenses to Adversarial Examples
- [**658**Star][10m] [Jupyter Notebook] [supercowpowers/data_hacking](https://github.com/SuperCowPowers/data_hacking) Data Hacking Project
- [**657**Star][1y] [Rust] [endgameinc/xori](https://github.com/endgameinc/xori) Xori is an automation-ready disassembly and static analysis library for PE32, 32+ and shellcode
- [**637**Star][21d] [PS] [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) A repository of sysmon configuration modules
- [**587**Star][6m] [nshalabi/sysmontools](https://github.com/nshalabi/sysmontools) Utilities for Sysmon
- [**568**Star][11m] [JS] [raineorshine/solgraph](https://github.com/raineorshine/solgraph) Visualize Solidity control flow for smart contract security analysis.
- [**551**Star][3y] [Makefile] [veficos/reverse-engineering-for-beginners](https://github.com/veficos/reverse-engineering-for-beginners) translate project of Drops
- [**523**Star][2m] [mhaggis/sysmon-dfir](https://github.com/mhaggis/sysmon-dfir) Sources, configuration and how to detect evil things utilizing Microsoft Sysmon.
- [**522**Star][4m] [Java] [java-deobfuscator/deobfuscator](https://github.com/java-deobfuscator/deobfuscator) The real deal
- [**507**Star][8m] [JS] [mindedsecurity/jstillery](https://github.com/mindedsecurity/jstillery) Advanced JavaScript Deobfuscation via Partial Evaluation
- [**480**Star][1y] [ksluckow/awesome-symbolic-execution](https://github.com/ksluckow/awesome-symbolic-execution) A curated list of awesome symbolic execution resources including essential research papers, lectures, videos, and tools.
- [**449**Star][12m] [C++] [ntquery/scylla](https://github.com/ntquery/scylla) Imports Reconstructor
- [**447**Star][3m] [Go] [retroplasma/flyover-reverse-engineering](https://github.com/retroplasma/flyover-reverse-engineering) Reversing Apple's 3D satellite mode
- [**446**Star][11m] [Batchfile] [ion-storm/sysmon-config](https://github.com/ion-storm/sysmon-config) Advanced Sysmon configuration, Installer & Auto Updater with high-quality event tracing
- [**437**Star][2y] [PS] [danielbohannon/revoke-obfuscation](https://github.com/danielbohannon/revoke-obfuscation) PowerShell Obfuscation Detection Framework
- [**408**Star][2y] [Py] [fossfreedom/indicator-sysmonitor](https://github.com/fossfreedom/indicator-sysmonitor) Ubuntu application indicator to show various system parameters
- [**408**Star][19d] [Py] [crytic/slither](https://github.com/crytic/slither) Static Analyzer for Solidity
- [**383**Star][1y] [HTML] [maestron/reverse-engineering-tutorials](https://github.com/maestron/reverse-engineering-tutorials) Reverse Engineering Tutorials
- [**366**Star][10y] [C] [brl/obfuscated-openssh](https://github.com/brl/obfuscated-openssh) strengthens the initial SSH handshake against systems that identify or classify various network protocols by examining data in  transit for static signatures
- [**344**Star][1y] [Ruby] [calebfenton/dex-oracle](https://github.com/calebfenton/dex-oracle) A pattern based Dalvik deobfuscator which uses limited execution to improve semantic analysis
- [**308**Star][25d] [Py] [baderj/domain_generation_algorithms](https://github.com/baderj/domain_generation_algorithms) Some results of my DGA reversing efforts
- [**306**Star][2m] [C] [nagyd/sdlpop](https://github.com/nagyd/sdlpop) An open-source port of Prince of Persia, based on the disassembly of the DOS version.
- [**291**Star][28d] [C] [tomb5/tomb5](https://github.com/tomb5/tomb5) Chronicles Disassembly translated to C source code.
- [**265**Star][3m] [Assembly] [pret/pokeyellow](https://github.com/pret/pokeyellow) Disassembly of Pokemon Yellow
- [**240**Star][4m] [JS] [consensys/surya](https://github.com/consensys/surya) A set of utilities for exploring Solidity contracts
- [**224**Star][2y] [Py] [rub-syssec/syntia](https://github.com/rub-syssec/syntia) Program synthesis based deobfuscation framework for the USENIX 2017 paper "Syntia: Synthesizing the Semantics of Obfuscated Code"
- [**214**Star][2m] [Py] [rpisec/llvm-deobfuscator](https://github.com/rpisec/llvm-deobfuscator) 
- [**211**Star][12m] [Java] [neo23x0/fnord](https://github.com/neo23x0/fnord) Pattern Extractor for Obfuscated Code
- [**198**Star][1m] [F#] [b2r2-org/b2r2](https://github.com/b2r2-org/b2r2) B2R2 is a collection of useful algorithms, functions, and tools for binary analysis.
- [**194**Star][3y] [C#] [codeshark-dev/nofuserex](https://github.com/codeshark-dev/nofuserex) Free deobfuscator for ConfuserEx.
- [**180**Star][3m] [Py] [eth-sri/debin](https://github.com/eth-sri/debin) Machine Learning to Deobfuscate Binaries
- [**174**Star][2y] [C] [geosn0w/reverse-engineering-tutorials](https://github.com/geosn0w/reverse-engineering-tutorials) Some Reverse Engineering Tutorials for Beginners
- [**169**Star][1y] [PS] [mattifestation/pssysmontools](https://github.com/mattifestation/pssysmontools) Sysmon Tools for PowerShell
- [**164**Star][2m] [JS] [lelinhtinh/de4js](https://github.com/lelinhtinh/de4js) JavaScript Deobfuscator and Unpacker
- [**158**Star][6m] [C] [kkamagui/shadow-box-for-x86](https://github.com/kkamagui/shadow-box-for-x86) Lightweight and Practical Kernel Protector for x86 (Presented at BlackHat Asia 2017/2018, beVX 2018 and HITBSecConf 2017)
- [**151**Star][9m] [C] [adrianyy/eacreversing](https://github.com/adrianyy/eacreversing) Reversing EasyAntiCheat.
- [**148**Star][6m] [olafhartong/sysmon-cheatsheet](https://github.com/olafhartong/sysmon-cheatsheet) All sysmon event types and their fields explained
- [**144**Star][2m] [Java] [superblaubeere27/obfuscator](https://github.com/superblaubeere27/obfuscator) A java obfuscator (GUI)
- [**140**Star][12m] [C++] [finixbit/elf-parser](https://github.com/finixbit/elf-parser) Lightweight elf binary parser with no external dependencies - Sections, Symbols, Relocations, Segments
- [**139**Star][7m] [C] [glv2/bruteforce-wallet](https://github.com/glv2/bruteforce-wallet) Try to find the password of an encrypted Peercoin (or Bitcoin, Litecoin, etc...) wallet file.
- [**137**Star][4y] [C] [xairy/kaslr-bypass-via-prefetch](https://github.com/xairy/kaslr-bypass-via-prefetch) A proof-of-concept KASLR bypass for the Linux kernel via timing prefetch (dilettante implementation, better read the original paper:
- [**134**Star][1y] [PS] [darkoperator/posh-sysmon](https://github.com/darkoperator/posh-sysmon) PowerShell module for creating and managing Sysinternals Sysmon config files.
- [**129**Star][3y] [Swift] [magic-akari/wannacry](https://github.com/magic-akari/wannacry) 
- [**122**Star][1y] [PS] [mattifestation/bhusa2018_sysmon](https://github.com/mattifestation/bhusa2018_sysmon) All materials from our Black Hat 2018 "Subverting Sysmon" talk
- [**119**Star][5m] [C#] [akaion/jupiter](https://github.com/akaion/jupiter) A Windows virtual memory editing library with support for pattern scanning.
- [**118**Star][2y] [Py] [malus-security/sandblaster](https://github.com/malus-security/sandblaster) Reversing the Apple sandbox
- [**117**Star][4m] [PS] [thom-s/netsec-ps-scripts](https://github.com/thom-s/netsec-ps-scripts) Collection of PowerShell network security scripts for system administrators.
- [**114**Star][4m] [we5ter/flerken](https://github.com/we5ter/flerken) A Solution For Cross-Platform Obfuscated Commands Detection
- [**111**Star][2y] [Py] [cfsworks/wavebird-reversing](https://github.com/cfsworks/wavebird-reversing) Reverse-engineering the WaveBird protocol for the betterment of mankind
- [**109**Star][1y] [Shell] [jgamblin/blackhat-macos-config](https://github.com/jgamblin/blackhat-macos-config) Configure Your Macbook For Blackhat
- [**109**Star][8m] [C#] [virb3/de4dot-cex](https://github.com/virb3/de4dot-cex) de4dot deobfuscator with full support for vanilla ConfuserEx
- [**108**Star][3y] [ios-reverse-engineering-dev/swift-apps-reverse-engineering](https://github.com/ios-reverse-engineering-dev/swift-apps-reverse-engineering) Swift Apps Reverse Engineering reading book
- [**107**Star][4m] [C#] [matterpreter/shhmon](https://github.com/matterpreter/shhmon) Neutering Sysmon via driver unload
- [**106**Star][4m] [Go] [bnagy/gapstone](https://github.com/bnagy/gapstone) gapstone is a Go binding for the capstone disassembly library
- [**99**Star][4m] [C++] [marcosd4h/sysmonx](https://github.com/marcosd4h/sysmonx) An Augmented Drop-In Replacement of Sysmon
- [**98**Star][1y] [C#] [holly-hacker/eazfixer](https://github.com/holly-hacker/eazfixer) A deobfuscation tool for Eazfuscator.
- [**97**Star][3y] [Py] [fdiskyou/kcshell](https://github.com/fdiskyou/kcshell) 交互式汇编/反汇编 Shell，Python3编写，基于Keystone/Capstone
- [**97**Star][11d] [PHP] [cybercog/laravel-optimus](https://github.com/cybercog/laravel-optimus) Transform your internal id's to obfuscated integers based on Knuth's integer hash.
- [**88**Star][2y] [PS] [danielbohannon/out-fincodedcommand](https://github.com/danielbohannon/out-fincodedcommand) POC Highlighting Obfuscation Techniques used by FIN threat actors based on cmd.exe's replace functionality and cmd.exe/powershell.exe's stdin command invocation capabilities
- [**85**Star][11m] [C++] [basketwill/sysmon_reverse](https://github.com/basketwill/sysmon_reverse) 
- [**82**Star][4m] [blockchainlabsnz/awesome-solidity](https://github.com/blockchainlabsnz/awesome-solidity) A curated list of awesome Solidity resources
- [**80**Star][4m] [sbousseaden/panache_sysmon](https://github.com/sbousseaden/panache_sysmon) A Sysmon Config for APTs Techniques Detection
- [**79**Star][5m] [Assembly] [thecodeartist/elf-parser](https://github.com/thecodeartist/elf-parser) Identifying/Extracting various sections of an ELF file
- [**70**Star][3y] [Py] [antelox/fopo-php-deobfuscator](https://github.com/antelox/fopo-php-deobfuscator) A simple script to deobfuscate PHP file obfuscated with FOPO Obfuscator -
- [**68**Star][5m] [splunk/ta-microsoft-sysmon](https://github.com/splunk/ta-microsoft-sysmon) TA-microsoft-sysmon
- [**67**Star][2y] [Py] [sapir/sonare](https://github.com/sapir/sonare) A Qt-based disassembly viewer based on radare2
- [**64**Star][11m] [Zeek] [salesforce/bro-sysmon](https://github.com/salesforce/bro-sysmon) How to Zeek Sysmon Logs!
- [**60**Star][1y] [Java] [java-deobfuscator/deobfuscator-gui](https://github.com/java-deobfuscator/deobfuscator-gui) An awesome GUI for an awesome deobfuscator
- [**60**Star][4y] [Objective-C++] [steven-michaud/reverse-engineering-on-osx](https://github.com/steven-michaud/reverse-engineering-on-osx) Reverse Engineering on OS X
- [**56**Star][1y] [Nix] [dapphub/ds-auth](https://github.com/dapphub/ds-auth) Updatable, unobtrusive Solidity authorization pattern
- [**56**Star][7m] [TS] [geeksonsecurity/illuminatejs](https://github.com/geeksonsecurity/illuminatejs) IlluminateJs is a static JavaScript deobfuscator
- [**55**Star][5m] [basketwill/z0bpctools](https://github.com/basketwill/z0bpctools) 一个windows反汇编工具，界面风格防OllyDbg 利用业余开发了一款类似仿OLlyDbg界面的 IDA静态反编译工具，目前是1.0版本，功能不是很强大但是基本功能有了
- [**55**Star][2y] [TeX] [season-lab/survey-symbolic-execution](https://github.com/season-lab/survey-symbolic-execution) 对有关符号执行相关工具和技术的调查
- [**55**Star][3m] [C] [resilar/crchack](https://github.com/resilar/crchack) Reversing CRC for fun and profit
- [**53**Star][7y] [C++] [eschweiler/proreversing](https://github.com/eschweiler/proreversing) Open and generic Anti-Anti Reversing Framework. Works in 32 and 64 bits.
- [**53**Star][3y] [PS] [elevenpaths/telefonica-wannacry-filerestorer](https://github.com/elevenpaths/telefonica-wannacry-filerestorer) Tool to restore some WannaCry files which encryption weren't finish properly
- [**52**Star][1m] [C] [danielkrupinski/vac](https://github.com/danielkrupinski/vac) Source code of Valve Anti-Cheat obtained from disassembly of compiled modules
- [**52**Star][11m] [Assembly] [pret/pokepinball](https://github.com/pret/pokepinball) disassembly of pokémon pinball
- [**50**Star][2y] [JS] [ericr/sol-function-profiler](https://github.com/ericr/sol-function-profiler) Solidity Contract Function Profiler
- [**50**Star][2y] [Py] [sfwishes/ollvm_de_fla](https://github.com/sfwishes/ollvm_de_fla) deobfuscation ollvm's fla
- [**47**Star][5y] [jameshabben/sysmon-queries](https://github.com/jameshabben/sysmon-queries) Queries to parse sysmon event log file with microsoft logparser
- [**47**Star][7m] [C++] [talvos/talvos](https://github.com/talvos/talvos) Talvos is a dynamic-analysis framework and debugger for Vulkan/SPIR-V programs.
- [**45**Star][14d] [Assembly] [drenn1/oracles-disasm](https://github.com/Drenn1/oracles-disasm) Disassembly of Oracle of Ages and Seasons
- [**45**Star][2m] [Lua] [dsasmblr/cheat-engine](https://github.com/dsasmblr/cheat-engine) Cheat Engine scripts, tutorials, tools, and more.
- [**41**Star][2y] [C] [cocoahuke/mackextdump](https://github.com/cocoahuke/mackextdump) mackextdump：从macOS中dump Kext信息
- [**40**Star][3m] [jsecurity101/windows-api-to-sysmon-events](https://github.com/jsecurity101/windows-api-to-sysmon-events) A repository that maps API calls to Sysmon Event ID's.
- [**39**Star][1y] [Py] [dissectmalware/batch_deobfuscator](https://github.com/dissectmalware/batch_deobfuscator) Deobfuscate batch scripts obfuscated using string substitution and escape character techniques.
- [**38**Star][5m] [Assembly] [marespiaut/rayman_disasm](https://github.com/marespiaut/rayman_disasm) Reverse-engineering effort for the 1995 MS-DOS game “Rayman”
- [**36**Star][2y] [Py] [extremecoders-re/bytecode_simplifier](https://github.com/extremecoders-re/bytecode_simplifier) A generic deobfuscator for PjOrion obfuscated python scripts
- [**36**Star][2y] [Py] [extremecoders-re/pjorion-deobfuscator](https://github.com/extremecoders-re/pjorion-deobfuscator) A deobfuscator for PjOrion, python cfg generator and more
- [**36**Star][3y] [C++] [steven-michaud/sandboxmirror](https://github.com/steven-michaud/sandboxmirror) Tool for reverse-engineering Apple's sandbox
- [**35**Star][4y] [C#] [bnagy/crabstone](https://github.com/bnagy/crabstone) crabstone is a Ruby binding to the capstone disassembly library by Nguyen Anh Quynh
- [**35**Star][3y] [C] [topcss/wannacry](https://github.com/topcss/wannacry) 勒索病毒WannaCry反编译源码
- [**34**Star][6y] [JS] [michenriksen/hackpad](https://github.com/michenriksen/hackpad) A web application hacker's toolbox. Base64 encoding/decoding, URL encoding/decoding, MD5/SHA1/SHA256/HMAC hashing, code deobfuscation, formatting, highlighting and much more.
- [**33**Star][1y] [ObjC] [jakeajames/reverse-engineering](https://github.com/jakeajames/reverse-engineering) nothing important
- [**32**Star][1y] [mhaggis/sysmon-splunk-app](https://github.com/mhaggis/sysmon-splunk-app) Sysmon Splunk App
- [**31**Star][3y] [mhaggis/app_splunk_sysmon_hunter](https://github.com/mhaggis/app_splunk_sysmon_hunter) Splunk App to assist Sysmon Threat Hunting
- [**31**Star][4y] [Pascal] [pigrecos/codedeobfuscator](https://github.com/pigrecos/codedeobfuscator) Code Deobfuscator
- [**29**Star][2y] [C++] [nuand/kalibrate-bladerf](https://github.com/nuand/kalibrate-bladerf) kalibrate-bladeRF
- [**27**Star][2m] [JS] [b-mueller/sabre](https://github.com/b-mueller/sabre) Security analyzer for Solidity smart contracts. Uses MythX, the premier smart contract security service.
- [**27**Star][2m] [C] [usineur/sdlpop](https://github.com/usineur/SDLPoP) An open-source port of Prince of Persia, based on the disassembly of the DOS version.
- [**24**Star][5y] [JS] [vector35/hackinggames](https://github.com/vector35/hackinggames) Hacking Games in a Hacked Game
- [**22**Star][2y] [Py] [zigzag2050/mzphp2-deobfuscator](https://github.com/zigzag2050/mzphp2-deobfuscator) A de-obfuscate tool for code generated by mzphp2. 用于解混淆mzphp2加密的php文件的工具。
- [**21**Star][1y] [Lua] [yoshifan/ram-watch-cheat-engine](https://github.com/yoshifan/ram-watch-cheat-engine) Lua script framework for RAM watch displays using Cheat Engine, with a focus on Dolphin emulator.
- [**21**Star][2m] [Py] [verabe/veriman](https://github.com/verabe/veriman) Analysis tool for Solidity smart contracts. Prototype.
- [**20**Star][1y] [Batchfile] [olafhartong/ta-sysmon-deploy](https://github.com/olafhartong/ta-sysmon-deploy) Deploy and maintain Symon through the Splunk Deployment Sever


***


## <a id="bc2b78af683e7ba983205592de8c3a7a"></a>Tool-Other


- [**1534**Star][3y] [Py] [x0rz/eqgrp_lost_in_translation](https://github.com/x0rz/eqgrp_lost_in_translation) Decrypted content of odd.tar.xz.gpg, swift.tar.xz.gpg and windows.tar.xz.gpg
- [**669**Star][3y] [Py] [n1nj4sec/memorpy](https://github.com/n1nj4sec/memorpy) Python library using ctypes to search/edit windows / linux / macOS / SunOS programs memory
- [**159**Star][5y] [C#] [radiowar/nfcgui](https://github.com/radiowar/nfcgui) GUI tool for NFC protocol analysis


***


## <a id="4fe330ae3e5ce0b39735b1bfea4528af"></a>angr


### <a id="1ede5ade1e55074922eb4b6386f5ca65"></a>Tool


- [**534**Star][12d] [Py] [angr/angr-doc](https://github.com/angr/angr-doc) Documentation for the angr suite
- [**305**Star][2m] [Py] [salls/angrop](https://github.com/salls/angrop) a rop gadget finder and chain builder 
- [**246**Star][2y] [Py] [jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf) 
- [**197**Star][18d] [Py] [angr/angr-management](https://github.com/angr/angr-management) A GUI for angr. Being developed *very* slowly.
- [**195**Star][2y] [PS] [vysecurity/angrypuppy](https://github.com/vysecurity/ANGRYPUPPY) Bloodhound Attack Path Automation in CobaltStrike
- [**169**Star][2y] [HTML] [ihebski/angryfuzzer](https://github.com/ihebski/angryfuzzer) Tools for information gathering
- [**122**Star][1y] [Py] [axt/angr-utils](https://github.com/axt/angr-utils) Handy utilities for the angr binary analysis framework, most notably CFG visualization
- [**115**Star][6m] [Py] [andreafioraldi/angrgdb](https://github.com/andreafioraldi/angrgdb) Use angr inside GDB. Create an angr state from the current debugger state.
- [**106**Star][1y] [Py] [sidechannelmarvels/jeangrey](https://github.com/sidechannelmarvels/jeangrey) A tool to perform differential fault analysis attacks (DFA).
- [**91**Star][1y] [Py] [fsecurelabs/z3_and_angr_binary_analysis_workshop](https://github.com/FSecureLABS/z3_and_angr_binary_analysis_workshop) Code and exercises for a workshop on z3 and angr
- [**64**Star][17d] [Shell] [angr/angr-dev](https://github.com/angr/angr-dev) Some helper scripts to set up an environment for angr development.
- [**64**Star][7m] [Assembly] [cdisselkoen/pitchfork](https://github.com/cdisselkoen/pitchfork) Detecting Spectre vulnerabilities using symbolic execution, built on angr (github.com/angr/angr)
- [**61**Star][4y] [Shell] [praetorian-code/epictreasure](https://github.com/praetorian-code/epictreasure) radare, angr, pwndbg, binjitsu, ect in a box ready for pwning
- [**47**Star][25d] [Py] [ercoppa/symbolic-execution-tutorial](https://github.com/ercoppa/symbolic-execution-tutorial) Tutorial on Symbolic Execution. Hands-on session is based on the angr framework.
- [**33**Star][14d] [Py] [angr/angr-platforms](https://github.com/angr/angr-platforms) A collection of extensions to angr to handle new platforms
- [**30**Star][12d] [C] [angr/binaries](https://github.com/angr/binaries) A repository with binaries for angr tests and examples.
- [**24**Star][7m] [Py] [andreafioraldi/r2angrdbg](https://github.com/andreafioraldi/r2angrdbg) 在 radare2 调试器中使用 angr
- [**23**Star][2y] [Py] [fabros/angr-antievasion](https://github.com/fabros/angr-antievasion) Final project for the M.Sc. in Engineering in Computer Science at Università degli Studi di Roma "La Sapienza" (A.Y. 2016/2017).
- [**23**Star][4y] [bannsec/angr-windows](https://github.com/bannsec/angr-Windows) Windows builds for use with angr framework
- [**22**Star][23d] [Py] [fmagin/angr-cli](https://github.com/fmagin/angr-cli) Repo for various angr ipython features to give it more of a cli feeling
- [**20**Star][2y] [PS] [mdsecactivebreach/angrypuppy](https://github.com/mdsecactivebreach/angrypuppy) Bloodhound Attack Path Automation in CobaltStrike
- [**19**Star][2y] [Py] [brandon-everhart/angryida](https://github.com/brandon-everhart/angryida) Python based angr plug in for IDA Pro.
    - Also In Section: [IDA->Tools->Import Export->No Category](#8ad723b704b044e664970b11ce103c09) |
- [**12**Star][1y] [Py] [ash09/angr-static-analysis-for-vuzzer64](https://github.com/ash09/angr-static-analysis-for-vuzzer64) Angr-based static analysis tool for vusec/vuzzer64 fuzzing tool
- [**11**Star][3y] [Py] [n00py/angryhippo](https://github.com/n00py/angryhippo) Exploiting the HippoConnect protocol for HippoRemote
- [**8**Star][1y] [C] [shellphish/patcherex](https://github.com/shellphish/patcherex) please go to angr/patcherex instead of this!
- [**8**Star][3y] [C++] [project64/angrylion-rdp](https://github.com/project64/angrylion-rdp) 
- [**3**Star][2y] [Py] [futaki-futaba/angr-sample](https://github.com/futaki-futaba/angr-sample) angr 7向けのサンプルプログラムです


### <a id="042ef9d415350eeb97ac2539c2fa530e"></a>Post


- 2016.04 [] [Solving kao's toy project with symbolic execution and angr](https://0xec.blogspot.com/2016/04/solving-kaos-toy-project-with-symbolic.html)
- 2016.02 [theobsidiantower] [Angr and me](https://theobsidiantower.com/2016/02/11/4047a80b3927bd0a09363e7ccd202effe4b336aa.html)
- 2014.08 [3xp10it] [angr解题](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/11/16/angr%E8%A7%A3%E9%A2%98/)
- 2014.08 [3xp10it] [angr解题](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/11/16/angr%E8%A7%A3%E9%A2%98/)




***


## <a id="324874bb7c3ead94eae6f1fa1af4fb68"></a>Debug


### <a id="d22bd989b2fdaeda14b64343b472dfb6"></a>Tool


- [**1544**Star][6y] [Py] [google/pyringe](https://github.com/google/pyringe) Debugger capable of attaching to and injecting code into python processes.
- [**1450**Star][10d] [Go] [google/gapid](https://github.com/google/gapid) Graphics API Debugger
- [**1422**Star][17d] [C++] [eteran/edb-debugger](https://github.com/eteran/edb-debugger) edb is a cross platform AArch32/x86/x86-64 debugger.
- [**1413**Star][19d] [Go] [cosmos72/gomacro](https://github.com/cosmos72/gomacro) Interactive Go interpreter and debugger with REPL, Eval, generics and Lisp-like macros
- [**1374**Star][4y] [C++] [valvesoftware/vogl](https://github.com/valvesoftware/vogl) OpenGL capture / playback debugger.
- [**1275**Star][4m] [Go] [solo-io/squash](https://github.com/solo-io/squash) The debugger for microservices
- [**1147**Star][5m] [C++] [cgdb/cgdb](https://github.com/cgdb/cgdb) Console front-end to the GNU debugger
- [**1128**Star][20d] [C] [blacksphere/blackmagic](https://github.com/blacksphere/blackmagic) In application debugger for ARM Cortex microcontrollers.
- [**899**Star][10d] [Py] [derekselander/lldb](https://github.com/derekselander/lldb) A collection of LLDB aliases/regexes and Python scripts to aid in your debugging sessions
- [**836**Star][8d] [C++] [tasvideos/bizhawk](https://github.com/tasvideos/bizhawk) BizHawk is a multi-system emulator written in C#. BizHawk provides nice features for casual gamers such as full screen, and joypad support in addition to full rerecording and debugging tools for all system cores.
- [**708**Star][2y] [Go] [sidkshatriya/dontbug](https://github.com/sidkshatriya/dontbug) Dontbug is a reverse debugger for PHP
- [**627**Star][3y] [C] [chokepoint/azazel](https://github.com/chokepoint/azazel) Azazel is a userland rootkit based off of the original LD_PRELOAD technique from Jynx rootkit. It is more robust and has additional features, and focuses heavily around anti-debugging and anti-detection.
- [**573**Star][4y] [C++] [microsoft/iediagnosticsadapter](https://github.com/microsoft/iediagnosticsadapter) IE Diagnostics Adapter is a standalone exe that enables tools to debug and diagnose IE11 using the Chrome remote debug protocol.
- [**560**Star][21d] [C#] [microsoft/miengine](https://github.com/microsoft/miengine) The Visual Studio MI Debug Engine ("MIEngine") provides an open-source Visual Studio Debugger extension that works with MI-enabled debuggers such as gdb, lldb, and clrdbg.
- [**521**Star][1y] [C] [wubingzheng/memleax](https://github.com/wubingzheng/memleax) debugs memory leak of running process. Not maintained anymore, try `libleak` please.
- [**462**Star][5m] [C++] [emoon/prodbg](https://github.com/emoon/prodbg) Debugging the way it's meant to be done
- [**430**Star][4y] [C] [alonho/pytrace](https://github.com/alonho/pytrace) pytrace is a fast python tracer. it records function calls, arguments and return values. can be used for debugging and profiling.
- [**423**Star][4m] [C++] [cobaltfusion/debugviewpp](https://github.com/cobaltfusion/debugviewpp) DebugView++, collects, views, filters your application logs, and highlights information that is important to you!
- [**418**Star][26d] [C++] [simonkagstrom/kcov](https://github.com/simonkagstrom/kcov) Code coverage tool for compiled programs, Python and Bash which uses debugging information to collect and report data without special compilation options
- [**377**Star][1m] [Py] [pdbpp/pdbpp](https://github.com/pdbpp/pdbpp) pdb++, a drop-in replacement for pdb (the Python debugger)
- [**354**Star][2y] [C++] [glsl-debugger/glsl-debugger](https://github.com/glsl-debugger/glsl-debugger) GLSL source level debugger.
- [**354**Star][8y] [Py] [openrce/pydbg](https://github.com/openrce/pydbg) A pure-python win32 debugger interface.
- [**332**Star][8m] [Py] [romanvm/python-web-pdb](https://github.com/romanvm/python-web-pdb) Web-based remote UI for Python's PDB debugger
- [**306**Star][21d] [Java] [widdix/aws-s3-virusscan](https://github.com/widdix/aws-s3-virusscan) Free Antivirus for S3 Buckets
- [**291**Star][12d] [Py] [sosreport/sos](https://github.com/sosreport/sos) A unified tool for collecting system logs and other debug information
- [**289**Star][3y] [C++] [develbranch/tinyantivirus](https://github.com/develbranch/tinyantivirus) TinyAntivirus is an open source antivirus engine designed for detecting polymorphic virus and disinfecting it.
- [**288**Star][2y] [Java] [cnfree/eclipse-class-decompiler](https://github.com/cnfree/eclipse-class-decompiler) Eclipse Class Decompiler integrates JD, Jad, FernFlower, CFR, Procyon seamlessly with Eclipse and allows Java developers to debug class files without source code directly
- [**285**Star][2m] [C++] [changeofpace/viviennevmm](https://github.com/changeofpace/viviennevmm) VivienneVMM is a stealthy debugging framework implemented via an Intel VT-x hypervisor.
- [**272**Star][4m] [Py] [mariovilas/winappdbg](https://github.com/mariovilas/winappdbg) WinAppDbg Debugger
- [**270**Star][21d] [Py] [ionelmc/python-manhole](https://github.com/ionelmc/python-manhole) Debugging manhole for python applications.
- [**267**Star][4y] [C] [blankwall/macdbg](https://github.com/blankwall/macdbg) Simple easy to use C and python debugging framework for OSX
- [**255**Star][3y] [Py] [airsage/petrel](https://github.com/airsage/petrel) Tools for writing, submitting, debugging, and monitoring Storm topologies in pure Python
- [**250**Star][2y] [Py] [dbgx/lldb.nvim](https://github.com/dbgx/lldb.nvim) Debugger integration with a focus on ease-of-use.
- [**250**Star][2m] [Py] [quantopian/qdb](https://github.com/quantopian/qdb) Quantopian Remote Debugger for Python
- [**240**Star][6m] [C++] [facebook/ds2](https://github.com/facebook/ds2) Debug server for lldb.
- [**239**Star][8m] [C++] [strivexjun/xantidebug](https://github.com/strivexjun/xantidebug) VMProtect 3.x Anti-debug Method Improved
- [**239**Star][8m] [Py] [beeware/bugjar](https://github.com/beeware/bugjar) A interactive graphical debugger for Python code.
- [**233**Star][2m] [Py] [gilligan/vim-lldb](https://github.com/gilligan/vim-lldb) lldb debugger integration plugin for vim
- [**220**Star][9m] [letoram/senseye](https://github.com/letoram/senseye) Dynamic Visual Debugging / Reverse Engineering Toolsuite
- [**218**Star][2m] [Py] [nteseyes/pylane](https://github.com/nteseyes/pylane) An python vm injector with debug tools, based on gdb.
- [**213**Star][12d] [C++] [thalium/icebox](https://github.com/thalium/icebox) Virtual Machine Introspection, Tracing & Debugging
- [**209**Star][2m] [C] [joyent/mdb_v8](https://github.com/joyent/mdb_v8) postmortem debugging for Node.js and other V8-based programs
- [**200**Star][6m] [C++] [rainers/cv2pdb](https://github.com/rainers/cv2pdb) converter of DMD CodeView/DWARF debug information to PDB files
- [**184**Star][6m] [C] [therealsaumil/static-arm-bins](https://github.com/therealsaumil/static-arm-bins) 静态编译的arm二进制文件, 用于调试和运行时分析
- [**182**Star][5y] [C] [gdbinit/onyx-the-black-cat](https://github.com/gdbinit/onyx-the-black-cat) Kernel extension to disable anti-debug tricks and other useful XNU "features"
- [**164**Star][12d] [C++] [devinacker/bsnes-plus](https://github.com/devinacker/bsnes-plus) debug-oriented fork of bsnes
- [**163**Star][3m] [JS] [ant4g0nist/vegvisir](https://github.com/ant4g0nist/vegvisir) 基于浏览器的LLDB 调试器
- [**163**Star][1m] [C++] [jrfonseca/drmingw](https://github.com/jrfonseca/drmingw) Postmortem debugging tools for MinGW.
- [**157**Star][2y] [C] [armadito/armadito-av](https://github.com/armadito/armadito-av) Armadito antivirus main repository
- [**154**Star][4y] [Py] [kbandla/immunitydebugger](https://github.com/kbandla/immunitydebugger) ImmunityDebugger
- [**152**Star][5y] [Shell] [hellman/fixenv](https://github.com/hellman/fixenv) Fix stack addresses (when no ASLR) with and without debugging
- [**151**Star][2y] [Py] [reswitched/cagetheunicorn](https://github.com/reswitched/cagetheunicorn) Debugging/emulating environment for Switch code
- [**146**Star][1m] [Py] [wenzel/pyvmidbg](https://github.com/wenzel/pyvmidbg) LibVMI-based debug server, implemented in Python. Building a guest aware, stealth and agentless full-system debugger
- [**142**Star][2y] [C++] [honorarybot/pulsedbg](https://github.com/honorarybot/pulsedbg) Hypervisor-based debugger
- [**137**Star][9m] [Py] [nh2/strace-pipes-presentation](https://github.com/nh2/strace-pipes-presentation) 利用strace+管道/socket进行调试
- [**133**Star][4y] [C] [jvoisin/pangu](https://github.com/jvoisin/pangu) Toolkit to detect/crash/attack GNU debugging-related tools
- [**125**Star][5m] [Py] [igio90/uddbg](https://github.com/igio90/uddbg) A gdb like debugger that provide a runtime env to unicorn emulator and additionals features!
- [**124**Star][3y] [Py] [alonemonkey/antiantidebug](https://github.com/alonemonkey/antiantidebug) tweak、 lldb python for anti anti debug
- [**120**Star][21d] [C++] [intel/opencl-intercept-layer](https://github.com/intel/opencl-intercept-layer) Intercept Layer for Debugging and Analyzing OpenCL Applications
- [**117**Star][4y] [Shell] [dholm/dotgdb](https://github.com/dholm/dotgdb) GDB scripts to add support for low level debugging and reverse engineering
- [**116**Star][2y] [C++] [skylined/edgedbg](https://github.com/skylined/edgedbg) A simple command line exe to start and debug the Microsoft Edge browser.
- [**109**Star][3m] [C] [david-reguera-garcia-dreg/dbgchild](https://github.com/david-reguera-garcia-dreg/dbgchild) Debug Child Process Tool (auto attach)
- [**108**Star][1m] [Pascal] [fenix01/cheatengine-library](https://github.com/fenix01/cheatengine-library) Cheat Engine Library is based on CheatEngine a debugger and coding environment particularly aimed at games, but can also be used for other purposes like debugging applications and used in schools for teaching how computers work
- [**105**Star][2y] [C] [formyown/alesense-antivirus](https://github.com/formyown/alesense-antivirus) 一款拥有完整交互界面与驱动级拦截能力的开源杀毒软件
- [**104**Star][1m] [C] [checkpointsw/scout](https://github.com/checkpointsw/scout) Instruction based research debugger
- [**103**Star][18d] [stonedreamforest/mirage](https://github.com/stonedreamforest/mirage) kernel-mode Anti-Anti-Debug plugin. based on intel vt-x && ept technology
- [**95**Star][2y] [C] [cetfor/antidbg](https://github.com/cetfor/antidbg) A bunch of Windows anti-debugging tricks.
- [**93**Star][12d] [JS] [microsoftedge/jsdbg](https://github.com/microsoftedge/jsdbg) Debugging extensions for Microsoft Edge and other Chromium-based browsers
- [**86**Star][4y] [Py] [sogeti-esec-lab/lkd](https://github.com/sogeti-esec-lab/lkd) Local Kernel Debugger (LKD) is a python wrapper around dbgengine.dll
- [**86**Star][2y] [Py] [wasiher/chrome_remote_interface_python](https://github.com/wasiher/chrome_remote_interface_python) Chrome Debugging Protocol interface for Python
- [**86**Star][7y] [Py] [stevenseeley/heaper](https://github.com/stevenseeley/heaper) heaper, an advanced heap analysis plugin for Immunity Debugger
- [**85**Star][21d] [Py] [rocky/python2-trepan](https://github.com/rocky/python2-trepan) A gdb-like Python 2.x Debugger in the Trepan family
- [**82**Star][3m] [C] [taviso/cefdebug](https://github.com/taviso/cefdebug) Minimal code to connect to a CEF debugger.
- [**73**Star][5m] [0xd4d/dnspy-unity-mono](https://github.com/0xd4d/dnspy-unity-mono) Fork of Unity mono that's used to compile mono.dll with debugging support enabled
- [**70**Star][7m] [C++] [thomasthelen/antidebugging](https://github.com/thomasthelen/antidebugging) A collection of c++ programs that demonstrate common ways to detect the presence of an attached debugger.
- [**70**Star][4y] [C++] [waleedassar/antidebug](https://github.com/waleedassar/antidebug) Collection Of Anti-Debugging Tricks
- [**65**Star][5m] [C++] [nccgroup/xendbg](https://github.com/nccgroup/xendbg) A feature-complete reference implementation of a modern Xen VMI debugger.
- [**64**Star][4y] [C#] [wintellect/procmondebugoutput](https://github.com/wintellect/procmondebugoutput) See your trace statements in Sysinternals Process Monitor
- [**59**Star][4y] [JS] [auth0-blog/react-flux-debug-actions-sample](https://github.com/auth0-blog/react-flux-debug-actions-sample) This repository shows how you can use Flux actions to reproduce your user's issues in your own browser
- [**58**Star][3m] [Py] [quarkslab/lldbagility](https://github.com/quarkslab/lldbagility) A tool for debugging macOS virtual machines
- [**57**Star][6m] [JS] [pownjs/pown-cdb](https://github.com/pownjs/pown-cdb) Automate common Chrome Debug Protocol tasks to help debug web applications from the command-line and actively monitor and intercept HTTP requests and responses.
- [**54**Star][3m] [C#] [southpolenator/sharpdebug](https://github.com/southpolenator/SharpDebug) C# debugging automation tool
- [**51**Star][3m] [C#] [smourier/tracespy](https://github.com/smourier/tracespy) TraceSpy is a pure .NET, 100% free and open source, alternative to the very popular SysInternals DebugView tool.
- [**49**Star][1y] [C++] [alphaseclab/anti-debug](https://github.com/alphaseclab/anti-debug) 
- [**48**Star][4m] [blackint3/awesome-debugging](https://github.com/blackint3/awesome-debugging) Why Debugging?（为什么要调试？）
- [**48**Star][9m] [C++] [stoyan-shopov/troll](https://github.com/stoyan-shopov/troll) troll：ARM Cortex-M 处理器 C 语言源码调试器
- [**44**Star][1y] [C#] [micli/netcoredebugging](https://github.com/micli/netcoredebugging) A repository maintains the book of ".NET Core application debugging" sample code.
- [**44**Star][2y] [Py] [zedshaw/zadm4py](https://github.com/zedshaw/zadm4py) Zed's Awesome Debug Macros for Python
- [**43**Star][1y] [C++] [johnsonjason/rvdbg](https://github.com/johnsonjason/RVDbg) RVDbg is a debugger/exception handler for Windows processes and has the capability to circumvent anti-debugging techniques. (Cleaner, documented code base being worked on in: core branch)
- [**42**Star][1m] [SystemVerilog] [azonenberg/starshipraider](https://github.com/azonenberg/starshipraider) High performance embedded systems debug/reverse engineering platform
- [**42**Star][5y] [C] [cemeyer/msp430-emu-uctf](https://github.com/cemeyer/msp430-emu-uctf) msp430 emulator for uctf (with remote GDB debugging, reverse debugging, and optional symbolic execution)
- [**42**Star][2m] [Erlang] [etnt/edbg](https://github.com/etnt/edbg) edbg：基于 tty 的 Erlang 调试/追踪接口
- [**41**Star][4y] [Py] [crowdstrike/pyspresso](https://github.com/crowdstrike/pyspresso) The pyspresso package is a Python-based framework for debugging Java.
- [**41**Star][2y] [C] [seemoo-lab/nexmon_debugger](https://github.com/seemoo-lab/nexmon_debugger) Debugger with hardware breakpoints and memory watchpoints for BCM4339 Wi-Fi chips
- [**39**Star][7y] [C] [gdbinit/gimmedebugah](https://github.com/gdbinit/gimmedebugah) A small utility to inject a Info.plist into binaries.
- [**38**Star][2y] [C] [shellbombs/strongod](https://github.com/shellbombs/strongod) StrongOD(anti anti-debug plugin) driver source code.
- [**37**Star][3y] [C] [0xbadc0de1/vmp_dbg](https://github.com/0xbadc0de1/vmp_dbg) This is a VmProtect integrated debugger, that will essentially allow you to disasm and debug vmp partially virtualized functions at the vmp bytecode level. It was made using TitanEngine for the debug engine and Qt for the gui. Do not expect much of it and feel free to report any bugs.
- [**36**Star][3y] [C] [adamgreen/mri](https://github.com/adamgreen/mri) MRI - Monitor for Remote Inspection. The gdb compatible debug monitor for Cortex-M devices.
- [**35**Star][2y] [Py] [meyer9/ethdasm](https://github.com/meyer9/ethdasm) Tool for auditing Ethereum contracts
- [**35**Star][2m] [C] [gdbinit/efi_dxe_emulator](https://github.com/gdbinit/efi_dxe_emulator) EFI DXE Emulator and Interactive Debugger
- [**34**Star][2y] [Py] [g2p/vido](https://github.com/g2p/vido) wrap commands in throwaway virtual machines — easy kernel debugging and regression testing
- [**32**Star][4m] [C++] [creaink/ucom](https://github.com/creaink/ucom) A simple Serial-Port/TCP/UDP debugging tool.
- [**32**Star][4m] [C++] [imugee/xdv](https://github.com/imugee/xdv) XDV is disassembler or debugger that works based on the extension plugin.
- [**29**Star][6m] [C++] [marakew/syser](https://github.com/marakew/syser) syser debugger x32/x64 ring3
- [**29**Star][3m] [C++] [vertextoedge/windowfunctiontracer](https://github.com/vertextoedge/windowfunctiontracer) Window Executable file Function tracer using Debugging API
- [**28**Star][2y] [PS] [enddo/hatdbg](https://github.com/enddo/hatdbg) Minimal WIN32 Debugger in powershell
- [**28**Star][7y] [C] [jonathansalwan/vmndh-2k12](https://github.com/jonathansalwan/vmndh-2k12) Emulator, debugger and compiler for the NDH architecture - Emulator for CTF NDH 2k12
- [**27**Star][8y] [Py] [fitblip/pydbg](https://github.com/fitblip/pydbg) A pure-python win32 debugger interface.
- [**27**Star][2y] [C] [okazakinagisa/vtbaseddebuggerwin7](https://github.com/okazakinagisa/vtbaseddebuggerwin7) Simple kernelmode driver.
- [**26**Star][6y] [Py] [fireeye/pycommands](https://github.com/fireeye/pycommands) PyCommand Scripts for Immunity Debugger
- [**25**Star][3y] [C] [jacktang310/kerneldebugonnexus6p](https://github.com/jacktang310/kerneldebugonnexus6p) 
- [**24**Star][1y] [Py] [cosine0/amphitrite](https://github.com/cosine0/amphitrite) Symbolic debugging tool using JonathanSalwan/Triton
- [**22**Star][8m] [Py] [laanwj/dwarf_to_c](https://github.com/laanwj/dwarf_to_c) Tool to recover C headers (types, function signatures) from DWARF debug data
- [**22**Star][1y] [C#] [malcomvetter/antidebug](https://github.com/malcomvetter/antidebug) PoC: Prevent a debugger from attaching to managed .NET processes via a watcher process code pattern.
- [**22**Star][3y] [Assembly] [osandamalith/anti-debug](https://github.com/osandamalith/anti-debug) Some of the Anti-Debugging Tricks
- [**20**Star][5y] [C] [tongzeyu/hooksysenter](https://github.com/tongzeyu/hooksysenter) hook sysenter，重载内核，下硬件断点到debugport，防止debugport清零


### <a id="136c41f2d05739a74c6ec7d8a84df1e8"></a>Post






***


## <a id="9f8d3f2c9e46fbe6c25c22285c8226df"></a>BAP


### <a id="f10e9553770db6f98e8619dcd74166ef"></a>Tool


- [**1106**Star][14d] [OCaml] [binaryanalysisplatform/bap](https://github.com/binaryanalysisplatform/bap) Binary Analysis Platform
- [**411**Star][13d] [HTML] [w3c/webappsec](https://github.com/w3c/webappsec) Web Application Security Working Group repo
- [**299**Star][17d] [JS] [w3c/webappsec-trusted-types](https://github.com/w3c/webappsec-trusted-types) A browser API to prevent DOM-Based Cross Site Scripting in modern web applications.
- [**289**Star][3y] [Py] [dhilipsiva/webapp-checklist](https://github.com/dhilipsiva/webapp-checklist) Technical details that a programmer of a web application should consider before making the site public.
- [**126**Star][7y] [pwnwiki/webappdefaultsdb](https://github.com/pwnwiki/webappdefaultsdb) A DB of known Web Application Admin URLS, Username/Password Combos and Exploits
- [**106**Star][19d] [Py] [ajinabraham/webappsec](https://github.com/ajinabraham/webappsec) Web Application Security
- [**101**Star][1m] [HTML] [w3c/webappsec-csp](https://github.com/w3c/webappsec-csp) WebAppSec Content Security Policy
- [**61**Star][7y] [JS] [enablesecurity/webapp-exploit-payloads](https://github.com/EnableSecurity/Webapp-Exploit-Payloads) a collection of payloads for common webapps
- [**52**Star][6y] [Py] [lijiejie/outlook_webapp_brute](https://github.com/lijiejie/outlook_webapp_brute) Microsoft Outlook WebAPP Brute
- [**45**Star][9m] [Py] [binaryanalysisplatform/bap-tutorial](https://github.com/binaryanalysisplatform/bap-tutorial) The BAP tutorial
- [**35**Star][5y] [OCaml] [argp/bap](https://github.com/argp/bap) Binary Analysis Platform -- I will try to keep this updated with patches, fixes, etc.
- [**28**Star][5y] [Py] [infosec-au/webappsec-toolkit](https://github.com/infosec-au/webappsec-toolkit) Web Application Security related tools. Includes backdoors, proof of concepts and tricks
- [**26**Star][2y] [JS] [bkimminich/webappsec-nutshell](https://github.com/bkimminich/webappsec-nutshell) An ultra-compact intro (or refresher) to Web Application Security.
- [**16**Star][4y] [Py] [redcanaryco/cbapi2](https://github.com/redcanaryco/cbapi2) Red Canary Carbon Black API
- [**16**Star][1y] [C#] [jpginc/xbapappwhitelistbypasspoc](https://github.com/jpginc/xbapappwhitelistbypasspoc) 
- [**15**Star][2y] [Rust] [maurer/bap-rust](https://github.com/maurer/bap-rust) 
- [**11**Star][2m] [OCaml] [binaryanalysisplatform/bap-bindings](https://github.com/binaryanalysisplatform/bap-bindings) C Bindings to BAP
- [**10**Star][3y] [Java] [rafaelrpinto/vulnerablejavawebapplication](https://github.com/rafaelrpinto/vulnerablejavawebapplication) A Java Web Application with common legacy security flaws for tests with Arachni Scanner and ModSecurity
- [**9**Star][2y] [HTML] [mister2tone/metasploit-webapp](https://github.com/mister2tone/metasploit-webapp) Metasploit framework via HTTP services
- [**7**Star][4m] [Py] [binaryanalysisplatform/bap-python](https://github.com/binaryanalysisplatform/bap-python) BAP python bindings
- [**7**Star][9y] [PHP] [ircmaxell/xssbadwebapp](https://github.com/ircmaxell/xssbadwebapp) A Intentionally Vulnerable Bad Web Application With XSS Vulnerabilities - *DO NOT USE!!!*
- [**6**Star][2y] [HTML] [ambulong/dbapp_ctf_201801](https://github.com/ambulong/dbapp_ctf_201801) 安恒CTF一月赛部分POC
- [**1**Star][20d] [C] [binaryanalysisplatform/bap-testsuite](https://github.com/binaryanalysisplatform/bap-testsuite) BAP test suite
- [**1**Star][3y] [C] [maurer/libbap](https://github.com/maurer/libbap) C Bindings for BAP
- [**1**Star][8m] [spy86/owaspwebapplicationsecuritytestingchecklist](https://github.com/spy86/owaspwebapplicationsecuritytestingchecklist) 
- [**0**Star][3y] [C#] [jstillwell/webapppentest](https://github.com/jstillwell/webapppentest) App for testing web apps for vulnerabilities like Sql injection


### <a id="e111826dde8fa44c575ce979fd54755d"></a>Post






***


## <a id="2683839f170250822916534f1db22eeb"></a>BinNavi


### <a id="2e4980c95871eae4ec0e76c42cc5c32f"></a>Tool


- [**382**Star][26d] [C++] [google/binexport](https://github.com/google/binexport) Export disassemblies into Protocol Buffers and to BinNavi databases
    - Also In Section: [IDA->Tools->Import Export->BinNavi](#11139e7d6db4c1cef22718868f29fe12) |
- [**213**Star][4y] [PLpgSQL] [cseagle/freedom](https://github.com/cseagle/freedom) capstone based disassembler for extracting to binnavi
    - Also In Section: [IDA->Tools->Import Export->BinNavi](#11139e7d6db4c1cef22718868f29fe12) |
- [**25**Star][7y] [Py] [tosanjay/bopfunctionrecognition](https://github.com/tosanjay/bopfunctionrecognition) plugin to BinNavi tool to analyze a x86 binanry file to find buffer overflow prone functions. Such functions are important for vulnerability analysis.
    - Also In Section: [IDA->Tools->Import Export->BinNavi](#11139e7d6db4c1cef22718868f29fe12) |


### <a id="ff4dc5c746cb398d41fb69a4f8dfd497"></a>Post


- 2015.12 [summitroute] [Setting up fREedom and BinNavi](https://summitroute.com/blog/2015/12/31/setting_up_freedom_and_binnavi/)
- 2015.12 [addxorrol] [Open-Source BinNavi ... and fREedom](http://addxorrol.blogspot.com/2015/12/open-source-binnavi-and-freedom.html)
- 2015.08 [freebuf] [逆向分析神器BinNavi开源了](http://www.freebuf.com/sectool/75529.html)
- 2008.11 [addxorrol] [BinDiff / BinNavi User Forum](http://addxorrol.blogspot.com/2008/11/bindiff-binnavi-user-forum.html)
- 2008.11 [addxorrol] [BinNavi v2 and PHP !](http://addxorrol.blogspot.com/2008/11/binnavi-v2-and-php.html)




***


## <a id="0971f295b0f67dc31b7aa45caf3f588f"></a>Decompiler


### <a id="e67c18b4b682ceb6716388522f9a1417"></a>Tool


- [**20779**Star][8d] [Java] [skylot/jadx](https://github.com/skylot/jadx) Dex to Java decompiler
- [**7733**Star][1m] [Java] [java-decompiler/jd-gui](https://github.com/java-decompiler/jd-gui) A standalone Java Decompiler GUI
- [**3135**Star][26d] [Java] [deathmarine/luyten](https://github.com/deathmarine/luyten) An Open Source Java Decompiler Gui for Procyon
- [**1867**Star][1y] [Java] [jindrapetrik/jpexs-decompiler](https://github.com/jindrapetrik/jpexs-decompiler) JPEXS Free Flash Decompiler
- [**1652**Star][12m] [Java] [fesh0r/fernflower](https://github.com/fesh0r/fernflower) Unofficial mirror of FernFlower Java decompiler (All pulls should be submitted upstream)
- [**1466**Star][12d] [Py] [rocky/python-uncompyle6](https://github.com/rocky/python-uncompyle6) A cross-version Python bytecode decompiler
- [**1109**Star][1y] [Py] [wibiti/uncompyle2](https://github.com/wibiti/uncompyle2) Python 2.7 decompiler
- [**1084**Star][4m] [Py] [storyyeller/krakatau](https://github.com/storyyeller/krakatau) Java decompiler, assembler, and disassembler
- [**764**Star][12m] [C++] [comaeio/porosity](https://github.com/comaeio/porosity) *UNMAINTAINED* Decompiler and Security Analysis tool for Blockchain-based Ethereum Smart-Contracts
- [**678**Star][3y] [Batchfile] [ufologist/onekey-decompile-apk](https://github.com/ufologist/onekey-decompile-apk) 一步到位反编译apk工具(onekey decompile apk)
- [**673**Star][18d] [C#] [uxmal/reko](https://github.com/uxmal/reko) Reko is a binary decompiler.
- [**671**Star][11m] [C++] [zrax/pycdc](https://github.com/zrax/pycdc) C++ python bytecode disassembler and decompiler
- [**573**Star][2y] [C++] [zneak/fcd](https://github.com/zneak/fcd) An optimizing decompiler
- [**538**Star][6m] [Java] [java-decompiler/jd-eclipse](https://github.com/java-decompiler/jd-eclipse) A Java Decompiler Eclipse plugin
- [**533**Star][5y] [Py] [mysterie/uncompyle2](https://github.com/mysterie/uncompyle2) A Python 2.5, 2.6, 2.7 byte-code decompiler
- [**483**Star][3y] [Lua] [viruscamp/luadec](https://github.com/viruscamp/luadec) Lua Decompiler for lua 5.1 , 5.2 and 5.3
- [**389**Star][3y] [Py] [gstarnberger/uncompyle](https://github.com/gstarnberger/uncompyle) Python decompiler
- [**383**Star][3y] [C] [micrictor/stuxnet](https://github.com/micrictor/stuxnet) Open-source decompile of Stuxnet/myRTUs
- [**347**Star][16d] [C#] [steamdatabase/valveresourceformat](https://github.com/steamdatabase/valveresourceformat) Valve's Source 2 resource file format (also known as Stupid Valve Format) parser and decompiler.
- [**331**Star][11d] [Java] [leibnitz27/cfr](https://github.com/leibnitz27/cfr) This is the public repository for the CFR Java decompiler
- [**327**Star][2m] [C++] [silverf0x/rpcview](https://github.com/silverf0x/rpcview) RpcView is a free tool to explore and decompile Microsoft RPC interfaces
- [**306**Star][5y] [C++] [draperlaboratory/fracture](https://github.com/draperlaboratory/fracture) an architecture-independent decompiler to LLVM IR
- [**283**Star][8m] [Shell] [venshine/decompile-apk](https://github.com/venshine/decompile-apk)  auto decompile function for produce Java source code and resources from Android Apk files that displayed on GUI.
- [**243**Star][3m] [Java] [kwart/jd-cmd](https://github.com/kwart/jd-cmd) Command line Java Decompiler
- [**242**Star][11d] [C#] [icsharpcode/avaloniailspy](https://github.com/icsharpcode/avaloniailspy) Avalonia-based .NET Decompiler (port of ILSpy)
- [**240**Star][2m] [Java] [ata4/bspsrc](https://github.com/ata4/bspsrc) A Source engine map decompiler
- [**234**Star][5y] [C] [sztupy/luadec51](https://github.com/sztupy/luadec51) Lua Decompiler for Lua version 5.1
- [**232**Star][1y] [C++] [wwwg/wasmdec](https://github.com/wwwg/wasmdec) WebAssembly to C decompiler
- [**226**Star][11d] [C++] [boomerangdecompiler/boomerang](https://github.com/BoomerangDecompiler/boomerang) Boomerang Decompiler - Fighting the code-rot :)
- [**196**Star][1y] [C++] [cararasu/holodec](https://github.com/cararasu/holodec) Decompiler for x86 and x86-64 ELF binaries
- [**164**Star][3y] [C#] [jamesjlinden/unity-decompiled](https://github.com/jamesjlinden/unity-decompiled) 
- [**148**Star][3y] [C#] [endgameinc/py2exedecompiler](https://github.com/endgameinc/py2exedecompiler) Decompiles Exe created by Py2Exe using uncompyle6 for both python 2 and 3.
- [**136**Star][6y] [Py] [nightnord/ljd](https://github.com/nightnord/ljd) LuaJIT raw-bytecode decompiler
- [**129**Star][6y] [Lua] [bobsayshilol/luajit-decomp](https://github.com/bobsayshilol/luajit-decomp) LuaJIT decompiler
- [**113**Star][1y] [Java] [despector/despector](https://github.com/despector/despector) Java / Kotlin Decompiler and AST Library
- [**87**Star][4m] [Clojure] [clojure-goes-fast/clj-java-decompiler](https://github.com/clojure-goes-fast/clj-java-decompiler) clj-java-decompiler: 将 Clojure 反编译为 Java
- [**87**Star][11d] [Py] [pnfsoftware/jeb2-samplecode](https://github.com/pnfsoftware/jeb2-samplecode) Sample extensions for JEB Decompiler
- [**85**Star][4y] [C] [electrojustin/triad-decompiler](https://github.com/electrojustin/triad-decompiler) TRiad Is A Decompiler. Triad is a tiny, free and open source, Capstone based x86 decompiler for ELF binaries.
- [**82**Star][2y] [C++] [nemerle/dcc](https://github.com/nemerle/dcc) This is a heavily updated version of the old DOS executable decompiler DCC
- [**77**Star][3m] [Py] [pfalcon/scratchablock](https://github.com/pfalcon/scratchablock) Yet another crippled decompiler project
- [**67**Star][1y] [PHP] [irelance/jsc-decompile-mozjs-34](https://github.com/irelance/jsc-decompile-mozjs-34) A javascript bytecode decoder for mozilla spider-monkey version 34. May decompile jsc file compile by cocos-2dx
- [**57**Star][16d] [Py] [matt-kempster/mips_to_c](https://github.com/matt-kempster/mips_to_c) A MIPS decompiler.
- [**57**Star][5y] [C] [molnarg/dead0007](https://github.com/molnarg/dead0007) Decompiler for SpiderMonkey 1.8 XDR bytecode
- [**54**Star][7m] [Clojure] [bronsa/tools.decompiler](https://github.com/bronsa/tools.decompiler) A decompiler for clojure, in clojure
- [**53**Star][7y] [Visual Basic .NET] [vbgamer45/semi-vb-decompiler](https://github.com/vbgamer45/semi-vb-decompiler) Partial decompiler for Visual Basic. Code source of file struture infomation.
- [**49**Star][12d] [Py] [rocky/python-decompile3](https://github.com/rocky/python-decompile3) Python decompiler for 3.7+. Stripped down from uncompyle6 so we can refactor and fix up some long-standing problems
- [**40**Star][2y] [Py] [wibiti/evedec](https://github.com/wibiti/evedec) Eve Online decrypter/decompiler
- [**32**Star][1y] [C++] [fortiguard-lion/rpcview](https://github.com/fortiguard-lion/rpcview) RpcView is a free tool to explore and decompile Microsoft RPC interfaces
- [**31**Star][2y] [Visual Basic .NET] [dzzie/myaut_contrib](https://github.com/dzzie/myaut_contrib) mod to myaut2exe decompiler
- [**28**Star][16d] [Py] [dottedmag/archmage](https://github.com/dottedmag/archmage) A reader and decompiler for files in the CHM format
- [**28**Star][12m] [Java] [minecraftforge/fernflower](https://github.com/minecraftforge/fernflower) Unofficial mirror of FernFlower Java decompiler, Subtree split of:
- [**28**Star][28d] [C++] [schdub/protodec](https://github.com/schdub/protodec) Protobuf decompiler
- [**27**Star][1y] [C#] [jeffreye/avaloniailspy](https://github.com/jeffreye/avaloniailspy) Avalonia-based .NET Decompiler (port of ILSpy)
- [**25**Star][1y] [Py] [nviso-be/decompile-py2exe](https://github.com/nviso-be/decompile-py2exe) Decompile py2exe Python 3 generated EXEs
- [**21**Star][7m] [Py] [beched/abi-decompiler](https://github.com/beched/abi-decompiler) Ethereum (EVM) smart contracts reverse engineering helper utility
- [**21**Star][1y] [C] [rfalke/decompiler-subjects](https://github.com/rfalke/decompiler-subjects) Tests cases for binary decompilers
- [**19**Star][6m] [Java] [pnfsoftware/jeb-plugin-libra](https://github.com/pnfsoftware/jeb-plugin-libra) Libra decompiler plugin for JEB
- [**19**Star][23d] [Shell] [gzu-liyujiang/apkdecompiler](https://github.com/gzu-liyujiang/apkdecompiler) 【Linux系统】上apk反编译助手，已打包为ApkDecompiler.deb，支持debian系linux，如debian、ubuntu、mint、deepin等等
- [**11**Star][3y] [Emacs Lisp] [xiongtx/jdecomp](https://github.com/xiongtx/jdecomp) Emacs interface to Java decompilers
- [**10**Star][6y] [Py] [gdelugre/fupy](https://github.com/gdelugre/fupy) A small and dirty Python 2 decompiler written in Python.
- [**10**Star][2y] [C++] [uglyoldbob/decompiler](https://github.com/uglyoldbob/decompiler) A decompiler targeting c and similar languages.
- [**9**Star][2y] [C++] [darknesswind/nutcracker](https://github.com/darknesswind/nutcracker) fork from DamianXVI's squirrel decompiler
- [**9**Star][3y] [C++] [shauren/protobuf-decompiler](https://github.com/shauren/protobuf-decompiler) 
- [**8**Star][7m] [Java] [soxs/osrsupdater](https://github.com/soxs/osrsupdater) A simple (and outdated) Old-School RuneScape decompiler/deobfuscator. Performs field and method analysis which uses ASM and bytecode patterns for identification. Identified fields could be used for creating bot clients or QoL clients. For educational use only.
- [**8**Star][10m] [PHP] [vaibhavpandeyvpz/deapk](https://github.com/vaibhavpandeyvpz/deapk) DeAPK is an open-source, online APK decompiler which lets you upload an APK and then decompile it to Smali or Java sources. It is built using Laravel, Vue.js, Bootstrap, FontAwesome, Pusher, Redis, MySQL, apktool, jadx and hosted atop DigitalOcean cloud platform.
- [**5**Star][1y] [C#] [fireboyd78/unluacnet](https://github.com/fireboyd78/unluacnet) A Lua 5.1 decompiler library written in C#. Based on the original Java version of "unluac" by tehtmi.
- [**5**Star][2m] [Kotlin] [kotcrab/mist](https://github.com/kotcrab/mist) Interactive MIPS disassembler and decompiler
- [**5**Star][4m] [TS] [x87/scout](https://github.com/x87/scout) Scout Decompiler
- [**1**Star][2y] [Haskell] [wertercatt/mrifk](https://github.com/wertercatt/mrifk) A decompiler and disassembler for the Glulx virtual machine.
- [**1**Star][6y] [Haskell] [rel-eng/jdec](https://github.com/rel-eng/jdec) java decompiler written in haskell
- [**1**Star][2m] [Java] [maxpixelstudios/minecraftdecompiler](https://github.com/maxpixelstudios/minecraftdecompiler) A useful tool to decompile and deobfuscate Minecraft by CFR and Proguard/SRG/CSRG/TSRG mappings
- [**0**Star][2y] [Java] [dgileadi/dg.jdt.ls.decompiler](https://github.com/dgileadi/dg.jdt.ls.decompiler) 
- [**None**Star][xdasm/decompiler](https://bitbucket.org/xdasm/decompiler/issues?status=new&status=open) 


### <a id="a748b79105651a8fd8ae856a7dc2b1de"></a>Post






***


## <a id="2df6d3d07e56381e1101097d013746a0"></a>Disassemble


### <a id="59f472c7575951c57d298aef21e7d73c"></a>Tool


- [**1374**Star][20d] [C] [zyantific/zydis](https://github.com/zyantific/zydis) Fast and lightweight x86/x86-64 disassembler library
- [**1346**Star][12m] [Rust] [das-labor/panopticon](https://github.com/das-labor/panopticon) A libre cross-platform disassembler.
- [**877**Star][11m] [C++] [wisk/medusa](https://github.com/wisk/medusa) An open source interactive disassembler
- [**835**Star][8d] [GLSL] [khronosgroup/spirv-cross](https://github.com/khronosgroup/spirv-cross)  a practical tool and library for performing reflection on SPIR-V and disassembling SPIR-V back to high level languages.
- [**828**Star][3m] [C++] [redasmorg/redasm](https://github.com/redasmorg/redasm) The OpenSource Disassembler
- [**693**Star][5y] [C] [vmt/udis86](https://github.com/vmt/udis86) Disassembler Library for x86 and x86-64
- [**627**Star][3m] [C] [gdabah/distorm](https://github.com/gdabah/distorm) Powerful Disassembler Library For x86/AMD64
- [**430**Star][2m] [C#] [0xd4d/iced](https://github.com/0xd4d/iced) x86/x64 disassembler, instruction decoder & encoder
- [**351**Star][21d] [Ruby] [jjyg/metasm](https://github.com/jjyg/metasm) This is the main repository for metasm, a free assembler / disassembler / compiler written in ruby
- [**268**Star][3y] [HTML] [xem/minix86](https://github.com/xem/minix86) x86 (MS-DOS) documentation, disassembler and emulator - WIP
- [**246**Star][5m] [Py] [bontchev/pcodedmp](https://github.com/bontchev/pcodedmp) A VBA p-code disassembler
- [**198**Star][6m] [Py] [athre0z/wasm](https://github.com/athre0z/wasm) WebAssembly decoder & disassembler library
- [**139**Star][17d] [C++] [grammatech/ddisasm](https://github.com/grammatech/ddisasm) A fast and accurate disassembler
- [**136**Star][2y] [Java] [tinylcy/classanalyzer](https://github.com/tinylcy/classanalyzer) A Java Class File Disassembler
- [**89**Star][6m] [Java] [llvm-but-worse/java-disassembler](https://github.com/LLVM-but-worse/java-disassembler) The Java Disassembler
- [**88**Star][9m] [Py] [blacknbunny/peanalyzer](https://github.com/blacknbunny/peanalyzer) Advanced Portable Executable File Analyzer And Disassembler 32 & 64 Bit
- [**86**Star][2y] [C++] [rmitton/goaldis](https://github.com/rmitton/goaldis) Jak & Daxter GOAL disassembler
- [**81**Star][3y] [Py] [januzellij/hopperscripts](https://github.com/januzellij/hopperscripts) Collection of scripts I use in the Hopper disassembler
- [**80**Star][2y] [Py] [rsc-dev/pbd](https://github.com/rsc-dev/pbd) Pbd is a Python module to disassemble serialized protocol buffers descriptors (
- [**69**Star][6m] [Py] [tintinweb/ethereum-dasm](https://github.com/tintinweb/ethereum-dasm) An ethereum evm bytecode disassembler and static/dynamic analysis tool
- [**65**Star][11m] [Pascal] [mahdisafsafi/univdisasm](https://github.com/mahdisafsafi/univdisasm) x86 Disassembler and Analyzer
- [**62**Star][5m] [Py] [crytic/pyevmasm](https://github.com/crytic/pyevmasm) Ethereum Virtual Machine (EVM) disassembler and assembler
- [**57**Star][14d] [Py] [rocky/python-xdis](https://github.com/rocky/python-xdis) Python cross-version bytecode library and disassembler
- [**52**Star][30d] [C++] [hasherezade/vidi](https://github.com/hasherezade/vidi) ViDi Visual Disassembler (experimental)
- [**32**Star][6m] [C++] [vector35/generate_assembler](https://github.com/vector35/generate_assembler) generate assemblers from disassemblers, 2018 jailbreak security summit talk
- [**30**Star][3y] [Py] [rmtew/peasauce](https://github.com/rmtew/peasauce) Peasauce Interactive Disassembler
- [**25**Star][3m] [HTML] [shahril96/online-assembler-disassembler](https://github.com/shahril96/online-assembler-disassembler) Online assembler and disassembler
- [**24**Star][3y] [Py] [0xbc/chiasm-shell](https://github.com/0xbc/chiasm-shell) Python-based interactive assembler/disassembler CLI, powered by Keystone/Capstone.
- [**23**Star][2y] [C++] [verideth/repen](https://github.com/verideth/repen) Simple C8 disassembler
- [**22**Star][5y] [C#] [tophertimzen/shellcodetester](https://github.com/tophertimzen/shellcodetester) GUI Application in C# to run and disassemble shellcode


### <a id="a6eb5a22deb33fc1919eaa073aa29ab5"></a>Post






***


## <a id="975d9f08e2771fccc112d9670eae1ed1"></a>GDB


### <a id="5f4381b0a90d88dd2296c2936f7e7f70"></a>Tool


- [**7019**Star][10d] [JS] [cs01/gdbgui](https://github.com/cs01/gdbgui) Browser-based frontend to gdb (gnu debugger). Add breakpoints, view the stack, visualize data structures, and more in C, C++, Go, Rust, and Fortran. Run gdbgui from the terminal and a new tab will open in your browser.
- [**6052**Star][13d] [Py] [cyrus-and/gdb-dashboard](https://github.com/cyrus-and/gdb-dashboard) Modular visual interface for GDB in Python
- [**3784**Star][11m] [Py] [longld/peda](https://github.com/longld/peda) Python Exploit Development Assistance for GDB
- [**2568**Star][1m] [Py] [hugsy/gef](https://github.com/hugsy/gef)  GDB Enhanced Features for exploit devs & reversers
- [**2439**Star][16d] [Py] [pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) Exploit Development and Reverse Engineering with GDB Made Easy
- [**1417**Star][3m] [Go] [hellogcc/100-gdb-tips](https://github.com/hellogcc/100-gdb-tips) A collection of gdb tips. 100 maybe just mean many here.
- [**452**Star][3m] [Py] [scwuaptx/pwngdb](https://github.com/scwuaptx/pwngdb) gdb for pwn
- [**446**Star][1y] [Py] [jfoote/exploitable](https://github.com/jfoote/exploitable) The 'exploitable' GDB plugin. I don't work at CERT anymore, but here is the original homepage:
- [**244**Star][2m] [JS] [bet4it/hyperpwn](https://github.com/bet4it/hyperpwn) A hyper plugin to provide a flexible GDB GUI with the help of GEF, pwndbg or peda
- [**208**Star][2m] [Py] [sakhnik/nvim-gdb](https://github.com/sakhnik/nvim-gdb) Neovim thin wrapper for GDB, LLDB and PDB
- [**196**Star][2y] [Py] [sqlab/symgdb](https://github.com/sqlab/symgdb) symbolic execution plugin for gdb
- [**186**Star][4y] [Py] [leeyiw/cgdb-manual-in-chinese](https://github.com/leeyiw/cgdb-manual-in-chinese) 《CGDB中文手册》
- [**174**Star][21d] [Shell] [rocky/zshdb](https://github.com/rocky/zshdb) gdb-like "trepan" debugger for zsh
- [**152**Star][1m] [Py] [rogerhu/gdb-heap](https://github.com/rogerhu/gdb-heap) Heap Analyzer for Python
- [**150**Star][1m] [Py] [gdbinit/lldbinit](https://github.com/gdbinit/lldbinit) A gdbinit clone for LLDB
- [**137**Star][2y] [kevinsbobo/cheat-sheet](https://github.com/kevinsbobo/cheat-sheet) 速查表包括了 Vim, Git, Shell, Gcc, Gdb 常用命令及快捷键
- [**132**Star][4y] [C] [espressif/esp-gdbstub](https://github.com/espressif/esp-gdbstub) 
- [**126**Star][3m] [Py] [deroko/lldbinit](https://github.com/deroko/lldbinit) Similar implementation of .gdbinit from fG
- [**101**Star][3m] [Py] [cs01/pygdbmi](https://github.com/cs01/pygdbmi) A library to parse gdb mi output, as well as control gdb subprocesses
- [**93**Star][2m] [C] [weirdnox/emacs-gdb](https://github.com/weirdnox/emacs-gdb) GDB graphical interface for GNU Emacs
- [**93**Star][5y] [Py] [zachriggle/peda](https://github.com/zachriggle/peda) PEDA - Python Exploit Development Assistance for GDB
- [**91**Star][5m] [Py] [vuvova/gdb-tools](https://github.com/vuvova/gdb-tools) Various tools to improve the gdb experience
- [**87**Star][2m] [Py] [alset0326/peda-arm](https://github.com/alset0326/peda-arm) GDB plugin peda for arm
- [**85**Star][2y] [C] [javierhonduco/write-a-strace-and-gdb](https://github.com/javierhonduco/write-a-strace-and-gdb) A tiny system call tracer and debugger implementation
- [**79**Star][3m] [Py] [miyagaw61/exgdb](https://github.com/miyagaw61/exgdb) Extension for GDB
- [**73**Star][3m] [hugsy/gdb-static](https://github.com/hugsy/gdb-static) Public repository of static GDB and GDBServer
- [**73**Star][21d] [Py] [rocky/python3-trepan](https://github.com/rocky/python3-trepan) A gdb-like Python3 Debugger in the Trepan family
- [**69**Star][14d] [Py] [koutheir/libcxx-pretty-printers](https://github.com/koutheir/libcxx-pretty-printers) GDB Pretty Printers for libc++ of Clang/LLVM
- [**62**Star][4m] [OCaml] [copy/gdbprofiler](https://github.com/copy/gdbprofiler) Rich man's profiler, a profiler for native OCaml and other executables
- [**61**Star][1y] [Py] [hq6/gdbshellpipe](https://github.com/hq6/gdbshellpipe) Enable piping of internal command output to external commands
- [**56**Star][5m] [Py] [stef/pyrsp](https://github.com/stef/pyrsp) python implementation of the GDB Remote Serial Protocol
- [**54**Star][10m] [Shell] [mzpqnxow/embedded-toolkit](https://github.com/mzpqnxow/embedded-toolkit) Prebuilt statically linked gdbserver and gawk executables for Linux on ARMEL, MIPS/MIPSEL and more platforms for use on embedded devices, including for systems with many different ABIs (including more than 20 statically linked gdbserver executables)
- [**52**Star][8y] [Py] [crossbowerbt/gdb-python-utils](https://github.com/crossbowerbt/gdb-python-utils) A library for GDB (with python support), that adds useful functions to the standard 'gdb' library.
- [**52**Star][2y] [Go] [cyrus-and/gdb](https://github.com/cyrus-and/gdb) Go GDB/MI interface
- [**47**Star][6y] [C] [gdbinit/gdb-ng](https://github.com/gdbinit/gdb-ng) Apple's gdb fork with some fixes and enhancements
- [**46**Star][11m] [Shell] [mzpqnxow/gdb-static-cross](https://github.com/mzpqnxow/gdb-static-cross) Shell scripts, sourceable "activate" scripts and instructions for building a statically linked gdb-7.12 gdbserver using cross-compile toolchains. Includes more than 20 statically linked gdbserver executables for different architectures, byte orders and ABIs
- [**46**Star][1m] [TeX] [zxgio/gdb_gef-cheatsheet](https://github.com/zxgio/gdb_gef-cheatsheet) GDB + GEF cheatsheet for reversing binaries
- [**44**Star][2m] [Py] [scwuaptx/peda](https://github.com/scwuaptx/peda) PEDA - Python Exploit Development Assistance for GDB
- [**41**Star][4m] [Rust] [cbourjau/cargo-with](https://github.com/cbourjau/cargo-with) A third-party cargo extension to run the build artifacts through tools like `gdb`
- [**39**Star][2m] [Py] [sharkdp/stack-inspector](https://github.com/sharkdp/stack-inspector) A gdb command to inspect the size of objects on the stack
- [**38**Star][10m] [Py] [wapiflapi/gxf](https://github.com/wapiflapi/gxf) Gdb Extension Framework is a bunch of python code around the gdb api.
- [**37**Star][5y] [Py] [philwantsfish/gdb_commands](https://github.com/philwantsfish/gdb_commands) GDB commands to aid exploit development
- [**36**Star][9d] [Ruby] [david942j/gdb-ruby](https://github.com/david942j/gdb-ruby) It's time for Ruby lovers to use Ruby in gdb, and gdb in Ruby!
- [**36**Star][2y] [Py] [tromey/gdb-gui](https://github.com/tromey/gdb-gui) A gdb gui written in Python, running inside gdb itself.
- [**33**Star][2m] [Py] [akiym/pedal](https://github.com/akiym/pedal) PEDAL - Python Exploit Development Assistance for GDB Lite
- [**33**Star][1y] [Py] [damziobro/gdb-automatic-deadlock-detector](https://github.com/DamZiobro/gdb-automatic-deadlock-detector) Script adds new command to GDB which allows automatically detect C/C++ thread locking and deadlocks in GDB debugger
- [**25**Star][13d] [C] [mborgerson/gdbstub](https://github.com/mborgerson/gdbstub) A simple, dependency-free GDB stub that can be easily dropped in to your project.
- [**24**Star][1m] [Py] [daskol/gdb-colour-filter](https://github.com/daskol/gdb-colour-filter) Colourify backtrace output in GDB with Python API
- [**23**Star][1m] [Perl] [occivink/kakoune-gdb](https://github.com/occivink/kakoune-gdb) gdb integration plugin
- [**23**Star][2y] [C] [tommythorn/yari](https://github.com/tommythorn/yari) YARI is a high performance open source FPGA soft-core RISC implementation, binary compatible with MIPS I. The distribution package includes a complete SoC, simulator, GDB stub, scripts, and various examples.
- [**23**Star][3y] [Py] [zachriggle/pwndbg](https://github.com/zachriggle/pwndbg) GDB插件，辅助漏洞开发和逆向
- [**22**Star][3y] [Py] [tromey/gdb-helpers](https://github.com/tromey/gdb-helpers) GDB helper scripts
- [**21**Star][23d] [C] [yugr/libdebugme](https://github.com/yugr/libdebugme) Automatically spawn gdb on error.
- [**20**Star][6m] [Batchfile] [cldrn/insecureprogrammingdb](https://github.com/cldrn/insecureprogrammingdb) Insecure programming functions database
- [**20**Star][2y] [Py] [kelwin/peda](https://github.com/kelwin/peda) PEDA - Python Exploit Development Assistance for GDB
- [**19**Star][8d] [C#] [sysprogs/bsptools](https://github.com/sysprogs/bsptools) Tools for generating VisualGDB BSPs
- [**18**Star][4y] [C] [niklasb/dump-seccomp](https://github.com/niklasb/dump-seccomp) GDB plugin to dump SECCOMP rules set via prctnl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)
- [**15**Star][3y] [C] [andyneff/hello-world-gdb](https://github.com/andyneff/hello-world-gdb) Simple hello world program for debugging with gdb
- [**15**Star][6y] [gdbinit/kgmacros](https://github.com/gdbinit/kgmacros) Fixed kgmacros to work with VMware kernel gdb stub
- [**15**Star][2y] [C] [rkx1209/bitvisor-gdb](https://github.com/rkx1209/bitvisor-gdb) gdbserver implementation on BitVisor
- [**15**Star][1m] [C++] [satharus/disass](https://github.com/satharus/disass) [WIP] FOSS GNU Debugger (GDB) interface for GNU/Linux.
- [**14**Star][3y] [Py] [0xmitsurugi/gdbscripts](https://github.com/0xmitsurugi/gdbscripts) Python scripts for gdb, reverse engineering oriented
- [**14**Star][3y] [JS] [ben-ha/gdbface](https://github.com/ben-ha/gdbface) GDB web frontend written in Javascript
- [**14**Star][11m] [TeX] [zxgio/gdb-cheatsheet](https://github.com/zxgio/gdb-cheatsheet) GDB cheatsheet for reversing binaries
- [**13**Star][2y] [Py] [pageflt/gdb-memstr](https://github.com/pageflt/gdb-memstr) Generate arbitrary strings out of contents of ELF sections
- [**10**Star][3y] [JS] [gogoprog/atom-gdb](https://github.com/gogoprog/atom-gdb) Atom plugin to set gdb breakpoints in .gdbinit file and run an external debugger as QtCreator or ddd
- [**10**Star][2y] [Py] [kikimo/pygdb](https://github.com/kikimo/pygdb) pygdb：Linux 调试器，支持 dwarf-2 调试信息，能调试 x86/x64 程序
- [**10**Star][26d] [C] [resetnow/esp-gdbstub](https://github.com/resetnow/esp-gdbstub) ESP8266 debugging tool
- [**10**Star][2y] [Py] [stephenr/gdb_scripts](https://github.com/stephenr/gdb_scripts) 
- [**8**Star][5y] [Py] [ctu-iig/802.11p-wireless-regdb](https://github.com/ctu-iig/802.11p-wireless-regdb) Wireless regulatory database for CRDA
- [**4**Star][11m] [C] [adapteva/epiphany-binutils-gdb](https://github.com/adapteva/epiphany-binutils-gdb) Merged gdb and binutils repository
- [**3**Star][1y] [Py] [grant-h/gdbscripts](https://github.com/grant-h/gdbscripts) An assorted collection of GDB scripts.
- [**2**Star][4m] [Py] [artem-nefedov/uefi-gdb](https://github.com/artem-nefedov/uefi-gdb) UEFI OVMF symbol load script for GDB
- [**2**Star][9m] [C#] [sysprogs/visualgdbextensibilityexamples](https://github.com/sysprogs/visualgdbextensibilityexamples) 
- [**2**Star][2y] [Py] [tentpegbob/ropgadget](https://github.com/tentpegbob/ropgadget) Extends ROPgadget so that it can be used inside of GDB via Python.
- [**1**Star][3y] [elauqsap/vtgdb](https://github.com/elauqsap/vtgdb) vulnerability and threat repository using a graph architecture
- [**1**Star][2y] [Py] [monkeyman79/janitor](https://github.com/monkeyman79/janitor) Collection of GDB commands for low-level debugging, aimed at bringing debug.exe flavor into GDB command line interface.
- [**0**Star][4y] [Py] [0xd3d0/pygdb](https://github.com/0xd3d0/pygdb) Automatically exported from code.google.com/p/pygdb
- [**0**Star][2y] [JS] [pgigis/routingdb](https://github.com/pgigis/routingdb) 
- [**None**Star][sha0coder/gdb_automatization](https://bitbucket.org/sha0coder/gdb_automatization) 


### <a id="37b17362d72f9c8793973bc4704893a2"></a>Post


- 2019.11 [ocallahan] [Supercharging Gdb With Pernosco](https://robert.ocallahan.org/2019/11/supercharging-gdb-with-pernosco.html)
- 2019.10 [FOSSiFoundation] [A Unified Debug Server for Deeply Embedded Systems and GDB/LLDB - Simon Cook - ORConf 2019](https://www.youtube.com/watch?v=bfxHGq2m8M8)
- 2019.10 [TheLinuxFoundation] [Using Serial kdb / kgdb to Debug the Linux Kernel - Douglas Anderson, Google](https://www.youtube.com/watch?v=HBOwoSyRmys)
- 2019.09 [GNUToolsCauldron] [GDB: Tab-Completion & Command Options - GNU Tools Cauldron 2019](https://www.youtube.com/watch?v=jEllWJ0at9o)
- 2019.09 [GNUToolsCauldron] [GDB on s390x: To-dos and Challenges - GNU Tools Cauldron 2019](https://www.youtube.com/watch?v=iQAd5Atlz1s)
- 2019.09 [GNUToolsCauldron] [GDB BoF - GNU Tools Cauldron 2019](https://www.youtube.com/watch?v=vdzpbnGDvZM)
- 2019.09 [GNUToolsCauldron] [A New Debug Server for Supporting GDB on Embedded Platforms - GNU Tools Cauldron 2019](https://www.youtube.com/watch?v=mQYKEzWAoqI)
- 2019.05 [tunnelshade] [Quick linux kernel with gdb setup with little help from Linux distros](https://tunnelshade.in/blog/2019/05/linux-kernel-gdb-setup/)
- 2019.02 [360] [ARM汇编之堆栈溢出实战分析四(GDB)](https://www.anquanke.com/post/id/170651/)
- 2019.01 [freebuf] [ARM汇编之堆栈溢出实战分析三（GDB）](https://www.freebuf.com/news/193664.html)
- 2019.01 [360] [ARM汇编之堆栈溢出实战分析二(GDB)](https://www.anquanke.com/post/id/169186/)
- 2019.01 [360] [ARM汇编之堆栈溢出实战分析（GDB）](https://www.anquanke.com/post/id/169071/)
- 2018.09 [blackroomsec] [Reversing small crackme w/ GDB-Peda](https://www.blackroomsec.com/reversing-small-crackme-w-gdb-peda/)
- 2018.09 [doyler] [Metasploit adduser Analysis via GDB (SLAE Exam Assignment #5.2)](https://www.doyler.net/security-not-included/metasploit-adduser-analysis)
- 2018.07 [pediy] [[编程][翻译]　用 gdb 学 C 语言](https://bbs.pediy.com/thread-229985.htm)
- 2018.05 [djmanilaice] [Ignorance .gdbinit](http://djmanilaice.blogspot.com/2018/05/ignorance-gdbinit.html)
- 2018.05 [360] [DEFCON CHINA议题解读 | Triton和符号执行在 GDB 上](https://www.anquanke.com/post/id/144984/)
- 2018.03 [aliyun] [利用GDB实现进程注入](https://xz.aliyun.com/t/2164)
- 2018.02 [freebuf] [GDB调试CVE-2018-5711 PHP-GD拒绝服务漏洞](http://www.freebuf.com/vuls/162029.html)
- 2018.02 [HITCON] [[HITCON CMT 2017] R0D202 - 陳威伯 - Triton and Symbolic execution on GDB](https://www.youtube.com/watch?v=LOTQIAVXdCI)
- 2018.01 [jvns] [How does gdb call functions?](https://jvns.ca/blog/2018/01/04/how-does-gdb-call-functions/)
- 2017.12 [pediy] [[原创] 如何在pwn题中更有效地使用GDB](https://bbs.pediy.com/thread-223337.htm)
- 2017.10 [sysprogs] [Explaining project format changes in VisualGDB 5.3](https://sysprogs.com/w/explaining-project-format-changes-in-visualgdb-5-3/)
- 2017.09 [pediy] [[原创]分享一份儿我做的速查表 - 包括了 Vim, Git, Shell, Gcc, Gdb 常用命令及快捷键](https://bbs.pediy.com/thread-221178.htm)
- 2017.08 [sysprogs] [The Updated VisualGDB Embedded Debugging Experience](https://sysprogs.com/w/the-updated-visualgdb-embedded-debug-experience/)
- 2017.08 [pediy] [[分享]用debugserver + lldb代替gdb进行动态调试](https://bbs.pediy.com/thread-220091.htm)
- 2017.08 [360] [利用GDB调试ARM代码](https://www.anquanke.com/post/id/86536/)
- 2017.06 [sysprogs] [Clang IntelliSense Improvements in VisualGDB 5.3 Preview 2](https://sysprogs.com/w/clang-intellisense-improvements-in-visualgdb-5-3-preview-2/)
- 2017.05 [n0where] [GDB Exploit Development & Reverse Engineering: pwndbg](https://n0where.net/gdb-exploit-development-reverse-engineering-pwndbg)
- 2017.05 [abatchy] [Analyzing Metasploit linux/x86/adduser module using GDB](http://www.abatchy.com/2017/05/dissecting-metasploit-linuxx86adduser)
- 2017.05 [abatchy] [Analyzing Metasploit linux/x86/adduser module using GDB](http://www.abatchy.com/2017/05/tcp-reverse-shell-in-assembly-null)
- 2017.03 [360] [安卓Hacking Part 20：使用GDB在Android模拟器上调试应用程序](https://www.anquanke.com/post/id/85819/)
- 2017.03 [nsfocus] [利用GDB、KGDB调试应用程序及内核驱动模块](http://blog.nsfocus.net/gdb-kgdb-debug-application/)
- 2017.03 [dustri] [Solving "warning: Probes-based dynamic linker interface failed." in GDB](https://dustri.org/b/solving-warning-probes-based-dynamic-linker-interface-failed-in-gdb.html)
- 2017.03 [n0where] [Browser-based GDB frontend: gdbGUI](https://n0where.net/web-gdb-gui-gdbgui)
- 2017.02 [] [Stepping backward in gdb](http://0x90909090.blogspot.com/2017/02/stepping-backward-in-gdb.html)
- 2017.01 [n0where] [Multi-Architecture GDB Enhanced Features for Exploiters & Reverse-Engineers: GEF](https://n0where.net/multi-architecture-gdb-enhanced-features-for-exploiters-reverse-engineers-gef)
- 2017.01 [360] [使用KGDB实现Android内核调试](https://www.anquanke.com/post/id/85352/)
- 2017.01 [trendmicro] [Practical Android Debugging Via KGDB](https://blog.trendmicro.com/trendlabs-security-intelligence/practical-android-debugging-via-kgdb/)
- 2017.01 [pediy] [[原创]lldb/gdb通信协议研究](https://bbs.pediy.com/thread-215106.htm)
- 2016.11 [pediy] [[下载]VisualGDB 5.x & VisualKernel 2.x破解补丁(2017-10-10更新)](https://bbs.pediy.com/thread-213895.htm)
- 2016.10 [sysprogs] [Exploring advanced STM32 code samples with VisualGDB](https://sysprogs.com/w/exploring-advanced-stm32-code-samples-with-visualgdb/)
- 2016.09 [sysprogs] [VisualGDB 5.2 Beta 1 is out](https://sysprogs.com/w/visualgdb-5-2-beta-1-is-out/)
- 2016.09 [] [Break On Call and Break On Ret under gdb](http://0x90909090.blogspot.com/2016/09/break-on-call-and-break-on-ret-under-gdb.html)
- 2016.09 [metricpanda] [Tips for Productive Debugging with GDB](https://metricpanda.com/tips-for-productive-debugging-with-gdb)
- 2016.09 [sysprogs] [10 Reasons to Try Out MSBuild for your VisualGDB Projects](https://sysprogs.com/w/10-reasons-to-try-out-msbuild-for-your-visualgdb-projects/)
- 2016.08 [sysprogs] [Clang IntelliSense improvements in VisualGDB 5.2](https://sysprogs.com/w/clang-intellisense-improvements-in-visualgdb-5-2/)
- 2016.08 [jvns] [How does gdb work?](https://jvns.ca/blog/2016/08/10/how-does-gdb-work/)
- 2016.08 [brendangregg] [gdb Debugging Full Example (Tutorial): ncurses](http://brendangregg.com/blog/2016-08-09/gdb-example-ncurses.html)
- 2016.07 [sysprogs] [The New Advanced Memory Window in VisualGDB 5.2](https://sysprogs.com/w/the-new-advanced-memory-window-in-visualgdb-5-2/)
- 2016.07 [sysprogs] [Extending the VisualGDB Test System](https://sysprogs.com/w/extending-the-visualgdb-test-system/)
- 2016.07 [sysprogs] [The New Unit Test Support in VisualGDB 5.2](https://sysprogs.com/w/the-new-unit-test-support-in-visualgdb-5-2/)
- 2016.06 [suchakra] [Fast Tracing with GDB](https://suchakra.wordpress.com/2016/06/29/fast-tracing-with-gdb/)
- 2016.06 [] [Sandboxing a linux malware with gdb](http://0x90909090.blogspot.com/2016/06/sandboxing-linux-malware-with-gdb.html)
- 2016.06 [n0where] [GDB Front End: PINCE](https://n0where.net/gdb-front-end-pince)
- 2016.06 [n0where] [Python Exploit Development GDB Assistance: Peda](https://n0where.net/python-exploit-development-gdb-assistance)
- 2016.06 [rapid7] [GDB for Fun (and Profit!)](https://blog.rapid7.com/2016/06/15/gdb-for-fun-and-profit/)
- 2016.06 [paraschetal] [Gracker level1 (GDB basics)](https://paraschetal.in/gracker-level01)
- 2016.03 [freebuf] [Libheap：一款用于分析Glibc堆结构的GDB调试工具](http://www.freebuf.com/sectool/99893.html)
- 2016.02 [blahcat] [Ruxmon 08/2016 - Making GDB great again](http://blahcat.github.io/2016/08/27/ruxmon-16-making-gdb-great-again/)
- 2016.01 [eugenekolo] [Better disassembly with GDB/PEDA](https://eugenekolo.com/blog/better-disassembly-with-gdb-peda/)
- 2015.09 [nsfocus] [用GDB排查Python程序故障](http://blog.nsfocus.net/python-program-troubleshooting-gdb-2/)
- 2015.09 [n0where] [Modular visual interface for GDB: GDB dashboard](https://n0where.net/modular-visual-interface-for-gdb-gdb-dashboard)
- 2015.08 [contextis] [KGDB on Android - Debugging the kernel like a boss](https://www.contextis.com/blog/kgdb-on-android-debugging-the-kernel-like-a-boss)
- 2015.04 [sysprogs] [VisualGDB 5.0 Beta 1 – Refactoring and C++ CodeMap](https://sysprogs.com/w/visualgdb-5-0-beta-1-refactoring-and-c-codemap/)
- 2015.04 [sysprogs] [Exploring code with VisualGDB 5.0 Preview 4](https://sysprogs.com/w/exploring-code-with-visualgdb-5-0-preview-4/)
- 2014.05 [parsiya] [Pasting Shellcode in GDB using Python](https://parsiya.net/blog/2014-05-25-pasting-shellcode-in-gdb-using-python/)
- 2014.04 [firebitsbr] [Golang: Introduction to Go Debugging with GDB](https://firebitsbr.wordpress.com/2014/04/13/golang-introduction-to-go-debugging-with-gdb/)
- 2014.02 [reverse] [Don’t die GDB, we love you: kgmacros ported to Mavericks.](https://reverse.put.as/2014/02/21/dont-die-gdb-we-love-you-kgmacros-ported-to-mavericks/)
- 2014.02 [jvns] [Three steps to learning GDB](https://jvns.ca/blog/2014/02/10/three-steps-to-learning-gdb/)
- 2013.11 [blackmoreops] [How to fix GDBus Error org freedesktop PolicyKit1 Error Failed An authentication agent already exists for the given subject error in Kali, LMDE or Debian Linux?](https://www.blackmoreops.com/2013/11/19/fix-gdbus-error-org-freedesktop-policykit1-error-failed-authentication-agent-already-exists-given-subject-error-kali-lmde-debian-linux/)
- 2013.11 [reverse] [One small patch for GDB, one giant leap for reversers!](https://reverse.put.as/2013/11/08/one-small-patch-for-gdb-one-giant-leap-for-reversers/)
- 2013.03 [reverse] [How to compile GDB in Mountain Lion (updated)](https://reverse.put.as/2013/03/20/how-to-compile-gdb-in-mountain-lion-updated/)
- 2012.06 [sysprogs] [A GDB update for Android-NDK fixes many bugs](https://sysprogs.com/w/a-gdb-update-for-android-ndk-fixes-many-bugs/)
- 2012.04 [reverse] [How to compile GDB for iOS!](https://reverse.put.as/2012/04/16/how-to-compile-gdb-for-ios/)
- 2012.01 [reverse] [Anti-debug trick #1: Abusing Mach-O to crash GDB](https://reverse.put.as/2012/01/31/anti-debug-trick-1-abusing-mach-o-to-crash-gdb/)
- 2012.01 [debasish] [Basic Reverse Engineering with GDB](http://www.debasish.in/2012/01/reversing-simple-program-with-gdb.html)
- 2012.01 [crossbowerbt] [In-memory-fuzzing in Linux (with GDB and Python)](https://crossbowerbt.github.io/in_memory_fuzzing.html)
- 2011.08 [reverse] [Another patch for Apple’s GDB: the define/commands problem](https://reverse.put.as/2011/08/20/another-patch-for-apples-gdb-the-definecommands-problem/)
- 2011.08 [reverse] [How GDB disables ASLR in Mac OS X Lion](https://reverse.put.as/2011/08/11/how-gdb-disables-aslr-in-mac-os-x-lion/)
- 2011.03 [heelan] [Heap Scripts for TCMalloc with GDB’s Python API](https://sean.heelan.io/2011/03/30/heap-scripts-for-tcmalloc-with-gdbs-python-api/)
- 2011.02 [reverse] [Update to GDB patches – fix for a "new" bug](https://reverse.put.as/2011/02/21/update-to-gdb-patches-fix-a-new-bug/)
- 2011.02 [coolshell] [GDB中应该知道的几个调试方法](https://coolshell.cn/articles/3643.html)
- 2010.12 [pediy] [[原创]Linux基本反汇编结构与GDB入门](https://bbs.pediy.com/thread-126018.htm)
- 2010.11 [arxiv] [[1011.5295] GDB: Group Distance Bounding Protocols](https://arxiv.org/abs/1011.5295)
- 2010.10 [reverse] [A new GDB frontend and some pics from the past](https://reverse.put.as/2010/10/11/a-new-gdb-frontend-and-some-pics-from-the-past/)
- 2010.08 [reverse] [GDB anti-debug, Otool/otx anti-disassembly… It’s Challenge number 3 !!!](https://reverse.put.as/2010/08/18/gdb-anti-debug-otoolotx-anti-disassembly-its-challenge-number-3/)
- 2009.10 [coolshell] [GDB 7.0 发布](https://coolshell.cn/articles/1525.html)
- 2009.09 [coolshell] [高科技：GDB回溯调试](https://coolshell.cn/articles/1502.html)
- 2009.08 [reverse] [Anatomy of a GDB anti-debug trick part II: GDB isn’t alone!](https://reverse.put.as/2009/08/26/anatomy-of-a-gdb-anti-debug-trick-part-ii-gdb-isnt-alone/)
- 2009.08 [reverse] [GDB patches](https://reverse.put.as/2009/08/26/gdb-patches/)
- 2009.08 [reverse] [Anatomy of a GDB anti-debug trick](https://reverse.put.as/2009/08/13/anatomy-of-a-gdb-anti-debug-trick/)
- 2009.08 [reverse] [Fix for Apple’s GDB bug or why Apple forks are bad...](https://reverse.put.as/2009/08/10/fix-for-apples-gdb-bug-or-why-apple-forks-are-bad/)
- 2009.08 [reverse] [Workaround for Apple’s GDB bug...](https://reverse.put.as/2009/08/06/workaround-for-apples-gdb-bug/)
- 2009.05 [pediy] [[分享]使用GDB调试程序](https://bbs.pediy.com/thread-87580.htm)
- 2009.04 [morepypy] [4 weeks of GDB](https://morepypy.blogspot.com/2009/04/4-weeks-of-gdb.html)
- 2009.04 [coldwind] [How to make your life simpler - GDB scripts embedded in assembly source code](http://gynvael.coldwind.pl/?id=177)
- 2009.03 [travisgoodspeed] [An Open GDBProxy!](http://travisgoodspeed.blogspot.com/2009/03/open-gdbproxy.html)
- 2009.01 [reverse] [How to compile GDB and other Apple open source packages in Mac OS X](https://reverse.put.as/2009/01/14/how-to-compile-gdb-and-other-apple-open-source-packages-in-mac-os-x/)
- 2008.11 [pediy] [[分享]linux 调试工具 GDB 使用教程](https://bbs.pediy.com/thread-77746.htm)
- 2008.11 [reverse] [Apple’s GDB Bug?](https://reverse.put.as/2008/11/28/apples-gdb-bug/)
- 2007.10 [reverse] [GDB input radix option](https://reverse.put.as/2007/10/18/gdb-input-radix-option/)




***


## <a id="70e64e3147675c9bcd48d4f475396e7f"></a>Monitor


### <a id="cd76e644d8ddbd385939bb17fceab205"></a>Tools


- [**1419**Star][9m] [C] [namhyung/uftrace](https://github.com/namhyung/uftrace) Function (graph) tracer for user-space
- [**186**Star][2y] [C++] [sidechannelmarvels/tracer](https://github.com/sidechannelmarvels/tracer) Set of Dynamic Binary Instrumentation and visualization tools for execution traces.
- [**157**Star][27d] [C] [immunityinc/libptrace](https://github.com/immunityinc/libptrace) An event driven multi-core process debugging, tracing, and manipulation framework.
- [**138**Star][1m] [PS] [lazywinadmin/monitor-adgroupmembership](https://github.com/lazywinadmin/Monitor-ADGroupMembership) PowerShell script to monitor Active Directory groups and send an email when someone is changing the membership
- [**115**Star][9y] [C] [ice799/ltrace](https://github.com/ice799/ltrace) ltrace intercepts and records dynamic library calls which are called by an executed process and the signals received by that process. It can also intercept and print the system calls executed by the program.
- [**110**Star][3y] [C#] [goldshtn/etrace](https://github.com/goldshtn/etrace) Command-line tool for ETW tracing on files and real-time events
- [**108**Star][30d] [ObjC] [objective-see/processmonitor](https://github.com/objective-see/processmonitor) Process Monitor Library (based on Apple's new Endpoint Security Framework)
- [**96**Star][6m] [Py] [teemu-l/execution-trace-viewer](https://github.com/teemu-l/execution-trace-viewer) Tool for viewing and analyzing execution traces
- [**91**Star][2y] [C++] [epam/nfstrace](https://github.com/epam/nfstrace) Network file system monitor and analyzer
- [**88**Star][2m] [Py] [assurancemaladiesec/certstreammonitor](https://github.com/assurancemaladiesec/certstreammonitor) Monitor certificates generated for specific domain strings and associated, store data into sqlite3 database, alert you when sites come online.
- [**83**Star][1y] [C] [marcusbotacin/branchmonitoringproject](https://github.com/marcusbotacin/branchmonitoringproject) A branch-monitor-based solution for process monitoring.
- [**82**Star][4y] [C] [eklitzke/ptrace-call-userspace](https://github.com/eklitzke/ptrace-call-userspace) Example of how to use the ptrace(2) system call to call a userspace method.
- [**71**Star][7m] [C++] [invictus1306/functrace](https://github.com/invictus1306/functrace) A function tracer
- [**68**Star][2y] [Py] [ianmiell/autotrace](https://github.com/ianmiell/autotrace) Runs a process, and gives you the output along with other telemetry on the process, all in one terminal window.
- [**62**Star][2y] [C++] [finixbit/ftrace](https://github.com/finixbit/ftrace) Simple Function calls tracer
- [**60**Star][2y] [DTrace] [brendangregg/dtrace-tools](https://github.com/brendangregg/dtrace-tools) DTrace tools for FreeBSD
- [**52**Star][3y] [C] [sciencemanx/ftrace](https://github.com/sciencemanx/ftrace) trace local function calls like strace and ltrace
- [**46**Star][6m] [Go] [oscp/openshift-monitoring](https://github.com/oscp/openshift-monitoring) A realtime distributed monitoring tool for OpenShift Enterprise
- [**44**Star][5y] [C] [rpaleari/qtrace](https://github.com/rpaleari/qtrace) QTrace, a "zero knowledge" system call tracer
- [**39**Star][4y] [C++] [simutrace/simutrace](https://github.com/simutrace/simutrace) Tracing framework for full system simulators
- [**37**Star][1y] [C] [egguncle/ptraceinject](https://github.com/egguncle/ptraceinject) 进程注入
- [**35**Star][13d] [C] [efficios/babeltrace](https://github.com/efficios/babeltrace) The Babeltrace project provides trace read and write libraries, as well as a trace converter. Plugins can be created for any trace format to allow its conversion to/from another trace format.
- [**32**Star][2y] [C] [alex9191/kernelmodemonitor](https://github.com/alex9191/kernelmodemonitor) Kernel-Mode driver and User-Mode application communication project
- [**31**Star][1y] [C] [iamgublin/ndis6.30-netmonitor](https://github.com/iamgublin/ndis6.30-netmonitor) NDIS6.30 Filter Library
- [**27**Star][2y] [C] [openbsm/bsmtrace](https://github.com/openbsm/bsmtrace) BSM based intrusion detection system
- [**26**Star][2y] [Go] [benjojo/traceroute-haiku](https://github.com/benjojo/traceroute-haiku) A thing you can traceroute and it gives you a haiku inside the trace
- [**25**Star][3m] [C] [airbus-cert/pstrace](https://github.com/airbus-cert/pstrace) Trace ScriptBlock execution for powershell v2
- [**24**Star][2y] [C++] [sshsshy/zerotrace](https://github.com/sshsshy/zerotrace) 
- [**21**Star][2y] [C++] [microsoft/firewalleventmonitor](https://github.com/microsoft/firewalleventmonitor) Listens for Firewall rule match events generated by Microsoft Hyper-V Virtual Filter Protocol (VFP) extension.




# <a id="86cb7d8f548ca76534b5828cb5b0abce"></a>Radare2


***


## <a id="0e08f9478ed8388319f267e75e2ef1eb"></a>Plugins&&Scripts


### <a id="ec3f0b5c2cf36004c4dd3d162b94b91a"></a>Radare2


- [**11588**Star][12d] [C] [radareorg/radare2](https://github.com/radareorg/radare2) unix-like reverse engineering framework and commandline tools


### <a id="6922457cb0d4b6b87a34caf39aa31dfe"></a>Recent Add


- [**410**Star][6m] [Py] [itayc0hen/a-journey-into-radare2](https://github.com/itayc0hen/a-journey-into-radare2) A series of tutorials about radare2 framework from
- [**339**Star][28d] [TeX] [radareorg/radare2book](https://github.com/radareorg/radare2book) Radare2 official book
- [**259**Star][1m] [C] [radareorg/r2dec-js](https://github.com/radareorg/r2dec-js) radare2 plugin - converts asm to pseudo-C code.
- [**258**Star][4m] [Rust] [radareorg/radeco](https://github.com/radareorg/radeco) radare2-based decompiler and symbol executor
- [**202**Star][3m] [PS] [wiredpulse/posh-r2](https://github.com/wiredpulse/posh-r2) PowerShell - Rapid Response... For the incident responder in you!
- [**183**Star][4m] [radareorg/r2con](https://github.com/radareorg/r2con) Radare Congress Stuff
- [**175**Star][2m] [C] [radareorg/radare2-extras](https://github.com/radareorg/radare2-extras) Source graveyard and random candy for radare2
- [**155**Star][2y] [C] [ifding/radare2-tutorial](https://github.com/ifding/radare2-tutorial) Reverse Engineering using Radare2
- [**149**Star][2y] [Py] [mhelwig/apk-anal](https://github.com/mhelwig/apk-anal) Android APK analyzer based on radare2 and others.
    - Also In Section: [Android->Tools->Recent Add1](#883a4e0dd67c6482d28a7a14228cd942) |
- [**126**Star][27d] [JS] [radareorg/radare2-r2pipe](https://github.com/radareorg/radare2-r2pipe) Access radare2 via pipe from any programming language!
- [**123**Star][12m] [C] [wenzel/r2vmi](https://github.com/wenzel/r2vmi) Hypervisor-Level Debugger based on Radare2 / LibVMI, using VMI IO and debug plugins
- [**108**Star][2y] [Py] [guedou/jupyter-radare2](https://github.com/guedou/jupyter-radare2) Just a simple radare2 Jupyter kernel
- [**98**Star][2m] [C] [radareorg/radare2-bindings](https://github.com/radareorg/radare2-bindings) Bindings of the r2 api for Valabind and friends
- [**97**Star][3y] [C] [s4n7h0/practical-reverse-engineering-using-radare2](https://github.com/s4n7h0/practical-reverse-engineering-using-radare2) Training Materials of Practical Reverse Engineering using Radare2
- [**94**Star][2y] [Py] [radareorg/r2con2017](https://github.com/radareorg/r2con2017) r2con 2017 September 6-9
- [**90**Star][3m] [Py] [radareorg/r2con2019](https://github.com/radareorg/r2con2019) slides and materials
- [**89**Star][4m] [Py] [securisec/r2wiki](https://github.com/securisec/r2wiki) Radare 2 wiki
- [**88**Star][1y] [TeX] [zxgio/r2-cheatsheet](https://github.com/zxgio/r2-cheatsheet) Radare2 cheat-sheet
- [**86**Star][1y] [HTML] [radareorg/r2con2018](https://github.com/radareorg/r2con2018) 
- [**82**Star][8m] [C] [nowsecure/dirtycow](https://github.com/nowsecure/dirtycow) radare2 IO plugin for Linux and Android. Modifies files owned by other users via dirtycow Copy-On-Write cache vulnerability
- [**79**Star][1m] [Shell] [radareorg/radare2-pm](https://github.com/radareorg/radare2-pm) Package Manager for Radare2
- [**78**Star][3y] [Py] [pinkflawd/r2graphity](https://github.com/pinkflawd/r2graphity) Creating function call graphs based on radare2 framwork, plot fancy graphs and extract behavior indicators
- [**68**Star][22d] [C] [radareorg/radare2-regressions](https://github.com/radareorg/radare2-regressions) Regression Tests for the Radare2 Reverse Engineer's Debugger
- [**67**Star][3y] [Java] [octopus-platform/bjoern](https://github.com/octopus-platform/bjoern) Binary analysis platform based on Octopus and Radare2
- [**63**Star][10m] [C] [zigzagsecurity/survival-guide-radare2](https://github.com/zigzagsecurity/survival-guide-radare2) Basic tutorials for reverse engineer with radare2
- [**62**Star][2y] [C] [tobaljackson/2017-sit-re-presentation](https://github.com/tobaljackson/2017-sit-re-presentation) Intro to radare2 presentation files.
- [**56**Star][2y] [JS] [jpenalbae/r2-scripts](https://github.com/jpenalbae/r2-scripts) Multiple radare2 rpipe scripts
- [**49**Star][2y] [JS] [jpenalbae/rarop](https://github.com/jpenalbae/rarop) Graphical ROP chain builder using radare2 and r2pipe
- [**41**Star][3y] [C] [bluec0re/reversing-radare2](https://github.com/bluec0re/reversing-radare2) A reversing series with radare2
- [**34**Star][3y] [CSS] [monosource/radare2-explorations](https://github.com/monosource/radare2-explorations) A book on learning radare2.
- [**33**Star][2y] [Py] [guedou/r2scapy](https://github.com/guedou/r2scapy) a radare2 plugin that decodes packets with Scapy
- [**28**Star][12m] [C] [mrmacete/r2scripts](https://github.com/mrmacete/r2scripts) Collection of scripts for radare2
- [**27**Star][3y] [Py] [gdataadvancedanalytics/r2graphity](https://github.com/gdataadvancedanalytics/r2graphity) Creating function call graphs based on radare2 framwork, plot fancy graphs and extract behavior indicators
- [**27**Star][2y] [C] [yara-rules/r2yara](https://github.com/yara-rules/r2yara) r2yara - Module for Yara using radare2 information
- [**27**Star][11m] [radareorg/r2jp](https://github.com/radareorg/r2jp) Japanese Community of radare2
- [**26**Star][3y] [C] [monosource/radare2-explorations-binaries](https://github.com/monosource/radare2-explorations-binaries) Supplement to radare2-explorations.
- [**25**Star][3y] [ObjC] [kpwn/rapd2](https://github.com/kpwn/rapd2) simple radare2 rap:// server
- [**24**Star][2y] [Rust] [sushant94/rune](https://github.com/sushant94/rune) rune - radare2 based symbolic emulator
- [**21**Star][5y] [C] [pastcompute/lca2015-radare2-tutorial](https://github.com/pastcompute/lca2015-radare2-tutorial) Examples and demos for my LCA2015 radare2 tutorial
- [**19**Star][10m] [Py] [radare/radare2-r2pipe-api](https://github.com/radare/radare2-r2pipe-api) r2pipe-api repo
- [**18**Star][2y] [Py] [countercept/radare2-scripts](https://github.com/countercept/radare2-scripts) A collection of useful radare2 scripts!
- [**18**Star][4m] [C#] [radareorg/r2wars](https://github.com/radareorg/r2wars) Corewars but within r2
- [**16**Star][2y] [arnaugamez/ncnlabs-introrewithr2](https://github.com/arnaugamez/ncnlabs-introrewithr2) 
- [**16**Star][2y] [enovella/r2con-prequals-rhme3](https://github.com/enovella/r2con-prequals-rhme3) r2 the Rhme3! The RHme (Riscure Hack me) is a low level hardware CTF that comes in the form of an Arduino board (AVR architecture). It involves a set of SW and HW challenges to test your skills in different areas such as side channel analysis, fault injection, reverse-engineering and software exploitation. In our talk we will briefly recap RHme2…
- [**16**Star][2y] [C] [safiire/radare2-dan32](https://github.com/safiire/radare2-dan32) Binary, Analysis, and Disassembler Radare2 Plugins for Dan32 architechture binaries
- [**16**Star][5y] [Py] [tyilo/kextd_patcher](https://github.com/tyilo/kextd_patcher) Patch kextd using radare2
- [**16**Star][7m] [Rust] [radareorg/r2pipe.rs](https://github.com/radareorg/r2pipe.rs) Rust crate for r2pipe
- [**15**Star][5m] [JS] [securisec/r2retdec](https://github.com/securisec/r2retdec) Use a local instance of retdec to decompile functions in radare2
- [**15**Star][2m] [C] [esanfelix/r2con2019-ctf-kernel](https://github.com/esanfelix/r2con2019-ctf-kernel) Kernel exploitation challenge(s) I prepared for the r2con 2019 CTF.
- [**14**Star][1y] [Py] [ndaprela/r2dbg](https://github.com/ndaprela/r2dbg) interface for radare2 based on r2pipe tailored for debugging
- [**13**Star][4y] [Py] [shaded-enmity/r2-ropstats](https://github.com/shaded-enmity/r2-ropstats) A set of tools based on radare2 for analysis of ROP gadgets and payloads.
- [**12**Star][1y] [C] [radare/radare2-au](https://github.com/radare/radare2-au) Audio Support for radare2
- [**11**Star][1y] [Go] [wolfvan/yararet](https://github.com/wolfvan/yararet) Carving tool based in Radare2 & Yara
- [**10**Star][3y] [Py] [newlog/r2msdn](https://github.com/newlog/r2msdn) r2 plugin to add MSDN documentation URLs and parameter names to imported function calls
- [**10**Star][4m] [Py] [ps1337/pwntools-r2](https://github.com/ps1337/pwntools-r2) Launch radare2 like a boss from pwntools in tmux
- [**10**Star][26d] [Go] [radareorg/r2pm](https://github.com/radareorg/r2pm) Radare2 cross platform package manager
- [**9**Star][7m] [Py] [jacobpimental/r2-gohelper](https://github.com/jacobpimental/r2-gohelper) gopclntab finder and analyzer for Radare2
- [**9**Star][2y] [Java] [redmed666/mal6raph](https://github.com/redmed666/mal6raph) mal6raph: 结合radare2 和 neo4j, 辅助函数级别的相似性分析
- [**8**Star][2y] [montekki/r2evm](https://github.com/montekki/r2evm) 
- [**8**Star][3y] [Py] [newlog/r2com](https://github.com/newlog/r2com) radare2 script to help on COM objects reverse engineering
- [**8**Star][3y] [C] [radare/gradare2](https://github.com/radare/gradare2) Port of gradare GTK/VTE frontend to r2
- [**7**Star][12m] [Rust] [radareorg/esil-rs](https://github.com/radareorg/esil-rs) Radare2's ESIL in Rust
- [**7**Star][3y] [Py] [thestr4ng3r/bokken](https://github.com/thestr4ng3r/bokken) Bokken is a GUI for radare2. Don't use this, use
- [**6**Star][2y] [Py] [d00rt/gootkit_string_patcher](https://github.com/d00rt/gootkit_string_patcher) A python script using radare2 for decrypt and patch the strings of GootKit malware
- [**6**Star][2y] [Py] [h4ng3r/r2apktool](https://github.com/h4ng3r/r2apktool) radare2 based alternative to apktool
- [**6**Star][27d] [Dockerfile] [kr1tzb1tz/r2playground](https://github.com/kr1tzb1tz/r2playground) 
- [**6**Star][4m] [C] [radareorg/r2hexagon](https://github.com/radareorg/r2hexagon) Hexagon disassembler code generator from the official instruction manual.
- [**5**Star][2y] [jacobpimental/intro-to-radare2](https://github.com/jacobpimental/intro-to-radare2) 
- [**5**Star][12m] [securisec/r2wiki-rtd](https://github.com/securisec/r2wiki-rtd) r2wiki for readthedocs
- [**4**Star][4y] [Py] [andrewaeva/strange-functions](https://github.com/andrewaeva/strange-functions) Extract functions and opcodes with radare2
- [**4**Star][1y] [Py] [mytbk/radare-uefi](https://github.com/mytbk/radare-uefi) helper radare2 script to analyze UEFI firmware modules
- [**4**Star][7m] [Rust] [xermicus/r2deob](https://github.com/xermicus/r2deob) deobfuscation PoC with r2 + ESIL
- [**3**Star][2y] [Py] [antonin-deniau/bnstrings](https://github.com/antonin-deniau/bnstrings) Binaryninja plugin that use radare2 to find and add strings to binaryninja
- [**2**Star][3y] [h4ng3r/r2dextest](https://github.com/h4ng3r/r2dextest) Dalvik tests generator for radare2 using on androguard
- [**2**Star][2y] [C++] [jubal-r/ronin](https://github.com/jubal-r/ronin) Radare2 GUI
- [**0**Star][1y] [Py] [d4em0n/r2snow](https://github.com/d4em0n/r2snow) Integrate radare2 with snowman decompiler


### <a id="1a6652a1cb16324ab56589cb1333576f"></a>With Other Tools


#### <a id="dfe53924d678f9225fc5ece9413b890f"></a>No Category


- [**378**Star][27d] [JS] [nowsecure/r2frida](https://github.com/nowsecure/r2frida) Radare2 and Frida better together.
    - Also In Section: [DBI->Frida->Tools->With Other Tools->Radare2](#ac053c4da818ca587d57711d2ff66278) |
- [**79**Star][8m] [Py] [guedou/r2m2](https://github.com/guedou/r2m2) radare2 + miasm2 = ♥
- [**47**Star][11m] [Py] [nowsecure/r2lldb](https://github.com/nowsecure/r2lldb) radare2-lldb integration
- [**34**Star][12m] [CSS] [nowsecure/r2frida-book](https://github.com/nowsecure/r2frida-book) The radare2 + frida book for Mobile Application assessment
    - Also In Section: [DBI->Frida->Tools->With Other Tools->Radare2](#ac053c4da818ca587d57711d2ff66278) |


#### <a id="1cfe869820ecc97204a350a3361b31a7"></a>IDA


- [**175**Star][14d] [C++] [radareorg/r2ghidra-dec](https://github.com/radareorg/r2ghidra-dec) Deep ghidra decompiler integration for radare2
    - Also In Section: [Ghidra->Plugins->With Other Tools->Radare2](#e1cc732d1388084530b066c26e24887b) |
- [**125**Star][8m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->Import Export->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[IDA->Tools->Function->No Category](#347a2158bdd92b00cd3d4ba9a0be00ae) |
- [**123**Star][2m] [Py] [radare/radare2ida](https://github.com/radare/radare2ida) Tools, documentation and scripts to move projects from IDA to R2 and viceversa
    - Also In Section: [IDA->Tools->Import Export->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |




### <a id="f7778a5392b90b03a3e23ef94a0cc3c6"></a>GUI


#### <a id="8f151d828263d3bc038f75f8d6418758"></a>GUI


- [**67**Star][1y] [JS] [radareorg/radare2-webui](https://github.com/radareorg/radare2-webui) webui repository for radare2
- [**47**Star][8y] [Py] [radare/bokken](https://github.com/radare/bokken) python-gtk UI for radare2
- [**35**Star][3y] [C#] [m4ndingo/radare2gui_dotnet](https://github.com/m4ndingo/radare2gui_dotnet) Another radare2 gui for windows
- [**23**Star][2y] [c++] [dax89/r2gui](https://github.com/dax89/r2gui) Unofficial Qt5 frontend for Radare2


#### <a id="df45c3c60bd074e21d650266aa85c241"></a>Cutter


- [**6176**Star][8d] [C++] [radareorg/cutter](https://github.com/radareorg/cutter) Reverse Engineering Platform powered by radare2
- [**8**Star][8m] [Py] [daringjoker/assembly-refrence](https://github.com/daringjoker/assembly-refrence) A plugin for Cutter that show the information about the assembly instruction currently selected .. only for x86 and x64
- [**8**Star][9m] [Py] [radareorg/cutter-jupyter](https://github.com/radareorg/cutter-jupyter) Jupyter Plugin for Cutter
- [**6**Star][10m] [Py] [securitykitten/cutter_scripts](https://github.com/securitykitten/cutter_scripts) A collection of scripts for Cutter
- [**2**Star][6m] [Py] [javieryuste/radare2-deep-graph](https://github.com/javieryuste/radare2-deep-graph) A Cutter plugin to generate radare2 graphs






***


## <a id="95fdc7692c4eda74f7ca590bb3f12982"></a>Posts&&Videos


### <a id="a4debf888d112b91e56c90136f513ec0"></a>未分类


- 2019.10 [prsecurity] [Radare2 for RE CTF](https://medium.com/p/e0163cb0466e)
- 2019.09 [securityartwork] [YaraRET (I): Carving with Radare2 & Yara](https://www.securityartwork.es/2019/09/02/yararet-i-carving-with-radare2-yara/)
- 2019.07 [freebuf] [教你使用Cutter和Radare2对APT32恶意程序流程图进行反混淆处理](https://www.freebuf.com/articles/network/208019.html)
- 2019.07 [THER] [0x0D - FLARE-On #3 Challenge Part 2 [Reversing with Radare2]](https://www.youtube.com/watch?v=QP9Cepdqf-o)
- 2019.07 [THER] [0x09 Cross References [Reversing with Radare2]](https://www.youtube.com/watch?v=yOtx6LL_R08)
- 2019.07 [THER] [0x08 Navigation [Reversing with Radare2]](https://www.youtube.com/watch?v=rkygJSjJbso)
- 2019.07 [THER] [0x04 Target Application [Reversing with Radare2]](https://www.youtube.com/watch?v=jlr3FablVIc)
- 2019.06 [THER] [0x03 Environment Setup [Reversing with Radare2]](https://www.youtube.com/watch?v=qGSFk_CkIaw)
- 2019.06 [THER] [0x02 What is Radare2 [Reversing with Radare2]](https://www.youtube.com/watch?v=9fLfD2fZWiA)
- 2019.06 [THER] [0x00 Intro [Reversing with Radare2]](https://www.youtube.com/watch?v=Lva32dXS0mU)
- 2019.06 [hitbsecconf] [#HITB2019AMS D1T3 - Overcoming Fear: Reversing With Radare2 - Arnau Gamez Montolio](https://www.youtube.com/watch?v=317dNavABKo)
- 2019.05 [X0x0FFB347] [Solving MalwareTech Shellcode challenges with some radare2 magic!](https://medium.com/p/b91c85babe4b)
- 2019.05 [360] [使用Cutter和Radare2对APT32恶意程序流程图进行反混淆处理](https://www.anquanke.com/post/id/178047/)
- 2019.05 [SagiDana] [Radare2 — Keep It Or Leave It?](https://medium.com/p/3d45059ec0d1)
- 2019.04 [X0x0FFB347] [Solving MalwareTech String Challenges With Some Radare2 Magic!](https://medium.com/p/98ebd8ff0b88)
- 2019.04 [radare] [Radare2 Summer of Code 2019 Selection Results](https://radareorg.github.io/blog/posts/rsoc-2019-selection/)
- 2019.04 [radare] [Radare2 Summer of Code 2019 Selection Results](http://radare.today/posts/rsoc-2019-selection/)
- 2019.03 [sans] [Binary Analysis with Jupyter and Radare2](https://isc.sans.edu/forums/diary/Binary+Analysis+with+Jupyter+and+Radare2/24748/)
- 2019.02 [freebuf] [Radare2：一款类Unix命令行逆向安全框架](https://www.freebuf.com/sectool/195703.html)
- 2019.02 [radare] [Radare2 Community Survey Results](http://radare.today/posts/radare2-survey/)
- 2019.02 [radare] [Radare2 Community Survey Results](https://radareorg.github.io/blog/posts/radare2-survey/)
- 2019.01 [ly0n] [Kaspersky “Terminal.exe” crackme analysis with Radare2](http://ly0n.me/2019/01/25/kaspersky-terminal-exe-crackme-analysis-with-radare2/)
- 2019.01 [ly0n] [Kaspersky “Terminal.exe” crackme analysis with Radare2](https://paumunoz.tech/2019/01/25/kaspersky-terminal-exe-crackme-analysis-with-radare2/)
- 2019.01 [ly0n] [Reversing x64 linux code with Radare2 part II](http://ly0n.me/2019/01/14/reversing-x64-linux-code-with-radare2-part-ii/)
- 2019.01 [ly0n] [Reversing x64 linux code with Radare2 part II](https://paumunoz.tech/2019/01/14/reversing-x64-linux-code-with-radare2-part-ii/)
- 2019.01 [ly0n] [Reversing C code in x64 systems with Radare2 part I](http://ly0n.me/2019/01/10/reversing-c-code-in-x64-systems-with-radare2-part-i/)
- 2019.01 [ly0n] [Reversing C code in x64 systems with Radare2 part I](https://paumunoz.tech/2019/01/10/reversing-c-code-in-x64-systems-with-radare2-part-i/)
- 2018.10 [DEFCONConference] [DEF CON 26 CAR HACKING VILLAGE - Ben Gardiner - CAN Signal Extraction from OpenXC with Radare2](https://www.youtube.com/watch?v=UoevuAS-4dM)
- 2018.10 [PancakeNopcode] [r2con2018 - Bug Classification using radare2 - by Andrea Sindoni](https://www.youtube.com/watch?v=p8DIu81JV2g)
- 2018.10 [moveax] [Protostar: Unravel stack0 with Radare2](https://moveax.me/stack0/)
- 2018.08 [radare] [Radare2 and bioinformatics: a good match?](http://radare.today/posts/radare2-bioinformatics/)
- 2018.08 [radare] [Radare2 and bioinformatics: a good match?](https://radareorg.github.io/blog/posts/radare2-bioinformatics/)
- 2018.07 [radare] [Background Tasks in radare2](https://radareorg.github.io/blog/posts/background_tasks/)
- 2018.07 [radare] [Background Tasks in radare2](http://radare.today/posts/background_tasks/)
- 2018.07 [pediy] [[翻译]radare2高阶](https://bbs.pediy.com/thread-229524.htm)
- 2018.07 [pediy] [[翻译]Radare2进阶](https://bbs.pediy.com/thread-229523.htm)
- 2018.07 [pediy] [[翻译]radare2入门](https://bbs.pediy.com/thread-229522.htm)
- 2018.06 [megabeets] [Decrypting APT33’s Dropshot Malware with Radare2 and Cutter – Part 2](https://www.megabeets.net/decrypting-dropshot-with-radare2-and-cutter-part-2/)
- 2018.06 [sans] [Binary analysis with Radare2](https://isc.sans.edu/forums/diary/Binary+analysis+with+Radare2/23723/)
- 2018.05 [megabeets] [Decrypting APT33’s Dropshot Malware with Radare2 and Cutter  – Part 1](https://www.megabeets.net/decrypting-dropshot-with-radare2-and-cutter-part-1/)
- 2018.04 [moveax] [Dr Von Noizeman’s Nuclear Bomb defused with Radare2](https://moveax.me/dr-von-noizemans-binary-bomb/)
- 2018.04 [reversingminds] [Easy way for analyzing the GootKit banking malware with radare2](http://reversingminds-blog.logdown.com/posts/7369479)
- 2018.03 [pediy] [[翻译]在Windows平台下的使用radare2进行调试](https://bbs.pediy.com/thread-225529.htm)
- 2018.03 [moveax] [BombLab Dissected with Radare2](https://moveax.me/bomblab/)
- 2018.03 [dustri] [Radare2 is accepted in the Google Summer of Code 2018](https://dustri.org/b/radare2-is-accepted-in-the-google-summer-of-code-2018.html)
- 2018.03 [moveax] [IOLI-Crackme with Radare2: Closing Thoughts](https://moveax.me/ioli-crackme-radare2/)
- 2018.02 [moveax] [Crackme0x09 Dissected with Radare2](https://moveax.me/crackme0x09/)
- 2018.02 [moveax] [Crackme0x08 Dissected with Radare2](https://moveax.me/crackme0x08/)
- 2018.02 [moveax] [Crackme0x07 Dissected with Radare2](https://moveax.me/crackme0x07/)
- 2018.02 [moveax] [Crackme0x06 Dissected with Radare2](https://moveax.me/crackme0x06/)
- 2018.01 [moveax] [Crackme0x05 Dissected with Radare2](https://moveax.me/crackme0x05/)
- 2018.01 [moveax] [Crackme0x04 Dissected with Radare2](https://moveax.me/crackme0x04/)
- 2018.01 [moveax] [Radare2’s Visual Mode](https://moveax.me/radare2-visual-mode/)
- 2018.01 [moveax] [Crackme0x03 Dissected with Radare2](https://moveax.me/crackme0x03/)
- 2018.01 [megabeets] [Reversing a Self-Modifying Binary with radare2](https://www.megabeets.net/reversing-a-self-modifying-binary-with-radare2/)
- 2018.01 [moveax] [Crackme0x02 Dissected with Radare2](https://moveax.me/crackme0x02/)
- 2018.01 [moveax] [Crackme0x01 Dissected with Radare2](https://moveax.me/crackme0x01/)
- 2018.01 [moveax] [An excuse to learn Radare2](https://moveax.me/radare-intro/)
- 2017.12 [positive] [Debugging EVM bytecode with radare2](https://medium.com/p/9e0e13cbd936)
- 2017.12 [goggleheadedhacker] [Reverse Engineering With Radare2 — Part 2](https://goggleheadedhacker.com/blog/post/2)
- 2017.12 [positive] [Reversing EVM bytecode with radare2](https://medium.com/p/ab77247e5e53)
- 2017.12 [jacob16682] [Reverse Engineering With Radare2 — Part 2](https://medium.com/p/83b71df7ffe4)
- 2017.12 [goggleheadedhacker] [Reverse Engineering Using Radare2](https://goggleheadedhacker.com/blog/post/1)
- 2017.12 [jacob16682] [Reverse Engineering Using Radare2](https://medium.com/p/588775ea38d5)
- 2017.12 [radiofreerobotron] [ROPEmporium: Pivot 64-bit CTF Walkthrough With Radare2](http://radiofreerobotron.net/blog/2017/12/04/ropemporium-pivot-ctf-walkthrough2/)
- 2017.12 [PancakeNopcode] [recon2017 - Bubble Struggle Call Graph Visualization with Radare2 - by mari0n](https://www.youtube.com/watch?v=ofRP2PorryU)
- 2017.11 [radiofreerobotron] [ROPEmporium: Pivot 32-bit CTF Walkthrough With Radare2](http://radiofreerobotron.net/blog/2017/11/23/ropemporium-pivot-ctf-walkthrough/)
- 2017.11 [aliyun] [Radare2使用实战](https://xz.aliyun.com/t/1515)
- 2017.11 [aliyun] [Radare2使用全解](https://xz.aliyun.com/t/1514)
- 2017.11 [dustri] [Solving game2 from the badge of Black Alps 2017 with radare2](https://dustri.org/b/solving-game2-from-the-badge-of-black-alps-2017-with-radare2.html)
- 2017.10 [animal0day] [Hack.lu - HeapHeaven write-up with radare2 and pwntools (ret2libc)](https://animal0day.blogspot.com/2017/10/hacklu-heapheaven-write-up-with-radare2.html)
- 2017.10 [megabeets] [Reverse engineering a Gameboy ROM with radare2](https://www.megabeets.net/reverse-engineering-a-gameboy-rom-with-radare2/)
- 2017.09 [PancakeNopcode] [r2con2017 - Diaphora with radare2 by matalaz and pancake](https://www.youtube.com/watch?v=dAwXrUKaUsw)
- 2017.09 [dustri] [Defeating IOLI with radare2 in 2017](https://dustri.org/b/defeating-ioli-with-radare2-in-2017.html)
- 2017.08 [rkx1209] [GSoC Final: radare2 Timeless Debugger](https://rkx1209.github.io/2017/08/27/gsoc-final-report.html)
- 2017.08 [rootedconmadrid] [ABEL VALERO - Radare2 - 1.0 [Rooted CON 2017 - ENG]](https://www.youtube.com/watch?v=wCDIWllIiag)
- 2017.08 [rootedconmadrid] [ABEL VALERO - Radare2 - 1.0 [Rooted CON 2017 - ESP]](https://www.youtube.com/watch?v=Bt7WJNwXw3M)
- 2017.07 [pediy] [[翻译]Radare2文档(1)](https://bbs.pediy.com/thread-219090.htm)
- 2017.05 [n0where] [Reverse Engineering Framework: radare2](https://n0where.net/reverse-engineering-framework-radare2)
- 2017.03 [radare] [Radare2 and Capstone](https://radareorg.github.io/blog/posts/radare2-capstone/)
- 2017.03 [radare] [Radare2 and Capstone](http://radare.today/posts/radare2-capstone/)
- 2017.03 [xpnsec] [Radare2 - Using Emulation To Unpack Metasploit Encoders](https://blog.xpnsec.com/radare2-using-emulation-to-unpack-metasploit-encoders/)
- 2017.01 [PancakeNopcode] [Reversing with Radare2 at OverdriveCon (unofficial periscope stream)](https://www.youtube.com/watch?v=Z_8RkFNnpJw)
- 2017.01 [PancakeNopcode] [radare2 1.0 r2con](https://www.youtube.com/watch?v=tPmyMfZSr_4)
- 2016.11 [dustri] [Radare2 at the Grehack 2016](https://dustri.org/b/radare2-at-the-grehack-2016.html)
- 2016.11 [X0x6d696368] [OpenOCD (ARC dev branch) dumping Zheino A1 firmware (with plausability check via radare2)](https://www.youtube.com/watch?v=npT2Y8DTEbI)
- 2016.10 [securityblog] [Install latest radare2 on Kali](http://securityblog.gr/3791/install-latest-radare2-on-kali/)
- 2016.10 [insinuator] [Reverse Engineering With Radare2 – Part 3](https://insinuator.net/2016/10/reverse-engineering-with-radare2-part-3/)
- 2016.10 [X0x6d696368] [OpenOCD dumping WD800JG firmware via Bus Blaster ... then import into Radare2](https://www.youtube.com/watch?v=IwnPbNhd2GM)
- 2016.10 [unlogic] [FrogSEK KGM video walkthrough with radare2](http://unlogic.co.uk/2016/10/13/FrogSEK%20KGM%20video%20walkthrough%20with%20radare2/index.html)
- 2016.10 [unlogic] [FrogSEK KGM video walkthrough with radare2](https://www.unlogic.co.uk/2016/10/13/frogsek-kgm-video-walkthrough-with-radare2/)
- 2016.09 [securityblog] [Disassembling functions with Radare2](http://securityblog.gr/3648/disassembling-functions-with-radare2/)
- 2016.09 [PancakeNopcode] [Presentación de radare2 en la FiberParty 2009 (spanish)](https://www.youtube.com/watch?v=4AEEKsR8JJs)
- 2016.09 [dustri] [Defeating crp-'s collide with radare2](https://dustri.org/b/defeating-crp-s-collide-with-radare2.html)
- 2016.09 [PancakeNopcode] [r2con - pwning embedded systems with radare2 by Daniel Romero](https://www.youtube.com/watch?v=u9auCsrjPBQ)
- 2016.09 [PancakeNopcode] [r2con 2016 - Jay Rosenberg - Improving PE analysis on radare2](https://www.youtube.com/watch?v=HOYVQvRuZ_M)
- 2016.09 [PancakeNopcode] [r2con 2016 - SkUaTeR patching Cidox via radare2's r2k:// on kernel demo](https://www.youtube.com/watch?v=8c-g5STp114)
- 2016.08 [insinuator] [Reverse Engineering With Radare2 – Part 2](https://insinuator.net/2016/08/reverse-engineering-with-radare2-part-2/)
- 2016.08 [insinuator] [Reverse Engineering With Radare2 – Part 1](https://insinuator.net/2016/08/reverse-engineering-with-radare2-part-1/)
- 2016.08 [radare] [Retrieving configuration of a Remote Administration Tool (Malware) with radare2 statically](http://radare.today/posts/malware-static-analysis/)
- 2016.08 [radare] [Retrieving configuration of a Remote Administration Tool (Malware) with radare2 statically](https://radareorg.github.io/blog/posts/malware-static-analysis/)
- 2016.08 [radare] [Crosscompile radare2 with dockcross](http://radare.today/posts/dockcross/)
- 2016.08 [radare] [Crosscompile radare2 with dockcross](https://radareorg.github.io/blog/posts/dockcross/)
- 2016.08 [insinuator] [Reverse Engineering With Radare2 – Intro](https://insinuator.net/2016/08/reverse-engineering-with-radare2-intro/)
- 2016.08 [PancakeNopcode] [Neuroflip's radare2 0 sidparty (2010-03-17)](https://www.youtube.com/watch?v=DBKMGWXoliU)
- 2016.06 [devit] [Diving Into Radare2](https://blog.devit.co/diving-into-radare2/)
- 2016.06 [unlogic] [crackserial_linux with radare2](http://unlogic.co.uk/2016/06/13/crackserial_linux%20with%20radare2/index.html)
- 2016.06 [unlogic] [crackserial_linux with radare2](https://www.unlogic.co.uk/2016/06/13/crackserial_linux-with-radare2/)
- 2016.06 [radare] [Radare2 Explorations: New book released!](http://radare.today/posts/radare2-explorations/)
- 2016.06 [radare] [Radare2 Explorations: New book released!](https://radareorg.github.io/blog/posts/radare2-explorations/)
- 2016.06 [unlogic] [Binary Bomb with Radare2 - Secret Phase](http://unlogic.co.uk/2016/06/06/Binary%20Bomb%20with%20Radare2%20-%20Secret%20Phase/index.html)
- 2016.06 [unlogic] [Binary Bomb with Radare2 - Secret Phase](https://www.unlogic.co.uk/2016/06/06/binary-bomb-with-radare2-secret-phase/)
- 2016.05 [unlogic] [Binary Bomb with Radare2 - Phase 6](http://unlogic.co.uk/2016/05/27/Binary%20Bomb%20with%20Radare2%20-%20Phase%206/index.html)
- 2016.05 [unlogic] [Binary Bomb with Radare2 - Phase 6](https://www.unlogic.co.uk/2016/05/27/binary-bomb-with-radare2-phase-6/)
- 2016.05 [unlogic] [Binary Bomb with Radare2 - Phase 5](http://unlogic.co.uk/2016/05/12/Binary%20Bomb%20with%20Radare2%20-%20Phase%205/index.html)
- 2016.05 [unlogic] [Binary Bomb with Radare2 - Phase 5](https://www.unlogic.co.uk/2016/05/12/binary-bomb-with-radare2-phase-5/)
- 2016.05 [unlogic] [Binary Bomb with Radare2 - Phase 4](http://unlogic.co.uk/2016/05/05/Binary%20Bomb%20with%20Radare2%20-%20Phase%204/index.html)
- 2016.05 [unlogic] [Binary Bomb with Radare2 - Phase 4](https://www.unlogic.co.uk/2016/05/05/binary-bomb-with-radare2-phase-4/)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Phase 3](http://unlogic.co.uk/2016/04/27/Binary%20Bomb%20with%20Radare2%20-%20Phase%203/index.html)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Phase 3](https://www.unlogic.co.uk/2016/04/27/binary-bomb-with-radare2-phase-3/)
- 2016.04 [PancakeNopcode] [Radare2 from A to Z @ NcN 2015](https://www.youtube.com/watch?v=fM802s0tiDw)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Phase 2](http://unlogic.co.uk/2016/04/20/Binary%20Bomb%20with%20Radare2%20-%20Phase%202/index.html)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Phase 2](https://www.unlogic.co.uk/2016/04/20/binary-bomb-with-radare2-phase-2/)
- 2016.04 [aassfxxx] [Breaking Cerber strings obfuscation with Python and radare2](http://aassfxxx.infos.st/article26/breaking-cerber-strings-obfuscation-with-python-and-radare2)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Phase 1](http://unlogic.co.uk/2016/04/14/Binary%20Bomb%20with%20Radare2%20-%20Phase%201/index.html)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Phase 1](https://www.unlogic.co.uk/2016/04/14/binary-bomb-with-radare2-phase-1/)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Prelude](http://unlogic.co.uk/2016/04/12/Binary%20Bomb%20with%20Radare2%20-%20Prelude/index.html)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Prelude](https://www.unlogic.co.uk/2016/04/12/binary-bomb-with-radare2-prelude/)
- 2016.03 [techorganic] [Radare 2 in 0x1E minutes](https://blog.techorganic.com/2016/03/08/radare-2-in-0x1e-minutes/)
- 2016.02 [ZeroNights] [Anton Kochkov — ESIL — universal IL (Intermediate Language) for Radare2](https://www.youtube.com/watch?v=hVD6ev_9VgE)
- 2016.01 [freebuf] [使用Radare2和Ruby开发恶意软件配置解析器](http://www.freebuf.com/articles/system/94912.html)
- 2016.01 [dustri] [How to radare2 a fake openssh exploit](https://dustri.org/b/how-to-radare2-a-fake-openssh-exploit.html)
- 2015.12 [PancakeNopcode] [Radare2 on Apple Watch](https://www.youtube.com/watch?v=MKZCBYCMh78)
- 2015.12 [radare] [Unpacking shikata-ga-nai by scripting radare2](http://radare.today/posts/unpacking-shikata-ga-nai-by-scripting-radare2/)
- 2015.12 [radare] [Unpacking shikata-ga-nai by scripting radare2](https://radareorg.github.io/blog/posts/unpacking-shikata-ga-nai-by-scripting-radare2/)
- 2015.11 [dustri] [Exploiting exp200 from Defcamp 2015 finals with radare2](https://dustri.org/b/exploiting-exp200-from-defcamp-2015-finals-with-radare2.html)
- 2015.11 [dustri] [Reversing re200 from Defcamp (D-CTF) final 2015 with radare2](https://dustri.org/b/reversing-re200-from-defcamp-d-ctf-final-2015-with-radare2.html)
- 2015.11 [PancakeNopcode] [Radare2's September Gource](https://www.youtube.com/watch?v=gJnGlmHmQVY)
- 2015.10 [PancakeNopcode] [Skuater and ThePoPe explaining how the ESIL evaluation loop works. #radare2 #nn5ed #navajasnegras](https://www.youtube.com/watch?v=qiuLdZ9kXLY)
- 2015.08 [dustri] [Pwning exploit400 from the Nullcon 2014 CTF with radare2](https://dustri.org/b/pwning-exploit400-from-the-nullcon-2014-ctf-with-radare2.html)
- 2015.08 [dustri] [Pwning sushi from BSides Vancouver CTF with radare2](https://dustri.org/b/pwning-sushi-from-bsides-vancouver-ctf-with-radare2.html)
- 2015.05 [radare] [Defeating baby_rop with radare2](http://radare.today/posts/defeating-baby_rop-with-radare2/)
- 2015.05 [radare] [Defeating baby_rop with radare2](https://radareorg.github.io/blog/posts/defeating-baby_rop-with-radare2/)
- 2015.05 [radare] [Using radare2 to pwn things](http://radare.today/posts/using-radare2/)
- 2015.05 [radare] [Using radare2 to pwn things](https://radareorg.github.io/blog/posts/using-radare2/)
- 2015.04 [dustri] [Exploiting ezhp (pwn200) from PlaidCTF 2014 with radare2](https://dustri.org/b/exploiting-ezhp-pwn200-from-plaidctf-2014-with-radare2.html)
- 2015.04 [PancakeNopcode] [Radare2 debugger swipe on UbuntuTouch](https://www.youtube.com/watch?v=QrTHvJ3MSt8)
- 2015.01 [radare] [Parsing a fileformat with radare2](http://radare.today/posts/parsing-a-fileformat-with-radare2/)
- 2015.01 [radare] [Parsing a fileformat with radare2](https://radareorg.github.io/blog/posts/parsing-a-fileformat-with-radare2/)
- 2014.12 [dustri] [Exploiting Zengarden (Boston Key Party 2014, pwn300) with radare2](https://dustri.org/b/exploiting-zengarden-boston-key-party-2014-pwn300-with-radare2.html)
- 2014.11 [radare] [Radare2 is documented](http://radare.today/posts/radare2-is-documented/)
- 2014.11 [radare] [Radare2 is documented](https://radareorg.github.io/blog/posts/radare2-is-documented/)
- 2014.10 [radare] [Solving 'At gunpoint' from hack.lu 2014 with radare2](http://radare.today/posts/solving-at-gunpoint-from-hack-lu-2014-with-radare2/)
- 2014.10 [radare] [Solving 'At gunpoint' from hack.lu 2014 with radare2](https://radareorg.github.io/blog/posts/solving-at-gunpoint-from-hack-lu-2014-with-radare2/)
- 2014.09 [radare] [Adventures with Radare2 #1: A Simple Shellcode Analysis](http://radare.today/posts/adventures-with-radare2-1-a-simple-shellcode-analysis/)
- 2014.09 [radare] [Adventures with Radare2 #1: A Simple Shellcode Analysis](https://radareorg.github.io/blog/posts/adventures-with-radare2-1-a-simple-shellcode-analysis/)
- 2014.08 [dustri] [PwniumCTF 2014 - kernel (150) with radare2](https://dustri.org/b/pwniumctf-2014-kernel-150-with-radare2.html)
- 2014.05 [radare] [Getting the latest radare2](http://radare.today/posts/getting-the-latest-radare2/)
- 2014.05 [radare] [Getting the latest radare2](https://radareorg.github.io/blog/posts/getting-the-latest-radare2/)
- 2014.03 [theevilbit] [radare2 reverse engineering framework: rasm2](http://theevilbit.blogspot.com/2014/03/radare2-reverse-engineering-framework.html)
- 2014.03 [theevilbit] [radare2 reverse engineering framework: rax2](http://theevilbit.blogspot.com/2014/03/radare2-reverse-engineering-framework_16.html)
- 2013.12 [toolswatch] [radare2, the reverse engineering framework v0.9.6 released](http://www.toolswatch.org/2013/12/radare2-the-reverse-engineering-framework-v0-9-6-released/)
- 2013.11 [dustri] [Defeating crackme03 with radare2](https://dustri.org/b/defeating-crackme03-with-radare2.html)
- 2013.08 [dustri] [Defeating ioli with radare2](https://dustri.org/b/defeating-ioli-with-radare2.html)
- 2013.08 [dustri] [Defeating crp-'s bf with radare2](https://dustri.org/b/defeating-crp-s-bf-with-radare2.html)
- 2013.08 [dustri] [Defeating crp-'s 888 with radare2](https://dustri.org/b/defeating-crp-s-888-with-radare2.html)
- 2012.08 [dustri] [Defeating lincrackme3 with radare2](https://dustri.org/b/defeating-lincrackme3-with-radare2.html)


### <a id="d86e19280510aee0bcf2599f139cfbf7"></a>Cutter


- 2019.12 [megabeets] [5 Ways to patch binaries with Cutter](https://www.megabeets.net/5-ways-to-patch-binaries-with-cutter/)
- 2019.07 [THER] [0x0C - Cutter: FLARE-On #3 Challenge Part 1 [Reversing with Radare2]](https://www.youtube.com/watch?v=hbEpVwD5rJI)
- 2018.10 [PancakeNopcode] [r2con2018 - Cutter by @xarkes](https://www.youtube.com/watch?v=w8Bl5ZSmmZM)
- 2018.08 [radare] [GSoC 2018 Final: Debugging and Emulation Support for Cutter](https://radareorg.github.io/blog/posts/cutter_debug/)
- 2017.12 [n0where] [Qt C++ radare2 GUI: Cutter](https://n0where.net/qt-c-radare2-gui-cutter)




# <a id="afb7259851922935643857c543c4b0c2"></a>BinaryNinja


***


## <a id="3034389f5aaa9d7b0be6fa7322340aab"></a>Plugins&&Scripts


### <a id="a750ac8156aa0ff337a8639649415ef1"></a>Recent Add


- [**2820**Star][1m] [Py] [androguard/androguard](https://github.com/androguard/androguard) Reverse engineering, Malware and goodware analysis of Android applications ... and more (ninja !)
- [**498**Star][4y] [Py] [vector35/deprecated-binaryninja-python](https://github.com/vector35/deprecated-binaryninja-python) Deprecated Binary Ninja prototype written in Python
- [**328**Star][5m] [Py] [vector35/binaryninja-api](https://github.com/vector35/binaryninja-api) Public API, examples, documentation and issues for Binary Ninja
- [**280**Star][3m] [Py] [pbiernat/ripr](https://github.com/pbiernat/ripr) Package Binary Code as a Python class using Binary Ninja and Unicorn Engine
- [**201**Star][14d] [JS] [ret2got/disasm.pro](https://github.com/ret2got/disasm.pro) A realtime assembler/disassembler (formerly known as disasm.ninja)
- [**177**Star][6m] [Py] [trailofbits/binjascripts](https://github.com/trailofbits/binjascripts) Scripts for Binary Ninja
- [**141**Star][2y] [Py] [snare/binjatron](https://github.com/snare/binjatron) Binary Ninja plugin for Voltron integration
- [**95**Star][3y] [appsecco/defcon24-infra-monitoring-workshop](https://github.com/appsecco/defcon24-infra-monitoring-workshop) Defcon24 Workshop Contents : Ninja Level Infrastructure Monitoring
- [**85**Star][3y] [Py] [vector35/binaryninja-plugins](https://github.com/vector35/binaryninja-plugins) Repository to track Binary Ninja Plugins, Themes, and other related tools
- [**56**Star][2m] [Py] [forallsecure/bncov](https://github.com/forallsecure/bncov) Scriptable Binary Ninja plugin for coverage analysis and visualization
- [**40**Star][1y] [Py] [cetfor/papermachete](https://github.com/cetfor/papermachete) A project that uses Binary Ninja and GRAKN.AI to perform static analysis on binary files with the goal of identifying bugs in software.
- [**37**Star][10m] [Py] [carstein/annotator](https://github.com/carstein/Annotator) Binary Ninja Function Annotator
- [**31**Star][3y] [Py] [nopdev/binjadock](https://github.com/nopdev/binjadock) An extendable, tabbed, dockable UI widget plugin for BinaryNinja
- [**31**Star][1m] [Py] [whitequark/binja_itanium_cxx_abi](https://github.com/whitequark/binja_itanium_cxx_abi) Binary Ninja Itanium C++ ABI Plugin
- [**31**Star][6m] [Py] [withzombies/bnil-graph](https://github.com/withzombies/bnil-graph) A BinaryNinja plugin to graph a BNIL instruction tree
- [**29**Star][2y] [Py] [ernw/binja-ipython](https://github.com/ernw/binja-ipython) A plugin to integrate an IPython kernel into Binary Ninja.
- [**28**Star][6m] [Py] [fluxchief/binaryninja_avr](https://github.com/fluxchief/binaryninja_avr) Binaryninja AVR architecture plugin with lifting
- [**25**Star][4m] [Py] [trailofbits/objcgraphview](https://github.com/trailofbits/objcgraphview) A graph view plugin for Binary Ninja to visualize Objective-C
- [**25**Star][19d] [Py] [riverloopsec/hashashin](https://github.com/riverloopsec/hashashin) Hashashin: A Fuzzy Matching Tool for Binary Ninja
- [**24**Star][2y] [Py] [nccgroup/binja_dynamics](https://github.com/nccgroup/binja_dynamics) A PyQt5 frontend to the binjatron plugin for Binary Ninja that includes highlighting features aimed at making it easier for beginners to learn about reverse engineering
- [**21**Star][6m] [Py] [zznop/binjago](https://github.com/zznop/binjago) Binary Ninja plugin for ROP gadget calculation
- [**19**Star][4m] [Py] [joshwatson/binaryninja-msp430](https://github.com/joshwatson/binaryninja-msp430) msp430 Architecture plugin for Binary Ninja
- [**18**Star][2y] [Py] [joshwatson/binaryninja-bookmarks](https://github.com/joshwatson/binaryninja-bookmarks) Plugin for BinaryNinja that provides bookmarking functionality
- [**18**Star][12m] [Py] [transferwise/pg_ninja](https://github.com/transferwise/pg_ninja) The ninja elephant obfuscation and replica tool
- [**17**Star][2y] [Py] [extremecoders-re/bnpy](https://github.com/extremecoders-re/bnpy) An architecture plugin for binary ninja to disassemble raw python bytecode
- [**16**Star][6m] [Py] [carstein/syscaller](https://github.com/carstein/syscaller) Binary Ninja Syscall Annotator
- [**16**Star][1y] [Py] [lunixbochs/bnrepl](https://github.com/lunixbochs/bnrepl) Run your Binary Ninja Python console in a separate Terminal window.
- [**16**Star][3y] [Py] [rootbsd/binaryninja_plugins](https://github.com/rootbsd/binaryninja_plugins) Binary ninja plugins
- [**15**Star][3y] [Py] [orndorffgrant/bnhook](https://github.com/orndorffgrant/bnhook) binary ninja plugin for adding custom hooks to executables
- [**15**Star][5m] [Py] [zznop/bn-genesis](https://github.com/zznop/bn-genesis) Binary Ninja plugin suite for SEGA Genesis ROM hacking
- [**14**Star][3y] [Py] [coldheat/liil](https://github.com/coldheat/liil) Linear IL view for Binary Ninja
- [**12**Star][2y] [Py] [gitmirar/binaryninjayaraplugin](https://github.com/gitmirar/binaryninjayaraplugin) Yara Plugin for Binary Ninja
- [**12**Star][8m] [Py] [ktn1990/cve-2019-10869](https://github.com/ktn1990/cve-2019-10869) (Wordpress) Ninja Forms File Uploads Extension <= 3.0.22 – Unauthenticated Arbitrary File Upload
- [**11**Star][3m] [C++] [0x1f9f1/binja-pattern](https://github.com/0x1f9f1/binja-pattern) 
- [**10**Star][2y] [Py] [chokepoint/bnpincoverage](https://github.com/chokepoint/bnpincoverage) Visually analyze basic block code coverage in Binary Ninja using Pin output.
- [**10**Star][5y] [Py] [emileaben/scapy-dns-ninja](https://github.com/emileaben/scapy-dns-ninja) Minimal DNS answering machine, for customized/programmable answers
- [**10**Star][2m] [Py] [zznop/bn-brainfuck](https://github.com/zznop/bn-brainfuck) Brainfuck architecture module and loader for Binary Ninja
- [**9**Star][10m] [Py] [manouchehri/binaryninja-radare2](https://github.com/manouchehri/binaryninja-radare2) DEPRECIATED
- [**8**Star][2y] [Py] [cah011/binja-avr](https://github.com/cah011/binja-avr) AVR assembly plugin for Binary Ninja
- [**8**Star][6m] [Py] [joshwatson/binaryninja-microcorruption](https://github.com/joshwatson/binaryninja-microcorruption) BinaryView Plugin for Microcorruption CTF memory dumps
- [**8**Star][4m] [Py] [whitequark/binja-i8086](https://github.com/whitequark/binja-i8086) 16-bit x86 architecture for Binary Ninja
- [**7**Star][1y] [Py] [rick2600/xref_call_finder](https://github.com/rick2600/xref_call_finder) Plugin for binary ninja to find calls to function recursively
- [**6**Star][1y] [Py] [kudelskisecurity/binaryninja_cortex](https://github.com/kudelskisecurity/binaryninja_cortex) A Binary Ninja plugin to load Cortex-based MCU firmware
- [**5**Star][6m] [Py] [0x1f9f1/binja-msvc](https://github.com/0x1f9f1/binja-msvc) 
- [**5**Star][3y] [agnosticlines/binaryninja-plugins](https://github.com/agnosticlines/binaryninja-plugins) A repo with a listing of binary ninja scripts + plugins (massively inspired by
- [**5**Star][6m] [Py] [bkerler/annotate](https://github.com/bkerler/annotate) Binary Ninja plugin for annotation of arguments for functions
- [**5**Star][5m] [Py] [icecr4ck/bngb](https://github.com/icecr4ck/bnGB) Binary Ninja Game Boy loader and architecture plugin for analysing and disassembling GB ROM.
- [**4**Star][11m] [HTML] [evanrichter/base16-binary-ninja](https://github.com/evanrichter/base16-binary-ninja) Base16 Color Template for Binja
- [**3**Star][2y] [Py] [nallar/binja-function-finder](https://github.com/nallar/binja-function-finder) Binary ninja plugin which adds simple tools for finding functions
- [**2**Star][3m] [Py] [404d/peutils](https://github.com/404d/peutils) Binary Ninja plugin providing various niche utilities for working with PE binaries
- [**2**Star][11m] [Py] [blurbdust/binaryninja_plan9_aout](https://github.com/blurbdust/binaryninja_plan9_aout) Binary Ninja Plugin for disassembling plan 9 a.out binaries
- [**2**Star][5m] [Py] [icecr4ck/bnmiasm](https://github.com/icecr4ck/bnmiasm) Plugin to visualize Miasm IR graph in Binary Ninja.
- [**2**Star][3y] [C] [jhurliman/binaryninja-functionmatcher](https://github.com/jhurliman/binaryninja-functionmatcher) A Binary Ninja plugin to match functions and transplant symbols between similar binaries
- [**2**Star][3y] [Py] [rick2600/textify_function](https://github.com/rick2600/textify_function) Plugin for binary ninja to textify function to copy and paste
- [**2**Star][6m] [Py] [vasco-jofra/jump-table-branch-editor](https://github.com/vasco-jofra/jump-table-branch-editor) A binary ninja plugin that eases fixing jump table branches
- [**1**Star][1y] [Py] [arcnor/binja_search](https://github.com/arcnor/binja_search) Binary Ninja search plugin
- [**1**Star][2y] [Py] [kapaw/binaryninja-lc3](https://github.com/kapaw/binaryninja-lc3) LC-3 architecture plugin for Binary Ninja
- [**0**Star][3y] [Py] [ehennenfent/binja_spawn_terminal](https://github.com/ehennenfent/binja_spawn_terminal) A tiny plugin for Binary Ninja that enables the ui to spawn terminals on Ubuntu and OS


### <a id="bba1171ac550958141dfcb0027716f41"></a>With Other Tools


#### <a id="c2f94ad158b96c928ee51461823aa953"></a>No Category


- [**149**Star][2y] [Py] [hugsy/binja-retdec](https://github.com/hugsy/binja-retdec) Binary Ninja plugin to decompile binaries using RetDec API
- [**8**Star][3m] [Py] [c3r34lk1ll3r/binrida](https://github.com/c3r34lk1ll3r/BinRida) Plugin for Frida in Binary Ninja
    - Also In Section: [DBI->Frida->Tools->With Other Tools->Binary Ninja](#f9008a00e2bbc7535c88602aa79c8fd8) |


#### <a id="713fb1c0075947956651cc21a833e074"></a>IDA


- [**68**Star][9m] [Py] [lunixbochs/revsync](https://github.com/lunixbochs/revsync) realtime cross-tool collaborative reverse engineering
    - Also In Section: [IDA->Tools->Import Export->BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a) |
- [**61**Star][6m] [Py] [zznop/bnida](https://github.com/zznop/bnida) Suite of plugins that provide the ability to transfer analysis data between Binary Ninja and IDA
    - Also In Section: [IDA->Tools->Import Export->BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a) |
    - [ida_export](https://github.com/zznop/bnida/blob/master/ida/ida_export.py) 将数据从IDA中导入
    - [ida_import](https://github.com/zznop/bnida/blob/master/ida/ida_import.py) 将数据导入到IDA
    - [binja_export](https://github.com/zznop/bnida/blob/master/binja_export.py) 将数据从BinaryNinja中导出
    - [binja_import](https://github.com/zznop/bnida/blob/master/binja_import.py) 将数据导入到BinaryNinja
- [**14**Star][6m] [Py] [cryptogenic/idc_importer](https://github.com/cryptogenic/idc_importer) A Binary Ninja plugin for importing IDC database dumps from IDA.
    - Also In Section: [IDA->Tools->Import Export->BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a) |






***


## <a id="2d24dd6f0c01a084e88580ad22ce5b3c"></a>Posts&&Videos


- 2019.08 [trailofbits] [Reverse Taint Analysis Using Binary Ninja](http://blog.trailofbits.com/2019/08/29/reverse-taint-analysis-using-binary-ninja/)
- 2018.09 [aliyun] [使用Binary Ninja调试共享库](https://xz.aliyun.com/t/2826)
- 2018.09 [kudelskisecurity] [Analyzing ARM Cortex-based MCU firmwares using Binary Ninja](https://research.kudelskisecurity.com/2018/09/25/analyzing-arm-cortex-based-mcu-firmwares-using-binary-ninja/)
- 2018.07 [aliyun] [WCTF 2018  -   binja - rswc](https://xz.aliyun.com/t/2436)
- 2018.04 [trailofbits] [Vulnerability Modeling with Binary Ninja](https://blog.trailofbits.com/2018/04/04/vulnerability-modeling-with-binary-ninja/)
- 2018.01 [pediy] [[翻译]逆向平台Binary Ninja介绍](https://bbs.pediy.com/thread-224141.htm)
- 2017.11 [] [bnpy - A python architecture plugin for Binary Ninja](https://0xec.blogspot.com/2017/11/bnpy-python-architecture-plugin-for.html)
- 2017.10 [ret2] [Untangling Exotic Architectures with Binary Ninja](http://blog.ret2.io/2017/10/17/untangling-exotic-architectures-with-binary-ninja/)
- 2017.10 [chokepoint] [Pin Visual Coverage Tool for Binary Ninja](http://www.chokepoint.net/2017/10/pin-visual-coverage-tool-for-binary.html)
- 2017.03 [GynvaelEN] [Hacking Livestream #14: Binary Ninja Plugins (with carstein)](https://www.youtube.com/watch?v=c9Tn2nEPp7A)
- 2016.12 [kchung] [Binary Ninja: IPython and the Python Console](https://blog.kchung.co/binary-ninja-ipython-and-the-python-console/)
- 2016.03 [arm] [Introduction to the Binary Ninja API](http://arm.ninja/2016/03/08/intro-to-binary-ninja-api/)


# <a id="2f81493de610f9b796656b269380b2de"></a>Windows


***


## <a id="620af0d32e6ac1f4a3e97385d4d3efc0"></a>PE


### <a id="574db8bbaafbee72eeb30e28e2799458"></a>Tool


- [**877**Star][8m] [Py] [erocarrera/pefile](https://github.com/erocarrera/pefile) pefile is a Python module to read and work with PE (Portable Executable) files
- [**634**Star][10d] [C] [thewover/donut](https://github.com/thewover/donut) Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters
- [**537**Star][1y] [C#] [ghostpack/safetykatz](https://github.com/ghostpack/safetykatz)  combination of slightly modified version of Mimikatz project and .NET PE Loader.
- [**522**Star][4y] [C] [jondonym/peinjector](https://github.com/jondonym/peinjector) peinjector - MITM PE file infector
- [**426**Star][2y] [Py] [endgameinc/gym-malware](https://github.com/endgameinc/gym-malware) a malware manipulation environment for OpenAI's gym
- [**388**Star][1y] [Assembly] [hasherezade/pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode) Converts PE into a shellcode
- [**385**Star][3m] [Jupyter Notebook] [endgameinc/ember](https://github.com/endgameinc/ember) a collection of features from PE files that serve as a benchmark dataset for researchers.
- [**365**Star][2y] [petoolse/petools](https://github.com/petoolse/petools) PE Tools - Portable executable (PE) manipulation toolkit
- [**344**Star][1y] [Assembly] [egebalci/amber](https://github.com/egebalci/amber) a reflective PE packer for bypassing security products and mitigations
- [**337**Star][5m] [C] [merces/pev](https://github.com/merces/pev) The PE file analysis toolkit
- [**316**Star][24d] [C++] [trailofbits/pe-parse](https://github.com/trailofbits/pe-parse) Principled, lightweight C/C++ PE parser
- [**315**Star][14d] [VBA] [itm4n/vba-runpe](https://github.com/itm4n/vba-runpe) A VBA implementation of the RunPE technique or how to bypass application whitelisting.
- [**296**Star][12d] [C++] [hasherezade/libpeconv](https://github.com/hasherezade/libpeconv) A library to load, manipulate, dump PE files. See also:
- [**285**Star][7m] [Java] [katjahahn/portex](https://github.com/katjahahn/portex) Java library to analyse Portable Executable files with a special focus on malware analysis and PE malformation robustness
- [**283**Star][2y] [C++] [google/syzygy](https://github.com/google/syzygy) a suite of tools for the instrumentation of COFF object files and PE binaries
- [**227**Star][3y] [C++] [secrary/infectpe](https://github.com/secrary/infectpe) Inject custom code into PE file [This project is not maintained anymore]
- [**189**Star][5y] [C++] [rwfpl/rewolf-x86-virtualizer](https://github.com/rwfpl/rewolf-x86-virtualizer) Simple VM based x86 PE (portable exectuable) protector.
- [**151**Star][6y] [Py] [hiddenillusion/analyzepe](https://github.com/hiddenillusion/analyzepe) Wraps around various tools and provides some additional checks/information to produce a centralized report of a PE file.
- [**146**Star][5m] [C++] [darthton/polychaos](https://github.com/darthton/polychaos) PE permutation library
- [**140**Star][1y] [Py] [codypierce/hackers-grep](https://github.com/codypierce/hackers-grep) hackers-grep is a utility to search for strings in PE executables including imports, exports, and debug symbols
- [**137**Star][22d] [Py] [rvn0xsy/cooolis-ms](https://github.com/rvn0xsy/cooolis-ms) Cooolis-ms is a server that supports the Metasploit Framework RPC. It is used to work with the Shellcode and PE loader. To some extent, it bypasses the static killing of anti-virus software, and allows the Cooolis-ms server to communicate with the Metasploit server. Separation.
- [**129**Star][3m] [C++] [nettitude/simplepeloader](https://github.com/nettitude/simplepeloader) In-Memory PE Loader
- [**122**Star][3y] [C] [l0n3c0d3r/ceed](https://github.com/l0n3c0d3r/ceed) A tiny x86 compiler with ELF and PE target
- [**111**Star][2m] [C] [hasherezade/chimera_pe](https://github.com/hasherezade/chimera_pe) ChimeraPE (a PE injector type - alternative to: RunPE, ReflectiveLoader, etc) - a template for manual loading of EXE, loading imports payload-side
- [**111**Star][2m] [C] [hasherezade/chimera_pe](https://github.com/hasherezade/chimera_pe) ChimeraPE (a PE injector type - alternative to: RunPE, ReflectiveLoader, etc) - a template for manual loading of EXE, loading imports payload-side
- [**110**Star][7y] [C++] [abhisek/pe-loader-sample](https://github.com/abhisek/pe-loader-sample) Proof of concept implementation of in-memory PE Loader based on ReflectiveDLLInjection Technique
- [**105**Star][6y] [Py] [secretsquirrel/recomposer](https://github.com/secretsquirrel/recomposer) Randomly changes Win32/64 PE Files for 'safer' uploading to malware and sandbox sites.
- [**96**Star][2y] [C++] [hasherezade/pe_recovery_tools](https://github.com/hasherezade/pe_recovery_tools) Helper tools for recovering dumped PE files
- [**88**Star][3y] [C++] [egebalci/cminer](https://github.com/egebalci/cminer) Cminer is a tool for enumerating the code caves in PE files.
- [**83**Star][2y] [C++] [benjaminsoelberg/reflectivepeloader](https://github.com/benjaminsoelberg/reflectivepeloader) Reflective PE loader for DLL injection
- [**49**Star][7y] [C++] [frankstain/pe-loader](https://github.com/frankstain/pe-loader) library, which help to describe or load and execute PE files.
- [**45**Star][2m] [C++] [avast/pelib](https://github.com/avast/pelib) PE file manipulation library.
- [**42**Star][1y] [Py] [jpcertcc/impfuzzy](https://github.com/jpcertcc/impfuzzy) Fuzzy Hash calculated from import API of PE files
- [**38**Star][3y] [Py] [cysinfo/pymal](https://github.com/cysinfo/pymal) PyMal is a python based interactive Malware Analysis Framework. It is built on the top of three pure python programes Pefile, Pydbg and Volatility.
- [**38**Star][1m] [YARA] [te-k/pe](https://github.com/te-k/pe) CLI tool to analyze PE files
- [**37**Star][3y] [Py] [dungtv543/dutas](https://github.com/dungtv543/dutas) Analysis PE file or Shellcode
- [**35**Star][4y] [C] [motazreda/malwarefragmentationtool](https://github.com/motazreda/malwarefragmentationtool) Malware Fragmentation Tool its a tool that simply fragment the PE file and it can disassemble the PE file, etc this tool very useful for people who do malware research or analysis for pe_files
- [**33**Star][3y] [HTML] [wolfram77web/app-peid](https://github.com/wolfram77web/app-peid) PEiD detects most common packers, cryptors and compilers for PE files.
- [**32**Star][1y] [C++] [ntraiseharderror/dreadnought](https://github.com/ntraiseharderror/dreadnought) PoC for detecting and dumping code injection (built and extended on UnRunPE)
- [**31**Star][2y] [Py] [ihack4falafel/subrosa](https://github.com/ihack4falafel/subrosa) Basic tool to automate backdooring PE files
- [**30**Star][1y] [C++] [ntraiseharderror/unrunpe](https://github.com/ntraiseharderror/unrunpe) PoC for detecting and dumping process hollowing code injection
- [**29**Star][2y] [Py] [ice3man543/malscan](https://github.com/ice3man543/malscan) A Simple PE File Heuristics Scanners
- [**29**Star][2y] [C] [jnastarot/native_peloader](https://github.com/jnastarot/native_peloader) PE(compressed dll) memory loader using nt api
- [**29**Star][4m] [Py] [obscuritylabs/pefixup](https://github.com/obscuritylabs/pefixup) PE File Blessing - To continue or not to continue
- [**28**Star][1y] [C++] [jiazhang0/seloader](https://github.com/jiazhang0/seloader) Secure EFI Loader designed to authenticate the non-PE files
- [**27**Star][5y] [Py] [matonis/rippe](https://github.com/matonis/rippe) ripPE - section extractor and profiler for PE file analysis
- [**26**Star][2y] [C++] [kernelm0de/runpe-processhollowing](https://github.com/kernelm0de/RunPE-ProcessHollowing) RunPE
- [**24**Star][6y] [C++] [edix/malwareresourcescanner](https://github.com/edix/malwareresourcescanner) Scanning and identifying XOR encrypted PE files in PE resources
- [**24**Star][2y] [C++] [polycone/pe-loader](https://github.com/polycone/pe-loader) A Windows PE format file loader
- [**21**Star][3m] [C] [jackullrich/trunpe](https://github.com/jackullrich/trunpe) A modified RunPE (process hollowing) technique avoiding the usage of SetThreadContext by appending a TLS section which calls the original entrypoint.
- [**18**Star][3y] [Py] [0xyg3n/mem64](https://github.com/0xyg3n/mem64) Run Any Native PE file as a memory ONLY Payload , most likely as a shellcode using hta attack vector which interacts with Powershell.
- [**17**Star][5y] [C] [maldevel/pedumper](https://github.com/maldevel/pedumper) Dump Windows PE file information in C
- [**16**Star][2y] [Py] [aserper/ahk-dumper](https://github.com/aserper/ahk-dumper) Ahk-dumper is a tool to dump AutoHotKey code from the RDATA section of a PE file.
- [**14**Star][7m] [Assembly] [egebalci/iat_api](https://github.com/egebalci/iat_api) Assembly block for finding and calling the windows API functions inside import address table(IAT) of the running PE file.
- [**14**Star][2y] [C++] [wyexe/peloader](https://github.com/wyexe/PELoader) 
- [**12**Star][1y] [Go] [egebalci/mappe](https://github.com/egebalci/mappe) MapPE constructs the memory mapped image of given PE files.
- [**10**Star][3y] [Py] [cloudtracer/pefile.pypy](https://github.com/cloudtracer/pefile.pypy) Pypy.js compatible version of pefile.py for use in offline browser implementation
- [**10**Star][3y] [johntroony/pe-codecaving](https://github.com/johntroony/pe-codecaving) Work files for my blog post "Code Caving in a PE file.
- [**10**Star][5y] [C++] [opensecurityresearch/slacker](https://github.com/opensecurityresearch/slacker) A prototype file slack space remover
- [**8**Star][2y] [C] [in3o/binclass](https://github.com/in3o/binclass) Recovering Object information from a C++ compiled Binary/Malware (mainly written for PE files) , linked dynamically and completely Stripped.
- [**8**Star][3y] [C++] [thecxx/image](https://github.com/thecxx/image) PE Loader for win32
- [**5**Star][2y] [Py] [deadbits/pe-static](https://github.com/deadbits/pe-static) Static file analysis for PE files
- [**5**Star][2y] [C] [jmcph4/peek](https://github.com/jmcph4/peek) PEek is a simple PE file viewer.
- [**5**Star][4y] [C++] [waleedassar/timedatestamp](https://github.com/waleedassar/timedatestamp) Discover TimeDateStamps In PE File
- [**5**Star][11m] [Go] [abdullah2993/go-runpe](https://github.com/abdullah2993/go-runpe) 
- [**3**Star][2y] [C++] [kernelm0de/runpe_detecter](https://github.com/kernelm0de/RunPE_Detecter) RunPE Detecter
- [**2**Star][4y] [Py] [missmalware/importdict](https://github.com/missmalware/importdict) An easy way to identify imports of interest in a PE file
- [**0**Star][9m] [Py] [0xd0cf11e/pefile](https://github.com/0xd0cf11e/pefile) Anything related to PE Files


### <a id="7e890d391fa32df27beb1377a371518b"></a>Post


- 2019.12 [aliyun] [手工shellcode注入PE文件](https://xz.aliyun.com/t/6939)
- 2019.10 [freebuf] [PEpper：一款针对可执行程序的开源恶意软件静态分析工具](https://www.freebuf.com/sectool/214265.html)
- 2019.09 [sevagas] [Process PE Injection Basics](https://blog.sevagas.com/?Process-PE-Injection-Basics)
- 2019.07 [hexacorn] [PE Section names – re-visited, again](http://www.hexacorn.com/blog/2019/07/26/pe-section-names-re-visited-again/)
- 2019.06 [hasherezade] [PE-sieve v0.2.1 release notes - import recovery & unpacking ASPack (part 2)](https://www.youtube.com/watch?v=-YVrU4-507A)
- 2019.05 [0x00sec] [Backdoorin pe files](https://0x00sec.org/t/backdoorin-pe-files/13912/)
- 2019.05 [360] [Windows调试艺术——PE文件变形（一）](https://www.anquanke.com/post/id/178088/)
- 2019.05 [arxiv] [[1905.01999] A Benchmark API Call Dataset for Windows PE Malware Classification](https://arxiv.org/abs/1905.01999)
- 2019.04 [decoder] [Combinig LUAFV PostLuafvPostReadWrite Race Condition PE with DiagHub collector exploit -> from standard user to SYSTEM](https://decoder.cloud/2019/04/29/combinig-luafv-postluafvpostreadwrite-race-condition-pe-with-diaghub-collector-exploit-from-standard-user-to-system/)
- 2019.04 [MalwareAnalysisForHedgehogs] [Malware Theory - PE Malformations and Anomalies](https://www.youtube.com/watch?v=-0DEEbQq8jU)
- 2019.04 [freebuf] [Xori：一款针对PE32和Shellcode的自动化反编译与静态分析库](https://www.freebuf.com/sectool/199629.html)
- 2019.03 [hexacorn] [PE files and the DemoScene](http://www.hexacorn.com/blog/2019/03/14/pe-files-and-the-demoscene/)
- 2019.03 [] [携带恶意PE文件的壁纸类应用出现在Google Play](http://blogs.360.cn/post/malicious_PE_files_discovered_on_Google%20Play.html)
- 2019.03 [] [携带恶意PE文件的壁纸类应用出现在Google Play](http://blogs.360.cn/post/malicious_PE_files_discovered_on_Google%20Play.html)
- 2019.03 [] [Malicious PE files discovered on Google Play](http://blogs.360.cn/post/malicious_PE_files_discovered_on_GooglePlay_EN.html)
- 2019.03 [hexacorn] [PE Compilation Timestamps vs. forensics](http://www.hexacorn.com/blog/2019/03/11/pe-compilation-timestamps-vs-forensics/)
- 2019.03 [cristivlad25] [Machine Learning for Malware Detection - 4 - Portable Executable (PE) Files](https://www.youtube.com/watch?v=2Pr6MNcXLFE)
- 2019.03 [hexacorn] [Extracting and Parsing PE signatures en masse](http://www.hexacorn.com/blog/2019/03/03/extracting-and-parsing-pe-signatures-en-masse/)
- 2019.02 [hexacorn] [PE files and the Easy Programming Language (EPL)](http://www.hexacorn.com/blog/2019/02/13/pe-files-and-the-easy-programming-language-epl/)
- 2019.01 [pediy] [[原创]PE加载器的简单实现](https://bbs.pediy.com/thread-249133.htm)
- 2019.01 [fuzzysecurity] [Powershell PE Injection: This is not the Calc you are looking for!](http://fuzzysecurity.com/tutorials/20.html)
- 2019.01 [fuzzysecurity] [Avoiding antivirus && Backdooring PE files](http://fuzzysecurity.com/tutorials/3.html)
- 2019.01 [fuzzysecurity] [Subvert-PE](http://fuzzysecurity.com/scripts/18.html)
- 2019.01 [fuzzysecurity] [Interpret-PE](http://fuzzysecurity.com/scripts/17.html)
- 2019.01 [hshrzd] [PE-bear – version 0.3.9 available](https://hshrzd.wordpress.com/2019/01/13/pe-bear-version-0-3-9-available/)
- 2019.01 [hexacorn] [Hunting for additional PE timestamps](http://www.hexacorn.com/blog/2019/01/04/hunting-for-additional-pe-timestamps/)
- 2019.01 [freebuf] [利用PNG像素隐藏PE代码：分析PNG Dropper新样本](https://www.freebuf.com/articles/system/191833.html)
- 2018.12 [pediy] [[分享][原创]小型PE查看器](https://bbs.pediy.com/thread-248108.htm)
- 2018.11 [n0where] [Investigate Inline Hooks: PE-sieve](https://n0where.net/investigate-inline-hooks-pe-sieve)
- 2018.11 [hasherezade] [PE-sieve 0.1.5 release notes - what are the dump modes about?](https://www.youtube.com/watch?v=pQY-Fq9I4fs)
- 2018.11 [360] [一PE感染型木马行为分析、清理及感染文件修复](https://www.anquanke.com/post/id/163203/)
- 2018.10 [pediy] [[原创]代码二次开发 C语言实现给自己的PE文件添加一个section（区段）](https://bbs.pediy.com/thread-247542.htm)
- 2018.10 [osandamalith] [PE Sec Info – A Simple Tool to Manipulate ASLR and DEP Flags](https://osandamalith.com/2018/10/24/pe-sec-info-a-simple-tool-to-manipulate-aslr-and-dep-flags/)
- 2018.10 [pediy] [[原创]PE文件解析 系列文章(二）](https://bbs.pediy.com/thread-247303.htm)
- 2018.10 [pediy] [[原创]PE文件解析  系列文章(一)](https://bbs.pediy.com/thread-247114.htm)
- 2018.09 [andreafortuna] [Some thoughts about PE Injection](https://www.andreafortuna.org/dfir/some-thoughts-about-pe-injection/)
- 2018.09 [infosecinstitute] [Back-dooring PE Files on Windows [Updated 2018]](https://resources.infosecinstitute.com/back-dooring-pe-files-windows/)
- 2018.08 [aliyun] [『功守道』软件供应链安全大赛·PE二进制赛季启示录：下篇](https://xz.aliyun.com/t/2679)
- 2018.08 [aliyun] [『功守道』软件供应链安全大赛·PE二进制赛季启示录：上篇](https://xz.aliyun.com/t/2677)
- 2018.08 [360] [『功守道』软件供应链安全大赛·PE二进制赛季启示录](https://www.anquanke.com/post/id/158443/)
- 2018.08 [pediy] [PE结构导出表信息读取](https://bbs.pediy.com/thread-246420.htm)
- 2018.07 [didierstevens] [Extracting DotNetToJScript’s PE Files](https://blog.didierstevens.com/2018/07/25/extracting-dotnettojscripts-pe-files/)
- 2018.06 [pentesttoolz] [PE Linux – Linux Privilege Escalation Tool](https://pentesttoolz.com/2018/06/18/pe-linux-linux-privilege-escalation-tool/)
- 2018.05 [reversingminds] [A simple unpacker of a simple PE packer (shrinkwrap)](http://reversingminds-blog.logdown.com/posts/7742670-a-simple-unpacker-a-simple-pe-packer)
- 2018.04 [dist67] [VBA Maldoc: Form-Embedded PE File](https://www.youtube.com/watch?v=sLz_O2h8i74)
- 2018.04 [pediy] [[原创][新手]010纯手工编辑打造PE文件](https://bbs.pediy.com/thread-226033.htm)
- 2018.04 [pediy] [[原创]C++读取PE文件中的资源表](https://bbs.pediy.com/thread-225868.htm)
- 2018.04 [hshrzd] [PE-bear – version 0.3.8 available](https://hshrzd.wordpress.com/2018/04/04/pe-bear-version-0-3-8-available/)
- 2018.04 [hexacorn] [Enlightened and Unenlightened PE files](http://www.hexacorn.com/blog/2018/04/02/enlightened-and-unenlightened-pe-files/)
- 2018.04 [pediy] [[原创]记一个PESpin0.3x壳的详细脱壳笔记和脱壳脚本](https://bbs.pediy.com/thread-225617.htm)
- 2018.03 [MalwareAnalysisForHedgehogs] [Malware Theory - Memory Mapping of PE Files](https://www.youtube.com/watch?v=cc1tX1t_bLg)
- 2018.03 [MalwareAnalysisForHedgehogs] [Malware Theory - Basic Structure of PE Files](https://www.youtube.com/watch?v=l6GjU8fm8sM)
- 2018.03 [BinaryAdventure] [MALWARE ANALYSIS - Adlice PEViewer Introduction/Review](https://www.youtube.com/watch?v=kYg4ZsOGB-k)
- 2018.02 [pediy] [[原创]发一个我用C语言编写的PEInfo（附源码，基于win32 sdk）](https://bbs.pediy.com/thread-224630.htm)
- 2018.02 [pediy] [[原创]浅谈XP下最小PE](https://bbs.pediy.com/thread-224540.htm)
- 2018.02 [randhome] [Another PE tool](https://www.randhome.io/blog/2018/02/04/another-pe-tool/)
- 2018.01 [KirbiflintCracking] [Testing my SimplePEReader](https://www.youtube.com/watch?v=m6DxDzHbjA4)
- 2018.01 [arxiv] [[1801.08917] Learning to Evade Static PE Machine Learning Malware Models via Reinforcement Learning](https://arxiv.org/abs/1801.08917)
- 2018.01 [pediy] [[分享]PE结构体中导出表/导入表解析——初阶](https://bbs.pediy.com/thread-224265.htm)
- 2018.01 [hasherezade] [Unpacking Ramnit with HollowsHunter/PE-sieve](https://www.youtube.com/watch?v=pfPlAdLk0pA)
- 2018.01 [hasherezade] [Unpacking Loki Bot with HollowsHunter/PE-sieve](https://www.youtube.com/watch?v=OAm7BngfW1Q)
- 2017.12 [hasherezade] [Unpacking TrickBot with PE-sieve](https://www.youtube.com/watch?v=lTywPmZEU1A)
- 2017.12 [evi1cg] [BypassAV With ReflectivePEInjection](https://evi1cg.me/archives/BypassAV_With_ReflectivePEInjection.html)
- 2017.12 [hasherezade] [DEMO: Unpackig process hollowing with PE-sieve](https://www.youtube.com/watch?v=7xtxOD1LX7U)
- 2017.12 [pediy] [[翻译]利用PE文件映射库libpeconv来解决FlareOn4 CTF比赛的挑战题6](https://bbs.pediy.com/thread-223576.htm)
- 2017.12 [hasherezade] [My experiments with ProcessDoppelganging - running a PE from any file](https://www.youtube.com/watch?v=ExMsobWztKw)
- 2017.12 [hasherezade] [Unpacking Magniber ransomware with PE-sieve (former: 'hook_finder')](https://www.youtube.com/watch?v=lqWJaaofNf4)
- 2017.12 [360] [深入分析PE可执行文件是如何进行加壳和数据混淆的](https://www.anquanke.com/post/id/90173/)
- 2017.11 [360] [手把手教你在PE文件中植入无法检测的后门（下）](https://www.anquanke.com/post/id/87308/)
- 2017.11 [hasherezade] [DEMO: a custom PE loader using libpeconv](https://www.youtube.com/watch?v=x3T3qFEDkF0)
- 2017.11 [360] [手把手教你在PE文件中植入无法检测的后门（上）](https://www.anquanke.com/post/id/87298/)
- 2017.11 [hasherezade] [RunPE - 32 and 64 bit](https://www.youtube.com/watch?v=y0GKFCrGCFY)
- 2017.11 [360] [PE文件感染技术（Part II）](https://www.anquanke.com/post/id/87223/)
- 2017.11 [phrozen] [RunPE Detector Version 2](https://www.phrozen.io/page/runpe-detector-version-2)
- 2017.10 [pediy] [[翻译]首款反射式PE壳<琥珀>简介](https://bbs.pediy.com/thread-222407.htm)
- 2017.10 [sans] [PE files and debug info](https://isc.sans.edu/forums/diary/PE+files+and+debug+info/22982/)
- 2017.10 [pediy] [[原创]ReflectiveLoader（远程线程的注入 PE的修正）](https://bbs.pediy.com/thread-222187.htm)
- 2017.10 [pentest] [Introducing New Packing Method: First Reflective PE Packer Amber](https://pentest.blog/introducing-new-packing-method-first-reflective-pe-packer/)
- 2017.10 [4hou] [Authenticode签名伪造——PE文件的签名伪造与签名验证劫持](http://www.4hou.com/system/7937.html)
- 2017.10 [pediy] [[原创]由浅入深PE基础学习-菜鸟手动查询导出表、相对虚拟地址(RVA)与文件偏移地址转换(FOA)](https://bbs.pediy.com/thread-221766.htm)
- 2017.10 [3gstudent] [Authenticode签名伪造——PE文件的签名伪造与签名验证劫持](https://3gstudent.github.io/3gstudent.github.io/Authenticode%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0-PE%E6%96%87%E4%BB%B6%E7%9A%84%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0%E4%B8%8E%E7%AD%BE%E5%90%8D%E9%AA%8C%E8%AF%81%E5%8A%AB%E6%8C%81/)
- 2017.10 [3gstudent] [Authenticode签名伪造——PE文件的签名伪造与签名验证劫持](https://3gstudent.github.io/3gstudent.github.io/Authenticode%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0-PE%E6%96%87%E4%BB%B6%E7%9A%84%E7%AD%BE%E5%90%8D%E4%BC%AA%E9%80%A0%E4%B8%8E%E7%AD%BE%E5%90%8D%E9%AA%8C%E8%AF%81%E5%8A%AB%E6%8C%81/)
- 2017.10 [qmemcpy] [Manually dumping PE files from memory](https://qmemcpy.io/post/manually-dumping-pe-files-from-memory)
- 2017.09 [pediy] [[原创]写壳的一些成果[TLS完美处理,压缩功能实现,AntiDump-过LordPE,调用sprintf?,IAT重定向]](https://bbs.pediy.com/thread-221477.htm)
- 2017.09 [4hou] [PE文件全解析](http://www.4hou.com/system/7782.html)
- 2017.09 [] [Binary offsets, virtual addresses and pefile](https://5d4a.wordpress.com/2017/09/21/binary-offsets-virtual-addresses-and-pefile/)
- 2017.08 [freebuf] [浅谈非PE的攻击技巧](http://www.freebuf.com/articles/terminal/144662.html)
- 2017.08 [4hou] [Microsoft图标显示错误，攻击者可任意隐藏恶意PE文件](http://www.4hou.com/system/7076.html)
- 2017.08 [360] [披着羊皮的狼：如何利用Windows图标显示漏洞伪装PE文件](https://www.anquanke.com/post/id/86587/)
- 2017.08 [MalwareAnalysisForHedgehogs] [Malware Analysis - Unpacking RunPE Loyeetro Trojan](https://www.youtube.com/watch?v=iXY2a1Bto6k)
- 2017.08 [freebuf] [老毛桃PE盘工具木马：一款“通杀”浏览器的主页劫持大盗](http://www.freebuf.com/articles/web/143462.html)
- 2017.08 [MalwareAnalysisForHedgehogs] [Malware Analysis - PortexAnalyzer Repair and Dump PE Files](https://www.youtube.com/watch?v=1XUYQwsIGOQ)
- 2017.08 [cybereason] [A zebra in sheep's clothing: How a Microsoft icon-display bug in Windows allows attackers to masquerade PE files with special icons](https://www.cybereason.com/blog/windows-icon-display-bug)
- 2017.07 [pediy] [[原创][原创]LordPE Bug修复](https://bbs.pediy.com/thread-219046.htm)
- 2017.07 [n0where] [Professional PE file Explorer: PPEE](https://n0where.net/professional-pe-file-explorer-ppee)
- 2017.07 [sans] [PE Section Name Descriptions](https://isc.sans.edu/forums/diary/PE+Section+Name+Descriptions/22576/)
- 2017.06 [toolswatch] [PPEE v1.09 – Professional PE file Explorer](http://www.toolswatch.org/2017/06/ppee-v1-09-professional-pe-file-explorer/)
- 2017.05 [360] [Bitdefender在处理PE代码签名的organizationName字段时存在缓冲区溢出漏洞](https://www.anquanke.com/post/id/86144/)
- 2017.05 [secist] [PE结构学习02-导出表](http://www.secist.com/archives/3451.html)
- 2017.05 [secist] [PE结构学习01-DOS头-NT头-节表头](http://www.secist.com/archives/3404.html)
- 2017.05 [mzrst] [Professional PE Explorer compatibility](https://www.mzrst.com/blog/2017/05/04/pe-analysis-tool-compatibility/)
- 2017.04 [lucasg] [The sad state of PE parsing](http://lucasg.github.io/2017/04/28/the-sad-state-of-pe-parsing/)
- 2017.04 [pediy] [PE结构学习之理论基础](https://bbs.pediy.com/thread-217241.htm)
- 2017.04 [n0where] [Inject Custom Code Into PE File: InfectPE](https://n0where.net/inject-custom-code-into-pe-file-infectpe)
- 2017.04 [venus] [反检测技术二：制造PE文件后门](https://paper.seebug.org/264/)
- 2017.03 [] [67,000 cuts with python-pefile](https://0xec.blogspot.com/2017/03/67000-cuts-with-python-pefile.html)
- 2017.03 [sans] [Searching for Base64-encoded PE Files](https://isc.sans.edu/forums/diary/Searching+for+Base64encoded+PE+Files/22199/)
- 2017.03 [4hou] [免杀的艺术：PE文件后门的植入（二）](http://www.4hou.com/technology/3882.html)
- 2017.03 [n0where] [Windows PE Binary Static Analysis Tool : BinSkim](https://n0where.net/windows-pe-binary-static-analysis-tool-binskim)
- 2017.03 [pediy] [[原创]PE2Shellcode](https://bbs.pediy.com/thread-216034.htm)
- 2017.02 [hasherezade] [Unpacking a self overwriting PE (Neutrino bot - stage #1)](https://www.youtube.com/watch?v=m_xh33M_CRo)
- 2017.02 [hasherezade] [Unpacking a self-overwriting PE (Zbot)](https://www.youtube.com/watch?v=2gkBk9KR8rQ)
- 2017.01 [360] [反侦测的艺术part2：精心打造PE后门（含演示视频）](https://www.anquanke.com/post/id/85335/)
- 2017.01 [pentest] [Art of Anti Detection 2 – PE Backdoor Manufacturing](https://pentest.blog/art-of-anti-detection-2-pe-backdoor-manufacturing/)
- 2016.12 [hexacorn] [PE Section names – re-visited](http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/)
- 2016.12 [hshrzd] [Introducing PE_unmapper](https://hshrzd.wordpress.com/2016/12/02/introducing-pe_unmapper/)
- 2016.09 [pediy] [[原创]PE简单加壳_隐藏/加密重定位信息工具C++源码](https://bbs.pediy.com/thread-212994.htm)
- 2016.09 [pediy] [[原创]献上Win PE文件格式解释源码](https://bbs.pediy.com/thread-212960.htm)
- 2016.08 [toolswatch] [PPEE Professional PE file Explorer v1.06](http://www.toolswatch.org/2016/08/ppee-professional-pe-file-explorer-v1-06/)
- 2016.08 [3gstudent] [隐写技巧——在PE文件的数字证书中隐藏Payload](https://3gstudent.github.io/3gstudent.github.io/%E9%9A%90%E5%86%99%E6%8A%80%E5%B7%A7-%E5%9C%A8PE%E6%96%87%E4%BB%B6%E7%9A%84%E6%95%B0%E5%AD%97%E8%AF%81%E4%B9%A6%E4%B8%AD%E9%9A%90%E8%97%8FPayload/)
- 2016.08 [3gstudent] [隐写技巧——在PE文件的数字证书中隐藏Payload](https://3gstudent.github.io/3gstudent.github.io/%E9%9A%90%E5%86%99%E6%8A%80%E5%B7%A7-%E5%9C%A8PE%E6%96%87%E4%BB%B6%E7%9A%84%E6%95%B0%E5%AD%97%E8%AF%81%E4%B9%A6%E4%B8%AD%E9%9A%90%E8%97%8FPayload/)
- 2016.07 [hexacorn] [PEFix – simple PE file re-aligner](http://www.hexacorn.com/blog/2016/07/09/pefix-simple-pe-file-re-aligner/)
- 2016.06 [pediy] [[原创]菜鸟对PEid 0.95 Cave 查找功能逆向](https://bbs.pediy.com/thread-211094.htm)
- 2016.06 [mzrst] [Professional PE Explorer – PPEE](https://www.mzrst.com/blog/2016/06/15/pe-explorer/)
- 2016.06 [pediy] [[翻译]Windows PE文件中的数字签名格式](https://bbs.pediy.com/thread-210709.htm)
- 2016.05 [hackingarticles] [Hack Remote Windows 10 PC using Cypher (Adding Shellcode to PE files)](http://www.hackingarticles.in/hack-remote-windows-10-pc-using-cypher-adding-shellcode-pe-files/)
- 2016.05 [n0where] [PE Executables Static Analyzer: Manalyze](https://n0where.net/pe-executables-static-analyzer-manalyze)
- 2016.05 [0x00sec] [PE File Infection](https://0x00sec.org/t/pe-file-infection/401/)
- 2016.05 [sans] [CVE-2016-2208 Symantec Antivirus Engine Malformed PE Header Parser Memory Access Violation](https://isc.sans.edu/forums/diary/CVE20162208+Symantec+Antivirus+Engine+Malformed+PE+Header+Parser+Memory+Access+Violation/21069/)
- 2016.05 [freebuf] [Manalyze：PE文件的静态分析工具](http://www.freebuf.com/sectool/104378.html)
- 2016.04 [cyber] [Presenting PeNet: a native .NET library for analyzing PE Headers with PowerShell](https://cyber.wtf/2016/04/18/presenting-penet-a-native-net-library-for-analyzing-pe-headers-with-powershell/)
- 2016.04 [securityblog] [Edit PE file properties using C](http://securityblog.gr/3314/edit-pe-file-properties-using-c/)
- 2016.02 [pediy] [[原创]64位CreateProcess逆向:(三)PE格式的解析与效验](https://bbs.pediy.com/thread-208101.htm)
- 2016.02 [360] [在windows环境下使用Volatility或PE Capture捕捉执行代码（PE/DLL/驱动恶意文件）](https://www.anquanke.com/post/id/83507/)
- 2015.12 [secureallthethings] [Add PE Code Signing to Backdoor Factory (BDF)](http://secureallthethings.blogspot.com/2015/12/add-pe-code-signing-to-backdoor-factory.html)
- 2015.12 [missmalware] [PE Import Analysis for Beginners and Lazy People](http://missmalware.com/2015/12/pe-import-analysis-for-beginners-and-lazy-people/)
- 2015.12 [pediy] [[原创]一个C++的PE文件操作类](https://bbs.pediy.com/thread-206304.htm)
- 2015.12 [pediy] [[原创]通过c++代码给PE文件添加一个区段](https://bbs.pediy.com/thread-206197.htm)
- 2015.11 [securityblog] [FileAlyzer – Analyze files – Read PE information](http://securityblog.gr/2963/filealyzer-analyze-files-read-pe-information/)
- 2015.11 [securityblog] [Read Portable Executable (PE) information](http://securityblog.gr/2960/read-portable-executable-pe-information/)
- 2015.11 [freebuf] [逆向工程（二）：从一个简单的实例来了解PE文件](http://www.freebuf.com/articles/system/86596.html)
- 2015.11 [pediy] [[原创][开源]LordPE框架设计之精简版](https://bbs.pediy.com/thread-206136.htm)
- 2015.11 [pediy] [[原创]手查PE重定向](https://bbs.pediy.com/thread-206072.htm)
- 2015.11 [pediy] [[原创][开源]Win32控制台解析PE文件](https://bbs.pediy.com/thread-206060.htm)
- 2015.11 [pediy] [[原创]手查PE导出表](https://bbs.pediy.com/thread-205989.htm)
- 2015.10 [grandstreamdreams] [Updating Dell BIOS using WinPE](http://grandstreamdreams.blogspot.com/2015/10/updating-dell-bios-using-winpe.html)
- 2015.10 [n0where] [PE Static Malware Analysis: PortEx](https://n0where.net/pe-static-malware-analysis-portex)
- 2015.09 [n0where] [MITM PE file infector: PEInjector](https://n0where.net/mitm-pe-file-infector-peinjector)
- 2015.09 [] [奇技淫巧：不用PE，没有密码临机控制Win7](http://www.91ri.org/14214.html)
- 2015.08 [pediy] [[原创]PE解析逆向LoadString](https://bbs.pediy.com/thread-203675.htm)
- 2015.08 [hexacorn] [Two PE tools you might have never heard of. Now you do.](http://www.hexacorn.com/blog/2015/08/15/two-pe-tools-you-might-have-never-heard-of-now-you-do/)
- 2015.06 [pediy] [[原创][开源]EnumPE 枚举文件中的PNG](https://bbs.pediy.com/thread-201705.htm)
- 2015.05 [pediy] [[原创]PE文件学习之地址转换器编写](https://bbs.pediy.com/thread-200914.htm)
- 2015.05 [guitmz] [Having fun with PE files and GoLang](https://www.guitmz.com/having-fun-with-pe-files-and-golang/)
- 2015.05 [securityblog] [Dump PE file in C](http://securityblog.gr/2583/dump-pe-file/)
- 2015.03 [sans] [From PEiD To YARA](https://isc.sans.edu/forums/diary/From+PEiD+To+YARA/19473/)
- 2015.03 [pediy] [[原创]元宵节献礼，用类的思想处理PE结构附源码](https://bbs.pediy.com/thread-198427.htm)
- 2015.01 [toolswatch] [PEStudio v8.46 Released](http://www.toolswatch.org/2015/01/pestudio-v8-46/)
- 2014.12 [coder] [Developing PE file packer step-by-step. Step 4. Running](https://coder.pub/2014/09/developing-pe-file-packer-step-by-step-step-4-running/)
- 2014.10 [coder] [Developing PE file packer step-by-step. Step 12 – bugfixes](https://coder.pub/2014/10/pe-file-packer-step-by-step-step-12-bugfixes/)
- 2014.10 [coder] [Developing PE file packer step-by-step. Step 11. Command line interface. Final version](https://coder.pub/2014/10/pe-packer-step-by-step-step-11-command-line-interface/)
- 2014.09 [coder] [Developing PE file packer step-by-step. Step 9. Delay-loaded DLLs and Image Config](https://coder.pub/2014/09/pe-file-packer-step-by-step-step-9/)
- 2014.09 [alex] [PE Trick #1: A Codeless PE Binary File That Runs](http://www.alex-ionescu.com/?p=211)
- 2014.09 [coder] [Developing PE file packer step-by-step. Step 8. DLL’s and exports](https://coder.pub/2014/09/pe-file-packer-step-by-step-step-8-dlls-and-exports/)
- 2014.09 [coder] [Developing PE file packer step-by-step. Step 7. Relocations](https://coder.pub/2014/09/pe-file-packer-step-by-step-step-7-relocations/)
- 2014.09 [coder] [Developing PE file packer step-by-step. Step 6. TLS](https://coder.pub/2014/09/pe-file-packer-step-by-step-step-6-tls/)
- 2014.09 [coder] [Developing PE file packer step-by-step. Step 5. Resources](https://coder.pub/2014/09/pe-file-packer-step-by-step-step-5-resources/)
- 2014.09 [coder] [Developing PE file packer step-by-step. Step 3. Unpacking](https://coder.pub/2014/09/pe-file-packer-step-by-step-step-3-unpacking/)
- 2014.08 [viper] [Analyzing and mining PE32 files](http://viper.li/blog/2014-08-28-analyzing-and-mining-pe32-files.html)
- 2014.08 [coder] [Developing PE file packer step-by-step. Step 2. Packing](https://coder.pub/2014/08/pe-file-packer-step-by-step-2-packing/)
- 2014.08 [pediy] [[原创]PECompact v2.xx脱壳之魔兽改键精灵去弹广告](https://bbs.pediy.com/thread-191388.htm)
- 2014.08 [coder] [Developing PE file packer step-by-step. Step 1](https://coder.pub/2014/08/pe-file-packer-step-by-step-1/)
- 2014.08 [pediy] [[原创]PE文件格式解析](https://bbs.pediy.com/thread-191221.htm)
- 2014.07 [thomasmaurer] [Add drivers to SCVMM Bare-Metal WinPE Image](https://www.thomasmaurer.ch/2014/07/add-drivers-to-scvmm-bare-metal-winpe-image/)
- 2014.06 [toolswatch] [PEStudio v8.29 – Static Investigation of Executables Released](http://www.toolswatch.org/2014/06/pestudio-v8-29-static-investigation-of-executables-released/)
- 2014.05 [malwarebytes] [Five PE Analysis Tools Worth Looking At](https://blog.malwarebytes.com/threat-analysis/2014/05/five-pe-analysis-tools-worth-looking-at/)
- 2014.05 [ulsrl] [PE Imports](http://ulsrl.org/pe-portable-executable/)
- 2014.04 [sevagas] [PE injection explained](https://blog.sevagas.com/?PE-injection-explained)
- 2014.04 [yurichev] [9-Apr-2014: Couple of win32 PE patching utilities](https://yurichev.com/blog/82/)
- 2014.03 [hshrzd] [PE-bear – version 0.3.7 available!](https://hshrzd.wordpress.com/2014/03/23/pe-bear-version-0-3-7-avaliable/)
- 2014.03 [macnica] [PEヘッダでパッカーの有無を見分ける方法](http://blog.macnica.net/blog/2014/03/pe-5284.html)
- 2014.02 [evilsocket] [Libpe - a Fast PE32/PE32+ Parsing Library.](https://www.evilsocket.net/2014/02/21/libpe-a-fast-pe32pe32-parsing-library/)
- 2014.02 [yurichev] [18-Feb-2014: PE add imports](https://yurichev.com/blog/79/)
- 2014.02 [hshrzd] [PE-bear – version 0.3.6 avaliable!](https://hshrzd.wordpress.com/2014/02/11/pe-bear-version-0-3-6-avaliable/)
- 2014.02 [dustri] [PEiD to Yara, now with Python3!](https://dustri.org/b/peid-to-yara-now-with-python3.html)
- 2014.01 [hshrzd] [PE-bear – version 0.3.5 avaliable!](https://hshrzd.wordpress.com/2014/01/22/pe-bear-version-0-3-5-avaliable/)
- 2014.01 [coder] [Developing PE file packer step-by-step. Step 10. Overall architecture](https://coder.pub/2014/10/pe-file-packer-step-by-step-step-10-overall-architecture/)
- 2013.12 [] [手工详细分析老壳 PEncrypt_4.0](http://www.91ri.org/7891.html)
- 2013.12 [pediy] [[原创]PE解析软件](https://bbs.pediy.com/thread-182161.htm)
- 2013.12 [pediy] [[原创][15Pb培训第三阶段课后小项目]PE解析工具](https://bbs.pediy.com/thread-182131.htm)
- 2013.12 [pediy] [[原创]PEedit](https://bbs.pediy.com/thread-182116.htm)
- 2013.12 [pediy] [[原创]PE文件编辑器](https://bbs.pediy.com/thread-182106.htm)
- 2013.11 [hshrzd] [PE-bear – version 0.3.0 avaliable!](https://hshrzd.wordpress.com/2013/11/23/pe-bear-version-0-3-0-avaliable/)
- 2013.10 [pediy] [[原创][下载]PE文件壳的设计过程](https://bbs.pediy.com/thread-180609.htm)
- 2013.10 [yurichev] [16-Oct-2013: Add import to PE executable file](https://yurichev.com/blog/76/)
- 2013.09 [pediy] [[原创]汇编编写Windows PE文件小工具](https://bbs.pediy.com/thread-179410.htm)
- 2013.09 [pediy] [[分享]两个半成品PE-DIY工具](https://bbs.pediy.com/thread-178820.htm)
- 2013.09 [pediy] [[原创]自己写的一个简单的PE资源查看工具（源码）](https://bbs.pediy.com/thread-178186.htm)
- 2013.08 [ulsrl] [Robustly Parsing the PE Header](http://ulsrl.org/robustly-parsing-the-pe-header/)
- 2013.08 [cerbero] [PE Insider](http://cerbero-blog.com/?p=1228)
- 2013.08 [pediy] [[原创]基于ARM平台下的WINDOWS RT的PE文件逆向初步研究](https://bbs.pediy.com/thread-176827.htm)
- 2013.08 [pediy] [[原创]学习PE写的一个添加节区的工具](https://bbs.pediy.com/thread-176481.htm)
- 2013.07 [trendmicro] [Trend Micro Solutions for PE_EXPIRO](https://blog.trendmicro.com/trendlabs-security-intelligence/trend-micro-solutions-for-pe_expiro/)
- 2013.07 [hshrzd] [PE-bear – version 0.1.8 avaliable!](https://hshrzd.wordpress.com/2013/07/23/pe-bear-version-0-1-8-avaliable/)
- 2013.07 [hshrzd] [PE-bear – version 0.1.5 avaliable!](https://hshrzd.wordpress.com/2013/07/14/pe-bear-version-0-1-5-avaliable/)
- 2013.07 [pediy] [[原创]PEBundle+UPX的还原修复](https://bbs.pediy.com/thread-175249.htm)
- 2013.07 [hshrzd] [Introducing PE-bear: a new viewer/editor for PE files](https://hshrzd.wordpress.com/2013/07/09/introducing-new-pe-files-reversing-tool/)
- 2013.07 [p0w3rsh3ll] [Creating a WinPE bootable image with Powershell 4](https://p0w3rsh3ll.wordpress.com/2013/07/02/creating-a-winpe-bootable-image-with-powershell-4/)
- 2013.06 [debasish] [PEiD Memory Corruption Vulnerability](http://www.debasish.in/2013/06/peid-memory-corruption-vulnerability.html)
- 2013.06 [pediy] [[原创]PE文件菜单资源的格式分析](https://bbs.pediy.com/thread-173664.htm)
- 2013.06 [pediy] [[原创]拿Win7系统下的notepad.exe文件用19个实例来猜测Win7PE加载器的一些行为](https://bbs.pediy.com/thread-173506.htm)
- 2013.06 [debasish] [Injecting Shellcode into a Portable Executable(PE) using Python](http://www.debasish.in/2013/06/injecting-shellcode-into-portable.html)
- 2013.06 [pediy] [[原创]PE感染&ShellCode编写技术补充](https://bbs.pediy.com/thread-172961.htm)
- 2013.05 [cerbero] [CVE-2012-0158: RTF/OLE/CFBF/PE](http://cerbero-blog.com/?p=1097)
- 2013.05 [pediy] [[原创]自己写的PE查看工具及源码](https://bbs.pediy.com/thread-171020.htm)
- 2013.04 [coder] [Developing PE file packer step-by-step. Step 12 – bugfixes](https://kaimi.io/en/2013/04/developing-pe-file-packer-step-by-step-step-12-bugfixes/)
- 2013.04 [pediy] [[原创]QueryPE我写的PE工具](https://bbs.pediy.com/thread-168316.htm)
- 2013.04 [cerbero] [Detect broken PE manifests](http://cerbero-blog.com/?p=1004)
- 2013.01 [pediy] [[原创]高仿LoadPE源码](https://bbs.pediy.com/thread-161746.htm)
- 2013.01 [sans] [Digital Forensics Case Leads: Sleeper Malware targets diplomatic entities in Europe & Asia, banking trojan travelling through Skype, DropBox decryption, PE file analysis, and retrieving iPhone VoiceMail](https://digital-forensics.sans.org/blog/2013/01/20/digital-forensics-case-leads-sleeper-malware-targets-diplomatic-entities-in-europe-asia-banking-trojan-travelling-through-skype-dropbox-decryption-pe-file-analysis-and-retrieving-iphone-voi)
- 2013.01 [pediy] [[原创]断断续续写了好长时间的LordPE仿制源代码](https://bbs.pediy.com/thread-161101.htm)
- 2013.01 [pediy] [[原创]lua引导WindowsPE系统源码](https://bbs.pediy.com/thread-160628.htm)
- 2012.11 [hexacorn] [Top 100+ malicious types of 32-bit PE files](http://www.hexacorn.com/blog/2012/11/19/top-100-malicious-types-of-32-bit-pe-files/)
- 2012.11 [welivesecurity] [Win32/Morto – Made in China, now with PE file infection](https://www.welivesecurity.com/2012/11/14/win32morto-made-in-china/)
- 2012.10 [pediy] [[分享]为PE Optimizer添加拖放功能](https://bbs.pediy.com/thread-157637.htm)
- 2012.10 [hexacorn] [Random Stats from 1.2M samples – PE Section Names](http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/)
- 2012.10 [coder] [Developing PE file packer step-by-step. Step 11. Command line interface. Final version](https://kaimi.io/en/2012/10/developing-pe-file-packer-step-by-step-step-11-command-line-interface-final-version/)
- 2012.09 [coder] [Developing PE file packer step-by-step. Step 10. Overall architecture](https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-10-overall-architecture/)
- 2012.09 [coder] [Developing PE file packer step-by-step. Step 9. Delay-loaded DLLs and Image Config](https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-9-delay-loaded-dlls-and-image-config/)
- 2012.09 [coder] [Developing PE file packer step-by-step. Step 8. DLL’s and exports](https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-8-dlls-and-exports/)
- 2012.09 [coder] [Developing PE file packer step-by-step. Step 7. Relocations](https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-7-relocations/)
- 2012.09 [coder] [Developing PE file packer step-by-step. Step 6. TLS](https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-6-tls/)
- 2012.09 [octopuslabs] [R4ndom’s Tutorial #22: Code Caves and PE Sections](http://octopuslabs.io/legend/blog/archives/2390)
- 2012.09 [coder] [Developing PE file packer step-by-step. Step 5. Resources](https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-5-resources/)
- 2012.09 [coder] [Developing PE file packer step-by-step. Step 4. Running](https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-4-running/)
- 2012.09 [coder] [Developing PE file packer step-by-step. Step 3. Unpacking](https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-3-unpacking/)
- 2012.09 [coder] [Developing PE file packer step-by-step. Step 2. Packing](https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-2-packing/)
- 2012.09 [coder] [Developing PE file packer step-by-step. Step 1](https://kaimi.io/en/2012/09/developing-pe-file-packer-step-by-step-step-1/)
- 2012.09 [hexacorn] [PESectionExtractor – Extracting PE sections and their strings](http://www.hexacorn.com/blog/2012/09/02/pesectionextractor-extracting-pe-sections-and-their-strings/)
- 2012.09 [hexacorn] [Perfect Timestomping a.k.a. Finding suspicious PE files with clustering](http://www.hexacorn.com/blog/2012/09/01/perfect-timestomping-a-k-a-finding-suspicious-pe-files-with-clustering/)
- 2012.08 [rsa] [Identifying the country of origin for a malware PE executable](https://community.rsa.com/community/products/netwitness/blog/2012/08/22/identifying-the-country-of-origin-for-a-malware-pe-executable)
- 2012.08 [pediy] [[原创]手写Min PE(语音教程)](https://bbs.pediy.com/thread-154857.htm)
- 2012.08 [p0w3rsh3ll] [Convert vbscript to powershell used in WinPE](https://p0w3rsh3ll.wordpress.com/2012/08/14/convert-vbscript-to-powershell-used-in-winpe/)
- 2012.08 [p0w3rsh3ll] [Powershell 3 in WinPE 4 on Hyper-V 3](https://p0w3rsh3ll.wordpress.com/2012/08/01/powershell-3-in-winpe-4-on-hyper-v-3/)
- 2012.07 [p0w3rsh3ll] [powershell memory requirements in WinPE 4.0](https://p0w3rsh3ll.wordpress.com/2012/07/31/powershell-memory-requirements-in-winpe-4-0/)
- 2012.07 [pediy] [点滴记录--stubPE之procs](https://bbs.pediy.com/thread-153659.htm)
- 2012.07 [pediy] [点滴记录--PE结构学习](https://bbs.pediy.com/thread-153131.htm)
- 2012.06 [cerbero] [PE analysis (part 1)](http://cerbero-blog.com/?p=446)
- 2012.06 [pediy] [[原创]iPE Src](https://bbs.pediy.com/thread-151967.htm)
- 2012.06 [pediy] [[原创]PEInfo_v0.04 开源](https://bbs.pediy.com/thread-151887.htm)
- 2012.06 [pediy] [[原创]基于《加密与解密》上的PE-Armor-0.46源码的整理版源码](https://bbs.pediy.com/thread-151831.htm)
- 2012.05 [pediy] [[原创]一步一步实现在PE文件中添加可执行代码](https://bbs.pediy.com/thread-151304.htm)
- 2012.05 [p0w3rsh3ll] [Powershell in WinPE](https://p0w3rsh3ll.wordpress.com/2012/05/22/powershell-in-winpe/)
- 2012.05 [pediy] [[原创]自己写的PE分析工具（附源代码）](https://bbs.pediy.com/thread-150447.htm)
- 2012.05 [joxeankoret] [Embedding a shellcode in a PE file](http://joxeankoret.com/blog/2012/05/06/embedding-a-shellcode-in-a-pe-file/)
- 2012.05 [pediy] [[原创]PE监控器(监控系统PE文件的创建和改写操作）（开源）](https://bbs.pediy.com/thread-150065.htm)
- 2012.04 [malwarebytes] [Intentional PE Corruption](https://blog.malwarebytes.com/cybercrime/2012/04/intentional-pe-corruption/)
- 2012.04 [pediy] [[原创]一种保护应用程序的方法 模拟Windows PE加载器，从内存资源中加载DLL](https://bbs.pediy.com/thread-149326.htm)
- 2012.03 [pelock] [PE Format Poster](https://www.pelock.com/blog/2012/03/29/pe-format-poster/)
- 2012.02 [hexacorn] [Extracting Strings from PE sections](http://www.hexacorn.com/blog/2012/02/21/extracting-strings-from-pe-sections/)
- 2011.12 [pediy] [[原创]手工打造小PE总结](https://bbs.pediy.com/thread-144699.htm)
- 2011.11 [pediy] [[原创]新人学习PE](https://bbs.pediy.com/thread-143212.htm)
- 2011.10 [pediy] [[下载]自己弄的外壳PE-panzer，给大家玩玩](https://bbs.pediy.com/thread-142151.htm)
- 2011.10 [pediy] [[原创]感染PE增加导入项实现注入](https://bbs.pediy.com/thread-141950.htm)
- 2011.10 [pediy] [[原创]PE LOADER，可运行MS自带的程序](https://bbs.pediy.com/thread-141891.htm)
- 2011.09 [pediy] [[原创]也谈PE重定位表](https://bbs.pediy.com/thread-140722.htm)
- 2011.09 [a1logic] [PE File Format](https://www.a1logic.com/2011/09/06/pe-file-format/)
- 2011.09 [pediy] [[原创]清除 PE 文件里的数字签名](https://bbs.pediy.com/thread-139716.htm)
- 2011.08 [pediy] [[原创]无hook无patch 无自定义peloader 在内核加载执行驱动](https://bbs.pediy.com/thread-138397.htm)
- 2011.08 [pediy] [[原创]PE文件格式学习笔记](https://bbs.pediy.com/thread-138392.htm)
- 2011.07 [pediy] [[原创]手脱PECompact 2.x+IAT修复的简单方法](https://bbs.pediy.com/thread-137883.htm)
- 2011.07 [pediy] [[原创]PE文件病毒初探](https://bbs.pediy.com/thread-137291.htm)
- 2011.07 [pediy] [[原创]我也发个PE文件查看器](https://bbs.pediy.com/thread-137042.htm)
- 2011.07 [pediy] [[原创]PE格式解析工具](https://bbs.pediy.com/thread-137031.htm)
- 2011.07 [pediy] [[原创]PESpin 1.33全保护脱壳笔记](https://bbs.pediy.com/thread-136773.htm)
- 2011.07 [vexillium] [PE Import Table and custom DLL paths](http://j00ru.vexillium.org/?p=881)
- 2011.07 [vexillium] [PE Import Table and custom DLL paths](https://j00ru.vexillium.org/2011/07/pe-import-table-and-custom-dll-paths/)
- 2011.07 [reversinglabs] [Constant Insecurity: Things you didn’t know about (PE) Portable Executable file format](https://blog.reversinglabs.com/blog/constant-insecurity-things-you-didnt-know-about-pe-portable-executable-file-format)
- 2011.07 [hexblog] [Unpacking mpress’ed PE+ DLLs with the Bochs plugin](http://www.hexblog.com/?p=403)
- 2011.06 [pediy] [[转帖]巨强悍的ASProtect脱壳机：ASProtect unpacker by PE_Kill](https://bbs.pediy.com/thread-135658.htm)
- 2011.05 [pediy] [[原创]病毒修改PE文件过程](https://bbs.pediy.com/thread-134165.htm)
- 2011.04 [codereversing] [Writing a File Infector/Encrypter: PE File Modification/Section Injection (2/4)](http://www.codereversing.com/blog/archives/92)
- 2011.04 [pediy] [[原创]发一个我写的简单PE结构解析工具](https://bbs.pediy.com/thread-132797.htm)
- 2011.04 [pediy] [[原创]给PEID 增加皮肤及音乐 一看就懂了哇](https://bbs.pediy.com/thread-132116.htm)
- 2011.03 [pediy] [SDK获得文件指针后 怎么移动指针到PE头啊](https://bbs.pediy.com/thread-131379.htm)
- 2011.02 [pediy] [给PEiD添加换肤功能（易语言源码）](https://bbs.pediy.com/thread-129868.htm)
- 2011.02 [pediy] [[原创]手工分析一个老壳PEncrypt_4.0 超详细](https://bbs.pediy.com/thread-129586.htm)
- 2011.02 [toolswatch] [NPE File Analyzer v1.0.0.0 released](http://www.toolswatch.org/2011/02/npe-file-analyzer-v1-0-0-0-released/)
- 2011.02 [pediy] [[讨论]关于给PE增加新输入表](https://bbs.pediy.com/thread-128888.htm)
- 2011.02 [pediy] [[推荐]一起学习PE格式之一判断PE文件格式（一）（二）](https://bbs.pediy.com/thread-128885.htm)
- 2011.01 [pediy] [菜鸟编写PE文件分析工具](https://bbs.pediy.com/thread-127478.htm)
- 2010.12 [pediy] [[原创]浅析PE文件感染](https://bbs.pediy.com/thread-127202.htm)
- 2010.12 [pediy] [[下载]PECompact 2.x-3.x 最新脱壳机 [支持Dll重定位]](https://bbs.pediy.com/thread-127196.htm)
- 2010.12 [pediy] [[原创]PE Fix bug SQLiteMaestro~ 自己动手,丰衣足食](https://bbs.pediy.com/thread-125916.htm)
- 2010.11 [pediy] [[原创]提取嵌入文件中的 PE 文件](https://bbs.pediy.com/thread-125674.htm)
- 2010.11 [pediy] [[原创]PE简单签名验证实现](https://bbs.pediy.com/thread-125599.htm)
- 2010.11 [pediy] [[原创]手动打造97字节PE](https://bbs.pediy.com/thread-125328.htm)
- 2010.11 [pediy] [[原创]豪杰超级DVD播放器Ⅲ破解之菜鸟了解PE文件](https://bbs.pediy.com/thread-124741.htm)
- 2010.11 [pediy] [[原创]手工PE 大小460字节](https://bbs.pediy.com/thread-124533.htm)
- 2010.11 [pediy] [[分享]发布 PESpin 1.32自动脱壳机](https://bbs.pediy.com/thread-124054.htm)
- 2010.10 [pediy] [PE病毒学习(一、二、三、四、五、六、七、八）](https://bbs.pediy.com/thread-123287.htm)
- 2010.10 [pediy] [[原创]解析PE结构之-----导出表](https://bbs.pediy.com/thread-122632.htm)
- 2010.10 [pediy] [[原创]国庆PE总复习(1-7)合集](https://bbs.pediy.com/thread-121488.htm)
- 2010.09 [pediy] [[原创]手脱PEX 0.99](https://bbs.pediy.com/thread-119891.htm)
- 2010.09 [pediy] [[原创]极小的恶作剧程序(188字节)--PE学习](https://bbs.pediy.com/thread-119614.htm)
- 2010.08 [pediy] [[原创]PECompact2变形工具](https://bbs.pediy.com/thread-118380.htm)
- 2010.08 [pediy] [[原创]小菜自编PE分析工具](https://bbs.pediy.com/thread-117787.htm)
- 2010.06 [pediy] [[原创]如何用程序判定一个PE文件是否加壳](https://bbs.pediy.com/thread-115515.htm)
- 2010.06 [pediy] [[讨论]发现LordPE一个bug](https://bbs.pediy.com/thread-114733.htm)
- 2010.06 [pediy] [[原创]自己构建PE](https://bbs.pediy.com/thread-114681.htm)
- 2010.05 [pediy] [[原创]PE资源字符串ID计算方法](https://bbs.pediy.com/thread-113040.htm)
- 2010.05 [pediy] [[原创]菜鸟对PELOCK的分析..没技术..职业灌水](https://bbs.pediy.com/thread-112667.htm)
- 2010.02 [pediy] [[原创]PE-Armor壳后继报道：从密码表逆向恢复策略！](https://bbs.pediy.com/thread-107885.htm)
- 2010.02 [pediy] [[原创]也谈PE-Armor0.49记事本的脱壳经历](https://bbs.pediy.com/thread-107842.htm)
- 2010.02 [pediy] [[原创]手写PE文件介绍PE文件（添加了图标资源，看图吧）](https://bbs.pediy.com/thread-107439.htm)
- 2010.02 [pediy] [[原创]PE格式简析](https://bbs.pediy.com/thread-107313.htm)
- 2010.02 [pediy] [[原创]MSIL-PE-EXE 感染策略](https://bbs.pediy.com/thread-106762.htm)
- 2010.01 [pediy] [[原创]一个不太通用的PE感染方法](https://bbs.pediy.com/thread-106054.htm)
- 2010.01 [pediy] [[原创]PESpin v1.32脱壳机](https://bbs.pediy.com/thread-105340.htm)
- 2009.12 [pediy] [[原创]简易的PE loader](https://bbs.pediy.com/thread-102717.htm)
- 2009.05 [pediy] [[原创]利用python+pefile库做PE格式文件的快速开发](https://bbs.pediy.com/thread-89838.htm)
- 2009.04 [pediy] [[原创]PELoader + 多线程解密的壳样例](https://bbs.pediy.com/thread-86569.htm)
- 2009.03 [pediy] [[原创]软件保护壳专题 - PE Loader的构建](https://bbs.pediy.com/thread-83669.htm)
- 2005.01 [pediy] [[2005.1月话题]保护模式与 PE Loader 行为研究](https://bbs.pediy.com/thread-9417.htm)




***


## <a id="89f963773ee87e2af6f9170ee60a7fb2"></a>DLL


### <a id="4dcfd9135aa5321b7fa65a88155256f9"></a>Recent Add


#### <a id="9753a9d52e19c69dc119bf03e9d7c3d2"></a>Tools


- [**1915**Star][22d] [C#] [lucasg/dependencies](https://github.com/lucasg/dependencies) A rewrite of the old legacy software "depends.exe" in C# for Windows devs to troubleshoot dll load dependencies issues.
- [**1333**Star][10m] [C] [fancycode/memorymodule](https://github.com/fancycode/memorymodule) Library to load a DLL from memory.
- [**1146**Star][27d] [C#] [perfare/il2cppdumper](https://github.com/perfare/il2cppdumper) Restore dll from Unity il2cpp binary file (except code)
- [**793**Star][11m] [C#] [terminals-origin/terminals](https://github.com/terminals-origin/terminals) Terminals is a secure, multi tab terminal services/remote desktop client. It uses Terminal Services ActiveX Client (mstscax.dll). The project started from the need of controlling multiple connections simultaneously. It is a complete replacement for the mstsc.exe (Terminal Services) client. This is official source moved from Codeplex.
- [**388**Star][7m] [C++] [hasherezade/dll_to_exe](https://github.com/hasherezade/dll_to_exe) Converts a DLL into EXE
- [**367**Star][1y] [PS] [netspi/pesecurity](https://github.com/NetSPI/PESecurity) PowerShell module to check if a Windows binary (EXE/DLL) has been compiled with ASLR, DEP, SafeSEH, StrongNaming, and Authenticode.
- [**363**Star][19d] [C#] [3f/dllexport](https://github.com/3f/dllexport) .NET DllExport
- [**296**Star][2y] [C++] [sensepost/rattler](https://github.com/sensepost/rattler) Automated DLL Enumerator
- [**265**Star][3y] [C++] [professor-plum/reflective-driver-loader](https://github.com/professor-plum/reflective-driver-loader)  injection technique base off Reflective DLL injection 
- [**244**Star][2y] [C#] [jephthai/openpasswordfilter](https://github.com/jephthai/openpasswordfilter) An open source custom password filter DLL and userspace service to better protect / control Active Directory domain passwords.
- [**240**Star][10m] [C++] [wbenny/detoursnt](https://github.com/wbenny/detoursnt) Detours with just single dependency - NTDLL
- [**230**Star][1y] [C#] [misaka-mikoto-tech/monohooker](https://github.com/Misaka-Mikoto-Tech/MonoHooker) hook C# method at runtime without modify dll file (such as UnityEditor.dll)
- [**215**Star][6m] [C#] [erfg12/memory.dll](https://github.com/erfg12/memory.dll) C# Hacking library for making PC game trainers.
- [**214**Star][26d] [C++] [chuyu-team/mint](https://github.com/Chuyu-Team/MINT) Contains the definitions for the Windows Internal UserMode API from ntdll.dll, samlib.dll and winsta.dll.
- [**190**Star][13d] [C++] [s1lentq/regamedll_cs](https://github.com/s1lentq/regamedll_cs) a result of reverse engineering of original library mod HLDS (build 6153beta) using DWARF debug info embedded into linux version of HLDS, cs.so
- [**164**Star][7m] [C] [bytecode77/r77-rootkit](https://github.com/bytecode77/r77-rootkit) Ring 3 Rootkit DLL
- [**156**Star][4y] [Py] [borjamerino/pazuzu](https://github.com/borjamerino/pazuzu) Reflective DLL to run binaries from memory
- [**140**Star][7m] [Visual Basic .NET] [dzzie/pdfstreamdumper](https://github.com/dzzie/pdfstreamdumper) research tool for the analysis of malicious pdf documents. make sure to run the installer first to get all of the 3rd party dlls installed correctly.
- [**136**Star][27d] [C] [mity/mctrl](https://github.com/mity/mctrl) C library providing set of additional user interface controls for Windows, intended to be complementary to standard Win32API controls from USER32.DLL and COMCTL32.DLL.
- [**133**Star][3m] [C++] [itm4n/usodllloader](https://github.com/itm4n/usodllloader) Windows - Weaponizing privileged file writes with the Update Session Orchestrator service
- [**133**Star][3m] [C#] [fireeye/duedlligence](https://github.com/fireeye/duedlligence) Shellcode runner for all application whitelisting bypasses
- [**123**Star][1y] [C] [cylancevulnresearch/reflectivedllrefresher](https://github.com/cylancevulnresearch/reflectivedllrefresher) Universal Unhooking
- [**121**Star][29d] [C++] [phackt/stager.dll](https://github.com/phackt/stager.dll) Code from this article:
- [**116**Star][3m] [C#] [infosecn1nja/sharpdoor](https://github.com/infosecn1nja/sharpdoor) SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
- [**113**Star][2m] [C++] [outflanknl/recon-ad](https://github.com/outflanknl/recon-ad) Recon-AD, an AD recon tool based on ADSI and reflective DLL’s
- [**112**Star][10m] [C] [strivexjun/memorymodulepp](https://github.com/strivexjun/memorymodulepp) Library to load a DLL from memory
- [**92**Star][5y] [Py] [neo23x0/dllrunner](https://github.com/neo23x0/dllrunner) Smart DLL execution for malware analysis in sandbox systems
- [**89**Star][1y] [PS] [realoriginal/reflectivepotato](https://github.com/realoriginal/reflectivepotato) MSFRottenPotato built as a Reflective DLL.
- [**82**Star][2y] [C] [hvqzao/foolavc](https://github.com/hvqzao/foolavc) foolav successor - loads DLL, executable or shellcode into memory and runs it effectively bypassing AV
- [**81**Star][11m] [C] [mr-un1k0d3r/maliciousdllgenerator](https://github.com/mr-un1k0d3r/maliciousdllgenerator) DLL Generator for side loading attack
- [**77**Star][1m] [C] [hasherezade/module_overloading](https://github.com/hasherezade/module_overloading) A more stealthy variant of "DLL hollowing"
- [**73**Star][1y] [Batchfile] [b4rtik/hiddenpowershelldll](https://github.com/b4rtik/hiddenpowershelldll) 
- [**72**Star][1y] [C#] [0xbadjuju/rundotnetdll32](https://github.com/0xbadjuju/rundotnetdll32) A tool to run .Net DLLs from the command line
- [**67**Star][4y] [C] [microwave89/rtsectiontest](https://github.com/microwave89/rtsectiontest) An Attempt to Bypass Memory Scanners By Misusing the ntdll.dll "RT" Section.
- [**66**Star][11m] [C++] [jacksonvd/pwnedpasswordsdll](https://github.com/jacksonvd/pwnedpasswordsdll) Open source solution to check prospective AD passwords against previously breached passwords
- [**59**Star][2m] [Py] [mavenlin/dll_wrapper_gen](https://github.com/mavenlin/dll_wrapper_gen) Automatic generation of Dll wrapper for both 32 bit and 64 bit Dll
- [**55**Star][23d] [C] [danielkrupinski/vac-hooks](https://github.com/danielkrupinski/vac-hooks) Hook WinAPI functions used by Valve Anti-Cheat. Log calls and intercept arguments & return values. DLL written in C.
- [**55**Star][8m] [C] [gosecure/dllpasswordfilterimplant](https://github.com/gosecure/dllpasswordfilterimplant) DLL Password Filter Implant with Exfiltration Capabilities
- [**54**Star][2y] [PS] [byt3bl33d3r/invoke-autoit](https://github.com/byt3bl33d3r/invoke-autoit) Loads the AutoIt DLL and PowerShell assemblies into memory and executes the specified keystrokes
- [**53**Star][7m] [C] [strivexjun/hidedll](https://github.com/strivexjun/hidedll) Hide DLL / Hide Module / Hide Dynamic Link Library
- [**52**Star][2y] [C] [shadowsocks/libsscrypto](https://github.com/shadowsocks/libsscrypto) Build libsscrypto.dll for shadowsocks-windows.
- [**51**Star][2y] [JS] [cerebral/webpack-packager](https://github.com/cerebral/webpack-packager) A service that packages DLL bundles and manifests
- [**50**Star][3y] [Visual Basic .NET] [fireeye/remote_lookup](https://github.com/fireeye/remote_lookup) Resolves DLL API entrypoints for a process w/ remote query capabilities.
- [**47**Star][2y] [JS] [cerebral/webpack-dll](https://github.com/cerebral/webpack-dll) A service that converts a package into a DLL and manifest
- [**47**Star][1y] [C++] [lianglixin/memdllloader](https://github.com/lianglixin/memdllloader) 加载内存当中的DLL文件
- [**45**Star][2y] [C#] [amarkulo/openpasswordfilter](https://github.com/amarkulo/openpasswordfilter) An open source custom password filter DLL and userspace service to better protect / control Active Directory domain passwords.
- [**44**Star][5m] [C#] [userr00t/universalunityhooks](https://github.com/userr00t/universalunityhooks) A framework designed to hook into and modify methods in unity games via dlls
- [**43**Star][1y] [C#] [enkomio/rundotnetdll](https://github.com/enkomio/rundotnetdll) A simple utility to list all methods of a given .NET Assembly and to invoke them
- [**43**Star][5m] [C] [w1nds/dll2shellcode](https://github.com/w1nds/dll2shellcode) dll转shellcode工具
- [**42**Star][1y] [C++] [userexistserror/dllloadershellcode](https://github.com/userexistserror/dllloadershellcode) Shellcode to load an appended Dll
- [**42**Star][1y] [C] [wanttobeno/dllprotect](https://github.com/wanttobeno/dllprotect) dll文件加解密和内存加载
- [**38**Star][17d] [Rust] [verideth/dll_hook-rs](https://github.com/verideth/dll_hook-rs) Rust code to show how hooking in rust with a dll works.
- [**36**Star][2y] [C#] [scavanger/memorymodule.net](https://github.com/scavanger/memorymodule.net) Loading a native DLL in the memory.
- [**36**Star][1y] [C#] [adrenak/unidll](https://github.com/adrenak/unidll) Editor window to create DLLs from C# code in Unity
- [**36**Star][11m] [C#] [codefoundryde/legacywrapper](https://github.com/codefoundryde/legacywrapper) LegacyWrapper uses a x86 wrapper to call legacy dlls from a 64 bit process (or vice versa).
- [**35**Star][2m] [C] [nordicsemiconductor/pynrfjprog](https://github.com/nordicsemiconductor/pynrfjprog) Python wrapper around the nrfjprog dynamic link library (DLL)
- [**35**Star][2y] [C#] [0xbadjuju/tellmeyoursecrets](https://github.com/0xbadjuju/tellmeyoursecrets) A C# DLL to Dump LSA Secrets
- [**33**Star][4y] [C++] [5loyd/makecode](https://github.com/5loyd/makecode) Dll Convert to Shellcode.
- [**32**Star][10m] [C] [ctxis/capemon](https://github.com/ctxis/capemon) CAPE monitor DLLs
- [**32**Star][11m] [C++] [jacksonvd/pwnedpasswordsdll-api](https://github.com/jacksonvd/pwnedpasswordsdll-api) Open source solution to check prospective AD passwords against previously breached passwords
- [**31**Star][2y] [C++] [rprop/cppdll](https://github.com/rprop/cppdll) CppDLL a small tool that will help you generate Cpp Header(.h) and Import Library(.lib) from Dynamic Link Library(.dll)
- [**30**Star][2y] [deroko/payloadrestrictions](https://github.com/deroko/payloadrestrictions) EMET 集成到 Win10Insider 之后改名为 PayloadRestrictions，文章分析了 PayloadRestrictions.dll 的加载过程
- [**27**Star][2y] [C] [1ce0ear/dllloaderunpacker](https://github.com/1ce0ear/dllloaderunpacker) a Windows malware reversing tool to unpack the DLL loader malware in runtime.
- [**27**Star][2y] [C] [deroko/activationcontexthook](https://github.com/deroko/activationcontexthook) activationcontexthook：Hook 进程，强制进程加载重定向的 DLL
- [**27**Star][7m] [C++] [jnastarot/soul_eater](https://github.com/jnastarot/soul_eater) it can extract functions from .dll, .exe, .sys and it be work! :)
- [**27**Star][9m] [C++] [karaulov/warcraftiii_dll_126-127](https://github.com/karaulov/warcraftiii_dll_126-127) Improvements for Warcraft III 126a used in new DoTA (d1stats.ru). Auto unload from w3x map and load to Warcraft III !
- [**27**Star][3y] [C] [tinysec/runwithdll](https://github.com/tinysec/runwithdll) windows create process with a dll load first time via LdrHook
- [**27**Star][3y] [JS] [fliphub/d-l-l](https://github.com/fliphub/d-l-l) Simplified DLL config creator & handler
- [**23**Star][3y] [C] [david-reguera-garcia-dreg/phook](https://github.com/david-reguera-garcia-dreg/phook) Full DLL Hooking, phrack 65
- [**23**Star][5y] [C++] [liamkarlmitchell/signaturescanner](https://github.com/liamkarlmitchell/signaturescanner) I wanted a nicer signature scanner that worked the way I wanted. Include however you want in your own DLL project.
- [**23**Star][1y] [Assembly] [osandamalith/pesecinfo](https://github.com/osandamalith/pesecinfo) A simple tool to view important DLL Characteristics and change DEP and ASLR
- [**23**Star][7y] [C++] [wyyqyl/hidemodule](https://github.com/wyyqyl/hidemodule) The dll that can hide itself and then delete itselft.
- [**22**Star][3y] [C++] [bblanchon/dllhelper](https://github.com/bblanchon/dllhelper) How to GetProcAddress() like a boss
- [**21**Star][5m] [C#] [empier/memoryeditor](https://github.com/empier/memoryeditor) [C#]Main.exe < - > [C_DLL] < - > [C_KERNEL] = Memory_Editor via Kernel
- [**21**Star][5m] [Shell] [exe-thumbnailer/exe-thumbnailer](https://github.com/exe-thumbnailer/exe-thumbnailer) Thumbnailer for .exe/.dll/.msi/.lnk files on Linux systems.
- [**19**Star][3y] [C++] [changeofpace/remote-process-cookie-for-windows-7](https://github.com/changeofpace/remote-process-cookie-for-windows-7) Obtain remote process cookies by performing a brute-force attack on ntdll.RtlDecodePointer using known pointer encodings.
- [**19**Star][10m] [C] [graykernel/grayfrost](https://github.com/graykernel/grayfrost) C++ DLL Bootstrapper for spinning up the CLR for C# Payloads
- [**19**Star][8m] [C++] [benjaminsoelberg/rundll-ng](https://github.com/benjaminsoelberg/rundll-ng) A better alternative to RunDLL32
- [**18**Star][2y] [C++] [3gstudent/passwordfilter](https://github.com/3gstudent/passwordfilter) 2 ways of Password Filter DLL to record the plaintext password
- [**15**Star][7m] [C] [1captainnemo1/dllreverseshell](https://github.com/1captainnemo1/dllreverseshell) A CUSTOM CODED FUD DLL, CODED IN C , WHEN LOADED , VIA A DECOY WEB-DELIVERY MODULE( FIRING A DECOY PROGRAM), WILL GIVE A REVERSE SHELL (POWERSHELL) FROM THE VICTIM MACHINE TO THE ATTACKER CONSOLE , OVER LAN AND WAN.
- [**15**Star][2y] [C] [jnastarot/ice9](https://github.com/jnastarot/ice9) ice9 - is anticheat based on usermode tricks and undocumented methods , builded as dll for loading trought the shibari framework
- [**15**Star][2y] [C++] [ms-jdow/rtlsdr-cplusplus-vs2010](https://github.com/ms-jdow/rtlsdr-cplusplus-vs2010) MS Visual Studio version of the Oliver Jowett branch for rtlsdr.dll. This version is in C++ with slight additional functonality.
- [**15**Star][10d] [C++] [wohlsoft/lunalua](https://github.com/wohlsoft/lunalua) LunaLua - LunaDLL with Lua, is a free extension for SMBX game engine
- [**14**Star][2y] [JS] [3gstudent/exceldllloader](https://github.com/3gstudent/exceldllloader) Execute DLL via the Excel.Application object's RegisterXLL() method
- [**14**Star][4y] [hexx0r/cve-2015-6132](https://github.com/hexx0r/cve-2015-6132) Microsoft Office / COM Object DLL Planting
- [**14**Star][1y] [C++] [hmihaidavid/hooks](https://github.com/hmihaidavid/hooks) A DLL that performs IAT hooking
- [**13**Star][2y] [C] [3gstudent/add-dll-exports](https://github.com/3gstudent/add-dll-exports) Use to generate DLL through Visual Studio
- [**11**Star][1y] [Py] [makipl/aslr_disabler](https://github.com/makipl/aslr_disabler) Disables ASLR flag IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE in IMAGE_OPTIONAL_HEADER on pre-compiled EXE. Works for both 32 and 64 bit Windows EXE/PE images
- [**11**Star][2y] [C++] [seanpesce/d3d11-wrapper](https://github.com/seanpesce/d3d11-wrapper) d3d11.dll wrapper for intercepting DirectX 11 function calls.
- [**9**Star][1y] [C++] [abinmm/memdllloader_blackbone](https://github.com/abinmm/memdllloader_blackbone) Windows memory hacking library
- [**9**Star][1y] [C++] [dissectmalware/winnativeio](https://github.com/dissectmalware/winnativeio) Using Undocumented NTDLL Functions to Read/Write/Delete File
- [**8**Star][2y] [C++] [mgostih/snifferih](https://github.com/mgostih/snifferih) DLL Hooking Packet Sniffer
- [**6**Star][1y] [C++] [ovidiuvio/libntdbg](https://github.com/ovidiuvio/libntdbg) ntdll native api wrapper, used by VSDebugPro
- [**5**Star][6y] [C++] [sanje2v/mantapropertyextension](https://github.com/sanje2v/mantapropertyextension) This extension extends Windows Explorer Property System to show information about EXE, DLL, OBJ and other binary files
- [**5**Star][3y] [C] [xiaomagexiao/gamedll](https://github.com/xiaomagexiao/gamedll) gamedll
- [**5**Star][3y] [C++] [wyexe/newyugioh_cheatdll_x64](https://github.com/wyexe/NewYuGiOh_CheatDLL_x64) 
- [**4**Star][1y] [C++] [aschrein/apiparse](https://github.com/aschrein/apiparse) Small project to learn windows dll hooking techniques based on sources of renderdoc and apitrace
- [**4**Star][2y] [C] [re4lity/cve-2017-11907](https://github.com/re4lity/cve-2017-11907) Windows: heap overflow in jscript.dll in Array.sort
- [**4**Star][1y] [C++] [rtcrowley/offensive-netsh-helper](https://github.com/rtcrowley/offensive-netsh-helper) Maintain Windows Persistence with an evil Netshell Helper DLL
- [**3**Star][9m] [secforce/macro-keystrokes](https://github.com/secforce/macro-keystrokes) PoC of execution of commands on a Word macro, without the use of rundll32.exe and importation of kernel32 libraries such as CreateRemoteThread or CreateProcessA. This technique simply relies on sending keystrokes to the host.
- [**3**Star][4y] [C] [thomaslaurenson/cellxml-offreg](https://github.com/thomaslaurenson/cellxml-offreg) CellXML-offreg.exe is a portable Windows tool that parses an offline Windows Registry hive file and converts it to the RegXML format. CellXML-offreg leverages the Microsoft Windows offreg.dll library to aid in parsing the Registry structure.
- [**2**Star][4y] [C#] [ericlaw1979/dllrewriter](https://github.com/ericlaw1979/dllrewriter) Rewrite Chrome.dll so Alt+F,C maps to Close Tab
- [**2**Star][2y] [C++] [wanttobeno/dlib-attacher](https://github.com/wanttobeno/dlib-attacher) 给PE添加dll,只支持32位程序。
- [**1**Star][2y] [c++] [C4t0ps1s/dllgrabber](https://bitbucket.org/c4t0ps1s/dllgrabber) 
- [**1**Star][C#] [ceramicskate0/outlook_data_exfil](https://github.com/ceramicskate0/outlook_data_exfil) DLL/plugin that is a POC for data exfil via Outlook
- [**1**Star][3y] [C#] [giovannidicanio/safearraysamples](https://github.com/giovannidicanio/safearraysamples) Mixed C++/C# project containing a native DLL that produces array data using safe arrays, that are consumed by a C# UI.
- [**0**Star][2y] [C] [vallejocc/poc-find-chrome-ktlsprotocolmethod](https://github.com/vallejocc/poc-find-chrome-ktlsprotocolmethod) Proof of Concept code to download chrome.dll symbols from chromium symbols store and find the bssl::kTLSProtocolMethod table of pointers (usually hooked by malware)


#### <a id="b05f4c5cdfe64e1dde2a3c8556e85827"></a>Post


- 2019.12 [freebuf] [如何使用ADSI接口和反射型DLL枚举活动目录](https://www.freebuf.com/articles/system/218855.html)
- 2019.11 [tyranidslair] [The Internals of AppLocker - Part 4 - Blocking DLL Loading](https://tyranidslair.blogspot.com/2019/11/the-internals-of-applocker-part-4.html)
- 2019.09 [hexacorn] [RunDll32 — API calling](http://www.hexacorn.com/blog/2019/09/28/rundll32-api-calling/)
- 2019.09 [4hou] [《MiniDumpWriteDump via COM+ Services DLL》的利用测试](https://www.4hou.com/technology/20146.html)
- 2019.08 [osandamalith] [Converting an EXE to a DLL](https://osandamalith.com/2019/08/26/converting-an-exe-to-a-dll/)
- 2019.06 [4hou] [域渗透——利用dnscmd在DNS服务器上实现远程加载Dll](https://www.4hou.com/penetration/18447.html)
- 2019.06 [hexacorn] [Playing with Delay-Loaded DLLs…](http://www.hexacorn.com/blog/2019/06/03/playing-with-delay-loaded-dlls/)
- 2019.05 [3gstudent] [域渗透——利用dnscmd在DNS服务器上实现远程加载Dll](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8dnscmd%E5%9C%A8DNS%E6%9C%8D%E5%8A%A1%E5%99%A8%E4%B8%8A%E5%AE%9E%E7%8E%B0%E8%BF%9C%E7%A8%8B%E5%8A%A0%E8%BD%BDDll/)
- 2019.05 [3gstudent] [域渗透——利用dnscmd在DNS服务器上实现远程加载Dll](https://3gstudent.github.io/3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8dnscmd%E5%9C%A8DNS%E6%9C%8D%E5%8A%A1%E5%99%A8%E4%B8%8A%E5%AE%9E%E7%8E%B0%E8%BF%9C%E7%A8%8B%E5%8A%A0%E8%BD%BDDll/)
- 2019.05 [4sysops] [PS Protector: Convert your PowerShell module into a .NET assembly DLL](https://4sysops.com/archives/ps-protector-convert-your-powershell-module-into-a-net-assembly-dll/)
- 2019.05 [0x00sec] [Malicious DLL execution using Apple's APSDaemon.exe signed binary](https://0x00sec.org/t/malicious-dll-execution-using-apples-apsdaemon-exe-signed-binary/13409/)
- 2019.04 [4hou] [Qt5漏洞导致Cisco WebEx和Malwarebytes反病毒产品可远程加载任意DLL](https://www.4hou.com/vulnerable/17257.html)
- 2019.04 [id] [DLL CryptoMix](http://id-ransomware.blogspot.com/2019/04/dll-cryptomix-ransomware.html)
- 2019.03 [CyborgElf] [How To Make an Internal DLL Game Hack C++ (Rainbow Six Siege)](https://www.youtube.com/watch?v=wrIPVBXXisc)
- 2019.02 [] [No Source Code For a 14-Year Old Vulnerable DLL? No Problem. (CVE-2018-20250)](https://blog.0patch.com/2019/02/no-source-code-for-14-year-old.html)
- 2018.12 [srcincite] [WebExec Reloaded :: Cisco Webex Meetings Desktop App Update Service DLL Planting Elevation of Privilege Vulnerability](https://srcincite.io/blog/2018/12/03/webexec-reloaded-cisco-webex-meetings-desktop-app-lpe.html)




### <a id="3b4617e54405a32290224b729ff9f2b3"></a>DLL Injection


#### <a id="b0d50ee42d53b1f88b32988d34787137"></a>Tools


- [**1094**Star][6y] [C] [stephenfewer/reflectivedllinjection](https://github.com/stephenfewer/reflectivedllinjection) Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process.
- [**963**Star][2y] [C] [fdiskyou/injectallthethings](https://github.com/fdiskyou/injectallthethings) Seven different DLL injection techniques in one single project.
- [**713**Star][5m] [C++] [darthton/xenos](https://github.com/darthton/xenos) Windows dll injector
- [**588**Star][2m] [PS] [monoxgas/srdi](https://github.com/monoxgas/srdi) Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
- [**370**Star][7y] [C++] [opensecurityresearch/dllinjector](https://github.com/opensecurityresearch/dllinjector) dll injection tool that implements various methods
- [**273**Star][2y] [C++] [gellin/teamviewer_permissions_hook_v1](https://github.com/gellin/teamviewer_permissions_hook_v1) A proof of concept injectable C++ dll, that uses naked inline hooking and direct memory modification to change your TeamViewer permissions.
- [**190**Star][2y] [C] [sud01oo/processinjection](https://github.com/sud01oo/ProcessInjection) Some ways to inject a DLL into a alive process
- [**189**Star][7y] [C++] [hzphreak/vminjector](https://github.com/hzphreak/vminjector) DLL Injection tool to unlock guest VMs
- [**189**Star][7y] [C++] [hzphreak/vminjector](https://github.com/hzphreak/VMInjector) DLL Injection tool to unlock guest VMs
- [**188**Star][7d] [C++] [wunkolo/uwpdumper](https://github.com/wunkolo/uwpdumper) DLL and Injector for dumping UWP applications at run-time to bypass encrypted file system protection.
- [**173**Star][12m] [C++] [jonatan1024/clrinject](https://github.com/jonatan1024/clrinject) 将 C＃EXE 或 DLL 程序集注入任意CLR 运行时或者其他进程的 AppDomain
- [**173**Star][6m] [C++] [strivexjun/driverinjectdll](https://github.com/strivexjun/driverinjectdll) Using Driver Global Injection dll, it can hide DLL modules
- [**168**Star][6y] [Py] [infodox/python-dll-injection](https://github.com/infodox/python-dll-injection) Python toolkit for injecting DLL files into running processes on Windows
- [**142**Star][4y] [C] [dismantl/improvedreflectivedllinjection](https://github.com/dismantl/improvedreflectivedllinjection) An improvement of the original reflective DLL injection technique by Stephen Fewer of Harmony Security
- [**109**Star][2y] [C] [securestate/syringe](https://github.com/securestate/syringe) A General Purpose DLL & Code Injection Utility
- [**91**Star][2y] [C] [3gstudent/inject-dll-by-process-doppelganging](https://github.com/3gstudent/inject-dll-by-process-doppelganging) Process Doppelgänging
- [**87**Star][3y] [C] [zerosum0x0/threadcontinue](https://github.com/zerosum0x0/threadcontinue) Reflective DLL injection using SetThreadContext() and NtContinue()
- [**85**Star][3y] [C] [countercept/doublepulsar-usermode-injector](https://github.com/countercept/doublepulsar-usermode-injector) A utility to use the usermode shellcode from the DOUBLEPULSAR payload to reflectively load an arbitrary DLL into another process, for use in testing detection techniques or other security research.
- [**78**Star][1m] [C++] [nefarius/injector](https://github.com/nefarius/injector) Command line utility to inject and eject DLLs
- [**71**Star][1y] [C++] [3gstudent/inject-dll-by-apc](https://github.com/3gstudent/inject-dll-by-apc) Asynchronous Procedure Calls
- [**71**Star][1y] [C] [alex9191/kernel-dll-injector](https://github.com/alex9191/kernel-dll-injector) Kernel-Mode Driver that loads a dll into every new created process that loads kernel32.dll module
- [**61**Star][9d] [C] [danielkrupinski/memject](https://github.com/danielkrupinski/memject) Simple Dll injector loading from memory. Supports PE header and entry point erasure. Written in C99.
- [**58**Star][3y] [C++] [azerg/remote_dll_injector](https://github.com/azerg/remote_dll_injector) Stealth DLL injector
- [**56**Star][8m] [C] [rapid7/reflectivedllinjection](https://github.com/rapid7/reflectivedllinjection) Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process.
- [**53**Star][2y] [C++] [mq1n/dllthreadinjectiondetector](https://github.com/mq1n/dllthreadinjectiondetector) 
- [**52**Star][2y] [C] [nccgroup/ncloader](https://github.com/nccgroup/ncloader) A session-0 capable dll injection utility
- [**51**Star][1y] [C] [adrianyy/keinject](https://github.com/adrianyy/keinject) Kernel LdrLoadDll injector
- [**51**Star][3y] [C++] [zer0mem0ry/standardinjection](https://github.com/zer0mem0ry/standardinjection) A simple Dll Injection demonstration
- [**50**Star][1y] [C] [realoriginal/reflective-rewrite](https://github.com/realoriginal/reflective-rewrite) Attempt to rewrite StephenFewers Reflective DLL Injection to make it a little more stealthy. Some code taken from Meterpreter & sRDI. Currently a work in progress.
- [**49**Star][2y] [C++] [zodiacon/dllinjectionwiththreadcontext](https://github.com/zodiacon/dllinjectionwiththreadcontext) This is a sample that shows how to leverage SetThreadContext for DLL injection
- [**46**Star][4y] [C++] [papadp/reflective-injection-detection](https://github.com/papadp/reflective-injection-detection) a program to detect reflective dll injection on a live machine
- [**40**Star][3y] [C++] [zer0mem0ry/manualmap](https://github.com/zer0mem0ry/manualmap) A Simple demonstration of manual dll injector
- [**36**Star][10m] [C++] [nanoric/pkn](https://github.com/nanoric/pkn) core of pkn game hacking project. Including mainly for process management, memory management, and DLL injecttion. Also PE analysis, windows registry management, compile-time sting encryption, byte-code emulator, etc. Most of them can run under kernel mode.
- [**36**Star][2y] [C++] [rolfrolles/wbdeshook](https://github.com/rolfrolles/wbdeshook) DLL-injection based solution to Brecht Wyseur's wbDES challenge (based on SysK's Phrack article)
- [**36**Star][2y] [C++] [blole/injectory](https://github.com/blole/injectory) command-line interface dll injector
- [**34**Star][1m] [Assembly] [danielkrupinski/inflame](https://github.com/danielkrupinski/inflame) User-mode Windows DLL injector written in Assembly language (FASM syntax) with WinAPI.
- [**30**Star][1y] [C++] [psmitty7373/eif](https://github.com/psmitty7373/eif) Evil Reflective DLL Injection Finder
- [**29**Star][1y] [C++] [notscimmy/libinject](https://github.com/notscimmy/libinject) Currently supports injecting signed/unsigned DLLs in 64-bit processes
- [**29**Star][3y] [C++] [stormshield/beholder-win32](https://github.com/stormshield/beholder-win32) A sample on how to inject a DLL from a kernel driver
- [**27**Star][1y] [HTML] [flyrabbit/winproject](https://github.com/flyrabbit/winproject) Hook, DLLInject, PE_Tool
- [**27**Star][7m] [C++] [m-r-j-o-h-n/swh-injector](https://github.com/m-r-j-o-h-n/swh-injector) An Injector that can inject dll into game process protected by anti cheat using SetWindowsHookEx.
- [**27**Star][5y] [C] [olsut/kinject-x64](https://github.com/olsut/kinject-x64) Kinject - kernel dll injector, currently available in x86 version, will be updated to x64 soon.
- [**27**Star][12m] [C] [sqdwr/loadimageinject](https://github.com/sqdwr/loadimageinject) LoadImage Routine Inject Dll
- [**26**Star][2y] [C] [ice3man543/zeusinjector](https://github.com/ice3man543/zeusinjector) An Open Source Windows DLL Injector With All Known Techniques Available
- [**25**Star][6y] [C] [whyallyn/paythepony](https://github.com/whyallyn/paythepony) Pay the Pony is hilarityware that uses the Reflective DLL injection library to inject into a remote process, encrypt and demand a ransom for files, and inflict My Little Pony madness on a system.
- [**23**Star][12d] [Py] [fullshade/py-memject](https://github.com/fullshade/py-memject) A Windows .DLL injector written in Python
- [**21**Star][5y] [C] [nyx0/dll-inj3cti0n](https://github.com/nyx0/dll-inj3cti0n) Another dll injection tool.
- [**20**Star][9m] [C#] [enkomio/managedinjector](https://github.com/enkomio/managedinjector) A C# DLL injection library
- [**20**Star][6y] [C#] [tmthrgd/dll-injector](https://github.com/tmthrgd/dll-injector) Inject and detour DLLs and program functions both managed and unmanaged in other programs, written (almost) purely in C#. [Not maintained].
- [**19**Star][6y] [C++] [coreyauger/slimhook](https://github.com/coreyauger/slimhook) Demonstration of dll injection. As well loading .net runtime and calling .net code. Example hijacking d3d9 dll and altering rendering of games.
- [**17**Star][7y] [C] [strobejb/injdll](https://github.com/strobejb/injdll) DLL Injection commandline utility
- [**17**Star][3y] [C#] [cameronaavik/ilject](https://github.com/cameronaavik/ilject) Provides a way which you can load a .NET dll/exe from disk, modify/inject IL, and then run the assembly all in memory without modifying the file.
- [**15**Star][1y] [C] [ntraiseharderror/phage](https://github.com/ntraiseharderror/phage) Reflective DLL Injection style process infector
- [**15**Star][3y] [C] [portcullislabs/wxpolicyenforcer](https://github.com/portcullislabs/wxpolicyenforcer) Injectable Windows DLL which enforces a W^X memory policy on a process
- [**14**Star][1y] [C#] [ulysseswu/vinjex](https://github.com/ulysseswu/vinjex) A simple DLL injection lib using Easyhook, inspired by VInj.
- [**13**Star][5y] [C++] [matrix86/wincodeinjection](https://github.com/matrix86/wincodeinjection) Dll Injection and Code injection sample
- [**13**Star][4y] [C++] [spl0i7/dllinject](https://github.com/spl0i7/dllinject) Mineweeper bot by DLL Injection
- [**11**Star][8m] [C#] [ihack4falafel/dll-injection](https://github.com/ihack4falafel/dll-injection) C# program that takes process id and path to DLL payload to perform DLL injection method.
- [**11**Star][2y] [C++] [sherazibrahim/dll-injector](https://github.com/sherazibrahim/dll-injector) I created a dll injector I am going to Open source its Code. But remember one thing that is any one can use it only for Educational purpose .I again say do not use it to damage anyone's Computer.But one thing if you are using it for some good purpose like to help someone who really need help then I permit you to use it.
- [**7**Star][1y] [C] [haidragon/newinjectdrv](https://github.com/haidragon/newinjectdrv) APC注入DLL内核层
- [**7**Star][2y] [C++] [pfussell/pivotal](https://github.com/pfussell/pivotal) A MITM proxy server for reflective DLL injection through WinINet
- [**7**Star][4m] [C] [userexistserror/injectdll](https://github.com/userexistserror/injectdll) Inject a Dll from memory
- [**6**Star][1y] [thesph1nx/covenant](https://github.com/thesph1nx/covenant) Metepreter clone - DLL Injection Backdoor
- [**6**Star][5y] [C] [mwwolters/dll-injection](https://github.com/mwwolters/DLL-Injection) 
- [**5**Star][4y] [C++] [ciantic/remotethreader](https://github.com/ciantic/remotethreader) Helps you to inject your dll in another process
- [**4**Star][6m] [C++] [reclassnet/reclass.net-memorypipeplugin](https://github.com/reclassnet/reclass.net-memorypipeplugin) A ReClass.NET plugin which allows direct memory access via dll injection.
- [**1**Star][10m] [PS] [getrektboy724/maldll](https://github.com/getrektboy724/maldll) A bunch of malicius dll to inject to a process


#### <a id="1a0b0dab4cdbab08bbdc759bab70dbb6"></a>Post


- 2019.12 [freebuf] [如何防止恶意的第三方DLL注入到进程](https://www.freebuf.com/articles/system/219198.html)
- 2019.06 [aliyun] [Windows 10 Task Scheduler服务DLL注入漏洞分析](https://xz.aliyun.com/t/5286)
- 2018.10 [pediy] [[原创]代替创建用户线程使用ShellCode注入DLL的小技巧](https://bbs.pediy.com/thread-247515.htm)
- 2018.10 [4hou] [如何利用DLL注入绕过Win10勒索软件保护](http://www.4hou.com/technology/13923.html)
- 2018.10 [0x00sec] [Reflective Dll Injection - Any Way to check If a process is already injected?](https://0x00sec.org/t/reflective-dll-injection-any-way-to-check-if-a-process-is-already-injected/8980/)
- 2018.09 [pediy] [[原创]win10_arm64 驱动注入dll 到 arm32程序](https://bbs.pediy.com/thread-247032.htm)
- 2018.08 [freebuf] [sRDI：一款通过Shellcode实现反射型DLL注入的强大工具](http://www.freebuf.com/sectool/181426.html)
- 2018.07 [4hou] [注入系列——DLL注入](http://www.4hou.com/technology/12703.html)
- 2018.06 [0x00sec] [Reflective DLL Injection - AV detects at runtime](https://0x00sec.org/t/reflective-dll-injection-av-detects-at-runtime/7307/)
- 2018.06 [qq] [【游戏漏洞】注入DLL显示游戏窗口](http://gslab.qq.com/article-508-1.html)
- 2017.12 [secist] [Mavinject | Dll Injected](http://www.secist.com/archives/5912.html)
- 2017.12 [secvul] [SSM终结dll注入](https://secvul.com/topics/951.html)
- 2017.10 [nsfocus] [【干货分享】Sandbox技术之DLL注入](http://blog.nsfocus.net/sandbox-technology-dll-injection/)
- 2017.10 [freebuf] [DLL注入新姿势：反射式DLL注入研究](http://www.freebuf.com/articles/system/151161.html)
- 2017.10 [pediy] [[原创]通过Wannacry分析内核shellcode注入dll技术](https://bbs.pediy.com/thread-221756.htm)
- 2017.09 [360] [Dll注入新姿势：SetThreadContext注入](https://www.anquanke.com/post/id/86786/)
- 2017.08 [silentbreaksecurity] [sRDI – Shellcode Reflective DLL Injection](https://silentbreaksecurity.com/srdi-shellcode-reflective-dll-injection/)
- 2017.08 [360] [DLL注入那些事](https://www.anquanke.com/post/id/86671/)
- 2017.08 [freebuf] [系统安全攻防战：DLL注入技术详解](http://www.freebuf.com/articles/system/143640.html)
- 2017.08 [pediy] [[翻译]多种DLL注入技术原理介绍](https://bbs.pediy.com/thread-220405.htm)
- 2017.07 [0x00sec] [Reflective DLL Injection](https://0x00sec.org/t/reflective-dll-injection/3080/)
- 2017.07 [zerosum0x0] [ThreadContinue - Reflective DLL Injection Using SetThreadContext() and NtContinue()](https://zerosum0x0.blogspot.com/2017/07/threadcontinue-reflective-injection.html)
- 2017.07 [zerosum0x0] [Proposed Windows 10 EAF/EMET "Bypass" for Reflective DLL Injection](https://zerosum0x0.blogspot.com/2017/06/proposed-eafemet-bypass-for-reflective.html)
- 2017.05 [360] [NSA武器库：DOUBLEPULSAR的内核DLL注入技术](https://www.anquanke.com/post/id/86137/)
- 2017.05 [lallouslab] [7 DLL injection techniques in Microsoft Windows](http://lallouslab.net/2017/05/15/7-dll-injection-techniques-in-the-microsoft-windows/)
- 2017.05 [3or] [mimilib DHCP Server Callout DLL injection](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)
- 2017.05 [3or] [Hunting DNS Server Level Plugin dll injection](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html)
- 2017.04 [arvanaghi] [DLL Injection Using LoadLibrary in C](https://arvanaghi.com/blog/dll-injection-using-loadlibrary-in-C/)
- 2017.04 [countercept] [Analyzing the DOUBLEPULSAR Kernel DLL Injection Technique](https://countercept.com/blog/analyzing-the-doublepulsar-kernel-dll-injection-technique/)
- 2017.04 [countercept] [Analyzing the DOUBLEPULSAR Kernel DLL Injection Technique](https://countercept.com/our-thinking/analyzing-the-doublepulsar-kernel-dll-injection-technique/)
- 2017.04 [pentestlab] [DLL Injection](https://pentestlab.blog/2017/04/04/dll-injection/)
- 2016.06 [lowleveldesign] [!injectdll – a remote thread approach](https://lowleveldesign.org/2016/06/27/injectdll-a-remote-thread-approach/)
- 2016.04 [ketansingh] [Hacking games with DLL Injection](https://ketansingh.net/hacking-games-with-dll-injection/)
- 2016.02 [freebuf] [通过 DLL 注入和代码修改绕过 XIGNCODE3 的反作弊保护](http://www.freebuf.com/articles/terminal/96741.html)
- 2016.01 [freebuf] [DLL注入的几种姿势（二）：CreateRemoteThread And More](http://www.freebuf.com/articles/system/94693.html)
- 2016.01 [freebuf] [DLL注入的几种姿势（一）：Windows Hooks](http://www.freebuf.com/articles/system/93413.html)
- 2015.08 [rapid7] [Using Reflective DLL Injection to exploit IE Elevation Policies](https://blog.rapid7.com/2015/08/28/using-reflective-dll-injection-to-exploit-ie-elevation-policies/)
- 2015.07 [pediy] [[原创]今天写了个apc注入dll代码，可以当工具使用](https://bbs.pediy.com/thread-202078.htm)
- 2015.05 [WarrantyVoider] [DAI dll injection test - successfull](https://www.youtube.com/watch?v=hYU_W1gRtZE)
- 2015.04 [securestate] [DLL Injection Part 2: CreateRemoteThread and More](https://warroom.securestate.com/dll-injection-part-2-createremotethread-and-more/)
- 2015.04 [securestate] [DLL Injection Part 2: CreateRemoteThread and More](https://warroom.rsmus.com/dll-injection-part-2-createremotethread-and-more/)
- 2015.03 [securestate] [DLL Injection Part 1: SetWindowsHookEx](https://warroom.securestate.com/dll-injection-part-1-setwindowshookex/)
- 2015.03 [securestate] [DLL Injection Part 1: SetWindowsHookEx](https://warroom.rsmus.com/dll-injection-part-1-setwindowshookex/)
- 2015.03 [securestate] [DLL Injection Part 0: Understanding DLL Usage](https://warroom.securestate.com/dll-injection-part-0-understanding-dll-usage/)
- 2015.03 [securestate] [DLL Injection Part 0: Understanding DLL Usage](https://warroom.rsmus.com/dll-injection-part-0-understanding-dll-usage/)
- 2014.04 [pediy] [[分享]重读老文章：DLL注入的又一个梗](https://bbs.pediy.com/thread-186778.htm)
- 2014.04 [pediy] [[分享]老文章系列：APC注入DLL的梗](https://bbs.pediy.com/thread-186631.htm)
- 2014.01 [osandamalith] [Ophcrack Path Subversion Arbitrary DLL Injection Code Execution](https://osandamalith.com/2014/01/18/ophcrack-path-subversion-arbitrary-dll-injection-code-execution/)
- 2013.09 [debasish] [Inline API Hooking using DLL Injection](http://www.debasish.in/2013/09/inline-api-hooking-using-dll-injection.html)
- 2013.09 [freebuf] [对国内各种安全卫士产品的一种通用虐杀、DLL注入、本地代码执行的方法](http://www.freebuf.com/vuls/12597.html)
- 2013.06 [msreverseengineering] [What is DLL Injection and How is it used for Reverse Engineering?](http://www.msreverseengineering.com/blog/2014/6/23/what-is-dll-injection-and-how-is-it-used-for-reverse-engineering)
- 2013.05 [pediy] [[原创]关于dll注入方法](https://bbs.pediy.com/thread-171190.htm)
- 2013.03 [pediy] [[原创]DLL注入之远线程方式](https://bbs.pediy.com/thread-167175.htm)
- 2013.02 [pediy] [[原创]易语言静态编译的DLL注入到其他语言写的EXE中后的完美卸载](https://bbs.pediy.com/thread-162742.htm)
- 2012.10 [octopuslabs] [DLL Injection – A Splash Bitmap](http://octopuslabs.io/legend/blog/archives/1785)
- 2012.09 [debasish] [KeyLogging through DLL Injection[The Simplest Way]](http://www.debasish.in/2012/09/keylogging-through-dll-injectionthe.html)
- 2012.09 [volatility] [MoVP 2.1 Atoms (The New Mutex), Classes and DLL Injection](https://volatility-labs.blogspot.com/2012/09/movp-21-atoms-new-mutex-classes-and-dll.html)
- 2012.06 [freebuf] [[更新]一款非常不错的dll注入器 – RemoteDLL V2](http://www.freebuf.com/sectool/3970.html)
- 2011.11 [pediy] [[原创]滴水逆向学习收获1-双进程无dll注入（1楼，17楼，21楼，27楼，30楼，33楼）[已更新至33楼]](https://bbs.pediy.com/thread-142554.htm)
- 2011.06 [pediy] [[原创]利用钩子函数来注入DLL的一个具体应用：点击桌面不同图标，播放相应音符](https://bbs.pediy.com/thread-136144.htm)
- 2011.01 [pediy] [[原创]进程管理dll注入综合小工具[附源码]](https://bbs.pediy.com/thread-127924.htm)
- 2010.12 [pediy] [[原创]Ring3下劫持CreateProcess注入dll](https://bbs.pediy.com/thread-126226.htm)
- 2010.01 [pediy] [[原创]dll注入辅助工具[带源码]](https://bbs.pediy.com/thread-104642.htm)
- 2009.08 [pediy] [[原创]最简单的DLL注入](https://bbs.pediy.com/thread-94799.htm)
- 2009.07 [pediy] [[原创]注入DLL之ANSI版--改自Jeffrey的《windows核心编程》](https://bbs.pediy.com/thread-92631.htm)
- 2008.11 [pediy] [[原创]N种内核注入DLL的思路及实现](https://bbs.pediy.com/thread-75887.htm)
- 2007.12 [pediy] [[原创]QueueUserApc实现DLL注入](https://bbs.pediy.com/thread-56071.htm)
- 2006.11 [pediy] [再谈Dll注入NetTransport 2.25.337[原创]](https://bbs.pediy.com/thread-35556.htm)
- 2006.10 [pediy] [[原创]Dll注入NetTransport 2.25.337](https://bbs.pediy.com/thread-34096.htm)
- 2005.08 [pediy] [ApiHook，InjectDll 单元及其应用 [Delphi代码]](https://bbs.pediy.com/thread-16088.htm)




### <a id="f39e40e340f61ae168b67424baac5cc6"></a>DLL Hijack


#### <a id="c9cdcc6f4acbeda6c8ac8f4a1ba1ea6b"></a>Tools


- [**431**Star][7m] [Pascal] [mojtabatajik/robber](https://github.com/mojtabatajik/robber) Robber is open source tool for finding executables prone to DLL hijacking
- [**299**Star][11m] [C++] [anhkgg/superdllhijack](https://github.com/anhkgg/superdllhijack) A general DLL hijack technology, don't need to manually export the same function interface of the DLL, so easy! 
- [**175**Star][5m] [C++] [strivexjun/aheadlib-x86-x64](https://github.com/strivexjun/aheadlib-x86-x64) hijack dll Source Code Generator. support x86/x64
- [**126**Star][1y] [PS] [itm4n/ikeext-privesc](https://github.com/itm4n/ikeext-privesc) Windows IKEEXT DLL Hijacking Exploit Tool
- [**113**Star][5y] [C++] [adamkramer/dll_hijack_detect](https://github.com/adamkramer/dll_hijack_detect) Detects DLL hijacking in running processes on Windows systems
- [**93**Star][10m] [C++] [cyberark/dllspy](https://github.com/cyberark/dllspy) DLL Hijacking Detection Tool
- [**79**Star][1y] [C#] [djhohnstein/.net-profiler-dll-hijack](https://github.com/djhohnstein/.net-profiler-dll-hijack) Implementation of the .NET Profiler DLL hijack in C#
- [**68**Star][18d] [C++] [itm4n/cdpsvcdllhijacking](https://github.com/itm4n/cdpsvcdllhijacking) Windows 10 CDPSvc DLL Hijacking - From LOCAL SERVICE to SYSTEM
- [**49**Star][3y] [C++] [enigma0x3/messagebox](https://github.com/enigma0x3/messagebox) PoC dlls for Task Scheduler COM Hijacking
- [**44**Star][5y] [JS] [rapid7/dllhijackauditkit](https://github.com/rapid7/dllhijackauditkit) This toolkit detects applications vulnerable to DLL hijacking (released in 2010)
- [**32**Star][12m] [Assembly] [zeffy/prxdll_templates](https://github.com/zeffy/prxdll_templates) Thread-safe and deadlock free template projects for hijacking various Windows system DLLs
- [**28**Star][24d] [C] [myfreeer/qbittorrent-portable](https://github.com/myfreeer/qbittorrent-portable) dll-hijack based qbittorrent portable plugin
- [**24**Star][4y] [C] [fortiguard-lion/anti-dll-hijacking](https://github.com/fortiguard-lion/anti-dll-hijacking) 
- [**23**Star][9m] [C] [djhohnstein/wlbsctrl_poc](https://github.com/djhohnstein/wlbsctrl_poc) C++ POC code for the wlbsctrl.dll hijack on IKEEXT
- [**18**Star][9m] [C#] [djhohnstein/tsmsisrv_poc](https://github.com/djhohnstein/tsmsisrv_poc) C# POC code for the SessionEnv dll hijack by utilizing called functions of TSMSISrv.dll
- [**12**Star][2y] [C++] [guanginuestc/dll-hijacking](https://github.com/guanginuestc/dll-hijacking) 
- [**11**Star][4m] [C] [myfreeer/vscode-portable](https://github.com/myfreeer/vscode-portable) make visual studio code portable with dll-hijack
- [**2**Star][1y] [kernelm0de/cve-2018-8090](https://github.com/kernelm0de/cve-2018-8090) DLL Hijacking in Quickheal Total Security/ Internet Security/ Antivirus Pro (Installers)


#### <a id="01e95333e07439ac8326253aa8950b4f"></a>Post


- 2019.06 [4hou] [戴尔预装的SupportAssist组件存在DLL劫持漏洞，全球超过1亿台设备面临网络攻击风险](https://www.4hou.com/vulnerable/18764.html)
- 2019.05 [4hou] [《Lateral Movement — SCM and DLL Hijacking Primer》的利用扩展](https://www.4hou.com/technology/18008.html)
- 2019.04 [3gstudent] [《Lateral Movement — SCM and DLL Hijacking Primer》的利用扩展](https://3gstudent.github.io/3gstudent.github.io/Lateral-Movement-SCM-and-DLL-Hijacking-Primer-%E7%9A%84%E5%88%A9%E7%94%A8%E6%89%A9%E5%B1%95/)
- 2019.04 [3gstudent] [《Lateral Movement — SCM and DLL Hijacking Primer》的利用扩展](https://3gstudent.github.io/3gstudent.github.io/Lateral-Movement-SCM-and-DLL-Hijacking-Primer-%E7%9A%84%E5%88%A9%E7%94%A8%E6%89%A9%E5%B1%95/)
- 2019.04 [specterops] [Lateral Movement — SCM and Dll Hijacking Primer](https://medium.com/p/d2f61e8ab992)
- 2019.01 [sans] [DLL Hijacking Like a Boss!](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1493862085.pdf)
- 2018.11 [t00ls] [一种通用DLL劫持技术研究](https://www.t00ls.net/articles-48756.html)
- 2018.11 [pediy] [[原创]一种通用DLL劫持技术研究](https://bbs.pediy.com/thread-248050.htm)
- 2018.09 [DoktorCranium] [Understanding how DLL Hijacking works](https://www.youtube.com/watch?v=XADSrZEJdXY)
- 2018.09 [astr0baby] [Understanding how DLL Hijacking works](https://astr0baby.wordpress.com/2018/09/08/understanding-how-dll-hijacking-works/)
- 2018.08 [parsiya] [DVTA - Part 5 - Client-side Storage and DLL Hijacking](https://parsiya.net/blog/2018-08-25-dvta-part-5-client-side-storage-and-dll-hijacking/)
- 2018.08 [parsiya] [DVTA - Part 5 - Client-side Storage and DLL Hijacking](https://parsiya.net/blog/2018-08-25-dvta---part-5---client-side-storage-and-dll-hijacking/)
- 2018.06 [cybereason] [Attackers incriminate a signed Oracle process for DLL hijacking, running Mimikatz](https://www.cybereason.com/blog/oracle-mimikatz-dll-hijacking)
- 2018.05 [360] [独辟蹊径：如何通过URL文件实现DLL劫持](https://www.anquanke.com/post/id/145715/)
- 2018.05 [insert] [DLL Hijacking via URL files](https://insert-script.blogspot.com/2018/05/dll-hijacking-via-url-files.html)
- 2017.10 [cybereason] [Siofra, a free tool built by Cybereason researcher, exposes DLL hijacking vulnerabilities in Windows programs](https://www.cybereason.com/blog/blog-siofra-free-tool-exposes-dll-hijacking-vulnerabilities-in-windows)
- 2017.08 [securiteam] [SSD Advisory – Dashlane DLL Hijacking](https://blogs.securiteam.com/index.php/archives/3357)
- 2017.05 [4hou] [Windows 下的 7 种 DLL 劫持技术](http://www.4hou.com/technology/4945.html)
- 2017.05 [pediy] [[原创]让代码飞出一段钢琴曲（freepiano小助手）（全局键盘钩子+dll劫持）+有码](https://bbs.pediy.com/thread-217330.htm)
- 2017.03 [pentestlab] [DLL Hijacking](https://pentestlab.blog/2017/03/27/dll-hijacking/)
- 2017.03 [pediy] [[原创]不用导出任何函数的DLL劫持注入,完美!](https://bbs.pediy.com/thread-216348.htm)
- 2017.03 [sophos] [Q&A: Wikileaks, the CIA, ‘Fine Dining’ and DLL hijacks](https://news.sophos.com/en-us/2017/03/10/qa-wikileaks-the-cia-fine-dining-and-dll-hijacks/)
- 2017.03 [opera] [DLL hijacking and the Opera browser](http://blogs.opera.com/security/2017/03/dll-hijacking-opera-browser/)
- 2017.02 [4hou] [如何利用 DLL hijack 轻松绕过AMSI？](http://www.4hou.com/technology/3179.html)
- 2016.12 [4hou] [DLL劫持漏洞自动化识别工具Rattler测试](http://www.4hou.com/technology/1156.html)
- 2016.12 [3gstudent] [DLL劫持漏洞自动化识别工具Rattler测试](https://3gstudent.github.io/3gstudent.github.io/DLL%E5%8A%AB%E6%8C%81%E6%BC%8F%E6%B4%9E%E8%87%AA%E5%8A%A8%E5%8C%96%E8%AF%86%E5%88%AB%E5%B7%A5%E5%85%B7Rattler%E6%B5%8B%E8%AF%95/)
- 2016.12 [3gstudent] [DLL劫持漏洞自动化识别工具Rattler测试](https://3gstudent.github.io/3gstudent.github.io/DLL%E5%8A%AB%E6%8C%81%E6%BC%8F%E6%B4%9E%E8%87%AA%E5%8A%A8%E5%8C%96%E8%AF%86%E5%88%AB%E5%B7%A5%E5%85%B7Rattler%E6%B5%8B%E8%AF%95/)
- 2016.10 [trustfoundry] [What is DLL Hijacking?](https://trustfoundry.net/what-is-dll-hijacking/)
- 2016.08 [hackingarticles] [Hack Remote Windows PC using Office OLE Multiple DLL Hijack Vulnerabilities](http://www.hackingarticles.in/hack-remote-windows-pc-using-office-ole-multiple-dll-hijack-vulnerabilities/)
- 2016.05 [pediy] [[原创]DLL劫持生成器 源码开放（纯WINDOWS SDK）+ 实例分析](https://bbs.pediy.com/thread-210530.htm)
- 2016.03 [] [深入解析DLL劫持漏洞](http://www.91ri.org/15471.html)
- 2016.01 [360] [DLL劫持攻击指南](https://www.anquanke.com/post/id/83229/)
- 2016.01 [gracefulsecurity] [PrivEsc: DLL Hijacking](https://www.gracefulsecurity.com/privesc-dll-hijacking/)
- 2015.12 [textslashplain] [DLL Hijacking Just Won’t Die](https://textslashplain.com/2015/12/18/dll-hijacking-just-wont-die/)
- 2015.12 [fortinet] [A Crash Course In DLL Hijacking](https://www.fortinet.com/blog/industry-trends/a-crash-course-in-dll-hijacking.html)
- 2015.09 [freebuf] [老树开新花：DLL劫持漏洞新玩法](http://www.freebuf.com/articles/78807.html)
- 2015.09 [trendmicro] [Shadow Force Uses DLL Hijacking, Targets South Korean Company](https://blog.trendmicro.com/trendlabs-security-intelligence/shadow-force-uses-dll-hijacking-targets-south-korean-company/)
- 2015.07 [securiteam] [SSD Advisory – Internet Explorer 11 Rendering Engine DLL Hijacking](https://blogs.securiteam.com/index.php/archives/2530)
- 2015.05 [securify] [Exploiting the Xamarin.Android DLL hijack vulnerability](https://securify.nl/en/blog/SFY20150502/exploiting-the-xamarin_android-dll-hijack-vulnerability.html)
- 2015.03 [sans] [Detecting DLL Hijacking on Windows](https://digital-forensics.sans.org/blog/2015/03/25/detecting-dll-hijacking-on-windows)
- 2015.01 [welivesecurity] [Corel vulnerabilities could allow hackers in via DLL hijacking](https://www.welivesecurity.com/2015/01/14/corel-vulnerabilities-allow-hackers-via-dll-hijacking/)
- 2013.08 [DoktorCranium] [Dll Hijacking Reloaded](https://www.youtube.com/watch?v=DQPgBNNtUh0)
- 2013.06 [pediy] [[原创]VEH-硬件断点+dll劫持内存补丁](https://bbs.pediy.com/thread-174263.htm)
- 2013.06 [tencent] [DLL劫持漏洞解析](https://security.tencent.com/index.php/blog/msg/20)
- 2013.01 [freebuf] [Dll Hijack检测工具—Dll Hijack Auditor](http://www.freebuf.com/sectool/6966.html)
- 2012.12 [antiy] [DLL劫持恶意代码对主动防御技术的挑战](http://antiy.com/response/challenge-of-dll-hijacking-malware-against-active-defense-tech.html)
- 2012.11 [nobunkum] [COM Hijacking, or DLL Hijacking come back](http://nobunkum.ru/analytics/en-com-hijacking)
- 2012.02 [pediy] [[原创]lpk.dll劫持病毒分析[附查杀工具及源码]](https://bbs.pediy.com/thread-147062.htm)
- 2011.08 [greyhathacker] [McAfee VirusScan Enterprise DLL hijacking autostart entry point](http://www.greyhathacker.net/?p=354)
- 2010.09 [sans] [Digital Forensics Practitioners Take Note: MS DLL Hijacking](https://digital-forensics.sans.org/blog/2010/09/08/digital-forensics-practitioners-note-ms-dll-hijacking)
- 2010.09 [pediy] [[原创]纯汇编USP10.DLL劫持](https://bbs.pediy.com/thread-119945.htm)
- 2010.08 [sans] [DLL hijacking - what are you doing ?](https://isc.sans.edu/forums/diary/DLL+hijacking+what+are+you+doing/9460/)
- 2010.08 [dankaminsky] [Regarding DLL Hijacking](https://dankaminsky.com/2010/08/27/regarding-dll-hijacking/)
- 2010.08 [corelan] [DLL Hijacking (KB 2269637) – the unofficial list](https://www.corelan.be/index.php/2010/08/25/dll-hijacking-kb-2269637-the-unofficial-list/)
- 2010.08 [trustedsec] [SET v0.6.1 – Metasploit DLL Hijack Demo](https://www.trustedsec.com/2010/08/set-v0-6-1-metasploit-dll-hijack-demo/)
- 2010.08 [rapid7] [Exploiting DLL Hijacking Flaws](https://blog.rapid7.com/2010/08/22/exploiting-dll-hijacking-flaws/)
- 2010.08 [sans] [DLL hijacking vulnerabilities](https://isc.sans.edu/forums/diary/DLL+hijacking+vulnerabilities/9445/)
- 2009.11 [pediy] [usp10.dll木马逆向之dll劫持](https://bbs.pediy.com/thread-101412.htm)
- 2009.01 [pediy] [[原创]DLL劫持USER32](https://bbs.pediy.com/thread-80477.htm)
- 2008.03 [pediy] [[样章1]《加密与解密(第三版)》--18.2.4 DLL劫持技术（内存补丁技术）](https://bbs.pediy.com/thread-60849.htm)






***


## <a id="40fd1488e4a26ebf908f44fdcedd9675"></a>UAC


### <a id="02517eda8c2519c564a19219e97d6237"></a>Tools


- [**2355**Star][11d] [C] [hfiref0x/uacme](https://github.com/hfiref0x/uacme) Defeating Windows User Account Control
- [**2307**Star][1m] [PS] [k8gege/k8tools](https://github.com/k8gege/k8tools) K8工具合集(内网渗透/提权工具/远程溢出/漏洞利用/扫描工具/密码破解/免杀工具/Exploit/APT/0day/Shellcode/Payload/priviledge/BypassUAC/OverFlow/WebShell/PenTest) Web GetShell Exploit(Struts2/Zimbra/Weblogic/Tomcat/Apache/Jboss/DotNetNuke/zabbix)
- [**1688**Star][3m] [Py] [rootm0s/winpwnage](https://github.com/rootm0s/winpwnage) UAC bypass, Elevate, Persistence and Execution methods
- [**226**Star][2y] [fuzzysecurity/defcon25](https://github.com/fuzzysecurity/defcon25) UAC 0day, all day!
- [**143**Star][2y] [C++] [hjc4869/uacbypass](https://github.com/hjc4869/uacbypass) A demo to bypass windows 10 default UAC configuration using IFileOperation and dll hijacking
- [**121**Star][9m] [C] [dimopouloselias/alpc-mmc-uac-bypass](https://github.com/dimopouloselias/alpc-mmc-uac-bypass) UAC Bypass with mmc via alpc
- [**104**Star][3y] [C++] [cn33liz/tpminituacbypass](https://github.com/cn33liz/tpminituacbypass) Bypassing User Account Control (UAC) using TpmInit.exe
- [**86**Star][4y] [Visual Basic .NET] [vozzie/uacscript](https://github.com/vozzie/uacscript) Windows 7 UAC Bypass Vulnerability in the Windows Script Host
- [**79**Star][3y] [PS] [winscripting/uac-bypass](https://github.com/winscripting/uac-bypass) 
- [**75**Star][8m] [Go] [0x9ef/golang-uacbypasser](https://github.com/0x9ef/golang-uacbypasser) UAC bypass techniques implemented and written in Go
- [**75**Star][3m] [Py] [zenix-blurryface/sneakyexe](https://github.com/zenix-blurryface/sneakyexe) Embedding a "UAC-Bypassing" function into your custom payload
- [**67**Star][2y] [C++] [3gstudent/use-com-objects-to-bypass-uac](https://github.com/3gstudent/use-com-objects-to-bypass-uac) 
- [**62**Star][9m] [Ruby] [gushmazuko/winbypass](https://github.com/gushmazuko/winbypass) Windows UAC Bypass
- [**59**Star][5y] [C++] [malwaretech/uacelevator](https://github.com/malwaretech/uacelevator) Passive UAC elevation using dll infection
- [**53**Star][2y] [fsecurelabs/defcon25_uac_workshop](https://github.com/FSecureLABS/defcon25_uac_workshop) UAC 0Day all day!
- [**42**Star][10m] [C++] [bytecode77/slui-file-handler-hijack-privilege-escalation](https://github.com/bytecode77/slui-file-handler-hijack-privilege-escalation) 利用 slui.exe 的文件 Handler 劫持漏洞实现 UAC 绕过和本地提权
- [**40**Star][4m] [C#] [nyan-x-cat/uac-escaper](https://github.com/nyan-x-cat/uac-escaper) Escalation / Bypass Windows UAC
- [**36**Star][3y] [C++] [cn33liz/tpminituacanniversarybypass](https://github.com/cn33liz/tpminituacanniversarybypass) Bypassing User Account Control (UAC) using TpmInit.exe
- [**36**Star][2y] [fuzzysecurity/defcon-beijing-uac](https://github.com/fuzzysecurity/defcon-beijing-uac) Slide deck for DefCon Beijing
- [**29**Star][1y] [C] [dro/uac-launchinf-poc](https://github.com/dro/uac-launchinf-poc) Windows 10 UAC bypass PoC using LaunchInfSection
- [**27**Star][1y] [C++] [alphaseclab/bypass-uac](https://github.com/alphaseclab/bypass-uac) 
- [**17**Star][1y] [C] [advancedhacker101/bypass-uac](https://github.com/advancedhacker101/bypass-uac) Small utility written in c++ to bypass windows UAC prompt
- [**14**Star][2y] [PS] [bartblaze/dccwuacbypass](https://github.com/bartblaze/dccwuacbypass) PowerShell script to bypass UAC using DCCW
- [**12**Star][3m] [Py] [rootm0s/uub](https://github.com/rootm0s/uub) UIAccess UAC Bypass using token duplication and keyboard events
- [**10**Star][1y] [125k/uac_bypass_hid](https://github.com/125K/UAC_Bypass_HID) This payload bypasses the UAC
- [**10**Star][1y] [125k/uac_bypass_hid](https://github.com/125k/uac_bypass_hid) This payload bypasses the UAC
- [**9**Star][2m] [C++] [pedro-javierf/twicexploit](https://github.com/pedro-javierf/twicexploit) Proof of concept open source implementation of an UAC bypass exploit, based in 2 windows failures.
- [**6**Star][3y] [Batchfile] [caledoniaproject/sdclt-win10-uacbypass](https://github.com/caledoniaproject/sdclt-win10-uacbypass) 
- [**3**Star][2y] [Batchfile] [genome21/bypassuac](https://github.com/genome21/bypassuac) Program bypasses the UAC prompt for Admin privileges when running a program.


### <a id="90d7d5feb7fd506dc8fd6ee0d7e98285"></a>Post


- 2019.11 [4hou] [CVE-2019-1388： Windows UAC权限提升漏洞](https://www.4hou.com/info/news/21710.html)
- 2019.10 [freebuf] [UAC绕过初探](https://www.freebuf.com/articles/system/216337.html)
- 2019.09 [4sysops] [Security options in Windows Server 2016: Accounts and UAC](https://4sysops.com/archives/security-options-in-windows-server-2016-accounts-and-uac/)
- 2019.08 [freebuf] [SneakyEXE：一款嵌入式UAC绕过工具](https://www.freebuf.com/sectool/209097.html)
- 2019.04 [markmotig] [Brute Forcing Admin Passwords with UAC](https://medium.com/p/e711c551ad7e)
- 2019.03 [4hou] [通过模拟可信目录绕过UAC的利用分析](https://www.4hou.com/technology/16713.html)
- 2019.03 [aliyun] [如何滥用Access Tokens UIAccess绕过UAC](https://xz.aliyun.com/t/4126)
- 2019.02 [3gstudent] [通过模拟可信目录绕过UAC的利用分析](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87%E6%A8%A1%E6%8B%9F%E5%8F%AF%E4%BF%A1%E7%9B%AE%E5%BD%95%E7%BB%95%E8%BF%87UAC%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)
- 2019.02 [3gstudent] [通过模拟可信目录绕过UAC的利用分析](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87%E6%A8%A1%E6%8B%9F%E5%8F%AF%E4%BF%A1%E7%9B%AE%E5%BD%95%E7%BB%95%E8%BF%87UAC%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)
- 2019.02 [sans] [UAC is not all that bad really](https://isc.sans.edu/forums/diary/UAC+is+not+all+that+bad+really/24620/)
- 2019.01 [fuzzysecurity] [Anatomy of UAC Attacks](http://fuzzysecurity.com/tutorials/27.html)
- 2019.01 [sevagas] [Yet another sdclt UAC bypass](https://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass)
- 2018.11 [4hou] [利用metasploit绕过UAC的5种方式](http://www.4hou.com/system/13707.html)
- 2018.11 [tenable] [UAC Bypass by Mocking Trusted Directories](https://medium.com/p/24a96675f6e)
- 2018.10 [0x000x00] [How to bypass UAC in newer Windows versions](https://0x00-0x00.github.io/research/2018/10/31/How-to-bypass-UAC-in-newer-Windows-versions.html)
- 2018.10 [tyranidslair] [Farewell to the Token Stealing UAC Bypass](https://tyranidslair.blogspot.com/2018/10/farewell-to-token-stealing-uac-bypass.html)
- 2018.10 [freebuf] [使用Metasploit绕过UAC的多种方法](http://www.freebuf.com/articles/system/185311.html)
- 2018.09 [freebuf] [一种绕过UAC的技术介绍](http://www.freebuf.com/articles/system/184140.html)
- 2018.09 [hackingarticles] [Multiple Ways to Bypass UAC using Metasploit](http://www.hackingarticles.in/multiple-ways-to-bypass-uac-using-metasploit/)
- 2018.09 [hexacorn] [A bit of a qUACkery – how to elevate… w/o doing a single thing ;)](http://www.hexacorn.com/blog/2018/09/07/a-bit-of-a-quackery-how-to-elevate-w-o-doing-a-single-thing/)
- 2018.05 [4hou] [如何利用注册表修改技术绕过UAC限制](http://www.4hou.com/web/11849.html)
- 2018.05 [360] [利用注册表键值绕过UAC实现提权](https://www.anquanke.com/post/id/145538/)
- 2018.05 [3gstudent] [通过COM组件IARPUninstallStringLauncher绕过UAC](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87COM%E7%BB%84%E4%BB%B6IARPUninstallStringLauncher%E7%BB%95%E8%BF%87UAC/)
- 2018.05 [3gstudent] [通过COM组件IARPUninstallStringLauncher绕过UAC](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87COM%E7%BB%84%E4%BB%B6IARPUninstallStringLauncher%E7%BB%95%E8%BF%87UAC/)
- 2018.03 [rehmann] [Edimax EW-7811Un, EW-7611ULB, EW-7722UTn, EW-7811UTC, EW-7822ULC, EW7833UAC USB Wifi Drivers](https://rehmann.co/blog/edimax-ew-7811un-ew-7611ulb-ew-7722utn-ew-7811utc-ew-7822ulc-ew7833uac-usb-wifi-drivers/)
- 2018.01 [ZeroNights] [James Forshaw  - Abusing Access Tokens for UAC Bypasses](https://www.youtube.com/watch?v=UTvOfmtNVKI)
- 2017.12 [caceriadespammers] [UAC Bypass & Research con UAC-A-Mola por @pablogonzalezpe](http://www.caceriadespammers.com.ar/2017/12/uac-bypass-research-con-uac-a-mola-pablogonzalezpe.html)
- 2017.11 [hackingarticles] [7 Ways to Privilege Escalation of  Windows 7 PC (Bypass UAC)](http://www.hackingarticles.in/7-ways-to-privilege-escalation-of-windows-7-pc-bypass-uac/)
- 2017.10 [4hou] [如何利用CLR绕过UAC](http://www.4hou.com/system/7744.html)
- 2017.09 [freebuf] [如何通过.NET程序绕过UAC](http://www.freebuf.com/articles/web/148779.html)
- 2017.09 [360] [利用感染的PPT文件绕过UAC策略](https://www.anquanke.com/post/id/86903/)
- 2017.09 [360] [如何通过特权.NET应用绕过UAC](https://www.anquanke.com/post/id/86898/)
- 2017.09 [3gstudent] [Use CLR to bypass UAC](https://3gstudent.github.io/3gstudent.github.io/Use-CLR-to-bypass-UAC/)
- 2017.09 [aliyun] [Empire中的Invoke-WScriptBypassUAC利用分析](https://xz.aliyun.com/t/1025)
- 2017.09 [4hou] [Empire中的Invoke-WScriptBypassUAC利用分析](http://www.4hou.com/technology/7636.html)
- 2017.09 [4hou] [绕过UAC系列之 SDCLT的利用](http://www.4hou.com/technology/5704.html)
- 2017.09 [3gstudent] [Empire中的Invoke-WScriptBypassUAC利用分析](https://3gstudent.github.io/3gstudent.github.io/Empire%E4%B8%AD%E7%9A%84Invoke-WScriptBypassUAC%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)
- 2017.09 [3gstudent] [Empire中的Invoke-WScriptBypassUAC利用分析](https://3gstudent.github.io/3gstudent.github.io/Empire%E4%B8%AD%E7%9A%84Invoke-WScriptBypassUAC%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/)
- 2017.09 [fortinet] [PowerPoint File Armed with CVE-2017-0199 and UAC Bypass](https://www.fortinet.com/blog/threat-research/powerpoint-file-armed-with-cve-2017-0199-and-uac-bypass.html)
- 2017.08 [360] [利用CMSTP.exe实现UAC Bypass和加载DLL](https://www.anquanke.com/post/id/86685/)
- 2017.08 [secist] [添加bypassuac_comhijack.rb模块绕过UAC](http://www.secist.com/archives/4136.html)
- 2017.08 [hackingarticles] [Bypass UAC in Windows 10 using bypass_comhijack Exploit](http://www.hackingarticles.in/bypass-uac-windows-10-using-bypass_comhijack-exploit/)
- 2017.06 [bartblaze] [Display Color Calibration tool DCCW and UAC bypasses](https://bartblaze.blogspot.com/2017/06/display-color-calibration-tool-dccw-and.html)
- 2017.06 [hackingarticles] [Bypass UAC Protection of Remote Windows 10 PC (Via FodHelper Registry Key)](http://www.hackingarticles.in/bypass-uac-protection-remote-windows-10-pc-via-fodhelper-registry-key/)
- 2017.06 [pentestlab] [UAC Bypass – SDCLT](https://pentestlab.blog/2017/06/09/uac-bypass-sdclt/)
- 2017.06 [4hou] [利用fodhelper.exe实现无文件Bypass UAC](http://www.4hou.com/technology/5233.html)
- 2017.06 [pentestlab] [UAC Bypass – Fodhelper](https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/)
- 2017.05 [4hou] [如何使用SilentCleanup绕过UAC？](http://www.4hou.com/technology/4834.html)
- 2017.05 [3gstudent] [Study Notes of using SilentCleanup to bypass UAC](https://3gstudent.github.io/3gstudent.github.io/Study-Notes-of-using-SilentCleanup-to-bypass-UAC/)
- 2017.05 [winscripting] [First entry: Welcome and fileless UAC bypass](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
- 2017.05 [4hou] [如何使用任务计划程序绕过UAC？](http://www.4hou.com/technology/4583.html)
- 2017.05 [moxia] [如何利用sdclt磁盘备份工具绕过UAC](http://www.moxia.org/Blog.php/index.php/archives/246)
- 2017.05 [360] [看我如何利用事件查看器绕过UAC（用户帐户控制）](https://www.anquanke.com/post/id/86006/)
- 2017.05 [pentestlab] [UAC Bypass – Task Scheduler](https://pentestlab.blog/2017/05/03/uac-bypass-task-scheduler/)
- 2017.05 [pentestlab] [UAC Bypass – Event Viewer](https://pentestlab.blog/2017/05/02/uac-bypass-event-viewer/)
- 2017.04 [4hou] [如何利用sdclt.exe绕过UAC？](http://www.4hou.com/technology/4221.html)
- 2017.03 [360] [看我如何利用sdclt.exe实现无文件绕过UAC](https://www.anquanke.com/post/id/85772/)
- 2017.03 [3gstudent] [Study Notes of using sdclt.exe to bypass UAC](https://3gstudent.github.io/3gstudent.github.io/Study-Notes-of-using-sdclt.exe-to-bypass-UAC/)
- 2017.03 [freebuf] [如何利用sdclt磁盘备份工具绕过UAC](http://www.freebuf.com/sectool/129579.html)
- 2017.03 [win] [Prevent interactive logon of Local Admins - Only allow UAC elevation](http://blog.win-fu.com/2017/03/prevent-interactive-logon-of-local.html)
- 2017.03 [enigma0x3] [“Fileless” UAC Bypass using sdclt.exe](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)
- 2017.03 [enigma0x3] [Bypassing UAC using App Paths](https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/)
- 2017.03 [sans] [Another example of maldoc string obfuscation, with extra bonus: UAC bypass](https://isc.sans.edu/forums/diary/Another+example+of+maldoc+string+obfuscation+with+extra+bonus+UAC+bypass/22153/)
- 2017.02 [decoder] [Bypassing UAC from a remote powershell and escalating to “SYSTEM”](https://decoder.cloud/2017/02/03/bypassing-uac-from-a-remote-powershell-and-escalting-to-system/)
- 2017.01 [sans] [Malicious Office files using fileless UAC bypass to drop KEYBASE malware](https://isc.sans.edu/forums/diary/Malicious+Office+files+using+fileless+UAC+bypass+to+drop+KEYBASE+malware/22011/)
- 2017.01 [flashpoint] [Dridex Banking Trojan Returns, Leverages New UAC Bypass Method](https://www.flashpoint-intel.com/blog/cybercrime/blog-dridex-banking-trojan-returns/)
- 2016.12 [360] [Fareit木马新变种：恶意宏绕过UAC提权新方法](https://www.anquanke.com/post/id/85174/)
- 2016.12 [fortinet] [Malicious Macro Bypasses UAC to Elevate Privilege for Fareit Malware](https://www.fortinet.com/blog/threat-research/malicious-macro-bypasses-uac-to-elevate-privilege-for-fareit-malware.html)
- 2016.12 [sans] [UAC Bypass in JScript Dropper](https://isc.sans.edu/forums/diary/UAC+Bypass+in+JScript+Dropper/21813/)
- 2016.12 [mdsec] [Eventvwr File-less UAC Bypass CNA](https://www.mdsec.co.uk/2016/12/cna-eventvwr-uac-bypass/)
- 2016.11 [venus] [UAC 攻击剖析](https://paper.seebug.org/127/)
- 2016.11 [hasherezade] [DEMO: A malware bypassing UAC set to max (Windows 7 32bit)](https://www.youtube.com/watch?v=lEFXBKdfzB8)
- 2016.10 [freebuf] [巧用COM接口IARPUninstallStringLauncher绕过UAC](http://www.freebuf.com/articles/system/116611.html)
- 2016.09 [freebuf] [动手打造Bypass UAC自动化测试小工具，可绕过最新版Win10](http://www.freebuf.com/sectool/114592.html)
- 2016.09 [360] [Bypass-UAC-帮你绕过Windows的用户账户控制](https://www.anquanke.com/post/id/84582/)
- 2016.09 [freebuf] [Bypass UAC的一个实例分析](http://www.freebuf.com/articles/system/112823.html)
- 2016.08 [hackingarticles] [Hack Admin Access of Remote Windows 10 PC using TpmInit UACBypass](http://www.hackingarticles.in/hack-admin-access-remote-windows-10-pc-using-tpminituacbypass/)
- 2016.08 [3gstudent] [Study Notes Weekly No.1(Monitor WMI & ExportsToC++ & Use DiskCleanup bypass UAC)](https://3gstudent.github.io/3gstudent.github.io/Study-Notes-Weekly-No.1(Monitor-WMI_ExportsToC++_Use-DiskCleanup-bypass-UAC)/)
- 2016.08 [3gstudent] [Study Notes Weekly No.1(Monitor WMI & ExportsToC++ & Use DiskCleanup bypass UAC)](https://3gstudent.github.io/3gstudent.github.io/Study-Notes-Weekly-No.1(Monitor-WMI_ExportsToC++_Use-DiskCleanup-bypass-UAC)/)
- 2016.08 [ensilo] [Adding UAC Bypass to the Attacker’s Tool Set](https://blog.ensilo.com/adding-uac-bypass-to-the-attackers-tool-set)
- 2016.08 [360] [使用EVENTVWR.EXE和注册表劫持实现“无文件”UAC绕过](https://www.anquanke.com/post/id/84411/)
- 2016.08 [uacmeltdown] [Bypassing User Account Control (UAC) using TpmInit.exe](http://uacmeltdown.blogspot.com/2016/08/bypassing-user-account-control-uac.html)
- 2016.08 [enigma0x3] [“Fileless” UAC Bypass Using eventvwr.exe and Registry Hijacking](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
- 2016.07 [enigma0x3] [Bypassing UAC on Windows 10 using Disk Cleanup](https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/)
- 2016.06 [DoktorCranium] [Windows 10 UAC bypass with custom Meterpreter payloads](https://www.youtube.com/watch?v=4wVr2HIJn9I)
- 2016.03 [pediy] [[原创]一个32位程序bypass win7 - win10 UAC(x86/x64)](https://bbs.pediy.com/thread-208717.htm)
- 2016.02 [freebuf] [BypassUAC：Windows系统UAC绕过利器](http://www.freebuf.com/sectool/95661.html)
- 2015.10 [evi1cg] [使用Powershell Bypass UAC](https://evi1cg.me/archives/Powershell_Bypass_UAC.html)
- 2015.10 [freebuf] [Windows用户帐户控制 (UAC) 的绕过与缓解方式](http://www.freebuf.com/articles/system/83369.html)
- 2015.10 [freebuf] [利用PowerShell绕过UAC](http://www.freebuf.com/articles/system/81286.html)
- 2015.09 [harmj0y] [Invoke-BypassUAC](http://www.harmj0y.net/blog/powershell/invoke-bypassuac/)
- 2015.09 [360] [借用UAC完成的提权思路分享](https://www.anquanke.com/post/id/82441/)
- 2015.09 [freebuf] [借用UAC完成的提权思路分享](http://www.freebuf.com/articles/others-articles/78758.html)
- 2015.09 [mikefrobbins] [Working around UAC (User Access Control) without running PowerShell elevated](http://mikefrobbins.com/2015/09/17/working-around-uac-user-access-control-without-running-powershell-elevated/)
- 2015.07 [cmu] [The Risks of Disabling the Windows UAC](https://insights.sei.cmu.edu/cert/2015/07/the-risks-of-disabling-the-windows-uac.html)
- 2015.07 [cyberarms] [System level Access and Plain Text Passwords using Bypass UAC and Mimikatz](https://cyberarms.wordpress.com/2015/07/04/system-level-access-and-plain-text-passwords-using-bypass-uac-and-mimikatz/)
- 2015.06 [grandstreamdreams] [Stop UAC screen blackouts or UAC dimming delays](http://grandstreamdreams.blogspot.com/2015/06/stop-uac-screen-blackouts-or-uac.html)
- 2015.05 [cylance] [Trick me once, ShameOnUAC](https://www.cylance.com/en_us/blog/trick-me-once-shameonuac.html)
- 2015.05 [privacy] [Adaptive Penetration Testing 4: Windows UAC Bypass](http://privacy-pc.com/articles/adaptive-penetration-testing-4-windows-uac-bypass.html)
- 2015.05 [myonlinesecurity] [Microsoft patches AppCompat UAC bypass vulnerability | Bleen](https://myonlinesecurity.co.uk/microsoft-patches-appcompat-uac-bypass-vulnerability-bleen/)
- 2015.03 [securityblog] [Invoking UAC for Privilege Escalation in batch file](http://securityblog.gr/2174/invoking-uac-for-privilege-escalation-in-batch-file/)
- 2015.01 [pediy] [[分享]win8.1 x86/x64 bypass UAC新玩法](https://bbs.pediy.com/thread-196235.htm)
- 2014.12 [greyhathacker] [Bypassing Windows User Account Control (UAC) and ways of mitigation](http://www.greyhathacker.net/?p=796)
- 2014.11 [malwaretech] [Passive UAC Elevation](https://www.malwaretech.com/2014/11/passive-uac-elevation.html)
- 2014.07 [publicintelligence] [DHS Unaccompanied Alien Children (UACs) 2014 Location of Origin Map](https://publicintelligence.net/dhs-uac-map/)
- 2014.05 [rapid7] [From the Trenches: The New Generate Dynamic Stager Auxiliary, UAC Bypass and NAT](https://blog.rapid7.com/2014/05/15/from-the-trenches-the-new-generate-dynamic-stager-auxiliary-uac-bypass-and-nat/)
- 2014.04 [pediy] [Bypass Win8.1 UAC源码 + 文档](https://bbs.pediy.com/thread-187210.htm)
- 2014.04 [pediy] [绕过win8.1 x64 UAC视频演示](https://bbs.pediy.com/thread-187024.htm)
- 2014.04 [secureidentity] [Fileservers and UAC](https://secureidentity.se/fileservers-and-uac/)
- 2014.03 [hackingarticles] [Bypass UAC Protection of Remote Windows PC in Memory Injection](http://www.hackingarticles.in/bypass-uac-protection-of-remote-windows-pc-in-memory-injection/)
- 2013.11 [myonlinesecurity] [Using a standard User Account  with high UAC settings in Windows 7](https://myonlinesecurity.co.uk/using-a-standard-user-account-with-high-uac-settings-in-windows-7/)
- 2013.10 [codeinsecurity] [Steam UAC bypass via code execution](https://codeinsecurity.wordpress.com/2013/10/11/steam-uac-bypass-via-code-execution/)
- 2013.02 [securityblog] [Enable or Disable UAC from command line](http://securityblog.gr/1644/enable-or-disable-uac-from-command-line/)
- 2011.12 [] [突破UAC，获取system提权](http://www.91ri.org/2570.html)
- 2011.05 [infosecblog] [Non-supporting of UAC](https://www.infosecblog.org/2011/05/non-supporting-of-uac/)
- 2011.02 [rebootuser] [Windows 7, UAC & Network Applications](https://www.rebootuser.com/?p=555)
- 2011.01 [trustedsec] [Windows UAC Bypass now in Metasploit!](https://www.trustedsec.com/2011/01/windows-uac-bypass-now-in-metasploit/)
- 2011.01 [trustedsec] [Bypass Windows 7 x86/x64 UAC Fully Patched – Meterpreter Module](https://www.trustedsec.com/2011/01/bypass-windows-uac/)
- 2010.06 [publicintelligence] [Naval Security Group Activity (NAVSECGRUACT) Sugar Grove](https://publicintelligence.net/naval-security-group-activity-navsecgruact-sugar-grove/)
- 2008.05 [microsoft] [UAC, an Excellent Description and Discussion by Crispin Cowan](https://cloudblogs.microsoft.com/microsoftsecure/2008/05/12/uac-an-excellent-description-and-discussion-by-crispin-cowan/)
- 2007.08 [pediy] [[原创]解决Vista下文件名中带Update不能通过UAC认证的问题。](https://bbs.pediy.com/thread-50084.htm)
- 2007.02 [microsoft] [The Value of UAC in Windows Vista](https://cloudblogs.microsoft.com/microsoftsecure/2007/02/12/the-value-of-uac-in-windows-vista/)
- 2006.06 [microsoft] [Windows Vista User Account Control (UAC)](https://cloudblogs.microsoft.com/microsoftsecure/2006/06/28/windows-vista-user-account-control-uac/)




***


## <a id="0fed6a96b28f339611e7b111b8f42c23"></a>Sysmon


### <a id="d48f038b58dc921660be221b4e302f70"></a>Tools


- [**206**Star][1y] [JS] [jpcertcc/sysmonsearch](https://github.com/jpcertcc/sysmonsearch) Investigate suspicious activity by visualizing Sysmon's event log
- [**126**Star][5m] [JS] [baronpan/sysmonhunter](https://github.com/baronpan/sysmonhunter) An easy ATT&CK-based Sysmon hunting tool, showing in Blackhat USA 2019 Arsenal
- [**19**Star][10m] [Py] [jymcheong/sysmonresources](https://github.com/jymcheong/sysmonresources) Consolidation of various resources related to Microsoft Sysmon & sample data/log
- [**17**Star][6m] [olafhartong/sysmon-configs](https://github.com/olafhartong/sysmon-configs) Various complete configs
- [**12**Star][4y] [defensivedepth/sysmon_ossec](https://github.com/defensivedepth/sysmon_ossec) OSSEC Decoder & Rulesets for Sysmon Events
- [**10**Star][6m] [sametsazak/sysmon](https://github.com/sametsazak/sysmon) Sysmon and wazuh integration with Sigma sysmon rules [updated]
- [**9**Star][1y] [PS] [davebremer/export-sysmonlogs](https://github.com/davebremer/export-sysmonlogs) 
- [**9**Star][2y] [kidcrash22/sysmon-threat-intel](https://github.com/kidcrash22/sysmon-threat-intel) 
- [**8**Star][19d] [PS] [hestat/ossec-sysmon](https://github.com/hestat/ossec-sysmon) A Ruleset to enhance detection capabilities of Ossec using Sysmon
- [**1**Star][3y] [PS] [nick-c/sysmon-installer](https://github.com/nick-c/sysmon-installer) A Sysmon Install script using the Powershell Application Deployment Toolkit
- [**1**Star][3m] [PS] [op7ic/sysmonfencer](https://github.com/op7ic/sysmonfencer) A tool designed to help in deployment and log collection for Sysmon across windows domain
- [**0**Star][2y] [PS] [stahler/sysmon_powershell](https://github.com/stahler/sysmon_powershell) Sysmon demo with PowerShell examples


### <a id="2c8cb7fdf765b9d930569f7c64042d62"></a>Post


- 2019.12 [vanimpe] [Use Sysmon DNS data for incident response](https://www.vanimpe.eu/2019/12/02/use-sysmon-dns-data-for-incident-response/)
- 2019.11 [4hou] [你不知道的威胁狩猎技巧：Windows API 与 Sysmon 事件的映射](https://www.4hou.com/system/21461.html)
- 2019.10 [HackersOnBoard] [Subverting Sysmon Application of a Formalized Security Product Evasion Methodology](https://www.youtube.com/watch?v=7eor4Gq1YXE)
- 2019.09 [sans] [Parsing Sysmon Events for IR Indicators](https://digital-forensics.sans.org/blog/2019/09/25/parsing-sysmon-events-for-ir-indicators)
- 2019.09 [blackhillsinfosec] [Getting Started With Sysmon](https://www.blackhillsinfosec.com/getting-started-with-sysmon/)
- 2019.09 [osandamalith] [Unloading the Sysmon Minifilter Driver](https://osandamalith.com/2019/09/22/unloading-the-sysmon-minifilter-driver/)
- 2019.09 [specterops] [Shhmon — Silencing Sysmon via Driver Unload](https://medium.com/p/682b5be57650)
- 2019.09 [4hou] [如何逃逸Sysmon工具对DNS的监控](https://www.4hou.com/web/18660.html)
- 2019.09 [olafhartong] [Sysmon 10.4 release](https://medium.com/p/7f7480300dff)
- 2019.09 [blackhillsinfosec] [Webcast: Windows logging, Sysmon, and ELK](https://www.blackhillsinfosec.com/webcast-windows-logging-sysmon-and-elk/)
- 2019.08 [blackhillsinfosec] [Webcast: Implementing Sysmon and Applocker](https://www.blackhillsinfosec.com/webcast-implementing-sysmon-and-applocker/)
- 2019.07 [eforensicsmag] [Using Sysmon and ETW For So Much More | By David Kennedy](https://eforensicsmag.com/using-sysmon-and-etw-for-so-much-more-by-david-kennedy/)
- 2019.06 [nosecurecode] [Sysmon in a Box](https://nosecurecode.com/2019/06/29/sysmon-in-a-box/)
- 2019.06 [binarydefense] [Using Sysmon and ETW For So Much More - Binary Defense](https://www.binarydefense.com/using-sysmon-and-etw-for-so-much-more/)
- 2019.06 [360] [如何规避Sysmon DNS监控](https://www.anquanke.com/post/id/180418/)
- 2019.06 [SecurityWeekly] [Sysmon DNS Logging, Gravwell - PSW #608](https://www.youtube.com/watch?v=e_E6F1G6b88)
- 2019.06 [xpnsec] [Evading Sysmon DNS Monitoring](https://blog.xpnsec.com/evading-sysmon-dns-monitoring/)
- 2019.06 [olafhartong] [Using Sysmon in Azure Sentinel](https://medium.com/p/883eb6ffc431)
- 2019.05 [olafhartong] [Sysmon 10.0 - New features and changes](https://medium.com/p/e82106f2e00)
- 2019.02 [specterops] [Putting Sysmon v9.0 AND/OR Grouping Logic to the Test](https://medium.com/p/c3ec27263df8)
- 2019.02 [hexacorn] [Sysmon – ideas, and gotchas](http://www.hexacorn.com/blog/2019/02/14/sysmon-ideas-and-gotchas/)
- 2019.01 [pediy] [[原创]开源逆向的部分微软的sysmon工具的源代码](https://bbs.pediy.com/thread-249225.htm)
- 2019.01 [salesforce] [Test out Bro-Sysmon](https://medium.com/p/a6fad1c8bb88)
- 2019.01 [sans] [Threat Hunting via Sysmon](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1554993664.pdf)
- 2019.01 [sans] [Threat Hunting in the Enterprise with Winlogbeat, Sysmon, and ELK](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1569872879.pdf)
- 2019.01 [sans] [Hunting with Sysmon to Unveil the Evil](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1570561576.pdf)
- 2018.12 [specterops] [Real-Time Sysmon Processing via KSQL and HELK — Part 3: Basic Use Case 🏹](https://medium.com/p/8fbf383cb54f)
- 2018.12 [specterops] [Real-Time Sysmon Processing via KSQL and HELK — Part 2: Sysmon-Join KSQL Recipe 📖](https://medium.com/p/ae47b4525212)
- 2018.11 [salesforce] [Open Sourcing Bro-Sysmon](https://medium.com/p/946295bc7da2)
- 2018.11 [securityartwork] [Evading AV with Shellter. I also have Sysmon & Wazuh III. GAME OVER](https://www.securityartwork.es/2018/11/06/evading-av-with-shellter-i-also-have-sysmon-wazuh-iii-game-over/)
- 2018.11 [specterops] [Real-Time Sysmon Processing via KSQL and HELK — Part 1: Initial Integration 🏗](https://medium.com/p/88c2b6eac839)
- 2018.11 [securityartwork] [Evading AV with Shellter. I also have Sysmon and Wazuh II](https://www.securityartwork.es/2018/11/05/evading-av-with-shellter-i-also-have-sysmon-and-wazuh-ii/)
- 2018.11 [securityartwork] [Evading AV with Shellter. I also have Sysmon and Wazuh I](https://www.securityartwork.es/2018/11/02/evading-av-with-shellter-i-also-have-sysmon-and-wazuh-i/)
- 2018.10 [4hou] [绕过Sysmon的两种方法](http://www.4hou.com/web/13984.html)
- 2018.10 [360] [如何规避Sysmon](https://www.anquanke.com/post/id/161630/)
- 2018.10 [darkoperator] [Operating Offensively Against Sysmon](https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon)
- 2018.09 [root9b] [DETECTING ADVANCED THREATS WITH SYSMON, WEF, AND ELASTICSEARCH](https://www.root9b.com/newsroom/detecting-advanced-threats-with-sysmon-wef-and-elasticsearch/)
- 2018.09 [jpcert] [Visualise Sysmon Logs and Detect Suspicious Device Behaviour -SysmonSearch-](https://blog.jpcert.or.jp/2018/09/visualise-sysmon-logs-and-detect-suspicious-device-behaviour--sysmonsearch.html)
- 2018.09 [360] [微软轻量级系统监控工具sysmon原理与实现完全分析（下篇）](https://www.anquanke.com/post/id/159820/)
- 2018.08 [360] [微软轻量级系统监控工具sysmon原理与实现完全分析（上篇）](https://www.anquanke.com/post/id/156704/)
- 2018.07 [syspanda] [Threat Hunting: Fine Tuning Sysmon & Logstash to find Malware Callbacks C&C](https://www.syspanda.com/index.php/2018/07/30/threat-hunting-fine-tuning-sysmon-logstash-find-malware-callbacks-cc/)
- 2018.07 [hexacorn] [Sysmon doing lines, part 5](http://www.hexacorn.com/blog/2018/07/21/sysmon-doing-lines-part-5/)
- 2018.07 [4hou] [如何使用Sysmon来检测利用CMSTP绕过UAC的攻击](http://www.4hou.com/technology/12577.html)
- 2018.07 [360] [使用 Sysmon 来检测利用 CMSTP 绕过 UAC 的攻击](https://www.anquanke.com/post/id/151197/)
- 2018.07 [specterops] [Categorizing and Enriching Security Events in an ELK with the Help of Sysmon and ATT&CK](https://medium.com/p/6c8e30234d34)
- 2018.07 [cyberwardog] [Categorizing and Enriching Security Events in an ELK with the Help of Sysmon and ATT&CK](https://cyberwardog.blogspot.com/2018/07/categorizing-and-enriching-security.html)
- 2018.06 [hexacorn] [Sysmon doing lines, part 3](http://www.hexacorn.com/blog/2018/06/29/sysmon-doing-lines-part-3/)
- 2018.06 [olafhartong] [Endpoint detection Superpowers on the cheap — part 3 — Sysmon Tampering](https://medium.com/p/49c2dc9bf6d9)
- 2018.03 [360] [测试你的DFIR工具： Sysmon事件日志中的安全问题剖析](https://www.anquanke.com/post/id/101681/)
- 2018.03 [danielbohannon] [Test Your DFIR Tools: Sysmon Edition](http://www.danielbohannon.com/blog-1/2018/3/19/test-your-dfir-tools-sysmon-edition)
- 2018.03 [silentbreaksecurity] [Windows Events, Sysmon and Elk…oh my! (Part 2)](https://silentbreaksecurity.com/windows-events-sysmon-elk-part-2/)
- 2018.02 [silentbreaksecurity] [Windows Events, Sysmon and Elk…oh my!](https://silentbreaksecurity.com/windows-events-sysmon-elk/)
- 2018.02 [HITCON] [[HITCON CMT 2017] R1D201 - Tracking Mimikatz by Sysmon and Elasticsearch](https://www.youtube.com/watch?v=GMe1jMRD2Pw)
- 2017.12 [hexacorn] [Sysmon doing lines, part 2](http://www.hexacorn.com/blog/2017/12/11/sysmon-doing-lines-part-2/)
- 2017.11 [darkoperator] [Operational Look at Sysinternals Sysmon 6.20 Update](https://www.darkoperator.com/blog/2017/11/24/operational-look-at-sysinternals-sysmon-620-update)
- 2017.11 [nosecurecode] [Sysmon View 1.4 released!](https://nosecurecode.blog/2017/11/25/sysmon-view-1-4-released/)
- 2017.11 [nosecurecode] [Sysmon View 1.4 released!](https://nosecurecode.com/2017/11/25/sysmon-view-1-4-released/)
- 2017.11 [cqureacademy] [Building A Perfect Sysmon Configuration File](https://cqureacademy.com/blog/server-monitoring/sysmon-configuration-file)
- 2017.11 [freebuf] [如何使用Sysmon监视工具来寻找含有宏的恶意文档](http://www.freebuf.com/sectool/152065.html)
- 2017.10 [syspanda] [Monitoring the monitor: Sysmon status](https://www.syspanda.com/index.php/2017/10/31/monitoring-monitor-sysmon-status/)
- 2017.10 [4hou] [用Sysmon进行威胁狩猎：发现具有宏的Word文档](http://www.4hou.com/web/8084.html)
- 2017.10 [n00py] [Detecting CrackMapExec (CME) with Bro, Sysmon, and Powershell logs](https://www.n00py.io/2017/10/detecting-crackmapexec-cme-with-bro-sysmon-and-powershell-logs/)
- 2017.10 [darkoperator] [Sysinternals Sysmon 6.10 Tracking of Permanent WMI Events](https://www.darkoperator.com/blog/2017/10/15/sysinternals-sysmon-610-tracking-of-permanent-wmi-events)
- 2017.10 [4hou] [如何使用Sysmon寻找带宏的Word恶意文档](http://www.4hou.com/tools/7968.html)
- 2017.10 [360] [Sysmon在威胁检测中的应用：检测启用宏的Word文档](https://www.anquanke.com/post/id/87002/)
- 2017.10 [malwarenailed] [Hunting Mimikatz Using Sysmon + ELK  - Part 2 of Series](http://malwarenailed.blogspot.com/2017/10/hunting-mimikatz-using-sysmon-elk-part.html)
- 2017.10 [syspanda] [Threat Hunting with Sysmon: Word Document with Macro](https://www.syspanda.com/index.php/2017/10/10/threat-hunting-sysmon-word-document-macro/)
- 2017.10 [hexacorn] [Sysmon doing lines](http://www.hexacorn.com/blog/2017/10/02/sysmon-doing-lines/)
- 2017.09 [malwarenailed] [Enhanced PowerShell Logging and Sysmon Logs to ElasticSearch and Visualization/Dashboarding using Kibana - Part 1 of Series](http://malwarenailed.blogspot.com/2017/09/enhanced-powershell-logging-and-sysmon.html)
- 2017.08 [n0where] [Tracking & Visualizing Sysmon Logs: Sysmon View](https://n0where.net/tracking-visualizing-sysmon-logs-sysmon-view)
- 2017.08 [nosecurecode] [Sysmon Shell – Release 1.1](https://nosecurecode.blog/2017/08/12/sysmon-shell-release-1-1/)
- 2017.08 [nosecurecode] [Sysmon Shell – Release 1.1](https://nosecurecode.com/2017/08/12/sysmon-shell-release-1-1/)
- 2017.07 [nosecurecode] [Visualizing & Tracking Sysmon events with Sysmon View 1.2](https://nosecurecode.blog/2017/07/29/visualizing-tracking-sysmon-events-with-sysmon-view-1-2/)
- 2017.07 [nosecurecode] [Visualizing & Tracking Sysmon events with Sysmon View 1.2](https://nosecurecode.com/2017/07/29/visualizing-tracking-sysmon-events-with-sysmon-view-1-2/)
- 2017.07 [syspanda] [Detecting Outbound connections Pt. 1 – Sysmon](https://www.syspanda.com/index.php/2017/07/13/sysmon-detecting-outbound-connections-geoip-logstash/)
- 2017.06 [securitylogs] [Sysmon & the pyramid of hell!](https://securitylogs.org/2017/06/24/sysmon-the-pyramid-of-hell/)
- 2017.06 [nosecurecode] [Updated SysmonView](https://nosecurecode.blog/2017/06/10/updated-sysmonview/)
- 2017.06 [nosecurecode] [Updated Sysmon View](https://nosecurecode.com/2017/06/10/updated-sysmonview/)
- 2017.05 [syspanda] [Sysmon: Getting started](https://www.syspanda.com/index.php/2017/05/19/sysmon-getting-started/)
- 2017.05 [logrhythm] [Detecting WannaCry Activity on Sysmon-Enabled Hosts](https://logrhythm.com/blog/detecting-wannacry-activity-on-sysmon-enabled-hosts/)
- 2017.05 [nosecurecode] [Sysmon View](https://nosecurecode.blog/2017/05/05/sysmon-view/)
- 2017.05 [nosecurecode] [Sysmon View](https://nosecurecode.com/2017/05/05/sysmon-view/)
- 2017.04 [3or] [Hunting mimikatz with sysmon: monitoring OpenProcess()](https://blog.3or.de/hunting-mimikatz-with-sysmon-monitoring-openprocess.html)
- 2017.04 [4hou] [通过APC实现Dll注入——绕过Sysmon监控](http://www.4hou.com/technology/4393.html)
- 2017.04 [cyberwardog] [Chronicles of a Threat Hunter: Hunting for Remotely Executed Code via Services & Lateral Movement with Sysmon, Win Event Logs, and ELK](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html)
- 2017.04 [3gstudent] [通过APC实现Dll注入——绕过Sysmon监控](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87APC%E5%AE%9E%E7%8E%B0Dll%E6%B3%A8%E5%85%A5-%E7%BB%95%E8%BF%87Sysmon%E7%9B%91%E6%8E%A7/)
- 2017.04 [3gstudent] [通过APC实现Dll注入——绕过Sysmon监控](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87APC%E5%AE%9E%E7%8E%B0Dll%E6%B3%A8%E5%85%A5-%E7%BB%95%E8%BF%87Sysmon%E7%9B%91%E6%8E%A7/)
- 2017.04 [cyberwardog] [Chronicles of a Threat Hunter: Hunting for In-Memory Mimikatz with Sysmon, Win Event Logs, and ELK - Part III (Overpass-the-Hash - EIDs 10, 4624, 4648, 4768)](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for.html)
- 2017.03 [cyberwardog] [Chronicles of a Threat Hunter: Hunting for WMImplant with Sysmon and ELK - Part I (EID 1,12, 13, 17 & 18)](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_26.html)
- 2017.03 [cyberwardog] [Chronicles of a Threat Hunter: Hunting for In-Memory Mimikatz with Sysmon and ELK - Part II (Event ID 10)](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html)
- 2017.03 [nosecurecode] [Sysmon Shell](https://nosecurecode.blog/2017/03/14/sysmon-shell/)
- 2017.03 [nosecurecode] [Sysmon Shell](https://nosecurecode.com/2017/03/14/sysmon-shell/)
- 2017.03 [cyberwardog] [Chronicles of a Threat Hunter: Hunting for In-Memory Mimikatz with Sysmon and ELK - Part I (Event ID 7)](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html)
- 2017.03 [rsa] [Why Sysmon when you have NWE](https://community.rsa.com/community/products/netwitness/blog/2017/03/10/why-sysmon-when-you-have-ecat)
- 2017.03 [nettitude] [Effectively analysing sysmon logs](https://labs.nettitude.com/blog/effectively-analysing-sysmon-logs/)
- 2017.03 [syspanda] [Advanced Sysmon filtering using Logstash](https://www.syspanda.com/index.php/2017/03/03/sysmon-filtering-using-logstash/)
- 2017.03 [cyberwardog] [Building a Sysmon Dashboard with an ELK Stack](https://cyberwardog.blogspot.com/2017/03/building-sysmon-dashboard-with-elk-stack.html)
- 2017.03 [syspanda] [Setting up Windows Event Forwarder Server (WEF) (Domain) – Sysmon Part 2/3](https://www.syspanda.com/index.php/2017/03/01/setting-up-windows-event-forwarder-server-wef-domain-sysmon-part-23/)
- 2017.02 [syspanda] [Deploying Sysmon through Group Policy (GPO) *Updated scroll down*](https://www.syspanda.com/index.php/2017/02/28/deploying-sysmon-through-gpo/)
- 2017.02 [rsa] [Log - Sysmon 6 Windows Event Collection](https://community.rsa.com/community/products/netwitness/blog/2017/02/28/log-sysmon-6-windows-event-collection)
- 2017.02 [darkoperator] [Posh-Sysmon Module for Creating Sysmon Configuration Files](https://www.darkoperator.com/blog/2017/2/17/posh-sysmon-powershell-module-for-creating-sysmon-configuration-files)
- 2017.02 [holisticinfosec] [Toolsmith Release Advisory: Sysmon v6 for Securitay](https://holisticinfosec.blogspot.com/2017/02/toolsmith-release-advisory-sysmon-v6.html)
- 2017.02 [nettitude] [Putting attackers in hi vis jackets with sysmon](https://labs.nettitude.com/blog/putting-attackers-in-hi-vis-jackets-with-sysmon/)
- 2017.02 [angelalonso] [Hunting malicious behaviour abusing PowerShell with Sysmon and Splunk](http://blog.angelalonso.es/2017/02/hunting-malicious-behaviour-abusing.html)
- 2017.02 [freebuf] [使用Sysmon和Splunk探测网络环境中横向渗透](http://www.freebuf.com/sectool/125846.html)
- 2017.01 [securitylogs] [Presentation on Sysmon Deployment](https://securitylogs.org/2017/01/17/presentation-on-sysmon-deployment/)
- 2017.01 [securitylogs] [Sysmon 5 : New opportunities for hunting](https://securitylogs.org/2017/01/17/sysmon-5-new-opportunities-for-hunting/)
- 2016.12 [freebuf] [使用轻量级工具Sysmon监视你的系统](http://www.freebuf.com/sectool/122779.html)
- 2016.12 [] [Sysmon - The Best Free Windows Monitoring Tool You Aren't Using](http://909research.com/sysmon-the-best-free-windows-monitoring-tool-you-arent-using/)
- 2016.10 [cqureacademy] [Sysmon: how to set up, update and use?](https://cqureacademy.com/blog/server-monitoring/sysmon)
- 2016.09 [jshlbrd] [Hunter’s Tool Chest: Sysmon](https://medium.com/p/1b26896f7d47)
- 2016.05 [securitylogs] [Sysmon version 4 : Cool filtering!](https://securitylogs.org/2016/05/07/sysmon-version-4-cool-filtering/)
- 2016.05 [securitylogs] [Sysmon logs at scale analyzed with Splunk](https://securitylogs.org/2016/05/07/sysmon-logs-at-scale/)
- 2015.12 [defensivedepth] [New Sysmon OSSEC Decoders….](https://defensivedepth.com/2015/12/19/new-sysmon-ossec-decoders/)
- 2015.09 [defensivedepth] [#SOCAugusta Deck: Sysmon & Security Onion Integration](https://defensivedepth.com/2015/09/11/socaugusta-deck-sysmon-security-onion-integration/)
- 2015.06 [defensivedepth] [Sysmon & Security Onion, Part 5: Sysmon Event Collection](https://defensivedepth.com/2015/06/11/sysmon-security-onion-part-5-sysmon-event-collection/)
- 2015.06 [root9b] [Detecting Advanced Threats with Sysmon, WEF, and ElasticSearch](https://www.root9b.com/newsroom/detecting-advanced-threats-sysmon-wef-and-elasticsearch)
- 2015.05 [defensivedepth] [Sysmon & Security Onion, Part 4: Integrating Security Onion and Sysmon](https://defensivedepth.com/2015/05/24/sysmon-security-onion-part-4-integrating-security-onion-and-sysmon/)
- 2015.04 [p0w3rsh3ll] [Deploy Sysmon with PowerShell Desired State Configuration](https://p0w3rsh3ll.wordpress.com/2015/04/21/deploy-sysmon-with-powershell-desired-state-configuration/)
- 2015.04 [defensivedepth] [Sysmon & Security Onion, Part 3: Enterprise Security Monitoring](https://defensivedepth.com/2015/04/20/sysmon-security-onion-part-3-enterprise-security-monitoring/)
- 2015.04 [defensivedepth] [Sysmon & Security Onion, Part 2: Rise of Intelligence-Driven Computer Network Defense](https://defensivedepth.com/2015/04/06/sysmon-security-onion-part-2-rise-of-intelligence-driven-computer-network-defense/)
- 2015.04 [defensivedepth] [Sysmon & Security Onion: Monitoring Key Windows Processes for Anomalies](https://defensivedepth.com/2015/04/01/monitoring-key-windows-processes-for-anomalies/)
- 2015.03 [defensivedepth] [Sysmon & Security Onion, Part 1: Rise of the Encrypted Web](https://defensivedepth.com/2015/03/29/sysmon-security-onion-part-1-rise-of-the-encrypted-web/)
- 2015.03 [defensivedepth] [Using Sysmon To Enrich Security Onion’s Host-Level Capabilities](https://defensivedepth.com/2015/03/27/using-sysmon-to-enrich-security-onions-host-level-capabilities/)
- 2015.03 [bsk] [Detect System File Manipulations with SysInternals Sysmon](https://www.bsk-consulting.de/2015/03/21/detect-system-file-manipulations-with-sysinternals-sysmon/)
- 2015.02 [crowdstrike] [Parsing Sysmon Events for IR Indicators](https://www.crowdstrike.com/blog/sysmon-2/)
- 2015.02 [holisticinfosec] [toolsmith: Sysmon 2.0 & EventViz](https://holisticinfosec.blogspot.com/2015/02/toolsmith-sysmon-20-eventviz.html)
- 2015.02 [bsk] [Sysmon Example Config XML](https://www.bsk-consulting.de/2015/02/04/sysmon-example-config-xml/)
- 2015.01 [] [OS X 10.9.x - sysmond XPC Privilege Escalation](http://0day5.com/archives/2826/)
- 2014.08 [sans] [Using Sysinternals System Monitor (Sysmon) in a Malware Analysis Lab](https://digital-forensics.sans.org/blog/2014/08/12/sysmon-in-malware-analysis-lab)
- 2014.08 [darkoperator] [Sysinternals New Tool Sysmon (System Monitor)](https://www.darkoperator.com/blog/2014/8/8/sysinternals-sysmon)




***


## <a id="ac43a3ce5a889d8b18cf22acb6c31a72"></a>ETW


### <a id="0af4bd8ca0fd27c9381a2d1fa8b71a1f"></a>Tools


- [**1228**Star][10d] [JS] [jpcertcc/logontracer](https://github.com/jpcertcc/logontracer) Investigate malicious Windows logon by visualizing and analyzing Windows event log
- [**865**Star][22d] [C++] [google/uiforetw](https://github.com/google/uiforetw) User interface for recording and managing ETW traces
- [**654**Star][10m] [Roff] [palantir/windows-event-forwarding](https://github.com/palantir/windows-event-forwarding) A repository for using windows event forwarding for incident detection and response
- [**640**Star][3y] [PS] [hlldz/invoke-phant0m](https://github.com/hlldz/invoke-phant0m) Windows Event Log Killer
- [**609**Star][19d] [PS] [sbousseaden/evtx-attack-samples](https://github.com/sbousseaden/evtx-attack-samples) windows events samples associated to specific attack and post-exploitation techniques
- [**504**Star][10m] [C#] [lowleveldesign/wtrace](https://github.com/lowleveldesign/wtrace) Command line tracing tool for Windows, based on ETW.
- [**479**Star][5m] [PS] [sans-blue-team/deepbluecli](https://github.com/sans-blue-team/deepbluecli) a PowerShell Module for Threat Hunting via Windows Event Logs
- [**446**Star][9m] [PS] [nsacyber/event-forwarding-guidance](https://github.com/nsacyber/Event-Forwarding-Guidance) Configuration guidance for implementing collection of security relevant Windows Event Log events by using Windows Event Forwarding. #nsacyber
- [**393**Star][10m] [Py] [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx) Pure Python parser for recent Windows Event Log files (.evtx)
- [**341**Star][1y] [C++] [qax-a-team/eventcleaner](https://github.com/QAX-A-Team/EventCleaner) A tool mainly to erase specified records from Windows event logs, with additional functionalities.
- [**306**Star][1m] [C#] [zodiacon/procmonx](https://github.com/zodiacon/procmonx) Extended Process Monitor-like tool based on Event Tracing for Windows
- [**282**Star][3m] [C#] [fireeye/silketw](https://github.com/fireeye/silketw) flexible C# wrappers for ETW
- [**282**Star][10m] [C#] [nsacyber/windows-event-log-messages](https://github.com/nsacyber/Windows-Event-Log-Messages) Retrieves the definitions of Windows Event Log messages embedded in Windows binaries and provides them in discoverable formats. #nsacyber
- [**261**Star][3m] [C++] [gametechdev/presentmon](https://github.com/gametechdev/presentmon) Tool for collection and processing of ETW events related to DXGI presentation.
- [**249**Star][3m] [C++] [microsoft/krabsetw](https://github.com/microsoft/krabsetw) KrabsETW provides a modern C++ wrapper and a .NET wrapper around the low-level ETW trace consumption functions.
- [**214**Star][2y] [Py] [thiber-org/userline](https://github.com/thiber-org/userline) Query and report user logons relations from MS Windows Security Events
- [**146**Star][5m] [Py] [fireeye/pywintrace](https://github.com/fireeye/pywintrace) Python 编写的 ETW（Event Tracing for Windows） Wrapper
- [**144**Star][2y] [PS] [jepaynemsft/weffles](https://github.com/jepaynemsft/weffles) Build a fast, free, and effective Threat Hunting/Incident Response Console with Windows Event Forwarding and PowerBI
- [**128**Star][4m] [Py] [mvelazc0/oriana](https://github.com/mvelazc0/oriana) Oriana is a threat hunting tool that leverages a subset of Windows events to build relationships, calculate totals and run analytics. The results are presented in a Web layer to help defenders identify outliers and suspicious behavior on corporate environments.
- [**99**Star][3y] [C#] [cyberpoint/ruxcon2016etw](https://github.com/cyberpoint/ruxcon2016etw) Ruxcon2016 POC Code
- [**82**Star][2y] [C#] [zacbrown/powerkrabsetw](https://github.com/zacbrown/powerkrabsetw) PowerKrabsEtw is a PowerShell interface for doing real-time ETW tracing.
- [**70**Star][5m] [Py] [dgunter/evtxtoelk](https://github.com/dgunter/evtxtoelk) A lightweight tool to load Windows Event Log evtx files into Elasticsearch.
- [**54**Star][6m] [PS] [tasox/logrm](https://github.com/tasox/logrm) LogRM is a post exploitation powershell script which it uses windows event logs to gather information about internal network
- [**47**Star][2y] [Py] [devgc/eventmonkey](https://github.com/devgc/eventmonkey) A Windows Event Processing Utility
- [**43**Star][2y] [C#] [zacbrown/hiddentreasure-etw-demo](https://github.com/zacbrown/hiddentreasure-etw-demo) Basic demo for Hidden Treasure talk.
- [**30**Star][2y] [C#] [zacbrown/powershellmethodauditor](https://github.com/zacbrown/powershellmethodauditor) PowerShellMethodAuditor listens to the PowerShell ETW provider and logs PowerShell method invocations.
- [**29**Star][2y] [C#] [aviavni/nativeleakdetector](https://github.com/aviavni/nativeleakdetector) Win32 memory leak detector with ETW
- [**28**Star][5m] [fuzzysecurity/bh-arsenal-2019](https://github.com/fuzzysecurity/bh-arsenal-2019) SilkETW & SilkService
- [**27**Star][4y] [Py] [williballenthin/python-evt](https://github.com/williballenthin/python-evt) Pure Python parser for classic Windows Event Log files (.evt)
- [**22**Star][4y] [C#] [lallousx86/wepexplorer](https://github.com/lallousx86/wepexplorer) Windows Events Providers Explorer
- [**12**Star][1y] [PS] [piesecurity/windowseventstocsvtimeline](https://github.com/piesecurity/windowseventstocsvtimeline) Simple Powershell scripts to collect all Windows Event Logs from a host and parse them into one CSV timeline.
- [**7**Star][4m] [PS] [1cysw0rdk0/whodunnit](https://github.com/1cysw0rdk0/whodunnit) A PS forensics tool for Scraping, Filtering and Exporting Windows Event Logs
- [**7**Star][5y] [R] [holisticinfosec/eventviz](https://github.com/holisticinfosec/eventviz) EventViz Windows event log viewer
- [**4**Star][3m] [C#] [ceramicskate0/swelf](https://github.com/ceramicskate0/swelf) Simple Windows Event Log Forwarder (SWELF). Its easy to use/simply works Log Forwarder, EVTX Parser and Reader. Make it your log forwarder through the configuration of the software. Now in early release here at
- [**2**Star][1y] [C++] [randomascii/bigfiles](https://github.com/randomascii/bigfiles) This repo exists for storing large data files such as ETW traces or crash dumps, often associated with blog posts


### <a id="11c4c804569626c1eb02140ba557bb85"></a>Post


- 2019.12 [Cooper] [EventList, Matching Windows Event Log IDs With MITRE ATT&CK - Miriam Wiesner](https://www.youtube.com/watch?v=l5PpbOmopyA)
- 2019.09 [adventuresincyberchallenges] [Powershell Encoded Payload In Clear Text in Windows Event Log 4688](https://adventuresincyberchallenges.blogspot.com/2019/09/powershell-encoded-payload-in-clear.html)
- 2019.09 [Cyb3rWard0g] [Threat Hunting with ETW events and HELK — Part 2: Shipping ETW events to HELK ⚒](https://medium.com/p/16837116d2f5)
- 2019.09 [Cyb3rWard0g] [Threat Hunting with ETW events and HELK — Part 1: Installing SilkETW 🏄‍♀🏄](https://medium.com/p/6eb74815e4a0)
- 2019.05 [freebuf] [SilkETW：一款针对Windows事件追踪的自定义C#封装工具](https://www.freebuf.com/sectool/203531.html)
- 2019.04 [4sysops] [Forward Windows events to a Syslog server with free SolarWinds Event Log Forwarder for Windows](https://4sysops.com/archives/forward-windows-events-to-a-syslog-server-with-free-solarwinds-event-log-forwarder-for-windows/)
- 2019.02 [360] [ETW注册表监控windows内核实现原理](https://www.anquanke.com/post/id/171298/)
- 2019.01 [sans] [Rocking Your Windows EventID with ELK Stack](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1492181323.pdf)
- 2019.01 [sans] [Threat Hunting via Windows Event Logs](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1524493093.pdf)
- 2019.01 [sans] [Hunting for Lateral Movement Using Windows Event Log](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1536265369.pdf)
- 2018.12 [palantir] [Tampering with Windows Event Tracing: Background, Offense, and Defense](https://medium.com/p/4be7ac62ac63)
- 2018.12 [sophos] [Hunting for threats with Intercept X and the Windows Event Collector](https://news.sophos.com/en-us/2018/12/03/hunting-for-threats-with-intercept-x-and-the-windows-event-collector/)
- 2018.08 [4sysops] [Query multiple Windows event logs with PowerShell](https://4sysops.com/archives/query-multiple-windows-event-logs-with-powershell/)
- 2018.07 [criteo] [Grab ETW Session, Providers and Events](http://labs.criteo.com/2018/07/grab-etw-session-providers-and-events/)
- 2018.07 [3gstudent] [Windows Event Viewer Log (EVT)单条日志清除（三）——删除当前系统指定指定时间段evt日志记录](https://3gstudent.github.io/3gstudent.github.io/Windows-Event-Viewer-Log-(EVT)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%89-%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E6%8C%87%E5%AE%9A%E6%8C%87%E5%AE%9A%E6%97%B6%E9%97%B4%E6%AE%B5evt%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)
- 2018.07 [3gstudent] [Windows Event Viewer Log (EVT)单条日志清除（三）——删除当前系统指定指定时间段evt日志记录](https://3gstudent.github.io/3gstudent.github.io/Windows-Event-Viewer-Log-(EVT)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%89-%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E6%8C%87%E5%AE%9A%E6%8C%87%E5%AE%9A%E6%97%B6%E9%97%B4%E6%AE%B5evt%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)
- 2018.07 [pentesttoolz] [LogonTracer – Investigate Malicious Windows Logon By Visualizing And Analyzing Windows Event Log](https://pentesttoolz.com/2018/07/17/logontracer-investigate-malicious-windows-logon-by-visualizing-and-analyzing-windows-event-log/)
- 2018.07 [dragos] [EvtxToElk: A Python Module to Load Windows Event Logs into ElasticSearch](https://dragos.com/blog/20180717EvtxToElk.html)
- 2018.07 [3gstudent] [Windows Event Viewer Log (EVT)单条日志清除（二）——程序实现删除evt文件指定时间段的日志记录](https://3gstudent.github.io/3gstudent.github.io/Windows-Event-Viewer-Log-(EVT)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%8C-%E7%A8%8B%E5%BA%8F%E5%AE%9E%E7%8E%B0%E5%88%A0%E9%99%A4evt%E6%96%87%E4%BB%B6%E6%8C%87%E5%AE%9A%E6%97%B6%E9%97%B4%E6%AE%B5%E7%9A%84%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)
- 2018.07 [3gstudent] [Windows Event Viewer Log (EVT)单条日志清除（二）——程序实现删除evt文件指定时间段的日志记录](https://3gstudent.github.io/3gstudent.github.io/Windows-Event-Viewer-Log-(EVT)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%8C-%E7%A8%8B%E5%BA%8F%E5%AE%9E%E7%8E%B0%E5%88%A0%E9%99%A4evt%E6%96%87%E4%BB%B6%E6%8C%87%E5%AE%9A%E6%97%B6%E9%97%B4%E6%AE%B5%E7%9A%84%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95/)
- 2018.07 [3gstudent] [Windows Event Viewer Log (EVT)单条日志清除（一）——删除思路与实例](https://3gstudent.github.io/3gstudent.github.io/Windows-Event-Viewer-Log-(EVT)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%80-%E5%88%A0%E9%99%A4%E6%80%9D%E8%B7%AF%E4%B8%8E%E5%AE%9E%E4%BE%8B/)
- 2018.07 [3gstudent] [Windows Event Viewer Log (EVT)单条日志清除（一）——删除思路与实例](https://3gstudent.github.io/3gstudent.github.io/Windows-Event-Viewer-Log-(EVT)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%80-%E5%88%A0%E9%99%A4%E6%80%9D%E8%B7%AF%E4%B8%8E%E5%AE%9E%E4%BE%8B/)
- 2018.06 [hecfblog] [ETW Event Tracing for Windows and ETL Files](http://www.hecfblog.com/2018/06/etw-event-tracing-for-windows-and-etl.html)
- 2018.04 [5yx] [Windows Event Log to the Dark Side](https://medium.com/p/9c8ad92637f2)
- 2018.03 [intrinsec] [Centralisation des journaux avec Windows Event Forwarding](https://securite.intrinsec.com/2018/03/16/centralisation-wef-siem/)
- 2018.03 [illuminati] [Performance Series Part 1 – How to collect an ETW/Xperf trace to capture general performance issues](https://illuminati.services/2018/03/08/performance-how-to-collect-an-etw-xperf-trace-to-capture-general-performance-issues/)
- 2018.01 [rsa] [Feed - Windows Event ID Criticality](https://community.rsa.com/community/products/netwitness/blog/2018/01/17/feed-windows-event-id-criticality)
- 2017.09 [blackhillsinfosec] [End-Point Log Consolidation with Windows Event Forwarder](https://www.blackhillsinfosec.com/end-point-log-consolidation-windows-event-forwarder/)
- 2017.09 [fireeye] [Introducing pywintrace: A Python Wrapper for ETW](https://www.fireeye.com/blog/threat-research/2017/09/pywintrace-python-wrapper-for-etw.html)
- 2017.09 [redplait] [ETW private loggers](http://redplait.blogspot.com/2017/09/etw-private-loggers.html)
- 2017.08 [asd] [Technical Guidance for Windows Event Logging](https://asd.gov.au/publications/protect/windows-event-logging-technical-guidance.htm)
- 2017.07 [huntingmalware] [Hooking Windows events without knowing anything about C/C++](https://blog.huntingmalware.com/notes/WMI)
- 2017.07 [clong] [The Windows Event Forwarding Survival Guide](https://medium.com/p/2010db7a68c4)
- 2017.06 [illuminati] [Quick and Dirty – Collect an ETW shutdown trace on Windows 7.](https://illuminati.services/2017/06/21/quick-and-dirty-collect-an-etw-shutdown-trace-on-windows-7/)
- 2017.05 [redplait] [kernel etw traces in windows 10](http://redplait.blogspot.com/2017/05/kernel-etw-traces-in-windows-10.html)
- 2017.04 [4hou] [隐藏的宝藏：ETW的入侵检测（第1部分）](http://www.4hou.com/technology/4255.html)
- 2017.03 [p0w3rsh3ll] [ETW provider security – fix event id 30](https://p0w3rsh3ll.wordpress.com/2017/03/20/etw-provider-security-fix-event-id-30/)
- 2017.03 [syspanda] [Sending Windows Event Forwarder Server (WEF) Logs to Elasticsearch (Winlogbeat)](https://www.syspanda.com/index.php/2017/03/01/sending-windows-event-forwarder-server-wef-logs-to-elasticsearch/)
- 2017.03 [syspanda] [Setting up Windows Event Forwarder Server (WEF) (Domain) – GPO Deployment Part 3/3](https://www.syspanda.com/index.php/2017/03/01/setting-up-windows-event-forwarder-server-wef-domain-gpo-deployment-part-33/)
- 2017.03 [syspanda] [Setting up Windows Event Forwarder Server (WEF) (Domain) Part 1/3](https://www.syspanda.com/index.php/2017/03/01/setting-up-windows-event-forwarder-server-wef-domain-part-13/)
- 2017.02 [guardicore] [Who’s Afraid of ETW? GuardiCore Guide to Building a Robust Windows Agent](https://www.guardicore.com/2017/02/whos-afraid-etw-guardicore-guide-building-robust-windows-agent/)
- 2017.01 [rsa] [Logs - Collecting Windows Events with WEC](https://community.rsa.com/community/products/netwitness/blog/2017/01/30/logs-collecting-windows-events-with-wec)
- 2017.01 [rsa] [ESA - Intrusion Detection with Windows Event Logs](https://community.rsa.com/community/products/netwitness/blog/2017/01/06/esa-intrusion-detection-with-windows-event-logs)
- 2016.11 [4hou] [如何通过ETW实现对USB键盘的键盘记录？](http://www.4hou.com/technology/1210.html)
- 2016.10 [3gstudent] [Study Notes Weekly No.3(Use odbcconf to load dll & Get-Exports & ETW USB Keylogger)](https://3gstudent.github.io/3gstudent.github.io/Study-Notes-Weekly-No.3(Use-odbcconf-to-load-dll-&-Get-Exports-&-ETW-USB-Keylogger)/)
- 2016.10 [3gstudent] [Study Notes Weekly No.3(Use odbcconf to load dll & Get-Exports & ETW USB Keylogger)](https://3gstudent.github.io/3gstudent.github.io/Study-Notes-Weekly-No.3(Use-odbcconf-to-load-dll-&-Get-Exports-&-ETW-USB-Keylogger)/)
- 2016.09 [sans] [Windows Events log for IR/Forensics ,Part 2](https://isc.sans.edu/forums/diary/Windows+Events+log+for+IRForensics+Part+2/21501/)
- 2016.09 [sans] [Windows Events log for IR/Forensics ,Part 1](https://isc.sans.edu/forums/diary/Windows+Events+log+for+IRForensics+Part+1/21493/)
- 2016.09 [n0where] [Python Windows Event Log Parser: python-evtx](https://n0where.net/python-windows-event-log-parser-python-evtx)
- 2016.08 [sans] [Recommended Reading: Intrusion Detection Using Indicators of Compromise Based on Best Practices and Windows Event Logs](https://isc.sans.edu/forums/diary/Recommended+Reading+Intrusion+Detection+Using+Indicators+of+Compromise+Based+on+Best+Practices+and+Windows+Event+Logs/21419/)
- 2016.08 [logz] [Windows Event Log Analysis with Winlogbeat & Logz.io](https://logz.io/blog/windows-event-log-analysis/)
- 2016.01 [lallouslab] [Windows Events Providers Explorer](http://lallouslab.net/2016/01/25/windows-events-providers-explorer/)
- 2015.12 [jaapbrasser] [PSBlogweek: PowerShell logging in the Windows Event log](https://www.jaapbrasser.com/psblogweek-powershell-logging-in-the-windows-event-log/)
- 2015.07 [vanimpe] [Use EvtxParser to convert Windows Event Log files to XML](https://www.vanimpe.eu/2015/07/16/use-evtxparser-convert-windows-event-log-files-xml/)
- 2015.06 [summitroute] [Shipping Windows Events to Heka and ElasticSearch](https://summitroute.com/blog/2015/06/14/shipping_windows_events_to_heka_and_elasticsearch/)
- 2014.10 [windowsir] [Windows Event Logs](http://windowsir.blogspot.com/2014/10/windows-event-logs.html)
- 2014.04 [lowleveldesign] [LowLevelDesign.NLog.Ext and ETW targets for NLog](https://lowleveldesign.org/2014/04/18/etw-providers-for-nlog/)
- 2013.02 [sans] [Parsing Windows Eventlogs in Powershell](https://isc.sans.edu/forums/diary/Parsing+Windows+Eventlogs+in+Powershell/15298/)
- 2012.09 [lowleveldesign] [Diagnosing ADO.NET with ETW traces](https://lowleveldesign.org/2012/09/07/diagnosing-ado-net-with-etw-traces/)
- 2012.03 [lowleveldesign] [A managed ETW provider and the 15002 error](https://lowleveldesign.org/2012/03/14/a-managed-etw-provider-and-the-15002-error/)
- 2011.05 [thomasmaurer] [Powershell: How to export Windows Eventlogs with Powershell](https://www.thomasmaurer.ch/2011/05/powershell-how-to-export-windows-eventlogs-with-powershell/)
- 2009.04 [sans] [Strange Windows Event Log entry](https://isc.sans.edu/forums/diary/Strange+Windows+Event+Log+entry/6208/)
- 2008.03 [chuvakin] [Poll #7: What tools do you use for Windows Event Log collection?](http://chuvakin.blogspot.hk/2008/03/poll-7-what-tools-do-you-use-for.html)
- 2007.12 [alienvault] [Tutorial 5: Windows event logging](https://www.alienvault.com/blogs/labs-research/tutorial-5-windows-event-logging)




***


## <a id="184bbacd8b9e08c30cc9ffcee9513f44"></a>AppLocker


### <a id="8f1876dff78e80b60d00de25994276d9"></a>Tools


- [**921**Star][7m] [PS] [api0cradle/ultimateapplockerbypasslist](https://github.com/api0cradle/ultimateapplockerbypasslist) The goal of this repository is to document the most common techniques to bypass AppLocker.
- [**132**Star][13d] [PS] [nsacyber/applocker-guidance](https://github.com/nsacyber/applocker-guidance) Configuration guidance for implementing application whitelisting with AppLocker. #nsacyber
- [**51**Star][8m] [PS] [api0cradle/poweral](https://github.com/api0cradle/poweral) A Powershell module that helps you identify AppLocker weaknesses
- [**40**Star][2y] [milkdevil/ultimateapplockerbypasslist](https://github.com/milkdevil/ultimateapplockerbypasslist) 
- [**37**Star][4y] [C#] [cn33liz/sharpcat](https://github.com/cn33liz/sharpcat) SharpCat - A Simple Reversed Command Shell which can be started using InstallUtil (Bypassing AppLocker)
- [**33**Star][2y] [C] [demonsec666/secist_applocker](https://github.com/demonsec666/secist_applocker) 
- [**20**Star][1y] [ivan1ee/regasm_installutil_applockerbypass](https://github.com/ivan1ee/regasm_installutil_applockerbypass) AppLocker Bypass With Regasm/InstallUtil
- [**14**Star][2y] [XSLT] [3gstudent/use-msxsl-to-bypass-applocker](https://github.com/3gstudent/use-msxsl-to-bypass-applocker) Learn from Casey Smith@subTee
- [**8**Star][5y] [PS] [strictlymike/invoke-schmapplocker](https://github.com/strictlymike/invoke-schmapplocker) Bypass AppLocker EXE file policies
- [**7**Star][11m] [api0cradle/applocker-stuff](https://github.com/api0cradle/applocker-stuff) Just some random stuff for AppLocker
- [**5**Star][2y] [homjxi0e/applockerbpg](https://github.com/homjxi0e/applockerbpg) AppLocker Bypassing Method )(


### <a id="286317d6d7c1a0578d8f5db940201320"></a>Post


- 2019.11 [tyranidslair] [The Internals of AppLocker - Part 3 - Access Tokens and Access Checking](https://tyranidslair.blogspot.com/2019/11/the-internals-of-applocker-part-3.html)
- 2019.11 [tyranidslair] [The Internals of AppLocker - Part 2 - Blocking Process Creation](https://tyranidslair.blogspot.com/2019/11/the-internals-of-applocker-part-2.html)
- 2019.11 [tyranidslair] [The Internals of AppLocker - Part 1 - Overview and Setup](https://tyranidslair.blogspot.com/2019/11/the-internals-of-applocker-part-1.html)
- 2019.09 [blackhillsinfosec] [Getting Started With AppLocker](https://www.blackhillsinfosec.com/getting-started-with-applocker/)
- 2019.08 [p0w3rsh3ll] [How to delete a single Applocker rule](https://p0w3rsh3ll.wordpress.com/2019/08/02/how-to-delete-a-single-applocker-rule/)
- 2019.05 [oddvar] [A small discovery about AppLocker](https://oddvar.moe/2019/05/29/a-small-discovery-about-applocker/)
- 2019.04 [4hou] [通过regsrv32.exe绕过Applocker应用程序白名单的多种方法](https://www.4hou.com/web/17354.html)
- 2019.03 [4sysops] [Application whitelisting: Software Restriction Policies vs. AppLocker vs. Windows Defender Application Control](https://4sysops.com/archives/application-whitelisting-software-restriction-policies-vs-applocker-vs-windows-defender-application-control/)
- 2019.03 [4hou] [逃避手段再开花——从一个能逃避AppLocker和AMSI检测的Office文档讲起](https://www.4hou.com/system/16916.html)
- 2019.03 [yoroi] [The Document that Eluded AppLocker and AMSI](https://blog.yoroi.company/research/the-document-that-eluded-applocker-and-amsi/)
- 2019.03 [p0w3rsh3ll] [Applocker and PowerShell: how do they tightly work together?](https://p0w3rsh3ll.wordpress.com/2019/03/07/applocker-and-powershell-how-do-they-tightly-work-together/)
- 2019.02 [4hou] [如何以管理员身份绕过AppLocker](http://www.4hou.com/web/16213.html)
- 2019.02 [oddvar] [Bypassing AppLocker as an admin](https://oddvar.moe/2019/02/01/bypassing-applocker-as-an-admin/)
- 2019.01 [hackingarticles] [Windows Applocker Policy – A Beginner’s Guide](https://www.hackingarticles.in/windows-applocker-policy-a-beginners-guide/)
- 2019.01 [t00ls] [投稿文章：Bypass Applocker + 免杀执行任意 shellcode [ csc + installUtil ]](https://www.t00ls.net/articles-49443.html)
- 2018.12 [hecfblog] [Daily Blog #580: Applocker and Windows 10](https://www.hecfblog.com/2018/12/daily-blog-580-applocker-and-windows-10.html)
- 2018.12 [hecfblog] [Daily Blog #581: Forensic Lunch Test Kitchen 12/28/18 Syscache Applocker and Server 2012](https://www.hecfblog.com/2018/12/daily-blog-581-forensic-lunch-test.html)
- 2018.12 [360] [多维度对抗Windows AppLocker](https://www.anquanke.com/post/id/168633/)
- 2018.12 [tsscyber] [BloodHound.xpab — Applocker bypass](https://medium.com/p/895377ffa98e)
- 2018.10 [tsscyber] [AppLocker Bypass — presentationhost.exe](https://medium.com/p/8c87b2354cd4)
- 2018.10 [oddvar] [%Temp%orary Constrained Language mode in AppLocker](https://oddvar.moe/2018/10/06/temporary-constrained-language-mode-in-applocker/)
- 2018.10 [xpnsec] [AppLocker CLM Bypass via COM](https://blog.xpnsec.com/constrained-language-mode-bypass/)
- 2018.09 [aliyun] [如何通过COM绕过AppLocker的约束语言模式(CLM)](https://xz.aliyun.com/t/2822)
- 2018.09 [360] [如何利用COM绕过AppLocker CLM](https://www.anquanke.com/post/id/160948/)
- 2018.09 [oddvar] [AppLocker – Making sure that local rules are removed](https://oddvar.moe/2018/09/28/applocker-making-sure-that-local-rules-are-removed/)
- 2018.09 [mdsec] [AppLocker CLM Bypass via COM](https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/)
- 2018.09 [360] [如何绕过AppLocker自定义规则](https://www.anquanke.com/post/id/159892/)
- 2018.09 [improsec] [AppLocker - hash *bad*listing](https://improsec.com/blog/applocker-hash-badlisting)
- 2018.09 [improsec] [AppLocker - hash *bad*listing](https://improsec.com/tech-blog/applocker-hash-badlisting)
- 2018.09 [rastamouse] [Enumerating AppLocker Config](https://rastamouse.me/2018/09/enumerating-applocker-config/)
- 2018.07 [oddvar] [AppLocker for admins – Does it work?](https://oddvar.moe/2018/07/27/applocker-for-admins-does-it-work/)
- 2018.05 [4hou] [利用CMSTP绕过AppLocker并执行代码](http://www.4hou.com/technology/11743.html)
- 2018.05 [oddvar] [Real whitelisting attempt using AppLocker](https://oddvar.moe/2018/05/14/real-whitelisting-attempt-using-applocker/)
- 2018.05 [pentestlab] [AppLocker Bypass – CMSTP](https://pentestlab.blog/2018/05/10/applocker-bypass-cmstp/)
- 2018.04 [3gstudent] [利用Assembly Load & LoadFile绕过Applocker的分析总结](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8Assembly-Load-&-LoadFile%E7%BB%95%E8%BF%87Applocker%E7%9A%84%E5%88%86%E6%9E%90%E6%80%BB%E7%BB%93/)
- 2018.04 [3gstudent] [利用Assembly Load & LoadFile绕过Applocker的分析总结](https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8Assembly-Load-&-LoadFile%E7%BB%95%E8%BF%87Applocker%E7%9A%84%E5%88%86%E6%9E%90%E6%80%BB%E7%BB%93/)
- 2018.04 [aliyun] [利用PowerShell诊断脚本执行命令并绕过AppLocker](https://xz.aliyun.com/t/2247)
- 2018.03 [secist] [AppLocker_Bypass List](http://www.secist.com/archives/6506.html)
- 2018.03 [3gstudent] [使用LUA脚本绕过Applocker的测试分析](https://3gstudent.github.io/3gstudent.github.io/%E4%BD%BF%E7%94%A8LUA%E8%84%9A%E6%9C%AC%E7%BB%95%E8%BF%87Applocker%E7%9A%84%E6%B5%8B%E8%AF%95%E5%88%86%E6%9E%90/)
- 2018.03 [3gstudent] [使用LUA脚本绕过Applocker的测试分析](https://3gstudent.github.io/3gstudent.github.io/%E4%BD%BF%E7%94%A8LUA%E8%84%9A%E6%9C%AC%E7%BB%95%E8%BF%87Applocker%E7%9A%84%E6%B5%8B%E8%AF%95%E5%88%86%E6%9E%90/)
- 2018.03 [aliyun] [使用LUA脚本绕过Applocker的测试分析](https://xz.aliyun.com/t/2110)
- 2018.02 [4hou] [如何利用PowerShell诊断脚本执行命令并绕过AppLocker](http://www.4hou.com/system/10274.html)
- 2018.02 [secist] [Secist_Applocker_Bypass：一款applocker绕过的集合工具](http://www.secist.com/archives/6333.html)
- 2018.01 [bohops] [Loading Alternate Data Stream (ADS) DLL/CPL Binaries to Bypass AppLocker](https://bohops.com/2018/01/23/loading-alternate-data-stream-ads-dll-cpl-binaries-to-bypass-applocker/)
- 2018.01 [bohops] [Executing Commands and Bypassing AppLocker with PowerShell Diagnostic Scripts](https://bohops.com/2018/01/07/executing-commands-and-bypassing-applocker-with-powershell-diagnostic-scripts/)
- 2017.12 [oddvar] [Harden Windows with AppLocker – based on Case study part 2](https://oddvar.moe/2017/12/21/harden-windows-with-applocker-based-on-case-study-part-2/)
- 2017.12 [oddvar] [AppLocker – Case study – How insecure is it really? – Part 2](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/)
- 2017.12 [oddvar] [Harden Windows with AppLocker – based on Case study part 1](https://oddvar.moe/2017/12/13/harden-windows-with-applocker-based-on-case-study-part-1/)
- 2017.09 [4hou] [绕过AppLocker系列之Regasm和Regsvcs的利用](http://www.4hou.com/technology/5642.html)
- 2017.07 [4hou] [绕过AppLocker系列之CreateRestrictedToken的利用](http://www.4hou.com/technology/6810.html)
- 2017.07 [4hou] [绕过AppLocker系列之弱路径规则的利用](http://www.4hou.com/technology/5641.html)
- 2017.07 [4hou] [绕过AppLocker系列之控制面板的利用](http://www.4hou.com/technology/5738.html)
- 2017.07 [4hou] [如何利用msxsl绕过AppLocker？](http://www.4hou.com/system/6203.html)
- 2017.07 [3gstudent] [Use msxsl to bypass AppLocker](https://3gstudent.github.io/3gstudent.github.io/Use-msxsl-to-bypass-AppLocker/)
- 2017.07 [4hou] [绕过AppLocker系列之MSBuild的利用](http://www.4hou.com/system/5739.html)
- 2017.07 [evi1cg] [Bypass AppLocker With MSXSL.EXE](https://evi1cg.me/archives/AppLocker_Bypass_MSXSL.html)
- 2017.07 [pentestlab] [AppLocker Bypass – CreateRestrictedToken](https://pentestlab.blog/2017/07/07/applocker-bypass-createrestrictedtoken/)
- 2017.07 [pentestlab] [AppLocker Bypass – MSXSL](https://pentestlab.blog/2017/07/06/applocker-bypass-msxsl/)
- 2017.06 [4hou] [绕过AppLocker系列之Rundll32的利用](http://www.4hou.com/technology/5737.html)
- 2017.06 [aliyun] [绕过AppLocker系列之MSIEXEC的利用](https://xz.aliyun.com/t/1101)
- 2017.06 [4hou] [绕过AppLocker系列之MSIEXEC的利用](http://www.4hou.com/technology/5612.html)
- 2017.06 [360] [AppLocker绕过之文件拓展名](https://www.anquanke.com/post/id/86290/)
- 2017.06 [pentestlab] [AppLocker Bypass – MSIEXEC](https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/)
- 2017.06 [4hou] [看我如何利用文件扩展名绕过AppLocker？](http://www.4hou.com/info/news/5424.html)
- 2017.06 [pentestlab] [AppLocker Bypass – IEExec](https://pentestlab.blog/2017/06/13/applocker-bypass-ieexec/)
- 2017.06 [pentestlab] [AppLocker Bypass – File Extensions](https://pentestlab.blog/2017/06/12/applocker-bypass-file-extensions/)
- 2017.06 [pentestlab] [AppLocker Bypass – Assembly Load](https://pentestlab.blog/2017/06/06/applocker-bypass-assembly-load/)
- 2017.06 [pentestlab] [AppLocker Bypass – BgInfo](https://pentestlab.blog/2017/06/05/applocker-bypass-bginfo/)
- 2017.05 [pentestlab] [AppLocker Bypass – MSBuild](https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/)
- 2017.05 [freebuf] [利用Regsvr32绕过Applocker的限制策略](http://www.freebuf.com/articles/terminal/135391.html)
- 2017.05 [360] [如何通过修改注册表绕过AppLocker](https://www.anquanke.com/post/id/86149/)
- 2017.05 [pentestlab] [AppLocker Bypass – Control Panel](https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/)
- 2017.05 [pentestlab] [AppLocker Bypass – Rundll32](https://pentestlab.blog/2017/05/23/applocker-bypass-rundll32/)
- 2017.05 [pentestlab] [AppLocker Bypass – Weak Path Rules](https://pentestlab.blog/2017/05/22/applocker-bypass-weak-path-rules/)
- 2017.05 [pentestlab] [AppLocker Bypass – Regasm and Regsvcs](https://pentestlab.blog/2017/05/19/applocker-bypass-regasm-and-regsvcs/)
- 2017.05 [contextis] [Applocker Bypass via Registry Key Manipulation](https://www.contextis.com/blog/applocker-bypass-via-registry-key-manipulation)
- 2017.05 [] [AppLocker Bypass – InstallUtil](http://www.91ri.org/17058.html)
- 2017.05 [pentestlab] [AppLocker Bypass – Regsvr32](https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/)
- 2017.05 [pentestlab] [AppLocker Bypass – InstallUtil](https://pentestlab.blog/2017/05/08/applocker-bypass-installutil/)
- 2017.02 [4hou] [不可阻挡的PowerShell ：Red Teamer告诉你如何突破简单的AppLocker策略](http://www.4hou.com/technology/3273.html)
- 2016.11 [evi1cg] [Bypassing Applocker with msiexec](https://evi1cg.me/archives/Bypassing_Applocker_with_msiexec.html)
- 2016.09 [evi1cg] [Bypassing Applocker with MSBuild.exe](https://evi1cg.me/archives/ypassing_Applocker_with_MSBuild-exe.html)
- 2016.09 [evi1cg] [AppLocker Bypass Techniques](https://evi1cg.me/archives/AppLocker_Bypass_Techniques.html)
- 2016.05 [cybrary] [[podcast] Software Restriction Policies and Applocker](https://www.cybrary.it/2016/05/58518/)
- 2016.04 [360] [利用regsvr32可以绕过MS Applocker保护机制运行代码](https://www.anquanke.com/post/id/83825/)
- 2016.03 [malwarebytes] [Windows AppLocker: An Introduction](https://blog.malwarebytes.com/101/2016/03/windows-applocker-an-introduction/)
- 2016.01 [freebuf] [Applocker：Windows网络保护之应用程序控制策略](http://www.freebuf.com/sectool/93632.html)
- 2015.04 [p0w3rsh3ll] [Configure Applocker with Desired State Configuration](https://p0w3rsh3ll.wordpress.com/2015/04/02/configure-applocker-with-desired-state-configuration/)
- 2014.10 [pentestpartners] [Using Applocker to protect your users from themselves, and you from your users](https://www.pentestpartners.com/security-blog/using-applocker-to-protect-your-users-from-themselves-and-you-from-your-users/)
- 2014.08 [sans] [AppLocker Event Logs with OSSEC 2.8](https://isc.sans.edu/forums/diary/AppLocker+Event+Logs+with+OSSEC+28/18539/)
- 2012.02 [p0w3rsh3ll] [Working with Applocker and Filepath Rules](https://p0w3rsh3ll.wordpress.com/2012/02/08/working-with-applocker-and-filepath-rules/)
- 2012.01 [p0w3rsh3ll] [Working with GPO and Applocker](https://p0w3rsh3ll.wordpress.com/2012/01/14/working-with-gpo-and-applocker/)
- 2011.07 [zeltser] [AppLocker for Containing Windows Malware in the Enterprise](https://zeltser.com/applocker-for-malware-incident-response/)




***


## <a id="b478e9a9a324c963da11437d18f04998"></a>Tools


### <a id="f9fad1d4d1f0e871a174f67f63f319d8"></a>Recent Add




### <a id="518d80dfb8e9dda028d18ace1d3f3981"></a>Procmon


- [**9**Star][3y] [C#] [lowleveldesign/send2procmon](https://github.com/lowleveldesign/send2procmon) A command line tool that sends its input data to a running procmon instance.
- [**0**Star][6y] [Py] [ldh0227/pmonparser](https://github.com/ldh0227/pmonparser) Process Monitor Log File Parser (Only Input Support csv format)
- [**0**Star][8m] [Py] [xrkk/procmonlogfilter](https://github.com/xrkk/procmonlogfilter) 解析ProcessMonitor生成的日志，过滤有效信息，并导入IDA等工具中查看。（代码编写于2017年，此处仅做备份。）


### <a id="d90b60dc79837e06d8ba2a7ee1f109d3"></a>.NET


- [**12676**Star][14d] [C#] [0xd4d/dnspy](https://github.com/0xd4d/dnspy) .NET debugger and assembly editor
- [**9261**Star][11d] [C#] [icsharpcode/ilspy](https://github.com/icsharpcode/ilspy) .NET Decompiler
- [**3694**Star][27d] [C#] [0xd4d/de4dot](https://github.com/0xd4d/de4dot) .NET deobfuscator and unpacker.
- [**3263**Star][7m] [JS] [sindresorhus/speed-test](https://github.com/sindresorhus/speed-test) Test your internet connection speed and ping using speedtest.net from the CLI
- [**1657**Star][14d] [C#] [jbevain/cecil](https://github.com/jbevain/cecil) Cecil is a library to inspect, modify and create .NET programs and libraries.
- [**251**Star][1y] [C#] [brianhama/de4dot](https://github.com/brianhama/de4dot) .NET deobfuscator and unpacker.
- [**217**Star][11m] [C#] [rainwayapp/warden](https://github.com/rainwayapp/warden) Warden.NET is an easy to use process management library for keeping track of processes on Windows.
- [**173**Star][2m] [ASP] [lowleveldesign/debug-recipes](https://github.com/lowleveldesign/debug-recipes) My notes collected while debugging various .NET and Windows problems.
- [**70**Star][8m] [C#] [fsecurelabs/sharpcliphistory](https://github.com/FSecureLABS/SharpClipHistory) SharpClipHistory is a .NET application written in C# that can be used to read the contents of a user's clipboard history in Windows 10 starting from the 1809 Build.
- [**52**Star][16d] [C#] [9ee1/capstone.net](https://github.com/9ee1/capstone.net) .NET Core and .NET Framework binding for the Capstone Disassembly Framework


### <a id="6d2fe834b7662ecdd48c17163f732daf"></a>Environment Setup


- [**1521**Star][11m] [PS] [joefitzgerald/packer-windows](https://github.com/joefitzgerald/packer-windows) Windows templates that can be used to create boxes for Vagrant using Packer
- [**1347**Star][1m] [Go] [securitywithoutborders/hardentools](https://github.com/securitywithoutborders/hardentools) Hardentools is a utility that disables a number of risky Windows features.
- [**1156**Star][1y] [HTML] [nsacyber/windows-secure-host-baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline) Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings. #nsacyber
- [**1008**Star][6m] [adolfintel/windows10-privacy](https://github.com/adolfintel/windows10-privacy) Windows 10 Privacy Guide
- [**508**Star][17d] [PS] [stefanscherer/packer-windows](https://github.com/stefanscherer/packer-windows) Windows Templates for Packer: Win10, Server 2016, 1709, 1803, 1809, 2019, 1903, 1909, Insider with Docker


### <a id="8bfd27b42bb75956984994b3419fb582"></a>Process Injection




### <a id="1c6069610d73eb4246b58d78c64c9f44"></a>Code Injection




### <a id="7c1541a69da4c025a89b0571d8ce73d2"></a>Memory Module




### <a id="19cfd3ea4bd01d440efb9d4dd97a64d0"></a>VT&&Hypbervisor


- [**1348**Star][22d] [C] [intel/haxm](https://github.com/intel/haxm)  cross-platform hardware-assisted virtualization engine (hypervisor), widely used as an accelerator for Android Emulator and QEMU
- [**1011**Star][1y] [C] [ionescu007/simplevisor](https://github.com/ionescu007/simplevisor) a simple, portable, Intel VT-x hypervisor with two specific goals: using the least amount of assembly code (10 lines), and having the smallest amount of VMX-related code to support dynamic hyperjacking and unhyperjacking (that is, virtualizing the host state from within the host). It works on Windows and UEFI.
- [**717**Star][23d] [C++] [tandasat/hyperplatform](https://github.com/tandasat/hyperplatform) Intel VT-x based hypervisor aiming to provide a thin VM-exit filtering platform on Windows.
- [**570**Star][12m] [C] [asamy/ksm](https://github.com/asamy/ksm) A fast, hackable and simple x64 VT-x hypervisor for Windows and Linux. Builtin userspace sandbox and introspection engine.
    - Also In Section: [Linux->Tools->Recent Add](#203d00ef3396d68f5277c90279f4ebf3) |
- [**449**Star][3y] [POV-Ray SDL] [hzqst/syscall-monitor](https://github.com/hzqst/syscall-monitor)  a system monitor program (like Sysinternal's Process Monitor) using Intel VT-X/EPT for Windows7+
    - Also In Section: [Windows->Tools->SystemCall](#d295182c016bd9c2d5479fe0e98a75df) |
- [**189**Star][10m] [C++] [kelvinhack/khypervisor](https://github.com/kelvinhack/khypervisor) kHypervisor is a lightweight bluepill-like nested VMM for Windows, it provides and emulating a basic function of Intel VT-x


### <a id="c3cda3278305549f4c21df25cbf638a4"></a>Kernel&&Driver


- [**933**Star][9m] [C] [microsoft/windows-driver-frameworks](https://github.com/microsoft/windows-driver-frameworks) a set of libraries that make it simple to write high-quality device drivers.
- [**781**Star][19d] [axtmueller/windows-kernel-explorer](https://github.com/axtmueller/windows-kernel-explorer) A free but powerful Windows kernel research tool.
- [**510**Star][5m] [Py] [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus) Tool for exploration and tracing of the Windows kernel
- [**479**Star][1m] [C] [jkornev/hidden](https://github.com/jkornev/hidden) Windows driver with usermode interface which can hide objects of file-system and registry, protect processes and etc
- [**325**Star][2y] [Rust] [pravic/winapi-kmd-rs](https://github.com/pravic/winapi-kmd-rs) Windows Kernel-Mode Drivers written in Rust
- [**278**Star][2y] [C++] [sam-b/windows_kernel_address_leaks](https://github.com/sam-b/windows_kernel_address_leaks) Examples of leaking Kernel Mode information from User Mode on Windows
- [**278**Star][12d] [PS] [microsoftdocs/windows-driver-docs](https://github.com/MicrosoftDocs/windows-driver-docs) The official Windows Driver Kit documentation sources
- [**232**Star][4y] [C] [markjandrews/wrk-v1.2](https://github.com/markjandrews/wrk-v1.2) Windows Research Kernel


### <a id="920b69cea1fc334bbc21a957dd0d9f6f"></a>Registry


- [**490**Star][14d] [Batchfile] [chef-koch/regtweaks](https://github.com/chef-koch/regtweaks) Windows Registry Tweaks (Win 7 - Win 10)
- [**288**Star][8m] [Py] [williballenthin/python-registry](https://github.com/williballenthin/python-registry) Read access to Windows Registry files.
- [**161**Star][1y] [msuhanov/regf](https://github.com/msuhanov/regf) Windows registry file format specification


### <a id="d295182c016bd9c2d5479fe0e98a75df"></a>SystemCall


- [**725**Star][2m] [HTML] [j00ru/windows-syscalls](https://github.com/j00ru/windows-syscalls) Windows System Call Tables (NT/2000/XP/2003/Vista/2008/7/2012/8/10)
- [**449**Star][3y] [POV-Ray SDL] [hzqst/syscall-monitor](https://github.com/hzqst/syscall-monitor)  a system monitor program (like Sysinternal's Process Monitor) using Intel VT-X/EPT for Windows7+
    - Also In Section: [Windows->Tools->VT](#19cfd3ea4bd01d440efb9d4dd97a64d0) |
- [**328**Star][2m] [C] [hfiref0x/syscalltables](https://github.com/hfiref0x/syscalltables) Windows NT x64 Syscall tables
- [**277**Star][2y] [Assembly] [tinysec/windows-syscall-table](https://github.com/tinysec/windows-syscall-table) windows syscall table from xp ~ 10 rs4


### <a id="1afda3039b4ab9a3a1f60b179ccb3e76"></a>Other


- [**1296**Star][4y] [C++] [microsoft/microsoft-pdb](https://github.com/microsoft/microsoft-pdb) Information from Microsoft about the PDB format. We'll try to keep this up to date. Just trying to help the CLANG/LLVM community get onto Windows.
- [**949**Star][3m] [C] [basil00/divert](https://github.com/basil00/divert) Windows Packet Divert
- [**863**Star][14d] [C++] [henrypp/simplewall](https://github.com/henrypp/simplewall) Simple tool to configure Windows Filtering Platform (WFP) which can configure network activity on your computer.
- [**726**Star][2m] [Py] [diyan/pywinrm](https://github.com/diyan/pywinrm) Python library for Windows Remote Management (WinRM)
- [**578**Star][3y] [Pascal] [t-d-k/librecrypt](https://github.com/t-d-k/librecrypt) Transparent on-the-fly disk encryption for Windows. LUKS compatible.
- [**570**Star][1m] [C] [hfiref0x/winobjex64](https://github.com/hfiref0x/winobjex64) Windows Object Explorer 64-bit
- [**463**Star][8m] [C#] [microsoft/dbgshell](https://github.com/microsoft/dbgshell) A PowerShell front-end for the Windows debugger engine.
- [**418**Star][15d] [C] [samba-team/samba](https://github.com/samba-team/samba) he standard Windows interoperability suite of programs for Linux and Unix
- [**405**Star][3y] [C++] [rwfpl/rewolf-wow64ext](https://github.com/rwfpl/rewolf-wow64ext) Helper library for x86 programs that runs under WOW64 layer on x64 versions of Microsoft Windows operating systems.
- [**403**Star][3y] [C#] [zenlulz/memorysharp](https://github.com/zenlulz/memorysharp) A C# based memory editing library targeting Windows applications, offering various functions to extract and inject data and codes into remote processes to allow interoperability.
- [**389**Star][2m] [C#] [microsoft/binskim](https://github.com/microsoft/binskim) A binary static analysis tool that provides security and correctness results for Windows Portable Executable and *nix ELF binary formats
- [**387**Star][19d] [Jupyter Notebook] [microsoft/windowsdefenderatp-hunting-queries](https://github.com/microsoft/windowsdefenderatp-hunting-queries) Sample queries for Advanced hunting in Microsoft Defender ATP
- [**370**Star][27d] [Ruby] [winrb/winrm](https://github.com/winrb/winrm) Ruby library for Windows Remote Management
- [**367**Star][1y] [PS] [netspi/pesecurity](https://github.com/netspi/pesecurity) PowerShell module to check if a Windows binary (EXE/DLL) has been compiled with ASLR, DEP, SafeSEH, StrongNaming, and Authenticode.
- [**360**Star][12d] [C#] [digitalruby/ipban](https://github.com/digitalruby/ipban)  Monitors failed logins and bad behavior and bans ip addresses on Windows and Linux. Highly configurable, lean and powerful.
- [**353**Star][2y] [C++] [zerosum0x0/winrepl](https://github.com/zerosum0x0/winrepl) x86 and x64 assembly "read-eval-print loop" shell for Windows
- [**318**Star][3y] [C] [sdhand/x11fs](https://github.com/sdhand/x11fs) A tool for manipulating X windows
- [**298**Star][3y] [C++] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools) a small suite of tools to test various symbolic link types of Windows
- [**289**Star][2y] [C++] [godaddy/procfilter](https://github.com/godaddy/procfilter) A YARA-integrated process denial framework for Windows
- [**281**Star][1y] [C++] [fireeye/flare-wmi](https://github.com/fireeye/flare-wmi) various documentation and code projects that describe the Windows Management Instrumentation (WMI) technology
- [**269**Star][12m] [Py] [hakril/pythonforwindows](https://github.com/hakril/pythonforwindows) A codebase aimed to make interaction with Windows and native execution easier
- [**238**Star][5m] [PS] [microsoft/aaronlocker](https://github.com/microsoft/aaronlocker) Robust and practical application whitelisting for Windows
- [**233**Star][10m] [Go] [masterzen/winrm](https://github.com/masterzen/winrm) Command-line tool and library for Windows remote command execution in Go
- [**232**Star][1y] [C++] [ionescu007/simpleator](https://github.com/ionescu007/simpleator) Simpleator ("Simple-ator") is an innovative Windows-centric x64 user-mode application emulator that leverages several new features that were added in Windows 10 Spring Update (1803), also called "Redstone 4", with additional improvements that were made in Windows 10 October Update (1809), aka "Redstone 5".
- [**229**Star][4m] [C] [tishion/mmloader](https://github.com/tishion/mmloader) A library for loading dll module bypassing windows PE loader from memory (x86/x64)
- [**228**Star][3m] [C] [leecher1337/ntvdmx64](https://github.com/leecher1337/ntvdmx64) Run Microsoft Windows NTVDM (DOS) on 64bit Editions
- [**226**Star][1y] [C++] [rexdf/commandtrayhost](https://github.com/rexdf/commandtrayhost) A command line program monitor systray for Windows
- [**222**Star][2y] [C++] [intelpt/windowsintelpt](https://github.com/intelpt/windowsintelpt) This driver implements the Intel Processor Trace functionality in Intel Skylake architecture for Microsoft Windows
- [**210**Star][3m] [adguardteam/adguardforwindows](https://github.com/adguardteam/adguardforwindows) AdGuard for Windows open bug tracker
- [**208**Star][10m] [C] [hzqst/unicorn_pe](https://github.com/hzqst/unicorn_pe) Unicorn PE is an unicorn based instrumentation project designed to emulate code execution for windows PE files.
- [**206**Star][3y] [C++] [k2/ehtrace](https://github.com/k2/ehtrace) ATrace is a tool for tracing execution of binaries on Windows.
- [**205**Star][3m] [C] [jasonwhite/ducible](https://github.com/jasonwhite/ducible) A tool to make Windows builds reproducible.
- [**202**Star][2y] [Py] [euske/pyrexecd](https://github.com/euske/pyrexecd) Standalone SSH server for Windows
- [**193**Star][11m] [C] [ionescu007/winipt](https://github.com/ionescu007/winipt) The Windows Library for Intel Process Trace (WinIPT) is a project that leverages the new Intel Processor Trace functionality exposed by Windows 10 Redstone 5 (1809), through a set of libraries and a command-line tool.
- [**192**Star][1m] [C++] [blackint3/openark](https://github.com/blackint3/openark) OpenArk is a open source anti-rookit(ARK) tool on Windows.
- [**192**Star][3y] [Ruby] [zed-0xff/pedump](https://github.com/zed-0xff/pedump) dump windows PE files using ruby
- [**174**Star][3y] [C#] [gangzhuo/kcptun-gui-windows](https://github.com/gangzhuo/kcptun-gui-windows) GUI for kcptun (
- [**171**Star][2m] [Py] [gleeda/memtriage](https://github.com/gleeda/memtriage) Allows you to quickly query a Windows machine for RAM artifacts
- [**164**Star][3y] [C++] [zer0mem0ry/runpe](https://github.com/zer0mem0ry/runpe) Code that allows running another windows PE in the same address space as the host process.
- [**163**Star][2m] [PS] [dsccommunity/activedirectorydsc](https://github.com/dsccommunity/ActiveDirectoryDsc) contains DSC resources for deployment and configuration of Active Directory.
- [**158**Star][7m] [C#] [wohlstand/destroy-windows-10-spying](https://github.com/wohlstand/destroy-windows-10-spying) Destroy Windows Spying tool
- [**151**Star][3y] [C] [pustladi/windows-2000](https://github.com/pustladi/windows-2000) Microsoft Windows 2000 Professional — (Source Codes)
- [**151**Star][2y] [Rust] [trailofbits/flying-sandbox-monster](https://github.com/trailofbits/flying-sandbox-monster)  sandboxes the Malware Protection engine in an AppContainer on Windows, written in Rust.
- [**149**Star][1y] [C++] [justasmasiulis/nt_wrapper](https://github.com/justasmasiulis/nt_wrapper) A wrapper library around native windows sytem APIs
- [**143**Star][11d] [C#] [microsoft/windowsprotocoltestsuites](https://github.com/microsoft/windowsprotocoltestsuites) Windows Protocol Test Suites provide interoperability testing against an implementation of the Windows open specifications.
- [**137**Star][4y] [Py] [pentestmonkey/pysecdump](https://github.com/pentestmonkey/pysecdump) Python-based tool to dump security information from Windows systems
- [**136**Star][6y] [C++] [zer0fl4g/nanomite](https://github.com/zer0fl4g/nanomite) Graphical Debugger for x64 and x86 on Windows
- [**135**Star][2m] [C] [nomorefood/putty-cac](https://github.com/nomorefood/putty-cac) Windows Secure Shell Client With Support For Smart Cards & Certificates
- [**134**Star][2y] [Py] [binarydefense/auto-ossec](https://github.com/binarydefense/auto-ossec)  automatically provision OSSEC agents for both Linux and Windows
- [**134**Star][7m] [CMake] [pothosware/pothossdr](https://github.com/pothosware/pothossdr) Pothos SDR windows development environment
- [**133**Star][1y] [C++] [3gstudent/eventlogedit-evtx--evolution](https://github.com/3gstudent/eventlogedit-evtx--evolution) Remove individual lines from Windows XML Event Log (EVTX) files
- [**133**Star][3y] [C++] [ioactive/i-know-where-your-page-lives](https://github.com/ioactive/i-know-where-your-page-lives) I Know Where Your Page Lives: Derandomizing the latest Windows 10 Kernel - ZeroNights 2016
- [**129**Star][2y] [Py] [dviros/rat-via-telegram](https://github.com/dviros/rat-via-telegram) Windows Remote Post Breach Tool via Telegram
- [**124**Star][5m] [Py] [fireeye/flare-qdb](https://github.com/fireeye/flare-qdb) Command-line and Python debugger for instrumenting and modifying native software behavior on Windows and Linux.
- [**116**Star][3y] [Batchfile] [bartblaze/disable-intel-amt](https://github.com/bartblaze/disable-intel-amt) Tool to disable Intel AMT on Windows
- [**115**Star][8m] [C++] [dragonquesthero/pubg-pak-hacker](https://github.com/dragonquesthero/pubg-pak-hacker) use windows kernel deriver hidden file and itself to Bypass BE
- [**114**Star][4y] [C++] [chengchengcc/ark-tools](https://github.com/chengchengcc/ark-tools) Windows Ark tools and demo
- [**111**Star][8m] [C] [wbenny/ksocket](https://github.com/wbenny/ksocket) KSOCKET provides a very basic example how to make a network connections in the Windows Driver by using WSK
- [**108**Star][2m] [PS] [powershell/windowscompatibility](https://github.com/powershell/windowscompatibility) Module that allows Windows PowerShell Modules to be used from PSCore6
- [**107**Star][1m] [Py] [ernw/windows-insight](https://github.com/ernw/windows-insight) The content of this repository aims to assist efforts on analysing inner working principles, functionalities, and properties of the Microsoft Windows operating system. This repository stores relevant documentation as well as executable files needed for conducting analysis studies.
- [**107**Star][5y] [C] [malwaretech/tinyxpb](https://github.com/malwaretech/tinyxpb) Windows XP 32-Bit Bootkit
- [**106**Star][2y] [C++] [zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) Hitch a free ride to Ring 0 on Windows
- [**105**Star][4m] [soffensive/windowsblindread](https://github.com/soffensive/windowsblindread) A list of files / paths to probe when arbitrary files can be read on a Microsoft Windows operating system
- [**105**Star][11m] [Py] [thelinuxchoice/pyrat](https://github.com/thelinuxchoice/pyrat) Windows Remote Administration Tool (RAT)
- [**104**Star][2y] [C++] [iceb0y/windows-container](https://github.com/iceb0y/windows-container) A lightweight sandbox for Windows application
- [**102**Star][3m] [C++] [giovannidicanio/winreg](https://github.com/giovannidicanio/winreg) Convenient high-level C++ wrapper around the Windows Registry API
- [**100**Star][2y] [C] [shellster/dcsyncmonitor](https://github.com/shellster/dcsyncmonitor) Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events.
- [**100**Star][2m] [C#] [tyranid/windowsrpcclients](https://github.com/tyranid/windowsrpcclients) This respository is a collection of C# class libraries which implement RPC clients for various versions of the Windows Operating System from 7 to Windows 10.
- [**98**Star][10d] [C] [libyal/libevtx](https://github.com/libyal/libevtx) Library and tools to access the Windows XML Event Log (EVTX) format
- [**97**Star][3y] [C++] [luctalpe/wmimon](https://github.com/luctalpe/wmimon) Tool to monitor WMI activity on Windows
- [**96**Star][2y] [PS] [australiancybersecuritycentre/windows_event_logging](https://github.com/australiancybersecuritycentre/windows_event_logging) Windows Event Forwarding subscriptions, configuration files and scripts that assist with implementing ACSC's protect publication, Technical Guidance for Windows Event Logging.
- [**96**Star][4y] [PS] [nsacyber/certificate-authority-situational-awareness](https://github.com/nsacyber/Certificate-Authority-Situational-Awareness) Identifies unexpected and prohibited certificate authority certificates on Windows systems. #nsacyber
- [**94**Star][11m] [PS] [equk/windows](https://github.com/equk/windows)  tweaks for Windows
- [**93**Star][2y] [C++] [kentonv/dvorak-qwerty](https://github.com/kentonv/dvorak-qwerty) "Dvorak-Qwerty ⌘" (DQ) keyboard layout for Windows and Unix/Linux/X
- [**89**Star][2y] [PS] [realparisi/wmi_monitor](https://github.com/realparisi/wmi_monitor) Log newly created WMI consumers and processes to the Windows Application event log
- [**89**Star][17d] [C++] [sinakarvandi/process-magics](https://github.com/sinakarvandi/process-magics) This is a collection of interesting codes about Windows Process creation.
- [**89**Star][22d] [C] [vigem/hidguardian](https://github.com/vigem/hidguardian) Windows kernel-mode driver for controlling access to various input devices.
- [**87**Star][1y] [PS] [deepzec/win-portfwd](https://github.com/deepzec/win-portfwd) Powershell script to setup windows port forwarding using native netsh client
- [**87**Star][8y] [C] [zoloziak/winnt4](https://github.com/zoloziak/winnt4) Windows NT4 Kernel Source code
- [**86**Star][1y] [C++] [malwaretech/appcontainersandbox](https://github.com/malwaretech/appcontainersandbox) An example sandbox using AppContainer (Windows 8+)
- [**86**Star][4y] [JS] [nsacyber/locklevel](https://github.com/nsacyber/LOCKLEVEL) A prototype that demonstrates a method for scoring how well Windows systems have implemented some of the top 10 Information Assurance mitigation strategies. #nsacyber
- [**84**Star][3y] [C++] [outflanknl/netshhelperbeacon](https://github.com/outflanknl/NetshHelperBeacon) Example DLL to load from Windows NetShell
- [**83**Star][1y] [Py] [silascutler/lnkparse](https://github.com/silascutler/lnkparse) Windows Shortcut file (LNK) parser
- [**82**Star][2m] [C] [0xcpu/winaltsyscallhandler](https://github.com/0xcpu/winaltsyscallhandler) Some research on AltSystemCallHandlers functionality in Windows 10 20H1 18999
- [**82**Star][5y] [C] [nukem9/virtualdbghide](https://github.com/nukem9/virtualdbghide) Windows kernel mode driver to prevent detection of debuggers.
- [**82**Star][2y] [Go] [snail007/autostart](https://github.com/snail007/autostart) autostart tools to set your application auto startup after desktop login,only for desktop version of linux , windows , mac.
- [**81**Star][13d] [C] [andreybazhan/symstore](https://github.com/andreybazhan/symstore) The history of Windows Internals via symbols.
- [**80**Star][3y] [C++] [cbayet/poolsprayer](https://github.com/cbayet/poolsprayer) Simple library to spray the Windows Kernel Pool
- [**80**Star][3y] [C++] [wpo-foundation/win-shaper](https://github.com/wpo-foundation/win-shaper) Windows traffic-shaping packet filter
- [**75**Star][1m] [C++] [sidyhe/dxx](https://github.com/sidyhe/dxx) Windows Kernel Driver with C++ runtime
- [**74**Star][2y] [C++] [eyeofra/winconmon](https://github.com/eyeofra/winconmon) Windows Console Monitoring
- [**72**Star][5y] [C#] [khr0x40sh/whitelistevasion](https://github.com/khr0x40sh/whitelistevasion) Collection of scripts, binaries and the like to aid in WhiteList Evasion on a Microsoft Windows Network.
- [**71**Star][10m] [PS] [iamrootsh3ll/anchorwatch](https://github.com/iamrootsh3ll/anchorwatch) A Rogue Device Detection Script with Email Alerts Functionality for Windows Subsystem
- [**70**Star][4y] [C++] [nccgroup/windowsdaclenumproject](https://github.com/nccgroup/windowsdaclenumproject) A collection of tools to enumerate and analyse Windows DACLs
- [**69**Star][11m] [PS] [itskindred/winportpush](https://github.com/itskindred/winportpush) A simple PowerShell utility used for pivoting into internal networks via a compromised Windows host.
- [**68**Star][20d] [C++] [nmgwddj/learn-windows-drivers](https://github.com/nmgwddj/learn-windows-drivers) Windows drivers 开发的各个基础示例，包含进程、内存、注册表、回调等管理
- [**68**Star][1m] [PS] [dsccommunity/certificatedsc](https://github.com/dsccommunity/CertificateDsc) This DSC Resource module can be used to simplify administration of certificates on a Windows Server.
- [**67**Star][4m] [Go] [0xrawsec/gene](https://github.com/0xrawsec/gene) Signature Engine for Windows Event Logs
- [**66**Star][2y] [C#] [parsingteam/teleshadow2](https://github.com/parsingteam/teleshadow2) TeleShadow - Telegram Desktop Session Stealer (Windows)
- [**66**Star][5y] [C++] [rwfpl/rewolf-dllpackager](https://github.com/rwfpl/rewolf-dllpackager) Simple tool to bundle windows DLLs with PE executable
- [**65**Star][8m] [C] [xiao70/x70fsd](https://github.com/xiao70/x70fsd) Windows file system filter drivers(minifilter) to encrypt, compress, or otherwise modify file-based data require some of the most complex kernel software developed for Windows.
- [**63**Star][6m] [PS] [rgl/windows-domain-controller-vagrant](https://github.com/rgl/windows-domain-controller-vagrant) Example Windows Domain Controller
- [**62**Star][3y] [C] [arvanaghi/windows-dll-injector](https://github.com/arvanaghi/windows-dll-injector) A basic Windows DLL injector in C using CreateRemoteThread and LoadLibrary. Implemented for educational purposes.
- [**62**Star][4y] [Py] [poorbillionaire/windows-prefetch-parser](https://github.com/poorbillionaire/windows-prefetch-parser) Parse Windows Prefetch files: Supports XP - Windows 10 Prefetch files
- [**62**Star][1y] [tyranid/windows-attacksurface-workshop](https://github.com/tyranid/windows-attacksurface-workshop) Workshop material for a Windows Attack Surface Analysis Workshop
- [**61**Star][5y] [C] [evilsocket/libpe](https://github.com/evilsocket/libpe) A C/C++ library to parse Windows portable executables written with speed and stability in mind.
- [**61**Star][3y] [C++] [maldevel/driver-loader](https://github.com/maldevel/driver-loader) Windows驱动加载器
- [**61**Star][1y] [Py] [srounet/pymem](https://github.com/srounet/pymem) A python library for windows, providing the needed functions to start working on your own with memory editing.
- [**61**Star][1y] [C++] [tandasat/debuglogger](https://github.com/tandasat/debuglogger) A software driver that lets you log kernel-mode debug output into a file on Windows.
- [**60**Star][3y] [PS] [kevin-robertson/conveigh](https://github.com/kevin-robertson/conveigh) Conveigh is a Windows PowerShell LLMNR/NBNS spoofer detection tool
- [**60**Star][2m] [Go] [konimarti/opc](https://github.com/konimarti/opc) OPC DA client in Golang for monitoring and analyzing process data based on Windows COM.
- [**59**Star][8d] [C++] [henrypp/errorlookup](https://github.com/henrypp/errorlookup) Simple tool for retrieving information about Windows errors codes.
- [**59**Star][4y] [Py] [psychomario/pyinject](https://github.com/psychomario/pyinject) A python module to help inject shellcode/DLLs into windows processes
- [**58**Star][5y] [C] [hackedteam/soldier-win](https://github.com/hackedteam/soldier-win) RCS Soldier for Windows
- [**57**Star][7m] [PS] [gnieboer/gnuradio_windows_build_scripts](https://github.com/gnieboer/gnuradio_windows_build_scripts) A series of Powershell scripts to automatically download, build from source, and install GNURadio and -all- it's dependencies as 64-bit native binaries then package as an msi using Visual Studio 2015
- [**57**Star][6y] [Assembly] [hackedteam/core-win64](https://github.com/hackedteam/core-win64) RCS Agent for Windows (64bit)
- [**57**Star][2y] [C#] [mch2112/sharp80](https://github.com/mch2112/sharp80) TRS80 Emulator for Windows
- [**55**Star][3y] [C#] [nccgroup/mnemosyne](https://github.com/nccgroup/mnemosyne) mnemosyne：通用Windows内存抓取工具
- [**55**Star][1y] [C#] [tyranid/windowsruntimesecuritydemos](https://github.com/tyranid/windowsruntimesecuritydemos) Demos for Presentation on Windows Runtime Security
- [**54**Star][26d] [Go] [giuliocomi/backoori](https://github.com/giuliocomi/backoori) Tool aided persistence via Windows URI schemes abuse
- [**53**Star][2y] [C#] [guardicore/azure_password_harvesting](https://github.com/guardicore/azure_password_harvesting) Plaintext Password harvesting from Azure Windows VMs
- [**53**Star][5y] [C++] [hackedteam/core-win32](https://github.com/hackedteam/core-win32) RCS Agent for Windows (32bit)
- [**52**Star][2m] [TSQL] [horsicq/xntsv](https://github.com/horsicq/xntsv) XNTSV program for detailed viewing of system structures for Windows.
- [**52**Star][1y] [PS] [pldmgg/winadmincenterps](https://github.com/pldmgg/winadmincenterps) Copy of Windows Admin Center (
- [**51**Star][1y] [C++] [tomladder/winlib](https://github.com/tomladder/winlib) Windows Manipulation Library (x64, User/Kernelmode)
- [**50**Star][7m] [C] [hfiref0x/mpenum](https://github.com/hfiref0x/mpenum) Enumerate Windows Defender threat families and dump their names according category
- [**50**Star][3y] [Py] [matthewdunwoody/block-parser](https://github.com/matthewdunwoody/block-parser) Parser for Windows PowerShell script block logs
- [**49**Star][3y] [Py] [dfirfpi/dpapilab](https://github.com/dfirfpi/dpapilab) Windows DPAPI laboratory
- [**49**Star][3y] [PS] [enclaveconsulting/crypto-pki](https://github.com/enclaveconsulting/crypto-pki) Scripts related to Windows cryptography and PKI.
- [**49**Star][7m] [C++] [0x00-0x00/cve-2019-0841-bypass](https://github.com/0x00-0x00/cve-2019-0841-bypass) A fully automatic CVE-2019-0841 bypass targeting all versions of Edge in Windows 10.
- [**48**Star][2y] [C++] [cherrypill/system_info](https://github.com/cherrypill/system_info) Hardware information tool for Windows
- [**48**Star][1m] [PS] [littl3field/audix](https://github.com/littl3field/audix) Audix is a PowerShell tool to quickly configure the Windows Event Audit Policies for security monitoring
- [**47**Star][7m] [Go] [hectane/go-acl](https://github.com/hectane/go-acl) Go library for manipulating ACLs on Windows
- [**47**Star][1y] [C++] [silica/sandbox](https://github.com/silica/sandbox) Application virtualization tool for Windows
- [**46**Star][6m] [C#] [ericzimmerman/prefetch](https://github.com/ericzimmerman/prefetch) Windows Prefetch parser. Supports all known versions from Windows XP to Windows 10.
- [**46**Star][2y] [C++] [nccgroup/psr](https://github.com/nccgroup/psr) Pointer Sequence Reverser - enable you to see how Windows C++ application is accessing a particular data member or object.
- [**46**Star][2m] [C#] [brunull/pace](https://github.com/brunull/pace) A Remote Access Tool for Windows.
- [**46**Star][13d] [Assembly] [borjamerino/windows-one-way-stagers](https://github.com/BorjaMerino/Windows-One-Way-Stagers) Windows Stagers to circumvent restrictive network environments
- [**45**Star][3y] [C] [gentilkiwi/basic_rpc](https://github.com/gentilkiwi/basic_rpc) Samples about Microsoft RPC and native API calls in Windows C
- [**45**Star][19d] [TSQL] [kacos2000/windowstimeline](https://github.com/kacos2000/windowstimeline) SQLite query & Powershell scripts to parse the Windows 10 (v1803+) ActivitiesCache.db
- [**45**Star][3y] [PS] [lazywinadmin/winformps](https://github.com/lazywinadmin/winformps) PowerShell functions for Windows Forms controls
- [**45**Star][28d] [C#] [damonmohammadbagher/nativepayload_reverseshell](https://github.com/damonmohammadbagher/nativepayload_reverseshell) This is Simple C# Source code to Bypass almost "all" AVS, (kaspersky v19, Eset v12 v13 ,Trend-Micro v16, Comodo & Windows Defender Bypassed via this method Very Simple)
- [**44**Star][14d] [Py] [technowlogy-pushpender/technowhorse](https://github.com/technowlogy-pushpender/technowhorse) TechNowHorse is a RAT (Remote Administrator Trojan) Generator for Windows/Linux systems written in Python 3.
- [**43**Star][9m] [C] [souhailhammou/drivers](https://github.com/souhailhammou/drivers) Windows Drivers
- [**42**Star][2y] [C] [nixawk/awesome-windows-debug](https://github.com/nixawk/awesome-windows-debug) Debug Windows Application / Kernel
- [**42**Star][7m] [Visual Basic .NET] [s1egesystems/ghostsquadhackers-javascript-encrypter-encoder](https://github.com/s1egesystems/ghostsquadhackers-javascript-encrypter-encoder) Encrypt/Encode your Javascript code. (Windows Scripting)
- [**42**Star][1y] [C++] [3gstudent/windows-eventlog-bypass](https://github.com/3gstudent/Windows-EventLog-Bypass) Use subProcessTag Value From TEB to identify Event Log Threads
- [**41**Star][3y] [PS] [sikkandar-sha/sec-audit](https://github.com/sikkandar-sha/sec-audit) PowerShell Script for Windows Server Compliance / Security Configuration Audit
- [**40**Star][1y] [Py] [mnrkbys/vss_carver](https://github.com/mnrkbys/vss_carver) Carves and recreates VSS catalog and store from Windows disk image.
- [**40**Star][6m] [Py] [silv3rhorn/artifactextractor](https://github.com/silv3rhorn/artifactextractor) Extract common Windows artifacts from source images and VSCs
- [**39**Star][3y] [C] [scubsrgroup/taint-analyse](https://github.com/scubsrgroup/taint-analyse) Windows平台下的细粒度污点分析工具
- [**39**Star][6m] [HTML] [sophoslabs/cve-2019-0888](https://github.com/sophoslabs/cve-2019-0888) PoC for CVE-2019-0888 - Use-After-Free in Windows ActiveX Data Objects (ADO)
- [**38**Star][1y] [C++] [3gstudent/eventlogedit-evt--general](https://github.com/3gstudent/eventlogedit-evt--general) Remove individual lines from Windows Event Viewer Log (EVT) files
- [**38**Star][5m] [C#] [nyan-x-cat/disable-windows-defender](https://github.com/nyan-x-cat/disable-windows-defender) Changing values to bypass windows defender C#
- [**38**Star][2y] [Py] [roothaxor/pystat](https://github.com/roothaxor/pystat) Advanced Netstat Using Python For Windows
- [**38**Star][3y] [C++] [yejiansnake/windows-sys-base](https://github.com/yejiansnake/windows-sys-base) windows 系统API C++封装库，包含进程间通讯，互斥，内存队列等通用功能
- [**37**Star][1y] [C++] [rokups/reflectiveldr](https://github.com/rokups/reflectiveldr) Position-idependent Windows DLL loader based on ReflectiveDLL project.
- [**36**Star][4y] [PS] [5alt/zerorat](https://github.com/5alt/zerorat) ZeroRAT是一款windows上的一句话远控
- [**36**Star][5y] [C++] [kkar/teamviewer-dumper-in-cpp](https://github.com/kkar/teamviewer-dumper-in-cpp) Dumps TeamViewer ID,Password and account settings from a running TeamViewer instance by enumerating child windows.
- [**36**Star][4y] [C++] [n3k/ekoparty2015_windows_smep_bypass](https://github.com/n3k/ekoparty2015_windows_smep_bypass) Windows SMEP Bypass U=S
- [**36**Star][1y] [C] [realoriginal/alpc-diaghub](https://github.com/realoriginal/alpc-diaghub) Utilizing the ALPC Flaw in combiniation with Diagnostics Hub as found in Server 2016 and Windows 10.
- [**35**Star][12d] [PS] [dsccommunity/xfailovercluster](https://github.com/dsccommunity/xFailOverCluster) This module contains DSC resources for deployment and configuration of Windows Server Failover Cluster.
- [**35**Star][7m] [PS] [swisscom/powergrr](https://github.com/swisscom/powergrr) PowerGRR is an API client library in PowerShell working on Windows, Linux and macOS for GRR automation and scripting.
- [**35**Star][6m] [C++] [parkovski/wsudo](https://github.com/parkovski/wsudo) Proof of concept sudo for Windows
- [**34**Star][5m] [C++] [blackint3/none](https://github.com/blackint3/none) UNONE and KNONE is a couple of open source base library that makes it easy to develop software on Windows.
- [**34**Star][1m] [C#] [ericzimmerman/appcompatcacheparser](https://github.com/ericzimmerman/appcompatcacheparser) AppCompatCache (shimcache) parser. Supports Windows 7 (x86 and x64), Windows 8.x, and Windows 10
- [**34**Star][1y] [PS] [ptylenda/kubernetes-for-windows](https://github.com/ptylenda/kubernetes-for-windows) Ansible playbooks and Packer templates for creating hybrid Windows/Linux Kubernetes 1.10+ cluster with experimental Flannel pod network (host-gw backend)
- [**34**Star][2y] [C++] [swwwolf/obderef](https://github.com/swwwolf/obderef) Decrement Windows Kernel for fun and profit
- [**34**Star][26d] [C] [zfigura/semblance](https://github.com/zfigura/semblance) Disassembler for Windows executables. Supports 16-bit NE (New Executable), MZ (DOS), and PE (Portable Executable, i.e. Win32) files.
- [**33**Star][2y] [Batchfile] [3gstudent/winpcap_install](https://github.com/3gstudent/winpcap_install) Auto install WinPcap on Windows(command line)
- [**33**Star][3y] [C++] [kingsunc/minidump](https://github.com/kingsunc/minidump) windows软件崩溃解决方案
- [**32**Star][3y] [C++] [ecologylab/ecotuiodriver](https://github.com/ecologylab/ecotuiodriver) Diver to convert tuio touch events into windows touch events. Started as GSoC 2012 project.
- [**32**Star][3y] [C++] [swwwolf/cbtest](https://github.com/swwwolf/cbtest) Windows kernel-mode callbacks tutorial driver
- [**31**Star][5m] [C] [csandker/inmemoryshellcode](https://github.com/csandker/inmemoryshellcode) A Collection of In-Memory Shellcode Execution Techniques for Windows
- [**31**Star][8y] [C] [hackedteam/driver-win64](https://github.com/hackedteam/driver-win64) Windows (64bit) agent driver
- [**31**Star][2y] [C++] [hsluoyz/rmtsvc](https://github.com/hsluoyz/rmtsvc) A web-based remote desktop & control service for Windows.
- [**30**Star][3y] [CSS] [botherder/flexikiller](https://github.com/botherder/flexikiller) flexikiller：移除FlexiSpy 木马（Windows/Mac）
- [**30**Star][2y] [C#] [modzero/mod0umleitung](https://github.com/modzero/mod0umleitung) modzero DNS Masquerading Server for Windows
- [**29**Star][7y] [Shell] [artemdinaburg/optimizevm](https://github.com/artemdinaburg/optimizevm) Make Windows VMs Faster
- [**29**Star][1y] [Py] [skelsec/windows_ad_dos_poc](https://github.com/skelsec/windows_ad_dos_poc) PoC code for crashing windows active directory
- [**29**Star][3y] [Py] [6e726d/pywiwi](https://github.com/6e726d/pywiwi) Python Windows Wifi
- [**28**Star][2y] [C] [bot-man-jl/wfp-traffic-redirection-driver](https://github.com/bot-man-jl/wfp-traffic-redirection-driver) WFP Traffic Redirection Driver is used to redirect NIC traffic on network layer and framing layer, based on Windows Filtering Platform (WFP).
- [**28**Star][2y] [defcon-russia/shortcut_auto_bind](https://github.com/defcon-russia/shortcut_auto_bind) Windows LNK/URL shortcut auto-binding hotkey (not a bug, feature)
- [**28**Star][8y] [C] [hackedteam/driver-win32](https://github.com/hackedteam/driver-win32) Windows (32bit) agent driver
- [**28**Star][4y] [C] [icewall/forcedelete](https://github.com/icewall/forcedelete) Windows driver including couple different techniques for file removal when regular operation isn't possible.
- [**28**Star][5y] [C++] [michael4338/tdi](https://github.com/michael4338/tdi) Windows Kernel Driver - Create a driver device in TDI layer of windows kernel to capture network data packets
- [**28**Star][10m] [C#] [raandree/managedpasswordfilter](https://github.com/raandree/managedpasswordfilter) Windows Password Filter that uses managed code internally
- [**27**Star][5m] [C#] [717021/pcmgr](https://github.com/717021/pcmgr) Windows 任务管理器重制版 A rebulid version for Windows task manager.
- [**27**Star][3y] [C++] [int0/ltmdm64_poc](https://github.com/int0/ltmdm64_poc) ltmdm64_poc：利用ltmdm64.sys 的漏洞绕过 Windows 7 SP1 x64 的代码完整性检查
- [**27**Star][7m] [C++] [slyd0g/timestomper](https://github.com/slyd0g/TimeStomper) PoC that manipulates Windows file times using SetFileTime() API
- [**27**Star][2y] [Py] [the404hacking/windows-python-rat](https://github.com/the404hacking/windows-python-rat) A New Microsoft Windows Remote Administrator Tool [RAT] with Python by Sir.4m1R.
- [**26**Star][7y] [C++] [avalon1610/lpc](https://github.com/avalon1610/lpc) windows LPC library
- [**26**Star][3y] [Pascal] [martindrab/vrtuletree](https://github.com/martindrab/vrtuletree) VrtuleTree is a tool that displays information about driver and device objects present in the system and relations between them. Its functionality is very similar to famous DeviceTree, however, VrtuleTree emhasises on stability and support of latest Windows versions
- [**26**Star][2y] [C++] [strikerx3/whvpclient](https://github.com/strikerx3/whvpclient) Windows Hypervisor Platform client
- [**26**Star][4y] [Py] [stratosphereips/stratospherewindowsips](https://github.com/stratosphereips/StratosphereWindowsIps) The Stratosphere IPS is a free software IPS that uses network behavior to detect and block malicious actions.
- [**25**Star][2y] [C++] [apriorit/custom-bootloader](https://github.com/apriorit/custom-bootloader) A demo tutorial for low-level and kernel developers - developing a custom Windows boot loader
- [**25**Star][6y] [C++] [dominictobias/detourxs](https://github.com/dominictobias/detourxs) A x86/64 library for detouring functions on Windows OS
- [**24**Star][4y] [C] [ltangjian/firewall](https://github.com/ltangjian/firewall) Based on the research of Windows network architecture and the core packet filtering firewall technology, using NDIS intermediate driver, the article achieved the filter of the core layer, and completed the Windows Personal Firewall Design and Implementation.
- [**24**Star][5y] [C++] [michael4338/ndis](https://github.com/michael4338/ndis) Windows Kernel Driver - Create a driver device in intermediate layer of Windows kernel based on NDIS, which communicates with and connect upper layer (user mode applications) and lower layer (miniport driver/network card). Create self-defined protocols for transmitting data and control communications by simulating very simple HTTP, TCP and ARP p…
- [**24**Star][1y] [Py] [rootm0s/casper](https://github.com/rootm0s/casper) 👻 Socket based RAT for Windows with evasion techniques and other features for control
- [**24**Star][4y] [C++] [thecybermind/ipredir](https://github.com/thecybermind/ipredir) IP redirection+NAT for Windows
- [**24**Star][3m] [C] [hypersine/windowssudo](https://github.com/HyperSine/WindowsSudo) A linux-like su/sudo on Windows. Transferred from
- [**23**Star][3y] [C] [hedgeh/sewindows](https://github.com/hedgeh/sewindows) 在Windows上建立一个开源的强制访问控制框架及SDK。使Windows平台的应用开发者，可以不用关心操作系统底层技术，只用进行简单的SDK调用或配置就可以保护自己的应用程序。
- [**23**Star][4y] [JS] [kolanich/cleanunwantedupdates](https://github.com/kolanich/cleanunwantedupdates) A set of scripts to detect updates of Microsoft (TM) Windows (TM) OS which harm users' privacy and uninstall them
- [**22**Star][1y] [C] [codereba/netmon](https://github.com/codereba/netmon) network filter driver that control network send speed, based on windows tdi framework.
- [**21**Star][4y] [C#] [adamcaudill/curvelock](https://github.com/adamcaudill/curvelock) Experimental File & Message Encryption for Windows
- [**21**Star][3y] [Visual Basic .NET] [appsecco/winmanipulate](https://github.com/appsecco/winmanipulate) A simple tool to manipulate window objects in Windows
- [**21**Star][2y] [C] [microwave89/drvtricks](https://github.com/microwave89/drvtricks) drvtriks kernel driver for Windows 7 SP1 and 8.1 x64, that tricks around in your system.
- [**21**Star][1y] [JS] [mindpointgroup/stig-cli](https://github.com/MindPointGroup/stig-cli) A CLI for perusing DISA STIG content Mac, Linux, and Windows Compatible
- [**20**Star][3y] [C++] [andrewgaspar/km-stl](https://github.com/andrewgaspar/km-stl) A drop-in replacement for the C++ STL for kernel mode Windows drivers. The goal is to have implementations for things like the standard algorithms that don't require memory allocations or exceptions, and for implementations of type traits and other compile-time related headers. Full implementation of the STL is a non-goal.
- [**20**Star][7m] [C] [mtth-bfft/ntsec](https://github.com/mtth-bfft/ntsec) Standalone tool to explore the security model of Windows and its NT kernel. Use it to introspect privilege assignments and access right assignments, enumerate attack surfaces from the point of view of a sandboxed process, etc.
- [**20**Star][1m] [C++] [mullvad/libwfp](https://github.com/mullvad/libwfp) C++ library for interacting with the Windows Filtering Platform (WFP)
- [**20**Star][3y] [PS] [rasta-mouse/invoke-loginprompt](https://github.com/rasta-mouse/invoke-loginprompt) Invokes a Windows Security Login Prompt and outputs the clear text password.




***


## <a id="3939f5e83ca091402022cb58e0349ab8"></a>Posts&&Videos


### <a id="8e1344cae6e5f9a33e4e5718a012e292"></a>Recent Add




### <a id="fa89526db1f9373c57ea4ffa1ac8c39f"></a>DEP


- 2019.11 [aliyun] [ARM EXP 开发 - 绕过 DEP 执行 mprotect()](https://xz.aliyun.com/t/6750)
- 2019.07 [codingvision] [Bypassing ASLR and DEP - Getting Shells with pwntools](https://codingvision.net/security/bypassing-aslr-dep-getting-shells-with-pwntools)
- 2019.01 [fuzzysecurity] [MS13-009 Use-After-Free IE8 (DEP)](http://fuzzysecurity.com/exploits/20.html)
- 2019.01 [fuzzysecurity] [BlazeVideo HDTV Player 6.6 Professional SEH&DEP&ASLR](http://fuzzysecurity.com/exploits/11.html)
- 2019.01 [fuzzysecurity] [NCMedia Sound Editor Pro v7.5.1 SEH&DEP&ASLR](http://fuzzysecurity.com/exploits/16.html)
- 2019.01 [fuzzysecurity] [ALLMediaServer 0.8 SEH&DEP&ASLR](http://fuzzysecurity.com/exploits/15.html)
- 2018.12 [360] [CoolPlayer bypass DEP(CVE-2008-3408)分析](https://www.anquanke.com/post/id/167424/)
- 2018.09 [duo] [Weak Apple DEP Authentication Leaves Enterprises Vulnerable to Social Engineering Attacks and Rogue Devices](https://duo.com/blog/weak-apple-dep-authentication-leaves-enterprises-vulnerable-to-social-engineering-attacks-and-rogue-devices)
- 2018.09 [3or] [ARM Exploitation - Defeating DEP - executing mprotect()](https://blog.3or.de/arm-exploitation-defeating-dep-executing-mprotect.html)
- 2018.09 [3or] [ARM Exploitation - Defeating DEP - execute system()](https://blog.3or.de/arm-exploitation-defeating-dep-execute-system.html)
- 2018.06 [pediy] [[原创]Easy MPEG to DVD Burner 1.7.11 SEH + DEP Bypass Local Buffer Overflow](https://bbs.pediy.com/thread-228537.htm)
- 2018.05 [pediy] [[翻译]DEP缓解技术(一)](https://bbs.pediy.com/thread-226625.htm)
- 2017.12 [360] [利用缓解技术：数据执行保护（DEP）](https://www.anquanke.com/post/id/91266/)
- 2017.12 [0x00sec] [Exploit Mitigation Techniques - Data Execution Prevention (DEP)](https://0x00sec.org/t/exploit-mitigation-techniques-data-execution-prevention-dep/4634/)
- 2017.10 [freebuf] [在64位系统中使用ROP+Return-to-dl-resolve来绕过ASLR+DEP](http://www.freebuf.com/articles/system/149364.html)
- 2017.10 [freebuf] [如何在32位系统中使用ROP+Return-to-dl来绕过ASLR+DEP](http://www.freebuf.com/articles/system/149214.html)
- 2017.08 [pediy] [[原创]利用Ret2Libc挑战DEP——利用ZwSetInformationProcess](https://bbs.pediy.com/thread-220346.htm)
- 2017.06 [360] [ropasaurusrex:ROP入门教程——DEP（下）](https://www.anquanke.com/post/id/86197/)
- 2017.06 [360] [ropasaurusrex:ROP入门教程——DEP（上）](https://www.anquanke.com/post/id/86196/)
- 2017.05 [myonlinesecurity] [fake clothing order Berhanu (PURCHASE DEPARTMENT) using winace files delivers Loki bot](https://myonlinesecurity.co.uk/fake-clothing-order-berhanu-purchase-department-using-winace-files-delivers-loki-bot/)
- 2017.04 [4hou] [Windows Shellcode学习笔记——利用VirtualAlloc绕过DEP](http://www.4hou.com/technology/4093.html)
- 2017.03 [4hou] [Windows Shellcode学习笔记——通过VirtualProtect绕过DEP](http://www.4hou.com/technology/3943.html)
- 2017.03 [3gstudent] [Windows Shellcode学习笔记——利用VirtualAlloc绕过DEP](https://3gstudent.github.io/3gstudent.github.io/Windows-Shellcode%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0-%E5%88%A9%E7%94%A8VirtualAlloc%E7%BB%95%E8%BF%87DEP/)
- 2017.03 [3gstudent] [Windows Shellcode学习笔记——利用VirtualAlloc绕过DEP](https://3gstudent.github.io/3gstudent.github.io/Windows-Shellcode%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0-%E5%88%A9%E7%94%A8VirtualAlloc%E7%BB%95%E8%BF%87DEP/)
- 2017.03 [pediy] [[原创]VUPlayer 2.49 - '.pls' Stack Buffer Overflow (Bypass DEP)](https://bbs.pediy.com/thread-216313.htm)
- 2017.03 [3gstudent] [Windows Shellcode学习笔记——通过VirtualProtect绕过DEP](https://3gstudent.github.io/3gstudent.github.io/Windows-Shellcode%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0-%E9%80%9A%E8%BF%87VirtualProtect%E7%BB%95%E8%BF%87DEP/)
- 2017.03 [3gstudent] [Windows Shellcode学习笔记——通过VirtualProtect绕过DEP](https://3gstudent.github.io/3gstudent.github.io/Windows-Shellcode%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0-%E9%80%9A%E8%BF%87VirtualProtect%E7%BB%95%E8%BF%87DEP/)
- 2016.11 [freebuf] [“优雅”的Linux漏洞：用罕见方式绕过ASLR和DEP保护机制](http://www.freebuf.com/articles/terminal/120911.html)
- 2016.03 [myonlinesecurity] [YOUR REFUND DEPOSIT COPY Lloyds Bank  – fake PDF malware](https://myonlinesecurity.co.uk/your-refund-deposit-copy-lloyds-bank-fake-pdf-malware/)
- 2016.03 [trendmicro] [Massive Malvertising Campaign in US Leads to Angler Exploit Kit/BEDEP](https://blog.trendmicro.com/trendlabs-security-intelligence/malvertising-campaign-in-us-leads-to-angler-exploit-kitbedep/)
- 2016.01 [pediy] [[翻译]Windows Exploit开发教程第九章-Exploitme3 (DEP)](https://bbs.pediy.com/thread-207043.htm)
- 2015.12 [ly0n] [MS08_067 exploit analysis – part II defeating DEP](https://paumunoz.tech/2015/12/30/ms08_067-exploit-analysis-part-ii-defeating-dep/)
- 2015.12 [ly0n] [MS08_067 exploit analysis – part II defeating DEP](http://ly0n.me/2015/12/30/ms08_067-exploit-analysis-part-ii-defeating-dep/)
- 2015.12 [freebuf] [利用Chakra JIT绕过DEP和CFG](http://www.freebuf.com/articles/system/89616.html)
- 2015.12 [conix] [CONIX participe au DEP 2015](http://blog.conix.fr/conix-participe-au-dep-2015/)
- 2015.12 [tencent] [利用Chakra JIT绕过DEP和CFG](https://xlab.tencent.com/cn/2015/12/09/bypass-dep-and-cfg-using-jit-compiler-in-chakra-engine/)
- 2015.11 [knapsy] [Easy File Sharing Web Server v7.2 - Remote SEH Buffer Overflow (DEP Bypass With ROP)](http://blog.knapsy.com/blog/2015/11/25/easy-file-sharing-web-server-v7-dot-2-remote-seh-buffer-overflow-dep-bypass-with-rop/)
- 2015.03 [trendmicro] [BEDEP: Backdoors Brought Into The Light By Flash Zero-Days](https://blog.trendmicro.com/trendlabs-security-intelligence/bedep-backdoors-brought-into-the-light-by-flash-zero-days/)
- 2015.02 [freebuf] [黄金搭档：安全研究人员发现Flash 0day漏洞与BEDEP病毒存在密切关联](http://www.freebuf.com/news/58781.html)
- 2015.02 [trendmicro] [BEDEP Malware Tied To Adobe Zero-Days](https://blog.trendmicro.com/trendlabs-security-intelligence/bedep-malware-tied-to-adobe-zero-days/)
- 2014.09 [ekoparty] [SAP SECURITY IN DEPTH en la #eko10](https://ekoparty.blogspot.com/2014/09/sap-security-in-depth-en-la-eko10.html)
- 2014.06 [netspi] [Verifying ASLR, DEP, and SafeSEH with PowerShell](https://blog.netspi.com/verifying-aslr-dep-and-safeseh-with-powershell/)
- 2014.03 [nsfocus] [Microsoft Silverlight DEP/ASLR安全保护机制绕过漏洞](http://www.nsfocus.net/index.php?act=advisory&do=view&adv_id=57)
- 2014.02 [tekwizz123] [Bypassing ASLR and DEP on Windows 7: The Audio Converter Case](http://tekwizz123.blogspot.com/2014/02/bypassing-aslr-and-dep-on-windows-7.html)
- 2013.11 [mcafee] [Solving the Mystery of the Office Zero-Day Exploit and DEP](https://securingtomorrow.mcafee.com/mcafee-labs/solving-the-mystery-of-the-office-zero-day-exploit-and-dep/)
- 2013.08 [pediy] [[原创]异想天开之文档格式漏洞ByPass ASLR+DEP](https://bbs.pediy.com/thread-177458.htm)
- 2013.05 [pediy] [[原创]DEP异常内核流程分析](https://bbs.pediy.com/thread-172034.htm)
- 2013.02 [corelan] [DEPS – Precise Heap Spray on Firefox and IE10](https://www.corelan.be/index.php/2013/02/19/deps-precise-heap-spray-on-firefox-and-ie10/)
- 2012.06 [sogeti] [Bypassing ASLR and DEP on Adobe Reader X](http://esec-lab.sogeti.com/posts/2012/06/22/bypassing-aslr-and-dep-on-adobe-reader-x.html)
- 2012.06 [a1logic] [Disable DEP and ASLR on Windows 7 64bit at compile time](https://www.a1logic.com/2012/06/14/disable-dep-and-aslr-on-windows-7-64bit-at-compile-time/)
- 2012.05 [freebuf] [Windows 8 DEP bypass](http://www.freebuf.com/vuls/450.html)
- 2012.02 [pediy] [[原创]利用stackpivot和ROP绕过ASLR+DEP学习笔记](https://bbs.pediy.com/thread-146321.htm)
- 2011.10 [dist67] [White Hat Shellcode Workshop: Enforcing Permanent DEP](https://www.youtube.com/watch?v=UUQz5JsWirI)
- 2011.08 [pediy] [[翻译]利用msvcr71.dll 与mona.py实现通用绕过DEP/ASLR](https://bbs.pediy.com/thread-139241.htm)
- 2011.07 [pediy] [[求助]safeseh和DEP都开启了,有办法破吗](https://bbs.pediy.com/thread-137468.htm)
- 2011.07 [corelan] [Universal DEP/ASLR bypass with msvcr71.dll and mona.py](https://www.corelan.be/index.php/2011/07/03/universal-depaslr-bypass-with-msvcr71-dll-and-mona-py/)
- 2011.03 [pediy] [[原创]Winamp Overflow Exploit (Win7 ASLR and DEP Bypass)](https://bbs.pediy.com/thread-131440.htm)
- 2011.01 [trendmicro] [Using Information Leakage to Avoid ASLR+DEP](https://blog.trendmicro.com/trendlabs-security-intelligence/using-information-leakage-to-avoid-aslrdep/)
- 2010.09 [pediy] [[翻译]Exploit 编写系列教程第十篇:用ROP束缚DEP-酷比魔方](https://bbs.pediy.com/thread-120952.htm)
- 2010.09 [immunityinc] [DEPLIB 2.0](https://www.immunityinc.com/downloads/DEPLIB20_ekoparty.pdf)
- 2010.06 [corelan] [Exploit writing tutorial part 10 : Chaining DEP with ROP – the Rubik’s[TM] Cube](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/)
- 2010.03 [trendmicro] [New Exploit Bypasses DEP](https://blog.trendmicro.com/trendlabs-security-intelligence/new-exploit-bypasses-aslr-and-dep/)
- 2009.12 [talosintelligence] [DEP and Heap Sprays](https://blog.talosintelligence.com/2009/12/dep-and-heap-sprays.html)
- 2009.12 [pediy] [[翻译]Exploit 编写系列教程第六篇 绕过Cookie,SafeSeh,HW DEP 和ASLR](https://bbs.pediy.com/thread-102719.htm)
- 2009.09 [corelan] [Exploit writing tutorial part 6 : Bypassing Stack Cookies, SafeSeh, SEHOP, HW DEP and ASLR](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)
- 2009.02 [pediy] [[原创]MS08-067通用bypass DEP的缓冲区溢出栈帧构造方法的学习](https://bbs.pediy.com/thread-81667.htm)
- 2008.11 [talosintelligence] [Fun with SSDT Hooks and DEP](https://blog.talosintelligence.com/2008/11/fun-with-ssdt-hooks-and-dep.html)
- 2008.11 [immunityinc] [DEPLIB](https://www.immunityinc.com/downloads/DEPLIB.pdf)


### <a id="af06263e9a92f6036dc5d4c4b28b9d8c"></a>Procmon


- 2017.06 [lowleveldesign] [How to decode managed stack frames in procmon traces](https://lowleveldesign.org/2017/06/23/how-to-decode-managed-stack-frames-in-procmon-traces/)
- 2017.02 [lowleveldesign] [When procmon trace is not enough](https://lowleveldesign.org/2017/02/20/when-procmon-trace-is-not-enough/)
- 2016.09 [dist67] [Malware: Process Explorer &  Procmon](https://www.youtube.com/watch?v=vq12OCVm2-o)
- 2015.06 [guyrleech] [Advanced Procmon Part 2 – Filtering inclusions](https://guyrleech.wordpress.com/2015/06/22/advanced-procmon-part-2-filtering-inclusions/)
- 2014.12 [guyrleech] [Advanced Procmon Part 1 – Filtering exclusions](https://guyrleech.wordpress.com/2014/12/25/advanced-procmon-part-1-filtering-exclusions/)




# <a id="dc664c913dc63ec6b98b47fcced4fdf0"></a>Linux


***


## <a id="a63015576552ded272a242064f3fe8c9"></a>ELF


### <a id="929786b8490456eedfb975a41ca9da07"></a>Tools


- [**930**Star][15d] [Py] [eliben/pyelftools](https://github.com/eliben/pyelftools) Parsing ELF and DWARF in Python
- [**787**Star][2m] [C] [nixos/patchelf](https://github.com/nixos/patchelf) A small utility to modify the dynamic linker and RPATH of ELF executables
- [**411**Star][9m] [Assembly] [mewmew/dissection](https://github.com/mewmew/dissection) The dissection of a simple "hello world" ELF binary.
- [**337**Star][9m] [Py] [rek7/fireelf](https://github.com/rek7/fireelf) Fileless Linux Malware Framework
- [**277**Star][4m] [Shell] [cryptolok/aslray](https://github.com/cryptolok/aslray) Linux ELF x32/x64 ASLR DEP/NX bypass exploit with stack-spraying
- [**233**Star][2m] [C] [elfmaster/libelfmaster](https://github.com/elfmaster/libelfmaster) Secure ELF parsing/loading library for forensics reconstruction of malware, and robust reverse engineering tools
- [**181**Star][4y] [C++] [jacob-baines/elfparser](https://github.com/jacob-baines/elfparser) Cross Platform ELF analysis
- [**163**Star][7m] [C++] [serge1/elfio](https://github.com/serge1/elfio) ELFIO - ELF (Executable and Linkable Format) reader and producer implemented as a header only C++ library
- [**155**Star][5y] [C] [arisada/midgetpack](https://github.com/arisada/midgetpack) midgetpack is a multiplatform secure ELF packer
- [**149**Star][2y] [C] [elfmaster/skeksi_virus](https://github.com/elfmaster/skeksi_virus) Devestating and awesome Linux X86_64 ELF Virus
- [**144**Star][2y] [C] [ixty/mandibule](https://github.com/ixty/mandibule) 向远程进程注入ELF文件
- [**140**Star][1y] [C++] [aclements/libelfin](https://github.com/aclements/libelfin) C++11 ELF/DWARF parser
- [**137**Star][4m] [Py] [tunz/binch](https://github.com/tunz/binch) A light ELF binary patch tool in python urwid
- [**133**Star][8m] [Rust] [aep/elfkit](https://github.com/aep/elfkit) rust elf parsing, manipulation and (re)linking toolkit
- [**123**Star][5y] [Py] [ucsb-seclab/leakless](https://github.com/ucsb-seclab/leakless) Function redirection via ELF tricks.
- [**111**Star][2y] [Go] [lloydlabs/elf-strings](https://github.com/lloydlabs/elf-strings)  read an ELF binary's string sections within a given binary. This is meant to be much like the strings UNIX utility, however is purpose built for ELF binaries.
- [**107**Star][5y] [C] [ioactive/melkor_elf_fuzzer](https://github.com/ioactive/melkor_elf_fuzzer) Melkor is a very intuitive and easy-to-use ELF file format fuzzer to find functional and security bugs in ELF parsers.
- [**73**Star][1y] [Ruby] [fbkcs/msf-elf-in-memory-execution](https://github.com/fbkcs/msf-elf-in-memory-execution) msf-elf-in-memory-execution: Metasploit模块, 用于在内存中执行ELF文件
- [**64**Star][5y] [Py] [sqall01/zwoelf](https://github.com/sqall01/zwoelf) An ELF parsing and manipulation library for Python
- [**61**Star][3y] [Assembly] [cranklin/cranky-data-virus](https://github.com/cranklin/cranky-data-virus) Educational virus written in Assembly that infects 32-bit ELF executables on Linux using the data segment infection method
- [**61**Star][2y] [Perl] [xlogicx/m2elf](https://github.com/xlogicx/m2elf) Converts Machine Code to x86 (32-bit) Linux executable (auto-wrapping with ELF headers)
- [**57**Star][7m] [Assembly] [guitmz/memrun](https://github.com/guitmz/memrun) Small tool to run ELF binaries from memory with a given process name
- [**56**Star][11m] [Py] [genymobile/copydeps](https://github.com/genymobile/copydeps) Analyze and copy library dependencies of ELF binaries
- [**55**Star][5y] [C] [anestisb/melkor-android](https://github.com/anestisb/melkor-android) An Android port of the melkor ELF fuzzer
- [**52**Star][1m] [C] [termux/termux-elf-cleaner](https://github.com/termux/termux-elf-cleaner) Utility to remove unused ELF sections causing warnings.
- [**50**Star][4y] [Py] [wapiflapi/wsym](https://github.com/wapiflapi/wsym) Adds symbols to a ELF file.
- [**47**Star][11m] [C] [imbushuo/boot-shim](https://github.com/imbushuo/boot-shim) Bootstraps ARM32/ARM64 ELF payloads on Qualcomm Windows platforms
- [**46**Star][8m] [Py] [capeleidokos/elf_diff](https://github.com/capeleidokos/elf_diff) A tool to compare ELF binaries
- [**45**Star][4m] [Py] [aencode/elf_analysis](https://github.com/aencode/elf_analysis) Perform Static and dynamic analysis on 32 bit ELF binary, and automate the process of stack based overflow exploitation.
- [**45**Star][6m] [C] [wangyinuo/fixelfsection](https://github.com/wangyinuo/fixelfsection) 
- [**44**Star][2y] [Py] [wizh/rop-chainer](https://github.com/wizh/rop-chainer) static program analysis tool that generates return-oriented exploits for ELF binaries
- [**41**Star][3y] [Py] [devttys0/botox](https://github.com/devttys0/botox) SIGSTOPing ELF binaries since 0x7E1
- [**41**Star][3y] [C] [jmpews/evilelf](https://github.com/jmpews/evilelf) Malicious use of ELF such as .so inject, func hook and so on.
- [**38**Star][2y] [C] [en14c/pivirus](https://github.com/en14c/pivirus) sample linux x86_64 ELF virus
- [**37**Star][3d] [C] [uclinux-dev/elf2flt](https://github.com/uclinux-dev/elf2flt) ELF to bFLT (binary flat) converter for no-mmu Linux targets
- [**36**Star][3y] [C++] [tartanllama/libelfin](https://github.com/tartanllama/libelfin) C++11 ELF/DWARF parser
- [**33**Star][3m] [Java] [fornwall/jelf](https://github.com/fornwall/jelf) ELF parsing library in java.
- [**29**Star][2m] [C] [martinribelotta/elfloader](https://github.com/martinribelotta/elfloader) ARMv7M ELF loader
- [**27**Star][2y] [Go] [namhyung/elftree](https://github.com/namhyung/elftree) ELF library dependency viewer
- [**26**Star][2m] [Ruby] [david942j/rbelftools](https://github.com/david942j/rbelftools) ELF parser library implemented in pure Ruby!
- [**23**Star][1m] [Haskell] [galoisinc/elf-edit](https://github.com/galoisinc/elf-edit) The elf-edit library provides a datatype suitable for reading and writing Elf files.
- [**22**Star][6y] [C] [t00sh/elf-poison](https://github.com/t00sh/elf-poison) Proof Of Concept for inserting code in ELF binaries.
- [**21**Star][3m] [Go] [tunz/binch-go](https://github.com/tunz/binch-go) A lightweight command-line ELF binary patch tool written in Go
- [**21**Star][3y] [C] [elemeta/elfloader](https://github.com/elemeta/elfloader) load so file into current memory space and run function
- [**20**Star][4m] [C] [en14c/erebus](https://github.com/en14c/erebus) Poc for ELF64 runtime infection via GOT poisoning technique by elfmaster
- [**18**Star][6y] [C] [depierre/pts](https://github.com/depierre/pts) Packer for PE and ELF, 32 and 64bits.
- [**13**Star][2y] [Go] [guitmz/gocave](https://github.com/guitmz/gocave) Finding code caves in ELF files with GoLang
- [**12**Star][8m] [Go] [guitmz/ezuri](https://github.com/guitmz/ezuri) A Simple Linux ELF Runtime Crypter
- [**9**Star][2y] [Nim] [guitmz/nim-cephei](https://github.com/guitmz/nim-cephei) Probably the first ELF binary infector ever created in Nim.
- [**9**Star][4y] [C] [sugawaray/efiboot](https://github.com/sugawaray/efiboot) A tool to execute an elf binary in the UEFI shell environment.
- [**7**Star][2y] [C] [mfaerevaag/elfinjector](https://github.com/mfaerevaag/elfinjector) Code injector for ELF binaries (incl. PIE)
- [**7**Star][29d] [C] [colortear/elf-packer](https://github.com/colortear/elf-packer) Encrypts 64-bit elf files that decrypt at runtime.
- [**5**Star][8m] [PHP] [ircmaxell/php-elf-symbolresolver](https://github.com/ircmaxell/php-elf-symbolresolver) A linux object file (ELF) parser
- [**4**Star][2m] [C] [adwait1-g/parsemyelf](https://github.com/adwait1-g/parsemyelf) A bunch of tools which help in understanding ELF binaries better
- [**4**Star][2y] [C] [efidroid/modules_elf2efi](https://github.com/efidroid/modules_elf2efi) convert statically linked ELF binaries to PE images for UEFI
- [**2**Star][9m] [Py] [capeleidokos/leidokos-changereport](https://github.com/capeleidokos/leidokos-changereport) Generates change reports with elf_diff for the Kaleidoscope firmware
- [**2**Star][2y] [C] [youben11/parself](https://github.com/youben11/parself) Yet another elf parser
- [**2**Star][1y] [C] [tyoma/symreader](https://github.com/tyoma/symreader) C++ ELF parser
- [**1**Star][5y] [c] [renorobert/core2elf](https://bitbucket.org/renorobert/core2elf) 


### <a id="72d101d0f32d5521d5d305e7e653fdd3"></a>Post


- 2019.10 [aliyun] [64 位 elf 的 one_gadget 通杀思路](https://xz.aliyun.com/t/6598)
- 2019.10 [HackersOnBoard] [AFL's Blindspot and How to Resist AFL Fuzzing for Arbitrary ELF Binaries](https://www.youtube.com/watch?v=fhNNPJVlj4A)
- 2019.10 [HackersOnBoard] [Black Hat USA 2016 Intra-Process Memory Protection for App on ARM & X86 Leveraging the ELF ABI](https://www.youtube.com/watch?v=IeBrb1-AtOk)
- 2019.09 [freebuf] [CVE-2018-6924：解析FreeBSD ELF 头导致内核内存泄露](https://www.freebuf.com/vuls/213345.html)
- 2019.07 [quarkslab] [CVE-2018-6924: FreeBSD ELF Header Parsing Kernel Memory Disclosure](https://blog.quarkslab.com/cve-2018-6924-freebsd-elf-header-parsing-kernel-memory-disclosure.html)
- 2019.07 [trendmicro] [A Quick and Efficient Method For Locating the main() function of Linux ELF Malware Variants](https://blog.trendmicro.com/trendlabs-security-intelligence/a-quick-and-efficient-method-for-locating-the-main-function-of-linux-elf-malware-variants/)
- 2019.05 [0x00sec] [Doubt infect ELF](https://0x00sec.org/t/doubt-infect-elf/13605/)
- 2019.04 [guitmz] [Linux ELF Runtime Crypter](https://www.guitmz.com/linux-elf-runtime-crypter/)
- 2019.03 [guitmz] [Running ELF executables from memory](https://www.guitmz.com/running-elf-from-memory/)
- 2019.02 [icyphox] [Python for Reverse Engineering #1: ELF Binaries](https://medium.com/p/e31e92c33732)
- 2019.01 [aliyun] [圣诞老人的ELFs：在没有execve的情况下运行Linux可执行文件](https://xz.aliyun.com/t/3856)
- 2019.01 [freebuf] [Pwntools之DynELF原理探究](https://www.freebuf.com/news/193646.html)
- 2019.01 [rapid7] [Santa's ELFs: Running Linux Executables Without execve](https://blog.rapid7.com/2019/01/03/santas-elfs-running-linux-executables-without-execve/)
- 2018.12 [360] [Linux系统内存执行ELF的多种方式](https://www.anquanke.com/post/id/168791/)
- 2018.12 [ZeroNights] [Yaroslav Moskvin - ELF execution in Linux RAM](https://www.youtube.com/watch?v=Q23nuzZ5YJI)
- 2018.11 [k3170makan] [Introduction to the ELF Format (Part VII): Dynamic Linking / Loading and the .dynamic section](http://blog.k3170makan.com/2018/11/introduction-to-elf-format-part-vii.html)
- 2018.10 [k3170makan] [Introduction to the ELF Format (Part VI) : More Relocation tricks - r_addend execution (Part 3)](http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-vi-more.html)
- 2018.10 [k3170makan] [Introduction to The ELF Format (Part VI): The Symbol Table and Relocations (Part 2)](http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-vi_18.html)
- 2018.10 [k3170makan] [Introduction to the ELF Format (Part VI) : The Symbol Table and Relocations (Part 1)](http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-vi.html)
- 2018.10 [k3170makan] [Introduction to the ELF Format (Part V) : Understanding C start up .init_array and .fini_array sections](http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-v.html)
- 2018.10 [k3170makan] [Introduction to The ELF Format (Part IV): Exploring Section Types and Special Sections](http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-iv.html)
- 2018.09 [k3170makan] [Introduction to the ELF File Format (Part III) : The Section Headers](http://blog.k3170makan.com/2018/09/introduction-to-elf-file-format-part.html)
- 2018.09 [k3170makan] [Introduction to the ELF Format Part II : Understanding Program Headers](http://blog.k3170makan.com/2018/09/introduction-to-elf-format-part-ii.html)
- 2018.09 [k3170makan] [Introduction to the ELF Format : The ELF Header (Part I)](http://blog.k3170makan.com/2018/09/introduction-to-elf-format-elf-header.html)
- 2018.08 [intezer] [Intezer Analyze™ ELF Support Release: Hakai Variant Case Study](https://www.intezer.com/elf-support-released-hakai-malware/)
- 2018.08 [0x00sec] [Issues with elf file injection tutorial by pico](https://0x00sec.org/t/issues-with-elf-file-injection-tutorial-by-pico/8029/)
- 2018.08 [knapsy] [FileVault CTF Challenge - ELF X64 Buffer Overflow](https://blog.knapsy.com/blog/2018/08/05/filevault-ctf-challenge-elf-x64-buffer-overflow/)
- 2018.06 [0x00sec] [Dissecting and exploiting ELF files](https://0x00sec.org/t/dissecting-and-exploiting-elf-files/7267/)
- 2018.05 [advancedpersistentjest] [Writeups – ELF Crumble (DEFCON Quals)](https://advancedpersistentjest.com/2018/05/14/writeups-elf-crumble-defcon-quals/)
- 2018.04 [aliyun] [ELF病毒分析](https://xz.aliyun.com/t/2254)
- 2018.03 [360] [如何Fuzz ELF文件中的任意函数](https://www.anquanke.com/post/id/100801/)
- 2018.01 [rekall] [ELF hacking with Rekall](http://blog.rekall-forensic.com/2018/01/elf-hacking-with-rekall.html)
- 2018.01 [blahcat] [Fuzzing arbitrary functions in ELF binaries](http://blahcat.github.io/2018/03/11/fuzzing-arbitrary-functions-in-elf-binaries/)
- 2018.01 [pediy] [[翻译]GNU Hash ELF Sections](https://bbs.pediy.com/thread-223668.htm)
- 2017.12 [blackhillsinfosec] [A Holiday Tale of Two Teams: The Blue Team Barbie & Red Team Elf on the Shelf saga](https://www.blackhillsinfosec.com/holiday-tale-two-teams-blue-team-barbie-red-team-elf-shelf-saga/)
- 2017.10 [pediy] [[翻译]自己动手编写一个Linux调试器系列之4 ELF文件格式与DWARF调试格式 by lantie@15PB](https://bbs.pediy.com/thread-221957.htm)
- 2017.09 [guitmz] [More fun with ELF files and GoLang - Code Caves](https://www.guitmz.com/more-fun-with-elf-files-and-golang-code-caves/)
- 2017.07 [0x00sec] [[PatchMe] Playing With ELF Structures](https://0x00sec.org/t/patchme-playing-with-elf-structures/2750/)
- 2017.05 [freebuf] [分析静态编译加剥离的ELF文件的一些方法](http://www.freebuf.com/articles/terminal/134980.html)
- 2017.04 [veritas501] [【搬运】ELF如何摧毁圣诞](http://veritas501.space/2017/04/13/[%E6%90%AC%E8%BF%90]ELF%E5%A6%82%E4%BD%95%E6%91%A7%E6%AF%81%E5%9C%A3%E8%AF%9E/)
- 2016.12 [advancedpersistentjest] [Technique – Dumping ELF from Format String](https://advancedpersistentjest.com/2016/12/23/technique-dumping-elf-from-format-string/)
- 2016.12 [8090] [借助DynELF实现无libc的漏洞利用小结](http://www.8090-sec.com/archives/5957)
- 2016.12 [360] [借助DynELF实现无libc的漏洞利用小结](https://www.anquanke.com/post/id/85129/)
- 2016.12 [360] [一个 ELF 蠕虫分析](https://www.anquanke.com/post/id/85117/)
- 2016.10 [talosintelligence] [Hopper Disassembler ELF Section Header Size Code Execution Vulnerability](https://talosintelligence.com/vulnerability_reports/TALOS-2016-0222)
- 2016.10 [talosintelligence] [Vulnerability Spotlight: Hopper Disassembler ELF Section Header Size Code Execution](https://blog.talosintelligence.com/2016/10/hopper.html)
- 2016.09 [freebuf] [安卓ELF恶意软件深度分析](http://www.freebuf.com/articles/system/113964.html)
- 2016.07 [pediy] [[原创]ELF文件加密简单小工具源码](https://bbs.pediy.com/thread-211632.htm)
- 2016.06 [backtrace] [Exploiting ELF Expansion Variables](https://backtrace.io/blog/backtrace/exploiting-elf-expansion-variables/)
- 2016.06 [virusbulletin] [VB2015 paper: DDoS Trojan: A Malicious Concept that Conquered the ELF Format](https://www.virusbulletin.com/blog/2016/06/vb2015-paper-ddos-trojan-malicious-concept-conquered-elf-format1/)
- 2016.05 [0x00sec] [ELFun File Injector](https://0x00sec.org/t/elfun-file-injector/410/)
- 2016.04 [freebuf] [MMD-0053-2016：ELF/STD IRC Bot恶意软件分析](http://www.freebuf.com/articles/system/102432.html)
- 2016.04 [backtrace] [ELF shared library injection forensics](https://backtrace.io/blog/backtrace/elf-shared-library-injection-forensics/)
- 2016.04 [deepsec] [Return of the Penguin Challenge – ELF (?) Binary (?)](http://blog.deepsec.net/return-of-the-penguin-challenge-elf-binary/)
- 2016.02 [360] [MMD-0051-2016 – 小型ELF远程后门程序揭秘](https://www.anquanke.com/post/id/83446/)
- 2016.01 [n0where] [Cross Platform ELF Analysis: ELF Parser](https://n0where.net/cross-platform-elf-analysis-elf-parser)
- 2015.12 [toolswatch] [[New Tool] ELF Parser v1.4.0](http://www.toolswatch.org/2015/12/new-tool-elf-parser-v1-4-0/)
- 2015.11 [freebuf] [ELF反调试初探](http://www.freebuf.com/sectool/83509.html)
- 2015.09 [linux] [The 101 of ELF Binaries on Linux: Understanding and Analysis](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/)
- 2015.08 [pediy] [[原创]Android安全防御-ELF篇（简单总结）](https://bbs.pediy.com/thread-203611.htm)
- 2015.07 [pnfsoftware] [Android Dalvik, inside OAT, inside ELF](https://www.pnfsoftware.com/blog/android-oat-elf-jeb2-plugin/)
- 2015.07 [] [Execution of ELF](http://4ngelboy.blogspot.com/2016/10/execution-of-elf.html)
- 2015.06 [freebuf] [浅谈被加壳ELF文件的DUMP修复](http://www.freebuf.com/articles/system/69553.html)
- 2015.06 [v0ids3curity] [Rebuilding ELF from Coredump](https://www.voidsecurity.in/2015/06/rebuilding-elf-from-coredump.html)
- 2015.05 [freebuf] [浅谈被加壳ELF的调试](http://www.freebuf.com/articles/system/67927.html)
- 2015.05 [guitmz] [Having fun with ELF files and GoLang](https://www.guitmz.com/having-fun-with-elf-files-and-golang/)
- 2015.05 [evilsocket] [Android Native API Hooking With Library Injection and ELF Introspection.](https://www.evilsocket.net/2015/05/04/android-native-api-hooking-with-library-injecto/)
- 2015.02 [w00tsec] [Firmware Forensics: Diffs, Timelines, ELFs and Backdoors](https://w00tsec.blogspot.com/2015/02/firmware-forensics-diffs-timelines-elfs.html)
- 2014.12 [v0ids3curity] [Return to VDSO using ELF Auxiliary Vectors](https://www.voidsecurity.in/2014/12/return-to-vdso-using-elf-auxiliary.html)
- 2014.11 [ioactive] [ELF Parsing Bugs by Example  with Melkor Fuzzer](https://ioactive.com/elf-parsing-bugs-by-example-with-melkor-fuzzer/)
- 2014.10 [pediy] [[原创]基于Android的ELF PLT/GOT符号重定向过程及ELF Hook实现](https://bbs.pediy.com/thread-193720.htm)
- 2014.10 [allsoftwaresucks] [abusing Mesa by hooking ELFs and ioctl](http://allsoftwaresucks.blogspot.com/2014/10/abusing-mesa-by-hooking-elfs-and-ioctl.html)
- 2014.10 [pediy] [[原创]ELF DIY For Anddroid](https://bbs.pediy.com/thread-193279.htm)
- 2014.09 [pediy] [[原创]ELF section修复的一些思考](https://bbs.pediy.com/thread-192874.htm)
- 2014.09 [cerbero] [Stripping symbols from an ELF](http://cerbero-blog.com/?p=1494)
- 2014.07 [evilsocket] [Back From the Grave: ELF32 Universal Command Injector](https://www.evilsocket.net/2014/07/17/back-from-the-grave-elf32-universal-command-injector/)
- 2014.04 [pediy] [[原创]最近学习ELF结构，顺便写了个解析工具](https://bbs.pediy.com/thread-186445.htm)
- 2013.12 [jvns] [Day 42: How to run a simple ELF executable, from scratch (I don't know)](https://jvns.ca/blog/2013/12/13/day-42-how-to-run-an-elf-executable-i-dont-know/)
- 2013.12 [aassfxxx] [Hiding code in ELF binary](http://aassfxxx.infos.st/article25/hiding-code-in-elf-binary)
- 2013.11 [] [Autopsie d'un fichier ELF](http://0x90909090.blogspot.com/2013/11/autopsie-dun-fichier-elf.html)
- 2013.11 [cerbero] [ELF Support](http://cerbero-blog.com/?p=1404)
- 2013.10 [] [ajout de code à un binaire elf?](http://0x90909090.blogspot.com/2013/10/ajout-de-code-un-binaire-elf.html)
- 2013.10 [] [En tête ELF](http://0x90909090.blogspot.com/2013/10/en-tete-elf.html)
- 2013.09 [pediy] [[原创]LINUX ELF HOOK DEMO源码](https://bbs.pediy.com/thread-178320.htm)
- 2013.08 [pediy] [[原创]LINUX ELF文件动态加载调试](https://bbs.pediy.com/thread-178086.htm)
- 2013.08 [cerbero] [Dissecting an ELF with C++ Types](http://cerbero-blog.com/?p=1217)
- 2013.05 [aassfxxx] [Making ELF packer for fun and chocapicz (part 2)](http://aassfxxx.infos.st/article24/making-elf-packer-for-fun-and-chocapicz-part-2)
- 2013.05 [volatility] [MoVP II - 1.2 - VirtualBox ELF64 Core Dumps](https://volatility-labs.blogspot.com/2013/05/movp-ii-12-virtualbox-elf64-core-dumps.html)
- 2013.05 [aassfxxx] [Making ELF packer for fun and chocapicz](http://aassfxxx.infos.st/article23/making-elf-packer-for-fun-and-chocapicz)
- 2013.01 [dustri] [Screwing elf header for fun and profit](https://dustri.org/b/screwing-elf-header-for-fun-and-profit.html)
- 2012.10 [pediy] [[原创]一个ELF格式的脱壳破解记录](https://bbs.pediy.com/thread-157645.htm)
- 2012.09 [pediy] [[翻译]42字节可执行文件；ELF介绍；求Kx（四）](https://bbs.pediy.com/thread-156332.htm)
- 2011.11 [thireus] [execve("/bin//sh", ["/bin//sh"], NULL) - Linux elf32-i386](https://blog.thireus.com/execvebinsh-binsh-null/)
- 2011.07 [pediy] [关于ida调试android elf可执行文件](https://bbs.pediy.com/thread-137536.htm)
- 2010.03 [publicintelligence] [ELF/VLF Wave-injection and Magnetospheric Probing with HAARP](https://publicintelligence.net/elfvlf-wave-injection-and-magnetospheric-probing-with-haarp/)
- 2010.03 [publicintelligence] [Ionospheric modification and ELF/VLF wave generation by HAARP](https://publicintelligence.net/ionospheric-modification-and-elfvlf-wave-generation-by-haarp/)
- 2009.08 [evilcodecave] [SSH Malware Analysis – udp.pl, Juno and Stealth ELFs Reversing](https://evilcodecave.wordpress.com/2009/08/17/ssh-malware-analysis-udp-pl-juno-and-stealth-elfs-reversing/)
- 2008.11 [pediy] [[原创]手工打造ELF文件](https://bbs.pediy.com/thread-76967.htm)
- 2007.06 [mckeay] [This is clearly a Shadow Run Elf, not a Vulcan!](http://www.mckeay.net/2007/06/05/this-is-clearly-a-shadow-run-elf-not-a-vulcan/)
- 2007.03 [pediy] [[原创]无聊，发个 elf 压缩壳。](https://bbs.pediy.com/thread-40406.htm)
- 2005.11 [sans] [XML RPC worm - New Variant - ELF_LUPPER.B](https://isc.sans.edu/forums/diary/XML+RPC+worm+New+Variant+ELFLUPPERB/829/)
- 2005.01 [pediy] [关于ELF文件格式的实验](https://bbs.pediy.com/thread-9793.htm)




***


## <a id="89e277bca2740d737c1aeac3192f374c"></a>Tools


### <a id="203d00ef3396d68f5277c90279f4ebf3"></a>Recent Add


- [**1544**Star][2y] [C] [ezlippi/webbench](https://github.com/ezlippi/webbench) Webbench是Radim Kolar在1997年写的一个在linux下使用的非常简单的网站压测工具。它使用fork()模拟多个客户端同时访问我们设定的URL，测试网站在压力下工作的性能，最多可以模拟3万个并发连接去测试网站的负载能力。官网地址:
- [**1450**Star][2m] [C] [feralinteractive/gamemode](https://github.com/feralinteractive/gamemode) Optimise Linux system performance on demand
- [**1413**Star][21d] [C++] [google/nsjail](https://github.com/google/nsjail) A light-weight process isolation tool, making use of Linux namespaces and seccomp-bpf syscall filters (with help of the kafel bpf language)
- [**895**Star][29d] [C] [buserror/simavr](https://github.com/buserror/simavr) simavr is a lean, mean and hackable AVR simulator for linux & OSX
- [**759**Star][1m] [Py] [korcankaraokcu/pince](https://github.com/korcankaraokcu/pince) A reverse engineering tool that'll supply the place of Cheat Engine for linux
- [**741**Star][2m] [C] [yrp604/rappel](https://github.com/yrp604/rappel) A linux-based assembly REPL for x86, amd64, armv7, and armv8
- [**731**Star][17d] [C] [strace/strace](https://github.com/strace/strace) strace is a diagnostic, debugging and instructional userspace utility for Linux
- [**585**Star][3y] [C] [ktap/ktap](https://github.com/ktap/ktap) a new scripting dynamic tracing tool for Linux
- [**570**Star][12m] [C] [asamy/ksm](https://github.com/asamy/ksm) A fast, hackable and simple x64 VT-x hypervisor for Windows and Linux. Builtin userspace sandbox and introspection engine.
    - Also In Section: [Windows->Tools->VT](#19cfd3ea4bd01d440efb9d4dd97a64d0) |
- [**565**Star][12d] [C++] [intel/linux-sgx](https://github.com/intel/linux-sgx) Intel SGX for Linux*
- [**560**Star][2m] [Py] [autotest/autotest](https://github.com/autotest/autotest) Fully automated tests on Linux
- [**536**Star][5m] [C++] [nytrorst/shellcodecompiler](https://github.com/nytrorst/shellcodecompiler) compiles C/C++ style code into a small, position-independent and NULL-free shellcode for Windows (x86 and x64) and Linux (x86 and x64)
- [**509**Star][8m] [C] [iovisor/ply](https://github.com/iovisor/ply) Dynamic Tracing in Linux
- [**506**Star][3y] [C] [gaffe23/linux-inject](https://github.com/gaffe23/linux-inject) Tool for injecting a shared object into a Linux process
- [**468**Star][9d] [C] [libreswan/libreswan](https://github.com/libreswan/libreswan) an Internet Key Exchange (IKE) implementation for Linux.
- [**462**Star][2y] [C++] [aimtuxofficial/aimtux](https://github.com/aimtuxofficial/aimtux) A large Linux csgo cheat/hack
- [**441**Star][12d] [C] [facebook/openbmc](https://github.com/facebook/openbmc) OpenBMC is an open software framework to build a complete Linux image for a Board Management Controller (BMC).
- [**405**Star][10m] [Shell] [microsoft/linux-vm-tools](https://github.com/microsoft/linux-vm-tools) Hyper-V Linux Guest VM Enhancements
- [**393**Star][2m] [Shell] [yadominjinta/atilo](https://github.com/yadominjinta/atilo) Linux installer for termux
- [**355**Star][3y] [C] [adtac/fssb](https://github.com/adtac/fssb) A filesystem sandbox for Linux using syscall intercepts.
- [**354**Star][2m] [C] [seccomp/libseccomp](https://github.com/seccomp/libseccomp) an easy to use, platform independent, interface to the Linux Kernel's syscall filtering mechanism
- [**331**Star][5m] [Go] [capsule8/capsule8](https://github.com/capsule8/capsule8) cloud-native behavioral security monitoring
- [**318**Star][3y] [C] [chobits/tapip](https://github.com/chobits/tapip) user-mode TCP/IP stack based on linux tap device
- [**282**Star][2m] [Py] [facebook/fbkutils](https://github.com/facebook/fbkutils) A variety of utilities built and maintained by Facebook's Linux Kernel Team that we wish to share with the community.
- [**233**Star][2y] [C] [hardenedlinux/grsecurity-101-tutorials](https://github.com/hardenedlinux/grsecurity-101-tutorials) 增强 Linux 内核安全的内核补丁集
- [**228**Star][8m] [C] [wkz/ply](https://github.com/wkz/ply) Light-weight Dynamic Tracer for Linux
- [**203**Star][3y] [C] [google/kasan](https://github.com/google/kasan) KernelAddressSanitizer, a fast memory error detector for the Linux kernel
- [**199**Star][4y] [C] [dismantl/linux-injector](https://github.com/dismantl/linux-injector) Utility for injecting executable code into a running process on x86/x64 Linux
- [**192**Star][7m] [C] [andikleen/simple-pt](https://github.com/andikleen/simple-pt) Simple Intel CPU processor tracing on Linux
- [**173**Star][1m] [C] [netoptimizer/network-testing](https://github.com/netoptimizer/network-testing) Network Testing Tools for testing the Linux network stack
- [**147**Star][22d] [Shell] [hardenedlinux/debian-gnu-linux-profiles](https://github.com/hardenedlinux/debian-gnu-linux-profiles) Debian GNU/Linux based Services Profiles
- [**144**Star][15d] [Shell] [sclorg/s2i-python-container](https://github.com/sclorg/s2i-python-container) Python container images based on Red Hat Software Collections and intended for OpenShift and general usage, that provide a platform for building and running Python applications. Users can choose between Red Hat Enterprise Linux, Fedora, and CentOS based images.
- [**140**Star][7y] [C] [johnath/beep](https://github.com/johnath/beep) beep is a command line tool for linux that beeps the PC speaker
- [**139**Star][7m] [C] [dzzie/scdbg](https://github.com/dzzie/scdbg) note: current build is VS_LIBEMU project. This cross platform gcc build is for Linux users but is no longer updated. modification of the libemu sctest project to add basic debugger capabilities and more output useful for manual RE. The newer version will run under WINE
- [**133**Star][1m] [C] [arsv/minibase](https://github.com/arsv/minibase) small static userspace tools for Linux
- [**127**Star][10y] [C] [spotify/linux](https://github.com/spotify/linux) Spotify's Linux kernel for Debian-based systems
- [**122**Star][5m] [C] [dschanoeh/socketcand](https://github.com/dschanoeh/socketcand) A deprecated fork of socketcand. Please got to linux-can for the latest version.
- [**119**Star][2m] [Py] [containers/udica](https://github.com/containers/udica) This repository contains a tool for generating SELinux security profiles for containers
- [**116**Star][1y] [Shell] [fox-it/linux-luks-tpm-boot](https://github.com/fox-it/linux-luks-tpm-boot) A guide for setting up LUKS boot with a key from TPM in Linux
- [**109**Star][2m] [Py] [vstinner/python-ptrace](https://github.com/vstinner/python-ptrace) a debugger using ptrace (Linux, BSD and Darwin system call to trace processes) written in Python
- [**99**Star][2y] [Shell] [aoncyberlabs/cexigua](https://github.com/AonCyberLabs/Cexigua) Linux based inter-process code injection without ptrace(2)
- [**97**Star][7m] [Shell] [gavinlyonsrepo/cylon](https://github.com/gavinlyonsrepo/cylon) Updates, maintenance, backups and system checks in a TUI menu driven bash shell script for an Arch based Linux distro
- [**93**Star][6m] [Shell] [vincentbernat/eudyptula-boot](https://github.com/vincentbernat/eudyptula-boot) Boot a Linux kernel in a VM without a dedicated root filesystem.
- [**83**Star][2y] [C] [xobs/novena-linux](https://github.com/xobs/novena-linux) Linux kernel with Novena patches -- expect frequent rebases!
- [**77**Star][6m] [Py] [cybereason/linux_plumber](https://github.com/cybereason/linux_plumber) A python implementation of a grep friendly ftrace wrapper
- [**74**Star][3y] [Shell] [inquisb/unix-privesc-check](https://github.com/inquisb/unix-privesc-check) Shell script that runs on UNIX systems (tested on Solaris 9, HPUX 11, various Linux distributions, FreeBSD 6.2). It detects misconfigurations that could allow local unprivileged user to escalate to other users (e.g. root) or to access local apps (e.g. databases). This is a collaborative rework of version 1.0
- [**72**Star][7m] [C] [hc0d3r/alfheim](https://github.com/hc0d3r/alfheim) a linux process hacker tool
- [**70**Star][14d] [Shell] [sclorg/s2i-php-container](https://github.com/sclorg/s2i-php-container) PHP container images based on Red Hat Software Collections and intended for OpenShift and general usage, that provide a platform for building and running PHP applications. Users can choose between Red Hat Enterprise Linux, Fedora, and CentOS based images.
- [**68**Star][16d] [drduh/pc-engines-apu-router-guide](https://github.com/drduh/pc-engines-apu-router-guide) Guide to building a Linux or BSD router on the PC Engines APU platform
- [**68**Star][10d] [TS] [flathub/linux-store-frontend](https://github.com/flathub/linux-store-frontend) A web application to browse and install applications present in Flatpak repositories. Powers
- [**65**Star][3m] [Py] [archlinux/arch-security-tracker](https://github.com/archlinux/arch-security-tracker) Arch Linux Security Tracker
- [**65**Star][8d] [Shell] [mdrights/liveslak](https://github.com/mdrights/liveslak) 中文化的隐私加强 GNU/Linux 系统 - Forked from Alien Bob's powerful building script for Slackware Live.
- [**60**Star][2y] [C] [skeeto/ptrace-examples](https://github.com/skeeto/ptrace-examples) Examples for Linux ptrace(2)
- [**58**Star][2y] [Go] [evilsocket/ftrace](https://github.com/evilsocket/ftrace) Go library to trace Linux syscalls using the FTRACE kernel framework.
- [**58**Star][3m] [Java] [exalab/anlinux-adfree](https://github.com/exalab/anlinux-adfree) AnLinux, Ad free version.
- [**58**Star][3y] [CSS] [wizardforcel/sploitfun-linux-x86-exp-tut-zh](https://github.com/wizardforcel/sploitfun-linux-x86-exp-tut-zh) 
- [**54**Star][1y] [Py] [k4yt3x/defense-matrix](https://github.com/k4yt3x/defense-matrix) Express security essentials deployment for Linux Servers
- [**53**Star][10m] [C] [marcan/lsirec](https://github.com/marcan/lsirec) LSI SAS2008/SAS2108 low-level recovery tool for Linux
- [**52**Star][1y] [C] [pymumu/jail-shell](https://github.com/pymumu/jail-shell) Jail-shell is a linux security tool mainly using chroot, namespaces technologies, limiting users to perform specific commands, and access sepcific directories.
- [**49**Star][3m] [C] [thibault-69/rat-hodin-v2.9](https://github.com/Thibault-69/RAT-Hodin-v2.9) Remote Administration Tool for Linux
- [**49**Star][2y] [C] [cnlohr/wifirxpower](https://github.com/cnlohr/wifirxpower) Linux-based WiFi RX Power Grapher
- [**49**Star][3y] [Assembly] [t00sh/assembly](https://github.com/t00sh/assembly) Collection of Linux shellcodes
- [**45**Star][2y] [Go] [c-bata/systracer](https://github.com/c-bata/systracer) Yet another system call tracer written in Go.
- [**45**Star][6y] [JS] [cyberpython/wifiscanandmap](https://github.com/cyberpython/wifiscanandmap) A Linux Python application to create maps of 802.11 networks
- [**45**Star][4y] [C] [shadowsocks/iptables](https://github.com/shadowsocks/iptables) iptables is the userspace command line program used to configure the Linux 2.4.x and later packet filtering ruleset. It is targeted towards system administrators.
- [**44**Star][7m] [C] [junxzm1990/pomp](https://github.com/junxzm1990/pomp) 在 Linux 系统上开发 POMP 系统，分析崩溃后的 artifacts
- [**43**Star][6m] [Ruby] [b1ack0wl/linux_mint_poc](https://github.com/b1ack0wl/linux_mint_poc) 
- [**43**Star][2y] [C] [gcwnow/linux](https://github.com/gcwnow/linux) Linux kernel for GCW Zero (Ingenic JZ4770)
- [**41**Star][3y] [Py] [fnzv/trsh](https://github.com/fnzv/trsh) trsh：使用电报 API 与 Linux 服务器通信，Python编写。
- [**40**Star][11d] [Dockerfile] [ironpeakservices/iron-alpine](https://github.com/ironPeakServices/iron-alpine) Hardened alpine linux baseimage for Docker.
- [**39**Star][2m] [C] [stephenrkell/trap-syscalls](https://github.com/stephenrkell/trap-syscalls) Monitor, rewrite and/or otherwise trap system calls... on Linux/x86-64 only, for now.
- [**38**Star][3m] [PHP] [cesnet/pakiti-server](https://github.com/cesnet/pakiti-server) Pakiti provides a monitoring mechanism to check the patching status of Linux systems.
- [**35**Star][8y] [C] [sduverger/ld-shatner](https://github.com/sduverger/ld-shatner) ld-linux code injector
- [**34**Star][4m] [C] [peterbjornx/meloader](https://github.com/peterbjornx/meloader) Linux i386 tool to load and execute ME modules.
- [**34**Star][3y] [screetsec/dracos](https://github.com/screetsec/dracos) Dracos Linux (
- [**33**Star][2y] [C++] [cnrig/cnrig](https://github.com/cnrig/cnrig) Static CryptoNight CPU miner for Linux + automatic updates
- [**33**Star][3y] [Go] [egebalci/the-eye](https://github.com/egebalci/the-eye) Simple security surveillance script for linux distributions.
- [**33**Star][12m] [C] [p3n3troot0r/socketv2v](https://github.com/p3n3troot0r/socketv2v) Mainline Linux Kernel integration of IEEE 802.11p, IEEE 1609.{3,4}, and developmental userspace utility for using J2735 over WAVE
- [**32**Star][6m] [C] [jcsaezal/pmctrack](https://github.com/jcsaezal/pmctrack) an OS-oriented performance monitoring tool for Linux (
- [**32**Star][7y] [C] [nbareil/net2pcap](https://github.com/nbareil/net2pcap)  a simple network-to-pcap capture file for Linux. Its goal is to be as simple as possible to be used in hostile environments
- [**32**Star][1y] [C] [perceptionpoint/suprotect](https://github.com/perceptionpoint/suprotect) Changing memory protection in an arbitrary process
- [**32**Star][4y] [C] [a0rtega/bdldr](https://github.com/a0rtega/bdldr) bdldr is an unofficial engine loader for Bitdefender ® for Linux
- [**30**Star][2y] [PHP] [opt-oss/ng-netms](https://github.com/opt-oss/ng-netms) NG-NetMS is a new end-to-end network management platform for your Linux servers, Cisco, Juniper, HP and Extreme routers, switches and firewalls.
- [**27**Star][1m] [Shell] [adnanhodzic/anon-hotspot](https://github.com/adnanhodzic/anon-hotspot) On demand Debian Linux (Tor) Hotspot setup tool
- [**27**Star][2y] [Py] [morphuslabs/distinct](https://github.com/morphuslabs/distinct) Find potential Indicators of Compromise among similar Linux servers
- [**27**Star][2m] [C] [oracle/libdtrace-ctf](https://github.com/oracle/libdtrace-ctf) libdtrace-ctf is the Compact Type Format library used by DTrace on Linux
- [**27**Star][1y] [Py] [thesecondsun/pasm](https://github.com/thesecondsun/pasm) Linux assembler/disassembler based on Rasm2
- [**27**Star][5y] [Py] [bendemott/captiveportal](https://github.com/bendemott/captiveportal) A captive portal that can be used on most linux distributions.
- [**26**Star][12m] [C] [plutonium-dbg/plutonium-dbg](https://github.com/plutonium-dbg/plutonium-dbg) Kernel-based debugger for Linux applications
- [**26**Star][2m] [C] [oracle/dtrace-utils](https://github.com/oracle/dtrace-utils) DTrace-utils contains the Userspace portion of the DTrace port to Linux
- [**25**Star][8y] [aheadley/logitech-solar-k750-linux](https://github.com/aheadley/logitech-solar-k750-linux) Userspace "driver" for the Logitech k750 Solar Keyboard. A fork of the repo from
- [**24**Star][1y] [Py] [m4rktn/jogan](https://github.com/m4rktn/jogan) Pentest Tools & Packages Installer [Linux/Termux]
- [**23**Star][5y] [C++] [behzad-a/dytan](https://github.com/behzad-a/dytan) Dytan Taint Analysis Framework on Linux 64-bit
- [**23**Star][3y] [Py] [remnux/distro](https://github.com/remnux/distro) This repository contains supplementary files for building and using the REMnux Linux distribution. See
- [**23**Star][5y] [Assembly] [zerosum0x0/slae64](https://github.com/zerosum0x0/slae64) x64 Linux Shellcode
- [**22**Star][3y] [Shell] [johntroony/luks-ops](https://github.com/johntroony/luks-ops) A bash script to automate the most basic usage of LUKS volumes in Linux VPS
- [**22**Star][5y] [munmap/linux-kernel-bugs-db](https://github.com/munmap/linux-kernel-bugs-db) 
- [**21**Star][1y] [Py] [syno3/babymux](https://github.com/syno3/babymux) pentesting tool for noob hackers.Runs on linux and termux
- [**20**Star][3y] [C] [leixiangwu/cse509-rootkit](https://github.com/leixiangwu/cse509-rootkit) After attackers manage to gain access to a remote (or local) machine and elevate their privileges to "root", they typically want to maintain their access, while hiding their presence from the normal users and administrators of the system. This basic rootkit works on the Linux operating system and is a loadable kernel module which when loaded int…




***


## <a id="f6d78e82c3e5f67d13d9f00c602c92f0"></a>Post&&Videos


### <a id="bdf33f0b1200cabea9c6815697d9e5aa"></a>Recent Add






# Contribute
Contents auto exported by Our System, please raise Issue if you have any question.