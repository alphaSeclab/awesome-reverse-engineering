# Reverse Engineering


Reverse Engineering Resource Collection. 3000+ open source tools, ~600 blog posts.



# PS
[中文版本](https://github.com/alphaSeclab/awesome-reverse-engineering/blob/master/Readme.md)


# Directory
- [IDA](#08e59e476824a221f6e4a69c0bba7d63)
    - [Tools](#f11ab1ff46aa300cc3e86528b8a98ad7)
        - [(97) NoCategory](#c39a6d8598dde6abfeef43faf931beb5)
        - [Structure&&Class](#fb4f0c061a72fc38656691746e7c45ce)
            - [(6) NoCategory](#fa5ede9a4f58d4efd98585d3158be4fb)
            - [(8) C++Class&&VirtualTable](#4900b1626f10791748b20630af6d6123)
        - [(3) Collection](#a7dac37cd93b8bb42c7d6aedccb751b3)
        - [(9) Skin&&Theme](#fabf03b862a776bbd8bcc4574943a65a)
        - [(4) Firmware&&EmbedDevice](#a8f5db3ab4bc7bc3d6ca772b3b9b0b1e)
        - [Signature(FLIRT...)&&Diff&&Match](#02088f4884be6c9effb0f1e9a3795e58)
            - [(17) NoCategory](#cf04b98ea9da0056c055e2050da980c1)
            - [FLIRT](#19360afa4287236abe47166154bc1ece)
                - [(3) FLIRTSignatureCollection](#1c9d8dfef3c651480661f98418c49197)
                - [(2) FLIRTSignatureGenerate](#a9a63d23d32c6c789ca4d2e146c9b6d0)
            - [(11) Diff&&Match](#161e5a3437461dc8959cc923e6a18ef7)
            - [(7) Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a)
        - [(6) IDB](#5e91b280aab7f242cbc37d64ddbff82f)
        - [(5) CollaborativeRE](#206ca17fc949b8e0ae62731d9bb244cb)
        - [(9) SyncWithDebugger](#f7d311685152ac005cfce5753c006e4b)
        - [ImportExport&&SyncWithOtherTools](#6fb7e41786c49cc3811305c520dfe9a1)
            - [(13) NoCategory](#8ad723b704b044e664970b11ce103c09)
            - [(5) Ghidra](#c7066b0c388cd447e980bf0eb38f39ab)
            - [(3) BinNavi](#11139e7d6db4c1cef22718868f29fe12)
            - [(3) BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a)
            - [(2) Radare2](#21ed198ae5a974877d7a635a4b039ae3)
            - [(4) Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd)
            - [(2) IntelPin](#dd0332da5a1482df414658250e6357f8)
        - [SpecificTarget](#004c199e1dbf71769fbafcd8e58d1ead)
            - [(26) NoCategory](#5578c56ca09a5804433524047840980e)
            - [(2) GoLang](#1b17ac638aaa09852966306760fda46b)
            - [(4) WindowsDriver](#4c158ccc5aee04383755851844fdd137)
            - [(4) PS3&&PS4](#315b1b8b41c67ae91b841fce1d4190b5)
            - [(33) Loader&Processor](#cb59d84840e41330a7b5e275c0b81725)
            - [(4) PDB](#f5e51763bb09d8fd47ee575a98bedca1)
            - [(2) Flash&&SWF](#7d0681efba2cf3adaba2780330cd923a)
            - [(4) MalwareFamily](#841d605300beba45c3be131988514a03)
            - [(1) CTF](#ad44205b2d943cfa2fa805b2643f4595)
        - [IDAPython](#ad68872e14f70db53e8d9519213ec039)
            - [(8) NoCategory](#2299bc16945c25652e5ad4d48eae8eca)
            - [(1) cheatsheets](#c42137cf98d6042372b1fd43c3635135)
        - [(6) InstructRef&&Doc](#846eebe73bef533041d74fc711cafb43)
        - [ScriptWritting](#c08ebe5b7eec9fc96f8eff36d1d5cc7d)
            - [(9) NoCategory](#45fd7cfce682c7c25b4f3fbc4c461ba2)
            - [(3) Qt](#1a56a5b726aaa55ec5b7a5087d6c8968)
            - [(3) Console&&GUI](#1721c09501e4defed9eaa78b8d708361)
            - [(2) Template](#227fbff77e3a13569ef7b007344d5d2e)
            - [(2) OtherLang](#8b19bb8cf9a5bc9e6ab045f3b4fabf6a)
        - [(16) Ancient](#dc35a2b02780cdaa8effcae2b6ce623e)
        - [Debug&&DynamicData](#e3e7030efc3b4de3b5b8750b7d93e6dd)
            - [(10) NoCategory](#2944dda5289f494e5e636089db0d6a6a)
            - [(10) DBIData](#0fbd352f703b507853c610a664f024d1)
            - [(4) DebuggerData](#b31acf6c84a9506066d497af4e702bf5)
        - [(14) Decompiler&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9)
        - [(7) DeObfuscate](#7199e8787c0de5b428f50263f965fda7)
        - [Nav&&QuickAccess&&Graph&&Image](#fcf75a0881617d1f684bc8b359c684d7)
            - [(15) NoCategory](#c5b120e1779b928d860ad64ff8d23264)
            - [(9) GUIEnhencement](#03fac5b3abdbd56974894a261ce4e25f)
            - [(3) Graph](#3b1dba00630ce81cba525eea8fcdae08)
            - [(3) Search](#8f9468e9ab26128567f4be87ead108d7)
        - [(7) Android](#66052f824f5054aa0f70785a2389a478)
        - [Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O](#2adc0044b2703fb010b3bf73b1f1ea4a)
            - [(5) NoCategory](#8530752bacfb388f3726555dc121cb1a)
            - [(3) kernelCache](#82d0fa2d6934ce29794a651513934384)
            - [(3) Mach-O](#d249a8d09a3f25d75bb7ba8b32bd9ec5)
            - [(3) Swift](#1c698e298f6112a86c12881fbd8173c7)
        - [(9) ELF](#e5e403123c70ddae7bd904d3a3005dbb)
        - [(5) Microcode](#7a2977533ccdac70ee6e58a7853b756b)
        - [(6) Emulator](#b38dab81610be087bd5bc7785269b8cc)
        - [RecentAdd](#c39dbae63d6a3302c4df8073b4d1cdc8)
        - [(4) PartOfOtherTool](#83de90385d03ac8ef27360bfcdc1ab48)
        - [Vul](#1ded622dca60b67288a591351de16f8b)
            - [(7) NoCategory](#385d6777d0747e79cccab0a19fa90e7e)
            - [(2) ROP](#cf2efa7e3edb24975b92d2e26ca825d2)
        - [(7) Patch](#7d557bc3d677d206ef6c5a35ca8b3a14)
        - [(3) Other](#7dfd8abad50c14cd6bdc8d8b79b6f595)
        - [Function](#90bf5d31a3897400ac07e15545d4be02)
            - [(4) NoCategory](#347a2158bdd92b00cd3d4ba9a0be00ae)
            - [(6) Rename&&Prefix&&Tag](#73813456eeb8212fd45e0ea347bec349)
            - [(5) Nav&&Search](#e4616c414c24b58626f834e1be079ebc)
            - [(2) demangle](#cadae88b91a57345d266c68383eb05c5)
        - [(3) TaintAnalysis&&SymbolicExecution](#34ac84853604a7741c61670f2a075d20)
        - [(8) string](#9dcc6c7dd980bec1f92d0cc9a2209a24)
        - [(3) encrypt&&decrypt](#06d2caabef97cf663bd29af2b1fe270c)
    - [Video&&Post](#18c6a45392d6b383ea24b363d2f3e76b)
        - [(15) Malware](#0b3e1936ad7c4ccc10642e994c653159)
        - [(6) Series-LabelessIntroduction](#04cba8dbb72e95d9c721fe16a3b48783)
        - [(24) Series-ReversingWithIDAFromScrach](#1a2e56040cfc42c11c5b4fa86978cc19)
        - [Series-UsingIDAPythonToMakeYourLifeEasier](#e838a1ecdcf3d068547dd0d7b5c446c6)
            - [(6) Original](#7163f7c92c9443e17f3f76cc16c2d796)
            - [(5) ZH](#fc62c644a450f3e977af313edd5ab124)
        - [(50) Tool&&Plugin&&Script](#3d3bc775abd7f254ff9ff90d669017c9)
        - [(9) Tips&&Tricks](#a4bd25d3dc2f0be840e39674be67d66b)
        - [(146) NoCategory](#4187e477ebc45d1721f045da62dbf4e8)
        - [(5) Translate-TheIDAProBook](#ea11818602eb33e8b165eb18d3710965)
        - [(2) Translate-ReverseEngineeringCodeWithIDAPro](#ec5f7b9ed06500c537aa25851a3f2d3a)
        - [(5) Series-ReversingCCodeWithIDA](#8433dd5df40aaf302b179b1fda1d2863)
        - [(7) REPractice](#d8e48eb05d72db3ac1e050d8ebc546e1)
        - [(2) 新添加的](#37634a992983db427ce41b37dd9a98c2)
- [Ghidra](#319821036a3319d3ade5805f384d3165)
    - [Plugins&&Scripts](#fa45b20f6f043af1549b92f7c46c9719)
        - [(16) RecentAdd](#ce70b8d45be0a3d29705763564623aca)
        - [SpecificTarget](#69dc4207618a2977fe8cd919e7903fa5)
            - [(3) NoCategory](#da5d2b05da13f8e65aa26d6a1c95a8d0)
            - [(18) Loader&&Processor](#058bb9893323f337ad1773725d61f689)
            - [(2) Xbox](#51a2c42c6d339be24badf52acb995455)
        - [WithOtherTools](#99e3b02da53f1dbe59e0e277ef894687)
            - [(2) Radare2](#e1cc732d1388084530b066c26e24887b)
            - [(1) NoCategory](#5923db547e1f04f708272543021701d2)
            - [(5) IDA](#d832a81018c188bf585fcefa3ae23062)
            - [(1) DBI](#60e86981b2c98f727587e7de927e0519)
        - [(1) Skin&&Theme](#cccbd06c6b9b03152d07a4072152ae27)
        - [(2) Ghidra](#2ae406afda6602c8f02d73678b2ff040)
    - [Post&&Videos](#273df546f1145fbed92bb554a327b87a)
        - [(65) RecentAdd](#ce49901b4914f3688ef54585c8f9df1a)
- [x64dbg](#b1a6c053e88e86ce01bbd78c54c63a7c)
    - [Plugins&&Scripts](#b4a856db286f9f29b5a32d477d6b3f3a)
        - [(62) RecentAdd](#da5688c7823802e734c39b539aa39df7)
        - [(1) x64dbg](#353ea40f2346191ecb828210a685f9db)
    - [Post&&Videos](#22894d6f2255dc43d82dd46bdbc20ba1)
- [OllyDbg](#37e37e665eac00de3f55a13dcfd47320)
    - [Plugins&&Scripts](#7834e399e48e6c64255a1a0fdb6b88f5)
        - [(12) RecentAdd](#92c44f98ff5ad8f8b0f5e10367262f9b)
    - [Post&&Videos](#8dd3e63c4e1811973288ea8f1581dfdb)
- [WinDBG](#0a506e6fb2252626add375f884c9095e)
    - [Plugins&&Scripts](#37eea2c2e8885eb435987ccf3f467122)
        - [(64) RecentAdd](#2ef75ae7852daa9862b2217dca252cc3)
    - [(9) Post&&Videos](#6d8bac8bfb5cda00c7e3bd38d64cbce3)
- [Cuckoo](#0ae4ddb81ff126789a7e08b0768bd693)
    - [Tools](#5830a8f8fb3af1a336053d84dd7330a1)
        - [(35) RecentAdd](#f2b5c44c2107db2cec6c60477c6aa1d0)
    - [(15) Post&&Videos](#ec0a441206d9a2fe1625dce0a679d466)
- [Radare2](#86cb7d8f548ca76534b5828cb5b0abce)
    - [Plugins&&Scripts](#0e08f9478ed8388319f267e75e2ef1eb)
        - [(33) RecentAdd](#6922457cb0d4b6b87a34caf39aa31dfe)
        - [(1) Radare2](#ec3f0b5c2cf36004c4dd3d162b94b91a)
        - [WithOtherTools](#1a6652a1cb16324ab56589cb1333576f)
            - [(4) NoCategory](#dfe53924d678f9225fc5ece9413b890f)
            - [(3) IDA](#1cfe869820ecc97204a350a3361b31a7)
        - [(5) GUI](#f7778a5392b90b03a3e23ef94a0cc3c6)
    - [(168) Posts&&Videos](#95fdc7692c4eda74f7ca590bb3f12982)
- [BinaryNinja](#afb7259851922935643857c543c4b0c2)
    - [Plugins&&Scripts](#3034389f5aaa9d7b0be6fa7322340aab)
        - [(38) RecentAdd](#a750ac8156aa0ff337a8639649415ef1)
        - [WithOtherTools](#bba1171ac550958141dfcb0027716f41)
            - [(2) NoCategory](#c2f94ad158b96c928ee51461823aa953)
            - [(3) IDA](#713fb1c0075947956651cc21a833e074)
    - [(7) Posts&&Videos](#2d24dd6f0c01a084e88580ad22ce5b3c)
- [DBI](#7ab3a7005d6aa699562b3a0a0c6f2cff)
    - [DynamoRIO](#c8cdb0e30f24e9b7394fcd5681f2e419)
        - [Tools](#6c4841dd91cb173093ea2c8d0b557e71)
            - [(7) RecentAdd](#ff0abe26a37095f6575195950e0b7f94)
            - [(2) DynamoRIO](#3a577a5b4730a1b5b3b325269509bb0a)
            - [(3) WithOtherTools](#928642a55eff34b6b52622c6862addd2)
        - [(16) Posts&&Videos](#9479ce9f475e4b9faa4497924a2e40fc)
    - [IntelPin](#7b8a493ca344f41887792fcc008573e7)
        - [Tools](#fe5a6d7f16890542c9e60857706edfde)
            - [(15) RecentAdd](#78a2edf9aa41eb321436cb150ea70a54)
            - [WithOtherTools](#e6a829abd8bbc5ad2e5885396e3eec04)
                - [(8) NoCategory](#e129288dfadc2ab0890667109f93a76d)
        - [Posts&&Videos](#226190bea6ceb98ee5e2b939a6515fac)
    - [Frida](#f24f1235fd45a1aa8d280eff1f03af7e)
        - [Tools](#a5336a0f9e8e55111bda45c8d74924c1)
            - [(97) RecentAdd](#54836a155de0c15b56f43634cd9cfecf)
            - [WithOtherTools](#74fa0c52c6104fd5656c93c08fd1ba86)
                - [(1) NoCategory](#00a86c65a84e58397ee54e85ed57feaf)
                - [(3) IDA](#d628ec92c9eea0c4b016831e1f6852b3)
                - [(2) BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8)
                - [(2) Radare2](#ac053c4da818ca587d57711d2ff66278)
            - [(1) Frida](#6d3c24e43835420063f9ca50ba805f15)
        - [(25) Posts&&Videos](#a1a7e3dd7091b47384c75dba8f279caf)
    - [Other](#5a9974bfcf7cdf9b05fe7a7dc5272213)
- [VM&&Emulator](#747ddaa20f643da415284bfba9cda3a2)
    - [QEMU](#796b64906655228d8a1ff8c0dd390451)
        - [Tools](#296c7f25266b25e5ee1107dd76e40dd2)
            - [(7) RecentAdd](#82072558d99a6cf23d4014c0ae5b420a)
        - [Post&&Videos](#5df30a166c2473fdadf5a578d1a70e32)
    - [Other](#a13effff89633708c814ae9410da835a)
- [Android](#11a59671b467a8cdbdd4ea9d5e5d9b51)
    - [Tools](#2110ded2aa5637fa933cc674bc33bf21)
        - [(182) RecentAdd1](#883a4e0dd67c6482d28a7a14228cd942)
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
        - [(15) ReverseEngineering](#6d2b758b3269bac7d69a2d2c8b45194c)
        - [(42) RecentAdd](#63fd2c592145914e99f837cecdc5a67c)
    - [(2) Posts&&Videos](#f0493b259e1169b5ddd269b13cfd30e6)
- [Apple&&iOS&&iXxx](#069664f347ae73b1370c4f5a2ec9da9f)
    - [Tools](#58cd9084afafd3cd293564c1d615dd7f)
        - [(204) RecentAdd](#d0108e91e6863289f89084ff09df39d0)
        - [(7) XCode](#7037d96c1017978276cb920f65be2297)
    - [Posts&&Videos](#c97bbe32bbd26c72ceccb43400e15bf1)
- [Windows](#2f81493de610f9b796656b269380b2de)
    - [Tools](#b478e9a9a324c963da11437d18f04998)
        - [(213) NoCategory](#1afda3039b4ab9a3a1f60b179ccb3e76)
        - [(10) ETW](#0af4bd8ca0fd27c9381a2d1fa8b71a1f)
        - [Sysmon](#d48f038b58dc921660be221b4e302f70)
        - [(5) WSL](#8ed6f25b321f7b19591ce2908b30cc88)
        - [(10) .NET](#d90b60dc79837e06d8ba2a7ee1f109d3)
        - [新添加的](#f9fad1d4d1f0e871a174f67f63f319d8)
        - [(5) Environment&&环境&&配置](#6d2fe834b7662ecdd48c17163f732daf)
        - [进程注入](#8bfd27b42bb75956984994b3419fb582)
        - [(1) DLL注入](#b0d50ee42d53b1f88b32988d34787137)
        - [代码注入](#1c6069610d73eb4246b58d78c64c9f44)
        - [内存模块](#7c1541a69da4c025a89b0571d8ce73d2)
        - [(6) Shellcode](#16001cb2fae35b722deaa3b9a8e5f4d5)
        - [(6) VT&&虚拟化&&Hypbervisor](#19cfd3ea4bd01d440efb9d4dd97a64d0)
        - [(8) 内核&&驱动](#c3cda3278305549f4c21df25cbf638a4)
        - [(3) 注册表](#920b69cea1fc334bbc21a957dd0d9f6f)
        - [(4) 系统调用](#d295182c016bd9c2d5479fe0e98a75df)
    - [Posts&&Videos](#3939f5e83ca091402022cb58e0349ab8)
- [Linux](#dc664c913dc63ec6b98b47fcced4fdf0)
    - [(101) Tools](#89e277bca2740d737c1aeac3192f374c)
    - [Post&&Videos](#f6d78e82c3e5f67d13d9f00c602c92f0)
- [Hook](#3f1fde99538be4662dca6747a365640b)
    - [(109) Tools](#cfe974d48bbb90a930bf667c173616c7)
- [Monitor](#70e64e3147675c9bcd48d4f475396e7f)
    - [(29) Tools](#cd76e644d8ddbd385939bb17fceab205)
- [Malware](#09fa851959ff48f5667a2099c861eab8)
    - [(270) Tools](#e781a59e4f4daab058732cf66f77bfb9)
- [Game](#28aa8187f8a1e38ca5a55aa31a5ee0c3)
    - [(58) Tools](#07f0c2cbf63c1d7de6f21fa43443ede3)
- [OtherTools](#d3690e0b19c784e104273fe4d64b2362)
    - [(284) RecentAdd](#1d9dec1320a5d774dc8e0e7604edfcd3)
    - [(14) angr](#4fe330ae3e5ce0b39735b1bfea4528af)
    - [(116) Debug](#324874bb7c3ead94eae6f1fa1af4fb68)
    - [RecentAdd1](#9d0f15756c4435d1ea79c21fcfda101f)
    - [BAP](#9f8d3f2c9e46fbe6c25c22285c8226df)
    - [(3) BinNavi](#2683839f170250822916534f1db22eeb)
    - [(55) Decompiler](#0971f295b0f67dc31b7aa45caf3f588f)
    - [(30) Disassemble](#2df6d3d07e56381e1101097d013746a0)
    - [(19) GDB](#975d9f08e2771fccc112d9670eae1ed1)
    - [(4) Captcha](#9526d018b9815156cb001ceee36f6b1d)
    - [(3) 其他](#bc2b78af683e7ba983205592de8c3a7a)
- [Posts&&Videos](#dd1e42d17eefb275a804584a848b82a6)
    - [RecentAdd](#48d6a0efe043af4bed4cbba665a4502c)
- [Rootkit&&Bootkit](#5fdcfc70dd87360c2dddcae008076547)
    - [(67) Tools](#b8d6f237c04188a10f511cd8988de28a)
- [Hardware](#069468057aac03c102abdbeb7a5decf6)
    - [Firmware](#3574d46dd09566f898b407cebe9df29b)
        - [(44) Firmware](#649d2aece91551af8b48d29f52943804)
        - [(3) Intel](#fff92e7d304e2c927ef3530f4d327456)
- [Crypto](#948dbc64bc0ff4a03296988574f5238c)
    - [(117) Tools](#a6b0a9b9184fd78c8b87ccfe48a8e544)
- [TODO](#35f8efcff18d0449029e9d3157ac0899)


# <a id="35f8efcff18d0449029e9d3157ac0899"></a>TODO


- Add more tools and posts


# <a id="08e59e476824a221f6e4a69c0bba7d63"></a>IDA


***


## <a id="f11ab1ff46aa300cc3e86528b8a98ad7"></a>Tools


- Mainly from Github


### <a id="c39dbae63d6a3302c4df8073b4d1cdc8"></a>RecentAdd




### <a id="c39a6d8598dde6abfeef43faf931beb5"></a>NoCategory


- [**1044**Star][13d] [Py] [fireeye/flare-ida](https://github.com/fireeye/flare-ida) Multiple IDA plugins and IDAPython scripts
    - [StackStrings](https://github.com/fireeye/flare-ida/blob/master/plugins/stackstrings_plugin.py) recovery of manually constructed strings described [here](http://www.fireeye.com/blog/threat-research/2014/08/flare-ida-pro-script-series-automatic-recovery-of-constructed-strings-in-malware.html)
    - [Struct Typer](https://github.com/fireeye/flare-ida/blob/master/plugins/struct_typer_plugin.py) implements the struct typing described [here](https://www.mandiant.com/blog/applying-function-types-structure-fields-ida/)
    - [ApplyCalleeType](https://github.com/fireeye/flare-ida/blob/master/python/flare/apply_callee_type.py) specify or choose a function type for indirect calls as described [here](https://www.fireeye.com/blog/threat-research/2015/04/flare_ida_pro_script.html)
    - [argtracker](https://github.com/fireeye/flare-ida/blob/master/python/flare/argtracker.py) identify static arguments to functions used within a program
    - [idb2pat](https://github.com/fireeye/flare-ida/blob/master/python/flare/idb2pat.py) generate function patterns from an existing IDB database that can then be turned into FLIRT signatures to help identify similar functions in new files. [more info](https://www.fireeye.com/blog/threat-research/2015/01/flare_ida_pro_script.html)
    - [objc2_analyzer](https://github.com/fireeye/flare-ida/blob/master/python/flare/objc2_analyzer.py) creates cross-references between selector references and their implementations as defined in the Objective-C runtime related sections of the target Mach-O executable
    - [MSDN Annotations](https://github.com/fireeye/flare-ida/tree/master/python/flare/IDB_MSDN_Annotator) adds MSDN information from a XML file to the IDB database. [more info](https://www.fireeye.com/blog/threat-research/2014/09/flare-ida-pro-script-series-msdn-annotations-ida-pro-for-malware-analysis.html)
    - [ironstrings](https://github.com/fireeye/flare-ida/tree/master/python/flare/ironstrings) uses code emulation to recover constructed strings (stackstrings) from malware
    - [Shellcode Hashes](https://github.com/fireeye/flare-ida/tree/master/shellcode_hashes) create the database for hash search described in [here](https://www.mandiant.com/blog/precalculated-string-hashes-reverse-engineering-shellcode/)
- [**735**Star][6m] [Py] [devttys0/ida](https://github.com/devttys0/ida) Collection of IDA Python plugins/scripts/modules.


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
- [**315**Star][2m] [C] [ohjeongwook/darungrim](https://github.com/ohjeongwook/darungrim) A patch analysis tool 
    - [IDA插件](https://github.com/ohjeongwook/darungrim/tree/master/Src/IDAPlugin) 
    - [DGEngine](https://github.com/ohjeongwook/darungrim/tree/master/Src/DGEngine) 
- [**307**Star][1y] [C++] [nevermoe/unity_metadata_loader](https://github.com/nevermoe/unity_metadata_loader)  load strings and method/class names in global-metadata.dat to IDA
- [**274**Star][3m] [Py] [jpcertcc/aa-tools](https://github.com/jpcertcc/aa-tools) Multiple RE plugins and scripts
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
- [**115**Star][1y] [Py] [vallejocc/reverse-engineering-arsenal](https://github.com/vallejocc/Reverse-Engineering-Arsenal) Useful Scripts for helping in reverse engeenering
    - [WinDbg](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/WinDbg) WinDBG script collection
    - [IDA-set_symbols_for_addresses](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/IDA/set_symbols_for_addresses.py) asks you for a file containing pairs address - symbol. It walks all segments searching for DWORDs matching the addresses of the given file of pairs address - symbols, and it will name the variable containing the address with the symbol name
    - [IDA-stack_strings_deobfuscator_1](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/IDA/stack_strings_deobfuscator_1.py) Some malware families construct strings into the stack
    - [RevealPE](https://github.com/vallejocc/Reverse-Engineering-Arsenal/tree/master/Standalone/RevealPE) 
- [**80**Star][3m] [Py] [takahiroharuyama/ida_haru](https://github.com/takahiroharuyama/ida_haru) scripts for IDA Pro
    - [bindiff](https://github.com/takahiroharuyama/ida_haru/blob/master/bindiff/README.org) BinDiff wrapper script for multiple binary diffing
    - [eset_crackme](https://github.com/takahiroharuyama/ida_haru/blob/master/eset_crackme/README.org) IDA Pro loader/processor modules for ESET CrackMe driver VM
    - [fn_fuzzy](https://github.com/takahiroharuyama/ida_haru/blob/master/fn_fuzzy/README.org) IDAPython script for fast multiple binary diffing triage
    - [stackstring_static](https://github.com/takahiroharuyama/ida_haru/blob/master/stackstring_static/README.org) IDAPython script statically-recovering strings constructed in stack
- [**74**Star][10m] [Py] [secrary/ida-scripts](https://github.com/secrary/ida-scripts) IDAPro scripts/plugins
    - [dumpDyn](https://github.com/secrary/ida-scripts/blob/master/dumpDyn/README.md) IDAPython plugin(script) which saves comments, names, breakpoints, functions from one execution to another.
    - [idenLib](https://github.com/secrary/ida-scripts/blob/master/idenLib/README.md) Library Function Identification
    - [IOCTL_decode](https://github.com/secrary/ida-scripts/blob/master/IOCTL_decode.py) Windows Device IO Control Code
    - [XORCheck](https://github.com/secrary/ida-scripts/blob/master/XORCheck.py) check xor
- [**60**Star][2y] [Py] [tmr232/idabuddy](https://github.com/tmr232/idabuddy)  a reverse-engineer's best friend. Designed to be everything Clippy the Office Assistant was, and more!
- [**59**Star][2y] [C++] [alexhude/loadprocconfig](https://github.com/alexhude/loadprocconfig) IDA Plugin to load processor configuration files.
- [**57**Star][2m] [Py] [williballenthin/idawilli](https://github.com/williballenthin/idawilli) IDA Pro resources, scripts, and configurations
    - [hint_calls](https://github.com/williballenthin/idawilli/blob/master/plugins/hint_calls/readme.md) IDA plugin to display the calls and strings referenced by a function as hints.
    - [dynamic_hints](https://github.com/williballenthin/idawilli/blob/master/plugins/dynamic_hints/readme.md) an example plugin that demonstrates how to provide custom hints with dynamic data.
    - [add_segment](https://github.com/williballenthin/idawilli/tree/master/scripts/add_segment) IDAPython plugin that adds the contents of a file as a new segment in an existing idb
    - [color](https://github.com/williballenthin/idawilli/tree/master/scripts/color) IDAPython script that colors instructions
    - [find_ptrs](https://github.com/williballenthin/idawilli/tree/master/scripts/find_ptrs) IDAPython script that scans through the .text section for values that could be pointers (32-bit).
    - [yara_fn](https://github.com/williballenthin/idawilli/tree/master/scripts/yara_fn) IDAPython script that generates a YARA rule to match against the basic blocks of the current function
    - [idawilli](https://github.com/williballenthin/idawilli/tree/master/idawilli) a python module that contains utilities for working with the idapython scripting interface.
    - [themes](https://github.com/williballenthin/idawilli/tree/master/themes) colors and skins
- [**54**Star][1y] [Py] [zardus/idalink](https://github.com/zardus/idalink) idalink arose of the need to easily use IDA's API for analysis without wanting to be stuck in the IDA interface
- [**52**Star][3y] [C++] [sektioneins/wwcd](https://github.com/sektioneins/wwcd) Capstone powered IDA view
- [**51**Star][2y] [Py] [cseagle/ida_clemency](https://github.com/cseagle/ida_clemency) IDA cLEMENCy Tools
- [**50**Star][3m] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA tools and scripts collection
    - Also In Section: [IDA->Tools->ImportExport->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |[DBI->Frida->Tools->RecentAdd](#54836a155de0c15b56f43634cd9cfecf) |
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
- [**49**Star][11m] [Py] [agustingianni/utilities](https://github.com/agustingianni/utilities) Uncategorized utilities
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
- [**47**Star][3y] [Py] [jjo-sec/idataco](https://github.com/jjo-sec/idataco) IDATACO IDA Pro Plugin
- [**45**Star][7y] [Py] [carlosgprado/milf](https://github.com/carlosgprado/milf) An IDA Pro swiss army knife 
    - [milf](https://github.com/carlosgprado/MILF/blob/master/milf.py) Some useful methods in vulnerability discovery
- [**42**Star][4y] [C++] [nihilus/guid-finder](https://github.com/nihilus/guid-finder) find GUID/UUIDs
- [**40**Star][6m] [Visual Basic] [dzzie/re_plugins](https://github.com/dzzie/re_plugins) misc reverse engineering plugins
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
- [**27**Star][5m] [Py] [enovella/re-scripts](https://github.com/enovella/re-scripts) IDA, Ghidra and Radare2 scripts(no documentation)
- [**26**Star][5y] [Py] [bastkerg/recomp](https://github.com/bastkerg/recomp) IDA recompiler（No Documentation）
- [**26**Star][8m] [C++] [offlinej/ida-rpc](https://github.com/offlinej/ida-rpc) Discord rich presence plugin for IDA Pro 7.0
- [**25**Star][3y] [Py] [zyantific/continuum](https://github.com/zyantific/continuum) Plugin adding multi-binary project support to IDA Pro (WIP)
- [**23**Star][10m] [C++] [trojancyborg/ida_jni_rename](https://github.com/trojancyborg/ida_jni_rename) IDA JNI clal rename
- [**22**Star][5y] [Py] [nihilus/idascope](https://github.com/nihilus/idascope)  An IDA Pro extension for easier (malware) reverse engineering（Bitbucket has newer version）
- [**22**Star][4y] [Py] [onethawt/idapyscripts](https://github.com/onethawt/idapyscripts) IDAPython scripts
    - [DataXrefCounter ](https://github.com/onethawt/idapyscripts/blob/master/dataxrefcounter.py)  A small IDAPython plugin which enumerates all of the the x-references in a specific segment and counts the frequency of usage
- [**22**Star][3y] [C++] [patois/idaplugins](https://github.com/patois/idaplugins) Random IDA scripts, plugins, example code (some of it may be old and not working anymore)
- [**21**Star][3m] [Py] [nlitsme/idascripts](https://github.com/nlitsme/idascripts) IDApro idc and idapython script collection
    - [enumerators](https://github.com/nlitsme/idascripts/blob/master/enumerators.py) Enumeration utilities for idapython
- [**21**Star][2m] [Py] [rceninja/re-scripts](https://github.com/rceninja/re-scripts) 
    - [Hyperv-Scripts](https://github.com/rceninja/re-scripts/tree/master/scripts/Hyperv-Scripts) 
    - [IA32-MSR-Decoder](https://github.com/rceninja/re-scripts/tree/master/scripts/IA32-MSR-Decoder) an IDA script which helps you to find and decode all MSR codes inside binary files
    - [IA32-VMX-Helper](https://github.com/rceninja/re-scripts/tree/master/scripts/IA32-VMX-Helper) an IDA script (Updated IA32 MSR Decoder) which helps you to find and decode all MSR/VMCS codes inside binary files
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
- [**20**Star][1m] [Py] [mephi42/ida-kallsyms](https://github.com/mephi42/ida-kallsyms) (No Doc)
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
- [**15**Star][7m] [CMake] [google/idaidle](https://github.com/google/idaidle) a plugin for the commercial IDA Pro disassembler that warns users if they leave their instance idling for too long
- [**14**Star][4y] [C++] [nihilus/fast_idb2sig_and_loadmap_ida_plugins](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins) ida plugins
    - [LoadMap](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins/tree/master/LoadMap)  An IDA plugin, which loads a VC/Borland/Dede map file into IDA 4.5
    - [idb2sig](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins/blob/master/idb2sig/ReadMe.txt) 
- [**13**Star][2y] [Py] [cisco-talos/pdata_check](https://github.com/cisco-talos/pdata_check) identify unusual runtimes based on the pdata section and the last instruction of the runtime function
- [**13**Star][12m] [C++] [nihilus/graphslick](https://github.com/nihilus/graphslick) IDA Plugin - GraphSlick
- [**13**Star][1y] [Py] [cxm95/ida_wrapper](https://github.com/cxm95/ida_wrapper) An IDA_Wrapper for linux, shipped with an Function Identifier. It works well with Driller on static linked binaries.
- [**12**Star][1y] [Assembly] [gabrielravier/cave-story-decompilation](https://github.com/gabrielravier/cave-story-decompilation) Decompilation of Cave Story. Can be opened with IDA Pro (freeware and pro version).
- [**11**Star][2y] [Py] [0xddaa/iddaa](https://github.com/0xddaa/iddaa) idapython scripts
- [**11**Star][5y] [Py] [dshikashio/idarest](https://github.com/dshikashio/idarest) Expose some basic IDA Pro interactions through a REST API for JSONP
- [**11**Star][9m] [C++] [ecx86/ida7-supportlib](https://github.com/ecx86/ida7-supportlib) IDA-SupportLib library by sirmabus, ported to IDA 7
- [**10**Star][4y] [C++] [revel8n/spu3dbg](https://github.com/revel8n/spu3dbg) Ida Pro debugger module for the anergistic SPU emulator.
- [**9**Star][4y] [Py] [nfarrar/ida-colorschemes](https://github.com/nfarrar/ida-colorschemes) A .clr colorscheme generator for IDA Pro 6.4+.
- [**9**Star][5y] [Ruby] [rogwfu/plympton](https://github.com/rogwfu/plympton) Library to work with yaml exported IDA Pro information and run statistics
- [**9**Star][8m] [Py] [0xcpu/relieve](https://github.com/0xcpu/relieve) Scripts used for reverse engineering, malware analysis.
    - [elfie](https://github.com/0xcpu/relieve/blob/master/elfie.py)  display (basic) info about an ELF, similar to readelf.
    - [elforensics](https://github.com/0xcpu/relieve/blob/master/elforensics.py)  check ELF for entry point hooks, RWX sections, CTORS & GOT & PLT hooks, function prologue trampolines.
    - [dololi](https://github.com/0xcpu/relieve/tree/master/dololi) unfinished, the idea is to automatically generate an executable that calls exports from DLL(s).
- [**8**Star][5y] [Py] [daniel_plohmann/idapatchwork](https://bitbucket.org/daniel_plohmann/idapatchwork) Stitching against malware families with IDA Pro
- [**8**Star][2y] [C++] [ecx86/ida7-segmentselect](https://github.com/ecx86/ida7-segmentselect) IDA-SegmentSelect library by sirmabus, ported to IDA 7
- [**8**Star][27d] [Py] [lanhikari22/gba-ida-pseudo-terminal](https://github.com/lanhikari22/gba-ida-pseudo-terminal) IDAPython tools to aid with analysis, disassembly and data extraction using IDA python commands, tailored for the GBA architecture at some parts
- [**8**Star][1m] [C++] [nlitsme/idcinternals](https://github.com/nlitsme/idcinternals) investigate the internals of IDA
- [**8**Star][3y] [Py] [pwnslinger/ibt](https://github.com/pwnslinger/ibt) IDA Pro Back Tracer - Initial project toward automatic customized protocols structure extraction
- [**8**Star][2y] [C++] [shazar14/idadump](https://github.com/shazar14/idadump) An IDA Pro script to verify binaries found in a sample and write them to disk
- [**7**Star][2y] [Py] [swackhamer/ida_scripts](https://github.com/swackhamer/ida_scripts) IDAPython scripts（No Doc）
- [**7**Star][9m] [Py] [techbliss/ida_pro_http_ip_geolocator](https://github.com/techbliss/ida_pro_http_ip_geolocator) look up web addresses and resolve it to a ip and look it via google maps
- [**7**Star][5y] [Py] [techbliss/processor-changer](https://github.com/techbliss/processor-changer) change processor inside ida, No need to Reopen Ida Pro
- [**7**Star][1y] [C++] [tenable/mida](https://github.com/tenable/mida) an IDA plugin which extracts RPC interfaces and recreates the associated IDL file
- [**6**Star][2y] [CMake] [elemecca/cmake-ida](https://github.com/elemecca/cmake-ida) This project provides CMake support for building IDA Pro modules.
- [**6**Star][2y] [Py] [fireundubh/ida7-alleycat](https://github.com/fireundubh/ida7-alleycat) Alleycat plugin by devttys0, ported to IDA 7
- [**6**Star][8m] [Py] [geosn0w/dumpanywhere64](https://github.com/geosn0w/dumpanywhere64) An IDA (Interactive Disassembler) script that can save a chunk of binary from an address.
- [**6**Star][1y] [C++] [ecx86/ida7-hexrays-invertif](https://github.com/ecx86/ida7-hexrays-invertif) Hex-Rays Invert if statement plugin for IDA 7.0
- [**5**Star][3y] [Py] [andreafioraldi/idavshelp](https://github.com/andreafioraldi/idavshelp) IDAPython plugin to integrate Visual Studio Help Viewer in IDA Pro >= 6.8.
- [**5**Star][5m] [Py] [fdiskyou/ida-plugins](https://github.com/fdiskyou/ida-plugins) IDAPython scripts（No Documentation）
    - [banned_functions](https://github.com/fdiskyou/ida-plugins/blob/master/banned_functions.py) 
- [**5**Star][3y] [Py] [gh0st3rs/idassldump](https://github.com/gh0st3rs/idassldump) Simple IDAPython script for dump ssl traffic to file
- [**5**Star][1y] [C++] [lab313ru/m68k_fixer](https://github.com/lab313ru/m68k_fixer) IDA Pro plugin fixer for m68k
- [**5**Star][5y] [C#] [npetrovski/ida-smartpatcher](https://github.com/npetrovski/ida-smartpatcher) IDA apply patch GUI
- [**5**Star][4y] [Py] [tmr232/tarkus](https://github.com/tmr232/tarkus) Plugin Manager for IDA Pro
- [**4**Star][2m] [Py] [gitmirar/idaextapi](https://github.com/gitmirar/idaextapi) IDA API utlitites
- [**4**Star][3y] [Py] [hustlelabs/joseph](https://github.com/hustlelabs/joseph) IDA Viewer Plugins
- [**4**Star][1y] [savagedd/samp-server-idb](https://github.com/savagedd/samp-server-idb) 
- [**4**Star][2m] [Py] [spigwitmer/golang_struct_builder](https://github.com/spigwitmer/golang_struct_builder) IDA 7.0+ script that auto-generates structs and interfaces from runtime metadata found in golang binaries
- [**3**Star][9m] [Py] [gdataadvancedanalytics/ida-python](https://github.com/gdataadvancedanalytics/ida-python) Random assembly of IDA Python scripts
    - [defineIAT](https://github.com/gdataadvancedanalytics/ida-python/blob/master/Trickbot/defineIAT.py) written for the Trickbot sample with sha256 8F590AC32A7C7C0DDFBFA7A70E33EC0EE6EB8D88846DEFBDA6144FADCC23663A
    - [stringDecryption](https://github.com/gdataadvancedanalytics/ida-python/blob/master/Trickbot/stringDecryption.py) written for the Trickbot sample with sha256 8F590AC32A7C7C0DDFBFA7A70E33EC0EE6EB8D88846DEFBDA6144FADCC23663A
- [**3**Star][2y] [Py] [ypcrts/ida-pro-segments](https://github.com/ypcrts/ida-pro-segments) It's very hard to load multiple files in the IDA GUI without it exploding. This makes it easy.
- [**3**Star][1y] [abarbatei/ida-utils](https://github.com/abarbatei/ida-utils) links, information and helper scripts for IDA Pro
- [**2**Star][2y] [C++] [ecx86/ida7-oggplayer](https://github.com/ecx86/ida7-oggplayer) IDA-OggPlayer library by sirmabus, ported to IDA 7
- [**2**Star][2y] [Py] [mayl8822/ida](https://github.com/mayl8822/ida) SearchGoogle
- [**2**Star][5y] [C++] [nihilus/ida-x86emu](https://github.com/nihilus/ida-x86emu) x86 emulator
- [**2**Star][4y] [Py] [nihilus/idapatchwork](https://github.com/nihilus/idapatchwork) Stitching against malware families with IDA Pro
- [**2**Star][2y] [Py] [sbouber/idaplugins](https://github.com/sbouber/idaplugins) 
- [**2**Star][2m] [Py] [psxvoid/idapython-debugging-dynamic-enrichment](https://github.com/psxvoid/idapython-debugging-dynamic-enrichment) 
- [**1**Star][2y] [Py] [andreafioraldi/idamsdnhelp](https://github.com/andreafioraldi/idamsdnhelp) IdaPython plugin to open MSDN Search page
- [**1**Star][1y] [Py] [farzonl/idapropluginlab4](https://github.com/farzonl/idapropluginlab4) An ida pro plugin that tracks def use chains of a given x86 binary.
- [**1**Star][2m] [Py] [voidsec/ida-helpers](https://github.com/voidsec/ida-helpers) Collection of IDA helpers
- [**0**Star][3y] [Py] [kcufid/my_ida_python](https://github.com/kcufid/my_ida_python) My idapython decode data
- [**0**Star][1y] [Py] [ruipin/idapy](https://github.com/ruipin/idapy) Various IDAPython libraries and scripts
- [**0**Star][8m] [Py] [tkmru/idapython-scripts](https://github.com/tkmru/idapython-scripts) IDAPro scripts


### <a id="fb4f0c061a72fc38656691746e7c45ce"></a>Structure&&Class


#### <a id="fa5ede9a4f58d4efd98585d3158be4fb"></a>NoCategory


- [**927**Star][12d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) a static Binary Code Analysis Toolkit, designed to help reverse engineers, directly from IDA or using Python for automation.
    - Also In Section: [IDA->Tools->TaintAnalysis](#34ac84853604a7741c61670f2a075d20) |
- [**656**Star][16d] [Py] [igogo-x86/hexrayspytools](https://github.com/igogo-x86/hexrayspytools) assists in the creation of classes/structures and detection of virtual tables
- [**167**Star][1y] [Py] [bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) An IDA Toolkit for analyzing iOS kernelcaches
    - Also In Section: [IDA->Tools->Apple->kernelCache](#82d0fa2d6934ce29794a651513934384) |
- [**138**Star][4y] [C++] [nihilus/hexrays_tools](https://github.com/nihilus/hexrays_tools) Assist in creation of new structure definitions / virtual calls detection
- [**103**Star][3m] [Py] [lucasg/findrpc](https://github.com/lucasg/findrpc) Ida script to extract RPC interface from binaries
- [**4**Star][3y] [C#] [andreafioraldi/idagrabstrings](https://github.com/andreafioraldi/idagrabstrings) IDAPython plugin to manipulate strings in a specified range of addresses
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |


#### <a id="4900b1626f10791748b20630af6d6123"></a>C++Class&&VirtualTable


- [**604**Star][3m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) IDAPython tool for C++ vtables reconstruction
    - Also In Section: [IDA->Tools->Debug->DebuggerData](#b31acf6c84a9506066d497af4e702bf5) |
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


- [**170**Star][9m] [C++] [ecx86/classinformer-ida7](https://github.com/ecx86/classinformer-ida7) ClassInformer backported for IDA Pro 7.0
- [**129**Star][2y] [Py] [nccgroup/susanrtti](https://github.com/nccgroup/SusanRTTI) Another RTTI Parsing IDA plugin
- [**90**Star][1y] [C++] [rub-syssec/marx](https://github.com/rub-syssec/marx) Uncovering Class Hierarchies in C++ Programs
    - [IDA导出](https://github.com/rub-syssec/marx/blob/master/ida_export/export.py) 
    - [IDA导入插件](https://github.com/rub-syssec/marx/tree/master/ida_import) 
    - [core](https://github.com/rub-syssec/marx/tree/master/src) 
- [**69**Star][7y] [C] [nektra/vtbl-ida-pro-plugin](https://github.com/nektra/vtbl-ida-pro-plugin) Identifying Virtual Table Functions using VTBL IDA Pro Plugin + Deviare Hooking Engine
- [**35**Star][5y] [C++] [nihilus/ida_classinformer](https://github.com/nihilus/ida_classinformer) IDA ClassInformer PlugIn
- [**32**Star][2y] [Py] [krystalgamer/dec2struct](https://github.com/krystalgamer/dec2struct) Python plugin to easily setup vtables in IDA using declaration files
- [**16**Star][2y] [C++] [mwl4/ida_gcc_rtti](https://github.com/mwl4/ida_gcc_rtti) Class informer plugin for IDA which supports parsing GCC RTTI




### <a id="a7dac37cd93b8bb42c7d6aedccb751b3"></a>Collection


- [**1749**Star][2m] [onethawt/idaplugins-list](https://github.com/onethawt/idaplugins-list) A list of IDA Plugins
- [**358**Star][9m] [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) Awesome IDA, x64DBG & OllyDBG plugin
    - Also In Section: [x64dbg->Plugins->RecentAdd](#da5688c7823802e734c39b539aa39df7) |
- [**10**Star][1y] [Py] [ecx86/ida-scripts](https://github.com/ecx86/ida-scripts) Collection of my IDA Pro/Hex-Rays scripts and plugins


### <a id="fabf03b862a776bbd8bcc4574943a65a"></a>Skin&&Theme


- [**720**Star][6m] [Py] [zyantific/idaskins](https://github.com/zyantific/idaskins) Plugin providing advanced skinning support for IDA Pro utilizing Qt stylesheets, similar to CSS.
- [**257**Star][7y] [eugeneching/ida-consonance](https://github.com/eugeneching/ida-consonance) Consonance, a dark color theme for IDA.
- [**106**Star][6m] [CSS] [0xitx/ida_nightfall](https://github.com/0xitx/ida_nightfall) A dark color theme for IDA Pro
- [**58**Star][7y] [gynophage/solarized_ida](https://github.com/gynophage/solarized_ida) "Solarized Dark" color scheme for IDA Pro.
- [**10**Star][7y] [Py] [luismiras/ida-color-scripts](https://github.com/luismiras/ida-color-scripts) a collection of color scripts for IDA Pro. They deal with import and export of color themes.
- [**9**Star][2y] [CSS] [gbps/x64dbg-consonance-theme](https://github.com/gbps/x64dbg-consonance-theme) dark x64dbg color theme based on IDA Consonance
- [**6**Star][5y] [Py] [techbliss/ida-styler](https://github.com/techbliss/ida-styler) Small Plugin to change the style off Ida Pro
- [**3**Star][2m] [rootbsd/ida_pro_zinzolin_theme](https://github.com/rootbsd/ida_pro_zinzolin_theme) IDA Pro zinzolin theme
- [**1**Star][1y] [C] [albertzsigovits/idc-dark](https://github.com/albertzsigovits/idc-dark) A dark-mode color scheme for Hex-Rays IDA using idc


### <a id="a8f5db3ab4bc7bc3d6ca772b3b9b0b1e"></a>Firmware&&EmbedDevice


- [**5165**Star][1m] [Py] [refirmlabs/binwalk](https://github.com/ReFirmLabs/binwalk) a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.
    - [IDA插件](https://github.com/ReFirmLabs/binwalk/tree/master/src/scripts) 
    - [binwalk](https://github.com/ReFirmLabs/binwalk/tree/master/src/binwalk) 
- [**490**Star][4m] [Py] [maddiestone/idapythonembeddedtoolkit](https://github.com/maddiestone/idapythonembeddedtoolkit) a set of script to automate many of the steps associated with statically analyzing, or reverse engineering, the firmware of embedded devices in IDA Pro.
- [**174**Star][2y] [Py] [duo-labs/idapython](https://github.com/duo-labs/idapython)  a few Python modules developed for use with IDA Pro from the researchers at Duo Labs.
    - Also In Section: [IDA->Tools->Apple->NoCategory](#8530752bacfb388f3726555dc121cb1a) |
    - [cortex_m_firmware](https://github.com/duo-labs/idapython/blob/master/cortex_m_firmware.py) grooms an IDA Pro database containing firmware from an ARM Cortex M microcontroller.
    - [amnesia](https://github.com/duo-labs/idapython/blob/master/amnesia.py)  an IDAPython module designed to use byte level heuristics to find ARM thumb instructions in undefined bytes in an IDA Pro database
    - [REobjc](https://github.com/duo-labs/idapython/blob/master/reobjc.py)  an IDAPython module designed to make proper cross references between calling functions and called functions in Objective-C methods
- [**94**Star][18d] [Py] [pagalaxylab/vxhunter](https://github.com/PAGalaxyLab/vxhunter) A ToolSet for VxWorks Based Embedded Device Analyses.
    - [R2](https://github.com/PAGalaxyLab/vxhunter/blob/master/firmware_tools/vxhunter_r2_py2.py) 
    - [IDA插件](https://github.com/PAGalaxyLab/vxhunter/blob/master/firmware_tools/vxhunter_ida.py) 
    - [Ghidra插件](https://github.com/PAGalaxyLab/vxhunter/tree/master/firmware_tools/ghidra) 


### <a id="02088f4884be6c9effb0f1e9a3795e58"></a>Signature(FLIRT...)&&Diff&&Match


#### <a id="cf04b98ea9da0056c055e2050da980c1"></a>NoCategory


- [**418**Star][17d] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) a scalable assembly management and analysis platform
    - Also In Section: [IDA->Tools->PartOfOtherTool](#83de90385d03ac8ef27360bfcdc1ab48) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 
- [**149**Star][1y] [C++] [ajkhoury/sigmaker-x64](https://github.com/ajkhoury/SigMaker-x64) IDA Pro 7.0 compatible SigMaker plugin
- [**130**Star][1y] [Py] [cisco-talos/bass](https://github.com/cisco-talos/bass) a framework designed to automatically generate antivirus signatures from samples belonging to previously generated malware clusters
- [**71**Star][4y] [Py] [icewall/bindifffilter](https://github.com/icewall/bindifffilter) IDA Pro plugin making easier work on BinDiff results
- [**69**Star][5y] [Py] [arvinddoraiswamy/slid](https://github.com/arvinddoraiswamy/slid) detect static lib
- [**51**Star][2m] [Py] [vrtadmin/first-plugin-ida](https://github.com/vrtadmin/first-plugin-ida) Function Identification and Recovery Signature Tool
- [**45**Star][1y] [Py] [l4ys/idasignsrch](https://github.com/l4ys/idasignsrch) IDAPython Plugin for searching signatures, use xml signature database from IDA_Signsrch
- [**33**Star][3y] [Py] [g4hsean/binauthor](https://github.com/g4hsean/binauthor) an IDA pro plugin developped through research at concordia in the area of binary authorship identification
- [**31**Star][1y] [Py] [cisco-talos/casc](https://github.com/cisco-talos/casc)  IDA Pro plug-in to generate signatures
- [**25**Star][2y] [LLVM] [syreal17/cardinal](https://github.com/syreal17/cardinal) Similarity Analysis to Defeat Malware Compiler Variations
- [**23**Star][5m] [Py] [xorpd/fcatalog_server](https://github.com/xorpd/fcatalog_server) Functions Catalog
- [**21**Star][3y] [Py] [xorpd/fcatalog_client](https://github.com/xorpd/fcatalog_client) fcatalog idapython client
- [**18**Star][5y] [Py] [zaironne/snippetdetector](https://github.com/zaironne/snippetdetector) IDA Python scripts project for snippets detection
- [**16**Star][8y] [C++] [alexander-pick/idb2pat](https://github.com/alexander-pick/idb2pat) idb2pat plugin, fixed to work with IDA 6.2
- [**14**Star][8y] [Standard ML] [letsunlockiphone/iphone-baseband-ida-pro-signature-files](https://github.com/letsunlockiphone/iphone-baseband-ida-pro-signature-files) IDA Pro Signature Files iPhone Baseband Reversing
    - Also In Section: [IDA->Tools->Apple->NoCategory](#8530752bacfb388f3726555dc121cb1a) |
- [**3**Star][4y] [Py] [ayuto/discover_win](https://github.com/ayuto/discover_win) compare linux and windows binary, rename windows binary functions
    - Also In Section: [IDA->Tools->Function->Rename](#73813456eeb8212fd45e0ea347bec349) |
- [**0**Star][1y] [Py] [gh0st3rs/idaprotosync](https://github.com/gh0st3rs/idaprotosync) IDAPython plugin for identifies functions prototypes between two or more IDBs


#### <a id="19360afa4287236abe47166154bc1ece"></a>FLIRT


##### <a id="1c9d8dfef3c651480661f98418c49197"></a>FLIRTSignatureCollection


- [**599**Star][26d] [Max] [maktm/flirtdb](https://github.com/Maktm/FLIRTDB) A community driven collection of IDA FLIRT signature files
- [**307**Star][4m] [push0ebp/sig-database](https://github.com/push0ebp/sig-database) IDA FLIRT Signature Database
- [**4**Star][8m] [cloudwindby/ida-pro-sig](https://github.com/cloudwindby/ida-pro-sig) IDA PRO FLIRT signature files MSVC2017的sig文件


##### <a id="a9a63d23d32c6c789ca4d2e146c9b6d0"></a>FLIRTSignatureGenerate


- [**59**Star][10m] [Py] [push0ebp/allirt](https://github.com/push0ebp/allirt) Tool that converts All of libc to signatures for IDA Pro FLIRT Plugin. and utility make sig with FLAIR easily
- [**42**Star][8m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - Also In Section: [IDA->Tools->ImportExport->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[Ghidra->Plugins->WithOtherTools->IDA](#d832a81018c188bf585fcefa3ae23062) |




#### <a id="161e5a3437461dc8959cc923e6a18ef7"></a>Diff&&Match


- [**1542**Star][1m] [Py] [joxeankoret/diaphora](https://github.com/joxeankoret/diaphora) program diffing
- [**358**Star][12d] [Py] [checkpointsw/karta](https://github.com/checkpointsw/karta) source code assisted fast binary matching plugin for IDA
- [**330**Star][12m] [Py] [joxeankoret/pigaios](https://github.com/joxeankoret/pigaios) A tool for matching and diffing source codes directly against binaries.
- [**136**Star][1y] [Py] [nirizr/rematch](https://github.com/nirizr/rematch) REmatch, a complete binary diffing framework that is free and strives to be open source and community driven.
- [**94**Star][6m] [Visual Basic] [dzzie/idacompare](https://github.com/dzzie/idacompare) a plugin for IDA which is designed to help you  line up functions across two separate disassemblies
- [**73**Star][4y] [C] [nihilus/ida_signsrch](https://github.com/nihilus/ida_signsrch) IDA Pro plug-in conversion of Luigi Auriemma's signsrch signature matching tool.
- [**72**Star][5y] [Py] [binsigma/binsourcerer](https://github.com/binsigma/binsourcerer) Assembly to Source Code Matching Framework for IDA Pro.
- [**72**Star][3y] [vrtadmin/first](https://github.com/vrtadmin/first) Function Identification and Recovery Signature Tool
- [**52**Star][5y] [C++] [filcab/patchdiff2](https://github.com/filcab/patchdiff2) IDA binary differ. Since code.google.com/p/patchdiff2/ seemed abandoned, I did the obvious thing…
- [**14**Star][3y] [Py] [0x00ach/idadiff](https://github.com/0x00ach/idadiff) The script uses the @Heurs MACHOC algorithm (https://github.com/ANSSI-FR/polichombr) in order to build tiny CFG hashes of a source binary sample in IDA PRO
- [**14**Star][5y] [C++] [binsigma/binclone](https://github.com/binsigma/binclone) detecting code clones in malware


#### <a id="46c9dfc585ae59fe5e6f7ddf542fb31a"></a>Yara


- [**431**Star][1m] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) IDA pro plugin to find crypto constants (and more)
    - Also In Section: [IDA->Tools->encrypt](#06d2caabef97cf663bd29af2b1fe270c) |
- [**92**Star][2m] [Py] [hyuunnn/hyara](https://github.com/hyuunnn/Hyara) IDA Plugin that provides convenience when writing yararule.
    - [IDA插件](https://github.com/hy00un/hyara/tree/master/IDA%20Plugin) 
    - [BinaryNinja插件](https://github.com/hy00un/hyara/tree/master/BinaryNinja%20Plugin) 
- [**92**Star][2m] [Py] [hyuunnn/hyara](https://github.com/hyuunnn/hyara) Yara rule making tool (IDA Pro & Binary Ninja Plugin)
- [**82**Star][1y] [Py] [oalabs/findyara](https://github.com/oalabs/findyara) IDA python plugin to scan your binary with yara rules
- [**16**Star][11m] [Py] [bnbdr/ida-yara-processor](https://github.com/bnbdr/ida-yara-processor) Loader and processor for YARA's compiled rule format
    - Also In Section: [IDA->Tools->SpecificTarget->Loader](#cb59d84840e41330a7b5e275c0b81725) |
- [**14**Star][1y] [Py] [alexander-hanel/ida_yara](https://github.com/alexander-hanel/ida_yara) scan data within in an IDB using Yara
- [**14**Star][1y] [Py] [souhailhammou/idaray-plugin](https://github.com/souhailhammou/idaray-plugin) IDARay is an IDA Pro plugin that matches the database against multiple YARA files which themselves may contain multiple rules.




### <a id="5e91b280aab7f242cbc37d64ddbff82f"></a>IDB


- [**316**Star][6m] [Py] [williballenthin/python-idb](https://github.com/williballenthin/python-idb)  a library for accessing the contents of IDA Pro databases
- [**149**Star][29d] [Py] [nccgroup/idahunt](https://github.com/nccgroup/idahunt) a framework to analyze binaries with IDA Pro and hunt for things in IDA Pro
- [**86**Star][5m] [C++] [nlitsme/idbutil](https://github.com/nlitsme/idbutil) extracting information from IDA databases
- [**79**Star][3m] [Py] [nlitsme/pyidbutil](https://github.com/nlitsme/pyidbutil) extracting information from IDA databases
- [**18**Star][1y] [Py] [kkhaike/tinyidb](https://github.com/kkhaike/tinyidb) export userdata from huge idb
- [**0**Star][4y] [C] [hugues92/idaextrapassplugin](https://github.com/hugues92/idaextrapassplugin) idb fix and clean


### <a id="206ca17fc949b8e0ae62731d9bb244cb"></a>CollaborativeRE


- [**505**Star][11m] [Py] [idarlingteam/idarling](https://github.com/IDArlingTeam/IDArling) a collaborative reverse engineering plugin for IDA Pro and Hex-Rays
- [**258**Star][1y] [C++] [dga-mi-ssi/yaco](https://github.com/dga-mi-ssi/yaco) a Hex-Rays IDA plugin enabling collaborative reverse-engineering on IDA databases for multiple users
- [**88**Star][5y] [Py] [cubicalabs/idasynergy](https://github.com/cubicalabs/idasynergy) IDA Plugin with svn integerted
- [**71**Star][1m] [C++] [cseagle/collabreate](https://github.com/cseagle/collabreate) IDA Pro Collaboration/Synchronization Plugin
- [**4**Star][2y] [Py] [argussecurity/psida](https://bitbucket.org/socialauth/login/atlassianid/?next=%2Fargussecurity%2Fpsida) Python Scripts for IDA [by the Argus Research Team]


### <a id="f7d311685152ac005cfce5753c006e4b"></a>SyncWithDebugger


- [**457**Star][8d] [C] [bootleg/ret-sync](https://github.com/bootleg/ret-sync) a set of plugins that help to synchronize a debugging session (WinDbg/GDB/LLDB/OllyDbg/OllyDbg2/x64dbg) with IDA/Ghidra disassemblers
    - Also In Section: [x64dbg->Plugins->RecentAdd](#da5688c7823802e734c39b539aa39df7) |
    - [GDB插件](https://github.com/bootleg/ret-sync/tree/master/ext_gdb) 
    - [Ghidra插件](https://github.com/bootleg/ret-sync/tree/master/ext_ghidra) 
    - [IDA插件](https://github.com/bootleg/ret-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/bootleg/ret-sync/tree/master/ext_lldb) 
    - [OD](https://github.com/bootleg/ret-sync/tree/master/ext_olly1) 
    - [OD2](https://github.com/bootleg/ret-sync/tree/master/ext_olly2) 
    - [WinDgb](https://github.com/bootleg/ret-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/bootleg/ret-sync/tree/master/ext_x64dbg) 
- [**290**Star][10m] [C] [a1ext/labeless](https://github.com/a1ext/labeless) Seamless synchronization of labels, function names, comments and global variables (w/wo demangling); Dynamic dumping of debugged process memory regions
    - [IDA插件](https://github.com/a1ext/labeless/tree/master/labeless_ida) 
    - [OD](https://github.com/a1ext/labeless/tree/master/labeless_olly) 
    - [OD2](https://github.com/a1ext/labeless/tree/master/labeless_olly2) 
    - [x64dbg](https://github.com/a1ext/labeless/tree/master/labeless_x64dbg) 
- [**169**Star][12m] [Py] [andreafioraldi/idangr](https://github.com/andreafioraldi/idangr) Use angr in the IDA Pro debugger generating a state from the current debug session
- [**128**Star][2y] [Py] [comsecuris/gdbida](https://github.com/comsecuris/gdbida) a visual bridge between a GDB session and IDA Pro's disassembler
    - [IDA插件](https://github.com/comsecuris/gdbida/blob/master/ida_gdb_bridge.py) 
    - [GDB脚本](https://github.com/comsecuris/gdbida/blob/master/gdb_ida_bridge_client.py) 
- [**97**Star][4y] [C++] [quarkslab/qb-sync](https://github.com/quarkslab/qb-sync) add some helpful glue between IDA Pro and Windbg
    - [GDB插件](https://github.com/quarkslab/qb-sync/tree/master/ext_gdb) 
    - [IDA插件](https://github.com/quarkslab/qb-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/quarkslab/qb-sync/tree/master/ext_lldb) 
    - [OD2](https://github.com/quarkslab/qb-sync/tree/master/ext_olly2) 
    - [WinDbg](https://github.com/quarkslab/qb-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/quarkslab/qb-sync/tree/master/ext_x64dbg) 
- [**44**Star][3m] [JS] [sinakarvandi/windbg2ida](https://github.com/sinakarvandi/windbg2ida) dump each step in Windbg then shows these steps in IDA Windbg2ida
    - [Windbg脚本](https://github.com/sinakarvandi/windbg2ida/blob/master/windbg2ida.js) JavaScript
    - [IDA脚本](https://github.com/sinakarvandi/windbg2ida/blob/master/IDAScript.py) 
- [**36**Star][10m] [Py] [anic/ida2pwntools](https://github.com/anic/ida2pwntools) a IDA 7.0 plugins that helps to attach process created by pwntools and debug pwn
- [**28**Star][1y] [Py] [iweizime/dbghider](https://github.com/iweizime/dbghider) hide IDA Winddows debugger from processes.
- [**17**Star][7y] [Py] [rmadair/windbg2ida](https://github.com/rmadair/windbg2ida) Import debugging traces from WinDBG into IDA. Color the graph, fill in the value of all operands, etc.


### <a id="6fb7e41786c49cc3811305c520dfe9a1"></a>ImportExport&&SyncWithOtherTools


#### <a id="8ad723b704b044e664970b11ce103c09"></a>NoCategory


- [**162**Star][2m] [Py] [x64dbg/x64dbgida](https://github.com/x64dbg/x64dbgida) Official x64dbg plugin for IDA Pro.
    - Also In Section: [x64dbg->Plugins->RecentAdd](#da5688c7823802e734c39b539aa39df7) |
- [**145**Star][2m] [C++] [alschwalm/dwarfexport](https://github.com/alschwalm/dwarfexport) Export dwarf debug information from IDA Pro
- [**97**Star][2y] [Py] [robindavid/idasec](https://github.com/robindavid/idasec) IDA plugin for reverse-engineering and dynamic interactions with the Binsec platform
- [**67**Star][12m] [Py] [lucasg/idamagnum](https://github.com/lucasg/idamagnum)  a plugin for integrating MagnumDB requests within IDA
- [**59**Star][26d] [Py] [binaryanalysisplatform/bap-ida-python](https://github.com/binaryanalysisplatform/bap-ida-python) interoperatibility between BAP and IDA Pro
- [**35**Star][5y] [Py] [siberas/ida2sym](https://github.com/siberas/ida2sym) IDAScript to create Symbol file which can be loaded in WinDbg via AddSyntheticSymbol
- [**28**Star][6y] [C++] [oct0xor/deci3dbg](https://github.com/oct0xor/deci3dbg) Ida Pro debugger module for Playstation 3
    - Also In Section: [IDA->Tools->SpecificTarget->PS3](#315b1b8b41c67ae91b841fce1d4190b5) |
- [**28**Star][5m] [C++] [thalium/idatag](https://github.com/thalium/idatag) IDA plugin to explore and browse tags
- [**19**Star][2y] [Py] [brandon-everhart/angryida](https://github.com/brandon-everhart/angryida) Python based angr plug in for IDA Pro.
    - Also In Section: [OtherTools->angr](#4fe330ae3e5ce0b39735b1bfea4528af) |
- [**16**Star][4y] [C++] [m417z/mapimp](https://github.com/m417z/mapimp) an OllyDbg plugin which will help you to import map files exported by IDA, Dede, IDR, Microsoft and Borland linkers.
- [**16**Star][5y] [Py] [danielmgmi/virusbattle-ida-plugin](https://github.com/danielmgmi/virusbattle-ida-plugin) The plugin is an integration of Virus Battle API to the well known IDA Disassembler.
- [**8**Star][7y] [C++] [patois/madnes](https://github.com/patois/madnes) IDA plugin to export symbols and names from IDA db so they can be loaded into FCEUXD SP
- [**3**Star][1y] [Py] [r00tus3r/differential_debugging](https://github.com/r00tus3r/differential_debugging) Differential debugging using IDA Python and GDB


#### <a id="c7066b0c388cd447e980bf0eb38f39ab"></a>Ghidra


- [**296**Star][3m] [Py] [cisco-talos/ghida](https://github.com/cisco-talos/ghida) an IDA Pro plugin that integrates the Ghidra decompiler in IDA.
    - Also In Section: [Ghidra->Plugins->WithOtherTools->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**236**Star][8m] [Py] [daenerys-sre/source](https://github.com/daenerys-sre/source)  A framework for interoperability between IDA and Ghidra
    - Also In Section: [Ghidra->Plugins->WithOtherTools->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**86**Star][3m] [Py] [cisco-talos/ghidraaas](https://github.com/cisco-talos/ghidraaas) a simple web server that exposes Ghidra analysis through REST APIs
    - Also In Section: [Ghidra->Plugins->WithOtherTools->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**47**Star][2m] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
    - Also In Section: [Ghidra->Plugins->WithOtherTools->IDA](#d832a81018c188bf585fcefa3ae23062) |[x64dbg->Plugins->RecentAdd](#da5688c7823802e734c39b539aa39df7) |
- [**42**Star][8m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->FLIRT->FLIRTSignatureGenerate](#a9a63d23d32c6c789ca4d2e146c9b6d0) |[Ghidra->Plugins->WithOtherTools->IDA](#d832a81018c188bf585fcefa3ae23062) |


#### <a id="11139e7d6db4c1cef22718868f29fe12"></a>BinNavi


- [**378**Star][1m] [C++] [google/binexport](https://github.com/google/binexport) Export disassemblies into Protocol Buffers and to BinNavi databases
    - Also In Section: [OtherTools->BinNavi](#2683839f170250822916534f1db22eeb) |
- [**213**Star][4y] [PLpgSQL] [cseagle/freedom](https://github.com/cseagle/freedom) capstone based disassembler for extracting to binnavi
    - Also In Section: [OtherTools->BinNavi](#2683839f170250822916534f1db22eeb) |
- [**25**Star][7y] [Py] [tosanjay/bopfunctionrecognition](https://github.com/tosanjay/bopfunctionrecognition) plugin to BinNavi tool to analyze a x86 binanry file to find buffer overflow prone functions. Such functions are important for vulnerability analysis.
    - Also In Section: [OtherTools->BinNavi](#2683839f170250822916534f1db22eeb) |


#### <a id="d1ff64bee76f6749aef6100d72bfbe3a"></a>BinaryNinja


- [**68**Star][8m] [Py] [lunixbochs/revsync](https://github.com/lunixbochs/revsync) realtime cross-tool collaborative reverse engineering
    - Also In Section: [BinaryNinja->Plugins->WithOtherTools->IDA](#713fb1c0075947956651cc21a833e074) |
- [**60**Star][5m] [Py] [zznop/bnida](https://github.com/zznop/bnida) Suite of plugins that provide the ability to transfer analysis data between Binary Ninja and IDA
    - Also In Section: [BinaryNinja->Plugins->WithOtherTools->IDA](#713fb1c0075947956651cc21a833e074) |
    - [ida_export](https://github.com/zznop/bnida/blob/master/ida/ida_export.py) 将数据从IDA中导入
    - [ida_import](https://github.com/zznop/bnida/blob/master/ida/ida_import.py) 将数据导入到IDA
    - [binja_export](https://github.com/zznop/bnida/blob/master/binja_export.py) 将数据从BinaryNinja中导出
    - [binja_import](https://github.com/zznop/bnida/blob/master/binja_import.py) 将数据导入到BinaryNinja
- [**14**Star][5m] [Py] [cryptogenic/idc_importer](https://github.com/cryptogenic/idc_importer) A Binary Ninja plugin for importing IDC database dumps from IDA.
    - Also In Section: [BinaryNinja->Plugins->WithOtherTools->IDA](#713fb1c0075947956651cc21a833e074) |


#### <a id="21ed198ae5a974877d7a635a4b039ae3"></a>Radare2


- [**125**Star][7m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->Function->NoCategory](#347a2158bdd92b00cd3d4ba9a0be00ae) |[Radare2->Plugins->WithOtherTools->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**123**Star][1m] [Py] [radare/radare2ida](https://github.com/radare/radare2ida) Tools, documentation and scripts to move projects from IDA to R2 and viceversa
    - Also In Section: [Radare2->Plugins->WithOtherTools->IDA](#1cfe869820ecc97204a350a3361b31a7) |


#### <a id="a1cf7f7f849b4ca2101bd31449c2a0fd"></a>Frida


- [**129**Star][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) a reverse engineering framework created to simplify dynamic instrumentation with Frida
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |[DBI->Frida->Tools->WithOtherTools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**82**Star][5y] [Py] [techbliss/frida_for_ida_pro](https://github.com/techbliss/frida_for_ida_pro) plugin for ida pro thar uses the Frida api
    - Also In Section: [DBI->Frida->Tools->WithOtherTools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
- [**50**Star][3m] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA tools and scripts collection
    - Also In Section: [IDA->Tools->NoCategory](#c39a6d8598dde6abfeef43faf931beb5) |[DBI->Frida->Tools->RecentAdd](#54836a155de0c15b56f43634cd9cfecf) |
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
    - Also In Section: [DBI->Frida->Tools->RecentAdd](#54836a155de0c15b56f43634cd9cfecf) |


#### <a id="dd0332da5a1482df414658250e6357f8"></a>IntelPin


- [**133**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |[IDA->Tools->Vul->NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |[DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**43**Star][3y] [Batchfile] [maldiohead/idapin](https://github.com/maldiohead/idapin) plugin of ida with pin
    - Also In Section: [DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |




### <a id="004c199e1dbf71769fbafcd8e58d1ead"></a>SpecificTarget


#### <a id="5578c56ca09a5804433524047840980e"></a>NoCategory


- [**538**Star][2y] [Py] [anatolikalysch/vmattack](https://github.com/anatolikalysch/vmattack) static and dynamic virtualization-based packed analysis and deobfuscation.
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**197**Star][4y] [Py] [f8left/decllvm](https://github.com/f8left/decllvm) IDA plugin for OLLVM analysis
- [**116**Star][1y] [Py] [xerub/idastuff](https://github.com/xerub/idastuff) IDA Pro/Hexrays plugins, mainly targeted at ARM processors
- [**93**Star][4m] [Py] [themadinventor/ida-xtensa](https://github.com/themadinventor/ida-xtensa) IDAPython plugin for Tensilica Xtensa (as seen in ESP8266)
- [**91**Star][17d] [Py] [fboldewin/com-code-helper](https://github.com/fboldewin/com-code-helper) Two IDAPython Scripts help you to reconstruct Microsoft COM (Component Object Model) Code
- [**82**Star][4y] [C++] [wjp/idados](https://github.com/wjp/idados) Eric Fry's IDA/DOSBox debugger plugin
    - Also In Section: [IDA->Tools->Debug->NoCategory](#2944dda5289f494e5e636089db0d6a6a) |
- [**75**Star][3m] [Py] [coldzer0/ida-for-delphi](https://github.com/coldzer0/ida-for-delphi) IDA Python Script to Get All function names from Event Constructor (VCL)
- [**59**Star][2y] [Py] [isra17/nrs](https://github.com/isra17/nrs) NSIS Reversing Suite with IDA Plugins
- [**56**Star][3m] [Py] [giantbranch/mipsaudit](https://github.com/giantbranch/mipsaudit) IDA script to assist in MIPS static scan
- [**55**Star][5m] [C++] [troybowman/dtxmsg](https://github.com/troybowman/dtxmsg) an IDA plugin that helped me reverse-engineer the DTXConnectionServices framework.
- [**50**Star][9m] [C] [lab313ru/smd_ida_tools](https://github.com/lab313ru/smd_ida_tools) Special IDA Pro tools for the Sega Genesis/Megadrive romhackers
- [**47**Star][2y] [C++] [antid0tecom/aarch64_armv81extension](https://github.com/antid0tecom/aarch64_armv81extension) IDA AArch64 processor extender extension: Adding support for ARMv8.1 opcodes
- [**33**Star][3y] [Py] [sam-b/windows_syscalls_dumper](https://github.com/sam-b/windows_syscalls_dumper) A dirty IDAPython script to dump windows system call number/name pairs as JSON
- [**24**Star][3y] [C++] [sektioneins/aarch64_cryptoextension](https://github.com/sektioneins/aarch64_cryptoextension) IDA AArch64 processor extender extension: Adding crypto extension instructions (AES/SHA1/SHA256)
- [**23**Star][3y] [Py] [pfalcon/ida-xtensa2](https://github.com/pfalcon/ida-xtensa2) IDAPython plugin for Tensilica Xtensa (as seen in ESP8266), version 2
- [**21**Star][11m] [Py] [howmp/comfinder](https://github.com/howmp/comfinder) IDA plugin for COM
    - Also In Section: [IDA->Tools->Function->Rename](#73813456eeb8212fd45e0ea347bec349) |
- [**20**Star][5y] [Py] [digitalbond/ibal](https://github.com/digitalbond/ibal) IDA Pro Bootrom Analysis Library, which contains a number of useful functions for analyzing embedded ROMs
- [**18**Star][2y] [C] [andywhittaker/idaproboschme7x](https://github.com/andywhittaker/idaproboschme7x) IDA Pro Bosch ME7x C16x Disassembler Helper
- [**16**Star][3y] [Py] [0xdeva/ida-cpu-risc-v](https://github.com/0xdeva/ida-cpu-risc-v) RISCV-V disassembler for IDA Pro
- [**15**Star][5y] [Py] [dolphin-emu/gcdsp-ida](https://github.com/dolphin-emu/gcdsp-ida) An IDA plugin for GC DSP reverse engineering
- [**11**Star][2y] [C++] [hyperiris/gekkops](https://github.com/hyperiris/gekkops) Nintendo GameCube Gekko CPU Extension plug-in for IDA Pro 5.2
- [**4**Star][3y] [Py] [neogeodev/idaneogeo](https://github.com/neogeodev/idaneogeo) NeoGeo binary loader & helper for the Interactive Disassembler
- [**2**Star][4m] [C] [extremlapin/glua_c_headers_for_ida](https://github.com/extremlapin/glua_c_headers_for_ida) Glua module C headers for IDA
- [**2**Star][5m] [Py] [lucienmp/idapro_m68k](https://github.com/lucienmp/idapro_m68k) Extends existing support in IDA for the m68k by adding gdb step-over and type information support
- [**0**Star][8m] [C] [0xd0cf11e/idcscripts](https://github.com/0xd0cf11e/idcscripts) Scripts used when analyzing files in IDA
    - [emotet-decode](https://github.com/0xd0cf11e/idcscripts/blob/master/emotet/emotet-decode.idc) 解码emotet
- [**0**Star][2m] [C++] [marakew/emuppc](https://github.com/marakew/emuppc) simple PowerPC emulator for unpack into IDAPro some PowerPC binary


#### <a id="cb59d84840e41330a7b5e275c0b81725"></a>Loader&Processor


- [**204**Star][1y] [Py] [fireeye/idawasm](https://github.com/fireeye/idawasm) IDA Pro loader and processor modules for WebAssembly
- [**158**Star][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**155**Star][2y] [Py] [crytic/ida-evm](https://github.com/crytic/ida-evm) IDA Processor Module for the Ethereum Virtual Machine (EVM)
- [**142**Star][8d] [Py] [argp/iboot64helper](https://github.com/argp/iboot64helper) IDAPython loader to help with AArch64 iBoot, iBEC, and SecureROM reverse engineering
- [**128**Star][2y] [C] [gsmk/hexagon](https://github.com/gsmk/hexagon) IDA processor module for the hexagon (QDSP6) processor
- [**107**Star][1y] [pgarba/switchidaproloader](https://github.com/pgarba/switchidaproloader) Loader for IDA Pro to support the Nintendo Switch NRO binaries
- [**78**Star][8m] [Py] [reswitched/loaders](https://github.com/reswitched/loaders) IDA Loaders for Switch binaries(NSO / NRO)
- [**72**Star][2y] [Py] [embedi/meloader](https://github.com/embedi/meloader) Intel Management Engine firmware loader plugin for IDA
- [**55**Star][6m] [C++] [mefistotelis/ida-pro-loadmap](https://github.com/mefistotelis/ida-pro-loadmap) Plugin for IDA Pro disassembler which allows loading .map files.
- [**37**Star][12m] [C++] [patois/nesldr](https://github.com/patois/nesldr) Nintendo Entertainment System (NES) ROM loader module for IDA Pro
- [**35**Star][1y] [Py] [bnbdr/ida-bpf-processor](https://github.com/bnbdr/ida-bpf-processor) BPF Processor for IDA Python
- [**33**Star][1y] [C++] [teammolecule/toshiba-mep-idp](https://github.com/TeamMolecule/toshiba-mep-idp) IDA Pro module for Toshiba MeP processors
- [**32**Star][5y] [Py] [0xebfe/3dsx-ida-pro-loader](https://github.com/0xebfe/3dsx-ida-pro-loader) IDA PRO Loader for 3DSX files
- [**28**Star][4y] [C] [gdbinit/teloader](https://github.com/gdbinit/teloader) A TE executable format loader for IDA
- [**27**Star][3y] [Py] [w4kfu/ida_loader](https://github.com/w4kfu/ida_loader) Some loader module for IDA
- [**26**Star][3m] [Py] [ghassani/mclf-ida-loader](https://github.com/ghassani/mclf-ida-loader) An IDA file loader for Mobicore trustlet and driver binaries
- [**23**Star][2y] [C++] [balika011/belf](https://github.com/balika011/belf) Balika011's PlayStation 4 ELF loader for IDA Pro 7.0/7.1
- [**23**Star][6y] [vtsingaras/qcom-mbn-ida-loader](https://github.com/vtsingaras/qcom-mbn-ida-loader) IDA loader plugin for Qualcomm Bootloader Stages
- [**20**Star][3y] [C++] [patois/ndsldr](https://github.com/patois/ndsldr) Nintendo DS ROM loader module for IDA Pro
- [**18**Star][8y] [Py] [rpw/flsloader](https://github.com/rpw/flsloader) IDA Pro loader module for Infineon/Intel-based iPhone baseband firmwares
- [**17**Star][8m] [C++] [gocha/ida-snes-ldr](https://github.com/gocha/ida-snes-ldr) SNES ROM Cartridge File Loader for IDA (Interactive Disassembler) 6.x
- [**16**Star][11m] [Py] [bnbdr/ida-yara-processor](https://github.com/bnbdr/ida-yara-processor) Loader and processor for YARA's compiled rule format
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |
- [**16**Star][8m] [C++] [gocha/ida-65816-module](https://github.com/gocha/ida-65816-module) SNES 65816 processor plugin for IDA (Interactive Disassembler) 6.x
- [**16**Star][1y] [Py] [lcq2/riscv-ida](https://github.com/lcq2/riscv-ida) RISC-V ISA processor module for IDAPro 7.x
- [**16**Star][1y] [Py] [ptresearch/nios2](https://github.com/ptresearch/nios2) IDA Pro processor module for Altera Nios II Classic/Gen2 microprocessor architecture
- [**14**Star][2y] [Py] [patois/necromancer](https://github.com/patois/necromancer) IDA Pro V850 Processor Module Extension
- [**13**Star][1y] [Py] [rolfrolles/hiddenbeeloader](https://github.com/rolfrolles/hiddenbeeloader) IDA loader module for Hidden Bee's custom executable file format
- [**10**Star][4y] [C++] [areidz/nds_loader](https://github.com/areidz/nds_loader) Nintendo DS loader module for IDA Pro 6.1
- [**10**Star][6y] [Py] [cycad/mbn_loader](https://github.com/cycad/mbn_loader) IDA Pro Loader Plugin for Samsung Galaxy S4 ROMs
- [**7**Star][1y] [C++] [fail0verflow/rl78-ida-proc](https://github.com/fail0verflow/rl78-ida-proc) Renesas RL78 processor module for IDA
- [**5**Star][8m] [C++] [gocha/ida-spc700-module](https://github.com/gocha/ida-spc700-module) SNES SPC700 processor plugin for IDA (Interactive Disassembler)
- [**3**Star][8m] [C++] [gocha/ida-snes_spc-ldr](https://github.com/gocha/ida-snes_spc-ldr) SNES-SPC700 Sound File Loader for IDA (Interactive Disassembler)
- [**2**Star][2m] [C] [cisco-talos/ida_tilegx](https://github.com/cisco-talos/ida_tilegx) This is an IDA processor module for the Tile-GX processor architecture


#### <a id="1b17ac638aaa09852966306760fda46b"></a>GoLang


- [**367**Star][9m] [Py] [sibears/idagolanghelper](https://github.com/sibears/idagolanghelper) Set of IDA Pro scripts for parsing GoLang types information stored in compiled binary
- [**292**Star][1m] [Py] [strazzere/golang_loader_assist](https://github.com/strazzere/golang_loader_assist) Making GO reversing easier in IDA Pro


#### <a id="4c158ccc5aee04383755851844fdd137"></a>WindowsDriver


- [**303**Star][1y] [Py] [fsecurelabs/win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) A tool to help when dealing with Windows IOCTL codes or reversing Windows drivers.
- [**218**Star][1y] [Py] [nccgroup/driverbuddy](https://github.com/nccgroup/driverbuddy) IDA Python script to assist with the reverse engineering of Windows kernel drivers.
- [**74**Star][5y] [Py] [tandasat/winioctldecoder](https://github.com/tandasat/winioctldecoder) IDA Plugin which decodes Windows Device I/O control code into DeviceType, FunctionCode, AccessType and MethodType.
- [**23**Star][1y] [C] [ioactive/kmdf_re](https://github.com/ioactive/kmdf_re) Helper idapython code for reversing kmdf drivers


#### <a id="315b1b8b41c67ae91b841fce1d4190b5"></a>PS3&&PS4


- [**68**Star][2m] [C] [aerosoul94/ida_gel](https://github.com/aerosoul94/ida_gel) A collection of IDA loaders for various game console ELF's. (PS3, PSVita, WiiU)
- [**55**Star][7y] [C++] [kakaroto/ps3ida](https://github.com/kakaroto/ps3ida) IDA scripts and plugins for PS3
- [**44**Star][2y] [C] [aerosoul94/dynlib](https://github.com/aerosoul94/dynlib) IDA Pro plugin to aid PS4 user mode ELF reverse engineering.
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
- [**28**Star][6y] [C++] [oct0xor/deci3dbg](https://github.com/oct0xor/deci3dbg) Ida Pro debugger module for Playstation 3
    - Also In Section: [IDA->Tools->ImportExport->NoCategory](#8ad723b704b044e664970b11ce103c09) |


#### <a id="f5e51763bb09d8fd47ee575a98bedca1"></a>PDB


- [**96**Star][4m] [C++] [mixaill/fakepdb](https://github.com/mixaill/fakepdb) 通过IDA数据库生成PDB文件
- [**38**Star][1y] [Py] [ax330d/ida_pdb_loader](https://github.com/ax330d/ida_pdb_loader) IDA PDB Loader
- [**14**Star][1y] [CMake] [gdataadvancedanalytics/bindifflib](https://github.com/gdataadvancedanalytics/bindifflib) Automated library compilation and PDB annotation with CMake and IDA Pro
- [**2**Star][5m] [Py] [clarkb7/annotate_lineinfo](https://github.com/clarkb7/annotate_lineinfo) Annotate IDA with source and line number information from a PDB


#### <a id="7d0681efba2cf3adaba2780330cd923a"></a>Flash&&SWF


- [**33**Star][1y] [Py] [kasperskylab/actionscript3](https://github.com/kasperskylab/actionscript3) Tools for static and dynamic analysis of ActionScript3 SWF files.
- [**27**Star][4y] [C++] [nihilus/ida-pro-swf](https://github.com/nihilus/ida-pro-swf) SWF Process


#### <a id="841d605300beba45c3be131988514a03"></a>MalwareFamily


- [**9**Star][2y] [Py] [d00rt/easy_way_nymaim](https://github.com/d00rt/easy_way_nymaim) An IDA Pro script for creating a clearer idb for nymaim malware
- [**8**Star][3y] [Py] [thngkaiyuan/mynaim](https://github.com/thngkaiyuan/mynaim) IDAPython Deobfuscation Scripts for Nymaim Samples
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**4**Star][2y] [Py] [immortalp0ny/fyvmdisassembler](https://github.com/immortalp0ny/fyvmdisassembler) IDAPython scripts for devirtualization/disassembly FinSpy VM
- [**4**Star][8m] [C] [lacike/gandcrab_string_decryptor](https://github.com/lacike/gandcrab_string_decryptor) IDC script for decrypting strings in the GandCrab v5.1-5.3
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |


#### <a id="ad44205b2d943cfa2fa805b2643f4595"></a>CTF


- [**130**Star][2y] [Py] [pwning/defcon25-public](https://github.com/pwning/defcon25-public) Publicly released tools/plugins from PPP for DEFCON 25 CTF Finals




### <a id="ad68872e14f70db53e8d9519213ec039"></a>IDAPython


#### <a id="2299bc16945c25652e5ad4d48eae8eca"></a>NoCategory


- [**711**Star][25d] [Py] [idapython/src](https://github.com/idapython/src) IDAPython project for Hex-Ray's IDA Pro
- [**368**Star][2m] [Py] [tmr232/sark](https://github.com/tmr232/sark) IDAPython Made Easy
- [**249**Star][2y] [Py] [intezer/docker-ida](https://github.com/intezer/docker-ida) Run IDA Pro disassembler in Docker containers for automating, scaling and distributing the use of IDAPython scripts.
- [**80**Star][4y] [idapython/bin](https://github.com/idapython/bin) IDAPython binaries
- [**68**Star][2y] [Py] [alexander-hanel/idapython6to7](https://github.com/alexander-hanel/idapython6to7) 
- [**43**Star][1y] [Py] [nirizr/pytest-idapro](https://github.com/nirizr/pytest-idapro) A pytest module for The Interactive Disassembler and IDAPython; Record and Replay IDAPython API, execute inside IDA or use mockups of IDAPython API.
- [**28**Star][2y] [Py] [kerrigan29a/idapython_virtualenv](https://github.com/kerrigan29a/idapython_virtualenv) Enable Virtualenv or Conda in IDAPython
- [**23**Star][3y] [Py] [devttys0/idascript](https://github.com/devttys0/idascript) a wrapper around IDA Pro that makes it easy to automate the execution of IDA scripts  against target files from the command line


#### <a id="c42137cf98d6042372b1fd43c3635135"></a>cheatsheets


- [**233**Star][7d] [Py] [inforion/idapython-cheatsheet](https://github.com/inforion/idapython-cheatsheet) Scripts and cheatsheets for IDAPython




### <a id="846eebe73bef533041d74fc711cafb43"></a>InstructRef&&Doc


- [**496**Star][12m] [PLpgSQL] [nologic/idaref](https://github.com/nologic/idaref) IDA Pro Instruction Reference Plugin
- [**444**Star][4m] [C++] [alexhude/friend](https://github.com/alexhude/friend) Flexible Register/Instruction Extender aNd Documentation
    - Also In Section: [IDA->Tools->Nav->NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**244**Star][2y] [Py] [gdelugre/ida-arm-system-highlight](https://github.com/gdelugre/ida-arm-system-highlight) IDA script for highlighting and decoding ARM system instructions
- [**105**Star][1m] [Py] [neatmonster/amie](https://github.com/neatmonster/amie) A Minimalist Instruction Extender for the ARM architecture and IDA Pro
- [**45**Star][8y] [Py] [zynamics/msdn-plugin-ida](https://github.com/zynamics/msdn-plugin-ida) Imports MSDN documentation into IDA Pro
- [**24**Star][3y] [AutoIt] [yaseralnajjar/ida-msdn-helper](https://github.com/yaseralnajjar/IDA-MSDN-helper) IDA Pro MSDN Helper


### <a id="c08ebe5b7eec9fc96f8eff36d1d5cc7d"></a>ScriptWritting


#### <a id="45fd7cfce682c7c25b4f3fbc4c461ba2"></a>NoCategory


- [**386**Star][3y] [Py] [36hours/idaemu](https://github.com/36hours/idaemu) an IDA Pro Plugin use for emulating code in IDA Pro.
    - Also In Section: [IDA->Tools->Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**279**Star][25d] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) marries a supported binary analysis framework, such as IDA Pro or Radare2, with Unicorn’s emulation framework to provide the user with an easy to use and flexible interface for scripting emulation tasks
    - Also In Section: [IDA->Tools->Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**135**Star][8d] [Py] [arizvisa/ida-minsc](https://github.com/arizvisa/ida-minsc) a plugin for IDA Pro that assists a user with scripting the IDAPython plugin that is bundled with the disassembler.
- [**101**Star][17d] [Py] [patois/idapyhelper](https://github.com/patois/idapyhelper) IDAPyHelper is a script for the Interactive Disassembler that helps writing IDAPython scripts and plugins.
- [**74**Star][4m] [C++] [0xeb/ida-qscripts](https://github.com/0xeb/ida-qscripts) An IDA plugin to increase productivity when developing scripts for IDA
    - Also In Section: [IDA->Tools->Nav->NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**42**Star][5m] [C++] [0xeb/ida-climacros](https://github.com/0xeb/ida-climacros) Create and use macros in IDA's CLIs
- [**32**Star][2y] [CMake] [zyantific/ida-cmake](https://github.com/zyantific/ida-cmake) IDA plugin CMake build-script
- [**22**Star][1y] [Py] [nirizr/idasix](https://github.com/nirizr/idasix) IDAPython compatibility library. idasix aims to create a smooth ida development process and allow a single codebase to function with multiple IDA/IDAPython versions
- [**4**Star][7m] [inndy/idapython-cheatsheet](https://github.com/inndy/idapython-cheatsheet) scripting IDA like a Pro


#### <a id="1a56a5b726aaa55ec5b7a5087d6c8968"></a>Qt


- [**25**Star][12m] [techbliss/ida_pro_ultimate_qt_build_guide](https://github.com/techbliss/ida_pro_ultimate_qt_build_guide) Ida Pro Ultimate Qt Build Guide
- [**13**Star][2m] [Py] [tmr232/cute](https://github.com/tmr232/cute) Cross-Qt compatibility module for IDAPython.
- [**9**Star][3y] [Py] [techbliss/ida_pro_screen_recorder](https://github.com/techbliss/ida_pro_screen_recorder) PyQt plugin for Ida Pro for Screen recording.


#### <a id="1721c09501e4defed9eaa78b8d708361"></a>Console&&GUI


- [**267**Star][17d] [Py] [eset/ipyida](https://github.com/eset/ipyida) IPython console integration for IDA Pro
- [**231**Star][2y] [Jupyter Notebook] [james91b/ida_ipython](https://github.com/james91b/ida_ipython) An IDA Pro Plugin for embedding an IPython Kernel
- [**175**Star][4m] [Py] [techbliss/python_editor](https://github.com/techbliss/python_editor) Better CodeEditor for Ida Pro.


#### <a id="227fbff77e3a13569ef7b007344d5d2e"></a>Template


- [**5**Star][2y] [C++] [patois/ida_vs2017](https://github.com/patois/ida_vs2017) IDA 7.x VisualStudio 2017 Sample Project for IDA and HexRays plugins (works with Community Edition)
- [**4**Star][5y] [JS] [nihilus/ida-pro-plugin-wizard-for-vs2013](https://github.com/nihilus/ida-pro-plugin-wizard-for-vs2013) IDA Pro plugin wizard for VisualStudio 2013


#### <a id="8b19bb8cf9a5bc9e6ab045f3b4fabf6a"></a>OtherLang


- [**22**Star][3y] [Java] [cblichmann/idajava](https://github.com/cblichmann/idajava) Java integration for Hex-Rays IDA Pro
- [**8**Star][3y] [C++] [nlitsme/idaperl](https://github.com/nlitsme/idaperl) perl scripting support for IDApro




### <a id="dc35a2b02780cdaa8effcae2b6ce623e"></a>Ancient


- [**162**Star][4y] [Py] [osirislab/fentanyl](https://github.com/osirislab/Fentanyl) an IDAPython script that makes patching significantly easier
- [**127**Star][6y] [C++] [crowdstrike/crowddetox](https://github.com/crowdstrike/crowddetox) CrowdStrike CrowdDetox Plugin for Hex-Rays，automatically removes junk code and variables from Hex-Rays function decompilation
- [**94**Star][5y] [Py] [nihilus/ida-idc-scripts](https://github.com/nihilus/ida-idc-scripts) Varoius IDC-scripts I've collected during the years.
- [**83**Star][6y] [Py] [einstein-/hexrays-python](https://github.com/einstein-/hexrays-python) Python bindings for the Hexrays Decompiler
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


### <a id="e3e7030efc3b4de3b5b8750b7d93e6dd"></a>Debug&&DynamicData


#### <a id="2944dda5289f494e5e636089db0d6a6a"></a>NoCategory


- [**391**Star][12m] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) Debugger plugin for IDA Pro backed by the Unicorn Engine
    - Also In Section: [IDA->Tools->Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**185**Star][5y] [C++] [nihilus/scyllahide](https://github.com/nihilus/scyllahide) an x64/x86 usermode Anti-Anti-Debug library
- [**107**Star][2m] [Py] [danielplohmann/apiscout](https://github.com/danielplohmann/apiscout) simplifying Windows API import recovery on arbitrary memory dumps
- [**82**Star][4y] [C++] [wjp/idados](https://github.com/wjp/idados) Eric Fry's IDA/DOSBox debugger plugin
    - Also In Section: [IDA->Tools->SpecificTarget->NoCategory](#5578c56ca09a5804433524047840980e) |
- [**56**Star][7y] [Py] [cr4sh/ida-vmware-gdb](https://github.com/cr4sh/ida-vmware-gdb) Helper script for Windows kernel debugging with IDA Pro on VMware + GDB stub
- [**42**Star][5y] [Py] [nihilus/idasimulator](https://github.com/nihilus/idasimulator) a plugin that extends IDA's conditional breakpoint support, making it easy to augment / replace complex executable code inside a debugged process with Python code.
- [**38**Star][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) some idapython scripts for android debugging.
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**22**Star][5y] [Py] [techbliss/scylladumper](https://github.com/techbliss/scylladumper) Ida Plugin to Use the Awsome Scylla plugin
- [**14**Star][5y] [Py] [techbliss/free_the_debuggers](https://github.com/techbliss/free_the_debuggers) Free_the_Debuggers
- [**0**Star][2y] [Py] [benh11235/ida-windbglue](https://github.com/benh11235/ida-windbglue) Humble suite of scripts to assist with remote debugging using IDA pro client and winDBG server.


#### <a id="0fbd352f703b507853c610a664f024d1"></a>DBIData


- [**933**Star][12m] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) Code Coverage Explorer for IDA Pro & Binary Ninja
    - Also In Section: [DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->Tools->WithOtherTools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |[DBI->Frida->Tools->WithOtherTools->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**133**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [IDA->Tools->ImportExport->IntelPin](#dd0332da5a1482df414658250e6357f8) |[IDA->Tools->Vul->NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |[DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**129**Star][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) a reverse engineering framework created to simplify dynamic instrumentation with Frida
    - Also In Section: [IDA->Tools->ImportExport->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |[DBI->Frida->Tools->WithOtherTools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**121**Star][5y] [C++] [zachriggle/ida-splode](https://github.com/zachriggle/ida-splode) Augmenting Static Reverse Engineering with Dynamic Analysis and Instrumentation
    - Also In Section: [DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/zachriggle/ida-splode/tree/master/py) 
    - [PinTool](https://github.com/zachriggle/ida-splode/tree/master/src) 
- [**117**Star][2y] [C++] [0xphoenix/mazewalker](https://github.com/0xphoenix/mazewalker) Toolkit for enriching and speeding up static malware analysis
    - Also In Section: [DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |
    - [mazeui](https://github.com/0xphoenix/mazewalker/blob/master/MazeUI/mazeui.py) 在IDA中显示界面
    - [PyScripts](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/PyScripts) Python脚本，处理收集到的数据
    - [PinClient](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/src) 
- [**88**Star][8y] [C] [neuroo/runtime-tracer](https://github.com/neuroo/runtime-tracer) Dynamic tracing for binary applications (using PIN), IDA plugin to visualize and interact with the traces
    - Also In Section: [DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |
    - [PinTool](https://github.com/neuroo/runtime-tracer/tree/master/tracer) 
    - [IDA插件](https://github.com/neuroo/runtime-tracer/tree/master/ida-pin) 
- [**80**Star][3y] [Py] [davidkorczynski/repeconstruct](https://github.com/davidkorczynski/repeconstruct)  automatically unpacking binaries and rebuild the binaries in a manner well-suited for further analysis, specially focused on further manual analysis in IDA pro.
- [**51**Star][11m] [Py] [cisco-talos/dyndataresolver](https://github.com/cisco-talos/dyndataresolver) Dynamic Data Resolver (DDR) IDA Pro Plug-in
    - Also In Section: [DBI->DynamoRIO->Tools->WithOtherTools](#928642a55eff34b6b52622c6862addd2) |
    - [DDR](https://github.com/cisco-talos/dyndataresolver/blob/master/VS_project/ddr/ddr.sln) 基于DyRIO的Client
    - [IDA插件](https://github.com/cisco-talos/dyndataresolver/tree/master/IDAplugin) 
- [**20**Star][8m] [C++] [secrary/findloop](https://github.com/secrary/findloop) find possible encryption/decryption or compression/decompression code
    - Also In Section: [DBI->DynamoRIO->Tools->WithOtherTools](#928642a55eff34b6b52622c6862addd2) |
- [**15**Star][1y] [C++] [agustingianni/instrumentation](https://github.com/agustingianni/instrumentation) Collection of tools implemented using pintools aimed to help in the task of reverse engineering.
    - Also In Section: [DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |
    - [CodeCoverage](https://github.com/agustingianni/instrumentation/tree/master/CodeCoverage) 
    - [Pinnacle](https://github.com/agustingianni/instrumentation/tree/master/Pinnacle) 
    - [Recoverer](https://github.com/agustingianni/instrumentation/tree/master/Recoverer) 
    - [Resolver](https://github.com/agustingianni/instrumentation/tree/master/Resolver) 


#### <a id="b31acf6c84a9506066d497af4e702bf5"></a>DebuggerData


- [**604**Star][3m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) IDAPython tool for C++ vtables reconstruction
    - Also In Section: [IDA->Tools->Structure->C++Class](#4900b1626f10791748b20630af6d6123) |
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


- [**385**Star][4m] [Py] [ynvb/die](https://github.com/ynvb/die)  an IDA python plugin designed to enrich IDA`s static analysis with dynamic data
- [**380**Star][4y] [Py] [deresz/funcap](https://github.com/deresz/funcap) IDA Pro script to add some useful runtime info to static analysis
- [**104**Star][3y] [Py] [c0demap/codemap](https://github.com/c0demap/codemap) a binary analysis tool for "run-trace visualization" provided as IDA plugin.
    - [IDA插件](https://github.com/c0demap/codemap/blob/master/idapythonrc.py) 
    - [Web服务器](https://github.com/c0demap/codemap/tree/master/codemap/server) 




### <a id="d2166f4dac4eab7fadfe0fd06467fbc9"></a>Decompiler&&AST


- [**1668**Star][7m] [C++] [yegord/snowman](https://github.com/yegord/snowman)  a native code to C/C++ decompiler, supporting x86, AMD64, and ARM architectures
    - Also In Section: [x64dbg->Plugins->RecentAdd](#da5688c7823802e734c39b539aa39df7) |
    - [IDA插件](https://github.com/yegord/snowman/tree/master/src/ida-plugin) 
    - [snowman](https://github.com/yegord/snowman/tree/master/src/snowman) QT界面
    - [nocode](https://github.com/yegord/snowman/tree/master/src/nocode) 命令行工具
    - [nc](https://github.com/yegord/snowman/tree/master/src/nc) 核心代码，可作为库使用
- [**1321**Star][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) Hex-Rays Decompiler plugin for better code navigation
    - Also In Section: [IDA->Tools->Nav->NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>View Details</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**467**Star][4y] [Py] [einstein-/decompiler](https://github.com/EiNSTeiN-/decompiler) A decompiler with multiple backend support, written in Python. Works with IDA and Capstone.
- [**406**Star][3m] [C++] [avast/retdec-idaplugin](https://github.com/avast/retdec-idaplugin) RetDec plugin for IDA
- [**292**Star][5y] [C++] [smartdec/smartdec](https://github.com/smartdec/smartdec) SmartDec decompiler
    - [IDA插件](https://github.com/smartdec/smartdec/tree/master/src/ida-plugin) 
    - [nocode](https://github.com/smartdec/smartdec/tree/master/src/nocode) 命令行反编译器
    - [smartdec](https://github.com/smartdec/smartdec/tree/master/src/smartdec) 带GUI界面的反编译器
    - [nc](https://github.com/smartdec/smartdec/tree/master/src/nc) 反编译器的核心代码
- [**286**Star][5y] [Py] [aaronportnoy/toolbag](https://github.com/aaronportnoy/toolbag) The IDA Toolbag is a plugin providing supplemental functionality to Hex-Rays IDA Pro disassembler.
- [**229**Star][6m] [Py] [patois/dsync](https://github.com/patois/dsync) IDAPython plugin that synchronizes disassembler and decompiler views
    - Also In Section: [IDA->Tools->Nav->NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**167**Star][1y] [Py] [tintinweb/ida-batch_decompile](https://github.com/tintinweb/ida-batch_decompile) IDA Batch Decompile plugin and script for Hex-Ray's IDA Pro that adds the ability to batch decompile multiple files and their imports with additional annotations (xref, stack var size) to the pseudocode .c file
- [**158**Star][8d] [Py] [fireeye/fidl](https://github.com/fireeye/fidl) A sane API for IDA Pro's decompiler. Useful for malware RE and vulnerability research
- [**150**Star][1y] [Py] [ax330d/hrdev](https://github.com/ax330d/hrdev) Hex-Rays Decompiler Enhanced View
    - Also In Section: [IDA->Tools->Nav->GUIEnhencement](#03fac5b3abdbd56974894a261ce4e25f) |
- [**103**Star][8m] [Py] [sibears/hrast](https://github.com/sibears/hrast) PoC of modifying HexRays AST
- [**89**Star][6m] [Py] [patois/hrdevhelper](https://github.com/patois/hrdevhelper) HexRays decompiler plugin that visualizes the ctree of decompiled functions.
    - Also In Section: [IDA->Tools->Nav->GUIEnhencement](#03fac5b3abdbd56974894a261ce4e25f) |
- [**64**Star][12d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) An IDAPython decompiler script that helps auditing calls to the memcpy() and memmove() functions.
    - Also In Section: [IDA->Tools->Vul->NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |
- [**23**Star][2y] [C++] [dougallj/dj_ida_plugins](https://github.com/dougallj/dj_ida_plugins) Plugins for IDA Pro and Hex-Rays


### <a id="7199e8787c0de5b428f50263f965fda7"></a>DeObfuscate


- [**1360**Star][2m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) Automatically extract obfuscated strings from malware.
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**538**Star][2y] [Py] [anatolikalysch/vmattack](https://github.com/anatolikalysch/vmattack) static and dynamic virtualization-based packed analysis and deobfuscation.
    - Also In Section: [IDA->Tools->SpecificTarget->NoCategory](#5578c56ca09a5804433524047840980e) |
- [**293**Star][4m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) Hex-Rays microcode API plugin for breaking an obfuscating compiler
    - Also In Section: [IDA->Tools->Microcode](#7a2977533ccdac70ee6e58a7853b756b) |
- [**202**Star][2y] [Py] [tkmru/nao](https://github.com/tkmru/nao) Simple No-meaning Assembly Omitter for IDA Pro (CURRENTLY UNDER DEVELOPMENT)
    - Also In Section: [IDA->Tools->Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**47**Star][2y] [Py] [riscure/drop-ida-plugin](https://github.com/riscure/drop-ida-plugin) Experimental opaque predicate detection for IDA Pro
- [**23**Star][4m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
    - Also In Section: [IDA->Tools->TaintAnalysis](#34ac84853604a7741c61670f2a075d20) |
- [**8**Star][3y] [Py] [thngkaiyuan/mynaim](https://github.com/thngkaiyuan/mynaim) IDAPython Deobfuscation Scripts for Nymaim Samples
    - Also In Section: [IDA->Tools->SpecificTarget->MalwareFamily](#841d605300beba45c3be131988514a03) |


### <a id="fcf75a0881617d1f684bc8b359c684d7"></a>Nav&&QuickAccess&&Graph&&Image


#### <a id="c5b120e1779b928d860ad64ff8d23264"></a>NoCategory


- [**1321**Star][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) Hex-Rays Decompiler plugin for better code navigation
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
        <details>
        <summary>View Details</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**444**Star][4m] [C++] [alexhude/friend](https://github.com/alexhude/friend) Flexible Register/Instruction Extender aNd Documentation
    - Also In Section: [IDA->Tools->InstructRef](#846eebe73bef533041d74fc711cafb43) |
- [**364**Star][2m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) Make your IDA Lazy!
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->Tools->Vul->NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |
        <details>
        <summary>View Details</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**328**Star][3m] [Py] [pfalcon/scratchabit](https://github.com/pfalcon/scratchabit) Easily retargetable and hackable interactive disassembler with IDAPython-compatible plugin API
- [**229**Star][6m] [Py] [patois/dsync](https://github.com/patois/dsync) IDAPython plugin that synchronizes disassembler and decompiler views
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**184**Star][1m] [Py] [danigargu/dereferencing](https://github.com/danigargu/dereferencing) IDA Pro plugin that implements more user-friendly register and stack views
- [**130**Star][2y] [Py] [comsecuris/ida_strcluster](https://github.com/comsecuris/ida_strcluster) extending IDA's string navigation capabilities
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
- [**99**Star][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) IDAPython plugin for finding function strings recursively
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->Tools->Function->Nav](#e4616c414c24b58626f834e1be079ebc) |
- [**80**Star][1y] [Py] [ax330d/functions-plus](https://github.com/ax330d/functions-plus) IDA Pro plugin to show functions in a tree view
    - Also In Section: [IDA->Tools->Function->Nav](#e4616c414c24b58626f834e1be079ebc) |
- [**74**Star][4m] [C++] [0xeb/ida-qscripts](https://github.com/0xeb/ida-qscripts) An IDA plugin to increase productivity when developing scripts for IDA
    - Also In Section: [IDA->Tools->ScriptWritting->NoCategory](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**48**Star][3m] [C++] [jinmo/ifred](https://github.com/jinmo/ifred) IDA command palette & more (Ctrl+Shift+P, Ctrl+P)
- [**40**Star][4m] [Py] [tmr232/brutal-ida](https://github.com/tmr232/brutal-ida) Block Redo & Undo To Achieve Legacy IDA
- [**23**Star][7y] [C++] [cr4sh/ida-ubigraph](https://github.com/cr4sh/ida-ubigraph) IDA Pro plug-in and tools for displaying 3D graphs of procedures using UbiGraph
- [**17**Star][2y] [Py] [tmr232/graphgrabber](https://github.com/tmr232/graphgrabber) grab full-resolution images of IDA graphs.
- [**5**Star][2y] [Py] [handsomematt/ida_func_ptr](https://github.com/handsomematt/ida_func_ptr) Easily create and copy function pointers to functions in IDA.


#### <a id="03fac5b3abdbd56974894a261ce4e25f"></a>GUIEnhencement


- [**203**Star][14d] [Py] [patois/idacyber](https://github.com/patois/idacyber) Data Visualization Plugin for IDA Pro
- [**150**Star][1y] [Py] [ax330d/hrdev](https://github.com/ax330d/hrdev) Hex-Rays Decompiler Enhanced View
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**105**Star][2y] [Py] [danigargu/idatropy](https://github.com/danigargu/idatropy) a plugin for Hex-Ray's IDA Pro designed to generate charts of entropy and histograms using the power of idapython and matplotlib.
- [**89**Star][6m] [Py] [patois/hrdevhelper](https://github.com/patois/hrdevhelper) HexRays decompiler plugin that visualizes the ctree of decompiled functions.
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**51**Star][17d] [Py] [patois/xray](https://github.com/patois/xray) Hexrays decompiler plugin that colorizes and filters the decompiler's output based on regular expressions
- [**20**Star][4m] [C++] [revspbird/hightlight](https://github.com/revspbird/hightlight) a plugin for ida of version 7.2 to help know F5 window codes better
- [**5**Star][3y] [Py] [oct0xor/ida_pro_graph_styling](https://github.com/oct0xor/ida_pro_graph_styling) Advanced Ida Pro Instruction Highlighting
- [**5**Star][2y] [C] [teppay/ida](https://github.com/teppay/ida) my files related to IDA
- [**3**Star][2y] [Py] [andreafioraldi/idaretaddr](https://github.com/andreafioraldi/idaretaddr) Highlight the return address of a function in the Ida Pro debugger
    - Also In Section: [IDA->Tools->Function->NoCategory](#347a2158bdd92b00cd3d4ba9a0be00ae) |


#### <a id="3b1dba00630ce81cba525eea8fcdae08"></a>Graph


- [**2563**Star][5m] [Java] [google/binnavi](https://github.com/google/binnavi) a binary analysis IDE that allows to inspect, navigate, edit and annotate control flow graphs and call graphs of disassembled code.
- [**232**Star][2y] [C++] [fireeye/simplifygraph](https://github.com/fireeye/simplifygraph) IDA Pro plugin to assist with complex graphs
- [**39**Star][8m] [Py] [rr-/ida-images](https://github.com/rr-/ida-images) Image preview plugin for IDA disassembler.


#### <a id="8f9468e9ab26128567f4be87ead108d7"></a>Search


- [**150**Star][2y] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) Fuzzy search tool for IDA Pro.
    - Also In Section: [IDA->Tools->Function->Nav](#e4616c414c24b58626f834e1be079ebc) |
- [**64**Star][3y] [Py] [xorpd/idsearch](https://github.com/xorpd/idsearch) A search tool for IDA
- [**23**Star][5m] [Py] [alexander-hanel/hansel](https://github.com/alexander-hanel/hansel) a simple but flexible search for IDA




### <a id="66052f824f5054aa0f70785a2389a478"></a>Android


- [**244**Star][7d] [C++] [strazzere/android-scripts](https://github.com/strazzere/android-scripts) Collection of Android reverse engineering scripts
    - Also In Section: [Android->Tools->ReverseEngineering](#6d2b758b3269bac7d69a2d2c8b45194c) |
- [**158**Star][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->SpecificTarget->Loader](#cb59d84840e41330a7b5e275c0b81725) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**116**Star][4y] [Py] [cvvt/dumpdex](https://github.com/cvvt/dumpdex) IDA python script to dynamically dump DEX in memory
    - Also In Section: [Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**79**Star][2y] [Py] [zhkl0228/androidattacher](https://github.com/zhkl0228/androidattacher) IDA debugging plugin for android armv7 so
    - Also In Section: [Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**39**Star][5y] [Py] [techbliss/adb_helper_qt_super_version](https://github.com/techbliss/adb_helper_qt_super_version) All You Need For Ida Pro And Android Debugging
    - Also In Section: [Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**38**Star][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) some idapython scripts for android debugging.
    - Also In Section: [IDA->Tools->Debug->NoCategory](#2944dda5289f494e5e636089db0d6a6a) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**16**Star][7y] [C++] [strazzere/dalvik-header-plugin](https://github.com/strazzere/dalvik-header-plugin) Dalvik Header Plugin for IDA Pro
    - Also In Section: [Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |


### <a id="2adc0044b2703fb010b3bf73b1f1ea4a"></a>Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O


#### <a id="8530752bacfb388f3726555dc121cb1a"></a>NoCategory


- [**174**Star][2y] [Py] [duo-labs/idapython](https://github.com/duo-labs/idapython)  a few Python modules developed for use with IDA Pro from the researchers at Duo Labs.
    - Also In Section: [IDA->Tools->Firmware](#a8f5db3ab4bc7bc3d6ca772b3b9b0b1e) |
    - [cortex_m_firmware](https://github.com/duo-labs/idapython/blob/master/cortex_m_firmware.py) grooms an IDA Pro database containing firmware from an ARM Cortex M microcontroller.
    - [amnesia](https://github.com/duo-labs/idapython/blob/master/amnesia.py)  an IDAPython module designed to use byte level heuristics to find ARM thumb instructions in undefined bytes in an IDA Pro database
    - [REobjc](https://github.com/duo-labs/idapython/blob/master/reobjc.py)  an IDAPython module designed to make proper cross references between calling functions and called functions in Objective-C methods
- [**167**Star][8y] [Py] [zynamics/objc-helper-plugin-ida](https://github.com/zynamics/objc-helper-plugin-ida) Simplifies working with Objective-C binaries in IDA Pro
- [**21**Star][3y] [aozhimin/ios-monitor-resources](https://github.com/aozhimin/ios-monitor-resources) 对各厂商的 iOS SDK 性能监控方案的整理和收集后的资源
- [**17**Star][9y] [C++] [alexander-pick/patchdiff2_ida6](https://github.com/alexander-pick/patchdiff2_ida6) patched up patchdiff2 to compile and work with IDA 6 on OSX
- [**14**Star][8y] [Standard ML] [letsunlockiphone/iphone-baseband-ida-pro-signature-files](https://github.com/letsunlockiphone/iphone-baseband-ida-pro-signature-files) IDA Pro Signature Files iPhone Baseband Reversing
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->NoCategory](#cf04b98ea9da0056c055e2050da980c1) |


#### <a id="82d0fa2d6934ce29794a651513934384"></a>kernelCache


- [**167**Star][1y] [Py] [bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) An IDA Toolkit for analyzing iOS kernelcaches
    - Also In Section: [IDA->Tools->Structure->NoCategory](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**137**Star][8y] [stefanesser/ida-ios-toolkit](https://github.com/stefanesser/ida-ios-toolkit) Collection of idapython scripts for dealing with the iOS kernelcache
- [**50**Star][1y] [Py] [synacktiv-contrib/kernelcache-laundering](https://github.com/Synacktiv-contrib/kernelcache-laundering) load iOS12 kernelcaches and PAC code in IDA


#### <a id="d249a8d09a3f25d75bb7ba8b32bd9ec5"></a>Mach-O


- [**47**Star][7m] [C] [gdbinit/extractmacho](https://github.com/gdbinit/extractmacho) IDA plugin to extract Mach-O binaries located in the disassembly or data
- [**18**Star][3y] [C] [cocoahuke/iosdumpkernelfix](https://github.com/cocoahuke/iosdumpkernelfix) This tool will help to fix the Mach-O header of iOS kernel which dump from the memory. So that IDA or function symbol-related tools can loaded function symbols of ios kernel correctly
- [**17**Star][8y] [C] [gdbinit/machoplugin](https://github.com/gdbinit/machoplugin) IDA plugin to Display Mach-O headers


#### <a id="1c698e298f6112a86c12881fbd8173c7"></a>Swift


- [**52**Star][3y] [Py] [tobefuturer/ida-swift-demangle](https://github.com/tobefuturer/ida-swift-demangle) A tool to demangle Swift function names in IDA.
- [**17**Star][3y] [Py] [tylerha97/swiftdemang](https://github.com/0xtyh/swiftdemang) Demangle Swift
- [**17**Star][4y] [Py] [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle) An IDA plugin to demangle Swift function names
    - Also In Section: [IDA->Tools->Function->demangle](#cadae88b91a57345d266c68383eb05c5) |




### <a id="e5e403123c70ddae7bd904d3a3005dbb"></a>ELF


- [**522**Star][2y] [C] [lunixbochs/patchkit](https://github.com/lunixbochs/patchkit) binary patching from Python
    - Also In Section: [IDA->Tools->Patch](#7d557bc3d677d206ef6c5a35ca8b3a14) |
    - [IDA插件](https://github.com/lunixbochs/patchkit/tree/master/ida) 
    - [patchkit](https://github.com/lunixbochs/patchkit/tree/master/core) 
- [**204**Star][5y] [C] [snare/ida-efiutils](https://github.com/snare/ida-efiutils) Some scripts for IDA Pro to assist with reverse engineering EFI binaries
- [**158**Star][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->Tools->SpecificTarget->Loader](#cb59d84840e41330a7b5e275c0b81725) |[Android->Tools->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**125**Star][7m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [IDA->Tools->ImportExport->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[IDA->Tools->Function->NoCategory](#347a2158bdd92b00cd3d4ba9a0be00ae) |[Radare2->Plugins->WithOtherTools->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**92**Star][2y] [C++] [gdbinit/efiswissknife](https://github.com/gdbinit/efiswissknife) An IDA plugin to improve (U)EFI reversing
- [**84**Star][3m] [Py] [yeggor/uefi_retool](https://github.com/yeggor/uefi_retool) finding proprietary protocols in UEFI firmware and UEFI modules analysing
- [**44**Star][2y] [C] [aerosoul94/dynlib](https://github.com/aerosoul94/dynlib) IDA Pro plugin to aid PS4 user mode ELF reverse engineering.
    - Also In Section: [IDA->Tools->SpecificTarget->PS3](#315b1b8b41c67ae91b841fce1d4190b5) |
- [**44**Star][4y] [Py] [danse-macabre/ida-efitools](https://github.com/danse-macabre/ida-efitools) Some scripts for IDA Pro to assist with reverse engineering EFI binaries
- [**43**Star][4y] [Py] [strazzere/idant-wanna](https://github.com/strazzere/idant-wanna) ELF header abuse


### <a id="7a2977533ccdac70ee6e58a7853b756b"></a>Microcode


- [**293**Star][4m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) Hex-Rays microcode API plugin for breaking an obfuscating compiler
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**186**Star][4m] [C++] [chrisps/hexext](https://github.com/chrisps/Hexext) a plugin to improve the output of the hexrays decompiler through microcode manipulation.
- [**63**Star][17d] [Py] [patois/genmc](https://github.com/patois/genmc) Display Hex-Rays Microcode
- [**48**Star][2m] [Py] [idapython/pyhexraysdeob](https://github.com/idapython/pyhexraysdeob) A port of Rolf Rolles hexraysdeob
- [**19**Star][9m] [Py] [neatmonster/mcexplorer](https://github.com/neatmonster/mcexplorer) Python portage of the Microcode Explorer plugin


### <a id="b38dab81610be087bd5bc7785269b8cc"></a>Emulator


- [**488**Star][1y] [Py] [alexhude/uemu](https://github.com/alexhude/uemu) Tiny cute emulator plugin for IDA based on unicorn.
- [**391**Star][12m] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) Debugger plugin for IDA Pro backed by the Unicorn Engine
    - Also In Section: [IDA->Tools->Debug->NoCategory](#2944dda5289f494e5e636089db0d6a6a) |
- [**386**Star][3y] [Py] [36hours/idaemu](https://github.com/36hours/idaemu) an IDA Pro Plugin use for emulating code in IDA Pro.
    - Also In Section: [IDA->Tools->ScriptWritting->NoCategory](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**279**Star][25d] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) marries a supported binary analysis framework, such as IDA Pro or Radare2, with Unicorn’s emulation framework to provide the user with an easy to use and flexible interface for scripting emulation tasks
    - Also In Section: [IDA->Tools->ScriptWritting->NoCategory](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**202**Star][2y] [Py] [tkmru/nao](https://github.com/tkmru/nao) Simple No-meaning Assembly Omitter for IDA Pro (CURRENTLY UNDER DEVELOPMENT)
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**125**Star][3y] [Py] [codypierce/pyemu](https://github.com/codypierce/pyemu) x86 Emulator in Python


### <a id="83de90385d03ac8ef27360bfcdc1ab48"></a>PartOfOtherTool


- [**1531**Star][7d] [Py] [lifting-bits/mcsema](https://github.com/lifting-bits/mcsema) Framework for lifting x86, amd64, and aarch64 program binaries to LLVM bitcode
    - [IDA7插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida7) 用于反汇编二进制文件并生成控制流程图
    - [IDA插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida) 用于反汇编二进制文件并生成控制流程图
    - [Binja插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/binja) 用于反汇编二进制文件并生成控制流程图
    - [mcsema](https://github.com/lifting-bits/mcsema/tree/master/mcsema) 
- [**418**Star][17d] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) a scalable assembly management and analysis platform
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->NoCategory](#cf04b98ea9da0056c055e2050da980c1) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 
- [**27**Star][4y] [Scheme] [yifanlu/cgen](https://github.com/yifanlu/cgen) CGEN with support for generating IDA Pro IDP modules
- [**23**Star][2y] [Py] [tintinweb/unbox](https://github.com/tintinweb/unbox) a convenient one-click unpack and decompiler tool that wraps existing 3rd party applications like IDA Pro, JD-Cli, Dex2Src, and others to provide a convenient archiver liker command line interfaces to unpack and decompile various types of files


### <a id="1ded622dca60b67288a591351de16f8b"></a>Vul


#### <a id="385d6777d0747e79cccab0a19fa90e7e"></a>NoCategory


- [**491**Star][7m] [Py] [danigargu/heap-viewer](https://github.com/danigargu/heap-viewer) An IDA Pro plugin to examine the glibc heap, focused on exploit development
- [**375**Star][2y] [Py] [1111joe1111/ida_ea](https://github.com/1111joe1111/ida_ea) A set of exploitation/reversing aids for IDA
- [**364**Star][2m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) Make your IDA Lazy!
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->Tools->Nav->NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>View Details</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**139**Star][7m] [Py] [iphelix/ida-sploiter](https://github.com/iphelix/ida-sploiter) a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's capabilities as an exploit development and vulnerability research tool.
- [**133**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [IDA->Tools->ImportExport->IntelPin](#dd0332da5a1482df414658250e6357f8) |[IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**64**Star][12d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) An IDAPython decompiler script that helps auditing calls to the memcpy() and memmove() functions.
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**32**Star][6y] [Py] [coldheat/quicksec](https://github.com/coldheat/quicksec) IDAPython script for quick vulnerability analysis


#### <a id="cf2efa7e3edb24975b92d2e26ca825d2"></a>ROP


- [**53**Star][3y] [Py] [patois/drgadget](https://github.com/patois/drgadget) IDAPython plugin for the Interactive Disassembler 
- [**19**Star][2y] [Py] [lucasg/idarop](https://github.com/lucasg/idarop) ROP database plugin for IDA




### <a id="7d557bc3d677d206ef6c5a35ca8b3a14"></a>Patch


- [**720**Star][12m] [Py] [keystone-engine/keypatch](https://github.com/keystone-engine/keypatch) Multi-architecture assembler for IDA Pro. Powered by Keystone Engine.
- [**522**Star][2y] [C] [lunixbochs/patchkit](https://github.com/lunixbochs/patchkit) binary patching from Python
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
    - [IDA插件](https://github.com/lunixbochs/patchkit/tree/master/ida) 
    - [patchkit](https://github.com/lunixbochs/patchkit/tree/master/core) 
- [**87**Star][5y] [Py] [iphelix/ida-patcher](https://github.com/iphelix/ida-patcher) a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's ability to patch binary files and memory.
- [**42**Star][3y] [C++] [mrexodia/idapatch](https://github.com/mrexodia/idapatch) IDA plugin to patch IDA Pro in memory.
- [**30**Star][3m] [Py] [scottmudge/debugautopatch](https://github.com/scottmudge/debugautopatch) Patching system improvement plugin for IDA.
- [**16**Star][8y] [C++] [jkoppel/reprogram](https://github.com/jkoppel/reprogram) Patch binaries at load-time
- [**0**Star][7m] [Py] [tkmru/genpatch](https://github.com/tkmru/genpatch) IDA plugin that generates a python script for patch


### <a id="7dfd8abad50c14cd6bdc8d8b79b6f595"></a>Other


- [**121**Star][2y] [Shell] [feicong/ida_for_mac_green](https://github.com/feicong/ida_for_mac_green) IDAPro for macOS
- [**31**Star][5m] [angelkitty/ida7.0](https://github.com/angelkitty/ida7.0) 
- [**16**Star][2y] [jas502n/ida7.0-pro](https://github.com/jas502n/ida7.0-pro) IDA7.0  download


### <a id="90bf5d31a3897400ac07e15545d4be02"></a>Function


#### <a id="347a2158bdd92b00cd3d4ba9a0be00ae"></a>NoCategory


- [**125**Star][7m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->ImportExport->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[Radare2->Plugins->WithOtherTools->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**11**Star][2y] [C++] [fireundubh/ida7-functionstringassociate](https://github.com/fireundubh/ida7-functionstringassociate) FunctionStringAssociate plugin by sirmabus, ported to IDA 7
- [**3**Star][2y] [Py] [andreafioraldi/idaretaddr](https://github.com/andreafioraldi/idaretaddr) Highlight the return address of a function in the Ida Pro debugger
    - Also In Section: [IDA->Tools->Nav->GUIEnhencement](#03fac5b3abdbd56974894a261ce4e25f) |
- [**2**Star][5m] [Py] [farzonl/idapropluginlab3](https://github.com/farzonl/idapropluginlab3) An Ida plugin that does static analysis to describe what malware is doing.


#### <a id="73813456eeb8212fd45e0ea347bec349"></a>Rename&&Prefix&&Tag


- [**289**Star][2m] [Py] [a1ext/auto_re](https://github.com/a1ext/auto_re) IDA PRO auto-renaming plugin with tagging support
- [**118**Star][5y] [C++] [zyantific/retypedef](https://github.com/zyantific/retypedef) Name substitution plugin for IDA Pro
- [**95**Star][2y] [Py] [gaasedelen/prefix](https://github.com/gaasedelen/prefix) Function Prefixing for IDA Pro
- [**48**Star][3y] [Py] [alessandrogario/ida-function-tagger](https://github.com/alessandrogario/ida-function-tagger) This IDAPython script tags subroutines according to their use of imported functions
- [**21**Star][11m] [Py] [howmp/comfinder](https://github.com/howmp/comfinder) IDA plugin for COM
    - Also In Section: [IDA->Tools->SpecificTarget->NoCategory](#5578c56ca09a5804433524047840980e) |
- [**3**Star][4y] [Py] [ayuto/discover_win](https://github.com/ayuto/discover_win) compare linux and windows binary, rename windows binary functions
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->NoCategory](#cf04b98ea9da0056c055e2050da980c1) |


#### <a id="e4616c414c24b58626f834e1be079ebc"></a>Nav&&Search


- [**178**Star][6m] [Py] [hasherezade/ida_ifl](https://github.com/hasherezade/ida_ifl) IFL - Interactive Functions List (plugin for IDA Pro)
- [**150**Star][2y] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) Fuzzy search tool for IDA Pro.
    - Also In Section: [IDA->Tools->Nav->Search](#8f9468e9ab26128567f4be87ead108d7) |
- [**99**Star][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) IDAPython plugin for finding function strings recursively
    - Also In Section: [IDA->Tools->string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->Tools->Nav->NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**80**Star][1y] [Py] [ax330d/functions-plus](https://github.com/ax330d/functions-plus) IDA Pro plugin to show functions in a tree view
    - Also In Section: [IDA->Tools->Nav->NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**34**Star][3y] [Py] [darx0r/reef](https://github.com/darx0r/reef) IDAPython plugin for finding Xrefs from a function


#### <a id="cadae88b91a57345d266c68383eb05c5"></a>demangle


- [**17**Star][4y] [Py] [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle) An IDA plugin to demangle Swift function names
    - Also In Section: [IDA->Tools->Apple->Swift](#1c698e298f6112a86c12881fbd8173c7) |
- [**14**Star][1y] [Py] [ax330d/exports-plus](https://github.com/ax330d/exports-plus) IDA Pro plugin to view Exports




### <a id="34ac84853604a7741c61670f2a075d20"></a>TaintAnalysis&&SymbolicExecution


- [**927**Star][12d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) a static Binary Code Analysis Toolkit, designed to help reverse engineers, directly from IDA or using Python for automation.
    - Also In Section: [IDA->Tools->Structure->NoCategory](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**864**Star][2y] [C++] [illera88/ponce](https://github.com/illera88/ponce) Symbolic Execution just one-click away!
- [**23**Star][4m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |


### <a id="9dcc6c7dd980bec1f92d0cc9a2209a24"></a>string


- [**1360**Star][2m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) Automatically extract obfuscated strings from malware.
    - Also In Section: [IDA->Tools->DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**364**Star][2m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) Make your IDA Lazy!
    - Also In Section: [IDA->Tools->Nav->NoCategory](#c5b120e1779b928d860ad64ff8d23264) |[IDA->Tools->Vul->NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |
        <details>
        <summary>View Details</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**180**Star][1m] [Py] [joxeankoret/idamagicstrings](https://github.com/joxeankoret/idamagicstrings) An IDA Python script to extract information from string constants.
- [**130**Star][2y] [Py] [comsecuris/ida_strcluster](https://github.com/comsecuris/ida_strcluster) extending IDA's string navigation capabilities
    - Also In Section: [IDA->Tools->Nav->NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**99**Star][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) IDAPython plugin for finding function strings recursively
    - Also In Section: [IDA->Tools->Nav->NoCategory](#c5b120e1779b928d860ad64ff8d23264) |[IDA->Tools->Function->Nav](#e4616c414c24b58626f834e1be079ebc) |
- [**45**Star][5y] [Py] [kyrus/ida-translator](https://github.com/kyrus/ida-translator) A plugin for IDA Pro that assists in decoding arbitrary character sets in an IDA Pro database into Unicode, then automatically invoking a web-based translation service (currently Google Translate) to translate that foreign text into English.
- [**4**Star][3y] [C#] [andreafioraldi/idagrabstrings](https://github.com/andreafioraldi/idagrabstrings) IDAPython plugin to manipulate strings in a specified range of addresses
    - Also In Section: [IDA->Tools->Structure->NoCategory](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**4**Star][8m] [C] [lacike/gandcrab_string_decryptor](https://github.com/lacike/gandcrab_string_decryptor) IDC script for decrypting strings in the GandCrab v5.1-5.3
    - Also In Section: [IDA->Tools->SpecificTarget->MalwareFamily](#841d605300beba45c3be131988514a03) |


### <a id="06d2caabef97cf663bd29af2b1fe270c"></a>encrypt&&decrypt


- [**431**Star][1m] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) IDA pro plugin to find crypto constants (and more)
    - Also In Section: [IDA->Tools->Signature(FLIRT...)->Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |
- [**122**Star][2m] [Py] [you0708/ida](https://github.com/you0708/ida) A Python implementation of FindCrypt plugin.
    - [IDA主题](https://github.com/you0708/ida/tree/master/theme) 
    - [findcrypt](https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt) IDA FindCrypt/FindCrypt2 插件的Python版本
- [**41**Star][7y] [C++] [vlad902/findcrypt2-with-mmx](https://github.com/vlad902/findcrypt2-with-mmx) IDA Pro findcrypt2 plug-in with MMX AES instruction finding support




***


## <a id="18c6a45392d6b383ea24b363d2f3e76b"></a>Video&&Post


### <a id="37634a992983db427ce41b37dd9a98c2"></a>新添加的


- 2019.11 [4hou] [反作弊游戏如何破解，看看《黑色沙漠》逆向分析过程：使用 IDAPython 和 FLIRT 签名恢复 IAT](https://www.4hou.com/web/21806.html)
- 2019.11 [aliyun_xz] [使用IDA microcode去除ollvm混淆(下)](https://xz.aliyun.com/t/6795)


### <a id="4187e477ebc45d1721f045da62dbf4e8"></a>NoCategory


- 2019.10 [amossys] [Exploring Hex-Rays microcode](https://blog.amossys.fr/stage-2019-hexraysmicrocode.html)
- 2019.07 [kienbigmummy] [Cách export data trong IDA](https://medium.com/p/d4c8128704f)
- 2019.05 [360_anquanke_learning] [IDAPython实战项目——DES算法识别](https://www.anquanke.com/post/id/177808/)
- 2019.05 [carbonblack] [fn_fuzzy: Fast Multiple Binary Diffing Triage with IDA](https://www.carbonblack.com/2019/05/09/fn_fuzzy-fast-multiple-binary-diffing-triage-with-ida/)
- 2019.05 [aliyun_xz] [混淆IDA F5的一个小技巧-x86](https://xz.aliyun.com/t/5062)
- 2019.03 [freebuf] [Ponce：一键即可实现符号执行（IDA插件）](https://www.freebuf.com/sectool/197708.html)
- 2019.03 [360_anquanke_learning] [为CHIP-8编写IDA processor module](https://www.anquanke.com/post/id/172217/)
- 2019.01 [pediy_new_digest] [[原创]IDA7.2安装包分析](https://bbs.pediy.com/thread-248989.htm)
- 2019.01 [pediy_new_digest] [[原创]IDA 在解析 IA64 中的 brl 指令时存在一个 Bug](https://bbs.pediy.com/thread-248983.htm)
- 2019.01 [ly0n] [Cracking with IDA (redh@wk 2.5 crackme)](https://paumunoz.tech/2019/01/05/cracking-with-ida-redhwk-2-5-crackme/)
- 2018.11 [hexblog] [IDA 7.2 – The Mac Rundown](http://www.hexblog.com/?p=1300)
- 2018.11 [pediy_new_digest] [[原创]IDA动态调试ELF](https://bbs.pediy.com/thread-247830.htm)
- 2018.10 [pediy_new_digest] [[原创] 修复 IDA Pro 7.0在macOS Mojave崩溃的问题](https://bbs.pediy.com/thread-247334.htm)
- 2018.10 [ptsecurity_blog] [Modernizing IDA Pro: how to make processor module glitches go away](http://blog.ptsecurity.com/2018/10/modernizing-ida-pro-how-to-make.html)
- 2018.10 [aliyun_xz] [IDA-minsc在Hex-Rays插件大赛中获得第二名（2）](https://xz.aliyun.com/t/2842)
- 2018.10 [aliyun_xz] [IDA-minsc在Hex-Rays插件大赛中获得第二名（1）](https://xz.aliyun.com/t/2841)
- 2018.10 [aliyun_xz] [通过两个IDAPython插件支持A12 PAC指令和iOS12 kernelcache 重定位](https://xz.aliyun.com/t/2839)
- 2018.09 [cisco_blogs] [IDA-minsc Wins Second Place in Hex-Rays Plugins Contest](https://blogs.cisco.com/security/talos/ida-minsc-wins-second-place-in-hex-rays-plugins-contest)
- 2018.09 [dustri] [IDAPython vs. r2pipe](https://dustri.org/b/idapython-vs-r2pipe.html)
- 2018.06 [pediy_new_digest] [[翻译]在IDA中使用Python Z3库来简化函数中的算术运算](https://bbs.pediy.com/thread-228688.htm)
- 2018.05 [hexblog] [IDAPython: wrappers are only wrappers](http://www.hexblog.com/?p=1219)
- 2018.05 [tradahacking] [So sánh binary bằng IDA và các công cụ bổ trợ](https://medium.com/p/651e62117695)
- 2018.04 [pediy_new_digest] [[翻译]IDAPython-Book（Alexander Hanel）](https://bbs.pediy.com/thread-225920.htm)
- 2018.03 [hexblog] [IDA on non-OS X/Retina Hi-DPI displays](http://www.hexblog.com/?p=1180)
- 2018.03 [pediy_new_digest] [[翻译]IDA v6.5 文本执行](https://bbs.pediy.com/thread-225514.htm)
- 2018.02 [pediy_new_digest] [[原创]逆向技术之熟悉IDA工具](https://bbs.pediy.com/thread-224499.htm)
- 2018.01 [pediy_new_digest] [[原创]ARM Linux下搭建IDA Pro远程调试环境](https://bbs.pediy.com/thread-224337.htm)
- 2018.01 [pediy_new_digest] [[翻译]对抗IDA Pro调试器ARM反汇编的技巧](https://bbs.pediy.com/thread-223894.htm)
- 2017.12 [youtube_OALabs] [Debugging shellcode using BlobRunner and IDA Pro](https://www.youtube.com/watch?v=q9q8dy-2Jeg)
- 2017.12 [pediy_new_digest] [[原创]IDA7.0 Mac 插件编译指南](https://bbs.pediy.com/thread-223211.htm)
- 2017.12 [pediy_new_digest] [[原创]IDA 插件- FRIEND 的安装和使用](https://bbs.pediy.com/thread-223156.htm)
- 2017.12 [youtube_BinaryAdventure] [IDAPython Tutorial with example script](https://www.youtube.com/watch?v=5ehI2wgcSGo)
- 2017.11 [youtube_OALabs] [How To Defeat Anti-VM and Anti-Debug Packers With IDA Pro](https://www.youtube.com/watch?v=WlE8abc8V-4)
- 2017.11 [pediy_new_digest] [[原创]IDAPython脚本分享 - 自动在JNI_OnLoad下断点](https://bbs.pediy.com/thread-222998.htm)
- 2017.11 [pediy_new_digest] [[求助]IDA Pro调试so，附加完毕，跳到目标so基址，但是内容都是DCB伪指令？](https://bbs.pediy.com/thread-222646.htm)
- 2017.11 [youtube_OALabs] [IDA Pro Malware Analysis Tips](https://www.youtube.com/watch?v=qCQRKLaz2nQ)
- 2017.10 [hexblog] [IDA and common Python issues](http://www.hexblog.com/?p=1132)
- 2017.10 [pediy_new_digest] [[分享]IDA + VMware 调试win7 x64](https://bbs.pediy.com/thread-221884.htm)
- 2017.06 [pediy_new_digest] [[翻译]IDA Hex-Rays反编译器使用的一些小技巧](https://bbs.pediy.com/thread-218780.htm)
- 2017.06 [qmemcpy] [IDA series, part 2: debugging a .NET executable](https://qmemcpy.io/post/ida-series-2-debugging-net)
- 2017.06 [qmemcpy] [IDA series, part 1: the Hex-Rays decompiler](https://qmemcpy.io/post/ida-series-1-hex-rays)
- 2017.05 [3gstudent] [逆向分析——使用IDA动态调试WanaCrypt0r中的tasksche.exe](https://3gstudent.github.io/3gstudent.github.io/%E9%80%86%E5%90%91%E5%88%86%E6%9E%90-%E4%BD%BF%E7%94%A8IDA%E5%8A%A8%E6%80%81%E8%B0%83%E8%AF%95WanaCrypt0r%E4%B8%AD%E7%9A%84tasksche.exe/)
- 2017.05 [pediy_new_digest] [[原创] IDA导入Jni.h](https://bbs.pediy.com/thread-217701.htm)
- 2017.05 [oct0xor] [Advanced Ida Pro Instruction Highlighting](http://oct0xor.github.io/2017/05/03/ida_coloring/)
- 2017.05 [repret] [Improving Coverage Guided Fuzzing, Using Static Analysis](https://repret.wordpress.com/2017/05/01/improving-coverage-guided-fuzzing-using-static-analysis/)
- 2017.04 [osandamalith] [Executing Shellcode Directly](https://osandamalith.com/2017/04/11/executing-shellcode-directly/)
- 2017.04 [hexacorn] [IDA, hotpatched functions and signatures that don’t work…](http://www.hexacorn.com/blog/2017/04/07/ida-hotpatched-functions-and-signatures-that-dont-work/)
- 2017.04 [_0xec] [Remote debugging in IDA Pro by http tunnelling](https://0xec.blogspot.com/2017/04/remote-debugging-in-ida-pro-by-http.html)
- 2017.03 [pediy_new_digest] [[翻译]如何让 IDA Pro 使用我们提供的 Python 版本以及如何在 Chroot 的环境中运行 IDA Pro](https://bbs.pediy.com/thread-216643.htm)
- 2017.01 [kudelskisecurity] [SANS Holiday Hack Challenge 2016](https://research.kudelskisecurity.com/2017/01/06/sans-holiday-hack-challenge-2016/)
- 2016.12 [adelmas] [API Hooking with IDA Pro](http://adelmas.com/blog/ida_api_hooking.php)
- 2016.12 [hexacorn] [IDA, function alignment and signatures that don’t work…](http://www.hexacorn.com/blog/2016/12/27/ida-function-alignment-and-signatures-that-dont-work/)
- 2016.10 [_0x90] [Build IDA Pro KeyPatch for Fedora Linux](https://www.0x90.se/build-ida-pro-keypatch-for-fedora-linux/)
- 2016.05 [lucasg] [Do not load dll from System32 directly into IDA](http://lucasg.github.io/2016/05/30/Do-not-load-dll-from-System32-directly-into-IDA/)
- 2016.04 [hexacorn] [Creating IDT/IDS files for IDA from MS libraries with symbols](http://www.hexacorn.com/blog/2016/04/22/creating-idtids-files-for-ida-from-ms-libraries-with-symbols/)
- 2016.02 [pediy_new_digest] [[原创]翻译，IDA调试Dalvik](https://bbs.pediy.com/thread-207891.htm)
- 2016.01 [pediy_new_digest] [[原创]Android 5.0 + IDA 6.8 调试经验分享](https://bbs.pediy.com/thread-207548.htm)
- 2016.01 [insinuator] [Dynamic IDA Enrichment (aka. DIE)](https://insinuator.net/2016/01/die/)
- 2016.01 [360_anquanke_learning] [在OSX上编译非osx ida pro插件](https://www.anquanke.com/post/id/83385/)
- 2016.01 [adventuresincyberchallenges] [SANS Holiday Hack Quest 2015](https://adventuresincyberchallenges.blogspot.com/2016/01/holiday-hack-quest.html)
- 2015.12 [yifan] [CGEN for IDA Pro](http://yifan.lu/2015/12/29/cgen-for-ida-pro/)
- 2015.12 [pediy_new_digest] [调试篇---安卓arm/x86平台之IDA or GDB长驱直入](https://bbs.pediy.com/thread-206654.htm)
- 2015.12 [hexacorn] [IDAPython – making strings decompiler-friendly](http://www.hexacorn.com/blog/2015/12/21/idapython-making-strings-decompiler-friendly/)
- 2015.12 [pediy_new_digest] [[原创]IDA Pro 6.8 安装密码爆破的可行性分析](https://bbs.pediy.com/thread-206346.htm)
- 2015.11 [govolution] [Very first steps with IDA](https://govolution.wordpress.com/2015/11/06/very-first-steps-with-ida/)
- 2015.08 [pediy_new_digest] [[原创]一步步搭建ida pro动态调试SO环境。](https://bbs.pediy.com/thread-203080.htm)
- 2015.07 [hexblog] [Hack of the day #0: Somewhat-automating pseudocode HTML generation, with IDAPython.](http://www.hexblog.com/?p=921)
- 2015.06 [msreverseengineering_blog] [Transparent Deobfuscation with IDA Processor Module Extensions](http://www.msreverseengineering.com/blog/2015/6/29/transparent-deobfuscation-with-ida-processor-module-extensions)
- 2015.02 [pediy_new_digest] [[原创]使用IDA PRO+OllyDbg+PEview 追踪windows API 动态链接库函数的调用过程。](https://bbs.pediy.com/thread-197829.htm)
- 2014.12 [hexblog] [Augmenting IDA UI with your own actions.](http://www.hexblog.com/?p=886)
- 2014.10 [vexillium] [SECURE 2014 slide deck and Hex-Rays IDA Pro advisories published](https://j00ru.vexillium.org/2014/10/secure-2014-slide-deck-and-hex-rays-ida-pro-advisories-published/)
- 2014.10 [pediy_new_digest] [[原创]解决IDA的F5(hexray 1.5)不能用于FPU栈用满的情况](https://bbs.pediy.com/thread-193414.htm)
- 2014.08 [3xp10it_archive] [ida插件使用备忘录](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/27/ida%E6%8F%92%E4%BB%B6%E4%BD%BF%E7%94%A8%E5%A4%87%E5%BF%98%E5%BD%95/)
- 2014.08 [3xp10it_archive] [ida通过usb调试ios下的app](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/25/ida%E9%80%9A%E8%BF%87usb%E8%B0%83%E8%AF%95ios%E4%B8%8B%E7%9A%84app/)
- 2014.08 [3xp10it_archive] [ida批量下断点追踪函数调用](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/12/21/ida%E6%89%B9%E9%87%8F%E4%B8%8B%E6%96%AD%E7%82%B9%E8%BF%BD%E8%B8%AA%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8/)
- 2014.08 [3xp10it_archive] [ida插件使用备忘录](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/27/ida%E6%8F%92%E4%BB%B6%E4%BD%BF%E7%94%A8%E5%A4%87%E5%BF%98%E5%BD%95/)
- 2014.08 [3xp10it_archive] [ida插件mynav](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/01/22/ida%E6%8F%92%E4%BB%B6mynav/)
- 2014.08 [3xp10it_archive] [ida通过usb调试ios下的app](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/25/ida%E9%80%9A%E8%BF%87usb%E8%B0%83%E8%AF%95ios%E4%B8%8B%E7%9A%84app/)
- 2014.08 [3xp10it_archive] [ida批量下断点追踪函数调用](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/12/21/ida%E6%89%B9%E9%87%8F%E4%B8%8B%E6%96%AD%E7%82%B9%E8%BF%BD%E8%B8%AA%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8/)
- 2014.07 [hexblog] [IDA Dalvik debugger: tips and tricks](http://www.hexblog.com/?p=809)
- 2014.04 [hexblog] [Extending IDAPython in IDA 6.5: Be careful about the GIL](http://www.hexblog.com/?p=788)
- 2014.03 [zdziarski] [The Importance of Forensic Tools Validation](https://www.zdziarski.com/blog/?p=3112)
- 2014.03 [evilsocket] [Programmatically Identifying and Isolating Functions Inside Executables Like IDA Does.](https://www.evilsocket.net/2014/03/11/programmatically-identifying-and-isolating-functions-inside-executables-like-ida-does/)
- 2014.02 [silentsignal_blog] [From Read to Domain Admin – Abusing Symantec Backup Exec with Frida](https://blog.silentsignal.eu/2014/02/27/from-read-to-domain-admin-abusing-symantec-backup-exec-with-frida/)
- 2013.12 [hexblog] [Interacting with IDA through IPC channels](http://www.hexblog.com/?p=773)
- 2013.06 [trustwave_SpiderLabs_Blog] [Debugging Android Libraries using IDA](https://www.trustwave.com/Resources/SpiderLabs-Blog/Debugging-Android-Libraries-using-IDA/)
- 2013.05 [v0ids3curity] [Defeating anti-debugging techniques using IDA and x86 emulator plugin](https://www.voidsecurity.in/2013/05/defeating-anti-debugging-techniques.html)
- 2013.05 [hexblog] [Loading your own modules from your IDAPython scripts with idaapi.require()](http://www.hexblog.com/?p=749)
- 2013.04 [hexblog] [Installing PIP packages, and using them from IDA on a 64-bit machine](http://www.hexblog.com/?p=726)
- 2013.03 [pediy_new_digest] [[原创]IDA Demo6.4破解笔记](https://bbs.pediy.com/thread-167109.htm)
- 2012.11 [redplait] [pyside for ida pro 6.3 - part 2](http://redplait.blogspot.com/2012/11/pyside-for-ida-pro-63-part-2.html)
- 2012.10 [redplait] [AVX/XOP instructions processor extender for IDA Pro](http://redplait.blogspot.com/2012/10/avxxop-instructions-processor-extender.html)
- 2012.10 [redplait] [IDA Pro 6.3 SDK is broken ?](http://redplait.blogspot.com/2012/10/ida-pro-63-sdk-is-broken.html)
- 2012.10 [redplait] [pyside for ida pro 6.3](http://redplait.blogspot.com/2012/10/pyside-for-ida-pro-63.html)
- 2012.09 [redplait] [IDA loader of .dcu files from XE3](http://redplait.blogspot.com/2012/09/ida-loader-of-dcu-files-from-xe3.html)
- 2012.08 [tencent_security_blog] [浅谈IDA脚本在漏洞挖掘中的应用](https://security.tencent.com/index.php/blog/msg/4)
- 2012.07 [cr4] [VMware + GDB stub + IDA](http://blog.cr4.sh/2012/07/vmware-gdb-stub-ida.html)
- 2012.06 [pediy_new_digest] [[原创]PRX loader for IDA](https://bbs.pediy.com/thread-152647.htm)
- 2012.06 [pediy_new_digest] [[翻译]API Call Tracing - PEfile, PyDbg and IDAPython](https://bbs.pediy.com/thread-151870.htm)
- 2012.05 [redplait] [dcu files loader for ida pro v2](http://redplait.blogspot.com/2012/05/dcu-files-loader-for-ida-pro-v2.html)
- 2012.05 [redplait] [dcu files loader for ida pro](http://redplait.blogspot.com/2012/05/dcu-files-loader-for-ida-pro.html)
- 2012.03 [redplait] [updated perl binding for IDA Pro](http://redplait.blogspot.com/2012/03/updated-perl-binding-for-ida-pro.html)
- 2012.03 [pediy_new_digest] [[原创]IDA批量模式](https://bbs.pediy.com/thread-147777.htm)
- 2012.02 [pediy_new_digest] [[原创]IDA Android Remote Debug](https://bbs.pediy.com/thread-146721.htm)
- 2012.01 [pediy_new_digest] [[原创]IDA 6.1 bool 及 默认对齐 sizeof 设置永久修复](https://bbs.pediy.com/thread-145188.htm)
- 2011.12 [redplait] [IDA 5.60 PICode analyzer plugin for win64](http://redplait.blogspot.com/2011/12/ida-560-picode-analyzer-plugin-for.html)
- 2011.10 [reverse_archives] [How to create IDA C/C++ plugins with Xcode](https://reverse.put.as/2011/10/31/how-to-create-ida-cc-plugins-with-xcode/)
- 2011.10 [pediy_new_digest] [[转帖]IDA PRO 6.1 远程调试 Android](https://bbs.pediy.com/thread-141739.htm)
- 2011.09 [pediy_new_digest] [[推荐]IDA sp-analysis failed 不能F5的 解决方案之(一)](https://bbs.pediy.com/thread-140002.htm)
- 2011.08 [pediy_new_digest] [[原创]用IDA Pro + OD 来分析扫雷](https://bbs.pediy.com/thread-138855.htm)
- 2011.08 [pediy_new_digest] [[原创]IDA + GDBServer实现iPhone程序远程调试](https://bbs.pediy.com/thread-138472.htm)
- 2011.08 [redplait] [perl inside IDA Pro](http://redplait.blogspot.com/2011/08/perl-inside-ida-pro.html)
- 2011.07 [redplait] [несколько pdb в ida pro](http://redplait.blogspot.com/2011/07/pdb-ida-pro.html)
- 2011.07 [pediy_new_digest] [[原创]IDA + Debug 插件 实现64Bit Exe脱壳](https://bbs.pediy.com/thread-137416.htm)
- 2011.06 [pediy_new_digest] [[翻译]使用VMWare GDB和IDA调试Windows内核](https://bbs.pediy.com/thread-135229.htm)
- 2011.05 [pediy_new_digest] [[分享]IDA 6.1 版本不能F5的解决办法](https://bbs.pediy.com/thread-134363.htm)
- 2011.05 [pediy_new_digest] [[原创]IDAPython+OdbgScript动态获取程序执行流程](https://bbs.pediy.com/thread-134171.htm)
- 2011.03 [pediy_new_digest] [[原创]Ida Pro Advanced 6.0 中木马分析](https://bbs.pediy.com/thread-131195.htm)
- 2011.03 [pediy_new_digest] [[原创]IDA SDK合并jmp乱序插件代码示例阅读](https://bbs.pediy.com/thread-131016.htm)
- 2011.01 [hexblog] [IDA & Qt: Under the hood](http://www.hexblog.com/?p=250)
- 2010.12 [pediy_new_digest] [[原创]ida 静态分析 破除时间限制](https://bbs.pediy.com/thread-126668.htm)
- 2010.10 [pediy_new_digest] [[下载]IDA pro代码破解揭秘的随书例子下载](https://bbs.pediy.com/thread-123432.htm)
- 2010.10 [hexblog] [Calculating API hashes with IDA Pro](http://www.hexblog.com/?p=193)
- 2010.09 [publicintelligence] [(U//FOUO) FBI Warning: Extremists Likely to Retaliate Against Florida Group’s Planned “International Burn A Koran Day”](https://publicintelligence.net/ufouo-fbi-warning-extremists-likely-to-retaliate-against-florida-group%e2%80%99s-planned-%e2%80%9cinternational-burn-a-koran-day%e2%80%9d/)
- 2010.08 [mattoh] [Exporting IDA function for IDC Script Usage](https://mattoh.wordpress.com/2010/08/06/exporting-ida-function-for-idc-script-usage/)
- 2010.07 [hexblog] [Implementing command completion for IDAPython](http://www.hexblog.com/?p=129)
- 2010.07 [hexblog] [Running scripts from the command line with idascript](http://www.hexblog.com/?p=128)
- 2010.06 [hexblog] [Extending IDC and IDAPython](http://www.hexblog.com/?p=126)
- 2010.04 [hexblog] [Kernel debugging with IDA Pro / Windbg plugin and VirtualKd](http://www.hexblog.com/?p=123)
- 2010.03 [hexblog] [Using custom viewers from IDAPython](http://www.hexblog.com/?p=119)
- 2010.01 [hexblog] [Debugging ARM code snippets in IDA Pro 5.6 using QEMU emulator](http://www.hexblog.com/?p=111)
- 2009.12 [pediy_new_digest] [[原创]Symbian_Remote_Debugger_With_IDA](https://bbs.pediy.com/thread-103934.htm)
- 2009.10 [pediy_new_digest] [[原创]IDA学习笔记](https://bbs.pediy.com/thread-99560.htm)
- 2009.09 [hexblog] [Develop your master boot record and debug it with IDA Pro and the Bochs debugger plugin](http://www.hexblog.com/?p=103)
- 2009.02 [hexblog] [Advanced Windows Kernel Debugging with VMWare and IDA’s GDB debugger](http://www.hexblog.com/?p=94)
- 2008.10 [evilcodecave] [IDA Pro Enhances Hostile Code Analysis Support](https://evilcodecave.wordpress.com/2008/10/04/ida-pro-enhances-hostile-code-analysis-support/)
- 2008.09 [pediy_new_digest] [[原创]ShellCode Locator for IDA 5.2](https://bbs.pediy.com/thread-72947.htm)
- 2008.08 [evilcodecave] [IDA Debugger Malformed SEH Causes Crash](https://evilcodecave.wordpress.com/2008/08/31/ida-debugger-malformed-seh-causes-crash/)
- 2008.04 [pediy_new_digest] [[原创]idb_2_pat for ida pro V5.2](https://bbs.pediy.com/thread-62825.htm)
- 2007.08 [pediy_new_digest] [[原创]基于 ida 的反汇编转换 Obj 的可行性 笔记(1)](https://bbs.pediy.com/thread-49910.htm)
- 2007.04 [pediy_new_digest] [[翻译]Pinczakko的AwardBIOS逆向工程指导](https://bbs.pediy.com/thread-42166.htm)
- 2007.02 [pediy_new_digest] [IDA Plugin 编写基础](https://bbs.pediy.com/thread-38900.htm)
- 2006.09 [pediy_new_digest] [[翻译]Using IDA Pro's Debugger](https://bbs.pediy.com/thread-31667.htm)
- 2006.09 [pediy_new_digest] [[翻译]Customizing IDA Pro](https://bbs.pediy.com/thread-31658.htm)
- 2006.08 [msreverseengineering_blog] [Defeating HyperUnpackMe2 with an IDA Processor Module](http://www.msreverseengineering.com/blog/2014/8/5/defeating-hyperunpackme2-with-an-ida-processor-module)
- 2004.11 [pediy_new_digest] [又说 IDA 边界修改插件](https://bbs.pediy.com/thread-7150.htm)


### <a id="a4bd25d3dc2f0be840e39674be67d66b"></a>Tips&&Tricks


- 2019.07 [hexacorn] [Batch decompilation with IDA / Hex-Rays Decompiler](http://www.hexacorn.com/blog/2019/07/04/batch-decompilation-with-ida-hex-rays-decompiler/)
- 2019.06 [openanalysis] [Disable ASLR for Easier Malware Debugging With x64dbg and IDA Pro](https://oalabs.openanalysis.net/2019/06/12/disable-aslr-for-easier-malware-debugging/)
- 2019.06 [youtube_OALabs] [Disable ASLR For Easier Malware Debugging With x64dbg and IDA Pro](https://www.youtube.com/watch?v=DGX7oZvdmT0)
- 2019.06 [openanalysis] [Reverse Engineering C++ Malware With IDA Pro: Classes, Constructors, and Structs](https://oalabs.openanalysis.net/2019/06/03/reverse-engineering-c-with-ida-pro-classes-constructors-and-structs/)
- 2019.06 [youtube_OALabs] [Reverse Engineering C++ Malware With IDA Pro](https://www.youtube.com/watch?v=o-FFGIloxvE)
- 2019.03 [aliyun_xz] [IDA Pro7.0使用技巧总结](https://xz.aliyun.com/t/4205)
- 2018.06 [checkpoint_research] [Scriptable Remote Debugging with Windbg and IDA Pro](https://research.checkpoint.com/scriptable-remote-debugging-windbg-ida-pro/)
- 2015.07 [djmanilaice] [Pycharm for your IDA development](http://djmanilaice.blogspot.com/2015/07/pycharm-for-your-ida-development.html)
- 2015.07 [djmanilaice] [Auto open dlls and exe in current directory for IDA](http://djmanilaice.blogspot.com/2015/07/auto-open-dlls-and-exe-in-current.html)


### <a id="0b3e1936ad7c4ccc10642e994c653159"></a>Malware


- 2019.04 [360_anquanke_learning] [两种姿势批量解密恶意驱动中的上百条字串](https://www.anquanke.com/post/id/175964/)
- 2019.03 [cyber] [Using IDA Python to analyze Trickbot](https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/)
- 2019.01 [youtube_OALabs] [Lazy String Decryption Tips With IDA PRO and Shade Ransomware Unpacked!](https://www.youtube.com/watch?v=RfnuMhosxuQ)
- 2018.09 [4hou] [Hidden Bee恶意软件家族的定制IDA装载模块开发](http://www.4hou.com/technology/13438.html)
- 2018.09 [4hou] [用IDAPython解密Gootkit中的字符串](http://www.4hou.com/technology/13209.html)
- 2018.05 [youtube_OALabs] [Unpacking Gootkit Part 2 - Debugging Anti-Analysis Tricks With IDA Pro and x64dbg](https://www.youtube.com/watch?v=QgUlPvEE4aw)
- 2018.04 [youtube_OALabs] [Unpacking VB6 Packers With IDA Pro and API Hooks (Re-Upload)](https://www.youtube.com/watch?v=ylWInOcQy2s)
- 2018.03 [youtube_OALabs] [Unpacking Gootkit Malware With IDA Pro and X64dbg - Subscriber Request](https://www.youtube.com/watch?v=242Tn0IL2jE)
- 2018.01 [youtube_OALabs] [Unpacking Pykspa Malware With Python and IDA Pro - Subscriber Request Part 1](https://www.youtube.com/watch?v=HfSQlC76_s4)
- 2017.11 [youtube_OALabs] [Unpacking Process Injection Malware With IDA PRO (Part 2)](https://www.youtube.com/watch?v=kdNQhfgoQoU)
- 2017.11 [youtube_OALabs] [Unpacking Process Injection Malware With IDA PRO (Part 1)](https://www.youtube.com/watch?v=ScBB-Hi7NxQ)
- 2017.06 [hackers_arise] [Reverse Engineering Malware, Part 3:  IDA Pro Introduction](https://www.hackers-arise.com/single-post/2017/06/22/Reverse-Engineering-Malware-Part-3-IDA-Pro-Introduction)
- 2017.05 [4hou] [逆向分析——使用IDA动态调试WanaCrypt0r中的tasksche.exe](http://www.4hou.com/technology/4832.html)
- 2017.05 [3gstudent] [逆向分析——使用IDA动态调试WanaCrypt0r中的tasksche.exe](https://3gstudent.github.io/3gstudent.github.io/%E9%80%86%E5%90%91%E5%88%86%E6%9E%90-%E4%BD%BF%E7%94%A8IDA%E5%8A%A8%E6%80%81%E8%B0%83%E8%AF%95WanaCrypt0r%E4%B8%AD%E7%9A%84tasksche.exe/)
- 2012.06 [trustwave_SpiderLabs_Blog] [Defeating Flame String Obfuscation with IDAPython](https://www.trustwave.com/Resources/SpiderLabs-Blog/Defeating-Flame-String-Obfuscation-with-IDAPython/)


### <a id="04cba8dbb72e95d9c721fe16a3b48783"></a>Series-LabelessIntroduction


- 2018.10 [checkpoint] [Labeless Part 6: How to Resolve Obfuscated API Calls in the Ngioweb Proxy Malware - Check Point Research](https://research.checkpoint.com/labeless-part-6-how-to-resolve-obfuscated-api-calls-in-the-ngioweb-proxy-malware/)
- 2018.10 [checkpoint] [Labeless Part 5: How to Decrypt Strings in Boleto Banking Malware Without Reconstructing Decryption Algorithm. - Check Point Research](https://research.checkpoint.com/labeless-part-5-how-to-decrypt-strings-in-boleto-banking-malware-without-reconstructing-decryption-algorithm/)
- 2018.10 [checkpoint] [Labeless Part 4: Scripting - Check Point Research](https://research.checkpoint.com/labeless-part-4-scripting/)
- 2018.08 [checkpoint] [Labeless Part 3: How to Dump and Auto-Resolve WinAPI Calls in LockPos Point-of-Sale Malware - Check Point Research](https://research.checkpoint.com/19558-2/)
- 2018.08 [checkpoint] [Labeless Part 2: Installation - Check Point Research](https://research.checkpoint.com/installing-labeless/)
- 2018.08 [checkpoint] [Labeless Part 1: An Introduction - Check Point Research](https://research.checkpoint.com/labeless-an-introduction/)


### <a id="1a2e56040cfc42c11c5b4fa86978cc19"></a>Series-ReversingWithIDAFromScrach


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


### <a id="e838a1ecdcf3d068547dd0d7b5c446c6"></a>Series-UsingIDAPythonToMakeYourLifeEasier


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




### <a id="8433dd5df40aaf302b179b1fda1d2863"></a>Series-ReversingCCodeWithIDA


- 2019.01 [ly0n] [Reversing C code with IDA part V](https://paumunoz.tech/2019/01/12/reversing-c-code-with-ida-part-v/)
- 2019.01 [ly0n] [Reversing C code with IDA part IV](https://paumunoz.tech/2019/01/07/reversing-c-code-with-ida-part-iv/)
- 2019.01 [ly0n] [Reversing C code with IDA part III](https://paumunoz.tech/2019/01/02/reversing-c-code-with-ida-part-iii/)
- 2018.12 [ly0n] [Reversing C code with IDA part II](https://paumunoz.tech/2018/12/31/reversing-c-code-with-ida-part-ii/)
- 2018.01 [ly0n] [Reversing C code with IDA part I](https://paumunoz.tech/2018/01/11/reversing-c-code-with-ida-part-i/)


### <a id="3d3bc775abd7f254ff9ff90d669017c9"></a>Tool&&Plugin&&Script


- 2019.10 [vmray_blog] [VMRay IDA Plugin v1.1: Streamlining Deep-Dive Malware Analysis](https://www.vmray.com/cyber-security-blog/vmray-ida-plugin-v1-1-streamlining-deep-dive-malware-analysis/)
- 2019.10 [talosintelligence_blog] [New IDA Pro plugin provides TileGX support](https://blog.talosintelligence.com/2019/10/new-ida-pro-plugin-provides-tilegx.html)
- 2019.09 [talosintelligence_blog] [GhIDA: Ghidra decompiler for IDA Pro](https://blog.talosintelligence.com/2019/09/ghida.html)
- 2019.04 [_0xeb] [climacros – IDA productivity tool](http://0xeb.net/2019/04/climacros-ida-productivity-tool/)
- 2019.04 [_0xeb] [QScripts – IDA Scripting productivity tool](http://0xeb.net/2019/04/ida-qscripts/)
- 2019.03 [_0xeb] [Daenerys: IDA Pro and Ghidra interoperability framework](http://0xeb.net/2019/03/daenerys-ida-pro-and-ghidra-interoperability-framework/)
- 2019.02 [kitploit_home] [HexRaysCodeXplorer - Hex-Rays Decompiler Plugin For Better Code Navigation](https://www.kitploit.com/2019/02/hexrayscodexplorer-hex-rays-decompiler.html)
- 2019.02 [kitploit_home] [Ponce - IDA Plugin For Symbolic Execution Just One-Click Away!](https://www.kitploit.com/2019/02/ponce-ida-plugin-for-symbolic-execution.html)
- 2019.01 [talosintelligence_blog] [Dynamic Data Resolver (DDR) - IDA Plugin](https://blog.talosintelligence.com/2019/01/ddr.html)
- 2018.12 [securityonline] [HexRaysCodeXplorer: Hex-Rays Decompiler plugin for better code navigation](https://securityonline.info/codexplorer/)
- 2018.11 [4hou] [FLARE脚本系列：使用idawasm IDA Pro插件逆向WebAssembly（Wasm）模块](http://www.4hou.com/reverse/13935.html)
- 2018.10 [aliyun_xz] [用idawasm IDA Pro逆向WebAssembly模块](https://xz.aliyun.com/t/2854)
- 2018.10 [fireeye_threat_research] [FLARE Script Series: Reverse Engineering WebAssembly Modules Using the
idawasm IDA Pro Plugin](https://www.fireeye.com/blog/threat-research/2018/10/reverse-engineering-webassembly-modules-using-the-idawasm-ida-pro-plugin.html)
- 2018.10 [vmray_blog] [Introducing the IDA Plugin for VMRay Analyzer](https://www.vmray.com/cyber-security-blog/ida-plugin-vmray-analyzer/)
- 2018.09 [ptsecurity_blog] [How we developed the NIOS II processor module for IDA Pro](http://blog.ptsecurity.com/2018/09/how-we-developed-nios-ii-processor.html)
- 2018.09 [talosintelligence_blog] [IDA-minsc Wins Second Place in Hex-Rays Plugins Contest](https://blog.talosintelligence.com/2018/09/ida-minsc.html)
- 2018.09 [msreverseengineering_blog] [Weekend Project: A Custom IDA Loader Module for the Hidden Bee Malware Family](http://www.msreverseengineering.com/blog/2018/9/2/weekend-project-a-custom-ida-loader-module-for-the-hidden-bee-malware-family)
- 2018.08 [360_anquanke_learning] [Lua程序逆向之为Luac编写IDA Pro处理器模块](https://www.anquanke.com/post/id/153699/)
- 2018.06 [dougallj] [Writing a Hex-Rays Plugin: VMX Intrinsics](https://dougallj.wordpress.com/2018/06/04/writing-a-hex-rays-plugin-vmx-intrinsics/)
- 2018.05 [freebuf] [HeapViewer：一款专注于漏洞利用开发的IDA Pro插件](http://www.freebuf.com/sectool/171632.html)
- 2018.03 [pediy_new_digest] [[翻译]使用 IDAPython 写一个简单的x86模拟器](https://bbs.pediy.com/thread-225091.htm)
- 2018.03 [_0xeb] [Using Z3 with IDA to simplify arithmetic operations in functions](http://0xeb.net/2018/03/using-z3-with-ida-to-simplify-arithmetic-operations-in-functions/)
- 2018.02 [securityonline] [IDAPython Embedded Toolkit: IDAPython scripts for automating analysis of firmware of embedded devices](https://securityonline.info/idapython-embedded-toolkit-idapython-scripts-for-automating-analysis-of-firmware-of-embedded-devices/)
- 2018.02 [_0xeb] [Writing a simple x86 emulator with IDAPython](http://0xeb.net/2018/02/writing-a-simple-x86-emulator-with-idapython/)
- 2018.01 [fireeye_threat_research] [FLARE IDA Pro Script Series: Simplifying Graphs in IDA](https://www.fireeye.com/blog/threat-research/2018/01/simplifying-graphs-in-ida.html)
- 2017.12 [ret2] [What's New in Lighthouse v0.7](http://blog.ret2.io/2017/12/07/lighthouse-v0.7/)
- 2017.12 [youtube_OALabs] [Using Yara Rules With IDA Pro - New Tool!](https://www.youtube.com/watch?v=zAKi9KWYyfM)
- 2017.11 [youtube_hasherezade] [IFL - Interactive Functions List - a plugin for IDA Pro](https://www.youtube.com/watch?v=L6sROW_MivE)
- 2017.11 [securityonline] [IDA EA: A set of exploitation/reversing aids for IDA](https://securityonline.info/ida-ea-exploitation-reversing-ida/)
- 2017.06 [reverse_archives] [EFI Swiss Knife – An IDA plugin to improve (U)EFI reversing](https://reverse.put.as/2017/06/13/efi-swiss-knife-an-ida-plugin-to-improve-uefi-reversing/)
- 2017.04 [redplait] [etwex - ida plugin for Etw traces IIDs searching](http://redplait.blogspot.com/2017/04/etwex-ida-plugin-for-etw-traces-iids.html)
- 2017.04 [360_anquanke_learning] [IDAPython：一个可以解放双手的 IDA 插件](https://www.anquanke.com/post/id/85890/)
- 2017.03 [duksctf] [Make IDA Pro Great Again](http://duksctf.github.io/2017/03/15/Make-IDA-Pro-Great-Again.html)
- 2017.03 [redplait] [ida plugin for RFG fixups processing](http://redplait.blogspot.com/2017/03/ida-plugin-for-rfg-fixups-processing.html)
- 2017.02 [argus_sec] [Collaborative Reverse Engineering with PSIDA - Argus Cyber Security](https://argus-sec.com/collaborative-reverse-engineering-psida/)
- 2016.01 [eugenekolo] [A walk through the binary with IDA](https://eugenekolo.com/blog/a-walk-through-the-binary-with-ida/)
- 2015.12 [360_anquanke_learning] [适用于IDA Pro的CGEN框架](https://www.anquanke.com/post/id/83210/)
- 2015.12 [freebuf] [FLARE IDA Pro的脚本系列：自动化提取函数参数](http://www.freebuf.com/sectool/89273.html)
- 2015.04 [nul] [VMProtect + IDA Pro　做一回强悍的加密](http://www.nul.pw/2015/04/29/86.html)
- 2015.03 [joxeankoret] [Diaphora, a program diffing plugin for IDA Pro](http://joxeankoret.com/blog/2015/03/13/diaphora-a-program-diffing-plugin-for-ida-pro/)
- 2014.10 [devttys0] [A Code Signature Plugin for IDA](http://www.devttys0.com/2014/10/a-code-signature-plugin-for-ida/)
- 2014.09 [freebuf] [火眼（FireEye）实验室FLARE IDA Pro脚本系列：MSDN注释插件](http://www.freebuf.com/sectool/43334.html)
- 2014.08 [3xp10it_archive] [ida插件mynav](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/01/22/ida%E6%8F%92%E4%BB%B6mynav/)
- 2014.05 [oct0xor] [Deci3dbg - Ida Pro Debugger Module for Playstation 3](http://oct0xor.github.io/2014/05/30/deci3dbg/)
- 2013.11 [quarkslab_blog] [IDA processor module](https://blog.quarkslab.com/ida-processor-module.html)
- 2013.06 [redplait] [IDA loader of .dcu files from XE4](http://redplait.blogspot.com/2013/06/ida-loader-of-dcu-files-from-xe4.html)
- 2012.07 [reverse_archives] [ExtractMachO: an IDA plugin to extract Mach-O binaries from disassembly](https://reverse.put.as/2012/07/30/extractmacho-an-ida-plugin-to-extract-mach-o-binaries-from-disassembly/)
- 2011.11 [reverse_archives] [Display Mach-O headers plugin for IDA](https://reverse.put.as/2011/11/03/display-mach-o-headers-plugin-for-ida/)
- 2011.04 [hexblog] [VirusTotal plugin for IDA Pro](http://www.hexblog.com/?p=324)
- 2010.05 [joxeankoret] [MyNav, a python plugin for IDA Pro](http://joxeankoret.com/blog/2010/05/02/mynav-a-python-plugin-for-ida-pro/)


### <a id="ea11818602eb33e8b165eb18d3710965"></a>Translate-TheIDAProBook


- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book 第六章](https://bbs.pediy.com/thread-75632.htm)
- 2008.10 [pediy_new_digest] [[翻译]（20081030更新）The IDA Pro Book 第12章：使用FLIRT签名识别库](https://bbs.pediy.com/thread-75422.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book(第二章)](https://bbs.pediy.com/thread-74943.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro book 第5章---IDA DATA DISPLAY](https://bbs.pediy.com/thread-74838.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book(第一章)](https://bbs.pediy.com/thread-74564.htm)


### <a id="ec5f7b9ed06500c537aa25851a3f2d3a"></a>Translate-ReverseEngineeringCodeWithIDAPro


- 2009.01 [pediy_new_digest] [[原创]Reverse Engineering Code with IDA Pro第七章中文译稿](https://bbs.pediy.com/thread-80580.htm)
- 2008.06 [pediy_new_digest] [[翻译]Reverse Engineering Code with IDA Pro(第一、二章)](https://bbs.pediy.com/thread-66010.htm)


### <a id="d8e48eb05d72db3ac1e050d8ebc546e1"></a>REPractice


- 2019.06 [devco] [破密行動: 以不尋常的角度破解 IDA Pro 偽隨機數](https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way/)
- 2019.04 [venus_seebug] [使用 IDA Pro 的 REobjc 模块逆向 Objective-C 二进制文件](https://paper.seebug.org/887/)
- 2018.11 [somersetrecon] [Introduction to IDAPython for Vulnerability Hunting - Part 2](http://www.somersetrecon.com/blog/2018/8/2/idapython-part-2)
- 2018.07 [360_anquanke_learning] [如何使用 IDAPython 寻找漏洞](https://www.anquanke.com/post/id/151898/)
- 2018.07 [somersetrecon] [Introduction to IDAPython for Vulnerability Hunting](http://www.somersetrecon.com/blog/2018/7/6/introduction-to-idapython-for-vulnerability-hunting)
- 2018.03 [duo_blog_duo_labs] [Reversing Objective-C Binaries With the REobjc Module for IDA Pro](https://duo.com/blog/reversing-objective-c-binaries-with-the-reobjc-module-for-ida-pro)
- 2006.05 [pediy_new_digest] [Themida v1008 驱动程序分析,去除花指令的 IDA 文件](https://bbs.pediy.com/thread-25836.htm)




# <a id="319821036a3319d3ade5805f384d3165"></a>Ghidra


***


## <a id="fa45b20f6f043af1549b92f7c46c9719"></a>Plugins&&Scripts


### <a id="2ae406afda6602c8f02d73678b2ff040"></a>Ghidra


- [**18381**Star][7d] [Java] [nationalsecurityagency/ghidra](https://github.com/nationalsecurityagency/ghidra) Ghidra is a software reverse engineering (SRE) framework
- [**27**Star][2m] [Dockerfile] [dukebarman/ghidra-builder](https://github.com/dukebarman/ghidra-builder) Docker image for building ghidra RE framework from source


### <a id="ce70b8d45be0a3d29705763564623aca"></a>RecentAdd


- [**445**Star][8m] [YARA] [ghidraninja/ghidra_scripts](https://github.com/ghidraninja/ghidra_scripts) Scripts for the Ghidra software reverse engineering suite.
    - [binwalk](https://github.com/ghidraninja/ghidra_scripts/blob/master/binwalk.py) Runs binwalk on the current program and bookmarks the findings
    - [yara](https://github.com/ghidraninja/ghidra_scripts/blob/master/yara.py) Automatically find crypto constants in the loaded program - allows to very quickly identify crypto code.
    - [swift_demangler](https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py) Automatically demangle swift function names
    - [golang_renamer](https://github.com/ghidraninja/ghidra_scripts/blob/master/golang_renamer.py) Restores function names from a stripped Go binary
- [**201**Star][7m] [Java] [rolfrolles/ghidrapal](https://github.com/rolfrolles/ghidrapal) Ghidra Program Analysis Library(No Doc)
- [**59**Star][8m] [nationalsecurityagency/ghidra-data](https://github.com/nationalsecurityagency/ghidra-data) Supporting Data Archives for Ghidra
- [**50**Star][8m] [aldelaro5/ghidra-gekko-broadway-lang](https://github.com/aldelaro5/ghidra-gekko-broadway-lang) Ghidra language definition for the Gekko and Broadway CPU variant used in the Nintendo GameCube and Nintendo Wii respectively
- [**50**Star][1m] [Makefile] [blacktop/docker-ghidra](https://github.com/blacktop/docker-ghidra) Ghidra Client/Server Docker Image
- [**47**Star][26d] [Shell] [bkerler/ghidra_installer](https://github.com/bkerler/ghidra_installer) Helper scripts to set up OpenJDK 11 and scale Ghidra for 4K on Ubuntu 18.04 / 18.10
- [**39**Star][2m] [Py] [kc0bfv/pcode-emulator](https://github.com/kc0bfv/pcode-emulator) A PCode Emulator for Ghidra.
- [**35**Star][30d] [Java] [ayrx/jnianalyzer](https://github.com/ayrx/jnianalyzer) Analysis scripts for Ghidra to work with Android NDK libraries.
- [**35**Star][14d] [Py] [vdoo-connected-trust/ghidra-pyi-generator](https://github.com/vdoo-connected-trust/ghidra-pyi-generator) Generates `.pyi` type stubs for the entire Ghidra API
- [**32**Star][2m] [Py] [pagalaxylab/ghidra_scripts](https://github.com/pagalaxylab/ghidra_scripts) Scripts for the Ghidra.
- [**18**Star][5m] [Java] [edmcman/ghidra-scala-loader](https://github.com/edmcman/ghidra-scala-loader) An extension to load Ghidra scripts written in Scala
- [**18**Star][8m] [Java] [kant2002/ghidra](https://github.com/kant2002/ghidra) As it is obvious from the name this is version of NSA Ghidra which actually could be built from sources
- [**16**Star][5m] [hedgeberg/rl78_sleigh](https://github.com/hedgeberg/rl78_sleigh) An implementation of the RL78 ISA for Ghidra SRE
- [**14**Star][1m] [Java] [threatrack/ghidra-patchdiff-correlator](https://github.com/threatrack/ghidra-patchdiff-correlator) This project tries to provide additional Ghidra Version Tracking Correlators suitable for patch diffing.
- [**10**Star][2m] [Java] [threatrack/ghidra-fid-generator](https://github.com/threatrack/ghidra-fid-generator) Code for generating Ghidra FidDb files (currently only for static libraries available in the CentOS repositories)
- [**5**Star][8m] [Py] [0xd0cf11e/ghidra](https://github.com/0xd0cf11e/ghidra) Anything related to Ghidra


### <a id="69dc4207618a2977fe8cd919e7903fa5"></a>SpecificTarget


#### <a id="da5d2b05da13f8e65aa26d6a1c95a8d0"></a>NoCategory


- [**117**Star][26d] [Java] [al3xtjames/ghidra-firmware-utils](https://github.com/al3xtjames/ghidra-firmware-utils) Ghidra utilities for analyzing PC firmware
- [**103**Star][16d] [Java] [astrelsky/ghidra-cpp-class-analyzer](https://github.com/astrelsky/ghidra-cpp-class-analyzer) Ghidra C++ Class and Run Time Type Information Analyzer
- [**93**Star][6m] [Java] [felberj/gotools](https://github.com/felberj/gotools) Plugin for Ghidra to assist reversing Golang binaries


#### <a id="058bb9893323f337ad1773725d61f689"></a>Loader&&Processor


- [**88**Star][2m] [Java] [adubbz/ghidra-switch-loader](https://github.com/adubbz/ghidra-switch-loader) Nintendo Switch loader for Ghidra
- [**76**Star][2m] [Py] [leveldown-security/svd-loader-ghidra](https://github.com/leveldown-security/svd-loader-ghidra) 
- [**62**Star][28d] [Java] [beardypig/ghidra-emotionengine](https://github.com/beardypig/ghidra-emotionengine) Ghidra Processor for the Play Station 2's Emotion Engine MIPS based CPU
- [**55**Star][4m] [Assembly] [xyzz/ghidra-mep](https://github.com/xyzz/ghidra-mep) Toshiba MeP processor module for GHIDRA
- [**53**Star][16d] [Java] [cuyler36/ghidra-gamecube-loader](https://github.com/cuyler36/ghidra-gamecube-loader) A Nintendo GameCube binary loader for Ghidra
- [**51**Star][9m] [Java] [jogolden/ghidraps4loader](https://github.com/jogolden/ghidraps4loader) A Ghidra loader for PlayStation 4 binaries.
- [**43**Star][3m] [Java] [nalen98/ebpf-for-ghidra](https://github.com/nalen98/ebpf-for-ghidra) eBPF Processor for Ghidra
- [**33**Star][5m] [Java] [idl3r/ghidravmlinuxloader](https://github.com/idl3r/ghidravmlinuxloader) 
- [**32**Star][2m] [Java] [zerokilo/n64loaderwv](https://github.com/zerokilo/n64loaderwv) Ghidra Loader Module for N64 ROMs
- [**31**Star][4m] [cturt/gameboy_ghidrasleigh](https://github.com/cturt/gameboy_ghidrasleigh) Ghidra Processor support for Nintendo Game Boy
- [**27**Star][2m] [Java] [zerokilo/xexloaderwv](https://github.com/zerokilo/xexloaderwv) Ghidra Loader Module for X360 XEX Files
- [**27**Star][1m] [vgkintsugi/ghidra-segasaturn-processor](https://github.com/vgkintsugi/ghidra-segasaturn-processor) A Ghidra processor module for the Sega Saturn (SuperH SH-2)
- [**25**Star][9m] [Assembly] [thog/ghidra_falcon](https://github.com/thog/ghidra_falcon) Support of Nvidia Falcon processors for Ghidra (WIP)
- [**19**Star][6m] [guedou/ghidra-processor-mep](https://github.com/guedou/ghidra-processor-mep) Toshiba MeP-c4 for Ghidra
- [**14**Star][1m] [Java] [neatmonster/mclf-ghidra-loader](https://github.com/neatmonster/mclf-ghidra-loader) Ghidra loader module for the Mobicore trustlet and driver binaries
- [**7**Star][3m] [Java] [ballon-rouge/rx-proc-ghidra](https://github.com/ballon-rouge/rx-proc-ghidra) Renesas RX processor module for Ghidra
- [**5**Star][5m] [CSS] [lcq2/griscv](https://github.com/lcq2/griscv) RISC-V processor plugin for Ghidra
- [**4**Star][2m] [Java] [zerokilo/c64loaderwv](https://github.com/zerokilo/c64loaderwv) Ghidra Loader Module for C64 programs


#### <a id="51a2c42c6d339be24badf52acb995455"></a>Xbox


- [**24**Star][9m] [Java] [jonas-schievink/ghidraxbe](https://github.com/jonas-schievink/ghidraxbe) A Ghidra extension for loading Xbox Executables (.xbe files)
- [**17**Star][9m] [Java] [jayfoxrox/ghidra-xbox-extensions](https://github.com/jayfoxrox/ghidra-xbox-extensions) Tools to analyze original Xbox files in the Ghidra SRE framework




### <a id="99e3b02da53f1dbe59e0e277ef894687"></a>WithOtherTools


#### <a id="5923db547e1f04f708272543021701d2"></a>NoCategory


- [**42**Star][2m] [Java] [revolver-ocelot-saa/ghidrax64dbg](https://github.com/revolver-ocelot-saa/ghidrax64dbg) Extract annoations from Ghidra into an X32/X64 dbg database
    - Also In Section: [x64dbg->Plugins->RecentAdd](#da5688c7823802e734c39b539aa39df7) |


#### <a id="e1cc732d1388084530b066c26e24887b"></a>Radare2


- [**166**Star][11d] [C++] [radareorg/r2ghidra-dec](https://github.com/radareorg/r2ghidra-dec) Deep ghidra decompiler integration for radare2
    - Also In Section: [Radare2->Plugins->WithOtherTools->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**36**Star][4m] [Java] [radare/ghidra-r2web](https://github.com/radare/ghidra-r2web) Ghidra plugin to start an r2 webserver to let r2 interact with it


#### <a id="d832a81018c188bf585fcefa3ae23062"></a>IDA


- [**296**Star][3m] [Py] [cisco-talos/ghida](https://github.com/cisco-talos/ghida) an IDA Pro plugin that integrates the Ghidra decompiler in IDA.
    - Also In Section: [IDA->Tools->ImportExport->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |
- [**236**Star][8m] [Py] [daenerys-sre/source](https://github.com/daenerys-sre/source)  A framework for interoperability between IDA and Ghidra
    - Also In Section: [IDA->Tools->ImportExport->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |
- [**86**Star][3m] [Py] [cisco-talos/ghidraaas](https://github.com/cisco-talos/ghidraaas) a simple web server that exposes Ghidra analysis through REST APIs
    - Also In Section: [IDA->Tools->ImportExport->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |
- [**47**Star][2m] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
    - Also In Section: [IDA->Tools->ImportExport->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[x64dbg->Plugins->RecentAdd](#da5688c7823802e734c39b539aa39df7) |
- [**42**Star][8m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - Also In Section: [IDA->Tools->ImportExport->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[IDA->Tools->Signature(FLIRT...)->FLIRT->FLIRTSignatureGenerate](#a9a63d23d32c6c789ca4d2e146c9b6d0) |


#### <a id="60e86981b2c98f727587e7de927e0519"></a>DBI


- [**100**Star][3m] [Java] [0ffffffffh/dragondance](https://github.com/0ffffffffh/dragondance) Binary code coverage visualizer plugin for Ghidra
    - Also In Section: [DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |
    - [Ghidra插件](https://github.com/0ffffffffh/dragondance/blob/master/README.md) 
    - [coverage-pin](https://github.com/0ffffffffh/dragondance/blob/master/coveragetools/README.md) 使用Pin收集信息




### <a id="cccbd06c6b9b03152d07a4072152ae27"></a>Skin&&Theme


- [**75**Star][9m] [Py] [elliiot/ghidra_darknight](https://github.com/elliiot/ghidra_darknight) DarkNight theme for Ghidra




***


## <a id="273df546f1145fbed92bb554a327b87a"></a>Post&&Videos


### <a id="ce49901b4914f3688ef54585c8f9df1a"></a>RecentAdd


- 2019.11 [deadc0de] [Scripting Ghidra with Python](https://deadc0de.re/articles/ghidra-scripting-python.html)
- 2019.11 [4hou] [使用Ghidra对WhatsApp VOIP Stack 溢出漏洞的补丁对比分析](https://www.4hou.com/vulnerable/21141.html)
- 2019.10 [securityaffairs] [Researchers discovered a code execution flaw in NSA GHIDRA](https://securityaffairs.co/wordpress/92280/hacking/ghidra-code-execution-flaw.html)
- 2019.10 [4hou] [CVE-2019-16941: NSA Ghidra工具RCE漏洞](https://www.4hou.com/info/news/20698.html)
- 2019.09 [venus_seebug] [使用 Ghidra 对 iOS 应用进行 msgSend 分析](https://paper.seebug.org/1037/)
- 2019.09 [4hou] [利用Ghidra分析TP-link M7350 4G随身WiFi的RCE漏洞](https://www.4hou.com/vulnerable/20267.html)
- 2019.09 [4hou] [使用Ghidra对iOS应用进行msgSend分析](https://www.4hou.com/system/20326.html)
- 2019.09 [dustri] [Radare2, IDA Pro, and Binary ninja, a metaphoric comparison](https://dustri.org/b/radare2-ida-pro-and-binary-ninja-a-metaphoric-comparison.html)
- 2019.09 [youtube_WarrantyVoider] [X360 XEX Decompiling With Ghidra](https://www.youtube.com/watch?v=coGz0f7hHTM)
- 2019.08 [youtube_WarrantyVoider] [N64 ROM Decompiling With Ghidra - N64LoaderWV](https://www.youtube.com/watch?v=3d3a39LuCwc)
- 2019.08 [aliyun_xz] [CVE-2019-12103  使用Ghidra分析TP-Link M7350上的预认证RCE](https://xz.aliyun.com/t/6017)
- 2019.08 [4hou] [基于Ghidra和Neo4j的RPC分析技术](https://www.4hou.com/technology/19730.html)
- 2019.08 [hackertor] [Ghidra (Linux) 9.0.4 Arbitrary Code Execution](https://hackertor.com/2019/08/12/ghidra-linux-9-0-4-arbitrary-code-execution/)
- 2019.08 [kitploit_exploit] [Ghidra (Linux) 9.0.4 Arbitrary Code Execution](https://exploit.kitploit.com/2019/08/ghidra-linux-904-arbitrary-code.html)
- 2019.07 [hackertor] [NA – CVE-2019-13623 – In NSA Ghidra through 9.0.4, path traversal can…](https://hackertor.com/2019/07/17/na-cve-2019-13623-in-nsa-ghidra-through-9-0-4-path-traversal-can/)
- 2019.07 [hackertor] [NA – CVE-2019-13625 – NSA Ghidra before 9.0.1 allows XXE when a…](https://hackertor.com/2019/07/17/na-cve-2019-13625-nsa-ghidra-before-9-0-1-allows-xxe-when-a/)
- 2019.06 [dawidgolak] [IcedID aka #Bokbot Analysis with Ghidra.](https://medium.com/p/560e3eccb766)
- 2019.05 [vimeo_user18478112] [Three Heads are Better Than One: Mastering Ghidra - Alexei Bulazel, Jeremy Blackthorne - INFILTRATE 2019](https://vimeo.com/335158460)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Stack Depth (to detect stack manipulation)](https://www.youtube.com/watch?v=hP9FQrD61tk)
- 2019.04 [aliyun_xz] [利用Ghidra分析恶意软件Emotet](https://xz.aliyun.com/t/4931)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Shadow Hammer (Stage 1: Setup.exe) complete static Analysis](https://www.youtube.com/watch?v=gI0nZR4z7_M)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Search Program Text... (to find XOR decoding functions in malware)](https://www.youtube.com/watch?v=MaxwIxrmrWY)
- 2019.04 [X0xd0cf11e] [Analyzing Emotet with Ghidra — Part 2](https://medium.com/p/9efbea374b14)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Android APK (it's basically dex2jar with a .dex decompiler)](https://www.youtube.com/watch?v=At_T6riSb9A)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Version Tracking](https://www.youtube.com/watch?v=K83T7iVla5s)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Export Symbols and Load External Libraries (to resolve imported function names)](https://www.youtube.com/watch?v=Avn8s7iW3Rc)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Data Type Manager / Archives and Parse C Source... (resolve function signatures)](https://www.youtube.com/watch?v=u15-r5Erfnw)
- 2019.04 [X0xd0cf11e] [Analyzing Emotet with Ghidra — Part 1](https://medium.com/p/4da71a5c8d69)
- 2019.04 [youtube_X0x6d696368] [ghidra_scripts: RC4Decryptor.py](https://www.youtube.com/watch?v=kXaHrPyZtGs)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Generate Checksum... (to extract hashes of embedded malware artifacts)](https://www.youtube.com/watch?v=vLG7c5Eae0s)
- 2019.04 [msreverseengineering_blog] [An Abstract Interpretation-Based Deobfuscation Plugin for Ghidra](https://www.msreverseengineering.com/blog/2019/4/17/an-abstract-interpretation-based-deobfuscation-plugin-for-ghidra)
- 2019.04 [youtube_X0x6d696368] [Ghidra: FunctionID (to identify libraries and code reuse)](https://www.youtube.com/watch?v=P8Ul2K7pEfU)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Server / Shared Projects (using ghidra-server.org)](https://www.youtube.com/watch?v=ka4vGxLmr4w)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Bytes View (to patch binary and export to a working PE file)](https://www.youtube.com/watch?v=utUqAbfURko)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Fixing Bugs (Fixing PE section import size alignment)](https://www.youtube.com/watch?v=vpt7-Hn-Uhg)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Clear Flow and Repair, and Patch Instruction (to defeat anti-disassembly)](https://www.youtube.com/watch?v=H9DyLQ2iuyE)
- 2019.04 [shogunlab] [Here Be Dragons: Reverse Engineering with Ghidra - Part 0 [Main Windows & CrackMe]](https://www.shogunlab.com/blog/2019/04/12/here-be-dragons-ghidra-0.html)
- 2019.04 [aliyun_xz] [如何开发用于漏洞研究的Ghidra插件，Part 1](https://xz.aliyun.com/t/4723)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Scripting (Python) (a quick introduction by implementing pipeDecoder.py)](https://www.youtube.com/watch?v=WLXlq3lvUGs)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Decompile and compile (to quickly reimplement malware decoding functions)](https://www.youtube.com/watch?v=YuwOgBDt_b4)
- 2019.04 [youtube_X0x6d696368] [Ghidra: EditBytesScript (to fix/manipulate PE header to load ShadowHammer setup.exe sample)](https://www.youtube.com/watch?v=7__tiVMPIEE)
- 2019.04 [youtube_X0x6d696368] [Ghidra: Extract and Import ... (to extract resources from PE binaries)](https://www.youtube.com/watch?v=M19ZSTAgubI)
- 2019.04 [youtube_X0x6d696368] [Ghidra: YaraGhidraGUIScript (to generate a YARA signature for threat/retro hunting)](https://www.youtube.com/watch?v=tBvxVkJrkh0)
- 2019.04 [youtube_X0x6d696368] [Ghidra: XORMemoryScript (to XOR decode strings)](https://www.youtube.com/watch?v=vPqs7E_nhdQ)
- 2019.04 [somersetrecon] [Ghidra Plugin Development for Vulnerability Research - Part-1](https://www.somersetrecon.com/blog/2019/ghidra-plugin-development-for-vulnerability-research-part-1)
- 2019.04 [yoroi_blog] [Ghidra SRE: The AZORult Field Test](https://blog.yoroi.company/research/ghidra-sre-the-azorult-field-test/)
- 2019.03 [youtube_GhidraNinja] [Reversing WannaCry Part 1 - Finding the killswitch and unpacking the malware in #Ghidra](https://www.youtube.com/watch?v=Sv8yu12y5zM)
- 2019.03 [nsfocus_blog] [Ghidra Software Reverse Engineering Framework逆向工具分析](http://blog.nsfocus.net/ghidra-software-reverse-engineering-framework/)
- 2019.03 [venus_seebug] [Ghidra 从 XXE 到 RCE](https://paper.seebug.org/861/)
- 2019.03 [tencent_xlab] [Ghidra 从 XXE 到 RCE](https://xlab.tencent.com/cn/2019/03/18/ghidra-from-xxe-to-rce/)
- 2019.03 [wololo] [PS4 release: GhidraPS4Loader and Playstation 4 Flash tool](http://wololo.net/2019/03/18/ps4-release-ghidraps4loader-and-playstation-4-flash-tool/)
- 2019.03 [youtube_GhidraNinja] [Reverse engineering with #Ghidra: Breaking an embedded firmware encryption scheme](https://www.youtube.com/watch?v=4urMITJKQQs)
- 2019.03 [sans_edu_diaryarchive] [Tip: Ghidra & ZIP Files](https://isc.sans.edu/forums/diary/Tip+Ghidra+ZIP+Files/24732/)
- 2019.03 [youtube_HackerSploit] [Malware Analysis With Ghidra - Stuxnet Analysis](https://www.youtube.com/watch?v=TJhfnItRVOA)
- 2019.03 [cybersecpolitics] [Ghidra: A meta changer?](https://cybersecpolitics.blogspot.com/2019/03/ghidra-meta-changer.html)
- 2019.03 [freecodecamp] [How I solved a simple CrackMe challenge with the NSA’s Ghidra](https://medium.com/p/d7e793c5acd2)
- 2019.03 [youtube_GhidraNinja] [Ghidra quickstart & tutorial: Solving a simple crackme](https://www.youtube.com/watch?v=fTGTnrgjuGA)
- 2019.03 [sans_edu_diaryarchive] [Analysing meterpreter payload with Ghidra](https://isc.sans.edu/forums/diary/Analysing+meterpreter+payload+with+Ghidra/24722/)
- 2019.03 [freebuf] [BUF早餐铺 | NSA 公布逆向工程框架 Ghidra；沙特智能电话本应用Dalil泄露500多万用户信息；英特尔处理器面临新的 Spoiler 攻击](https://www.freebuf.com/news/197518.html)
- 2019.03 [_0xeb] [Ghidra: A quick overview for the curious](http://0xeb.net/2019/03/ghidra-a-quick-overview/)
- 2019.03 [freebuf] [RSA 2019丨NSA内部开源反汇编工具集Ghidra](https://www.freebuf.com/news/197482.html)
- 2019.03 [n0where] [NSA Software Reverse Engineering Framework: Ghidra](https://n0where.net/nsa-software-reverse-engineering-framework-ghidra)
- 2019.03 [malwaretech] [Video: First Look at Ghidra (NSA Reverse Engineering Tool)](https://www.malwaretech.com/2019/03/video-first-look-at-ghidra-nsa-reverse-engineering-tool.html)
- 2019.03 [youtube_MalwareTech] [First Look at Ghidra (NSA Reverse Engineering Tool)](https://www.youtube.com/watch?v=285b_DEmvHY)
- 2019.01 [linuxjournal] [GitHub Announces that Free Accounts Now Can Create Private Repositories, Bash-5.0 Released, iPhone Apps Linked to Golduck Malware, Godot Game Engine Reaches 3.1 Beta, NSA to Open-Source Its GHIDRA Reverse-Engineering Tool](https://www.linuxjournal.com/content/github-announces-free-accounts-now-can-create-private-repositories-bash-50-released-iphone)




# <a id="b1a6c053e88e86ce01bbd78c54c63a7c"></a>x64dbg


***


## <a id="b4a856db286f9f29b5a32d477d6b3f3a"></a>Plugins&&Scripts


### <a id="353ea40f2346191ecb828210a685f9db"></a>x64dbg


- [**34521**Star][14d] [C++] [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) An open-source x64/x32 debugger for windows.


### <a id="da5688c7823802e734c39b539aa39df7"></a>RecentAdd


- [**1668**Star][7m] [C++] [yegord/snowman](https://github.com/yegord/snowman)  a native code to C/C++ decompiler, supporting x86, AMD64, and ARM architectures
    - Also In Section: [IDA->Tools->Decompiler](#d2166f4dac4eab7fadfe0fd06467fbc9) |
    - [IDA插件](https://github.com/yegord/snowman/tree/master/src/ida-plugin) 
    - [snowman](https://github.com/yegord/snowman/tree/master/src/snowman) QT界面
    - [nocode](https://github.com/yegord/snowman/tree/master/src/nocode) 命令行工具
    - [nc](https://github.com/yegord/snowman/tree/master/src/nc) 核心代码，可作为库使用
- [**1348**Star][23d] [C] [x64dbg/x64dbgpy](https://github.com/x64dbg/x64dbgpy) Automating x64dbg using Python, Snapshots:
- [**1132**Star][2y] [C++] [x64dbg/gleebug](https://github.com/x64dbg/gleebug) Debugging Framework for Windows.
- [**971**Star][27d] [Py] [x64dbg/docs](https://github.com/x64dbg/docs) x64dbg Documentation
- [**457**Star][8d] [C] [bootleg/ret-sync](https://github.com/bootleg/ret-sync) a set of plugins that help to synchronize a debugging session (WinDbg/GDB/LLDB/OllyDbg/OllyDbg2/x64dbg) with IDA/Ghidra disassemblers
    - Also In Section: [IDA->Tools->SyncWithDebugger](#f7d311685152ac005cfce5753c006e4b) |
    - [GDB插件](https://github.com/bootleg/ret-sync/tree/master/ext_gdb) 
    - [Ghidra插件](https://github.com/bootleg/ret-sync/tree/master/ext_ghidra) 
    - [IDA插件](https://github.com/bootleg/ret-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/bootleg/ret-sync/tree/master/ext_lldb) 
    - [OD](https://github.com/bootleg/ret-sync/tree/master/ext_olly1) 
    - [OD2](https://github.com/bootleg/ret-sync/tree/master/ext_olly2) 
    - [WinDgb](https://github.com/bootleg/ret-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/bootleg/ret-sync/tree/master/ext_x64dbg) 
- [**358**Star][9m] [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) Awesome IDA, x64DBG & OllyDBG plugin
    - Also In Section: [IDA->Tools->Collection](#a7dac37cd93b8bb42c7d6aedccb751b3) |
- [**162**Star][2m] [Py] [x64dbg/x64dbgida](https://github.com/x64dbg/x64dbgida) Official x64dbg plugin for IDA Pro.
    - Also In Section: [IDA->Tools->ImportExport->NoCategory](#8ad723b704b044e664970b11ce103c09) |
- [**75**Star][3m] [C] [ahmadmansoor/advancedscript](https://github.com/ahmadmansoor/advancedscript) Add More Features for x64dbg Script System,with some Functions which will help Plugin Coder
- [**75**Star][7d] [C] [horsicq/nfdx64dbg](https://github.com/horsicq/nfdx64dbg) Plugin for x64dbg Linker/Compiler/Tool detector.
- [**74**Star][3y] [C++] [x64dbg/xedparse](https://github.com/x64dbg/xedparse)  A MASM-like, single-line plaintext assembler
- [**71**Star][2y] [C] [0ffffffffh/api-break-for-x64dbg](https://github.com/0ffffffffh/api-break-for-x64dbg) x64dbg plugin to set breakpoints automatically to Win32/64 APIs
- [**71**Star][2y] [Py] [x64dbg/mona](https://github.com/x64dbg/mona) Fork of mona.py with x64dbg support
- [**67**Star][7d] [C] [horsicq/stringsx64dbg](https://github.com/horsicq/stringsx64dbg) Strings plugin for x64dbg
- [**47**Star][2m] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
    - Also In Section: [IDA->Tools->ImportExport->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[Ghidra->Plugins->WithOtherTools->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**42**Star][2m] [Java] [revolver-ocelot-saa/ghidrax64dbg](https://github.com/revolver-ocelot-saa/ghidrax64dbg) Extract annoations from Ghidra into an X32/X64 dbg database
    - Also In Section: [Ghidra->Plugins->WithOtherTools->NoCategory](#5923db547e1f04f708272543021701d2) |
- [**42**Star][7m] [YARA] [x64dbg/yarasigs](https://github.com/x64dbg/yarasigs) Various Yara signatures (possibly to be included in a release later).
- [**41**Star][7d] [C] [horsicq/pex64dbg](https://github.com/horsicq/pex64dbg) pe viewer
- [**40**Star][3y] [C++] [x64dbg/interobfu](https://github.com/x64dbg/interobfu) Intermediate x86 instruction representation for use in obfuscation/deobfuscation.
- [**38**Star][3y] [C] [changeofpace/force-page-protection](https://github.com/changeofpace/force-page-protection) This x64dbg plugin sets the page protection for memory mapped views in scenarios which cause NtProtectVirtualMemory to fail.
- [**38**Star][3y] [C++] [kurapicabs/x64_tracer](https://github.com/kurapicabs/x64_tracer) x64dbg conditional branches logger [Plugin]
- [**38**Star][3y] [CSS] [thundercls/x64dbg_vs_dark](https://github.com/thundercls/x64dbg_vs_dark) x64dbg stylesheet like visual studio dark theme
- [**35**Star][3y] [C] [changeofpace/pe-header-dump-utilities](https://github.com/changeofpace/pe-header-dump-utilities) This x64dbg plugin adds several commands for dumping PE header information by address.
- [**29**Star][1y] [Assembly] [mrfearless/apiinfo-plugin-x86](https://github.com/mrfearless/apiinfo-plugin-x86) APIInfo Plugin (x86) - A Plugin For x64dbg
- [**29**Star][3y] [Py] [x64dbg/x64dbgbinja](https://github.com/x64dbg/x64dbgbinja) Official x64dbg plugin for Binary Ninja
- [**28**Star][2y] [C] [x64dbg/slothbp](https://github.com/x64dbg/slothbp) Collaborative Breakpoint Manager for x64dbg.
- [**27**Star][2y] [atom0s/ceautoasm-x64dbg](https://github.com/atom0s/ceautoasm-x64dbg) An x64dbg plugin that allows users to execute Cheat Engine auto assembler scripts within x64dbg.
- [**26**Star][2y] [C] [x64dbg/plugintemplate](https://github.com/x64dbg/plugintemplate) Plugin template for x64dbg. Releases:
- [**25**Star][1y] [Assembly] [mrfearless/apisearch-plugin-x86](https://github.com/mrfearless/apisearch-plugin-x86) APISearch Plugin (x86) - A Plugin For x64dbg
- [**23**Star][3y] [C++] [chausner/1337patch](https://github.com/chausner/1337patch) Simple command-line tool to apply patches exported by x64dbg to running processes
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
- [**12**Star][2y] [C] [x64dbg/capstone_wrapper](https://github.com/x64dbg/capstone_wrapper) C++ wrapper for capstone (x86 only)
- [**12**Star][24d] [C] [x64dbg/qtplugin](https://github.com/x64dbg/qtplugin) Plugin demonstrating how to link with Qt.
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




# <a id="37e37e665eac00de3f55a13dcfd47320"></a>OllyDbg


***


## <a id="7834e399e48e6c64255a1a0fdb6b88f5"></a>Plugins&&Scripts


### <a id="92c44f98ff5ad8f8b0f5e10367262f9b"></a>RecentAdd


- [**75**Star][5y] [C++] [quangnh89/ollycapstone](https://github.com/quangnh89/ollycapstone) This is a plugin for OllyDbg 1.10 to replace the old disasm engine by Capstone disassembly/disassembler framework.
- [**47**Star][8y] [C] [stephenfewer/ollysockettrace](https://github.com/stephenfewer/ollysockettrace) OllySocketTrace is a plugin for OllyDbg to trace the socket operations being performed by a process.
- [**44**Star][6m] [thomasthelen/ollydbg-scripts](https://github.com/thomasthelen/ollydbg-scripts) Unpacking scripts for Ollydbg.
- [**40**Star][8y] [C] [stephenfewer/ollyheaptrace](https://github.com/stephenfewer/ollyheaptrace) OllyHeapTrace is a plugin for OllyDbg to trace the heap operations being performed by a process.
- [**38**Star][1y] [Batchfile] [romanzaikin/ollydbg-v1.10-with-best-plugins-and-immunity-debugger-theme-](https://github.com/romanzaikin/ollydbg-v1.10-with-best-plugins-and-immunity-debugger-theme-) Make OllyDbg v1.10 Look like Immunity Debugger & Best Plugins
- [**36**Star][8y] [C] [stephenfewer/ollycalltrace](https://github.com/stephenfewer/ollycalltrace) OllyCallTrace is a plugin for OllyDbg to trace the call chain of a thread.
- [**24**Star][6y] [C++] [epsylon3/odbgscript](https://github.com/epsylon3/odbgscript) OllyDBG Script Engine
- [**22**Star][3y] [Py] [ehabhussein/ollydbg-binary-execution-visualizer](https://github.com/ehabhussein/ollydbg-binary-execution-visualizer) reverse engineering, visual binary analysis
- [**20**Star][5y] [C++] [lynnux/holyshit](https://github.com/lynnux/holyshit) ollydbg plugin, the goal is to make life easier. The project is DEAD!
- [**15**Star][8y] [C] [zynamics/ollydbg-immunitydbg-exporter](https://github.com/zynamics/ollydbg-immunitydbg-exporter) Exporters for OllyDbg and ImmunityDbg for use with zynamics BinNavi <= 3.0
- [**14**Star][5y] [C++] [sinsoul/ollight](https://github.com/sinsoul/ollight) A Code highlighting plugin for OllyDbg 2.01.
- [**9**Star][2y] [Assembly] [dentrax/dll-injection-with-assembly](https://github.com/dentrax/dll-injection-with-assembly) DLL Injection to Exe with Assembly using OllyDbg




***


## <a id="8dd3e63c4e1811973288ea8f1581dfdb"></a>Post&&Videos




# <a id="0a506e6fb2252626add375f884c9095e"></a>WinDBG


***


## <a id="37eea2c2e8885eb435987ccf3f467122"></a>Plugins&&Scripts


### <a id="2ef75ae7852daa9862b2217dca252cc3"></a>RecentAdd


- [**565**Star][6m] [C#] [fremag/memoscope.net](https://github.com/fremag/memoscope.net) Dump and analyze .Net applications memory ( a gui for WinDbg and ClrMd )
- [**390**Star][2y] [C++] [swwwolf/wdbgark](https://github.com/swwwolf/wdbgark) WinDBG Anti-RootKit Extension
- [**275**Star][13d] [Py] [hugsy/defcon_27_windbg_workshop](https://github.com/hugsy/defcon_27_windbg_workshop) DEFCON 27 workshop - Modern Debugging with WinDbg Preview
- [**227**Star][9m] [C++] [microsoft/windbg-samples](https://github.com/microsoft/windbg-samples) Sample extensions, scripts, and API uses for WinDbg.
- [**189**Star][7m] [Py] [corelan/windbglib](https://github.com/corelan/windbglib) Public repository for windbglib, a wrapper around pykd.pyd (for Windbg), used by mona.py
- [**155**Star][3y] [Py] [theevilbit/exploit_generator](https://github.com/theevilbit/exploit_generator) Automated Exploit generation with WinDBG
- [**141**Star][1y] [Py] [bruce30262/twindbg](https://github.com/bruce30262/twindbg) PEDA-like debugger UI for WinDbg
- [**134**Star][14d] [C#] [chrisnas/debuggingextensions](https://github.com/chrisnas/debuggingextensions) Host of debugging-related extensions such as post-mortem tools or WinDBG extensions
- [**133**Star][5y] [C] [goldshtn/windbg-extensions](https://github.com/goldshtn/windbg-extensions) Various extensions for WinDbg
- [**121**Star][17d] [JS] [0vercl0k/windbg-scripts](https://github.com/0vercl0k/windbg-scripts) A bunch of JavaScript extensions for WinDbg.
- [**96**Star][21d] [C++] [fdiskyou/iris](https://github.com/fdiskyou/iris) WinDbg extension to display Windows process mitigations
- [**89**Star][2y] [HTML] [sam-b/windbg-plugins](https://github.com/sam-b/windbg-plugins) Any useful windbg plugins I've written.
- [**79**Star][5y] [C++] [tandasat/findpg](https://github.com/tandasat/findpg) Windbg extension to find PatchGuard pages
- [**77**Star][3y] [HTML] [szimeus/evalyzer](https://github.com/szimeus/evalyzer) Using WinDBG to tap into JavaScript and help with deobfuscation and browser exploit detection
- [**70**Star][7d] [C++] [rodneyviana/netext](https://github.com/rodneyviana/netext) WinDbg extension for data mining managed heap. It also includes commands to list http request, wcf services, WIF tokens among others
- [**69**Star][2y] [C++] [lynnux/windbg_hilight](https://github.com/lynnux/windbg_hilight) A windbg plugin to hilight text in Disassembly and Command windows. Support x86 and x64.
- [**66**Star][2m] [davidfowl/windbgcheatsheet](https://github.com/davidfowl/windbgcheatsheet) This is a cheat sheet for windbg
- [**64**Star][1y] [vagnerpilar/windbgtree](https://github.com/vagnerpilar/windbgtree) A command tree based on commands and extensions for Windows Kernel Debugging.
- [**62**Star][26d] [JS] [hugsy/windbg_js_scripts](https://github.com/hugsy/windbg_js_scripts) Toy scripts for playing with WinDbg JS API
- [**60**Star][2m] [C++] [imugee/pegasus](https://github.com/imugee/pegasus) reverse engineering extension plugin for windbg
- [**59**Star][3y] [C++] [markhc/windbg_to_c](https://github.com/markhc/windbg_to_c) Translates WinDbg "dt" structure dump to a C structure
- [**58**Star][3y] [rehints/windbg](https://github.com/rehints/windbg) 
- [**51**Star][2y] [Py] [cisco-talos/dotnet_windbg](https://github.com/cisco-talos/dotnet_windbg) 
- [**50**Star][4y] [C++] [fishstiqz/poolinfo](https://github.com/fishstiqz/poolinfo) kernel pool windbg extension
- [**50**Star][2y] [C#] [zodiacon/windbgx](https://github.com/zodiacon/windbgx) An attempt to create a friendly version of WinDbg
- [**45**Star][2y] [Py] [kukfa/bindbg](https://github.com/kukfa/bindbg) Binary Ninja plugin that syncs WinDbg to Binary Ninja
- [**43**Star][1y] [bulentrahimkazanci/windbg-cheat-sheet](https://github.com/bulentrahimkazanci/windbg-cheat-sheet) A practical guide to analyze memory dumps of .Net applications by using Windbg
- [**42**Star][3y] [C++] [pstolarz/dumpext](https://github.com/pstolarz/dumpext) WinDbg debugger extension library providing various tools to analyse, dump and fix (restore) Microsoft Portable Executable files for both 32 (PE) and 64-bit (PE+) platforms.
- [**40**Star][11m] [C#] [kevingosse/windbg-extensions](https://github.com/kevingosse/windbg-extensions) Extensions for the new WinDbg
- [**38**Star][3y] [C++] [andreybazhan/dbgext](https://github.com/andreybazhan/dbgext) Debugger extension for the Debugging Tools for Windows (WinDbg, KD, CDB, NTSD).
- [**34**Star][6m] [C++] [seancline/pyext](https://github.com/seancline/pyext) WinDbg Extensions for Python
- [**33**Star][2y] [C] [long123king/tokenext](https://github.com/long123king/tokenext) A windbg extension, extracting token related contents
- [**31**Star][3y] [osandamalith/apimon](https://github.com/osandamalith/apimon) A simple API monitor for Windbg
- [**28**Star][7y] [C++] [cr4sh/dbgcb](https://github.com/cr4sh/dbgcb) Engine for communication with remote kernel debugger (KD, WinDbg) from drivers and applications
- [**28**Star][2y] [C++] [dshikashio/pybag](https://github.com/dshikashio/pybag) CPython module for Windbg's dbgeng plus additional wrappers.
- [**28**Star][2y] [C++] [fdfalcon/typeisolationdbg](https://github.com/fdfalcon/typeisolationdbg) A little WinDbg extension to help dump the state of Win32k Type Isolation structures.
- [**27**Star][2m] [C++] [progmboy/win32kext](https://github.com/progmboy/win32kext) windbg plugin for win32k debugging
- [**24**Star][3y] [long123king/grep](https://github.com/long123king/grep) Grep-like WinDbg extension
- [**22**Star][3m] [wangray/windbg-for-gdb-users](https://github.com/wangray/windbg-for-gdb-users) "Pwntools does not support Windows. Use a real OS ;)" — Zach Riggle, 2015
- [**21**Star][5y] [stolas/windbg-darktheme](https://github.com/stolas/windbg-darktheme) A dark theme for WinDBG.
- [**21**Star][5y] [Py] [windbgscripts/pykd](https://github.com/windbgscripts/pykd) This contains Helpful PYKD (Python Extension for Windbg) scripts
- [**18**Star][3y] [Py] [ajkhoury/windbg2struct](https://github.com/ajkhoury/windbg2struct) Takes a Windbg dumped structure (using the 'dt' command) and formats it into a C structure
- [**14**Star][3y] [C] [lowleveldesign/lldext](https://github.com/lowleveldesign/lldext) LLD WinDbg extension
- [**13**Star][3y] [C++] [evandowning/windbg-trace](https://github.com/evandowning/windbg-trace) Use WinDBG to trace the Windows API calls of any Portable Executable file
- [**13**Star][1y] [JS] [osrdrivers/windbg-exts](https://github.com/osrdrivers/windbg-exts) Various WinDbg extensions and scripts
- [**13**Star][6y] [pccq2002/windbg](https://github.com/pccq2002/windbg) windbg open source
- [**12**Star][1y] [Py] [wu-wenxiang/tool-windbg-pykd-scripts](https://github.com/wu-wenxiang/tool-windbg-pykd-scripts) Pykd scripts collection for Windbg
- [**11**Star][1y] [C] [0cch/luadbg](https://github.com/0cch/luadbg) Lua Extension for Windbg
- [**11**Star][6y] [baoqi/uni-trace](https://github.com/baoqi/uni-trace) Universal Trace Debugger Engine. Currently, only support windbg on Windows, but the long term goal is to also support GDB or LLDB
- [**10**Star][1y] [C++] [jkornev/cfgdump](https://github.com/jkornev/cfgdump) Windbg extension that allows you analyze Control Flow Guard map
- [**10**Star][3y] [C] [pstolarz/asprext](https://github.com/pstolarz/asprext) ASProtect reverse engineering & analysis WinDbg extension
- [**10**Star][3y] [C] [pstolarz/scriptext](https://github.com/pstolarz/scriptext) WinDbg scripting language utilities.
- [**9**Star][1y] [C#] [indy-singh/automateddumpanalysis](https://github.com/indy-singh/automateddumpanalysis) A simple tool that helps you run common diagnostics steps instead of battling with WinDbg.
- [**8**Star][1y] [abarbatei/windbg-info](https://github.com/abarbatei/windbg-info) collection of links related to using and improving windbg
- [**7**Star][8y] [C] [pcguru34/windbgshark](https://github.com/pcguru34/windbgshark) Automatically exported from code.google.com/p/windbgshark
- [**7**Star][9m] [C#] [xquintana/dumpreport](https://github.com/xquintana/dumpreport) Console application that creates an HTML report from a Windows user-mode dump file, using WinDBG or CDB debuggers. Although it's been mainly designed for crash dump analysis of Windows applications developed in C++, it can also be used to read hang dumps or .Net dumps.
- [**5**Star][6y] [Py] [bannedit/windbg](https://github.com/bannedit/windbg) 
- [**5**Star][5y] [C++] [dshikashio/pywindbg](https://github.com/dshikashio/pywindbg) Python Windbg extension
- [**5**Star][5y] [lallousx86/windbg-scripts](https://github.com/lallousx86/windbg-scripts) Windbg scripts
- [**5**Star][2y] [Py] [seancline/pythonsymbols](https://github.com/seancline/pythonsymbols) A WinDbg symbol server for all recent versions of CPython.
- [**4**Star][1m] [repnz/windbg-cheat-sheet](https://github.com/repnz/windbg-cheat-sheet) My personal cheat sheet for using WinDbg for kernel debugging
- [**2**Star][4y] [C] [tenpoku1000/windbg_logger](https://github.com/tenpoku1000/windbg_logger) カーネルデバッグ中の Visual Studio 内蔵 WinDbg の通信内容を記録するアプリケーションとデバイスドライバです。
- [**2**Star][2y] [C++] [vincentse/watchtrees](https://github.com/vincentse/watchtrees) Debugger extension for the Windows Debugging Tools (WinDBG, KD, CDB, NTSD). It add commands to manage watches.
- [**0**Star][9m] [C++] [kevingosse/lldb-loadmanaged](https://github.com/kevingosse/lldb-loadmanaged) LLDB plugin capable of executing plugins written for WinDbg/ClrMD




***


## <a id="6d8bac8bfb5cda00c7e3bd38d64cbce3"></a>Post&&Videos


- 2019.10 [freebuf] [Iris：一款可执行常见Windows漏洞利用检测的WinDbg扩展](https://www.freebuf.com/sectool/214276.html)
- 2019.08 [lowleveldesign] [Synthetic types and tracing syscalls in WinDbg](https://lowleveldesign.org/2019/08/27/synthetic-types-and-tracing-syscalls-in-windbg/)
- 2019.08 [hackertor] [Iris – WinDbg Extension To Perform Basic Detection Of Common Windows Exploit Mitigations](https://hackertor.com/2019/08/16/iris-windbg-extension-to-perform-basic-detection-of-common-windows-exploit-mitigations/)
- 2019.07 [osr] [How L1 Terminal Fault (L1TF) Mitigation and WinDbg Wasted My Morning (a.k.a. Yak Shaving: WinDbg Edition)](https://www.osr.com/blog/2019/07/02/how-l1-terminal-fault-l1tf-mitigation-and-windbg-wasted-my-morning-a-k-a-yak-shaving-windbg-edition/)
- 2019.06 [360_anquanke_learning] [《Dive into Windbg系列》Explorer无法启动排查](https://www.anquanke.com/post/id/179748/)
- 2019.04 [360_anquanke_learning] [《Dive into Windbg系列》AudioSrv音频服务故障](https://www.anquanke.com/post/id/176343/)
- 2019.03 [aliyun_xz] [为WinDbg和LLDB编写ClrMD扩展](https://xz.aliyun.com/t/4459)
- 2019.03 [offensive_security] [Development of a new Windows 10 KASLR Bypass (in One WinDBG Command)](https://www.offensive-security.com/vulndev/development-of-a-new-windows-10-kaslr-bypass-in-one-windbg-command/)
- 2019.02 [youtube_OALabs] [WinDbg Basics for Malware Analysis](https://www.youtube.com/watch?v=QuFJpH3My7A)


# <a id="11a59671b467a8cdbdd4ea9d5e5d9b51"></a>Android


***


## <a id="2110ded2aa5637fa933cc674bc33bf21"></a>Tools


### <a id="63fd2c592145914e99f837cecdc5a67c"></a>RecentAdd


- [**5948**Star][2m] [Java] [google/android-classyshark](https://github.com/google/android-classyshark) Analyze any Android/Java based app or game
- [**4872**Star][7m] [Java] [guardianproject/haven](https://github.com/guardianproject/haven) Haven is for people who need a way to protect their personal spaces and possessions without compromising their own privacy, through an Android app and on-device sensors
- [**4752**Star][7d] [C++] [facebook/redex](https://github.com/facebook/redex) A bytecode optimizer for Android apps
- [**3578**Star][24d] [C++] [anbox/anbox](https://github.com/anbox/anbox)  a container-based approach to boot a full Android system on a regular GNU/Linux system
- [**1361**Star][3y] [C++] [aslody/turbodex](https://github.com/aslody/turbodex) fast load dex in memory.
- [**1114**Star][11d] [Java] [huangyz0918/androidwm](https://github.com/huangyz0918/androidwm) An android image watermark library that supports invisible digital watermarks (steganography).
- [**873**Star][2m] [C] [504ensicslabs/lime](https://github.com/504ensicslabs/lime) LiME (formerly DMD) is a Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, such as those powered by Android. The tool supports acquiring memory either to the file system of the device or over the network. LiME is unique in that it is the first tool that allows full memory captures f…
- [**664**Star][7y] [Java] [honeynet/apkinspector](https://github.com/honeynet/apkinspector) APKinspector is a powerful GUI tool for analysts to analyze the Android applications.
- [**537**Star][27d] [nordicsemiconductor/android-nrf-connect](https://github.com/nordicsemiconductor/android-nrf-connect) Documentation and issue tracker for nRF Connect for Android.
- [**447**Star][11m] [Kotlin] [shadowsocks/kcptun-android](https://github.com/shadowsocks/kcptun-android) kcptun for Android.
- [**408**Star][2m] [CSS] [angea/pocorgtfo](https://github.com/angea/pocorgtfo) a "PoC or GTFO" mirror with extra article index, direct links and clean PDFs.
- [**404**Star][1y] [Java] [testwhat/smaliex](https://github.com/testwhat/smaliex) A wrapper to get de-optimized dex from odex/oat/vdex.
- [**320**Star][2y] [Kotlin] [ollide/intellij-java2smali](https://github.com/ollide/intellij-java2smali) A plugin for IntelliJ IDEA & Android Studio to easily compile Java & Kotlin files to smali.
- [**283**Star][2y] [Java] [simbiose/encryption](https://github.com/simbiose/encryption) Encryption is a simple way to encrypt and decrypt strings on Android and Java project.
- [**276**Star][8m] [Py] [micropyramid/forex-python](https://github.com/micropyramid/forex-python) Foreign exchange rates, Bitcoin price index and currency conversion using ratesapi.io
- [**267**Star][4y] [C] [samsung/adbi](https://github.com/samsung/adbi) Android Dynamic Binary Instrumentation tool for tracing Android native layer
- [**253**Star][3m] [Py] [amimo/dcc](https://github.com/amimo/dcc) DCC (Dex-to-C Compiler) is method-based aot compiler that can translate DEX code to C code.
- [**250**Star][2y] [Java] [panhongwei/tracereader](https://github.com/panhongwei/tracereader) android小工具，通过读取trace文件，回溯整个整个程序执行调用树。
- [**206**Star][2m] [C] [derrekr/fastboot3ds](https://github.com/derrekr/fastboot3ds) A homebrew bootloader for the Nintendo 3DS that is similar to android's fastboot.
- [**174**Star][1m] [Java] [calebfenton/apkfile](https://github.com/calebfenton/apkfile) Android app analysis and feature extraction library
- [**173**Star][7y] [Py] [trivio/common_crawl_index](https://github.com/trivio/common_crawl_index) billions of pages randomly crawled from the internet
- [**161**Star][1y] [Java] [iqiyi/dexsplitter](https://github.com/iqiyi/dexsplitter) Analyze contribution rate of each module to the apk size
- [**158**Star][3y] [Java] [googlecloudplatform/endpoints-codelab-android](https://github.com/googlecloudplatform/endpoints-codelab-android) endpoints-codelab-android
- [**137**Star][2y] [Java] [gnaixx/hidex-hack](https://github.com/gnaixx/hidex-hack) anti reverse by hack dex file
- [**102**Star][6m] [Py] [vmavromatis/absolutely-proprietary](https://github.com/vmavromatis/absolutely-proprietary) Proprietary package detector for arch-based distros. Compares your installed packages against Parabola's package blacklist and then prints your Stallman Freedom Index (free/total).
- [**93**Star][2y] [C++] [femto-dev/femto](https://github.com/femto-dev/femto) Sequence Indexing and Search
- [**89**Star][4y] [C] [rchiossi/dexterity](https://github.com/rchiossi/dexterity) Dex manipulation library
- [**79**Star][3y] [Py] [dancezarp/tbdex](https://github.com/dancezarp/tbdex) 
- [**75**Star][2m] [Py] [tp7309/ttdedroid](https://github.com/tp7309/ttdedroid) 一键反编译工具One key for quickly decompile apk/aar/dex/jar, support by jadx/dex2jar/enjarify/cfr.
- [**66**Star][3y] [Py] [crange/crange](https://github.com/crange/crange) Crange is a tool to index and cross-reference C/C++ source code
- [**65**Star][1y] [Py] [cryptax/dextools](https://github.com/cryptax/dextools) Miscellaenous DEX (Dalvik Executable) tools
- [**54**Star][9m] [Py] [circl/potiron](https://github.com/circl/potiron) Potiron - Normalize, Index and Visualize Network Capture
- [**54**Star][5y] [Go] [hailocab/logslam](https://github.com/hailocab/logslam) A lightweight lumberjack protocol compliant logstash indexer
- [**43**Star][1y] [JS] [intoli/slice](https://github.com/intoli/slice) A JavaScript implementation of Python's negative indexing and extended slice syntax.
- [**43**Star][3y] [Java] [miracle963/zjdroid](https://github.com/miracle963/zjdroid) 基于Xposed Framewrok的动态逆向分析模块，逆向分析者可以通过ZjDroid完成以下工作： DEX文件的内存dump 基于Dalvik关键指针的内存BackSmali，有效破解加固应用 敏感API的动态监控 指定内存区域数据dump 获取应用加载DEX信息。 获取指定DEX文件加载类信息。 dump Dalvik java堆信息。 在目标进程动态运行lua脚本。
- [**38**Star][5y] [Py] [jakev/oat2dex-python](https://github.com/jakev/oat2dex-python) Extract DEX files from an ART ELF binary
- [**37**Star][2y] [HTML] [keenrivals/bugsite-index](https://github.com/keenrivals/bugsite-index) Index of websites publishing bugs along the lines of heartbleed.com
- [**36**Star][1y] [Py] [aptnotes/tools](https://github.com/aptnotes/tools) Tools to interact with APTnotes reporting/index.
- [**32**Star][3y] [Py] [mdegrazia/osx-quicklook-parser](https://github.com/mdegrazia/osx-quicklook-parser) Parse the Mac Quickook index.sqlite database
- [**28**Star][6y] [MATLAB] [vedaldi/visualindex](https://github.com/vedaldi/visualindex) A simple demo of visual object matching using VLFeat
- [**25**Star][5y] [Py] [fygrave/dnslyzer](https://github.com/fygrave/dnslyzer) DNS traffic indexer and analyzer
- [**23**Star][5y] [Py] [burningcodes/dexconfuse](https://github.com/burningcodes/dexconfuse) 简易dex混淆器


### <a id="883a4e0dd67c6482d28a7a14228cd942"></a>RecentAdd1


- [**154**Star][2m] [Java] [reddr/libscout](https://github.com/reddr/libscout) Third-party library detector for Java/Android apps
- [**154**Star][3m] [Java] [rednaga/axmlprinter](https://github.com/rednaga/axmlprinter) Library for parsing and printing compiled Android manifest files
- [**146**Star][2y] [Py] [mhelwig/apk-anal](https://github.com/mhelwig/apk-anal) Android APK analyzer based on radare2 and others.
    - Also In Section: [Radare2->Plugins->RecentAdd](#6922457cb0d4b6b87a34caf39aa31dfe) |
- [**145**Star][9m] [Java] [lanchon/haystack](https://github.com/lanchon/haystack) Signature Spoofing Patcher for Android
- [**141**Star][1m] [Java] [joshjdevl/libsodium-jni](https://github.com/joshjdevl/libsodium-jni) (Android) Networking and Cryptography Library (NaCL) JNI binding. JNI is utilized for fastest access to native code. Accessible either in Android or Java application. Uses SWIG to generate Java JNI bindings. SWIG definitions are extensible to other languages.
- [**138**Star][8m] [Py] [ale5000-git/tingle](https://github.com/ale5000-git/tingle) Android patcher
- [**136**Star][2m] [nathanchance/android-kernel-clang](https://github.com/nathanchance/android-kernel-clang) Information on compiling Android kernels with Clang
- [**131**Star][3y] [Batchfile] [eliteandroidapps/whatsapp-key-db-extractor](https://github.com/eliteandroidapps/whatsapp-key-db-extractor) Allows WhatsApp users to extract their cipher key and databases on non-rooted Android devices.
- [**130**Star][4y] [C] [hiteshd/android-rootkit](https://github.com/hiteshd/android-rootkit) A rootkit for Android. Based on "Android platform based linux kernel rootkit" from Phrack Issue 68
- [**123**Star][1m] [osm0sis/android-busybox-ndk](https://github.com/osm0sis/android-busybox-ndk) Keeping track of instructions and patches for building busybox with the Android NDK
- [**122**Star][4y] [irsl/adb-backup-apk-injection](https://github.com/irsl/adb-backup-apk-injection) Android ADB backup APK Injection POC
- [**121**Star][3m] [Shell] [exalab/anlinux-resources](https://github.com/exalab/anlinux-resources) Image and Script for LinuxOnAndroid App
- [**121**Star][7y] [Py] [liato/android-market-api-py](https://github.com/liato/android-market-api-py) A Python port of the java Android Market API.
- [**119**Star][1m] [C++] [stealth/lophttpd](https://github.com/stealth/lophttpd) lots of performance (or lots of porn, if you prefer) httpd: Easy, chrooted, fast and simple to use HTTP server for static content. Runs on Linux, BSD, Android and OSX/Darwin. It's free but if you like it, consider donating to the EFF:
- [**117**Star][2m] [Java] [auth0/lock.android](https://github.com/auth0/lock.android) Android Library to authenticate using Auth0 and with a Native Look & Feel
- [**117**Star][3y] [Java] [rafaeltoledo/android-security](https://github.com/rafaeltoledo/android-security) An app showcase of some techniques to improve Android app security
- [**117**Star][9m] [Java] [securityfirst/umbrella_android](https://github.com/securityfirst/umbrella_android) Digital and Physical Security Advice App
- [**116**Star][21d] [Kotlin] [babylonhealth/certificate-transparency-android](https://github.com/babylonhealth/certificate-transparency-android) Certificate transparency for Android and Java
- [**115**Star][4m] [Java] [andprox/andprox](https://github.com/andprox/andprox) Native Android Proxmark3 client (no root required)
- [**113**Star][4y] [Java] [evilsocket/pdusms](https://github.com/evilsocket/pdusms) PoC app for raw pdu manipulation on Android.
- [**109**Star][2y] [C] [pbatard/bootimg-tools](https://github.com/pbatard/bootimg-tools) Android boot.img creation and extraction tools [NOTE: This project is NO LONGER maintained]
- [**104**Star][9m] [C++] [quarkslab/android-restriction-bypass](https://github.com/quarkslab/android-restriction-bypass) PoC to bypass Android restrictions
- [**104**Star][11m] [Java] [varunon9/remote-control-pc](https://github.com/varunon9/remote-control-pc) Control Laptop using Android. Remote control PC consists of android as well as desktop app written in Java to control laptop using phone.
- [**103**Star][19d] [Py] [virb3/apk-utilities](https://github.com/virb3/apk-utilities) Tools and scripts to manipulate Android APKs
- [**99**Star][10m] [winterssy/miui-purify](https://github.com/winterssy/miui-purify) 个人兴趣项目存档，使用 apktool 魔改 MIUI ROM，去除 MIUI 系统新增的广告。
- [**98**Star][7m] [Py] [alexmyg/andropytool](https://github.com/alexmyg/andropytool) A framework for automated extraction of static and dynamic features from Android applications
- [**95**Star][4y] [Java] [zencodex/hack-android](https://github.com/zencodex/hack-android) Collection tools for hack android, java
- [**94**Star][2y] [Java] [dexpatcher/dex2jar](https://github.com/dexpatcher/dex2jar) Unofficial dex2jar updated for Android 8
- [**90**Star][2y] [Java] [5gsd/aimsicdl](https://github.com/5gsd/aimsicdl) AIMSICD Lite (Android IMSI-Catcher Detector) - reloaded!
- [**90**Star][3y] [Java] [mingyuan-xia/patdroid](https://github.com/mingyuan-xia/patdroid) A Program Analysis Toolkit for Android
- [**90**Star][8y] [Java] [securitycompass/androidlabs](https://github.com/securitycompass/androidlabs) Android security labs
- [**88**Star][1y] [Objective-C] [cmackay/google-analytics-plugin](https://github.com/cmackay/google-analytics-plugin) Cordova Google Analytics Plugin for Android & iOS
- [**87**Star][2m] [Scala] [rsertelon/android-keystore-recovery](https://github.com/rsertelon/android-keystore-recovery) A tool to recover your lost Android keystore password
- [**86**Star][3y] [Py] [ucsb-seclab/baredroid](https://github.com/ucsb-seclab/baredroid) bare-metal analysis on Android devices
- [**85**Star][7y] [Java] [thomascannon/android-sms-spoof](https://github.com/thomascannon/android-sms-spoof) PoC app which takes advantage of Android's SmsReceiverService being exported to fake an incoming SMS with no permissions.
- [**82**Star][2y] [Kotlin] [viktordegtyarev/callreclib](https://github.com/viktordegtyarev/callreclib) Call Recorder fix for Android 7 and Android 6
- [**81**Star][4y] [Py] [android-dtf/dtf](https://github.com/android-dtf/dtf) Android Device Testing Framework ("dtf")
- [**80**Star][2m] [Py] [sashs/filebytes](https://github.com/sashs/filebytes) Library to read and edit files in the following formats: Executable and Linking Format (ELF), Portable Executable (PE), MachO and OAT (Android Runtime)
- [**77**Star][12d] [HTML] [android-x86/android-x86.github.io](https://github.com/android-x86/android-x86.github.io) Official Website for Android-x86 Project
- [**77**Star][2y] [C++] [daizhongyin/securitysdk](https://github.com/daizhongyin/securitysdk) Android安全SDK，提供基础的安全防护能力，如安全webview、IPC安全通信、应用和插件安全更新、威胁情报搜集等等
- [**76**Star][3y] [Py] [moosd/needle](https://github.com/moosd/needle) Android framework injection made easy
- [**75**Star][3y] [Java] [guardianproject/cacheword](https://github.com/guardianproject/cacheword) a password caching and management service for Android
- [**74**Star][2m] [Ruby] [devunwired/apktools](https://github.com/devunwired/apktools) Ruby library for reading/parsing APK resource data
- [**74**Star][16d] [Py] [nightwatchcybersecurity/truegaze](https://github.com/nightwatchcybersecurity/truegaze) Static analysis tool for Android/iOS apps focusing on security issues outside the source code
- [**74**Star][11m] [Java] [thelinuxchoice/droidtracker](https://github.com/thelinuxchoice/droidtracker) Script to generate an Android App to track location in real time
- [**72**Star][2y] [C++] [vusec/guardion](https://github.com/vusec/guardion) Android GuardION patches to mitigate DMA-based Rowhammer attacks on ARM
- [**70**Star][4y] [Py] [programa-stic/marvin-django](https://github.com/programa-stic/marvin-django) Marvin-django is the UI/database part of the Marvin project. Marvin is a platform for security analysis of Android apps.
- [**69**Star][2y] [androidtamer/androidtamer](https://github.com/androidtamer/androidtamer) We Use Github Extensively and openly. So it becomes dificult to track what's what and what's where. This repository is a master repo to Help with that.
- [**69**Star][8d] [Java] [auth0/auth0.android](https://github.com/auth0/auth0.android) Android toolkit for Auth0 API
- [**67**Star][1y] [Shell] [kiyadesu/android](https://github.com/kiyadesu/Android) walk into Android security step by step
- [**66**Star][6y] [C] [hiikezoe/android_run_root_shell](https://github.com/hiikezoe/android_run_root_shell) 
- [**66**Star][10m] [Py] [yelp/parcelgen](https://github.com/yelp/parcelgen) Helpful tool to make data objects easier for Android
- [**66**Star][18d] [Py] [imtiazkarimik23/atfuzzer](https://github.com/imtiazkarimik23/atfuzzer) "Opening Pandora's Box through ATFuzzer: Dynamic Analysis of AT Interface for Android Smartphones" ACSAC 2019
- [**65**Star][5y] [Java] [guardianproject/trustedintents](https://github.com/guardianproject/trustedintents) library for flexible trusted interactions between Android apps
- [**65**Star][6y] [C++] [trevd/android_root](https://github.com/trevd/android_root) Got Root!
- [**65**Star][8y] [C] [robclemons/arpspoof](https://github.com/robclemons/Arpspoof) Android port of Arpspoof
- [**64**Star][6y] [Java] [ibrahimbalic/androidrat](https://github.com/ibrahimbalic/androidrat) Android RAT
- [**63**Star][2m] [Java] [flankerhqd/bindump4j](https://github.com/flankerhqd/bindump4j) A portable utility to locate android binder service
- [**62**Star][2y] [C] [wlach/orangutan](https://github.com/wlach/orangutan) Simulate native events on Android-like devices
- [**60**Star][7y] [Java] [intrepidusgroup/iglogger](https://github.com/intrepidusgroup/iglogger) Class to help with adding logging function in smali output from 3rd party Android apps.
- [**58**Star][5y] [C] [poliva/dexinfo](https://github.com/poliva/dexinfo) A very rudimentary Android DEX file parser
- [**56**Star][2y] [Java] [amotzte/android-mock-location-for-development](https://github.com/amotzte/android-mock-location-for-development) allows to change mock location from command line on real devices
- [**56**Star][1y] [C] [jduck/canhazaxs](https://github.com/jduck/canhazaxs) A tool for enumerating the access to entries in the file system of an Android device.
- [**56**Star][5m] [Java] [pnfsoftware/jeb2-androsig](https://github.com/pnfsoftware/jeb2-androsig) Android Library Code Recognition
- [**56**Star][24d] [Kotlin] [m1dr05/istheapp](https://github.com/m1dr05/istheapp) Open-source android spyware
- [**54**Star][1y] [JS] [enovella/androidtrainings](https://github.com/enovella/androidtrainings) Mobile security trainings based on android
- [**54**Star][22d] [Py] [ucsb-seclab/agrigento](https://github.com/ucsb-seclab/agrigento) Agrigento is a tool to identify privacy leaks in Android apps by performing black-box differential analysis on the network traffic.
- [**53**Star][2y] [Java] [modzero/modjoda](https://github.com/modzero/modjoda) Java Object Deserialization on Android
- [**53**Star][3y] [Shell] [nvssks/android-responder](https://github.com/nvssks/android-responder) Scripts for running Responder.py in an Android (rooted) device.
- [**53**Star][5y] [Java] [thuxnder/androiddevice.info](https://github.com/thuxnder/androiddevice.info) Android app collecting device information and submiting it to
- [**53**Star][3y] [Java] [giovannicolonna/msfvenom-backdoor-android](https://github.com/giovannicolonna/msfvenom-backdoor-android) Android backdoored app, improved source code of msfvenom android .apk
- [**50**Star][2m] [Py] [nelenkov/android-device-check](https://github.com/nelenkov/android-device-check) Check Android device security settings
- [**49**Star][5y] [Java] [retme7/broadanywhere_poc_by_retme_bug_17356824](https://github.com/retme7/broadanywhere_poc_by_retme_bug_17356824) a poc of Android bug 17356824
- [**48**Star][3y] [Shell] [osm0sis/apk-patcher](https://github.com/osm0sis/apk-patcher) Patch APKs on-the-fly from Android recovery (Proof of Concept)
- [**48**Star][5y] [C++] [sogeti-esec-lab/android-fde](https://github.com/sogeti-esec-lab/android-fde) Tools to work on Android Full Disk Encryption (FDE).
- [**48**Star][7y] [tias/android-busybox-ndk](https://github.com/tias/android-busybox-ndk) Keeping track of instructions and patches for building busybox with the android NDK
- [**46**Star][3y] [Py] [alessandroz/pupy](https://github.com/alessandroz/pupy) Pupy is an opensource, multi-platform (Windows, Linux, OSX, Android), multi function RAT (Remote Administration Tool) mainly written in python. It features a all-in-memory execution guideline and leaves very low footprint. Pupy can communicate using various transports, migrate into processes (reflective injection), load remote python code, pytho…
- [**46**Star][5m] [Py] [cryptax/angeapk](https://github.com/cryptax/angeapk) Encrypting a PNG into an Android application
- [**45**Star][1y] [Java] [kaushikravikumar/realtimetaxiandroiddemo](https://github.com/kaushikravikumar/realtimetaxiandroiddemo) PubNub Demo that uses a Publish/Subscribe model to implement a realtime map functionality similar to Lyft/Uber.
- [**44**Star][5m] [Java] [tlamb96/kgb_messenger](https://github.com/tlamb96/kgb_messenger) An Android CTF practice challenge
- [**43**Star][2y] [Java] [m301/rdroid](https://github.com/m301/rdroid) [Android RAT] Remotely manage your android phone using PHP Interface
- [**42**Star][2m] [Java] [nowsecure/cybertruckchallenge19](https://github.com/nowsecure/cybertruckchallenge19) Android security workshop material taught during the CyberTruck Challenge 2019 (Detroit USA).
- [**41**Star][4y] [C] [sesuperuser/super-bootimg](https://github.com/sesuperuser/super-bootimg) Tools to edit Android boot.img. NDK buildable, to be usable in an update.zip
- [**41**Star][2y] [Shell] [xtiankisutsa/twiga](https://github.com/xtiankisutsa/twiga) twiga：枚举 Android 设备，获取了解其内部部件和漏洞利用的信息
- [**41**Star][5y] [Java] [tacixat/cfgscandroid](https://github.com/TACIXAT/CFGScanDroid) Control Flow Graph Scanning for Android
- [**40**Star][2y] [Java] [ivianuu/contributer](https://github.com/ivianuu/contributer) Inject all types like views or a conductor controllers with @ContributesAndroidInjector
- [**40**Star][7y] [C++] [taintdroid/android_platform_dalvik](https://github.com/taintdroid/android_platform_dalvik) Mirror of git://android.git.kernel.org/platform/dalvik.git with TaintDroid additions (mirror lags official Android)
- [**39**Star][5y] [C] [cyanogenmod/android_external_openssl](https://github.com/cyanogenmod/android_external_openssl) OpenSSL for Android
- [**39**Star][1y] [Py] [sundaysec/andspoilt](https://github.com/sundaysec/andspoilt) Run interactive android exploits in linux.
- [**38**Star][7m] [Java] [pnfsoftware/jnihelper](https://github.com/pnfsoftware/jnihelper) jeb-plugin-android-jni-helper
- [**38**Star][11m] [Java] [thelinuxchoice/droidcam](https://github.com/thelinuxchoice/droidcam) Script to generate an Android App to take photos from Cameras
- [**36**Star][8d] [Java] [cliqz-oss/browser-android](https://github.com/cliqz-oss/browser-android) CLIQZ for Android
- [**36**Star][4y] [Java] [julianschuette/condroid](https://github.com/julianschuette/condroid) Symbolic/concolic execution of Android apps
- [**36**Star][10m] [Kotlin] [cbeuw/cloak-android](https://github.com/cbeuw/cloak-android) Android client of Cloak
- [**35**Star][6m] [Py] [bkerler/dump_avb_signature](https://github.com/bkerler/dump_avb_signature) Dump Android Verified Boot Signature
- [**35**Star][5y] [C#] [redth/android.signature.tool](https://github.com/redth/android.signature.tool) Simple GUI tool for Mac and Windows to help find the SHA1 and MD5 hashes of your Android keystore's and apk's
- [**35**Star][3y] [Java] [serval-snt-uni-lu/droidra](https://github.com/serval-snt-uni-lu/droidra) Taming Reflection to Support Whole-Program Analysis of Android Apps
- [**35**Star][7d] [Java] [gedsh/invizible](https://github.com/gedsh/invizible) Android application for Internet privacy and security
- [**34**Star][2y] [hardenedlinux/armv7-nexus7-grsec](https://github.com/hardenedlinux/armv7-nexus7-grsec) Hardened PoC: PaX for Android
- [**34**Star][10m] [Kotlin] [cbeuw/goquiet-android](https://github.com/cbeuw/goquiet-android) GoQuiet plugin on android
- [**33**Star][3y] [Java] [riramar/pubkey-pin-android](https://github.com/riramar/pubkey-pin-android) Just another example for Android Public Key Pinning (based on OWASP example)
- [**32**Star][2y] [dweinstein/dockerfile-androguard](https://github.com/dweinstein/dockerfile-androguard) docker file for use with androguard python android app analysis tool
- [**32**Star][1y] [C] [jp-bennett/fwknop2](https://github.com/jp-bennett/fwknop2) A replacement fwknop client for android.
- [**32**Star][6m] [Shell] [robertohuertasm/apk-decompiler](https://github.com/robertohuertasm/apk-decompiler) Small Rust utility to decompile Android apks
- [**30**Star][7m] [Java] [pnfsoftware/jeb2-plugin-oat](https://github.com/pnfsoftware/jeb2-plugin-oat) Android OAT Plugin for JEB
- [**30**Star][2y] [Java] [amitshekhariitbhu/applock](https://github.com/amitshekhariitbhu/applock) Android Application for app lock
- [**28**Star][4m] [Py] [azmatt/anaximander](https://github.com/azmatt/anaximander) Python Code to Map Cell Towers From a Cellebrite Android Dump
- [**28**Star][1y] [C] [calebfenton/native-harness-target](https://github.com/calebfenton/native-harness-target) Android app for demonstrating native library harnessing
- [**28**Star][2m] [Py] [cryptax/droidlysis](https://github.com/cryptax/droidlysis) Property extractor for Android apps
- [**27**Star][4y] [C] [anarcheuz/android-pocs](https://github.com/anarcheuz/android-pocs) 
- [**27**Star][2y] [Java] [martinstyk/apkanalyzer](https://github.com/martinstyk/apkanalyzer) Java tool for analyzing Android APK files
- [**26**Star][2m] [grapheneos/os_issue_tracker](https://github.com/grapheneos/os_issue_tracker) Issue tracker for GrapheneOS Android Open Source Project hardening work. Standalone projects like Auditor, AttestationServer and hardened_malloc have their own dedicated trackers.
- [**26**Star][1y] [Ruby] [ajitsing/apktojava](https://github.com/ajitsing/apktojava) View android apk as java code in gui
- [**25**Star][3y] [zyrikby/android_permission_evolution](https://github.com/zyrikby/android_permission_evolution) Analysis of the evolution of Android permissions. This repository contains the results presented in the paper "Small Changes, Big Changes: An Updated View on the Android Permission System".
- [**25**Star][11m] [Visual Basic] [modify24x7/ultimate-advanced-apktool](https://github.com/modify24x7/ultimate-advanced-apktool) v4.1
- [**24**Star][2y] [Java] [commonsguy/autofillfollies](https://github.com/commonsguy/autofillfollies) Demonstration of security issues with Android 8.0 autofill
- [**24**Star][12m] [C++] [zsshen/yadd](https://github.com/zsshen/yadd) Yet another Android Dex bytecode Disassembler: a static Android app disassembler for fast class and method signature extraction and code structure visualization.
- [**24**Star][13d] [JS] [fsecurelabs/android-keystore-audit](https://github.com/fsecurelabs/android-keystore-audit) 
- [**24**Star][4y] [Java] [stealthcopter/steganography](https://github.com/stealthcopter/steganography) Android Steganography Library
- [**22**Star][27d] [Java] [snail007/goproxy-ss-plugin-android](https://github.com/snail007/goproxy-ss-plugin-android) goproxy安卓全局代理，ss goproxy安卓插件, goproxy :
- [**21**Star][7y] [C] [0xroot/whitesnow](https://github.com/0xroot/whitesnow) An experimental rootkit for Android
- [**21**Star][1y] [Smali] [dan7800/vulnerableandroidapporacle](https://github.com/dan7800/vulnerableandroidapporacle) 
- [**20**Star][9m] [Rust] [gamozolabs/slime_tree](https://github.com/gamozolabs/slime_tree) Worst Android kernel fuzzer
- [**20**Star][5y] [snifer/l4bsforandroid](https://github.com/snifer/l4bsforandroid) Repositorio de APK para Hacking y Seguridad
- [**19**Star][18d] [Smali] [aress31/sci](https://github.com/aress31/sci) Framework designed to automate the process of assembly code injection (trojanising) within Android applications.
- [**19**Star][2m] [C] [cybersaxostiger/androiddump](https://github.com/cybersaxostiger/androiddump) A tool pulls loaded binaries ordered by memory regions
- [**19**Star][1m] [Java] [h3xstream/find-sec-bugs](https://github.com/h3xstream/find-sec-bugs) The FindBugs plugin for security audits of Java web applications and Android applications. (Also work with Scala and Groovy projects)
- [**19**Star][5y] [Java] [juxing/adoreforandroid](https://github.com/juxing/adoreforandroid) Transplant adore rootkit for Android platform.
- [**18**Star][3y] [C] [freddierice/farm-root](https://github.com/freddierice/farm-root) Farm root is a root for android devices using the dirty cow vulnerability
- [**18**Star][7y] [Java] [jseidl/goldeneye-mobile](https://github.com/jseidl/goldeneye-mobile) GoldenEye Mobile Android Layer 7 HTTP DoS Test Tool
- [**18**Star][4y] [Java] [meleap/myo_andoridemg](https://github.com/meleap/myo_andoridemg) We got the Myo's EMG-data on Android by hacking bluetooth.
- [**18**Star][6y] [Java] [taufderl/whatsapp-sniffer-android-poc](https://github.com/taufderl/whatsapp-sniffer-android-poc) proof of concept app to show how to upload and decrypt WhatsApp backup database
- [**18**Star][9d] [jqorz/biquge_crack](https://github.com/jqorz/biquge_crack) 笔趣阁_Android_去广告修改版（免费看小说！无广告！秒开无等待！）反编译学习
- [**17**Star][3y] [bemre/bankbot-mazain](https://github.com/bemre/bankbot-mazain) 针对Android设备的开源手机银行木马BankBot / Mazain分析
- [**17**Star][6y] [Py] [thomascannon/android-fde-decryption](https://github.com/thomascannon/android-fde-decryption) Cracking and decrypting Android Full Device Encryption
- [**17**Star][6y] [Java] [fsecurelabs/mwr-android](https://github.com/FSecureLABS/mwr-android) A collection of utilities for Android applications.
- [**16**Star][2y] [androidtamer/tools](https://github.com/androidtamer/tools) This website will be holding list / details of each and every tool available via Android Tamer
- [**16**Star][4y] [lewisrhine/kotlin-for-android-developers-zh](https://github.com/lewisrhine/kotlin-for-android-developers-zh) Kotlin for android developers in chinese.
- [**16**Star][5y] [C++] [trustonic/trustonic-tee-user-space](https://github.com/trustonic/trustonic-tee-user-space) Android user space components for the Trustonic Trusted Execution Environment
- [**15**Star][4m] [hyrathon/hitcon2019](https://github.com/hyrathon/hitcon2019) Slides(In both CN and EN) & WP(outdated) of my topic in HITCON 2019 about bug hunting in Android NFC
- [**15**Star][7y] [Vim script] [jlarimer/android-stuff](https://github.com/jlarimer/android-stuff) Random scripts and files I use for Android reversing
- [**15**Star][2y] [Java] [tanprathan/sievepwn](https://github.com/tanprathan/sievepwn) An android application which exploits sieve through android components.
- [**14**Star][2y] [C++] [chenzhihui28/securitydemo](https://github.com/chenzhihui28/securitydemo) ndk进行简单的签名校验，密钥保护demo,android应用签名校验
- [**13**Star][2y] [anelkaos/ada](https://github.com/anelkaos/ada) Android Automation Tool
- [**13**Star][2y] [Scala] [fschrofner/glassdoor](https://github.com/fschrofner/glassdoor) glassdoor is a modern, autonomous security framework for Android APKs. POC, unmaintained unfortunately.
- [**13**Star][6y] [Shell] [k3170makan/droidsploit](https://github.com/k3170makan/droidsploit) A collection of scripts to find common application vulnerabilities in Android Applications
- [**13**Star][5y] [Py] [lifeasageek/morula](https://github.com/lifeasageek/morula) Morula is a secure replacement of Zygote to fortify weakened ASLR on Android
- [**13**Star][12m] [Shell] [theyahya/android-decompile](https://github.com/theyahya/android-decompile) 
- [**12**Star][1y] [JS] [integrity-sa/android](https://github.com/integrity-sa/android) Repository with research related to Android
- [**12**Star][3y] [Java] [miguelmarco/zcashpannel](https://github.com/miguelmarco/zcashpannel) An android front-end to the zcash wallet through onion services
- [**12**Star][5y] [Java] [poliva/radare-installer](https://github.com/poliva/radare-installer) Application to easily download and install radare2 on android devices
- [**12**Star][3y] [Py] [zyrikby/bboxtester](https://github.com/zyrikby/bboxtester) Tool to measure code coverage of Android applications when their source code is not available
- [**11**Star][7y] [Java] [jeffers102/keystorecracker](https://github.com/jeffers102/keystorecracker) Helps retrieve forgotten keystore passwords using your commonly used segments. Great for those forgotten Android keystore passphrases, which is exactly why I created this tool in the first place!
- [**11**Star][7m] [Java] [radare/radare2-installer](https://github.com/radare/radare2-installer) Application to easily download and install radare2 on android devices
- [**11**Star][1y] [Java] [wishihab/wedefend-android](https://github.com/wishihab/wedefend-android) ⛔
- [**11**Star][1y] [Java] [zjsnowman/hackandroid](https://github.com/zjsnowman/hackandroid) Android安全之 Activity 劫持与反劫持
- [**11**Star][1y] [Java] [mandyonze/droidsentinel](https://github.com/Mandyonze/DroidSentinel) Analizador de tráfico para dispositivos Android potencialmente comprometidos como parte de una botnet orientado a detectar ataques DDoS.
- [**10**Star][5y] [C] [christianpapathanasiou/defcon-18-android-rootkit-mindtrick](https://github.com/christianpapathanasiou/defcon-18-android-rootkit-mindtrick) Worlds first Google Android kernel rootkit as featured at DEF CON 18
- [**10**Star][2m] [Py] [clviper/droidstatx](https://github.com/clviper/droidstatx) Python tool that generates an Xmind map with all the information gathered and any evidence of possible vulnerabilities identified via static analysis. The map itself is an Android Application Pentesting Methodology component, which assists Pentesters to cover all important areas during an assessment.
- [**10**Star][4y] [Java] [cyberscions/digitalbank](https://github.com/cyberscions/digitalbank) Android Digital Bank Vulnerable Mobile App
- [**9**Star][3y] [C++] [android-art-intel/nougat](https://github.com/android-art-intel/nougat) ART-Extension for Android Nougat
- [**9**Star][2y] [Java] [djkovrik/comicser](https://github.com/djkovrik/comicser) Udacity Android Developer Nanodegree - Capstone project.
- [**9**Star][2y] [Java] [optimistanoop/android-developer-nanodegree](https://github.com/optimistanoop/android-developer-nanodegree) This repo contains all 8 Apps developed during Udacity Android Developer Nanodegree. These all Apps met expectation during code review process of Udacity Android Developer Nanodegree.
- [**9**Star][12m] [C#] [preemptive/protected-todoazureauth](https://github.com/preemptive/protected-todoazureauth) Example of protecting a Xamarin.Android app with Dotfuscator’s Root Check
- [**9**Star][1y] [Kotlin] [smartnsoft/android-monero-miner](https://github.com/smartnsoft/android-monero-miner) A minimal SDK that lets an integrator add a Monero Miner using the Javascript miner created by CoinHive. The Monero Miner can be used with any CoinHive address and is a proof of concept of an alternative to ad banners and interstitials for mobile app developers that want to get retributed for their work without spamming their users with bad adve…
- [**8**Star][7y] [Py] [agnivesh/aft](https://github.com/agnivesh/aft) [Deprecated] Android Forensic Toolkit
- [**8**Star][4y] [Java] [appknox/vulnerable-application](https://github.com/appknox/vulnerable-application) Test Android Application.
- [**8**Star][5y] [Shell] [bbqlinux/android-udev-rules](https://github.com/bbqlinux/android-udev-rules) 
- [**8**Star][2y] [JS] [checkmarx/webviewgoat](https://github.com/checkmarx/webviewgoat) A deliberately vulnerable Android application to demonstrate exfiltration scenarios
- [**8**Star][4y] [C] [ele7enxxh/fakeodex](https://github.com/ele7enxxh/fakeodex) modify field(modWhen, crc) in android odex file;安卓APP“寄生兽”漏洞
- [**8**Star][10m] [C] [hcamael/android_kernel_pwn](https://github.com/hcamael/android_kernel_pwn) android kernel pwn
- [**8**Star][6m] [Go] [shosta/androsectest](https://github.com/shosta/androsectest) Automate the setup of your Android Pentest and perform automatically static tests
- [**8**Star][6y] [Java] [fsecurelabs/mwr-tls](https://github.com/FSecureLABS/mwr-tls) A collection of utilities for interacting with SSL and X509 Certificates on Android.
- [**7**Star][5y] [CSS] [dhirajongithub/owasp_kalp_mobile_project](https://github.com/dhirajongithub/owasp_kalp_mobile_project) OWASP KALP Mobile Project is an android application developed for users to view OWASP Top 10 (WEB and MOBILE) on mobile devices.
- [**7**Star][2y] [Py] [sathish09/xender2shell](https://github.com/sathish09/xender2shell) 利用 web.xender.com 入侵用户的 Android 手机
- [**7**Star][1m] [C++] [amrashraf/androshield](https://github.com/amrashraf/androshield) An ASP.NET web application that responsible of detecting and reporting vulnerabilities in android applications by static and dynamic analysis methodologies.
- [**6**Star][2y] [C#] [advancedhacker101/android-c-sharp-rat-server](https://github.com/advancedhacker101/android-c-sharp-rat-server) This is a plugin for the c# R.A.T server providing extension to android based phone systems
- [**6**Star][11m] [as0ler/android-examples](https://github.com/as0ler/android-examples) APK's used as example Apps for decompiling
- [**6**Star][4m] [Py] [h1nayoshi/smalien](https://github.com/h1nayoshi/smalien) Information flow analysis tool for Android applications
- [**6**Star][2y] [Py] [silentsignal/android-param-annotate](https://github.com/silentsignal/android-param-annotate) Android parameter annotator for Dalvik/Smali disassembly
- [**6**Star][3y] [Java] [theblixguy/scanlinks](https://github.com/theblixguy/scanlinks) Block unsafe and dangerous links on your Android device!
- [**5**Star][5y] [vaginessa/pwn-pad-arsenal-tools](https://github.com/vaginessa/pwn-pad-arsenal-tools) Penetration Testing Apps for Android Devices


### <a id="fa49f65b8d3c71b36c6924ce51c2ca0c"></a>HotFix


- [**14478**Star][26d] [Java] [tencent/tinker](https://github.com/tencent/tinker) Tinker is a hot-fix solution library for Android, it supports dex, library and resources update without reinstall apk.
- [**6678**Star][3y] [C++] [alibaba/andfix](https://github.com/alibaba/andfix) AndFix is a library that offer hot-fix for Android App.
- [**3431**Star][13d] [Java] [meituan-dianping/robust](https://github.com/meituan-dianping/robust) Robust is an Android HotFix solution with high compatibility and high stability. Robust can fix bugs immediately without a reboot.
- [**1111**Star][5m] [Java] [manbanggroup/phantom](https://github.com/manbanggroup/phantom)  唯一零 Hook 稳定占坑类 Android 热更新插件化方案


### <a id="ec395c8f974c75963d88a9829af12a90"></a>Package


- [**5028**Star][1m] [Java] [meituan-dianping/walle](https://github.com/meituan-dianping/walle) Android Signature V2 Scheme签名下的新一代渠道包打包神器


### <a id="767078c52aca04c452c095f49ad73956"></a>Collection


- [**1650**Star][2y] [Shell] [juude/droidreverse](https://github.com/juude/droidreverse) reverse engineering tools for android
- [**65**Star][8m] [wufengxue/android-reverse](https://github.com/wufengxue/android-reverse) 安卓逆向工具汇总


### <a id="17408290519e1ca7745233afea62c43c"></a>App


- [**12203**Star][14d] [Java] [signalapp/signal-android](https://github.com/signalapp/Signal-Android) A private messenger for Android.


### <a id="7f353b27e45b5de6b0e6ac472b02cbf1"></a>Xposed


- [**8597**Star][26d] [Java] [android-hacker/virtualxposed](https://github.com/android-hacker/virtualxposed) A simple app to use Xposed without root, unlock the bootloader or modify system image, etc.
- [**2470**Star][6m] [taichi-framework/taichi](https://github.com/taichi-framework/taichi) A framework to use Xposed module with or without Root/Unlock bootloader, supportting Android 5.0 ~ 10.0
- [**1963**Star][27d] [Java] [elderdrivers/edxposed](https://github.com/elderdrivers/edxposed) Elder driver Xposed Framework.
- [**1702**Star][1y] [Java] [ac-pm/inspeckage](https://github.com/ac-pm/inspeckage) Android Package Inspector - dynamic analysis with api hooks, start unexported activities and more. (Xposed Module)
- [**1593**Star][26d] [Java] [tiann/epic](https://github.com/tiann/epic) Dynamic java method AOP hook for Android(continution of Dexposed on ART), Supporting 4.0~10.0
- [**1485**Star][2y] [Kotlin] [gh0u1l5/wechatmagician](https://github.com/gh0u1l5/wechatmagician) WechatMagician is a Xposed module written in Kotlin, that allows you to completely control your Wechat.
- [**1291**Star][27d] [Java] [android-hacker/exposed](https://github.com/android-hacker/exposed) A library to use Xposed without root or recovery(or modify system image etc..).
- [**823**Star][5y] [halfkiss/zjdroid](https://github.com/halfkiss/zjdroid) Android app dynamic reverse tool based on Xposed framework.
- [**782**Star][7m] [Java] [blankeer/mdwechat](https://github.com/blankeer/mdwechat) 一个能让微信 Material Design 化的 Xposed 模块
- [**633**Star][21d] [Java] [ganyao114/sandhook](https://github.com/ganyao114/sandhook) Android ART Hook/Native Inline Hook/Single Instruction Hook - support 4.4 - 10.0 32/64 bit - Xposed API Compat
- [**475**Star][2m] [Java] [tornaco/x-apm](https://github.com/tornaco/x-apm) 应用管理 Xposed
- [**423**Star][3y] [Makefile] [mindmac/androideagleeye](https://github.com/mindmac/androideagleeye) An Xposed and adbi based module which is capable of hooking both Java and Native methods targeting Android OS.
- [**321**Star][1y] [C] [smartdone/dexdump](https://github.com/smartdone/dexdump) 快速脱一代壳的xposed插件
- [**302**Star][12d] [bigsinger/androididchanger](https://github.com/bigsinger/androididchanger) Xposed Module for Changing Android Device Info
- [**289**Star][14d] [Java] [ganyao114/sandvxposed](https://github.com/ganyao114/sandvxposed) Xposed environment without root (OS 5.0 - 10.0)
- [**279**Star][2y] [C++] [rovo89/android_art](https://github.com/rovo89/android_art) Android ART with modifications for the Xposed framework.
- [**213**Star][1y] [Kotlin] [paphonb/androidp-ify](https://github.com/paphonb/androidp-ify) [Xposed] Use features introduced in Android P on your O+ Device!
- [**201**Star][1y] [C] [gtoad/android_inline_hook](https://github.com/gtoad/android_inline_hook) Build an so file to automatically do the android_native_hook work. Supports thumb-2/arm32 and ARM64 ! With this, tools like Xposed can do android native hook.
- [**127**Star][1y] [Java] [bmax121/budhook](https://github.com/bmax121/budhook) An Android hook framework written like Xposed,based on YAHFA.
- [**121**Star][3y] [Java] [rastapasta/pokemon-go-xposed](https://github.com/rastapasta/pokemon-go-xposed) 
- [**79**Star][3m] [Go] [tillson/git-hound](https://github.com/tillson/git-hound) GitHound pinpoints exposed API keys on GitHub using pattern matching, commit history searching, and a unique result scoring system. A batch-catching, pattern-matching, patch-attacking secret snatcher.
- [**66**Star][13d] [Java] [lianglixin/sandvxposed](https://github.com/lianglixin/sandvxposed) Xposed environment without root (OS 5.0 - 10.0)
- [**63**Star][9m] [FreeMarker] [dvdandroid/xposedmoduletemplate](https://github.com/dvdandroid/xposedmoduletemplate) Easily create a Xposed Module with Android Studio
- [**54**Star][3m] [uniking/dingding](https://github.com/uniking/dingding) 免root远程钉钉打卡，支持wifi和gps定位，仅支持android系统。本项目出于学习目的，仅用于学习玩耍,请于24小时后自行删除。xposed, crack,package,dingtalk,remote control
- [**49**Star][10m] [Py] [hrkfdn/deckard](https://github.com/hrkfdn/deckard) Deckard performs static and dynamic binary analysis on Android APKs to extract Xposed hooks
- [**37**Star][10m] [Java] [egguncle/xposednavigationbar](https://github.com/egguncle/xposednavigationbar) Xposed导航栏功能拓展模块
- [**36**Star][7m] [Py] [anantshri/ds_store_crawler_parser](https://github.com/anantshri/ds_store_crawler_parser) a parser + crawler for .DS_Store files exposed publically
- [**34**Star][5y] [Java] [wooyundota/intentmonitor](https://github.com/wooyundota/intentmonitor) Tool based xposed can monitor the android intents
- [**28**Star][5y] [Java] [mindmac/xposedautomation](https://github.com/mindmac/xposedautomation) A demo to show how to install Xposed and enable Xposed based module automatically
- [**26**Star][5y] [Java] [twilightgod/malwarebuster](https://github.com/twilightgod/malwarebuster) This is a Xposed module. It helps to prevent malwares to register service/receiver which were disabled in My Android Tools before.


### <a id="50f63dce18786069de2ec637630ff167"></a>Pack&&Unpack


- [**1757**Star][7m] [C++] [wrbug/dumpdex](https://github.com/wrbug/dumpdex) Android unpack
- [**1607**Star][3y] [Makefile] [drizzlerisk/drizzledumper](https://github.com/drizzlerisk/drizzledumper) a memory-search-based Android unpack tool.
- [**1438**Star][3m] [C++] [vaibhavpandeyvpz/apkstudio](https://github.com/vaibhavpandeyvpz/apkstudio) Open-source, cross platform Qt based IDE for reverse-engineering Android application packages.
- [**1028**Star][3y] [C++] [zyq8709/dexhunter](https://github.com/zyq8709/dexhunter) General Automatic Unpacking Tool for Android Dex Files
- [**807**Star][3m] [C] [strazzere/android-unpacker](https://github.com/strazzere/android-unpacker) Android Unpacker presented at Defcon 22: Android Hacker Protection Level 0
- [**691**Star][1m] [YARA] [rednaga/apkid](https://github.com/rednaga/apkid) Android Application Identifier for Packers, Protectors, Obfuscators and Oddities - PEiD for Android
- [**356**Star][2m] [Java] [patrickfav/uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) A cli tool that helps signing and zip aligning single or multiple Android application packages (APKs) with either debug or provided release certificates. It supports v1, v2 and v3 Android signing scheme has an embedded debug keystore and auto verifies after signing.
- [**313**Star][5m] [Shell] [1n3/reverseapk](https://github.com/1n3/reverseapk) Quickly analyze and reverse engineer Android packages
- [**295**Star][2y] [Shell] [checkpointsw/android_unpacker](https://github.com/checkpointsw/android_unpacker) A (hopefully) generic unpacker for packed Android apps.
- [**187**Star][3y] [Py] [drizzlerisk/tunpacker](https://github.com/drizzlerisk/tunpacker) TUnpacker是一款Android脱壳工具
- [**185**Star][3y] [Py] [andy10101/apkdetecter](https://github.com/andy10101/apkdetecter) Android Apk查壳工具及源代码
- [**147**Star][3y] [Py] [drizzlerisk/bunpacker](https://github.com/drizzlerisk/bunpacker) BUnpacker是一款Android脱壳工具
- [**104**Star][3y] [Java] [cvvt/apptroy](https://github.com/cvvt/apptroy) An Online Analysis System for Packed Android Malware
- [**102**Star][3y] [Java] [liuyufei/sslkiller](https://github.com/liuyufei/sslkiller) SSLKiller is used for killing SSL verification functions on Android client side. With SSLKiller, You can intercept app's HTTPS communication packages between the client and server.
- [**89**Star][2y] [Objective-C] [wooyundota/dumpdex](https://github.com/wooyundota/dumpdex) Android Unpack tool based on Cydia
- [**66**Star][5y] [Py] [ajinabraham/xenotix-apk-reverser](https://github.com/ajinabraham/xenotix-apk-reverser) Xenotix APK Reverser is an OpenSource Android Application Package (APK) decompiler and disassembler powered by dex2jar, baksmali and jd-core.
- [**29**Star][7m] [Java] [cristianturetta/mad-spy](https://github.com/cristianturetta/mad-spy) We developed a malware for educational purposes. In particular, our goal is to provide a PoC of what is known as a Repacking attack, a known technique widely used by malware cybercrooks to trojanize android apps. The answer to solve this particular goal boils down in the simplicity of APK decompiling and smali code injection.
- [**21**Star][4m] [Py] [botherder/snoopdroid](https://github.com/botherder/snoopdroid) Extract packages from an Android device
- [**10**Star][2y] [Shell] [nickdiego/docker-ollvm](https://github.com/nickdiego/docker-ollvm) Easily build and package Obfuscator-LLVM into Android NDK.


### <a id="596b6cf8fd36bc4c819335f12850a915"></a>HOOK


- [**1468**Star][3m] [C] [iqiyi/xhook](https://github.com/iqiyi/xhook) a PLT (Procedure Linkage Table) hook library for Android native ELF 
- [**1466**Star][2m] [C++] [jmpews/hookzz](https://github.com/jmpews/hookzz) a hook framework for arm/arm64/ios/android, and [dev] branch is being refactored.
- [**795**Star][7m] [C++] [aslody/whale](https://github.com/aslody/whale) Hook Framework for Android/IOS/Linux/MacOS
- [**524**Star][6m] [Java] [aslody/andhook](https://github.com/asLody/AndHook) Android dynamic instrumentation framework
- [**399**Star][2y] [Java] [pqpo/inputmethodholder](https://github.com/pqpo/inputmethodholder) A keyboard listener for Android which by hooking the InputMethodManager. 通过hook监听系统键盘显示
- [**344**Star][7m] [C] [turing-technician/fasthook](https://github.com/turing-technician/fasthook) Android ART Hook
- [**216**Star][3y] [Java] [zhengmin1989/wechatsportcheat](https://github.com/zhengmin1989/wechatsportcheat) 手把手教你当微信运动第一名 – 利用Android Hook进行微信运动作弊
- [**189**Star][4y] [C++] [aslody/elfhook](https://github.com/aslody/elfhook) modify PLT to hook api, supported android 5\6.
- [**115**Star][9m] [Java] [turing-technician/virtualfasthook](https://github.com/turing-technician/virtualfasthook) Android application hooking tool based on FastHook + VirtualApp
- [**58**Star][2y] [Java] [nightoftwelve/virtualhookex](https://github.com/nightoftwelve/virtualhookex) Android application hooking tool based on VirtualHook/VirtualApp
- [**54**Star][3y] [Rust] [nccgroup/assethook](https://github.com/nccgroup/assethook) LD_PRELOAD magic for Android's AssetManager
- [**35**Star][1m] [C++] [chickenhook/chickenhook](https://github.com/chickenhook/chickenhook) A linux / android hooking framework


### <a id="5afa336e229e4c38ad378644c484734a"></a>Emulator


- [**1474**Star][1y] [C++] [f1xpl/openauto](https://github.com/f1xpl/openauto) AndroidAuto headunit emulator
- [**518**Star][7m] [Java] [limboemu/limbo](https://github.com/limboemu/limbo) Limbo is a QEMU-based emulator for Android. It currently supports PC & ARM emulation for Intel x86 and ARM architecture. See our wiki
    - Also In Section: [VM->QEMU->Tools->RecentAdd](#82072558d99a6cf23d4014c0ae5b420a) |
- [**466**Star][3m] [Java] [strazzere/anti-emulator](https://github.com/strazzere/anti-emulator) Android Anti-Emulator
- [**426**Star][1y] [Py] [evilsocket/smali_emulator](https://github.com/evilsocket/smali_emulator) This software will emulate a smali source file generated by apktool.
- [**202**Star][3y] [Py] [mseclab/nathan](https://github.com/mseclab/nathan) Android Emulator for mobile security testing
- [**168**Star][11m] [Py] [mnkgrover08-zz/whatsapp_automation](https://github.com/mnkgrover08-zz/whatsapp_automation) Whatsapp Automation is a collection of APIs that interact with WhatsApp messenger running in an Android emulator, allowing developers to build projects that automate sending and receiving messages, adding new contacts and broadcasting messages multiple contacts.
- [**147**Star][5y] [C] [strazzere/android-lkms](https://github.com/strazzere/android-lkms) Android Loadable Kernel Modules - mostly used for reversing and debugging on controlled systems/emulators
- [**27**Star][2y] [Shell] [gustavosotnas/avd-launcher](https://github.com/gustavosotnas/avd-launcher) Front-end to Android Virtual Devices (AVDs) emulator from Google.
- [**16**Star][1y] [Py] [abhi-r3v0/droxes](https://github.com/abhi-r3v0/droxes) A simple script to turn an Android device/emulator into a test-ready box.


### <a id="0a668d220ce74e11ed2738c4e3ae3c9e"></a>IDA


- [**158**Star][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->SpecificTarget->Loader](#cb59d84840e41330a7b5e275c0b81725) |
- [**116**Star][4y] [Py] [cvvt/dumpdex](https://github.com/cvvt/dumpdex) IDA python script to dynamically dump DEX in memory
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |
- [**79**Star][2y] [Py] [zhkl0228/androidattacher](https://github.com/zhkl0228/androidattacher) IDA debugging plugin for android armv7 so
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |
- [**39**Star][5y] [Py] [techbliss/adb_helper_qt_super_version](https://github.com/techbliss/adb_helper_qt_super_version) All You Need For Ida Pro And Android Debugging
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |
- [**38**Star][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) some idapython scripts for android debugging.
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->Tools->Debug->NoCategory](#2944dda5289f494e5e636089db0d6a6a) |
- [**16**Star][7y] [C++] [strazzere/dalvik-header-plugin](https://github.com/strazzere/dalvik-header-plugin) Dalvik Header Plugin for IDA Pro
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |


### <a id="bb9f8e636857320abf0502c19af6c763"></a>Debug


- [**10738**Star][17d] [Java] [konloch/bytecode-viewer](https://github.com/konloch/bytecode-viewer) A Java 8+ Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More)
- [**6708**Star][9m] [Java] [amitshekhariitbhu/android-debug-database](https://github.com/amitshekhariitbhu/android-debug-database) A library for debugging android databases and shared preferences - Make Debugging Great Again
- [**522**Star][5y] [Py] [swdunlop/andbug](https://github.com/swdunlop/andbug) Android Debugging Library
- [**466**Star][7y] [Shell] [kosborn/p2p-adb](https://github.com/kosborn/p2p-adb) Phone to Phone Android Debug Bridge - A project for "debugging" phones... from other phones.
- [**123**Star][3y] [C++] [cheetahsec/avmdbg](https://github.com/cheetahsec/avmdbg) a lightweight debugger for android virtual machine.
- [**106**Star][6y] [Java] [isecpartners/android-opendebug](https://github.com/isecpartners/android-opendebug) Make any application debuggable
- [**97**Star][3y] [Py] [cx9527/strongdb](https://github.com/cx9527/strongdb) gdb plugin for android debugging
- [**65**Star][6y] [Py] [anbc/andbug](https://github.com/anbc/andbug) Android Debugging Library
- [**56**Star][3y] [C] [gnaixx/anti-debug](https://github.com/gnaixx/anti-debug) Android detect debugger
- [**55**Star][4m] [Shell] [wuseman/wbruter](https://github.com/wuseman/wbruter) Crack your non-rooted android device pin code with 100% guarantee aslong as usb debugging has been enable. Wbruter also has support for parallel ssh brute forcing via pssh
- [**21**Star][12m] [C++] [gtoad/android_anti_debug](https://github.com/gtoad/android_anti_debug) An example of android anti-debug.


### <a id="f975a85510f714ec3cc2551e868e75b8"></a>Malware


- [**422**Star][4m] [Shell] [ashishb/android-malware](https://github.com/ashishb/android-malware) Collection of android malware samples
- [**347**Star][2m] [Java] [droidefense/engine](https://github.com/droidefense/engine) Droidefense: Advance Android Malware Analysis Framework
- [**191**Star][4y] [HTML] [faber03/androidmalwareevaluatingtools](https://github.com/faber03/androidmalwareevaluatingtools) Evaluation tools for malware Android
- [**124**Star][2y] [Java] [brompwnie/uitkyk](https://github.com/brompwnie/uitkyk) Android Frida库, 用于分析App查找恶意行为
    - Also In Section: [DBI->Frida->Tools->RecentAdd](#54836a155de0c15b56f43634cd9cfecf) |
- [**116**Star][7y] [C] [secmobi/amatutor](https://github.com/secmobi/amatutor) Android恶意代码分析教程
- [**96**Star][2y] [Lua] [niallmcl/deep-android-malware-detection](https://github.com/niallmcl/deep-android-malware-detection) Code for Deep Android Malware Detection paper
- [**82**Star][5y] [Py] [maldroid/maldrolyzer](https://github.com/maldroid/maldrolyzer) Simple framework to extract "actionable" data from Android malware (C&Cs, phone numbers etc.)
- [**67**Star][10m] [dkhuuthe/madlira](https://github.com/dkhuuthe/madlira) Malware detection using learning and information retrieval for Android
- [**65**Star][3y] [C++] [soarlab/maline](https://github.com/soarlab/maline) Android Malware Detection Framework
- [**64**Star][1y] [Py] [mwleeds/android-malware-analysis](https://github.com/mwleeds/android-malware-analysis) This project seeks to apply machine learning algorithms to Android malware classification.
- [**59**Star][5m] [Py] [hgascon/adagio](https://github.com/hgascon/adagio) Structural Analysis and Detection of Android Malware
- [**49**Star][2y] [java] [toufikairane/andromalware](https://github.com/tfairane/andromalware) Android Malware for educational purpose
- [**47**Star][2y] [HTML] [mburakergenc/malware-detection-using-machine-learning](https://github.com/mburakergenc/malware-detection-using-machine-learning) Malware detection project on Android devices using machine learning classification algorithms.
- [**45**Star][1y] [Py] [maoqyhz/droidcc](https://github.com/maoqyhz/droidcc) Android malware detection using deep learning, contains android malware samples, papers, tools etc.
- [**40**Star][1y] [Java] [miwong/intellidroid](https://github.com/miwong/intellidroid) A targeted input generator for Android that improves the effectiveness of dynamic malware analysis.
- [**40**Star][1y] [traceflight/android-malware-datasets](https://github.com/traceflight/android-malware-datasets) Popular Android malware datasets
- [**32**Star][5y] [Shell] [vt-magnum-research/antimalware](https://github.com/vt-magnum-research/antimalware) Dynamic malware analysis for the Android platform
- [**29**Star][2y] [virqdroid/android_malware](https://github.com/virqdroid/android_malware) 
- [**27**Star][3y] [fouroctets/android-malware-samples](https://github.com/fouroctets/android-malware-samples) Android Malware Samples
- [**24**Star][3y] [Py] [bunseokbot/androtools](https://github.com/bunseokbot/androtools) Android malware static & dynamic analysis and automated action (deprecated)
- [**19**Star][2y] [Py] [namk12/malware-detection](https://github.com/namk12/malware-detection) Deep Learning Based Android Malware Detection Framework
- [**15**Star][3y] [Java] [darrylburke/androidmalwareexample](https://github.com/darrylburke/androidmalwareexample) Proof of Concept example of Android Malware used for Research Purposes
- [**13**Star][5y] [JS] [cheverebe/android-malware](https://github.com/cheverebe/android-malware) Injected malicious code into legitimate andoid applications. Converted a keyboard app into a keylogger and an MP3 downloader into an image thief.
- [**13**Star][5m] [HTML] [fmind/euphony](https://github.com/fmind/euphony) Harmonious Unification of Cacophonous Anti-Virus Vendor Labels for Android Malware
- [**12**Star][8m] [Py] [vinayakumarr/android-malware-detection](https://github.com/vinayakumarr/android-malware-detection) Android malware detection using static and dynamic analysis
- [**11**Star][2m] [Py] [jacobsoo/amtracker](https://github.com/jacobsoo/amtracker) Android Malware Tracker
- [**11**Star][2y] [Py] [tlatkdgus1/android-malware-analysis-system](https://github.com/tlatkdgus1/android-malware-analysis-system) Android Malware Detection based on Deep Learning
- [**9**Star][4y] [Java] [acprimer/malwaredetector](https://github.com/acprimer/malwaredetector) android malwarre detector
- [**9**Star][2y] [Py] [mldroid/csbd](https://github.com/mldroid/csbd) The repository contains the python implementation of the Android Malware Detection paper: "Empirical assessment of machine learning-based malware detectors for Android: Measuring the Gap between In-the-Lab and In-the-Wild Validation Scenarios"
- [**7**Star][3y] [Java] [waallen/http-sms-android-malware](https://github.com/waallen/http-sms-android-malware) HTTP and SMS spam testing application
- [**6**Star][7y] [Java] [ssesha/malwarescanner](https://github.com/ssesha/malwarescanner) Android app performing hash based malware detection
- [**6**Star][3y] [Py] [tuomao/android_malware_detection](https://github.com/tuomao/android_malware_detection) 
- [**6**Star][8y] [Java] [twitter-university/antimalware](https://github.com/twitter-university/antimalware) An Android Eclipse project demonstrating how to build a simple anti-malware application
- [**6**Star][1y] [Py] [aliemamalinezhad/machine-learning](https://github.com/aliemamalinezhad/machine-learning) android-malware-classification using machine learning algorithms


### <a id="1d83ca6d8b02950be10ac8e4b8a2d976"></a>Obfuscate


- [**3059**Star][1m] [Java] [calebfenton/simplify](https://github.com/calebfenton/simplify) Generic Android Deobfuscator
- [**290**Star][4m] [C] [shadowsocks/simple-obfs-android](https://github.com/shadowsocks/simple-obfs-android) A simple obfuscating tool for Android
- [**76**Star][4y] [Java] [enovella/jebscripts](https://github.com/enovella/jebscripts) A set of JEB Python/Java scripts for reverse engineering Android obfuscated code
- [**11**Star][1y] [Java] [miwong/tiro](https://github.com/miwong/tiro) TIRO - A hybrid iterative deobfuscation framework for Android applications
- [**10**Star][14d] [Py] [omirzaei/androdet](https://github.com/omirzaei/androdet) AndrODet: An Adaptive Android Obfuscation Detector


### <a id="6d2b758b3269bac7d69a2d2c8b45194c"></a>ReverseEngineering


- [**9178**Star][10d] [Java] [ibotpeaches/apktool](https://github.com/ibotpeaches/apktool) A tool for reverse engineering Android apk files
- [**1967**Star][26d] [Java] [genymobile/gnirehtet](https://github.com/genymobile/gnirehtet) Gnirehtet provides reverse tethering for Android
- [**577**Star][2m] [C++] [secrary/andromeda](https://github.com/secrary/andromeda) Andromeda - Interactive Reverse Engineering Tool for Android Applications
- [**542**Star][3y] [Java] [linchaolong/apktoolplus](https://github.com/linchaolong/apktoolplus) apk analysis tool
- [**437**Star][7m] [maddiestone/androidappre](https://github.com/maddiestone/androidappre) Android App Reverse Engineering Workshop
- [**331**Star][7y] [Java] [brutall/brut.apktool](https://github.com/brutall/brut.apktool) A tool for reverse engineering Android apk files
- [**265**Star][9m] [Dockerfile] [cryptax/androidre](https://github.com/cryptax/androidre) Reverse engineering Android
- [**244**Star][7d] [C++] [strazzere/android-scripts](https://github.com/strazzere/android-scripts) Collection of Android reverse engineering scripts
    - Also In Section: [IDA->Tools->Android](#66052f824f5054aa0f70785a2389a478) |
- [**102**Star][3y] [feicong/android-app-sec](https://github.com/feicong/android-app-sec) ISC 2016安全训练营－安卓app逆向与安全防护 ppt
- [**54**Star][9y] [Emacs Lisp] [nelhage/reverse-android](https://github.com/nelhage/reverse-android) Reverse-engineering tools for Android applications
- [**50**Star][5m] [Smali] [hellohudi/androidreversenotes](https://github.com/hellohudi/androidreversenotes) Android逆向笔记---从入门到入土
- [**28**Star][3y] [nextco/android-decompiler](https://github.com/nextco/android-decompiler) A hight quality list of tools to reverse engineering code from android.
- [**14**Star][2m] [Smali] [freedom-wy/reverse_android](https://github.com/freedom-wy/reverse_android) 安卓从开发到逆向
- [**9**Star][2y] [Smali] [yifengyou/android-software-security-and-reverse-analysis](https://github.com/yifengyou/android-software-security-and-reverse-analysis) Android软件安全与逆向分析
- [**6**Star][2y] [CSS] [oscar0812/apktoolfx](https://github.com/oscar0812/apktoolfx) A GUI for Apktool to make reverse engineering of android apps a breeze.




***


## <a id="f0493b259e1169b5ddd269b13cfd30e6"></a>Posts&&Videos


- 2019.12 [aliyun_xz] [Android智能终端系统的安全加固（上）](https://xz.aliyun.com/t/6852)
- 2019.11 [venus_seebug] [Android勒索病毒分析（上）](https://paper.seebug.org/1085/)


# <a id="069664f347ae73b1370c4f5a2ec9da9f"></a>Apple&&iOS&&iXxx


***


## <a id="58cd9084afafd3cd293564c1d615dd7f"></a>Tools


### <a id="d0108e91e6863289f89084ff09df39d0"></a>RecentAdd


- [**11013**Star][2y] [Objective-C] [bang590/jspatch](https://github.com/bang590/jspatch) JSPatch bridge Objective-C and Javascript using the Objective-C runtime. You can call any Objective-C class and method in JavaScript by just including a small engine. JSPatch is generally used to hotfix iOS App.
- [**10902**Star][12d] [Objective-C] [flipboard/flex](https://github.com/flipboard/flex) An in-app debugging and exploration tool for iOS
- [**7992**Star][2m] [Py] [facebook/chisel](https://github.com/facebook/chisel) Chisel is a collection of LLDB commands to assist debugging iOS apps.
- [**5764**Star][3m] [Objective-C] [square/ponydebugger](https://github.com/square/ponydebugger) Remote network and data debugging for your native iOS app using Chrome Developer Tools
- [**4627**Star][16d] [C] [google/ios-webkit-debug-proxy](https://github.com/google/ios-webkit-debug-proxy) A DevTools proxy (Chrome Remote Debugging Protocol) for iOS devices (Safari Remote Web Inspector).
- [**4343**Star][13d] [Swift] [signalapp/signal-ios](https://github.com/signalapp/Signal-iOS) A private messenger for iOS.
- [**3653**Star][4m] [C] [facebook/fishhook](https://github.com/facebook/fishhook) A library that enables dynamically rebinding symbols in Mach-O binaries running on iOS.
- [**3280**Star][2m] [Swift] [yagiz/bagel](https://github.com/yagiz/bagel) a little native network debugging tool for iOS
- [**3202**Star][4m] [Objective-C] [naituw/ipapatch](https://github.com/naituw/ipapatch) Patch iOS Apps, The Easy Way, Without Jailbreak.
- [**2838**Star][12d] [Objective-C] [facebook/idb](https://github.com/facebook/idb) idb is a flexible command line interface for automating iOS simulators and devices
- [**2731**Star][22d] [Makefile] [theos/theos](https://github.com/theos/theos) A cross-platform suite of tools for building and deploying software for iOS and other platforms.
- [**2683**Star][4m] [Objective-C] [dantheman827/ios-app-signer](https://github.com/dantheman827/ios-app-signer) This is an app for OS X that can (re)sign apps and bundle them into ipa files that are ready to be installed on an iOS device.
- [**2681**Star][1m] [Objective-C] [kjcracks/clutch](https://github.com/kjcracks/clutch) Fast iOS executable dumper
- [**2020**Star][20d] [Objective-C] [ios-control/ios-deploy](https://github.com/ios-control/ios-deploy) Install and debug iPhone apps from the command line, without using Xcode
- [**2016**Star][3y] [Swift] [urinx/iosapphook](https://github.com/urinx/iosapphook) 专注于非越狱环境下iOS应用逆向研究，从dylib注入，应用重签名到App Hook
- [**1774**Star][1y] [aozhimin/ios-monitor-platform](https://github.com/aozhimin/ios-monitor-platform) 
- [**1676**Star][28d] [Swift] [pmusolino/wormholy](https://github.com/pmusolino/wormholy) iOS network debugging, like a wizard 🧙‍♂️
- [**1574**Star][22d] [ivrodriguezca/re-ios-apps](https://github.com/ivrodriguezca/re-ios-apps) A completely free, open source and online course about Reverse Engineering iOS Applications.
- [**1419**Star][5y] [C++] [gdbinit/machoview](https://github.com/gdbinit/machoview) MachOView fork
- [**1239**Star][2m] [michalmalik/osx-re-101](https://github.com/michalmalik/osx-re-101) A collection of resources for OSX/iOS reverse engineering.
- [**1191**Star][6y] [gdbinit/gdbinit](https://github.com/gdbinit/gdbinit) Gdbinit for OS X, iOS and others - x86, x86_64 and ARM
- [**1024**Star][2y] [Objective-C] [zhengmin1989/ios_ice_and_fire](https://github.com/zhengmin1989/ios_ice_and_fire) iOS冰与火之歌
- [**996**Star][2m] [Objective-C] [lmirosevic/gbdeviceinfo](https://github.com/lmirosevic/gbdeviceinfo) Detects the hardware, software and display of the current iOS or Mac OS X device at runtime.
- [**835**Star][1y] [Shell] [kpwn/iosre](https://github.com/kpwn/iosre) iOS Reverse Engineering
- [**815**Star][7d] [JS] [cypress-io/cypress-example-recipes](https://github.com/cypress-io/cypress-example-recipes) Various recipes for testing common scenarios with Cypress
- [**766**Star][12d] [Shell] [aqzt/kjyw](https://github.com/aqzt/kjyw) 快捷运维，代号kjyw，项目基于shell、python，运维脚本工具库，收集各类运维常用工具脚本，实现快速安装nginx、mysql、php、redis、nagios、运维经常使用的脚本等等...
- [**647**Star][3y] [Objective-C] [isecpartners/introspy-ios](https://github.com/isecpartners/introspy-ios) Security profiling for blackbox iOS
- [**634**Star][1y] [Swift] [phynet/ios-url-schemes](https://github.com/phynet/ios-url-schemes) a github solution from my gist of iOS list for urls schemes
- [**514**Star][5y] [Py] [project-imas/mdm-server](https://github.com/project-imas/mdm-server) Sample iOS MDM server
- [**498**Star][25d] [Swift] [google/science-journal-ios](https://github.com/google/science-journal-ios) Use the sensors in your mobile devices to perform science experiments. Science doesn’t just happen in the classroom or lab—tools like Science Journal let you see how the world works with just your phone.
- [**468**Star][8m] [C++] [everettjf/machoexplorer](https://github.com/everettjf/machoexplorer) [WIP] Explore MachO File on macOS and Windows
- [**466**Star][24d] [pixelcyber/thor](https://github.com/pixelcyber/thor) HTTP Sniffer/Capture on iOS for Network Debug & Inspect.
- [**430**Star][11m] [captainarash/the_holy_book_of_x86](https://github.com/captainarash/the_holy_book_of_x86) A simple guide to x86 architecture, assembly, memory management, paging, segmentation, SMM, BIOS....
- [**405**Star][5y] [Objective-C] [mp0w/ios-headers](https://github.com/mp0w/ios-headers) iOS 5.0/5.1/6.0/6.1/7.0/7.1/8.0/8.1 Headers of All Frameworks (private and not) + SpringBoard
- [**380**Star][11m] [C] [coolstar/electra1131](https://github.com/coolstar/electra1131) Electra for iOS 11.0 - 11.3.1
- [**377**Star][2y] [Objective-C] [codermjlee/mjapptools](https://github.com/codermjlee/mjapptools) 【越狱-逆向】处理iOS APP信息的命令行工具
- [**375**Star][6y] [C] [heardrwt/revealloader](https://github.com/heardrwt/revealloader) Reveal Loader dynamically loads libReveal.dylib (Reveal.app support) into iOS apps on jailbroken devices.
- [**369**Star][1y] [C++] [alonemonkey/iosrebook](https://github.com/alonemonkey/iosrebook) 《iOS应用逆向与安全》随书源码
- [**337**Star][2m] [C] [trailofbits/cb-multios](https://github.com/trailofbits/cb-multios) DARPA Challenges Sets for Linux, Windows, and macOS
- [**332**Star][3y] [Logos] [bishopfox/ispy](https://github.com/bishopfox/ispy) A reverse engineering framework for iOS
- [**305**Star][7d] [Swift] [securing/iossecuritysuite](https://github.com/securing/iossecuritysuite) iOS platform security & anti-tampering Swift library
- [**291**Star][4y] [Perl] [bishopfox/theos-jailed](https://github.com/bishopfox/theos-jailed) A version of Theos/CydiaSubstrate for non-jailbroken iOS devices
- [**284**Star][2y] [Swift] [krausefx/watch.user](https://github.com/krausefx/watch.user) Every iOS app you ever gave permission to use your camera can record you any time it runs - without notice
- [**244**Star][18d] [C++] [s0uthwest/futurerestore](https://github.com/s0uthwest/futurerestore) iOS upgrade and downgrade tool utilizing SHSH blobs
- [**241**Star][4y] [C++] [meeloo/xspray](https://github.com/meeloo/xspray) A front end for lldb on OS X for Mac and iOS targets, with a twist
- [**238**Star][6m] [JS] [we11cheng/wcshadowrocket](https://github.com/we11cheng/wcshadowrocket) iOS Shadowrocket(砸壳重签,仅供参考,添加节点存在问题)。另一个fq项目potatso源码参见:
- [**231**Star][3m] [Swift] [shadowsocksr-live/ishadowsocksr](https://github.com/shadowsocksr-live/ishadowsocksr) ShadowsocksR for iOS, come from
- [**227**Star][3y] [Swift] [trailofbits/secureenclavecrypto](https://github.com/trailofbits/secureenclavecrypto) Demonstration library for using the Secure Enclave on iOS
- [**198**Star][1y] [Objective-C] [sunweiliang/neteasemusiccrack](https://github.com/sunweiliang/neteasemusiccrack) iOS网易云音乐 免VIP下载、去广告、去更新 无需越狱...
- [**198**Star][12d] [Swift] [auth0/lock.swift](https://github.com/auth0/Lock.swift) A Swift & iOS framework to authenticate using Auth0 and with a Native Look & Feel
- [**197**Star][2y] [proteas/native-lldb-for-ios](https://github.com/proteas/native-lldb-for-ios) native LLDB(v3.8) for iOS
- [**196**Star][4m] [Py] [googleprojectzero/ios-messaging-tools](https://github.com/googleprojectzero/ios-messaging-tools) several tools Project Zero uses to test iPhone messaging
- [**179**Star][4y] [Objective-C] [iosre/hippocamphairsalon](https://github.com/iosre/hippocamphairsalon) A simple universal memory editor (game trainer) on OSX/iOS
- [**176**Star][20d] [JS] [nowsecure/node-applesign](https://github.com/nowsecure/node-applesign) NodeJS module and commandline utility for re-signing iOS applications (IPA files).
- [**176**Star][11m] [zekesnider/nintendoswitchrestapi](https://github.com/zekesnider/nintendoswitchrestapi) Reverse engineered REST API used in the Nintendo Switch app for iOS. Includes documentation on Splatoon 2's API.
- [**172**Star][1y] [C++] [samyk/frisky](https://github.com/samyk/frisky) Instruments to assist in binary application reversing and augmentation, geared towards walled gardens like iOS and macOS
- [**166**Star][7m] [proteas/unstripped-ios-kernels](https://github.com/proteas/unstripped-ios-kernels) Unstripped iOS Kernels
- [**165**Star][2y] [C++] [google/pawn](https://github.com/google/pawn) 从基于 Intel 的工作站和笔记本电脑中提取 BIOS 固件
- [**162**Star][2y] [C++] [encounter/futurerestore](https://github.com/encounter/futurerestore) (unmaintained) iOS upgrade and downgrade tool utilizing SHSH blobs (unofficial fork supporting iOS 11 and newer devices)
- [**162**Star][6y] [C] [gdbinit/readmem](https://github.com/gdbinit/readmem) A small OS X/iOS userland util to dump processes memory
- [**159**Star][2m] [smilezxlee/crackediosapps](https://github.com/smilezxlee/crackediosapps) iOS端破解版App集合，包含破解版QQ、破解版抖音、破解版百度网盘、破解版麻花、钉钉打卡助手、破解版墨墨背单词、破解版网易云音乐、破解版芒果TV
- [**158**Star][8m] [C] [tboox/itrace](https://github.com/tboox/itrace) Trace objc method call for ios and mac
- [**154**Star][4m] [mac4n6/presentations](https://github.com/mac4n6/presentations) Presentation Archives for my macOS and iOS Related Research
- [**152**Star][7y] [Py] [intrepidusgroup/imdmtools](https://github.com/intrepidusgroup/imdmtools) Intrepidus Group's iOS MDM tools
- [**144**Star][3y] [Py] [biosbits/bits](https://github.com/biosbits/bits) BIOS Implementation Test Suite
- [**143**Star][2y] [C] [rodionovd/liblorgnette](https://github.com/rodionovd/liblorgnette) Interprocess dlsym() for OS X & iOS
- [**142**Star][9m] [Py] [dlcowen/fseventsparser](https://github.com/dlcowen/fseventsparser) Parser for OSX/iOS FSEvents Logs
- [**137**Star][7m] [C++] [macmade/dyld_cache_extract](https://github.com/macmade/dyld_cache_extract) A macOS utility to extract dynamic libraries from the dyld_shared_cache of macOS and iOS.
- [**130**Star][3m] [Py] [apperian/ios-checkipa](https://github.com/apperian/ios-checkipa) Scans an IPA file and parses its Info.plist and embedded.mobileprovision files. Performs checks of expected key/value relationships and displays the results.
- [**129**Star][4y] [Go] [benjojo/dos_ssh](https://github.com/benjojo/dos_ssh) Use BIOS ram hacks to make a SSH server out of any INT 10 13h app (MS-DOS is one of those)
- [**125**Star][4y] [Py] [sektioneins/sandbox_toolkit](https://github.com/sektioneins/sandbox_toolkit) Toolkit for binary iOS / OS X sandbox profiles
- [**124**Star][3m] [Py] [platomav/biosutilities](https://github.com/platomav/biosutilities) Various BIOS Utilities for Modding/Research
- [**123**Star][1m] [C] [projecthorus/radiosonde_auto_rx](https://github.com/projecthorus/radiosonde_auto_rx) Automatically Track Radiosonde Launches using RTLSDR
- [**119**Star][2y] [Swift] [lxdcn/nepackettunnelvpndemo](https://github.com/lxdcn/nepackettunnelvpndemo) iOS VPN client implementation demo based on iOS9 NetworkExtension NETunnelProvider APIs
- [**113**Star][3y] [Objective-C++] [yonsm/ipafine](https://github.com/yonsm/ipafine) iOS IPA package refine and resign
- [**110**Star][2y] [Objective-C] [rozbo/ios-pubgm-hack](https://github.com/rozbo/ios-pubgm-hack) iOS吃鸡辅助
- [**110**Star][7m] [C] [siguza/imobax](https://github.com/siguza/imobax) iOS Mobile Backup Extractor
- [**105**Star][7y] [intrepidusgroup/trustme](https://github.com/intrepidusgroup/trustme) Disable certificate trust checks on iOS devices.
- [**101**Star][2y] [Objective-C++] [electrajailbreak/cydia](https://github.com/electrajailbreak/cydia) Cydia modified for iOS 11/Electra
- [**99**Star][2y] [antid0tecom/ios-kerneldocs](https://github.com/Antid0teCom/ios-kerneldocs) Various files helping to better understand the iOS / WatchOS / tvOS kernels
- [**98**Star][2y] [Py] [google/legilimency](https://github.com/google/legilimency) A Memory Research Platform for iOS
- [**95**Star][2y] [Objective-C] [xslim/mobiledevicemanager](https://github.com/xslim/mobiledevicemanager) Manage iOS devices through iTunes lib
- [**93**Star][7y] [C] [planetbeing/ios-jailbreak-patchfinder](https://github.com/planetbeing/ios-jailbreak-patchfinder) Analyzes a binary iOS kernel to determine function offsets and where to apply the canonical jailbreak patches.
- [**90**Star][5y] [Objective-C] [project-imas/app-password](https://github.com/project-imas/app-password) Custom iOS user authentication mechanism (password with security questions for self reset)
- [**89**Star][3y] [Objective-C] [jamie72/ipapatch](https://github.com/jamie72/ipapatch) Patch iOS Apps, The Easy Way, Without Jailbreak.
- [**85**Star][7m] [Py] [aaronst/macholibre](https://github.com/aaronst/macholibre) Mach-O & Universal Binary Parser
- [**84**Star][2y] [Objective-C] [siguza/phoenixnonce](https://github.com/siguza/phoenixnonce) 64-bit nonce setter for iOS 9.3.4-9.3.5
- [**81**Star][2y] [C] [axi0mx/ios-kexec-utils](https://github.com/axi0mx/ios-kexec-utils) boot LLB/iBoot/iBSS/iBEC image from a jailbroken iOS kernel
- [**79**Star][4y] [mi3security/su-a-cyder](https://github.com/mi3security/su-a-cyder) Home-Brewed iOS Malware PoC Generator (BlackHat ASIA 2016)
- [**79**Star][5m] [Objective-C] [smilezxlee/zxhookdetection](https://github.com/smilezxlee/zxhookdetection) 【iOS应用安全】hook及越狱的基本防护与检测
- [**79**Star][1y] [Shell] [iaik/ios-analysis](https://github.com/iaik/ios-analysis) Automated Binary Analysis on iOS
- [**77**Star][2y] [Objective-C] [cocoahuke/ioskextdump](https://github.com/cocoahuke/ioskextdump) Dump Kext information from iOS kernel cache. Applicable to the kernel which dump from memory
- [**73**Star][8d] [C] [certificate-helper/tls-inspector](https://github.com/certificate-helper/tls-inspector) Easily view and inspect X.509 certificates on your iOS device.
- [**72**Star][2y] [Objective-C] [sunweiliang/baiduyuncrack](https://github.com/sunweiliang/baiduyuncrack) iOS百度云盘 破解速度限制、去广告、去更新 无需越狱~
- [**71**Star][3y] [C++] [razzile/liberation](https://github.com/razzile/liberation) A runtime patching library for iOS. Major rework on unfinished branch
- [**70**Star][3m] [C++] [macmade/unicorn-bios](https://github.com/macmade/unicorn-bios) Basic BIOS emulator for Unicorn Engine.
- [**67**Star][2m] [C] [brandonplank/rootlessjb4](https://github.com/BrandonPlank/rootlessJB4) rootlessJB that supports iOS 12.0 - 12.2 & 12.4
- [**67**Star][9d] [Py] [ehco1996/aioshadowsocks](https://github.com/ehco1996/aioshadowsocks) 用 asyncio 重写 shadowsocks ~
- [**65**Star][3y] [Objective-C] [zhengmin1989/yalu102](https://github.com/zhengmin1989/yalu102) incomplete iOS 10.2 jailbreak for 64 bit devices by qwertyoruiopz and marcograssi
- [**60**Star][4y] [shadowsocks/tun2socks-ios](https://github.com/shadowsocks/tun2socks-ios) tun2socks as a library for iOS apps
- [**57**Star][4y] [HTML] [nccgroup/iodide](https://github.com/nccgroup/iodide) The Cisco IOS Debugger and Integrated Disassembler Environment
- [**55**Star][3y] [C++] [s-kanev/xiosim](https://github.com/s-kanev/xiosim) A detailed michroarchitectural x86 simulator
- [**55**Star][3y] [C] [synack/chaoticmarch](https://github.com/synack/chaoticmarch) A mechanism for automating input events on iOS
- [**54**Star][1y] [JS] [userlandkernel/jailbreakme-unified](https://github.com/userlandkernel/jailbreakme-unified) Framework for iOS browser exploitation to kernel privileges and rootfs remount
- [**53**Star][2y] [jkpang/timliu-ios](https://github.com/jkpang/timliu-ios) iOS开发常用三方库、插件、知名博客等等
- [**53**Star][2y] [rehints/blackhat_2017](https://github.com/rehints/blackhat_2017) Betraying the BIOS: Where the Guardians of the BIOS are Failing
- [**51**Star][1y] [C] [bazad/threadexec](https://github.com/bazad/threadexec) A library to execute code in the context of other processes on iOS 11.
- [**51**Star][1y] [C] [pwn20wndstuff/osiris](https://github.com/pwn20wndstuff/osiris) Osiris developer jailbreak for iOS 11.0 - 11.4b3
- [**51**Star][3y] [HTML] [pwnsdx/ios-uri-schemes-abuse-poc](https://github.com/pwnsdx/ios-uri-schemes-abuse-poc) A set of URI schemes bugs that lead Safari to crash/freeze.
- [**49**Star][1y] [Swift] [sherlouk/swiftprovisioningprofile](https://github.com/sherlouk/swiftprovisioningprofile) Parse iOS mobile provisioning files into Swift models
- [**47**Star][6m] [Py] [ivrodriguezca/decrypt-ios-apps-script](https://github.com/ivrodriguezca/decrypt-ios-apps-script) Python script to SSH into your jailbroken device, decrypt an iOS App and transfer it to your local machine
- [**47**Star][5y] [PHP] [cloudsec/aioshell](https://github.com/cloudsec/aioshell) A php webshell run under linux based webservers. v0.05
- [**46**Star][1y] [uefitech/resources](https://github.com/uefitech/resources) One-stop shop for UEFI/BIOS specifications/utilities by UEFI.Tech community
- [**45**Star][2y] [C] [geosn0w/ios-10.1.1-project-0-exploit-fork](https://github.com/geosn0w/ios-10.1.1-project-0-exploit-fork) iOS 10.1.1 Project 0 Exploit Compatible with All arm64 devices for Jailbreak Development
- [**45**Star][1y] [Go] [unixpickle/cve-2018-4407](https://github.com/unixpickle/cve-2018-4407) Crash macOS and iOS devices with one packet
- [**44**Star][4y] [C] [samdmarshall/machodiff](https://github.com/samdmarshall/machodiff) mach-o diffing tool
- [**43**Star][5y] [Shell] [netspi/heapdump-ios](https://github.com/netspi/heapdump-ios) Dump IOS application heap space from memory
- [**42**Star][2y] [Py] [klsecservices/ios_mips_gdb](https://github.com/klsecservices/ios_mips_gdb) Cisco MIPS debugger
- [**41**Star][3y] [kd1991/oxul103-jailbreak](https://github.com/KD1991/OXUL103-Jailbreak) A NEW 64-bit JAILBREAK FOR iOS 10.3,10.3.1,10.3.2,10.3.x. (Untethered).
- [**40**Star][1y] [C] [in7egral/taig8-ios-jailbreak-patchfinder](https://github.com/in7egral/taig8-ios-jailbreak-patchfinder) Analyzes a binary iOS kernel to determine function offsets and where to apply the canonical jailbreak patches.
- [**39**Star][4y] [Pascal] [senjaxus/delphi_remote_access_pc](https://github.com/senjaxus/delphi_remote_access_pc) Remote access in Delphi 7 and Delphi XE5 (With sharer files, CHAT and Forms Inheritance) || Acesso Remoto em Delphi 7 e Delphi XE5 (Com Compartilhador de Arquivos, CHAT e Herança de Formulários)
- [**38**Star][3m] [Py] [gh2o/rvi_capture](https://github.com/gh2o/rvi_capture) rvictl for Linux and Windows: capture packets sent/received by iOS devices
- [**38**Star][4y] [C] [taichisocks/shadowsocks](https://github.com/taichisocks/shadowsocks) Lightweight shadowsocks client for iOS and Mac OSX base on shadowsocks-libev
- [**38**Star][8m] [Shell] [userlandkernel/plataoplomo](https://github.com/userlandkernel/plataoplomo) Collection of (at time of release) iOS bugs I found
- [**36**Star][3y] [Objective-C++] [cyhe/iossecurity-attack](https://github.com/cyhe/iossecurity-attack) APP安全(逆向攻击篇)
- [**34**Star][4y] [Py] [curehsu/ez-wave](https://github.com/curehsu/ez-wave) Tools for Evaluating and Exploiting Z-Wave Networks using Software-Defined Radios.
- [**34**Star][1y] [Swift] [vixentael/zka-example](https://github.com/vixentael/zka-example) Zero Knowledge Application example, iOS, notes sharing, Firebase backend
- [**33**Star][3y] [Objective-C] [integrity-sa/introspy-ios](https://github.com/integrity-sa/introspy-ios) Security profiling for blackbox iOS
- [**33**Star][7y] [C] [mubix/fakenetbios](https://github.com/mubix/fakenetbios) See here:
- [**33**Star][1m] [Objective-C] [proteas/ios13-sandbox-profile-format](https://github.com/proteas/ios13-sandbox-profile-format) Binary Format of iOS 13 Sandbox Profile Collection
- [**32**Star][2y] [applebetas/mterminal-jailed](https://github.com/applebetas/mterminal-jailed) An iOS 11 compatible fork of MTerminal using Ian Beer's tfp0 exploit
- [**32**Star][1y] [Objective-C] [lycajb/lycajb](https://github.com/lycajb/lycajb) LycaJB is a project that aims to fill the gap in iOS 11.0 - 11.3.1 jailbreaks. While this jailbreak is specifically aimed at developers it could be turned into a public stable jailbreak which includes Cydia. Right now we had to make the hard decision to remove Cydia from LycaJB as it caused our test devices to bootloop. We are working hard to ma…
- [**32**Star][9m] [Swift] [vixentael/ios-datasec-basics](https://github.com/vixentael/ios-datasec-basics) iOS data security basics: key management, workshop for iOS Con UK
- [**31**Star][3y] [Py] [as0ler/r2clutch](https://github.com/as0ler/r2clutch) r2-based tool to decrypt iOS applications
- [**30**Star][8y] [Py] [hubert3/isniff](https://github.com/hubert3/isniff) SSL man-in-the-middle tool targeting iOS devices < 4.3.5
- [**29**Star][2y] [Swift] [jeanshuang/potatso](https://github.com/jeanshuang/potatso) 适配Xcode9.3 iOS11.3 Swift3.3编译通过。 (unmaintained) Potatso is an iOS client that implements Shadowsocks proxy with the leverage of NetworkExtension framework in iOS 9.
- [**29**Star][9m] [C] [mrmacete/r2-ios-kernelcache](https://github.com/mrmacete/r2-ios-kernelcache) Radare2 plugin to parse modern iOS 64-bit kernel caches
- [**29**Star][3y] [Objective-C] [mtigas/iobfs](https://github.com/mtigas/iobfs) Building obfs4proxy for Tor-enabled iOS apps.
- [**28**Star][2y] [Objective-C] [dannagle/packetsender-ios](https://github.com/dannagle/packetsender-ios) Packet Sender for iOS, Send/Receive UDP/TCP
- [**28**Star][4y] [C] [scallywag/nbtscan](https://github.com/scallywag/nbtscan) NetBIOS scanning tool. Currently segfaults!
- [**27**Star][1y] [alonemonkey/iosrebook-issues](https://github.com/alonemonkey/iosrebook-issues) 《iOS应用逆向与安全》 勘误
- [**27**Star][14d] [Perl] [hknutzen/netspoc](https://github.com/hknutzen/netspoc) A network security policy compiler. Netspoc is targeted at large environments with a large number of firewalls and admins. Firewall rules are derived from a single rule set. Supported are Cisco IOS, NX-OS, ASA and IPTables.
- [**27**Star][7m] [Py] [qingxp9/cve-2019-6203-poc](https://github.com/qingxp9/cve-2019-6203-poc) PoC for CVE-2019-6203, works on < iOS 12.2, macOS < 10.14.4
- [**27**Star][3y] [C] [salmg/audiospoof](https://github.com/salmg/audiospoof) Magnetic stripe spoofer implementing audio waves.
- [**27**Star][4m] [Py] [mvelazc0/purplespray](https://github.com/mvelazc0/purplespray) PurpleSpray is an adversary simulation tool that executes password spray behavior under different scenarios and conditions with the purpose of generating attack telemetry in properly monitored Windows enterprise environments
- [**26**Star][2y] [C++] [cuitche/code-obfuscation](https://github.com/cuitche/code-obfuscation) 一款iOS代码混淆工具(A code obfuscation tool for iOS.)
- [**26**Star][5m] [HTML] [devnetsandbox/sbx_multi_ios](https://github.com/devnetsandbox/sbx_multi_ios) Sample code, examples, and resources for use with the DevNet Multi-IOS Sandbox
- [**26**Star][3y] [Assembly] [gyje/bios_rootkit](https://github.com/gyje/bios_rootkit) 来自Freebuf评论区,一个UEFI马.
- [**26**Star][2m] [Rust] [marcograss/rust-kernelcache-extractor](https://github.com/marcograss/rust-kernelcache-extractor) Extract a decrypted iOS 64-bit kernelcache
- [**26**Star][4y] [Objective-C] [qiuyuzhou/shadowsocks-ios](https://github.com/qiuyuzhou/shadowsocks-ios) No maintaining. Try this
- [**26**Star][3y] [Objective-C] [nabla-c0d3/ios-reversing](https://github.com/nabla-c0d3/ios-reversing) Some iOS tools and scripts from 2014 for iOS reversing.
- [**25**Star][2y] [C] [embedi/tcl_shellcode](https://github.com/embedi/tcl_shellcode) A template project for creating a shellcode for the Cisco IOS in the C language
- [**25**Star][1y] [HTML] [649/crash-ios-exploit](https://github.com/649/crash-ios-exploit) Repository dedicated to storing a multitude of iOS/macOS/OSX/watchOS crash bugs. Some samples need to be viewed as raw in order to see the Unicode. Please do not intentionally abuse these exploits.
- [**24**Star][5y] [Objective-C] [samdmarshall/ios-internals](https://github.com/samdmarshall/ios-internals) iOS related code
- [**23**Star][5y] [Ruby] [claudijd/bnat](https://github.com/claudijd/bnat) "Broken NAT" - A suite of tools focused on detecting and interacting with publicly available BNAT scenerios
- [**22**Star][4y] [sunkehappy/ios-reverse-engineering-tools-backup](https://github.com/sunkehappy/ios-reverse-engineering-tools-backup) Some guys find the old lsof could not be downloaded. But I have it and I want to share it.
- [**22**Star][1y] [PHP] [svelizdonoso/asyrv](https://github.com/svelizdonoso/asyrv) ASYRV es una aplicación escrita en PHP/MySQL, con Servicios Web mal desarrollados(SOAP/REST/XML), esperando ayudar a los entusiastas de la seguridad informática a comprender esta tecnología tan utilizada hoy en día por las Organizaciones.
- [**20**Star][1y] [C] [downwithup/cve-2018-16712](https://github.com/downwithup/cve-2018-16712) PoC Code for CVE-2018-16712 (exploit by MmMapIoSpace)
- [**20**Star][4y] [C] [jonathanseals/ios-kexec-utils](https://github.com/jonathanseals/ios-kexec-utils) I'm taking a break, I swear
- [**20**Star][1y] [Ruby] [martinvigo/ransombile](https://github.com/martinvigo/ransombile) Ransombile is a tool that can be used in different scenarios to compromise someone’s digital life when having physical access to a locked mobile device
- [**19**Star][3y] [Swift] [depoon/injectiblelocationspoofing](https://github.com/depoon/injectiblelocationspoofing) Location Spoofing codes for iOS Apps via Code Injection
- [**19**Star][6y] [Logos] [iosre/iosrelottery](https://github.com/iosre/iosrelottery) 
- [**17**Star][1y] [C] [xerub/ios-kexec-utils](https://github.com/xerub/ios-kexec-utils) I'm taking a break, I swear
- [**16**Star][4y] [ashishb/ios-malware](https://github.com/ashishb/ios-malware) iOS malware samples
- [**16**Star][1y] [C] [jailbreaks/empty_list](https://github.com/jailbreaks/empty_list) empty_list - exploit for p0 issue 1564 (CVE-2018-4243) iOS 11.0 - 11.3.1 kernel r/w
- [**16**Star][1y] [Py] [r3dxpl0it/cve-2018-4407](https://github.com/r3dxpl0it/cve-2018-4407) IOS/MAC Denial-Of-Service [POC/EXPLOIT FOR MASSIVE ATTACK TO IOS/MAC IN NETWORK]
- [**15**Star][2y] [Objective-C++] [ay-kay/cda](https://github.com/ay-kay/cda) iOS command line tool to search for installed apps and list container paths (bundle, data, group)
- [**15**Star][2y] [Swift] [vgmoose/nc-client](https://github.com/vgmoose/nc-client) [iOS] netcat gui app, for using the 10.1.x mach_portal root exploit on device
- [**15**Star][11m] [aliasrobotics/rctf](https://github.com/aliasrobotics/rctf) Scenarios of the Robotics CTF (RCTF), a playground to challenge robot security.
- [**14**Star][2y] [Py] [mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) a list of BIOS/Firmware fixes adressing CVE-2017-5715, CVE-2017-5753, CVE-2017-5754
- [**14**Star][7y] [Py] [trotsky/insyde-tools](https://github.com/trotsky/insyde-tools) (Inactive) Tools for unpacking and modifying an InsydeH2O UEFI BIOS now merged into coreboot
- [**13**Star][1y] [Objective-C] [omerporze/toothfairy](https://github.com/omerporze/toothfairy) CVE-2018-4330 POC for iOS
- [**13**Star][6y] [Py] [yuejd/ios_restriction_passcode_crack---python-version](https://github.com/yuejd/ios_restriction_passcode_crack---python-version) Crack ios Restriction PassCode in Python
- [**12**Star][8y] [C] [akgood/iosbasicconstraintsworkaround](https://github.com/akgood/iosbasicconstraintsworkaround) Proof-of-Concept OpenSSL-based workaround for iOS basicConstraints SSL certificate validation vulnerability
- [**12**Star][10m] [Py] [wyatu/cve-2018-4407](https://github.com/wyatu/cve-2018-4407) CVE-2018-4407 IOS/macOS kernel crash
- [**11**Star][3y] [Objective-C] [openjailbreak/yalu102](https://github.com/openjailbreak/yalu102) incomplete iOS 10.2 jailbreak for 64 bit devices by qwertyoruiopz and marcograssi
- [**10**Star][1y] [Py] [zteeed/cve-2018-4407-ios](https://github.com/zteeed/cve-2018-4407-ios) POC: Heap buffer overflow in the networking code in the XNU operating system kernel
- [**9**Star][2y] [proappleos/upgrade-from-any-jailbroken-device-to-ios-11.1.2-with-blobs](https://github.com/proappleos/upgrade-from-any-jailbroken-device-to-ios-11.1.2-with-blobs) How to Upgrade any Jailbroken Device to iOS 11.1.2 with Blobs
- [**9**Star][4y] [C] [yigitcanyilmaz/iohideventsystemuserclient](https://github.com/yigitcanyilmaz/iohideventsystemuserclient) iOS Kernel Race Vulnerability (Patched on iOS 9.3.2,OSX 10.11.5,tvOS 9.2.1 by Apple)
- [**8**Star][3y] [Objective-C] [imokhles/boptionloader](https://github.com/imokhles/boptionloader) side load BOptionsPro for BBM to improve BBM app on iOS device ( first BBM tweak ever for non jailbroken devices )
- [**8**Star][6y] [C] [linusyang/sslpatch](https://github.com/linusyang/sslpatch) Patch iOS SSL vulnerability (CVE-2014-1266)
- [**8**Star][2y] [JS] [ansjdnakjdnajkd/frinfo](https://github.com/ansjdnakjdnajkd/frinfo) Dump files, data, cookies, keychain and etc. from iOS device with one click.
- [**8**Star][2y] [C] [syst3ma/cisco_ios_research](https://github.com/syst3ma/cisco_ios_research) 
- [**7**Star][7y] [Objective-C] [hayaq/recodesign](https://github.com/hayaq/recodesign) Re-codesigning tool for iOS ipa file
- [**7**Star][2y] [pinczakko/nsa_bios_backdoor_articles](https://github.com/pinczakko/nsa_bios_backdoor_articles) PDF files of my articles on NSA BIOS backdoor
- [**7**Star][1y] [C] [ukern-developers/xnu-kernel-fuzzer](https://github.com/ukern-developers/xnu-kernel-fuzzer) Kernel Fuzzer for Apple's XNU, mainly meant for the iOS operating system
- [**6**Star][2y] [C] [jduncanator/isniff](https://github.com/jduncanator/isniff) Packet capture and network sniffer for Apple iOS devices (iPhone / iPod). An implementation of iOS 5+ Remote Virtual Interface service and pcapd.
- [**6**Star][6y] [Shell] [rawrly/juicejacking](https://github.com/rawrly/juicejacking) Several script and images used with the juice jacking kiosks
- [**6**Star][10m] [Py] [shawarkhanethicalhacker/cve-2019-8389](https://github.com/shawarkhanethicalhacker/cve-2019-8389) [CVE-2019-8389] An exploit code for exploiting a local file read vulnerability in Musicloud v1.6 iOS Application
- [**6**Star][8y] [Ruby] [spiderlabs/bnat-suite](https://github.com/spiderlabs/bnat-suite) "Broken NAT" - A suite of tools focused on detecting/exploiting/fixing publicly available BNAT scenerios
- [**4**Star][2y] [C] [chibitronics/ltc-os](https://github.com/chibitronics/ltc-os) ChibiOS-based operating system for the Love-to-Code project
- [**4**Star][2y] [Swift] [crazyquark/keysafe](https://github.com/crazyquark/keysafe) A technical demo on how to use KeySecGeneratePair() with the secure enclave in iOS 9+
- [**4**Star][8y] [Objective-C] [spiderlabs/twsl2011-007_ios_code_workaround](https://github.com/spiderlabs/twsl2011-007_ios_code_workaround) Workaround for the vulnerability identified by TWSL2011-007 or CVE-2008-0228 - iOS x509 Certificate Chain Validation Vulnerability
- [**4**Star][3y] [Objective-C] [kd1991/ipapatch](https://github.com/KD1991/IPAPatch) Patch iOS Apps, The Easy Way, Without Jailbreak.
- [**3**Star][5y] [Objective-C] [martianz/shadowsocks-ios](https://github.com/martianz/shadowsocks-ios) shadowsocks client for OSX and non-jailbroken iPhone and iPad
- [**3**Star][3y] [Objective-C] [openjailbreak/yalu](https://github.com/openjailbreak/yalu) incomplete ios 8.4.1 jailbreak by Kim Jong Cracks (8.4.1 codesign & sandbox bypass w/ LPE to root & untether)
- [**3**Star][4y] [Py] [torque59/yso-mobile-security-framework](https://github.com/torque59/yso-mobile-security-framework) Mobile Security Framework is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static and dynamic analysis.
- [**3**Star][1y] [tthtlc/awesome_malware_techniques](https://github.com/tthtlc/awesome_malware_techniques) This will compile a list of Android, iOS, Linux malware techniques for attacking and detection purposes.
- [**2**Star][3y] [Py] [alexplaskett/needle](https://github.com/alexplaskett/needle) The iOS Security Testing Framework.
- [**2**Star][11m] [anonymouz4/apple-remote-crash-tool-cve-2018-4407](https://github.com/anonymouz4/apple-remote-crash-tool-cve-2018-4407) Crashes any macOS High Sierra or iOS 11 device that is on the same WiFi network
- [**2**Star][7y] [felipefmmobile/ios-plist-encryptor](https://github.com/felipefmmobile/ios-plist-encryptor) IOS *.plist encryptor project. Protect your *.plist files from jailbroken
- [**2**Star][2y] [C] [kigkrazy/hookzz](https://github.com/kigkrazy/hookzz) a cute hook framwork for arm/arm64/ios/android
- [**2**Star][2y] [Ruby] [mtjailed/msf-webkit-10.3](https://github.com/mtjailed/msf-webkit-10.3) A metasploit module for webkit exploits and PoC's targeting devices running iOS 10+
- [**2**Star][3y] [C] [ohdarling/potatso-ios](https://github.com/ohdarling/potatso-ios) Potatso is an iOS client that implements Shadowsocks proxy with the leverage of NetworkExtension framework in iOS 9.


### <a id="7037d96c1017978276cb920f65be2297"></a>XCode


- [**1388**Star][14d] [Swift] [johnno1962/injectioniii](https://github.com/johnno1962/injectioniii) Re-write of Injection for Xcode in (mostly) Swift4
- [**562**Star][19d] [Objective-C] [hdb-li/lldebugtool](https://github.com/hdb-li/lldebugtool) LLDebugTool is a debugging tool for developers and testers that can help you analyze and manipulate data in non-xcode situations.
- [**499**Star][7y] [C] [ghughes/fruitstrap](https://github.com/ghughes/fruitstrap) Install and debug iPhone apps from the command line, without using Xcode
- [**178**Star][4y] [Objective-C] [x43x61x69/otx](https://github.com/x43x61x69/otx) The Mach-O disassembler. Now 64bit and Xcode 6 compatible.
- [**134**Star][12m] [Shell] [onmyway133/swiftsnippets](https://github.com/onmyway133/SwiftSnippets) A collection of Swift snippets to be used in Xcode 
- [**48**Star][2y] [C++] [tonyzesto/pubgprivxcode85](https://github.com/tonyzesto/pubgprivxcode85) Player ESP 3D Box ESP Nametag ESP Lightweight Code Secure Injection Dedicated Cheat Launcher Secured Against Battleye Chicken Dinner Every Day. Win more matches than ever before with CheatAutomation’s Playerunknown’s Battlegrounds cheat! Our stripped down, ESP only cheat gives you the key features you need to take out your opponents and be eatin…
- [**44**Star][3y] [Shell] [vtky/resign](https://github.com/vtky/resign) XCode Project to resign .ipa files




***


## <a id="c97bbe32bbd26c72ceccb43400e15bf1"></a>Posts&&Videos




# <a id="0ae4ddb81ff126789a7e08b0768bd693"></a>Cuckoo


***


## <a id="5830a8f8fb3af1a336053d84dd7330a1"></a>Tools


### <a id="f2b5c44c2107db2cec6c60477c6aa1d0"></a>RecentAdd


- [**4015**Star][3m] [JS] [cuckoosandbox/cuckoo](https://github.com/cuckoosandbox/cuckoo) Cuckoo Sandbox is an automated dynamic malware analysis system
- [**453**Star][2y] [Py] [idanr1986/cuckoo-droid](https://github.com/idanr1986/cuckoo-droid) Automated Android Malware Analysis with Cuckoo Sandbox.
- [**357**Star][3y] [Py] [spender-sandbox/cuckoo-modified](https://github.com/spender-sandbox/cuckoo-modified) Modified edition of cuckoo
- [**303**Star][2m] [Py] [hatching/vmcloak](https://github.com/hatching/vmcloak) Automated Virtual Machine Generation and Cloaking for Cuckoo Sandbox.
- [**245**Star][4y] [C] [begeekmyfriend/cuckoofilter](https://github.com/begeekmyfriend/cuckoofilter) Substitute for bloom filter.
- [**236**Star][5y] [C] [conix-security/zer0m0n](https://github.com/conix-security/zer0m0n) zer0m0n driver for cuckoo sandbox
- [**236**Star][6m] [Py] [cuckoosandbox/community](https://github.com/cuckoosandbox/community) Repository of modules and signatures contributed by the community
- [**236**Star][3m] [Py] [brad-sp/cuckoo-modified](https://github.com/brad-sp/cuckoo-modified) Modified edition of cuckoo
- [**222**Star][1y] [PHP] [cuckoosandbox/monitor](https://github.com/cuckoosandbox/monitor) The new Cuckoo Monitor.
- [**218**Star][3m] [Shell] [blacktop/docker-cuckoo](https://github.com/blacktop/docker-cuckoo) Cuckoo Sandbox Dockerfile
- [**200**Star][2y] [C] [david-reguera-garcia-dreg/anticuckoo](https://github.com/david-reguera-garcia-dreg/anticuckoo) A tool to detect and crash Cuckoo Sandbox
- [**150**Star][3y] [Shell] [buguroo/cuckooautoinstall](https://github.com/buguroo/cuckooautoinstall) Auto Installer Script for Cuckoo Sandbox
- [**124**Star][4y] [Py] [davidoren/cuckoosploit](https://github.com/davidoren/cuckoosploit) An environment for comprehensive, automated analysis of web-based exploits, based on Cuckoo sandbox.
- [**121**Star][4y] [C] [cuckoosandbox/cuckoomon](https://github.com/cuckoosandbox/cuckoomon) DEPRECATED - replaced with "monitor"
- [**117**Star][3y] [Py] [honeynet/cuckooml](https://github.com/honeynet/cuckooml) Machine Learning for Cuckoo Sandbox
- [**82**Star][2y] [Py] [idanr1986/cuckoodroid-2.0](https://github.com/idanr1986/cuckoodroid-2.0) Automated Android Malware Analysis with Cuckoo Sandbox.
- [**78**Star][5y] [Py] [idanr1986/cuckoo](https://github.com/idanr1986/cuckoo) A Cuckoo Sandbox Extension for Android
- [**70**Star][8m] [Py] [jpcertcc/malconfscan-with-cuckoo](https://github.com/jpcertcc/malconfscan-with-cuckoo) Cuckoo Sandbox plugin for extracts configuration data of known malware
- [**69**Star][4m] [PowerShell] [nbeede/boombox](https://github.com/nbeede/boombox) Automatic deployment of Cuckoo Sandbox malware lab using Packer and Vagrant
- [**68**Star][3y] [C] [angelkillah/zer0m0n](https://github.com/angelkillah/zer0m0n) zer0m0n driver for cuckoo sandbox
- [**56**Star][7m] [Py] [hatching/sflock](https://github.com/hatching/sflock) Sample staging & detonation utility to be used in combination with Cuckoo Sandbox.
- [**54**Star][4y] [Py] [rodionovd/cuckoo-osx-analyzer](https://github.com/rodionovd/cuckoo-osx-analyzer) An OS X analyzer for Cuckoo Sandbox project
- [**39**Star][7y] [Perl] [xme/cuckoomx](https://github.com/xme/cuckoomx) CuckooMX is a project to automate analysis of files transmitted over SMTP (using the Cuckoo sandbox)
- [**38**Star][3y] [C] [spender-sandbox/cuckoomon-modified](https://github.com/spender-sandbox/cuckoomon-modified) Modified edition of cuckoomon
- [**35**Star][5m] [ocatak/malware_api_class](https://github.com/ocatak/malware_api_class) Malware dataset for security researchers, data scientists. Public malware dataset generated by Cuckoo Sandbox based on Windows OS API calls analysis for cyber security researchers
- [**32**Star][1y] [Py] [phdphuc/mac-a-mal-cuckoo](https://github.com/phdphuc/mac-a-mal-cuckoo) extends the open-source Cuckoo Sandbox (legacy) with functionality for analyzing macOS malware in macOS guest VM(s).
- [**28**Star][3y] [Py] [0x71/cuckoo-linux](https://github.com/0x71/cuckoo-linux) Linux malware analysis based on Cuckoo Sandbox.
- [**19**Star][5y] [C] [zer0box/zer0m0n](https://github.com/zer0box/zer0m0n) zer0m0n driver for cuckoo sandbox
- [**14**Star][6m] [Py] [ryuchen/panda-sandbox](https://github.com/ryuchen/panda-sandbox) 这是一个基于 Cuckoo 开源版本的沙箱的修订版本, 该版本完全为了适配国内软件环境所打造
- [**12**Star][3y] [Py] [keithjjones/cuckoo-modified-api](https://github.com/keithjjones/cuckoo-modified-api) A Python library to interface with a cuckoo-modified instance
- [**10**Star][4y] [Py] [tribalchicken/postfix-cuckoolyse](https://github.com/tribalchicken/postfix-cuckoolyse) A Postfix filter which takes a piped message and submits it to Cuckoo Sandbox
- [**7**Star][2y] [Py] [kojibhy/cuckoo-yara-auto](https://github.com/kojibhy/cuckoo-yara-auto) simple python script to add yara rules in cuckoo sandbox
- [**6**Star][3y] [Py] [xme/cuckoo](https://github.com/xme/cuckoo) Miscellaneous files related to Cuckoo sandbox
- [**2**Star][3y] [Shell] [harryr/cockatoo](https://github.com/harryr/cockatoo) Torified Cuckoo malware analyser in a Docker container with VirtualBox
- [**2**Star][7y] [Shell] [hiddenillusion/cuckoo3.2](https://github.com/hiddenillusion/cuckoo3.2) This repo contains patches for the 0.3.2 release of the cuckoo sandbox (




***


## <a id="ec0a441206d9a2fe1625dce0a679d466"></a>Post&&Videos


- 2019.10 [sectechno] [Cuckoo Sandbox – Automated Malware Analysis Framework](https://sectechno.com/cuckoo-sandbox-automated-malware-analysis-framework-2/)
- 2019.04 [eforensicsmag] [How to Integrate RSA Malware Analysis with Cuckoo Sandbox | By Luiz Henrique Borges](https://eforensicsmag.com/how-to-integrate-rsa-malware-analysis-with-cuckoo-sandbox-by-luiz-henrique-borges/)
- 2019.02 [thehive_project] [Cortex-Analyzers 1.15.3 get ready for  URLhaus and Cuckoo](https://blog.thehive-project.org/2019/02/26/cortex-analyzers-1-15-3-get-ready-for-urlhaus-and-cuckoo/)
- 2018.07 [360_anquanke_learning] [一例IRC Bot针对Cuckoo沙箱的猥琐对抗分析](https://www.anquanke.com/post/id/152631/)
- 2018.05 [trustedsec] [Malware Analysis is for the (Cuckoo) Birds – Working with Proxmox](https://www.trustedsec.com/2018/05/working-with-proxmox/)
- 2018.05 [trustedsec] [Protected: Malware Analysis is for the (Cuckoo) Birds](https://www.trustedsec.com/2018/05/malware-cuckoo-1/)
- 2018.05 [trustedsec] [Protected: Malware Analysis is for the (Cuckoo) Birds – Cuckoo Installation Notes for Debian](https://www.trustedsec.com/2018/05/malware-cuckoo-2/)
- 2018.04 [ly0n] [Automating malware analysis, cuckoo api + postfix](https://paumunoz.tech/2018/04/25/automating-malware-analysis-cuckoo-api-postfix/)
- 2018.04 [ly0n] [Automating malware analysis, cuckoo api + postfix](http://ly0n.me/2018/04/25/automating-malware-analysis-cuckoo-api-postfix/)
- 2018.04 [rapid7] [Threat Intel Book Club: The Cuckoo's Egg wrap-up](https://blog.rapid7.com/2018/04/12/threat-intel-book-club-the-cuckoos-egg-wrap-up/)
- 2018.04 [nviso] [Painless Cuckoo Sandbox Installation](https://blog.nviso.be/2018/04/12/painless-cuckoo-sandbox-installation/)
- 2018.03 [rapid7] [Next Threat Intel Book Club 4/5: Recapping The Cuckoo’s Egg](https://blog.rapid7.com/2018/03/18/next-threat-intel-book-club-4-5-recapping-the-cuckoos-egg/)
- 2018.03 [ensurtec] [Cuckoo Sandbox Setup Tutorial](https://ensurtec.com/cuckoo-sandbox-setup-tutorial/)
- 2018.01 [fortinet] [Prevalent Threats Targeting Cuckoo Sandbox Detection and Our Mitigation](https://blog.fortinet.com/2018/01/03/prevalent-threats-targeting-cuckoo-sandbox-detection-and-our-mitigation)
- 2018.01 [fortinet] [Prevalent Threats Targeting Cuckoo Sandbox Detection and Our Mitigation](https://www.fortinet.com/blog/threat-research/prevalent-threats-targeting-cuckoo-sandbox-detection-and-our-mitigation.html)


# <a id="7ab3a7005d6aa699562b3a0a0c6f2cff"></a>DBI


***


## <a id="c8cdb0e30f24e9b7394fcd5681f2e419"></a>DynamoRIO


### <a id="6c4841dd91cb173093ea2c8d0b557e71"></a>Tools


#### <a id="3a577a5b4730a1b5b3b325269509bb0a"></a>DynamoRIO


- [**1373**Star][13d] [C] [dynamorio/drmemory](https://github.com/dynamorio/drmemory) Memory Debugger for Windows, Linux, Mac, and Android
- [**1212**Star][10d] [C] [dynamorio/dynamorio](https://github.com/dynamorio/dynamorio) Dynamic Instrumentation Tool Platform


#### <a id="ff0abe26a37095f6575195950e0b7f94"></a>RecentAdd


- [**246**Star][4m] [C] [ampotos/dynstruct](https://github.com/ampotos/dynstruct) Reverse engineering tool for automatic structure recovering and memory use analysis based on DynamoRIO and Capstone
- [**120**Star][5y] [C++] [breakingmalware/selfie](https://github.com/breakingmalware/selfie) A Tool to Unpack Self-Modifying Code using DynamoRIO
- [**118**Star][3m] [C++] [googleprojectzero/drsancov](https://github.com/googleprojectzero/drsancov) DynamoRIO plugin to get ASAN and SanitizerCoverage compatible output for closed-source executables
- [**53**Star][4y] [C] [lgeek/dynamorio_pin_escape](https://github.com/lgeek/dynamorio_pin_escape) 
- [**16**Star][12d] [C] [firodj/bbtrace](https://github.com/firodj/bbtrace) Basic Block Trace: DynamoRIO client
- [**13**Star][5m] [C++] [vanhauser-thc/afl-dynamorio](https://github.com/vanhauser-thc/afl-dynamorio) run AFL with dynamorio
- [**10**Star][2y] [C++] [atrosinenko/afl-dr](https://github.com/atrosinenko/afl-dr) Experiment in implementation of an instrumentation for American Fuzzy Lop using DynamoRIO


#### <a id="928642a55eff34b6b52622c6862addd2"></a>WithOtherTools


- [**51**Star][11m] [Py] [cisco-talos/dyndataresolver](https://github.com/cisco-talos/dyndataresolver) Dynamic Data Resolver (DDR) IDA Pro Plug-in
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |
    - [DDR](https://github.com/cisco-talos/dyndataresolver/blob/master/VS_project/ddr/ddr.sln) 基于DyRIO的Client
    - [IDA插件](https://github.com/cisco-talos/dyndataresolver/tree/master/IDAplugin) 
- [**20**Star][8m] [C++] [secrary/findloop](https://github.com/secrary/findloop) find possible encryption/decryption or compression/decompression code
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |
- [**6**Star][2y] [C++] [ncatlin/drgat](https://github.com/ncatlin/drgat) The DynamoRIO client for rgat




### <a id="9479ce9f475e4b9faa4497924a2e40fc"></a>Posts&&Videos


- 2019.10 [freebuf] [DrSemu：基于动态行为的恶意软件检测与分类工具](https://www.freebuf.com/sectool/214277.html)
- 2019.06 [freebuf] [Functrace：使用DynamoRIO追踪函数调用](https://www.freebuf.com/sectool/205989.html)
- 2019.01 [360_anquanke_learning] [深入浅出——基于DynamoRIO的strace和ltrace](https://www.anquanke.com/post/id/169257/)
- 2018.08 [n0where] [Dynamic API Call Tracer for Windows and Linux Applications: Drltrace](https://n0where.net/dynamic-api-call-tracer-for-windows-and-linux-applications-drltrace)
- 2018.07 [topsec_adlab] [动态二进制修改(Dynamic Binary Instrumentation)入门：Pin、DynamoRIO、Frida](http://blog.topsec.com.cn/%e5%8a%a8%e6%80%81%e4%ba%8c%e8%bf%9b%e5%88%b6%e4%bf%ae%e6%94%b9dynamic-binary-instrumentation%e5%85%a5%e9%97%a8%ef%bc%9apin%e3%80%81dynamorio%e3%80%81frida/)
- 2018.07 [topsec_adlab] [动态二进制修改(Dynamic Binary Instrumentation)入门：Pin、DynamoRIO、Frida](http://blog.topsec.com.cn/ad_lab/%e5%8a%a8%e6%80%81%e4%ba%8c%e8%bf%9b%e5%88%b6%e4%bf%ae%e6%94%b9dynamic-binary-instrumentation%e5%85%a5%e9%97%a8%ef%bc%9apin%e3%80%81dynamorio%e3%80%81frida/)
- 2018.07 [topsec_adlab] [动态二进制修改(Dynamic Binary Instrumentation)入门：Pin、DynamoRIO、Frida](http://blog.topsec.com.cn/%e5%8a%a8%e6%80%81%e4%ba%8c%e8%bf%9b%e5%88%b6%e4%bf%ae%e6%94%b9dynamic-binary-instrumentation%e5%85%a5%e9%97%a8%ef%bc%9apin%e3%80%81dynamorio%e3%80%81frida/)
- 2018.07 [topsec_adlab] [动态二进制修改(Dynamic Binary Instrumentation)入门：Pin、DynamoRIO、Frida](http://blog.topsec.com.cn/2018/07/%e5%8a%a8%e6%80%81%e4%ba%8c%e8%bf%9b%e5%88%b6%e4%bf%ae%e6%94%b9dynamic-binary-instrumentation%e5%85%a5%e9%97%a8%ef%bc%9apin%e3%80%81dynamorio%e3%80%81frida/)
- 2017.11 [youtube_SECConsult] [The Art of Fuzzing - Demo 10: In-memory Fuzzing HashCalc using DynamoRio](https://www.youtube.com/watch?v=FEJGlgBeUJ8)
- 2017.11 [youtube_SECConsult] [The Art of Fuzzing - Demo 6: Extract Coverage Information using DynamoRio](https://www.youtube.com/watch?v=Ur_E9c2vX1A)
- 2016.11 [360_anquanke_learning] [“Selfie”：利用DynamoRIO实现自修改代码自动脱壳的神器](https://www.anquanke.com/post/id/84999/)
- 2016.09 [securitygossip] [Practical Memory Checking With Dr. Memory](http://securitygossip.com/blog/2016/09/12/2016-09-12/)
- 2016.09 [sjtu_gossip] [Practical Memory Checking With Dr. Memory](https://loccs.sjtu.edu.cn/gossip/blog/2016/09/12/2016-09-12/)
- 2016.08 [n0where] [Dynamic Instrumentation Tool Platform: DynamoRIO](https://n0where.net/dynamic-instrumentation-tool-platform-dynamorio)
- 2012.10 [redplait] [building dynamorio](http://redplait.blogspot.com/2012/10/building-dynamorio.html)
- 2011.06 [redplait] [dynamorio](http://redplait.blogspot.com/2011/06/dynamorio.html)




***


## <a id="7b8a493ca344f41887792fcc008573e7"></a>IntelPin


### <a id="fe5a6d7f16890542c9e60857706edfde"></a>Tools


#### <a id="78a2edf9aa41eb321436cb150ea70a54"></a>RecentAdd


- [**424**Star][4y] [C++] [jonathansalwan/pintools](https://github.com/jonathansalwan/pintools) Pintool example and PoC for dynamic binary analysis
- [**298**Star][1m] [C] [vusec/vuzzer](https://github.com/vusec/vuzzer) depends heavily on a modeified version of DataTracker, which in turn depends on LibDFT pintool.
- [**148**Star][5y] [C++] [f-secure/sulo](https://github.com/f-secure/sulo) Dynamic instrumentation tool for Adobe Flash Player built on Intel Pin
- [**114**Star][5m] [C++] [hasherezade/tiny_tracer](https://github.com/hasherezade/tiny_tracer) A Pin Tool for tracing API calls etc
- [**65**Star][3y] [C++] [m000/dtracker](https://github.com/m000/dtracker) DataTracker: A Pin tool for collecting high-fidelity data provenance from unmodified programs.
- [**60**Star][2y] [C++] [hasherezade/mypintools](https://github.com/hasherezade/mypintools) Tools to run with Intel PIN
- [**48**Star][7y] [C++] [cr4sh/code-coverage-analysis-tools](https://github.com/cr4sh/code-coverage-analysis-tools) Code coverage analysis tools for the PIN Toolkit
- [**42**Star][8m] [C++] [angorafuzzer/libdft64](https://github.com/angorafuzzer/libdft64) libdft for Intel Pin 3.x and 64 bit platform. (Dynamic taint tracking, taint analysis)
- [**39**Star][4y] [C++] [corelan/pin](https://github.com/corelan/pin) Collection of pin tools
- [**36**Star][3y] [C++] [paulmehta/ablation](https://github.com/paulmehta/ablation) Augmenting Static Analysis Using Pintool: Ablation
- [**30**Star][4y] [C++] [0xddaa/pin](https://github.com/0xddaa/pin) Use Intel Pin tools to analysis binary.
- [**27**Star][1y] [C++] [fdiskyou/winalloctracer](https://github.com/fdiskyou/WinAllocTracer) Pintool that logs and tracks calls to RtlAllocateHeap, RtlReAllocateHeap, RtlFreeHeap, VirtualAllocEx, and VirtualFreeEx.
- [**26**Star][7y] [C++] [jingpu/pintools](https://github.com/jingpu/pintools) 
- [**25**Star][2m] [C++] [boegel/mica](https://github.com/boegel/mica) a Pin tool for collecting microarchitecture-independent workload characteristics
- [**22**Star][6y] [C++] [jbremer/pyn](https://github.com/jbremer/pyn) Awesome Python bindings for Pintool


#### <a id="e6a829abd8bbc5ad2e5885396e3eec04"></a>WithOtherTools


##### <a id="e129288dfadc2ab0890667109f93a76d"></a>NoCategory


- [**933**Star][12m] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) Code Coverage Explorer for IDA Pro & Binary Ninja
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |[DBI->Frida->Tools->WithOtherTools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |[DBI->Frida->Tools->WithOtherTools->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**133**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [IDA->Tools->ImportExport->IntelPin](#dd0332da5a1482df414658250e6357f8) |[IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |[IDA->Tools->Vul->NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**121**Star][5y] [C++] [zachriggle/ida-splode](https://github.com/zachriggle/ida-splode) Augmenting Static Reverse Engineering with Dynamic Analysis and Instrumentation
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |
    - [IDA插件](https://github.com/zachriggle/ida-splode/tree/master/py) 
    - [PinTool](https://github.com/zachriggle/ida-splode/tree/master/src) 
- [**117**Star][2y] [C++] [0xphoenix/mazewalker](https://github.com/0xphoenix/mazewalker) Toolkit for enriching and speeding up static malware analysis
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |
    - [mazeui](https://github.com/0xphoenix/mazewalker/blob/master/MazeUI/mazeui.py) 在IDA中显示界面
    - [PyScripts](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/PyScripts) Python脚本，处理收集到的数据
    - [PinClient](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/src) 
- [**100**Star][3m] [Java] [0ffffffffh/dragondance](https://github.com/0ffffffffh/dragondance) Binary code coverage visualizer plugin for Ghidra
    - Also In Section: [Ghidra->Plugins->WithOtherTools->DBI](#60e86981b2c98f727587e7de927e0519) |
    - [Ghidra插件](https://github.com/0ffffffffh/dragondance/blob/master/README.md) 
    - [coverage-pin](https://github.com/0ffffffffh/dragondance/blob/master/coveragetools/README.md) 使用Pin收集信息
- [**88**Star][8y] [C] [neuroo/runtime-tracer](https://github.com/neuroo/runtime-tracer) Dynamic tracing for binary applications (using PIN), IDA plugin to visualize and interact with the traces
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |
    - [PinTool](https://github.com/neuroo/runtime-tracer/tree/master/tracer) 
    - [IDA插件](https://github.com/neuroo/runtime-tracer/tree/master/ida-pin) 
- [**43**Star][3y] [Batchfile] [maldiohead/idapin](https://github.com/maldiohead/idapin) plugin of ida with pin
    - Also In Section: [IDA->Tools->ImportExport->IntelPin](#dd0332da5a1482df414658250e6357f8) |
- [**15**Star][1y] [C++] [agustingianni/instrumentation](https://github.com/agustingianni/instrumentation) Collection of tools implemented using pintools aimed to help in the task of reverse engineering.
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |
    - [CodeCoverage](https://github.com/agustingianni/instrumentation/tree/master/CodeCoverage) 
    - [Pinnacle](https://github.com/agustingianni/instrumentation/tree/master/Pinnacle) 
    - [Recoverer](https://github.com/agustingianni/instrumentation/tree/master/Recoverer) 
    - [Resolver](https://github.com/agustingianni/instrumentation/tree/master/Resolver) 






### <a id="226190bea6ceb98ee5e2b939a6515fac"></a>Posts&&Videos






***


## <a id="f24f1235fd45a1aa8d280eff1f03af7e"></a>Frida


### <a id="a5336a0f9e8e55111bda45c8d74924c1"></a>Tools


#### <a id="6d3c24e43835420063f9ca50ba805f15"></a>Frida


- [**4398**Star][9d] [Makefile] [frida/frida](https://github.com/frida/frida) Clone this repo to build Frida


#### <a id="54836a155de0c15b56f43634cd9cfecf"></a>RecentAdd


- [**1150**Star][24d] [JS] [alonemonkey/frida-ios-dump](https://github.com/alonemonkey/frida-ios-dump) pull decrypted ipa from jailbreak device
- [**632**Star][9d] [Py] [igio90/dwarf](https://github.com/igio90/dwarf) Full featured multi arch/os debugger built on top of PyQt5 and frida
- [**546**Star][19d] [JS] [nccgroup/house](https://github.com/nccgroup/house) A runtime mobile application analysis toolkit with a Web GUI, powered by Frida, written in Python.
- [**478**Star][12d] [JS] [iddoeldor/frida-snippets](https://github.com/iddoeldor/frida-snippets) Hand-crafted Frida examples
- [**416**Star][3m] [C] [frida/frida-python](https://github.com/frida/frida-python) Frida Python bindings
- [**405**Star][1y] [C++] [vah13/extracttvpasswords](https://github.com/vah13/extracttvpasswords) tool to extract passwords from TeamViewer memory using Frida
- [**398**Star][12m] [Py] [dstmath/frida-unpack](https://github.com/dstmath/frida-unpack) unpack script based on frida
- [**397**Star][2y] [JS] [0xdea/frida-scripts](https://github.com/0xdea/frida-scripts) A collection of my Frida.re instrumentation scripts to facilitate reverse engineering of mobile apps.
- [**316**Star][5y] [C++] [frida/cryptoshark](https://github.com/frida/cryptoshark) Self-optimizing cross-platform code tracer based on dynamic recompilation
- [**316**Star][16d] [C] [frida/frida-core](https://github.com/frida/frida-core) Frida core library intended for static linking into bindings
- [**298**Star][29d] [JS] [chichou/bagbak](https://github.com/ChiChou/bagbak) Yet another frida based iOS dumpdecrypted
- [**293**Star][3m] [JS] [smartdone/frida-scripts](https://github.com/smartdone/frida-scripts) frida scripts
- [**278**Star][8m] [Py] [nightbringer21/fridump](https://github.com/nightbringer21/fridump) A universal memory dumper using Frida
- [**265**Star][2y] [Py] [antojoseph/frida-android-hooks](https://github.com/antojoseph/frida-android-hooks) Lets you hook Method Calls in Frida ( Android )
- [**250**Star][1y] [Py] [igio90/frick](https://github.com/igio90/frick) aka the first debugger built on top of frida
- [**228**Star][8d] [JS] [frenchyeti/dexcalibur](https://github.com/frenchyeti/dexcalibur) Dynamic binary instrumentation tool designed for Android application and powered by Frida. It disassembles dex, analyzes it statically, generates hooks, discovers reflected methods, stores intercepted data and does new things from it. Its aim is to be an all-in-one Android reverse engineering platform.
- [**227**Star][14d] [C] [frida/frida-gum](https://github.com/frida/frida-gum) Low-level code instrumentation library used by frida-core
- [**192**Star][4m] [C] [nowsecure/frida-cycript](https://github.com/nowsecure/frida-cycript) Cycript fork powered by Frida.
- [**190**Star][6m] [JS] [xiaokanghub/frida-android-unpack](https://github.com/xiaokanghub/frida-android-unpack) this unpack script for Android O and Android P
- [**152**Star][2m] [JS] [interference-security/frida-scripts](https://github.com/interference-security/frida-scripts) Frida Scripts
- [**137**Star][3y] [JS] [as0ler/frida-scripts](https://github.com/as0ler/frida-scripts) Repository including some useful frida script for iOS Reversing
- [**132**Star][1m] [TypeScript] [chame1eon/jnitrace](https://github.com/chame1eon/jnitrace) A Frida based tool that traces usage of the JNI API in Android apps.
- [**125**Star][7m] [enovella/r2frida-wiki](https://github.com/enovella/r2frida-wiki) This repo aims at providing practical examples on how to use r2frida
- [**124**Star][3y] [JS] [antojoseph/diff-gui](https://github.com/antojoseph/diff-gui) GUI for Frida -Scripts
- [**124**Star][2y] [Java] [brompwnie/uitkyk](https://github.com/brompwnie/uitkyk) Android Frida库, 用于分析App查找恶意行为
    - Also In Section: [Android->Tools->Malware](#f975a85510f714ec3cc2551e868e75b8) |
- [**118**Star][8d] [JS] [fuzzysecurity/fermion](https://github.com/fuzzysecurity/fermion) Fermion, an electron wrapper for Frida & Monaco.
- [**108**Star][2y] [C] [b-mueller/frida-detection-demo](https://github.com/b-mueller/frida-detection-demo) Some examples for detecting frida on Android
- [**108**Star][9d] [C++] [frida/frida-node](https://github.com/frida/frida-node) Frida Node.js bindings
- [**107**Star][8m] [Py] [rootbsd/fridump3](https://github.com/rootbsd/fridump3) A universal memory dumper using Frida for Python 3
- [**103**Star][1y] [JS] [thecjw/frida-android-scripts](https://github.com/thecjw/frida-android-scripts) Some frida scripts
- [**97**Star][2y] [Java] [piasy/fridaandroidtracer](https://github.com/piasy/fridaandroidtracer) A runnable jar that generate Javascript hook script to hook Android classes.
- [**94**Star][2m] [JS] [frida/frida-java-bridge](https://github.com/frida/frida-java-bridge) Java runtime interop from Frida
- [**90**Star][1y] [C] [grimm-co/notquite0dayfriday](https://github.com/grimm-co/notquite0dayfriday) This is a repo which documents real bugs in real software to illustrate trends, learn how to prevent or find them more quickly.
- [**88**Star][2y] [Py] [mind0xp/frida-python-binding](https://github.com/mind0xp/frida-python-binding) Easy to use Frida python binding script
- [**86**Star][3y] [JS] [oalabs/frida-wshook](https://github.com/oalabs/frida-wshook) Script analysis tool based on Frida.re
- [**85**Star][2m] [Py] [demantz/frizzer](https://github.com/demantz/frizzer) Frida-based general purpose fuzzer
- [**83**Star][3y] [JS] [oalabs/frida-extract](https://github.com/oalabs/frida-extract) Frida.re based RunPE (and MapViewOfSection) extraction tool
- [**79**Star][4m] [JS] [frida/frida-presentations](https://github.com/frida/frida-presentations) Public presentations given on Frida at conferences
- [**77**Star][4m] [C] [oleavr/ios-inject-custom](https://github.com/oleavr/ios-inject-custom) Example showing how to use Frida for standalone injection of a custom payload
- [**75**Star][3y] [Py] [antojoseph/diff-droid](https://github.com/antojoseph/diff-droid) Various Scripts for Mobile Pen-testing with Frida
- [**70**Star][21d] [JS] [andreafioraldi/frida-js-afl-instr](https://github.com/andreafioraldi/frida-js-afl-instr) An example on how to do performant in-memory fuzzing with AFL++ and Frida
- [**64**Star][2m] [Py] [hamz-a/jeb2frida](https://github.com/hamz-a/jeb2frida) Automated Frida hook generation with JEB
- [**62**Star][4m] [TypeScript] [nowsecure/airspy](https://github.com/nowsecure/airspy) AirSpy - Frida-based tool for exploring and tracking the evolution of Apple's AirDrop protocol implementation on i/macOS, from the server's perspective. Released during BH USA 2019 Training
- [**54**Star][8m] [JS] [hamz-a/frida-android-libbinder](https://github.com/hamz-a/frida-android-libbinder) PoC Frida script to view Android libbinder traffic
- [**53**Star][19d] [Py] [hamz-a/frida-android-helper](https://github.com/hamz-a/frida-android-helper) Frida Android utilities
- [**50**Star][1y] [JS] [fortiguard-lion/frida-scripts](https://github.com/fortiguard-lion/frida-scripts) 
- [**50**Star][3m] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA tools and scripts collection
    - Also In Section: [IDA->Tools->NoCategory](#c39a6d8598dde6abfeef43faf931beb5) |[IDA->Tools->ImportExport->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |
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
- [**50**Star][21d] [Py] [frida/frida-tools](https://github.com/frida/frida-tools) Frida CLI tools
- [**46**Star][1y] [JS] [maltek/swift-frida](https://github.com/maltek/swift-frida) Frida library for interacting with Swift programs.
- [**45**Star][4m] [JS] [nowsecure/frida-trace](https://github.com/nowsecure/frida-trace) Trace APIs declaratively through Frida.
- [**42**Star][2y] [HTML] [digitalinterruption/fridaworkshop](https://github.com/digitalinterruption/fridaworkshop) Break Apps with Frida workshop material
- [**42**Star][5m] [TypeScript] [igio90/hooah-trace](https://github.com/igio90/hooah-trace) Instructions tracing powered by frida
- [**41**Star][3m] [Swift] [frida/frida-swift](https://github.com/frida/frida-swift) Frida Swift bindings
- [**40**Star][2y] [Py] [agustingianni/memrepl](https://github.com/agustingianni/memrepl) a frida based script that aims to help a researcher in the task of exploitation of memory corruption related bugs
    - Also In Section: [IDA->Tools->ImportExport->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |
- [**39**Star][4m] [TypeScript] [oleavr/frida-agent-example](https://github.com/oleavr/frida-agent-example) Example Frida agent written in TypeScript
- [**39**Star][7m] [C] [sensepost/frida-windows-playground](https://github.com/sensepost/frida-windows-playground) A collection of Frida hooks for experimentation on Windows platforms.
- [**37**Star][8d] [JS] [frida/frida-compile](https://github.com/frida/frida-compile) Compile a Frida script comprised of one or more Node.js modules
- [**34**Star][8d] [CSS] [frida/frida-website](https://github.com/frida/frida-website) Frida's website
- [**33**Star][2m] [Py] [dmaasland/mcfridafee](https://github.com/dmaasland/mcfridafee) 
- [**28**Star][2y] [JS] [versprite/engage](https://github.com/versprite/engage) Tools and Materials for the Frida Engage Blog Series
- [**28**Star][4m] [Java] [dineshshetty/fridaloader](https://github.com/dineshshetty/fridaloader) A quick and dirty app to download and launch Frida on Genymotion
- [**28**Star][7m] [C++] [frida/v8](https://github.com/frida/v8) Frida depends on V8
- [**26**Star][2y] [Py] [androidtamer/frida-push](https://github.com/androidtamer/frida-push) Wrapper tool to identify the remote device and push device specific frida-server binary.
- [**26**Star][1y] [JS] [ioactive/bluecrawl](https://github.com/ioactive/bluecrawl) Frida (Android) Script for extracting bluetooth information
- [**26**Star][3m] [JS] [nowsecure/frida-uikit](https://github.com/nowsecure/frida-uikit) Inspect and manipulate UIKit-based GUIs through Frida.
- [**26**Star][6m] [TypeScript] [igio90/frida-onload](https://github.com/igio90/frida-onload) Frida module to hook module initializations on android
- [**25**Star][3m] [C++] [frida/frida-clr](https://github.com/frida/frida-clr) Frida .NET bindings
- [**24**Star][9m] [TypeScript] [woza-lab/woza](https://github.com/woza-lab/woza) [Deprecated]Dump application ipa from jailbroken iOS based on frida. (Node edition)
- [**19**Star][3y] [JS] [dweinstein/node-frida-contrib](https://github.com/dweinstein/node-frida-contrib) frida utility-belt
- [**19**Star][7m] [JS] [iddoeldor/mplus](https://github.com/iddoeldor/mplus) Intercept android apps based on unity3d (Mono) using Frida
- [**19**Star][4m] [JS] [nowsecure/frida-uiwebview](https://github.com/nowsecure/frida-uiwebview) Inspect and manipulate UIWebView-hosted GUIs through Frida.
- [**18**Star][5y] [JS] [frida/aurora](https://github.com/frida/aurora) Proof-of-concept web app built on top of Frida
- [**17**Star][2y] [Py] [igio90/fridaandroidtracer](https://github.com/igio90/fridaandroidtracer) Android application tracer powered by Frida
- [**17**Star][2y] [Py] [notsosecure/dynamic-instrumentation-with-frida](https://github.com/notsosecure/dynamic-instrumentation-with-frida) Dynamic Instrumentation with Frida
- [**17**Star][4m] [JS] [nowsecure/frida-screenshot](https://github.com/nowsecure/frida-screenshot) Grab screenshots using Frida.
- [**16**Star][4m] [JS] [freehuntx/frida-mono-api](https://github.com/freehuntx/frida-mono-api) All the mono c exports, ready to be used in frida!
- [**15**Star][4m] [JS] [nowsecure/frida-fs](https://github.com/nowsecure/frida-fs) Create a stream from a filesystem resource.
- [**12**Star][2m] [Shell] [virb3/magisk-frida](https://github.com/virb3/magisk-frida) 
- [**11**Star][4m] [JS] [nowsecure/mjolner](https://github.com/nowsecure/mjolner) Cycript backend powered by Frida.
- [**10**Star][1y] [JS] [andreafioraldi/taint-with-frida](https://github.com/andreafioraldi/taint-with-frida) just an experiment
- [**10**Star][5y] [JS] [frida/cloudspy](https://github.com/frida/cloudspy) Proof-of-concept web app built on top of Frida
- [**9**Star][10m] [JS] [lmangani/node_ssl_logger](https://github.com/lmangani/node_ssl_logger) Decrypt and log process SSL traffic via Frida Injection
- [**9**Star][2y] [JS] [random-robbie/frida-docker](https://github.com/random-robbie/frida-docker) Dockerised Version of Frida
- [**9**Star][3m] [Py] [melisska/neomorph](https://github.com/melisska/neomorph) Frida Python Tool
- [**9**Star][9m] [JS] [rubaljain/frida-jb-bypass](https://github.com/rubaljain/frida-jb-bypass) Frida script to bypass the iOS application Jailbreak Detection
- [**7**Star][2m] [JS] [freehuntx/frida-inject](https://github.com/freehuntx/frida-inject) This module allows you to easily inject javascript using frida and frida-load.
- [**6**Star][4m] [JS] [nowsecure/frida-panic](https://github.com/nowsecure/frida-panic) Easy crash-reporting for Frida-based applications.
- [**6**Star][10m] [JS] [eybisi/fridascripts](https://github.com/eybisi/fridascripts) 
- [**5**Star][1m] [TypeScript] [nowsecure/frida-remote-stream](https://github.com/nowsecure/frida-remote-stream) Create an outbound stream over a message transport.
- [**4**Star][5m] [JS] [davuxcom/frida-scripts](https://github.com/davuxcom/frida-scripts) Inject JS and C# into Windows apps, call COM and WinRT APIs
- [**4**Star][2y] [JS] [frida/frida-load](https://github.com/frida/frida-load) Load a Frida script comprised of one or more Node.js modules
- [**4**Star][16d] [JS] [sipcapture/hepjack.js](https://github.com/sipcapture/hepjack.js) Elegantly Sniff Forward-Secrecy TLS/SIP to HEP at the source using Frida
- [**3**Star][4m] [JS] [nowsecure/frida-memory-stream](https://github.com/nowsecure/frida-memory-stream) Create a stream from one or more memory regions.
- [**3**Star][2m] [JS] [margular/frida-skeleton](https://github.com/margular/frida-skeleton) This repository is supposed to define infrastructure of frida on hook android including some useful functions
- [**3**Star][2y] [JS] [myzhan/frida-examples](https://github.com/myzhan/frida-examples) Examples of using frida.
- [**2**Star][1y] [rhofixxxx/kick-off-owasp_webapp_security_vulnerabilities](https://github.com/rhofixxxx/kick-off-OWASP_WebApp_Security_Vulnerabilities) Want to keep your Web application from getting hacked? Here's how to get serious about secure apps. So let's do it! Open Friday, Aug 2016 - Presentation Notes.
- [**1**Star][1y] [JS] [ddurando/frida-scripts](https://github.com/ddurando/frida-scripts) 


#### <a id="74fa0c52c6104fd5656c93c08fd1ba86"></a>WithOtherTools


##### <a id="00a86c65a84e58397ee54e85ed57feaf"></a>NoCategory


- [**570**Star][1y] [Java] [federicodotta/brida](https://github.com/federicodotta/brida) The new bridge between Burp Suite and Frida!


##### <a id="d628ec92c9eea0c4b016831e1f6852b3"></a>IDA


- [**933**Star][12m] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) Code Coverage Explorer for IDA Pro & Binary Ninja
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->Tools->WithOtherTools->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**129**Star][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) a reverse engineering framework created to simplify dynamic instrumentation with Frida
    - Also In Section: [IDA->Tools->ImportExport->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |[IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**82**Star][5y] [Py] [techbliss/frida_for_ida_pro](https://github.com/techbliss/frida_for_ida_pro) plugin for ida pro thar uses the Frida api
    - Also In Section: [IDA->Tools->ImportExport->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |


##### <a id="f9008a00e2bbc7535c88602aa79c8fd8"></a>BinaryNinja


- [**933**Star][12m] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) Code Coverage Explorer for IDA Pro & Binary Ninja
    - Also In Section: [IDA->Tools->Debug->DBIData](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->Tools->WithOtherTools->NoCategory](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->Tools->WithOtherTools->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**8**Star][2m] [Py] [bowline90/binrida](https://github.com/bowline90/binrida) Plugin for Frida in Binary Ninja
    - Also In Section: [BinaryNinja->Plugins->WithOtherTools->NoCategory](#c2f94ad158b96c928ee51461823aa953) |


##### <a id="ac053c4da818ca587d57711d2ff66278"></a>Radare2


- [**370**Star][25d] [JS] [nowsecure/r2frida](https://github.com/nowsecure/r2frida) Radare2 and Frida better together.
    - Also In Section: [Radare2->Plugins->WithOtherTools->NoCategory](#dfe53924d678f9225fc5ece9413b890f) |
- [**34**Star][11m] [CSS] [nowsecure/r2frida-book](https://github.com/nowsecure/r2frida-book) The radare2 + frida book for Mobile Application assessment
    - Also In Section: [Radare2->Plugins->WithOtherTools->NoCategory](#dfe53924d678f9225fc5ece9413b890f) |






### <a id="a1a7e3dd7091b47384c75dba8f279caf"></a>Posts&&Videos


- 2019.07 [hackertor] [Dwarf – Full Featured Multi Arch/Os Debugger Built On Top Of PyQt5 And Frida](https://hackertor.com/2019/07/13/dwarf-full-featured-multi-arch-os-debugger-built-on-top-of-pyqt5-and-frida/)
- 2019.05 [nsfocus_blog] [Frida应用基础及 APP https证书验证破解](http://blog.nsfocus.net/frida%e5%ba%94%e7%94%a8%e5%9f%ba%e7%a1%80%e5%8f%8a-app-https%e8%af%81%e4%b9%a6%e9%aa%8c%e8%af%81%e7%a0%b4%e8%a7%a3/)
- 2019.05 [nsfocus_blog] [Frida应用基础及 APP https证书验证破解](http://blog.nsfocus.net/frida-application-foundation-app-https-certificate-verification-cracking-2/)
- 2019.05 [nsfocus_blog] [Frida应用基础及APP https证书验证破解](http://blog.nsfocus.net/frida-application-foundation-app-https-certificate-verification-cracking/)
- 2019.05 [CodeColorist] [Trace child process with frida on macOS](https://medium.com/p/3b8f0f953f3d)
- 2019.05 [360_anquanke_learning] [FRIDA脚本系列（四）更新篇：几个主要机制的大更新](https://www.anquanke.com/post/id/177597/)
- 2019.03 [360_anquanke_learning] [FRIDA脚本系列（三）超神篇：百度AI“调教”抖音AI](https://www.anquanke.com/post/id/175621/)
- 2019.03 [securityinnovation_blog] [Setting up Frida Without Jailbreak on the Latest iOS 12.1.4 Device](https://blog.securityinnovation.com/frida)
- 2019.02 [nowsecure_blog] [Frida 12.3 Debuts New Crash Reporting Feature](https://www.nowsecure.com/blog/2019/02/07/frida-12-3-debuts-new-crash-reporting-feature/)
- 2019.01 [fuzzysecurity_tutorials] [Application Introspection & Hooking With Frida](http://fuzzysecurity.com/tutorials/29.html)
- 2019.01 [fuping] [安卓APP测试之HOOK大法-Frida篇](https://fuping.site/2019/01/25/Frida-Hook-SoulAPP/)
- 2019.01 [360_anquanke_learning] [FRIDA脚本系列（二）成长篇：动静态结合逆向WhatsApp](https://www.anquanke.com/post/id/169315/)
- 2019.01 [pediy_new_digest] [[原创]介召几个frida在安卓逆向中使用的脚本以及延时Hook手法](https://bbs.pediy.com/thread-248848.htm)
- 2018.12 [360_anquanke_learning] [FRIDA脚本系列（一）入门篇：在安卓8.1上dump蓝牙接口和实例](https://www.anquanke.com/post/id/168152/)
- 2018.12 [pediy_new_digest] [[原创]CVE-2017-4901 VMware虚拟机逃逸漏洞分析【Frida Windows实例】](https://bbs.pediy.com/thread-248384.htm)
- 2018.12 [freebuf] [一篇文章带你领悟Frida的精髓（基于安卓8.1）](https://www.freebuf.com/articles/system/190565.html)
- 2018.12 [pediy_new_digest] [[原创] Frida操作手册-Android环境准备](https://bbs.pediy.com/thread-248293.htm)
- 2018.11 [4hou] [使用FRIDA为Android应用进行脱壳的操作指南](http://www.4hou.com/technology/14404.html)
- 2018.11 [pediy_new_digest] [[原创]Frida Bypass Android SSL pinning example 1](https://bbs.pediy.com/thread-247967.htm)
- 2018.11 [freebuf] [Frida-Wshook：一款基于Frida.re的脚本分析工具](https://www.freebuf.com/sectool/188726.html)
- 2018.11 [360_anquanke_learning] [如何使用FRIDA搞定Android加壳应用](https://www.anquanke.com/post/id/163390/)
- 2018.11 [ioactive_blog] [Extracting Bluetooth Metadata in an Object’s Memory Using Frida](https://ioactive.com/extracting-bluetooth-metadata-in-an-objects-memory-using-frida/)
- 2018.11 [fortinet] [How-to Guide: Defeating an Android Packer with FRIDA](https://www.fortinet.com/blog/threat-research/defeating-an-android-packer-with-frida.html)
- 2018.10 [youtube_PancakeNopcode] [r2con2018 - Analyzing Swift Apps With swift-frida and radare2 - by Malte Kraus](https://www.youtube.com/watch?v=yp6E9-h6yYQ)
- 2018.10 [serializethoughts] [Bypassing Android FLAG_SECURE using FRIDA](https://serializethoughts.com/2018/10/07/bypassing-android-flag_secure-using-frida/)




***


## <a id="5a9974bfcf7cdf9b05fe7a7dc5272213"></a>Other




# <a id="d3690e0b19c784e104273fe4d64b2362"></a>OtherTools


***


## <a id="1d9dec1320a5d774dc8e0e7604edfcd3"></a>RecentAdd


- [**19651**Star][2m] [Jupyter Notebook] [camdavidsonpilon/probabilistic-programming-and-bayesian-methods-for-hackers](https://github.com/camdavidsonpilon/probabilistic-programming-and-bayesian-methods-for-hackers) aka "Bayesian Methods for Hackers": An introduction to Bayesian methods + probabilistic programming with a computation/understanding-first, mathematics-second point of view. All in pure Python ;)
- [**13183**Star][26d] [Py] [corentinj/real-time-voice-cloning](https://github.com/corentinj/real-time-voice-cloning) Clone a voice in 5 seconds to generate arbitrary speech in real-time
- [**11174**Star][7d] [Java] [oracle/graal](https://github.com/oracle/graal) Run Programs Faster Anywhere
- [**11106**Star][2m] [Jupyter Notebook] [selfteaching/the-craft-of-selfteaching](https://github.com/selfteaching/the-craft-of-selfteaching) One has no future if one couldn't teach themself.
- [**10107**Star][8d] [Go] [goharbor/harbor](https://github.com/goharbor/harbor) An open source trusted cloud native registry project that stores, signs, and scans content.
- [**7685**Star][7d] [Go] [git-lfs/git-lfs](https://github.com/git-lfs/git-lfs) Git extension for versioning large files
- [**6954**Star][13d] [Go] [nats-io/nats-server](https://github.com/nats-io/nats-server) High-Performance server for NATS, the cloud native messaging system.
- [**6844**Star][2m] [Go] [sqshq/sampler](https://github.com/sqshq/sampler) A tool for shell commands execution, visualization and alerting. Configured with a simple YAML file.
- [**6440**Star][9m] [HTML] [open-power-workgroup/hospital](https://github.com/open-power-workgroup/hospital) OpenPower工作组收集汇总的医院开放数据
- [**6284**Star][27d] [Py] [seatgeek/fuzzywuzzy](https://github.com/seatgeek/fuzzywuzzy) Fuzzy String Matching in Python
- [**5870**Star][6m] [JS] [haotian-wang/google-access-helper](https://github.com/haotian-wang/google-access-helper) 谷歌访问助手破解版
- [**5845**Star][2m] [Gnuplot] [nasa-jpl/open-source-rover](https://github.com/nasa-jpl/open-source-rover) A build-it-yourself, 6-wheel rover based on the rovers on Mars!
- [**5811**Star][7m] [JS] [sindresorhus/fkill-cli](https://github.com/sindresorhus/fkill-cli) Fabulously kill processes. Cross-platform.
- [**5715**Star][8m] [C] [xoreaxeaxeax/movfuscator](https://github.com/xoreaxeaxeax/movfuscator) The single instruction C compiler
- [**5674**Star][22d] [JS] [swagger-api/swagger-editor](https://github.com/swagger-api/swagger-editor) Swagger Editor
- [**5653**Star][16d] [Go] [casbin/casbin](https://github.com/casbin/casbin) An authorization library that supports access control models like ACL, RBAC, ABAC in Golang
- [**5317**Star][7d] [Py] [mlflow/mlflow](https://github.com/mlflow/mlflow) Open source platform for the machine learning lifecycle
- [**5163**Star][3m] [Py] [ytisf/thezoo](https://github.com/ytisf/thezoo) A repository of LIVE malwares for your own joy and pleasure. theZoo is a project created to make the possibility of malware analysis open and available to the public.
- [**4990**Star][1m] [Py] [snare/voltron](https://github.com/snare/voltron) A hacky debugger UI for hackers
- [**4928**Star][13d] [ASP] [hq450/fancyss](https://github.com/hq450/fancyss) fancyss is a project providing tools to across the GFW on asuswrt/merlin based router.
- [**4868**Star][9d] [Shell] [denisidoro/navi](https://github.com/denisidoro/navi) An interactive cheatsheet tool for the command-line
- [**4838**Star][10d] [Go] [gcla/termshark](https://github.com/gcla/termshark) A terminal UI for tshark, inspired by Wireshark
- [**4793**Star][8m] [Py] [10se1ucgo/disablewintracking](https://github.com/10se1ucgo/disablewintracking) Uses some known methods that attempt to minimize tracking in Windows 10
- [**4710**Star][8d] [C++] [paddlepaddle/paddle-lite](https://github.com/PaddlePaddle/Paddle-Lite) Multi-platform high performance deep learning inference engine (『飞桨』多平台高性能深度学习预测引擎）
- [**4630**Star][6m] [powershell/win32-openssh](https://github.com/powershell/win32-openssh) Win32 port of OpenSSH
- [**4575**Star][11m] [Py] [ecthros/uncaptcha2](https://github.com/ecthros/uncaptcha2) defeating the latest version of ReCaptcha with 91% accuracy
- [**4551**Star][1y] [C] [upx/upx](https://github.com/upx/upx) UPX - the Ultimate Packer for eXecutables
- [**4549**Star][8d] [C++] [mozilla/rr](https://github.com/mozilla/rr) Record and Replay Framework
- [**4485**Star][18d] [TypeScript] [apis-guru/graphql-voyager](https://github.com/apis-guru/graphql-voyager) 
- [**4339**Star][12m] [Py] [lennylxx/ipv6-hosts](https://github.com/lennylxx/ipv6-hosts) Fork of
- [**4256**Star][11m] [JS] [butterproject/butter-desktop](https://github.com/butterproject/butter-desktop) All the free parts of Popcorn Time
- [**4243**Star][9d] [Rust] [timvisee/ffsend](https://github.com/timvisee/ffsend) Easily and securely share files from the command line
- [**4165**Star][2y] [forter/security-101-for-saas-startups](https://github.com/forter/security-101-for-saas-startups) security tips for startups
- [**4039**Star][1m] [JS] [sigalor/whatsapp-web-reveng](https://github.com/sigalor/whatsapp-web-reveng) Reverse engineering WhatsApp Web.
- [**4023**Star][2m] [Java] [jesusfreke/smali](https://github.com/jesusfreke/smali) smali/baksmali
- [**3936**Star][13d] [Go] [dexidp/dex](https://github.com/dexidp/dex) OpenID Connect Identity (OIDC) and OAuth 2.0 Provider with Pluggable Connectors
- [**3916**Star][7d] [Py] [angr/angr](https://github.com/angr/angr) A powerful and user-friendly binary analysis platform!
- [**3908**Star][14d] [Rust] [svenstaro/genact](https://github.com/svenstaro/genact) a nonsense activity generator
- [**3907**Star][1m] [C] [aquynh/capstone](https://github.com/aquynh/capstone) Capstone disassembly/disassembler framework: Core (Arm, Arm64, BPF, EVM, M68K, M680X, MOS65xx, Mips, PPC, RISCV, Sparc, SystemZ, TMS320C64x, Web Assembly, X86, X86_64, XCore) + bindings.
- [**3876**Star][7d] [C++] [baldurk/renderdoc](https://github.com/baldurk/renderdoc) RenderDoc is a stand-alone graphics debugging tool.
- [**3841**Star][8m] [Go] [eranyanay/1m-go-websockets](https://github.com/eranyanay/1m-go-websockets) handling 1M websockets connections in Go
- [**3832**Star][2m] [Objective-C] [sveinbjornt/sloth](https://github.com/sveinbjornt/sloth) Mac app that shows all open files, directories and sockets in use by all running processes. Nice GUI for lsof.
- [**3749**Star][2m] [Go] [microsoft/ethr](https://github.com/microsoft/ethr) Ethr is a Network Performance Measurement Tool for TCP, UDP & HTTP.
- [**3731**Star][13d] [Go] [hashicorp/consul-template](https://github.com/hashicorp/consul-template) Template rendering, notifier, and supervisor for
- [**3681**Star][11d] [jjqqkk/chromium](https://github.com/jjqqkk/chromium) Chromium browser with SSL VPN. Use this browser to unblock websites.
- [**3675**Star][8d] [HTML] [hamukazu/lets-get-arrested](https://github.com/hamukazu/lets-get-arrested) This project is intended to protest against the police in Japan
- [**3660**Star][1y] [Py] [misterch0c/shadowbroker](https://github.com/misterch0c/shadowbroker) The Shadow Brokers "Lost In Translation" leak
- [**3647**Star][8d] [JS] [lesspass/lesspass](https://github.com/lesspass/lesspass) 
- [**3612**Star][17d] [HTML] [consensys/smart-contract-best-practices](https://github.com/consensys/smart-contract-best-practices) A guide to smart contract security best practices
- [**3597**Star][1y] [C#] [nummer/destroy-windows-10-spying](https://github.com/nummer/destroy-windows-10-spying) Destroy Windows Spying tool
- [**3591**Star][3y] [Perl] [x0rz/eqgrp](https://github.com/x0rz/eqgrp) Decrypted content of eqgrp-auction-file.tar.xz
- [**3538**Star][4m] [Shell] [chengr28/revokechinacerts](https://github.com/chengr28/revokechinacerts) Revoke Chinese certificates.
- [**3525**Star][8d] [Pascal] [cheat-engine/cheat-engine](https://github.com/cheat-engine/cheat-engine) Cheat Engine. A development environment focused on modding
- [**3464**Star][15d] [C] [cyan4973/xxhash](https://github.com/cyan4973/xxhash) Extremely fast non-cryptographic hash algorithm
- [**3317**Star][2y] [scanate/ethlist](https://github.com/scanate/ethlist) The Comprehensive Ethereum Reading List
- [**3269**Star][27d] [C] [microsoft/windows-driver-samples](https://github.com/microsoft/windows-driver-samples) This repo contains driver samples prepared for use with Microsoft Visual Studio and the Windows Driver Kit (WDK). It contains both Universal Windows Driver and desktop-only driver samples.
- [**3266**Star][12d] [C] [virustotal/yara](https://github.com/virustotal/yara) The pattern matching swiss knife
- [**3258**Star][5y] [C++] [google/lmctfy](https://github.com/google/lmctfy) lmctfy is the open source version of Google’s container stack, which provides Linux application containers.
- [**3255**Star][7d] [C] [mikebrady/shairport-sync](https://github.com/mikebrady/shairport-sync) AirPlay audio player. Shairport Sync adds multi-room capability with Audio Synchronisation
- [**3234**Star][8d] [Java] [oldmanpushcart/greys-anatomy](https://github.com/oldmanpushcart/greys-anatomy) Java诊断工具
- [**3215**Star][27d] [JS] [koenkk/zigbee2mqtt](https://github.com/koenkk/zigbee2mqtt) Zigbee
- [**3210**Star][1m] [TypeScript] [google/incremental-dom](https://github.com/google/incremental-dom) An in-place DOM diffing library
- [**3210**Star][11d] [C] [tmate-io/tmate](https://github.com/tmate-io/tmate) Instant Terminal Sharing
- [**3205**Star][2m] [Shell] [gfw-breaker/ssr-accounts](https://github.com/gfw-breaker/ssr-accounts) 一键部署Shadowsocks服务；免费Shadowsocks账号分享；免费SS账号分享; 翻墙；无界，自由门，SquirrelVPN
- [**3145**Star][1y] [Shell] [toyodadoubi/doubi](https://github.com/toyodadoubi/doubi) 一个逗比写的各种逗比脚本~
- [**3120**Star][10d] [C] [meetecho/janus-gateway](https://github.com/meetecho/janus-gateway) Janus WebRTC Server
- [**3113**Star][28d] [CSS] [readthedocs/sphinx_rtd_theme](https://github.com/readthedocs/sphinx_rtd_theme) Sphinx theme for readthedocs.org
- [**3106**Star][7d] [C] [qemu/qemu](https://github.com/qemu/qemu) Official QEMU mirror. Please see
- [**3065**Star][9d] [Go] [tencent/bk-cmdb](https://github.com/tencent/bk-cmdb) 蓝鲸智云配置平台(BlueKing CMDB)
- [**3062**Star][1y] [Swift] [zhuhaow/spechtlite](https://github.com/zhuhaow/spechtlite) A rule-based proxy for macOS
- [**3061**Star][20d] [C] [unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn) Unicorn CPU emulator framework (ARM, AArch64, M68K, Mips, Sparc, X86)
- [**3046**Star][4m] [C++] [google/robotstxt](https://github.com/google/robotstxt) The repository contains Google's robots.txt parser and matcher as a C++ library (compliant to C++11).
- [**2991**Star][1y] [PHP] [owner888/phpspider](https://github.com/owner888/phpspider) 《我用爬虫一天时间“偷了”知乎一百万用户，只为证明PHP是世界上最好的语言 》所使用的程序
- [**2962**Star][14d] [Objective-C] [google/santa](https://github.com/google/santa) A binary whitelisting/blacklisting system for macOS
- [**2962**Star][8d] [Py] [quantaxis/quantaxis](https://github.com/quantaxis/quantaxis) QUANTAXIS 支持任务调度 分布式部署的 股票/期货/自定义市场 数据/回测/模拟/交易/可视化 纯本地PAAS量化解决方案
- [**2895**Star][10d] [C] [libfuse/sshfs](https://github.com/libfuse/sshfs) A network filesystem client to connect to SSH servers
- [**2876**Star][7m] [C] [p-h-c/phc-winner-argon2](https://github.com/p-h-c/phc-winner-argon2) The password hash Argon2, winner of PHC
- [**2874**Star][4y] [Objective-C] [maciekish/iresign](https://github.com/maciekish/iresign) iReSign allows iDevice app bundles (.ipa) files to be signed or resigned with a digital certificate from Apple for distribution. This tool is aimed at enterprises users, for enterprise deployment, when the person signing the app is different than the person(s) developing it.
- [**2850**Star][8d] [C] [lxc/lxc](https://github.com/lxc/lxc) LXC - Linux Containers
- [**2840**Star][5m] [Py] [instantbox/instantbox](https://github.com/instantbox/instantbox) Get a clean, ready-to-go Linux box in seconds.
- [**2825**Star][15d] [Py] [espressif/esptool](https://github.com/espressif/esptool) ESP8266 and ESP32 serial bootloader utility
- [**2820**Star][1m] [Assembly] [cirosantilli/x86-bare-metal-examples](https://github.com/cirosantilli/x86-bare-metal-examples) Dozens of minimal operating systems to learn x86 system programming. Tested on Ubuntu 17.10 host in QEMU 2.10 and real hardware. Userland cheat at:
- [**2802**Star][9m] [Py] [plasma-disassembler/plasma](https://github.com/plasma-disassembler/plasma) Plasma is an interactive disassembler for x86/ARM/MIPS. It can generates indented pseudo-code with colored syntax.
- [**2763**Star][1m] [JS] [trufflesuite/ganache-cli](https://github.com/trufflesuite/ganache-cli) Fast Ethereum RPC client for testing and development
- [**2755**Star][7d] [C++] [qtox/qtox](https://github.com/qtox/qtox) qTox is a chat, voice, video, and file transfer IM client using the encrypted peer-to-peer Tox protocol.
- [**2746**Star][8d] [C] [processhacker/processhacker](https://github.com/processhacker/processhacker) A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware.
- [**2735**Star][7d] [TypeScript] [webhintio/hint](https://github.com/webhintio/hint) 
- [**2648**Star][3m] [Py] [drivendata/cookiecutter-data-science](https://github.com/drivendata/cookiecutter-data-science) A logical, reasonably standardized, but flexible project structure for doing and sharing data science work.
- [**2619**Star][8m] [leandromoreira/linux-network-performance-parameters](https://github.com/leandromoreira/linux-network-performance-parameters) Learn where some of the network sysctl variables fit into the Linux/Kernel network flow
- [**2610**Star][2m] [Swift] [zhuhaow/nekit](https://github.com/zhuhaow/nekit) A toolkit for Network Extension Framework
- [**2600**Star][21d] [JS] [knownsec/kcon](https://github.com/knownsec/kcon) KCon is a famous Hacker Con powered by Knownsec Team.
- [**2598**Star][8d] [JS] [popcorn-official/popcorn-desktop](https://github.com/popcorn-official/popcorn-desktop) Popcorn Time is a multi-platform, free software BitTorrent client that includes an integrated media player. Desktop ( Windows / Mac / Linux ) a Butter-Project Fork
- [**2588**Star][1m] [pditommaso/awesome-pipeline](https://github.com/pditommaso/awesome-pipeline) A curated list of awesome pipeline toolkits inspired by Awesome Sysadmin
- [**2564**Star][8y] [C] [id-software/quake](https://github.com/id-software/quake) Quake GPL Source Release
- [**2555**Star][1m] [C] [esnet/iperf](https://github.com/esnet/iperf) A TCP, UDP, and SCTP network bandwidth measurement tool
- [**2495**Star][2m] [Java] [jboss-javassist/javassist](https://github.com/jboss-javassist/javassist) Java bytecode engineering toolkit
- [**2480**Star][8d] [Go] [adguardteam/adguardhome](https://github.com/adguardteam/adguardhome) Network-wide ads & trackers blocking DNS server
- [**2472**Star][11m] [JS] [weixin/miaow](https://github.com/weixin/Miaow) A set of plugins for Sketch include drawing links & marks, UI Kit & Color sync, font & text replacing.
- [**2463**Star][13d] [JS] [vitaly-t/pg-promise](https://github.com/vitaly-t/pg-promise) PostgreSQL interface for Node.js
- [**2451**Star][3y] [Py] [google/enjarify](https://github.com/google/enjarify) a tool for translating Dalvik bytecode to equivalent Java bytecode.
- [**2395**Star][3y] [OCaml] [facebookarchive/pfff](https://github.com/facebookarchive/pfff) Tools for code analysis, visualizations, or style-preserving source transformation.
- [**2366**Star][7d] [Java] [mock-server/mockserver](https://github.com/mock-server/mockserver) MockServer enables easy mocking of any system you integrate with via HTTP or HTTPS with clients written in Java, JavaScript and Ruby. MockServer also includes a proxy that introspects all proxied traffic including encrypted SSL traffic and supports Port Forwarding, Web Proxying (i.e. HTTP proxy), HTTPS Tunneling Proxying (using HTTP CONNECT) and…
- [**2351**Star][8d] [C] [domoticz/domoticz](https://github.com/domoticz/domoticz) monitor and configure various devices like: Lights, Switches, various sensors/meters like Temperature, Rain, Wind, UV, Electra, Gas, Water and much more
- [**2342**Star][3m] [Go] [vuvuzela/vuvuzela](https://github.com/vuvuzela/vuvuzela) Private messaging system that hides metadata
- [**2330**Star][1m] [JS] [pa11y/pa11y](https://github.com/pa11y/pa11y) Pa11y is your automated accessibility testing pal
- [**2317**Star][10d] [C] [tsl0922/ttyd](https://github.com/tsl0922/ttyd) Share your terminal over the web
- [**2316**Star][5y] [C] [abrasive/shairport](https://github.com/abrasive/shairport) Airtunes emulator! Shairport is no longer maintained.
- [**2291**Star][3y] [Py] [lmacken/pyrasite](https://github.com/lmacken/pyrasite) Inject code into running Python processes
- [**2272**Star][1m] [C] [moby/hyperkit](https://github.com/moby/hyperkit) A toolkit for embedding hypervisor capabilities in your application
- [**2271**Star][22d] [JS] [talkingdata/inmap](https://github.com/talkingdata/inmap) 大数据地理可视化
- [**2246**Star][16d] [dumb-password-rules/dumb-password-rules](https://github.com/dumb-password-rules/dumb-password-rules) Shaming sites with dumb password rules.
- [**2201**Star][11d] [Go] [google/mtail](https://github.com/google/mtail) extract whitebox monitoring data from application logs for collection in a timeseries database
- [**2187**Star][21d] [C++] [google/bloaty](https://github.com/google/bloaty) Bloaty McBloatface: a size profiler for binaries
- [**2171**Star][14d] [C] [armmbed/mbedtls](https://github.com/armmbed/mbedtls) An open source, portable, easy to use, readable and flexible SSL library
- [**2168**Star][16d] [getlantern/lantern-binaries](https://github.com/getlantern/lantern-binaries) Lantern installers binary downloads.
- [**2123**Star][16d] [Assembly] [pret/pokered](https://github.com/pret/pokered) disassembly of Pokémon Red/Blue
- [**2105**Star][7d] [goq/telegram-list](https://github.com/goq/telegram-list) List of telegram groups, channels & bots // Список интересных групп, каналов и ботов телеграма // Список чатов для программистов
- [**2081**Star][8d] [C] [flatpak/flatpak](https://github.com/flatpak/flatpak) Linux application sandboxing and distribution framework
- [**2071**Star][30d] [Go] [theupdateframework/notary](https://github.com/theupdateframework/notary) Notary is a project that allows anyone to have trust over arbitrary collections of data
- [**2047**Star][6m] [Go] [maxmcd/webtty](https://github.com/maxmcd/webtty) Share a terminal session over WebRTC
- [**2032**Star][7d] [C++] [openthread/openthread](https://github.com/openthread/openthread) OpenThread released by Google is an open-source implementation of the Thread networking protocol
- [**2006**Star][9m] [C] [dekunukem/nintendo_switch_reverse_engineering](https://github.com/dekunukem/nintendo_switch_reverse_engineering) A look at inner workings of Joycon and Nintendo Switch
- [**2004**Star][4y] [C] [probablycorey/wax](https://github.com/probablycorey/wax) Wax is now being maintained by alibaba
- [**1992**Star][25d] [Swift] [github/softu2f](https://github.com/github/softu2f) Software U2F authenticator for macOS
- [**1990**Star][4m] [swiftonsecurity/sysmon-config](https://github.com/swiftonsecurity/sysmon-config) Sysmon configuration file template with default high-quality event tracing
- [**1983**Star][2m] [C++] [asmjit/asmjit](https://github.com/asmjit/asmjit) Complete x86/x64 JIT and AOT Assembler for C++
- [**1958**Star][26d] [C#] [mathewsachin/captura](https://github.com/mathewsachin/captura) Capture Screen, Audio, Cursor, Mouse Clicks and Keystrokes
- [**1940**Star][3y] [C#] [lazocoder/windows-hacks](https://github.com/lazocoder/windows-hacks) Creative and unusual things that can be done with the Windows API.
- [**1939**Star][2m] [C] [microsoft/procdump-for-linux](https://github.com/microsoft/procdump-for-linux) A Linux version of the ProcDump Sysinternals tool
- [**1902**Star][7d] [Go] [solo-io/gloo](https://github.com/solo-io/gloo) An Envoy-Powered API Gateway
- [**1901**Star][3m] [Go] [minishift/minishift](https://github.com/minishift/minishift) Run OpenShift 3.x locally
- [**1880**Star][14d] [C++] [mhammond/pywin32](https://github.com/mhammond/pywin32) Python for Windows (pywin32) Extensions
- [**1876**Star][5y] [C++] [tum-vision/lsd_slam](https://github.com/tum-vision/lsd_slam) LSD-SLAM
- [**1863**Star][4y] [Objective-C] [xcodeghostsource/xcodeghost](https://github.com/xcodeghostsource/xcodeghost) "XcodeGhost" Source
- [**1861**Star][4m] [Java] [adoptopenjdk/jitwatch](https://github.com/adoptopenjdk/jitwatch) Log analyser / visualiser for Java HotSpot JIT compiler. Inspect inlining decisions, hot methods, bytecode, and assembly. View results in the JavaFX user interface.
- [**1849**Star][11m] [C++] [googlecreativelab/open-nsynth-super](https://github.com/googlecreativelab/open-nsynth-super) Open NSynth Super is an experimental physical interface for the NSynth algorithm
- [**1848**Star][29d] [C] [github/glb-director](https://github.com/github/glb-director) GitHub Load Balancer Director and supporting tooling.
- [**1846**Star][8m] [Py] [netflix-skunkworks/stethoscope](https://github.com/Netflix-Skunkworks/stethoscope) Personalized, user-focused recommendations for employee information security.
- [**1841**Star][2m] [C] [retroplasma/earth-reverse-engineering](https://github.com/retroplasma/earth-reverse-engineering) Reversing Google's 3D satellite mode
- [**1841**Star][13d] [C++] [acidanthera/lilu](https://github.com/acidanthera/Lilu) Arbitrary kext and process patching on macOS
- [**1835**Star][1y] [Java] [yeriomin/yalpstore](https://github.com/yeriomin/yalpstore) Download apks from Google Play Store
- [**1830**Star][7d] [C++] [pytorch/glow](https://github.com/pytorch/glow) Compiler for Neural Network hardware accelerators
- [**1829**Star][1y] [Py] [jinnlynn/genpac](https://github.com/jinnlynn/genpac) PAC/Dnsmasq/Wingy file Generator, working with gfwlist, support custom rules.
- [**1827**Star][2m] [Go] [influxdata/kapacitor](https://github.com/influxdata/kapacitor) Open source framework for processing, monitoring, and alerting on time series data
- [**1819**Star][13d] [Py] [trailofbits/manticore](https://github.com/trailofbits/manticore) Symbolic execution tool
- [**1788**Star][28d] [Go] [gdamore/tcell](https://github.com/gdamore/tcell) Tcell is an alternate terminal package, similar in some ways to termbox, but better in others.
- [**1777**Star][18d] [PHP] [ezyang/htmlpurifier](https://github.com/ezyang/htmlpurifier) Standards compliant HTML filter written in PHP
- [**1776**Star][13d] [C++] [apitrace/apitrace](https://github.com/apitrace/apitrace) Tools for tracing OpenGL, Direct3D, and other graphics APIs
- [**1770**Star][3y] [Objective-C] [alibaba/wax](https://github.com/alibaba/wax) Wax is a framework that lets you write native iPhone apps in Lua.
- [**1759**Star][12d] [C] [google/wuffs](https://github.com/google/wuffs) Wrangling Untrusted File Formats Safely
- [**1747**Star][8d] [17mon/china_ip_list](https://github.com/17mon/china_ip_list) 
- [**1743**Star][12m] [JS] [puppeteer/examples](https://github.com/puppeteer/examples) Use case-driven examples for using Puppeteer and headless chrome
- [**1740**Star][8d] [PHP] [wordpress/wordpress-coding-standards](https://github.com/wordpress/wordpress-coding-standards) PHP_CodeSniffer rules (sniffs) to enforce WordPress coding conventions
- [**1694**Star][14d] [Go] [hashicorp/memberlist](https://github.com/hashicorp/memberlist) Golang package for gossip based membership and failure detection
- [**1694**Star][3y] [CoffeeScript] [okturtles/dnschain](https://github.com/okturtles/dnschain) A blockchain-based DNS + HTTP server that fixes HTTPS security, and more!
- [**1693**Star][3m] [Py] [anorov/cloudflare-scrape](https://github.com/anorov/cloudflare-scrape) A Python module to bypass Cloudflare's anti-bot page.
- [**1693**Star][7d] [TSQL] [brentozarultd/sql-server-first-responder-kit](https://github.com/brentozarultd/sql-server-first-responder-kit) sp_Blitz, sp_BlitzCache, sp_BlitzFirst, sp_BlitzIndex, and other SQL Server scripts for health checks and performance tuning.
- [**1665**Star][6m] [C++] [microsoft/detours](https://github.com/microsoft/detours) Detours is a software package for monitoring and instrumenting API calls on Windows. It is distributed in source code form.
- [**1662**Star][4y] [Java] [dodola/hotfix](https://github.com/dodola/hotfix) 安卓App热补丁动态修复框架
- [**1659**Star][7d] [Java] [apache/geode](https://github.com/apache/geode) Apache Geode
- [**1655**Star][6m] [C] [easyhook/easyhook](https://github.com/easyhook/easyhook) The reinvention of Windows API Hooking
- [**1654**Star][3m] [JS] [tylerbrock/mongo-hacker](https://github.com/tylerbrock/mongo-hacker) MongoDB Shell Enhancements for Hackers
- [**1647**Star][3m] [Py] [boppreh/keyboard](https://github.com/boppreh/keyboard) Hook and simulate global keyboard events on Windows and Linux.
- [**1627**Star][9d] [sarojaba/awesome-devblog](https://github.com/sarojaba/awesome-devblog) 어썸데브블로그. 국내 개발 블로그 모음(only 실명으로).
- [**1620**Star][14d] [JS] [efforg/privacybadger](https://github.com/efforg/privacybadger) Privacy Badger is a browser extension that automatically learns to block invisible trackers.
- [**1608**Star][2y] [JS] [addyosmani/a11y](https://github.com/addyosmani/a11y) Accessibility audit tooling for the web (beta)
- [**1600**Star][8d] [C++] [lief-project/lief](https://github.com/lief-project/lief) Library to Instrument Executable Formats
- [**1599**Star][9m] [JS] [localtunnel/server](https://github.com/localtunnel/server) server for localtunnel.me
- [**1580**Star][1y] [C] [qihoo360/phptrace](https://github.com/qihoo360/phptrace) A tracing and troubleshooting tool for PHP scripts.
- [**1577**Star][1m] [Objective-C] [ealeksandrov/provisionql](https://github.com/ealeksandrov/provisionql) Quick Look plugin for apps and provisioning profile files
- [**1563**Star][12d] [C] [codahale/bcrypt-ruby](https://github.com/codahale/bcrypt-ruby)  Ruby binding for the OpenBSD bcrypt() password hashing algorithm, allowing you to easily store a secure hash of your users' passwords.
- [**1562**Star][17d] [C] [p-gen/smenu](https://github.com/p-gen/smenu) Terminal utility that reads words from standard input or from a file and creates an interactive selection window just below the cursor. The selected word(s) are sent to standard output for further processing.
- [**1560**Star][14d] [Java] [gchq/gaffer](https://github.com/gchq/Gaffer) A large-scale entity and relation database supporting aggregation of properties
- [**1540**Star][2y] [C++] [hteso/iaito](https://github.com/hteso/iaito) A Qt and C++ GUI for radare2 reverse engineering framework
- [**1014**Star][3y] [C++] [aguinet/wannakey](https://github.com/aguinet/wannakey) Wannacry in-memory key recovery
- [**960**Star][7m] [PHP] [jenssegers/optimus](https://github.com/jenssegers/optimus)  id transformation With this library, you can transform your internal id's to obfuscated integers based on Knuth's integer has和
- [**906**Star][7m] [C++] [dfhack/dfhack](https://github.com/DFHack/dfhack) Memory hacking library for Dwarf Fortress and a set of tools that use it
- [**891**Star][11m] [JS] [levskaya/jslinux-deobfuscated](https://github.com/levskaya/jslinux-deobfuscated) An old version of Mr. Bellard's JSLinux rewritten to be human readable, hand deobfuscated and annotated.
- [**698**Star][1y] [Jupyter Notebook] [anishathalye/obfuscated-gradients](https://github.com/anishathalye/obfuscated-gradients) Obfuscated Gradients Give a False Sense of Security: Circumventing Defenses to Adversarial Examples
- [**656**Star][1y] [Rust] [endgameinc/xori](https://github.com/endgameinc/xori) Xori is an automation-ready disassembly and static analysis library for PE32, 32+ and shellcode
- [**653**Star][9m] [Jupyter Notebook] [supercowpowers/data_hacking](https://github.com/SuperCowPowers/data_hacking) Data Hacking Project
- [**626**Star][13d] [PowerShell] [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) A repository of sysmon configuration modules
- [**576**Star][5m] [nshalabi/sysmontools](https://github.com/nshalabi/sysmontools) Utilities for Sysmon
- [**566**Star][10m] [JS] [raineorshine/solgraph](https://github.com/raineorshine/solgraph) Visualize Solidity control flow for smart contract security analysis.
- [**551**Star][3y] [Makefile] [veficos/reverse-engineering-for-beginners](https://github.com/veficos/reverse-engineering-for-beginners) translate project of Drops
- [**520**Star][28d] [mhaggis/sysmon-dfir](https://github.com/mhaggis/sysmon-dfir) Sources, configuration and how to detect evil things utilizing Microsoft Sysmon.
- [**519**Star][4m] [Java] [java-deobfuscator/deobfuscator](https://github.com/java-deobfuscator/deobfuscator) The real deal
- [**502**Star][8m] [JS] [mindedsecurity/jstillery](https://github.com/mindedsecurity/jstillery) Advanced JavaScript Deobfuscation via Partial Evaluation
- [**472**Star][1y] [ksluckow/awesome-symbolic-execution](https://github.com/ksluckow/awesome-symbolic-execution) A curated list of awesome symbolic execution resources including essential research papers, lectures, videos, and tools.
- [**444**Star][11m] [C++] [ntquery/scylla](https://github.com/ntquery/scylla) Imports Reconstructor
- [**443**Star][11m] [Batchfile] [ion-storm/sysmon-config](https://github.com/ion-storm/sysmon-config) Advanced Sysmon configuration, Installer & Auto Updater with high-quality event tracing
- [**433**Star][2y] [PowerShell] [danielbohannon/revoke-obfuscation](https://github.com/danielbohannon/revoke-obfuscation) PowerShell Obfuscation Detection Framework
- [**406**Star][1y] [Py] [fossfreedom/indicator-sysmonitor](https://github.com/fossfreedom/indicator-sysmonitor) Ubuntu application indicator to show various system parameters
- [**405**Star][2m] [Go] [retroplasma/flyover-reverse-engineering](https://github.com/retroplasma/flyover-reverse-engineering) Reversing Apple's 3D satellite mode
- [**403**Star][17d] [Py] [crytic/slither](https://github.com/crytic/slither) Static Analyzer for Solidity
- [**382**Star][1y] [HTML] [maestron/reverse-engineering-tutorials](https://github.com/maestron/reverse-engineering-tutorials) Reverse Engineering Tutorials
- [**367**Star][10y] [C] [brl/obfuscated-openssh](https://github.com/brl/obfuscated-openssh) 
- [**342**Star][12m] [Ruby] [calebfenton/dex-oracle](https://github.com/calebfenton/dex-oracle) A pattern based Dalvik deobfuscator which uses limited execution to improve semantic analysis
- [**303**Star][1m] [C] [nagyd/sdlpop](https://github.com/nagyd/sdlpop) An open-source port of Prince of Persia, based on the disassembly of the DOS version.
- [**302**Star][14d] [Py] [baderj/domain_generation_algorithms](https://github.com/baderj/domain_generation_algorithms) Some results of my DGA reversing efforts
- [**281**Star][7d] [C] [tomb5/tomb5](https://github.com/tomb5/tomb5) Chronicles Disassembly translated to C source code.
- [**264**Star][2m] [Assembly] [pret/pokeyellow](https://github.com/pret/pokeyellow) Disassembly of Pokemon Yellow
- [**236**Star][4m] [JS] [consensys/surya](https://github.com/consensys/surya) A set of utilities for exploring Solidity contracts
- [**222**Star][2y] [Py] [rub-syssec/syntia](https://github.com/rub-syssec/syntia) Program synthesis based deobfuscation framework for the USENIX 2017 paper "Syntia: Synthesizing the Semantics of Obfuscated Code"
- [**210**Star][11m] [Java] [neo23x0/fnord](https://github.com/neo23x0/fnord) Pattern Extractor for Obfuscated Code
- [**197**Star][18d] [F#] [b2r2-org/b2r2](https://github.com/b2r2-org/b2r2) B2R2 is a collection of useful algorithms, functions, and tools for binary analysis.
- [**197**Star][2m] [Py] [rpisec/llvm-deobfuscator](https://github.com/rpisec/llvm-deobfuscator) 
- [**193**Star][3y] [C#] [codeshark-dev/nofuserex](https://github.com/codeshark-dev/nofuserex) Free deobfuscator for ConfuserEx.
- [**180**Star][2m] [Py] [eth-sri/debin](https://github.com/eth-sri/debin) Machine Learning to Deobfuscate Binaries
- [**171**Star][2y] [C] [geosn0w/reverse-engineering-tutorials](https://github.com/geosn0w/reverse-engineering-tutorials) Some Reverse Engineering Tutorials for Beginners
- [**170**Star][1y] [PowerShell] [mattifestation/pssysmontools](https://github.com/mattifestation/pssysmontools) Sysmon Tools for PowerShell
- [**156**Star][6m] [C] [kkamagui/shadow-box-for-x86](https://github.com/kkamagui/shadow-box-for-x86) Lightweight and Practical Kernel Protector for x86 (Presented at BlackHat Asia 2017/2018, beVX 2018 and HITBSecConf 2017)
- [**156**Star][1m] [JS] [lelinhtinh/de4js](https://github.com/lelinhtinh/de4js) JavaScript Deobfuscator and Unpacker
- [**149**Star][8m] [C] [adrianyy/eacreversing](https://github.com/adrianyy/eacreversing) Reversing EasyAntiCheat.
- [**146**Star][6m] [olafhartong/sysmon-cheatsheet](https://github.com/olafhartong/sysmon-cheatsheet) All sysmon event types and their fields explained
- [**138**Star][11m] [C++] [finixbit/elf-parser](https://github.com/finixbit/elf-parser) Lightweight elf binary parser with no external dependencies - Sections, Symbols, Relocations, Segments
- [**138**Star][6m] [C] [glv2/bruteforce-wallet](https://github.com/glv2/bruteforce-wallet) Try to find the password of an encrypted Peercoin (or Bitcoin, Litecoin, etc...) wallet file.
- [**137**Star][30d] [Java] [superblaubeere27/obfuscator](https://github.com/superblaubeere27/obfuscator) A java obfuscator (GUI)
- [**137**Star][4y] [C] [xairy/kaslr-bypass-via-prefetch](https://github.com/xairy/kaslr-bypass-via-prefetch) A proof-of-concept KASLR bypass for the Linux kernel via timing prefetch (dilettante implementation, better read the original paper:
- [**133**Star][1y] [PowerShell] [darkoperator/posh-sysmon](https://github.com/darkoperator/posh-sysmon) PowerShell module for creating and managing Sysinternals Sysmon config files.
- [**129**Star][3y] [Swift] [magic-akari/wannacry](https://github.com/magic-akari/wannacry) 
- [**122**Star][1y] [PowerShell] [mattifestation/bhusa2018_sysmon](https://github.com/mattifestation/bhusa2018_sysmon) All materials from our Black Hat 2018 "Subverting Sysmon" talk
- [**119**Star][4m] [C#] [akaion/jupiter](https://github.com/akaion/jupiter) A Windows virtual memory editing library with support for pattern scanning.
- [**117**Star][2y] [Py] [malus-security/sandblaster](https://github.com/malus-security/sandblaster) Reversing the Apple sandbox
- [**116**Star][3m] [PowerShell] [thom-s/netsec-ps-scripts](https://github.com/thom-s/netsec-ps-scripts) Collection of PowerShell network security scripts for system administrators.
- [**113**Star][4m] [we5ter/flerken](https://github.com/we5ter/flerken) A Solution For Cross-Platform Obfuscated Commands Detection
- [**111**Star][2y] [Py] [cfsworks/wavebird-reversing](https://github.com/cfsworks/wavebird-reversing) Reverse-engineering the WaveBird protocol for the betterment of mankind
- [**109**Star][1y] [Shell] [jgamblin/blackhat-macos-config](https://github.com/jgamblin/blackhat-macos-config) Configure Your Macbook For Blackhat
- [**107**Star][3m] [C#] [matterpreter/shhmon](https://github.com/matterpreter/shhmon) Neutering Sysmon via driver unload
- [**106**Star][3m] [Go] [bnagy/gapstone](https://github.com/bnagy/gapstone) gapstone is a Go binding for the capstone disassembly library
- [**105**Star][3y] [ios-reverse-engineering-dev/swift-apps-reverse-engineering](https://github.com/ios-reverse-engineering-dev/swift-apps-reverse-engineering) Swift Apps Reverse Engineering reading book
- [**97**Star][3y] [Py] [fdiskyou/kcshell](https://github.com/fdiskyou/kcshell) 交互式汇编/反汇编 Shell，Python3编写，基于Keystone/Capstone
- [**97**Star][1y] [C#] [holly-hacker/eazfixer](https://github.com/holly-hacker/eazfixer) A deobfuscation tool for Eazfuscator.
- [**96**Star][3m] [C++] [marcosd4h/sysmonx](https://github.com/marcosd4h/sysmonx) An Augmented Drop-In Replacement of Sysmon
- [**95**Star][7m] [C#] [virb3/de4dot-cex](https://github.com/virb3/de4dot-cex) de4dot deobfuscator with full support for vanilla ConfuserEx
- [**94**Star][1m] [PHP] [cybercog/laravel-optimus](https://github.com/cybercog/laravel-optimus) Transform your internal id's to obfuscated integers based on Knuth's integer hash.
- [**89**Star][2y] [PowerShell] [danielbohannon/out-fincodedcommand](https://github.com/danielbohannon/out-fincodedcommand) POC Highlighting Obfuscation Techniques used by FIN threat actors based on cmd.exe's replace functionality and cmd.exe/powershell.exe's stdin command invocation capabilities
- [**83**Star][10m] [C++] [basketwill/sysmon_reverse](https://github.com/basketwill/sysmon_reverse) 
- [**80**Star][3m] [blockchainlabsnz/awesome-solidity](https://github.com/blockchainlabsnz/awesome-solidity) A curated list of awesome Solidity resources
- [**80**Star][3m] [sbousseaden/panache_sysmon](https://github.com/sbousseaden/panache_sysmon) A Sysmon Config for APTs Techniques Detection
- [**79**Star][4m] [Assembly] [thecodeartist/elf-parser](https://github.com/thecodeartist/elf-parser) Identifying/Extracting various sections of an ELF file
- [**70**Star][3y] [Py] [antelox/fopo-php-deobfuscator](https://github.com/antelox/fopo-php-deobfuscator) A simple script to deobfuscate PHP file obfuscated with FOPO Obfuscator -
- [**66**Star][2y] [Py] [sapir/sonare](https://github.com/sapir/sonare) A Qt-based disassembly viewer based on radare2
- [**66**Star][4m] [splunk/ta-microsoft-sysmon](https://github.com/splunk/ta-microsoft-sysmon) TA-microsoft-sysmon
- [**64**Star][10m] [Zeek] [salesforce/bro-sysmon](https://github.com/salesforce/bro-sysmon) How to Zeek Sysmon Logs!
- [**60**Star][1y] [Java] [java-deobfuscator/deobfuscator-gui](https://github.com/java-deobfuscator/deobfuscator-gui) An awesome GUI for an awesome deobfuscator
- [**60**Star][4y] [Objective-C++] [steven-michaud/reverse-engineering-on-osx](https://github.com/steven-michaud/reverse-engineering-on-osx) Reverse Engineering on OS X
- [**56**Star][1y] [Nix] [dapphub/ds-auth](https://github.com/dapphub/ds-auth) Updatable, unobtrusive Solidity authorization pattern
- [**55**Star][5m] [basketwill/z0bpctools](https://github.com/basketwill/z0bpctools) 一个windows反汇编工具，界面风格防OllyDbg 利用业余开发了一款类似仿OLlyDbg界面的 IDA静态反编译工具，目前是1.0版本，功能不是很强大但是基本功能有了
- [**55**Star][6m] [TypeScript] [geeksonsecurity/illuminatejs](https://github.com/geeksonsecurity/illuminatejs) IlluminateJs is a static JavaScript deobfuscator
- [**55**Star][2y] [TeX] [season-lab/survey-symbolic-execution](https://github.com/season-lab/survey-symbolic-execution) 对有关符号执行相关工具和技术的调查
- [**55**Star][2m] [C] [resilar/crchack](https://github.com/resilar/crchack) Reversing CRC for fun and profit
- [**53**Star][7y] [C++] [eschweiler/proreversing](https://github.com/eschweiler/proreversing) Open and generic Anti-Anti Reversing Framework. Works in 32 and 64 bits.
- [**53**Star][3y] [PowerShell] [elevenpaths/telefonica-wannacry-filerestorer](https://github.com/elevenpaths/telefonica-wannacry-filerestorer) Tool to restore some WannaCry files which encryption weren't finish properly
- [**52**Star][10m] [Assembly] [pret/pokepinball](https://github.com/pret/pokepinball) disassembly of pokémon pinball
- [**50**Star][2y] [JS] [ericr/sol-function-profiler](https://github.com/ericr/sol-function-profiler) Solidity Contract Function Profiler
- [**50**Star][2y] [Py] [sfwishes/ollvm_de_fla](https://github.com/sfwishes/ollvm_de_fla) deobfuscation ollvm's fla
- [**49**Star][12d] [C] [danielkrupinski/vac](https://github.com/danielkrupinski/vac) Source code of Valve Anti-Cheat obtained from disassembly of compiled modules
- [**47**Star][5y] [jameshabben/sysmon-queries](https://github.com/jameshabben/sysmon-queries) Queries to parse sysmon event log file with microsoft logparser
- [**47**Star][6m] [C++] [talvos/talvos](https://github.com/talvos/talvos) Talvos is a dynamic-analysis framework and debugger for Vulkan/SPIR-V programs.
- [**45**Star][2m] [Assembly] [drenn1/oracles-disasm](https://github.com/Drenn1/oracles-disasm) Disassembly of Oracle of Ages and Seasons
- [**41**Star][2y] [C] [cocoahuke/mackextdump](https://github.com/cocoahuke/mackextdump) mackextdump：从macOS中dump Kext信息
- [**41**Star][2m] [Lua] [dsasmblr/cheat-engine](https://github.com/dsasmblr/cheat-engine) Cheat Engine scripts, tutorials, tools, and more.
- [**39**Star][1y] [Py] [dissectmalware/batch_deobfuscator](https://github.com/dissectmalware/batch_deobfuscator) Deobfuscate batch scripts obfuscated using string substitution and escape character techniques.
- [**39**Star][2m] [jsecurity101/windows-api-to-sysmon-events](https://github.com/jsecurity101/windows-api-to-sysmon-events) A repository that maps API calls to Sysmon Event ID's.
- [**36**Star][2y] [Py] [extremecoders-re/pjorion-deobfuscator](https://github.com/extremecoders-re/pjorion-deobfuscator) A deobfuscator for PjOrion, python cfg generator and more
- [**36**Star][4m] [Assembly] [marespiaut/rayman_disasm](https://github.com/marespiaut/rayman_disasm) Reverse-engineering effort for the 1995 MS-DOS game “Rayman”
- [**36**Star][3y] [C++] [steven-michaud/sandboxmirror](https://github.com/steven-michaud/sandboxmirror) Tool for reverse-engineering Apple's sandbox
- [**35**Star][4y] [C#] [bnagy/crabstone](https://github.com/bnagy/crabstone) crabstone is a Ruby binding to the capstone disassembly library by Nguyen Anh Quynh
- [**35**Star][2y] [Py] [extremecoders-re/bytecode_simplifier](https://github.com/extremecoders-re/bytecode_simplifier) A generic deobfuscator for PjOrion obfuscated python scripts
- [**34**Star][3y] [C] [topcss/wannacry](https://github.com/topcss/wannacry) 勒索病毒WannaCry反编译源码
- [**33**Star][11m] [Objective-C] [jakeajames/reverse-engineering](https://github.com/jakeajames/reverse-engineering) nothing important
- [**33**Star][6y] [JS] [michenriksen/hackpad](https://github.com/michenriksen/hackpad) A web application hacker's toolbox. Base64 encoding/decoding, URL encoding/decoding, MD5/SHA1/SHA256/HMAC hashing, code deobfuscation, formatting, highlighting and much more.
- [**32**Star][1y] [mhaggis/sysmon-splunk-app](https://github.com/mhaggis/sysmon-splunk-app) Sysmon Splunk App
- [**31**Star][4y] [Pascal] [pigrecos/codedeobfuscator](https://github.com/pigrecos/codedeobfuscator) Code Deobfuscator
- [**30**Star][3y] [mhaggis/app_splunk_sysmon_hunter](https://github.com/mhaggis/app_splunk_sysmon_hunter) Splunk App to assist Sysmon Threat Hunting
- [**29**Star][2y] [C++] [nuand/kalibrate-bladerf](https://github.com/nuand/kalibrate-bladerf) kalibrate-bladeRF
- [**27**Star][2m] [JS] [b-mueller/sabre](https://github.com/b-mueller/sabre) Security analyzer for Solidity smart contracts. Uses MythX, the premier smart contract security service.
- [**27**Star][1m] [C] [usineur/sdlpop](https://github.com/usineur/SDLPoP) An open-source port of Prince of Persia, based on the disassembly of the DOS version.
- [**24**Star][5y] [JS] [vector35/hackinggames](https://github.com/vector35/hackinggames) Hacking Games in a Hacked Game
- [**22**Star][2y] [Py] [zigzag2050/mzphp2-deobfuscator](https://github.com/zigzag2050/mzphp2-deobfuscator) A de-obfuscate tool for code generated by mzphp2. 用于解混淆mzphp2加密的php文件的工具。
- [**21**Star][28d] [Py] [verabe/veriman](https://github.com/verabe/veriman) Analysis tool for Solidity smart contracts. Prototype.
- [**20**Star][1y] [Batchfile] [olafhartong/ta-sysmon-deploy](https://github.com/olafhartong/ta-sysmon-deploy) Deploy and maintain Symon through the Splunk Deployment Sever
- [**20**Star][1y] [Lua] [yoshifan/ram-watch-cheat-engine](https://github.com/yoshifan/ram-watch-cheat-engine) Lua script framework for RAM watch displays using Cheat Engine, with a focus on Dolphin emulator.


***


## <a id="4fe330ae3e5ce0b39735b1bfea4528af"></a>angr


- [**526**Star][7d] [Py] [angr/angr-doc](https://github.com/angr/angr-doc) Documentation for the angr suite
- [**192**Star][11d] [Py] [angr/angr-management](https://github.com/angr/angr-management) A GUI for angr. Being developed *very* slowly.
- [**121**Star][12m] [Py] [axt/angr-utils](https://github.com/axt/angr-utils) Handy utilities for the angr binary analysis framework, most notably CFG visualization
- [**112**Star][5m] [Py] [andreafioraldi/angrgdb](https://github.com/andreafioraldi/angrgdb) Use angr inside GDB. Create an angr state from the current debugger state.
- [**91**Star][1y] [Py] [fsecurelabs/z3_and_angr_binary_analysis_workshop](https://github.com/FSecureLABS/z3_and_angr_binary_analysis_workshop) Code and exercises for a workshop on z3 and angr
- [**64**Star][1m] [Shell] [angr/angr-dev](https://github.com/angr/angr-dev) Some helper scripts to set up an environment for angr development.
- [**60**Star][4y] [Shell] [praetorian-code/epictreasure](https://github.com/praetorian-code/epictreasure) radare, angr, pwndbg, binjitsu, ect in a box ready for pwning
- [**47**Star][1y] [Py] [ercoppa/symbolic-execution-tutorial](https://github.com/ercoppa/symbolic-execution-tutorial) Tutorial on Symbolic Execution. Hands-on session is based on the angr framework.
- [**33**Star][1m] [Py] [angr/angr-platforms](https://github.com/angr/angr-platforms) A collection of extensions to angr to handle new platforms
- [**30**Star][27d] [C] [angr/binaries](https://github.com/angr/binaries) A repository with binaries for angr tests and examples.
- [**25**Star][6m] [Py] [andreafioraldi/r2angrdbg](https://github.com/andreafioraldi/r2angrdbg) 在 radare2 调试器中使用 angr
- [**23**Star][4y] [bannsec/angr-windows](https://github.com/bannsec/angr-Windows) Windows builds for use with angr framework
- [**22**Star][4m] [Py] [fmagin/angr-cli](https://github.com/fmagin/angr-cli) Repo for various angr ipython features to give it more of a cli feeling
- [**19**Star][2y] [Py] [brandon-everhart/angryida](https://github.com/brandon-everhart/angryida) Python based angr plug in for IDA Pro.
    - Also In Section: [IDA->Tools->ImportExport->NoCategory](#8ad723b704b044e664970b11ce103c09) |


***


## <a id="324874bb7c3ead94eae6f1fa1af4fb68"></a>Debug


- [**1545**Star][6y] [Py] [google/pyringe](https://github.com/google/pyringe) Debugger capable of attaching to and injecting code into python processes.
- [**1430**Star][7d] [Go] [google/gapid](https://github.com/google/gapid) Graphics API Debugger
- [**1410**Star][8d] [Go] [cosmos72/gomacro](https://github.com/cosmos72/gomacro) Interactive Go interpreter and debugger with REPL, Eval, generics and Lisp-like macros
- [**1402**Star][7d] [C++] [eteran/edb-debugger](https://github.com/eteran/edb-debugger) edb is a cross platform AArch32/x86/x86-64 debugger.
- [**1374**Star][4y] [C++] [valvesoftware/vogl](https://github.com/valvesoftware/vogl) OpenGL capture / playback debugger.
- [**1262**Star][3m] [Go] [solo-io/squash](https://github.com/solo-io/squash) The debugger for microservices
- [**1142**Star][4m] [C++] [cgdb/cgdb](https://github.com/cgdb/cgdb) Console front-end to the GNU debugger
- [**1110**Star][18d] [C] [blacksphere/blackmagic](https://github.com/blacksphere/blackmagic) In application debugger for ARM Cortex microcontrollers.
- [**868**Star][5m] [Py] [derekselander/lldb](https://github.com/derekselander/lldb) A collection of LLDB aliases/regexes and Python scripts to aid in your debugging sessions
- [**822**Star][7d] [C++] [tasvideos/bizhawk](https://github.com/tasvideos/bizhawk) BizHawk is a multi-system emulator written in C#. BizHawk provides nice features for casual gamers such as full screen, and joypad support in addition to full rerecording and debugging tools for all system cores.
- [**708**Star][2y] [Go] [sidkshatriya/dontbug](https://github.com/sidkshatriya/dontbug) Dontbug is a reverse debugger for PHP
- [**623**Star][3y] [C] [chokepoint/azazel](https://github.com/chokepoint/azazel) Azazel is a userland rootkit based off of the original LD_PRELOAD technique from Jynx rootkit. It is more robust and has additional features, and focuses heavily around anti-debugging and anti-detection.
- [**573**Star][4y] [C++] [microsoft/iediagnosticsadapter](https://github.com/microsoft/iediagnosticsadapter) IE Diagnostics Adapter is a standalone exe that enables tools to debug and diagnose IE11 using the Chrome remote debug protocol.
- [**557**Star][1m] [C#] [microsoft/miengine](https://github.com/microsoft/miengine) The Visual Studio MI Debug Engine ("MIEngine") provides an open-source Visual Studio Debugger extension that works with MI-enabled debuggers such as gdb, lldb, and clrdbg.
- [**519**Star][1y] [C] [wubingzheng/memleax](https://github.com/wubingzheng/memleax) debugs memory leak of running process. Not maintained anymore, try `libleak` please.
- [**460**Star][4m] [C++] [emoon/prodbg](https://github.com/emoon/prodbg) Debugging the way it's meant to be done
- [**431**Star][4y] [C] [alonho/pytrace](https://github.com/alonho/pytrace) pytrace is a fast python tracer. it records function calls, arguments and return values. can be used for debugging and profiling.
- [**415**Star][2m] [C++] [simonkagstrom/kcov](https://github.com/simonkagstrom/kcov) Code coverage tool for compiled programs, Python and Bash which uses debugging information to collect and report data without special compilation options
- [**399**Star][3m] [C++] [cobaltfusion/debugviewpp](https://github.com/cobaltfusion/debugviewpp) DebugView++, collects, views, filters your application logs, and highlights information that is important to you!
- [**353**Star][2y] [C++] [glsl-debugger/glsl-debugger](https://github.com/glsl-debugger/glsl-debugger) GLSL source level debugger.
- [**353**Star][8y] [Py] [openrce/pydbg](https://github.com/openrce/pydbg) A pure-python win32 debugger interface.
- [**336**Star][20d] [Py] [pdbpp/pdbpp](https://github.com/pdbpp/pdbpp) pdb++, a drop-in replacement for pdb (the Python debugger)
- [**331**Star][8m] [Py] [romanvm/python-web-pdb](https://github.com/romanvm/python-web-pdb) Web-based remote UI for Python's PDB debugger
- [**306**Star][25d] [Java] [widdix/aws-s3-virusscan](https://github.com/widdix/aws-s3-virusscan) Free Antivirus for S3 Buckets
- [**287**Star][3y] [C++] [develbranch/tinyantivirus](https://github.com/develbranch/tinyantivirus) TinyAntivirus is an open source antivirus engine designed for detecting polymorphic virus and disinfecting it.
- [**287**Star][2m] [Py] [sosreport/sos](https://github.com/sosreport/sos) A unified tool for collecting system logs and other debug information
- [**285**Star][2y] [Java] [cnfree/eclipse-class-decompiler](https://github.com/cnfree/eclipse-class-decompiler) Eclipse Class Decompiler integrates JD, Jad, FernFlower, CFR, Procyon seamlessly with Eclipse and allows Java developers to debug class files without source code directly
- [**279**Star][1m] [C++] [changeofpace/viviennevmm](https://github.com/changeofpace/viviennevmm) VivienneVMM is a stealthy debugging framework implemented via an Intel VT-x hypervisor.
- [**269**Star][3m] [Py] [mariovilas/winappdbg](https://github.com/mariovilas/winappdbg) WinAppDbg Debugger
- [**267**Star][4y] [C] [blankwall/macdbg](https://github.com/blankwall/macdbg) Simple easy to use C and python debugging framework for OSX
- [**267**Star][11m] [Py] [ionelmc/python-manhole](https://github.com/ionelmc/python-manhole) Debugging manhole for python applications.
- [**254**Star][3y] [Py] [airsage/petrel](https://github.com/airsage/petrel) Tools for writing, submitting, debugging, and monitoring Storm topologies in pure Python
- [**249**Star][2y] [Py] [dbgx/lldb.nvim](https://github.com/dbgx/lldb.nvim) Debugger integration with a focus on ease-of-use.
- [**248**Star][1m] [Py] [quantopian/qdb](https://github.com/quantopian/qdb) Quantopian Remote Debugger for Python
- [**239**Star][5m] [C++] [facebook/ds2](https://github.com/facebook/ds2) Debug server for lldb.
- [**239**Star][7m] [Py] [beeware/bugjar](https://github.com/beeware/bugjar) A interactive graphical debugger for Python code.
- [**232**Star][7m] [C++] [strivexjun/xantidebug](https://github.com/strivexjun/xantidebug) VMProtect 3.x Anti-debug Method Improved
- [**231**Star][2m] [Py] [gilligan/vim-lldb](https://github.com/gilligan/vim-lldb) lldb debugger integration plugin for vim
- [**220**Star][8m] [letoram/senseye](https://github.com/letoram/senseye) Dynamic Visual Debugging / Reverse Engineering Toolsuite
- [**215**Star][25d] [Py] [nteseyes/pylane](https://github.com/nteseyes/pylane) An python vm injector with debug tools, based on gdb.
- [**210**Star][8d] [C++] [thalium/icebox](https://github.com/thalium/icebox) Virtual Machine Introspection, Tracing & Debugging
- [**207**Star][2m] [C] [joyent/mdb_v8](https://github.com/joyent/mdb_v8) postmortem debugging for Node.js and other V8-based programs
- [**200**Star][5m] [C++] [rainers/cv2pdb](https://github.com/rainers/cv2pdb) converter of DMD CodeView/DWARF debug information to PDB files
- [**182**Star][5y] [C] [gdbinit/onyx-the-black-cat](https://github.com/gdbinit/onyx-the-black-cat) Kernel extension to disable anti-debug tricks and other useful XNU "features"
- [**178**Star][5m] [C] [therealsaumil/static-arm-bins](https://github.com/therealsaumil/static-arm-bins) 静态编译的arm二进制文件, 用于调试和运行时分析
- [**162**Star][2m] [JS] [ant4g0nist/vegvisir](https://github.com/ant4g0nist/vegvisir) 基于浏览器的LLDB 调试器
- [**162**Star][10d] [C++] [jrfonseca/drmingw](https://github.com/jrfonseca/drmingw) Postmortem debugging tools for MinGW.
- [**161**Star][13d] [C++] [devinacker/bsnes-plus](https://github.com/devinacker/bsnes-plus) debug-oriented fork of bsnes
- [**156**Star][2y] [C] [armadito/armadito-av](https://github.com/armadito/armadito-av) Armadito antivirus main repository
- [**154**Star][4y] [Py] [kbandla/immunitydebugger](https://github.com/kbandla/immunitydebugger) ImmunityDebugger
- [**151**Star][5y] [Shell] [hellman/fixenv](https://github.com/hellman/fixenv) Fix stack addresses (when no ASLR) with and without debugging
- [**151**Star][2y] [Py] [reswitched/cagetheunicorn](https://github.com/reswitched/cagetheunicorn) Debugging/emulating environment for Switch code
- [**144**Star][18d] [Py] [wenzel/pyvmidbg](https://github.com/wenzel/pyvmidbg) LibVMI-based debug server, implemented in Python. Building a guest aware, stealth and agentless full-system debugger
- [**141**Star][2y] [C++] [honorarybot/pulsedbg](https://github.com/honorarybot/pulsedbg) Hypervisor-based debugger
- [**137**Star][9m] [Py] [nh2/strace-pipes-presentation](https://github.com/nh2/strace-pipes-presentation) 利用strace+管道/socket进行调试
- [**131**Star][4y] [C] [jvoisin/pangu](https://github.com/jvoisin/pangu) Toolkit to detect/crash/attack GNU debugging-related tools
- [**124**Star][2y] [Py] [alonemonkey/antiantidebug](https://github.com/alonemonkey/antiantidebug) tweak、 lldb python for anti anti debug
- [**124**Star][4m] [Py] [igio90/uddbg](https://github.com/igio90/uddbg) A gdb like debugger that provide a runtime env to unicorn emulator and additionals features!
- [**119**Star][18d] [C++] [intel/opencl-intercept-layer](https://github.com/intel/opencl-intercept-layer) Intercept Layer for Debugging and Analyzing OpenCL Applications
- [**117**Star][4y] [Shell] [dholm/dotgdb](https://github.com/dholm/dotgdb) GDB scripts to add support for low level debugging and reverse engineering
- [**116**Star][2y] [C++] [skylined/edgedbg](https://github.com/skylined/edgedbg) A simple command line exe to start and debug the Microsoft Edge browser.
- [**109**Star][2m] [C] [david-reguera-garcia-dreg/dbgchild](https://github.com/david-reguera-garcia-dreg/dbgchild) Debug Child Process Tool (auto attach)
- [**106**Star][16d] [Pascal] [fenix01/cheatengine-library](https://github.com/fenix01/cheatengine-library) Cheat Engine Library is based on CheatEngine a debugger and coding environment particularly aimed at games, but can also be used for other purposes like debugging applications and used in schools for teaching how computers work
- [**104**Star][12d] [C] [checkpointsw/scout](https://github.com/checkpointsw/scout) Instruction based research debugger
- [**102**Star][2y] [C] [formyown/alesense-antivirus](https://github.com/formyown/alesense-antivirus) 一款拥有完整交互界面与驱动级拦截能力的开源杀毒软件
- [**96**Star][2y] [C] [cetfor/antidbg](https://github.com/cetfor/antidbg) A bunch of Windows anti-debugging tricks.
- [**95**Star][1m] [JS] [microsoftedge/jsdbg](https://github.com/microsoftedge/jsdbg) Debugging extensions for Microsoft Edge and other Chromium-based browsers
- [**86**Star][4y] [Py] [sogeti-esec-lab/lkd](https://github.com/sogeti-esec-lab/lkd) Local Kernel Debugger (LKD) is a python wrapper around dbgengine.dll
- [**86**Star][2y] [Py] [wasiher/chrome_remote_interface_python](https://github.com/wasiher/chrome_remote_interface_python) Chrome Debugging Protocol interface for Python
- [**86**Star][7y] [Py] [stevenseeley/heaper](https://github.com/stevenseeley/heaper) heaper, an advanced heap analysis plugin for Immunity Debugger
- [**85**Star][2m] [Py] [rocky/python2-trepan](https://github.com/rocky/python2-trepan) A gdb-like Python 2.x Debugger in the Trepan family
- [**82**Star][2m] [C] [taviso/cefdebug](https://github.com/taviso/cefdebug) Minimal code to connect to a CEF debugger.
- [**76**Star][23d] [stonedreamforest/mirage](https://github.com/stonedreamforest/mirage) kernel-mode Anti-Anti-Debug plugin. based on intel vt-x && ept technology
- [**69**Star][6m] [C++] [thomasthelen/antidebugging](https://github.com/thomasthelen/antidebugging) A collection of c++ programs that demonstrate common ways to detect the presence of an attached debugger.
- [**69**Star][4m] [0xd4d/dnspy-unity-mono](https://github.com/0xd4d/dnspy-unity-mono) Fork of Unity mono that's used to compile mono.dll with debugging support enabled
- [**64**Star][4m] [C++] [nccgroup/xendbg](https://github.com/nccgroup/xendbg) A feature-complete reference implementation of a modern Xen VMI debugger.
- [**63**Star][4y] [C++] [waleedassar/antidebug](https://github.com/waleedassar/antidebug) Collection Of Anti-Debugging Tricks
- [**62**Star][4y] [C#] [wintellect/procmondebugoutput](https://github.com/wintellect/procmondebugoutput) See your trace statements in Sysinternals Process Monitor
- [**59**Star][2m] [Py] [quarkslab/lldbagility](https://github.com/quarkslab/lldbagility) A tool for debugging macOS virtual machines
- [**59**Star][4y] [JS] [auth0-blog/react-flux-debug-actions-sample](https://github.com/auth0-blog/react-flux-debug-actions-sample) This repository shows how you can use Flux actions to reproduce your user's issues in your own browser
- [**57**Star][6m] [JS] [pownjs/pown-cdb](https://github.com/pownjs/pown-cdb) Automate common Chrome Debug Protocol tasks to help debug web applications from the command-line and actively monitor and intercept HTTP requests and responses.
- [**54**Star][2m] [C#] [southpolenator/sharpdebug](https://github.com/southpolenator/SharpDebug) C# debugging automation tool
- [**50**Star][2m] [C#] [smourier/tracespy](https://github.com/smourier/tracespy) TraceSpy is a pure .NET, 100% free and open source, alternative to the very popular SysInternals DebugView tool.
- [**48**Star][9m] [C++] [stoyan-shopov/troll](https://github.com/stoyan-shopov/troll) troll：ARM Cortex-M 处理器 C 语言源码调试器
- [**44**Star][1y] [C++] [alphaseclab/anti-debug](https://github.com/alphaseclab/anti-debug) 
- [**44**Star][3m] [blackint3/awesome-debugging](https://github.com/blackint3/awesome-debugging) Why Debugging?（为什么要调试？）
- [**44**Star][2y] [Py] [zedshaw/zadm4py](https://github.com/zedshaw/zadm4py) Zed's Awesome Debug Macros for Python
- [**43**Star][1y] [C++] [johnsonjason/rvdbg](https://github.com/johnsonjason/RVDbg) RVDbg is a debugger/exception handler for Windows processes and has the capability to circumvent anti-debugging techniques. (Cleaner, documented code base being worked on in: core branch)
- [**42**Star][5y] [C] [cemeyer/msp430-emu-uctf](https://github.com/cemeyer/msp430-emu-uctf) msp430 emulator for uctf (with remote GDB debugging, reverse debugging, and optional symbolic execution)
- [**42**Star][1m] [Erlang] [etnt/edbg](https://github.com/etnt/edbg) edbg：基于 tty 的 Erlang 调试/追踪接口
- [**41**Star][15d] [SystemVerilog] [azonenberg/starshipraider](https://github.com/azonenberg/starshipraider) High performance embedded systems debug/reverse engineering platform
- [**41**Star][3y] [Py] [crowdstrike/pyspresso](https://github.com/crowdstrike/pyspresso) The pyspresso package is a Python-based framework for debugging Java.
- [**41**Star][1y] [C#] [micli/netcoredebugging](https://github.com/micli/netcoredebugging) A repository maintains the book of ".NET Core application debugging" sample code.
- [**41**Star][2y] [C] [seemoo-lab/nexmon_debugger](https://github.com/seemoo-lab/nexmon_debugger) Debugger with hardware breakpoints and memory watchpoints for BCM4339 Wi-Fi chips
- [**39**Star][7y] [C] [gdbinit/gimmedebugah](https://github.com/gdbinit/gimmedebugah) A small utility to inject a Info.plist into binaries.
- [**38**Star][2y] [C] [shellbombs/strongod](https://github.com/shellbombs/strongod) StrongOD(anti anti-debug plugin) driver source code.
- [**37**Star][3y] [C] [0xbadc0de1/vmp_dbg](https://github.com/0xbadc0de1/vmp_dbg) This is a VmProtect integrated debugger, that will essentially allow you to disasm and debug vmp partially virtualized functions at the vmp bytecode level. It was made using TitanEngine for the debug engine and Qt for the gui. Do not expect much of it and feel free to report any bugs.
- [**36**Star][2y] [C] [adamgreen/mri](https://github.com/adamgreen/mri) MRI - Monitor for Remote Inspection. The gdb compatible debug monitor for Cortex-M devices.
- [**35**Star][2y] [Py] [meyer9/ethdasm](https://github.com/meyer9/ethdasm) Tool for auditing Ethereum contracts
- [**34**Star][2y] [Py] [g2p/vido](https://github.com/g2p/vido) wrap commands in throwaway virtual machines — easy kernel debugging and regression testing
- [**32**Star][3m] [C++] [imugee/xdv](https://github.com/imugee/xdv) XDV is disassembler or debugger that works based on the extension plugin.
- [**31**Star][3m] [C++] [creaink/ucom](https://github.com/creaink/ucom) A simple Serial-Port/TCP/UDP debugging tool.
- [**31**Star][1m] [C] [gdbinit/efi_dxe_emulator](https://github.com/gdbinit/efi_dxe_emulator) EFI DXE Emulator and Interactive Debugger
- [**28**Star][2y] [PowerShell] [enddo/hatdbg](https://github.com/enddo/hatdbg) Minimal WIN32 Debugger in powershell
- [**28**Star][5m] [C++] [marakew/syser](https://github.com/marakew/syser) syser debugger x32/x64 ring3
- [**28**Star][7y] [C] [jonathansalwan/vmndh-2k12](https://github.com/jonathansalwan/vmndh-2k12) Emulator, debugger and compiler for the NDH architecture - Emulator for CTF NDH 2k12
- [**27**Star][8y] [Py] [fitblip/pydbg](https://github.com/fitblip/pydbg) A pure-python win32 debugger interface.
- [**27**Star][2y] [C] [okazakinagisa/vtbaseddebuggerwin7](https://github.com/okazakinagisa/vtbaseddebuggerwin7) Simple kernelmode driver.
- [**26**Star][5y] [Py] [fireeye/pycommands](https://github.com/fireeye/pycommands) PyCommand Scripts for Immunity Debugger
- [**25**Star][3y] [C] [jacktang310/kerneldebugonnexus6p](https://github.com/jacktang310/kerneldebugonnexus6p) 
- [**24**Star][1y] [Py] [cosine0/amphitrite](https://github.com/cosine0/amphitrite) Symbolic debugging tool using JonathanSalwan/Triton
- [**23**Star][3m] [C++] [vertextoedge/windowfunctiontracer](https://github.com/vertextoedge/windowfunctiontracer) Window Executable file Function tracer using Debugging API
- [**22**Star][8m] [Py] [laanwj/dwarf_to_c](https://github.com/laanwj/dwarf_to_c) Tool to recover C headers (types, function signatures) from DWARF debug data
- [**22**Star][1y] [C#] [malcomvetter/antidebug](https://github.com/malcomvetter/antidebug) PoC: Prevent a debugger from attaching to managed .NET processes via a watcher process code pattern.
- [**22**Star][3y] [Assembly] [osandamalith/anti-debug](https://github.com/osandamalith/anti-debug) Some of the Anti-Debugging Tricks
- [**20**Star][5y] [C] [tongzeyu/hooksysenter](https://github.com/tongzeyu/hooksysenter) hook sysenter，重载内核，下硬件断点到debugport，防止debugport清零


***


## <a id="9d0f15756c4435d1ea79c21fcfda101f"></a>RecentAdd1




***


## <a id="9f8d3f2c9e46fbe6c25c22285c8226df"></a>BAP




***


## <a id="2683839f170250822916534f1db22eeb"></a>BinNavi


- [**378**Star][1m] [C++] [google/binexport](https://github.com/google/binexport) Export disassemblies into Protocol Buffers and to BinNavi databases
    - Also In Section: [IDA->Tools->ImportExport->BinNavi](#11139e7d6db4c1cef22718868f29fe12) |
- [**213**Star][4y] [PLpgSQL] [cseagle/freedom](https://github.com/cseagle/freedom) capstone based disassembler for extracting to binnavi
    - Also In Section: [IDA->Tools->ImportExport->BinNavi](#11139e7d6db4c1cef22718868f29fe12) |
- [**25**Star][7y] [Py] [tosanjay/bopfunctionrecognition](https://github.com/tosanjay/bopfunctionrecognition) plugin to BinNavi tool to analyze a x86 binanry file to find buffer overflow prone functions. Such functions are important for vulnerability analysis.
    - Also In Section: [IDA->Tools->ImportExport->BinNavi](#11139e7d6db4c1cef22718868f29fe12) |


***


## <a id="0971f295b0f67dc31b7aa45caf3f588f"></a>Decompiler


- [**20619**Star][9d] [Java] [skylot/jadx](https://github.com/skylot/jadx) Dex to Java decompiler
- [**7628**Star][22d] [Java] [java-decompiler/jd-gui](https://github.com/java-decompiler/jd-gui) A standalone Java Decompiler GUI
- [**3091**Star][1m] [Java] [deathmarine/luyten](https://github.com/deathmarine/luyten) An Open Source Java Decompiler Gui for Procyon
- [**1842**Star][1y] [Java] [jindrapetrik/jpexs-decompiler](https://github.com/jindrapetrik/jpexs-decompiler) JPEXS Free Flash Decompiler
- [**1636**Star][11m] [Java] [fesh0r/fernflower](https://github.com/fesh0r/fernflower) Unofficial mirror of FernFlower Java decompiler (All pulls should be submitted upstream)
- [**1428**Star][7d] [Py] [rocky/python-uncompyle6](https://github.com/rocky/python-uncompyle6) A cross-version Python bytecode decompiler
- [**1106**Star][1y] [Py] [wibiti/uncompyle2](https://github.com/wibiti/uncompyle2) Python 2.7 decompiler
- [**1075**Star][3m] [Py] [storyyeller/krakatau](https://github.com/storyyeller/krakatau) Java decompiler, assembler, and disassembler
- [**762**Star][11m] [C++] [comaeio/porosity](https://github.com/comaeio/porosity) *UNMAINTAINED* Decompiler and Security Analysis tool for Blockchain-based Ethereum Smart-Contracts
- [**671**Star][3y] [Batchfile] [ufologist/onekey-decompile-apk](https://github.com/ufologist/onekey-decompile-apk) 一步到位反编译apk工具(onekey decompile apk)
- [**669**Star][7d] [C#] [uxmal/reko](https://github.com/uxmal/reko) Reko is a binary decompiler.
- [**663**Star][10m] [C++] [zrax/pycdc](https://github.com/zrax/pycdc) C++ python bytecode disassembler and decompiler
- [**572**Star][2y] [C++] [zneak/fcd](https://github.com/zneak/fcd) An optimizing decompiler
- [**534**Star][5m] [Java] [java-decompiler/jd-eclipse](https://github.com/java-decompiler/jd-eclipse) A Java Decompiler Eclipse plugin
- [**532**Star][4y] [Py] [mysterie/uncompyle2](https://github.com/mysterie/uncompyle2) A Python 2.5, 2.6, 2.7 byte-code decompiler
- [**474**Star][3y] [Lua] [viruscamp/luadec](https://github.com/viruscamp/luadec) Lua Decompiler for lua 5.1 , 5.2 and 5.3
- [**389**Star][3y] [Py] [gstarnberger/uncompyle](https://github.com/gstarnberger/uncompyle) Python decompiler
- [**380**Star][3y] [C] [micrictor/stuxnet](https://github.com/micrictor/stuxnet) Open-source decompile of Stuxnet/myRTUs
- [**340**Star][1m] [C#] [steamdatabase/valveresourceformat](https://github.com/steamdatabase/valveresourceformat) Valve's Source 2 resource file format (also known as Stupid Valve Format) parser and decompiler.
- [**319**Star][25d] [C++] [silverf0x/rpcview](https://github.com/silverf0x/rpcview) RpcView is a free tool to explore and decompile Microsoft RPC interfaces
- [**309**Star][11d] [Java] [leibnitz27/cfr](https://github.com/leibnitz27/cfr) This is the public repository for the CFR Java decompiler
- [**305**Star][5y] [C++] [draperlaboratory/fracture](https://github.com/draperlaboratory/fracture) an architecture-independent decompiler to LLVM IR
- [**271**Star][7m] [Shell] [venshine/decompile-apk](https://github.com/venshine/decompile-apk)  auto decompile function for produce Java source code and resources from Android Apk files that displayed on GUI.
- [**239**Star][2m] [Java] [kwart/jd-cmd](https://github.com/kwart/jd-cmd) Command line Java Decompiler
- [**238**Star][1m] [Java] [ata4/bspsrc](https://github.com/ata4/bspsrc) A Source engine map decompiler
- [**232**Star][5y] [C] [sztupy/luadec51](https://github.com/sztupy/luadec51) Lua Decompiler for Lua version 5.1
- [**229**Star][14d] [C#] [icsharpcode/avaloniailspy](https://github.com/icsharpcode/avaloniailspy) Avalonia-based .NET Decompiler (port of ILSpy)
- [**228**Star][1y] [C++] [wwwg/wasmdec](https://github.com/wwwg/wasmdec) WebAssembly to C decompiler
- [**223**Star][24d] [C++] [boomerangdecompiler/boomerang](https://github.com/BoomerangDecompiler/boomerang) Boomerang Decompiler - Fighting the code-rot :)
- [**195**Star][12m] [C++] [cararasu/holodec](https://github.com/cararasu/holodec) Decompiler for x86 and x86-64 ELF binaries
- [**163**Star][3y] [C#] [jamesjlinden/unity-decompiled](https://github.com/jamesjlinden/unity-decompiled) 
- [**147**Star][3y] [C#] [endgameinc/py2exedecompiler](https://github.com/endgameinc/py2exedecompiler) Decompiles Exe created by Py2Exe using uncompyle6 for both python 2 and 3.
- [**136**Star][6y] [Py] [nightnord/ljd](https://github.com/nightnord/ljd) LuaJIT raw-bytecode decompiler
- [**126**Star][6y] [Lua] [bobsayshilol/luajit-decomp](https://github.com/bobsayshilol/luajit-decomp) LuaJIT decompiler
- [**107**Star][1y] [Java] [despector/despector](https://github.com/despector/despector) Java / Kotlin Decompiler and AST Library
- [**87**Star][4m] [Clojure] [clojure-goes-fast/clj-java-decompiler](https://github.com/clojure-goes-fast/clj-java-decompiler) clj-java-decompiler: 将 Clojure 反编译为 Java
- [**85**Star][4y] [C] [electrojustin/triad-decompiler](https://github.com/electrojustin/triad-decompiler) TRiad Is A Decompiler. Triad is a tiny, free and open source, Capstone based x86 decompiler for ELF binaries.
- [**85**Star][5m] [Py] [pnfsoftware/jeb2-samplecode](https://github.com/pnfsoftware/jeb2-samplecode) Sample extensions for JEB Decompiler
- [**82**Star][2y] [C++] [nemerle/dcc](https://github.com/nemerle/dcc) This is a heavily updated version of the old DOS executable decompiler DCC
- [**66**Star][1y] [PHP] [irelance/jsc-decompile-mozjs-34](https://github.com/irelance/jsc-decompile-mozjs-34) A javascript bytecode decoder for mozilla spider-monkey version 34. May decompile jsc file compile by cocos-2dx
- [**55**Star][5y] [C] [molnarg/dead0007](https://github.com/molnarg/dead0007) Decompiler for SpiderMonkey 1.8 XDR bytecode
- [**54**Star][7m] [Clojure] [bronsa/tools.decompiler](https://github.com/bronsa/tools.decompiler) A decompiler for clojure, in clojure
- [**54**Star][1m] [Py] [matt-kempster/mips_to_c](https://github.com/matt-kempster/mips_to_c) A MIPS decompiler.
- [**53**Star][7y] [Visual Basic] [vbgamer45/semi-vb-decompiler](https://github.com/vbgamer45/semi-vb-decompiler) Partial decompiler for Visual Basic. Code source of file struture infomation.
- [**42**Star][7d] [Py] [rocky/python-decompile3](https://github.com/rocky/python-decompile3) Python decompiler for 3.7+. Stripped down from uncompyle6 so we can refactor and fix up some long-standing problems
- [**40**Star][2y] [Py] [wibiti/evedec](https://github.com/wibiti/evedec) Eve Online decrypter/decompiler
- [**31**Star][2y] [Visual Basic] [dzzie/myaut_contrib](https://github.com/dzzie/myaut_contrib) mod to myaut2exe decompiler
- [**31**Star][1y] [C++] [fortiguard-lion/rpcview](https://github.com/fortiguard-lion/rpcview) RpcView is a free tool to explore and decompile Microsoft RPC interfaces
- [**28**Star][7d] [Py] [dottedmag/archmage](https://github.com/dottedmag/archmage) A reader and decompiler for files in the CHM format
- [**27**Star][11m] [Java] [minecraftforge/fernflower](https://github.com/minecraftforge/fernflower) Unofficial mirror of FernFlower Java decompiler, Subtree split of:
- [**27**Star][7d] [C++] [schdub/protodec](https://github.com/schdub/protodec) Protobuf decompiler
- [**25**Star][1y] [C#] [jeffreye/avaloniailspy](https://github.com/jeffreye/avaloniailspy) Avalonia-based .NET Decompiler (port of ILSpy)
- [**24**Star][1y] [Py] [nviso-be/decompile-py2exe](https://github.com/nviso-be/decompile-py2exe) Decompile py2exe Python 3 generated EXEs
- [**21**Star][6m] [Py] [beched/abi-decompiler](https://github.com/beched/abi-decompiler) Ethereum (EVM) smart contracts reverse engineering helper utility
- [**21**Star][1y] [C] [rfalke/decompiler-subjects](https://github.com/rfalke/decompiler-subjects) Tests cases for binary decompilers


***


## <a id="2df6d3d07e56381e1101097d013746a0"></a>Disassemble


- [**1363**Star][29d] [C] [zyantific/zydis](https://github.com/zyantific/zydis) Fast and lightweight x86/x86-64 disassembler library
- [**1347**Star][11m] [Rust] [das-labor/panopticon](https://github.com/das-labor/panopticon) A libre cross-platform disassembler.
- [**874**Star][10m] [C++] [wisk/medusa](https://github.com/wisk/medusa) An open source interactive disassembler
- [**823**Star][2m] [C++] [redasmorg/redasm](https://github.com/redasmorg/redasm) The OpenSource Disassembler
- [**819**Star][7d] [GLSL] [khronosgroup/spirv-cross](https://github.com/khronosgroup/spirv-cross)  a practical tool and library for performing reflection on SPIR-V and disassembling SPIR-V back to high level languages.
- [**688**Star][5y] [C] [vmt/udis86](https://github.com/vmt/udis86) Disassembler Library for x86 and x86-64
- [**621**Star][3m] [C] [gdabah/distorm](https://github.com/gdabah/distorm) Powerful Disassembler Library For x86/AMD64
- [**427**Star][26d] [C#] [0xd4d/iced](https://github.com/0xd4d/iced) x86/x64 disassembler, instruction decoder & encoder
- [**348**Star][21d] [Ruby] [jjyg/metasm](https://github.com/jjyg/metasm) This is the main repository for metasm, a free assembler / disassembler / compiler written in ruby
- [**268**Star][3y] [HTML] [xem/minix86](https://github.com/xem/minix86) x86 (MS-DOS) documentation, disassembler and emulator - WIP
- [**244**Star][4m] [Py] [bontchev/pcodedmp](https://github.com/bontchev/pcodedmp) A VBA p-code disassembler
- [**197**Star][5m] [Py] [athre0z/wasm](https://github.com/athre0z/wasm) WebAssembly decoder & disassembler library
- [**137**Star][7d] [C++] [grammatech/ddisasm](https://github.com/grammatech/ddisasm) A fast and accurate disassembler
- [**137**Star][2y] [Java] [tinylcy/classanalyzer](https://github.com/tinylcy/classanalyzer) A Java Class File Disassembler
- [**89**Star][5m] [Java] [llvm-but-worse/java-disassembler](https://github.com/LLVM-but-worse/java-disassembler) The Java Disassembler
- [**87**Star][8m] [Py] [blacknbunny/peanalyzer](https://github.com/blacknbunny/peanalyzer) Advanced Portable Executable File Analyzer And Disassembler 32 & 64 Bit
- [**86**Star][2y] [C++] [rmitton/goaldis](https://github.com/rmitton/goaldis) Jak & Daxter GOAL disassembler
- [**80**Star][2y] [Py] [rsc-dev/pbd](https://github.com/rsc-dev/pbd) Pbd is a Python module to disassemble serialized protocol buffers descriptors (
- [**79**Star][3y] [Py] [januzellij/hopperscripts](https://github.com/januzellij/hopperscripts) Collection of scripts I use in the Hopper disassembler
- [**68**Star][5m] [Py] [tintinweb/ethereum-dasm](https://github.com/tintinweb/ethereum-dasm) An ethereum evm bytecode disassembler and static/dynamic analysis tool
- [**64**Star][11m] [Pascal] [mahdisafsafi/univdisasm](https://github.com/mahdisafsafi/univdisasm) x86 Disassembler and Analyzer
- [**62**Star][4m] [Py] [crytic/pyevmasm](https://github.com/crytic/pyevmasm) Ethereum Virtual Machine (EVM) disassembler and assembler
- [**56**Star][18d] [Py] [rocky/python-xdis](https://github.com/rocky/python-xdis) Python cross-version bytecode library and disassembler
- [**53**Star][9d] [C++] [hasherezade/vidi](https://github.com/hasherezade/vidi) ViDi Visual Disassembler (experimental)
- [**32**Star][5m] [C++] [vector35/generate_assembler](https://github.com/vector35/generate_assembler) generate assemblers from disassemblers, 2018 jailbreak security summit talk
- [**30**Star][3y] [Py] [rmtew/peasauce](https://github.com/rmtew/peasauce) Peasauce Interactive Disassembler
- [**25**Star][2m] [HTML] [shahril96/online-assembler-disassembler](https://github.com/shahril96/online-assembler-disassembler) Online assembler and disassembler
- [**24**Star][3y] [Py] [0xbc/chiasm-shell](https://github.com/0xbc/chiasm-shell) Python-based interactive assembler/disassembler CLI, powered by Keystone/Capstone.
- [**23**Star][2y] [C++] [verideth/repen](https://github.com/verideth/repen) Simple disassembler, going to support lots of architectures. Very easy to read and understand as well :)
- [**22**Star][5y] [C#] [tophertimzen/shellcodetester](https://github.com/tophertimzen/shellcodetester) GUI Application in C# to run and disassemble shellcode


***


## <a id="975d9f08e2771fccc112d9670eae1ed1"></a>GDB


- [**6968**Star][2m] [JS] [cs01/gdbgui](https://github.com/cs01/gdbgui) Browser-based frontend to gdb (gnu debugger). Add breakpoints, view the stack, visualize data structures, and more in C, C++, Go, Rust, and Fortran. Run gdbgui from the terminal and a new tab will open in your browser.
- [**6002**Star][11d] [Py] [cyrus-and/gdb-dashboard](https://github.com/cyrus-and/gdb-dashboard) Modular visual interface for GDB in Python
- [**1343**Star][3m] [Go] [hellogcc/100-gdb-tips](https://github.com/hellogcc/100-gdb-tips) A collection of gdb tips. 100 maybe just mean many here.
- [**448**Star][2m] [Py] [scwuaptx/pwngdb](https://github.com/scwuaptx/pwngdb) gdb for pwn
- [**231**Star][26d] [JS] [bet4it/hyperpwn](https://github.com/bet4it/hyperpwn) A hyper plugin to provide a flexible GDB GUI with the help of GEF, pwndbg or peda
- [**194**Star][2y] [Py] [sqlab/symgdb](https://github.com/sqlab/symgdb) symbolic execution plugin for gdb
- [**150**Star][14d] [Py] [gdbinit/lldbinit](https://github.com/gdbinit/lldbinit) A gdbinit clone for LLDB
- [**125**Star][2m] [Py] [deroko/lldbinit](https://github.com/deroko/lldbinit) Similar implementation of .gdbinit from fG
- [**100**Star][3m] [Py] [cs01/pygdbmi](https://github.com/cs01/pygdbmi) A library to parse gdb mi output, as well as control gdb subprocesses
- [**93**Star][1m] [C] [weirdnox/emacs-gdb](https://github.com/weirdnox/emacs-gdb) GDB graphical interface for GNU Emacs
- [**87**Star][1m] [Py] [alset0326/peda-arm](https://github.com/alset0326/peda-arm) GDB plugin peda for arm
- [**78**Star][2m] [Py] [miyagaw61/exgdb](https://github.com/miyagaw61/exgdb) Extension for GDB
- [**56**Star][4m] [Py] [stef/pyrsp](https://github.com/stef/pyrsp) python implementation of the GDB Remote Serial Protocol
- [**52**Star][8y] [Py] [crossbowerbt/gdb-python-utils](https://github.com/crossbowerbt/gdb-python-utils) A library for GDB (with python support), that adds useful functions to the standard 'gdb' library.
- [**47**Star][6y] [C] [gdbinit/gdb-ng](https://github.com/gdbinit/gdb-ng) Apple's gdb fork with some fixes and enhancements
- [**46**Star][11m] [Shell] [mzpqnxow/gdb-static-cross](https://github.com/mzpqnxow/gdb-static-cross) Shell scripts, sourceable "activate" scripts and instructions for building a statically linked gdb-7.12 gdbserver using cross-compile toolchains. Includes more than 20 statically linked gdbserver executables for different architectures, byte orders and ABIs
- [**46**Star][17d] [TeX] [zxgio/gdb_gef-cheatsheet](https://github.com/zxgio/gdb_gef-cheatsheet) GDB + GEF cheatsheet for reversing binaries
- [**20**Star][6m] [Batchfile] [cldrn/insecureprogrammingdb](https://github.com/cldrn/insecureprogrammingdb) Insecure programming functions database
- [**20**Star][2y] [Py] [kelwin/peda](https://github.com/kelwin/peda) PEDA - Python Exploit Development Assistance for GDB


***


## <a id="9526d018b9815156cb001ceee36f6b1d"></a>Captcha


- [**1544**Star][3m] [PHP] [mewebstudio/captcha](https://github.com/mewebstudio/captcha) Captcha for Laravel 5 & 6
- [**623**Star][23d] [Ruby] [markets/invisible_captcha](https://github.com/markets/invisible_captcha) Simple and flexible spam protection solution for Rails applications.

- [**66**Star][2y] [PHP] [josecl/cool-php-captcha](https://github.com/josecl/cool-php-captcha) This is the official GitHub project from code.google.com/p/cool-php-captcha
- [**20**Star][11m] [Py] [fsecurelabs/captcha_cracking](https://github.com/FSecureLABS/captcha_cracking) Helper scripts and tutorial for cracking text-based CAPTCHAs


***


## <a id="bc2b78af683e7ba983205592de8c3a7a"></a>其他


- [**1528**Star][3y] [Py] [x0rz/eqgrp_lost_in_translation](https://github.com/x0rz/eqgrp_lost_in_translation) Decrypted content of odd.tar.xz.gpg, swift.tar.xz.gpg and windows.tar.xz.gpg
- [**670**Star][3y] [Py] [n1nj4sec/memorpy](https://github.com/n1nj4sec/memorpy) Python library using ctypes to search/edit windows / linux / macOS / SunOS programs memory
- [**157**Star][4y] [C#] [radiowar/nfcgui](https://github.com/radiowar/nfcgui) GUI tool for NFC protocol analysis


# <a id="86cb7d8f548ca76534b5828cb5b0abce"></a>Radare2


***


## <a id="0e08f9478ed8388319f267e75e2ef1eb"></a>Plugins&&Scripts


### <a id="ec3f0b5c2cf36004c4dd3d162b94b91a"></a>Radare2


- [**11490**Star][7d] [C] [radareorg/radare2](https://github.com/radareorg/radare2) unix-like reverse engineering framework and commandline tools


### <a id="6922457cb0d4b6b87a34caf39aa31dfe"></a>RecentAdd


- [**407**Star][5m] [Py] [itayc0hen/a-journey-into-radare2](https://github.com/itayc0hen/a-journey-into-radare2) A series of tutorials about radare2 framework from
- [**329**Star][11d] [TeX] [radareorg/radare2book](https://github.com/radareorg/radare2book) r1 book transcription to r2
- [**257**Star][3m] [Rust] [radareorg/radeco](https://github.com/radareorg/radeco) radare2-based decompiler and symbol executor
- [**256**Star][19d] [C] [radareorg/r2dec-js](https://github.com/radareorg/r2dec-js) radare2 plugin - converts asm to pseudo-C code.
- [**204**Star][2m] [PowerShell] [wiredpulse/posh-r2](https://github.com/wiredpulse/posh-r2) PowerShell - Rapid Response... For the incident responder in you!
- [**183**Star][3m] [radareorg/r2con](https://github.com/radareorg/r2con) Radare Congress Stuff
- [**175**Star][1m] [C] [radareorg/radare2-extras](https://github.com/radareorg/radare2-extras) Source graveyard and random candy for radare2
- [**152**Star][2y] [C] [ifding/radare2-tutorial](https://github.com/ifding/radare2-tutorial) Reverse Engineering using Radare2
- [**146**Star][2y] [Py] [mhelwig/apk-anal](https://github.com/mhelwig/apk-anal) Android APK analyzer based on radare2 and others.
    - Also In Section: [Android->Tools->RecentAdd1](#883a4e0dd67c6482d28a7a14228cd942) |
- [**123**Star][11m] [C] [wenzel/r2vmi](https://github.com/wenzel/r2vmi) Hypervisor-Level Debugger based on Radare2 / LibVMI, using VMI IO and debug plugins
- [**123**Star][29d] [JS] [radareorg/radare2-r2pipe](https://github.com/radareorg/radare2-r2pipe) Access radare2 via pipe from any programming language!
- [**106**Star][2y] [Py] [guedou/jupyter-radare2](https://github.com/guedou/jupyter-radare2) Just a simple radare2 Jupyter kernel
- [**98**Star][1m] [C] [radareorg/radare2-bindings](https://github.com/radareorg/radare2-bindings) Bindings of the r2 api for Valabind and friends
- [**96**Star][3y] [C] [s4n7h0/practical-reverse-engineering-using-radare2](https://github.com/s4n7h0/practical-reverse-engineering-using-radare2) Training Materials of Practical Reverse Engineering using Radare2
- [**88**Star][1y] [TeX] [zxgio/r2-cheatsheet](https://github.com/zxgio/r2-cheatsheet) Radare2 cheat-sheet
- [**78**Star][19d] [Shell] [radareorg/radare2-pm](https://github.com/radareorg/radare2-pm) Package Manager for Radare2
- [**77**Star][2y] [Py] [pinkflawd/r2graphity](https://github.com/pinkflawd/r2graphity) Creating function call graphs based on radare2 framwork, plot fancy graphs and extract behavior indicators
- [**68**Star][7d] [C] [radareorg/radare2-regressions](https://github.com/radareorg/radare2-regressions) Regression Tests for the Radare2 Reverse Engineer's Debugger
- [**67**Star][3y] [Java] [octopus-platform/bjoern](https://github.com/octopus-platform/bjoern) Binary analysis platform based on Octopus and Radare2
- [**62**Star][9m] [C] [zigzagsecurity/survival-guide-radare2](https://github.com/zigzagsecurity/survival-guide-radare2) Basic tutorials for reverse engineer with radare2
- [**61**Star][2y] [C] [tobaljackson/2017-sit-re-presentation](https://github.com/tobaljackson/2017-sit-re-presentation) Intro to radare2 presentation files.
- [**56**Star][2y] [JS] [jpenalbae/r2-scripts](https://github.com/jpenalbae/r2-scripts) Multiple radare2 rpipe scripts
- [**41**Star][3y] [C] [bluec0re/reversing-radare2](https://github.com/bluec0re/reversing-radare2) A reversing series with radare2
- [**34**Star][3y] [CSS] [monosource/radare2-explorations](https://github.com/monosource/radare2-explorations) A book on learning radare2.
- [**33**Star][2y] [Py] [guedou/r2scapy](https://github.com/guedou/r2scapy) a radare2 plugin that decodes packets with Scapy
- [**28**Star][11m] [C] [mrmacete/r2scripts](https://github.com/mrmacete/r2scripts) Collection of scripts for radare2
- [**27**Star][2y] [C] [yara-rules/r2yara](https://github.com/yara-rules/r2yara) r2yara - Module for Yara using radare2 information
- [**27**Star][10m] [radareorg/r2jp](https://github.com/radareorg/r2jp) Japanese Community of radare2
- [**26**Star][3y] [C] [monosource/radare2-explorations-binaries](https://github.com/monosource/radare2-explorations-binaries) Supplement to radare2-explorations.
- [**25**Star][3y] [Py] [gdataadvancedanalytics/r2graphity](https://github.com/gdataadvancedanalytics/r2graphity) Creating function call graphs based on radare2 framwork, plot fancy graphs and extract behavior indicators
- [**25**Star][3y] [Objective-C] [kpwn/rapd2](https://github.com/kpwn/rapd2) simple radare2 rap:// server
- [**24**Star][2y] [Rust] [sushant94/rune](https://github.com/sushant94/rune) rune - radare2 based symbolic emulator
- [**21**Star][5y] [C] [pastcompute/lca2015-radare2-tutorial](https://github.com/pastcompute/lca2015-radare2-tutorial) Examples and demos for my LCA2015 radare2 tutorial


### <a id="1a6652a1cb16324ab56589cb1333576f"></a>WithOtherTools


#### <a id="dfe53924d678f9225fc5ece9413b890f"></a>NoCategory


- [**370**Star][25d] [JS] [nowsecure/r2frida](https://github.com/nowsecure/r2frida) Radare2 and Frida better together.
    - Also In Section: [DBI->Frida->Tools->WithOtherTools->Radare2](#ac053c4da818ca587d57711d2ff66278) |
- [**79**Star][7m] [Py] [guedou/r2m2](https://github.com/guedou/r2m2) radare2 + miasm2 = ♥
- [**44**Star][11m] [Py] [nowsecure/r2lldb](https://github.com/nowsecure/r2lldb) radare2-lldb integration
- [**34**Star][11m] [CSS] [nowsecure/r2frida-book](https://github.com/nowsecure/r2frida-book) The radare2 + frida book for Mobile Application assessment
    - Also In Section: [DBI->Frida->Tools->WithOtherTools->Radare2](#ac053c4da818ca587d57711d2ff66278) |


#### <a id="1cfe869820ecc97204a350a3361b31a7"></a>IDA


- [**166**Star][11d] [C++] [radareorg/r2ghidra-dec](https://github.com/radareorg/r2ghidra-dec) Deep ghidra decompiler integration for radare2
    - Also In Section: [Ghidra->Plugins->WithOtherTools->Radare2](#e1cc732d1388084530b066c26e24887b) |
- [**125**Star][7m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [IDA->Tools->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->Tools->ImportExport->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[IDA->Tools->Function->NoCategory](#347a2158bdd92b00cd3d4ba9a0be00ae) |
- [**123**Star][1m] [Py] [radare/radare2ida](https://github.com/radare/radare2ida) Tools, documentation and scripts to move projects from IDA to R2 and viceversa
    - Also In Section: [IDA->Tools->ImportExport->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |




### <a id="f7778a5392b90b03a3e23ef94a0cc3c6"></a>GUI


- [**5850**Star][8d] [C++] [radareorg/cutter](https://github.com/radareorg/cutter) Reverse Engineering Platform powered by radare2
- [**67**Star][1y] [JS] [radareorg/radare2-webui](https://github.com/radareorg/radare2-webui) webui repository for radare2
- [**47**Star][7y] [Py] [radare/bokken](https://github.com/radare/bokken) python-gtk UI for radare2
- [**35**Star][3y] [C#] [m4ndingo/radare2gui_dotnet](https://github.com/m4ndingo/radare2gui_dotnet) Another radare2 gui for windows
- [**23**Star][1y] [c++] [dax89/r2gui](https://github.com/dax89/r2gui) Unofficial Qt5 frontend for Radare2




***


## <a id="95fdc7692c4eda74f7ca590bb3f12982"></a>Posts&&Videos


- 2019.10 [prsecurity_] [Radare2 for RE CTF](https://medium.com/p/e0163cb0466e)
- 2019.09 [securityartwork] [YaraRET (I): Carving with Radare2 & Yara](https://www.securityartwork.es/2019/09/02/yararet-i-carving-with-radare2-yara/)
- 2019.07 [freebuf] [教你使用Cutter和Radare2对APT32恶意程序流程图进行反混淆处理](https://www.freebuf.com/articles/network/208019.html)
- 2019.07 [youtube_THER_SECURITY_LAB] [0x0D - FLARE-On #3 Challenge Part 2 [Reversing with Radare2]](https://www.youtube.com/watch?v=QP9Cepdqf-o)
- 2019.07 [youtube_THER_SECURITY_LAB] [0x0C - Cutter: FLARE-On #3 Challenge Part 1 [Reversing with Radare2]](https://www.youtube.com/watch?v=hbEpVwD5rJI)
- 2019.07 [youtube_THER_SECURITY_LAB] [0x09 Cross References [Reversing with Radare2]](https://www.youtube.com/watch?v=yOtx6LL_R08)
- 2019.07 [youtube_THER_SECURITY_LAB] [0x08 Navigation [Reversing with Radare2]](https://www.youtube.com/watch?v=rkygJSjJbso)
- 2019.07 [youtube_THER_SECURITY_LAB] [0x04 Target Application [Reversing with Radare2]](https://www.youtube.com/watch?v=jlr3FablVIc)
- 2019.06 [youtube_THER_SECURITY_LAB] [0x03 Environment Setup [Reversing with Radare2]](https://www.youtube.com/watch?v=qGSFk_CkIaw)
- 2019.06 [youtube_THER_SECURITY_LAB] [0x02 What is Radare2 [Reversing with Radare2]](https://www.youtube.com/watch?v=9fLfD2fZWiA)
- 2019.06 [youtube_THER_SECURITY_LAB] [0x00 Intro [Reversing with Radare2]](https://www.youtube.com/watch?v=Lva32dXS0mU)
- 2019.06 [youtube_hitbsecconf] [#HITB2019AMS D1T3 - Overcoming Fear: Reversing With Radare2 - Arnau Gamez Montolio](https://www.youtube.com/watch?v=317dNavABKo)
- 2019.05 [X0x0FFB347] [Solving MalwareTech Shellcode challenges with some radare2 magic!](https://medium.com/p/b91c85babe4b)
- 2019.05 [360_anquanke_learning] [使用Cutter和Radare2对APT32恶意程序流程图进行反混淆处理](https://www.anquanke.com/post/id/178047/)
- 2019.04 [X0x0FFB347] [Solving MalwareTech String Challenges With Some Radare2 Magic!](https://medium.com/p/98ebd8ff0b88)
- 2019.04 [radare] [Radare2 Summer of Code 2019 Selection Results](https://radareorg.github.io/blog/posts/rsoc-2019-selection/)
- 2019.04 [radare] [Radare2 Summer of Code 2019 Selection Results](http://radare.today/posts/rsoc-2019-selection/)
- 2019.03 [sans_edu_diaryarchive] [Binary Analysis with Jupyter and Radare2](https://isc.sans.edu/forums/diary/Binary+Analysis+with+Jupyter+and+Radare2/24748/)
- 2019.02 [freebuf] [Radare2：一款类Unix命令行逆向安全框架](https://www.freebuf.com/sectool/195703.html)
- 2019.02 [radare] [Radare2 Community Survey Results](http://radare.today/posts/radare2-survey/)
- 2019.02 [radare] [Radare2 Community Survey Results](https://radareorg.github.io/blog/posts/radare2-survey/)
- 2019.01 [ly0n] [Kaspersky “Terminal.exe” crackme analysis with Radare2](http://ly0n.me/2019/01/25/kaspersky-terminal-exe-crackme-analysis-with-radare2/)
- 2019.01 [ly0n] [Kaspersky “Terminal.exe” crackme analysis with Radare2](https://paumunoz.tech/2019/01/25/kaspersky-terminal-exe-crackme-analysis-with-radare2/)
- 2019.01 [ly0n] [Reversing x64 linux code with Radare2 part II](http://ly0n.me/2019/01/14/reversing-x64-linux-code-with-radare2-part-ii/)
- 2019.01 [ly0n] [Reversing x64 linux code with Radare2 part II](https://paumunoz.tech/2019/01/14/reversing-x64-linux-code-with-radare2-part-ii/)
- 2019.01 [ly0n] [Reversing C code in x64 systems with Radare2 part I](http://ly0n.me/2019/01/10/reversing-c-code-in-x64-systems-with-radare2-part-i/)
- 2019.01 [ly0n] [Reversing C code in x64 systems with Radare2 part I](https://paumunoz.tech/2019/01/10/reversing-c-code-in-x64-systems-with-radare2-part-i/)
- 2018.10 [youtube_DEFCONConference] [DEF CON 26 CAR HACKING VILLAGE - Ben Gardiner - CAN Signal Extraction from OpenXC with Radare2](https://www.youtube.com/watch?v=UoevuAS-4dM)
- 2018.10 [youtube_PancakeNopcode] [r2con2018 - Bug Classification using radare2 - by Andrea Sindoni](https://www.youtube.com/watch?v=p8DIu81JV2g)
- 2018.10 [moveax] [Protostar: Unravel stack0 with Radare2](https://moveax.me/stack0/)
- 2018.08 [radare] [Radare2 and bioinformatics: a good match?](http://radare.today/posts/radare2-bioinformatics/)
- 2018.08 [radare] [Radare2 and bioinformatics: a good match?](https://radareorg.github.io/blog/posts/radare2-bioinformatics/)
- 2018.07 [radare] [Background Tasks in radare2](https://radareorg.github.io/blog/posts/background_tasks/)
- 2018.07 [radare] [Background Tasks in radare2](http://radare.today/posts/background_tasks/)
- 2018.07 [pediy_new_digest] [[翻译]radare2高阶](https://bbs.pediy.com/thread-229524.htm)
- 2018.07 [pediy_new_digest] [[翻译]Radare2进阶](https://bbs.pediy.com/thread-229523.htm)
- 2018.07 [pediy_new_digest] [[翻译]radare2入门](https://bbs.pediy.com/thread-229522.htm)
- 2018.06 [megabeets] [Decrypting APT33’s Dropshot Malware with Radare2 and Cutter – Part 2](https://www.megabeets.net/decrypting-dropshot-with-radare2-and-cutter-part-2/)
- 2018.06 [sans_edu_diaryarchive] [Binary analysis with Radare2](https://isc.sans.edu/forums/diary/Binary+analysis+with+Radare2/23723/)
- 2018.05 [megabeets] [Decrypting APT33’s Dropshot Malware with Radare2 and Cutter  – Part 1](https://www.megabeets.net/decrypting-dropshot-with-radare2-and-cutter-part-1/)
- 2018.04 [moveax] [Dr Von Noizeman’s Nuclear Bomb defused with Radare2](https://moveax.me/dr-von-noizemans-binary-bomb/)
- 2018.04 [reversingminds_blog] [Easy way for analyzing the GootKit banking malware with radare2](http://reversingminds-blog.logdown.com/posts/7369479)
- 2018.03 [pediy_new_digest] [[翻译]在Windows平台下的使用radare2进行调试](https://bbs.pediy.com/thread-225529.htm)
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
- 2017.12 [n0where] [Qt C++ radare2 GUI: Cutter](https://n0where.net/qt-c-radare2-gui-cutter)
- 2017.12 [radiofreerobotron] [ROPEmporium: Pivot 64-bit CTF Walkthrough With Radare2](http://radiofreerobotron.net/blog/2017/12/04/ropemporium-pivot-ctf-walkthrough2/)
- 2017.12 [youtube_PancakeNopcode] [recon2017 - Bubble Struggle Call Graph Visualization with Radare2 - by mari0n](https://www.youtube.com/watch?v=ofRP2PorryU)
- 2017.11 [radiofreerobotron] [ROPEmporium: Pivot 32-bit CTF Walkthrough With Radare2](http://radiofreerobotron.net/blog/2017/11/23/ropemporium-pivot-ctf-walkthrough/)
- 2017.11 [aliyun_xz] [Radare2使用实战](https://xz.aliyun.com/t/1515)
- 2017.11 [aliyun_xz] [Radare2使用全解](https://xz.aliyun.com/t/1514)
- 2017.11 [dustri] [Solving game2 from the badge of Black Alps 2017 with radare2](https://dustri.org/b/solving-game2-from-the-badge-of-black-alps-2017-with-radare2.html)
- 2017.10 [animal0day] [Hack.lu - HeapHeaven write-up with radare2 and pwntools (ret2libc)](https://animal0day.blogspot.com/2017/10/hacklu-heapheaven-write-up-with-radare2.html)
- 2017.10 [megabeets] [Reverse engineering a Gameboy ROM with radare2](https://www.megabeets.net/reverse-engineering-a-gameboy-rom-with-radare2/)
- 2017.09 [youtube_PancakeNopcode] [r2con2017 - Diaphora with radare2 by matalaz and pancake](https://www.youtube.com/watch?v=dAwXrUKaUsw)
- 2017.09 [dustri] [Defeating IOLI with radare2 in 2017](https://dustri.org/b/defeating-ioli-with-radare2-in-2017.html)
- 2017.08 [rkx1209] [GSoC Final: radare2 Timeless Debugger](https://rkx1209.github.io/2017/08/27/gsoc-final-report.html)
- 2017.08 [youtube_rootedconmadrid] [ABEL VALERO - Radare2 - 1.0 [Rooted CON 2017 - ENG]](https://www.youtube.com/watch?v=wCDIWllIiag)
- 2017.08 [youtube_rootedconmadrid] [ABEL VALERO - Radare2 - 1.0 [Rooted CON 2017 - ESP]](https://www.youtube.com/watch?v=Bt7WJNwXw3M)
- 2017.07 [pediy_new_digest] [[翻译]Radare2文档(1)](https://bbs.pediy.com/thread-219090.htm)
- 2017.05 [n0where] [Reverse Engineering Framework: radare2](https://n0where.net/reverse-engineering-framework-radare2)
- 2017.04 [kitploit_exploit] [radare2 '/format/wasm/wasm.c' Heap Buffer Overflow Vulnerability](https://exploit.kitploit.com/2017/04/radare2-formatwasmwasmc-heap-buffer.html)
- 2017.03 [radare] [Radare2 and Capstone](https://radareorg.github.io/blog/posts/radare2-capstone/)
- 2017.03 [radare] [Radare2 and Capstone](http://radare.today/posts/radare2-capstone/)
- 2017.03 [xpnsec_blog] [Radare2 - Using Emulation To Unpack Metasploit Encoders](https://blog.xpnsec.com/radare2-using-emulation-to-unpack-metasploit-encoders/)
- 2017.01 [youtube_PancakeNopcode] [Reversing with Radare2 at OverdriveCon (unofficial periscope stream)](https://www.youtube.com/watch?v=Z_8RkFNnpJw)
- 2017.01 [youtube_PancakeNopcode] [radare2 1.0 r2con](https://www.youtube.com/watch?v=tPmyMfZSr_4)
- 2016.11 [dustri] [Radare2 at the Grehack 2016](https://dustri.org/b/radare2-at-the-grehack-2016.html)
- 2016.11 [youtube_X0x6d696368] [OpenOCD (ARC dev branch) dumping Zheino A1 firmware (with plausability check via radare2)](https://www.youtube.com/watch?v=npT2Y8DTEbI)
- 2016.10 [securityblog_gr] [Install latest radare2 on Kali](http://securityblog.gr/3791/install-latest-radare2-on-kali/)
- 2016.10 [insinuator] [Reverse Engineering With Radare2 – Part 3](https://insinuator.net/2016/10/reverse-engineering-with-radare2-part-3/)
- 2016.10 [youtube_X0x6d696368] [OpenOCD dumping WD800JG firmware via Bus Blaster ... then import into Radare2](https://www.youtube.com/watch?v=IwnPbNhd2GM)
- 2016.10 [unlogic] [FrogSEK KGM video walkthrough with radare2](http://unlogic.co.uk/2016/10/13/FrogSEK%20KGM%20video%20walkthrough%20with%20radare2/index.html)
- 2016.10 [unlogic] [FrogSEK KGM video walkthrough with radare2](https://www.unlogic.co.uk/2016/10/13/frogsek-kgm-video-walkthrough-with-radare2/)
- 2016.10 [sans_edu_diaryarchive] [Radare2: rahash2](https://isc.sans.edu/forums/diary/Radare2+rahash2/21577/)
- 2016.09 [securityblog_gr] [Disassembling functions with Radare2](http://securityblog.gr/3648/disassembling-functions-with-radare2/)
- 2016.09 [youtube_PancakeNopcode] [Presentación de radare2 en la FiberParty 2009 (spanish)](https://www.youtube.com/watch?v=4AEEKsR8JJs)
- 2016.09 [dustri] [Defeating crp-'s collide with radare2](https://dustri.org/b/defeating-crp-s-collide-with-radare2.html)
- 2016.09 [youtube_PancakeNopcode] [r2con - pwning embedded systems with radare2 by Daniel Romero](https://www.youtube.com/watch?v=u9auCsrjPBQ)
- 2016.09 [youtube_PancakeNopcode] [r2con 2016 - Jay Rosenberg - Improving PE analysis on radare2](https://www.youtube.com/watch?v=HOYVQvRuZ_M)
- 2016.09 [youtube_PancakeNopcode] [r2con 2016 - SkUaTeR patching Cidox via radare2's r2k:// on kernel demo](https://www.youtube.com/watch?v=8c-g5STp114)
- 2016.08 [insinuator] [Reverse Engineering With Radare2 – Part 2](https://insinuator.net/2016/08/reverse-engineering-with-radare2-part-2/)
- 2016.08 [insinuator] [Reverse Engineering With Radare2 – Part 1](https://insinuator.net/2016/08/reverse-engineering-with-radare2-part-1/)
- 2016.08 [radare] [Retrieving configuration of a Remote Administration Tool (Malware) with radare2 statically](http://radare.today/posts/malware-static-analysis/)
- 2016.08 [radare] [Retrieving configuration of a Remote Administration Tool (Malware) with radare2 statically](https://radareorg.github.io/blog/posts/malware-static-analysis/)
- 2016.08 [radare] [Crosscompile radare2 with dockcross](http://radare.today/posts/dockcross/)
- 2016.08 [radare] [Crosscompile radare2 with dockcross](https://radareorg.github.io/blog/posts/dockcross/)
- 2016.08 [insinuator] [Reverse Engineering With Radare2 – Intro](https://insinuator.net/2016/08/reverse-engineering-with-radare2-intro/)
- 2016.08 [youtube_PancakeNopcode] [Neuroflip's radare2 0 sidparty (2010-03-17)](https://www.youtube.com/watch?v=DBKMGWXoliU)
- 2016.06 [devit] [Diving Into Radare2](https://blog.devit.co/diving-into-radare2/)
- 2016.06 [unlogic] [crackserial_linux with radare2](http://unlogic.co.uk/2016/06/13/crackserial_linux%20with%20radare2/index.html)
- 2016.06 [unlogic] [crackserial_linux with radare2](https://www.unlogic.co.uk/2016/06/13/crackserial_linux-with-radare2/)
- 2016.06 [radare] [Radare2 Explorations: New book released!](http://radare.today/posts/radare2-explorations/)
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
- 2016.04 [youtube_PancakeNopcode] [Radare2 from A to Z @ NcN 2015](https://www.youtube.com/watch?v=fM802s0tiDw)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Phase 2](http://unlogic.co.uk/2016/04/20/Binary%20Bomb%20with%20Radare2%20-%20Phase%202/index.html)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Phase 2](https://www.unlogic.co.uk/2016/04/20/binary-bomb-with-radare2-phase-2/)
- 2016.04 [aassfxxx] [Breaking Cerber strings obfuscation with Python and radare2](http://aassfxxx.infos.st/article26/breaking-cerber-strings-obfuscation-with-python-and-radare2)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Phase 1](http://unlogic.co.uk/2016/04/14/Binary%20Bomb%20with%20Radare2%20-%20Phase%201/index.html)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Phase 1](https://www.unlogic.co.uk/2016/04/14/binary-bomb-with-radare2-phase-1/)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Prelude](http://unlogic.co.uk/2016/04/12/Binary%20Bomb%20with%20Radare2%20-%20Prelude/index.html)
- 2016.04 [unlogic] [Binary Bomb with Radare2 - Prelude](https://www.unlogic.co.uk/2016/04/12/binary-bomb-with-radare2-prelude/)
- 2016.03 [techorganic] [Radare 2 in 0x1E minutes](https://blog.techorganic.com/2016/03/08/radare-2-in-0x1e-minutes/)
- 2016.01 [freebuf] [使用Radare2和Ruby开发恶意软件配置解析器](http://www.freebuf.com/articles/system/94912.html)
- 2016.01 [dustri] [How to radare2 a fake openssh exploit](https://dustri.org/b/how-to-radare2-a-fake-openssh-exploit.html)
- 2015.12 [youtube_PancakeNopcode] [Radare2 on Apple Watch](https://www.youtube.com/watch?v=MKZCBYCMh78)
- 2015.12 [radare] [Unpacking shikata-ga-nai by scripting radare2](http://radare.today/posts/unpacking-shikata-ga-nai-by-scripting-radare2/)
- 2015.12 [radare] [Unpacking shikata-ga-nai by scripting radare2](https://radareorg.github.io/blog/posts/unpacking-shikata-ga-nai-by-scripting-radare2/)
- 2015.11 [dustri] [Exploiting exp200 from Defcamp 2015 finals with radare2](https://dustri.org/b/exploiting-exp200-from-defcamp-2015-finals-with-radare2.html)
- 2015.11 [dustri] [Reversing re200 from Defcamp (D-CTF) final 2015 with radare2](https://dustri.org/b/reversing-re200-from-defcamp-d-ctf-final-2015-with-radare2.html)
- 2015.11 [youtube_PancakeNopcode] [Radare2's September Gource](https://www.youtube.com/watch?v=gJnGlmHmQVY)
- 2015.10 [youtube_PancakeNopcode] [Skuater and ThePoPe explaining how the ESIL evaluation loop works. #radare2 #nn5ed #navajasnegras](https://www.youtube.com/watch?v=qiuLdZ9kXLY)
- 2015.08 [dustri] [Pwning exploit400 from the Nullcon 2014 CTF with radare2](https://dustri.org/b/pwning-exploit400-from-the-nullcon-2014-ctf-with-radare2.html)
- 2015.08 [dustri] [Pwning sushi from BSides Vancouver CTF with radare2](https://dustri.org/b/pwning-sushi-from-bsides-vancouver-ctf-with-radare2.html)
- 2015.05 [radare] [Defeating baby_rop with radare2](http://radare.today/posts/defeating-baby_rop-with-radare2/)
- 2015.05 [radare] [Defeating baby_rop with radare2](https://radareorg.github.io/blog/posts/defeating-baby_rop-with-radare2/)
- 2015.05 [radare] [Using radare2 to pwn things](http://radare.today/posts/using-radare2/)
- 2015.05 [radare] [Using radare2 to pwn things](https://radareorg.github.io/blog/posts/using-radare2/)
- 2015.04 [dustri] [Exploiting ezhp (pwn200) from PlaidCTF 2014 with radare2](https://dustri.org/b/exploiting-ezhp-pwn200-from-plaidctf-2014-with-radare2.html)
- 2015.04 [youtube_PancakeNopcode] [Radare2 debugger swipe on UbuntuTouch](https://www.youtube.com/watch?v=QrTHvJ3MSt8)
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


# <a id="afb7259851922935643857c543c4b0c2"></a>BinaryNinja


***


## <a id="3034389f5aaa9d7b0be6fa7322340aab"></a>Plugins&&Scripts


### <a id="a750ac8156aa0ff337a8639649415ef1"></a>RecentAdd


- [**2787**Star][17d] [Py] [androguard/androguard](https://github.com/androguard/androguard) Reverse engineering, Malware and goodware analysis of Android applications ... and more (ninja !)
- [**498**Star][4y] [Py] [vector35/deprecated-binaryninja-python](https://github.com/vector35/deprecated-binaryninja-python) Deprecated Binary Ninja prototype written in Python
- [**320**Star][10d] [Py] [vector35/binaryninja-api](https://github.com/vector35/binaryninja-api) Public API, examples, documentation and issues for Binary Ninja
- [**279**Star][2m] [Py] [pbiernat/ripr](https://github.com/pbiernat/ripr) Package Binary Code as a Python class using Binary Ninja and Unicorn Engine
- [**185**Star][10d] [JS] [ret2got/disasm.pro](https://github.com/ret2got/disasm.pro) A realtime assembler/disassembler (formerly known as disasm.ninja)
- [**175**Star][6m] [Py] [trailofbits/binjascripts](https://github.com/trailofbits/binjascripts) Scripts for Binary Ninja
- [**141**Star][2y] [Py] [snare/binjatron](https://github.com/snare/binjatron) Binary Ninja plugin for Voltron integration
- [**94**Star][3y] [appsecco/defcon24-infra-monitoring-workshop](https://github.com/appsecco/defcon24-infra-monitoring-workshop) Defcon24 Workshop Contents : Ninja Level Infrastructure Monitoring
- [**85**Star][3y] [Py] [vector35/binaryninja-plugins](https://github.com/vector35/binaryninja-plugins) Repository to track Binary Ninja Plugins, Themes, and other related tools
- [**56**Star][2m] [Py] [forallsecure/bncov](https://github.com/forallsecure/bncov) Scriptable Binary Ninja plugin for coverage analysis and visualization
- [**31**Star][3y] [Py] [nopdev/binjadock](https://github.com/nopdev/binjadock) An extendable, tabbed, dockable UI widget plugin for BinaryNinja
- [**31**Star][5m] [Py] [withzombies/bnil-graph](https://github.com/withzombies/bnil-graph) A BinaryNinja plugin to graph a BNIL instruction tree
- [**30**Star][17d] [Py] [whitequark/binja_itanium_cxx_abi](https://github.com/whitequark/binja_itanium_cxx_abi) Binary Ninja Itanium C++ ABI Plugin
- [**29**Star][1y] [Py] [ernw/binja-ipython](https://github.com/ernw/binja-ipython) A plugin to integrate an IPython kernel into Binary Ninja.
- [**27**Star][5m] [Py] [fluxchief/binaryninja_avr](https://github.com/fluxchief/binaryninja_avr) Binaryninja AVR architecture plugin with lifting
- [**25**Star][3m] [Py] [trailofbits/objcgraphview](https://github.com/trailofbits/objcgraphview) A graph view plugin for Binary Ninja to visualize Objective-C
- [**24**Star][2y] [Py] [nccgroup/binja_dynamics](https://github.com/nccgroup/binja_dynamics) A PyQt5 frontend to the binjatron plugin for Binary Ninja that includes highlighting features aimed at making it easier for beginners to learn about reverse engineering
- [**19**Star][3m] [Py] [joshwatson/binaryninja-msp430](https://github.com/joshwatson/binaryninja-msp430) msp430 Architecture plugin for Binary Ninja
- [**18**Star][2y] [Py] [joshwatson/binaryninja-bookmarks](https://github.com/joshwatson/binaryninja-bookmarks) Plugin for BinaryNinja that provides bookmarking functionality
- [**18**Star][11m] [Py] [transferwise/pg_ninja](https://github.com/transferwise/pg_ninja) The ninja elephant obfuscation and replica tool
- [**17**Star][2y] [Py] [extremecoders-re/bnpy](https://github.com/extremecoders-re/bnpy) An architecture plugin for binary ninja to disassemble raw python bytecode
- [**16**Star][1y] [Py] [lunixbochs/bnrepl](https://github.com/lunixbochs/bnrepl) Run your Binary Ninja Python console in a separate Terminal window.
- [**16**Star][3y] [Py] [rootbsd/binaryninja_plugins](https://github.com/rootbsd/binaryninja_plugins) Binary ninja plugins
- [**15**Star][5m] [Py] [carstein/syscaller](https://github.com/carstein/syscaller) Binary Ninja Syscall Annotator
- [**15**Star][3y] [Py] [orndorffgrant/bnhook](https://github.com/orndorffgrant/bnhook) binary ninja plugin for adding custom hooks to executables
- [**15**Star][5m] [Py] [zznop/bn-genesis](https://github.com/zznop/bn-genesis) Binary Ninja plugin suite for SEGA Genesis ROM hacking
- [**14**Star][3y] [Py] [coldheat/liil](https://github.com/coldheat/liil) Linear IL view for Binary Ninja
- [**12**Star][2y] [Py] [gitmirar/binaryninjayaraplugin](https://github.com/gitmirar/binaryninjayaraplugin) Yara Plugin for Binary Ninja
- [**12**Star][7m] [Py] [ktn1990/cve-2019-10869](https://github.com/ktn1990/cve-2019-10869) (Wordpress) Ninja Forms File Uploads Extension <= 3.0.22 – Unauthenticated Arbitrary File Upload
- [**10**Star][2y] [Py] [chokepoint/bnpincoverage](https://github.com/chokepoint/bnpincoverage) Visually analyze basic block code coverage in Binary Ninja using Pin output.
- [**10**Star][5y] [Py] [emileaben/scapy-dns-ninja](https://github.com/emileaben/scapy-dns-ninja) Minimal DNS answering machine, for customized/programmable answers
- [**10**Star][2m] [Py] [zznop/bn-brainfuck](https://github.com/zznop/bn-brainfuck) Brainfuck architecture module and loader for Binary Ninja
- [**9**Star][9m] [Py] [manouchehri/binaryninja-radare2](https://github.com/manouchehri/binaryninja-radare2) DEPRECIATED
- [**8**Star][2y] [Py] [cah011/binja-avr](https://github.com/cah011/binja-avr) AVR assembly plugin for Binary Ninja
- [**8**Star][5m] [Py] [joshwatson/binaryninja-microcorruption](https://github.com/joshwatson/binaryninja-microcorruption) BinaryView Plugin for Microcorruption CTF memory dumps
- [**8**Star][3m] [Py] [whitequark/binja-i8086](https://github.com/whitequark/binja-i8086) 16-bit x86 architecture for Binary Ninja
- [**7**Star][12m] [Py] [rick2600/xref_call_finder](https://github.com/rick2600/xref_call_finder) Plugin for binary ninja to find calls to function recursively
- [**6**Star][1y] [Py] [kudelskisecurity/binaryninja_cortex](https://github.com/kudelskisecurity/binaryninja_cortex) A Binary Ninja plugin to load Cortex-based MCU firmware


### <a id="bba1171ac550958141dfcb0027716f41"></a>WithOtherTools


#### <a id="c2f94ad158b96c928ee51461823aa953"></a>NoCategory


- [**148**Star][1y] [Py] [hugsy/binja-retdec](https://github.com/hugsy/binja-retdec) Binary Ninja plugin to decompile binaries using RetDec API
- [**8**Star][2m] [Py] [bowline90/binrida](https://github.com/bowline90/binrida) Plugin for Frida in Binary Ninja
    - Also In Section: [DBI->Frida->Tools->WithOtherTools->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |


#### <a id="713fb1c0075947956651cc21a833e074"></a>IDA


- [**68**Star][8m] [Py] [lunixbochs/revsync](https://github.com/lunixbochs/revsync) realtime cross-tool collaborative reverse engineering
    - Also In Section: [IDA->Tools->ImportExport->BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a) |
- [**60**Star][5m] [Py] [zznop/bnida](https://github.com/zznop/bnida) Suite of plugins that provide the ability to transfer analysis data between Binary Ninja and IDA
    - Also In Section: [IDA->Tools->ImportExport->BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a) |
    - [ida_export](https://github.com/zznop/bnida/blob/master/ida/ida_export.py) 将数据从IDA中导入
    - [ida_import](https://github.com/zznop/bnida/blob/master/ida/ida_import.py) 将数据导入到IDA
    - [binja_export](https://github.com/zznop/bnida/blob/master/binja_export.py) 将数据从BinaryNinja中导出
    - [binja_import](https://github.com/zznop/bnida/blob/master/binja_import.py) 将数据导入到BinaryNinja
- [**14**Star][5m] [Py] [cryptogenic/idc_importer](https://github.com/cryptogenic/idc_importer) A Binary Ninja plugin for importing IDC database dumps from IDA.
    - Also In Section: [IDA->Tools->ImportExport->BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a) |






***


## <a id="2d24dd6f0c01a084e88580ad22ce5b3c"></a>Posts&&Videos


- 2018.09 [aliyun_xz] [使用Binary Ninja调试共享库](https://xz.aliyun.com/t/2826)
- 2018.09 [kudelskisecurity] [Analyzing ARM Cortex-based MCU firmwares using Binary Ninja](https://research.kudelskisecurity.com/2018/09/25/analyzing-arm-cortex-based-mcu-firmwares-using-binary-ninja/)
- 2018.04 [trailofbits] [Vulnerability Modeling with Binary Ninja](https://blog.trailofbits.com/2018/04/04/vulnerability-modeling-with-binary-ninja/)
- 2018.01 [pediy_new_digest] [[翻译]逆向平台Binary Ninja介绍](https://bbs.pediy.com/thread-224141.htm)
- 2017.11 [_0xec] [bnpy - A python architecture plugin for Binary Ninja](https://0xec.blogspot.com/2017/11/bnpy-python-architecture-plugin-for.html)
- 2017.10 [ret2] [Untangling Exotic Architectures with Binary Ninja](http://blog.ret2.io/2017/10/17/untangling-exotic-architectures-with-binary-ninja/)
- 2017.10 [chokepoint] [Pin Visual Coverage Tool for Binary Ninja](http://www.chokepoint.net/2017/10/pin-visual-coverage-tool-for-binary.html)


# <a id="dd1e42d17eefb275a804584a848b82a6"></a>Posts&&Videos


***


## <a id="48d6a0efe043af4bed4cbba665a4502c"></a>RecentAdd




# <a id="747ddaa20f643da415284bfba9cda3a2"></a>VM&&Emulator


***


## <a id="796b64906655228d8a1ff8c0dd390451"></a>QEMU


### <a id="296c7f25266b25e5ee1107dd76e40dd2"></a>Tools


#### <a id="82072558d99a6cf23d4014c0ae5b420a"></a>RecentAdd


- [**518**Star][7m] [Java] [limboemu/limbo](https://github.com/limboemu/limbo) Limbo is a QEMU-based emulator for Android. It currently supports PC & ARM emulation for Intel x86 and ARM architecture. See our wiki
    - Also In Section: [Android->Tools->Emulator](#5afa336e229e4c38ad378644c484734a) |
- [**273**Star][19d] [C] [beckus/qemu_stm32](https://github.com/beckus/qemu_stm32) QEMU with an STM32 microcontroller implementation
- [**242**Star][10m] [C++] [revng/revng](https://github.com/revng/revng) the core repository of the rev.ng project (mirror)
- [**99**Star][2y] [C] [comsecuris/luaqemu](https://github.com/comsecuris/luaqemu) QEMU-based framework exposing several of QEMU-internal APIs to a LuaJIT core injected into QEMU itself. Among other things, this allows fast prototyping of target systems without any native code and minimal effort in Lua.
- [**61**Star][1y] [C] [zhuowei/qemu](https://github.com/zhuowei/qemu) Patched version of QEMU for exploring XNU arm64 emulation.
- [**43**Star][2y] [Shell] [stayliv3/embedded-device-lab](https://github.com/stayliv3/embedded-device-lab) embedded-device-lab是一个利用qemu模拟真实世界中物联网漏洞的测试环境。由于物联网架构的特殊性，调试分析漏洞通常需要使用qemu模拟执行不同架构的可执行文件。而各种搭建环境，交叉编译是一件费事费力，令人忧伤的工作。 embedded-device-lab利用docker-compose，将各种漏洞调试环境一键化。简单使用两条命令，就可以直接使用gdb或者IDA动态分析相关漏洞。
- [**31**Star][2y] [C] [frederic/qemu-exynos-bootrom](https://github.com/frederic/qemu-exynos-bootrom) Emulating Exynos 4210 BootROM in QEMU




### <a id="5df30a166c2473fdadf5a578d1a70e32"></a>Post&&Videos






***


## <a id="a13effff89633708c814ae9410da835a"></a>Other




# <a id="2f81493de610f9b796656b269380b2de"></a>Windows


***


## <a id="b478e9a9a324c963da11437d18f04998"></a>Tools


### <a id="f9fad1d4d1f0e871a174f67f63f319d8"></a>新添加的




### <a id="1afda3039b4ab9a3a1f60b179ccb3e76"></a>NoCategory


- [**1288**Star][4y] [C++] [microsoft/microsoft-pdb](https://github.com/microsoft/microsoft-pdb) Information from Microsoft about the PDB format. We'll try to keep this up to date. Just trying to help the CLANG/LLVM community get onto Windows.
- [**940**Star][2m] [C] [basil00/divert](https://github.com/basil00/divert) Windows Packet Divert
- [**840**Star][21d] [C++] [henrypp/simplewall](https://github.com/henrypp/simplewall) Simple tool to configure Windows Filtering Platform (WFP) which can configure network activity on your computer.
- [**712**Star][1m] [Py] [diyan/pywinrm](https://github.com/diyan/pywinrm) Python library for Windows Remote Management (WinRM)
- [**577**Star][3y] [Pascal] [t-d-k/librecrypt](https://github.com/t-d-k/librecrypt) Transparent on-the-fly disk encryption for Windows. LUKS compatible.
- [**556**Star][11d] [C] [hfiref0x/winobjex64](https://github.com/hfiref0x/winobjex64) Windows Object Explorer 64-bit
- [**462**Star][7m] [C#] [microsoft/dbgshell](https://github.com/microsoft/dbgshell) A PowerShell front-end for the Windows debugger engine.
- [**411**Star][9d] [C] [samba-team/samba](https://github.com/samba-team/samba) he standard Windows interoperability suite of programs for Linux and Unix
- [**401**Star][3y] [C#] [zenlulz/memorysharp](https://github.com/zenlulz/memorysharp) A C# based memory editing library targeting Windows applications, offering various functions to extract and inject data and codes into remote processes to allow interoperability.
- [**400**Star][3y] [C++] [rwfpl/rewolf-wow64ext](https://github.com/rwfpl/rewolf-wow64ext) Helper library for x86 programs that runs under WOW64 layer on x64 versions of Microsoft Windows operating systems.
- [**381**Star][1m] [C#] [microsoft/binskim](https://github.com/microsoft/binskim) A binary static analysis tool that provides security and correctness results for Windows Portable Executable and *nix ELF binary formats
- [**379**Star][1m] [Jupyter Notebook] [microsoft/windowsdefenderatp-hunting-queries](https://github.com/microsoft/windowsdefenderatp-hunting-queries) Sample queries for Advanced hunting in Microsoft Defender ATP
- [**367**Star][1m] [Ruby] [winrb/winrm](https://github.com/winrb/winrm) Ruby library for Windows Remote Management
- [**364**Star][1y] [PowerShell] [netspi/pesecurity](https://github.com/netspi/pesecurity) PowerShell module to check if a Windows binary (EXE/DLL) has been compiled with ASLR, DEP, SafeSEH, StrongNaming, and Authenticode.
- [**350**Star][2y] [C++] [zerosum0x0/winrepl](https://github.com/zerosum0x0/winrepl) x86 and x64 assembly "read-eval-print loop" shell for Windows
- [**349**Star][8d] [C#] [digitalruby/ipban](https://github.com/digitalruby/ipban)  Monitors failed logins and bad behavior and bans ip addresses on Windows and Linux. Highly configurable, lean and powerful.
- [**317**Star][3y] [C] [sdhand/x11fs](https://github.com/sdhand/x11fs) A tool for manipulating X windows
- [**286**Star][2y] [C++] [godaddy/procfilter](https://github.com/godaddy/procfilter) A YARA-integrated process denial framework for Windows
- [**279**Star][1y] [C++] [fireeye/flare-wmi](https://github.com/fireeye/flare-wmi) various documentation and code projects that describe the Windows Management Instrumentation (WMI) technology
- [**277**Star][3y] [C++] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools) a small suite of tools to test various symbolic link types of Windows
- [**264**Star][11m] [Py] [hakril/pythonforwindows](https://github.com/hakril/pythonforwindows) A codebase aimed to make interaction with Windows and native execution easier
- [**233**Star][4m] [PowerShell] [microsoft/aaronlocker](https://github.com/microsoft/aaronlocker) Robust and practical application whitelisting for Windows
- [**232**Star][9m] [Go] [masterzen/winrm](https://github.com/masterzen/winrm) Command-line tool and library for Windows remote command execution in Go
- [**230**Star][12m] [C++] [ionescu007/simpleator](https://github.com/ionescu007/simpleator) Simpleator ("Simple-ator") is an innovative Windows-centric x64 user-mode application emulator that leverages several new features that were added in Windows 10 Spring Update (1803), also called "Redstone 4", with additional improvements that were made in Windows 10 October Update (1809), aka "Redstone 5".
- [**228**Star][4m] [C] [tishion/mmloader](https://github.com/tishion/mmloader) A library for loading dll module bypassing windows PE loader from memory (x86/x64)
- [**222**Star][2y] [C++] [intelpt/windowsintelpt](https://github.com/intelpt/windowsintelpt) This driver implements the Intel Processor Trace functionality in Intel Skylake architecture for Microsoft Windows
- [**220**Star][12m] [C++] [rexdf/commandtrayhost](https://github.com/rexdf/commandtrayhost) A command line program monitor systray for Windows
- [**211**Star][2m] [C] [leecher1337/ntvdmx64](https://github.com/leecher1337/ntvdmx64) Run Microsoft Windows NTVDM (DOS) on 64bit Editions
- [**209**Star][2m] [adguardteam/adguardforwindows](https://github.com/adguardteam/adguardforwindows) AdGuard for Windows open bug tracker
- [**205**Star][2m] [C] [jasonwhite/ducible](https://github.com/jasonwhite/ducible) A tool to make Windows builds reproducible.
- [**202**Star][2y] [Py] [euske/pyrexecd](https://github.com/euske/pyrexecd) Standalone SSH server for Windows
- [**202**Star][3y] [C++] [k2/ehtrace](https://github.com/k2/ehtrace) ATrace is a tool for tracing execution of binaries on Windows.
- [**201**Star][10m] [C] [hzqst/unicorn_pe](https://github.com/hzqst/unicorn_pe) Unicorn PE is an unicorn based instrumentation project designed to emulate code execution for windows PE files.
- [**193**Star][3y] [Ruby] [zed-0xff/pedump](https://github.com/zed-0xff/pedump) dump windows PE files using ruby
- [**191**Star][10m] [C] [ionescu007/winipt](https://github.com/ionescu007/winipt) The Windows Library for Intel Process Trace (WinIPT) is a project that leverages the new Intel Processor Trace functionality exposed by Windows 10 Redstone 5 (1809), through a set of libraries and a command-line tool.
- [**183**Star][18d] [C++] [blackint3/openark](https://github.com/blackint3/openark) OpenArk is a open source anti-rookit(ARK) tool on Windows.
- [**175**Star][3y] [C#] [gangzhuo/kcptun-gui-windows](https://github.com/gangzhuo/kcptun-gui-windows) GUI for kcptun (
- [**171**Star][1m] [Py] [gleeda/memtriage](https://github.com/gleeda/memtriage) Allows you to quickly query a Windows machine for RAM artifacts
- [**160**Star][24d] [PowerShell] [dsccommunity/activedirectorydsc](https://github.com/dsccommunity/ActiveDirectoryDsc) contains DSC resources for deployment and configuration of Active Directory.
- [**155**Star][3y] [C++] [zer0mem0ry/runpe](https://github.com/zer0mem0ry/runpe) Code that allows running another windows PE in the same address space as the host process.
- [**151**Star][2y] [Rust] [trailofbits/flying-sandbox-monster](https://github.com/trailofbits/flying-sandbox-monster)  sandboxes the Malware Protection engine in an AppContainer on Windows, written in Rust.
- [**149**Star][7m] [C#] [wohlstand/destroy-windows-10-spying](https://github.com/wohlstand/destroy-windows-10-spying) Destroy Windows Spying tool
- [**147**Star][1y] [C++] [justasmasiulis/nt_wrapper](https://github.com/justasmasiulis/nt_wrapper) A wrapper library around native windows sytem APIs
- [**146**Star][3y] [C] [pustladi/windows-2000](https://github.com/pustladi/windows-2000) Microsoft Windows 2000 Professional — (Source Codes)
- [**137**Star][4y] [Py] [pentestmonkey/pysecdump](https://github.com/pentestmonkey/pysecdump) Python-based tool to dump security information from Windows systems
- [**136**Star][8d] [C#] [microsoft/windowsprotocoltestsuites](https://github.com/microsoft/windowsprotocoltestsuites) Windows Protocol Test Suites provide interoperability testing against an implementation of the Windows open specifications.
- [**136**Star][6y] [C++] [zer0fl4g/nanomite](https://github.com/zer0fl4g/nanomite) Graphical Debugger for x64 and x86 on Windows
- [**135**Star][3y] [C++] [ioactive/i-know-where-your-page-lives](https://github.com/ioactive/i-know-where-your-page-lives) I Know Where Your Page Lives: Derandomizing the latest Windows 10 Kernel - ZeroNights 2016
- [**134**Star][2y] [Py] [binarydefense/auto-ossec](https://github.com/binarydefense/auto-ossec)  automatically provision OSSEC agents for both Linux and Windows
- [**133**Star][1m] [C] [nomorefood/putty-cac](https://github.com/nomorefood/putty-cac) Windows Secure Shell Client With Support For Smart Cards & Certificates
- [**132**Star][6m] [CMake] [pothosware/pothossdr](https://github.com/pothosware/pothossdr) Pothos SDR windows development environment
- [**130**Star][1y] [C++] [3gstudent/eventlogedit-evtx--evolution](https://github.com/3gstudent/eventlogedit-evtx--evolution) Remove individual lines from Windows XML Event Log (EVTX) files
- [**128**Star][2y] [Py] [dviros/rat-via-telegram](https://github.com/dviros/rat-via-telegram) Windows Remote Post Breach Tool via Telegram
- [**124**Star][5m] [Py] [fireeye/flare-qdb](https://github.com/fireeye/flare-qdb) Command-line and Python debugger for instrumenting and modifying native software behavior on Windows and Linux.
- [**115**Star][3y] [Batchfile] [bartblaze/disable-intel-amt](https://github.com/bartblaze/disable-intel-amt) Tool to disable Intel AMT on Windows
- [**112**Star][4y] [C++] [chengchengcc/ark-tools](https://github.com/chengchengcc/ark-tools) Windows Ark tools and demo
- [**112**Star][7m] [C++] [dragonquesthero/pubg-pak-hacker](https://github.com/dragonquesthero/pubg-pak-hacker) use windows kernel deriver hidden file and itself to Bypass BE
- [**110**Star][8m] [C] [wbenny/ksocket](https://github.com/wbenny/ksocket) KSOCKET provides a very basic example how to make a network connections in the Windows Driver by using WSK
- [**107**Star][5y] [C] [malwaretech/tinyxpb](https://github.com/malwaretech/tinyxpb) Windows XP 32-Bit Bootkit
- [**106**Star][2y] [C++] [zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) Hitch a free ride to Ring 0 on Windows
- [**104**Star][3m] [soffensive/windowsblindread](https://github.com/soffensive/windowsblindread) A list of files / paths to probe when arbitrary files can be read on a Microsoft Windows operating system
- [**103**Star][2y] [C++] [iceb0y/windows-container](https://github.com/iceb0y/windows-container) A lightweight sandbox for Windows application
- [**102**Star][2m] [PowerShell] [powershell/windowscompatibility](https://github.com/powershell/windowscompatibility) Module that allows Windows PowerShell Modules to be used from PSCore6
- [**101**Star][10m] [Py] [thelinuxchoice/pyrat](https://github.com/thelinuxchoice/pyrat) Windows Remote Administration Tool (RAT)
- [**100**Star][3m] [C++] [giovannidicanio/winreg](https://github.com/giovannidicanio/winreg) Convenient high-level C++ wrapper around the Windows Registry API
- [**100**Star][2y] [C] [shellster/dcsyncmonitor](https://github.com/shellster/dcsyncmonitor) Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events.
- [**96**Star][28d] [C] [libyal/libevtx](https://github.com/libyal/libevtx) Library and tools to access the Windows XML Event Log (EVTX) format
- [**96**Star][3y] [C++] [luctalpe/wmimon](https://github.com/luctalpe/wmimon) Tool to monitor WMI activity on Windows
- [**96**Star][4y] [PowerShell] [nsacyber/certificate-authority-situational-awareness](https://github.com/nsacyber/Certificate-Authority-Situational-Awareness) Identifies unexpected and prohibited certificate authority certificates on Windows systems. #nsacyber
- [**95**Star][10m] [PowerShell] [equk/windows](https://github.com/equk/windows)  tweaks for Windows
- [**95**Star][1m] [C#] [tyranid/windowsrpcclients](https://github.com/tyranid/windowsrpcclients) This respository is a collection of C# class libraries which implement RPC clients for various versions of the Windows Operating System from 7 to Windows 10.
- [**94**Star][2y] [PowerShell] [australiancybersecuritycentre/windows_event_logging](https://github.com/australiancybersecuritycentre/windows_event_logging) Windows Event Forwarding subscriptions, configuration files and scripts that assist with implementing ACSC's protect publication, Technical Guidance for Windows Event Logging.
- [**93**Star][2y] [C++] [kentonv/dvorak-qwerty](https://github.com/kentonv/dvorak-qwerty) "Dvorak-Qwerty ⌘" (DQ) keyboard layout for Windows and Unix/Linux/X
- [**88**Star][2y] [PowerShell] [realparisi/wmi_monitor](https://github.com/realparisi/wmi_monitor) Log newly created WMI consumers and processes to the Windows Application event log
- [**87**Star][18d] [Py] [ernw/windows-insight](https://github.com/ernw/windows-insight) The content of this repository aims to assist efforts on analysing inner working principles, functionalities, and properties of the Microsoft Windows operating system. This repository stores relevant documentation as well as executable files needed for conducting analysis studies.
- [**87**Star][2m] [C++] [sinakarvandi/process-magics](https://github.com/sinakarvandi/process-magics) This is a collection of interesting codes about Windows Process creation.
- [**87**Star][1y] [C] [vigem/hidguardian](https://github.com/vigem/hidguardian) Windows kernel-mode driver for controlling access to various input devices.
- [**87**Star][8y] [C] [zoloziak/winnt4](https://github.com/zoloziak/winnt4) Windows NT4 Kernel Source code
- [**86**Star][1y] [PowerShell] [deepzec/win-portfwd](https://github.com/deepzec/win-portfwd) Powershell script to setup windows port forwarding using native netsh client
- [**86**Star][1y] [C++] [malwaretech/appcontainersandbox](https://github.com/malwaretech/appcontainersandbox) An example sandbox using AppContainer (Windows 8+)
- [**86**Star][4y] [JS] [nsacyber/locklevel](https://github.com/nsacyber/LOCKLEVEL) A prototype that demonstrates a method for scoring how well Windows systems have implemented some of the top 10 Information Assurance mitigation strategies. #nsacyber
- [**84**Star][3y] [C++] [outflanknl/netshhelperbeacon](https://github.com/outflanknl/NetshHelperBeacon) Example DLL to load from Windows NetShell
- [**83**Star][2y] [Go] [snail007/autostart](https://github.com/snail007/autostart) autostart tools to set your application auto startup after desktop login,only for desktop version of linux , windows , mac.
- [**82**Star][1y] [Py] [silascutler/lnkparse](https://github.com/silascutler/lnkparse) Windows Shortcut file (LNK) parser
- [**81**Star][6m] [C] [andreybazhan/symstore](https://github.com/andreybazhan/symstore) The history of Windows Internals via symbols.
- [**81**Star][5y] [C] [nukem9/virtualdbghide](https://github.com/nukem9/virtualdbghide) Windows kernel mode driver to prevent detection of debuggers.
- [**80**Star][1m] [C] [0xcpu/winaltsyscallhandler](https://github.com/0xcpu/winaltsyscallhandler) Some research on AltSystemCallHandlers functionality in Windows 10 20H1 18999
- [**80**Star][3y] [C++] [cbayet/poolsprayer](https://github.com/cbayet/poolsprayer) Simple library to spray the Windows Kernel Pool
- [**80**Star][3y] [C++] [wpo-foundation/win-shaper](https://github.com/wpo-foundation/win-shaper) Windows traffic-shaping packet filter
- [**74**Star][2y] [C++] [eyeofra/winconmon](https://github.com/eyeofra/winconmon) Windows Console Monitoring
- [**71**Star][5y] [C#] [khr0x40sh/whitelistevasion](https://github.com/khr0x40sh/whitelistevasion) Collection of scripts, binaries and the like to aid in WhiteList Evasion on a Microsoft Windows Network.
- [**71**Star][22d] [C++] [sidyhe/dxx](https://github.com/sidyhe/dxx) Windows Kernel Driver with C++ runtime
- [**70**Star][9m] [PowerShell] [iamrootsh3ll/anchorwatch](https://github.com/iamrootsh3ll/anchorwatch) A Rogue Device Detection Script with Email Alerts Functionality for Windows Subsystem
- [**70**Star][4y] [C++] [nccgroup/windowsdaclenumproject](https://github.com/nccgroup/windowsdaclenumproject) A collection of tools to enumerate and analyse Windows DACLs
- [**69**Star][11m] [PowerShell] [itskindred/winportpush](https://github.com/itskindred/winportpush) A simple PowerShell utility used for pivoting into internal networks via a compromised Windows host.
- [**67**Star][23d] [PowerShell] [dsccommunity/certificatedsc](https://github.com/dsccommunity/CertificateDsc) This DSC Resource module can be used to simplify administration of certificates on a Windows Server.
- [**66**Star][4m] [Go] [0xrawsec/gene](https://github.com/0xrawsec/gene) Signature Engine for Windows Event Logs
- [**66**Star][3y] [C++] [nmgwddj/learn-windows-drivers](https://github.com/nmgwddj/learn-windows-drivers) Windows drivers 开发的各个基础示例，包含进程、内存、注册表、回调等管理
- [**66**Star][5y] [C++] [rwfpl/rewolf-dllpackager](https://github.com/rwfpl/rewolf-dllpackager) Simple tool to bundle windows DLLs with PE executable
- [**65**Star][1y] [C#] [parsingteam/teleshadow2](https://github.com/parsingteam/teleshadow2) TeleShadow - Telegram Desktop Session Stealer (Windows)
- [**64**Star][5m] [PowerShell] [rgl/windows-domain-controller-vagrant](https://github.com/rgl/windows-domain-controller-vagrant) Example Windows Domain Controller
- [**64**Star][8m] [C] [xiao70/x70fsd](https://github.com/xiao70/x70fsd) Windows file system filter drivers(minifilter) to encrypt, compress, or otherwise modify file-based data require some of the most complex kernel software developed for Windows.
- [**62**Star][5y] [C] [evilsocket/libpe](https://github.com/evilsocket/libpe) A C/C++ library to parse Windows portable executables written with speed and stability in mind.
- [**62**Star][4y] [Py] [poorbillionaire/windows-prefetch-parser](https://github.com/poorbillionaire/windows-prefetch-parser) Parse Windows Prefetch files: Supports XP - Windows 10 Prefetch files
- [**62**Star][1y] [tyranid/windows-attacksurface-workshop](https://github.com/tyranid/windows-attacksurface-workshop) Workshop material for a Windows Attack Surface Analysis Workshop
- [**61**Star][3y] [C++] [maldevel/driver-loader](https://github.com/maldevel/driver-loader) Windows驱动加载器
- [**61**Star][1y] [Py] [srounet/pymem](https://github.com/srounet/pymem) A python library for windows, providing the needed functions to start working on your own with memory editing.
- [**61**Star][1y] [C++] [tandasat/debuglogger](https://github.com/tandasat/debuglogger) A software driver that lets you log kernel-mode debug output into a file on Windows.
- [**60**Star][3y] [C] [arvanaghi/windows-dll-injector](https://github.com/arvanaghi/windows-dll-injector) A basic Windows DLL injector in C using CreateRemoteThread and LoadLibrary. Implemented for educational purposes.
- [**60**Star][3y] [PowerShell] [kevin-robertson/conveigh](https://github.com/kevin-robertson/conveigh) Conveigh is a Windows PowerShell LLMNR/NBNS spoofer detection tool
- [**59**Star][5y] [C] [hackedteam/soldier-win](https://github.com/hackedteam/soldier-win) RCS Soldier for Windows
- [**58**Star][4y] [Py] [psychomario/pyinject](https://github.com/psychomario/pyinject) A python module to help inject shellcode/DLLs into windows processes
- [**57**Star][6m] [PowerShell] [gnieboer/gnuradio_windows_build_scripts](https://github.com/gnieboer/gnuradio_windows_build_scripts) A series of Powershell scripts to automatically download, build from source, and install GNURadio and -all- it's dependencies as 64-bit native binaries then package as an msi using Visual Studio 2015
- [**57**Star][2y] [C#] [mch2112/sharp80](https://github.com/mch2112/sharp80) TRS80 Emulator for Windows
- [**56**Star][6y] [Assembly] [hackedteam/core-win64](https://github.com/hackedteam/core-win64) RCS Agent for Windows (64bit)
- [**56**Star][8d] [C++] [henrypp/errorlookup](https://github.com/henrypp/errorlookup) Simple tool for retrieving information about Windows errors codes.
- [**56**Star][27d] [Go] [konimarti/opc](https://github.com/konimarti/opc) OPC DA client in Golang for monitoring and analyzing process data based on Windows COM.
- [**55**Star][3y] [C#] [nccgroup/mnemosyne](https://github.com/nccgroup/mnemosyne) mnemosyne：通用Windows内存抓取工具
- [**55**Star][1y] [C#] [tyranid/windowsruntimesecuritydemos](https://github.com/tyranid/windowsruntimesecuritydemos) Demos for Presentation on Windows Runtime Security
- [**53**Star][2y] [C#] [guardicore/azure_password_harvesting](https://github.com/guardicore/azure_password_harvesting) Plaintext Password harvesting from Azure Windows VMs
- [**53**Star][5y] [C++] [hackedteam/core-win32](https://github.com/hackedteam/core-win32) RCS Agent for Windows (32bit)
- [**53**Star][1y] [PowerShell] [pldmgg/winadmincenterps](https://github.com/pldmgg/winadmincenterps) Copy of Windows Admin Center (
- [**50**Star][7m] [C] [hfiref0x/mpenum](https://github.com/hfiref0x/mpenum) Enumerate Windows Defender threat families and dump their names according category
- [**50**Star][2m] [TSQL] [horsicq/xntsv](https://github.com/horsicq/xntsv) XNTSV program for detailed viewing of system structures for Windows.
- [**50**Star][3y] [Py] [matthewdunwoody/block-parser](https://github.com/matthewdunwoody/block-parser) Parser for Windows PowerShell script block logs
- [**50**Star][1y] [C++] [tomladder/winlib](https://github.com/tomladder/winlib) Windows Manipulation Library (x64, User/Kernelmode)
- [**49**Star][3y] [Py] [dfirfpi/dpapilab](https://github.com/dfirfpi/dpapilab) Windows DPAPI laboratory
- [**49**Star][3y] [PowerShell] [enclaveconsulting/crypto-pki](https://github.com/enclaveconsulting/crypto-pki) Scripts related to Windows cryptography and PKI.
- [**48**Star][2y] [C++] [cherrypill/system_info](https://github.com/cherrypill/system_info) Hardware information tool for Windows
- [**48**Star][14d] [PowerShell] [littl3field/audix](https://github.com/littl3field/audix) Audix is a PowerShell tool to quickly configure the Windows Event Audit Policies for security monitoring
- [**48**Star][6m] [C++] [0x00-0x00/cve-2019-0841-bypass](https://github.com/0x00-0x00/cve-2019-0841-bypass) A fully automatic CVE-2019-0841 bypass targeting all versions of Edge in Windows 10.
- [**47**Star][1y] [C++] [silica/sandbox](https://github.com/silica/sandbox) Application virtualization tool for Windows
- [**47**Star][21d] [Go] [giuliocomi/backoori](https://github.com/giuliocomi/backoori) Tool aided persistence via Windows URI schemes abuse
- [**46**Star][5m] [C#] [ericzimmerman/prefetch](https://github.com/ericzimmerman/prefetch) Windows Prefetch parser. Supports all known versions from Windows XP to Windows 10.
- [**45**Star][2y] [C++] [nccgroup/psr](https://github.com/nccgroup/psr) Pointer Sequence Reverser - enable you to see how Windows C++ application is accessing a particular data member or object.
- [**45**Star][2m] [C#] [brunull/pace](https://github.com/brunull/pace) A Remote Access Tool for Windows.
- [**45**Star][18d] [Assembly] [borjamerino/windows-one-way-stagers](https://github.com/BorjaMerino/Windows-One-Way-Stagers) Windows Stagers to circumvent restrictive network environments
- [**44**Star][3y] [C] [gentilkiwi/basic_rpc](https://github.com/gentilkiwi/basic_rpc) Samples about Microsoft RPC and native API calls in Windows C
- [**44**Star][6m] [Go] [hectane/go-acl](https://github.com/hectane/go-acl) Go library for manipulating ACLs on Windows
- [**44**Star][8d] [TSQL] [kacos2000/windowstimeline](https://github.com/kacos2000/windowstimeline) SQLite query & Powershell scripts to parse the Windows 10 (v1803+) ActivitiesCache.db
- [**44**Star][3y] [PowerShell] [lazywinadmin/winformps](https://github.com/lazywinadmin/winformps) PowerShell functions for Windows Forms controls
- [**43**Star][8m] [C] [souhailhammou/drivers](https://github.com/souhailhammou/drivers) Windows Drivers
- [**42**Star][2y] [C] [nixawk/awesome-windows-debug](https://github.com/nixawk/awesome-windows-debug) Debug Windows Application / Kernel
- [**42**Star][1y] [C++] [3gstudent/windows-eventlog-bypass](https://github.com/3gstudent/Windows-EventLog-Bypass) Use subProcessTag Value From TEB to identify Event Log Threads
- [**41**Star][6m] [Visual Basic] [s1egesystems/ghostsquadhackers-javascript-encrypter-encoder](https://github.com/s1egesystems/ghostsquadhackers-javascript-encrypter-encoder) Encrypt/Encode your Javascript code. (Windows Scripting)
- [**40**Star][1y] [Py] [mnrkbys/vss_carver](https://github.com/mnrkbys/vss_carver) Carves and recreates VSS catalog and store from Windows disk image.
- [**40**Star][3y] [PowerShell] [sikkandar-sha/sec-audit](https://github.com/sikkandar-sha/sec-audit) PowerShell Script for Windows Server Compliance / Security Configuration Audit
- [**39**Star][5m] [Py] [silv3rhorn/artifactextractor](https://github.com/silv3rhorn/artifactextractor) Extract common Windows artifacts from source images and VSCs
- [**39**Star][5m] [HTML] [sophoslabs/cve-2019-0888](https://github.com/sophoslabs/cve-2019-0888) PoC for CVE-2019-0888 - Use-After-Free in Windows ActiveX Data Objects (ADO)
- [**38**Star][2y] [Py] [roothaxor/pystat](https://github.com/roothaxor/pystat) Advanced Netstat Using Python For Windows
- [**38**Star][3y] [C] [scubsrgroup/taint-analyse](https://github.com/scubsrgroup/taint-analyse) Windows平台下的细粒度污点分析工具
- [**37**Star][1y] [C++] [3gstudent/eventlogedit-evt--general](https://github.com/3gstudent/eventlogedit-evt--general) Remove individual lines from Windows Event Viewer Log (EVT) files
- [**37**Star][3y] [C++] [yejiansnake/windows-sys-base](https://github.com/yejiansnake/windows-sys-base) windows 系统API C++封装库，包含进程间通讯，互斥，内存队列等通用功能
- [**36**Star][5y] [C++] [kkar/teamviewer-dumper-in-cpp](https://github.com/kkar/teamviewer-dumper-in-cpp) Dumps TeamViewer ID,Password and account settings from a running TeamViewer instance by enumerating child windows.
- [**36**Star][4y] [C++] [n3k/ekoparty2015_windows_smep_bypass](https://github.com/n3k/ekoparty2015_windows_smep_bypass) Windows SMEP Bypass U=S
- [**35**Star][4y] [PowerShell] [5alt/zerorat](https://github.com/5alt/zerorat) ZeroRAT是一款windows上的一句话远控
- [**35**Star][1y] [C] [realoriginal/alpc-diaghub](https://github.com/realoriginal/alpc-diaghub) Utilizing the ALPC Flaw in combiniation with Diagnostics Hub as found in Server 2016 and Windows 10.
- [**34**Star][17d] [C#] [ericzimmerman/appcompatcacheparser](https://github.com/ericzimmerman/appcompatcacheparser) AppCompatCache (shimcache) parser. Supports Windows 7 (x86 and x64), Windows 8.x, and Windows 10
- [**34**Star][3m] [PowerShell] [dsccommunity/xfailovercluster](https://github.com/dsccommunity/xFailOverCluster) This module contains DSC resources for deployment and configuration of Windows Server Failover Cluster.
- [**34**Star][1y] [PowerShell] [ptylenda/kubernetes-for-windows](https://github.com/ptylenda/kubernetes-for-windows) Ansible playbooks and Packer templates for creating hybrid Windows/Linux Kubernetes 1.10+ cluster with experimental Flannel pod network (host-gw backend)
- [**34**Star][1y] [C++] [rokups/reflectiveldr](https://github.com/rokups/reflectiveldr) Position-idependent Windows DLL loader based on ReflectiveDLL project.
- [**34**Star][6m] [PowerShell] [swisscom/powergrr](https://github.com/swisscom/powergrr) PowerGRR is an API client library in PowerShell working on Windows, Linux and macOS for GRR automation and scripting.
- [**34**Star][2y] [C++] [swwwolf/obderef](https://github.com/swwwolf/obderef) Decrement Windows Kernel for fun and profit
- [**34**Star][23d] [C] [zfigura/semblance](https://github.com/zfigura/semblance) Disassembler for Windows executables. Supports 16-bit NE (New Executable), MZ (DOS), and PE (Portable Executable, i.e. Win32) files.
- [**34**Star][6m] [C++] [parkovski/wsudo](https://github.com/parkovski/wsudo) Proof of concept sudo for Windows
- [**33**Star][2y] [Batchfile] [3gstudent/winpcap_install](https://github.com/3gstudent/winpcap_install) Auto install WinPcap on Windows(command line)
- [**33**Star][3y] [C++] [kingsunc/minidump](https://github.com/kingsunc/minidump) windows软件崩溃解决方案
- [**33**Star][4m] [C#] [nyan-x-cat/disable-windows-defender](https://github.com/nyan-x-cat/disable-windows-defender) Changing values to bypass windows defender C#
- [**32**Star][3y] [C++] [ecologylab/ecotuiodriver](https://github.com/ecologylab/ecotuiodriver) Diver to convert tuio touch events into windows touch events. Started as GSoC 2012 project.
- [**32**Star][3y] [C++] [swwwolf/cbtest](https://github.com/swwwolf/cbtest) Windows kernel-mode callbacks tutorial driver
- [**32**Star][9d] [Py] [technowlogy-pushpender/technowhorse](https://github.com/technowlogy-pushpender/technowhorse) TechNowHorse is a RAT (Remote Administrator Trojan) Generator for Windows/Linux systems written in Python 3.
- [**31**Star][4m] [C++] [blackint3/none](https://github.com/blackint3/none) UNONE and KNONE is a couple of open source base library that makes it easy to develop software on Windows.
- [**31**Star][5m] [C] [csandker/inmemoryshellcode](https://github.com/csandker/inmemoryshellcode) A Collection of In-Memory Shellcode Execution Techniques for Windows
- [**30**Star][3y] [CSS] [botherder/flexikiller](https://github.com/botherder/flexikiller) flexikiller：移除FlexiSpy 木马（Windows/Mac）
- [**30**Star][8y] [C] [hackedteam/driver-win64](https://github.com/hackedteam/driver-win64) Windows (64bit) agent driver
- [**29**Star][6y] [Shell] [artemdinaburg/optimizevm](https://github.com/artemdinaburg/optimizevm) Make Windows VMs Faster
- [**29**Star][2y] [C#] [modzero/mod0umleitung](https://github.com/modzero/mod0umleitung) modzero DNS Masquerading Server for Windows
- [**29**Star][1y] [Py] [skelsec/windows_ad_dos_poc](https://github.com/skelsec/windows_ad_dos_poc) PoC code for crashing windows active directory
- [**29**Star][3y] [Py] [6e726d/pywiwi](https://github.com/6e726d/pywiwi) Python Windows Wifi
- [**28**Star][1y] [C] [bot-man-jl/wfp-traffic-redirection-driver](https://github.com/bot-man-jl/wfp-traffic-redirection-driver) WFP Traffic Redirection Driver is used to redirect NIC traffic on network layer and framing layer, based on Windows Filtering Platform (WFP).
- [**28**Star][2y] [defcon-russia/shortcut_auto_bind](https://github.com/defcon-russia/shortcut_auto_bind) Windows LNK/URL shortcut auto-binding hotkey (not a bug, feature)
- [**28**Star][4y] [C] [icewall/forcedelete](https://github.com/icewall/forcedelete) Windows driver including couple different techniques for file removal when regular operation isn't possible.
- [**28**Star][5y] [C++] [michael4338/tdi](https://github.com/michael4338/tdi) Windows Kernel Driver - Create a driver device in TDI layer of windows kernel to capture network data packets
- [**28**Star][2y] [C++] [hsluoyz/rmtsvc](https://github.com/hsluoyz/rmtsvc) A web-based remote desktop & control service for Windows.
- [**27**Star][8y] [C] [hackedteam/driver-win32](https://github.com/hackedteam/driver-win32) Windows (32bit) agent driver
- [**27**Star][3y] [C++] [int0/ltmdm64_poc](https://github.com/int0/ltmdm64_poc) ltmdm64_poc：利用ltmdm64.sys 的漏洞绕过 Windows 7 SP1 x64 的代码完整性检查
- [**27**Star][9m] [C#] [raandree/managedpasswordfilter](https://github.com/raandree/managedpasswordfilter) Windows Password Filter that uses managed code internally
- [**26**Star][4m] [C#] [717021/pcmgr](https://github.com/717021/pcmgr) Windows 任务管理器重制版 A rebulid version for Windows task manager.
- [**26**Star][7y] [C++] [avalon1610/lpc](https://github.com/avalon1610/lpc) windows LPC library
- [**26**Star][7m] [C++] [slyd0g/timestomper](https://github.com/slyd0g/TimeStomper) PoC that manipulates Windows file times using SetFileTime() API
- [**26**Star][2y] [C++] [strikerx3/whvpclient](https://github.com/strikerx3/whvpclient) Windows Hypervisor Platform client
- [**26**Star][4y] [Py] [stratosphereips/stratospherewindowsips](https://github.com/stratosphereips/StratosphereWindowsIps) The Stratosphere IPS is a free software IPS that uses network behavior to detect and block malicious actions.
- [**25**Star][2y] [C++] [apriorit/custom-bootloader](https://github.com/apriorit/custom-bootloader) A demo tutorial for low-level and kernel developers - developing a custom Windows boot loader
- [**25**Star][6y] [C++] [dominictobias/detourxs](https://github.com/dominictobias/detourxs) A x86/64 library for detouring functions on Windows OS
- [**24**Star][4y] [C] [ltangjian/firewall](https://github.com/ltangjian/firewall) Based on the research of Windows network architecture and the core packet filtering firewall technology, using NDIS intermediate driver, the article achieved the filter of the core layer, and completed the Windows Personal Firewall Design and Implementation.
- [**24**Star][3y] [Pascal] [martindrab/vrtuletree](https://github.com/martindrab/vrtuletree) VrtuleTree is a tool that displays information about driver and device objects present in the system and relations between them. Its functionality is very similar to famous DeviceTree, however, VrtuleTree emhasises on stability and support of latest Windows versions
- [**24**Star][5y] [C++] [michael4338/ndis](https://github.com/michael4338/ndis) Windows Kernel Driver - Create a driver device in intermediate layer of Windows kernel based on NDIS, which communicates with and connect upper layer (user mode applications) and lower layer (miniport driver/network card). Create self-defined protocols for transmitting data and control communications by simulating very simple HTTP, TCP and ARP p…
- [**24**Star][1y] [Py] [rootm0s/casper](https://github.com/rootm0s/casper) 👻 Socket based RAT for Windows with evasion techniques and other features for control
- [**24**Star][2y] [Py] [the404hacking/windows-python-rat](https://github.com/the404hacking/windows-python-rat) A New Microsoft Windows Remote Administrator Tool [RAT] with Python by Sir.4m1R.
- [**24**Star][4y] [C++] [thecybermind/ipredir](https://github.com/thecybermind/ipredir) IP redirection+NAT for Windows
- [**23**Star][3y] [C] [hedgeh/sewindows](https://github.com/hedgeh/sewindows) 在Windows上建立一个开源的强制访问控制框架及SDK。使Windows平台的应用开发者，可以不用关心操作系统底层技术，只用进行简单的SDK调用或配置就可以保护自己的应用程序。
- [**23**Star][4y] [JS] [kolanich/cleanunwantedupdates](https://github.com/kolanich/cleanunwantedupdates) A set of scripts to detect updates of Microsoft (TM) Windows (TM) OS which harm users' privacy and uninstall them
- [**23**Star][2m] [C] [doublelabyrinth/windowssudo](https://github.com/doublelabyrinth/windowssudo) A linux-like su/sudo on Windows.
- [**21**Star][4y] [C#] [adamcaudill/curvelock](https://github.com/adamcaudill/curvelock) Experimental File & Message Encryption for Windows
- [**21**Star][3y] [Visual Basic] [appsecco/winmanipulate](https://github.com/appsecco/winmanipulate) A simple tool to manipulate window objects in Windows
- [**21**Star][1y] [C] [codereba/netmon](https://github.com/codereba/netmon) network filter driver that control network send speed, based on windows tdi framework.
- [**21**Star][2y] [C] [microwave89/drvtricks](https://github.com/microwave89/drvtricks) drvtriks kernel driver for Windows 7 SP1 and 8.1 x64, that tricks around in your system.
- [**21**Star][1y] [JS] [mindpointgroup/stig-cli](https://github.com/MindPointGroup/stig-cli) A CLI for perusing DISA STIG content Mac, Linux, and Windows Compatible
- [**20**Star][3y] [C++] [andrewgaspar/km-stl](https://github.com/andrewgaspar/km-stl) A drop-in replacement for the C++ STL for kernel mode Windows drivers. The goal is to have implementations for things like the standard algorithms that don't require memory allocations or exceptions, and for implementations of type traits and other compile-time related headers. Full implementation of the STL is a non-goal.
- [**20**Star][7m] [C] [mtth-bfft/ntsec](https://github.com/mtth-bfft/ntsec) Standalone tool to explore the security model of Windows and its NT kernel. Use it to introspect privilege assignments and access right assignments, enumerate attack surfaces from the point of view of a sandboxed process, etc.
- [**20**Star][22d] [C++] [mullvad/libwfp](https://github.com/mullvad/libwfp) C++ library for interacting with the Windows Filtering Platform (WFP)
- [**20**Star][2y] [PowerShell] [rasta-mouse/invoke-loginprompt](https://github.com/rasta-mouse/invoke-loginprompt) Invokes a Windows Security Login Prompt and outputs the clear text password.
- [**20**Star][7d] [C#] [damonmohammadbagher/nativepayload_reverseshell](https://github.com/damonmohammadbagher/nativepayload_reverseshell) This is Simple C# Source code to Bypass almost "all" AVS, (kaspersky v19, Eset v12 v13 ,Trend-Micro v16, Comodo & Windows Defender Bypassed via this method Very Simple)


### <a id="0af4bd8ca0fd27c9381a2d1fa8b71a1f"></a>ETW


- [**1207**Star][8d] [JS] [jpcertcc/logontracer](https://github.com/jpcertcc/logontracer) Investigate malicious Windows logon by visualizing and analyzing Windows event log
- [**526**Star][14d] [PowerShell] [sbousseaden/evtx-attack-samples](https://github.com/sbousseaden/evtx-attack-samples) windows events samples associated to specific attack and post-exploitation techniques
- [**502**Star][9m] [C#] [lowleveldesign/wtrace](https://github.com/lowleveldesign/wtrace) Command line tracing tool for Windows, based on ETW.
- [**436**Star][8m] [PowerShell] [nsacyber/event-forwarding-guidance](https://github.com/nsacyber/Event-Forwarding-Guidance) Configuration guidance for implementing collection of security relevant Windows Event Log events by using Windows Event Forwarding. #nsacyber
- [**389**Star][9m] [Py] [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx) Pure Python parser for recent Windows Event Log files (.evtx)
- [**295**Star][11d] [C#] [zodiacon/procmonx](https://github.com/zodiacon/procmonx) Extended Process Monitor-like tool based on Event Tracing for Windows
- [**281**Star][9m] [C#] [nsacyber/windows-event-log-messages](https://github.com/nsacyber/Windows-Event-Log-Messages) Retrieves the definitions of Windows Event Log messages embedded in Windows binaries and provides them in discoverable formats. #nsacyber
- [**215**Star][2y] [Py] [thiber-org/userline](https://github.com/thiber-org/userline) Query and report user logons relations from MS Windows Security Events
- [**146**Star][4m] [Py] [fireeye/pywintrace](https://github.com/fireeye/pywintrace) Python 编写的 ETW（Event Tracing for Windows） Wrapper
- [**43**Star][2y] [C#] [zacbrown/hiddentreasure-etw-demo](https://github.com/zacbrown/hiddentreasure-etw-demo) 在内存取证中，使用 ETW（Windows事件追踪） 挖掘宝藏的新方式


### <a id="d48f038b58dc921660be221b4e302f70"></a>Sysmon




### <a id="8ed6f25b321f7b19591ce2908b30cc88"></a>WSL


- [**8495**Star][1m] [microsoft/wsl](https://github.com/microsoft/WSL) Issues found on WSL
- [**2825**Star][8m] [Shell] [goreliu/wsl-terminal](https://github.com/goreliu/wsl-terminal) Terminal emulator for Windows Subsystem for Linux (WSL)
- [**660**Star][9d] [Shell] [wslutilities/wslu](https://github.com/wslutilities/wslu) A collection of utilities for Windows 10 Linux Subsystems
- [**611**Star][4y] [Batchfile] [windowslies/blockwindows](https://github.com/windowslies/blockwindows) Stop Windows 10 Nagging and Spying. Works with Win7-10
- [**330**Star][3y] [C++] [xilun/cbwin](https://github.com/xilun/cbwin) Launch Windows programs from "Bash on Ubuntu on Windows" (WSL)


### <a id="d90b60dc79837e06d8ba2a7ee1f109d3"></a>.NET


- [**12453**Star][7d] [C#] [0xd4d/dnspy](https://github.com/0xd4d/dnspy) .NET debugger and assembly editor
- [**9141**Star][8d] [C#] [icsharpcode/ilspy](https://github.com/icsharpcode/ilspy) .NET Decompiler
- [**3645**Star][26d] [C#] [0xd4d/de4dot](https://github.com/0xd4d/de4dot) .NET deobfuscator and unpacker.
- [**3253**Star][7m] [JS] [sindresorhus/speed-test](https://github.com/sindresorhus/speed-test) Test your internet connection speed and ping using speedtest.net from the CLI
- [**1643**Star][1m] [C#] [jbevain/cecil](https://github.com/jbevain/cecil) Cecil is a library to inspect, modify and create .NET programs and libraries.
- [**251**Star][1y] [C#] [brianhama/de4dot](https://github.com/brianhama/de4dot) .NET deobfuscator and unpacker.
- [**215**Star][11m] [C#] [rainwayapp/warden](https://github.com/rainwayapp/warden) Warden.NET is an easy to use process management library for keeping track of processes on Windows.
- [**172**Star][1m] [ASP] [lowleveldesign/debug-recipes](https://github.com/lowleveldesign/debug-recipes) My notes collected while debugging various .NET and Windows problems.
- [**69**Star][8m] [C#] [fsecurelabs/sharpcliphistory](https://github.com/FSecureLABS/SharpClipHistory) SharpClipHistory is a .NET application written in C# that can be used to read the contents of a user's clipboard history in Windows 10 starting from the 1809 Build.
- [**49**Star][7m] [C#] [9ee1/capstone.net](https://github.com/9ee1/capstone.net) .NET Core and .NET Framework binding for the Capstone Disassembly Framework


### <a id="6d2fe834b7662ecdd48c17163f732daf"></a>Environment&&环境&&配置


- [**1519**Star][10m] [PowerShell] [joefitzgerald/packer-windows](https://github.com/joefitzgerald/packer-windows) Windows templates that can be used to create boxes for Vagrant using Packer
- [**1341**Star][10d] [Go] [securitywithoutborders/hardentools](https://github.com/securitywithoutborders/hardentools) Hardentools is a utility that disables a number of risky Windows features.
- [**1145**Star][1y] [HTML] [nsacyber/windows-secure-host-baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline) Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings. #nsacyber
- [**1000**Star][5m] [adolfintel/windows10-privacy](https://github.com/adolfintel/windows10-privacy) Windows 10 Privacy Guide
- [**488**Star][23d] [PowerShell] [stefanscherer/packer-windows](https://github.com/stefanscherer/packer-windows) Windows Templates for Packer: Win10, Server 2016, 1709, 1803, 1809, 2019, 1903, Insider with Docker


### <a id="8bfd27b42bb75956984994b3419fb582"></a>进程注入




### <a id="b0d50ee42d53b1f88b32988d34787137"></a>DLL注入


- [**699**Star][4m] [C++] [darthton/xenos](https://github.com/darthton/xenos) Windows dll injector


### <a id="1c6069610d73eb4246b58d78c64c9f44"></a>代码注入




### <a id="7c1541a69da4c025a89b0571d8ce73d2"></a>内存模块




### <a id="16001cb2fae35b722deaa3b9a8e5f4d5"></a>Shellcode


- [**533**Star][4m] [C++] [nytrorst/shellcodecompiler](https://github.com/nytrorst/shellcodecompiler) compiles C/C++ style code into a small, position-independent and NULL-free shellcode for Windows (x86 and x64) and Linux (x86 and x64)
    - Also In Section: [Linux->Tools](#89e277bca2740d737c1aeac3192f374c) |
- [**234**Star][4y] [Py] [pyana/pyana](https://github.com/pyana/pyana) Analyzing the Windows shellcode
- [**189**Star][1y] [Py] [thesecondsun/shellab](https://github.com/thesecondsun/shellab) Linux and Windows shellcode enrichment utility
- [**182**Star][5m] [C++] [jackullrich/shellcodestdio](https://github.com/jackullrich/shellcodestdio) An extensible framework for easily writing compiler optimized position independent x86 / x64 shellcode for windows platforms.
- [**161**Star][5m] [C] [odzhan/shellcode](https://github.com/odzhan/shellcode) Shellcodes for Windows/Linux/BSD running on x86, AMD64, ARM, ARM64
- [**150**Star][5m] [Assembly] [peterferrie/win-exec-calc-shellcode](https://github.com/peterferrie/win-exec-calc-shellcode) A small, null-free Windows shellcode that executes calc.exe (x86/x64, all OS/SPs)


### <a id="19cfd3ea4bd01d440efb9d4dd97a64d0"></a>VT&&虚拟化&&Hypbervisor


- [**1311**Star][18d] [C] [intel/haxm](https://github.com/intel/haxm)  cross-platform hardware-assisted virtualization engine (hypervisor), widely used as an accelerator for Android Emulator and QEMU
- [**1003**Star][1y] [C] [ionescu007/simplevisor](https://github.com/ionescu007/simplevisor) a simple, portable, Intel VT-x hypervisor with two specific goals: using the least amount of assembly code (10 lines), and having the smallest amount of VMX-related code to support dynamic hyperjacking and unhyperjacking (that is, virtualizing the host state from within the host). It works on Windows and UEFI.
- [**708**Star][3m] [C++] [tandasat/hyperplatform](https://github.com/tandasat/hyperplatform) Intel VT-x based hypervisor aiming to provide a thin VM-exit filtering platform on Windows.
- [**561**Star][11m] [C] [asamy/ksm](https://github.com/asamy/ksm) A fast, hackable and simple x64 VT-x hypervisor for Windows and Linux. Builtin userspace sandbox and introspection engine.
    - Also In Section: [Linux->Tools](#89e277bca2740d737c1aeac3192f374c) |
- [**446**Star][2y] [POV-Ray SDL] [hzqst/syscall-monitor](https://github.com/hzqst/syscall-monitor)  a system monitor program (like Sysinternal's Process Monitor) using Intel VT-X/EPT for Windows7+
    - Also In Section: [Windows->Tools->系统调用](#d295182c016bd9c2d5479fe0e98a75df) |
- [**189**Star][9m] [C++] [kelvinhack/khypervisor](https://github.com/kelvinhack/khypervisor) kHypervisor is a lightweight bluepill-like nested VMM for Windows, it provides and emulating a basic function of Intel VT-x


### <a id="c3cda3278305549f4c21df25cbf638a4"></a>内核&&驱动


- [**928**Star][9m] [C] [microsoft/windows-driver-frameworks](https://github.com/microsoft/windows-driver-frameworks) a set of libraries that make it simple to write high-quality device drivers.
- [**760**Star][13d] [axtmueller/windows-kernel-explorer](https://github.com/axtmueller/windows-kernel-explorer) A free but powerful Windows kernel research tool.
- [**506**Star][5m] [Py] [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus) Tool for exploration and tracing of the Windows kernel
- [**459**Star][22d] [C] [jkornev/hidden](https://github.com/jkornev/hidden) Windows driver with usermode interface which can hide objects of file-system and registry, protect processes and etc
- [**324**Star][2y] [Rust] [pravic/winapi-kmd-rs](https://github.com/pravic/winapi-kmd-rs) Windows Kernel-Mode Drivers written in Rust
- [**280**Star][2y] [C++] [sam-b/windows_kernel_address_leaks](https://github.com/sam-b/windows_kernel_address_leaks) Examples of leaking Kernel Mode information from User Mode on Windows
- [**278**Star][7d] [PowerShell] [microsoftdocs/windows-driver-docs](https://github.com/MicrosoftDocs/windows-driver-docs) The official Windows Driver Kit documentation sources
- [**232**Star][4y] [C] [markjandrews/wrk-v1.2](https://github.com/markjandrews/wrk-v1.2) Windows Research Kernel


### <a id="920b69cea1fc334bbc21a957dd0d9f6f"></a>注册表


- [**479**Star][7d] [Batchfile] [chef-koch/regtweaks](https://github.com/chef-koch/regtweaks) Windows Registry Tweaks (Win 7 - Win 10)
- [**288**Star][7m] [Py] [williballenthin/python-registry](https://github.com/williballenthin/python-registry) Read access to Windows Registry files.
- [**159**Star][1y] [msuhanov/regf](https://github.com/msuhanov/regf) Windows registry file format specification


### <a id="d295182c016bd9c2d5479fe0e98a75df"></a>系统调用


- [**712**Star][2m] [HTML] [j00ru/windows-syscalls](https://github.com/j00ru/windows-syscalls) Windows System Call Tables (NT/2000/XP/2003/Vista/2008/7/2012/8/10)
- [**446**Star][2y] [POV-Ray SDL] [hzqst/syscall-monitor](https://github.com/hzqst/syscall-monitor)  a system monitor program (like Sysinternal's Process Monitor) using Intel VT-X/EPT for Windows7+
    - Also In Section: [Windows->Tools->VT](#19cfd3ea4bd01d440efb9d4dd97a64d0) |
- [**316**Star][30d] [C] [hfiref0x/syscalltables](https://github.com/hfiref0x/syscalltables) Windows NT x64 Syscall tables
- [**276**Star][2y] [Assembly] [tinysec/windows-syscall-table](https://github.com/tinysec/windows-syscall-table) windows syscall table from xp ~ 10 rs4




***


## <a id="3939f5e83ca091402022cb58e0349ab8"></a>Posts&&Videos




# <a id="dc664c913dc63ec6b98b47fcced4fdf0"></a>Linux


***


## <a id="89e277bca2740d737c1aeac3192f374c"></a>Tools


- [**1533**Star][2y] [C] [ezlippi/webbench](https://github.com/ezlippi/webbench) Webbench是Radim Kolar在1997年写的一个在linux下使用的非常简单的网站压测工具。它使用fork()模拟多个客户端同时访问我们设定的URL，测试网站在压力下工作的性能，最多可以模拟3万个并发连接去测试网站的负载能力。官网地址:
- [**1422**Star][2m] [C] [feralinteractive/gamemode](https://github.com/feralinteractive/gamemode) Optimise Linux system performance on demand
- [**1406**Star][1m] [C++] [google/nsjail](https://github.com/google/nsjail) A light-weight process isolation tool, making use of Linux namespaces and seccomp-bpf syscall filters (with help of the kafel bpf language)
- [**884**Star][8d] [C] [buserror/simavr](https://github.com/buserror/simavr) simavr is a lean, mean and hackable AVR simulator for linux & OSX
- [**751**Star][17d] [Py] [korcankaraokcu/pince](https://github.com/korcankaraokcu/pince) A reverse engineering tool that'll supply the place of Cheat Engine for linux
- [**740**Star][1m] [C] [yrp604/rappel](https://github.com/yrp604/rappel) A linux-based assembly REPL for x86, amd64, armv7, and armv8
- [**717**Star][11d] [C] [strace/strace](https://github.com/strace/strace) strace is a diagnostic, debugging and instructional userspace utility for Linux
- [**582**Star][3y] [C] [ktap/ktap](https://github.com/ktap/ktap) a new scripting dynamic tracing tool for Linux
- [**561**Star][11m] [C] [asamy/ksm](https://github.com/asamy/ksm) A fast, hackable and simple x64 VT-x hypervisor for Windows and Linux. Builtin userspace sandbox and introspection engine.
    - Also In Section: [Windows->Tools->VT](#19cfd3ea4bd01d440efb9d4dd97a64d0) |
- [**559**Star][1m] [Py] [autotest/autotest](https://github.com/autotest/autotest) Fully automated tests on Linux
- [**552**Star][13d] [C++] [intel/linux-sgx](https://github.com/intel/linux-sgx) Intel SGX for Linux*
- [**533**Star][4m] [C++] [nytrorst/shellcodecompiler](https://github.com/nytrorst/shellcodecompiler) compiles C/C++ style code into a small, position-independent and NULL-free shellcode for Windows (x86 and x64) and Linux (x86 and x64)
    - Also In Section: [Windows->Tools->Shellcode](#16001cb2fae35b722deaa3b9a8e5f4d5) |
- [**502**Star][7m] [C] [iovisor/ply](https://github.com/iovisor/ply) Dynamic Tracing in Linux
- [**500**Star][3y] [C] [gaffe23/linux-inject](https://github.com/gaffe23/linux-inject) Tool for injecting a shared object into a Linux process
- [**466**Star][7d] [C] [libreswan/libreswan](https://github.com/libreswan/libreswan) an Internet Key Exchange (IKE) implementation for Linux.
- [**464**Star][2y] [C++] [aimtuxofficial/aimtux](https://github.com/aimtuxofficial/aimtux) A large Linux csgo cheat/hack
- [**437**Star][7d] [C] [facebook/openbmc](https://github.com/facebook/openbmc) OpenBMC is an open software framework to build a complete Linux image for a Board Management Controller (BMC).
- [**385**Star][9m] [Shell] [microsoft/linux-vm-tools](https://github.com/microsoft/linux-vm-tools) Hyper-V Linux Guest VM Enhancements
- [**384**Star][27d] [Shell] [yadominjinta/atilo](https://github.com/yadominjinta/atilo) Linux installer for termux
- [**353**Star][3y] [C] [adtac/fssb](https://github.com/adtac/fssb) A filesystem sandbox for Linux using syscall intercepts.
- [**346**Star][1m] [C] [seccomp/libseccomp](https://github.com/seccomp/libseccomp) an easy to use, platform independent, interface to the Linux Kernel's syscall filtering mechanism
- [**328**Star][4m] [Go] [capsule8/capsule8](https://github.com/capsule8/capsule8) cloud-native behavioral security monitoring
- [**316**Star][3y] [C] [chobits/tapip](https://github.com/chobits/tapip) user-mode TCP/IP stack based on linux tap device
- [**280**Star][24d] [Py] [facebook/fbkutils](https://github.com/facebook/fbkutils) A variety of utilities built and maintained by Facebook's Linux Kernel Team that we wish to share with the community.
- [**231**Star][2y] [C] [hardenedlinux/grsecurity-101-tutorials](https://github.com/hardenedlinux/grsecurity-101-tutorials) 增强 Linux 内核安全的内核补丁集
- [**227**Star][7m] [C] [wkz/ply](https://github.com/wkz/ply) Light-weight Dynamic Tracer for Linux
- [**203**Star][3y] [C] [google/kasan](https://github.com/google/kasan) KernelAddressSanitizer, a fast memory error detector for the Linux kernel
- [**198**Star][3y] [C] [dismantl/linux-injector](https://github.com/dismantl/linux-injector) Utility for injecting executable code into a running process on x86/x64 Linux
- [**189**Star][7m] [C] [andikleen/simple-pt](https://github.com/andikleen/simple-pt) Simple Intel CPU processor tracing on Linux
- [**173**Star][12d] [C] [netoptimizer/network-testing](https://github.com/netoptimizer/network-testing) Network Testing Tools for testing the Linux network stack
- [**147**Star][24d] [Shell] [hardenedlinux/debian-gnu-linux-profiles](https://github.com/hardenedlinux/debian-gnu-linux-profiles) Debian GNU/Linux based Services Profiles
- [**142**Star][28d] [Shell] [sclorg/s2i-python-container](https://github.com/sclorg/s2i-python-container) Python container images based on Red Hat Software Collections and intended for OpenShift and general usage, that provide a platform for building and running Python applications. Users can choose between Red Hat Enterprise Linux, Fedora, and CentOS based images.
- [**140**Star][2y] [C] [ixty/mandibule](https://github.com/ixty/mandibule) 向远程进程注入ELF文件
- [**140**Star][7y] [C] [johnath/beep](https://github.com/johnath/beep) beep is a command line tool for linux that beeps the PC speaker
- [**134**Star][6m] [C] [dzzie/scdbg](https://github.com/dzzie/scdbg) note: current build is VS_LIBEMU project. This cross platform gcc build is for Linux users but is no longer updated. modification of the libemu sctest project to add basic debugger capabilities and more output useful for manual RE. The newer version will run under WINE
- [**132**Star][14d] [C] [arsv/minibase](https://github.com/arsv/minibase) small static userspace tools for Linux
- [**126**Star][10y] [C] [spotify/linux](https://github.com/spotify/linux) Spotify's Linux kernel for Debian-based systems
- [**122**Star][4m] [C] [dschanoeh/socketcand](https://github.com/dschanoeh/socketcand) A deprecated fork of socketcand. Please got to linux-can for the latest version.
- [**115**Star][29d] [Py] [containers/udica](https://github.com/containers/udica) This repository contains a tool for generating SELinux security profiles for containers
- [**113**Star][1y] [Shell] [fox-it/linux-luks-tpm-boot](https://github.com/fox-it/linux-luks-tpm-boot) A guide for setting up LUKS boot with a key from TPM in Linux
- [**103**Star][2m] [Py] [vstinner/python-ptrace](https://github.com/vstinner/python-ptrace) a debugger using ptrace (Linux, BSD and Darwin system call to trace processes) written in Python
- [**99**Star][2y] [Shell] [aoncyberlabs/cexigua](https://github.com/AonCyberLabs/Cexigua) Linux based inter-process code injection without ptrace(2)
- [**96**Star][6m] [Shell] [gavinlyonsrepo/cylon](https://github.com/gavinlyonsrepo/cylon) Updates, maintenance, backups and system checks in a TUI menu driven bash shell script for an Arch based Linux distro
- [**93**Star][5m] [Shell] [vincentbernat/eudyptula-boot](https://github.com/vincentbernat/eudyptula-boot) Boot a Linux kernel in a VM without a dedicated root filesystem.
- [**83**Star][2y] [C] [xobs/novena-linux](https://github.com/xobs/novena-linux) Linux kernel with Novena patches -- expect frequent rebases!
- [**77**Star][6m] [Py] [cybereason/linux_plumber](https://github.com/cybereason/linux_plumber) A python implementation of a grep friendly ftrace wrapper
- [**73**Star][3y] [Shell] [inquisb/unix-privesc-check](https://github.com/inquisb/unix-privesc-check) Shell script that runs on UNIX systems (tested on Solaris 9, HPUX 11, various Linux distributions, FreeBSD 6.2). It detects misconfigurations that could allow local unprivileged user to escalate to other users (e.g. root) or to access local apps (e.g. databases). This is a collaborative rework of version 1.0
- [**71**Star][7m] [C] [hc0d3r/alfheim](https://github.com/hc0d3r/alfheim) a linux process hacker tool
- [**68**Star][3m] [TypeScript] [flathub/linux-store-frontend](https://github.com/flathub/linux-store-frontend) A web application to browse and install applications present in Flatpak repositories. Powers
- [**67**Star][13d] [Shell] [sclorg/s2i-php-container](https://github.com/sclorg/s2i-php-container) PHP container images based on Red Hat Software Collections and intended for OpenShift and general usage, that provide a platform for building and running PHP applications. Users can choose between Red Hat Enterprise Linux, Fedora, and CentOS based images.
- [**64**Star][3m] [Shell] [mdrights/liveslak](https://github.com/mdrights/liveslak) 中文化的隐私加强 GNU/Linux 系统 - Forked from Alien Bob's powerful building script for Slackware Live.
- [**63**Star][2m] [Py] [archlinux/arch-security-tracker](https://github.com/archlinux/arch-security-tracker) Arch Linux Security Tracker
- [**62**Star][20d] [drduh/pc-engines-apu-router-guide](https://github.com/drduh/pc-engines-apu-router-guide) Guide to building a Linux or BSD router on the PC Engines APU platform
- [**61**Star][2y] [Perl] [xlogicx/m2elf](https://github.com/xlogicx/m2elf) Converts Machine Code to x86 (32-bit) Linux executable (auto-wrapping with ELF headers)
- [**58**Star][2y] [Go] [evilsocket/ftrace](https://github.com/evilsocket/ftrace) Go library to trace Linux syscalls using the FTRACE kernel framework.
- [**58**Star][1y] [C] [skeeto/ptrace-examples](https://github.com/skeeto/ptrace-examples) Examples for Linux ptrace(2)
- [**57**Star][2m] [Java] [exalab/anlinux-adfree](https://github.com/exalab/anlinux-adfree) AnLinux, Ad free version.
- [**57**Star][3y] [CSS] [wizardforcel/sploitfun-linux-x86-exp-tut-zh](https://github.com/wizardforcel/sploitfun-linux-x86-exp-tut-zh) 
- [**54**Star][1y] [Py] [k4yt3x/defense-matrix](https://github.com/k4yt3x/defense-matrix) Express security essentials deployment for Linux Servers
- [**51**Star][9m] [C] [marcan/lsirec](https://github.com/marcan/lsirec) LSI SAS2008/SAS2108 low-level recovery tool for Linux
- [**49**Star][2y] [C] [cnlohr/wifirxpower](https://github.com/cnlohr/wifirxpower) Linux-based WiFi RX Power Grapher
- [**48**Star][1y] [C] [pymumu/jail-shell](https://github.com/pymumu/jail-shell) Jail-shell is a linux security tool mainly using chroot, namespaces technologies, limiting users to perform specific commands, and access sepcific directories.
- [**48**Star][3y] [Assembly] [t00sh/assembly](https://github.com/t00sh/assembly) Collection of Linux shellcodes
- [**45**Star][2y] [Go] [c-bata/systracer](https://github.com/c-bata/systracer) Yet another system call tracer written in Go.
- [**45**Star][6y] [JS] [cyberpython/wifiscanandmap](https://github.com/cyberpython/wifiscanandmap) A Linux Python application to create maps of 802.11 networks
- [**45**Star][3m] [C] [thibault-69/rat-hodin-v2.9](https://github.com/Thibault-69/RAT-Hodin-v2.9) Remote Administration Tool for Linux
- [**45**Star][4y] [C] [shadowsocks/iptables](https://github.com/shadowsocks/iptables) iptables is the userspace command line program used to configure the Linux 2.4.x and later packet filtering ruleset. It is targeted towards system administrators.
- [**44**Star][6m] [C] [junxzm1990/pomp](https://github.com/junxzm1990/pomp) 在 Linux 系统上开发 POMP 系统，分析崩溃后的 artifacts
- [**42**Star][6m] [Ruby] [b1ack0wl/linux_mint_poc](https://github.com/b1ack0wl/linux_mint_poc) 
- [**42**Star][1y] [C] [gcwnow/linux](https://github.com/gcwnow/linux) Linux kernel for GCW Zero (Ingenic JZ4770)
- [**41**Star][3y] [Py] [fnzv/trsh](https://github.com/fnzv/trsh) trsh：使用电报 API 与 Linux 服务器通信，Python编写。
- [**40**Star][4m] [C] [stephenrkell/trap-syscalls](https://github.com/stephenrkell/trap-syscalls) Monitor, rewrite and/or otherwise trap system calls... on Linux/x86-64 only, for now.
- [**39**Star][13d] [Dockerfile] [ironpeakservices/iron-alpine](https://github.com/ironPeakServices/iron-alpine) Hardened alpine linux baseimage for Docker.
- [**38**Star][3m] [PHP] [cesnet/pakiti-server](https://github.com/cesnet/pakiti-server) Pakiti provides a monitoring mechanism to check the patching status of Linux systems.
- [**35**Star][8y] [C] [sduverger/ld-shatner](https://github.com/sduverger/ld-shatner) ld-linux code injector
- [**34**Star][3m] [C] [peterbjornx/meloader](https://github.com/peterbjornx/meloader) Linux i386 tool to load and execute ME modules.
- [**34**Star][3y] [screetsec/dracos](https://github.com/screetsec/dracos) Dracos Linux (
- [**33**Star][2y] [C++] [cnrig/cnrig](https://github.com/cnrig/cnrig) Static CryptoNight CPU miner for Linux + automatic updates
- [**32**Star][3y] [Go] [egebalci/the-eye](https://github.com/egebalci/the-eye) Simple security surveillance script for linux distributions.
- [**32**Star][6m] [C] [jcsaezal/pmctrack](https://github.com/jcsaezal/pmctrack) an OS-oriented performance monitoring tool for Linux (
- [**32**Star][11m] [C] [p3n3troot0r/socketv2v](https://github.com/p3n3troot0r/socketv2v) Mainline Linux Kernel integration of IEEE 802.11p, IEEE 1609.{3,4}, and developmental userspace utility for using J2735 over WAVE
- [**32**Star][1y] [C] [perceptionpoint/suprotect](https://github.com/perceptionpoint/suprotect) Changing memory protection in an arbitrary process
- [**32**Star][4y] [C] [a0rtega/bdldr](https://github.com/a0rtega/bdldr) bdldr is an unofficial engine loader for Bitdefender ® for Linux
- [**31**Star][6y] [C] [nbareil/net2pcap](https://github.com/nbareil/net2pcap) Net2PCAP is a simple network-to-pcap capture file for Linux. Its goal is to be as simple as possible to be used in hostile environments
- [**30**Star][2y] [PHP] [opt-oss/ng-netms](https://github.com/opt-oss/ng-netms) NG-NetMS is a new end-to-end network management platform for your Linux servers, Cisco, Juniper, HP and Extreme routers, switches and firewalls.
- [**27**Star][2y] [Py] [morphuslabs/distinct](https://github.com/morphuslabs/distinct) Find potential Indicators of Compromise among similar Linux servers
- [**27**Star][1m] [C] [oracle/libdtrace-ctf](https://github.com/oracle/libdtrace-ctf) libdtrace-ctf is the Compact Type Format library used by DTrace on Linux
- [**27**Star][5y] [Py] [bendemott/captiveportal](https://github.com/bendemott/captiveportal) A captive portal that can be used on most linux distributions.
- [**26**Star][21d] [Shell] [adnanhodzic/anon-hotspot](https://github.com/adnanhodzic/anon-hotspot) On demand Debian Linux (Tor) Hotspot setup tool
- [**26**Star][11m] [C] [plutonium-dbg/plutonium-dbg](https://github.com/plutonium-dbg/plutonium-dbg) Kernel-based debugger for Linux applications
- [**26**Star][1y] [Py] [thesecondsun/pasm](https://github.com/thesecondsun/pasm) Linux assembler/disassembler based on Rasm2
- [**26**Star][2m] [C] [oracle/dtrace-utils](https://github.com/oracle/dtrace-utils) DTrace-utils contains the Userspace portion of the DTrace port to Linux
- [**25**Star][8y] [aheadley/logitech-solar-k750-linux](https://github.com/aheadley/logitech-solar-k750-linux) Userspace "driver" for the Logitech k750 Solar Keyboard. A fork of the repo from
- [**23**Star][5y] [C++] [behzad-a/dytan](https://github.com/behzad-a/dytan) Dytan Taint Analysis Framework on Linux 64-bit
- [**23**Star][1y] [Py] [m4rktn/jogan](https://github.com/m4rktn/jogan) Pentest Tools & Packages Installer [Linux/Termux]
- [**23**Star][3y] [Py] [remnux/distro](https://github.com/remnux/distro) This repository contains supplementary files for building and using the REMnux Linux distribution. See
- [**23**Star][5y] [Assembly] [zerosum0x0/slae64](https://github.com/zerosum0x0/slae64) x64 Linux Shellcode
- [**22**Star][3y] [Shell] [johntroony/luks-ops](https://github.com/johntroony/luks-ops) A bash script to automate the most basic usage of LUKS volumes in Linux VPS
- [**22**Star][5y] [munmap/linux-kernel-bugs-db](https://github.com/munmap/linux-kernel-bugs-db) 
- [**21**Star][1y] [Py] [syno3/babymux](https://github.com/syno3/babymux) pentesting tool for noob hackers.Runs on linux and termux
- [**20**Star][3y] [C] [leixiangwu/cse509-rootkit](https://github.com/leixiangwu/cse509-rootkit) After attackers manage to gain access to a remote (or local) machine and elevate their privileges to "root", they typically want to maintain their access, while hiding their presence from the normal users and administrators of the system. This basic rootkit works on the Linux operating system and is a loadable kernel module which when loaded int…


***


## <a id="f6d78e82c3e5f67d13d9f00c602c92f0"></a>Post&&Videos




# <a id="3f1fde99538be4662dca6747a365640b"></a>Hook


***


## <a id="cfe974d48bbb90a930bf667c173616c7"></a>Tools


- [**1228**Star][1y] [Kotlin] [gh0u1l5/wechatspellbook](https://github.com/gh0u1l5/wechatspellbook) 使用Kotlin编写的开源微信插件框架，底层需要 Xposed 或 VirtualXposed 等Hooking框架的支持，而顶层可以轻松对接Java、Kotlin、Scala等JVM系语言。让程序员能够在几分钟内编写出简单的微信插件，随意揉捏微信的内部逻辑。
- [**1222**Star][3y] [C] [tsudakageyu/minhook](https://github.com/tsudakageyu/minhook) The Minimalistic x86/x64 API Hooking Library for Windows
- [**1114**Star][1y] [Objective-C] [yulingtianxia/fishchat](https://github.com/yulingtianxia/fishchat) Hook WeChat.app on non-jailbroken devices.
- [**1004**Star][5m] [C++] [everdox/infinityhook](https://github.com/everdox/infinityhook) Hook system calls, context switches, page faults and more.
- [**757**Star][20d] [Go] [thoughtworks/talisman](https://github.com/thoughtworks/talisman) By hooking into the pre-push hook provided by Git, Talisman validates the outgoing changeset for things that look suspicious - such as authorization tokens and private keys.
- [**670**Star][7m] [Java] [pagalaxylab/yahfa](https://github.com/PAGalaxyLab/YAHFA) Yet Another Hook Framework for ART
- [**640**Star][3m] [C++] [stevemk14ebr/polyhook](https://github.com/stevemk14ebr/polyhook) x86/x64 C++ Hooking Library
- [**568**Star][7m] [Objective-C] [rpetrich/captainhook](https://github.com/rpetrich/captainhook) Common hooking/monkey patching headers for Objective-C on Mac OS X and iPhone OS. MIT licensed
- [**530**Star][1y] [Objective-C++] [davidgoldman/inspectivec](https://github.com/davidgoldman/inspectivec) objc_msgSend hook for debugging/inspection purposes.
- [**509**Star][11d] [C] [mohuihui/antispy](https://github.com/mohuihui/antispy) AntiSpy is a free but powerful anti virus and rootkits toolkit.It offers you the ability with the highest privileges that can detect,analyze and restore various kernel modifications and hooks.With its assistance,you can easily spot and neutralize malwares hidden from normal detectors.
- [**475**Star][1y] [C++] [tandasat/ddimon](https://github.com/tandasat/ddimon) Monitoring and controlling kernel API calls with stealth hook using EPT
- [**458**Star][6y] [C] [martona/mhook](https://github.com/martona/mhook) A Windows API hooking library
- [**436**Star][16d] [C++] [stevemk14ebr/polyhook_2_0](https://github.com/stevemk14ebr/polyhook_2_0) C++17, x86/x64 Hooking Libary v2.0
- [**401**Star][8m] [C] [darthton/hyperbone](https://github.com/darthton/hyperbone) Minimalistic VT-x hypervisor with hooks
- [**366**Star][26d] [C++] [0x09al/rdpthief](https://github.com/0x09al/rdpthief) Extracting Clear Text Passwords from mstsc.exe using API Hooking.
- [**361**Star][1m] [C++] [steven-michaud/hookcase](https://github.com/steven-michaud/hookcase) Tool for reverse engineering macOS/OS X
- [**357**Star][2y] [JS] [kamikat/tttfi](https://github.com/kamikat/tttfi) Middleware for IFTTT.
- [**339**Star][5m] [C] [zeex/subhook](https://github.com/zeex/subhook) Simple hooking library for C/C++ (x86 only, 32/64-bit, no dependencies)
- [**322**Star][2y] [Java] [mar-v-in/arthook](https://github.com/mar-v-in/arthook) Library for hooking on ART
- [**299**Star][1y] [C] [nektra/deviare2](https://github.com/nektra/deviare2) Deviare API Hook
- [**272**Star][2y] [C++] [gellin/teamviewer_permissions_hook_v1](https://github.com/gellin/teamviewer_permissions_hook_v1) A proof of concept injectable C++ dll, that uses naked inline hooking and direct memory modification to change your TeamViewer permissions.
- [**260**Star][11m] [C] [nbulischeck/tyton](https://github.com/nbulischeck/tyton) Kernel-Mode Rootkit Hunter
- [**245**Star][4m] [C] [gbps/gbhv](https://github.com/gbps/gbhv) Simple x86-64 VT-x Hypervisor with EPT Hooking
- [**238**Star][5m] [C] [outflanknl/dumpert](https://github.com/outflanknl/dumpert) LSASS memory dumper using direct system calls and API unhooking.
- [**233**Star][22d] [C] [kubo/plthook](https://github.com/kubo/plthook) Hook function calls by replacing PLT(Procedure Linkage Table) entries.
- [**217**Star][1y] [C#] [easy66/monohooker](https://github.com/easy66/monohooker) hook C# method at runtime without modify dll file (such as UnityEditor.dll)
- [**211**Star][1y] [C] [suvllian/process-inject](https://github.com/suvllian/process-inject) 在Windows环境下的进程注入方法：远程线程注入、创建进程挂起注入、反射注入、APCInject、SetWindowHookEX注入
- [**176**Star][11m] [C] [fate0/xmark](https://github.com/fate0/xmark) A PHP7 extension that can hook most functions/classes and parts of opcodes
- [**138**Star][7m] [C] [coolervoid/hiddenwall](https://github.com/coolervoid/hiddenwall) Tool to generate a Linux kernel module for custom rules with Netfilter hooking. (block ports, Hidden mode, rootkit functions etc)
- [**136**Star][12m] [C] [alex3434/wmi-static-spoofer](https://github.com/alex3434/wmi-static-spoofer) Spoofing the Windows 10 HDD/diskdrive serialnumber from kernel without hooking
- [**135**Star][20d] [C] [davidbuchanan314/tardis](https://github.com/davidbuchanan314/tardis) Trace And Rewrite Delays In Syscalls: Hooking time-related Linux syscalls to warp a process's perspective of time, using ptrace.
- [**133**Star][2m] [C] [kubo/funchook](https://github.com/kubo/funchook) Funchook - an API Hook Library
- [**131**Star][4m] [C] [hoshimin/hooklib](https://github.com/hoshimin/hooklib) The functions interception library written on pure C and NativeAPI with UserMode and KernelMode support
- [**128**Star][9d] [C++] [hasherezade/iat_patcher](https://github.com/hasherezade/iat_patcher) Persistent IAT hooking application - based on bearparser
- [**128**Star][1y] [C++] [m0n0ph1/iat-hooking-revisited](https://github.com/m0n0ph1/iat-hooking-revisited) Import address table (IAT) hooking is a well documented technique for intercepting calls to imported functions.
- [**119**Star][1m] [C++] [rebzzel/kiero](https://github.com/rebzzel/kiero) Universal graphical hook for a D3D9-D3D12, OpenGL and Vulcan based games.
- [**117**Star][1y] [C] [cylancevulnresearch/reflectivedllrefresher](https://github.com/cylancevulnresearch/reflectivedllrefresher) Universal Unhooking
- [**116**Star][2y] [C#] [tandasat/dotnethooking](https://github.com/tandasat/dotnethooking) Sample use cases of the .NET native code hooking technique
- [**115**Star][3y] [C] [gdabah/distormx](https://github.com/gdabah/distormx) The ultimate hooking library
- [**110**Star][6y] [Ruby] [spiderlabs/beef_injection_framework](https://github.com/spiderlabs/beef_injection_framework) Inject beef hooks into HTTP traffic and track hooked systems from cmdline
- [**105**Star][4y] [Java] [rednaga/dexhook](https://github.com/rednaga/dexhook) DexHook is a xposed module for capturing dynamically loaded dex files.
- [**104**Star][3m] [C++] [tandasat/simplesvmhook](https://github.com/tandasat/simplesvmhook) SimpleSvmHook is a research purpose hypervisor for Windows on AMD processors.
- [**96**Star][4y] [Py] [eset/vba-dynamic-hook](https://github.com/eset/vba-dynamic-hook) dynamically analyzes VBA macros inside Office documents by hooking function calls
- [**92**Star][3y] [C++] [shmuelyr/captainhook](https://github.com/shmuelyr/captainhook) CaptainHook is perfect x86/x64 hook environment
- [**78**Star][3y] [C] [stevemk14ebr/unihook](https://github.com/stevemk14ebr/unihook) Intercept arbitrary functions at run-time, without knowing their typedefs
- [**77**Star][19d] [C] [apriorit/mhook](https://github.com/apriorit/mhook) A Windows API hooking library
- [**76**Star][6m] [Py] [enigmabridge/certbot-external-auth](https://github.com/enigmabridge/certbot-external-auth) Certbot external DNS, HTTP, TLSSNI domain validation plugin with JSON output and scriptable hooks, with Dehydrated compatibility
- [**76**Star][3y] [C] [tinysec/iathook](https://github.com/tinysec/iathook) windows kernelmode and usermode IAT hook
- [**75**Star][1y] [C++] [hrbust86/hookmsrbysvm](https://github.com/hrbust86/hookmsrbysvm) hook msr by amd svm
- [**75**Star][6m] [C] [milabs/khook](https://github.com/milabs/khook) Linux Kernel hooking engine (x86)
- [**71**Star][1y] [C] [chinatiny/inlinehooklib](https://github.com/chinatiny/inlinehooklib) 同时支持用户和内核模式的Inlinehook库
- [**67**Star][5y] [C] [malwaretech/basichook](https://github.com/malwaretech/basichook) x86 Inline hooking engine (using trampolines)
- [**67**Star][2y] [C++] [secrary/hooking-via-instrumentationcallback](https://github.com/secrary/hooking-via-instrumentationcallback) codes for my blog post:
- [**66**Star][9m] [Java] [bolexliu/apptrack](https://github.com/bolexliu/apptrack) Xposed HookAPP逆向跟踪工具，跟踪Activity与Fragment启动信息等
- [**63**Star][1y] [C] [dodola/fbhookfork](https://github.com/dodola/fbhookfork) 从 fb 的 profilo 项目里提取出来的hook 库，自己用
- [**62**Star][2m] [C] [zyantific/zyan-hook-engine](https://github.com/zyantific/zyan-hook-engine) Advanced x86/x86-64 hooking library (WIP).
- [**58**Star][4y] [C++] [codereversing/directx9hook](https://github.com/codereversing/directx9hook) Runtime DirectX9 Hooking
- [**58**Star][2y] [JS] [vah13/win_zip_password](https://github.com/vah13/win_zip_password) Python script to hook ZIP files passwords in Windows 10
- [**58**Star][1y] [C#] [wledfor2/playhooky](https://github.com/wledfor2/playhooky) C# Runtime Hooking Library for .NET/Mono/Unity.
- [**57**Star][3y] [C] [codectile/paradise](https://github.com/codectile/paradise) x86/x86-64 hooking library
- [**57**Star][1y] [C++] [petrgeorgievsky/gtarenderhook](https://github.com/petrgeorgievsky/gtarenderhook) GTA SA rendering hook
- [**55**Star][13d] [C] [danielkrupinski/vac-hooks](https://github.com/danielkrupinski/vac-hooks) Hook WinAPI functions used by Valve Anti-Cheat. Log calls and intercept arguments & return values. DLL written in C.
- [**54**Star][5y] [C++] [malwaretech/fsthook](https://github.com/malwaretech/fsthook) A library for intercepting native functions by hooking KiFastSystemCall
- [**54**Star][3y] [C] [passingtheknowledge/ganxo](https://github.com/passingtheknowledge/ganxo) An opensource API hooking framework
- [**53**Star][1y] [C] [chen-charles/pedetour](https://github.com/chen-charles/pedetour) modify binary Portable Executable to hook its export functions
- [**46**Star][3y] [C] [zhuhuibeishadiao/pfhook](https://github.com/zhuhuibeishadiao/pfhook) Page fault hook use ept (Intel Virtualization Technology)
- [**45**Star][10m] [C] [ilammy/ftrace-hook](https://github.com/ilammy/ftrace-hook) Using ftrace for function hooking in Linux kernel
- [**45**Star][9m] [C] [jay/gethooks](https://github.com/jay/gethooks) GetHooks is a program designed for the passive detection and monitoring of hooks from a limited user account.
- [**44**Star][1y] [C++] [coltonon/reghookex](https://github.com/coltonon/reghookex) External mid-function hooking method to retrieve register data
- [**44**Star][28d] [C++] [wopss/renhook](https://github.com/wopss/renhook) An open-source x86 / x86-64 hooking library for Windows.
- [**42**Star][4m] [C#] [userr00t/universalunityhooks](https://github.com/userr00t/universalunityhooks) A framework designed to hook into and modify methods in unity games via dlls
- [**41**Star][9y] [C++] [cr4sh/ptbypass-poc](https://github.com/cr4sh/ptbypass-poc) Bypassing code hooks detection in modern anti-rootkits via building faked PTE entries.
- [**40**Star][10m] [C] [dzzie/hookexplorer](https://github.com/dzzie/hookexplorer) technical tool to analyze a process trying to find various types of runtime hooks. Interface and output is geared torwards security experts. Average users wont be able to decipher its output.
- [**38**Star][1y] [JS] [lmammino/webhook-tunnel](https://github.com/lmammino/webhook-tunnel) A little HTTP proxy suitable to create tunnels for webhook endpoints protected behind a firewall or a VPN
- [**37**Star][2y] [C++] [tanninone/usvfs](https://github.com/tanninone/usvfs) library using api hooking to implement process-local filesystem-independent file links.
- [**37**Star][5y] [Assembly] [muffins/rookit_playground](https://github.com/muffins/rookit_playground) Educational repository for learning about rootkits and Windows Kernel Hooks.
- [**37**Star][3m] [Perl] [theos/logos](https://github.com/theos/logos) Preprocessor that simplifies Objective-C hooking.
- [**35**Star][4y] [C++] [codereversing/wow64syscall](https://github.com/codereversing/wow64syscall) WoW64 Syscall Hooking
- [**35**Star][3y] [C] [harvie/libpurple-core-answerscripts](https://github.com/harvie/libpurple-core-answerscripts) Most-hackable Pidgin plugin! Framework for hooking scripts to respond received messages for various libpurple clients such as pidgin or finch
- [**35**Star][2y] [C] [jordan9001/superhide](https://github.com/jordan9001/superhide) Example of hooking a linux systemcall
- [**33**Star][2y] [C++] [menooker/fishhook](https://github.com/menooker/fishhook) An inline hook platform for Windows x86/x64
- [**33**Star][1y] [C++] [nickcano/reloadlibrary](https://github.com/nickcano/reloadlibrary) A quick-and-dirty anti-hook library proof of concept.
- [**33**Star][11m] [C++] [niemand-sec/directx11hook](https://github.com/niemand-sec/directx11hook) 
- [**33**Star][1y] [C#] [roshly/ayyhook-loader](https://github.com/roshly/ayyhook-loader) A Free Open Source Cheat Loader
- [**31**Star][5y] [idkwim/frooksinatra](https://github.com/idkwim/frooksinatra) POC of sysenter x64 LSTAR MSR hook
- [**30**Star][17d] [C++] [ayuto/dynamichooks](https://github.com/ayuto/dynamichooks) A C++ library to create function hooks dynamically, so you can easily embed it into other programming languages..
- [**30**Star][3m] [C++] [rokups/hooker](https://github.com/rokups/hooker) Minimalistic hooking library written in C
- [**30**Star][8m] [C#] [thaisenpm/loader2](https://github.com/thaisenpm/loader2) Nova Hook is an open source C# cheat loader currently built for CS:GO
- [**28**Star][11m] [C++] [hoangprod/leospecial-veh-hook](https://github.com/hoangprod/leospecial-veh-hook) Vectored Exception Handling Hooking Class
- [**27**Star][2y] [C] [deroko/activationcontexthook](https://github.com/deroko/activationcontexthook) activationcontexthook：Hook 进程，强制进程加载重定向的 DLL
- [**27**Star][6m] [C++] [m-r-j-o-h-n/swh-injector](https://github.com/m-r-j-o-h-n/swh-injector) An Injector that can inject dll into game process protected by anti cheat using SetWindowsHookEx.
- [**27**Star][4m] [C++] [netdex/twinject](https://github.com/netdex/twinject) Automated player and hooking framework for bullet hell games from the Touhou Project
- [**27**Star][2y] [C] [sentinel-one/minhook](https://github.com/sentinel-one/minhook) The Minimalistic x86/x64 API Hooking Library for Windows
- [**27**Star][10m] [JS] [shanselman/daskeyboard-q-nightscout](https://github.com/shanselman/daskeyboard-q-nightscout) Hooking up the DasKeyboard Q REST API to change the key colors in response to diabetic's glucose from NightScout
- [**27**Star][3y] [C] [tinysec/runwithdll](https://github.com/tinysec/runwithdll) windows create process with a dll load first time via LdrHook
- [**26**Star][1y] [HTML] [flyrabbit/winproject](https://github.com/flyrabbit/winproject) Hook, DLLInject, PE_Tool
- [**26**Star][3y] [C++] [ilyatk/hookengine](https://github.com/ilyatk/hookengine) 
- [**26**Star][5y] [C++] [strobejb/sslhook](https://github.com/strobejb/sslhook) OpenSSL hooking
- [**25**Star][5m] [Java] [mx-futhark/hook-any-text](https://github.com/mx-futhark/hook-any-text) The goal of this project is to provide an alternative to well established text hookers, whose features are restrained to a certain number of game engines and emulators.
- [**24**Star][2y] [Py] [dsnezhkov/octohook](https://github.com/dsnezhkov/octohook) Git Web Hook Tunnel for C2
- [**23**Star][3y] [C] [david-reguera-garcia-dreg/phook](https://github.com/david-reguera-garcia-dreg/phook) Full DLL Hooking, phrack 65
- [**23**Star][3y] [Java] [jackuhan/loginhook](https://github.com/jackuhan/loginhook) xposed的hook案例
- [**23**Star][6m] [C] [maikel233/x-hook-for-csgo](https://github.com/maikel233/x-hook-for-csgo) Aimtux for Windows.
- [**23**Star][3y] [C++] [matviy/leaguereplayhook](https://github.com/matviy/leaguereplayhook) Library for interacting with the League of Legends Spectator/Replay Client
- [**22**Star][3y] [C++] [apriorit/simple-antirootkit-sst-unhooker](https://github.com/apriorit/simple-antirootkit-sst-unhooker) This is a demo project to illustrate the way to verify and restore original SST in case of some malware hooks
- [**22**Star][3y] [C++] [bronzeme/ssdt_hook_x64](https://github.com/bronzeme/ssdt_hook_x64) 
- [**22**Star][6y] [C] [jyang772/hideprocesshookmdl](https://github.com/jyang772/hideprocesshookmdl) A simple rootkit to hide a process
- [**22**Star][2m] [C++] [legendl3n/smarthooker](https://github.com/legendl3n/smarthooker) The smartest hooking library.
- [**21**Star][4y] [C++] [xbased/xhook](https://github.com/xbased/xhook) Hook Windows API. supports Win7/8/10 x86 and x64 platform.


# <a id="70e64e3147675c9bcd48d4f475396e7f"></a>Monitor


***


## <a id="cd76e644d8ddbd385939bb17fceab205"></a>Tools


- [**1407**Star][7d] [C] [namhyung/uftrace](https://github.com/namhyung/uftrace) Function (graph) tracer for user-space
- [**183**Star][1y] [C++] [sidechannelmarvels/tracer](https://github.com/sidechannelmarvels/tracer) Set of Dynamic Binary Instrumentation and visualization tools for execution traces.
- [**145**Star][6d] [C] [immunityinc/libptrace](https://github.com/immunityinc/libptrace) An event driven multi-core process debugging, tracing, and manipulation framework.
- [**134**Star][12d] [PowerShell] [lazywinadmin/monitor-adgroupmembership](https://github.com/lazywinadmin/Monitor-ADGroupMembership) PowerShell script to monitor Active Directory groups and send an email when someone is changing the membership
- [**115**Star][9y] [C] [ice799/ltrace](https://github.com/ice799/ltrace) ltrace intercepts and records dynamic library calls which are called by an executed process and the signals received by that process. It can also intercept and print the system calls executed by the program.
- [**109**Star][2y] [C#] [goldshtn/etrace](https://github.com/goldshtn/etrace) Command-line tool for ETW tracing on files and real-time events
- [**104**Star][9d] [Objective-C] [objective-see/processmonitor](https://github.com/objective-see/processmonitor) Process Monitor Library (based on Apple's new Endpoint Security Framework)
- [**93**Star][5m] [Py] [teemu-l/execution-trace-viewer](https://github.com/teemu-l/execution-trace-viewer) Tool for viewing and analyzing execution traces
- [**89**Star][2y] [C++] [epam/nfstrace](https://github.com/epam/nfstrace) Network file system monitor and analyzer
- [**87**Star][1m] [Py] [assurancemaladiesec/certstreammonitor](https://github.com/assurancemaladiesec/certstreammonitor) Monitor certificates generated for specific domain strings and associated, store data into sqlite3 database, alert you when sites come online.
- [**83**Star][1y] [C] [marcusbotacin/branchmonitoringproject](https://github.com/marcusbotacin/branchmonitoringproject) A branch-monitor-based solution for process monitoring.
- [**82**Star][4y] [C] [eklitzke/ptrace-call-userspace](https://github.com/eklitzke/ptrace-call-userspace) Example of how to use the ptrace(2) system call to call a userspace method.
- [**68**Star][2y] [Py] [ianmiell/autotrace](https://github.com/ianmiell/autotrace) Runs a process, and gives you the output along with other telemetry on the process, all in one terminal window.
- [**60**Star][2y] [DTrace] [brendangregg/dtrace-tools](https://github.com/brendangregg/dtrace-tools) DTrace tools for FreeBSD
- [**60**Star][2y] [C++] [finixbit/ftrace](https://github.com/finixbit/ftrace) Simple Function calls tracer
- [**57**Star][6m] [C++] [invictus1306/functrace](https://github.com/invictus1306/functrace) A function tracer
- [**51**Star][3y] [C] [sciencemanx/ftrace](https://github.com/sciencemanx/ftrace) trace local function calls like strace and ltrace
- [**46**Star][5m] [Go] [oscp/openshift-monitoring](https://github.com/oscp/openshift-monitoring) A realtime distributed monitoring tool for OpenShift Enterprise
- [**44**Star][5y] [C] [rpaleari/qtrace](https://github.com/rpaleari/qtrace) QTrace, a "zero knowledge" system call tracer
- [**39**Star][4y] [C++] [simutrace/simutrace](https://github.com/simutrace/simutrace) Tracing framework for full system simulators
- [**37**Star][1y] [C] [egguncle/ptraceinject](https://github.com/egguncle/ptraceinject) 进程注入
- [**35**Star][7d] [C] [efficios/babeltrace](https://github.com/efficios/babeltrace) The Babeltrace project provides trace read and write libraries, as well as a trace converter. Plugins can be created for any trace format to allow its conversion to/from another trace format.
- [**32**Star][1y] [C] [alex9191/kernelmodemonitor](https://github.com/alex9191/kernelmodemonitor) Kernel-Mode driver and User-Mode application communication project
- [**31**Star][1y] [C] [iamgublin/ndis6.30-netmonitor](https://github.com/iamgublin/ndis6.30-netmonitor) NDIS6.30 Filter Library
- [**27**Star][1y] [C] [openbsm/bsmtrace](https://github.com/openbsm/bsmtrace) BSM based intrusion detection system
- [**26**Star][2y] [Go] [benjojo/traceroute-haiku](https://github.com/benjojo/traceroute-haiku) A thing you can traceroute and it gives you a haiku inside the trace
- [**25**Star][2m] [C] [airbus-cert/pstrace](https://github.com/airbus-cert/pstrace) Trace ScriptBlock execution for powershell v2
- [**23**Star][1y] [C++] [sshsshy/zerotrace](https://github.com/sshsshy/zerotrace) 
- [**21**Star][2y] [C++] [microsoft/firewalleventmonitor](https://github.com/microsoft/firewalleventmonitor) Listens for Firewall rule match events generated by Microsoft Hyper-V Virtual Filter Protocol (VFP) extension.


# <a id="28aa8187f8a1e38ca5a55aa31a5ee0c3"></a>Game


***


## <a id="07f0c2cbf63c1d7de6f21fa43443ede3"></a>Tools


- [**1124**Star][12d] [C++] [crosire/reshade](https://github.com/crosire/reshade) A generic post-processing injector for games and video software.
- [**1122**Star][3m] [Py] [openai/neural-mmo](https://github.com/openai/neural-mmo) Code for the paper "Neural MMO: A Massively Multiagent Game Environment for Training and Evaluating Intelligent Agents"
- [**723**Star][6m] [Assembly] [cirosantilli/x86-assembly-cheat](https://github.com/cirosantilli/x86-assembly-cheat) the bulk of the x86 instruction examples with assertions.
- [**515**Star][2m] [Kotlin] [jire/charlatano](https://github.com/jire/charlatano) Proves JVM cheats are viable on native games, and demonstrates the longevity against anti-cheat signature detection systems
- [**353**Star][18d] [C] [liji32/sameboy](https://github.com/liji32/sameboy) Game Boy and Game Boy Color emulator written in C
- [**351**Star][11d] [C#] [leaguesandbox/gameserver](https://github.com/leaguesandbox/gameserver) League Sandbox's Game Server
- [**260**Star][5m] [C++] [niemand-sec/anticheat-testing-framework](https://github.com/niemand-sec/anticheat-testing-framework) Framework for testing any Anti-Cheat
- [**244**Star][5y] [C++] [gametutorials/tutorials](https://github.com/gametutorials/tutorials) This holds the tutorials for GameTutorials.com
- [**244**Star][2y] [C] [zer0mem0ry/kernelbhop](https://github.com/zer0mem0ry/kernelbhop) Cheat that uses a driver instead WinAPI for Reading / Writing memory.
- [**215**Star][2m] [C] [xyzz/gamecard-microsd](https://github.com/xyzz/gamecard-microsd) microSD adapter for PlayStation Vita
- [**204**Star][4m] [C++] [eternityx/deadcell-csgo](https://github.com/eternityx/deadcell-csgo) Full source to the CS:GO cheat
- [**199**Star][3y] [Assembly] [vector35/pwnadventurez](https://github.com/vector35/pwnadventurez) NES zombie survival game made to be hacked
- [**195**Star][1y] [Java] [nocheatplus/nocheatplus](https://github.com/nocheatplus/nocheatplus) Anti cheating plugin for Minecraft (Bukkit/Spigot).
- [**193**Star][9m] [zardus/wargame-nexus](https://github.com/zardus/wargame-nexus) An sorted and updated list of security wargame sites.
- [**176**Star][3y] [hexorg/cheatenginetables](https://github.com/hexorg/cheatenginetables) Repository of tables for CheatEngine
- [**172**Star][7m] [C#] [krzys-h/undertalemodtool](https://github.com/krzys-h/undertalemodtool) The most complete tool for modding, decompiling and unpacking Undertale (and other Game Maker: Studio games!)
- [**163**Star][5m] [C++] [a5-/gamerfood_csgo](https://github.com/a5-/gamerfood_csgo) Fully featured CSGO cheat by Team Gamerfood
- [**125**Star][12m] [C++] [mq1n/nomercy](https://github.com/mq1n/nomercy) Open source anti cheat
- [**113**Star][1y] [C++] [scgywx/fooking](https://github.com/scgywx/fooking) distributed gateway server(php game server, tcp server, websocket server)
- [**106**Star][12d] [portswigger/xss-cheatsheet-data](https://github.com/portswigger/xss-cheatsheet-data) This repository contains all the XSS cheatsheet data to allow contributions from the community.
- [**104**Star][12d] [leomaurodesenv/game-datasets](https://github.com/leomaurodesenv/game-datasets) 
- [**104**Star][1y] [mitre/brawl-public-game-001](https://github.com/mitre/brawl-public-game-001) Data from a BRAWL Automated Adversary Emulation Exercise
- [**95**Star][9m] [C] [sagaantheepic/sagaan-anticheat-v2.0](https://github.com/ContionMig/ContionMig-AntiCheat) Anti Cheat i made in my free time. Credits to everyone who helped are in the files and some are in the code. I will definitely improve this Anti Cheat along the way, now its just beta. Enjoy.
- [**87**Star][6m] [TeX] [rudymatela/concise-cheat-sheets](https://github.com/rudymatela/concise-cheat-sheets) Cheat Sheets for programming languages and tools
- [**85**Star][8m] [C++] [huanghongkai/game-helper](https://github.com/huanghongkai/game-helper) 介绍入门级游戏辅助的原理，内附有2018年2月dnf辅助C++源码
- [**81**Star][2m] [Py] [mattcurrie/mgbdis](https://github.com/mattcurrie/mgbdis) Game Boy ROM disassembler with RGBDS compatible output
- [**79**Star][2y] [JS] [vmikhav/antipacman](https://github.com/vmikhav/AntiPacMan) HTML5 Pac-Man game with gesture recognition
- [**75**Star][3m] [ignitetechnologies/web-application-cheatsheet](https://github.com/ignitetechnologies/web-application-cheatsheet) This cheatsheet is aimed at the CTF Players and Beginners to help them understand Web Application Vulnerablity with examples.
- [**63**Star][21d] [C#] [firebaseextended/unity-solutions](https://github.com/FirebaseExtended/unity-solutions) Use Firebase tools to incorporate common features into your games!
- [**62**Star][8y] [Java] [yifanlu/psxperia](https://github.com/yifanlu/psxperia) This tool will take a PSX image that you legally own and convert it to be playable on the Xperia Play with the emulator extracted from the packaged game "Crash Bandicoot."
- [**61**Star][3y] [Shell] [abs0/wargames](https://github.com/abs0/wargames) Shell script to simulate the W.O.P.R. computer from WarGames (wopr)
- [**61**Star][7m] [C++] [apexlegendsuc/anti-cheat-emulator](https://github.com/apexlegendsuc/anti-cheat-emulator) 
- [**60**Star][2y] [C++] [jmasterx/agui](https://github.com/jmasterx/agui) C++ GUI API Aimed at Games
- [**56**Star][1y] [Py] [p1kachu/talking-with-cars](https://github.com/p1kachu/talking-with-cars) CAN analysis - Use your car as a gamepad!
- [**50**Star][3y] [C] [ryanmallon/thelostvikingstools](https://github.com/ryanmallon/thelostvikingstools) Reverse Engineered Tools/Library for the DOS game The Lost Vikings
- [**47**Star][4y] [Py] [topshed/rpi_8x8griddraw](https://github.com/topshed/rpi_8x8griddraw) A Python Pygame application for creating 8x8 images to load onto the Astro-Pi LED matrix
- [**46**Star][1y] [Py] [towerofhanoi/ctfsubmitter](https://github.com/towerofhanoi/ctfsubmitter) A flag submitter service with distributed attackers for attack/defense CTF games.
- [**45**Star][1m] [Py] [skoolkid/skoolkit](https://github.com/skoolkid/skoolkit) A suite of tools for creating disassemblies of ZX Spectrum games.
- [**44**Star][2y] [C#] [mythicmaniac/keyboard-minigames](https://github.com/mythicmaniac/keyboard-minigames) A snake game for the corsair RGB keyboards
- [**43**Star][2y] [JS] [auth0-blog/aliens-go-home-part-1](https://github.com/auth0-blog/aliens-go-home-part-1) GitHub repository that accompanies the first article of the "Developing Games with React, Redux, and SVG" series.
- [**42**Star][3m] [Pawn] [stypr/tmpleak](https://github.com/stypr/tmpleak) Leak off used temporary workspaces for ctf and wargames!
- [**38**Star][1y] [c++] [fluc-uc/emusdk](https://github.com/fluc-uc/emusdk) A simple SDK intended for people new to internal cheats. Written while I was drunk.
- [**38**Star][1y] [C++] [contionmig/lsass-usermode-bypass](https://github.com/ContionMig/LSASS-Usermode-Bypass) This bypass is for anti cheats like battleye and EAC. All this does is abuse lsass's handles and use them for yourself. This is quite useful as this is usermode which doesnt require you to find a way to load a driver
- [**36**Star][19d] [Assembly] [dpt/the-great-escape](https://github.com/dpt/the-great-escape) Reverse engineering classic ZX Spectrum game "The Great Escape"
- [**35**Star][4y] [Py] [iiseymour/game-of-life](https://github.com/iiseymour/game-of-life) Conway's Game Of Life
- [**33**Star][2m] [C++] [chinatiny/gameanticheat](https://github.com/chinatiny/gameanticheat) 反外挂
- [**33**Star][1y] [vu-aml/adlib](https://github.com/vu-aml/adlib) Game-Theoretic Adversarial Machine Learning Library
- [**33**Star][2m] [PHP] [safflower/solveme](https://github.com/safflower/solveme) SolveMe - Jeopardy CTF Platform (for wargame)
- [**30**Star][1y] [C++] [certt/1000base](https://github.com/certt/1000base) CS:GO cheat base
- [**28**Star][4y] [JS] [crisu83/ctf-game](https://github.com/crisu83/ctf-game) Fast-paced hot seat multiplayer game written in modern JavaScript.
- [**26**Star][1y] [C++] [cyanidee/snowflake](https://github.com/cyanidee/snowflake) A simple CSGO cheat base written in mind of begginers.
- [**26**Star][3y] [Ruby] [qazbnm456/docker-war](https://github.com/qazbnm456/docker-war) Docker based Wargame Platform - To practice your CTF skills
- [**25**Star][10m] [C++] [shaxzy/nixware-csgo](https://github.com/shaxzy/nixware-csgo) Source code of Nixware. Cheat doesn't inject for some reason, fix it uself or just paste from it
- [**24**Star][2y] [JS] [auth0-blog/nextjs-got](https://github.com/auth0-blog/nextjs-got) A simple nextjs application that showcases Game of Thrones Characters
- [**23**Star][1y] [Py] [gynvael/arcanesector](https://github.com/gynvael/arcanesector) Arcane Sector game - a CTF task, or old-school (MMO)RPG - depending on the perspective. The code is of terrible quality, you have been warned!
- [**20**Star][2y] [C] [bisoon/ps4-api-server](https://github.com/bisoon/ps4-api-server) PS4API server to handle client request for read/write to game memory
- [**20**Star][2y] [C++] [mrexodia/ceautoattach](https://github.com/mrexodia/ceautoattach) Tool to automatically make Cheat Engine attach to a process via the command line.
- [**20**Star][2y] [C] [nkga/cheat-driver](https://github.com/nkga/cheat-driver) Kernel mode driver for reading/writing process memory. C/Win32.


# <a id="09fa851959ff48f5667a2099c861eab8"></a>Malware


***


## <a id="e781a59e4f4daab058732cf66f77bfb9"></a>Tools


- [**1433**Star][1y] [TypeScript] [pedronauck/reworm](https://github.com/pedronauck/reworm) 
- [**927**Star][4m] [Py] [airbnb/binaryalert](https://github.com/airbnb/binaryalert) Serverless, Real-time & Retroactive Malware Detection.
- [**777**Star][2m] [Py] [gosecure/malboxes](https://github.com/gosecure/malboxes) Builds malware analysis Windows VMs so that you don't have to.
- [**679**Star][17d] [Py] [rurik/noriben](https://github.com/rurik/noriben) Portable, Simple, Malware Analysis Sandbox
- [**654**Star][8m] [Shell] [rfxn/linux-malware-detect](https://github.com/rfxn/linux-malware-detect) Linux Malware Detection (LMD)
- [**591**Star][5m] [fabrimagic72/malware-samples](https://github.com/fabrimagic72/malware-samples) A collection of malware samples caught by several honeypots i manage
- [**563**Star][2m] [Py] [certsocietegenerale/fame](https://github.com/certsocietegenerale/fame) FAME Automates Malware Evaluation
- [**551**Star][5y] [Py] [krmaxwell/maltrieve](https://github.com/krmaxwell/maltrieve) A tool to retrieve malware directly from the source for security researchers.
- [**534**Star][2m] [Py] [tencent/habomalhunter](https://github.com/tencent/habomalhunter) HaboMalHunter is a sub-project of Habo Malware Analysis System (
- [**488**Star][29d] [C] [hasherezade/demos](https://github.com/hasherezade/demos) Demos of various injection techniques found in malware
- [**423**Star][1y] [Py] [endgameinc/gym-malware](https://github.com/endgameinc/gym-malware) a malware manipulation environment for OpenAI's gym
- [**405**Star][5y] [Py] [paloaltonetworks/wirelurkerdetector](https://github.com/paloaltonetworks/wirelurkerdetector) Script for detecting the WireLurker malware family
- [**404**Star][5y] [Ruby] [svent/jsdetox](https://github.com/svent/jsdetox) A Javascript malware analysis tool
- [**392**Star][1m] [YARA] [guelfoweb/peframe](https://github.com/guelfoweb/peframe) PEframe is a open source tool to perform static analysis on Portable Executable malware and malicious MS Office documents.
- [**390**Star][6m] [JS] [capacitorset/box-js](https://github.com/capacitorset/box-js) A tool for studying JavaScript malware.
- [**386**Star][7d] [C#] [collinbarrett/filterlists](https://github.com/collinbarrett/filterlists) independent, comprehensive directory of filter and host lists for advertisements, trackers, malware, and annoyances.
- [**375**Star][7m] [Py] [secrary/ssma](https://github.com/secrary/ssma) SSMA - Simple Static Malware Analyzer [This project is not maintained anymore]
- [**370**Star][3y] [PHP] [nikicat/web-malware-collection](https://github.com/nikicat/web-malware-collection) Clone of svn repository of
- [**369**Star][5y] [Go] [vishvananda/wormhole](https://github.com/vishvananda/wormhole) A smart proxy to connect docker containers.
- [**366**Star][5y] [C] [arialdomartini/morris-worm](https://github.com/arialdomartini/morris-worm) The original Morris Worm source code
- [**366**Star][2m] [AngelScript] [inquest/malware-samples](https://github.com/inquest/malware-samples) A collection of malware samples and relevant dissection information, most probably referenced from
- [**363**Star][3m] [Py] [neo23x0/munin](https://github.com/neo23x0/munin) Online hash checker for Virustotal and other services
- [**362**Star][3y] [C] [gbrindisi/malware](https://github.com/gbrindisi/malware) malware source codes
- [**355**Star][3y] [JS] [antimalware/manul](https://github.com/antimalware/manul) Antimalware tool for websites
- [**353**Star][5m] [Py] [hasherezade/malware_analysis](https://github.com/hasherezade/malware_analysis) Various snippets created during malware analysis
- [**331**Star][8m] [Py] [rek7/fireelf](https://github.com/rek7/fireelf) Fileless Linux Malware Framework
- [**325**Star][7d] [Py] [fireeye/stringsifter](https://github.com/fireeye/stringsifter) A machine learning tool that automatically ranks strings based on their relevance for malware analysis.
- [**324**Star][3y] [mikesiko/practicalmalwareanalysis-labs](https://github.com/mikesiko/practicalmalwareanalysis-labs) Binaries for the book Practical Malware Analysis
- [**310**Star][21d] [C#] [malware-dev/mdk-se](https://github.com/malware-dev/mdk-se) Malware's Development Kit for SE
- [**307**Star][1y] [C++] [m0n0ph1/process-hollowing](https://github.com/m0n0ph1/process-hollowing) Great explanation of Process Hollowing (a Technique often used in Malware)
- [**304**Star][2y] [C++] [m0n0ph1/malware-1](https://github.com/m0n0ph1/malware-1) Malware source code samples leaked online uploaded to GitHub for those who want to analyze the code.
- [**302**Star][11m] [Assembly] [guitmz/virii](https://github.com/guitmz/virii) Collection of ancient computer virus source codes
- [**302**Star][4m] [JS] [hynekpetrak/malware-jail](https://github.com/hynekpetrak/malware-jail) Sandbox for semi-automatic Javascript malware analysis, deobfuscation and payload extraction. Written for Node.js
- [**283**Star][7m] [Java] [katjahahn/portex](https://github.com/katjahahn/portex) Java library to analyse Portable Executable files with a special focus on malware analysis and PE malformation robustness
- [**281**Star][8m] [Py] [phage-nz/ph0neutria](https://github.com/phage-nz/ph0neutria) ph0neutria is a malware zoo builder that sources samples straight from the wild. Everything is stored in Viper for ease of access and manageability.
- [**279**Star][4y] [Py] [monnappa22/limon](https://github.com/monnappa22/limon) Limon is a sandbox developed as a research project written in python, which automatically collects, analyzes, and reports on the run time indicators of Linux malware. It allows one to inspect Linux malware before execution, during execution, and after execution (post-mortem analysis) by performing static, dynamic and memory analysis using open s…
- [**277**Star][7m] [C] [rieck/malheur](https://github.com/rieck/malheur) A Tool for Automatic Analysis of Malware Behavior
- [**268**Star][2m] [JS] [hynekpetrak/javascript-malware-collection](https://github.com/hynekpetrak/javascript-malware-collection) Collection of almost 40.000 javascript malware samples
- [**252**Star][10m] [C++] [ramadhanamizudin/malware](https://github.com/ramadhanamizudin/malware) Malware Samples. Uploaded to GitHub for those want to analyse the code. Code mostly from:
- [**240**Star][1m] [Py] [a3sal0n/falcongate](https://github.com/a3sal0n/falcongate) A smart gateway to stop hackers and Malware attacks
- [**239**Star][3y] [Go] [egebalci/egesploit](https://github.com/egebalci/egesploit) EGESPLOIT is a golang library for malware development
- [**237**Star][8m] [C++] [mstfknn/malware-sample-library](https://github.com/mstfknn/malware-sample-library) Malware sample library.
- [**235**Star][6y] [Py] [xen0ph0n/yaragenerator](https://github.com/xen0ph0n/yaragenerator) quick, simple, and effective yara rule creation to isolate malware families and other malicious objects of interest
- [**230**Star][2m] [C++] [richkmeli/richkware](https://github.com/richkmeli/richkware) Framework for building Windows malware, written in C++
- [**228**Star][3y] [Visual Basic] [malwares/crypter](https://github.com/malwares/crypter) Windows Crypter
- [**225**Star][5y] [Py] [nanyomy/dht-woodworm](https://github.com/nanyomy/dht-woodworm) this python repo is used to get the info_hash from DHT network, enjoy it
- [**215**Star][3y] [Py] [mkorman90/volatilitybot](https://github.com/mkorman90/volatilitybot) An automated memory analyzer for malware samples and memory dumps
- [**212**Star][2m] [Py] [eset/malware-research](https://github.com/eset/malware-research) Code written as part of our various malware investigations
- [**206**Star][1y] [Py] [malicialab/avclass](https://github.com/malicialab/avclass) AVClass malware labeling tool
- [**202**Star][12d] [Py] [doomedraven/virustotalapi](https://github.com/doomedraven/virustotalapi) VirusTotal Full api
- [**198**Star][2m] [C++] [secrary/drsemu](https://github.com/secrary/drsemu) 根据动态行为检测恶意代码并进行分类
- [**196**Star][3y] [Ruby] [spiderlabs/malware-analysis](https://github.com/spiderlabs/malware-analysis) A repository of tools and scripts related to malware analysis
- [**191**Star][7m] [Shell] [gaenserich/hostsblock](https://github.com/gaenserich/hostsblock) an ad- and malware-blocking script for Linux
- [**188**Star][1y] [Py] [malwarereversebrasil/malwaresearch](https://github.com/malwarereversebrasil/malwaresearch) A command line tool to find malwares on http://openmalware.org
- [**187**Star][5y] [Ruby] [m4rco-/dorothy2](https://github.com/m4rco-/dorothy2) A malware/botnet analysis framework written in Ruby.
- [**185**Star][12m] [PowerShell] [felixweyne/processspawncontrol](https://github.com/felixweyne/processspawncontrol) a Powershell tool which aims to help in the behavioral (process) analysis of malware. PsC suspends newly launched processes, and gives the analyst the option to either keep the process suspended, or to resume it.
- [**183**Star][4y] [Py] [xen0ph0n/virustotal_api_tool](https://github.com/xen0ph0n/virustotal_api_tool) A Tool To Leverage Virus Total's Private API Key
- [**182**Star][4y] [Pascal] [chiggins/malware_sources](https://github.com/chiggins/malware_sources)  I found all of these samples on MalwareTech through Twitter somewhere
- [**178**Star][4m] [Py] [hanul93/kicomav](https://github.com/hanul93/kicomav) KicomAV is an open source (GPL v2) antivirus engine designed for detecting malware and disinfecting it.
- [**170**Star][12d] [JS] [cert-polska/mquery](https://github.com/cert-polska/mquery) YARA malware query accelerator (web frontend)
- [**170**Star][3y] [C++] [phat3/pindemonium](https://github.com/phat3/pindemonium) A pintool in order to unpack malware
- [**169**Star][2m] [C#] [samueltulach/virustotaluploader](https://github.com/samueltulach/virustotaluploader) C# Open-Source Winforms application for uploading files to VirusTotal
- [**168**Star][4y] [Py] [dynetics/malfunction](https://github.com/dynetics/malfunction) Malware Analysis Tool using Function Level Fuzzy Hashing
- [**164**Star][11m] [Py] [ghostmanager/domaincheck](https://github.com/ghostmanager/domaincheck) DomainCheck is designed to assist operators with monitoring changes related to their domain names. This includes negative changes in categorization, VirusTotal detections, and appearances on malware blacklists. DomainCheck currently works only with NameCheap.
- [**160**Star][3y] [Py] [504ensicslabs/damm](https://github.com/504ensicslabs/damm) Differential Analysis of Malware in Memory
- [**160**Star][3m] [Py] [blacktop/virustotal-api](https://github.com/blacktop/virustotal-api) Virus Total Public/Private/Intel API
- [**151**Star][8d] [C] [pkroma/processhacker](https://github.com/pkroma/processhacker) A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware—mirror of
- [**150**Star][6y] [onx/cih](https://github.com/onx/cih) The source code of the CIH virus
- [**149**Star][2m] [Shell] [countercept/snake](https://github.com/countercept/snake) snake - a malware storage zoo
- [**147**Star][2y] [C] [elfmaster/skeksi_virus](https://github.com/elfmaster/skeksi_virus) Devestating and awesome Linux X86_64 ELF Virus
- [**147**Star][6y] [C++] [kaiserfarrell/malware](https://github.com/kaiserfarrell/malware) virus collection source code
- [**145**Star][10m] [Dockerfile] [remnux/docker](https://github.com/remnux/docker) This repository contains Dockerfiles for building Docker images of popular malware analysis tools. See
- [**143**Star][3y] [Py] [codexgigassys/codex-backend](https://github.com/codexgigassys/codex-backend) Codex Gigas malware DNA profiling search engine discovers malware patterns and characteristics assisting individuals who are attracted in malware hunting.
- [**143**Star][3y] [Assembly] [ricardojrdez/anti-analysis-tricks](https://github.com/ricardojrdez/anti-analysis-tricks) Bunch of techniques potentially used by malware to detect analysis environments
- [**141**Star][11m] [C++] [virustotal/qt-virustotal-uploader](https://github.com/virustotal/qt-virustotal-uploader) VirusTotal Uploader written in C++ using QT framework
- [**140**Star][8m] [Objective-C] [objective-see/reikey](https://github.com/objective-see/reikey) Malware and other applications may install persistent keyboard "event taps" to intercept your keystrokes. ReiKey can scan, detect, and monitor for such taps!
- [**137**Star][10m] [Py] [gawen/virustotal](https://github.com/gawen/virustotal) 
- [**137**Star][8m] [Py] [mdudek-ics/trisis-triton-hatman](https://github.com/MDudek-ICS/TRISIS-TRITON-HATMAN) Repository containting original and decompiled files of TRISIS/TRITON/HATMAN malware
- [**134**Star][3y] [Py] [blacktop/malice](https://github.com/blacktop/malice) VirusTotal Wanna Be
- [**132**Star][4y] [Py] [korelogicsecurity/mastiff](https://github.com/korelogicsecurity/mastiff) Malware static analysis framework
- [**129**Star][9m] [HTML] [minhaskamal/cuteviruscollection](https://github.com/minhaskamal/cuteviruscollection) A Collection of Cute But Deadly Viruses (small-unharmful-annoying-harmless-funny-malware-virus-worm-windows-xp-7-10)
- [**127**Star][2y] [Py] [fireeye/flare-dbg](https://github.com/fireeye/flare-dbg) to aid malware reverse engineers in rapidly developing debugger scripts.
- [**125**Star][5y] [CSS] [merces/aleph](https://github.com/merces/aleph) An Open Source Malware Analysis Pipeline System
- [**124**Star][4y] [Py] [bwall/bamfdetect](https://github.com/bwall/bamfdetect) Identifies and extracts information from bots and other malware
- [**122**Star][3y] [Py] [grazfather/practicalmalwarelabs](https://github.com/grazfather/practicalmalwarelabs) Keep track of the labs from the book "Practical Malware Analysis"
- [**122**Star][3y] [malwares/dangerouszone](https://github.com/malwares/dangerouszone) Dangerous Malwares
- [**121**Star][3y] [C] [glacierw/mba](https://github.com/glacierw/mba) Malware Behavior Analyzer
- [**119**Star][10m] [Perl] [dave-theunsub/clamtk](https://github.com/dave-theunsub/clamtk) An easy to use, light-weight, on-demand virus scanner for Linux systems
- [**119**Star][19d] [Dockerfile] [harvard-itsecurity/docker-misp](https://github.com/harvard-itsecurity/docker-misp) Automated Docker MISP container - Malware Information Sharing Platform and Threat Sharing
- [**118**Star][3m] [neo23x0/vti-dorks](https://github.com/neo23x0/vti-dorks) Awesome VirusTotal Intelligence Search Queries
- [**115**Star][6m] [Shell] [moreseclab/ddg_malware_clean_tool](https://github.com/moreseclab/ddg_malware_clean_tool) Watchdogs 、kthrotlds 挖矿蠕虫清理脚本。
- [**113**Star][5m] [Py] [marcoramilli/malwaretrainingsets](https://github.com/marcoramilli/malwaretrainingsets) Free Malware Training Datasets for Machine Learning
- [**111**Star][12m] [PHP] [ollyxar/php-malware-detector](https://github.com/ollyxar/php-malware-detector) PHP malware detector
- [**111**Star][1y] [Py] [seifreed/malware-scripts](https://github.com/seifreed/malware-scripts) Useful scripts related with malware
- [**111**Star][7y] [Py] [sroberts/malwarehouse](https://github.com/sroberts/malwarehouse) A warehouse for your malware
- [**106**Star][7m] [Py] [evilsocket/ergo-pe-av](https://github.com/evilsocket/ergo-pe-av) 🧠 🦠 An artificial neural network and API to detect Windows malware, based on Ergo and LIEF.
- [**106**Star][4y] [Perl] [fastvpseestiou/antidoto](https://github.com/fastvpseestiou/antidoto) Linux antimalware and antirootkit tool
- [**104**Star][5y] [Py] [botherder/vxcage](https://github.com/botherder/vxcage) REST API based malware repository (abandoned)
- [**103**Star][2y] [glinares/officemalware](https://github.com/glinares/officemalware) 
- [**102**Star][12d] [Go] [virustotal/vt-cli](https://github.com/virustotal/vt-cli) VirusTotal Command Line Interface
- [**100**Star][5y] [JS] [malwarelu/malwasm](https://github.com/malwarelu/malwasm) Offline debugger for malware's reverse engineering
- [**99**Star][3y] [Py] [bontchev/wlscrape](https://github.com/bontchev/wlscrape) A tool for scrapping the possible malware from the Wikileaks AKP leak
- [**96**Star][7y] [0day1day/mwcrawler](https://github.com/0day1day/mwcrawler) Python Malware Crawler for Zoos and Repositories
- [**94**Star][2m] [PowerShell] [dbheise/vm_setup](https://github.com/dbheise/vm_setup) A collection of scripts to initialize a windows VM to run all the malwares!
- [**93**Star][3y] [Vim script] [citizenlab/malware-signatures](https://github.com/citizenlab/malware-signatures) Yara rules for malware families seen as part of targeted threats project
- [**92**Star][5y] [Py] [neo23x0/dllrunner](https://github.com/neo23x0/dllrunner) Smart DLL execution for malware analysis in sandbox systems
- [**91**Star][2y] [C] [christian-roggia/open-myrtus](https://github.com/christian-roggia/open-myrtus) RCEed version of computer malware / rootkit MyRTUs / Stuxnet.
- [**89**Star][2y] [HTML] [tigzy/malware-repo](https://github.com/tigzy/malware-repo) Malware Repository Framework
- [**88**Star][4y] [Py] [maltelligence/maltelligence](https://github.com/maltelligence/maltelligence) a Malware/Threat Analyst Desktop
- [**88**Star][2y] [Py] [icchy/tracecorn](https://github.com/icchy/tracecorn) Windows API tracer for malware (oldname: unitracer)
- [**87**Star][4y] [Py] [bindog/toymalwareclassification](https://github.com/bindog/toymalwareclassification) Kaggle微软恶意代码分类
- [**87**Star][4y] [Py] [malwaremusings/unpacker](https://github.com/malwaremusings/unpacker) Automated malware unpacker
- [**86**Star][21d] [Py] [fr0gger/vthunting](https://github.com/fr0gger/vthunting) Vthunting is a tiny script used to generate report about Virus Total hunting and send it by email, slack or telegram.
- [**84**Star][4y] [Py] [mgoffin/malwarecookbook](https://github.com/mgoffin/malwarecookbook) Malware Analyst's Cookbook stuffs
- [**79**Star][28d] [Rust] [warner/magic-wormhole.rs](https://github.com/warner/magic-wormhole.rs) NOT FUNCTIONAL YET. Slowly porting magic-wormhole to Rust. See wiki for game plan.
- [**78**Star][6y] [Zeek] [liamrandall/bromalware-exercise](https://github.com/liamrandall/bromalware-exercise) 
- [**77**Star][4m] [C] [angelkitty/computer-virus](https://github.com/angelkitty/computer-virus) 
- [**77**Star][2m] [Py] [danieluhricek/lisa](https://github.com/danieluhricek/lisa) Sandbox for automated Linux malware analysis.
- [**77**Star][5m] [C] [virustotal/c-vtapi](https://github.com/virustotal/c-vtapi) Official implementation of the VirusTotal API in C programming language
- [**76**Star][7d] [endermanch/malwaredatabase](https://github.com/endermanch/malwaredatabase) This repository is one of a few malware collections on the GitHub.
- [**76**Star][7y] [Objective-C] [jils/flashbackchecker](https://github.com/jils/flashbackchecker) Quick and easy checker for Mac Flashback malware variants
- [**75**Star][18d] [Jupyter Notebook] [k-vitali/malware-misc-re](https://github.com/k-vitali/malware-misc-re) Miscellaneous Malware RE
- [**73**Star][16d] [C] [ntraiseharderror/antimalware-research](https://github.com/ntraiseharderror/antimalware-research) Research on Anti-malware and other related security solutions
- [**72**Star][6y] [PowerShell] [mattifestation/powerworm](https://github.com/mattifestation/powerworm) Analysis, detection, and removal of the "Power Worm" PowerShell-based malware
- [**71**Star][7m] [Py] [rmanofcn/ml_malware_detect](https://github.com/RManOfCN/ML_Malware_detect) 阿里云安全恶意程序检测比赛
- [**70**Star][5y] [C] [fireeye/tools](https://github.com/fireeye/tools) general purpose and malware specific analysis tools
- [**70**Star][2y] [Py] [malwarereversebrasil/maltran](https://github.com/malwarereversebrasil/maltran) A command line tool to download malware exercises from malware-traffic-analysis.net
- [**70**Star][2y] [Py] [minervalabsresearch/mystique](https://github.com/minervalabsresearch/mystique) Mystique may be used to discover infection markers that can be used to vaccinate endpoints against malware. It receives as input a malicious sample and automatically generates a list of mutexes that could be used to as “vaccines” against the sample.
- [**69**Star][3y] [PowerShell] [darkoperator/posh-virustotal](https://github.com/darkoperator/posh-virustotal) PowerShell Module to interact with VirusTotal
- [**69**Star][11m] [C++] [fr0gger/rocprotect-v1](https://github.com/fr0gger/rocprotect-v1) Emulating Virtual Environment to stay protected against advanced malware
- [**68**Star][6m] [Py] [idiom/pftriage](https://github.com/idiom/pftriage) Python tool and library to help analyze files during malware triage and analysis.
- [**68**Star][15d] [Py] [nmantani/fileinsight-plugins](https://github.com/nmantani/fileinsight-plugins) a decoding toolbox of McAfee FileInsight hex editor for malware analysis
- [**67**Star][4y] [Py] [robbyfux/ragpicker](https://github.com/robbyfux/ragpicker) Ragpicker is a Plugin based malware crawler with pre-analysis and reporting functionalities. Use this tool if you are testing antivirus products, collecting malware for another analyzer/zoo.
- [**65**Star][9m] [YARA] [rootkiter/binary-files](https://github.com/rootkiter/binary-files) EarthWorm/Termite 停止更新
- [**64**Star][15d] [PHP] [bediger4000/php-malware-analysis](https://github.com/bediger4000/php-malware-analysis) Deobfuscation and analysis of PHP malware captured by a WordPress honey pot
- [**64**Star][10m] [YARA] [nheijmans/malzoo](https://github.com/nheijmans/malzoo) Mass static malware analysis tool
- [**63**Star][17d] [Visual Basic] [blackhacker511/blackworm](https://github.com/blackhacker511/blackworm) Black Worm Offical Repo
- [**63**Star][6m] [Py] [sysopfb/malware_decoders](https://github.com/sysopfb/malware_decoders) Static based decoders for malware samples
- [**62**Star][11m] [cmatthewbrooks/r2kit](https://github.com/cmatthewbrooks/r2kit) A set of scripts for a radare-based malware code analysis workflow
- [**62**Star][2m] [Go] [moldabekov/virusgotal](https://github.com/moldabekov/virusgotal) 
- [**61**Star][3y] [Assembly] [cranklin/cranky-data-virus](https://github.com/cranklin/cranky-data-virus) Educational virus written in Assembly that infects 32-bit ELF executables on Linux using the data segment infection method
- [**60**Star][4y] [Py] [samvartaka/malware](https://github.com/samvartaka/malware) Various malware, packer, crypter, etc. detection and analysis tools
- [**59**Star][1y] [C++] [cisco-talos/thanatosdecryptor](https://github.com/cisco-talos/thanatosdecryptor) ThanatosDecryptor is an executable program that attempts to decrypt certain files encrypted by the Thanatos malware.
- [**58**Star][3y] [Py] [adulau/malwareclassifier](https://github.com/adulau/malwareclassifier) Malware Classifier From Network Captures
- [**58**Star][12d] [C++] [cert-polska/ursadb](https://github.com/cert-polska/ursadb) Trigram database written in C++, suited for malware indexing
- [**58**Star][6y] [Py] [malwarelu/tools](https://github.com/malwarelu/tools) Malware.lu tools
- [**58**Star][1y] [PHP] [slangji/wp-missed-schedule](https://github.com/slangji/wp-missed-schedule) Find only missed schedule posts, every 15 minutes, and republish correctly 10 items each session. The Original plugin (only this) no longer available on WordPress.org for explicit author request! Compatible with WP 2.1+ to 4.9+ and 5.0-beta3 (100.000+ installs 300.000+ downloads 2016-04-13) Please: do not install unauthorized malware cloned forked!
- [**57**Star][3y] [Batchfile] [ayra/zipbomb](https://github.com/ayra/zipbomb) About an old technology that still screws up some anti virus software
- [**57**Star][4y] [JS] [gattermeier/nodejs-virus](https://github.com/gattermeier/nodejs-virus) A Node.js Proof of Concept Virus
- [**57**Star][3m] [Rust] [guitmz/fe2o3](https://github.com/guitmz/fe2o3) Simple prepender virus written in Rust
- [**56**Star][15d] [albertzsigovits/malware-writeups](https://github.com/albertzsigovits/malware-writeups) Personal research and publication on malware families
- [**55**Star][4y] [Py] [pidydx/smrt](https://github.com/pidydx/smrt) Sublime Malware Research Tool
- [**54**Star][2y] [Py] [afagarap/malware-classification](https://github.com/afagarap/malware-classification) Towards Building an Intelligent Anti-Malware System: A Deep Learning Approach using Support Vector Machine for Malware Classification
- [**54**Star][8y] [Py] [cranklin/python-virus](https://github.com/cranklin/python-virus) This is an educational computer virus written in Python to demonstrate how replication is done.
- [**51**Star][5m] [Py] [deadbits/malware-analysis-scripts](https://github.com/deadbits/malware-analysis-scripts) Collection of scripts for different malware analysis tasks
- [**51**Star][1y] [Py] [sysopfb/malware_scripts](https://github.com/sysopfb/malware_scripts) Various scripts for different malware families
- [**51**Star][4y] [Py] [znb/malware](https://github.com/znb/malware) Malware related code
- [**50**Star][6y] [C++] [jyang772/xor_crypter](https://github.com/jyang772/xor_crypter) XOR encryption, malware crypter
- [**50**Star][2y] [newlog/r2_malware_unpacking_training](https://github.com/newlog/r2_malware_unpacking_training) 使用 r2 脱壳恶意代码教程
- [**50**Star][12m] [JS] [platdrag/unblockablechains](https://github.com/platdrag/unblockablechains) Unblockable Chains - A POC on using blockchain as infrastructure for malware operations
- [**50**Star][8m] [Py] [yarox24/attack_monitor](https://github.com/yarox24/attack_monitor) Endpoint detection & Malware analysis software
- [**49**Star][2y] [Py] [adrianherrera/virustotal](https://github.com/adrianherrera/virustotal) A simple command-line script to interact with the virustotal-api
- [**48**Star][2y] [Py] [cert-polska/malwarecage](https://github.com/cert-polska/malwarecage) Malware repository component for samples & static configuration with REST API interface
- [**48**Star][2y] [Jupyter Notebook] [harrisonpim/bookworm](https://github.com/harrisonpim/bookworm) 
- [**48**Star][7m] [Jupyter Notebook] [hija/malwaredatascience](https://github.com/hija/malwaredatascience) Malware Data Science Reading Diary / Notes
- [**48**Star][3y] [C] [malwarelu/malware-lu](https://github.com/malwarelu/malware-lu) Automatically exported from code.google.com/p/malware-lu
- [**48**Star][6m] [Py] [pylyf/networm](https://github.com/pylyf/networm) Python network worm that spreads on the local network and gives the attacker control of these machines.
- [**47**Star][5m] [PHP] [bediger4000/reverse-php-malware](https://github.com/bediger4000/reverse-php-malware) De-obfuscate and reverse engineer PHP malware
- [**46**Star][1y] [Py] [aaaddress1/vtmal](https://github.com/aaaddress1/vtmal) Malware Sandbox Emulation in Python @ HITCON 2018
- [**45**Star][2y] [Pascal] [0x48piraj/malwarex](https://github.com/0x48piraj/malwarex) Collection of killers !
- [**45**Star][4y] [TeX] [gannimo/maldiv](https://github.com/gannimo/maldiv) Malware diversity
- [**45**Star][2y] [Ruby] [hammackj/uirusu](https://github.com/hammackj/uirusu) A rubygem for interacting with Virustotal.com's public API v2
- [**45**Star][4y] [C++] [tandasat/remotewritemonitor](https://github.com/tandasat/remotewritemonitor) A tool to help malware analysts tell that the sample is injecting code into other process.
- [**44**Star][8d] [stamparm/blackbook](https://github.com/stamparm/blackbook) Blackbook of malware domains
- [**43**Star][2y] [C] [bartblaze/matire](https://github.com/bartblaze/matire) Malware Analysis, Threat Intelligence and Reverse Engineering: LABS
- [**43**Star][3y] [Shell] [mueller-ma/block-ads-via-dns](https://github.com/mueller-ma/block-ads-via-dns) Block ads and malware via local DNS server
- [**43**Star][7m] [C#] [nyan-x-cat/lime-downloader](https://github.com/nyan-x-cat/lime-downloader) Simple Malware Downloader
- [**43**Star][4y] [Py] [xme/mime2vt](https://github.com/xme/mime2vt) Unpack MIME attachments from a file and check them against virustotal.com
- [**42**Star][9y] [Py] [9b/malpdfobj](https://github.com/9b/malpdfobj) Builds json representation of PDF malware sample
- [**41**Star][4y] [Py] [abdesslem/malwarehunter](https://github.com/abdesslem/malwarehunter) Static and automated/dynamic malware analysis
- [**41**Star][3y] [Py] [dnlongen/reglister](https://github.com/dnlongen/reglister) Recurse through a registry, identifying values with large data -- a registry malware hunter
- [**41**Star][4m] [maecproject/malware-behaviors](https://github.com/maecproject/malware-behaviors) A taxonomy and dictionary of malware behaviors.
- [**40**Star][1y] [Py] [alfa-group/robust-adv-malware-detection](https://github.com/alfa-group/robust-adv-malware-detection) Code repository for the paper "Adversarial Deep Learning for Robust Detection of Binary Encoded Malware"
- [**40**Star][3y] [Py] [fabiobaroni/was](https://github.com/fabiobaroni/was) Automatic USB drive malware scanning tool for the security-minded person
- [**40**Star][1y] [Shell] [waja/maldetect](https://github.com/waja/maldetect) Debian packaging of Linux Malware Detect (
- [**39**Star][1y] [Py] [dissectmalware/malwarecmdmonitor](https://github.com/dissectmalware/malwarecmdmonitor) Shows command lines used by latest instances analyzed on Hybrid-Analysis
- [**39**Star][3y] [Java] [kdkanishka/virustotal-public-api-v2.0-client](https://github.com/kdkanishka/virustotal-public-api-v2.0-client) VirusTotal public API 2.0 implementation in Java
- [**39**Star][2y] [PHP] [nao-sec/mal_getter](https://github.com/nao-sec/mal_getter) Tool for dropping malware from EK
- [**38**Star][5y] [C++] [adamkramer/rapid_env](https://github.com/adamkramer/rapid_env) Rapid deployment of Windows environment (files, registry keys, mutex etc) to facilitate malware analysis
- [**38**Star][1y] [C] [en14c/pivirus](https://github.com/en14c/pivirus) sample linux x86_64 ELF virus
- [**38**Star][3y] [Py] [jevalenciap/iptodomain](https://github.com/jevalenciap/iptodomain) This tool extract domains from IP address based in the information saved in virustotal.
- [**37**Star][12d] [Py] [bytesoverbombs/virusshare-search](https://github.com/bytesoverbombs/virusshare-search) Downloads VirusShare hashes (
- [**37**Star][3y] [C] [mwsrc/mass-malicious-script-dump](https://github.com/mwsrc/mass-malicious-script-dump) Mass malicious script dump/Malware src dump
- [**36**Star][5y] [C++] [adamkramer/jmp2it](https://github.com/adamkramer/jmp2it) Transfer EIP control to shellcode during malware analysis investigation
- [**36**Star][3y] [Py] [ec-digit-csirc/virustotal-tools](https://github.com/ec-digit-csirc/virustotal-tools) 
- [**36**Star][1y] [Py] [lasq88/deobfuscate](https://github.com/lasq88/deobfuscate) Python script to automatically deobfuscate malware code
- [**36**Star][4y] [C] [mempodippy/cub3](https://github.com/mempodippy/cub3) Proof of concept for LD_PRELOAD malware that uses extended attributes to protect files.
- [**36**Star][4y] [michael-yip/aptmalwarenotes](https://github.com/michael-yip/aptmalwarenotes) A repository of open source reports on different malware families used in targeted cyber intrusions ("APT").
- [**35**Star][7y] [C++] [csurage/rootkit](https://github.com/csurage/rootkit) Windows Malware
- [**35**Star][3y] [Shell] [huntergregal/malwaresandbox](https://github.com/huntergregal/malwaresandbox) A ready to deploy docker container for a fresh sandbox for on-the-fly malware analysis
- [**35**Star][4y] [C] [motazreda/malwarefragmentationtool](https://github.com/motazreda/malwarefragmentationtool) Malware Fragmentation Tool its a tool that simply fragment the PE file and it can disassemble the PE file, etc this tool very useful for people who do malware research or analysis for pe_files
- [**34**Star][19d] [Dockerfile] [misp/docker-misp](https://github.com/misp/docker-misp) Automated Docker MISP container - Malware Information Sharing Platform and Threat Sharing
- [**34**Star][5y] [Py] [shendo/netsink](https://github.com/shendo/netsink) Network sinkhole for isolated malware analysis
- [**34**Star][2y] [C] [nttiton/malware](https://github.com/NTTITON/Malware) 
- [**33**Star][2y] [Rust] [0xcpu/bonomen](https://github.com/0xcpu/bonomen) BONOMEN - Hunt for Malware Critical Process Impersonation
- [**33**Star][3y] [PHP] [gregzem/aibolit](https://github.com/gregzem/aibolit) Free malware and virus scanner for websites and ISP
- [**33**Star][2m] [C] [milter-manager/milter-manager](https://github.com/milter-manager/milter-manager) milter manager is a free software to protect you from spam mails and virus mails effectively with milter.
- [**33**Star][4y] [C] [soufianetahiri/vault-8-hive](https://github.com/soufianetahiri/vault-8-hive) Hive solves a critical problem for the malware operators at the CIA.
- [**33**Star][1y] [C] [thisissecurity/malware](https://github.com/thisissecurity/malware) 
- [**32**Star][3y] [Py] [harryr/maltrieve](https://github.com/harryr/maltrieve) A tool to retrieve malware directly from the source for security researchers.
- [**32**Star][5m] [Jupyter Notebook] [malware-revealer/malware-revealer](https://github.com/malware-revealer/malware-revealer) Spot malwares using Machine Learning techniques
- [**32**Star][4y] [Py] [mansosec/microsoft-malware-challenge](https://github.com/mansosec/microsoft-malware-challenge) 
- [**32**Star][6m] [Py] [shouc/knicky](https://github.com/shouc/knicky) A module-based static virus generator
- [**32**Star][7m] [C++] [tlgyt/absent-loader](https://github.com/tlgyt/absent-loader) Example Loader to be used as a learning resource for people interested in how commercially available malware is made.
- [**32**Star][7m] [Perl] [tripflex/cpsetup](https://github.com/tripflex/cpsetup) Intuitive bash/shell script to setup and harden/configure cPanel CentOS/RHEL server with ConfigServer Firewall, MailManage, MailQueue, Malware Detect, ClamAV, mod_cloudflare, CloudFlare RailGun, and many more applications and security tweaks
- [**31**Star][6y] [C++] [glmcdona/malm](https://github.com/glmcdona/malm) MALM: Malware Monitor
- [**31**Star][18d] [C++] [hasherezade/funky_malware_formats](https://github.com/hasherezade/funky_malware_formats) Parsers for custom malware formats ("Funky malware formats")
- [**31**Star][3y] [CSS] [malwares/malwares.github.io](https://github.com/malwares/malwares.github.io) malwares src dump
- [**31**Star][5y] [Assembly] [th4nat0s/no_sandboxes](https://github.com/th4nat0s/no_sandboxes) Test suite for bypassing Malware sandboxes.
- [**30**Star][1y] [Py] [bsvineethiitg/malwaregan](https://github.com/bsvineethiitg/malwaregan) Visualizing malware behavior, and proactive protection using GANs against zero-day attacks.
- [**30**Star][2y] [Py] [fideliscyber/data_mining](https://github.com/fideliscyber/data_mining) Data Mining Virus Total for threat feed building
- [**30**Star][6m] [Py] [fr0gger/unprotect](https://github.com/fr0gger/unprotect) Unprotect is a python tool for parsing PE malware and extract evasion techniques.
- [**30**Star][5y] [C] [karottc/linux-virus](https://github.com/karottc/linux-virus) A simple virus of linux. It can get root and destory your system.(这是一个简单的linux下的病毒，它仅能得到root权限和感染文件并进行破坏)
- [**30**Star][4y] [neu5ron/malware-traffic-analysis-pcaps](https://github.com/neu5ron/malware-traffic-analysis-pcaps) malware-traffic-analysis.net PCAPs repository.
- [**30**Star][3y] [Jupyter Notebook] [surajr/machine-learning-approach-for-malware-detection](https://github.com/surajr/machine-learning-approach-for-malware-detection) A Machine Learning approach for classifying a file as Malicious or Legitimate
- [**29**Star][5y] [Py] [hiddenillusion/filelookup](https://github.com/hiddenillusion/filelookup) Quick & dirty script to get info on a file from online resources (VirusTotal, Team Cymru, Shadow Server etc.)
- [**29**Star][4m] [Py] [intezer/mop](https://github.com/intezer/mop) MoP - "Master of Puppets" - Advanced malware tracking framework
- [**29**Star][4y] [techbliss/yara_mailware_quick_menu_scanner](https://github.com/techbliss/yara_mailware_quick_menu_scanner) Work Fast With the pattern matching swiss knife for malware researchers.
- [**29**Star][28d] [Py] [certtools/malware_name_mapping](https://github.com/certtools/malware_name_mapping) A mapping of used malware names to commonly known family names
- [**27**Star][2y] [Py] [deralexxx/firemisp](https://github.com/deralexxx/firemisp) FireEye Alert json files to MISP Malware information sharing plattform (Alpha)
- [**27**Star][2y] [mahmudz/malware](https://github.com/mahmudz/malware) 
- [**27**Star][1y] [Py] [mprhode/malware-prediction-rnn](https://github.com/mprhode/malware-prediction-rnn) RNN implementation with Keras for machine activity data to predict malware
- [**27**Star][1y] [PHP] [rakshitshah94/wordpress-wp-vcd-malware-attack-solution](https://github.com/rakshitshah94/wordpress-wp-vcd-malware-attack-solution) Another attack on wordpress 4.8
- [**27**Star][3y] [Py] [swackhamer/vt_notification_puller](https://github.com/swackhamer/vt_notification_puller) VirusTotal Intelligence Notification Puller
- [**27**Star][1y] [Py] [tildedennis/malware](https://github.com/tildedennis/malware) 
- [**26**Star][4y] [Py] [open-nsm/dockoo](https://github.com/open-nsm/dockoo) Malware analysis using Docker project
- [**26**Star][1y] [C++] [psaneme/kung-fu-malware](https://github.com/psaneme/kung-fu-malware) 
- [**26**Star][2y] [tatsui-geek/malware-traffic-analysis.net](https://github.com/tatsui-geek/malware-traffic-analysis.net) Download pcap files from
- [**25**Star][4y] [C++] [herrcore/cmddesktopswitch](https://github.com/herrcore/cmddesktopswitch) CmdDesktopSwitch is a small utility that lists all windows desktops and provides the option to switch between them. This can be used to identify and watch malware that has created a hidden desktop.
- [**24**Star][3y] [Ruby] [deadbits/maz](https://github.com/deadbits/maz) Malware Analysis Zoo
- [**24**Star][5y] [C++] [edix/malwareresourcescanner](https://github.com/edix/malwareresourcescanner) Scanning and identifying XOR encrypted PE files in PE resources
- [**24**Star][2y] [Py] [marcusbotacin/anti.analysis](https://github.com/marcusbotacin/anti.analysis) Malware Analysis, Anti-Analysis, and Anti-Anti-Analysis
- [**24**Star][5y] [Py] [sash-ko/kaggle-malware-classification](https://github.com/sash-ko/kaggle-malware-classification) Kaggle "Microsoft Malware Classification Challenge". 6th place solution
- [**24**Star][2y] [silvermoonsecurity/sandboxevasion](https://github.com/silvermoonsecurity/sandboxevasion) Malware sandbox evasion tricks and solution
- [**23**Star][2y] [bxlcity/malware](https://github.com/bxlcity/malware) 
- [**23**Star][11m] [Py] [coldshell/malware-scripts](https://github.com/coldshell/malware-scripts) 
- [**23**Star][2y] [Jupyter Notebook] [geekonlinecode/malware-machine-learning](https://github.com/geekonlinecode/malware-machine-learning) Malware Machine Learning
- [**23**Star][2y] [C] [ieeeicsg/ieee_taggant_system](https://github.com/ieeeicsg/ieee_taggant_system) Taggant System developed by the Malware Working Group of ICSG (Industry Connections Security Group) under the umbrella of IEEE
- [**23**Star][5m] [C++] [mbrengel/memscrimper](https://github.com/mbrengel/memscrimper) Code for the DIMVA 2018 paper: "MemScrimper: Time- and Space-Efficient Storage of Malware Sandbox Memory Dumps"
- [**23**Star][5m] [meitar/awesome-malware](https://github.com/meitar/awesome-malware) 
- [**23**Star][12d] [Java] [opticfusion1/mcantimalware](https://github.com/opticfusion1/mcantimalware) Anti-Malware for minecraft
- [**23**Star][3y] [Py] [te-k/malware-classification](https://github.com/te-k/malware-classification) Data and code for malware classification using machine learning (for fun, not production)
- [**23**Star][1y] [JS] [veggiedefender/marveloptics_malware](https://github.com/veggiedefender/marveloptics_malware) Deobfuscated + reverse engineered javascript malware
- [**23**Star][7m] [Py] [bonnetn/vba-obfuscator](https://github.com/bonnetn/vba-obfuscator) 2018 School project - PoC of malware code obfuscation in Word macros
- [**23**Star][8y] [C++] [cr4sh/simpleunpacker](https://github.com/cr4sh/simpleunpacker) Simple tool for unpacking packed/protected malware executables.
- [**23**Star][3m] [Py] [warner/magic-wormhole-transit-relay](https://github.com/warner/magic-wormhole-transit-relay) Transit Relay server for Magic-Wormhole
- [**22**Star][2y] [PHP] [gr33ntii/malware-collection](https://github.com/gr33ntii/malware-collection) 
- [**22**Star][2y] [C++] [grcasanova/supervirus](https://github.com/grcasanova/supervirus) Project aimed at creating a malware able to evolve and adapt to the various host machines through metamorphic modifications, spontaneous mutations, code imitation and DNA programming to enable/disable functionalities
- [**22**Star][4y] [Py] [infectedpacket/vxvault](https://github.com/infectedpacket/vxvault) Malware management program and tools
- [**22**Star][2y] [Go] [integrii/wormhole](https://github.com/integrii/wormhole) 
- [**22**Star][1y] [Py] [j40903272/malconv-keras](https://github.com/j40903272/malconv-keras) This is the implementation of MalConv proposed in [Malware Detection by Eating a Whole EXE](
- [**22**Star][6m] [Py] [keithjjones/malgazer](https://github.com/keithjjones/malgazer) A Python malware analysis library.
- [**21**Star][7m] [Py] [drbeni/malquarium](https://github.com/drbeni/malquarium) Malquarium - Modern Malware Repository
- [**21**Star][2y] [Py] [kudelskisecurity/check_all_apks](https://github.com/kudelskisecurity/check_all_apks) Check All APK's -- scripts for checking your phone for malware
- [**21**Star][3y] [C++] [malwares/malware](https://github.com/malwares/malware) Malware Samples. Uploaded to GitHub for those want to analyse the code.
- [**21**Star][3m] [Ruby] [pwelch/virustotal_api](https://github.com/pwelch/virustotal_api) Ruby Gem for VirusTotal API
- [**21**Star][4y] [C] [warcraft23/virus-and-windows-api-programing](https://github.com/warcraft23/virus-and-windows-api-programing) 中科大13级计算机病毒分析与WindowsAPI编程 授课老师：郭大侠
- [**20**Star][1y] [Py] [thisissecurity/sinkhole](https://github.com/thisissecurity/sinkhole) Miscellanous scripts used for malware analysis
- [**20**Star][3y] [unexpectedby/automated-malware-analysis-list](https://github.com/unexpectedBy/Automated-Malware-Analysis-List) My personal Automated Malware Analysis Sandboxes and Services
- [**20**Star][3y] [ulexec/windowsmalwaresourcecode](https://github.com/ulexec/WindowsMalwareSourceCode) Collection of Source Code of Various Malware Targeting the Windows Platform


# <a id="5fdcfc70dd87360c2dddcae008076547"></a>Rootkit&&Bootkit


***


## <a id="b8d6f237c04188a10f511cd8988de28a"></a>Tools


- [**1191**Star][9m] [C] [f0rb1dd3n/reptile](https://github.com/f0rb1dd3n/reptile) LKM Linux rootkit
- [**722**Star][8m] [C] [mempodippy/vlany](https://github.com/mempodippy/vlany) Linux LD_PRELOAD rootkit (x86 and x86_64 architectures)
- [**540**Star][2y] [Shell] [cloudsec/brootkit](https://github.com/cloudsec/brootkit) Lightweight rootkit implemented by bash shell scripts v0.10
- [**509**Star][5m] [C] [nurupo/rootkit](https://github.com/nurupo/rootkit) Linux rootkit for Ubuntu 16.04 and 10.04 (Linux Kernels 4.4.0 and 2.6.32), both i386 and amd64
- [**435**Star][3y] [C] [mncoppola/suterusu](https://github.com/mncoppola/suterusu) An LKM rootkit targeting Linux 2.6/3.x on x86(_64), and ARM
- [**426**Star][1y] [C] [novicelive/research-rootkit](https://github.com/novicelive/research-rootkit) LibZeroEvil & the Research Rootkit project.
- [**387**Star][2m] [milabs/awesome-linux-rootkits](https://github.com/milabs/awesome-linux-rootkits) awesome-linux-rootkits
- [**370**Star][2y] [C] [cr4sh/windowsregistryrootkit](https://github.com/cr4sh/windowsregistryrootkit) Kernel rootkit, that lives inside the Windows registry values data
- [**325**Star][2y] [TeX] [ivyl/rootkit](https://github.com/ivyl/rootkit) Sample Rootkit for Linux
- [**284**Star][3y] [C] [unix-thrust/beurk](https://github.com/unix-thrust/beurk) BEURK Experimental Unix RootKit
- [**184**Star][3y] [CSS] [r00tkillah/horsepill](https://github.com/r00tkillah/horsepill) a PoC of a ramdisk based containerizing root kit
- [**183**Star][3y] [Pascal] [bowlofstew/rootkit.com](https://github.com/bowlofstew/rootkit.com) Mirror of users section of rootkit.com
- [**170**Star][6m] [C] [ciyze/windows-rootkits](https://github.com/ciyze/Windows-Rootkits) 
- [**163**Star][6m] [C] [bytecode77/r77-rootkit](https://github.com/bytecode77/r77-rootkit) Ring 3 Rootkit DLL
- [**153**Star][3m] [C] [ajkhoury/uefi-bootkit](https://github.com/ajkhoury/UEFI-Bootkit) A small bootkit which does not rely on x64 assembly.
- [**148**Star][9m] [C] [darkabode/zerokit](https://github.com/darkabode/zerokit) Zerokit/GAPZ rootkit (non buildable and only for researching)
- [**142**Star][2m] [C] [mak-/mak_it-linux-rootkit](https://github.com/mak-/mak_it-linux-rootkit) This is a linux rootkit using many of the techniques described on
- [**139**Star][2y] [C] [eterna1/puszek-rootkit](https://github.com/eterna1/puszek-rootkit) linux rootkit
- [**137**Star][7y] [C] [quarkslab/dreamboot](https://github.com/quarkslab/dreamboot) UEFI bootkit
- [**130**Star][2y] [C++] [vmcall/latebros](https://github.com/vmcall/latebros) x64 usermode rootkit
- [**129**Star][7m] [C++] [schnocker/noeye](https://github.com/schnocker/noeye) An usermode BE Rootkit Bypass
- [**117**Star][5y] [C] [squiffy/masochist](https://github.com/squiffy/masochist) XNU Rootkit Framework
- [**103**Star][4y] [C] [m0n0ph1/win64-rovnix-vbr-bootkit](https://github.com/m0n0ph1/win64-rovnix-vbr-bootkit) Win64/Rovnix - Volume Boot Record Bootkit
- [**96**Star][6y] [C] [enzolovesbacon/inficere](https://github.com/enzolovesbacon/inficere) Mac OS X rootkit - for learning purposes
- [**96**Star][1y] [Pascal] [fdiskyou/www.rootkit.com](https://github.com/fdiskyou/www.rootkit.com) 
- [**95**Star][5y] [C++] [malwaretech/fakembr](https://github.com/malwaretech/fakembr) TDL4 style rootkit to spoof read/write requests to master boot record
- [**93**Star][3y] [PowerShell] [fuzzysecurity/capcom-rootkit](https://github.com/fuzzysecurity/capcom-rootkit) Capcom Rootkit POC
- [**93**Star][4y] [C] [scumjr/the-sea-watcher](https://github.com/scumjr/the-sea-watcher) Implementation of the SMM rootkit "The Watcher"
- [**87**Star][4y] [C] [yaoyumeng/adore-ng](https://github.com/yaoyumeng/adore-ng) linux rootkit adapted for 2.6 and 3.x
- [**84**Star][5y] [C] [nyx0/rovnix](https://github.com/nyx0/rovnix) Rovnix Bootkit
- [**72**Star][21d] [C] [naworkcaj/bdvl](https://github.com/naworkcaj/bdvl) LD_PRELOAD Linux rootkit (x86 & ARM)
- [**69**Star][6y] [C] [kedebug/scdetective](https://github.com/kedebug/scdetective) A kernel level anti-rootkit tool which runs on the windows platform.
- [**64**Star][3y] [C] [quokkalight/rkduck](https://github.com/quokkalight/rkduck) Linux v4.x.x Rootkit
- [**62**Star][5y] [C] [jiayy/lkm-rootkit](https://github.com/jiayy/lkm-rootkit) an lkm rootkit support x86/64,arm,mips
- [**60**Star][2y] [C] [croemheld/lkm-rootkit](https://github.com/croemheld/lkm-rootkit) A LKM rootkit for most newer kernel versions.
- [**60**Star][6m] [Py] [thesph1nx/spacecow](https://github.com/thesph1nx/spacecow) Windows Rootkit written in Python
- [**59**Star][2y] [tkmru/awesome-linux-rootkits](https://github.com/tkmru/awesome-linux-rootkits) 
- [**49**Star][3y] [maldevel/rootkits-list-download](https://github.com/maldevel/rootkits-list-download) A curated list of rootkits found on Github and other sites.
- [**49**Star][4m] [C] [pinkp4nther/sutekh](https://github.com/pinkp4nther/sutekh) An example rootkit that gives a userland process root permissions
- [**47**Star][2y] [C] [david-reguera-garcia-dreg/enyelkm](https://github.com/david-reguera-garcia-dreg/enyelkm) LKM rootkit for Linux x86 with the 2.6 kernel. It inserts salts inside system_call and sysenter_entry.
- [**47**Star][10m] [Java] [jreframeworker/jreframeworker](https://github.com/jreframeworker/jreframeworker) A practical tool for bytecode manipulation and creating Managed Code Rootkits (MCRs) in the Java Runtime Environment
- [**42**Star][3y] [C] [nextsecurity/gozi-mbr-rootkit](https://github.com/nextsecurity/gozi-mbr-rootkit) Gozi-MBR-rootkit Bootkit Modified
- [**40**Star][C] [d1w0u/arp-rootkit](https://github.com/d1w0u/arp-rootkit) An open source rootkit for the Linux Kernel to develop new ways of infection/detection.
- [**40**Star][2y] [C] [david-reguera-garcia-dreg/lsrootkit](https://github.com/david-reguera-garcia-dreg/lsrootkit) Rootkit Detector for UNIX
- [**38**Star][3y] [C++] [zibility/anti-rootkits](https://github.com/zibility/anti-rootkits) 内核级ARK工具。
- [**36**Star][3y] [C] [nexusbots/umbreon-rootkit](https://github.com/nexusbots/umbreon-rootkit) 
- [**34**Star][5y] [osiris123/cdriver_loader](https://github.com/osiris123/cdriver_loader) Kernel mode driver loader, injecting into the windows kernel, Rootkit. Driver injections.
- [**32**Star][9y] [C] [falk3n/subversive](https://github.com/falk3n/subversive) x86_64 linux rootkit using debug registers
- [**32**Star][6y] [sin5678/a-protect](https://github.com/sin5678/A-Protect) A-Protect Anti Rootkit Tool
- [**31**Star][7m] [C] [alex91ar/diamorphine](https://github.com/alex91ar/diamorphine) LKM rootkit for Linux Kernels 2.6.x/3.x/4.x
- [**31**Star][5y] [C] [christianpapathanasiou/apache-rootkit](https://github.com/christianpapathanasiou/apache-rootkit) A malicious Apache module with rootkit functionality
- [**31**Star][8y] [C] [swatkat/arkitlib](https://github.com/swatkat/arkitlib) Windows anti-rootkit library
- [**28**Star][3y] [C] [a7vinx/liinux](https://github.com/a7vinx/liinux) A linux rootkit works on kernel 4.0.X or higher
- [**28**Star][2y] [C++] [nervous/greenkit-rootkit](https://github.com/nervous/greenkit-rootkit) GreenKit is an userland rootkit hiding its own files and mining bitcoins on compromised computers. Do /NOT/ download or use this rootkit for malicious purposes. Use it only for your own knowledge.
- [**28**Star][4y] [C] [qianshanhai/q-shell](https://github.com/qianshanhai/q-shell) Unix remote login tool, rootkit shell tool
- [**27**Star][1y] [C] [alex9191/zerobank-ring0-bundle](https://github.com/alex9191/zerobank-ring0-bundle) Kernel-Mode rootkit that connects to a remote server to send & recv commands
- [**26**Star][6y] [C] [kacheo/kernelrootkit](https://github.com/kacheo/kernelrootkit) Linux kernel rootkit to hide certain files and processes.
- [**26**Star][3y] [Assembly] [cduplooy/rootkit](https://github.com/CDuPlooy/Rootkit) 
- [**25**Star][4y] [C] [hanj4096/wukong](https://github.com/hanj4096/wukong) A LKM rootkit for Linux kernel 2.6.x, 3.x and 4.x
- [**25**Star][6y] [C] [varshapaidi/kernel_rootkit](https://github.com/varshapaidi/kernel_rootkit) Linux Kernel Rootkit - To hide modules and ssh service
- [**24**Star][3y] [Assembly] [rehints/bootkitsbook](https://github.com/rehints/bootkitsbook) repository with additional materials and source code
- [**22**Star][5y] [C] [citypw/suterusu](https://github.com/citypw/suterusu) An LKM rootkit targeting Linux 2.6/3.x on x86(_64), and ARM
- [**22**Star][3y] [C] [jianpingzju/hypro](https://github.com/jianpingzju/Hypro) VMI on BitVisor to detect hidden rootkits.
- [**21**Star][7y] [C] [dsmatter/brootus](https://github.com/dsmatter/brootus) An educational Linux Kernel Rootkit
- [**20**Star][6y] [C++] [antirootkit/bdarkit](https://github.com/antirootkit/bdarkit) just an lite AntiRootkit for interesting
- [**20**Star][3y] [C++] [apriorit/antirootkit-anti-splicer](https://github.com/apriorit/antirootkit-anti-splicer) The project is a demo solution for one of the anti-rootkit techniques aimed on overcoming splicers
- [**20**Star][11m] [C] [blacchat/rkorova](https://github.com/blacchat/rkorova) ld_preload userland rootkit


# <a id="069468057aac03c102abdbeb7a5decf6"></a>Hardware


***


## <a id="3574d46dd09566f898b407cebe9df29b"></a>Firmware


### <a id="649d2aece91551af8b48d29f52943804"></a>Firmware


- [**6170**Star][6m] [rmerl/asuswrt-merlin](https://github.com/rmerl/asuswrt-merlin) Enhanced version of Asus's router firmware (Asuswrt) (legacy code base)
- [**3621**Star][2m] [C] [atmosphere-nx/atmosphere](https://github.com/atmosphere-nx/atmosphere) Atmosphère is a work-in-progress customized firmware for the Nintendo Switch.
- [**3209**Star][8d] [C] [betaflight/betaflight](https://github.com/betaflight/betaflight) Open Source Flight Controller Firmware
- [**3108**Star][4m] [C++] [px4/firmware](https://github.com/px4/firmware) PX4 Autopilot Software
- [**2810**Star][28d] [C] [tmk/tmk_keyboard](https://github.com/tmk/tmk_keyboard) Keyboard firmwares for Atmel AVR and Cortex-M
- [**2267**Star][1m] [C] [aurorawright/luma3ds](https://github.com/aurorawright/luma3ds) Noob-proof (N)3DS "Custom Firmware"
- [**1441**Star][19d] [C] [tianocore/edk2](https://github.com/tianocore/edk2) A modern, feature-rich, cross-platform firmware development environment for the UEFI and PI specifications
- [**784**Star][8d] [C] [fwupd/fwupd](https://github.com/fwupd/fwupd) A simple daemon to allow session software to update firmware
- [**633**Star][6m] [C] [travisgoodspeed/md380tools](https://github.com/travisgoodspeed/md380tools) Python tools and patched firmware for the TYT-MD380
- [**415**Star][5m] [preos-security/awesome-firmware-security](https://github.com/preos-security/awesome-firmware-security) Awesome Firmware Security & Other Helpful Documents
- [**370**Star][12d] [Py] [fkie-cad/fact_core](https://github.com/fkie-cad/fact_core) Firmware Analysis and Comparison Tool
- [**284**Star][5m] [C++] [rampagex/firmware-mod-kit](https://github.com/rampagex/firmware-mod-kit) Automatically exported from code.google.com/p/firmware-mod-kit
- [**279**Star][1m] [Py] [cwerling/psptool](https://github.com/cwerling/psptool) Display, extract, and manipulate PSP firmware inside UEFI images
- [**237**Star][11d] [Py] [avatartwo/avatar2](https://github.com/avatartwo/avatar2) Python core of avatar²
- [**237**Star][4y] [C] [jethrogb/uefireverse](https://github.com/jethrogb/uefireverse) Tools to help with Reverse Engineering UEFI-based firmware
- [**234**Star][11m] [C] [reisyukaku/reinand](https://github.com/reisyukaku/reinand) Minimalist 3DS custom firmware.
- [**193**Star][11m] [Py] [scanlime/coastermelt](https://github.com/scanlime/coastermelt) An effort to make open source firmware for burning anything other than Blu-Ray data onto plastic discs with a BD-R drive.
- [**168**Star][4y] [C] [silver13/h8mini-acro](https://github.com/silver13/h8mini-acro) acro firmware for eachine H8 mini
- [**161**Star][8y] [C] [poelzi/openchronos](https://github.com/poelzi/openchronos)  Open Source Firmware for the TI EZ430-Chronos Watch
- [**149**Star][1y] [C] [theofficialflow/update365](https://github.com/theofficialflow/update365) Custom Firmware 3.65 HENkaku Ensō Updater for PS Vita
- [**115**Star][17d] [Shell] [therealsaumil/armx](https://github.com/therealsaumil/armx) ARM-X Firmware Emulation Framework
- [**86**Star][3y] [advanced-threat-research/efi-whitelist](https://github.com/advanced-threat-research/efi-whitelist)  information about known EFI executable binaries extracted from (U)EFI firmware update images gathered from platform vendors' web-sites.
- [**77**Star][14d] [C] [open-power/skiboot](https://github.com/open-power/skiboot) OPAL boot and runtime firmware for POWER
- [**74**Star][3y] [C++] [avatarone/avatar-python](https://github.com/avatarone/avatar-python) Dynamic security analysis of embedded systems’ firmwares
- [**65**Star][26d] [Assembly] [hardenedlinux/firmware-anatomy](https://github.com/hardenedlinux/firmware-anatomy) Tear the firmware apart with your bare hands;-)
- [**63**Star][3y] [C] [seemoo-lab/bcm-public](https://github.com/seemoo-lab/bcm-public) DEPRECATED: Monitor Mode and Firmware patching framework for the Google Nexus 5, development moved to:
- [**60**Star][2y] [C] [samuelpowell/cx10-fnrf](https://github.com/samuelpowell/CX10-FNRF) Cheerson CX10 rate mode firmware with integrated RF
- [**60**Star][28d] [Shell] [nccgroup/asafw](https://github.com/nccgroup/asafw) Set of scripts to deal with Cisco ASA firmware [pack/unpack etc.]
- [**56**Star][5y] [Shell] [ge0rg/samsung-nx-hacks](https://github.com/ge0rg/samsung-nx-hacks) Firmware Hacks for the Linux-based Samsung NX mirrorless camera models (NX300, NX2000, ???)
- [**52**Star][6m] [Py] [bkerler/oppo_decrypt](https://github.com/bkerler/oppo_decrypt) Oppo/Oneplus .ops Firmware decrypter
- [**48**Star][2y] [Py] [q3k/m16c-interface](https://github.com/q3k/m16c-interface) A Serial IO programmer for Renesas M16C, includes security PIN bypass.
- [**45**Star][8m] [C] [groupgets/purethermal1-firmware](https://github.com/groupgets/purethermal1-firmware) Reference firmware for PureThermal 1 FLIR Lepton Dev Kit
- [**44**Star][6m] [Py] [firmadyne/scraper](https://github.com/firmadyne/scraper) Firmware scraper
- [**44**Star][4y] [Assembly] [raspberrypi/rpi-sense](https://github.com/raspberrypi/rpi-sense) Sense HAT firmware and driver
- [**43**Star][2y] [C] [rbaron/fitless](https://github.com/rbaron/fitless) A collection of toy firmwares for the ID115 fitness tracker
- [**40**Star][3y] [Assembly] [ilovepp/firminsight](https://github.com/ilovepp/firminsight) Automatic collect firmwares from internet,decompress,find binary code,extract info,file relation and function relation
- [**38**Star][3y] [Py] [fotisl/utimaco](https://github.com/fotisl/utimaco) Tools for reverse engineering the Utimaco Firmware
- [**37**Star][13d] [C] [microsoft/cfu](https://github.com/microsoft/cfu) Component Firmware Update
- [**36**Star][3y] [C] [brad-anton/proxbrute](https://github.com/brad-anton/proxbrute) Modified proxmark3 firmware to perform brute forcing of 26-Bit ProxCards
- [**36**Star][4y] [C] [sektioneins/xpwntool-lite](https://github.com/sektioneins/xpwntool-lite) Lightweight version of xpwntool just for decrypting IMG3 firmware files
- [**33**Star][2y] [Py] [ganapati/firmflaws](https://github.com/ganapati/firmflaws) Firmware analysis website + API
- [**29**Star][4m] [Py] [rot42/gnuk-extractor](https://github.com/rot42/gnuk-extractor) Extract PGP secret keys from Gnuk / Nitrokey Start firmwares
- [**26**Star][3y] [C++] [marcnewlin/mousejack-nes-controller](https://github.com/marcnewlin/mousejack-nes-controller) MouseJack NES controller firmware and build guide.
- [**25**Star][2y] [C] [ktemkin-archive/atmosphere](https://github.com/ktemkin-archive/Atmosphere) Atmosphère is a work-in-progress customized firmware for the Nintendo Switch.


### <a id="fff92e7d304e2c927ef3530f4d327456"></a>Intel


- [**507**Star][1m] [Py] [platomav/meanalyzer](https://github.com/platomav/meanalyzer) Intel Engine Firmware Analysis Tool
- [**465**Star][1y] [Py] [ptresearch/unme11](https://github.com/ptresearch/unme11) Intel ME 11.x Firmware Images Unpacker
- [**21**Star][2m] [Py] [flarn2006/bhstools](https://github.com/flarn2006/bhstools) Tools for interacting with Brinks BHS-3000 and BHS-4000 / IntelliBus, custom firmware for BHS-4000




# <a id="948dbc64bc0ff4a03296988574f5238c"></a>Crypto


***


## <a id="a6b0a9b9184fd78c8b87ccfe48a8e544"></a>Tools


- [**2369**Star][2m] [TeX] [crypto101/book](https://github.com/crypto101/book) Crypto 101, the introductory book on cryptography.
- [**1580**Star][7d] [Go] [bitnami-labs/sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) A Kubernetes controller and tool for one-way encrypted Secrets
- [**1433**Star][12d] [C++] [microsoft/seal](https://github.com/microsoft/seal) Microsoft SEAL is an easy-to-use and powerful homomorphic encryption library.
- [**832**Star][13d] [Haskell] [galoisinc/cryptol](https://github.com/galoisinc/cryptol) The Language of Cryptography
- [**758**Star][1y] [pfarb/awesome-crypto-papers](https://github.com/pfarb/awesome-crypto-papers) A curated list of cryptography papers, articles, tutorials and howtos.
- [**693**Star][5m] [C++] [stealth/opmsg](https://github.com/stealth/opmsg) opmsg message encryption
- [**660**Star][26d] [Java] [google/conscrypt](https://github.com/google/conscrypt) Conscrypt is a Java Security Provider that implements parts of the Java Cryptography Extension and Java Secure Socket Extension.
- [**619**Star][4y] [Go] [leo-stone/hack-petya](https://github.com/leo-stone/hack-petya) search key to restore petya encrypted mft
- [**482**Star][3m] [C] [microsoft/symcrypt](https://github.com/microsoft/symcrypt) Cryptographic library
- [**466**Star][3m] [miscreant/meta](https://github.com/miscreant/meta) 具备错误使用抗性的（Misuse-resistant ）对称加密库，支持 AES-SIV (RFC5297) 和 CHAIN/STREAM
- [**463**Star][8d] [C] [skeeto/enchive](https://github.com/skeeto/enchive) Encrypted personal archives
- [**432**Star][1m] [Go] [gorilla/securecookie](https://github.com/gorilla/securecookie) Package gorilla/securecookie encodes and decodes authenticated and optionally encrypted cookie values for Go web applications.
- [**394**Star][1y] [sweis/crypto-might-not-suck](https://github.com/sweis/crypto-might-not-suck) List of crypto projects that might not suck
- [**380**Star][21d] [C++] [msoos/cryptominisat](https://github.com/msoos/cryptominisat) An advanced SAT solver
- [**349**Star][7m] [Haskell] [jpmorganchase/constellation](https://github.com/jpmorganchase/constellation) Peer-to-peer encrypted message exchange
- [**334**Star][26d] [Shell] [umputun/nginx-le](https://github.com/umputun/nginx-le) Nginx with automatic let's encrypt (docker image)
- [**328**Star][10d] [Py] [efforg/starttls-everywhere](https://github.com/efforg/starttls-everywhere) A system for ensuring & authenticating STARTTLS encryption between mail servers
- [**323**Star][5m] [JS] [hr/crypter](https://github.com/hr/crypter) An innovative, convenient and secure cross-platform encryption app
- [**315**Star][2y] [Py] [ethventures/cryptotracker](https://github.com/ethventures/cryptotracker) A complete open source system for tracking and visualizing cryptocurrency price movements on leading exchanges
- [**305**Star][18d] [C] [jhuisi/charm](https://github.com/jhuisi/charm) A Framework for Rapidly Prototyping Cryptosystems
- [**270**Star][5y] [C] [conradev/dumpdecrypted](https://github.com/conradev/dumpdecrypted) Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk. This tool is necessary for security researchers to be able to look under the hood of encryption.
- [**265**Star][13d] [Py] [nucypher/nucypher](https://github.com/nucypher/nucypher) A decentralized network offering accessible, intuitive, and extensible cryptographic runtimes and interfaces for secrets management and dynamic access control.
- [**259**Star][3y] [Py] [pablocelayes/rsa-wiener-attack](https://github.com/pablocelayes/rsa-wiener-attack) A Python implementation of the Wiener attack on RSA public-key encryption scheme.
- [**253**Star][13d] [C] [icing/mod_md](https://github.com/icing/mod_md) Let's Encrypt (ACME) support for Apache httpd
- [**248**Star][1y] [batchfile] [zerodot1/coinblockerlists](https://github.com/zerodot1/coinblockerlists) Simple lists that can help prevent cryptomining in the browser or other applications.
- [**244**Star][14d] [C++] [evpo/encryptpad](https://github.com/evpo/encryptpad) Minimalist secure text editor and binary encryptor that implements RFC 4880 Open PGP format: symmetrically encrypted, compressed and integrity protected. The editor can protect files with passwords, key files or both.
- [**229**Star][7m] [C] [ctz/cifra](https://github.com/ctz/cifra) A collection of cryptographic primitives targeted at embedded use.
- [**225**Star][5y] [Objective-C] [limneos/weak_classdump](https://github.com/limneos/weak_classdump) Cycript real-time classdump . An alternative for encrypted binaries
- [**223**Star][1m] [C] [libyal/libfvde](https://github.com/libyal/libfvde) Library and tools to access FileVault Drive Encryption (FVDE) encrypted volumes
- [**222**Star][2m] [vixentael/my-talks](https://github.com/vixentael/my-talks) List of my talks and workshops: security engineering, applied cryptography, secure software development
- [**221**Star][12m] [C] [gkdr/lurch](https://github.com/gkdr/lurch) XEP-0384: OMEMO Encryption for libpurple.
- [**220**Star][2m] [Go] [cloudflare/tls-tris](https://github.com/cloudflare/tls-tris) crypto/tls, now with 100% more 1.3. THE API IS NOT STABLE AND DOCUMENTATION IS NOT GUARANTEED.
- [**204**Star][2y] [Java] [facebookresearch/asynchronousratchetingtree](https://github.com/facebookresearch/asynchronousratchetingtree) On Ends-to-Ends Encryption: Asynchronous Group Messaging with Strong Security Guarantees
- [**203**Star][5m] [Py] [nucypher/nufhe](https://github.com/nucypher/nufhe) NuCypher fully homomorphic encryption (NuFHE) library implemented in Python
- [**202**Star][5m] [TeX] [decrypto-org/rupture](https://github.com/decrypto-org/rupture) A framework for BREACH and other compression-based crypto attacks
- [**200**Star][7m] [C] [doublelabyrinth/how-does-navicat-encrypt-password](https://github.com/doublelabyrinth/how-does-navicat-encrypt-password) This repository tells you how Navicat encrypts database password.
- [**197**Star][10d] [anudeepnd/blacklist](https://github.com/anudeepnd/blacklist) Curated and well-maintained host file to block ads, tracking, cryptomining and more! Updated regularly.
- [**195**Star][2y] [Objective-C] [alonemonkey/dumpdecrypted](https://github.com/alonemonkey/dumpdecrypted) Dumps decrypted mach-o files from encrypted applications、framework or app extensions.
- [**185**Star][4y] [Java] [netspi/weblogicpassworddecryptor](https://github.com/netspi/weblogicpassworddecryptor) PowerShell script and Java code to decrypt WebLogic passwords
- [**176**Star][1m] [Py] [nolze/msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool) Python tool and library for decrypting MS Office files with passwords or other keys
- [**171**Star][13d] [C] [microsoft/pqcrypto-sidh](https://github.com/microsoft/pqcrypto-sidh) SIDH Library is a fast and portable software library that implements state-of-the-art supersingular isogeny cryptographic schemes. The chosen parameters aim to provide security against attackers running a large-scale quantum computer, and security against classical algorithms.
- [**153**Star][1m] [Go] [mimoo/disco](https://github.com/mimoo/disco) a protocol to encrypt communications and a cryptographic library based on Disco
- [**150**Star][2y] [Go] [kudelskisecurity/cdf](https://github.com/kudelskisecurity/cdf)  automatically test the correctness and security of cryptographic software
- [**149**Star][27d] [hl2guide/all-in-one-customized-adblock-list](https://github.com/hl2guide/all-in-one-customized-adblock-list) An all-in-one adblock list that thoroughly blocks trackers, popup ads, ads, unwanted cookies, fake news, cookie warning messages, unwanted comment sections, crypto-coin mining, YouTube clutter, Twitter guff and social network hassles. Development is halted at version 2.8.
- [**148**Star][1y] [PowerShell] [nexxai/cryptoblocker](https://github.com/nexxai/cryptoblocker) A script to deploy File Server Resource Manager and associated scripts to block infected users
- [**147**Star][17d] [C] [microchiptech/cryptoauthlib](https://github.com/microchiptech/cryptoauthlib) Library for interacting with the Crypto Authentication secure elements
- [**146**Star][3y] [C] [gentilkiwi/wanadecrypt](https://github.com/gentilkiwi/wanadecrypt) A decryptor for Wanacry (you need the private key!)
- [**143**Star][7d] [Rust] [brycx/orion](https://github.com/brycx/orion) Easy and usable rust crypto
- [**132**Star][1m] [jlopp/physical-bitcoin-attacks](https://github.com/jlopp/physical-bitcoin-attacks) A list of known attacks against Bitcoin / crypto asset owning entities that occurred in meatspace.
- [**129**Star][2y] [Ruby] [benlaurie/objecthash](https://github.com/benlaurie/objecthash) A way to cryptographically hash objects (in the JSON-ish sense) that works cross-language. And, therefore, cross-encoding.
- [**127**Star][5y] [Py] [fox-it/cryptophp](https://github.com/fox-it/cryptophp) CryptoPHP Indicators of Compromise
- [**108**Star][1m] [C] [libyal/libbde](https://github.com/libyal/libbde) Library and tools to access the BitLocker Drive Encryption (BDE) encrypted volumes
- [**94**Star][2y] [Py] [blackthorne/codetective](https://github.com/blackthorne/codetective) a tool to determine the crypto/encoding algorithm used according to traces from its representation
- [**91**Star][1m] [Py] [lockedbyte/cryptovenom](https://github.com/lockedbyte/cryptovenom) Cryptovenom: The Cryptography Swiss Army Knife
- [**89**Star][3y] [JS] [particle-iot/spark-protocol](https://github.com/particle-iot/spark-protocol) Node.JS module for hosting direct encrypted CoAP socket connections
- [**88**Star][2y] [Py] [blackploit/hash-identifier](https://github.com/blackploit/hash-identifier) Software to identify the different types of hashes used to encrypt data and especially passwords
- [**88**Star][5m] [tuupola/branca-spec](https://github.com/tuupola/branca-spec) Authenticated and encrypted API tokens using modern crypto
- [**88**Star][2m] [PHP] [zendframework/zend-crypt](https://github.com/zendframework/zend-crypt) Cryptographic component from Zend Framework
- [**86**Star][3m] [Rust] [kzen-networks/curv](https://github.com/kzen-networks/curv) Rust language general purpose elliptic curve cryptography.
- [**86**Star][24d] [Py] [tozny/rancher-lets-encrypt](https://github.com/tozny/rancher-lets-encrypt) Automatically create and manage certificates in Rancher using Let's Encrypt webroot verification via a minimal service
- [**83**Star][3y] [Shell] [scotthelme/lets-encrypt-smart-renew](https://github.com/scotthelme/lets-encrypt-smart-renew) Check the remaining validity period of a certificate before renewing.
- [**82**Star][11m] [Py] [duanhongyi/gmssl](https://github.com/duanhongyi/gmssl) a python crypto for sm2/sm3/sm4
- [**81**Star][3y] [Go] [whyrusleeping/zmsg](https://github.com/whyrusleeping/zmsg) A small program for sending messages via zcash encrypted memo fields
- [**75**Star][5m] [JS] [zencashofficial/arizen](https://github.com/zencashofficial/arizen) Arizen is the API wallet for Horizen with encrypted and only locally stored files!
- [**71**Star][2y] [HTML] [brandis-project/brandis](https://github.com/brandis-project/brandis) Brandis: End-to-end encryption for everyone
- [**71**Star][6m] [PHP] [vlucas/pikirasa](https://github.com/vlucas/pikirasa) PKI public/private RSA key encryption using the OpenSSL extension
- [**65**Star][4y] [PowerShell] [dlwyatt/protecteddata](https://github.com/dlwyatt/protecteddata) PowerShell Module for securely encrypting and sharing secret data such as passwords.
- [**64**Star][2m] [HTML] [deadlyelder/tools-for-cryptanalysis](https://github.com/deadlyelder/tools-for-cryptanalysis) A repository that aims to provide tools for cryptography and cryptanalysis
- [**64**Star][3y] [Ruby] [danielmiessler/caparser](https://github.com/danielmiessler/caparser) A quick and dirty PCAP parser that helps you identify who your applications are sending sensitive data to without encryption.
- [**63**Star][27d] [C] [gpg/libgcrypt](https://github.com/gpg/libgcrypt) The GNU crypto library
- [**63**Star][6m] [Py] [marcobellaccini/pyaescrypt](https://github.com/marcobellaccini/pyaescrypt) A Python 3 module and script that uses AES256-CBC to encrypt/decrypt files and streams in AES Crypt file format (version 2).
- [**62**Star][1y] [Py] [lclevy/unarcrypto](https://github.com/lclevy/unarcrypto) unarcrypto：描述 zip、rar、7zip 使用的加密算法
- [**62**Star][5m] [Shell] [nodesocket/cryptr](https://github.com/nodesocket/cryptr) A simple shell utility for encrypting and decrypting files using OpenSSL.
- [**60**Star][1y] [Shell] [galeone/letsencrypt-lighttpd](https://github.com/galeone/letsencrypt-lighttpd) Renew your let's encrypt certificates monthly, using lighttpd as webserver.
- [**60**Star][2y] [C] [gravity-postquantum/gravity-sphincs](https://github.com/gravity-postquantum/gravity-sphincs) Signature scheme submitted to NIST's Post-Quantum Cryptography Project
- [**58**Star][2y] [Py] [hasherezade/crypto_utils](https://github.com/hasherezade/crypto_utils) Set of my small utils related to cryptography, encoding, decoding etc
- [**56**Star][11m] [C] [smihica/pyminizip](https://github.com/smihica/pyminizip) To create a password encrypted zip file in python.
- [**52**Star][3y] [PowerShell] [m-dwyer/cryptoblocker](https://github.com/m-dwyer/cryptoblocker) A script to deploy File Server Resource Manager and associated scripts to block infected users
- [**51**Star][1y] [Py] [cisco-talos/pylocky_decryptor](https://github.com/cisco-talos/pylocky_decryptor) 
- [**47**Star][2y] [Shell] [samoshkin/docker-letsencrypt-certgen](https://github.com/samoshkin/docker-letsencrypt-certgen) Docker image to generate, renew, revoke RSA and/or ECDSA SSL certificates from LetsEncrypt CA using certbot and acme.sh clients in automated fashion
- [**45**Star][8m] [C] [cossacklabs/hermes-core](https://github.com/cossacklabs/hermes-core) Security framework for building multi-user end-to-end encrypted data storage and sharing/processing with zero leakage risks from storage and transport infrastructure.
- [**43**Star][3y] [C] [kudelskisecurity/sgx-reencrypt](https://github.com/kudelskisecurity/sgx-reencrypt) PoC of an SGX enclave performing symmetric reencryption
- [**40**Star][9m] [Shell] [jceminer/cn_cpu_miner](https://github.com/jceminer/cn_cpu_miner) Cryptonote CPU Miner
- [**39**Star][2y] [Py] [jamespayor/vector-homomorphic-encryption](https://github.com/jamespayor/vector-homomorphic-encryption) 6.857 project - implementation of scheme for encrypting integer vectors that allows addition, linear transformation, and weighted inner products.
- [**39**Star][6y] [C] [smartinm/diskcryptor](https://github.com/smartinm/diskcryptor) DiskCryptor - Open source partition encryption solution
- [**38**Star][3y] [Py] [hcamael/ctf-library](https://github.com/hcamael/ctf-library) 之Crypto
- [**38**Star][6y] [Objective-C] [nzn/nsuserdefaults-aesencryptor](https://github.com/nzn/nsuserdefaults-aesencryptor) NSUserDefaults category with AES encrypt/decrypt keys and values.
- [**38**Star][2y] [Py] [pegasuslab/wifi-miner-detector](https://github.com/PegasusLab/WiFi-Miner-Detector) Detecting malicious WiFi with mining cryptocurrency.
- [**35**Star][2y] [C#] [akalankauk/keep-it-secure-file-encryption](https://github.com/akalankauk/keep-it-secure-file-encryption) Keep It Secure Private Data Encryption & Decryption Tool
- [**35**Star][11y] [C] [alanquatermain/appencryptor](https://github.com/alanquatermain/appencryptor) A command-line tool to apply or remove Apple Binary Protection from an application.
- [**34**Star][1y] [kudelskisecurity/cryptochallenge18](https://github.com/kudelskisecurity/cryptochallenge18) Kudelski Security's 2018 pre-Black Hat crypto challenge
- [**31**Star][4y] [danielmiessler/ctfsolutiontypes](https://github.com/danielmiessler/ctfsolutiontypes) A collection of CTF solution types, i.e. not solutions to specific CTF challenges, but the general categories that those solutions fall under. Includes CTF solution categories for web, binary, network, crypto, and others. Please contribute!
- [**31**Star][2y] [Py] [fist0urs/kerberom](https://github.com/fist0urs/kerberom) Kerberom is a tool aimed to retrieve ARC4-HMAC'ed encrypted Tickets Granting Service (TGS) of accounts having a Service Principal Name (SPN) within an Active Directory
- [**30**Star][1y] [JS] [1lastbr3ath/drmine](https://github.com/1lastbr3ath/drmine) Dr. Mine is a node script written to aid automatic detection of in-browser cryptojacking.
- [**30**Star][14d] [C] [jedisct1/libhydrogen](https://github.com/jedisct1/libhydrogen) A lightweight, secure, easy-to-use crypto library suitable for constrained environments.
- [**30**Star][1y] [Go] [wybiral/reverseproxy](https://github.com/wybiral/reverseproxy) reverseproxy: Go语言编写的加密反向代理
- [**28**Star][1y] [TeX] [gossip-sjtu/k-hunt](https://github.com/gossip-sjtu/k-hunt) K-Hunt: Pinpointing Insecure Crypto Keys
- [**28**Star][9m] [Go] [mimoo/eureka](https://github.com/mimoo/eureka) Need to encrypt a file before sending it to someone? This is it.
- [**27**Star][1y] [Py] [nucypher/sputnik](https://github.com/nucypher/sputnik) Sputnik is an assembly language and interpreter for Fully Homomorphic Encryption
- [**26**Star][1y] [Shell] [hestat/minerchk](https://github.com/hestat/minerchk) Bash script to Check for malicious Cryptomining
- [**26**Star][1y] [Rust] [mortendahl/rust-paillier](https://github.com/mortendahl/rust-paillier) A pure-Rust implementation of the Paillier encryption scheme
- [**25**Star][3y] [Go] [aead/hydrogen](https://github.com/aead/hydrogen) Go implementation of libhydrogen - a lightweight, easy-to-use crypto library
- [**25**Star][1y] [JS] [coincheckup/crypto-supplies](https://github.com/coincheckup/crypto-supplies) Cryptocurrency circulating, maximum and total supplies
- [**25**Star][4y] [Shell] [mk-fg/dracut-crypt-sshd](https://github.com/mk-fg/dracut-crypt-sshd) dracut initramfs module to start sshd on early boot to enter encryption passphrase from across the internets
- [**25**Star][6m] [C] [underhandedcrypto/entries](https://github.com/underhandedcrypto/entries) A browsable archive of all Underhanded Crypto Contest entries.
- [**25**Star][6y] [C] [whyallyn/paythepony](https://github.com/whyallyn/paythepony) Pay the Pony is hilarityware that uses the Reflective DLL injection library to inject into a remote process, encrypt and demand a ransom for files, and inflict My Little Pony madness on a system.
- [**25**Star][3m] [Py] [blacknbunny/encdecshellcode](https://github.com/blacknbunny/encdecshellcode) Shellcode Encrypter & Decrypter With XOR Cipher
- [**24**Star][4y] [PHP] [lt/php-cryptopals](https://github.com/lt/php-cryptopals) The Matasano crypto challenges completed using PHP
- [**23**Star][2y] [C] [nucypher/nucypher-pre-python](https://github.com/nucypher/nucypher-pre-python) nucypher-pre-python：Python 实现的“代理重加密（Proxy Re-Encryption）”算法
- [**23**Star][2y] [ptresearch/intelme-crypto](https://github.com/ptresearch/intelme-crypto) 
- [**21**Star][3y] [Py] [neurobin/letsacme](https://github.com/neurobin/letsacme) A tiny script to issue and renew TLS/SSL certificate from Let's Encrypt
- [**21**Star][2y] [Py] [spec-sec/securechat](https://github.com/spec-sec/securechat) Encrypted chat server and client written in Python
- [**21**Star][13d] [Shell] [cryptomator/cryptomator-mac](https://github.com/cryptomator/cryptomator-mac) Cryptomator .dmg image for Mac
- [**20**Star][7d] [C++] [deeponion/deeponion](https://github.com/deeponion/deeponion) Official Source Repo for DeepOnion - Anonymous Cryptocurrency on TOR (based on the latest codebase from litecoin/bitcoin)
- [**20**Star][2y] [C] [gravity-postquantum/prune-horst](https://github.com/gravity-postquantum/prune-horst) Signature scheme submitted to NIST's Post-Quantum Cryptography Project
- [**20**Star][2y] [Py] [kudelskisecurity/cryptochallenge17](https://github.com/kudelskisecurity/cryptochallenge17) Kudelski Security's 2017 crypto challenge
- [**20**Star][25d] [cypurr-collective/cypurr-prezes](https://github.com/cypurr-collective/cypurr-prezes) presentation materials for our cryptoparties


# Contribute
Contents auto exported by Our System, please raise Issue if you have any question.