# 所有收集类项目:
- [收集的所有开源工具](https://github.com/alphaSeclab/sec-tool-list): 超过18K, 包括Markdown和Json两种格式
- [逆向资源](https://github.com/alphaSeclab/awesome-reverse-engineering): IDA/Ghidra/x64dbg/OllDbg/WinDBG/CuckooSandbox/Radare2/BinaryNinja/DynamoRIO/IntelPin/Frida/QEMU/Android安全/iOS安全/Window安全/Linux安全/macOS安全/游戏Hacking/Bootkit/Rootkit/Angr/Shellcode/进程注入/代码注入/DLL注入/WSL/Sysmon/...
- [网络相关的安全资源](https://github.com/alphaSeclab/awesome-network-stuff): 代理/GFW/反向代理/隧道/VPN/Tor/I2P，以及中间人/PortKnocking/嗅探/网络分析/网络诊断等
- [攻击性网络安全资源](https://github.com/alphaSeclab/awesome-cyber-security): 漏洞/渗透/物联网安全/数据渗透/Metasploit/BurpSuite/KaliLinux/C&C/OWASP/免杀/CobaltStrike/侦查/OSINT/社工/密码/凭证/威胁狩猎/Payload/WifiHacking/无线攻击/后渗透/提权/UAC绕过/...





# ReverseEngineering


- 跟逆向有关的资源收集。当前包括的工具个数4600+，并根据功能进行了粗糙的分类。部分工具添加了中文描述。当前包括文章数600左右。
- 此页只包含部分内容. [查看完整版](https://github.com/alphaSeclab/awesome-reverse-engineering/blob/master/Readme_full.md)



# 说明
[EnglishVersion](https://github.com/alphaSeclab/awesome-reverse-engineering/blob/master/Readme_en.md)


# 目录
- [IDA](#08e59e476824a221f6e4a69c0bba7d63)
    - [插件&&脚本](#f11ab1ff46aa300cc3e86528b8a98ad7)
        - [(97) 未分类](#c39a6d8598dde6abfeef43faf931beb5)
        - [结构体&&类的检测&&创建&&恢复](#fb4f0c061a72fc38656691746e7c45ce)
            - [(6) 未分类](#fa5ede9a4f58d4efd98585d3158be4fb)
            - [(8) C++类&&虚表](#4900b1626f10791748b20630af6d6123)
        - [(3) 收集](#a7dac37cd93b8bb42c7d6aedccb751b3)
        - [(9) 外观&&主题](#fabf03b862a776bbd8bcc4574943a65a)
        - [(4) 固件&&嵌入式设备](#a8f5db3ab4bc7bc3d6ca772b3b9b0b1e)
        - [签名(FLIRT等)&&比较(Diff)&&匹配](#02088f4884be6c9effb0f1e9a3795e58)
            - [(17) 未分类](#cf04b98ea9da0056c055e2050da980c1)
            - [FLIRT签名](#19360afa4287236abe47166154bc1ece)
                - [(3) FLIRT签名收集](#1c9d8dfef3c651480661f98418c49197)
                - [(2) FLIRT签名生成](#a9a63d23d32c6c789ca4d2e146c9b6d0)
            - [(11) Diff&&Match工具](#161e5a3437461dc8959cc923e6a18ef7)
            - [(7) Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a)
        - [(6) IDB操作](#5e91b280aab7f242cbc37d64ddbff82f)
        - [(5) 协作逆向&&多人操作相同IDB文件](#206ca17fc949b8e0ae62731d9bb244cb)
        - [(9) 与调试器同步&&通信&&交互](#f7d311685152ac005cfce5753c006e4b)
        - [导入导出&与其他工具交互](#6fb7e41786c49cc3811305c520dfe9a1)
            - [(13) 未分类](#8ad723b704b044e664970b11ce103c09)
            - [(5) Ghidra](#c7066b0c388cd447e980bf0eb38f39ab)
            - [(3) BinNavi](#11139e7d6db4c1cef22718868f29fe12)
            - [(3) BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a)
            - [(2) Radare2](#21ed198ae5a974877d7a635a4b039ae3)
            - [(4) Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd)
            - [(2) IntelPin](#dd0332da5a1482df414658250e6357f8)
        - [针对特定分析目标](#004c199e1dbf71769fbafcd8e58d1ead)
            - [(26) 未分类](#5578c56ca09a5804433524047840980e)
            - [(2) GoLang](#1b17ac638aaa09852966306760fda46b)
            - [(4) Windows驱动](#4c158ccc5aee04383755851844fdd137)
            - [(4) PS3&&PS4](#315b1b8b41c67ae91b841fce1d4190b5)
            - [(33) Loader&Processor](#cb59d84840e41330a7b5e275c0b81725)
            - [(4) PDB](#f5e51763bb09d8fd47ee575a98bedca1)
            - [(2) Flash&&SWF](#7d0681efba2cf3adaba2780330cd923a)
            - [(4) 特定样本家族](#841d605300beba45c3be131988514a03)
            - [(1) CTF](#ad44205b2d943cfa2fa805b2643f4595)
        - [IDAPython本身](#ad68872e14f70db53e8d9519213ec039)
            - [(8) 未分类](#2299bc16945c25652e5ad4d48eae8eca)
            - [(1) cheatsheets](#c42137cf98d6042372b1fd43c3635135)
        - [(6) 指令参考&文档](#846eebe73bef533041d74fc711cafb43)
        - [辅助脚本编写](#c08ebe5b7eec9fc96f8eff36d1d5cc7d)
            - [(9) 未分类](#45fd7cfce682c7c25b4f3fbc4c461ba2)
            - [(3) Qt](#1a56a5b726aaa55ec5b7a5087d6c8968)
            - [(3) 控制台&&窗口界面](#1721c09501e4defed9eaa78b8d708361)
            - [(2) 插件模板](#227fbff77e3a13569ef7b007344d5d2e)
            - [(2) 其他语言](#8b19bb8cf9a5bc9e6ab045f3b4fabf6a)
        - [(16) 古老的](#dc35a2b02780cdaa8effcae2b6ce623e)
        - [调试&&动态运行&动态数据](#e3e7030efc3b4de3b5b8750b7d93e6dd)
            - [(10) 未分类](#2944dda5289f494e5e636089db0d6a6a)
            - [(10) DBI数据](#0fbd352f703b507853c610a664f024d1)
            - [(4) 调试数据](#b31acf6c84a9506066d497af4e702bf5)
        - [(14) 反编译器&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9)
        - [(7) 反混淆](#7199e8787c0de5b428f50263f965fda7)
        - [效率&&导航&&快速访问&&图形&&图像&&可视化 ](#fcf75a0881617d1f684bc8b359c684d7)
            - [(15) 其他](#c5b120e1779b928d860ad64ff8d23264)
            - [(9) 显示增强](#03fac5b3abdbd56974894a261ce4e25f)
            - [(3) 图形&&图像](#3b1dba00630ce81cba525eea8fcdae08)
            - [(3) 搜索](#8f9468e9ab26128567f4be87ead108d7)
        - [(7) Android](#66052f824f5054aa0f70785a2389a478)
        - [Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O](#2adc0044b2703fb010b3bf73b1f1ea4a)
            - [(5) 未分类](#8530752bacfb388f3726555dc121cb1a)
            - [(3) 内核缓存](#82d0fa2d6934ce29794a651513934384)
            - [(3) Mach-O](#d249a8d09a3f25d75bb7ba8b32bd9ec5)
            - [(3) Swift](#1c698e298f6112a86c12881fbd8173c7)
        - [(9) ELF](#e5e403123c70ddae7bd904d3a3005dbb)
        - [(5) Microcode](#7a2977533ccdac70ee6e58a7853b756b)
        - [(6) 模拟器集成](#b38dab81610be087bd5bc7785269b8cc)
        - [新添加的](#c39dbae63d6a3302c4df8073b4d1cdc8)
        - [(4) 作为辅助&&构成其他的一环](#83de90385d03ac8ef27360bfcdc1ab48)
        - [漏洞](#1ded622dca60b67288a591351de16f8b)
            - [(7) 未分类](#385d6777d0747e79cccab0a19fa90e7e)
            - [(2) ROP](#cf2efa7e3edb24975b92d2e26ca825d2)
        - [(7) 补丁&&Patch](#7d557bc3d677d206ef6c5a35ca8b3a14)
        - [(3) 其他](#7dfd8abad50c14cd6bdc8d8b79b6f595)
        - [函数相关](#90bf5d31a3897400ac07e15545d4be02)
            - [(4) 未分类](#347a2158bdd92b00cd3d4ba9a0be00ae)
            - [(6) 重命名&&前缀&&标记](#73813456eeb8212fd45e0ea347bec349)
            - [(5) 导航&&查看&&查找](#e4616c414c24b58626f834e1be079ebc)
            - [(2) demangle](#cadae88b91a57345d266c68383eb05c5)
        - [(3) 污点分析&&符号执行](#34ac84853604a7741c61670f2a075d20)
        - [(8) 字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24)
        - [(3) 加密解密](#06d2caabef97cf663bd29af2b1fe270c)
    - [文章](#18c6a45392d6b383ea24b363d2f3e76b)
        - [(6) 系列文章-Labeless插件介绍](#04cba8dbb72e95d9c721fe16a3b48783)
        - [(24) 系列文章-使用IDA从零开始学逆向](#1a2e56040cfc42c11c5b4fa86978cc19)
        - [系列文章-IDAPython-让你的生活更美好](#e838a1ecdcf3d068547dd0d7b5c446c6)
            - [(6) 原文](#7163f7c92c9443e17f3f76cc16c2d796)
            - [(5) 译文](#fc62c644a450f3e977af313edd5ab124)
        - [工具&&插件&&脚本介绍](#3d3bc775abd7f254ff9ff90d669017c9)
            - [(56) 未分类](#cd66794473ea90aa6241af01718c3a7d)
            - [(3) Loader&&Processor](#43a4761e949187bf737e378819752c3b)
            - [(1) 与其他工具交互](#c7483f3b20296ac68084a8c866230e15)
        - [(10) Tips&&Tricks](#a4bd25d3dc2f0be840e39674be67d66b)
        - [(125) 未分类](#4187e477ebc45d1721f045da62dbf4e8)
        - [(5) 翻译-TheIDAProBook](#ea11818602eb33e8b165eb18d3710965)
        - [(2) 翻译-ReverseEngineeringCodeWithIDAPro](#ec5f7b9ed06500c537aa25851a3f2d3a)
        - [(5) 系列文章-使用IDA逆向C代码](#8433dd5df40aaf302b179b1fda1d2863)
        - [逆向实战](#d8e48eb05d72db3ac1e050d8ebc546e1)
            - [(11) 未分类](#374c6336120363a5c9d9a27d7d669bf3)
            - [(15) 恶意代码分析](#0b3e1936ad7c4ccc10642e994c653159)
            - [(2) 漏洞分析&&挖掘](#03465020d4140590326ae12c9601ecfd)
        - [(26) 新添加的](#37634a992983db427ce41b37dd9a98c2)
        - [(4) IDA本身](#2120fe5420607a363ae87f5d2fed459f)
        - [(1) Microcode](#e9ce398c2c43170e69c95fe9ad8d22fc)
        - [(1) IDA对抗](#9c0ec56f402a2b9938417f6ecbaeaa72)
- [Ghidra](#319821036a3319d3ade5805f384d3165)
    - [插件&&脚本](#fa45b20f6f043af1549b92f7c46c9719)
        - [(11) 新添加的](#ce70b8d45be0a3d29705763564623aca)
        - [特定分析目标](#69dc4207618a2977fe8cd919e7903fa5)
            - [(4) 未分类](#da5d2b05da13f8e65aa26d6a1c95a8d0)
            - [(18) Loader&&Processor](#058bb9893323f337ad1773725d61f689)
            - [(2) Xbox](#51a2c42c6d339be24badf52acb995455)
        - [与其他工具交互](#99e3b02da53f1dbe59e0e277ef894687)
            - [(2) Radare2](#e1cc732d1388084530b066c26e24887b)
            - [未分类](#5923db547e1f04f708272543021701d2)
            - [(5) IDA](#d832a81018c188bf585fcefa3ae23062)
            - [(1) DBI](#60e86981b2c98f727587e7de927e0519)
            - [(1) 调试器](#e81053b03a859e8ac72f7fe79e80341a)
        - [(1) 外观&&主题](#cccbd06c6b9b03152d07a4072152ae27)
        - [(4) Ghidra](#2ae406afda6602c8f02d73678b2ff040)
        - [脚本编写](#45910c8ea12447df9cdde2bea425f23f)
            - [(1) 其他](#c12ccb8e11ba94184f8f24767eb64212)
            - [(1) 编程语言](#b24e162720cffd2d2456488571c1a136)
    - [文章&&视频](#273df546f1145fbed92bb554a327b87a)
        - [(30) 新添加的](#ce49901b4914f3688ef54585c8f9df1a)
        - [(8) Ghidra漏洞](#b7fb955b670df2babc67e5942297444d)
        - [实战分析](#dd0d49a5e6bd34b372d9bbf4475e8024)
            - [(3) 漏洞分析&&挖掘](#375c75af4fa078633150415eec7c867d)
            - [(9) 未分类](#f0ab053d7a282ab520c3a327fc91ba2e)
            - [(9) 恶意代码](#4e3f53845efe99da287b2cea1bdda97c)
        - [其他](#92f60c044ed13b3ffde631794edd2756)
        - [Tips&&Tricks](#4bfa6dcf708b3f896870c9d3638c0cde)
        - [(5) 工具&&插件&&脚本](#0d086cf7980f65da8f7112b901fecdc1)
        - [新添加的1](#8962bde3fbfb1d1130879684bdf3eed0)
- [x64dbg](#b1a6c053e88e86ce01bbd78c54c63a7c)
    - [插件&&脚本](#b4a856db286f9f29b5a32d477d6b3f3a)
        - [(63) 新添加的](#da5688c7823802e734c39b539aa39df7)
        - [(1) x64dbg](#353ea40f2346191ecb828210a685f9db)
    - [文章&&视频](#22894d6f2255dc43d82dd46bdbc20ba1)
- [OllyDbg](#37e37e665eac00de3f55a13dcfd47320)
    - [插件&&脚本](#7834e399e48e6c64255a1a0fdb6b88f5)
        - [(13) 新添加的](#92c44f98ff5ad8f8b0f5e10367262f9b)
    - [文章&&视频](#8dd3e63c4e1811973288ea8f1581dfdb)
- [WinDBG](#0a506e6fb2252626add375f884c9095e)
    - [插件&&脚本](#37eea2c2e8885eb435987ccf3f467122)
        - [(66) 新添加的](#2ef75ae7852daa9862b2217dca252cc3)
    - [(9) 文章&&视频](#6d8bac8bfb5cda00c7e3bd38d64cbce3)
- [Cuckoo](#0ae4ddb81ff126789a7e08b0768bd693)
    - [工具](#5830a8f8fb3af1a336053d84dd7330a1)
        - [(40) 新添加的](#f2b5c44c2107db2cec6c60477c6aa1d0)
    - [(15) 文章&&视频](#ec0a441206d9a2fe1625dce0a679d466)
- [Radare2](#86cb7d8f548ca76534b5828cb5b0abce)
    - [插件&&脚本](#0e08f9478ed8388319f267e75e2ef1eb)
        - [(62) 新添加的](#6922457cb0d4b6b87a34caf39aa31dfe)
        - [(1) Radare2](#ec3f0b5c2cf36004c4dd3d162b94b91a)
        - [与其他工具交互](#1a6652a1cb16324ab56589cb1333576f)
            - [(4) 未分类](#dfe53924d678f9225fc5ece9413b890f)
            - [(3) IDA](#1cfe869820ecc97204a350a3361b31a7)
        - [(5) GUI](#f7778a5392b90b03a3e23ef94a0cc3c6)
    - [(168) 文章&&视频](#95fdc7692c4eda74f7ca590bb3f12982)
- [BinaryNinja](#afb7259851922935643857c543c4b0c2)
    - [插件&&脚本](#3034389f5aaa9d7b0be6fa7322340aab)
        - [(58) 新添加的](#a750ac8156aa0ff337a8639649415ef1)
        - [与其他工具交互](#bba1171ac550958141dfcb0027716f41)
            - [(2) 未分类](#c2f94ad158b96c928ee51461823aa953)
            - [(3) IDA](#713fb1c0075947956651cc21a833e074)
    - [(7) 文章&&视频](#2d24dd6f0c01a084e88580ad22ce5b3c)
- [DBI](#7ab3a7005d6aa699562b3a0a0c6f2cff)
    - [DynamoRIO](#c8cdb0e30f24e9b7394fcd5681f2e419)
        - [工具](#6c4841dd91cb173093ea2c8d0b557e71)
            - [(7) 新添加的](#ff0abe26a37095f6575195950e0b7f94)
            - [(2) DynamoRIO](#3a577a5b4730a1b5b3b325269509bb0a)
            - [(3) 与其他工具交互](#928642a55eff34b6b52622c6862addd2)
        - [(16) 文章&&视频](#9479ce9f475e4b9faa4497924a2e40fc)
    - [IntelPin](#7b8a493ca344f41887792fcc008573e7)
        - [工具](#fe5a6d7f16890542c9e60857706edfde)
            - [(18) 新添加的](#78a2edf9aa41eb321436cb150ea70a54)
            - [与其他工具交互](#e6a829abd8bbc5ad2e5885396e3eec04)
                - [(8) 未分类](#e129288dfadc2ab0890667109f93a76d)
        - [文章&&视频](#226190bea6ceb98ee5e2b939a6515fac)
    - [Frida](#f24f1235fd45a1aa8d280eff1f03af7e)
        - [工具](#a5336a0f9e8e55111bda45c8d74924c1)
            - [(100) 新添加的](#54836a155de0c15b56f43634cd9cfecf)
            - [与其他工具交互](#74fa0c52c6104fd5656c93c08fd1ba86)
                - [(1) 未分类](#00a86c65a84e58397ee54e85ed57feaf)
                - [(3) IDA](#d628ec92c9eea0c4b016831e1f6852b3)
                - [(2) BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8)
                - [(2) Radare2](#ac053c4da818ca587d57711d2ff66278)
            - [(1) Frida](#6d3c24e43835420063f9ca50ba805f15)
        - [(25) 文章&&视频](#a1a7e3dd7091b47384c75dba8f279caf)
    - [其他](#5a9974bfcf7cdf9b05fe7a7dc5272213)
- [模拟器&&虚拟机](#747ddaa20f643da415284bfba9cda3a2)
    - [QEMU](#796b64906655228d8a1ff8c0dd390451)
        - [工具](#296c7f25266b25e5ee1107dd76e40dd2)
            - [(42) 新添加的](#82072558d99a6cf23d4014c0ae5b420a)
        - [文章&&视频](#5df30a166c2473fdadf5a578d1a70e32)
    - [其他](#a13effff89633708c814ae9410da835a)
- [Android](#11a59671b467a8cdbdd4ea9d5e5d9b51)
    - [工具](#2110ded2aa5637fa933cc674bc33bf21)
        - [(182) 新添加的](#883a4e0dd67c6482d28a7a14228cd942)
        - [(4) HotFix](#fa49f65b8d3c71b36c6924ce51c2ca0c)
        - [(1) 打包](#ec395c8f974c75963d88a9829af12a90)
        - [(2) 收集](#767078c52aca04c452c095f49ad73956)
        - [(1) 各类App](#17408290519e1ca7745233afea62c43c)
        - [(30) Xposed](#7f353b27e45b5de6b0e6ac472b02cbf1)
        - [(19) 加壳&&脱壳](#50f63dce18786069de2ec637630ff167)
        - [(12) HOOK](#596b6cf8fd36bc4c819335f12850a915)
        - [(9) Emulator&&模拟器](#5afa336e229e4c38ad378644c484734a)
        - [(6) IDA](#0a668d220ce74e11ed2738c4e3ae3c9e)
        - [(11) Debug&&调试](#bb9f8e636857320abf0502c19af6c763)
        - [(34) Malware&&恶意代码](#f975a85510f714ec3cc2551e868e75b8)
        - [(5) Obfuscate&&混淆](#1d83ca6d8b02950be10ac8e4b8a2d976)
        - [(15) ReverseEngineering](#6d2b758b3269bac7d69a2d2c8b45194c)
        - [(319) 新添加的1](#63fd2c592145914e99f837cecdc5a67c)
    - [(2) 文章&&视频](#f0493b259e1169b5ddd269b13cfd30e6)
- [Apple&&iOS&&iXxx](#069664f347ae73b1370c4f5a2ec9da9f)
    - [工具](#58cd9084afafd3cd293564c1d615dd7f)
        - [(345) 新添加的](#d0108e91e6863289f89084ff09df39d0)
        - [(16) XCode](#7037d96c1017978276cb920f65be2297)
        - [(91) 越狱](#ff19d5d94315d035bbcb3ef0c348c75b)
        - [(8) LLDB](#c20772abc204dfe23f3e946f8c73dfda)
    - [文章&&视频](#c97bbe32bbd26c72ceccb43400e15bf1)
- [Windows](#2f81493de610f9b796656b269380b2de)
    - [工具](#b478e9a9a324c963da11437d18f04998)
        - [(213) 其他](#1afda3039b4ab9a3a1f60b179ccb3e76)
        - [(10) 事件日志&&事件追踪&&ETW](#0af4bd8ca0fd27c9381a2d1fa8b71a1f)
        - [(12) Sysmon](#d48f038b58dc921660be221b4e302f70)
        - [(18) WSL](#8ed6f25b321f7b19591ce2908b30cc88)
        - [(10) .NET](#d90b60dc79837e06d8ba2a7ee1f109d3)
        - [新添加的](#f9fad1d4d1f0e871a174f67f63f319d8)
        - [(5) Environment&&环境&&配置](#6d2fe834b7662ecdd48c17163f732daf)
        - [进程注入](#8bfd27b42bb75956984994b3419fb582)
        - [(1) DLL注入](#b0d50ee42d53b1f88b32988d34787137)
        - [代码注入](#1c6069610d73eb4246b58d78c64c9f44)
        - [内存模块](#7c1541a69da4c025a89b0571d8ce73d2)
        - [(115) Shellcode](#16001cb2fae35b722deaa3b9a8e5f4d5)
        - [(6) VT&&虚拟化&&Hypbervisor](#19cfd3ea4bd01d440efb9d4dd97a64d0)
        - [(8) 内核&&驱动](#c3cda3278305549f4c21df25cbf638a4)
        - [(3) 注册表](#920b69cea1fc334bbc21a957dd0d9f6f)
        - [(4) 系统调用](#d295182c016bd9c2d5479fe0e98a75df)
        - [加壳&&脱壳](#a82bb5fff6cb644fb34db2b257f2061b)
            - [(25) 新添加的](#ccd2a4f85dbac99ccbedc745c2768f01)
            - [(1) Themida](#197f3a24a98c86c065273c3121d13f3b)
            - [VMProtect](#d4b660c75f60ee317569b6eac48e117f)
    - [文章](#3939f5e83ca091402022cb58e0349ab8)
        - [(48) Themida](#cd60c8e438bde4b3da791eabf845f679)
- [Linux](#dc664c913dc63ec6b98b47fcced4fdf0)
    - [(101) 工具](#89e277bca2740d737c1aeac3192f374c)
    - [文章](#f6d78e82c3e5f67d13d9f00c602c92f0)
- [Hook](#3f1fde99538be4662dca6747a365640b)
    - [(252) 工具](#cfe974d48bbb90a930bf667c173616c7)
- [Monitor&&监控&&Trace&&追踪](#70e64e3147675c9bcd48d4f475396e7f)
    - [(29) 工具](#cd76e644d8ddbd385939bb17fceab205)
- [Malware&&恶意代码](#09fa851959ff48f5667a2099c861eab8)
    - [(574) 工具](#e781a59e4f4daab058732cf66f77bfb9)
- [Game&&游戏](#28aa8187f8a1e38ca5a55aa31a5ee0c3)
    - [(180) 工具](#07f0c2cbf63c1d7de6f21fa43443ede3)
- [其他](#d3690e0b19c784e104273fe4d64b2362)
    - [ 文章-新添加的](#9162e3507d24e58e9e944dd3f6066c0e)
    - [(284) 工具-新添加的](#1d9dec1320a5d774dc8e0e7604edfcd3)
    - [(3) 工具-其他](#bc2b78af683e7ba983205592de8c3a7a)
    - [angr](#4fe330ae3e5ce0b39735b1bfea4528af)
        - [(26) 工具](#1ede5ade1e55074922eb4b6386f5ca65)
        - [文章](#042ef9d415350eeb97ac2539c2fa530e)
    - [Debug&&调试](#324874bb7c3ead94eae6f1fa1af4fb68)
        - [(116) 工具](#d22bd989b2fdaeda14b64343b472dfb6)
        - [文章](#136c41f2d05739a74c6ec7d8a84df1e8)
    - [BAP](#9f8d3f2c9e46fbe6c25c22285c8226df)
        - [(26) 工具](#f10e9553770db6f98e8619dcd74166ef)
        - [文章](#e111826dde8fa44c575ce979fd54755d)
    - [BinNavi](#2683839f170250822916534f1db22eeb)
        - [(3) 工具](#2e4980c95871eae4ec0e76c42cc5c32f)
        - [文章](#ff4dc5c746cb398d41fb69a4f8dfd497)
    - [Decompiler&&反编译器](#0971f295b0f67dc31b7aa45caf3f588f)
        - [(73) 工具](#e67c18b4b682ceb6716388522f9a1417)
        - [文章](#a748b79105651a8fd8ae856a7dc2b1de)
    - [Disassemble&&反汇编](#2df6d3d07e56381e1101097d013746a0)
        - [(30) 工具](#59f472c7575951c57d298aef21e7d73c)
        - [文章](#a6eb5a22deb33fc1919eaa073aa29ab5)
    - [GDB](#975d9f08e2771fccc112d9670eae1ed1)
        - [(80) 工具](#5f4381b0a90d88dd2296c2936f7e7f70)
        - [文章](#37b17362d72f9c8793973bc4704893a2)
    - [Captcha&&验证码](#9526d018b9815156cb001ceee36f6b1d)
        - [(55) 工具](#1c6fda19fd076dcbda3ad733d7349e44)
        - [文章](#685f244ad7368e43dbde0a0966095066)
- [Rootkit&&Bootkit](#5fdcfc70dd87360c2dddcae008076547)
    - [(148) 工具](#b8d6f237c04188a10f511cd8988de28a)
    - [(100) 文章](#8645e29263f0886344127d352ebd6884)
- [硬件](#069468057aac03c102abdbeb7a5decf6)
    - [固件](#3574d46dd09566f898b407cebe9df29b)
        - [(44) Firmware&&固件](#649d2aece91551af8b48d29f52943804)
        - [(3) Intel](#fff92e7d304e2c927ef3530f4d327456)
- [Crypto&&加密&&算法](#948dbc64bc0ff4a03296988574f5238c)
    - [(117) 工具](#a6b0a9b9184fd78c8b87ccfe48a8e544)
- [TODO](#35f8efcff18d0449029e9d3157ac0899)


# <a id="35f8efcff18d0449029e9d3157ac0899"></a>TODO


- 对工具进行更细致的分类
- 为工具添加详细的中文描述，包括其内部实现原理和使用方式
- 添加非Github repo
- 补充文章
- 修改已添加文章的描述


# <a id="08e59e476824a221f6e4a69c0bba7d63"></a>IDA


***


## <a id="f11ab1ff46aa300cc3e86528b8a98ad7"></a>插件&&脚本


- 以Github开源工具为主


### <a id="c39dbae63d6a3302c4df8073b4d1cdc8"></a>新添加的




### <a id="c39a6d8598dde6abfeef43faf931beb5"></a>未分类


- [**1058**星][9d] [Py] [fireeye/flare-ida](https://github.com/fireeye/flare-ida) 多工具
    - [StackStrings](https://github.com/fireeye/flare-ida/blob/master/plugins/stackstrings_plugin.py) 自动恢复手动构造的字符串
    - [Struct Typer](https://github.com/fireeye/flare-ida/blob/master/plugins/struct_typer_plugin.py) implements the struct typing described [here](https://www.mandiant.com/blog/applying-function-types-structure-fields-ida/)
    - [ApplyCalleeType](https://github.com/fireeye/flare-ida/blob/master/python/flare/apply_callee_type.py) specify or choose a function type for indirect calls as described [here](https://www.fireeye.com/blog/threat-research/2015/04/flare_ida_pro_script.html)
    - [argtracker](https://github.com/fireeye/flare-ida/blob/master/python/flare/argtracker.py) 识别函数使用的静态参数
    - [idb2pat](https://github.com/fireeye/flare-ida/blob/master/python/flare/idb2pat.py) FLIRT签名生成
    - [objc2_analyzer](https://github.com/fireeye/flare-ida/blob/master/python/flare/objc2_analyzer.py) 在目标Mach-O可执行文件的与Objective-C运行时相关的部分中定义的选择器引用及其实现之间创建交叉引用
    - [MSDN Annotations](https://github.com/fireeye/flare-ida/tree/master/python/flare/IDB_MSDN_Annotator) 从XML文件中提取MSDN信息，添加到IDB数据库中
    - [ironstrings](https://github.com/fireeye/flare-ida/tree/master/python/flare/ironstrings) 使用代码模拟执行（flare-emu）, 恢复构造的字符串
    - [Shellcode Hashes](https://github.com/fireeye/flare-ida/tree/master/shellcode_hashes) 生成Hash数据库
- [**737**星][7m] [Py] [devttys0/ida](https://github.com/devttys0/ida) IDA插件/脚本/模块收集
    - [wpsearch](https://github.com/devttys0/ida/blob/master/scripts/wpsearch.py) 查找在MIPS WPS checksum实现中常见的立即数
    - [md5hash](https://github.com/devttys0/ida/tree/master/modules/md5hash) 纯Python版的MD5 hash实现（IDA的hashlib有问题）
    - [alleycat](https://github.com/devttys0/ida/tree/master/plugins/alleycat) 查找向指定的函数内代码块的路径、查找两个或多个函数之间的路径、生成交互式调用图、可编程
    - [codatify](https://github.com/devttys0/ida/tree/master/plugins/codatify) 定义IDA自动化分析时miss的ASCII字符串、函数、代码。将data段的所有未定义字节转换为DWORD（于是IDA可识别函数和跳转表指针）
    - [fluorescence](https://github.com/devttys0/ida/tree/master/plugins/fluorescence) 高亮函数调用指令
    - [leafblower](https://github.com/devttys0/ida/tree/master/plugins/leafblower) 识别常用的POSIX函数：printf, sprintf, memcmp, strcpy等
    - [localxrefs](https://github.com/devttys0/ida/tree/master/plugins/localxrefs) 在当前函数内部查找所有对任意选择文本的引用
    - [mipslocalvars](https://github.com/devttys0/ida/tree/master/plugins/mipslocalvars) 对栈上只用于存储寄存器的变量进行命名，简化栈数据分析（MISP）
    - [mipsrop](https://github.com/devttys0/ida/tree/master/plugins/mipsrop) 在MIPS可执行代码中搜寻ROP。查找常见的ROP
    - [rizzo](https://github.com/devttys0/ida/tree/master/plugins/rizzo) 对2个或多个IDB之间的函数进行识别和重命名，基于：函数签名、对唯一字符串/常量的引用、模糊签名、调用图
- [**318**星][2m] [C] [ohjeongwook/darungrim](https://github.com/ohjeongwook/darungrim) 软件补丁分析工具
    - [IDA插件](https://github.com/ohjeongwook/darungrim/tree/master/Src/IDAPlugin) 
    - [DGEngine](https://github.com/ohjeongwook/darungrim/tree/master/Src/DGEngine) 
- [**312**星][1y] [C++] [nevermoe/unity_metadata_loader](https://github.com/nevermoe/unity_metadata_loader) 将global-metadata.dat中的字符串和方法/类名称加载到IDA
- [**277**星][4m] [Py] [jpcertcc/aa-tools](https://github.com/jpcertcc/aa-tools) 多脚本
    - [apt17scan.py](https://github.com/jpcertcc/aa-tools/blob/master/apt17scan.py) Volatility插件, 检测APT17相关的恶意代码并提取配置
    - [emdivi_postdata_decoder](https://github.com/jpcertcc/aa-tools/blob/master/emdivi_postdata_decoder.py) 解码Emdivi post的数据
    - [emdivi_string_decryptor](https://github.com/jpcertcc/aa-tools/blob/master/emdivi_string_decryptor.py) IDAPython脚本, 解密Emdivi内的字符串
    - [citadel_decryptor](https://github.com/jpcertcc/aa-tools/tree/master/citadel_decryptor) Data decryption tool for Citadel
    - [adwind_string_decoder](https://github.com/jpcertcc/aa-tools/blob/master/adwind_string_decoder.py) Python script for decoding strings inside Adwind
    - [redleavesscan](https://github.com/jpcertcc/aa-tools/blob/master/redleavesscan.py) Volatility plugin for detecting RedLeaves and extracting its config
    - [datper_splunk](https://github.com/jpcertcc/aa-tools/blob/master/datper_splunk.py) Python script for detects Datper communication and adds result field to Splunk index
    - [datper_elk](https://github.com/jpcertcc/aa-tools/blob/master/datper_elk.py) Python script for detects Datper communication and adds result field to Elasticsearch index
    - [tscookie_decode](https://github.com/jpcertcc/aa-tools/blob/master/tscookie_decode.py) Python script for decrypting and parsing TSCookie configure data
    - [wellmess_cookie_decode](https://github.com/jpcertcc/aa-tools/blob/master/wellmess_cookie_decode.py) Python script for decoding WellMess's cookie data (support Python2)
    - [cobaltstrikescan](https://github.com/jpcertcc/aa-tools/blob/master/cobaltstrikescan.py) Volatility plugin for detecting Cobalt Strike Beacon and extracting its config
    - [tscookie_data_decode](https://github.com/jpcertcc/aa-tools/blob/master/tscookie_data_decode.py) Python script for decrypting and parsing TSCookie configure data
- [**114**星][1y] [Py] [vallejocc/reverse-engineering-arsenal](https://github.com/vallejocc/Reverse-Engineering-Arsenal) 逆向脚本收集
    - [WinDbg](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/WinDbg) Windbg脚本收集
    - [IDA-set_symbols_for_addresses](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/IDA/set_symbols_for_addresses.py) 遍历所有区段查找与指定的（地址，符号）匹配的DWORD地址，并将对应地址的值命名
    - [IDA-stack_strings_deobfuscator_1](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/IDA/stack_strings_deobfuscator_1.py) 反混淆栈字符串
    - [RevealPE](https://github.com/vallejocc/Reverse-Engineering-Arsenal/tree/master/Standalone/RevealPE) 
- [**80**星][4m] [Py] [takahiroharuyama/ida_haru](https://github.com/takahiroharuyama/ida_haru) 多工具
    - [bindiff](https://github.com/takahiroharuyama/ida_haru/blob/master/bindiff/README.org) 使用BinDiff对多个二进制文件进行对比，可多达100个
    - [eset_crackme](https://github.com/takahiroharuyama/ida_haru/blob/master/eset_crackme/README.org) ESET CrackMe driver VM loader/processor
    - [fn_fuzzy](https://github.com/takahiroharuyama/ida_haru/blob/master/fn_fuzzy/README.org) 快速二进制文件对比
    - [stackstring_static](https://github.com/takahiroharuyama/ida_haru/blob/master/stackstring_static/README.org) 静态恢复栈上的字符串
- [**75**星][10m] [Py] [secrary/ida-scripts](https://github.com/secrary/ida-scripts) 多脚本
    - [dumpDyn](https://github.com/secrary/ida-scripts/blob/master/dumpDyn/README.md) 保存动态分配并执行的代码的相关信息：注释、名称、断点、函数等，之后此代码在不同基址执行时使保存内容依然可用
    - [idenLib](https://github.com/secrary/ida-scripts/blob/master/idenLib/README.md) 库函数识别
    - [IOCTL_decode](https://github.com/secrary/ida-scripts/blob/master/IOCTL_decode.py) Windows驱动的IO控制码
    - [XORCheck](https://github.com/secrary/ida-scripts/blob/master/XORCheck.py) check xor
- [**60**星][2y] [Py] [tmr232/idabuddy](https://github.com/tmr232/idabuddy) 逆向滴好盆友??
- [**59**星][2y] [C++] [alexhude/loadprocconfig](https://github.com/alexhude/loadprocconfig) 加载处理器配置文件
- [**59**星][2m] [Py] [williballenthin/idawilli](https://github.com/williballenthin/idawilli) IDA Pro 资源、脚本和配置文件等
    - [hint_calls](https://github.com/williballenthin/idawilli/blob/master/plugins/hint_calls/readme.md) 以Hint的形式战士函数引用的call和字符串
    - [dynamic_hints](https://github.com/williballenthin/idawilli/blob/master/plugins/dynamic_hints/readme.md) 演示如何为动态数据提供自定义hint的示例插件
    - [add_segment](https://github.com/williballenthin/idawilli/tree/master/scripts/add_segment) 将已存在文件的内容添加为新的segment
    - [color](https://github.com/williballenthin/idawilli/tree/master/scripts/color) 对指令进行着色
    - [find_ptrs](https://github.com/williballenthin/idawilli/tree/master/scripts/find_ptrs) 扫描.text区段查找可能为指针的值,并进行标记
    - [yara_fn](https://github.com/williballenthin/idawilli/tree/master/scripts/yara_fn) 创建yara规则，匹配当前函数的basic block
    - [idawilli](https://github.com/williballenthin/idawilli/tree/master/idawilli) a python module that contains utilities for working with the idapython scripting interface.
    - [themes](https://github.com/williballenthin/idawilli/tree/master/themes) colors and skins
- [**58**星][12d] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA等多个工具的多个脚本
    - 重复区段: [IDA->插件->导入导出->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |[DBI->Frida->工具->新添加的](#54836a155de0c15b56f43634cd9cfecf) |
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor的多个脚本
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida多个脚本
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA Scripts
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) IDA插件，识别程序中的中文字符
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py) 辅助识别Objective-C成员函数的caller和callee
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) 使用gdbserver和IDA调试Android时，读取module列表和segment
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) 追踪指令流
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) 检测OLLVM，在某些情况下修复（Android/iOS）
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) 分析macho文件中的block结构
- [**54**星][1y] [Py] [zardus/idalink](https://github.com/zardus/idalink) 使用IDA API时保证不卡界面. 在后台启动与界面脱离IDA CLI会话, 再使用RPyC连接界面
- [**52**星][3y] [C++] [sektioneins/wwcd](https://github.com/sektioneins/wwcd) Capstone支持的IDA视图
- [**51**星][2y] [Py] [cseagle/ida_clemency](https://github.com/cseagle/ida_clemency) IDA cLEMENCy Tools
    - [clemency_ldr](https://github.com/cseagle/ida_clemency/blob/master/clemency_ldr.py) IDA加载程序模块，为9位，中端，cLEMENCy可执行文件创建基本的内存布局，并处理其加载。
    - [clemency_proc](https://github.com/cseagle/ida_clemency/blob/master/clemency_proc.py) IDA处理器模块，处理反汇编和汇编任务
    - [clemency_dump](https://github.com/cseagle/ida_clemency/blob/master/clemency_dump.py) IDA插件，将修改后的数据库内容转储到打包的9位中端字节文件中
    - [clemency_fix](https://github.com/cseagle/ida_clemency/blob/master/clemency_fix.py)  IDA plugin to assist with fixing up poorly disassembled functions that might branch/call into regions that continue to be marked as data blocks.
- [**49**星][12m] [Py] [agustingianni/utilities](https://github.com/agustingianni/utilities) 多个IDAPython脚本
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
- [**47**星][4y] [Py] [jjo-sec/idataco](https://github.com/jjo-sec/idataco) 多功能
- [**46**星][7y] [Py] [carlosgprado/milf](https://github.com/carlosgprado/milf) IDA瑞士军刀
    - [milf](https://github.com/carlosgprado/MILF/blob/master/milf.py) 辅助漏洞挖掘
- [**42**星][4y] [C++] [nihilus/guid-finder](https://github.com/nihilus/guid-finder) 查找GUID/UUID
- [**40**星][7m] [Visual Basic .NET] [dzzie/re_plugins](https://github.com/dzzie/re_plugins) 逆向插件收集
    - [IDASrvr](https://github.com/dzzie/re_plugins/tree/master/IDASrvr) wm_copydata IPC 服务器，通过WM_COPYDATA机制监听远程消息， 可从其他进程中想IDA发送命令，查询数据，控制接口显示
    - [IDA_JScript](https://github.com/dzzie/re_plugins/tree/master/IDA_JScript) 通过IDASrvr，使用JavaScript编写IDA脚本（依赖ActiveX）
    - [IDA_JScript_w_DukDbg](https://github.com/dzzie/re_plugins/tree/master/IDA_JScript_w_DukDbg) IDA_JScript进阶版
    - [IDASrvr2](https://github.com/dzzie/re_plugins/tree/master/IDASrvr2) IDASrvr进阶版，添加x64支持
    - [IdaUdpBridge](https://github.com/dzzie/re_plugins/tree/master/IdaUdpBridge) this replaces the udp command socket in idavbscript which was crashy
    - [IdaVbScript](https://github.com/dzzie/re_plugins/tree/master/IdaVbScript)  ton of small tools for IDA all thrown into one interface
    - [OllySrvr](https://github.com/dzzie/re_plugins/tree/master/OllySrvr)  wm_copydata IPC server running in olly
    - [Olly_hittrace](https://github.com/dzzie/re_plugins/tree/master/Olly_hittrace) You set breakpoints in the UI and it will then run   the app automating it and logging which ones were hit.
    - [Olly_module_bpx](https://github.com/dzzie/re_plugins/tree/master/Olly_module_bpx)    allow you to set breakpoints within modules which have not yet been loaded.
    - [Olly_vbscript](https://github.com/dzzie/re_plugins/tree/master/Olly_vbscript) vbscript automation capability for olly including working across breakpoint events.
    - [PyIDAServer](https://github.com/dzzie/re_plugins/tree/master/PyIDAServer) 测试在IDA中运行IPC服务器
    - [Wingraph32](https://github.com/dzzie/re_plugins/tree/master/Wingraph32) This is another experiment at a wingraph32 replacement for ida. This one has more features to hide nodes, and can also navigate IDA to the selected function when you click on it in the graph. 
    - [rabc_gui](https://github.com/dzzie/re_plugins/tree/master/flash_tools/rabc_gui) this is a GUI front end for RABCDAsm to disasm, reasm, and reinsert  modified script blocks back into flash files.
    - [swfdump_gui](https://github.com/dzzie/re_plugins/tree/master/flash_tools/swfdump_gui) when run against a target swf, it will create a decompressed version of the swf and a .txt disasm log file these files will be cached and used on subsequent loads. if you wish to start over from scratch use the tools->delete cached * options.
    - [gleegraph](https://github.com/dzzie/re_plugins/tree/master/gleegraph) a quick Wingraph32/qwingraph replacement that has some extra features such as being able to navigate IDA to the selected nodes when they are clicked on in graph view, as well as being able to rename the selected node from the  graph, or adding a prefix to all child nodes below it.
    - [hidden_strings](https://github.com/dzzie/re_plugins/tree/master/misc_tools/hidden_strings) scans for strings being build up in char arrays at runtime to hide from traditional strings output
    - [memdump_conglomerate](https://github.com/dzzie/re_plugins/tree/master/misc_tools/memdump_conglomerate) reads a folder full of memory dumps and puts them  all into a single dll husk so they will disassemble at the proper offsets.
    - [memdump_embedder](https://github.com/dzzie/re_plugins/tree/master/misc_tools/memdump_embedder) takes a memory dump and embeds it into a dummy dll husk so that you can disassemble it at the target base address without having to manually reset it everytime
    - [rtf_hexconvert](https://github.com/dzzie/re_plugins/tree/master/misc_tools/rtf_hexconvert) small tool to extract hex strings from a rtf document and show them in a listview. click on listitem to see decoded data in a hexeditor pane where you can save it
    - [uGrapher](https://github.com/dzzie/re_plugins/tree/master/uGrapher) rename real wingraph32.exe to _wingraph.exe and put this one in its place.
    - [wininet_hooks](https://github.com/dzzie/re_plugins/tree/master/wininet_hooks) Hook以下API调用并记录关键信息：HttpOpenRequest,InternetConnect,InternetReadFile,InternetCrackUrl,HttpSendRequest
- [**40**星][2y] [Py] [mxmssh/idametrics](https://github.com/mxmssh/idametrics) 收集x86体系结构的二进制可执行文件的静态软件复杂性度量
- [**38**星][2y] [Py] [saelo/ida_scripts](https://github.com/saelo/ida_scripts) 多脚本
    - [kernelcache](https://github.com/saelo/ida_scripts/blob/master/kernelcache.py) 识别并重命名iOS kernelcache函数stub。ARM64 Only
    - [ssdt](https://github.com/saelo/ida_scripts/blob/master/ssdt.py) 解析Windows内核中的syscall表
- [**34**星][4y] [Py] [madsc13ntist/idapython](https://github.com/madsc13ntist/idapython) IDAPython脚本收集（无文档）
- [**32**星][5y] [Py] [iphelix/ida-pomidor](https://github.com/iphelix/ida-pomidor) 在长时间的逆向中保存注意力和效率
- [**28**星][1y] [Py] [xyzz/vita-ida-physdump](https://github.com/xyzz/vita-ida-physdump) help with physical memory dump reversing
- [**27**星][1y] [Py] [daniel_plohmann/simplifire.idascope](https://bitbucket.org/daniel_plohmann/simplifire.idascope) 简化恶意代码分析
- [**27**星][6m] [Py] [enovella/re-scripts](https://github.com/enovella/re-scripts) IDA/Ghidra/Radare2脚本收集（无文档）
- [**26**星][5y] [Py] [bastkerg/recomp](https://github.com/bastkerg/recomp) IDA recompiler（无文档）
- [**26**星][8m] [C++] [offlinej/ida-rpc](https://github.com/offlinej/ida-rpc) Discord rich presence plugin for IDA Pro 7.0
- [**25**星][3y] [Py] [zyantific/continuum](https://github.com/zyantific/continuum) Plugin adding multi-binary project support to IDA Pro (WIP)
- [**23**星][2m] [Py] [rceninja/re-scripts](https://github.com/rceninja/re-scripts) 
    - [Hyperv-Scripts](https://github.com/rceninja/re-scripts/tree/master/scripts/Hyperv-Scripts) 
    - [IA32-MSR-Decoder](https://github.com/rceninja/re-scripts/tree/master/scripts/IA32-MSR-Decoder) 查找并解码所有的MSR码
    - [IA32-VMX-Helper](https://github.com/rceninja/re-scripts/tree/master/scripts/IA32-VMX-Helper) 查找并解码所有的MSR/VMCS码
- [**23**星][10m] [C++] [trojancyborg/ida_jni_rename](https://github.com/trojancyborg/ida_jni_rename) IDA JNI clal rename
- [**22**星][5y] [Py] [nihilus/idascope](https://github.com/nihilus/idascope) 辅助恶意代码逆向（Bitbucket上的代码较新）
- [**22**星][3m] [Py] [nlitsme/idascripts](https://github.com/nlitsme/idascripts) 枚举多种类型数据：Texts/NonFuncs/...
    - [enumerators](https://github.com/nlitsme/idascripts/blob/master/enumerators.py) Enumeration utilities for idapython
- [**22**星][4y] [Py] [onethawt/idapyscripts](https://github.com/onethawt/idapyscripts) IDAPython脚本
    - [DataXrefCounter ](https://github.com/onethawt/idapyscripts/blob/master/dataxrefcounter.py) 枚举指定区段的所有交叉引用，计算使用频率
- [**22**星][3y] [C++] [patois/idaplugins](https://github.com/patois/idaplugins) Random IDA scripts, plugins, example code (some of it may be old and not working anymore)
- [**20**星][1y] [Py] [hyuunnn/ida_python_scripts](https://github.com/hyuunnn/ida_python_scripts) IDAPython脚本
    - [IDA_comment](https://github.com/hyuunnn/ida_python_scripts/blob/master/IDA_comment.py) 
    - [ida_function_rename](https://github.com/hyuunnn/ida_python_scripts/blob/master/ida_function_rename.py) 
    - [variable_finder](https://github.com/hyuunnn/ida_python_scripts/blob/master/variable_finder.py) 
    - [assembler_disassembler](https://github.com/hyuunnn/ida_python_scripts/blob/master/assembler_disassembler.py) 
    - [api_visualization](https://github.com/hyuunnn/ida_python_scripts/tree/master/api_visualization) 
    - [Decoder](https://github.com/hyuunnn/ida_python_scripts/tree/master/Decoder) Multiple malware decoders
- [**20**星][2y] [C#] [zoebear/radia](https://github.com/zoebear/radia) 创建一个用于可视化代码的交互式、沉浸式环境，辅助二进制文件逆向
- [**20**星][3y] [Py] [ztrix/idascript](https://github.com/ztrix/idascript) Full functional idascript with stdin/stdout handled
- [**20**星][1y] [Py] [hyuunnn/ida_python_scripts](https://github.com/hyuunnn/ida_python_scripts) ida python scripts
- [**20**星][2m] [Py] [mephi42/ida-kallsyms](https://github.com/mephi42/ida-kallsyms) (No Doc)
- [**19**星][1y] [Py] [a1ext/ida-embed-arch-disasm](https://github.com/a1ext/ida-embed-arch-disasm) 使IDA可在32位数据库中反汇编x64代码(WOW64) 
- [**19**星][9m] [Py] [yellowbyte/reverse-engineering-playground](https://github.com/yellowbyte/reverse-engineering-playground) 逆向脚本收集，包括：IDAPython、文件分析、文件格式分析、文件系统分析、Shellcode分析
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
- [**17**星][1y] [Py] [honeybadger1613/etm_displayer](https://github.com/honeybadger1613/etm_displayer) IDA Pro плагин для отображения результата Coresight ETM трассировки perf'а
- [**16**星][5y] [fabi/idacsharp](https://github.com/fabi/idacsharp) C# 'Scripts' for IDA 6.6+ based on
- [**15**星][8m] [CMake] [google/idaidle](https://github.com/google/idaidle) 如果用户将实例闲置时间过长，则会警告用户。在预定的空闲时间后，该插件首先发出警告，然后再保存当前的disassemlby数据库并关闭IDA
- [**14**星][4y] [C++] [nihilus/fast_idb2sig_and_loadmap_ida_plugins](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins) 2个插件
    - [LoadMap](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins/tree/master/LoadMap)  An IDA plugin, which loads a VC/Borland/Dede map file into IDA 4.5
    - [idb2sig](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins/blob/master/idb2sig/ReadMe.txt) 
- [**13**星][2y] [Py] [cisco-talos/pdata_check](https://github.com/cisco-talos/pdata_check) 根据pdata节和运行时函数的最后一条指令识别异常运行时。
- [**13**星][12m] [C++] [nihilus/graphslick](https://github.com/nihilus/graphslick) IDA Plugin - GraphSlick
- [**13**星][1y] [Py] [cxm95/ida_wrapper](https://github.com/cxm95/ida_wrapper) An IDA_Wrapper for linux, shipped with an Function Identifier. It works well with Driller on static linked binaries.
- [**12**星][1y] [Assembly] [gabrielravier/cave-story-decompilation](https://github.com/gabrielravier/cave-story-decompilation) 使用IDA反编译的游戏洞窟物語（Cave Story）
- [**11**星][2y] [Py] [0xddaa/iddaa](https://github.com/0xddaa/iddaa) idapython scripts
- [**11**星][5y] [Py] [dshikashio/idarest](https://github.com/dshikashio/idarest) Expose some basic IDA Pro interactions through a REST API for JSONP
- [**11**星][10m] [C++] [ecx86/ida7-supportlib](https://github.com/ecx86/ida7-supportlib) IDA-SupportLib library by sirmabus, ported to IDA 7
- [**10**星][4y] [C++] [revel8n/spu3dbg](https://github.com/revel8n/spu3dbg) 调试anergistic SPU emulator
- [**9**星][4y] [Py] [nfarrar/ida-colorschemes](https://github.com/nfarrar/ida-colorschemes) A .clr colorscheme generator for IDA Pro 6.4+.
- [**9**星][1m] [C++] [nlitsme/idcinternals](https://github.com/nlitsme/idcinternals) 研究IDC脚本的内部表现形式
- [**9**星][5y] [Ruby] [rogwfu/plympton](https://github.com/rogwfu/plympton) Library to work with yaml exported IDA Pro information and run statistics
- [**9**星][9m] [Py] [0xcpu/relieve](https://github.com/0xcpu/relieve) 逆向/恶意代码分析脚本
    - [elfie](https://github.com/0xcpu/relieve/blob/master/elfie.py)  display (basic) info about an ELF, similar to readelf.
    - [elforensics](https://github.com/0xcpu/relieve/blob/master/elforensics.py)  check ELF for entry point hooks, RWX sections, CTORS & GOT & PLT hooks, function prologue trampolines.
    - [dololi](https://github.com/0xcpu/relieve/tree/master/dololi) unfinished, the idea is to automatically generate an executable that calls exports from DLL(s).
- [**8**星][5y] [Py] [daniel_plohmann/idapatchwork](https://bitbucket.org/daniel_plohmann/idapatchwork) Stitching against malware families with IDA Pro
- [**8**星][2y] [C++] [ecx86/ida7-segmentselect](https://github.com/ecx86/ida7-segmentselect) IDA-SegmentSelect library by sirmabus, ported to IDA 7
- [**8**星][2y] [Py] [fireundubh/ida7-alleycat](https://github.com/fireundubh/ida7-alleycat) Alleycat plugin by devttys0, ported to IDA 7
- [**8**星][1m] [Py] [lanhikari22/gba-ida-pseudo-terminal](https://github.com/lanhikari22/gba-ida-pseudo-terminal) IDAPython tools to aid with analysis, disassembly and data extraction using IDA python commands, tailored for the GBA architecture at some parts
- [**8**星][3y] [Py] [pwnslinger/ibt](https://github.com/pwnslinger/ibt) IDA Pro Back Tracer - Initial project toward automatic customized protocols structure extraction
- [**8**星][2y] [C++] [shazar14/idadump](https://github.com/shazar14/idadump) An IDA Pro script to verify binaries found in a sample and write them to disk
- [**7**星][2y] [Py] [swackhamer/ida_scripts](https://github.com/swackhamer/ida_scripts) IDAPython脚本（无文档）
- [**7**星][10m] [Py] [techbliss/ida_pro_http_ip_geolocator](https://github.com/techbliss/ida_pro_http_ip_geolocator) IDA 插件，查找网址并解析为 ip，通过Google 地图查看
- [**7**星][5y] [Py] [techbliss/processor-changer](https://github.com/techbliss/processor-changer) 修改处理器（需重新打开IDA）
- [**7**星][1y] [C++] [tenable/mida](https://github.com/tenable/mida) 提取RPC接口，重新创建关联的IDL文件
- [**7**星][1y] [C++] [ecx86/ida7-hexrays-invertif](https://github.com/ecx86/ida7-hexrays-invertif) Hex-Rays Invert if statement plugin for IDA 7.0
- [**6**星][2y] [CMake] [elemecca/cmake-ida](https://github.com/elemecca/cmake-ida) 使用CMake构建IDA Pro模块
- [**6**星][9m] [Py] [geosn0w/dumpanywhere64](https://github.com/geosn0w/dumpanywhere64) An IDA (Interactive Disassembler) script that can save a chunk of binary from an address.
- [**5**星][3y] [Py] [andreafioraldi/idavshelp](https://github.com/andreafioraldi/idavshelp) 在IDA中集成VS的帮助查看器
- [**5**星][5m] [Py] [fdiskyou/ida-plugins](https://github.com/fdiskyou/ida-plugins) IDAPython脚本（无文档）
    - [banned_functions](https://github.com/fdiskyou/ida-plugins/blob/master/banned_functions.py) 
- [**5**星][3y] [Py] [gh0st3rs/idassldump](https://github.com/gh0st3rs/idassldump) IDAPython脚本, 将SSL流量转储到文件
- [**5**星][1y] [C++] [lab313ru/m68k_fixer](https://github.com/lab313ru/m68k_fixer) IDA Pro plugin fixer for m68k
- [**5**星][5y] [C#] [npetrovski/ida-smartpatcher](https://github.com/npetrovski/ida-smartpatcher) IDA apply patch GUI
- [**5**星][4y] [Py] [tmr232/tarkus](https://github.com/tmr232/tarkus) Plugin Manager for IDA Pro
- [**5**星][2y] [abarbatei/ida-utils](https://github.com/abarbatei/ida-utils) links, information and helper scripts for IDA Pro
- [**4**星][2m] [Py] [gitmirar/idaextapi](https://github.com/gitmirar/idaextapi) IDA API utlitites
- [**4**星][3y] [Py] [hustlelabs/joseph](https://github.com/hustlelabs/joseph) IDA Viewer Plugins
- [**4**星][1y] [savagedd/samp-server-idb](https://github.com/savagedd/samp-server-idb) 
- [**4**星][2m] [Py] [spigwitmer/golang_struct_builder](https://github.com/spigwitmer/golang_struct_builder) IDA 7.0+ script that auto-generates structs and interfaces from runtime metadata found in golang binaries
- [**3**星][10m] [Py] [gdataadvancedanalytics/ida-python](https://github.com/gdataadvancedanalytics/ida-python) Random assembly of IDA Python scripts
    - [defineIAT](https://github.com/gdataadvancedanalytics/ida-python/blob/master/Trickbot/defineIAT.py) written for the Trickbot sample with sha256 8F590AC32A7C7C0DDFBFA7A70E33EC0EE6EB8D88846DEFBDA6144FADCC23663A
    - [stringDecryption](https://github.com/gdataadvancedanalytics/ida-python/blob/master/Trickbot/stringDecryption.py) written for the Trickbot sample with sha256 8F590AC32A7C7C0DDFBFA7A70E33EC0EE6EB8D88846DEFBDA6144FADCC23663A
- [**3**星][5y] [C++] [nihilus/ida-x86emu](https://github.com/nihilus/ida-x86emu) x86模拟执行
- [**3**星][2y] [Py] [ypcrts/ida-pro-segments](https://github.com/ypcrts/ida-pro-segments) It's very hard to load multiple files in the IDA GUI without it exploding. This makes it easy.
- [**2**星][2y] [C++] [ecx86/ida7-oggplayer](https://github.com/ecx86/ida7-oggplayer) IDA-OggPlayer library by sirmabus, ported to IDA 7
- [**2**星][2y] [Py] [mayl8822/ida](https://github.com/mayl8822/ida) 快速执行谷歌/百度/Bing搜索
- [**2**星][4y] [Py] [nihilus/idapatchwork](https://github.com/nihilus/idapatchwork) Stitching against malware families with IDA Pro
- [**2**星][2y] [Py] [sbouber/idaplugins](https://github.com/sbouber/idaplugins) 
- [**2**星][2m] [Py] [psxvoid/idapython-debugging-dynamic-enrichment](https://github.com/psxvoid/idapython-debugging-dynamic-enrichment) 
- [**1**星][2y] [Py] [andreafioraldi/idamsdnhelp](https://github.com/andreafioraldi/idamsdnhelp) 打开MSDN帮助搜索页
- [**1**星][1y] [Py] [farzonl/idapropluginlab4](https://github.com/farzonl/idapropluginlab4) An ida pro plugin that tracks def use chains of a given x86 binary.
- [**1**星][3m] [Py] [voidsec/ida-helpers](https://github.com/voidsec/ida-helpers) Collection of IDA helpers
- [**0**星][3y] [Py] [kcufid/my_ida_python](https://github.com/kcufid/my_ida_python) My idapython decode data
- [**0**星][1y] [Py] [ruipin/idapy](https://github.com/ruipin/idapy) Various IDAPython libraries and scripts
- [**0**星][9m] [Py] [tkmru/idapython-scripts](https://github.com/tkmru/idapython-scripts) IDAPro scripts


### <a id="fb4f0c061a72fc38656691746e7c45ce"></a>结构体&&类的检测&&创建&&恢复


#### <a id="fa5ede9a4f58d4efd98585d3158be4fb"></a>未分类


- [**931**星][16d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) 二进制代码静态分析工具。值分析（寄存器、内存）、污点分析、类型重建和传播（propagation）、前向/后向分析
    - 重复区段: [IDA->插件->污点分析](#34ac84853604a7741c61670f2a075d20) |
- [**664**星][19d] [Py] [igogo-x86/hexrayspytools](https://github.com/igogo-x86/hexrayspytools) 结构体和类重建插件
- [**168**星][1y] [Py] [bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) 使用IDA Pro重建iOS内核缓存的C++类
    - 重复区段: [IDA->插件->Apple->内核缓存](#82d0fa2d6934ce29794a651513934384) |
- [**140**星][4y] [C++] [nihilus/hexrays_tools](https://github.com/nihilus/hexrays_tools) 辅助结构体定义和虚函数检测
- [**103**星][3m] [Py] [lucasg/findrpc](https://github.com/lucasg/findrpc)  从二进制文件中提取内部的RPC结构体
- [**4**星][3y] [C#] [andreafioraldi/idagrabstrings](https://github.com/andreafioraldi/idagrabstrings) 在指定地址区间内搜索字符串，并将其映射为C结构体
    - 重复区段: [IDA->插件->字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |


#### <a id="4900b1626f10791748b20630af6d6123"></a>C++类&&虚表


- [**607**星][3m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) 利用IDA调试获取的信息，自动创建C++的虚表
    - 重复区段: [IDA->插件->调试->调试数据](#b31acf6c84a9506066d497af4e702bf5) |
        <details>
        <summary>查看详情</summary>


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


- [**171**星][10m] [C++] [ecx86/classinformer-ida7](https://github.com/ecx86/classinformer-ida7) ClassInformer backported for IDA Pro 7.0
- [**130**星][2y] [Py] [nccgroup/susanrtti](https://github.com/nccgroup/SusanRTTI) RTTI解析插件
- [**90**星][1y] [C++] [rub-syssec/marx](https://github.com/rub-syssec/marx) 揭示C++程序中的类继承结构
    - [IDA导出](https://github.com/rub-syssec/marx/blob/master/ida_export/export.py) 
    - [IDA导入插件](https://github.com/rub-syssec/marx/tree/master/ida_import) 
    - [core](https://github.com/rub-syssec/marx/tree/master/src) 
- [**69**星][7y] [C] [nektra/vtbl-ida-pro-plugin](https://github.com/nektra/vtbl-ida-pro-plugin) Identifying Virtual Table Functions using VTBL IDA Pro Plugin + Deviare Hooking Engine
- [**35**星][5y] [C++] [nihilus/ida_classinformer](https://github.com/nihilus/ida_classinformer) IDA ClassInformer PlugIn
- [**32**星][2y] [Py] [krystalgamer/dec2struct](https://github.com/krystalgamer/dec2struct) 使用类定义/声明文件，在 IDA 中轻松创建虚表
- [**16**星][2y] [C++] [mwl4/ida_gcc_rtti](https://github.com/mwl4/ida_gcc_rtti) Class informer plugin for IDA which supports parsing GCC RTTI




### <a id="a7dac37cd93b8bb42c7d6aedccb751b3"></a>收集


- [**1771**星][2d] [onethawt/idaplugins-list](https://github.com/onethawt/idaplugins-list) IDA插件收集
- [**363**星][9m] [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) IDA x64DBG OllyDBG 插件收集
    - 重复区段: [x64dbg->插件->新添加的](#da5688c7823802e734c39b539aa39df7) |
- [**10**星][1y] [Py] [ecx86/ida-scripts](https://github.com/ecx86/ida-scripts) IDA Pro/Hex-Rays configs, scripts, and plugins收集


### <a id="fabf03b862a776bbd8bcc4574943a65a"></a>外观&&主题


- [**723**星][6m] [Py] [zyantific/idaskins](https://github.com/zyantific/idaskins) 皮肤插件
- [**258**星][7y] [eugeneching/ida-consonance](https://github.com/eugeneching/ida-consonance) 黑色皮肤插件
- [**106**星][6m] [CSS] [0xitx/ida_nightfall](https://github.com/0xitx/ida_nightfall) 黑色主题插件
- [**58**星][7y] [gynophage/solarized_ida](https://github.com/gynophage/solarized_ida) Solarized黑色主题
- [**10**星][7y] [Py] [luismiras/ida-color-scripts](https://github.com/luismiras/ida-color-scripts) 导入导出颜色主题
- [**9**星][2y] [CSS] [gbps/x64dbg-consonance-theme](https://github.com/gbps/x64dbg-consonance-theme) 黑色的x64dbg主题
- [**6**星][5y] [Py] [techbliss/ida-styler](https://github.com/techbliss/ida-styler) 修改IDA样式
- [**3**星][2m] [rootbsd/ida_pro_zinzolin_theme](https://github.com/rootbsd/ida_pro_zinzolin_theme) zinzolin主题
- [**1**星][1y] [C] [albertzsigovits/idc-dark](https://github.com/albertzsigovits/idc-dark) A dark-mode color scheme for Hex-Rays IDA using idc


### <a id="a8f5db3ab4bc7bc3d6ca772b3b9b0b1e"></a>固件&&嵌入式设备


- [**5228**星][1m] [Py] [refirmlabs/binwalk](https://github.com/ReFirmLabs/binwalk) 固件分析工具（命令行+IDA插件）
    - [IDA插件](https://github.com/ReFirmLabs/binwalk/tree/master/src/scripts) 
    - [binwalk](https://github.com/ReFirmLabs/binwalk/tree/master/src/binwalk) 
- [**492**星][4m] [Py] [maddiestone/idapythonembeddedtoolkit](https://github.com/maddiestone/idapythonembeddedtoolkit) 自动分析嵌入式设备的固件
- [**177**星][2y] [Py] [duo-labs/idapython](https://github.com/duo-labs/idapython) Duo 实验室使用的IDAPython 脚本收集
    - 重复区段: [IDA->插件->Apple->未分类](#8530752bacfb388f3726555dc121cb1a) |
    - [cortex_m_firmware](https://github.com/duo-labs/idapython/blob/master/cortex_m_firmware.py)  整理包含ARM Cortex M微控制器固件的IDA Pro数据库
    - [amnesia](https://github.com/duo-labs/idapython/blob/master/amnesia.py) 使用字节级启发式在IDA Pro数据库中的未定义字节中查找ARM Thumb指令
    - [REobjc](https://github.com/duo-labs/idapython/blob/master/reobjc.py) 在Objective-C的调用函数和被调用函数之间进行适当的交叉引用
- [**101**星][1m] [Py] [pagalaxylab/vxhunter](https://github.com/PAGalaxyLab/vxhunter) 用于分析基于VxWorks的嵌入式设备的工具集
    - [R2](https://github.com/PAGalaxyLab/vxhunter/blob/master/firmware_tools/vxhunter_r2_py2.py) 
    - [IDA插件](https://github.com/PAGalaxyLab/vxhunter/blob/master/firmware_tools/vxhunter_ida.py) 
    - [Ghidra插件](https://github.com/PAGalaxyLab/vxhunter/tree/master/firmware_tools/ghidra) 


### <a id="02088f4884be6c9effb0f1e9a3795e58"></a>签名(FLIRT等)&&比较(Diff)&&匹配


#### <a id="cf04b98ea9da0056c055e2050da980c1"></a>未分类


- [**421**星][30d] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) 汇编代码管理与分析平台(独立工具+IDA插件)
    - 重复区段: [IDA->插件->作为辅助](#83de90385d03ac8ef27360bfcdc1ab48) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 
- [**149**星][1y] [C++] [ajkhoury/sigmaker-x64](https://github.com/ajkhoury/SigMaker-x64) IDA Pro 7.0 compatible SigMaker plugin
- [**131**星][1y] [Py] [cisco-talos/bass](https://github.com/cisco-talos/bass) 从先前生成的恶意软件集群的样本中自动生成AV签名
- [**71**星][4y] [Py] [icewall/bindifffilter](https://github.com/icewall/bindifffilter) IDA Pro plugin making easier work on BinDiff results
- [**69**星][5y] [Py] [arvinddoraiswamy/slid](https://github.com/arvinddoraiswamy/slid) 静态链接库检测
- [**51**星][2m] [Py] [vrtadmin/first-plugin-ida](https://github.com/vrtadmin/first-plugin-ida) 函数识别与签名恢复工具
- [**45**星][1y] [Py] [l4ys/idasignsrch](https://github.com/l4ys/idasignsrch) 签名搜索
- [**33**星][3y] [Py] [g4hsean/binauthor](https://github.com/g4hsean/binauthor) 识别未知二进制文件的作者
- [**31**星][1y] [Py] [cisco-talos/casc](https://github.com/cisco-talos/casc) 在IDA的反汇编和字符串窗口中, 辅助创建ClamAV NDB 和 LDB签名
- [**25**星][2y] [LLVM] [syreal17/cardinal](https://github.com/syreal17/cardinal) Similarity Analysis to Defeat Malware Compiler Variations
- [**24**星][6m] [Py] [xorpd/fcatalog_server](https://github.com/xorpd/fcatalog_server) Functions Catalog
- [**21**星][3y] [Py] [xorpd/fcatalog_client](https://github.com/xorpd/fcatalog_client) fcatalog idapython client
- [**18**星][5y] [Py] [zaironne/snippetdetector](https://github.com/zaironne/snippetdetector) IDA Python scripts project for snippets detection
- [**17**星][8y] [C++] [alexander-pick/idb2pat](https://github.com/alexander-pick/idb2pat) idb2pat plugin, fixed to work with IDA 6.2
- [**14**星][8y] [Standard ML] [letsunlockiphone/iphone-baseband-ida-pro-signature-files](https://github.com/letsunlockiphone/iphone-baseband-ida-pro-signature-files) IDA签名文件，iPhone基带逆向
    - 重复区段: [IDA->插件->Apple->未分类](#8530752bacfb388f3726555dc121cb1a) |
- [**3**星][4y] [Py] [ayuto/discover_win](https://github.com/ayuto/discover_win) 对比Linux和Windows二进制文件，对Windows文件未命名的函数进行自动重命名
    - 重复区段: [IDA->插件->函数相关->重命名](#73813456eeb8212fd45e0ea347bec349) |
- [**0**星][1y] [Py] [gh0st3rs/idaprotosync](https://github.com/gh0st3rs/idaprotosync) 在2个或多个函数中识别函数原型


#### <a id="19360afa4287236abe47166154bc1ece"></a>FLIRT签名


##### <a id="1c9d8dfef3c651480661f98418c49197"></a>FLIRT签名收集


- [**605**星][1m] [Max] [maktm/flirtdb](https://github.com/Maktm/FLIRTDB) A community driven collection of IDA FLIRT signature files
- [**321**星][5m] [push0ebp/sig-database](https://github.com/push0ebp/sig-database) IDA FLIRT Signature Database
- [**4**星][9m] [cloudwindby/ida-pro-sig](https://github.com/cloudwindby/ida-pro-sig) IDA PRO FLIRT signature files MSVC2017的sig文件


##### <a id="a9a63d23d32c6c789ca4d2e146c9b6d0"></a>FLIRT签名生成


- [**62**星][11m] [Py] [push0ebp/allirt](https://github.com/push0ebp/allirt) Tool that converts All of libc to signatures for IDA Pro FLIRT Plugin. and utility make sig with FLAIR easily
- [**54**星][8m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - 重复区段: [IDA->插件->导入导出->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[Ghidra->插件->与其他工具交互->IDA](#d832a81018c188bf585fcefa3ae23062) |




#### <a id="161e5a3437461dc8959cc923e6a18ef7"></a>Diff&&Match工具


- [**1554**星][5d] [Py] [joxeankoret/diaphora](https://github.com/joxeankoret/diaphora) program diffing
- [**360**星][25d] [Py] [checkpointsw/karta](https://github.com/checkpointsw/karta) source code assisted fast binary matching plugin for IDA
- [**332**星][1y] [Py] [joxeankoret/pigaios](https://github.com/joxeankoret/pigaios) A tool for matching and diffing source codes directly against binaries.
- [**135**星][1y] [Py] [nirizr/rematch](https://github.com/nirizr/rematch) REmatch, a complete binary diffing framework that is free and strives to be open source and community driven.
- [**95**星][7m] [Visual Basic .NET] [dzzie/idacompare](https://github.com/dzzie/idacompare) 汇编级别对比工具
- [**73**星][4y] [C] [nihilus/ida_signsrch](https://github.com/nihilus/ida_signsrch) signsrch签名匹配
- [**72**星][5y] [Py] [binsigma/binsourcerer](https://github.com/binsigma/binsourcerer) 反汇编与源码匹配
- [**72**星][3y] [vrtadmin/first](https://github.com/vrtadmin/first) 函数识别和签名恢复, 带服务器
- [**52**星][5y] [C++] [filcab/patchdiff2](https://github.com/filcab/patchdiff2) IDA binary differ. Since code.google.com/p/patchdiff2/ seemed abandoned, I did the obvious thing…
- [**14**星][3y] [Py] [0x00ach/idadiff](https://github.com/0x00ach/idadiff) IDAPython脚本，使用@Heurs MACHOC algorithm (https://github.com/ANSSI-FR/polichombr)算法创建二进制文件的CFG Hash，与其他样本对比。如果发现1-1关系，则重命名
- [**14**星][5y] [C++] [binsigma/binclone](https://github.com/binsigma/binclone) 检测恶意代码中的相似代码


#### <a id="46c9dfc585ae59fe5e6f7ddf542fb31a"></a>Yara


- [**449**星][2m] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) 使用Yara规则查找加密常量
    - 重复区段: [IDA->插件->加密解密](#06d2caabef97cf663bd29af2b1fe270c) |
- [**92**星][2m] [Py] [hyuunnn/hyara](https://github.com/hyuunnn/Hyara) 辅助编写Yara规则
    - [IDA插件](https://github.com/hy00un/hyara/tree/master/IDA%20Plugin) 
    - [BinaryNinja插件](https://github.com/hy00un/hyara/tree/master/BinaryNinja%20Plugin) 
- [**92**星][2m] [Py] [hyuunnn/hyara](https://github.com/hyuunnn/hyara) Yara rule making tool (IDA Pro & Binary Ninja Plugin)
- [**83**星][1y] [Py] [oalabs/findyara](https://github.com/oalabs/findyara) 使用Yara规则扫描二进制文件
- [**16**星][11m] [Py] [bnbdr/ida-yara-processor](https://github.com/bnbdr/ida-yara-processor) 针对已编译Yara规则文件的Loader&&Processor
    - 重复区段: [IDA->插件->针对特定分析目标->Loader](#cb59d84840e41330a7b5e275c0b81725) |
- [**14**星][1y] [Py] [alexander-hanel/ida_yara](https://github.com/alexander-hanel/ida_yara) 使用Yara扫描IDB数据
- [**14**星][1y] [Py] [souhailhammou/idaray-plugin](https://github.com/souhailhammou/idaray-plugin) IDARay is an IDA Pro plugin that matches the database against multiple YARA files which themselves may contain multiple rules.




### <a id="5e91b280aab7f242cbc37d64ddbff82f"></a>IDB操作


- [**316**星][6m] [Py] [williballenthin/python-idb](https://github.com/williballenthin/python-idb) idb 文件解析和分析工具
- [**151**星][1m] [Py] [nccgroup/idahunt](https://github.com/nccgroup/idahunt) 在IDA外部使用IDAPython脚本, 批量创建/读取/解析IDB文件, 可编写自己的IDB分析脚本,命令行工具,
- [**87**星][5m] [C++] [nlitsme/idbutil](https://github.com/nlitsme/idbutil) 从 IDA 数据库中提取数据，支持 idb 及 i64
- [**81**星][3m] [Py] [nlitsme/pyidbutil](https://github.com/nlitsme/pyidbutil) 读取IDB数据库
- [**18**星][1y] [Py] [kkhaike/tinyidb](https://github.com/kkhaike/tinyidb) 从巨型IDB数据库中导出用户数据
- [**0**星][4y] [C] [hugues92/idaextrapassplugin](https://github.com/hugues92/idaextrapassplugin) 修复与清理IDB数据库


### <a id="206ca17fc949b8e0ae62731d9bb244cb"></a>协作逆向&&多人操作相同IDB文件


- [**508**星][11m] [Py] [idarlingteam/idarling](https://github.com/IDArlingTeam/IDArling) 多人协作插件
- [**258**星][1y] [C++] [dga-mi-ssi/yaco](https://github.com/dga-mi-ssi/yaco) 利用Git版本控制，同步多人对相同二进制文件的修改
- [**88**星][5y] [Py] [cubicalabs/idasynergy](https://github.com/cubicalabs/idasynergy) 集成了版本控制系统(svn)的IDA插件
- [**71**星][2m] [C++] [cseagle/collabreate](https://github.com/cseagle/collabreate) Hook IDA的事件通知，将事件涉及的修改内容广播到中心服务器，中心服务器转发给其他分析相同文件的用户
- [**4**星][2y] [Py] [argussecurity/psida](https://bitbucket.org/socialauth/login/atlassianid/?next=%2Fargussecurity%2Fpsida) IDAPython脚本收集，当前只有协作逆向的脚本


### <a id="f7d311685152ac005cfce5753c006e4b"></a>与调试器同步&&通信&&交互


- [**471**星][5d] [C] [bootleg/ret-sync](https://github.com/bootleg/ret-sync) 在反汇编工具和调试器之间同步调试会话
    - 重复区段: [x64dbg->插件->新添加的](#da5688c7823802e734c39b539aa39df7) |
    - [GDB插件](https://github.com/bootleg/ret-sync/tree/master/ext_gdb) 
    - [Ghidra插件](https://github.com/bootleg/ret-sync/tree/master/ext_ghidra) 
    - [IDA插件](https://github.com/bootleg/ret-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/bootleg/ret-sync/tree/master/ext_lldb) 
    - [OD](https://github.com/bootleg/ret-sync/tree/master/ext_olly1) 
    - [OD2](https://github.com/bootleg/ret-sync/tree/master/ext_olly2) 
    - [WinDgb](https://github.com/bootleg/ret-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/bootleg/ret-sync/tree/master/ext_x64dbg) 
- [**292**星][10m] [C] [a1ext/labeless](https://github.com/a1ext/labeless) 在IDA和调试器之间无缝同步Label/注释等
    - [IDA插件](https://github.com/a1ext/labeless/tree/master/labeless_ida) 
    - [OD](https://github.com/a1ext/labeless/tree/master/labeless_olly) 
    - [OD2](https://github.com/a1ext/labeless/tree/master/labeless_olly2) 
    - [x64dbg](https://github.com/a1ext/labeless/tree/master/labeless_x64dbg) 
- [**179**星][1y] [Py] [andreafioraldi/idangr](https://github.com/andreafioraldi/idangr) 在IDA中使用angrdbg调试器进行调试
- [**132**星][2y] [Py] [comsecuris/gdbida](https://github.com/comsecuris/gdbida) 使用GDB调试时，在IDA中自动跟随当前GDB的调试位置
    - [IDA插件](https://github.com/comsecuris/gdbida/blob/master/ida_gdb_bridge.py) 
    - [GDB脚本](https://github.com/comsecuris/gdbida/blob/master/gdb_ida_bridge_client.py) 
- [**97**星][4y] [C++] [quarkslab/qb-sync](https://github.com/quarkslab/qb-sync) 使用调试器调试时，自动在IDA中跟随调试位置
    - [GDB插件](https://github.com/quarkslab/qb-sync/tree/master/ext_gdb) 
    - [IDA插件](https://github.com/quarkslab/qb-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/quarkslab/qb-sync/tree/master/ext_lldb) 
    - [OD2](https://github.com/quarkslab/qb-sync/tree/master/ext_olly2) 
    - [WinDbg](https://github.com/quarkslab/qb-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/quarkslab/qb-sync/tree/master/ext_x64dbg) 
- [**46**星][4m] [JS] [sinakarvandi/windbg2ida](https://github.com/sinakarvandi/windbg2ida) 在IDA中显示Windbg调试的每个步骤
    - [Windbg脚本](https://github.com/sinakarvandi/windbg2ida/blob/master/windbg2ida.js) JavaScript
    - [IDA脚本](https://github.com/sinakarvandi/windbg2ida/blob/master/IDAScript.py) 
- [**36**星][10m] [Py] [anic/ida2pwntools](https://github.com/anic/ida2pwntools) IDA插件，远程连接pwntools启动的程序进行pwn调试
- [**29**星][2y] [Py] [iweizime/dbghider](https://github.com/iweizime/dbghider) 向被调试进程隐藏IDA调试器
- [**19**星][7y] [Py] [rmadair/windbg2ida](https://github.com/rmadair/windbg2ida) 将WinDBG中的调试trace导入到IDA


### <a id="6fb7e41786c49cc3811305c520dfe9a1"></a>导入导出&与其他工具交互


#### <a id="8ad723b704b044e664970b11ce103c09"></a>未分类


- [**163**星][2m] [Py] [x64dbg/x64dbgida](https://github.com/x64dbg/x64dbgida) x64dbg插件，用于IDA数据导入导出
    - 重复区段: [x64dbg->插件->新添加的](#da5688c7823802e734c39b539aa39df7) |
- [**148**星][2m] [C++] [alschwalm/dwarfexport](https://github.com/alschwalm/dwarfexport) Export dwarf debug information from IDA Pro
- [**96**星][2y] [Py] [robindavid/idasec](https://github.com/robindavid/idasec) IDA插件，与Binsec 平台进行交互
- [**67**星][1y] [Py] [lucasg/idamagnum](https://github.com/lucasg/idamagnum) 在IDA中向MagnumDB发起请求, 查询枚举常量可能的值
- [**59**星][1m] [Py] [binaryanalysisplatform/bap-ida-python](https://github.com/binaryanalysisplatform/bap-ida-python) IDAPython脚本，在IDA中集成BAP
- [**35**星][5y] [Py] [siberas/ida2sym](https://github.com/siberas/ida2sym) IDAScript to create Symbol file which can be loaded in WinDbg via AddSyntheticSymbol
- [**28**星][6y] [C++] [oct0xor/deci3dbg](https://github.com/oct0xor/deci3dbg) Ida Pro debugger module for Playstation 3
    - 重复区段: [IDA->插件->针对特定分析目标->PS3](#315b1b8b41c67ae91b841fce1d4190b5) |
- [**28**星][5m] [C++] [thalium/idatag](https://github.com/thalium/idatag) IDA plugin to explore and browse tags
- [**19**星][2y] [Py] [brandon-everhart/angryida](https://github.com/brandon-everhart/angryida) 在IDA中集成angr二进制分析框架
    - 重复区段: [其他->angr->工具](#1ede5ade1e55074922eb4b6386f5ca65) |
- [**16**星][4y] [C++] [m417z/mapimp](https://github.com/m417z/mapimp) an OllyDbg plugin which will help you to import map files exported by IDA, Dede, IDR, Microsoft and Borland linkers.
- [**16**星][5y] [Py] [danielmgmi/virusbattle-ida-plugin](https://github.com/danielmgmi/virusbattle-ida-plugin) The plugin is an integration of Virus Battle API to the well known IDA Disassembler.
- [**8**星][7y] [C++] [patois/madnes](https://github.com/patois/madnes) 从IDB中导出符号和名称，使可在FCEUXD SP中导入
- [**3**星][1y] [Py] [r00tus3r/differential_debugging](https://github.com/r00tus3r/differential_debugging) Differential debugging using IDA Python and GDB


#### <a id="c7066b0c388cd447e980bf0eb38f39ab"></a>Ghidra


- [**299**星][4m] [Py] [cisco-talos/ghida](https://github.com/cisco-talos/ghida) 在IDA中集成Ghidra反编译器
    - 重复区段: [Ghidra->插件->与其他工具交互->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**238**星][9m] [Py] [daenerys-sre/source](https://github.com/daenerys-sre/source) 使IDA和Ghidra脚本通用, 无需修改
    - 重复区段: [Ghidra->插件->与其他工具交互->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**88**星][4m] [Py] [cisco-talos/ghidraaas](https://github.com/cisco-talos/ghidraaas) 通过REST API暴露Ghidra分析服务, 也是GhIDA的后端
    - 重复区段: [Ghidra->插件->与其他工具交互->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**54**星][8m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - 重复区段: [IDA->插件->签名(FLIRT等)->FLIRT签名->FLIRT签名生成](#a9a63d23d32c6c789ca4d2e146c9b6d0) |[Ghidra->插件->与其他工具交互->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**47**星][2m] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
    - 重复区段: [Ghidra->插件->与其他工具交互->IDA](#d832a81018c188bf585fcefa3ae23062) |[x64dbg->插件->新添加的](#da5688c7823802e734c39b539aa39df7) |


#### <a id="11139e7d6db4c1cef22718868f29fe12"></a>BinNavi


- [**382**星][18d] [C++] [google/binexport](https://github.com/google/binexport) 将反汇编以Protocol Buffer的形式导出为PostgreSQL数据库, 导入到BinNavi中使用
    - 重复区段: [其他->BinNavi->工具](#2e4980c95871eae4ec0e76c42cc5c32f) |
- [**213**星][4y] [PLpgSQL] [cseagle/freedom](https://github.com/cseagle/freedom) 从IDA中导出反汇编信息, 导入到binnavi中使用
    - 重复区段: [其他->BinNavi->工具](#2e4980c95871eae4ec0e76c42cc5c32f) |
- [**25**星][7y] [Py] [tosanjay/bopfunctionrecognition](https://github.com/tosanjay/bopfunctionrecognition) plugin to BinNavi tool to analyze a x86 binanry file to find buffer overflow prone functions. Such functions are important for vulnerability analysis.
    - 重复区段: [其他->BinNavi->工具](#2e4980c95871eae4ec0e76c42cc5c32f) |


#### <a id="d1ff64bee76f6749aef6100d72bfbe3a"></a>BinaryNinja


- [**68**星][8m] [Py] [lunixbochs/revsync](https://github.com/lunixbochs/revsync) IDA和Binja实时同步插件
    - 重复区段: [BinaryNinja->插件->与其他工具交互->IDA](#713fb1c0075947956651cc21a833e074) |
- [**61**星][6m] [Py] [zznop/bnida](https://github.com/zznop/bnida) 4个脚本，在IDA和BinaryNinja间交互数据
    - 重复区段: [BinaryNinja->插件->与其他工具交互->IDA](#713fb1c0075947956651cc21a833e074) |
    - [ida_export](https://github.com/zznop/bnida/blob/master/ida/ida_export.py) 将数据从IDA中导入
    - [ida_import](https://github.com/zznop/bnida/blob/master/ida/ida_import.py) 将数据导入到IDA
    - [binja_export](https://github.com/zznop/bnida/blob/master/binja_export.py) 将数据从BinaryNinja中导出
    - [binja_import](https://github.com/zznop/bnida/blob/master/binja_import.py) 将数据导入到BinaryNinja
- [**14**星][6m] [Py] [cryptogenic/idc_importer](https://github.com/cryptogenic/idc_importer) Binary Ninja插件，从IDA中导入IDC数据库转储
    - 重复区段: [BinaryNinja->插件->与其他工具交互->IDA](#713fb1c0075947956651cc21a833e074) |


#### <a id="21ed198ae5a974877d7a635a4b039ae3"></a>Radare2


- [**125**星][8m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) 将IDA Pro和Radare2识别的符号（目前仅函数）导出到ELF符号表
    - 重复区段: [IDA->插件->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->插件->函数相关->未分类](#347a2158bdd92b00cd3d4ba9a0be00ae) |[Radare2->插件->与其他工具交互->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**123**星][2m] [Py] [radare/radare2ida](https://github.com/radare/radare2ida) Tools, documentation and scripts to move projects from IDA to R2 and viceversa
    - 重复区段: [Radare2->插件->与其他工具交互->IDA](#1cfe869820ecc97204a350a3361b31a7) |


#### <a id="a1cf7f7f849b4ca2101bd31449c2a0fd"></a>Frida


- [**128**星][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) 在Frida Client和IDA之间建立连接，将运行时信息直接导入IDA，并可直接在IDA中控制Frida
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |[DBI->Frida->工具->与其他工具交互->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**83**星][5y] [Py] [techbliss/frida_for_ida_pro](https://github.com/techbliss/frida_for_ida_pro) 在IDA中使用Frida, 主要用于追踪函数
    - 重复区段: [DBI->Frida->工具->与其他工具交互->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
- [**58**星][12d] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA等多个工具的多个脚本
    - 重复区段: [IDA->插件->未分类](#c39a6d8598dde6abfeef43faf931beb5) |[DBI->Frida->工具->新添加的](#54836a155de0c15b56f43634cd9cfecf) |
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor的多个脚本
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida多个脚本
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA Scripts
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) IDA插件，识别程序中的中文字符
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py) 辅助识别Objective-C成员函数的caller和callee
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) 使用gdbserver和IDA调试Android时，读取module列表和segment
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) 追踪指令流
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) 检测OLLVM，在某些情况下修复（Android/iOS）
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) 分析macho文件中的block结构
- [**40**星][2y] [Py] [agustingianni/memrepl](https://github.com/agustingianni/memrepl) Frida 插件，辅助开发内存崩溃类的漏洞
    - 重复区段: [DBI->Frida->工具->新添加的](#54836a155de0c15b56f43634cd9cfecf) |


#### <a id="dd0332da5a1482df414658250e6357f8"></a>IntelPin


- [**134**星][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) 多功能, 带界面,辅助静态分析、漏洞挖掘、动态追踪(Pin)、导入导出等
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |[IDA->插件->漏洞->未分类](#385d6777d0747e79cccab0a19fa90e7e) |[DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**44**星][3y] [Batchfile] [maldiohead/idapin](https://github.com/maldiohead/idapin) plugin of ida with pin
    - 重复区段: [DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |




### <a id="004c199e1dbf71769fbafcd8e58d1ead"></a>针对特定分析目标


#### <a id="5578c56ca09a5804433524047840980e"></a>未分类


- [**542**星][2y] [Py] [anatolikalysch/vmattack](https://github.com/anatolikalysch/vmattack) 基于虚拟化的壳的分析(静态/动态)与反混淆
    - 重复区段: [IDA->插件->反混淆](#7199e8787c0de5b428f50263f965fda7) |
- [**199**星][4y] [Py] [f8left/decllvm](https://github.com/f8left/decllvm) IDA plugin for OLLVM analysis
- [**117**星][1y] [Py] [xerub/idastuff](https://github.com/xerub/idastuff) 针对ARM处理器
- [**101**星][4d] [Py] [fboldewin/com-code-helper](https://github.com/fboldewin/com-code-helper) IDAPython脚本, 辅助重建MS COM 代码
- [**93**星][4m] [Py] [themadinventor/ida-xtensa](https://github.com/themadinventor/ida-xtensa) 分析Tensilica Xtensa (as seen in ESP8266)
- [**82**星][4y] [C++] [wjp/idados](https://github.com/wjp/idados) DOSBox调试器插件
    - 重复区段: [IDA->插件->调试->未分类](#2944dda5289f494e5e636089db0d6a6a) |
- [**75**星][3m] [Py] [coldzer0/ida-for-delphi](https://github.com/coldzer0/ida-for-delphi) 针对Delphi的IDAPython脚本，从 Event Constructor (VCL)中获取所有函数名称
- [**59**星][2y] [Py] [isra17/nrs](https://github.com/isra17/nrs) 脱壳并分析NSIS installer打包的文件
- [**59**星][6m] [C++] [troybowman/dtxmsg](https://github.com/troybowman/dtxmsg) 辅助逆向DTXConnectionServices 框架
- [**57**星][4m] [Py] [giantbranch/mipsaudit](https://github.com/giantbranch/mipsaudit) IDA MIPS静态扫描脚本，汇编审计辅助脚本
- [**50**星][9m] [C] [lab313ru/smd_ida_tools](https://github.com/lab313ru/smd_ida_tools) Sega Genesis/MegaDrive ROM文件加载器，Z80音频驱动加载器，IDA Pro调试器
- [**47**星][2y] [C++] [antid0tecom/aarch64_armv81extension](https://github.com/antid0tecom/aarch64_armv81extension) IDA AArch64 处理器扩展：添加对ARMv8.1 opcodes的支持
- [**33**星][3y] [Py] [sam-b/windows_syscalls_dumper](https://github.com/sam-b/windows_syscalls_dumper) 转储Windows系统调用Call的 number/name，以json格式导出
- [**24**星][3y] [C++] [sektioneins/aarch64_cryptoextension](https://github.com/sektioneins/aarch64_cryptoextension) IDA AArch64 processor extender extension: Adding crypto extension instructions (AES/SHA1/SHA256)
- [**23**星][12m] [Py] [howmp/comfinder](https://github.com/howmp/comfinder) 查找标记COM组件中的函数
    - 重复区段: [IDA->插件->函数相关->重命名](#73813456eeb8212fd45e0ea347bec349) |
- [**23**星][3y] [Py] [pfalcon/ida-xtensa2](https://github.com/pfalcon/ida-xtensa2) IDAPython plugin for Tensilica Xtensa (as seen in ESP8266), version 2
- [**20**星][5y] [Py] [digitalbond/ibal](https://github.com/digitalbond/ibal) 辅助Bootrom分析
- [**19**星][2y] [C] [andywhittaker/idaproboschme7x](https://github.com/andywhittaker/idaproboschme7x) Bosch ME7x C16x反汇编辅助
- [**16**星][3y] [Py] [0xdeva/ida-cpu-risc-v](https://github.com/0xdeva/ida-cpu-risc-v) RISCV-V 反汇编器
- [**15**星][5y] [Py] [dolphin-emu/gcdsp-ida](https://github.com/dolphin-emu/gcdsp-ida) 辅助GC DSP逆向
- [**11**星][2y] [C++] [hyperiris/gekkops](https://github.com/hyperiris/gekkops) Nintendo GameCube Gekko CPU Extension plug-in for IDA Pro 5.2
- [**4**星][3y] [Py] [neogeodev/idaneogeo](https://github.com/neogeodev/idaneogeo) NeoGeo binary loader & helper for the Interactive Disassembler
- [**3**星][5m] [C] [extremlapin/glua_c_headers_for_ida](https://github.com/extremlapin/glua_c_headers_for_ida) Glua module C headers for IDA
- [**2**星][5m] [Py] [lucienmp/idapro_m68k](https://github.com/lucienmp/idapro_m68k) 扩展IDA对m68k的支持，添加gdb step-over 和类型信息支持
- [**0**星][9m] [C] [0xd0cf11e/idcscripts](https://github.com/0xd0cf11e/idcscripts) idc脚本
    - [emotet-decode](https://github.com/0xd0cf11e/idcscripts/blob/master/emotet/emotet-decode.idc) 解码emotet
- [**0**星][2m] [C++] [marakew/emuppc](https://github.com/marakew/emuppc) PowerPC模拟器，脱壳某些 PowerPC 二进制文件


#### <a id="cb59d84840e41330a7b5e275c0b81725"></a>Loader&Processor


- [**205**星][1y] [Py] [fireeye/idawasm](https://github.com/fireeye/idawasm) WebAssembly的加载器和解析器
- [**161**星][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->插件->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[Android->工具->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |[Android->工具->新添加的1](#63fd2c592145914e99f837cecdc5a67c) |
- [**155**星][2y] [Py] [crytic/ida-evm](https://github.com/crytic/ida-evm) 以太坊虚拟机的Processor模块
- [**146**星][20d] [Py] [argp/iboot64helper](https://github.com/argp/iboot64helper) IDAPython loader to help with AArch64 iBoot, iBEC, and SecureROM reverse engineering
- [**131**星][2y] [C] [gsmk/hexagon](https://github.com/gsmk/hexagon) IDA processor module for the hexagon (QDSP6) processor
- [**112**星][1y] [pgarba/switchidaproloader](https://github.com/pgarba/switchidaproloader) Loader for IDA Pro to support the Nintendo Switch NRO binaries
- [**79**星][9m] [Py] [reswitched/loaders](https://github.com/reswitched/loaders) IDA Loaders for Switch binaries(NSO / NRO)
- [**72**星][2y] [Py] [embedi/meloader](https://github.com/embedi/meloader) 加载英特尔管理引擎固件
- [**55**星][6m] [C++] [mefistotelis/ida-pro-loadmap](https://github.com/mefistotelis/ida-pro-loadmap) Plugin for IDA Pro disassembler which allows loading .map files.
- [**37**星][1y] [C++] [patois/nesldr](https://github.com/patois/nesldr) Nintendo Entertainment System (NES) ROM loader module for IDA Pro
- [**35**星][1y] [Py] [bnbdr/ida-bpf-processor](https://github.com/bnbdr/ida-bpf-processor) BPF Processor for IDA Python
- [**33**星][1y] [C++] [teammolecule/toshiba-mep-idp](https://github.com/TeamMolecule/toshiba-mep-idp) IDA Pro module for Toshiba MeP processors
- [**32**星][5y] [Py] [0xebfe/3dsx-ida-pro-loader](https://github.com/0xebfe/3dsx-ida-pro-loader) IDA PRO Loader for 3DSX files
- [**28**星][4y] [C] [gdbinit/teloader](https://github.com/gdbinit/teloader) A TE executable format loader for IDA
- [**27**星][3m] [Py] [ghassani/mclf-ida-loader](https://github.com/ghassani/mclf-ida-loader) An IDA file loader for Mobicore trustlet and driver binaries
- [**27**星][3y] [Py] [w4kfu/ida_loader](https://github.com/w4kfu/ida_loader) loader module 收集
- [**23**星][2y] [C++] [balika011/belf](https://github.com/balika011/belf) Balika011's PlayStation 4 ELF loader for IDA Pro 7.0/7.1
- [**23**星][6y] [vtsingaras/qcom-mbn-ida-loader](https://github.com/vtsingaras/qcom-mbn-ida-loader) IDA loader plugin for Qualcomm Bootloader Stages
- [**20**星][3y] [C++] [patois/ndsldr](https://github.com/patois/ndsldr) Nintendo DS ROM loader module for IDA Pro
- [**18**星][8y] [Py] [rpw/flsloader](https://github.com/rpw/flsloader) IDA Pro loader module for Infineon/Intel-based iPhone baseband firmwares
- [**17**星][9m] [C++] [gocha/ida-snes-ldr](https://github.com/gocha/ida-snes-ldr) SNES ROM Cartridge File Loader for IDA (Interactive Disassembler) 6.x
- [**16**星][11m] [Py] [bnbdr/ida-yara-processor](https://github.com/bnbdr/ida-yara-processor) 针对已编译Yara规则文件的Loader&&Processor
    - 重复区段: [IDA->插件->签名(FLIRT等)->Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |
- [**16**星][9m] [C++] [gocha/ida-65816-module](https://github.com/gocha/ida-65816-module) SNES 65816 processor plugin for IDA (Interactive Disassembler) 6.x
- [**16**星][1y] [Py] [lcq2/riscv-ida](https://github.com/lcq2/riscv-ida) RISC-V ISA处理器模块
- [**16**星][1y] [Py] [ptresearch/nios2](https://github.com/ptresearch/nios2) IDA Pro processor module for Altera Nios II Classic/Gen2 microprocessor architecture
- [**14**星][2y] [Py] [patois/necromancer](https://github.com/patois/necromancer) IDA Pro V850 Processor Module Extension
- [**13**星][1y] [Py] [rolfrolles/hiddenbeeloader](https://github.com/rolfrolles/hiddenbeeloader) IDA loader module for Hidden Bee's custom executable file format
- [**10**星][4y] [C++] [areidz/nds_loader](https://github.com/areidz/nds_loader) Nintendo DS loader module for IDA Pro 6.1
- [**10**星][6y] [Py] [cycad/mbn_loader](https://github.com/cycad/mbn_loader) IDA Pro Loader Plugin for Samsung Galaxy S4 ROMs
- [**7**星][1y] [C++] [fail0verflow/rl78-ida-proc](https://github.com/fail0verflow/rl78-ida-proc) Renesas RL78 processor module for IDA
- [**5**星][9m] [C++] [gocha/ida-spc700-module](https://github.com/gocha/ida-spc700-module) SNES SPC700 processor plugin for IDA (Interactive Disassembler)
- [**3**星][9m] [C++] [gocha/ida-snes_spc-ldr](https://github.com/gocha/ida-snes_spc-ldr) SNES-SPC700 Sound File Loader for IDA (Interactive Disassembler)
- [**2**星][3m] [C] [cisco-talos/ida_tilegx](https://github.com/cisco-talos/ida_tilegx) This is an IDA processor module for the Tile-GX processor architecture


#### <a id="1b17ac638aaa09852966306760fda46b"></a>GoLang


- [**376**星][9m] [Py] [sibears/idagolanghelper](https://github.com/sibears/idagolanghelper) 解析Go语言编译的二进制文件中的GoLang类型信息
- [**297**星][2m] [Py] [strazzere/golang_loader_assist](https://github.com/strazzere/golang_loader_assist) 辅助Go逆向


#### <a id="4c158ccc5aee04383755851844fdd137"></a>Windows驱动


- [**306**星][1y] [Py] [fsecurelabs/win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) A tool to help when dealing with Windows IOCTL codes or reversing Windows drivers.
- [**218**星][1y] [Py] [nccgroup/driverbuddy](https://github.com/nccgroup/driverbuddy) 辅助逆向Windows内核驱动
- [**74**星][5y] [Py] [tandasat/winioctldecoder](https://github.com/tandasat/winioctldecoder) IDA插件，将Windows设备IO控制码解码成为DeviceType, FunctionCode, AccessType, MethodType.
- [**23**星][1y] [C] [ioactive/kmdf_re](https://github.com/ioactive/kmdf_re) 辅助逆向KMDF驱动


#### <a id="315b1b8b41c67ae91b841fce1d4190b5"></a>PS3&&PS4


- [**69**星][3m] [C] [aerosoul94/ida_gel](https://github.com/aerosoul94/ida_gel) A collection of IDA loaders for various game console ELF's. (PS3, PSVita, WiiU)
- [**55**星][7y] [C++] [kakaroto/ps3ida](https://github.com/kakaroto/ps3ida) IDA scripts and plugins for PS3
- [**44**星][2y] [C] [aerosoul94/dynlib](https://github.com/aerosoul94/dynlib) 辅助PS4用户模式ELF逆向
    - 重复区段: [IDA->插件->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
- [**28**星][6y] [C++] [oct0xor/deci3dbg](https://github.com/oct0xor/deci3dbg) Ida Pro debugger module for Playstation 3
    - 重复区段: [IDA->插件->导入导出->未分类](#8ad723b704b044e664970b11ce103c09) |


#### <a id="f5e51763bb09d8fd47ee575a98bedca1"></a>PDB


- [**98**星][4m] [C++] [mixaill/fakepdb](https://github.com/mixaill/fakepdb) 通过IDA数据库生成PDB文件
- [**39**星][1y] [Py] [ax330d/ida_pdb_loader](https://github.com/ax330d/ida_pdb_loader) IDA PDB Loader
- [**14**星][1y] [CMake] [gdataadvancedanalytics/bindifflib](https://github.com/gdataadvancedanalytics/bindifflib) Automated library compilation and PDB annotation with CMake and IDA Pro
- [**2**星][6m] [Py] [clarkb7/annotate_lineinfo](https://github.com/clarkb7/annotate_lineinfo) Annotate IDA with source and line number information from a PDB


#### <a id="7d0681efba2cf3adaba2780330cd923a"></a>Flash&&SWF


- [**34**星][1y] [Py] [kasperskylab/actionscript3](https://github.com/kasperskylab/actionscript3) SWF Loader、ActionScript3 Processor和 IDA 调试辅助插件
- [**27**星][4y] [C++] [nihilus/ida-pro-swf](https://github.com/nihilus/ida-pro-swf) 处理SWF文件


#### <a id="841d605300beba45c3be131988514a03"></a>特定样本家族


- [**9**星][2y] [Py] [d00rt/easy_way_nymaim](https://github.com/d00rt/easy_way_nymaim) IDA脚本, 用于去除恶意代码nymaim的混淆,创建干净的idb
- [**8**星][3y] [Py] [thngkaiyuan/mynaim](https://github.com/thngkaiyuan/mynaim) Nymaim 家族样本反混淆插件
    - 重复区段: [IDA->插件->反混淆](#7199e8787c0de5b428f50263f965fda7) |
- [**4**星][2y] [Py] [immortalp0ny/fyvmdisassembler](https://github.com/immortalp0ny/fyvmdisassembler) 对 FinSpy VM进行反虚拟化/反汇编的IDAPython脚本
- [**4**星][8m] [C] [lacike/gandcrab_string_decryptor](https://github.com/lacike/gandcrab_string_decryptor) 解密 GandCrab v5.1-5.3 中的字符串
    - 重复区段: [IDA->插件->字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |


#### <a id="ad44205b2d943cfa2fa805b2643f4595"></a>CTF


- [**132**星][2y] [Py] [pwning/defcon25-public](https://github.com/pwning/defcon25-public) DEFCON 25 某Talk用到的 反汇编器和 IDA 模块




### <a id="ad68872e14f70db53e8d9519213ec039"></a>IDAPython本身


#### <a id="2299bc16945c25652e5ad4d48eae8eca"></a>未分类


- [**720**星][7d] [Py] [idapython/src](https://github.com/idapython/src) IDAPython源码
- [**373**星][2m] [Py] [tmr232/sark](https://github.com/tmr232/sark) IDAPython的高级抽象
- [**248**星][2y] [Py] [intezer/docker-ida](https://github.com/intezer/docker-ida) 在Docker容器中执行IDA, 以自动化/可扩展/分布式的方式执行IDAPython脚本
- [**82**星][4y] [idapython/bin](https://github.com/idapython/bin) IDAPython binaries
- [**69**星][2y] [Py] [alexander-hanel/idapython6to7](https://github.com/alexander-hanel/idapython6to7) 
- [**43**星][1y] [Py] [nirizr/pytest-idapro](https://github.com/nirizr/pytest-idapro) 辅助对IDAPython脚本进行单元测试
- [**29**星][3y] [Py] [kerrigan29a/idapython_virtualenv](https://github.com/kerrigan29a/idapython_virtualenv) 在IDAPython中启用Virtualenv或Conda，使可以有多个虚拟环境
- [**23**星][3y] [Py] [devttys0/idascript](https://github.com/devttys0/idascript) IDA的Wrapper，在命令行中自动对目标文件执行IDA脚本


#### <a id="c42137cf98d6042372b1fd43c3635135"></a>cheatsheets


- [**258**星][20d] [Py] [inforion/idapython-cheatsheet](https://github.com/inforion/idapython-cheatsheet) Scripts and cheatsheets for IDAPython




### <a id="846eebe73bef533041d74fc711cafb43"></a>指令参考&文档


- [**497**星][1y] [PLpgSQL] [nologic/idaref](https://github.com/nologic/idaref) 指令参考插件.
- [**449**星][4m] [C++] [alexhude/friend](https://github.com/alexhude/friend) 反汇编显示增强, 文档增强插件
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**250**星][2y] [Py] [gdelugre/ida-arm-system-highlight](https://github.com/gdelugre/ida-arm-system-highlight) 用于高亮和解码 ARM 系统指令
- [**106**星][2m] [Py] [neatmonster/amie](https://github.com/neatmonster/amie) 针对ARM架构的`FRIEND`插件, 文档增强
- [**45**星][8y] [Py] [zynamics/msdn-plugin-ida](https://github.com/zynamics/msdn-plugin-ida) Imports MSDN documentation into IDA Pro
- [**24**星][3y] [AutoIt] [yaseralnajjar/ida-msdn-helper](https://github.com/yaseralnajjar/IDA-MSDN-helper) IDA Pro MSDN Helper


### <a id="c08ebe5b7eec9fc96f8eff36d1d5cc7d"></a>辅助脚本编写


#### <a id="45fd7cfce682c7c25b4f3fbc4c461ba2"></a>未分类


- [**393**星][3y] [Py] [36hours/idaemu](https://github.com/36hours/idaemu) 基于Unicorn引擎的代码模拟插件
    - 重复区段: [IDA->插件->模拟器集成](#b38dab81610be087bd5bc7785269b8cc) |
- [**282**星][1m] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) 结合Unicorn引擎, 简化模拟脚本的编写
    - 重复区段: [IDA->插件->模拟器集成](#b38dab81610be087bd5bc7785269b8cc) |
- [**137**星][18d] [Py] [arizvisa/ida-minsc](https://github.com/arizvisa/ida-minsc) a plugin for IDA Pro that assists a user with scripting the IDAPython plugin that is bundled with the disassembler.
- [**104**星][29d] [Py] [patois/idapyhelper](https://github.com/patois/idapyhelper) IDAPython脚本编写辅助
- [**74**星][4m] [C++] [0xeb/ida-qscripts](https://github.com/0xeb/ida-qscripts) IDA“最近脚本/执行脚本”的进化版
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**42**星][6m] [C++] [0xeb/ida-climacros](https://github.com/0xeb/ida-climacros) 在IDA命令行接口中定义和使用静态/动态的宏
- [**32**星][2y] [CMake] [zyantific/ida-cmake](https://github.com/zyantific/ida-cmake) 使用CMake编译C++编写的IDA脚本
- [**22**星][1y] [Py] [nirizr/idasix](https://github.com/nirizr/idasix) IDAPython兼容库。创建平滑的IDA开发流程，使相同代码可应用于多个IDA/IDAPython版本
- [**4**星][7m] [inndy/idapython-cheatsheet](https://github.com/inndy/idapython-cheatsheet) scripting IDA like a Pro


#### <a id="1a56a5b726aaa55ec5b7a5087d6c8968"></a>Qt


- [**25**星][1y] [techbliss/ida_pro_ultimate_qt_build_guide](https://github.com/techbliss/ida_pro_ultimate_qt_build_guide) Ida Pro Ultimate Qt Build Guide
- [**13**星][3m] [Py] [tmr232/cute](https://github.com/tmr232/cute) 在IDAPython中兼容QT4/QT5
- [**9**星][3y] [Py] [techbliss/ida_pro_screen_recorder](https://github.com/techbliss/ida_pro_screen_recorder) PyQt plugin for Ida Pro for Screen recording.


#### <a id="1721c09501e4defed9eaa78b8d708361"></a>控制台&&窗口界面


- [**269**星][30d] [Py] [eset/ipyida](https://github.com/eset/ipyida) 集成IPython控制台
- [**232**星][2y] [Jupyter Notebook] [james91b/ida_ipython](https://github.com/james91b/ida_ipython) 嵌入IPython内核，集成IPython
- [**175**星][4m] [Py] [techbliss/python_editor](https://github.com/techbliss/python_editor) Python脚本编辑窗口


#### <a id="227fbff77e3a13569ef7b007344d5d2e"></a>插件模板


- [**5**星][2y] [C++] [patois/ida_vs2017](https://github.com/patois/ida_vs2017) IDA 7.x VS 2017 项目模板
- [**4**星][5y] [JS] [nihilus/ida-pro-plugin-wizard-for-vs2013](https://github.com/nihilus/ida-pro-plugin-wizard-for-vs2013) IDA Pro plugin wizard for VisualStudio 2013


#### <a id="8b19bb8cf9a5bc9e6ab045f3b4fabf6a"></a>其他语言


- [**22**星][3y] [Java] [cblichmann/idajava](https://github.com/cblichmann/idajava) Java integration for Hex-Rays IDA Pro
- [**8**星][3y] [C++] [nlitsme/idaperl](https://github.com/nlitsme/idaperl) 在IDA中使用Perl编写脚本




### <a id="dc35a2b02780cdaa8effcae2b6ce623e"></a>古老的


- [**162**星][4y] [Py] [osirislab/fentanyl](https://github.com/osirislab/Fentanyl) 简化打补丁
- [**127**星][6y] [C++] [crowdstrike/crowddetox](https://github.com/crowdstrike/crowddetox) CrowdStrike CrowdDetox Plugin for Hex-Rays，automatically removes junk code and variables from Hex-Rays function decompilation
- [**95**星][5y] [Py] [nihilus/ida-idc-scripts](https://github.com/nihilus/ida-idc-scripts) 多个IDC脚本收集
- [**82**星][6y] [Py] [einstein-/hexrays-python](https://github.com/einstein-/hexrays-python) Python bindings for the Hexrays Decompiler
- [**76**星][5y] [PHP] [v0s/plus22](https://github.com/v0s/plus22) Tool to analyze 64-bit binaries with 32-bit Hex-Rays Decompiler
- [**63**星][5y] [C] [nihilus/idastealth](https://github.com/nihilus/idastealth) 
- [**40**星][6y] [C++] [wirepair/idapinlogger](https://github.com/wirepair/idapinlogger) Logs instruction hits to a file which can be fed into IDA Pro to highlight which instructions were called.
- [**39**星][10y] [izsh/ida-python-scripts](https://github.com/izsh/ida-python-scripts) IDA Python Scripts
- [**39**星][8y] [Py] [zynamics/bincrowd-plugin-ida](https://github.com/zynamics/bincrowd-plugin-ida) BinCrowd Plugin for IDA Pro
- [**35**星][8y] [Py] [zynamics/ida2sql-plugin-ida](https://github.com/zynamics/ida2sql-plugin-ida) 
- [**27**星][4y] [C++] [luorui110120/idaplugins](https://github.com/luorui110120/idaplugins) 一堆IDA插件，无文档
- [**21**星][10y] [C++] [sporst/ida-pro-plugins](https://github.com/sporst/ida-pro-plugins) Collection of IDA Pro plugins I wrote over the years
- [**18**星][10y] [Py] [binrapt/ida](https://github.com/binrapt/ida) Python script which extracts procedures from IDA Win32 LST files and converts them to correctly dynamically linked compilable Visual C++ inline assembly.
- [**16**星][7y] [Py] [nihilus/optimice](https://github.com/nihilus/optimice) 
- [**10**星][10y] [jeads-sec/etherannotate_ida](https://github.com/jeads-sec/etherannotate_ida) EtherAnnotate IDA Pro Plugin - Parse EtherAnnotate trace files and markup IDA disassemblies with runtime values
- [**6**星][10y] [C] [jeads-sec/etherannotate_xen](https://github.com/jeads-sec/etherannotate_xen) EtherAnnotate Xen Ether Modification - Adds a feature to Ether that pulls register values and potential string values at each instruction during an instruction trace.


### <a id="e3e7030efc3b4de3b5b8750b7d93e6dd"></a>调试&&动态运行&动态数据


#### <a id="2944dda5289f494e5e636089db0d6a6a"></a>未分类


- [**395**星][1y] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) 用Unicorn引擎做后端的调试插件
    - 重复区段: [IDA->插件->模拟器集成](#b38dab81610be087bd5bc7785269b8cc) |
- [**187**星][5y] [C++] [nihilus/scyllahide](https://github.com/nihilus/scyllahide) 用户模式反-反调试
- [**107**星][15d] [Py] [danielplohmann/apiscout](https://github.com/danielplohmann/apiscout) 简化导入API恢复。可以从内存中恢复API信息。包含命令行版本和IDA插件。可以处理PE头被抹掉等ImpRec/ImpRec无法处理的情况。
- [**82**星][4y] [C++] [wjp/idados](https://github.com/wjp/idados) DOSBox调试器插件
    - 重复区段: [IDA->插件->针对特定分析目标->未分类](#5578c56ca09a5804433524047840980e) |
- [**57**星][7y] [Py] [cr4sh/ida-vmware-gdb](https://github.com/cr4sh/ida-vmware-gdb) 辅助Windows内核调试
- [**42**星][5y] [Py] [nihilus/idasimulator](https://github.com/nihilus/idasimulator) 扩展IDA的条件断点支持，在被调试进行中使用Python代码替换复杂的执行代码
- [**39**星][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) 辅助Android调试的IDAPython脚本
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |[Android->工具->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**22**星][5y] [Py] [techbliss/scylladumper](https://github.com/techbliss/scylladumper) Ida Plugin to Use the Awsome Scylla plugin
- [**14**星][5y] [Py] [techbliss/free_the_debuggers](https://github.com/techbliss/free_the_debuggers) 自动加载并执行调试器插件？？
- [**0**星][2y] [Py] [benh11235/ida-windbglue](https://github.com/benh11235/ida-windbglue) 与远程WinDBG调试服务器进行连接的"胶水"脚本


#### <a id="0fbd352f703b507853c610a664f024d1"></a>DBI数据


- [**943**星][1y] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - 重复区段: [DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->工具->与其他工具交互->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |[DBI->Frida->工具->与其他工具交互->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**134**星][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) 多功能, 带界面,辅助静态分析、漏洞挖掘、动态追踪(Pin)、导入导出等
    - 重复区段: [IDA->插件->导入导出->IntelPin](#dd0332da5a1482df414658250e6357f8) |[IDA->插件->漏洞->未分类](#385d6777d0747e79cccab0a19fa90e7e) |[DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**128**星][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) 在Frida Client和IDA之间建立连接，将运行时信息直接导入IDA，并可直接在IDA中控制Frida
    - 重复区段: [IDA->插件->导入导出->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |[DBI->Frida->工具->与其他工具交互->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**122**星][5y] [C++] [zachriggle/ida-splode](https://github.com/zachriggle/ida-splode) 使用Pin收集动态运行数据, 导入到IDA中查看
    - 重复区段: [DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/zachriggle/ida-splode/tree/master/py) 
    - [PinTool](https://github.com/zachriggle/ida-splode/tree/master/src) 
- [**117**星][2y] [C++] [0xphoenix/mazewalker](https://github.com/0xphoenix/mazewalker) 使用Pin收集数据，导入到IDA中查看
    - 重复区段: [DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |
    - [mazeui](https://github.com/0xphoenix/mazewalker/blob/master/MazeUI/mazeui.py) 在IDA中显示界面
    - [PyScripts](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/PyScripts) Python脚本，处理收集到的数据
    - [PinClient](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/src) 
- [**89**星][8y] [C] [neuroo/runtime-tracer](https://github.com/neuroo/runtime-tracer) 使用Pin收集运行数据并在IDA中显示
    - 重复区段: [DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |
    - [PinTool](https://github.com/neuroo/runtime-tracer/tree/master/tracer) 
    - [IDA插件](https://github.com/neuroo/runtime-tracer/tree/master/ida-pin) 
- [**80**星][3y] [Py] [davidkorczynski/repeconstruct](https://github.com/davidkorczynski/repeconstruct) 自动脱壳并重建二进制文件
- [**52**星][11m] [Py] [cisco-talos/dyndataresolver](https://github.com/cisco-talos/dyndataresolver) 动态数据解析. 在IDA中控制DyRIO执行程序的指定部分, 记录执行过程后传回数据到IDA
    - 重复区段: [DBI->DynamoRIO->工具->与其他工具交互](#928642a55eff34b6b52622c6862addd2) |
    - [DDR](https://github.com/cisco-talos/dyndataresolver/blob/master/VS_project/ddr/ddr.sln) 基于DyRIO的Client
    - [IDA插件](https://github.com/cisco-talos/dyndataresolver/tree/master/IDAplugin) 
- [**20**星][9m] [C++] [secrary/findloop](https://github.com/secrary/findloop) 使用DyRIO查找执行次数过多的代码块
    - 重复区段: [DBI->DynamoRIO->工具->与其他工具交互](#928642a55eff34b6b52622c6862addd2) |
- [**15**星][1y] [C++] [agustingianni/instrumentation](https://github.com/agustingianni/instrumentation) PinTool收集。收集数据可导入到IDA中
    - 重复区段: [DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |
    - [CodeCoverage](https://github.com/agustingianni/instrumentation/tree/master/CodeCoverage) 
    - [Pinnacle](https://github.com/agustingianni/instrumentation/tree/master/Pinnacle) 
    - [Recoverer](https://github.com/agustingianni/instrumentation/tree/master/Recoverer) 
    - [Resolver](https://github.com/agustingianni/instrumentation/tree/master/Resolver) 


#### <a id="b31acf6c84a9506066d497af4e702bf5"></a>调试数据


- [**607**星][3m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) 利用IDA调试获取的信息，自动创建C++的虚表
    - 重复区段: [IDA->插件->结构体->C++类](#4900b1626f10791748b20630af6d6123) |
        <details>
        <summary>查看详情</summary>


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


- [**386**星][5m] [Py] [ynvb/die](https://github.com/ynvb/die) 使用IDA调试器收集动态运行信息, 辅助静态分析
- [**380**星][4y] [Py] [deresz/funcap](https://github.com/deresz/funcap) 使用IDA调试时记录动态信息, 辅助静态分析
- [**104**星][3y] [Py] [c0demap/codemap](https://github.com/c0demap/codemap) Hook IDA，调试命中断点时将寄存器/内存信息保存到数据库，在web浏览器中查看
    - [IDA插件](https://github.com/c0demap/codemap/blob/master/idapythonrc.py) 
    - [Web服务器](https://github.com/c0demap/codemap/tree/master/codemap/server) 




### <a id="d2166f4dac4eab7fadfe0fd06467fbc9"></a>反编译器&&AST


- [**1672**星][7m] [C++] [yegord/snowman](https://github.com/yegord/snowman) Snowman反编译器，支持x86, AMD64, ARM。有独立的GUI工具、命令行工具、IDA/Radare2/x64dbg插件，也可以作为库使用
    - 重复区段: [x64dbg->插件->新添加的](#da5688c7823802e734c39b539aa39df7) |
    - [IDA插件](https://github.com/yegord/snowman/tree/master/src/ida-plugin) 
    - [snowman](https://github.com/yegord/snowman/tree/master/src/snowman) QT界面
    - [nocode](https://github.com/yegord/snowman/tree/master/src/nocode) 命令行工具
    - [nc](https://github.com/yegord/snowman/tree/master/src/nc) 核心代码，可作为库使用
- [**1329**星][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) 反编译插件, 多功能
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>查看详情</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**467**星][4y] [Py] [einstein-/decompiler](https://github.com/EiNSTeiN-/decompiler) 多后端的反编译器, 支持IDA和Capstone.
- [**418**星][3m] [C++] [avast/retdec-idaplugin](https://github.com/avast/retdec-idaplugin) retdec 的 IDA 插件
- [**293**星][5y] [C++] [smartdec/smartdec](https://github.com/smartdec/smartdec) 反编译器, 带IDA插件(进阶版为snowman)
    - [IDA插件](https://github.com/smartdec/smartdec/tree/master/src/ida-plugin) 
    - [nocode](https://github.com/smartdec/smartdec/tree/master/src/nocode) 命令行反编译器
    - [smartdec](https://github.com/smartdec/smartdec/tree/master/src/smartdec) 带GUI界面的反编译器
    - [nc](https://github.com/smartdec/smartdec/tree/master/src/nc) 反编译器的核心代码
- [**286**星][5y] [Py] [aaronportnoy/toolbag](https://github.com/aaronportnoy/toolbag) 反编译强化插件
- [**235**星][7m] [Py] [patois/dsync](https://github.com/patois/dsync) 反汇编和反编译窗口同步插件
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**180**星][20d] [Py] [fireeye/fidl](https://github.com/fireeye/fidl) A sane API for IDA Pro's decompiler. Useful for malware RE and vulnerability research
- [**167**星][1y] [Py] [tintinweb/ida-batch_decompile](https://github.com/tintinweb/ida-batch_decompile) 将多个文件及其import用附加注释（外部参照，堆栈变量大小）反编译到pseudocode.c文件
- [**150**星][1y] [Py] [ax330d/hrdev](https://github.com/ax330d/hrdev) 反编译输出增强: 使用Python Clang解析标准的IDA反编译结果
    - 重复区段: [IDA->插件->效率->显示增强](#03fac5b3abdbd56974894a261ce4e25f) |
- [**103**星][5d] [Py] [sibears/hrast](https://github.com/sibears/hrast) 演示如何修改AST(抽象语法树)
- [**90**星][6m] [Py] [patois/hrdevhelper](https://github.com/patois/hrdevhelper) 反编译函数CTree可视化
    - 重复区段: [IDA->插件->效率->显示增强](#03fac5b3abdbd56974894a261ce4e25f) |
- [**70**星][5d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) IDA反编译器脚本，辅助审计对于memcpy() 和memmove()函数的调用
    - 重复区段: [IDA->插件->漏洞->未分类](#385d6777d0747e79cccab0a19fa90e7e) |
- [**25**星][2y] [C++] [dougallj/dj_ida_plugins](https://github.com/dougallj/dj_ida_plugins) 向Hex-Rays反编译器添加VMX intrinsics


### <a id="7199e8787c0de5b428f50263f965fda7"></a>反混淆


- [**1365**星][3m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) 自动从恶意代码中提取反混淆后的字符串
    - 重复区段: [IDA->插件->字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**542**星][2y] [Py] [anatolikalysch/vmattack](https://github.com/anatolikalysch/vmattack) 基于虚拟化的壳的分析(静态/动态)与反混淆
    - 重复区段: [IDA->插件->针对特定分析目标->未分类](#5578c56ca09a5804433524047840980e) |
- [**304**星][4m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) 利用Hex-Rays microcode API破解编译器级别的混淆
    - 重复区段: [IDA->插件->Microcode](#7a2977533ccdac70ee6e58a7853b756b) |
- [**202**星][2y] [Py] [tkmru/nao](https://github.com/tkmru/nao) 移除死代码(dead code), 基于Unicorn引擎
    - 重复区段: [IDA->插件->模拟器集成](#b38dab81610be087bd5bc7785269b8cc) |
- [**47**星][2y] [Py] [riscure/drop-ida-plugin](https://github.com/riscure/drop-ida-plugin) Experimental opaque predicate detection for IDA Pro
- [**23**星][4m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
    - 重复区段: [IDA->插件->污点分析](#34ac84853604a7741c61670f2a075d20) |
- [**8**星][3y] [Py] [thngkaiyuan/mynaim](https://github.com/thngkaiyuan/mynaim) Nymaim 家族样本反混淆插件
    - 重复区段: [IDA->插件->针对特定分析目标->特定样本家族](#841d605300beba45c3be131988514a03) |


### <a id="fcf75a0881617d1f684bc8b359c684d7"></a>效率&&导航&&快速访问&&图形&&图像&&可视化 


#### <a id="c5b120e1779b928d860ad64ff8d23264"></a>其他


- [**1329**星][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) 反编译插件, 多功能
    - 重复区段: [IDA->插件->反编译器](#d2166f4dac4eab7fadfe0fd06467fbc9) |
        <details>
        <summary>查看详情</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**449**星][4m] [C++] [alexhude/friend](https://github.com/alexhude/friend) 反汇编显示增强, 文档增强插件
    - 重复区段: [IDA->插件->指令参考](#846eebe73bef533041d74fc711cafb43) |
- [**372**星][2m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) 若干快速访问功能, 扫描字符串格式化漏洞
    - 重复区段: [IDA->插件->字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->插件->漏洞->未分类](#385d6777d0747e79cccab0a19fa90e7e) |
        <details>
        <summary>查看详情</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**329**星][3m] [Py] [pfalcon/scratchabit](https://github.com/pfalcon/scratchabit) 交互式反汇编工具, 有与IDAPython兼容的插件API
- [**235**星][7m] [Py] [patois/dsync](https://github.com/patois/dsync) 反汇编和反编译窗口同步插件
    - 重复区段: [IDA->插件->反编译器](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**192**星][2m] [Py] [danigargu/dereferencing](https://github.com/danigargu/dereferencing) 调试时寄存器和栈显示增强
- [**130**星][2y] [Py] [comsecuris/ida_strcluster](https://github.com/comsecuris/ida_strcluster) 扩展IDA的字符串导航功能
    - 重复区段: [IDA->插件->字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
- [**99**星][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) 递归查找函数和字符串
    - 重复区段: [IDA->插件->字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->插件->函数相关->导航](#e4616c414c24b58626f834e1be079ebc) |
- [**81**星][7d] [Py] [ax330d/functions-plus](https://github.com/ax330d/functions-plus) 解析函数名称，按命名空间分组，将分组结果以树的形式展示
    - 重复区段: [IDA->插件->函数相关->导航](#e4616c414c24b58626f834e1be079ebc) |
- [**74**星][4m] [C++] [0xeb/ida-qscripts](https://github.com/0xeb/ida-qscripts) IDA“最近脚本/执行脚本”的进化版
    - 重复区段: [IDA->插件->辅助脚本编写->未分类](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**48**星][t] [C++] [jinmo/ifred](https://github.com/jinmo/ifred) IDA command palette & more (Ctrl+Shift+P, Ctrl+P)
- [**40**星][5m] [Py] [tmr232/brutal-ida](https://github.com/tmr232/brutal-ida) 在IDA 7.3中禁用Undo/Redo
- [**23**星][7y] [C++] [cr4sh/ida-ubigraph](https://github.com/cr4sh/ida-ubigraph) IDA Pro plug-in and tools for displaying 3D graphs of procedures using UbiGraph
- [**17**星][2y] [Py] [tmr232/graphgrabber](https://github.com/tmr232/graphgrabber) 获取IDA图的全分辨率图像
- [**5**星][2y] [Py] [handsomematt/ida_func_ptr](https://github.com/handsomematt/ida_func_ptr) 右键菜单中快速拷贝函数指针定义


#### <a id="03fac5b3abdbd56974894a261ce4e25f"></a>显示增强


- [**208**星][27d] [Py] [patois/idacyber](https://github.com/patois/idacyber) 交互式数据可视化插件
- [**150**星][1y] [Py] [ax330d/hrdev](https://github.com/ax330d/hrdev) 反编译输出增强: 使用Python Clang解析标准的IDA反编译结果
    - 重复区段: [IDA->插件->反编译器](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**105**星][2y] [Py] [danigargu/idatropy](https://github.com/danigargu/idatropy) 使用idapython和matplotlib的功能生成熵和直方图的图表
- [**90**星][6m] [Py] [patois/hrdevhelper](https://github.com/patois/hrdevhelper) 反编译函数CTree可视化
    - 重复区段: [IDA->插件->反编译器](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**52**星][29d] [Py] [patois/xray](https://github.com/patois/xray) 根据正则表达式对IDA反编译输出的特定内容进行高亮显示
- [**20**星][4m] [C++] [revspbird/hightlight](https://github.com/revspbird/hightlight) 反编译窗口中代码块和括号高亮
- [**5**星][3y] [Py] [oct0xor/ida_pro_graph_styling](https://github.com/oct0xor/ida_pro_graph_styling) call/jump指令高亮显示
- [**5**星][2y] [C] [teppay/ida](https://github.com/teppay/ida) 指令高亮，黑色主题
- [**3**星][2y] [Py] [andreafioraldi/idaretaddr](https://github.com/andreafioraldi/idaretaddr) 在IDA调试器中高亮函数的返回地址
    - 重复区段: [IDA->插件->函数相关->未分类](#347a2158bdd92b00cd3d4ba9a0be00ae) |


#### <a id="3b1dba00630ce81cba525eea8fcdae08"></a>图形&&图像


- [**2569**星][5m] [Java] [google/binnavi](https://github.com/google/binnavi) 二进制分析IDE, 对反汇编代码的控制流程图和调用图进行探查/导航/编辑/注释.(IDA插件的作用是导出反汇编)
- [**231**星][2y] [C++] [fireeye/simplifygraph](https://github.com/fireeye/simplifygraph) 复杂graphs的简化
- [**40**星][9m] [Py] [rr-/ida-images](https://github.com/rr-/ida-images) 图像预览插件，辅助查找图像解码函数（运行复杂代码，查看内存中是否存在图像）


#### <a id="8f9468e9ab26128567f4be87ead108d7"></a>搜索


- [**150**星][7d] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) 模糊搜索: 命令/函数/结构体
    - 重复区段: [IDA->插件->函数相关->导航](#e4616c414c24b58626f834e1be079ebc) |
- [**64**星][3y] [Py] [xorpd/idsearch](https://github.com/xorpd/idsearch) 搜索工具
- [**23**星][5m] [Py] [alexander-hanel/hansel](https://github.com/alexander-hanel/hansel) IDA搜索插件




### <a id="66052f824f5054aa0f70785a2389a478"></a>Android


- [**246**星][20d] [C++] [strazzere/android-scripts](https://github.com/strazzere/android-scripts) Android逆向脚本收集
    - 重复区段: [Android->工具->ReverseEngineering](#6d2b758b3269bac7d69a2d2c8b45194c) |
- [**161**星][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - 重复区段: [IDA->插件->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->插件->针对特定分析目标->Loader](#cb59d84840e41330a7b5e275c0b81725) |[Android->工具->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |[Android->工具->新添加的1](#63fd2c592145914e99f837cecdc5a67c) |
- [**118**星][4y] [Py] [cvvt/dumpdex](https://github.com/cvvt/dumpdex) 基于IDA python的Android DEX内存dump工具
    - 重复区段: [Android->工具->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**83**星][2y] [Py] [zhkl0228/androidattacher](https://github.com/zhkl0228/androidattacher) IDA debugging plugin for android armv7 so
    - 重复区段: [Android->工具->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**39**星][5y] [Py] [techbliss/adb_helper_qt_super_version](https://github.com/techbliss/adb_helper_qt_super_version) All You Need For Ida Pro And Android Debugging
    - 重复区段: [Android->工具->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**39**星][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) 辅助Android调试的IDAPython脚本
    - 重复区段: [IDA->插件->调试->未分类](#2944dda5289f494e5e636089db0d6a6a) |[Android->工具->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**16**星][7y] [C++] [strazzere/dalvik-header-plugin](https://github.com/strazzere/dalvik-header-plugin) Dalvik Header Plugin for IDA Pro
    - 重复区段: [Android->工具->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |


### <a id="2adc0044b2703fb010b3bf73b1f1ea4a"></a>Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O


#### <a id="8530752bacfb388f3726555dc121cb1a"></a>未分类


- [**177**星][2y] [Py] [duo-labs/idapython](https://github.com/duo-labs/idapython) Duo 实验室使用的IDAPython 脚本收集
    - 重复区段: [IDA->插件->固件](#a8f5db3ab4bc7bc3d6ca772b3b9b0b1e) |
    - [cortex_m_firmware](https://github.com/duo-labs/idapython/blob/master/cortex_m_firmware.py)  整理包含ARM Cortex M微控制器固件的IDA Pro数据库
    - [amnesia](https://github.com/duo-labs/idapython/blob/master/amnesia.py) 使用字节级启发式在IDA Pro数据库中的未定义字节中查找ARM Thumb指令
    - [REobjc](https://github.com/duo-labs/idapython/blob/master/reobjc.py) 在Objective-C的调用函数和被调用函数之间进行适当的交叉引用
- [**167**星][8y] [Py] [zynamics/objc-helper-plugin-ida](https://github.com/zynamics/objc-helper-plugin-ida) 辅助Objective-C二进制文件的分析
- [**21**星][3y] [aozhimin/ios-monitor-resources](https://github.com/aozhimin/ios-monitor-resources) 对各厂商的 iOS SDK 性能监控方案的整理和收集后的资源
- [**17**星][9y] [C++] [alexander-pick/patchdiff2_ida6](https://github.com/alexander-pick/patchdiff2_ida6) patched up patchdiff2 to compile and work with IDA 6 on OSX
- [**14**星][8y] [Standard ML] [letsunlockiphone/iphone-baseband-ida-pro-signature-files](https://github.com/letsunlockiphone/iphone-baseband-ida-pro-signature-files) IDA签名文件，iPhone基带逆向
    - 重复区段: [IDA->插件->签名(FLIRT等)->未分类](#cf04b98ea9da0056c055e2050da980c1) |


#### <a id="82d0fa2d6934ce29794a651513934384"></a>内核缓存


- [**168**星][1y] [Py] [bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) 使用IDA Pro重建iOS内核缓存的C++类
    - 重复区段: [IDA->插件->结构体->未分类](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**140**星][8y] [stefanesser/ida-ios-toolkit](https://github.com/stefanesser/ida-ios-toolkit) 辅助处理iOS kernelcache的IDAPython收集
- [**50**星][1y] [Py] [synacktiv-contrib/kernelcache-laundering](https://github.com/Synacktiv-contrib/kernelcache-laundering) load iOS12 kernelcaches and PAC code in IDA


#### <a id="d249a8d09a3f25d75bb7ba8b32bd9ec5"></a>Mach-O


- [**47**星][8m] [C] [gdbinit/extractmacho](https://github.com/gdbinit/extractmacho) IDA plugin to extract Mach-O binaries located in the disassembly or data
- [**18**星][3y] [C] [cocoahuke/iosdumpkernelfix](https://github.com/cocoahuke/iosdumpkernelfix) This tool will help to fix the Mach-O header of iOS kernel which dump from the memory. So that IDA or function symbol-related tools can loaded function symbols of ios kernel correctly
- [**17**星][8y] [C] [gdbinit/machoplugin](https://github.com/gdbinit/machoplugin) IDA plugin to Display Mach-O headers


#### <a id="1c698e298f6112a86c12881fbd8173c7"></a>Swift


- [**52**星][3y] [Py] [tobefuturer/ida-swift-demangle](https://github.com/tobefuturer/ida-swift-demangle) A tool to demangle Swift function names in IDA.
- [**17**星][3y] [Py] [tylerha97/swiftdemang](https://github.com/0xtyh/swiftdemang) Demangle Swift
- [**17**星][4y] [Py] [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle) 对Swift函数名进行demangle
    - 重复区段: [IDA->插件->函数相关->demangle](#cadae88b91a57345d266c68383eb05c5) |




### <a id="e5e403123c70ddae7bd904d3a3005dbb"></a>ELF


- [**525**星][2y] [C] [lunixbochs/patchkit](https://github.com/lunixbochs/patchkit) 给ELF文件打补丁(命令行+IDA插件)(可编写Python回调,C函数替换等)
    - 重复区段: [IDA->插件->补丁](#7d557bc3d677d206ef6c5a35ca8b3a14) |
    - [IDA插件](https://github.com/lunixbochs/patchkit/tree/master/ida) 
    - [patchkit](https://github.com/lunixbochs/patchkit/tree/master/core) 
- [**206**星][6y] [C] [snare/ida-efiutils](https://github.com/snare/ida-efiutils) 辅助ELF逆向
- [**161**星][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->插件->针对特定分析目标->Loader](#cb59d84840e41330a7b5e275c0b81725) |[Android->工具->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |[Android->工具->新添加的1](#63fd2c592145914e99f837cecdc5a67c) |
- [**125**星][8m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) 将IDA Pro和Radare2识别的符号（目前仅函数）导出到ELF符号表
    - 重复区段: [IDA->插件->导入导出->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[IDA->插件->函数相关->未分类](#347a2158bdd92b00cd3d4ba9a0be00ae) |[Radare2->插件->与其他工具交互->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**92**星][3y] [C++] [gdbinit/efiswissknife](https://github.com/gdbinit/efiswissknife) 辅助 (U)EFI reversing 逆向
- [**84**星][11d] [Py] [yeggor/uefi_retool](https://github.com/yeggor/uefi_retool) 在UEFI固件和UEFI模块分析中查找专有协议的工具
- [**44**星][2y] [C] [aerosoul94/dynlib](https://github.com/aerosoul94/dynlib) 辅助PS4用户模式ELF逆向
    - 重复区段: [IDA->插件->针对特定分析目标->PS3](#315b1b8b41c67ae91b841fce1d4190b5) |
- [**44**星][4y] [Py] [danse-macabre/ida-efitools](https://github.com/danse-macabre/ida-efitools) 辅助逆向ELF文件
- [**43**星][4y] [Py] [strazzere/idant-wanna](https://github.com/strazzere/idant-wanna) ELF header abuse


### <a id="7a2977533ccdac70ee6e58a7853b756b"></a>Microcode


- [**304**星][4m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) 利用Hex-Rays microcode API破解编译器级别的混淆
    - 重复区段: [IDA->插件->反混淆](#7199e8787c0de5b428f50263f965fda7) |
- [**185**星][5m] [C++] [chrisps/hexext](https://github.com/chrisps/Hexext) 通过操作microcode, 优化反编译器的数据
- [**65**星][29d] [Py] [patois/genmc](https://github.com/patois/genmc) 显示Hex-Rays 反编译器的Microcode，辅助开发Microcode插件
- [**54**星][2m] [Py] [idapython/pyhexraysdeob](https://github.com/idapython/pyhexraysdeob) 工具 RolfRolles/HexRaysDeob 的Python版本
- [**19**星][9m] [Py] [neatmonster/mcexplorer](https://github.com/neatmonster/mcexplorer) 工具 RolfRolles/HexRaysDeob 的 Python 版本


### <a id="b38dab81610be087bd5bc7785269b8cc"></a>模拟器集成


- [**504**星][12d] [Py] [alexhude/uemu](https://github.com/alexhude/uemu) 基于Unicorn的模拟器插件
- [**395**星][1y] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) 用Unicorn引擎做后端的调试插件
    - 重复区段: [IDA->插件->调试->未分类](#2944dda5289f494e5e636089db0d6a6a) |
- [**393**星][3y] [Py] [36hours/idaemu](https://github.com/36hours/idaemu) 基于Unicorn引擎的代码模拟插件
    - 重复区段: [IDA->插件->辅助脚本编写->未分类](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**282**星][1m] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) 结合Unicorn引擎, 简化模拟脚本的编写
    - 重复区段: [IDA->插件->辅助脚本编写->未分类](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**202**星][2y] [Py] [tkmru/nao](https://github.com/tkmru/nao) 移除死代码(dead code), 基于Unicorn引擎
    - 重复区段: [IDA->插件->反混淆](#7199e8787c0de5b428f50263f965fda7) |
- [**126**星][3y] [Py] [codypierce/pyemu](https://github.com/codypierce/pyemu) 在IDA中使用x86模拟器


### <a id="83de90385d03ac8ef27360bfcdc1ab48"></a>作为辅助&&构成其他的一环


- [**1542**星][20d] [Py] [lifting-bits/mcsema](https://github.com/lifting-bits/mcsema) 将x86, amd64, aarch64二进制文件转换成LLVM字节码
    - [IDA7插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida7) 用于反汇编二进制文件并生成控制流程图
    - [IDA插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida) 用于反汇编二进制文件并生成控制流程图
    - [Binja插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/binja) 用于反汇编二进制文件并生成控制流程图
    - [mcsema](https://github.com/lifting-bits/mcsema/tree/master/mcsema) 
- [**421**星][30d] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) 汇编代码管理与分析平台(独立工具+IDA插件)
    - 重复区段: [IDA->插件->签名(FLIRT等)->未分类](#cf04b98ea9da0056c055e2050da980c1) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 
- [**27**星][4y] [Scheme] [yifanlu/cgen](https://github.com/yifanlu/cgen) CGEN的Fork，增加了生成IDA IDP模块的支持
- [**23**星][2y] [Py] [tintinweb/unbox](https://github.com/tintinweb/unbox) Unbox is a convenient one-click unpack and decompiler tool that wraps existing 3rd party applications like IDA Pro, JD-Cli, Dex2Src, and others to provide a convenient archiver liker command line interfaces to unpack and decompile various types of files


### <a id="1ded622dca60b67288a591351de16f8b"></a>漏洞


#### <a id="385d6777d0747e79cccab0a19fa90e7e"></a>未分类


- [**492**星][7m] [Py] [danigargu/heap-viewer](https://github.com/danigargu/heap-viewer) 查看glibc堆, 主要用于漏洞开发
- [**376**星][2y] [Py] [1111joe1111/ida_ea](https://github.com/1111joe1111/ida_ea) 用于辅助漏洞开发和逆向
- [**372**星][2m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) 若干快速访问功能, 扫描字符串格式化漏洞
    - 重复区段: [IDA->插件->字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>查看详情</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**138**星][7m] [Py] [iphelix/ida-sploiter](https://github.com/iphelix/ida-sploiter) 辅助漏洞研究
- [**134**星][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) 多功能, 带界面,辅助静态分析、漏洞挖掘、动态追踪(Pin)、导入导出等
    - 重复区段: [IDA->插件->导入导出->IntelPin](#dd0332da5a1482df414658250e6357f8) |[IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**70**星][5d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) IDA反编译器脚本，辅助审计对于memcpy() 和memmove()函数的调用
    - 重复区段: [IDA->插件->反编译器](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**32**星][6y] [Py] [coldheat/quicksec](https://github.com/coldheat/quicksec) IDAPython script for quick vulnerability analysis


#### <a id="cf2efa7e3edb24975b92d2e26ca825d2"></a>ROP


- [**54**星][3y] [Py] [patois/drgadget](https://github.com/patois/drgadget) 开发和分析ROP链
- [**19**星][2y] [Py] [lucasg/idarop](https://github.com/lucasg/idarop) 列举并存储ROP gadgets




### <a id="7d557bc3d677d206ef6c5a35ca8b3a14"></a>补丁&&Patch


- [**727**星][1y] [Py] [keystone-engine/keypatch](https://github.com/keystone-engine/keypatch) 汇编/补丁插件, 支持多架构, 基于Keystone引擎
- [**525**星][2y] [C] [lunixbochs/patchkit](https://github.com/lunixbochs/patchkit) 给ELF文件打补丁(命令行+IDA插件)(可编写Python回调,C函数替换等)
    - 重复区段: [IDA->插件->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
    - [IDA插件](https://github.com/lunixbochs/patchkit/tree/master/ida) 
    - [patchkit](https://github.com/lunixbochs/patchkit/tree/master/core) 
- [**89**星][5y] [Py] [iphelix/ida-patcher](https://github.com/iphelix/ida-patcher) 二进制文件和内存补丁
- [**42**星][3y] [C++] [mrexodia/idapatch](https://github.com/mrexodia/idapatch) IDA plugin to patch IDA Pro in memory.
- [**31**星][4m] [Py] [scottmudge/debugautopatch](https://github.com/scottmudge/debugautopatch) Patching system improvement plugin for IDA.
- [**16**星][8y] [C++] [jkoppel/reprogram](https://github.com/jkoppel/reprogram) Patch binaries at load-time
- [**0**星][8m] [Py] [tkmru/genpatch](https://github.com/tkmru/genpatch) 生成用于打补丁的Python脚本


### <a id="7dfd8abad50c14cd6bdc8d8b79b6f595"></a>其他


- [**123**星][2y] [Shell] [feicong/ida_for_mac_green](https://github.com/feicong/ida_for_mac_green) IDAPro 绿化增强版 （macOS）
- [**34**星][5m] [angelkitty/ida7.0](https://github.com/angelkitty/ida7.0) 
- [**16**星][2y] [jas502n/ida7.0-pro](https://github.com/jas502n/ida7.0-pro) IDA7.0 下载


### <a id="90bf5d31a3897400ac07e15545d4be02"></a>函数相关


#### <a id="347a2158bdd92b00cd3d4ba9a0be00ae"></a>未分类


- [**125**星][8m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) 将IDA Pro和Radare2识别的符号（目前仅函数）导出到ELF符号表
    - 重复区段: [IDA->插件->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->插件->导入导出->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[Radare2->插件->与其他工具交互->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**11**星][2y] [C++] [fireundubh/ida7-functionstringassociate](https://github.com/fireundubh/ida7-functionstringassociate) FunctionStringAssociate plugin by sirmabus, ported to IDA 7
- [**3**星][2y] [Py] [andreafioraldi/idaretaddr](https://github.com/andreafioraldi/idaretaddr) 在IDA调试器中高亮函数的返回地址
    - 重复区段: [IDA->插件->效率->显示增强](#03fac5b3abdbd56974894a261ce4e25f) |
- [**2**星][5m] [Py] [farzonl/idapropluginlab3](https://github.com/farzonl/idapropluginlab3) 通过静态分析使用的函数，描述恶意代码的行为


#### <a id="73813456eeb8212fd45e0ea347bec349"></a>重命名&&前缀&&标记


- [**291**星][2m] [Py] [a1ext/auto_re](https://github.com/a1ext/auto_re) 自动化函数重命名
- [**119**星][5y] [C++] [zyantific/retypedef](https://github.com/zyantific/retypedef) 函数名称替换，可以自定义规则
- [**95**星][2y] [Py] [gaasedelen/prefix](https://github.com/gaasedelen/prefix) IDA 插件，为函数添加前缀
- [**48**星][3y] [Py] [alessandrogario/ida-function-tagger](https://github.com/alessandrogario/ida-function-tagger) 根据函数使用的导入表，对函数进行标记
- [**23**星][12m] [Py] [howmp/comfinder](https://github.com/howmp/comfinder) 查找标记COM组件中的函数
    - 重复区段: [IDA->插件->针对特定分析目标->未分类](#5578c56ca09a5804433524047840980e) |
- [**3**星][4y] [Py] [ayuto/discover_win](https://github.com/ayuto/discover_win) 对比Linux和Windows二进制文件，对Windows文件未命名的函数进行自动重命名
    - 重复区段: [IDA->插件->签名(FLIRT等)->未分类](#cf04b98ea9da0056c055e2050da980c1) |


#### <a id="e4616c414c24b58626f834e1be079ebc"></a>导航&&查看&&查找


- [**180**星][6m] [Py] [hasherezade/ida_ifl](https://github.com/hasherezade/ida_ifl) 交互式函数列表
- [**150**星][7d] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) 模糊搜索: 命令/函数/结构体
    - 重复区段: [IDA->插件->效率->搜索](#8f9468e9ab26128567f4be87ead108d7) |
- [**99**星][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) 递归查找函数和字符串
    - 重复区段: [IDA->插件->字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**81**星][7d] [Py] [ax330d/functions-plus](https://github.com/ax330d/functions-plus) 解析函数名称，按命名空间分组，将分组结果以树的形式展示
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**34**星][3y] [Py] [darx0r/reef](https://github.com/darx0r/reef) 显示"由指定函数发起的"交叉应用。可以理解为函数内部引用的其他函数


#### <a id="cadae88b91a57345d266c68383eb05c5"></a>demangle


- [**17**星][4y] [Py] [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle) 对Swift函数名进行demangle
    - 重复区段: [IDA->插件->Apple->Swift](#1c698e298f6112a86c12881fbd8173c7) |
- [**14**星][1y] [Py] [ax330d/exports-plus](https://github.com/ax330d/exports-plus) 修复IDA不显示全部导出项以及不对导出项名称进行demangle的问题




### <a id="34ac84853604a7741c61670f2a075d20"></a>污点分析&&符号执行


- [**931**星][16d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) 二进制代码静态分析工具。值分析（寄存器、内存）、污点分析、类型重建和传播（propagation）、前向/后向分析
    - 重复区段: [IDA->插件->结构体->未分类](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**868**星][2y] [C++] [illera88/ponce](https://github.com/illera88/ponce) 简化污点分析+符号执行
- [**23**星][4m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
    - 重复区段: [IDA->插件->反混淆](#7199e8787c0de5b428f50263f965fda7) |


### <a id="9dcc6c7dd980bec1f92d0cc9a2209a24"></a>字符串


- [**1365**星][3m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) 自动从恶意代码中提取反混淆后的字符串
    - 重复区段: [IDA->插件->反混淆](#7199e8787c0de5b428f50263f965fda7) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**372**星][2m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) 若干快速访问功能, 扫描字符串格式化漏洞
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |[IDA->插件->漏洞->未分类](#385d6777d0747e79cccab0a19fa90e7e) |
        <details>
        <summary>查看详情</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**181**星][2m] [Py] [joxeankoret/idamagicstrings](https://github.com/joxeankoret/idamagicstrings) 从字符串常量中提取信息
- [**130**星][2y] [Py] [comsecuris/ida_strcluster](https://github.com/comsecuris/ida_strcluster) 扩展IDA的字符串导航功能
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**99**星][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) 递归查找函数和字符串
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |[IDA->插件->函数相关->导航](#e4616c414c24b58626f834e1be079ebc) |
- [**45**星][5y] [Py] [kyrus/ida-translator](https://github.com/kyrus/ida-translator) 将IDB数据库中的任意字符集转换为Unicode，然后自动调用基于网页的翻译服务（当前只有谷歌翻译）将非英文语言翻译为英文
- [**4**星][3y] [C#] [andreafioraldi/idagrabstrings](https://github.com/andreafioraldi/idagrabstrings) 在指定地址区间内搜索字符串，并将其映射为C结构体
    - 重复区段: [IDA->插件->结构体->未分类](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**4**星][8m] [C] [lacike/gandcrab_string_decryptor](https://github.com/lacike/gandcrab_string_decryptor) 解密 GandCrab v5.1-5.3 中的字符串
    - 重复区段: [IDA->插件->针对特定分析目标->特定样本家族](#841d605300beba45c3be131988514a03) |


### <a id="06d2caabef97cf663bd29af2b1fe270c"></a>加密解密


- [**449**星][2m] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) 使用Yara规则查找加密常量
    - 重复区段: [IDA->插件->签名(FLIRT等)->Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |
- [**136**星][17d] [Py] [you0708/ida](https://github.com/you0708/ida) 查找加密常量
    - [IDA主题](https://github.com/you0708/ida/tree/master/theme) 
    - [findcrypt](https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt) IDA FindCrypt/FindCrypt2 插件的Python版本
- [**42**星][7y] [C++] [vlad902/findcrypt2-with-mmx](https://github.com/vlad902/findcrypt2-with-mmx) 对findcrypt2插件的增强，支持MMX AES指令




***


## <a id="18c6a45392d6b383ea24b363d2f3e76b"></a>文章


### <a id="37634a992983db427ce41b37dd9a98c2"></a>新添加的


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


### <a id="4187e477ebc45d1721f045da62dbf4e8"></a>未分类


- 2018.05 [tradahacking] [使用IDA和辅助工具比较二进制文件](https://medium.com/p/651e62117695)
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
- 2017.05 [repret] [静态分析提高 Fuzzing 的代码覆盖率：使用 IDA 脚本枚举所有 CMP 指令及与CMP 相关的 JUMP 指令，生成反转 CMP 条件的字典，Fuzzing 时由 KFUZZ 注入。](https://repret.wordpress.com/2017/05/01/improving-coverage-guided-fuzzing-using-static-analysis/)
- 2017.04 [osandamalith] [使Windows Loader直接执行ShellCode，IDA载入文件时崩溃，而且绕过大多数杀软。](https://osandamalith.com/2017/04/11/executing-shellcode-directly/)
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
- 2013.06 [trustwave] [使用IDA调试Android库](https://www.trustwave.com/Resources/SpiderLabs-Blog/Debugging-Android-Libraries-using-IDA/)
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
- 2015.07 [djmanilaice] [在PyCharm中编写IDAPython脚本时自动提示](http://djmanilaice.blogspot.com/2015/07/pycharm-for-your-ida-development.html)
- 2015.07 [djmanilaice] [使用IDA自动打开当前目录下的DLL和EXE](http://djmanilaice.blogspot.com/2015/07/auto-open-dlls-and-exe-in-current.html)


### <a id="04cba8dbb72e95d9c721fe16a3b48783"></a>系列文章-Labeless插件介绍


- 2018.10 [checkpoint] [Labeless Part 6: How to Resolve Obfuscated API Calls in the Ngioweb Proxy Malware - Check Point Research](https://research.checkpoint.com/labeless-part-6-how-to-resolve-obfuscated-api-calls-in-the-ngioweb-proxy-malware/)
- 2018.10 [checkpoint] [Labeless Part 5: How to Decrypt Strings in Boleto Banking Malware Without Reconstructing Decryption Algorithm. - Check Point Research](https://research.checkpoint.com/labeless-part-5-how-to-decrypt-strings-in-boleto-banking-malware-without-reconstructing-decryption-algorithm/)
- 2018.10 [checkpoint] [Labeless Part 4: Scripting - Check Point Research](https://research.checkpoint.com/labeless-part-4-scripting/)
- 2018.08 [checkpoint] [Labeless Part 3: How to Dump and Auto-Resolve WinAPI Calls in LockPos Point-of-Sale Malware - Check Point Research](https://research.checkpoint.com/19558-2/)
- 2018.08 [checkpoint] [Labeless Part 2: Installation - Check Point Research](https://research.checkpoint.com/installing-labeless/)
- 2018.08 [checkpoint] [Labeless Part 1: An Introduction - Check Point Research](https://research.checkpoint.com/labeless-an-introduction/)


### <a id="1a2e56040cfc42c11c5b4fa86978cc19"></a>系列文章-使用IDA从零开始学逆向


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


### <a id="e838a1ecdcf3d068547dd0d7b5c446c6"></a>系列文章-IDAPython-让你的生活更美好


#### <a id="7163f7c92c9443e17f3f76cc16c2d796"></a>原文


- 2016.06 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part6](https://unit42.paloaltonetworks.com/unit42-using-idapython-to-make-your-life-easier-part-6/)
- 2016.01 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part5](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-5/)
- 2016.01 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part4](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-4/)
- 2016.01 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part3](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-3/)
- 2015.12 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part2](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-2/)
- 2015.12 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part1](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-1/)


#### <a id="fc62c644a450f3e977af313edd5ab124"></a>译文


- 2016.01 [freebuf] [IDAPython：让你的生活更美好（五）](http://www.freebuf.com/articles/system/93440.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（四）](http://www.freebuf.com/articles/system/92505.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（三）](http://www.freebuf.com/articles/system/92488.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（二）](http://www.freebuf.com/sectool/92168.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（一）](http://www.freebuf.com/sectool/92107.html)




### <a id="8433dd5df40aaf302b179b1fda1d2863"></a>系列文章-使用IDA逆向C代码


- 2019.01 [ly0n] [Reversing C code with IDA part V](https://paumunoz.tech/2019/01/12/reversing-c-code-with-ida-part-v/)
- 2019.01 [ly0n] [Reversing C code with IDA part IV](https://paumunoz.tech/2019/01/07/reversing-c-code-with-ida-part-iv/)
- 2019.01 [ly0n] [Reversing C code with IDA part III](https://paumunoz.tech/2019/01/02/reversing-c-code-with-ida-part-iii/)
- 2018.12 [ly0n] [Reversing C code with IDA part II](https://paumunoz.tech/2018/12/31/reversing-c-code-with-ida-part-ii/)
- 2018.01 [ly0n] [Reversing C code with IDA part I](https://paumunoz.tech/2018/01/11/reversing-c-code-with-ida-part-i/)


### <a id="3d3bc775abd7f254ff9ff90d669017c9"></a>工具&&插件&&脚本介绍


#### <a id="cd66794473ea90aa6241af01718c3a7d"></a>未分类


- 2019.10 [vmray] [VMRay IDA Plugin v1.1: Streamlining Deep-Dive Malware Analysis](https://www.vmray.com/cyber-security-blog/vmray-ida-plugin-v1-1-streamlining-deep-dive-malware-analysis/)
- 2019.10 [talosintelligence] [New IDA Pro plugin provides TileGX support](https://blog.talosintelligence.com/2019/10/new-ida-pro-plugin-provides-tilegx.html)
- 2019.09 [talosintelligence] [GhIDA: Ghidra decompiler for IDA Pro](https://blog.talosintelligence.com/2019/09/ghida.html)
- 2019.05 [carbonblack] [fn_fuzzy: Fast Multiple Binary Diffing Triage with IDA](https://www.carbonblack.com/2019/05/09/fn_fuzzy-fast-multiple-binary-diffing-triage-with-ida/)
- 2019.04 [] [climacros – IDA productivity tool](http://0xeb.net/2019/04/climacros-ida-productivity-tool/)
- 2019.04 [] [QScripts – IDA Scripting productivity tool](http://0xeb.net/2019/04/ida-qscripts/)
- 2019.03 [] [Daenerys: IDA Pro and Ghidra interoperability framework](http://0xeb.net/2019/03/daenerys-ida-pro-and-ghidra-interoperability-framework/)
- 2019.03 [freebuf] [Ponce：一键即可实现符号执行（IDA插件）](https://www.freebuf.com/sectool/197708.html)
- 2019.02 [kitploit] [HexRaysCodeXplorer - Hex-Rays Decompiler Plugin For Better Code Navigation](https://www.kitploit.com/2019/02/hexrayscodexplorer-hex-rays-decompiler.html)
- 2019.02 [kitploit] [Ponce - IDA Plugin For Symbolic Execution Just One-Click Away!](https://www.kitploit.com/2019/02/ponce-ida-plugin-for-symbolic-execution.html)
- 2019.01 [talosintelligence] [Dynamic Data Resolver (DDR) - IDA Plugin](https://blog.talosintelligence.com/2019/01/ddr.html)
- 2018.12 [securityonline] [HexRaysCodeXplorer: Hex-Rays Decompiler plugin for better code navigation](https://securityonline.info/codexplorer/)
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
- 2018.06 [dougallj] [编写IDA反编译插件之: 处理VMX指令](https://dougallj.wordpress.com/2018/06/04/writing-a-hex-rays-plugin-vmx-intrinsics/)
- 2018.05 [hexblog] [IDAPython: wrappers are only wrappers](http://www.hexblog.com/?p=1219)
- 2018.05 [freebuf] [HeapViewer：一款专注于漏洞利用开发的IDA Pro插件](http://www.freebuf.com/sectool/171632.html)
- 2018.03 [pediy] [[翻译]使用 IDAPython 写一个简单的x86模拟器](https://bbs.pediy.com/thread-225091.htm)
- 2018.03 [] [Using Z3 with IDA to simplify arithmetic operations in functions](http://0xeb.net/2018/03/using-z3-with-ida-to-simplify-arithmetic-operations-in-functions/)
- 2018.02 [securityonline] [IDAPython Embedded Toolkit: IDAPython scripts for automating analysis of firmware of embedded devices](https://securityonline.info/idapython-embedded-toolkit-idapython-scripts-for-automating-analysis-of-firmware-of-embedded-devices/)
- 2018.02 [] [Writing a simple x86 emulator with IDAPython](http://0xeb.net/2018/02/writing-a-simple-x86-emulator-with-idapython/)
- 2018.01 [fireeye] [FLARE IDA Pro Script Series: Simplifying Graphs in IDA](https://www.fireeye.com/blog/threat-research/2018/01/simplifying-graphs-in-ida.html)
- 2017.12 [ret2] [What's New in Lighthouse v0.7](http://blog.ret2.io/2017/12/07/lighthouse-v0.7/)
- 2017.12 [OALabs] [Using Yara Rules With IDA Pro - New Tool!](https://www.youtube.com/watch?v=zAKi9KWYyfM)
- 2017.11 [hasherezade] [IFL - Interactive Functions List - a plugin for IDA Pro](https://www.youtube.com/watch?v=L6sROW_MivE)
- 2017.11 [securityonline] [IDA EA: A set of exploitation/reversing aids for IDA](https://securityonline.info/ida-ea-exploitation-reversing-ida/)
- 2017.06 [reverse] [EFISwissKnife 介绍](https://reverse.put.as/2017/06/13/efi-swiss-knife-an-ida-plugin-to-improve-uefi-reversing/)
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


#### <a id="c7483f3b20296ac68084a8c866230e15"></a>与其他工具交互


- 2018.09 [dustri] [IDAPython vs. r2pipe](https://dustri.org/b/idapython-vs-r2pipe.html)




### <a id="ea11818602eb33e8b165eb18d3710965"></a>翻译-TheIDAProBook


- 2008.10 [pediy] [[翻译]The IDA Pro Book 第六章](https://bbs.pediy.com/thread-75632.htm)
- 2008.10 [pediy] [[翻译]（20081030更新）The IDA Pro Book 第12章：使用FLIRT签名识别库](https://bbs.pediy.com/thread-75422.htm)
- 2008.10 [pediy] [[翻译]The IDA Pro Book(第二章)](https://bbs.pediy.com/thread-74943.htm)
- 2008.10 [pediy] [[翻译]The IDA Pro book 第5章---IDA DATA DISPLAY](https://bbs.pediy.com/thread-74838.htm)
- 2008.10 [pediy] [[翻译]The IDA Pro Book(第一章)](https://bbs.pediy.com/thread-74564.htm)


### <a id="ec5f7b9ed06500c537aa25851a3f2d3a"></a>翻译-ReverseEngineeringCodeWithIDAPro


- 2009.01 [pediy] [[原创]Reverse Engineering Code with IDA Pro第七章中文译稿](https://bbs.pediy.com/thread-80580.htm)
- 2008.06 [pediy] [[翻译]Reverse Engineering Code with IDA Pro(第一、二章)](https://bbs.pediy.com/thread-66010.htm)


### <a id="2120fe5420607a363ae87f5d2fed459f"></a>IDA本身


- 2019.01 [pediy] [[原创]IDA7.2安装包分析](https://bbs.pediy.com/thread-248989.htm)
- 2019.01 [pediy] [[原创]IDA 在解析 IA64 中的 brl 指令时存在一个 Bug](https://bbs.pediy.com/thread-248983.htm)
- 2018.11 [hexblog] [IDA 7.2 – The Mac Rundown](http://www.hexblog.com/?p=1300)
- 2018.10 [pediy] [[原创] 修复 IDA Pro 7.0在macOS Mojave崩溃的问题](https://bbs.pediy.com/thread-247334.htm)


### <a id="d8e48eb05d72db3ac1e050d8ebc546e1"></a>逆向实战


#### <a id="374c6336120363a5c9d9a27d7d669bf3"></a>未分类


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


#### <a id="0b3e1936ad7c4ccc10642e994c653159"></a>恶意代码分析


- 2019.04 [360] [两种姿势批量解密恶意驱动中的上百条字串](https://www.anquanke.com/post/id/175964/)
- 2019.03 [cyber] [使用IDAPython分析Trickbot](https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/)
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
- 2012.06 [trustwave] [使用IDAPython对Flame的字符串进行反混淆](https://www.trustwave.com/Resources/SpiderLabs-Blog/Defeating-Flame-String-Obfuscation-with-IDAPython/)


#### <a id="03465020d4140590326ae12c9601ecfd"></a>漏洞分析&&挖掘


- 2018.07 [360] [如何使用 IDAPython 寻找漏洞](https://www.anquanke.com/post/id/151898/)
- 2018.07 [somersetrecon] [如何使用IDAPython挖掘漏洞](http://www.somersetrecon.com/blog/2018/7/6/introduction-to-idapython-for-vulnerability-hunting)




### <a id="e9ce398c2c43170e69c95fe9ad8d22fc"></a>Microcode


- 2019.10 [amossys] [探秘Hex-Rays microcode](https://blog.amossys.fr/stage-2019-hexraysmicrocode.html)


### <a id="9c0ec56f402a2b9938417f6ecbaeaa72"></a>IDA对抗


- 2019.05 [aliyun] [混淆IDA F5的一个小技巧-x86](https://xz.aliyun.com/t/5062)




# <a id="319821036a3319d3ade5805f384d3165"></a>Ghidra


***


## <a id="fa45b20f6f043af1549b92f7c46c9719"></a>插件&&脚本


### <a id="2ae406afda6602c8f02d73678b2ff040"></a>Ghidra


- [**18649**星][2d] [Java] [nationalsecurityagency/ghidra](https://github.com/nationalsecurityagency/ghidra) 软件逆向框架
- [**59**星][9m] [nationalsecurityagency/ghidra-data](https://github.com/nationalsecurityagency/ghidra-data) Ghidra源代码存储库的配套存储库，作为放置可改善Ghidra的数据集的地方
- [**49**星][1m] [Shell] [bkerler/ghidra_installer](https://github.com/bkerler/ghidra_installer) 为Ghidra在Ubuntu 18.04 / 18.10上设置OpenJDK 11，以及针对4K的扩展
- [**27**星][3m] [Dockerfile] [dukebarman/ghidra-builder](https://github.com/dukebarman/ghidra-builder) Docker映像，用于从源代码构建Ghidra 逆向框架


### <a id="ce70b8d45be0a3d29705763564623aca"></a>新添加的


- [**455**星][8m] [YARA] [ghidraninja/ghidra_scripts](https://github.com/ghidraninja/ghidra_scripts) Ghidra脚本
    - [binwalk](https://github.com/ghidraninja/ghidra_scripts/blob/master/binwalk.py) 对当前程序运行BinWalk, 标注找到的内容
    - [yara](https://github.com/ghidraninja/ghidra_scripts/blob/master/yara.py) 使用Yara查找加密常量
    - [swift_demangler](https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py) 自动demangle Swift函数名
    - [golang_renamer](https://github.com/ghidraninja/ghidra_scripts/blob/master/golang_renamer.py) 恢复stripped Go二进制文件的函数名
- [**204**星][7m] [Java] [rolfrolles/ghidrapal](https://github.com/rolfrolles/ghidrapal) Ghidra 程序分析库(无文档)
- [**53**星][9m] [aldelaro5/ghidra-gekko-broadway-lang](https://github.com/aldelaro5/ghidra-gekko-broadway-lang) 在Nintendo GameCube和Nintendo Wii中分别使用的Gekko和Broadway CPU变体的Ghidra语言定义
- [**51**星][2m] [Makefile] [blacktop/docker-ghidra](https://github.com/blacktop/docker-ghidra) Ghidra 客户端/服务器的Docker镜像
- [**36**星][1m] [Java] [ayrx/jnianalyzer](https://github.com/ayrx/jnianalyzer) 可与Android NDK库一起使用的Ghidra脚本：解析FindNativeJNIMethods的输出，并将函数签名应用于二进制文件中的所有匹配函数。
- [**34**星][2m] [Py] [pagalaxylab/ghidra_scripts](https://github.com/pagalaxylab/ghidra_scripts) Ghidra脚本
    - [AnalyzeOCMsgSend](https://github.com/pagalaxylab/ghidra_scripts/blob/master/AnalyzeOCMsgSend.py) 
    - [trace_function_call_parm_value](https://github.com/pagalaxylab/ghidra_scripts/blob/master/trace_function_call_parm_value.py) 
- [**19**星][9m] [Java] [kant2002/ghidra](https://github.com/kant2002/ghidra) As it is obvious from the name this is version of NSA Ghidra which actually could be built from sources
- [**18**星][2m] [Java] [threatrack/ghidra-patchdiff-correlator](https://github.com/threatrack/ghidra-patchdiff-correlator) This project tries to provide additional Ghidra Version Tracking Correlators suitable for patch diffing.
- [**16**星][5m] [hedgeberg/rl78_sleigh](https://github.com/hedgeberg/rl78_sleigh) An implementation of the RL78 ISA for Ghidra SRE
- [**12**星][3m] [Java] [threatrack/ghidra-fid-generator](https://github.com/threatrack/ghidra-fid-generator) Code for generating Ghidra FidDb files (currently only for static libraries available in the CentOS repositories)
- [**5**星][8m] [Py] [0xd0cf11e/ghidra](https://github.com/0xd0cf11e/ghidra) Anything related to Ghidra


### <a id="69dc4207618a2977fe8cd919e7903fa5"></a>特定分析目标


#### <a id="da5d2b05da13f8e65aa26d6a1c95a8d0"></a>未分类


- [**123**星][3d] [Java] [al3xtjames/ghidra-firmware-utils](https://github.com/al3xtjames/ghidra-firmware-utils) 辅助PC固件逆向的各种模块
- [**108**星][29d] [Java] [astrelsky/ghidra-cpp-class-analyzer](https://github.com/astrelsky/ghidra-cpp-class-analyzer) C++类和运行时类型信息（RTTI）分析器
- [**94**星][6m] [Java] [felberj/gotools](https://github.com/felberj/gotools) 辅助Golang二进制逆向
- [**42**星][2m] [Py] [kc0bfv/pcode-emulator](https://github.com/kc0bfv/pcode-emulator) Ghidra的PCode模拟器


#### <a id="058bb9893323f337ad1773725d61f689"></a>Loader&&Processor


- [**90**星][3m] [Java] [adubbz/ghidra-switch-loader](https://github.com/adubbz/ghidra-switch-loader) Nintendo Switch loader for Ghidra
- [**79**星][2m] [Py] [leveldown-security/svd-loader-ghidra](https://github.com/leveldown-security/svd-loader-ghidra) 
- [**65**星][16d] [Java] [beardypig/ghidra-emotionengine](https://github.com/beardypig/ghidra-emotionengine) Ghidra Processor for the Play Station 2's Emotion Engine MIPS based CPU
- [**56**星][5m] [Assembly] [xyzz/ghidra-mep](https://github.com/xyzz/ghidra-mep) Toshiba MeP processor module for GHIDRA
- [**54**星][29d] [Java] [cuyler36/ghidra-gamecube-loader](https://github.com/cuyler36/ghidra-gamecube-loader) A Nintendo GameCube binary loader for Ghidra
- [**53**星][9m] [Java] [jogolden/ghidraps4loader](https://github.com/jogolden/ghidraps4loader) A Ghidra loader for PlayStation 4 binaries.
- [**44**星][3m] [Java] [nalen98/ebpf-for-ghidra](https://github.com/nalen98/ebpf-for-ghidra) eBPF Processor for Ghidra
- [**34**星][6m] [Java] [idl3r/ghidravmlinuxloader](https://github.com/idl3r/ghidravmlinuxloader) 
- [**32**星][t] [Java] [zerokilo/n64loaderwv](https://github.com/zerokilo/n64loaderwv) Ghidra Loader Module for N64 ROMs
- [**30**星][5m] [cturt/gameboy_ghidrasleigh](https://github.com/cturt/gameboy_ghidrasleigh) Ghidra Processor support for Nintendo Game Boy
- [**28**星][t] [Java] [zerokilo/xexloaderwv](https://github.com/zerokilo/xexloaderwv) Ghidra Loader Module for X360 XEX Files
- [**27**星][2m] [vgkintsugi/ghidra-segasaturn-processor](https://github.com/vgkintsugi/ghidra-segasaturn-processor) A Ghidra processor module for the Sega Saturn (SuperH SH-2)
- [**25**星][9m] [Assembly] [thog/ghidra_falcon](https://github.com/thog/ghidra_falcon) Support of Nvidia Falcon processors for Ghidra (WIP)
- [**19**星][7m] [guedou/ghidra-processor-mep](https://github.com/guedou/ghidra-processor-mep) Toshiba MeP-c4 for Ghidra
- [**15**星][2m] [Java] [neatmonster/mclf-ghidra-loader](https://github.com/neatmonster/mclf-ghidra-loader) Ghidra loader module for the Mobicore trustlet and driver binaries
- [**7**星][4m] [Java] [ballon-rouge/rx-proc-ghidra](https://github.com/ballon-rouge/rx-proc-ghidra) Renesas RX processor module for Ghidra
- [**5**星][5m] [CSS] [lcq2/griscv](https://github.com/lcq2/griscv) RISC-V processor plugin for Ghidra
- [**5**星][t] [Java] [zerokilo/c64loaderwv](https://github.com/zerokilo/c64loaderwv) Ghidra Loader Module for C64 programs


#### <a id="51a2c42c6d339be24badf52acb995455"></a>Xbox


- [**24**星][9m] [Java] [jonas-schievink/ghidraxbe](https://github.com/jonas-schievink/ghidraxbe) A Ghidra extension for loading Xbox Executables (.xbe files)
- [**18**星][10m] [Java] [jayfoxrox/ghidra-xbox-extensions](https://github.com/jayfoxrox/ghidra-xbox-extensions) Tools to analyze original Xbox files in the Ghidra SRE framework




### <a id="99e3b02da53f1dbe59e0e277ef894687"></a>与其他工具交互


#### <a id="5923db547e1f04f708272543021701d2"></a>未分类




#### <a id="e1cc732d1388084530b066c26e24887b"></a>Radare2


- [**175**星][6d] [C++] [radareorg/r2ghidra-dec](https://github.com/radareorg/r2ghidra-dec) Ghidra反编译器与Radare2深度集成
    - 重复区段: [Radare2->插件->与其他工具交互->IDA](#1cfe869820ecc97204a350a3361b31a7) |
- [**36**星][5m] [Java] [radare/ghidra-r2web](https://github.com/radare/ghidra-r2web) Ghidra插件，启动r2 web服务器, 使r2可与其交互


#### <a id="d832a81018c188bf585fcefa3ae23062"></a>IDA


- [**299**星][4m] [Py] [cisco-talos/ghida](https://github.com/cisco-talos/ghida) 在IDA中集成Ghidra反编译器
    - 重复区段: [IDA->插件->导入导出->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |
- [**238**星][9m] [Py] [daenerys-sre/source](https://github.com/daenerys-sre/source) 使IDA和Ghidra脚本通用, 无需修改
    - 重复区段: [IDA->插件->导入导出->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |
- [**88**星][4m] [Py] [cisco-talos/ghidraaas](https://github.com/cisco-talos/ghidraaas) 通过REST API暴露Ghidra分析服务, 也是GhIDA的后端
    - 重复区段: [IDA->插件->导入导出->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |
- [**54**星][8m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - 重复区段: [IDA->插件->导入导出->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[IDA->插件->签名(FLIRT等)->FLIRT签名->FLIRT签名生成](#a9a63d23d32c6c789ca4d2e146c9b6d0) |
- [**47**星][2m] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
    - 重复区段: [IDA->插件->导入导出->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[x64dbg->插件->新添加的](#da5688c7823802e734c39b539aa39df7) |


#### <a id="60e86981b2c98f727587e7de927e0519"></a>DBI


- [**102**星][3m] [Java] [0ffffffffh/dragondance](https://github.com/0ffffffffh/dragondance) 在Ghidra中进行代码覆盖情况的可视化
    - 重复区段: [DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |
    - [Ghidra插件](https://github.com/0ffffffffh/dragondance/blob/master/README.md) 
    - [coverage-pin](https://github.com/0ffffffffh/dragondance/blob/master/coveragetools/README.md) 使用Pin收集信息


#### <a id="e81053b03a859e8ac72f7fe79e80341a"></a>调试器


- [**42**星][2m] [Java] [revolver-ocelot-saa/ghidrax64dbg](https://github.com/revolver-ocelot-saa/ghidrax64dbg) 从Ghidra中提取注释，导入到X32/X64 dbg数据库
    - 重复区段: [x64dbg->插件->新添加的](#da5688c7823802e734c39b539aa39df7) |




### <a id="cccbd06c6b9b03152d07a4072152ae27"></a>外观&&主题


- [**78**星][9m] [Py] [elliiot/ghidra_darknight](https://github.com/elliiot/ghidra_darknight) DarkNight theme for Ghidra


### <a id="45910c8ea12447df9cdde2bea425f23f"></a>脚本编写


#### <a id="c12ccb8e11ba94184f8f24767eb64212"></a>其他


- [**40**星][19d] [Py] [vdoo-connected-trust/ghidra-pyi-generator](https://github.com/vdoo-connected-trust/ghidra-pyi-generator) 为整个Ghidra API生成.pyi类型stub，在PyCharm中使用，以增强Ghidra脚本开发体验


#### <a id="b24e162720cffd2d2456488571c1a136"></a>编程语言


- [**19**星][5m] [Java] [edmcman/ghidra-scala-loader](https://github.com/edmcman/ghidra-scala-loader) Ghidra扩展，家在Scala编写的Ghidra脚本






***


## <a id="273df546f1145fbed92bb554a327b87a"></a>文章&&视频


### <a id="8962bde3fbfb1d1130879684bdf3eed0"></a>新添加的1




### <a id="ce49901b4914f3688ef54585c8f9df1a"></a>新添加的


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


### <a id="b7fb955b670df2babc67e5942297444d"></a>Ghidra漏洞


- 2019.10 [securityaffairs] [Ghidra 9.0.4及之前版本的代码执行漏洞](https://securityaffairs.co/wordpress/92280/hacking/ghidra-code-execution-flaw.html)
- 2019.10 [4hou] [CVE-2019-16941: NSA Ghidra工具RCE漏洞](https://www.4hou.com/info/news/20698.html)
- 2019.08 [hackertor] [Ghidra (Linux) 9.0.4 Arbitrary Code Execution](https://hackertor.com/2019/08/12/ghidra-linux-9-0-4-arbitrary-code-execution/)
- 2019.08 [kitploit] [Ghidra (Linux) 9.0.4 Arbitrary Code Execution](https://exploit.kitploit.com/2019/08/ghidra-linux-904-arbitrary-code.html)
- 2019.07 [hackertor] [NA – CVE-2019-13623 – In NSA Ghidra through 9.0.4, path traversal can…](https://hackertor.com/2019/07/17/na-cve-2019-13623-in-nsa-ghidra-through-9-0-4-path-traversal-can/)
- 2019.07 [hackertor] [NA – CVE-2019-13625 – NSA Ghidra before 9.0.1 allows XXE when a…](https://hackertor.com/2019/07/17/na-cve-2019-13625-nsa-ghidra-before-9-0-1-allows-xxe-when-a/)
- 2019.03 [venus] [Ghidra 从 XXE 到 RCE](https://paper.seebug.org/861/)
- 2019.03 [tencent] [Ghidra 从 XXE 到 RCE](https://xlab.tencent.com/cn/2019/03/18/ghidra-from-xxe-to-rce/)


### <a id="dd0d49a5e6bd34b372d9bbf4475e8024"></a>实战分析


#### <a id="f0ab053d7a282ab520c3a327fc91ba2e"></a>未分类


- 2019.09 [venus] [使用 Ghidra 对 iOS 应用进行 msgSend 分析](https://paper.seebug.org/1037/)
- 2019.09 [4hou] [使用Ghidra对iOS应用进行msgSend分析](https://www.4hou.com/system/20326.html)
- 2019.09 [WarrantyVoider] [X360 XEX Decompiling With Ghidra](https://www.youtube.com/watch?v=coGz0f7hHTM)
- 2019.08 [WarrantyVoider] [N64 ROM Decompiling With Ghidra - N64LoaderWV](https://www.youtube.com/watch?v=3d3a39LuCwc)
- 2019.08 [4hou] [基于Ghidra和Neo4j的RPC分析技术](https://www.4hou.com/technology/19730.html)
- 2019.04 [X0x6d696368] [Ghidra: Search Program Text... (to find XOR decoding functions in malware)](https://www.youtube.com/watch?v=MaxwIxrmrWY)
- 2019.04 [shogunlab] [Here Be Dragons: Reverse Engineering with Ghidra - Part 0 [Main Windows & CrackMe]](https://www.shogunlab.com/blog/2019/04/12/here-be-dragons-ghidra-0.html)
- 2019.03 [GhidraNinja] [Reverse engineering with #Ghidra: Breaking an embedded firmware encryption scheme](https://www.youtube.com/watch?v=4urMITJKQQs)
- 2019.03 [GhidraNinja] [Ghidra quickstart & tutorial: Solving a simple crackme](https://www.youtube.com/watch?v=fTGTnrgjuGA)


#### <a id="375c75af4fa078633150415eec7c867d"></a>漏洞分析&&挖掘


- 2019.11 [4hou] [使用Ghidra对WhatsApp VOIP Stack 溢出漏洞的补丁对比分析](https://www.4hou.com/vulnerable/21141.html)
- 2019.09 [4hou] [利用Ghidra分析TP-link M7350 4G随身WiFi的RCE漏洞](https://www.4hou.com/vulnerable/20267.html)
- 2019.08 [aliyun] [CVE-2019-12103  使用Ghidra分析TP-Link M7350上的预认证RCE](https://xz.aliyun.com/t/6017)


#### <a id="4e3f53845efe99da287b2cea1bdda97c"></a>恶意代码


- 2019.06 [dawidgolak] [IcedID aka #Bokbot Analysis with Ghidra.](https://medium.com/p/560e3eccb766)
- 2019.04 [aliyun] [利用Ghidra分析恶意软件Emotet](https://xz.aliyun.com/t/4931)
- 2019.04 [X0x6d696368] [Ghidra: Shadow Hammer (Stage 1: Setup.exe) complete static Analysis](https://www.youtube.com/watch?v=gI0nZR4z7_M)
- 2019.04 [X0xd0cf11e] [Analyzing Emotet with Ghidra — Part 2](https://medium.com/p/9efbea374b14)
- 2019.04 [X0x6d696368] [Ghidra: Android APK (it's basically dex2jar with a .dex decompiler)](https://www.youtube.com/watch?v=At_T6riSb9A)
- 2019.04 [X0xd0cf11e] [Analyzing Emotet with Ghidra — Part 1](https://medium.com/p/4da71a5c8d69)
- 2019.03 [GhidraNinja] [Reversing WannaCry Part 1 - Finding the killswitch and unpacking the malware in #Ghidra](https://www.youtube.com/watch?v=Sv8yu12y5zM)
- 2019.03 [HackerSploit] [Malware Analysis With Ghidra - Stuxnet Analysis](https://www.youtube.com/watch?v=TJhfnItRVOA)
- 2019.03 [sans] [Analysing meterpreter payload with Ghidra](https://isc.sans.edu/forums/diary/Analysing+meterpreter+payload+with+Ghidra/24722/)




### <a id="92f60c044ed13b3ffde631794edd2756"></a>其他




### <a id="4bfa6dcf708b3f896870c9d3638c0cde"></a>Tips&&Tricks




### <a id="0d086cf7980f65da8f7112b901fecdc1"></a>工具&&插件&&脚本


- 2019.11 [deadc0de] [使用Python编写Ghidra脚本示例](https://deadc0de.re/articles/ghidra-scripting-python.html)
- 2019.04 [X0x6d696368] [ghidra_scripts: RC4Decryptor.py](https://www.youtube.com/watch?v=kXaHrPyZtGs)
- 2019.04 [aliyun] [如何开发用于漏洞研究的Ghidra插件，Part 1](https://xz.aliyun.com/t/4723)
- 2019.04 [somersetrecon] [Ghidra Plugin Development for Vulnerability Research - Part-1](https://www.somersetrecon.com/blog/2019/ghidra-plugin-development-for-vulnerability-research-part-1)
- 2019.03 [wololo] [PS4 release: GhidraPS4Loader and Playstation 4 Flash tool](http://wololo.net/2019/03/18/ps4-release-ghidraps4loader-and-playstation-4-flash-tool/)




# <a id="b1a6c053e88e86ce01bbd78c54c63a7c"></a>x64dbg


***


## <a id="b4a856db286f9f29b5a32d477d6b3f3a"></a>插件&&脚本


### <a id="353ea40f2346191ecb828210a685f9db"></a>x64dbg


- [**34576**星][26d] [C++] [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) Windows平台x32/x64调试器


### <a id="da5688c7823802e734c39b539aa39df7"></a>新添加的


- [**1672**星][7m] [C++] [yegord/snowman](https://github.com/yegord/snowman) Snowman反编译器，支持x86, AMD64, ARM。有独立的GUI工具、命令行工具、IDA/Radare2/x64dbg插件，也可以作为库使用
    - 重复区段: [IDA->插件->反编译器](#d2166f4dac4eab7fadfe0fd06467fbc9) |
    - [IDA插件](https://github.com/yegord/snowman/tree/master/src/ida-plugin) 
    - [snowman](https://github.com/yegord/snowman/tree/master/src/snowman) QT界面
    - [nocode](https://github.com/yegord/snowman/tree/master/src/nocode) 命令行工具
    - [nc](https://github.com/yegord/snowman/tree/master/src/nc) 核心代码，可作为库使用
- [**1341**星][1m] [C] [x64dbg/x64dbgpy](https://github.com/x64dbg/x64dbgpy) Automating x64dbg using Python, Snapshots:
- [**1133**星][2y] [C++] [x64dbg/gleebug](https://github.com/x64dbg/gleebug) Debugging Framework for Windows.
- [**972**星][1m] [Py] [x64dbg/docs](https://github.com/x64dbg/docs) x64dbg文档
- [**471**星][5d] [C] [bootleg/ret-sync](https://github.com/bootleg/ret-sync) 在反汇编工具和调试器之间同步调试会话
    - 重复区段: [IDA->插件->与调试器同步](#f7d311685152ac005cfce5753c006e4b) |
    - [GDB插件](https://github.com/bootleg/ret-sync/tree/master/ext_gdb) 
    - [Ghidra插件](https://github.com/bootleg/ret-sync/tree/master/ext_ghidra) 
    - [IDA插件](https://github.com/bootleg/ret-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/bootleg/ret-sync/tree/master/ext_lldb) 
    - [OD](https://github.com/bootleg/ret-sync/tree/master/ext_olly1) 
    - [OD2](https://github.com/bootleg/ret-sync/tree/master/ext_olly2) 
    - [WinDgb](https://github.com/bootleg/ret-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/bootleg/ret-sync/tree/master/ext_x64dbg) 
- [**363**星][9m] [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) IDA x64DBG OllyDBG 插件收集
    - 重复区段: [IDA->插件->收集](#a7dac37cd93b8bb42c7d6aedccb751b3) |
- [**163**星][2m] [Py] [x64dbg/x64dbgida](https://github.com/x64dbg/x64dbgida) x64dbg插件，用于IDA数据导入导出
    - 重复区段: [IDA->插件->导入导出->未分类](#8ad723b704b044e664970b11ce103c09) |
- [**78**星][4d] [C] [horsicq/nfdx64dbg](https://github.com/horsicq/nfdx64dbg) Plugin for x64dbg Linker/Compiler/Tool detector.
- [**77**星][3m] [C] [ahmadmansoor/advancedscript](https://github.com/ahmadmansoor/advancedscript) Add More Features for x64dbg Script System,with some Functions which will help Plugin Coder
- [**75**星][4y] [C++] [x64dbg/xedparse](https://github.com/x64dbg/xedparse)  A MASM-like, single-line plaintext assembler
- [**72**星][2y] [C] [0ffffffffh/api-break-for-x64dbg](https://github.com/0ffffffffh/api-break-for-x64dbg) x64dbg plugin to set breakpoints automatically to Win32/64 APIs
- [**71**星][2y] [Py] [x64dbg/mona](https://github.com/x64dbg/mona) Fork of mona.py with x64dbg support
- [**70**星][4d] [C] [horsicq/stringsx64dbg](https://github.com/horsicq/stringsx64dbg) Strings plugin for x64dbg
- [**47**星][2m] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
    - 重复区段: [IDA->插件->导入导出->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |[Ghidra->插件->与其他工具交互->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**43**星][7m] [YARA] [x64dbg/yarasigs](https://github.com/x64dbg/yarasigs) Various Yara signatures (possibly to be included in a release later).
- [**42**星][2m] [Java] [revolver-ocelot-saa/ghidrax64dbg](https://github.com/revolver-ocelot-saa/ghidrax64dbg) 从Ghidra中提取注释，导入到X32/X64 dbg数据库
    - 重复区段: [Ghidra->插件->与其他工具交互->调试器](#e81053b03a859e8ac72f7fe79e80341a) |
- [**41**星][4d] [C] [horsicq/pex64dbg](https://github.com/horsicq/pex64dbg) pe 查看
- [**40**星][3y] [C++] [x64dbg/interobfu](https://github.com/x64dbg/interobfu) Intermediate x86 instruction representation for use in obfuscation/deobfuscation.
- [**38**星][3y] [C] [changeofpace/force-page-protection](https://github.com/changeofpace/force-page-protection) This x64dbg plugin sets the page protection for memory mapped views in scenarios which cause NtProtectVirtualMemory to fail.
- [**38**星][3y] [C++] [kurapicabs/x64_tracer](https://github.com/kurapicabs/x64_tracer) x64dbg conditional branches logger [Plugin]
- [**38**星][3y] [CSS] [thundercls/x64dbg_vs_dark](https://github.com/thundercls/x64dbg_vs_dark) x64dbg stylesheet like visual studio dark theme
- [**37**星][3y] [C] [changeofpace/pe-header-dump-utilities](https://github.com/changeofpace/pe-header-dump-utilities) This x64dbg plugin adds several commands for dumping PE header information by address.
- [**29**星][1y] [Assembly] [mrfearless/apiinfo-plugin-x86](https://github.com/mrfearless/apiinfo-plugin-x86) APIInfo Plugin (x86) - A Plugin For x64dbg
- [**29**星][3y] [Py] [x64dbg/x64dbgbinja](https://github.com/x64dbg/x64dbgbinja) Official x64dbg plugin for Binary Ninja
- [**28**星][2y] [C] [x64dbg/plugintemplate](https://github.com/x64dbg/plugintemplate) Plugin template for x64dbg. Releases:
- [**28**星][2y] [C] [x64dbg/slothbp](https://github.com/x64dbg/slothbp) Collaborative Breakpoint Manager for x64dbg.
- [**27**星][2y] [atom0s/ceautoasm-x64dbg](https://github.com/atom0s/ceautoasm-x64dbg) An x64dbg plugin that allows users to execute Cheat Engine auto assembler scripts within x64dbg.
- [**25**星][1y] [Assembly] [mrfearless/apisearch-plugin-x86](https://github.com/mrfearless/apisearch-plugin-x86) APISearch Plugin (x86) - A Plugin For x64dbg
- [**24**星][3y] [C++] [chausner/1337patch](https://github.com/chausner/1337patch) Simple command-line tool to apply patches exported by x64dbg to running processes
- [**20**星][2y] [Py] [techbliss/x64dbg_script_editor](https://github.com/techbliss/x64dbg_script_editor) x64dbg Script editor v2.0
- [**19**星][5y] [C] [x64dbg/staticanalysis](https://github.com/x64dbg/staticanalysis) Static analysis plugin for x64dbg (now deprecated).
- [**17**星][2y] [C#] [thundercls/xhotspots](https://github.com/thundercls/xhotspots) xHotSpots plugin for x64dbg
- [**16**星][11m] [C] [mrfearless/x64dbg-plugin-template-for-visual-studio](https://github.com/mrfearless/x64dbg-plugin-template-for-visual-studio) x64dbg plugin template for visual studio
- [**15**星][4y] [C] [realgam3/x64dbg-python](https://github.com/realgam3/x64dbg-python) Automating x64dbg using Python
- [**13**星][8m] [C] [mrexodia/driver_unpacking](https://github.com/mrexodia/driver_unpacking) Source code for the "Kernel driver unpacking with x64dbg" blog post.
- [**13**星][1y] [Assembly] [mrfearless/x64dbg-plugin-sdk-for-x64-assembler](https://github.com/mrfearless/x64dbg-plugin-sdk-for-x64-assembler) x64dbg Plugin SDK For x64 Assembler
- [**12**星][2y] [C] [blaquee/slothemu](https://github.com/blaquee/slothemu) unicorn emulator for x64dbg
- [**12**星][1y] [Assembly] [mrfearless/apisearch-plugin-x64](https://github.com/mrfearless/apisearch-plugin-x64) APISearch Plugin (x64) - A Plugin For x64dbg
- [**12**星][1y] [Assembly] [mrfearless/copytoasm-plugin-x86](https://github.com/mrfearless/copytoasm-plugin-x86) CopyToAsm (x86) - A Plugin For x64dbg
- [**12**星][2y] [C] [thundercls/magicpoints](https://github.com/thundercls/magicpoints) MagicPoints plugin for x64dbg
- [**12**星][2y] [C] [x64dbg/capstone_wrapper](https://github.com/x64dbg/capstone_wrapper) C++ wrapper for capstone (x86 only)
- [**12**星][1m] [C] [x64dbg/qtplugin](https://github.com/x64dbg/qtplugin) Plugin demonstrating how to link with Qt.
- [**12**星][3y] [C] [x64dbg/testplugin](https://github.com/x64dbg/testplugin) Example plugin for x64dbg.
- [**11**星][1y] [Assembly] [mrfearless/x64dbg-plugin-sdk-for-x86-assembler](https://github.com/mrfearless/x64dbg-plugin-sdk-for-x86-assembler) x64dbg Plugin SDK For x86 Assembler
- [**9**星][3y] [C++] [jdavidberger/chaiscriptplugin](https://github.com/jdavidberger/chaiscriptplugin) Plugin which enables chai scripts to run inside of x64dbg
- [**9**星][1y] [Assembly] [mrfearless/today-plugin-x64](https://github.com/mrfearless/today-plugin-x64) Today Plugin (x64) - A Plugin For x64dbg
- [**4**星][3y] [C] [mrexodia/traceplugin](https://github.com/mrexodia/traceplugin) Very simple trace plugin example for x64dbg.
- [**4**星][1y] [Assembly] [mrfearless/autocmdline-plugin-x86](https://github.com/mrfearless/autocmdline-plugin-x86) AutoCmdLine Plugin (x86) - A Plugin For x64dbg
- [**4**星][1y] [Assembly] [mrfearless/copytoasm-plugin-x64](https://github.com/mrfearless/copytoasm-plugin-x64) CopyToAsm (x64) - A Plugin For x64dbg
- [**4**星][1y] [Assembly] [mrfearless/today-plugin-x86](https://github.com/mrfearless/today-plugin-x86) Today Plugin (x86) - A Plugin For x64dbg
- [**4**星][2y] [thomasthelen/upxunpacker](https://github.com/thomasthelen/upxunpacker) Scripts for x64dbg to find the OEP of exe files packed with UPX
- [**4**星][1y] [CSS] [x64dbg/blog](https://github.com/x64dbg/blog) Blog for x64dbg.
- [**3**星][1y] [Assembly] [mrfearless/autocmdline-plugin-x64](https://github.com/mrfearless/autocmdline-plugin-x64) AutoCmdLine Plugin (x64) - A Plugin For x64dbg
- [**3**星][3y] [stonedreamforest/x64dbg_theme_relaxyoureyes](https://github.com/stonedreamforest/x64dbg_theme_relaxyoureyes) Relax Your Eyes
- [**3**星][2y] [C#] [x64dbg/pluginmanager](https://github.com/x64dbg/pluginmanager) Plugin manager plugin for x64dbg.
- [**2**星][1y] [Assembly] [mrfearless/codeshot-plugin-x86](https://github.com/mrfearless/codeshot-plugin-x86) CodeShot Plugin (x86) - A Plugin For x64dbg
- [**2**星][1y] [Assembly] [mrfearless/stepint3-plugin-x86](https://github.com/mrfearless/stepint3-plugin-x86) StepInt3 Plugin (x86) - A Plugin For x64dbg
- [**2**星][1y] [C] [phidelpark/x64dbgplugins](https://github.com/phidelpark/x64dbgplugins) 디버거 x64dbg 플러그인
- [**2**星][2y] [C] [x64dbg/dbgit](https://github.com/x64dbg/dbgit) Simple plugin to automatically add x64dbg databases to version control.
- [**1**星][2y] [C++] [lllshamanlll/x64dbg_cpp_template](https://github.com/lllshamanlll/x64dbg_cpp_template) Simple, easy to use template plugin for x64dbg
- [**1**星][1y] [Assembly] [mrfearless/stepint3-plugin-x64](https://github.com/mrfearless/stepint3-plugin-x64) StepInt3 Plugin (x64) - A Plugin For x64dbg
- [**1**星][2y] [C++] [x64dbg/snowmandummy](https://github.com/x64dbg/snowmandummy) Dummy DLL for snowman.
- [**0**星][2y] [C] [x64dbg/getcharabcwidthsi_cache](https://github.com/x64dbg/getcharabcwidthsi_cache) Plugin to improve performance of QWindowsFontEngine::getGlyphBearings.




***


## <a id="22894d6f2255dc43d82dd46bdbc20ba1"></a>文章&&视频




# <a id="37e37e665eac00de3f55a13dcfd47320"></a>OllyDbg


***


## <a id="7834e399e48e6c64255a1a0fdb6b88f5"></a>插件&&脚本


### <a id="92c44f98ff5ad8f8b0f5e10367262f9b"></a>新添加的


- [**75**星][5y] [C++] [quangnh89/ollycapstone](https://github.com/quangnh89/ollycapstone) This is a plugin for OllyDbg 1.10 to replace the old disasm engine by Capstone disassembly/disassembler framework.
- [**48**星][8y] [C] [stephenfewer/ollysockettrace](https://github.com/stephenfewer/ollysockettrace) OllySocketTrace is a plugin for OllyDbg to trace the socket operations being performed by a process.
- [**45**星][6m] [thomasthelen/ollydbg-scripts](https://github.com/thomasthelen/ollydbg-scripts) Unpacking scripts for Ollydbg.
- [**41**星][1y] [Batchfile] [romanzaikin/ollydbg-v1.10-with-best-plugins-and-immunity-debugger-theme-](https://github.com/romanzaikin/ollydbg-v1.10-with-best-plugins-and-immunity-debugger-theme-) Make OllyDbg v1.10 Look like Immunity Debugger & Best Plugins
- [**41**星][8y] [C] [stephenfewer/ollyheaptrace](https://github.com/stephenfewer/ollyheaptrace) OllyHeapTrace is a plugin for OllyDbg to trace the heap operations being performed by a process.
- [**38**星][8y] [C] [stephenfewer/ollycalltrace](https://github.com/stephenfewer/ollycalltrace) OllyCallTrace is a plugin for OllyDbg to trace the call chain of a thread.
- [**24**星][6y] [C++] [epsylon3/odbgscript](https://github.com/epsylon3/odbgscript) OllyDBG Script Engine
- [**22**星][3y] [Py] [ehabhussein/ollydbg-binary-execution-visualizer](https://github.com/ehabhussein/ollydbg-binary-execution-visualizer) reverse engineering, visual binary analysis
- [**21**星][5y] [C++] [lynnux/holyshit](https://github.com/lynnux/holyshit) ollydbg plugin, the goal is to make life easier. The project is DEAD!
- [**15**星][8y] [C] [zynamics/ollydbg-immunitydbg-exporter](https://github.com/zynamics/ollydbg-immunitydbg-exporter) Exporters for OllyDbg and ImmunityDbg for use with zynamics BinNavi <= 3.0
- [**14**星][5y] [C++] [sinsoul/ollight](https://github.com/sinsoul/ollight) A Code highlighting plugin for OllyDbg 2.01.
- [**9**星][2y] [Assembly] [dentrax/dll-injection-with-assembly](https://github.com/dentrax/dll-injection-with-assembly) DLL Injection to Exe with Assembly using OllyDbg
- [**1**星][2y] [Assembly] [infocus7/assembly-simple-keygen](https://github.com/infocus7/assembly-simple-keygen) First time using Ollydbg for Reverse Engineering




***


## <a id="8dd3e63c4e1811973288ea8f1581dfdb"></a>文章&&视频




# <a id="0a506e6fb2252626add375f884c9095e"></a>WinDBG


***


## <a id="37eea2c2e8885eb435987ccf3f467122"></a>插件&&脚本


### <a id="2ef75ae7852daa9862b2217dca252cc3"></a>新添加的


- [**564**星][6m] [C#] [fremag/memoscope.net](https://github.com/fremag/memoscope.net) Dump and analyze .Net applications memory ( a gui for WinDbg and ClrMd )
- [**389**星][2y] [C++] [swwwolf/wdbgark](https://github.com/swwwolf/wdbgark) WinDBG Anti-RootKit Extension
- [**279**星][26d] [Py] [hugsy/defcon_27_windbg_workshop](https://github.com/hugsy/defcon_27_windbg_workshop) DEFCON 27 workshop - Modern Debugging with WinDbg Preview
- [**230**星][9m] [C++] [microsoft/windbg-samples](https://github.com/microsoft/windbg-samples) Sample extensions, scripts, and API uses for WinDbg.
- [**190**星][7m] [Py] [corelan/windbglib](https://github.com/corelan/windbglib) Public repository for windbglib, a wrapper around pykd.pyd (for Windbg), used by mona.py
- [**157**星][3y] [Py] [theevilbit/exploit_generator](https://github.com/theevilbit/exploit_generator) Automated Exploit generation with WinDBG
- [**141**星][1y] [Py] [bruce30262/twindbg](https://github.com/bruce30262/twindbg) PEDA-like debugger UI for WinDbg
- [**136**星][19d] [C#] [chrisnas/debuggingextensions](https://github.com/chrisnas/debuggingextensions) Host of debugging-related extensions such as post-mortem tools or WinDBG extensions
- [**135**星][5y] [C] [goldshtn/windbg-extensions](https://github.com/goldshtn/windbg-extensions) Various extensions for WinDbg
- [**123**星][10d] [JS] [0vercl0k/windbg-scripts](https://github.com/0vercl0k/windbg-scripts) A bunch of JavaScript extensions for WinDbg.
- [**97**星][1m] [C++] [fdiskyou/iris](https://github.com/fdiskyou/iris) WinDbg extension to display Windows process mitigations
- [**89**星][2y] [HTML] [sam-b/windbg-plugins](https://github.com/sam-b/windbg-plugins) Any useful windbg plugins I've written.
- [**79**星][6y] [C++] [tandasat/findpg](https://github.com/tandasat/findpg) Windbg extension to find PatchGuard pages
- [**77**星][3y] [HTML] [szimeus/evalyzer](https://github.com/szimeus/evalyzer) Using WinDBG to tap into JavaScript and help with deobfuscation and browser exploit detection
- [**72**星][17d] [C++] [rodneyviana/netext](https://github.com/rodneyviana/netext) WinDbg extension for data mining managed heap. It also includes commands to list http request, wcf services, WIF tokens among others
- [**69**星][2y] [C++] [lynnux/windbg_hilight](https://github.com/lynnux/windbg_hilight) A windbg plugin to hilight text in Disassembly and Command windows. Support x86 and x64.
- [**67**星][2m] [davidfowl/windbgcheatsheet](https://github.com/davidfowl/windbgcheatsheet) This is a cheat sheet for windbg
- [**64**星][1y] [vagnerpilar/windbgtree](https://github.com/vagnerpilar/windbgtree) A command tree based on commands and extensions for Windows Kernel Debugging.
- [**62**星][1m] [JS] [hugsy/windbg_js_scripts](https://github.com/hugsy/windbg_js_scripts) Toy scripts for playing with WinDbg JS API
- [**60**星][3m] [C++] [imugee/pegasus](https://github.com/imugee/pegasus) reverse engineering extension plugin for windbg
- [**59**星][3y] [C++] [markhc/windbg_to_c](https://github.com/markhc/windbg_to_c) Translates WinDbg "dt" structure dump to a C structure
- [**58**星][3y] [rehints/windbg](https://github.com/rehints/windbg) 
- [**51**星][2y] [Py] [cisco-talos/dotnet_windbg](https://github.com/cisco-talos/dotnet_windbg) 
- [**51**星][4y] [C++] [fishstiqz/poolinfo](https://github.com/fishstiqz/poolinfo) kernel pool windbg extension
- [**50**星][2y] [C#] [zodiacon/windbgx](https://github.com/zodiacon/windbgx) An attempt to create a friendly version of WinDbg
- [**45**星][2y] [Py] [kukfa/bindbg](https://github.com/kukfa/bindbg) Binary Ninja插件, 将Windbg的静态/动态调试同步至Binary Ninja
- [**45**星][3y] [C++] [pstolarz/dumpext](https://github.com/pstolarz/dumpext) WinDbg debugger extension library providing various tools to analyse, dump and fix (restore) Microsoft Portable Executable files for both 32 (PE) and 64-bit (PE+) platforms.
- [**43**星][3y] [C++] [andreybazhan/dbgext](https://github.com/andreybazhan/dbgext) Debugger extension for the Debugging Tools for Windows (WinDbg, KD, CDB, NTSD).
- [**43**星][1y] [bulentrahimkazanci/windbg-cheat-sheet](https://github.com/bulentrahimkazanci/windbg-cheat-sheet) A practical guide to analyze memory dumps of .Net applications by using Windbg
- [**40**星][11m] [C#] [kevingosse/windbg-extensions](https://github.com/kevingosse/windbg-extensions) Extensions for the new WinDbg
- [**37**星][2y] [C] [long123king/tokenext](https://github.com/long123king/tokenext) A windbg extension, extracting token related contents
- [**34**星][6m] [C++] [seancline/pyext](https://github.com/seancline/pyext) WinDbg Extensions for Python
- [**31**星][3y] [osandamalith/apimon](https://github.com/osandamalith/apimon) A simple API monitor for Windbg
- [**28**星][7y] [C++] [cr4sh/dbgcb](https://github.com/cr4sh/dbgcb) Engine for communication with remote kernel debugger (KD, WinDbg) from drivers and applications
- [**28**星][2y] [C++] [dshikashio/pybag](https://github.com/dshikashio/pybag) CPython module for Windbg's dbgeng plus additional wrappers.
- [**28**星][2y] [C++] [fdfalcon/typeisolationdbg](https://github.com/fdfalcon/typeisolationdbg) A little WinDbg extension to help dump the state of Win32k Type Isolation structures.
- [**28**星][3y] [long123king/grep](https://github.com/long123king/grep) Grep-like WinDbg extension
- [**27**星][2m] [C++] [progmboy/win32kext](https://github.com/progmboy/win32kext) windbg plugin for win32k debugging
- [**22**星][3m] [wangray/windbg-for-gdb-users](https://github.com/wangray/windbg-for-gdb-users) "Pwntools does not support Windows. Use a real OS ;)" — Zach Riggle, 2015
- [**21**星][5y] [stolas/windbg-darktheme](https://github.com/stolas/windbg-darktheme) A dark theme for WinDBG.
- [**21**星][5y] [Py] [windbgscripts/pykd](https://github.com/windbgscripts/pykd) This contains Helpful PYKD (Python Extension for Windbg) scripts
- [**18**星][3y] [Py] [ajkhoury/windbg2struct](https://github.com/ajkhoury/windbg2struct) Takes a Windbg dumped structure (using the 'dt' command) and formats it into a C structure
- [**15**星][6y] [pccq2002/windbg](https://github.com/pccq2002/windbg) windbg open source
- [**14**星][3y] [C] [lowleveldesign/lldext](https://github.com/lowleveldesign/lldext) LLD WinDbg extension
- [**14**星][1y] [JS] [osrdrivers/windbg-exts](https://github.com/osrdrivers/windbg-exts) Various WinDbg extensions and scripts
- [**13**星][3y] [C++] [evandowning/windbg-trace](https://github.com/evandowning/windbg-trace) Use WinDBG to trace the Windows API calls of any Portable Executable file
- [**12**星][1y] [Py] [wu-wenxiang/tool-windbg-pykd-scripts](https://github.com/wu-wenxiang/tool-windbg-pykd-scripts) Pykd scripts collection for Windbg
- [**11**星][1y] [C] [0cch/luadbg](https://github.com/0cch/luadbg) Lua Extension for Windbg
- [**11**星][6y] [baoqi/uni-trace](https://github.com/baoqi/uni-trace) Universal Trace Debugger Engine. Currently, only support windbg on Windows, but the long term goal is to also support GDB or LLDB
- [**10**星][1y] [C++] [jkornev/cfgdump](https://github.com/jkornev/cfgdump) Windbg extension that allows you analyze Control Flow Guard map
- [**10**星][3y] [C] [pstolarz/asprext](https://github.com/pstolarz/asprext) ASProtect reverse engineering & analysis WinDbg extension
- [**10**星][3y] [C] [pstolarz/scriptext](https://github.com/pstolarz/scriptext) WinDbg scripting language utilities.
- [**9**星][2y] [C#] [indy-singh/automateddumpanalysis](https://github.com/indy-singh/automateddumpanalysis) A simple tool that helps you run common diagnostics steps instead of battling with WinDbg.
- [**8**星][2y] [abarbatei/windbg-info](https://github.com/abarbatei/windbg-info) collection of links related to using and improving windbg
- [**7**星][8y] [C] [pcguru34/windbgshark](https://github.com/pcguru34/windbgshark) Automatically exported from code.google.com/p/windbgshark
- [**7**星][10m] [C#] [xquintana/dumpreport](https://github.com/xquintana/dumpreport) Console application that creates an HTML report from a Windows user-mode dump file, using WinDBG or CDB debuggers. Although it's been mainly designed for crash dump analysis of Windows applications developed in C++, it can also be used to read hang dumps or .Net dumps.
- [**6**星][5y] [lallousx86/windbg-scripts](https://github.com/lallousx86/windbg-scripts) Windbg scripts
- [**5**星][6y] [Py] [bannedit/windbg](https://github.com/bannedit/windbg) 
- [**5**星][5y] [C++] [dshikashio/pywindbg](https://github.com/dshikashio/pywindbg) Python Windbg extension
- [**5**星][2m] [repnz/windbg-cheat-sheet](https://github.com/repnz/windbg-cheat-sheet) My personal cheat sheet for using WinDbg for kernel debugging
- [**5**星][3y] [Py] [saaramar/nl_windbg](https://github.com/saaramar/nl_windbg) Base library for Windows kernel debugging
- [**5**星][2y] [Py] [seancline/pythonsymbols](https://github.com/seancline/pythonsymbols) A WinDbg symbol server for all recent versions of CPython.
- [**2**星][4y] [C] [tenpoku1000/windbg_logger](https://github.com/tenpoku1000/windbg_logger) カーネルデバッグ中の Visual Studio 内蔵 WinDbg の通信内容を記録するアプリケーションとデバイスドライバです。
- [**2**星][2y] [C++] [vincentse/watchtrees](https://github.com/vincentse/watchtrees) Debugger extension for the Windows Debugging Tools (WinDBG, KD, CDB, NTSD). It add commands to manage watches.
- [**0**星][10m] [C++] [kevingosse/lldb-loadmanaged](https://github.com/kevingosse/lldb-loadmanaged) LLDB plugin capable of executing plugins written for WinDbg/ClrMD
- [**0**星][9m] [C++] [lomomike/nethelps](https://github.com/lomomike/nethelps) NetHelps - WinDbg extension, helps to view some .Net internals information




***


## <a id="6d8bac8bfb5cda00c7e3bd38d64cbce3"></a>文章&&视频


- 2019.10 [freebuf] [Iris：一款可执行常见Windows漏洞利用检测的WinDbg扩展](https://www.freebuf.com/sectool/214276.html)
- 2019.08 [lowleveldesign] [Synthetic types and tracing syscalls in WinDbg](https://lowleveldesign.org/2019/08/27/synthetic-types-and-tracing-syscalls-in-windbg/)
- 2019.08 [hackertor] [Iris – WinDbg Extension To Perform Basic Detection Of Common Windows Exploit Mitigations](https://hackertor.com/2019/08/16/iris-windbg-extension-to-perform-basic-detection-of-common-windows-exploit-mitigations/)
- 2019.07 [osr] [How L1 Terminal Fault (L1TF) Mitigation and WinDbg Wasted My Morning (a.k.a. Yak Shaving: WinDbg Edition)](https://www.osr.com/blog/2019/07/02/how-l1-terminal-fault-l1tf-mitigation-and-windbg-wasted-my-morning-a-k-a-yak-shaving-windbg-edition/)
- 2019.06 [360] [《Dive into Windbg系列》Explorer无法启动排查](https://www.anquanke.com/post/id/179748/)
- 2019.04 [360] [《Dive into Windbg系列》AudioSrv音频服务故障](https://www.anquanke.com/post/id/176343/)
- 2019.03 [aliyun] [为WinDbg和LLDB编写ClrMD扩展](https://xz.aliyun.com/t/4459)
- 2019.03 [offensive] [Development of a new Windows 10 KASLR Bypass (in One WinDBG Command)](https://www.offensive-security.com/vulndev/development-of-a-new-windows-10-kaslr-bypass-in-one-windbg-command/)
- 2019.02 [OALabs] [WinDbg Basics for Malware Analysis](https://www.youtube.com/watch?v=QuFJpH3My7A)


# <a id="11a59671b467a8cdbdd4ea9d5e5d9b51"></a>Android


***


## <a id="2110ded2aa5637fa933cc674bc33bf21"></a>工具


### <a id="63fd2c592145914e99f837cecdc5a67c"></a>新添加的1


- [**6101**星][2m] [Java] [google/android-classyshark](https://github.com/google/android-classyshark) 分析基于Android/Java的App或游戏
- [**6094**星][5m] [Java] [qihoo360/replugin](https://github.com/qihoo360/replugin) RePlugin - A flexible, stable, easy-to-use Android Plug-in Framework
- [**5195**星][11d] [Py] [mobsf/mobile-security-framework-mobsf](https://github.com/MobSF/Mobile-Security-Framework-MobSF) Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.
    - 重复区段: [Malware->工具](#e781a59e4f4daab058732cf66f77bfb9) |
- [**5084**星][7d] [HTML] [owasp/owasp-mstg](https://github.com/owasp/owasp-mstg) 关于移动App安全开发、测试和逆向的相近手册
- [**4882**星][16d] [Java] [guardianproject/haven](https://github.com/guardianproject/haven) 通过Android应用和设备上的传感器保护自己的个人空间和财产而又不损害
- [**4776**星][4d] [C++] [facebook/redex](https://github.com/facebook/redex) Android App字节码优化器
- [**4306**星][7d] [Shell] [ashishb/android-security-awesome](https://github.com/ashishb/android-security-awesome) A collection of android security related resources
- [**3649**星][1m] [C++] [anbox/anbox](https://github.com/anbox/anbox) 在常规GNU / Linux系统上引导完整的Android系统，基于容器
- [**2314**星][1y] [Java] [csploit/android](https://github.com/csploit/android) cSploit - The most complete and advanced IT security professional toolkit on Android.
- [**2120**星][9m] [Py] [linkedin/qark](https://github.com/linkedin/qark) 查找Android App的漏洞, 支持源码或APK文件
- [**2095**星][10m] [jermic/android-crack-tool](https://github.com/jermic/android-crack-tool) 
- [**2051**星][13d] [Py] [sensepost/objection](https://github.com/sensepost/objection) runtimemobile exploration
- [**2011**星][7m] [Py] [fsecurelabs/drozer](https://github.com/FSecureLABS/drozer) The Leading Security Assessment Framework for Android.
- [**1976**星][] [Java] [kyson/androidgodeye](https://github.com/kyson/androidgodeye) AndroidGodEye:A performance monitor tool , like "Android Studio profiler" for Android , you can easily monitor the performance of your app real time in pc browser
- [**1925**星][7m] [Java] [fuzion24/justtrustme](https://github.com/fuzion24/justtrustme) An xposed module that disables SSL certificate checking for the purposes of auditing an app with cert pinning
- [**1430**星][11m] [Java] [aslody/legend](https://github.com/aslody/legend) (Android)无需Root即可Hook Java方法的框架, 支持Dalvik和Art环境
- [**1417**星][1m] [Java] [chrisk44/hijacker](https://github.com/chrisk44/hijacker) Aircrack, Airodump, Aireplay, MDK3 and Reaver GUI Application for Android
- [**1366**星][3y] [C++] [aslody/turbodex](https://github.com/aslody/turbodex) 在内存中快速加载dex
- [**1241**星][3m] [Java] [whataa/pandora](https://github.com/whataa/pandora) an android library for debugging what we care about directly in app.
- [**1235**星][1m] [Java] [find-sec-bugs/find-sec-bugs](https://github.com/find-sec-bugs/find-sec-bugs) The SpotBugs plugin for security audits of Java web applications and Android applications. (Also work with Kotlin, Groovy and Scala projects)
- [**1213**星][1m] [JS] [megatronking/httpcanary](https://github.com/megatronking/httpcanary) A powerful capture and injection tool for the Android platform
- [**1208**星][3m] [Java] [javiersantos/piracychecker](https://github.com/javiersantos/piracychecker) An Android library that prevents your app from being pirated / cracked using Google Play Licensing (LVL), APK signature protection and more. API 14+ required.
- [**1134**星][24d] [Java] [huangyz0918/androidwm](https://github.com/huangyz0918/androidwm) 一个支持不可见数字水印（隐写术）的android图像水印库。
- [**968**星][3y] [Java] [androidvts/android-vts](https://github.com/androidvts/android-vts) Android Vulnerability Test Suite - In the spirit of open data collection, and with the help of the community, let's take a pulse on the state of Android security. NowSecure presents an on-device app to test for recent device vulnerabilities.
- [**920**星][7y] [designativedave/androrat](https://github.com/designativedave/androrat) Remote Administration Tool for Android devices
- [**903**星][5y] [Java] [wszf/androrat](https://github.com/wszf/androrat) Remote Administration Tool for Android
- [**885**星][2m] [C] [504ensicslabs/lime](https://github.com/504ensicslabs/lime) LiME (formerly DMD) is a Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, such as those powered by Android. The tool supports acquiring memory either to the file system of the device or over the network. LiME is unique in that it is the first tool that allows full memory captures f…
- [**833**星][6y] [C] [madeye/gaeproxy](https://github.com/madeye/gaeproxy) GAEProxy for Android (Deprecated)
- [**820**星][3d] [proxymanapp/proxyman](https://github.com/proxymanapp/proxyman) Modern and Delightful HTTP Debugging Proxy for macOS, iOS and Android
- [**810**星][4m] [Scala] [antox/antox](https://github.com/antox/antox) Android client for Project Tox - Secure Peer to Peer Messaging
- [**800**星][3m] [sh4hin/androl4b](https://github.com/sh4hin/androl4b) 用于评估Android应用程序，逆向工程和恶意软件分析的虚拟机
    - 重复区段: [Malware->工具](#e781a59e4f4daab058732cf66f77bfb9) |
- [**769**星][1y] [C] [ele7enxxh/android-inline-hook](https://github.com/ele7enxxh/android-inline-hook) thumb16 thumb32 arm32 inlineHook in Android
- [**735**星][2y] [Java] [gcssloop/encrypt](https://github.com/gcssloop/encrypt) [暂停维护]Android 加密解密工具包。
- [**708**星][4y] [Py] [androbugs/androbugs_framework](https://github.com/androbugs/androbugs_framework) AndroBugs Framework is an efficient Android vulnerability scanner that helps developers or hackers find potential security vulnerabilities in Android applications. No need to install on Windows.
- [**668**星][1m] [doridori/android-security-reference](https://github.com/doridori/android-security-reference) A W.I.P Android Security Ref
- [**666**星][7y] [Java] [honeynet/apkinspector](https://github.com/honeynet/apkinspector) APKinspector is a powerful GUI tool for analysts to analyze the Android applications.
- [**608**星][7m] [JS] [vincentcox/stacoan](https://github.com/vincentcox/stacoan) StaCoAn is a crossplatform tool which aids developers, bugbounty hunters and ethical hackers performing static code analysis on mobile applications.
- [**585**星][2y] [Java] [hypertrack/hyperlog-android](https://github.com/hypertrack/hyperlog-android) Utility logger library for storing logs into database and push them to remote server for debugging
- [**559**星][6d] [Shell] [owasp/owasp-masvs](https://github.com/owasp/owasp-masvs) OWASP 移动App安全标准
- [**546**星][1m] [nordicsemiconductor/android-nrf-connect](https://github.com/nordicsemiconductor/android-nrf-connect) Documentation and issue tracker for nRF Connect for Android.
- [**541**星][1y] [Java] [jaredrummler/apkparser](https://github.com/jaredrummler/apkparser) APK parser for Android
- [**540**星][7y] [Java] [moxie0/androidpinning](https://github.com/moxie0/androidpinning) A standalone library project for certificate pinning on Android.
- [**527**星][4m] [JS] [wooyundota/droidsslunpinning](https://github.com/wooyundota/droidsslunpinning) Android certificate pinning disable tools
- [**518**星][3m] [Java] [megatronking/stringfog](https://github.com/megatronking/stringfog) 一款自动对字节码中的字符串进行加密Android插件工具
- [**511**星][] [Java] [happylishang/cacheemulatorchecker](https://github.com/happylishang/cacheemulatorchecker) Android模拟器检测，检测Android模拟器 ，获取相对真实的IMEI AndroidId 序列号 MAC地址等，作为DeviceID，应对防刷需求等
- [**488**星][2y] [b-mueller/android_app_security_checklist](https://github.com/b-mueller/android_app_security_checklist) Android App Security Checklist
- [**482**星][1m] [JS] [lyxhh/lxhtoolhttpdecrypt](https://github.com/lyxhh/lxhtoolhttpdecrypt) Simple Android/iOS protocol analysis and utilization tool
- [**471**星][2y] [Smali] [sensepost/kwetza](https://github.com/sensepost/kwetza) Python 脚本，将 Meterpreter payload 注入 Andorid App
- [**451**星][3y] [C++] [vusec/drammer](https://github.com/vusec/drammer) Native binary for testing Android phones for the Rowhammer bug
- [**450**星][12m] [Kotlin] [shadowsocks/kcptun-android](https://github.com/shadowsocks/kcptun-android) kcptun for Android.
- [**443**星][23d] [TS] [shroudedcode/apk-mitm](https://github.com/shroudedcode/apk-mitm) 
- [**431**星][5d] [C] [guardianproject/orbot](https://github.com/guardianproject/orbot) The Github home of Orbot: Tor on Android (Also available on gitlab!)
- [**426**星][11d] [Py] [thehackingsage/hacktronian](https://github.com/thehackingsage/hacktronian) All in One Hacking Tool for Linux & Android
- [**412**星][4m] [Java] [megatronking/netbare](https://github.com/megatronking/netbare) Net packets capture & injection library designed for Android
- [**411**星][3y] [Java] [fourbrother/kstools](https://github.com/fourbrother/kstools) Android中自动爆破签名工具
- [**409**星][3m] [CSS] [angea/pocorgtfo](https://github.com/angea/pocorgtfo) a "Proof of Concept or GTFO" mirror with extra article index, direct links and clean PDFs.
- [**408**星][1y] [Java] [testwhat/smaliex](https://github.com/testwhat/smaliex) A wrapper to get de-optimized dex from odex/oat/vdex.
- [**405**星][3y] [Java] [ac-pm/sslunpinning_xposed](https://github.com/ac-pm/sslunpinning_xposed) Android Xposed Module to bypass SSL certificate validation (Certificate Pinning).
- [**403**星][6y] [Java] [isecpartners/introspy-android](https://github.com/isecpartners/introspy-android) Security profiling for blackbox Android
- [**397**星][2y] [Java] [routerkeygen/routerkeygenandroid](https://github.com/routerkeygen/routerkeygenandroid) Router Keygen generate default WPA/WEP keys for several routers.
- [**382**星][2y] [Java] [davidbuchanan314/nxloader](https://github.com/davidbuchanan314/nxloader) My first Android app: Launch Fusée Gelée payloads from stock Android (CVE-2018-6242)
- [**379**星][5m] [Makefile] [crifan/android_app_security_crack](https://github.com/crifan/android_app_security_crack) 安卓应用的安全和破解
- [**379**星][1y] [CSS] [nowsecure/secure-mobile-development](https://github.com/nowsecure/secure-mobile-development) A Collection of Secure Mobile Development Best Practices
- [**378**星][2y] [Java] [jaredrummler/androidshell](https://github.com/jaredrummler/androidshell) Execute shell commands on Android.
- [**373**星][3y] [Py] [androidhooker/hooker](https://github.com/androidhooker/hooker) Hooker is an opensource project for dynamic analyses of Android applications. This project provides various tools and applications that can be use to automaticaly intercept and modify any API calls made by a targeted application.
    - 重复区段: [Hook->工具](#cfe974d48bbb90a930bf667c173616c7) |
- [**358**星][5m] [b3nac/android-reports-and-resources](https://github.com/b3nac/android-reports-and-resources) A big list of Android Hackerone disclosed reports and other resources.
- [**358**星][5m] [C] [the-cracker-technology/andrax-mobile-pentest](https://github.com/the-cracker-technology/andrax-mobile-pentest) ANDRAX The first and unique Penetration Testing platform for Android smartphones
- [**353**星][3y] [ObjC] [naituw/hackingfacebook](https://github.com/naituw/hackingfacebook) Kill Facebook for iOS's SSL Pinning
- [**333**星][17d] [Java] [datatheorem/trustkit-android](https://github.com/datatheorem/trustkit-android) Easy SSL pinning validation and reporting for Android.
- [**323**星][2y] [Kotlin] [ollide/intellij-java2smali](https://github.com/ollide/intellij-java2smali) A plugin for IntelliJ IDEA & Android Studio to easily compile Java & Kotlin files to smali.
- [**287**星][1y] [C] [freakishfox/xanso](https://github.com/freakishfox/xanso) Android So文件浏览修复工具
- [**285**星][2y] [Java] [simbiose/encryption](https://github.com/simbiose/encryption) Encryption is a simple way to encrypt and decrypt strings on Android and Java project.
- [**284**星][9m] [Py] [micropyramid/forex-python](https://github.com/micropyramid/forex-python) Foreign exchange rates, Bitcoin price index and currency conversion using ratesapi.io
- [**282**星][4y] [Py] [fuzzing/mffa](https://github.com/fuzzing/mffa) Media Fuzzing Framework for Android
- [**274**星][2y] [Java] [mateuszk87/badintent](https://github.com/mateuszk87/badintent) Intercept, modify, repeat and attack Android's Binder transactions using Burp Suite
- [**270**星][2y] [Java] [reoky/android-crackme-challenge](https://github.com/reoky/android-crackme-challenge) A collection of reverse engineering challenges for learning about the Android operating system and mobile security.
- [**267**星][4m] [Py] [amimo/dcc](https://github.com/amimo/dcc) DCC (Dex-to-C Compiler) is method-based aot compiler that can translate DEX code to C code.
- [**267**星][4y] [C] [samsung/adbi](https://github.com/samsung/adbi) Android Dynamic Binary Instrumentation tool for tracing Android native layer
- [**267**星][2y] [Kotlin] [temyco/security-workshop-sample](https://github.com/temyco/security-workshop-sample) This repository has been desired to show different Android Security Approach implementations using a simple sample project.
- [**265**星][3d] [Py] [den4uk/andriller](https://github.com/den4uk/andriller) Andriller - is software utility with a collection of forensic tools for smartphones. It performs read-only, forensically sound, non-destructive acquisition from Android devices.
- [**262**星][2y] [Java] [maxcamillo/android-keystore-password-recover](https://github.com/maxcamillo/android-keystore-password-recover) Automatically exported from code.google.com/p/android-keystore-password-recover
- [**258**星][3y] [Java] [flankerhqd/jaadas](https://github.com/flankerhqd/jaadas) Joint Advanced Defect assEsment for android applications
- [**258**星][7y] [Java] [isecpartners/android-ssl-bypass](https://github.com/isecpartners/android-ssl-bypass) Black box tool to bypass SSL verification on Android, even when pinning is used.
- [**256**星][3y] [C] [w-shackleton/android-netspoof](https://github.com/w-shackleton/android-netspoof) Network Spoofer
- [**254**星][2y] [Java] [panhongwei/tracereader](https://github.com/panhongwei/tracereader) android小工具，通过读取trace文件，回溯整个整个程序执行调用树。
- [**251**星][10m] [C] [chef-koch/android-vulnerabilities-overview](https://github.com/chef-koch/android-vulnerabilities-overview) An small overview of known Android vulnerabilities
- [**234**星][2m] [C] [grant-h/qu1ckr00t](https://github.com/grant-h/qu1ckr00t) A PoC application demonstrating the power of an Android kernel arbitrary R/W.
- [**234**星][1y] [Ruby] [hahwul/droid-hunter](https://github.com/hahwul/droid-hunter) (deprecated) Android application vulnerability analysis and Android pentest tool
- [**229**星][8m] [Java] [jieyushi/luffy](https://github.com/jieyushi/luffy) Android字节码插件，编译期间动态修改代码，改造添加全埋点日志采集功能模块，对常见控件进行监听处理
- [**225**星][3m] [Java] [virb3/trustmealready](https://github.com/virb3/trustmealready) Disable SSL verification and pinning on Android, system-wide
- [**208**星][18d] [C] [derrekr/fastboot3ds](https://github.com/derrekr/fastboot3ds) A homebrew bootloader for the Nintendo 3DS that is similar to android's fastboot.
- [**202**星][1y] [C#] [labo89/adbgui](https://github.com/labo89/adbgui) Wrapper for Android Debug Bridge (ADB) written in C#
- [**200**星][2y] [Java] [ernw/androtickler](https://github.com/ernw/androtickler) Penetration testing and auditing toolkit for Android apps.
- [**194**星][2y] [Java] [panhongwei/androidmethodhook](https://github.com/panhongwei/androidmethodhook) android art hook like Sophix
- [**183**星][2y] [Smali] [sslab-gatech/avpass](https://github.com/sslab-gatech/avpass) Tool for leaking and bypassing Android malware detection system
    - 重复区段: [Malware->工具](#e781a59e4f4daab058732cf66f77bfb9) |
- [**180**星][3y] [C] [kriswebdev/android_aircrack](https://github.com/kriswebdev/android_aircrack) Aircrack-ng command-line for Android. Binaries & source.
- [**173**星][2m] [Java] [calebfenton/apkfile](https://github.com/calebfenton/apkfile) Android app analysis and feature extraction library
- [**173**星][7y] [Py] [trivio/common_crawl_index](https://github.com/trivio/common_crawl_index) billions of pages randomly crawled from the internet
- [**170**星][9m] [thehackingsage/hackdroid](https://github.com/thehackingsage/hackdroid) Penetration Testing Apps for Android
- [**167**星][16d] [Java] [pwittchen/reactivewifi](https://github.com/pwittchen/reactivewifi) Android library listening available WiFi Access Points and related information with RxJava Observables
- [**161**星][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->插件->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->插件->针对特定分析目标->Loader](#cb59d84840e41330a7b5e275c0b81725) |[Android->工具->IDA](#0a668d220ce74e11ed2738c4e3ae3c9e) |
- [**161**星][1y] [Java] [iqiyi/dexsplitter](https://github.com/iqiyi/dexsplitter) Analyze contribution rate of each module to the apk size
- [**160**星][9m] [Py] [sch3m4/androidpatternlock](https://github.com/sch3m4/androidpatternlock) A little Python tool to crack the Pattern Lock on Android devices
- [**160**星][4y] [Py] [appknox/afe](https://github.com/appknox/AFE) Android Framework for Exploitation, is a framework for exploiting android based devices
- [**158**星][3y] [Java] [googlecloudplatform/endpoints-codelab-android](https://github.com/googlecloudplatform/endpoints-codelab-android) endpoints-codelab-android
- [**146**星][4m] [PostScript] [guardianproject/orfox](https://github.com/guardianproject/orfox) UPDATE: Orfox is being replaced by Tor Browser for Android. All future work and comments will be handled by Tor Project.
- [**145**星][3y] [Java] [zhouat/inject-hook](https://github.com/zhouat/inject-hook) for android
- [**142**星][3m] [Py] [technicaldada/hackerpro](https://github.com/technicaldada/hackerpro) All in One Hacking Tool for Linux & Android (Termux). Hackers are welcome in our blog
- [**140**星][4m] [Shell] [izzysoft/adebar](https://github.com/izzysoft/adebar) Android DEvice Backup And Report, using Bash and ADB
- [**137**星][2y] [Java] [gnaixx/hidex-hack](https://github.com/gnaixx/hidex-hack) anti reverse by hack dex file
- [**137**星][3y] [Java] [ysrc/anti-emulator](https://github.com/ysrc/anti-emulator) 基于文件特征的Android模拟器检测
- [**133**星][3y] [C++] [chenenyu/androidsecurity](https://github.com/chenenyu/androidsecurity) Android安全实践
- [**130**星][1y] [Java] [florent37/rxlifecycle](https://github.com/florent37/rxlifecycle) Rx binding of stock Android Activities & Fragment Lifecycle, avoiding memory leak
- [**130**星][2m] [pouyadarabi/instagram_ssl_pinning](https://github.com/pouyadarabi/instagram_ssl_pinning) Bypassing SSL Pinning in Instagram Android App
- [**127**星][4y] [C++] [chago/advmp](https://github.com/chago/advmp) 大自然的搬运工-Android虚拟机保护Demo
- [**125**星][5y] [Ruby] [mttkay/replicant](https://github.com/mttkay/replicant) A REPL for the Android Debug Bridge (ADB)
- [**124**星][2y] [Shell] [nccgroup/lazydroid](https://github.com/nccgroup/lazydroid) bash script to facilitate some aspects of an Android application assessment
- [**123**星][5y] [jacobsoo/androidslides](https://github.com/jacobsoo/androidslides) 
- [**122**星][3m] [Java] [aaronjwood/portauthority](https://github.com/aaronjwood/portauthority) A handy systems and security-focused tool, Port Authority is a very fast Android port scanner. Port Authority also allows you to quickly discover hosts on your network and will display useful network information about your device and other hosts.
- [**116**星][1y] [C++] [melonwxd/elfhooker](https://github.com/melonwxd/elfhooker) 兼容Android 32位和64位。基于EFL文件格式Hook的demo，hook了SurfaceFlinger进程的eglSwapBuffers函数，替换为new_eglSwapBuffers
- [**114**星][26d] [Java] [stringcare/androidlibrary](https://github.com/stringcare/androidlibrary) Android library to reveal or obfuscate strings and assets at runtime
- [**114**星][2y] [wpvsyou/mprop](https://github.com/wpvsyou/mprop) 修改Android prop脚本工具
- [**113**星][2y] [Py] [fsecurelabs/drozer-modules](https://github.com/FSecureLABS/drozer-modules) leading security testing framework for Android.
- [**112**星][4y] [Py] [androidsecuritytools/lobotomy](https://github.com/androidsecuritytools/lobotomy) Android Security Toolkit
- [**108**星][5y] [Py] [mspreitz/adel](https://github.com/mspreitz/adel) dumps all important SQLite Databases from a connected Android smartphone to the local disk and analyzes these files in a forensically accurate workflow
- [**104**星][4m] [JS] [adelphes/android-dev-ext](https://github.com/adelphes/android-dev-ext) Android debugging support for VS Code
- [**104**星][2y] [Kotlin] [heimashi/debug_view_kotlin](https://github.com/heimashi/debug_view_kotlin) 用kotlin实现的Android浮层调试控制台，实时的显示内存、FPS、文字log、app启动时间、Activity启动时间
- [**102**星][6m] [Py] [vmavromatis/absolutely-proprietary](https://github.com/vmavromatis/absolutely-proprietary) Proprietary package detector for arch-based distros. Compares your installed packages against Parabola's package blacklist and then prints your Stallman Freedom Index (free/total).
- [**101**星][9m] [Py] [zsdlove/apkvulcheck](https://github.com/zsdlove/apkvulcheck) This is a tool to help androidcoder to check the flaws in their projects.
- [**99**星][4y] [Java] [odrin/droid-watcher](https://github.com/odrin/droid-watcher) [OUTDATED & UNSUPPORTED] Droid Watcher - Android Spy Application
- [**95**星][4y] [Shell] [jlrodriguezf/whatspwn](https://github.com/jlrodriguezf/whatspwn) Linux tool used to extract sensitive data, inject backdoor or drop remote shells on android devices.
- [**94**星][2y] [C++] [woxihuannisja/stormhook](https://github.com/woxihuannisja/stormhook) StormHook is a Android Hook Framework for Dalvik and Art
- [**93**星][2y] [C++] [femto-dev/femto](https://github.com/femto-dev/femto) Sequence Indexing and Search
- [**93**星][1y] [Py] [integrity-sa/droidstatx](https://github.com/integrity-sa/droidstatx) Python tool that generates an Xmind map with all the information gathered and any evidence of possible vulnerabilities identified via static analysis. The map itself is an Android Application Pentesting Methodology component, which assists Pentesters to cover all important areas during an assessment.
- [**90**星][4y] [C] [rchiossi/dexterity](https://github.com/rchiossi/dexterity) Dex manipulation library
- [**90**星][8m] [JS] [adonespitogo/adobot-io](https://github.com/adonespitogo/adobot-io) Android Spyware Server
- [**89**星][2m] [pouyadarabi/facebook_ssl_pinning](https://github.com/pouyadarabi/facebook_ssl_pinning) Bypassing SSL Pinning in Facebook Android App
- [**87**星][4y] [Py] [necst/aamo](https://github.com/necst/aamo) AAMO: Another Android Malware Obfuscator
    - 重复区段: [Malware->工具](#e781a59e4f4daab058732cf66f77bfb9) |
- [**86**星][5y] [Java] [sysdream/fino](https://github.com/sysdream/fino) Android small footprint inspection tool
- [**85**星][2m] [Java] [rikkaapps/wadb](https://github.com/rikkaapps/wadb) A simple switch for adb (Android Debug Bridge) over network.
- [**83**星][1y] [Kotlin] [pvasa/easycrypt](https://github.com/pvasa/easycrypt) Android cryptography library with SecureRandom patches.
- [**81**星][2m] [Kotlin] [linkedin/dex-test-parser](https://github.com/linkedin/dex-test-parser) Find all test methods in an Android instrumentation APK
- [**79**星][3y] [Py] [dancezarp/tbdex](https://github.com/dancezarp/tbdex) 
- [**76**星][2d] [Py] [tp7309/ttdedroid](https://github.com/tp7309/ttdedroid) 一键反编译工具One key for quickly decompile apk/aar/dex/jar, support by jadx/dex2jar/enjarify/cfr.
- [**74**星][3y] [wtsxdev/android-security-list](https://github.com/wtsxdev/android-security-list) Collection of Android security related resources
- [**73**星][3d] [jawz101/mobileadtrackers](https://github.com/jawz101/mobileadtrackers) Taken from DNS logs while actively using Android apps over the years. Formatted in hostfile format.
- [**70**星][2y] [Java] [yolosec/routerkeygenandroid](https://github.com/yolosec/routerkeygenandroid) Router Keygen generate default WPA/WEP keys for several routers.
- [**69**星][2y] [Kotlin] [menjoo/android-ssl-pinning-webviews](https://github.com/menjoo/android-ssl-pinning-webviews) A simple demo app that demonstrates Certificate pinning and scheme/domain whitelisting in Android WebViews
- [**68**星][1y] [Java] [fooock/phone-tracker](https://github.com/fooock/phone-tracker) Phone tracker is an Android library to gather environment signals, like cell towers, wifi access points and gps locations.
- [**66**星][3y] [Py] [crange/crange](https://github.com/crange/crange) Crange is a tool to index and cross-reference C/C++ source code
- [**66**星][2y] [Java] [fsecurelabs/drozer-agent](https://github.com/FSecureLABS/drozer-agent) The Android Agent for the Mercury Security Assessment Framework.
- [**65**星][1y] [Py] [cryptax/dextools](https://github.com/cryptax/dextools) Miscellaenous DEX (Dalvik Executable) tools
- [**65**星][2y] [Java] [isacan/andzu](https://github.com/isacan/andzu) In-App Android Debugging Tool With Enhanced Logging, Networking Info, Crash reporting And More.
- [**63**星][4y] [Java] [ac-pm/proxyon](https://github.com/ac-pm/proxyon) Android Xposed Module to apply proxy for a specific app.
- [**63**星][20d] [Py] [meituan-dianping/lyrebird-android](https://github.com/meituan-dianping/lyrebird-android) 本程序是一个Lyrebird的插件，用于支持获取Android设备信息。
- [**62**星][1y] [pfalcon/awesome-linux-android-hacking](https://github.com/pfalcon/awesome-linux-android-hacking) List of hints and Q&As to get most of your Linux/Android device
- [**61**星][7m] [Java] [ajnas/wifips](https://github.com/ajnas/wifips) WiFi Based Indoor Positioning System, A MVP android Application
- [**61**星][6y] [Java] [isecpartners/android-killpermandsigchecks](https://github.com/isecpartners/android-killpermandsigchecks) Bypass signature and permission checks for IPCs
- [**61**星][6y] [Java] [gat3way/airpirate](https://github.com/gat3way/airpirate) Android 802.11 pentesting tool
- [**60**星][3m] [Java] [aagarwal1012/image-steganography-library-android](https://github.com/aagarwal1012/image-steganography-library-android) 
- [**60**星][2y] [Java] [geeksonsecurity/android-overlay-malware-example](https://github.com/geeksonsecurity/android-overlay-malware-example) Harmless Android malware using the overlay technique to steal user credentials.
    - 重复区段: [Malware->工具](#e781a59e4f4daab058732cf66f77bfb9) |
- [**60**星][2y] [Java] [globalpolicy/phonemonitor](https://github.com/globalpolicy/phonemonitor) A Remote Administration Tool for Android devices
- [**59**星][5d] [C] [watf-team/watf-bank](https://github.com/watf-team/watf-bank) WaTF Bank - What a Terrible Failure Mobile Banking Application for Android and iOS
- [**58**星][2m] [Java] [lizhangqu/android-bundle-support](https://github.com/lizhangqu/android-bundle-support) 增强型apk analyzer，支持ap_, ap, aar, aab, jar, so, awb, aab, apks等zip文件使用apk analyzer打开, android studio插件
- [**56**星][2y] [C] [mwpcheung/ssl-kill-switch2](https://github.com/mwpcheung/ssl-kill-switch2) Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and OS X Apps
- [**55**星][3y] [C++] [stealth/crash](https://github.com/stealth/crash) crypted admin shell: SSH-like strong crypto remote admin shell for Linux, BSD, Android, Solaris and OSX
- [**54**星][10m] [Py] [circl/potiron](https://github.com/circl/potiron) Potiron - Normalize, Index and Visualize Network Capture
- [**54**星][5y] [Go] [hailocab/logslam](https://github.com/hailocab/logslam) A lightweight lumberjack protocol compliant logstash indexer
- [**54**星][1y] [C] [shunix/tinyinjector](https://github.com/shunix/tinyinjector) Shared Library Injector on Android
- [**53**星][2y] [Java] [zyrikby/fsquadra](https://github.com/zyrikby/fsquadra) Fast detection of repackaged Android applications based on the comparison of resource files included into the package.
- [**52**星][2y] [Java] [owasp-ruhrpott/owasp-workshop-android-pentest](https://github.com/owasp-ruhrpott/owasp-workshop-android-pentest) Learning Penetration Testing of Android Applications
- [**52**星][7m] [C++] [virgilsecurity/virgil-crypto](https://github.com/virgilsecurity/virgil-crypto) Virgil Crypto is a high-level cryptographic library that allows you to perform all necessary operations for secure storing and transferring data and everything required to become HIPAA and GDPR compliant. Crypto Library is written in C++, suitable for mobile and server platforms and supports bindings with: Swift, Obj-C, Java (Android), С#/.NET, …
- [**51**星][2m] [C] [alainesp/hashsuitedroid](https://github.com/alainesp/hashsuitedroid) Hash Suite for Android
- [**51**星][1m] [Java] [guardianproject/tor-android](https://github.com/guardianproject/tor-android) Tor binary and library for Android
- [**49**星][3y] [Java] [necst/heldroid](https://github.com/necst/heldroid) Dissect Android Apps Looking for Ransomware Functionalities
- [**47**星][5y] [C] [mobileforensicsresearch/mem](https://github.com/mobileforensicsresearch/mem) Tool used for dumping memory from Android devices
- [**47**星][2y] [C] [shunix/androidgothook](https://github.com/shunix/androidgothook) GOT Hook implemented in Android
- [**46**星][5y] [Java] [monstersb/hijackandroidpoweroff](https://github.com/monstersb/hijackandroidpoweroff) Android hijack power off
- [**44**星][3y] [Java] [miracle963/zjdroid](https://github.com/miracle963/zjdroid) 基于Xposed Framewrok的动态逆向分析模块，逆向分析者可以通过ZjDroid完成以下工作： DEX文件的内存dump 基于Dalvik关键指针的内存BackSmali，有效破解加固应用 敏感API的动态监控 指定内存区域数据dump 获取应用加载DEX信息。 获取指定DEX文件加载类信息。 dump Dalvik java堆信息。 在目标进程动态运行lua脚本。
- [**43**星][1y] [JS] [intoli/slice](https://github.com/intoli/slice) A JavaScript implementation of Python's negative indexing and extended slice syntax.
- [**42**星][2y] [PHP] [paragonie/hpkp-builder](https://github.com/paragonie/hpkp-builder) Build HTTP Public-Key-Pinning headers from a JSON file (or build them programmatically)
- [**41**星][2y] [Java] [alepacheco/androrw](https://github.com/alepacheco/androrw) PoC Ransomware for android
- [**40**星][3y] [JS] [naman14/gnome-android-tool](https://github.com/naman14/gnome-android-tool) Gnome shell extension for adb tools
- [**39**星][2y] [Java] [tiked/androrw](https://github.com/tiked/androrw) PoC Ransomware for android
- [**39**星][11d] [C] [intel/kernelflinger](https://github.com/intel/kernelflinger)  the Intel UEFI bootloader for AndroidTM/BrilloTM
- [**39**星][3m] [TS] [whid-injector/whid-mobile-connector](https://github.com/whid-injector/whid-mobile-connector) Android Mobile App for Controlling WHID Injector remotely.
- [**38**星][1y] [Py] [aptnotes/tools](https://github.com/aptnotes/tools) Tools to interact with APTnotes reporting/index.
- [**38**星][5y] [Py] [jakev/oat2dex-python](https://github.com/jakev/oat2dex-python) Extract DEX files from an ART ELF binary
- [**38**星][2y] [HTML] [keenrivals/bugsite-index](https://github.com/keenrivals/bugsite-index) Index of websites publishing bugs along the lines of heartbleed.com
- [**36**星][11m] [Py] [pilgun/acvtool](https://github.com/pilgun/acvtool) ACVTool is a novel tool for measuring black-box code coverage of Android applications.
- [**34**星][7m] [Py] [claudiugeorgiu/riskindroid](https://github.com/claudiugeorgiu/riskindroid) 基于机器学习技术，对Android App进行定量风险分析
- [**33**星][7y] [C] [nwhusted/auditdandroid](https://github.com/nwhusted/auditdandroid) A Fork of Auditd geared specifically for running on the Android platform. Includes system applications, AOSP patches, and kernel patches to maximize the audit experience.
- [**33**星][2y] [Xtend] [splondike/polipoid](https://github.com/splondike/polipoid) Android wrapper for the polipo proxy
- [**32**星][2y] [amoghbl1/tor-browser](https://github.com/amoghbl1/tor-browser) Orfox - A Tor Browser for Android
- [**32**星][5y] [Py] [jonmetz/androfuzz](https://github.com/jonmetz/androfuzz) A fuzzing utility for Android that focuses on reporting and delivery portions of the fuzzing process
- [**32**星][2y] [knoobdev/bypass-facebook-ssl-pinning](https://github.com/knoobdev/bypass-facebook-ssl-pinning) Bypassing ssl pinning for facebook android app
- [**32**星][3y] [Py] [mdegrazia/osx-quicklook-parser](https://github.com/mdegrazia/osx-quicklook-parser) Parse the Mac Quickook index.sqlite database
- [**32**星][2y] [Shell] [mseclab/ahe17](https://github.com/mseclab/ahe17) Android Hacking Event 2017 Write-up
- [**32**星][5y] [Py] [xurubin/aurasium](https://github.com/xurubin/aurasium) Practical security policy enforcement for Android apps via bytecode rewriting and in-place reference monitor
- [**31**星][4y] [C] [ctxis/kgdb-android](https://github.com/ctxis/kgdb-android) Patches to the Nexus 6 (Shamu) kernel source to allow KGDB over serial debug cable
- [**31**星][7m] [Java] [jehy/rutracker-free](https://github.com/jehy/rutracker-free) Android thin client for rutracker.org, using Tor to avoid block.
- [**29**星][2y] [C] [wangyinuo/memdump](https://github.com/wangyinuo/memdump) android下的内存dump工具，可以dump so文件
- [**28**星][6y] [MATLAB] [vedaldi/visualindex](https://github.com/vedaldi/visualindex) A simple demo of visual object matching using VLFeat
- [**28**星][4m] [Go] [cs8425/go-adbbot](https://github.com/cs8425/go-adbbot) android bot based on adb and golang
- [**27**星][2y] [Java] [coh7eiqu8thabu/slocker](https://github.com/coh7eiqu8thabu/slocker) Source code of the SLocker Android ransomware
- [**26**星][3y] [Java] [whyalwaysmea/mobilesafe](https://github.com/whyalwaysmea/mobilesafe) 这是一个android版的手机卫士，包含一下功能：1.手机防盗 2. 黑名单设置 3.软件管理 4.进程管理 5.流量统计 6.缓存清理 7.手机杀毒 8.来电归属地显示 9.号码归属地查询 10.程序锁
- [**26**星][16d] [fkie-cad/destroid](https://github.com/fkie-cad/destroid) Fighting String Encryption in Android Malware
- [**25**星][3y] [Shell] [amoghbl1/orfox](https://github.com/amoghbl1/orfox) This is my repository for the orfox browser, a browser that uses tor to communicate and Firefox for Android as it's base.
- [**25**星][3y] [Java] [calebfenton/androidemulatordetect](https://github.com/calebfenton/androidemulatordetect) Android Emulator Detection
- [**25**星][5y] [Py] [fygrave/dnslyzer](https://github.com/fygrave/dnslyzer) DNS traffic indexer and analyzer
- [**25**星][1y] [Java] [sryze/wirebug](https://github.com/sryze/wirebug) Toggle Wi-Fi debugging on Android without a USB cable (needs root)
- [**25**星][5y] [wirelesscollege/securitytools](https://github.com/wirelesscollege/securitytools) android安全工具大全
- [**25**星][21d] [victorkifer/clicker](https://github.com/victorkifer/clicker) Wireless Presenter for Android and iOS, supports Windows, Linux and OS X
- [**24**星][8m] [appspector/android-sdk](https://github.com/appspector/android-sdk) AppSpector is a debugging service for mobile apps
- [**24**星][5y] [Py] [burningcodes/dexconfuse](https://github.com/burningcodes/dexconfuse) 简易dex混淆器
- [**23**星][3y] [Py] [skiddietech/hidaaf](https://github.com/skiddietech/hidaaf) Python - Human Interface Device Android Attack Framework
- [**22**星][2y] [JS] [feedhenry/mobile-security](https://github.com/feedhenry/mobile-security) FeedHenry Mobile Security
- [**22**星][1m] [Java] [orhun/k3pler](https://github.com/orhun/k3pler) Android network connection blocker and packet analyzer built on top of local HTTP proxy.
- [**22**星][7y] [brycethomas/liber80211](https://github.com/brycethomas/liber80211) 802.11 monitor mode for Android without root.
- [**20**星][2y] [C#] [vr-house/eazy-arcore-interface](https://github.com/vr-house/eazy-arcore-interface) Eazy ARCore Interface is a Unity3D plugin which makes development and debugging of ARCore projects easier. Specifically, it simulates how ARCore works in an Android device inside of Unity3D editor. Thus, it allows for faster development of ARCore apps, without the need to build and deploy to the device in order to test fuctionality
- [**20**星][11m] [Kotlin] [hacker1024/android-wifi-qr-code-generator](https://github.com/hacker1024/android-wifi-qr-code-generator) An android app that generates QR codes from your saved wifi networks.
- [**19**星][2y] [Java] [panagiotisdrakatos/t0rlib4android](https://github.com/panagiotisdrakatos/t0rlib4android) A minimal android controller library for Tor
- [**18**星][3y] [Java] [open-android/leakcanarydemo](https://github.com/open-android/leakcanarydemo) 内存泄漏检测工具，支持android studio eclipse
- [**18**星][1y] [Shell] [plowsec/android-ducky](https://github.com/plowsec/android-ducky) Rubber Ducky with Android
- [**16**星][7m] [zyrikby/stadyna](https://github.com/zyrikby/stadyna) Addressing the Problem of Dynamic Code Updates in the Security Analysis of Android Applications
- [**15**星][2y] [Kotlin] [ttymsd/traffic-monitor](https://github.com/ttymsd/traffic-monitor) traffic debugging library for android
- [**13**星][1y] [C] [gtoad/android_inline_hook_arm_example](https://github.com/gtoad/android_inline_hook_arm_example) 
- [**13**星][5y] [seattleandrew/digibrutedroid](https://github.com/seattleandrew/digibrutedroid) A 4-Digit PIN Brute Force attack for USB-OTG Android devices
- [**12**星][2y] [Java] [1van/activityhijacker](https://github.com/1van/activityhijacker) Hijack and AntiHijack for Android activity.
- [**12**星][11m] [C++] [vito11/camerahook](https://github.com/vito11/camerahook) An prototype to hook android camera preview data of third-party and system apps
- [**10**星][1y] [C] [gtoad/android_inline_hook_thumb_example](https://github.com/gtoad/android_inline_hook_thumb_example) 
- [**10**星][2m] [Rust] [timvisee/apbf](https://github.com/timvisee/apbf) Tool to brute force Android security pattern through TWRP recovery.
- [**10**星][2y] [Java] [yesterselga/password-strength-checker-android](https://github.com/yesterselga/password-strength-checker-android) Check password strength (Weak, Medium, Strong, Very Strong). Setting optional requirements by required length, with at least 1 special character, numbers and letters in uppercase or lowercase.
- [**7**星][5y] [Perl] [pentestpartners/android](https://github.com/pentestpartners/android) android
- [**7**星][2m] [Rust] [superandroidanalyzer/abxml-rs](https://github.com/superandroidanalyzer/abxml-rs) Android binary XML decoding library in Rust.
- [**6**星][4y] [Java] [cspf-founder/dodovulnerablebank](https://github.com/cspf-founder/dodovulnerablebank) Insecure Vulnerable Android Application that helps to learn hacing and securing apps
- [**6**星][12m] [Py] [datadancer/hiafuzz](https://github.com/datadancer/hiafuzz) Hybrid Interface Aware Fuzz for Android Kernel Drivers
- [**6**星][4y] [praveshagrawal/droid-toolkit](https://github.com/praveshagrawal/droid-toolkit) A complete toolkit for Android Hacking
- [**6**星][1y] [Java] [nishchalraj/passwordstrengthbar](https://github.com/nishchalraj/passwordstrengthbar) An android library to show the password strength using four strength bars with colours set for each.
- [**5**星][10m] [Java] [ioactive/aosp-downloadproviderheadersdumper](https://github.com/ioactive/aosp-downloadproviderheadersdumper) PoC Exploiting Headers Disclosure in Android's Download Provider (CVE-2018-9546)
- [**5**星][6y] [Java] [lanrat/wifi_recovery](https://github.com/lanrat/wifi_recovery) A simple android application to retrieve saved WIFI passwords
- [**5**星][2y] [TeX] [pietroborrello/android-malware-detection](https://github.com/pietroborrello/android-malware-detection) Detecting malicious android programs through ML techniques
- [**5**星][2y] [rev-code/androidclient](https://github.com/rev-code/androidclient) Android remote administration client
- [**5**星][t] [YARA] [qeeqbox/analyzer](https://github.com/qeeqbox/analyzer) Threat intelligence framework for extracting artifacts and IoCs from Windows, Linux, Android, iPhone, Blackberry, macOS binaries and more
- [**4**星][1y] [Py] [51j0/android-storage-extractor](https://github.com/51j0/android-storage-extractor) A tool to extract local data storage of an Android application in one click.
- [**4**星][7y] [Java] [asudhak/android-malware](https://github.com/asudhak/android-malware) Android Malware POC for CSC591
- [**4**星][2y] [Java] [flintx/airmanager](https://github.com/flintx/airmanager) 第九届全国大学生信息安全竞赛 参赛作品 Android部分
- [**4**星][2y] [Java] [fooock/shodand](https://github.com/fooock/shodand) Console and Android native Shodan application. Developed using MVP architecture, RxJava, Butterknife, zxing and more! Looking for collaborators, join now!
- [**4**星][2y] [TeX] [gelldur/msc-thesis](https://github.com/gelldur/msc-thesis) Master's Thesis: Decompiling Android OS applications
- [**4**星][6y] [C] [lance0312/vulnapp](https://github.com/lance0312/vulnapp) A vulnerable Android app
- [**4**星][4y] [C] [mono-man/kgdb-android](https://github.com/mono-man/kgdb-android) Patches to the Nexus 6 (Shamu) kernel source to allow KGDB over serial debug cable
- [**4**星][8m] [Java] [netdex/android-hid-script](https://github.com/netdex/android-hid-script) An Android app that allows you to script HID emulation tasks.
- [**4**星][3y] [OpenEdge ABL] [sp2014/android-malware-detector](https://github.com/sp2014/android-malware-detector) A machine learning based Android malware detection model.
- [**4**星][3y] [Java] [b00sti/wifi-analyzer](https://github.com/b00sti/wifi-analyzer) Analyzer 802.11 networks - android app [to refactor]
- [**4**星][6y] [Py] [sushant-hiray/android-malware-detection](https://github.com/sushant-hiray/android-malware-detection) Storehouse of scripts/code snippets corresponding to the current RnD project.
- [**3**星][7y] [Java] [alaasalman/aids](https://github.com/alaasalman/aids) Proof of concept Android Intrusion Detection System.
- [**3**星][2y] [Java] [alexeyzatsepin/cp-tester](https://github.com/alexeyzatsepin/cp-tester) Android application for finding vulnerabilities in all of content providers based on SQLite databases on your device with sql-injection
- [**3**星][3y] [Kotlin] [alilotfi/virustotalclient](https://github.com/alilotfi/virustotalclient) VirusTotal for Android checks the applications installed in your Android phone against VirusTotal (
- [**3**星][Py] [btx3/ipwebcam-destroyer](https://github.com/btx3/ipwebcam-destroyer) Android IP Webcam DoS Tool
- [**3**星][10m] [d4wu/unity3d-android-reverse-demo](https://github.com/d4wu/unity3d-android-reverse-demo) 
- [**3**星][6y] [C] [hiikezoe/libfb_mem_exploit](https://github.com/hiikezoe/libfb_mem_exploit) CVE-2013-2596 exploit for android
- [**3**星][2y] [Java] [leetcodes/poc-android-malware](https://github.com/leetcodes/poc-android-malware) A simple andorid malware uploading basic info to remote server
- [**3**星][5y] [Py] [niejuhu/pocs](https://github.com/niejuhu/pocs) Android漏洞验证程序
- [**3**星][9m] [Java] [pangodream/claudioremote](https://github.com/pangodream/claudioremote) Simple android App to show Claudio remote configuration capabilities
- [**3**星][3y] [prashantmi/android-h](https://github.com/prashantmi/android-h) Android Hacker is a software based on ADB (Android Debug Bridge) and can compromise any "Android Device"
- [**3**星][1y] [Shell] [wazehell/android-usb-pwn](https://github.com/wazehell/android-usb-pwn) simple script to pwn android phone with physical access
- [**3**星][2y] [Java] [threedr3am/ctf-android-writeup](https://github.com/xuanyonghao/ctf-android-writeup) 很久以前参加CTF比赛做出来的部分Android逆向题目wp（瞎写，自用记录）
- [**3**星][6y] [zoobab/busybox-static-for-android](https://github.com/zoobab/busybox-static-for-android) A static busybox for android
- [**3**星][3y] [Py] [zyrikby/fsquadra2](https://github.com/zyrikby/fsquadra2) Evaluation of Resource-based App Repackaging Detection in Android
- [**3**星][12y] [C] [bcopeland/android_packetspammer](https://github.com/bcopeland/android_packetspammer) packetspammer for android
- [**3**星][8m] [Visual Basic .NET] [pericena/apkdcx](https://github.com/pericena/apkdcx) Los programas nos ayudara a poder descomprimir o descompilar las aplicaciones que son desarrollada en Android, con la extensión”.apk “para poder modificar el código y mejorar la aplicación.
- [**2**星][2y] [androidtamer/awesome_android_pentest](https://github.com/androidtamer/awesome_android_pentest) Awesome android Pentest tools collection
- [**2**星][10m] [Shell] [b15mu7h/androidmalwarezoo](https://github.com/b15mu7h/androidmalwarezoo) A Collection of Android Malware
- [**2**星][12m] [Java] [b3nac/injuredandroid](https://github.com/b3nac/injuredandroid) A vulnerable Android application that shows simple examples of vulnerabilities in a ctf style.
- [**2**星][3y] [Py] [kr1shn4murt1/exploit-ms-17-010](https://github.com/kr1shn4murt1/exploit-ms-17-010) Exploit para vulnerabilidad ms17-010 desde android
- [**2**星][5y] [Py] [lanninghuanxue/droidj](https://github.com/lanninghuanxue/droidj) A System for Android Malware Detection and Analysis
- [**2**星][5y] [D] [monstersb/arpdetection](https://github.com/monstersb/arpdetection) Arp attack detection for android
- [**2**星][2y] [TeX] [neutze/master-latex-thesis](https://github.com/neutze/master-latex-thesis) Master's Thesis "Analysis of Android Cracking Tools and Investigations in Counter Measurements for Developers" at Fakultät für Informatik of Technische Universität München
- [**2**星][5y] [Java] [nodoraiz/latchhooks](https://github.com/nodoraiz/latchhooks) Hack for Android app hooking using latch
- [**2**星][2y] [Py] [pypygeek/amiv](https://github.com/pypygeek/AMIV) Android Malware Info Visibility Tool
- [**2**星][6y] [yangwenbo/resetpin](https://github.com/yangwenbo/resetpin) POC of Android Fragment Injection vulnerability, about reset PIN
- [**2**星][2m] [C++] [bootak/touchlogger-android-client](https://github.com/BOOtak/touchlogger-android-client) Log all gestures on android phone without root permissions (developer options enabled required!)
- [**1**星][1y] [Shell] [backtrackcroot/androidtoolbox](https://github.com/backtrackcroot/androidtoolbox) A android decompile tool set.
- [**1**星][3y] [Java] [ctf/ctf-android](https://github.com/ctf/ctf-android) Source code for CTF's Android app
- [**1**星][3y] [C++] [cvvt/challenge_for_ctf](https://github.com/cvvt/challenge_for_ctf) Source code of android challenges for capturing the flag
- [**1**星][7y] [C] [gerasiov/abootimg-android](https://github.com/gerasiov/abootimg-android) Android build of abootimg
- [**1**星][6y] [huyle333/androidmitllctf2013](https://github.com/huyle333/androidmitllctf2013) BUILDS Team 2 Android code from the MIT LL CTF 2013 for future reference. A list of APK files with different functions.
- [**1**星][8y] [Java] [rajasaur/ctfdroid](https://github.com/rajasaur/ctfdroid) Android app for talking to Forge
- [**1**星][4y] [Java] [sushanthikshwaku/antiv](https://github.com/sushanthikshwaku/antiv) Anti virus app for android using VirusTotal
- [**1**星][2y] [Py] [tum-i22/localizing-android-malicious-behaviors](https://github.com/tum-i22/localizing-android-malicious-behaviors) Initial implementation of a method to localize malicious behaviors from API call traces of Android apps
- [**1**星][8y] [utkanos/android_device_htc_rezound](https://github.com/utkanos/android_device_htc_rezound) working POC device for building bootable recovery
- [**1**星][8y] [utkanos/android_device_htc_vigor](https://github.com/utkanos/android_device_htc_vigor) poc cwmr port for htc rezound
- [**1**星][12m] [Java] [oxagast/ansvif_android](https://github.com/oxagast/ansvif_android) An Android frontend for ansvif fuzzing
- [**1**星][4y] [C] [ru-faraon/pixiewps-android](https://github.com/ru-faraon/pixiewps-android) 
- [**1**星][6y] [PHP] [akibsayyed/poc-android-malware-files](https://github.com/akibsayyed/poc-android-malware-files) PHP Files for Android malware
- [**0**星][5y] [Java] [anonim1133/ctf](https://github.com/anonim1133/ctf) Simple Android app to play Caputre The Flag. By using GPS and wifi it allows you to "capture the flags".
- [**0**星][3y] [Java] [artwyman/android_ctf](https://github.com/artwyman/android_ctf) 
- [**0**星][2y] [Py] [bizdak/silverboxcc](https://github.com/bizdak/silverboxcc) Reverse engineered android malware, and this is a C&C server for it
- [**0**星][7m] [Py] [brant-ruan/idf4apev](https://github.com/brant-ruan/idf4apev) Integrated Detection Framework for Android's Privilege Escalation Vulnerabilites
- [**0**星][4y] [C] [c0d3st0rm/android_kernel_tesco_ht7s3](https://github.com/c0d3st0rm/android_kernel_tesco_ht7s3) Android kernel source for Tesco's first Hudl (HT7S3). This is here only for reference, as Tesco don't host kernel sources anymore, and is unbuildable - the kernel configs are missing and so are some of the essential parts of the kernel, eg WiFi drivers.
- [**0**星][2y] [chicharitomu14/android-hover-attack-document](https://github.com/chicharitomu14/android-hover-attack-document) A document about Android Hover Attack in Chinese, organized from the paper “Using Hover to Compromise the Confidentiality of User Input on Android”
- [**0**星][7y] [ctfk/cl.ctfk](https://github.com/ctfk/cl.ctfk) Android CTF Game
- [**0**星][6y] [Java] [ctz/android-keystore](https://github.com/ctz/android-keystore) POC for Android keystore leak
- [**0**星][4m] [Perl] [debos99/droidvenom](https://github.com/debos99/droidvenom) DroidVenom is simple perl script for creating custom payload for android
- [**0**星][6y] [C] [enjens/android_kernel_sony_pollux_windy_stock](https://github.com/enjens/android_kernel_sony_pollux_windy_stock) Stock kernel with kexec patches for Sony Tablet Z WIFI
- [**0**星][4y] [Py] [eward9/android-backdoor-factory](https://github.com/eward9/android-backdoor-factory) 
- [**0**星][3y] [Java] [fathulkirom22/androidctf](https://github.com/fathulkirom22/androidctf) 
- [**0**星][6y] [Groovy] [jhong01/ctfpro](https://github.com/jhong01/ctfpro) Android Capture the Flag Pro
- [**0**星][5y] [Java] [kappaetakappa/robot-ctf-android](https://github.com/kappaetakappa/robot-ctf-android) Controller software for the Expo project
- [**0**星][10m] [Smali] [moviet/space-ghost](https://github.com/moviet/space-ghost) A simple example source codes of an initial android app cloner
- [**0**星][1y] [paradox5566/evihunter](https://github.com/paradox5566/evihunter) EviHunter is a static program analysis tool for parsing the evidentiary data from Android apps.
- [**0**星][5y] [preethams2/m_analysis](https://github.com/preethams2/m_analysis) Android malware tuts
- [**0**星][5y] [qwertgfdvgjh/xmanager](https://github.com/qwertgfdvgjh/xmanager) xManager-手机安全卫士/练手Android项目，自己独立开发
- [**0**星][3y] [Java] [sanjeet990/android-antivirus-project](https://github.com/sanjeet990/android-antivirus-project) This is an Antivirus project for Android that I created for my college project.
- [**0**星][3y] [serval-snt-uni-lu/hookranker](https://github.com/serval-snt-uni-lu/hookranker) Automatically Locating Malicious Payload in Piggybacked Android Apps (A Hook Ranking Approach)
- [**0**星][2y] [Java] [toulousehackingconvention/bestpig-reverse-android-serial](https://github.com/toulousehackingconvention/bestpig-reverse-android-serial) THC CTF 2018 - Reverse - Android serial
- [**0**星][7y] [C] [tvall43/android_kernel_grouper](https://github.com/tvall43/android_kernel_grouper) kernel for the Google Asus Nexus 7 (2012) Wifi (insane naming system, right?)
- [**0**星][5y] [vaginessa/kali_launcher_android_app](https://github.com/vaginessa/kali_launcher_android_app) Android Application to launch Kali Android chroot.
- [**0**星][6m] [C] [alex91ar/gdb-multiarch](https://github.com/alex91ar/gdb-multiarch) Patched GDB-Multiarch to debug android Kernels.


### <a id="883a4e0dd67c6482d28a7a14228cd942"></a>新添加的


- [**157**星][2m] [Java] [reddr/libscout](https://github.com/reddr/libscout) Third-party library detector for Java/Android apps
- [**154**星][3m] [Java] [rednaga/axmlprinter](https://github.com/rednaga/axmlprinter) Library for parsing and printing compiled Android manifest files
- [**149**星][2y] [Py] [mhelwig/apk-anal](https://github.com/mhelwig/apk-anal) Android APK analyzer based on radare2 and others.
    - 重复区段: [Radare2->插件->新添加的](#6922457cb0d4b6b87a34caf39aa31dfe) |
- [**146**星][10m] [Java] [lanchon/haystack](https://github.com/lanchon/haystack) Signature Spoofing Patcher for Android
- [**142**星][2m] [Java] [joshjdevl/libsodium-jni](https://github.com/joshjdevl/libsodium-jni) (Android) Networking and Cryptography Library (NaCL) JNI binding. JNI is utilized for fastest access to native code. Accessible either in Android or Java application. Uses SWIG to generate Java JNI bindings. SWIG definitions are extensible to other languages.
- [**139**星][3m] [nathanchance/android-kernel-clang](https://github.com/nathanchance/android-kernel-clang) Information on compiling Android kernels with Clang
- [**137**星][9m] [Py] [ale5000-git/tingle](https://github.com/ale5000-git/tingle) Android patcher
- [**136**星][3y] [Batchfile] [eliteandroidapps/whatsapp-key-db-extractor](https://github.com/eliteandroidapps/whatsapp-key-db-extractor) Allows WhatsApp users to extract their cipher key and databases on non-rooted Android devices.
- [**132**星][5y] [C] [hiteshd/android-rootkit](https://github.com/hiteshd/android-rootkit) A rootkit for Android. Based on "Android platform based linux kernel rootkit" from Phrack Issue 68
- [**129**星][3m] [Shell] [exalab/anlinux-resources](https://github.com/exalab/anlinux-resources) Image and Script for LinuxOnAndroid App
- [**127**星][2m] [osm0sis/android-busybox-ndk](https://github.com/osm0sis/android-busybox-ndk) Keeping track of instructions and patches for building busybox with the Android NDK
- [**122**星][4y] [irsl/adb-backup-apk-injection](https://github.com/irsl/adb-backup-apk-injection) Android ADB backup APK Injection POC
- [**121**星][7y] [Py] [liato/android-market-api-py](https://github.com/liato/android-market-api-py) A Python port of the java Android Market API.
- [**120**星][10m] [Java] [securityfirst/umbrella_android](https://github.com/securityfirst/umbrella_android) Digital and Physical Security Advice App
- [**120**星][2m] [C++] [stealth/lophttpd](https://github.com/stealth/lophttpd) lots of performance (or lots of porn, if you prefer) httpd: Easy, chrooted, fast and simple to use HTTP server for static content. Runs on Linux, BSD, Android and OSX/Darwin. It's free but if you like it, consider donating to the EFF:
- [**119**星][1m] [Kotlin] [babylonhealth/certificate-transparency-android](https://github.com/babylonhealth/certificate-transparency-android) Certificate transparency for Android and Java
- [**118**星][4m] [Java] [andprox/andprox](https://github.com/andprox/andprox) Native Android Proxmark3 client (no root required)
- [**117**星][2m] [Java] [auth0/lock.android](https://github.com/auth0/lock.android) Android Library to authenticate using Auth0 and with a Native Look & Feel
- [**117**星][3y] [Java] [rafaeltoledo/android-security](https://github.com/rafaeltoledo/android-security) An app showcase of some techniques to improve Android app security
- [**114**星][7m] [Py] [alexmyg/andropytool](https://github.com/alexmyg/andropytool) A framework for automated extraction of static and dynamic features from Android applications
- [**113**星][4y] [Java] [evilsocket/pdusms](https://github.com/evilsocket/pdusms) PoC app for raw pdu manipulation on Android.
- [**109**星][2y] [C] [pbatard/bootimg-tools](https://github.com/pbatard/bootimg-tools) Android boot.img creation and extraction tools [NOTE: This project is NO LONGER maintained]
- [**104**星][11d] [Py] [virb3/apk-utilities](https://github.com/virb3/apk-utilities) Tools and scripts to manipulate Android APKs
- [**104**星][12m] [Java] [varunon9/remote-control-pc](https://github.com/varunon9/remote-control-pc) Control Laptop using Android. Remote control PC consists of android as well as desktop app written in Java to control laptop using phone.
- [**103**星][9m] [C++] [quarkslab/android-restriction-bypass](https://github.com/quarkslab/android-restriction-bypass) PoC to bypass Android restrictions
- [**99**星][11m] [winterssy/miui-purify](https://github.com/winterssy/miui-purify) 个人兴趣项目存档，使用 apktool 魔改 MIUI ROM，去除 MIUI 系统新增的广告。
- [**97**星][4y] [Java] [zencodex/hack-android](https://github.com/zencodex/hack-android) Collection tools for hack android, java
- [**95**星][4m] [Java] [dexpatcher/dex2jar](https://github.com/dexpatcher/dex2jar) Unofficial dex2jar builds
- [**92**星][10d] [Py] [imtiazkarimik23/atfuzzer](https://github.com/imtiazkarimik23/atfuzzer) "Opening Pandora's Box through ATFuzzer: Dynamic Analysis of AT Interface for Android Smartphones" ACSAC 2019
- [**91**星][2y] [Java] [5gsd/aimsicdl](https://github.com/5gsd/aimsicdl) AIMSICD Lite (Android IMSI-Catcher Detector) - reloaded!
- [**90**星][3y] [Java] [mingyuan-xia/patdroid](https://github.com/mingyuan-xia/patdroid) A Program Analysis Toolkit for Android
- [**90**星][8y] [Java] [securitycompass/androidlabs](https://github.com/securitycompass/androidlabs) Android security labs
- [**88**星][1y] [ObjC] [cmackay/google-analytics-plugin](https://github.com/cmackay/google-analytics-plugin) Cordova Google Analytics Plugin for Android & iOS
- [**88**星][3m] [Scala] [rsertelon/android-keystore-recovery](https://github.com/rsertelon/android-keystore-recovery) A tool to recover your lost Android keystore password
- [**86**星][3y] [Py] [ucsb-seclab/baredroid](https://github.com/ucsb-seclab/baredroid) bare-metal analysis on Android devices
- [**85**星][7y] [Java] [thomascannon/android-sms-spoof](https://github.com/thomascannon/android-sms-spoof) PoC app which takes advantage of Android's SmsReceiverService being exported to fake an incoming SMS with no permissions.
- [**84**星][2y] [Kotlin] [viktordegtyarev/callreclib](https://github.com/viktordegtyarev/callreclib) Call Recorder fix for Android 7 and Android 6
- [**81**星][4y] [Py] [android-dtf/dtf](https://github.com/android-dtf/dtf) Android Device Testing Framework ("dtf")
- [**80**星][12m] [Java] [thelinuxchoice/droidtracker](https://github.com/thelinuxchoice/droidtracker) Script to generate an Android App to track location in real time
- [**79**星][3m] [Py] [sashs/filebytes](https://github.com/sashs/filebytes) Library to read and edit files in the following formats: Executable and Linking Format (ELF), Portable Executable (PE), MachO and OAT (Android Runtime)
- [**77**星][t] [HTML] [android-x86/android-x86.github.io](https://github.com/android-x86/android-x86.github.io) Official Website for Android-x86 Project
- [**77**星][2y] [C++] [daizhongyin/securitysdk](https://github.com/daizhongyin/securitysdk) Android安全SDK，提供基础的安全防护能力，如安全webview、IPC安全通信、应用和插件安全更新、威胁情报搜集等等
- [**77**星][11d] [Py] [nightwatchcybersecurity/truegaze](https://github.com/nightwatchcybersecurity/truegaze) Static analysis tool for Android/iOS apps focusing on security issues outside the source code
- [**76**星][3y] [Py] [moosd/needle](https://github.com/moosd/needle) Android framework injection made easy
- [**75**星][3y] [Java] [guardianproject/cacheword](https://github.com/guardianproject/cacheword) a password caching and management service for Android
- [**74**星][3m] [Ruby] [devunwired/apktools](https://github.com/devunwired/apktools) Ruby library for reading/parsing APK resource data
- [**73**星][2y] [C++] [vusec/guardion](https://github.com/vusec/guardion) Android GuardION patches to mitigate DMA-based Rowhammer attacks on ARM
- [**71**星][4y] [Py] [programa-stic/marvin-django](https://github.com/programa-stic/marvin-django) Marvin-django is the UI/database part of the Marvin project. Marvin is a platform for security analysis of Android apps.
- [**70**星][2y] [androidtamer/androidtamer](https://github.com/androidtamer/androidtamer) We Use Github Extensively and openly. So it becomes dificult to track what's what and what's where. This repository is a master repo to Help with that.
- [**69**星][15d] [Java] [auth0/auth0.android](https://github.com/auth0/auth0.android) Android toolkit for Auth0 API
- [**68**星][1y] [Shell] [kiyadesu/android](https://github.com/kiyadesu/Android) walk into Android security step by step
- [**66**星][11m] [Py] [yelp/parcelgen](https://github.com/yelp/parcelgen) Helpful tool to make data objects easier for Android
- [**65**星][5y] [Java] [guardianproject/trustedintents](https://github.com/guardianproject/trustedintents) library for flexible trusted interactions between Android apps
- [**65**星][6y] [Java] [ibrahimbalic/androidrat](https://github.com/ibrahimbalic/androidrat) Android RAT
- [**65**星][6y] [C++] [trevd/android_root](https://github.com/trevd/android_root) Got Root!
- [**65**星][8y] [C] [robclemons/arpspoof](https://github.com/robclemons/Arpspoof) Android port of Arpspoof
- [**64**星][3m] [Java] [flankerhqd/bindump4j](https://github.com/flankerhqd/bindump4j) A portable utility to locate android binder service
- [**64**星][7y] [C] [hiikezoe/android_run_root_shell](https://github.com/hiikezoe/android_run_root_shell) 
- [**62**星][2y] [C] [wlach/orangutan](https://github.com/wlach/orangutan) Simulate native events on Android-like devices
- [**61**星][7y] [Java] [intrepidusgroup/iglogger](https://github.com/intrepidusgroup/iglogger) Class to help with adding logging function in smali output from 3rd party Android apps.
- [**58**星][5y] [C] [poliva/dexinfo](https://github.com/poliva/dexinfo) A very rudimentary Android DEX file parser
- [**58**星][1m] [Kotlin] [m1dr05/istheapp](https://github.com/m1dr05/istheapp) Open-source android spyware
- [**57**星][2y] [Java] [amotzte/android-mock-location-for-development](https://github.com/amotzte/android-mock-location-for-development) allows to change mock location from command line on real devices
- [**56**星][1y] [C] [jduck/canhazaxs](https://github.com/jduck/canhazaxs) A tool for enumerating the access to entries in the file system of an Android device.
- [**55**星][1y] [JS] [enovella/androidtrainings](https://github.com/enovella/androidtrainings) Mobile security trainings based on android
- [**55**星][6m] [Java] [pnfsoftware/jeb2-androsig](https://github.com/pnfsoftware/jeb2-androsig) Android Library Code Recognition
- [**55**星][3d] [Java] [gedsh/invizible](https://github.com/gedsh/invizible) Android application for Internet privacy and security
- [**55**星][3y] [Java] [giovannicolonna/msfvenom-backdoor-android](https://github.com/giovannicolonna/msfvenom-backdoor-android) Android backdoored app, improved source code of msfvenom android .apk
- [**53**星][2y] [Java] [modzero/modjoda](https://github.com/modzero/modjoda) Java Object Deserialization on Android
- [**53**星][2m] [Py] [nelenkov/android-device-check](https://github.com/nelenkov/android-device-check) Check Android device security settings
- [**53**星][3y] [Shell] [nvssks/android-responder](https://github.com/nvssks/android-responder) Scripts for running Responder.py in an Android (rooted) device.
- [**53**星][5y] [Java] [thuxnder/androiddevice.info](https://github.com/thuxnder/androiddevice.info) Android app collecting device information and submiting it to
- [**53**星][1m] [Py] [ucsb-seclab/agrigento](https://github.com/ucsb-seclab/agrigento) Agrigento is a tool to identify privacy leaks in Android apps by performing black-box differential analysis on the network traffic.
- [**50**星][5y] [Java] [retme7/broadanywhere_poc_by_retme_bug_17356824](https://github.com/retme7/broadanywhere_poc_by_retme_bug_17356824) a poc of Android bug 17356824
- [**48**星][3y] [Shell] [osm0sis/apk-patcher](https://github.com/osm0sis/apk-patcher) Patch APKs on-the-fly from Android recovery (Proof of Concept)
- [**48**星][5y] [C++] [sogeti-esec-lab/android-fde](https://github.com/sogeti-esec-lab/android-fde) Tools to work on Android Full Disk Encryption (FDE).
- [**48**星][7y] [tias/android-busybox-ndk](https://github.com/tias/android-busybox-ndk) Keeping track of instructions and patches for building busybox with the android NDK
- [**47**星][3y] [Py] [alessandroz/pupy](https://github.com/alessandroz/pupy) Pupy is an opensource, multi-platform (Windows, Linux, OSX, Android), multi function RAT (Remote Administration Tool) mainly written in python. It features a all-in-memory execution guideline and leaves very low footprint. Pupy can communicate using various transports, migrate into processes (reflective injection), load remote python code, pytho…
- [**47**星][6m] [Java] [tlamb96/kgb_messenger](https://github.com/tlamb96/kgb_messenger) An Android CTF practice challenge
- [**46**星][5m] [Py] [cryptax/angeapk](https://github.com/cryptax/angeapk) Encrypting a PNG into an Android application
- [**46**星][1y] [Java] [kaushikravikumar/realtimetaxiandroiddemo](https://github.com/kaushikravikumar/realtimetaxiandroiddemo) PubNub Demo that uses a Publish/Subscribe model to implement a realtime map functionality similar to Lyft/Uber.
- [**44**星][2y] [Java] [m301/rdroid](https://github.com/m301/rdroid) [Android RAT] Remotely manage your android phone using PHP Interface
- [**43**星][10m] [Kotlin] [cbeuw/cloak-android](https://github.com/cbeuw/cloak-android) Android client of Cloak
- [**42**星][3m] [Java] [nowsecure/cybertruckchallenge19](https://github.com/nowsecure/cybertruckchallenge19) Android security workshop material taught during the CyberTruck Challenge 2019 (Detroit USA).
- [**41**星][4y] [C] [sesuperuser/super-bootimg](https://github.com/sesuperuser/super-bootimg) Tools to edit Android boot.img. NDK buildable, to be usable in an update.zip
- [**41**星][2y] [Shell] [xtiankisutsa/twiga](https://github.com/xtiankisutsa/twiga) twiga：枚举 Android 设备，获取了解其内部部件和漏洞利用的信息
- [**40**星][2y] [Java] [ivianuu/contributer](https://github.com/ivianuu/contributer) Inject all types like views or a conductor controllers with @ContributesAndroidInjector
- [**40**星][7y] [C++] [taintdroid/android_platform_dalvik](https://github.com/taintdroid/android_platform_dalvik) Mirror of git://android.git.kernel.org/platform/dalvik.git with TaintDroid additions (mirror lags official Android)
- [**40**星][5y] [Java] [tacixat/cfgscandroid](https://github.com/TACIXAT/CFGScanDroid) Control Flow Graph Scanning for Android
- [**40**星][12m] [Java] [thelinuxchoice/droidcam](https://github.com/thelinuxchoice/droidcam) Script to generate an Android App to take photos from Cameras
- [**39**星][5y] [C] [cyanogenmod/android_external_openssl](https://github.com/cyanogenmod/android_external_openssl) OpenSSL for Android
- [**39**星][1y] [Py] [sundaysec/andspoilt](https://github.com/sundaysec/andspoilt) Run interactive android exploits in linux.
- [**38**星][7m] [Java] [pnfsoftware/jnihelper](https://github.com/pnfsoftware/jnihelper) jeb-plugin-android-jni-helper
- [**37**星][5d] [Java] [cliqz-oss/browser-android](https://github.com/cliqz-oss/browser-android) CLIQZ for Android
- [**37**星][4y] [Java] [julianschuette/condroid](https://github.com/julianschuette/condroid) Symbolic/concolic execution of Android apps
- [**35**星][6m] [Py] [bkerler/dump_avb_signature](https://github.com/bkerler/dump_avb_signature) Dump Android Verified Boot Signature
- [**35**星][6y] [C#] [redth/android.signature.tool](https://github.com/redth/android.signature.tool) Simple GUI tool for Mac and Windows to help find the SHA1 and MD5 hashes of your Android keystore's and apk's
- [**35**星][3y] [Java] [serval-snt-uni-lu/droidra](https://github.com/serval-snt-uni-lu/droidra) Taming Reflection to Support Whole-Program Analysis of Android Apps
- [**34**星][2y] [hardenedlinux/armv7-nexus7-grsec](https://github.com/hardenedlinux/armv7-nexus7-grsec) Hardened PoC: PaX for Android
- [**34**星][10m] [Kotlin] [cbeuw/goquiet-android](https://github.com/cbeuw/goquiet-android) GoQuiet plugin on android
- [**33**星][1y] [C] [jp-bennett/fwknop2](https://github.com/jp-bennett/fwknop2) A replacement fwknop client for android.
- [**33**星][3y] [Java] [riramar/pubkey-pin-android](https://github.com/riramar/pubkey-pin-android) Just another example for Android Public Key Pinning (based on OWASP example)
- [**33**星][6m] [Shell] [robertohuertasm/apk-decompiler](https://github.com/robertohuertasm/apk-decompiler) Small Rust utility to decompile Android apks
- [**32**星][2y] [dweinstein/dockerfile-androguard](https://github.com/dweinstein/dockerfile-androguard) docker file for use with androguard python android app analysis tool
- [**30**星][4m] [Py] [azmatt/anaximander](https://github.com/azmatt/anaximander) Python Code to Map Cell Towers From a Cellebrite Android Dump
- [**30**星][7m] [Java] [pnfsoftware/jeb2-plugin-oat](https://github.com/pnfsoftware/jeb2-plugin-oat) Android OAT Plugin for JEB
- [**30**星][2y] [Java] [amitshekhariitbhu/applock](https://github.com/amitshekhariitbhu/applock) Android Application for app lock
- [**29**星][1y] [C] [calebfenton/native-harness-target](https://github.com/calebfenton/native-harness-target) Android app for demonstrating native library harnessing
- [**29**星][25d] [JS] [fsecurelabs/android-keystore-audit](https://github.com/fsecurelabs/android-keystore-audit) 
- [**28**星][3y] [Java] [martinstyk/apkanalyzer](https://github.com/martinstyk/apkanalyzer) Java tool for analyzing Android APK files
- [**27**星][4y] [C] [anarcheuz/android-pocs](https://github.com/anarcheuz/android-pocs) 
- [**27**星][2m] [Py] [cryptax/droidlysis](https://github.com/cryptax/droidlysis) Property extractor for Android apps
- [**27**星][3m] [grapheneos/os_issue_tracker](https://github.com/grapheneos/os_issue_tracker) Issue tracker for GrapheneOS Android Open Source Project hardening work. Standalone projects like Auditor, AttestationServer and hardened_malloc have their own dedicated trackers.
- [**26**星][1y] [Ruby] [ajitsing/apktojava](https://github.com/ajitsing/apktojava) View android apk as java code in gui
- [**25**星][3y] [zyrikby/android_permission_evolution](https://github.com/zyrikby/android_permission_evolution) Analysis of the evolution of Android permissions. This repository contains the results presented in the paper "Small Changes, Big Changes: An Updated View on the Android Permission System".
- [**25**星][11m] [Visual Basic .NET] [modify24x7/ultimate-advanced-apktool](https://github.com/modify24x7/ultimate-advanced-apktool) v4.1
- [**24**星][2y] [Java] [commonsguy/autofillfollies](https://github.com/commonsguy/autofillfollies) Demonstration of security issues with Android 8.0 autofill
- [**24**星][1y] [C++] [zsshen/yadd](https://github.com/zsshen/yadd) Yet another Android Dex bytecode Disassembler: a static Android app disassembler for fast class and method signature extraction and code structure visualization.
- [**24**星][4y] [Java] [stealthcopter/steganography](https://github.com/stealthcopter/steganography) Android Steganography Library
- [**24**星][1m] [Java] [snail007/goproxy-ss-plugin-android](https://github.com/snail007/goproxy-ss-plugin-android) goproxy安卓全局代理，ss goproxy安卓插件, goproxy :
- [**22**星][1m] [Smali] [aress31/sci](https://github.com/aress31/sci) Framework designed to automate the process of assembly code injection (trojanising) within Android applications.
- [**21**星][7y] [C] [0xroot/whitesnow](https://github.com/0xroot/whitesnow) An experimental rootkit for Android
- [**21**星][1y] [Smali] [dan7800/vulnerableandroidapporacle](https://github.com/dan7800/vulnerableandroidapporacle) 
- [**20**星][9m] [Rust] [gamozolabs/slime_tree](https://github.com/gamozolabs/slime_tree) Worst Android kernel fuzzer
- [**20**星][5y] [snifer/l4bsforandroid](https://github.com/snifer/l4bsforandroid) Repositorio de APK para Hacking y Seguridad
- [**19**星][3m] [C] [cybersaxostiger/androiddump](https://github.com/cybersaxostiger/androiddump) A tool pulls loaded binaries ordered by memory regions
- [**19**星][2m] [Java] [h3xstream/find-sec-bugs](https://github.com/h3xstream/find-sec-bugs) The FindBugs plugin for security audits of Java web applications and Android applications. (Also work with Scala and Groovy projects)
- [**19**星][5y] [Java] [juxing/adoreforandroid](https://github.com/juxing/adoreforandroid) Transplant adore rootkit for Android platform.
- [**19**星][5y] [C++] [trustonic/trustonic-tee-user-space](https://github.com/trustonic/trustonic-tee-user-space) Android user space components for the Trustonic Trusted Execution Environment
- [**18**星][3y] [C] [freddierice/farm-root](https://github.com/freddierice/farm-root) Farm root is a root for android devices using the dirty cow vulnerability
- [**18**星][7y] [Java] [jseidl/goldeneye-mobile](https://github.com/jseidl/goldeneye-mobile) GoldenEye Mobile Android Layer 7 HTTP DoS Test Tool
- [**18**星][4y] [Java] [meleap/myo_andoridemg](https://github.com/meleap/myo_andoridemg) We got the Myo's EMG-data on Android by hacking bluetooth.
- [**18**星][6y] [Java] [taufderl/whatsapp-sniffer-android-poc](https://github.com/taufderl/whatsapp-sniffer-android-poc) proof of concept app to show how to upload and decrypt WhatsApp backup database
- [**18**星][21d] [jqorz/biquge_crack](https://github.com/jqorz/biquge_crack) 笔趣阁_Android_去广告修改版（免费看小说！无广告！秒开无等待！）反编译学习
- [**17**星][3y] [bemre/bankbot-mazain](https://github.com/bemre/bankbot-mazain) 针对Android设备的开源手机银行木马BankBot / Mazain分析
- [**17**星][6y] [Py] [thomascannon/android-fde-decryption](https://github.com/thomascannon/android-fde-decryption) Cracking and decrypting Android Full Device Encryption
- [**17**星][6y] [Java] [fsecurelabs/mwr-android](https://github.com/FSecureLABS/mwr-android) A collection of utilities for Android applications.
- [**16**星][2y] [androidtamer/tools](https://github.com/androidtamer/tools) This website will be holding list / details of each and every tool available via Android Tamer
- [**16**星][4y] [lewisrhine/kotlin-for-android-developers-zh](https://github.com/lewisrhine/kotlin-for-android-developers-zh) Kotlin for android developers in chinese.
- [**15**星][2y] [C++] [chenzhihui28/securitydemo](https://github.com/chenzhihui28/securitydemo) ndk进行简单的签名校验，密钥保护demo,android应用签名校验
- [**15**星][4m] [hyrathon/hitcon2019](https://github.com/hyrathon/hitcon2019) Slides(In both CN and EN) & WP(outdated) of my topic in HITCON 2019 about bug hunting in Android NFC
- [**15**星][7y] [Vim script] [jlarimer/android-stuff](https://github.com/jlarimer/android-stuff) Random scripts and files I use for Android reversing
- [**15**星][2y] [Java] [tanprathan/sievepwn](https://github.com/tanprathan/sievepwn) An android application which exploits sieve through android components.
- [**13**星][2y] [anelkaos/ada](https://github.com/anelkaos/ada) Android Automation Tool
- [**13**星][2y] [Scala] [fschrofner/glassdoor](https://github.com/fschrofner/glassdoor) glassdoor is a modern, autonomous security framework for Android APKs. POC, unmaintained unfortunately.
- [**13**星][6y] [Shell] [k3170makan/droidsploit](https://github.com/k3170makan/droidsploit) A collection of scripts to find common application vulnerabilities in Android Applications
- [**13**星][5y] [Py] [lifeasageek/morula](https://github.com/lifeasageek/morula) Morula is a secure replacement of Zygote to fortify weakened ASLR on Android
- [**13**星][12m] [Shell] [theyahya/android-decompile](https://github.com/theyahya/android-decompile) 
- [**12**星][3m] [Py] [clviper/droidstatx](https://github.com/clviper/droidstatx) Python tool that generates an Xmind map with all the information gathered and any evidence of possible vulnerabilities identified via static analysis. The map itself is an Android Application Pentesting Methodology component, which assists Pentesters to cover all important areas during an assessment.
- [**12**星][1y] [JS] [integrity-sa/android](https://github.com/integrity-sa/android) Repository with research related to Android
- [**12**星][7y] [Java] [jeffers102/keystorecracker](https://github.com/jeffers102/keystorecracker) Helps retrieve forgotten keystore passwords using your commonly used segments. Great for those forgotten Android keystore passphrases, which is exactly why I created this tool in the first place!
- [**12**星][3y] [Java] [miguelmarco/zcashpannel](https://github.com/miguelmarco/zcashpannel) An android front-end to the zcash wallet through onion services
- [**12**星][5y] [Java] [poliva/radare-installer](https://github.com/poliva/radare-installer) Application to easily download and install radare2 on android devices
- [**12**星][3y] [Py] [zyrikby/bboxtester](https://github.com/zyrikby/bboxtester) Tool to measure code coverage of Android applications when their source code is not available
- [**11**星][7m] [Java] [radare/radare2-installer](https://github.com/radare/radare2-installer) Application to easily download and install radare2 on android devices
- [**11**星][1y] [Java] [wishihab/wedefend-android](https://github.com/wishihab/wedefend-android) ⛔
- [**11**星][1y] [Java] [zjsnowman/hackandroid](https://github.com/zjsnowman/hackandroid) Android安全之 Activity 劫持与反劫持
- [**11**星][2y] [Java] [mandyonze/droidsentinel](https://github.com/Mandyonze/DroidSentinel) Analizador de tráfico para dispositivos Android potencialmente comprometidos como parte de una botnet orientado a detectar ataques DDoS.
- [**10**星][5y] [C] [christianpapathanasiou/defcon-18-android-rootkit-mindtrick](https://github.com/christianpapathanasiou/defcon-18-android-rootkit-mindtrick) Worlds first Google Android kernel rootkit as featured at DEF CON 18
- [**10**星][4y] [Java] [cyberscions/digitalbank](https://github.com/cyberscions/digitalbank) Android Digital Bank Vulnerable Mobile App
- [**9**星][3y] [C++] [android-art-intel/nougat](https://github.com/android-art-intel/nougat) ART-Extension for Android Nougat
- [**9**星][5y] [Shell] [bbqlinux/android-udev-rules](https://github.com/bbqlinux/android-udev-rules) 
- [**9**星][2y] [Java] [djkovrik/comicser](https://github.com/djkovrik/comicser) Udacity Android Developer Nanodegree - Capstone project.
- [**9**星][4y] [C] [ele7enxxh/fakeodex](https://github.com/ele7enxxh/fakeodex) modify field(modWhen, crc) in android odex file;安卓APP“寄生兽”漏洞
- [**9**星][2y] [Java] [optimistanoop/android-developer-nanodegree](https://github.com/optimistanoop/android-developer-nanodegree) This repo contains all 8 Apps developed during Udacity Android Developer Nanodegree. These all Apps met expectation during code review process of Udacity Android Developer Nanodegree.
- [**9**星][1y] [C#] [preemptive/protected-todoazureauth](https://github.com/preemptive/protected-todoazureauth) Example of protecting a Xamarin.Android app with Dotfuscator’s Root Check
- [**9**星][6m] [Go] [shosta/androsectest](https://github.com/shosta/androsectest) Automate the setup of your Android Pentest and perform automatically static tests
- [**9**星][1y] [Kotlin] [smartnsoft/android-monero-miner](https://github.com/smartnsoft/android-monero-miner) A minimal SDK that lets an integrator add a Monero Miner using the Javascript miner created by CoinHive. The Monero Miner can be used with any CoinHive address and is a proof of concept of an alternative to ad banners and interstitials for mobile app developers that want to get retributed for their work without spamming their users with bad adve…
- [**8**星][7y] [Py] [agnivesh/aft](https://github.com/agnivesh/aft) [Deprecated] Android Forensic Toolkit
- [**8**星][4y] [Java] [appknox/vulnerable-application](https://github.com/appknox/vulnerable-application) Test Android Application.
- [**8**星][2y] [JS] [checkmarx/webviewgoat](https://github.com/checkmarx/webviewgoat) A deliberately vulnerable Android application to demonstrate exfiltration scenarios
- [**8**星][10m] [C] [hcamael/android_kernel_pwn](https://github.com/hcamael/android_kernel_pwn) android kernel pwn
- [**8**星][6y] [Java] [fsecurelabs/mwr-tls](https://github.com/FSecureLABS/mwr-tls) A collection of utilities for interacting with SSL and X509 Certificates on Android.
- [**7**星][5y] [CSS] [dhirajongithub/owasp_kalp_mobile_project](https://github.com/dhirajongithub/owasp_kalp_mobile_project) OWASP KALP Mobile Project is an android application developed for users to view OWASP Top 10 (WEB and MOBILE) on mobile devices.
- [**7**星][2y] [Py] [sathish09/xender2shell](https://github.com/sathish09/xender2shell) 利用 web.xender.com 入侵用户的 Android 手机
- [**7**星][2m] [C++] [amrashraf/androshield](https://github.com/amrashraf/androshield) An ASP.NET web application that responsible of detecting and reporting vulnerabilities in android applications by static and dynamic analysis methodologies.
- [**6**星][2y] [C#] [advancedhacker101/android-c-sharp-rat-server](https://github.com/advancedhacker101/android-c-sharp-rat-server) This is a plugin for the c# R.A.T server providing extension to android based phone systems
- [**6**星][11m] [as0ler/android-examples](https://github.com/as0ler/android-examples) APK's used as example Apps for decompiling
- [**6**星][5m] [Py] [h1nayoshi/smalien](https://github.com/h1nayoshi/smalien) Information flow analysis tool for Android applications
- [**6**星][2y] [Py] [silentsignal/android-param-annotate](https://github.com/silentsignal/android-param-annotate) Android parameter annotator for Dalvik/Smali disassembly
- [**6**星][3y] [Java] [theblixguy/scanlinks](https://github.com/theblixguy/scanlinks) Block unsafe and dangerous links on your Android device!
- [**6**星][5y] [vaginessa/pwn-pad-arsenal-tools](https://github.com/vaginessa/pwn-pad-arsenal-tools) Penetration Testing Apps for Android Devices


### <a id="fa49f65b8d3c71b36c6924ce51c2ca0c"></a>HotFix


- [**14557**星][5d] [Java] [tencent/tinker](https://github.com/tencent/tinker) Tinker is a hot-fix solution library for Android, it supports dex, library and resources update without reinstall apk.
- [**6684**星][3y] [C++] [alibaba/andfix](https://github.com/alibaba/andfix) AndFix is a library that offer hot-fix for Android App.
- [**3462**星][19d] [Java] [meituan-dianping/robust](https://github.com/meituan-dianping/robust) Robust is an Android HotFix solution with high compatibility and high stability. Robust can fix bugs immediately without a reboot.
- [**1117**星][5m] [Java] [manbanggroup/phantom](https://github.com/manbanggroup/phantom)  唯一零 Hook 稳定占坑类 Android 热更新插件化方案


### <a id="ec395c8f974c75963d88a9829af12a90"></a>打包


- [**5080**星][2m] [Java] [meituan-dianping/walle](https://github.com/meituan-dianping/walle) Android Signature V2 Scheme签名下的新一代渠道包打包神器


### <a id="767078c52aca04c452c095f49ad73956"></a>收集


- [**1663**星][2y] [Shell] [juude/droidreverse](https://github.com/juude/droidreverse) android 逆向工程工具集
- [**72**星][9m] [wufengxue/android-reverse](https://github.com/wufengxue/android-reverse) 安卓逆向工具汇总


### <a id="17408290519e1ca7745233afea62c43c"></a>各类App


- [**12285**星][3d] [Java] [signalapp/signal-android](https://github.com/signalapp/Signal-Android) A private messenger for Android.


### <a id="7f353b27e45b5de6b0e6ac472b02cbf1"></a>Xposed


- [**8756**星][1m] [Java] [android-hacker/virtualxposed](https://github.com/android-hacker/virtualxposed) A simple app to use Xposed without root, unlock the bootloader or modify system image, etc.
- [**2559**星][7m] [taichi-framework/taichi](https://github.com/taichi-framework/taichi) A framework to use Xposed module with or without Root/Unlock bootloader, supportting Android 5.0 ~ 10.0
- [**2034**星][4d] [Java] [elderdrivers/edxposed](https://github.com/elderdrivers/edxposed) Elder driver Xposed Framework.
- [**1726**星][1y] [Java] [ac-pm/inspeckage](https://github.com/ac-pm/inspeckage) Android Package Inspector - dynamic analysis with api hooks, start unexported activities and more. (Xposed Module)
- [**1655**星][1m] [Java] [tiann/epic](https://github.com/tiann/epic) Dynamic java method AOP hook for Android(continution of Dexposed on ART), Supporting 4.0~10.0
- [**1494**星][2y] [Kotlin] [gh0u1l5/wechatmagician](https://github.com/gh0u1l5/wechatmagician) WechatMagician is a Xposed module written in Kotlin, that allows you to completely control your Wechat.
- [**1296**星][1m] [Java] [android-hacker/exposed](https://github.com/android-hacker/exposed) A library to use Xposed without root or recovery(or modify system image etc..).
- [**839**星][5y] [halfkiss/zjdroid](https://github.com/halfkiss/zjdroid) 基于Xposed Framewrok的动态逆向分析模块
- [**790**星][8m] [Java] [blankeer/mdwechat](https://github.com/blankeer/mdwechat) 一个能让微信 Material Design 化的 Xposed 模块
- [**669**星][4d] [Java] [ganyao114/sandhook](https://github.com/ganyao114/sandhook) Android ART Hook/Native Inline Hook/Single Instruction Hook - support 4.4 - 10.0 32/64 bit - Xposed API Compat
- [**478**星][2m] [Java] [tornaco/x-apm](https://github.com/tornaco/x-apm) 应用管理 Xposed
- [**424**星][3y] [Makefile] [mindmac/androideagleeye](https://github.com/mindmac/androideagleeye) An Xposed and adbi based module which is capable of hooking both Java and Native methods targeting Android OS.
- [**322**星][1y] [C] [smartdone/dexdump](https://github.com/smartdone/dexdump) 一个用来快速脱一代壳的工具（稍微改下就可以脱类抽取那种壳）（Android）
- [**309**星][25d] [bigsinger/androididchanger](https://github.com/bigsinger/androididchanger) Xposed Module for Changing Android Device Info
- [**309**星][5d] [Java] [ganyao114/sandvxposed](https://github.com/ganyao114/sandvxposed) Xposed environment without root (OS 5.0 - 10.0)
- [**283**星][2y] [C++] [rovo89/android_art](https://github.com/rovo89/android_art) Android ART with modifications for the Xposed framework.
- [**214**星][1y] [Kotlin] [paphonb/androidp-ify](https://github.com/paphonb/androidp-ify) [Xposed] Use features introduced in Android P on your O+ Device!
- [**204**星][1y] [C] [gtoad/android_inline_hook](https://github.com/gtoad/android_inline_hook) Build an so file to automatically do the android_native_hook work. Supports thumb-2/arm32 and ARM64 ! With this, tools like Xposed can do android native hook.
- [**127**星][2y] [Java] [bmax121/budhook](https://github.com/bmax121/budhook) An Android hook framework written like Xposed,based on YAHFA.
- [**120**星][3y] [Java] [rastapasta/pokemon-go-xposed](https://github.com/rastapasta/pokemon-go-xposed) 
- [**79**星][4m] [Go] [tillson/git-hound](https://github.com/tillson/git-hound) GitHound pinpoints exposed API keys on GitHub using pattern matching, commit history searching, and a unique result scoring system. A batch-catching, pattern-matching, patch-attacking secret snatcher.
- [**71**星][26d] [Java] [lianglixin/sandvxposed](https://github.com/lianglixin/sandvxposed) Xposed environment without root (OS 5.0 - 10.0)
- [**64**星][10m] [FreeMarker] [dvdandroid/xposedmoduletemplate](https://github.com/dvdandroid/xposedmoduletemplate) Easily create a Xposed Module with Android Studio
- [**64**星][t] [uniking/dingding](https://github.com/uniking/dingding) 免root远程钉钉打卡，支持wifi和gps定位，仅支持android系统。本项目出于学习目的，仅用于学习玩耍,请于24小时后自行删除。xposed, crack,package,dingtalk,remote control
- [**49**星][10m] [Py] [hrkfdn/deckard](https://github.com/hrkfdn/deckard) Deckard performs static and dynamic binary analysis on Android APKs to extract Xposed hooks
- [**38**星][10m] [Java] [egguncle/xposednavigationbar](https://github.com/egguncle/xposednavigationbar) Xposed导航栏功能拓展模块
- [**36**星][8m] [Py] [anantshri/ds_store_crawler_parser](https://github.com/anantshri/ds_store_crawler_parser) a parser + crawler for .DS_Store files exposed publically
- [**34**星][5y] [Java] [wooyundota/intentmonitor](https://github.com/wooyundota/intentmonitor) Tool based xposed can monitor the android intents
- [**28**星][5y] [Java] [mindmac/xposedautomation](https://github.com/mindmac/xposedautomation) A demo to show how to install Xposed and enable Xposed based module automatically
- [**26**星][5y] [Java] [twilightgod/malwarebuster](https://github.com/twilightgod/malwarebuster) This is a Xposed module. It helps to prevent malwares to register service/receiver which were disabled in My Android Tools before.


### <a id="50f63dce18786069de2ec637630ff167"></a>加壳&&脱壳


- [**1793**星][8m] [C++] [wrbug/dumpdex](https://github.com/wrbug/dumpdex) Android脱壳
- [**1620**星][3y] [Makefile] [drizzlerisk/drizzledumper](https://github.com/drizzlerisk/drizzledumper) 是一款基于内存搜索的Android脱壳工具。
- [**1465**星][3m] [C++] [vaibhavpandeyvpz/apkstudio](https://github.com/vaibhavpandeyvpz/apkstudio) Open-source, cross platform Qt based IDE for reverse-engineering Android application packages.
- [**1036**星][3y] [C++] [zyq8709/dexhunter](https://github.com/zyq8709/dexhunter) General Automatic Unpacking Tool for Android Dex Files
- [**811**星][4m] [C] [strazzere/android-unpacker](https://github.com/strazzere/android-unpacker) Android Unpacker presented at Defcon 22: Android Hacker Protection Level 0
- [**712**星][2m] [YARA] [rednaga/apkid](https://github.com/rednaga/apkid) Android Application Identifier for Packers, Protectors, Obfuscators and Oddities - PEiD for Android
- [**366**星][3m] [Java] [patrickfav/uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) A cli tool that helps signing and zip aligning single or multiple Android application packages (APKs) with either debug or provided release certificates. It supports v1, v2 and v3 Android signing scheme has an embedded debug keystore and auto verifies after signing.
- [**322**星][6m] [Shell] [1n3/reverseapk](https://github.com/1n3/reverseapk) Quickly analyze and reverse engineer Android packages
- [**298**星][2y] [Shell] [checkpointsw/android_unpacker](https://github.com/checkpointsw/android_unpacker) A (hopefully) generic unpacker for packed Android apps.
- [**189**星][3y] [Py] [drizzlerisk/tunpacker](https://github.com/drizzlerisk/tunpacker) TUnpacker是一款Android脱壳工具
- [**187**星][3y] [Py] [andy10101/apkdetecter](https://github.com/andy10101/apkdetecter) Android Apk查壳工具及源代码
- [**148**星][3y] [Py] [drizzlerisk/bunpacker](https://github.com/drizzlerisk/bunpacker) BUnpacker是一款Android脱壳工具
- [**105**星][4y] [Java] [liuyufei/sslkiller](https://github.com/liuyufei/sslkiller) SSLKiller is used for killing SSL verification functions on Android client side. With SSLKiller, You can intercept app's HTTPS communication packages between the client and server.
- [**104**星][3y] [Java] [cvvt/apptroy](https://github.com/cvvt/apptroy) An Online Analysis System for Packed Android Malware
- [**89**星][2y] [ObjC] [wooyundota/dumpdex](https://github.com/wooyundota/dumpdex) Android Unpack tool based on Cydia
- [**68**星][5y] [Py] [ajinabraham/xenotix-apk-reverser](https://github.com/ajinabraham/xenotix-apk-reverser) Xenotix APK Reverser is an OpenSource Android Application Package (APK) decompiler and disassembler powered by dex2jar, baksmali and jd-core.
- [**30**星][7m] [Java] [cristianturetta/mad-spy](https://github.com/cristianturetta/mad-spy) We developed a malware for educational purposes. In particular, our goal is to provide a PoC of what is known as a Repacking attack, a known technique widely used by malware cybercrooks to trojanize android apps. The answer to solve this particular goal boils down in the simplicity of APK decompiling and smali code injection.
- [**22**星][5d] [Py] [botherder/snoopdroid](https://github.com/botherder/snoopdroid) Extract packages from an Android device
- [**10**星][2y] [Shell] [nickdiego/docker-ollvm](https://github.com/nickdiego/docker-ollvm) Easily build and package Obfuscator-LLVM into Android NDK.


### <a id="596b6cf8fd36bc4c819335f12850a915"></a>HOOK


- [**1500**星][19d] [C] [iqiyi/xhook](https://github.com/iqiyi/xhook) a PLT (Procedure Linkage Table) hook library for Android native ELF 
- [**1494**星][t] [C++] [jmpews/dobby](https://github.com/jmpews/Dobby) a lightweight, multi-platform, multi-architecture hook framework.
- [**804**星][17d] [C++] [aslody/whale](https://github.com/aslody/whale) Hook Framework for Android/IOS/Linux/MacOS
- [**530**星][7m] [Java] [aslody/andhook](https://github.com/asLody/AndHook) Android dynamic instrumentation framework
- [**400**星][3y] [Java] [pqpo/inputmethodholder](https://github.com/pqpo/inputmethodholder) A keyboard listener for Android which by hooking the InputMethodManager. 通过hook监听系统键盘显示
- [**361**星][8m] [C] [turing-technician/fasthook](https://github.com/turing-technician/fasthook) Android ART Hook
- [**216**星][3y] [Java] [zhengmin1989/wechatsportcheat](https://github.com/zhengmin1989/wechatsportcheat) 手把手教你当微信运动第一名 – 利用Android Hook进行微信运动作弊
- [**190**星][4y] [C++] [aslody/elfhook](https://github.com/aslody/elfhook) modify PLT to hook api, supported android 5\6.
- [**123**星][9m] [Java] [turing-technician/virtualfasthook](https://github.com/turing-technician/virtualfasthook) Android application hooking tool based on FastHook + VirtualApp
- [**58**星][2y] [Java] [nightoftwelve/virtualhookex](https://github.com/nightoftwelve/virtualhookex) Android application hooking tool based on VirtualHook/VirtualApp
- [**54**星][3y] [Rust] [nccgroup/assethook](https://github.com/nccgroup/assethook) LD_PRELOAD magic for Android's AssetManager
- [**36**星][19d] [C++] [chickenhook/chickenhook](https://github.com/chickenhook/chickenhook) A linux / android / MacOS hooking framework


### <a id="5afa336e229e4c38ad378644c484734a"></a>Emulator&&模拟器


- [**1492**星][1y] [C++] [f1xpl/openauto](https://github.com/f1xpl/openauto) AndroidAuto headunit emulator
- [**532**星][7m] [Java] [limboemu/limbo](https://github.com/limboemu/limbo) Limbo is a QEMU-based emulator for Android. It currently supports PC & ARM emulation for Intel x86 and ARM architecture. See our wiki
    - 重复区段: [模拟器->QEMU->工具->新添加的](#82072558d99a6cf23d4014c0ae5b420a) |
- [**471**星][3m] [Java] [strazzere/anti-emulator](https://github.com/strazzere/anti-emulator) Android Anti-Emulator
- [**428**星][2y] [Py] [evilsocket/smali_emulator](https://github.com/evilsocket/smali_emulator) This software will emulate a smali source file generated by apktool.
- [**202**星][3y] [Py] [mseclab/nathan](https://github.com/mseclab/nathan) Android Emulator for mobile security testing
- [**168**星][11m] [Py] [mnkgrover08-zz/whatsapp_automation](https://github.com/mnkgrover08-zz/whatsapp_automation) Whatsapp Automation is a collection of APIs that interact with WhatsApp messenger running in an Android emulator, allowing developers to build projects that automate sending and receiving messages, adding new contacts and broadcasting messages multiple contacts.
- [**148**星][5y] [C] [strazzere/android-lkms](https://github.com/strazzere/android-lkms) Android Loadable Kernel Modules - mostly used for reversing and debugging on controlled systems/emulators
- [**27**星][2y] [Shell] [gustavosotnas/avd-launcher](https://github.com/gustavosotnas/avd-launcher) Front-end to Android Virtual Devices (AVDs) emulator from Google.
- [**16**星][1y] [Py] [abhi-r3v0/droxes](https://github.com/abhi-r3v0/droxes) A simple script to turn an Android device/emulator into a test-ready box.


### <a id="0a668d220ce74e11ed2738c4e3ae3c9e"></a>IDA


- [**161**星][2m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->插件->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->插件->针对特定分析目标->Loader](#cb59d84840e41330a7b5e275c0b81725) |[Android->工具->新添加的1](#63fd2c592145914e99f837cecdc5a67c) |
- [**118**星][4y] [Py] [cvvt/dumpdex](https://github.com/cvvt/dumpdex) 基于IDA python的Android DEX内存dump工具
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |
- [**83**星][2y] [Py] [zhkl0228/androidattacher](https://github.com/zhkl0228/androidattacher) IDA debugging plugin for android armv7 so
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |
- [**39**星][5y] [Py] [techbliss/adb_helper_qt_super_version](https://github.com/techbliss/adb_helper_qt_super_version) All You Need For Ida Pro And Android Debugging
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |
- [**39**星][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) 辅助Android调试的IDAPython脚本
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |[IDA->插件->调试->未分类](#2944dda5289f494e5e636089db0d6a6a) |
- [**16**星][7y] [C++] [strazzere/dalvik-header-plugin](https://github.com/strazzere/dalvik-header-plugin) Dalvik Header Plugin for IDA Pro
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |


### <a id="bb9f8e636857320abf0502c19af6c763"></a>Debug&&调试


- [**10794**星][30d] [Java] [konloch/bytecode-viewer](https://github.com/konloch/bytecode-viewer) A Java 8+ Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More)
- [**6762**星][10m] [Java] [amitshekhariitbhu/android-debug-database](https://github.com/amitshekhariitbhu/android-debug-database) A library for debugging android databases and shared preferences - Make Debugging Great Again
- [**527**星][5y] [Py] [swdunlop/andbug](https://github.com/swdunlop/andbug) Android Debugging Library
- [**468**星][7y] [Shell] [kosborn/p2p-adb](https://github.com/kosborn/p2p-adb) Phone to Phone Android Debug Bridge - A project for "debugging" phones... from other phones.
- [**123**星][3y] [C++] [cheetahsec/avmdbg](https://github.com/cheetahsec/avmdbg) a lightweight debugger for android virtual machine.
- [**106**星][6y] [Java] [isecpartners/android-opendebug](https://github.com/isecpartners/android-opendebug) Make any application debuggable
- [**98**星][4y] [Py] [cx9527/strongdb](https://github.com/cx9527/strongdb) gdb plugin for android debugging
- [**65**星][6y] [Py] [anbc/andbug](https://github.com/anbc/andbug) Android Debugging Library
- [**57**星][3y] [C] [gnaixx/anti-debug](https://github.com/gnaixx/anti-debug) Android detect debugger
- [**56**星][5m] [Shell] [wuseman/wbruter](https://github.com/wuseman/wbruter) Crack your non-rooted android device pin code with 100% guarantee aslong as usb debugging has been enable. Wbruter also has support for parallel ssh brute forcing via pssh
- [**22**星][12m] [C++] [gtoad/android_anti_debug](https://github.com/gtoad/android_anti_debug) An example of android anti-debug.


### <a id="f975a85510f714ec3cc2551e868e75b8"></a>Malware&&恶意代码


- [**429**星][4m] [Shell] [ashishb/android-malware](https://github.com/ashishb/android-malware) Collection of android malware samples
- [**347**星][3m] [Java] [droidefense/engine](https://github.com/droidefense/engine) Droidefense: Advance Android Malware Analysis Framework
- [**192**星][4y] [HTML] [faber03/androidmalwareevaluatingtools](https://github.com/faber03/androidmalwareevaluatingtools) Evaluation tools for malware Android
- [**123**星][2y] [Java] [brompwnie/uitkyk](https://github.com/brompwnie/uitkyk) Android Frida库, 用于分析App查找恶意行为
    - 重复区段: [DBI->Frida->工具->新添加的](#54836a155de0c15b56f43634cd9cfecf) |
- [**117**星][7y] [C] [secmobi/amatutor](https://github.com/secmobi/amatutor) Android恶意代码分析教程
- [**97**星][2y] [Lua] [niallmcl/deep-android-malware-detection](https://github.com/niallmcl/deep-android-malware-detection) Code for Deep Android Malware Detection paper
- [**82**星][5y] [Py] [maldroid/maldrolyzer](https://github.com/maldroid/maldrolyzer) Simple framework to extract "actionable" data from Android malware (C&Cs, phone numbers etc.)
- [**67**星][10m] [dkhuuthe/madlira](https://github.com/dkhuuthe/madlira) Malware detection using learning and information retrieval for Android
- [**65**星][1y] [Py] [mwleeds/android-malware-analysis](https://github.com/mwleeds/android-malware-analysis) This project seeks to apply machine learning algorithms to Android malware classification.
- [**65**星][4y] [C++] [soarlab/maline](https://github.com/soarlab/maline) Android Malware Detection Framework
- [**59**星][5m] [Py] [hgascon/adagio](https://github.com/hgascon/adagio) Structural Analysis and Detection of Android Malware
- [**49**星][3y] [HTML] [mburakergenc/malware-detection-using-machine-learning](https://github.com/mburakergenc/malware-detection-using-machine-learning) Malware detection project on Android devices using machine learning classification algorithms.
- [**49**星][2y] [java] [toufikairane/andromalware](https://github.com/tfairane/andromalware) Android Malware for educational purpose
- [**46**星][1y] [Py] [maoqyhz/droidcc](https://github.com/maoqyhz/droidcc) Android malware detection using deep learning, contains android malware samples, papers, tools etc.
- [**40**星][2y] [Java] [miwong/intellidroid](https://github.com/miwong/intellidroid) A targeted input generator for Android that improves the effectiveness of dynamic malware analysis.
- [**40**星][1y] [traceflight/android-malware-datasets](https://github.com/traceflight/android-malware-datasets) Popular Android malware datasets
- [**33**星][5y] [Shell] [vt-magnum-research/antimalware](https://github.com/vt-magnum-research/antimalware) Dynamic malware analysis for the Android platform
- [**29**星][2y] [virqdroid/android_malware](https://github.com/virqdroid/android_malware) 
- [**27**星][3y] [fouroctets/android-malware-samples](https://github.com/fouroctets/android-malware-samples) Android Malware Samples
- [**24**星][3y] [Py] [bunseokbot/androtools](https://github.com/bunseokbot/androtools) Android malware static & dynamic analysis and automated action (deprecated)
- [**19**星][2y] [Py] [namk12/malware-detection](https://github.com/namk12/malware-detection) Deep Learning Based Android Malware Detection Framework
- [**15**星][3y] [Java] [darrylburke/androidmalwareexample](https://github.com/darrylburke/androidmalwareexample) Proof of Concept example of Android Malware used for Research Purposes
- [**13**星][5y] [JS] [cheverebe/android-malware](https://github.com/cheverebe/android-malware) Injected malicious code into legitimate andoid applications. Converted a keyboard app into a keylogger and an MP3 downloader into an image thief.
- [**13**星][6m] [HTML] [fmind/euphony](https://github.com/fmind/euphony) Harmonious Unification of Cacophonous Anti-Virus Vendor Labels for Android Malware
- [**13**星][8m] [Py] [vinayakumarr/android-malware-detection](https://github.com/vinayakumarr/android-malware-detection) Android malware detection using static and dynamic analysis
- [**11**星][3m] [Py] [jacobsoo/amtracker](https://github.com/jacobsoo/amtracker) Android Malware Tracker
- [**11**星][2y] [Py] [tlatkdgus1/android-malware-analysis-system](https://github.com/tlatkdgus1/android-malware-analysis-system) Android Malware Detection based on Deep Learning
- [**9**星][4y] [Java] [acprimer/malwaredetector](https://github.com/acprimer/malwaredetector) android malwarre detector
- [**9**星][2y] [Py] [mldroid/csbd](https://github.com/mldroid/csbd) The repository contains the python implementation of the Android Malware Detection paper: "Empirical assessment of machine learning-based malware detectors for Android: Measuring the Gap between In-the-Lab and In-the-Wild Validation Scenarios"
- [**7**星][3y] [Java] [waallen/http-sms-android-malware](https://github.com/waallen/http-sms-android-malware) HTTP and SMS spam testing application
- [**6**星][7y] [Java] [ssesha/malwarescanner](https://github.com/ssesha/malwarescanner) Android app performing hash based malware detection
- [**6**星][3y] [Py] [tuomao/android_malware_detection](https://github.com/tuomao/android_malware_detection) 
- [**6**星][8y] [Java] [twitter-university/antimalware](https://github.com/twitter-university/antimalware) An Android Eclipse project demonstrating how to build a simple anti-malware application
- [**6**星][1y] [Py] [aliemamalinezhad/machine-learning](https://github.com/aliemamalinezhad/machine-learning) android-malware-classification using machine learning algorithms


### <a id="1d83ca6d8b02950be10ac8e4b8a2d976"></a>Obfuscate&&混淆


- [**3078**星][2m] [Java] [calebfenton/simplify](https://github.com/calebfenton/simplify) Generic Android Deobfuscator
- [**294**星][4m] [C] [shadowsocks/simple-obfs-android](https://github.com/shadowsocks/simple-obfs-android) A simple obfuscating tool for Android
- [**76**星][4y] [Java] [enovella/jebscripts](https://github.com/enovella/jebscripts) A set of JEB Python/Java scripts for reverse engineering Android obfuscated code
- [**12**星][27d] [Py] [omirzaei/androdet](https://github.com/omirzaei/androdet) AndrODet: An Adaptive Android Obfuscation Detector
- [**11**星][1y] [Java] [miwong/tiro](https://github.com/miwong/tiro) TIRO - A hybrid iterative deobfuscation framework for Android applications


### <a id="6d2b758b3269bac7d69a2d2c8b45194c"></a>ReverseEngineering


- [**9285**星][23d] [Java] [ibotpeaches/apktool](https://github.com/ibotpeaches/apktool) A tool for reverse engineering Android apk files
- [**2053**星][1m] [Java] [genymobile/gnirehtet](https://github.com/genymobile/gnirehtet) Gnirehtet provides reverse tethering for Android
- [**585**星][2m] [C++] [secrary/andromeda](https://github.com/secrary/andromeda) Andromeda - Interactive Reverse Engineering Tool for Android Applications [This project is not maintained anymore]
- [**554**星][3y] [Java] [linchaolong/apktoolplus](https://github.com/linchaolong/apktoolplus)  apk 逆向分析工具
- [**545**星][12d] [maddiestone/androidappre](https://github.com/maddiestone/androidappre) Android App Reverse Engineering Workshop
- [**331**星][7y] [Java] [brutall/brut.apktool](https://github.com/brutall/brut.apktool) A tool for reverse engineering Android apk files
- [**267**星][10m] [Dockerfile] [cryptax/androidre](https://github.com/cryptax/androidre) 用于Android 逆向的 Docker 容器
- [**246**星][20d] [C++] [strazzere/android-scripts](https://github.com/strazzere/android-scripts) Android逆向脚本收集
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |
- [**102**星][3y] [feicong/android-app-sec](https://github.com/feicong/android-app-sec) ISC 2016安全训练营－安卓app逆向与安全防护 ppt
- [**54**星][5m] [Smali] [hellohudi/androidreversenotes](https://github.com/hellohudi/androidreversenotes) Android逆向笔记---从入门到入土
- [**54**星][9y] [Emacs Lisp] [nelhage/reverse-android](https://github.com/nelhage/reverse-android) Reverse-engineering tools for Android applications
- [**32**星][3y] [nextco/android-decompiler](https://github.com/nextco/android-decompiler) A hight quality list of tools to reverse engineering code from android.
- [**16**星][3m] [Smali] [freedom-wy/reverse_android](https://github.com/freedom-wy/reverse_android) 安卓从开发到逆向
- [**11**星][2y] [Smali] [yifengyou/android-software-security-and-reverse-analysis](https://github.com/yifengyou/android-software-security-and-reverse-analysis) Android软件安全与逆向分析
- [**6**星][2y] [CSS] [oscar0812/apktoolfx](https://github.com/oscar0812/apktoolfx) A GUI for Apktool to make reverse engineering of android apps a breeze.




***


## <a id="f0493b259e1169b5ddd269b13cfd30e6"></a>文章&&视频


- 2019.12 [aliyun] [Android智能终端系统的安全加固（上）](https://xz.aliyun.com/t/6852)
- 2019.11 [venus] [Android勒索病毒分析（上）](https://paper.seebug.org/1085/)


# <a id="069664f347ae73b1370c4f5a2ec9da9f"></a>Apple&&iOS&&iXxx


***


## <a id="58cd9084afafd3cd293564c1d615dd7f"></a>工具


### <a id="d0108e91e6863289f89084ff09df39d0"></a>新添加的


- [**11025**星][2y] [ObjC] [bang590/jspatch](https://github.com/bang590/jspatch) JSPatch bridge Objective-C and Javascript using the Objective-C runtime. You can call any Objective-C class and method in JavaScript by just including a small engine. JSPatch is generally used to hotfix iOS App.
- [**10966**星][2d] [ObjC] [flipboard/flex](https://github.com/flipboard/flex) An in-app debugging and exploration tool for iOS
- [**8031**星][2m] [Py] [facebook/chisel](https://github.com/facebook/chisel) Chisel is a collection of LLDB commands to assist debugging iOS apps.
- [**5775**星][3m] [ObjC] [square/ponydebugger](https://github.com/square/ponydebugger) Remote network and data debugging for your native iOS app using Chrome Developer Tools
- [**5451**星][3m] [Py] [axi0mx/ipwndfu](https://github.com/axi0mx/ipwndfu) open-source jailbreaking tool for many iOS devices
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**5390**星][5m] [C] [pwn20wndstuff/undecimus](https://github.com/pwn20wndstuff/undecimus) unc0ver jailbreak for iOS 11.0 - 12.4
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**4663**星][29d] [C] [google/ios-webkit-debug-proxy](https://github.com/google/ios-webkit-debug-proxy) A DevTools proxy (Chrome Remote Debugging Protocol) for iOS devices (Safari Remote Web Inspector).
- [**4397**星][4d] [Swift] [signalapp/signal-ios](https://github.com/signalapp/Signal-iOS) A private messenger for iOS.
- [**4248**星][8m] [ObjC] [alonemonkey/monkeydev](https://github.com/alonemonkey/monkeydev) CaptainHook Tweak、Logos Tweak and Command-line Tool、Patch iOS Apps, Without Jailbreak.
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**3686**星][4m] [C] [facebook/fishhook](https://github.com/facebook/fishhook) A library that enables dynamically rebinding symbols in Mach-O binaries running on iOS.
- [**3414**星][1m] [icodesign/potatso](https://github.com/icodesign/Potatso) Potatso is an iOS client that implements different proxies with the leverage of NetworkExtension framework in iOS 10+.
- [**3327**星][3m] [Swift] [yagiz/bagel](https://github.com/yagiz/bagel) a little native network debugging tool for iOS
- [**3071**星][10m] [JS] [jipegit/osxauditor](https://github.com/jipegit/osxauditor) OS X Auditor is a free Mac OS X computer forensics tool
- [**2867**星][4d] [ObjC] [facebook/idb](https://github.com/facebook/idb) idb is a flexible command line interface for automating iOS simulators and devices
- [**2795**星][16d] [Swift] [kasketis/netfox](https://github.com/kasketis/netfox) A lightweight, one line setup, iOS / OSX network debugging library!
- [**2753**星][1m] [Makefile] [theos/theos](https://github.com/theos/theos) A cross-platform suite of tools for building and deploying software for iOS and other platforms.
- [**2733**星][18d] [ObjC] [dantheman827/ios-app-signer](https://github.com/dantheman827/ios-app-signer) This is an app for OS X that can (re)sign apps and bundle them into ipa files that are ready to be installed on an iOS device.
- [**2708**星][2m] [ObjC] [kjcracks/clutch](https://github.com/kjcracks/clutch) Fast iOS executable dumper
- [**2345**星][6y] [C] [stefanesser/dumpdecrypted](https://github.com/stefanesser/dumpdecrypted) Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk. This tool is necessary for security researchers to be able to look under the hood of encryption.
- [**2057**星][11d] [ObjC] [ios-control/ios-deploy](https://github.com/ios-control/ios-deploy) Install and debug iPhone apps from the command line, without using Xcode
- [**1801**星][1y] [aozhimin/ios-monitor-platform](https://github.com/aozhimin/ios-monitor-platform) 
- [**1800**星][3y] [ObjC] [kpwn/yalu102](https://github.com/kpwn/yalu102) incomplete iOS 10.2 jailbreak for 64 bit devices by qwertyoruiopz and marcograssi
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**1774**星][3y] [ObjC] [tapwork/heapinspector-for-ios](https://github.com/tapwork/heapinspector-for-ios) Find memory issues & leaks in your iOS app without instruments
- [**1695**星][6m] [Py] [yelp/osxcollector](https://github.com/yelp/osxcollector) A forensic evidence collection & analysis toolkit for OS X
- [**1683**星][1m] [Swift] [pmusolino/wormholy](https://github.com/pmusolino/wormholy) iOS network debugging, like a wizard 🧙‍♂️
- [**1642**星][6m] [Objective-C++] [tencent/oomdetector](https://github.com/tencent/oomdetector) OOMDetector is a memory monitoring component for iOS which provides you with OOM monitoring, memory allocation monitoring, memory leak detection and other functions.
- [**1630**星][1m] [ivrodriguezca/re-ios-apps](https://github.com/ivrodriguezca/re-ios-apps) A completely free, open source and online course about Reverse Engineering iOS Applications.
- [**1444**星][5y] [C++] [gdbinit/machoview](https://github.com/gdbinit/machoview) MachOView fork
- [**1442**星][20d] [ObjC] [nabla-c0d3/ssl-kill-switch2](https://github.com/nabla-c0d3/ssl-kill-switch2) Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and OS X Apps
- [**1299**星][5m] [JS] [feross/spoof](https://github.com/feross/spoof) Easily spoof your MAC address in macOS, Windows, & Linux!
- [**1291**星][1m] [JS] [icymind/vrouter](https://github.com/icymind/vrouter) 一个基于 VirtualBox 和 openwrt 构建的项目, 旨在实现 macOS / Windows 平台的透明代理.
- [**1253**星][2m] [Vue] [chaitin/passionfruit](https://github.com/chaitin/passionfruit) iOSapp 黑盒评估工具。功能丰富，自带基于web的 GUI
- [**1252**星][9d] [michalmalik/osx-re-101](https://github.com/michalmalik/osx-re-101) OSX/iOS逆向资源收集
- [**1240**星][2y] [ObjC] [krausefx/detect.location](https://github.com/krausefx/detect.location) An easy way to access the user's iOS location data without actually having access
- [**1239**星][t] [C] [datatheorem/trustkit](https://github.com/datatheorem/trustkit) Easy SSL pinning validation and reporting for iOS, macOS, tvOS and watchOS.
- [**1215**星][8d] [YARA] [horsicq/detect-it-easy](https://github.com/horsicq/detect-it-easy) Program for determining types of files for Windows, Linux and MacOS.
- [**1199**星][6y] [gdbinit/gdbinit](https://github.com/gdbinit/gdbinit) Gdbinit for OS X, iOS and others - x86, x86_64 and ARM
- [**1193**星][7d] [JS] [alonemonkey/frida-ios-dump](https://github.com/alonemonkey/frida-ios-dump) pull decrypted ipa from jailbreak device
    - 重复区段: [DBI->Frida->工具->新添加的](#54836a155de0c15b56f43634cd9cfecf) |
- [**1174**星][5y] [Py] [hackappcom/ibrute](https://github.com/hackappcom/ibrute) AppleID bruteforce p0c
- [**1113**星][1y] [ObjC] [neoneggplant/eggshell](https://github.com/neoneggplant/eggshell) iOS/macOS/Linux Remote Administration Tool
- [**1026**星][2y] [ObjC] [zhengmin1989/ios_ice_and_fire](https://github.com/zhengmin1989/ios_ice_and_fire) iOS冰与火之歌
- [**1001**星][2m] [ObjC] [lmirosevic/gbdeviceinfo](https://github.com/lmirosevic/gbdeviceinfo) Detects the hardware, software and display of the current iOS or Mac OS X device at runtime.
- [**985**星][1y] [Py] [fsecurelabs/needle](https://github.com/FSecureLABS/needle) The iOS Security Testing Framework
- [**975**星][3y] [Py] [synack/knockknock](https://github.com/synack/knockknock) displays persistent items (scripts, commands, binaries, etc.), that are set to execute automatically on OS X
- [**936**星][3y] [C] [tyilo/insert_dylib](https://github.com/tyilo/insert_dylib) Command line utility for inserting a dylib load command into a Mach-O binary
- [**907**星][3m] [ObjC] [ptoomey3/keychain-dumper](https://github.com/ptoomey3/keychain-dumper) A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken
- [**866**星][8d] [ObjC] [meitu/mthawkeye](https://github.com/meitu/mthawkeye) Profiling / Debugging assist tools for iOS. (Memory Leak, OOM, ANR, Hard Stalling, Network, OpenGL, Time Profile ...)
- [**857**星][3y] [Py] [hubert3/isniff-gps](https://github.com/hubert3/isniff-gps) Passive sniffing tool for capturing and visualising WiFi location data disclosed by iOS devices
- [**847**星][1y] [Shell] [kpwn/iosre](https://github.com/kpwn/iosre) iOS Reverse Engineering
- [**840**星][] [JS] [cypress-io/cypress-example-recipes](https://github.com/cypress-io/cypress-example-recipes) Various recipes for testing common scenarios with Cypress
- [**812**星][5y] [ObjC] [isecpartners/ios-ssl-kill-switch](https://github.com/isecpartners/ios-ssl-kill-switch) Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS Apps
- [**807**星][2y] [Ruby] [dmayer/idb](https://github.com/dmayer/idb) iOS 渗透和研究过程中简化一些常见的任务
- [**796**星][5d] [Shell] [aqzt/kjyw](https://github.com/aqzt/kjyw) 快捷运维，代号kjyw，项目基于shell、python，运维脚本工具库，收集各类运维常用工具脚本，实现快速安装nginx、mysql、php、redis、nagios、运维经常使用的脚本等等...
- [**782**星][3y] [Go] [summitroute/osxlockdown](https://github.com/summitroute/osxlockdown) [No longer maintained] Apple OS X tool to audit for, and remediate, security configuration settings.
- [**745**星][5y] [ObjC] [kjcracks/yololib](https://github.com/kjcracks/yololib) dylib injector for mach-o binaries
- [**662**星][1y] [Py] [deepzec/bad-pdf](https://github.com/deepzec/bad-pdf) create malicious PDF file to steal NTLM(NTLMv1/NTLMv2) Hashes from windows machines
- [**653**星][3y] [C] [rentzsch/mach_inject](https://github.com/rentzsch/mach_inject) interprocess code injection for Mac OS X
- [**651**星][9m] [ObjC] [chenxiancai/stcobfuscator](https://github.com/chenxiancai/stcobfuscator) iOS全局自动化 代码混淆 工具！支持cocoapod组件代码一并 混淆，完美避开hardcode方法、静态库方法和系统库方法！
- [**649**星][3y] [ObjC] [isecpartners/introspy-ios](https://github.com/isecpartners/introspy-ios) Security profiling for blackbox iOS
- [**642**星][2y] [C] [coolstar/electra](https://github.com/coolstar/electra) iOS 11.0 - 11.1.2 越狱工具包, 基于 async_awake
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**636**星][1y] [Swift] [phynet/ios-url-schemes](https://github.com/phynet/ios-url-schemes)  a github solution from my gist of iOS list for urls schemes
- [**621**星][5y] [PHP] [pr0x13/idict](https://github.com/pr0x13/idict) iCloud Apple iD BruteForcer
- [**616**星][3y] [ObjC] [macmade/keychaincracker](https://github.com/macmade/keychaincracker) macOS keychain cracking tool
- [**604**星][2m] [siguza/ios-resources](https://github.com/siguza/ios-resources) Useful resources for iOS hacking
- [**583**星][3y] [C++] [tobefuturer/app2dylib](https://github.com/tobefuturer/app2dylib) A reverse engineering tool to convert iOS app to dylib
- [**558**星][3y] [advanced-threat-research/firmware-security-training](https://github.com/advanced-threat-research/firmware-security-training) 固件安全教程：从攻击者和防卫者的角度看BIOS / UEFI系统固件的安全
- [**530**星][3y] [ObjC] [herzmut/shadowsocks-ios](https://github.com/herzmut/shadowsocks-ios) Fork of shadowsocks/shadowsocks-iOS
- [**526**星][4y] [Py] [hackappcom/iloot](https://github.com/hackappcom/iloot) OpenSource tool for iCloud backup extraction
- [**522**星][2y] [Shell] [seemoo-lab/mobisys2018_nexmon_software_defined_radio](https://github.com/seemoo-lab/mobisys2018_nexmon_software_defined_radio) 将Broadcom的802.11ac Wi-Fi芯片变成软件定义的无线电，可在Wi-Fi频段传输任意信号
- [**517**星][3y] [ObjC] [pjebs/obfuscator-ios](https://github.com/pjebs/obfuscator-ios) Secure your app by obfuscating all the hard-coded security-sensitive strings.
- [**517**星][5y] [Py] [project-imas/mdm-server](https://github.com/project-imas/mdm-server) Sample iOS MDM server
- [**500**星][19d] [Swift] [google/science-journal-ios](https://github.com/google/science-journal-ios) Use the sensors in your mobile devices to perform science experiments. Science doesn’t just happen in the classroom or lab—tools like Science Journal let you see how the world works with just your phone.
- [**482**星][2y] [Objective-C++] [bishopfox/bfinject](https://github.com/bishopfox/bfinject) Dylib injection for iOS 11.0 - 11.1.2 with LiberiOS and Electra jailbreaks
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**482**星][1y] [Swift] [icepa/icepa](https://github.com/icepa/icepa) iOS system-wide VPN based Tor client
- [**478**星][7d] [pixelcyber/thor](https://github.com/pixelcyber/thor) HTTP Sniffer/Capture on iOS for Network Debug & Inspect.
- [**471**星][8m] [C++] [everettjf/machoexplorer](https://github.com/everettjf/machoexplorer) MachO文件查看器，支持Windows和macOS
- [**462**星][7d] [Java] [dsheirer/sdrtrunk](https://github.com/dsheirer/sdrtrunk) A cross-platform java application for decoding, monitoring, recording and streaming trunked mobile and related radio protocols using Software Defined Radios (SDR). Website:
- [**432**星][7y] [C] [juuso/keychaindump](https://github.com/juuso/keychaindump) A proof-of-concept tool for reading OS X keychain passwords
- [**430**星][11m] [captainarash/the_holy_book_of_x86](https://github.com/captainarash/the_holy_book_of_x86) A simple guide to x86 architecture, assembly, memory management, paging, segmentation, SMM, BIOS....
- [**430**星][2y] [ObjC] [jackrex/fakewechatloc](https://github.com/jackrex/fakewechatloc) 手把手教你制作一款iOS越狱App
- [**419**星][4y] [ObjC] [asido/systemmonitor](https://github.com/asido/systemmonitor) iOS application providing you all information about your device - hardware, operating system, processor, memory, GPU, network interface, storage and battery, including OpenGL powered visual representation in real time.
- [**415**星][2y] [zhengmin1989/greatiosjailbreakmaterial](https://github.com/zhengmin1989/greatiosjailbreakmaterial) Great iOS Jailbreak Material! - I read hundreds of papers and PPTs. Only list the most useful materials here!
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**406**星][5y] [ObjC] [mp0w/ios-headers](https://github.com/mp0w/ios-headers) iOS 5.0/5.1/6.0/6.1/7.0/7.1/8.0/8.1 Headers of All Frameworks (private and not) + SpringBoard
- [**404**星][1y] [C] [coalfire-research/ios-11.1.2-15b202-jailbreak](https://github.com/coalfire-research/ios-11.1.2-15b202-jailbreak) iOS 11.1.2 (15B202) Jailbreak
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**396**星][4m] [ansjdnakjdnajkd/ios](https://github.com/ansjdnakjdnajkd/ios) iOS渗透测试最有用的工具
- [**393**星][2y] [r0ysue/osg-translationteam](https://github.com/r0ysue/osg-translationteam) 看雪iOS安全小组的翻译团队作品集合，如有勘误，欢迎斧正！
- [**386**星][3y] [ObjC] [kpwn/yalu](https://github.com/kpwn/yalu) incomplete ios 8.4.1 jailbreak by Kim Jong Cracks (8.4.1 codesign & sandbox bypass w/ LPE to root & untether)
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**382**星][11m] [C] [coolstar/electra1131](https://github.com/coolstar/electra1131) electra1131: Electra for iOS 11.0 - 11.3.1
- [**375**星][1y] [C++] [alonemonkey/iosrebook](https://github.com/alonemonkey/iosrebook) 《iOS应用逆向与安全》随书源码
- [**375**星][20d] [Swift] [justeat/justlog](https://github.com/justeat/justlog) JustLog brings logging on iOS to the next level. It supports console, file and remote Logstash logging via TCP socket with no effort. Support for logz.io available.
- [**374**星][2y] [C++] [breenmachine/rottenpotatong](https://github.com/breenmachine/rottenpotatong) New version of RottenPotato as a C++ DLL and standalone C++ binary - no need for meterpreter or other tools.
- [**371**星][10d] [Shell] [matthewpierson/1033-ota-downgrader](https://github.com/matthewpierson/1033-ota-downgrader) First ever tool to downgrade ANY iPhone 5s, ANY iPad Air and (almost any) iPad Mini 2 to 10.3.3 with OTA blobs + checkm8!
- [**349**星][11d] [C] [jedisct1/swift-sodium](https://github.com/jedisct1/swift-sodium) Safe and easy to use crypto for iOS and macOS
- [**346**星][4m] [TS] [bacher09/pwgen-for-bios](https://github.com/bacher09/pwgen-for-bios) Password generator for BIOS
- [**340**星][2m] [C] [trailofbits/cb-multios](https://github.com/trailofbits/cb-multios) DARPA Challenges Sets for Linux, Windows, and macOS
- [**332**星][3y] [Logos] [bishopfox/ispy](https://github.com/bishopfox/ispy) A reverse engineering framework for iOS
- [**322**星][2m] [ObjC] [auth0/simplekeychain](https://github.com/auth0/simplekeychain) A Keychain helper for iOS to make it very simple to store/obtain values from iOS Keychain
- [**310**星][20d] [Swift] [securing/iossecuritysuite](https://github.com/securing/iossecuritysuite) iOS platform security & anti-tampering Swift library
- [**298**星][2y] [krausefx/steal.password](https://github.com/krausefx/steal.password) Easily get the user's Apple ID password, just by asking
- [**292**星][8y] [ObjC] [nst/spyphone](https://github.com/nst/spyphone) This project shows the kind of data a rogue iPhone application can collect.
- [**287**星][6m] [Shell] [0ki/mikrotik-tools](https://github.com/0ki/mikrotik-tools) Tools for Mikrotik devices -  universal jailbreak tool
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**287**星][1y] [Py] [manwhoami/mmetokendecrypt](https://github.com/manwhoami/mmetokendecrypt) Decrypts and extracts iCloud and MMe authorization tokens on Apple macOS / OS X. No user authentication needed. 🏅🌩
- [**283**星][2y] [Swift] [krausefx/watch.user](https://github.com/krausefx/watch.user) Every iOS app you ever gave permission to use your camera can record you any time it runs - without notice
- [**263**星][6d] [ObjC] [strongbox-password-safe/strongbox](https://github.com/strongbox-password-safe/strongbox) A KeePass/Password Safe Client for iOS and OS X
- [**247**星][1m] [C++] [s0uthwest/futurerestore](https://github.com/s0uthwest/futurerestore) iOS upgrade and downgrade tool utilizing SHSH blobs
- [**244**星][6m] [JS] [we11cheng/wcshadowrocket](https://github.com/we11cheng/wcshadowrocket) iOS Shadowrocket(砸壳重签,仅供参考,添加节点存在问题)。另一个fq项目potatso源码参见:
- [**242**星][4y] [C++] [meeloo/xspray](https://github.com/meeloo/xspray) A front end for lldb on OS X for Mac and iOS targets, with a twist
- [**241**星][2y] [C] [limneos/mobileminer](https://github.com/limneos/mobileminer) CPU Miner for ARM64 iOS Devices
- [**239**星][1y] [ObjC] [lmirosevic/gbping](https://github.com/lmirosevic/gbping) Highly accurate ICMP Ping controller for iOS
- [**238**星][4m] [Swift] [shadowsocksr-live/ishadowsocksr](https://github.com/shadowsocksr-live/ishadowsocksr) ShadowsocksR for iOS, come from
- [**229**星][3y] [Swift] [trailofbits/secureenclavecrypto](https://github.com/trailofbits/secureenclavecrypto) Demonstration library for using the Secure Enclave on iOS
- [**223**星][11m] [AppleScript] [lifepillar/csvkeychain](https://github.com/lifepillar/csvkeychain) Import/export between Apple Keychain.app and plain CSV file.
- [**219**星][6m] [ObjC] [rickyzhang82/tethering](https://github.com/rickyzhang82/tethering) Proxy and DNS Server on iOS
- [**213**星][8m] [C] [owasp/igoat](https://github.com/owasp/igoat) OWASP iGoat - A Learning Tool for iOS App Pentesting and Security by Swaroop Yermalkar
- [**211**星][5d] [TS] [bevry/getmac](https://github.com/bevry/getmac) Get the mac address of the current machine you are on via Node.js
- [**210**星][2y] [C] [cheesecakeufo/saigon](https://github.com/cheesecakeufo/saigon) iOS 10.2.1 - Discontinued version
- [**203**星][5m] [Py] [googleprojectzero/ios-messaging-tools](https://github.com/googleprojectzero/ios-messaging-tools) several tools Project Zero uses to test iPhone messaging
- [**200**星][5m] [PS] [mkellerman/invoke-commandas](https://github.com/mkellerman/invoke-commandas) Invoke Command As System/Interactive/GMSA/User on Local/Remote machine & returns PSObjects.
- [**199**星][25d] [ObjC] [everettjf/yolo](https://github.com/everettjf/yolo) Scripts or demo projects on iOS development or reverse engineering
- [**199**星][2y] [ObjC] [tihmstar/doubleh3lix](https://github.com/tihmstar/doubleh3lix) Jailbreak for iOS 10.x 64bit devices without KTRR
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**198**星][2y] [proteas/native-lldb-for-ios](https://github.com/proteas/native-lldb-for-ios) native LLDB(v3.8) for iOS
- [**198**星][19d] [Swift] [auth0/lock.swift](https://github.com/auth0/Lock.swift) A Swift & iOS framework to authenticate using Auth0 and with a Native Look & Feel
- [**195**星][1m] [Logos] [creantan/lookinloader](https://github.com/creantan/lookinloader) Lookin - iOS UI Debugging Tweak LookinLoader,Compatible with iOS 8~13
- [**193**星][4y] [C++] [isecpartners/jailbreak](https://github.com/isecpartners/jailbreak) Jailbreak
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**190**星][5d] [Py] [ydkhatri/mac_apt](https://github.com/ydkhatri/mac_apt) macOS Artifact Parsing Tool
- [**182**星][1m] [JS] [nowsecure/node-applesign](https://github.com/nowsecure/node-applesign) NodeJS module and commandline utility for re-signing iOS applications (IPA files).
- [**181**星][4y] [ObjC] [iosre/hippocamphairsalon](https://github.com/iosre/hippocamphairsalon) A simple universal memory editor (game trainer) on OSX/iOS
- [**181**星][12m] [zekesnider/nintendoswitchrestapi](https://github.com/zekesnider/nintendoswitchrestapi) Reverse engineered REST API used in the Nintendo Switch app for iOS. Includes documentation on Splatoon 2's API.
- [**180**星][4m] [Py] [anssi-fr/secuml](https://github.com/anssi-fr/secuml) Machine Learning for Computer Security
- [**180**星][8m] [Java] [yubico/ykneo-openpgp](https://github.com/yubico/ykneo-openpgp) OpenPGP applet for the YubiKey NEO
- [**174**星][1y] [ObjC] [macmade/filevaultcracker](https://github.com/macmade/filevaultcracker) macOS FileVault cracking tool
- [**172**星][15d] [C++] [samyk/frisky](https://github.com/samyk/frisky) Instruments to assist in binary application reversing and augmentation, geared towards walled gardens like iOS and macOS
- [**171**星][2y] [Py] [3gstudent/worse-pdf](https://github.com/3gstudent/worse-pdf) Turn a normal PDF file into malicious.Use to steal Net-NTLM Hashes from windows machines.
- [**171**星][10m] [Shell] [trustedsec/hardcidr](https://github.com/trustedsec/hardcidr) hardCIDR is a Linux Bash script, but also functions under macOS. Your mileage may vary on other distros. The script with no specified options will query ARIN and a pool of BGP route servers. The route server is selected at random at runtime.
- [**169**星][7m] [C] [octomagon/davegrohl](https://github.com/octomagon/davegrohl) A Password Cracker for macOS
- [**166**星][8m] [proteas/unstripped-ios-kernels](https://github.com/proteas/unstripped-ios-kernels) Unstripped iOS Kernels
- [**165**星][2y] [C++] [google/pawn](https://github.com/google/pawn) 从基于 Intel 的工作站和笔记本电脑中提取 BIOS 固件
- [**163**星][6y] [C] [gdbinit/readmem](https://github.com/gdbinit/readmem) A small OS X/iOS userland util to dump processes memory
- [**163**星][8m] [C] [tboox/itrace](https://github.com/tboox/itrace) Trace objc method call for ios and mac
- [**162**星][2y] [C++] [encounter/futurerestore](https://github.com/encounter/futurerestore) (unmaintained) iOS upgrade and downgrade tool utilizing SHSH blobs (unofficial fork supporting iOS 11 and newer devices)
- [**159**星][2m] [smilezxlee/crackediosapps](https://github.com/smilezxlee/crackediosapps) iOS端破解版App集合，包含破解版QQ、破解版抖音、破解版百度网盘、破解版麻花、钉钉打卡助手、破解版墨墨背单词、破解版网易云音乐、破解版芒果TV
- [**157**星][12d] [mac4n6/presentations](https://github.com/mac4n6/presentations) Presentation Archives for my macOS and iOS Related Research
- [**152**星][7y] [Py] [intrepidusgroup/imdmtools](https://github.com/intrepidusgroup/imdmtools) Intrepidus Group's iOS MDM tools
- [**147**星][3y] [Py] [biosbits/bits](https://github.com/biosbits/bits) BIOS Implementation Test Suite
- [**146**星][1y] [ObjC] [tihmstar/jelbrektime](https://github.com/tihmstar/jelbrektime) An developer jailbreak for Apple watch S3 watchOS 4.1
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**145**星][2y] [Shell] [depoon/iosdylibinjectiondemo](https://github.com/depoon/iosdylibinjectiondemo) Using this Repository to demo how to inject dynamic libraries into cracked ipa files for jailed iOS devices
- [**145**星][1y] [ObjC] [psychotea/meridianjb](https://github.com/psychotea/meridianjb) An iOS 10.x Jailbreak for all 64-bit devices.
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**144**星][10m] [Py] [dlcowen/fseventsparser](https://github.com/dlcowen/fseventsparser) Parser for OSX/iOS FSEvents Logs
- [**144**星][1y] [C] [geosn0w/osiris-jailbreak](https://github.com/geosn0w/osiris-jailbreak) An incomplete iOS 11.2 -> iOS 11.3.1 Jailbreak
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**144**星][4y] [ObjC] [etsy/bughunt-ios](https://github.com/etsy/bughunt-ios) 
- [**143**星][2y] [C] [rodionovd/liblorgnette](https://github.com/rodionovd/liblorgnette) Interprocess dlsym() for OS X & iOS
- [**140**星][4m] [Go] [greenboxal/dns-heaven](https://github.com/greenboxal/dns-heaven) 通过/etc/resolv.conf 启用本地 DNS stack 来修复（愚蠢的） macOS DNS stack
- [**139**星][2y] [Py] [google/tcp_killer](https://github.com/google/tcp_killer) 关闭 Linux或 MacOS 的 Tcp 端口
- [**139**星][8m] [C++] [macmade/dyld_cache_extract](https://github.com/macmade/dyld_cache_extract) A macOS utility to extract dynamic libraries from the dyld_shared_cache of macOS and iOS.
- [**130**星][4m] [Py] [apperian/ios-checkipa](https://github.com/apperian/ios-checkipa) Scans an IPA file and parses its Info.plist and embedded.mobileprovision files. Performs checks of expected key/value relationships and displays the results.
- [**129**星][4y] [Go] [benjojo/dos_ssh](https://github.com/benjojo/dos_ssh) Use BIOS ram hacks to make a SSH server out of any INT 10 13h app (MS-DOS is one of those)
- [**129**星][2m] [Py] [stratosphereips/stratospherelinuxips](https://github.com/stratosphereips/stratospherelinuxips) an intrusion prevention system that is based on behavioral detections and machine learning algorithms
- [**128**星][2y] [Py] [unfetter-discover/unfetter-analytic](https://github.com/unfetter-discover/unfetter-analytic) a framework for collecting events (process creation, network connections, Window Event Logs, etc.) from a client machine (Windows 7) and performing CAR analytics to detect potential adversary activity
- [**126**星][3m] [Py] [platomav/biosutilities](https://github.com/platomav/biosutilities) Various BIOS Utilities for Modding/Research
- [**126**星][4y] [Py] [sektioneins/sandbox_toolkit](https://github.com/sektioneins/sandbox_toolkit) Toolkit for binary iOS / OS X sandbox profiles
- [**125**星][8d] [C] [projecthorus/radiosonde_auto_rx](https://github.com/projecthorus/radiosonde_auto_rx) Automatically Track Radiosonde Launches using RTLSDR
- [**125**星][3y] [JS] [vtky/swizzler2](https://github.com/vtky/swizzler2) Swizzler2 - Hacking iOS applications
- [**121**星][2y] [Swift] [lxdcn/nepackettunnelvpndemo](https://github.com/lxdcn/nepackettunnelvpndemo) iOS VPN client implementation demo based on iOS9 NetworkExtension NETunnelProvider APIs
- [**119**星][1y] [Py] [winheapexplorer/winheap-explorer](https://github.com/winheapexplorer/winheap-explorer) heap-based bugs detection in x86 machine code for Windows applications.
- [**113**星][3y] [Objective-C++] [yonsm/ipafine](https://github.com/yonsm/ipafine) iOS IPA package refine and resign
- [**111**星][5m] [C++] [danielcardeenas/audiostego](https://github.com/danielcardeenas/audiostego) Audio file steganography. Hides files or text inside audio files and retrieve them automatically
- [**111**星][2y] [C] [openjailbreak/evasi0n6](https://github.com/openjailbreak/evasi0n6) Evasi0n6 Jailbreak by Evad3rs for iOS 6.0-6.1.2
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**110**星][7m] [C] [siguza/imobax](https://github.com/siguza/imobax) iOS Mobile Backup Extractor
- [**108**星][] [HTML] [cj123/canijailbreak.com](https://github.com/cj123/canijailbreak.com) a website which tells you whether you can jailbreak your iOS device.
    - 重复区段: [Apple->工具->越狱](#ff19d5d94315d035bbcb3ef0c348c75b) |
- [**106**星][7y] [intrepidusgroup/trustme](https://github.com/intrepidusgroup/trustme) Disable certificate trust checks on iOS devices.
- [**99**星][2y] [antid0tecom/ios-kerneldocs](https://github.com/Antid0teCom/ios-kerneldocs) Various files helping to better understand the iOS / WatchOS / tvOS kernels
- [**98**星][2y] [Py] [google/legilimency](https://github.com/google/legilimency) A Memory Research Platform for iOS
- [**96**星][7m] [Swift] [depoon/networkinterceptor](https://github.com/depoon/networkinterceptor) iOS URLRequest interception framework
- [**96**星][2y] [Swift] [liruqi/mume-ios](https://github.com/liruqi/mume-ios) an iOS client that implements custom proxies with the leverage of Network Extension framework introduced by Apple since iOS 9
- [**95**星][2y] [ObjC] [xslim/mobiledevicemanager](https://github.com/xslim/mobiledevicemanager) Manage iOS devices through iTunes lib
- [**93**星][1y] [Jupyter Notebook] [positivetechnologies/seq2seq-web-attack-detection](https://github.com/positivetechnologies/seq2seq-web-attack-detection) The implementation of the Seq2Seq model for web attack detection. The Seq2Seq model is usually used in Neural Machine Translation. The main goal of this project is to demonstrate the relevance of the NLP approach for web security.
- [**90**星][2y] [PS] [netbiosx/digital-signature-hijack](https://github.com/netbiosx/digital-signature-hijack) Binaries, PowerShell scripts and information about Digital Signature Hijacking.
- [**90**星][5y] [ObjC] [project-imas/app-password](https://github.com/project-imas/app-password) Custom iOS user authentication mechanism (password with security questions for self reset)
- [**85**星][4y] [Swift] [deniskr/keychainswiftapi](https://github.com/deniskr/keychainswiftapi) This Keychain Swift API library is a wrapper of iOS C Keychain Framework. It allows easily and securely storing sensitive data in secure keychain store.
- [**85**星][2y] [ObjC] [siguza/phoenixnonce](https://github.com/siguza/phoenixnonce) 64-bit nonce setter for iOS 9.3.4-9.3.5
- [**84**星][8m] [Py] [aaronst/macholibre](https://github.com/aaronst/macholibre) Mach-O & Universal Binary Parser
- [**83**星][10m] [Shell] [trailofbits/ios-integrity-validator](https://github.com/trailofbits/ios-integrity-validator) Integrity validator for iOS devices
- [**79**星][1y] [Swift] [aidevjoe/sandboxbrowser](https://github.com/aidevjoe/sandboxbrowser) A simple iOS sandbox file browser, you can share files through AirDrop
- [**79**星][4y] [mi3security/su-a-cyder](https://github.com/mi3security/su-a-cyder) Home-Brewed iOS Malware PoC Generator (BlackHat ASIA 2016)
- [**79**星][6y] [C] [peterfillmore/removepie](https://github.com/peterfillmore/removepie) removePIE changes the MH_PIE flag of the MACH-O header on iOS applications to disable ASLR on applications
- [**78**星][1y] [Shell] [iaik/ios-analysis](https://github.com/iaik/ios-analysis) Automated Binary Analysis on iOS
- [**77**星][2y] [ObjC] [cocoahuke/ioskextdump](https://github.com/cocoahuke/ioskextdump) Dump Kext information from iOS kernel cache. Applicable to the kernel which dump from memory
- [**75**星][7m] [Py] [tribler/dispersy](https://github.com/tribler/dispersy) The elastic database system. A database designed for P2P-like scenarios, where potentially millions of computers send database updates around.
- [**74**星][21d] [C] [certificate-helper/tls-inspector](https://github.com/certificate-helper/tls-inspector) Easily view and inspect X.509 certificates on your iOS device.
- [**72**星][4m] [C++] [macmade/unicorn-bios](https://github.com/macmade/unicorn-bios) Basic BIOS emulator for Unicorn Engine.
- [**72**星][6y] [Py] [piccimario/iphone-backup-analyzer-2](https://github.com/piccimario/iphone-backup-analyzer-2) iPBA, Qt version
- [**72**星][3y] [C++] [razzile/liberation](https://github.com/razzile/liberation) A runtime patching library for iOS. Major rework on unfinished branch
- [**72**星][22d] [Py] [ehco1996/aioshadowsocks](https://github.com/ehco1996/aioshadowsocks) 用 asyncio 重写 shadowsocks ~
- [**69**星][3m] [C] [brandonplank/rootlessjb4](https://github.com/BrandonPlank/rootlessJB4) rootlessJB that supports iOS 12.0 - 12.2 & 12.4
- [**67**星][14d] [Py] [guardianfirewall/grandmaster](https://github.com/guardianfirewall/grandmaster) A simplistic python tool that assists in automating iOS firmware decryption.
- [**65**星][4y] [zhengmin1989/ios-10-decrypted-kernel-cache](https://github.com/zhengmin1989/ios-10-decrypted-kernel-cache) iOS 10 Decrypted Kernel Cache
- [**65**星][5y] [ObjC] [project-imas/memory-security](https://github.com/project-imas/memory-security) Tools for securely clearing and validating iOS application memory
- [**63**星][2y] [josephlhall/dc25-votingvillage-report](https://github.com/josephlhall/dc25-votingvillage-report) A report to synthesize findings from the Defcon 25 Voting Machine Hacking Village
- [**62**星][8m] [C] [luoyanbei/testhookzz](https://github.com/luoyanbei/testhookzz) iOS逆向：使用HookZz框架hook游戏“我的战争”，进入上帝模式
- [**62**星][5m] [C++] [meitu/mtgldebug](https://github.com/meitu/mtgldebug) An OpenGL debugging tool for iOS.
- [**61**星][9y] [C] [chronic-dev/bootrom-dumper](https://github.com/chronic-dev/bootrom-dumper) Utility to Dump iPhone Bootrom
- [**61**星][6m] [PS] [texhex/biossledgehammer](https://github.com/texhex/biossledgehammer) Automated BIOS, ME, TPM firmware update and BIOS settings for HP devices
- [**61**星][10m] [ObjC] [tihmstar/v3ntex](https://github.com/tihmstar/v3ntex) getf tfp0 on iOS 12.0 - 12.1.2
- [**60**星][4y] [shadowsocks/tun2socks-ios](https://github.com/shadowsocks/tun2socks-ios) tun2socks as a library for iOS apps
- [**58**星][7m] [Perl] [dnsmichi/manubulon-snmp](https://github.com/dnsmichi/manubulon-snmp) Set of Icinga/Nagios plugins to check hosts and hardware wi the SNMP protocol.
- [**58**星][4y] [HTML] [nccgroup/iodide](https://github.com/nccgroup/iodide) The Cisco IOS Debugger and Integrated Disassembler Environment
- [**58**星][2y] [Shell] [tanprathan/fridpa](https://github.com/tanprathan/fridpa) An automated wrapper script for patching iOS applications (IPA files) and work on non-jailbroken device
- [**57**星][ObjC] [jrock007/tob](https://github.com/jrock007/tob) Free, open-source and ad-less Tor web browser for iOS
- [**56**星][10m] [ObjC] [geosn0w/chaos](https://github.com/geosn0w/chaos) Chaos iOS < 12.1.2 PoC by
- [**55**星][2y] [jkpang/timliu-ios](https://github.com/jkpang/timliu-ios) iOS开发常用三方库、插件、知名博客等等
- [**55**星][3y] [C++] [s-kanev/xiosim](https://github.com/s-kanev/xiosim) A detailed michroarchitectural x86 simulator
- [**55**星][3y] [C] [synack/chaoticmarch](https://github.com/synack/chaoticmarch) A mechanism for automating input events on iOS
- [**53**星][5m] [Py] [n0fate/ichainbreaker](https://github.com/n0fate/ichainbreaker) Breaking the iCloud Keychain Artifacts
- [**52**星][1y] [C] [bazad/threadexec](https://github.com/bazad/threadexec) A library to execute code in the context of other processes on iOS 11.
- [**52**星][2y] [rehints/blackhat_2017](https://github.com/rehints/blackhat_2017) Betraying the BIOS: Where the Guardians of the BIOS are Failing
- [**52**星][9m] [Logos] [zhaochengxiang/ioswechatfakelocation](https://github.com/zhaochengxiang/ioswechatfakelocation) A tweak that can fake location info in WeChat
- [**51**星][3y] [HTML] [pwnsdx/ios-uri-schemes-abuse-poc](https://github.com/pwnsdx/ios-uri-schemes-abuse-poc) A set of URI schemes bugs that lead Safari to crash/freeze.
- [**49**星][1y] [Swift] [sherlouk/swiftprovisioningprofile](https://github.com/sherlouk/swiftprovisioningprofile) Parse iOS mobile provisioning files into Swift models
- [**48**星][2y] [Shell] [leanvel/iinject](https://github.com/leanvel/iinject) Tool to automate the process of embedding dynamic libraries into iOS applications from GNU/Linux
- [**48**星][7m] [ObjC] [smilezxlee/zxhookutil](https://github.com/smilezxlee/zxhookutil) 【iOS逆向】Tweak工具函数集，基于theos、monkeyDev
- [**47**星][2m] [ObjC] [ooni/probe-ios](https://github.com/ooni/probe-ios) OONI Probe iOS
- [**47**星][4y] [Py] [ostorlab/jniostorlab](https://github.com/ostorlab/jniostorlab) JNI method enumeration in ELF files
- [**47**星][2m] [ObjC] [smilezxlee/zxrequestblock](https://github.com/smilezxlee/zxrequestblock) 一句话实现iOS应用底层所有网络请求拦截(如ajax请求拦截)，包含http-dns解决方法，有效防止DNS劫持，用于分析http，https请求，禁用/允许代理，防抓包等
- [**47**星][2m] [the-blockchain-bible/readme](https://github.com/the-blockchain-bible/readme) The Blockchain Bible,a collections for blockchain tech,bitcoin,ethereum,crypto currencies,cryptography,decentralized solutions,business scenarios,hyperledger tech,meetups,区块链,数字货币,加密货币,比特币,以太坊,密码学,去中心化,超级账本
- [**47**星][5y] [PHP] [cloudsec/aioshell](https://github.com/cloudsec/aioshell) A php webshell run under linux based webservers. v0.05
- [**46**星][2y] [C] [encounter/tsschecker](https://github.com/encounter/tsschecker) Check TSS signing status of iOS firmwares and save SHSH blobs
- [**46**星][2y] [uefitech/resources](https://github.com/uefitech/resources) One-stop shop for UEFI/BIOS specifications/utilities by UEFI.Tech community
- [**46**星][1y] [Go] [unixpickle/cve-2018-4407](https://github.com/unixpickle/cve-2018-4407) Crash macOS and iOS devices with one packet
- [**44**星][4y] [C] [samdmarshall/machodiff](https://github.com/samdmarshall/machodiff) mach-o diffing tool
- [**43**星][5y] [Shell] [netspi/heapdump-ios](https://github.com/netspi/heapdump-ios) Dump IOS application heap space from memory
- [**42**星][27d] [ObjC] [dineshshetty/ios-sandbox-dumper](https://github.com/dineshshetty/ios-sandbox-dumper) SandBox-Dumper makes use of multiple private libraries to provide exact locations of the application sandbox, application bundle and some other interesting information
- [**42**星][2y] [Py] [klsecservices/ios_mips_gdb](https://github.com/klsecservices/ios_mips_gdb) Cisco MIPS debugger
- [**40**星][7d] [Swift] [fonta1n3/fullynoded](https://github.com/fonta1n3/fullynoded) A Bitcoin Core GUI for iOS devices. Allows you to connect to and control multiple nodes via Tor
- [**39**星][3y] [Logos] [ahmadhashemi/immortal](https://github.com/ahmadhashemi/immortal) Prevent expiration of signed iOS applications & bypass 3 free signed applications per device limit
- [**39**星][3m] [Py] [gh2o/rvi_capture](https://github.com/gh2o/rvi_capture) rvictl for Linux and Windows: capture packets sent/received by iOS devices
- [**39**星][4y] [Pascal] [senjaxus/delphi_remote_access_pc](https://github.com/senjaxus/delphi_remote_access_pc) Remote access in Delphi 7 and Delphi XE5 (With sharer files, CHAT and Forms Inheritance) || Acesso Remoto em Delphi 7 e Delphi XE5 (Com Compartilhador de Arquivos, CHAT e Herança de Formulários)
- [**39**星][19d] [Shell] [userlandkernel/plataoplomo](https://github.com/userlandkernel/plataoplomo) Collection of (at time of release) iOS bugs I found
- [**39**星][2m] [Py] [meituan-dianping/lyrebird-ios](https://github.com/meituan-dianping/lyrebird-ios) 本程序是Lyrebird插件，您可以在插件中快速查看已连接iOS设备的详细设备信息，截取屏幕快照，以及查看已连接设备的应用信息。
- [**38**星][4y] [C] [taichisocks/shadowsocks](https://github.com/taichisocks/shadowsocks) Lightweight shadowsocks client for iOS and Mac OSX base on shadowsocks-libev
- [**38**星][1y] [ObjC] [xmartlabs/metalperformanceshadersproxy](https://github.com/xmartlabs/metalperformanceshadersproxy) A proxy for MetalPerformanceShaders which takes to a stub on a simulator and to the real implementation on iOS devices.
- [**37**星][4m] [Ruby] [appspector/ios-sdk](https://github.com/appspector/ios-sdk) AppSpector is a debugging service for mobile apps
- [**36**星][4y] [Objective-C++] [cyhe/iossecurity-attack](https://github.com/cyhe/iossecurity-attack) APP安全(逆向攻击篇)
- [**36**星][3y] [PS] [machosec/mystique](https://github.com/machosec/mystique) PowerShell module to play with Kerberos S4U extensions
- [**35**星][4y] [Py] [curehsu/ez-wave](https://github.com/curehsu/ez-wave) Tools for Evaluating and Exploiting Z-Wave Networks using Software-Defined Radios.
- [**35**星][1y] [Swift] [vixentael/zka-example](https://github.com/vixentael/zka-example) Zero Knowledge Application example, iOS, notes sharing, Firebase backend
- [**33**星][3y] [ObjC] [integrity-sa/introspy-ios](https://github.com/integrity-sa/introspy-ios) Security profiling for blackbox iOS
- [**33**星][7y] [C] [mubix/fakenetbios](https://github.com/mubix/fakenetbios) See here:
- [**33**星][9m] [Swift] [vixentael/ios-datasec-basics](https://github.com/vixentael/ios-datasec-basics) iOS data security basics: key management, workshop for iOS Con UK
- [**33**星][2m] [ObjC] [proteas/ios13-sandbox-profile-format](https://github.com/proteas/ios13-sandbox-profile-format) Binary Format of iOS 13 Sandbox Profile Collection
- [**31**星][3y] [Py] [as0ler/r2clutch](https://github.com/as0ler/r2clutch) r2-based tool to decrypt iOS applications
- [**31**星][3y] [Assembly] [gyje/bios_rootkit](https://github.com/gyje/bios_rootkit) 来自Freebuf评论区,一个UEFI马.
- [**31**星][2y] [proappleos/upgrade-from-10.3.x-to-ios-11.1.2-on-any-64bit-device-with-blobs](https://github.com/ProAppleOS/Upgrade-from-10.3.x-to-iOS-11.1.2-on-any-64Bit-device-with-Blobs) How to Upgrade any 64Bit Device from 10.3.x to 11.1.2 with Blobs
- [**30**星][3y] [ObjC] [mtigas/iobfs](https://github.com/mtigas/iobfs) Building obfs4proxy for Tor-enabled iOS apps.
- [**30**星][2y] [Shell] [pnptutorials/pnp-portablehackingmachine](https://github.com/pnptutorials/pnp-portablehackingmachine) This script will convert your Raspberry Pi 3 into a portable hacking machine.
- [**30**星][8y] [Py] [hubert3/isniff](https://github.com/hubert3/isniff) SSL man-in-the-middle tool targeting iOS devices < 4.3.5
- [**29**星][12m] [Py] [antid0tecom/ipad_accessory_research](https://github.com/antid0tecom/ipad_accessory_research) Research into Security of Apple Smart Keyboard and Apple Pencil
- [**29**星][4y] [ObjC] [quellish/facebook-ios-internal-headers](https://github.com/quellish/facebook-ios-internal-headers) Headers generated by reverse engineering the Facebook iOS binary
- [**29**星][8y] [sektioneins/.ipa-pie-scanner](https://github.com/sektioneins/.ipa-PIE-Scanner) Scans iPhone/iPad/iPod applications for PIE flags
- [**29**星][4y] [C] [scallywag/nbtscan](https://github.com/scallywag/nbtscan) NetBIOS scanning tool. Currently segfaults!
- [**28**星][2y] [ObjC] [dannagle/packetsender-ios](https://github.com/dannagle/packetsender-ios) Packet Sender for iOS, Send/Receive UDP/TCP
- [**28**星][2y] [Swift] [jeanshuang/potatso](https://github.com/jeanshuang/potatso) 适配Xcode9.3 iOS11.3 Swift3.3编译通过。 (unmaintained) Potatso is an iOS client that implements Shadowsocks proxy with the leverage of NetworkExtension framework in iOS 9.
- [**28**星][10m] [C] [mrmacete/r2-ios-kernelcache](https://github.com/mrmacete/r2-ios-kernelcache) Radare2 plugin to parse modern iOS 64-bit kernel caches
- [**28**星][3y] [C] [salmg/audiospoof](https://github.com/salmg/audiospoof) Magnetic stripe spoofer implementing audio waves.
- [**28**星][4y] [Swift] [urinx/device-9](https://github.com/urinx/device-9) 实时监测网速，IP，内存大小，温度等设备信息并显示在通知中心的 iOS App
- [**27**星][1y] [alonemonkey/iosrebook-issues](https://github.com/alonemonkey/iosrebook-issues) 《iOS应用逆向与安全》 勘误
- [**27**星][19d] [Perl] [hknutzen/netspoc](https://github.com/hknutzen/netspoc) A network security policy compiler. Netspoc is targeted at large environments with a large number of firewalls and admins. Firewall rules are derived from a single rule set. Supported are Cisco IOS, NX-OS, ASA and IPTables.
- [**27**星][3m] [Rust] [marcograss/rust-kernelcache-extractor](https://github.com/marcograss/rust-kernelcache-extractor) Extract a decrypted iOS 64-bit kernelcache
- [**27**星][7m] [Py] [qingxp9/cve-2019-6203-poc](https://github.com/qingxp9/cve-2019-6203-poc) PoC for CVE-2019-6203, works on < iOS 12.2, macOS < 10.14.4
- [**27**星][4m] [Py] [mvelazc0/purplespray](https://github.com/mvelazc0/purplespray) PurpleSpray is an adversary simulation tool that executes password spray behavior under different scenarios and conditions with the purpose of generating attack telemetry in properly monitored Windows enterprise environments
- [**26**星][2y] [C++] [cuitche/code-obfuscation](https://github.com/cuitche/code-obfuscation) 一款iOS代码混淆工具(A code obfuscation tool for iOS.)
- [**26**星][5m] [HTML] [devnetsandbox/sbx_multi_ios](https://github.com/devnetsandbox/sbx_multi_ios) Sample code, examples, and resources for use with the DevNet Multi-IOS Sandbox
- [**26**星][4y] [ObjC] [qiuyuzhou/shadowsocks-ios](https://github.com/qiuyuzhou/shadowsocks-ios) No maintaining. Try this
- [**26**星][3y] [ObjC] [nabla-c0d3/ios-reversing](https://github.com/nabla-c0d3/ios-reversing) Some iOS tools and scripts from 2014 for iOS reversing.
- [**26**星][4m] [Swift] [itsjohnye/lead-ios](https://github.com/itsjohnye/lead-ios) a featherweight iOS SS proxy client with interactive UI
- [**25**星][2y] [C] [embedi/tcl_shellcode](https://github.com/embedi/tcl_shellcode) A template project for creating a shellcode for the Cisco IOS in the C language
- [**25**星][1y] [HTML] [649/crash-ios-exploit](https://github.com/649/crash-ios-exploit) Repository dedicated to storing a multitude of iOS/macOS/OSX/watchOS crash bugs. Some samples need to be viewed as raw in order to see the Unicode. Please do not intentionally abuse these exploits.
- [**24**星][6y] [ObjC] [samdmarshall/ios-internals](https://github.com/samdmarshall/ios-internals) iOS related code
- [**23**星][5y] [Ruby] [claudijd/bnat](https://github.com/claudijd/bnat) "Broken NAT" - A suite of tools focused on detecting and interacting with publicly available BNAT scenerios
- [**23**星][12m] [ObjC] [rpwnage/warri0r](https://github.com/RPwnage/Warri0r) ios 12 Sandbox escape POC
- [**22**星][2y] [jasklabs/blackhat2017](https://github.com/jasklabs/blackhat2017) Data sets and examples for Jask Labs Blackhat 2017 Handout: Top 10 Machine Learning Cyber Security Use Cases
- [**22**星][4y] [sunkehappy/ios-reverse-engineering-tools-backup](https://github.com/sunkehappy/ios-reverse-engineering-tools-backup) Some guys find the old lsof could not be downloaded. But I have it and I want to share it.
- [**22**星][1y] [PHP] [svelizdonoso/asyrv](https://github.com/svelizdonoso/asyrv) ASYRV es una aplicación escrita en PHP/MySQL, con Servicios Web mal desarrollados(SOAP/REST/XML), esperando ayudar a los entusiastas de la seguridad informática a comprender esta tecnología tan utilizada hoy en día por las Organizaciones.
- [**21**星][2y] [troydo42/awesome-pen-test](https://github.com/troydo42/awesome-pen-test) Experiment with penetration testing Guides and Tools for WordPress, iOS, MacOS, Wifi and Car
- [**20**星][1y] [C] [downwithup/cve-2018-16712](https://github.com/downwithup/cve-2018-16712) PoC Code for CVE-2018-16712 (exploit by MmMapIoSpace)
- [**20**星][4y] [C] [jonathanseals/ios-kexec-utils](https://github.com/jonathanseals/ios-kexec-utils) I'm taking a break, I swear
- [**20**星][1y] [Ruby] [martinvigo/ransombile](https://github.com/martinvigo/ransombile) Ransombile is a tool that can be used in different scenarios to compromise someone’s digital life when having physical access to a locked mobile device
- [**19**星][3y] [Swift] [depoon/injectiblelocationspoofing](https://github.com/depoon/injectiblelocationspoofing) Location Spoofing codes for iOS Apps via Code Injection
- [**19**星][1y] [ObjC] [frpccluster/frpc-ios](https://github.com/frpccluster/frpc-ios) IOS,苹果版frpc.一个快速反向代理，可帮助您将NAT或防火墙后面的本地服务器暴露给Internet。
- [**19**星][6y] [Logos] [iosre/iosrelottery](https://github.com/iosre/iosrelottery) 
- [**18**星][4d] [Py] [adafruit/adafruit_circuitpython_rfm9x](https://github.com/adafruit/adafruit_circuitpython_rfm9x) CircuitPython module for the RFM95/6/7/8 LoRa wireless 433/915mhz packet radios.
- [**17**星][1y] [C] [xerub/ios-kexec-utils](https://github.com/xerub/ios-kexec-utils) I'm taking a break, I swear
- [**16**星][4y] [ashishb/ios-malware](https://github.com/ashishb/ios-malware) iOS malware samples
- [**16**星][2y] [ObjC] [mikaelbo/updateproxysettings](https://github.com/mikaelbo/updateproxysettings) A simple iOS command line tool for updating proxy settings
- [**16**星][1y] [Py] [r3dxpl0it/cve-2018-4407](https://github.com/r3dxpl0it/cve-2018-4407) IOS/MAC Denial-Of-Service [POC/EXPLOIT FOR MASSIVE ATTACK TO IOS/MAC IN NETWORK]
- [**15**星][2y] [Objective-C++] [ay-kay/cda](https://github.com/ay-kay/cda) iOS command line tool to search for installed apps and list container paths (bundle, data, group)
- [**15**星][2y] [Py] [mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) a list of BIOS/Firmware fixes adressing CVE-2017-5715, CVE-2017-5753, CVE-2017-5754
- [**15**星][2y] [Swift] [vgmoose/nc-client](https://github.com/vgmoose/nc-client) [iOS] netcat gui app, for using the 10.1.x mach_portal root exploit on device
- [**15**星][12m] [aliasrobotics/rctf](https://github.com/aliasrobotics/rctf) Scenarios of the Robotics CTF (RCTF), a playground to challenge robot security.
- [**14**星][2m] [refractionpoint/limacharlie](https://github.com/refractionpoint/limacharlie) Old home of LimaCharlie, open source EDR
- [**14**星][7y] [Py] [trotsky/insyde-tools](https://github.com/trotsky/insyde-tools) (Inactive) Tools for unpacking and modifying an InsydeH2O UEFI BIOS now merged into coreboot
- [**14**星][5y] [C] [yifanlu/polipo-ios](https://github.com/yifanlu/polipo-ios) iOS port of Polipo caching HTTP proxy
- [**13**星][1y] [ObjC] [omerporze/toothfairy](https://github.com/omerporze/toothfairy) CVE-2018-4330 POC for iOS
- [**13**星][6y] [Py] [yuejd/ios_restriction_passcode_crack---python-version](https://github.com/yuejd/ios_restriction_passcode_crack---python-version) Crack ios Restriction PassCode in Python
- [**13**星][1m] [Shell] [ewypych/icinga-domain-expiration-plugin](https://github.com/ewypych/icinga-domain-expiration-plugin) Icinga2/Nagios plugin for checking domain expiration
- [**12**星][8y] [C] [akgood/iosbasicconstraintsworkaround](https://github.com/akgood/iosbasicconstraintsworkaround) Proof-of-Concept OpenSSL-based workaround for iOS basicConstraints SSL certificate validation vulnerability
- [**12**星][10m] [Py] [wyatu/cve-2018-4407](https://github.com/wyatu/cve-2018-4407) CVE-2018-4407 IOS/macOS kernel crash
- [**11**星][8m] [Swift] [sambadiallob/pubnubchat](https://github.com/sambadiallob/pubnubchat) An anonymous chat iOS app made using PubNub
- [**11**星][3y] [ObjC] [flankerhqd/descriptor-describes-toctou](https://github.com/flankerhqd/descriptor-describes-toctou) POCs for IOMemoryDescriptor racing bugs in iOS/OSX kernels
- [**10**星][1y] [Py] [zteeed/cve-2018-4407-ios](https://github.com/zteeed/cve-2018-4407-ios) POC: Heap buffer overflow in the networking code in the XNU operating system kernel
- [**9**星][2y] [Logos] [asnowfish/ios-system](https://github.com/asnowfish/ios-system) iOS系统的逆向代码
- [**9**星][4y] [C] [yigitcanyilmaz/iohideventsystemuserclient](https://github.com/yigitcanyilmaz/iohideventsystemuserclient) iOS Kernel Race Vulnerability (Patched on iOS 9.3.2,OSX 10.11.5,tvOS 9.2.1 by Apple)
- [**9**星][2y] [C] [syst3ma/cisco_ios_research](https://github.com/syst3ma/cisco_ios_research) 
- [**9**星][2m] [nemo-wq/privilege_escalation](https://github.com/nemo-wq/privilege_escalation) Lab exercises to practice privilege escalation scenarios in AWS IAM. These exercises and the slides go through the basics behind AWS IAM, common weaknesses in AWS deployments, specific to IAM, and how to exploit them manually. This was run as a workshop at BruCon 2019.
- [**9**星][2y] [C] [syst3ma/cisco_ios_research](https://github.com/syst3ma/cisco_ios_research) 
- [**8**星][6y] [C] [linusyang/sslpatch](https://github.com/linusyang/sslpatch) Patch iOS SSL vulnerability (CVE-2014-1266)
- [**8**星][2y] [pinczakko/nsa_bios_backdoor_articles](https://github.com/pinczakko/nsa_bios_backdoor_articles) PDF files of my articles on NSA BIOS backdoor
- [**8**星][2y] [JS] [ansjdnakjdnajkd/frinfo](https://github.com/ansjdnakjdnajkd/frinfo) Dump files, data, cookies, keychain and etc. from iOS device with one click.
- [**7**星][7y] [ObjC] [hayaq/recodesign](https://github.com/hayaq/recodesign) Re-codesigning tool for iOS ipa file
- [**7**星][10m] [Py] [shawarkhanethicalhacker/cve-2019-8389](https://github.com/shawarkhanethicalhacker/cve-2019-8389) [CVE-2019-8389] An exploit code for exploiting a local file read vulnerability in Musicloud v1.6 iOS Application
- [**7**星][1y] [C] [ukern-developers/xnu-kernel-fuzzer](https://github.com/ukern-developers/xnu-kernel-fuzzer) Kernel Fuzzer for Apple's XNU, mainly meant for the iOS operating system
- [**6**星][2y] [C] [jduncanator/isniff](https://github.com/jduncanator/isniff) Packet capture and network sniffer for Apple iOS devices (iPhone / iPod). An implementation of iOS 5+ Remote Virtual Interface service and pcapd.
- [**6**星][6y] [Shell] [rawrly/juicejacking](https://github.com/rawrly/juicejacking) Several script and images used with the juice jacking kiosks
- [**6**星][8y] [Ruby] [spiderlabs/bnat-suite](https://github.com/spiderlabs/bnat-suite) "Broken NAT" - A suite of tools focused on detecting/exploiting/fixing publicly available BNAT scenerios
- [**4**星][11m] [anonymouz4/apple-remote-crash-tool-cve-2018-4407](https://github.com/anonymouz4/apple-remote-crash-tool-cve-2018-4407) Crashes any macOS High Sierra or iOS 11 device that is on the same WiFi network
- [**4**星][2y] [C] [chibitronics/ltc-os](https://github.com/chibitronics/ltc-os) ChibiOS-based operating system for the Love-to-Code project
- [**4**星][2y] [Swift] [crazyquark/keysafe](https://github.com/crazyquark/keysafe) A technical demo on how to use KeySecGeneratePair() with the secure enclave in iOS 9+
- [**4**星][8y] [ObjC] [spiderlabs/twsl2011-007_ios_code_workaround](https://github.com/spiderlabs/twsl2011-007_ios_code_workaround) Workaround for the vulnerability identified by TWSL2011-007 or CVE-2008-0228 - iOS x509 Certificate Chain Validation Vulnerability
- [**3**星][3y] [ObjC] [susnmos/xituhook](https://github.com/susnmos/xituhook) 逆向分析及修复稀土掘金iOS版客户端闪退bug
- [**3**星][4y] [Py] [torque59/yso-mobile-security-framework](https://github.com/torque59/yso-mobile-security-framework) Mobile Security Framework is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static and dynamic analysis.
- [**3**星][1y] [tthtlc/awesome_malware_techniques](https://github.com/tthtlc/awesome_malware_techniques) This will compile a list of Android, iOS, Linux malware techniques for attacking and detection purposes.
- [**3**星][4y] [Py] [tudorthe1ntruder/rubber-ducky-ios-pincode-bruteforce](https://github.com/tudorthe1ntruder/rubber-ducky-ios-pincode-bruteforce) 
- [**2**星][3y] [Py] [alexplaskett/needle](https://github.com/alexplaskett/needle) The iOS Security Testing Framework.
- [**2**星][5y] [HTML] [dhirajongithub/owasp-kalp-mobile-project-ios-app](https://github.com/dhirajongithub/owasp-kalp-mobile-project-ios-app) OWASP KALP Mobile Project is an iOS application developed for users to view OWASP Top 10 (WEB and MOBILE) on mobile device.
- [**2**星][2y] [C] [kigkrazy/hookzz](https://github.com/kigkrazy/hookzz) a cute hook framwork for arm/arm64/ios/android
- [**2**星][3y] [C] [ohdarling/potatso-ios](https://github.com/ohdarling/potatso-ios) Potatso is an iOS client that implements Shadowsocks proxy with the leverage of NetworkExtension framework in iOS 9.
- [**2**星][12m] [Py] [zeng9t/cve-2018-4407-ios-exploit](https://github.com/zeng9t/cve-2018-4407-ios-exploit) CVE-2018-4407,iOS exploit
- [**2**星][2y] [nrollr/ios](https://github.com/nrollr/ios) Ivan Krstić - Black Hat 2016 presentation
- [**1**星][10m] [Ruby] [hercules-team/augeasproviders_nagios](https://github.com/hercules-team/augeasproviders_nagios) Augeas-based nagios types and providers for Puppet
- [**1**星][4y] [Go] [jordan2175/ios-passcode-crack](https://github.com/jordan2175/ios-passcode-crack) Tool for cracking the iOS restrictions passcode
- [**0**星][2y] [ObjC] [joedaguy/exploit11.2](https://github.com/joedaguy/exploit11.2) Exploit iOS 11.2.x by ZIMPERIUM and semi-completed by me. Sandbox escapes on CVE-2018-4087.
- [**0**星][3y] [C] [maximehip/extra_recipe](https://github.com/maximehip/extra_recipe) Ian Beer's exploit for CVE-2017-2370 (kernel memory r/w on iOS 10.2)
- [**0**星][6y] [ObjC] [skycure/skycure_news](https://github.com/skycure/skycure_news) Sample news iOS application
- [**0**星][2y] [Py] [tsunghowu/diskimagecreator](https://github.com/tsunghowu/diskimagecreator) A python utility to process the input raw disk image and sign MBR/partitions with given corresponding keys. This tool is designed to help people attack the machine with a secure chain-of-trust boot process in UEFI BIOS.
- [**0**星][3y] [Swift] [jencisov/stackview](https://github.com/jencisov/StackView) POC project of StackViews on iOS
- [**0**星][2m] [HTML] [dotnetnicaragua/example-xss-crosssitescripting](https://github.com/dotnetnicaragua/example-xss-crosssitescripting) Ejemplo de vulnerabilidad: A7 - Secuencia de Comandos en Sitios Cruzados (XSS) según OWASP TOP 10 2017


### <a id="7037d96c1017978276cb920f65be2297"></a>XCode


- [**6203**星][3m] [ObjC] [johnno1962/injectionforxcode](https://github.com/johnno1962/injectionforxcode) Runtime Code Injection for Objective-C & Swift
- [**1606**星][2m] [Swift] [indragiek/inappviewdebugger](https://github.com/indragiek/inappviewdebugger) A UIView debugger (like Reveal or Xcode) that can be embedded in an app for on-device view debugging
- [**1409**星][27d] [Swift] [johnno1962/injectioniii](https://github.com/johnno1962/injectioniii) Re-write of Injection for Xcode in (mostly) Swift4
- [**572**星][1m] [ObjC] [hdb-li/lldebugtool](https://github.com/hdb-li/lldebugtool) LLDebugTool is a debugging tool for developers and testers that can help you analyze and manipulate data in non-xcode situations.
- [**497**星][7y] [C] [ghughes/fruitstrap](https://github.com/ghughes/fruitstrap) Install and debug iPhone apps from the command line, without using Xcode
- [**384**星][2m] [JS] [johnno1962/xprobeplugin](https://github.com/johnno1962/xprobeplugin) Live Memory Browser for Apps & Xcode
- [**179**星][4y] [ObjC] [x43x61x69/otx](https://github.com/x43x61x69/otx) The Mach-O disassembler. Now 64bit and Xcode 6 compatible.
- [**135**星][1y] [Swift] [danleechina/mixplaintext](https://github.com/danleechina/mixplaintext) 可对 Xcode 项目工程所有的 objective-c 文件内包含的明文进行加密混淆，提高逆向分析难度。
- [**135**星][1y] [Shell] [onmyway133/swiftsnippets](https://github.com/onmyway133/SwiftSnippets) A collection of Swift snippets to be used in Xcode 
- [**48**星][2y] [C++] [tonyzesto/pubgprivxcode85](https://github.com/tonyzesto/pubgprivxcode85) Player ESP 3D Box ESP Nametag ESP Lightweight Code Secure Injection Dedicated Cheat Launcher Secured Against Battleye Chicken Dinner Every Day. Win more matches than ever before with CheatAutomation’s Playerunknown’s Battlegrounds cheat! Our stripped down, ESP only cheat gives you the key features you need to take out your opponents and be eatin…
- [**45**星][6m] [Swift] [git-kevinchuang/potatso-swift5](https://github.com/git-kevinchuang/potatso-swift5) Potatso compiled with swift5 xcode 10.2.1 mojave 10.14.5
- [**44**星][3y] [Shell] [vtky/resign](https://github.com/vtky/resign) XCode Project to resign .ipa files
- [**28**星][1m] [Swift] [hdb-li/lldebugtoolswift](https://github.com/hdb-li/lldebugtoolswift) LLDebugTool is a debugging tool for developers and testers that can help you analyze and manipulate data in non-xcode situations.
- [**24**星][12m] [Swift] [shoheiyokoyama/lldb-debugging](https://github.com/shoheiyokoyama/lldb-debugging) The LLDB Debugging in C, Swift, Objective-C, Python and Xcode
- [**17**星][2y] [maxfong/obfuscatorxcplugin](https://github.com/maxfong/obfuscatorxcplugin) 逻辑混淆XCode插件
- [**1**星][2y] [Swift] [wdg/webshell-builder](https://github.com/wdg/webshell-builder) A WebShell application builder (no use of Xcode)


### <a id="ff19d5d94315d035bbcb3ef0c348c75b"></a>越狱


- [**5451**星][3m] [Py] [axi0mx/ipwndfu](https://github.com/axi0mx/ipwndfu) open-source jailbreaking tool for many iOS devices
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**5390**星][5m] [C] [pwn20wndstuff/undecimus](https://github.com/pwn20wndstuff/undecimus) unc0ver jailbreak for iOS 11.0 - 12.4
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**4248**星][8m] [ObjC] [alonemonkey/monkeydev](https://github.com/alonemonkey/monkeydev) CaptainHook Tweak、Logos Tweak and Command-line Tool、Patch iOS Apps, Without Jailbreak.
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**3221**星][5m] [ObjC] [naituw/ipapatch](https://github.com/naituw/ipapatch) Patch iOS Apps, The Easy Way, Without Jailbreak.
- [**2016**星][3y] [Swift] [urinx/iosapphook](https://github.com/urinx/iosapphook) 专注于非越狱环境下iOS应用逆向研究，从dylib注入，应用重签名到App Hook
- [**1800**星][3y] [ObjC] [kpwn/yalu102](https://github.com/kpwn/yalu102) incomplete iOS 10.2 jailbreak for 64 bit devices by qwertyoruiopz and marcograssi
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**642**星][2y] [C] [coolstar/electra](https://github.com/coolstar/electra) iOS 11.0 - 11.1.2 越狱工具包, 基于 async_awake
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**482**星][2y] [Objective-C++] [bishopfox/bfinject](https://github.com/bishopfox/bfinject) Dylib injection for iOS 11.0 - 11.1.2 with LiberiOS and Electra jailbreaks
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**415**星][2y] [zhengmin1989/greatiosjailbreakmaterial](https://github.com/zhengmin1989/greatiosjailbreakmaterial) Great iOS Jailbreak Material! - I read hundreds of papers and PPTs. Only list the most useful materials here!
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**404**星][1y] [C] [coalfire-research/ios-11.1.2-15b202-jailbreak](https://github.com/coalfire-research/ios-11.1.2-15b202-jailbreak) iOS 11.1.2 (15B202) Jailbreak
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**386**星][3y] [ObjC] [kpwn/yalu](https://github.com/kpwn/yalu) incomplete ios 8.4.1 jailbreak by Kim Jong Cracks (8.4.1 codesign & sandbox bypass w/ LPE to root & untether)
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**384**星][2y] [Assembly] [sgayou/kindle-5.6.5-jailbreak](https://github.com/sgayou/kindle-5.6.5-jailbreak) Kindle 5.6.5 exploitation tools.
- [**379**星][2y] [ObjC] [codermjlee/mjapptools](https://github.com/codermjlee/mjapptools) 【越狱-逆向】处理iOS APP信息的命令行工具
- [**375**星][6y] [C] [heardrwt/revealloader](https://github.com/heardrwt/revealloader) Reveal Loader dynamically loads libReveal.dylib (Reveal.app support) into iOS apps on jailbroken devices.
- [**365**星][9y] [C] [psgroove/psgroove](https://github.com/psgroove/psgroove) an open-source reimplementation of the psjailbreak exploit for AT90USB and related microcontrollers.
- [**291**星][4y] [Perl] [bishopfox/theos-jailed](https://github.com/bishopfox/theos-jailed) A version of Theos/CydiaSubstrate for non-jailbroken iOS devices
- [**287**星][6m] [Shell] [0ki/mikrotik-tools](https://github.com/0ki/mikrotik-tools) Tools for Mikrotik devices -  universal jailbreak tool
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**273**星][2y] [C] [bishopfox/bfdecrypt](https://github.com/bishopfox/bfdecrypt) Utility to decrypt App Store apps on jailbroken iOS 11.x
- [**240**星][2y] [ObjC] [sticktron/g0blin](https://github.com/sticktron/g0blin) a work-in-progress jailbreak for iOS 10.3.x (A7-A9)
- [**237**星][11m] [C] [geosn0w/osirisjailbreak12](https://github.com/geosn0w/osirisjailbreak12) iOS 12.0 -> 12.1.2 Incomplete Osiris Jailbreak with CVE-2019-6225 by GeoSn0w (FCE365)
- [**200**星][1y] [ObjC] [sunweiliang/neteasemusiccrack](https://github.com/sunweiliang/neteasemusiccrack) iOS网易云音乐 免VIP下载、去广告、去更新 无需越狱...
- [**199**星][2y] [ObjC] [tihmstar/doubleh3lix](https://github.com/tihmstar/doubleh3lix) Jailbreak for iOS 10.x 64bit devices without KTRR
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**193**星][4y] [C++] [isecpartners/jailbreak](https://github.com/isecpartners/jailbreak) Jailbreak
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**157**星][9y] [C] [comex/star](https://github.com/comex/star) the code behind the second incarnation of jailbreakme.com
- [**146**星][1y] [ObjC] [tihmstar/jelbrektime](https://github.com/tihmstar/jelbrektime) An developer jailbreak for Apple watch S3 watchOS 4.1
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**145**星][1y] [Shell] [kirovair/delectra](https://github.com/kirovair/delectra) An uninstaller script for Coolstars' Electra iOS 11.0 - 11.1.2 jailbreak.
- [**145**星][1y] [ObjC] [psychotea/meridianjb](https://github.com/psychotea/meridianjb) An iOS 10.x Jailbreak for all 64-bit devices.
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**144**星][1y] [C] [geosn0w/osiris-jailbreak](https://github.com/geosn0w/osiris-jailbreak) An incomplete iOS 11.2 -> iOS 11.3.1 Jailbreak
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**144**星][3y] [ObjC] [project-imas/security-check](https://github.com/project-imas/security-check) Application level, attached debug detect and jailbreak checking
- [**128**星][4y] [C] [stefanesser/opensource_taig](https://github.com/stefanesser/opensource_taig) Lets create an open source version of the latest TaiG jailbreak.
- [**111**星][2y] [C] [openjailbreak/evasi0n6](https://github.com/openjailbreak/evasi0n6) Evasi0n6 Jailbreak by Evad3rs for iOS 6.0-6.1.2
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**110**星][2y] [ObjC] [rozbo/ios-pubgm-hack](https://github.com/rozbo/ios-pubgm-hack) iOS吃鸡辅助
- [**109**星][9m] [ObjC] [devapple/yalu103](https://github.com/devapple/yalu103) incomplete iOS 10.3Betas jailbreak for 64 bit devices by qwertyoruiopz, marcograssi, and devapple (personal use)
- [**108**星][] [HTML] [cj123/canijailbreak.com](https://github.com/cj123/canijailbreak.com) a website which tells you whether you can jailbreak your iOS device.
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**100**星][2y] [Objective-C++] [electrajailbreak/cydia](https://github.com/electrajailbreak/cydia) Cydia modified for iOS 11/Electra
- [**99**星][2y] [ObjC] [geosn0w/yalu-jailbreak-ios-10.2](https://github.com/geosn0w/yalu-jailbreak-ios-10.2) My own fork of (Beta) Yalu Jailbreak for iOS 10.0 to 10.2 by
- [**96**星][3y] [Py] [chaitin/pro](https://github.com/chaitin/pro) A crappy tool used in our private PS4 jailbreak
- [**93**星][7y] [C] [planetbeing/ios-jailbreak-patchfinder](https://github.com/planetbeing/ios-jailbreak-patchfinder) Analyzes a binary iOS kernel to determine function offsets and where to apply the canonical jailbreak patches.
- [**89**星][3y] [ObjC] [jamie72/ipapatch](https://github.com/jamie72/ipapatch) Patch iOS Apps, The Easy Way, Without Jailbreak.
- [**89**星][3y] [Logos] [thomasfinch/priorityhub](https://github.com/thomasfinch/priorityhub) Sorted notifications jailbreak tweak
- [**83**星][5m] [ObjC] [smilezxlee/zxhookdetection](https://github.com/smilezxlee/zxhookdetection) 【iOS应用安全】hook及越狱的基本防护与检测(动态库注入检测、hook检测与防护、越狱检测、签名校验)
- [**80**星][2y] [C] [axi0mx/ios-kexec-utils](https://github.com/axi0mx/ios-kexec-utils) boot LLB/iBoot/iBSS/iBEC image from a jailbroken iOS kernel
- [**77**星][1y] [JS] [mtjailed/jailbreakme](https://github.com/mtjailed/jailbreakme) A webbased jailbreak solution unifying existing jailbreak me solutions and new ones.
- [**72**星][2y] [ObjC] [sunweiliang/baiduyuncrack](https://github.com/sunweiliang/baiduyuncrack) iOS百度云盘 破解速度限制、去广告、去更新 无需越狱~
- [**65**星][3y] [ObjC] [zhengmin1989/yalu102](https://github.com/zhengmin1989/yalu102) incomplete iOS 10.2 jailbreak for 64 bit devices by qwertyoruiopz and marcograssi
- [**62**星][2y] [ObjC] [rickhe/rhwechat](https://github.com/rickhe/rhwechat) iOS 无需越狱逆向微信：自动抢红包
- [**58**星][2y] [C++] [openjailbreak/jailbreakme-1.0](https://github.com/openjailbreak/jailbreakme-1.0) The first publicly available userland jailbreak for iPhoneOS 1.0.2/1.1.1 by cmw and dre
- [**55**星][1y] [JS] [userlandkernel/jailbreakme-unified](https://github.com/userlandkernel/jailbreakme-unified) Framework for iOS browser exploitation to kernel privileges and rootfs remount
- [**52**星][2y] [Shell] [alephsecurity/initroot](https://github.com/alephsecurity/initroot) Motorola Untethered Jailbreak: Exploiting CVE-2016-10277 for Secure Boot and Device Locking bypass
- [**51**星][1y] [C] [pwn20wndstuff/osiris](https://github.com/pwn20wndstuff/osiris) Osiris developer jailbreak for iOS 11.0 - 11.4b3
- [**50**星][9m] [Swift] [joncardasis/to-the-apples-core](https://github.com/joncardasis/to-the-apples-core) A collection of non-jailbroken code snippets on reverse-engineered iOS private apis
- [**49**星][2y] [JS] [idan5x/switcheroo](https://github.com/idan5x/switcheroo) Exploiting CVE-2016-4657 to JailBreak the Nintendo Switch
- [**47**星][6m] [Py] [ivrodriguezca/decrypt-ios-apps-script](https://github.com/ivrodriguezca/decrypt-ios-apps-script) Python script to SSH into your jailbroken device, decrypt an iOS App and transfer it to your local machine
- [**45**星][2y] [C] [geosn0w/ios-10.1.1-project-0-exploit-fork](https://github.com/geosn0w/ios-10.1.1-project-0-exploit-fork) iOS 10.1.1 Project 0 Exploit Compatible with All arm64 devices for Jailbreak Development
- [**41**星][3y] [kd1991/oxul103-jailbreak](https://github.com/KD1991/OXUL103-Jailbreak) A NEW 64-bit JAILBREAK FOR iOS 10.3,10.3.1,10.3.2,10.3.x. (Untethered).
- [**40**星][1y] [C] [in7egral/taig8-ios-jailbreak-patchfinder](https://github.com/in7egral/taig8-ios-jailbreak-patchfinder) Analyzes a binary iOS kernel to determine function offsets and where to apply the canonical jailbreak patches.
- [**37**星][5m] [C] [geosn0w/geofilza](https://github.com/geosn0w/geofilza) Filza No Jailbreak
- [**35**星][4y] [ObjC] [billy-ellis/ios-file-explorer](https://github.com/billy-ellis/ios-file-explorer) No-jailbreak file explorer application for iOS
- [**34**星][2y] [C] [mtjailed/purplesmoke](https://github.com/mtjailed/purplesmoke) A work-in-progress repository for breaking the security of iOS 11.2 up to 11.2.6
- [**33**星][2y] [ObjC] [mtjailed/privateapimanager](https://github.com/mtjailed/privateapimanager) A project providing usefull classes for reverse engineering iOS Private APIs on-device
- [**32**星][2y] [applebetas/mterminal-jailed](https://github.com/applebetas/mterminal-jailed) An iOS 11 compatible fork of MTerminal using Ian Beer's tfp0 exploit
- [**32**星][1y] [ObjC] [lycajb/lycajb](https://github.com/lycajb/lycajb) LycaJB is a project that aims to fill the gap in iOS 11.0 - 11.3.1 jailbreaks. While this jailbreak is specifically aimed at developers it could be turned into a public stable jailbreak which includes Cydia. Right now we had to make the hard decision to remove Cydia from LycaJB as it caused our test devices to bootloop. We are working hard to ma…
- [**32**星][2y] [ObjC] [mikaelbo/proxyswitcher](https://github.com/mikaelbo/proxyswitcher) Easily enable / disable WiFi proxy on a jailbroken iOS device
- [**29**星][2y] [C] [jndok/of32](https://github.com/jndok/of32) A simple tool to find offsets needed in 32bit jailbreaks. Feel free to contribute.
- [**25**星][8m] [Logos] [ruler225/jailbreaktweaks](https://github.com/ruler225/jailbreaktweaks) All of my open source jailbreak tweaks for iOS
- [**23**星][2y] [C] [openjailbreak/absinthe](https://github.com/openjailbreak/absinthe) Absinthe Jailbreak. Most recent version I've maintained. Help split this up into reusable modules for future userland jailbreaks. This is archived for future generations
- [**22**星][9m] [Logos] [leavez/runmario](https://github.com/leavez/runmario) iOS jailbreak tweak that allow playing SuperMarioRun on jailbreak device
- [**20**星][11m] [m4cs/ios-tweak-dev-tools](https://github.com/m4cs/ios-tweak-dev-tools) A collection of useful development tools and forks of tools that are geared towards iOS jailbreak developers.
- [**18**星][1y] [C++] [jakeajames/kernelsymbolfinder](https://github.com/jakeajames/kernelsymbolfinder) Get kernel symbols on device. No jailbreak required (note: unslid addresses)
- [**17**星][2y] [Roff] [mtjailed/mtjailed-native](https://github.com/mtjailed/mtjailed-native) A terminal emulator with remote shell for non-jailbroken iOS devices
- [**16**星][4y] [C#] [firecore/seas0npass-windows](https://github.com/firecore/seas0npass-windows) Windows version of the jailbreak tool for Apple TV 2G
- [**15**星][2y] [C] [jailbreaks/empty_list](https://github.com/jailbreaks/empty_list) empty_list - exploit for p0 issue 1564 (CVE-2018-4243) iOS 11.0 - 11.3.1 kernel r/w
- [**14**星][10m] [SourcePawn] [headline/gangs](https://github.com/headline/gangs) Gangs for Jailbreak Servers Running SourceMod
- [**11**星][8y] [i0n1c/corona-a5-exploit](https://github.com/i0n1c/corona-a5-exploit) The Corona A5 exploit used in the Absinthe jailbreak.
- [**11**星][3y] [ObjC] [openjailbreak/yalu102](https://github.com/openjailbreak/yalu102) incomplete iOS 10.2 jailbreak for 64 bit devices by qwertyoruiopz and marcograssi
- [**10**星][2y] [Swift] [6ilent/electralyzed_ios](https://github.com/6ilent/electralyzed_ios) Install Jailbreak tweaks without the hassle (iOS Version, Electra [iOS 11 - 11.1.2] Jailbreak Toolkit)
- [**10**星][2y] [ObjC] [elegantliar/wechathook](https://github.com/ElegantLiar/WeChatHook) iOS非越狱 逆向微信实现防撤回, 修改步数
- [**9**星][2y] [TeX] [abhinashjain/jailbreakdetection](https://github.com/abhinashjain/jailbreakdetection) iOS Jailbreak detection analysis - Comparison of jailed and jailbroken iOS devices
- [**9**星][4y] [Py] [b0n0n/ms-fitnessband-jailbreak](https://github.com/b0n0n/ms-fitnessband-jailbreak) simple scripts to parse and patch Microsoft fitness band firmware update file
- [**9**星][2y] [proappleos/upgrade-from-any-jailbroken-device-to-ios-11.1.2-with-blobs](https://github.com/proappleos/upgrade-from-any-jailbroken-device-to-ios-11.1.2-with-blobs) How to Upgrade any Jailbroken Device to iOS 11.1.2 with Blobs
- [**8**星][3y] [ObjC] [imokhles/boptionloader](https://github.com/imokhles/boptionloader) side load BOptionsPro for BBM to improve BBM app on iOS device ( first BBM tweak ever for non jailbroken devices )
- [**6**星][10m] [C] [cryptiiiic/skybreak](https://github.com/cryptiiiic/skybreak) 8.4.1 Jailbreak using CVE-2016-4655 / CVE-2016-4656
- [**4**星][4y] [luowenw/xiaohedoublepinyindict](https://github.com/luowenw/xiaohedoublepinyindict) Files that can be useful for XiaoHe double pinyin solution on non jailbreak IOS devices.
- [**4**星][3y] [ObjC] [kd1991/ipapatch](https://github.com/KD1991/IPAPatch) Patch iOS Apps, The Easy Way, Without Jailbreak.
- [**3**星][2y] [Logos] [artikushg/switcherxi](https://github.com/artikushg/switcherxi) The iOS 11 appswitcher for iOS 10 jailbreak.
- [**3**星][5y] [ObjC] [martianz/shadowsocks-ios](https://github.com/martianz/shadowsocks-ios) shadowsocks client for OSX and non-jailbroken iPhone and iPad
- [**3**星][3y] [ObjC] [openjailbreak/yalu](https://github.com/openjailbreak/yalu) incomplete ios 8.4.1 jailbreak by Kim Jong Cracks (8.4.1 codesign & sandbox bypass w/ LPE to root & untether)
- [**2**星][7y] [felipefmmobile/ios-plist-encryptor](https://github.com/felipefmmobile/ios-plist-encryptor) IOS *.plist encryptor project. Protect your *.plist files from jailbroken
- [**2**星][2y] [Ruby] [mtjailed/msf-webkit-10.3](https://github.com/mtjailed/msf-webkit-10.3) A metasploit module for webkit exploits and PoC's targeting devices running iOS 10+
- [**1**星][4y] [Shell] [app174/xcodeghost-clean](https://github.com/app174/xcodeghost-clean) Check and clean app contains XCodeGhost on your jailbreaked iDevice.
- [**0**星][3y] [ziki69/ios10jailbreak](https://github.com/ziki69/ios10jailbreak) iOS 10.1.1 jailbreak w/ support of iPhone 5s


### <a id="c20772abc204dfe23f3e946f8c73dfda"></a>LLDB


- [**784**星][3m] [C++] [nodejs/llnode](https://github.com/nodejs/llnode) An lldb plugin for Node.js and V8, which enables inspection of JavaScript states for insights into Node.js processes and their core dumps.
- [**636**星][2m] [C++] [apple/swift-lldb](https://github.com/apple/swift-lldb) This is the version of LLDB that supports the Swift programming language & REPL.
- [**492**星][20d] [Rust] [vadimcn/vscode-lldb](https://github.com/vadimcn/vscode-lldb) A native debugger extension for VSCode based on LLDB
- [**388**星][2m] [C++] [llvm-mirror/lldb](https://github.com/llvm-mirror/lldb) Mirror of official lldb git repository located at
- [**25**星][3y] [Py] [bnagy/francis](https://github.com/bnagy/francis) LLDB engine based tool to instrument OSX apps and triage crashes
- [**20**星][3y] [Py] [critiqjo/lldb.nvim](https://github.com/critiqjo/lldb.nvim) This repository was moved to
- [**16**星][2m] [Py] [malor/cpython-lldb](https://github.com/malor/cpython-lldb) LLDB script for debugging of CPython processes
- [**12**星][3y] [C++] [indutny/llnode](https://github.com/indutny/llnode) Node.js C++ lldb plugin




***


## <a id="c97bbe32bbd26c72ceccb43400e15bf1"></a>文章&&视频




# <a id="0ae4ddb81ff126789a7e08b0768bd693"></a>Cuckoo


***


## <a id="5830a8f8fb3af1a336053d84dd7330a1"></a>工具


### <a id="f2b5c44c2107db2cec6c60477c6aa1d0"></a>新添加的


- [**4042**星][3m] [JS] [cuckoosandbox/cuckoo](https://github.com/cuckoosandbox/cuckoo) Cuckoo Sandbox is an automated dynamic malware analysis system
- [**458**星][2y] [Py] [idanr1986/cuckoo-droid](https://github.com/idanr1986/cuckoo-droid) Automated Android Malware Analysis with Cuckoo Sandbox.
- [**357**星][3y] [Py] [spender-sandbox/cuckoo-modified](https://github.com/spender-sandbox/cuckoo-modified) cuckoo改版
- [**308**星][2m] [Py] [hatching/vmcloak](https://github.com/hatching/vmcloak) Automated Virtual Machine Generation and Cloaking for Cuckoo Sandbox.
- [**248**星][4y] [C] [begeekmyfriend/cuckoofilter](https://github.com/begeekmyfriend/cuckoofilter) Substitute for bloom filter.
- [**238**星][6m] [Py] [cuckoosandbox/community](https://github.com/cuckoosandbox/community) Repository of modules and signatures contributed by the community
- [**236**星][5y] [C] [conix-security/zer0m0n](https://github.com/conix-security/zer0m0n) zer0m0n driver for cuckoo sandbox
- [**236**星][3m] [Py] [brad-sp/cuckoo-modified](https://github.com/brad-sp/cuckoo-modified) Modified edition of cuckoo
- [**225**星][1y] [PHP] [cuckoosandbox/monitor](https://github.com/cuckoosandbox/monitor) The new Cuckoo Monitor.
- [**220**星][3m] [Shell] [blacktop/docker-cuckoo](https://github.com/blacktop/docker-cuckoo) Cuckoo Sandbox Dockerfile
- [**202**星][2y] [C] [david-reguera-garcia-dreg/anticuckoo](https://github.com/david-reguera-garcia-dreg/anticuckoo) A tool to detect and crash Cuckoo Sandbox
- [**151**星][3y] [Shell] [buguroo/cuckooautoinstall](https://github.com/buguroo/cuckooautoinstall) Auto Installer Script for Cuckoo Sandbox
- [**124**星][4y] [Py] [davidoren/cuckoosploit](https://github.com/davidoren/cuckoosploit) An environment for comprehensive, automated analysis of web-based exploits, based on Cuckoo sandbox.
- [**120**星][4y] [C] [cuckoosandbox/cuckoomon](https://github.com/cuckoosandbox/cuckoomon) DEPRECATED - replaced with "monitor"
- [**117**星][3y] [Py] [honeynet/cuckooml](https://github.com/honeynet/cuckooml) Machine Learning for Cuckoo Sandbox
- [**82**星][2y] [Py] [idanr1986/cuckoodroid-2.0](https://github.com/idanr1986/cuckoodroid-2.0) 自动化Android 恶意软件分析
- [**78**星][5y] [Py] [idanr1986/cuckoo](https://github.com/idanr1986/cuckoo) A Cuckoo Sandbox Extension for Android
- [**70**星][18d] [Py] [jpcertcc/malconfscan-with-cuckoo](https://github.com/jpcertcc/malconfscan-with-cuckoo) Cuckoo Sandbox plugin for extracts configuration data of known malware
- [**70**星][4m] [PS] [nbeede/boombox](https://github.com/nbeede/boombox) Automatic deployment of Cuckoo Sandbox malware lab using Packer and Vagrant
- [**69**星][3y] [C] [angelkillah/zer0m0n](https://github.com/angelkillah/zer0m0n) zer0m0n driver for cuckoo sandbox
- [**57**星][8m] [Py] [hatching/sflock](https://github.com/hatching/sflock) Sample staging & detonation utility to be used in combination with Cuckoo Sandbox.
- [**55**星][4y] [Py] [rodionovd/cuckoo-osx-analyzer](https://github.com/rodionovd/cuckoo-osx-analyzer) An OS X analyzer for Cuckoo Sandbox project
- [**52**星][1y] [C] [phdphuc/mac-a-mal](https://github.com/phdphuc/mac-a-mal) 追踪macOS恶意软件的内核驱动, 与Cuckoo沙箱组合使用
- [**39**星][7y] [Perl] [xme/cuckoomx](https://github.com/xme/cuckoomx) CuckooMX is a project to automate analysis of files transmitted over SMTP (using the Cuckoo sandbox)
- [**38**星][3y] [C] [spender-sandbox/cuckoomon-modified](https://github.com/spender-sandbox/cuckoomon-modified) Modified edition of cuckoomon
- [**36**星][5m] [ocatak/malware_api_class](https://github.com/ocatak/malware_api_class) Malware dataset for security researchers, data scientists. Public malware dataset generated by Cuckoo Sandbox based on Windows OS API calls analysis for cyber security researchers
- [**32**星][2y] [Py] [phdphuc/mac-a-mal-cuckoo](https://github.com/phdphuc/mac-a-mal-cuckoo) 扩展Cuckoo沙箱功能, 添加分析macOS恶意软件功能
- [**28**星][3y] [Py] [0x71/cuckoo-linux](https://github.com/0x71/cuckoo-linux) Linux malware analysis based on Cuckoo Sandbox.
- [**19**星][5y] [C] [zer0box/zer0m0n](https://github.com/zer0box/zer0m0n) zer0m0n driver for cuckoo sandbox
- [**16**星][14d] [Py] [ryuchen/panda-sandbox](https://github.com/ryuchen/panda-sandbox) 这是一个基于 Cuckoo 开源版本的沙箱的修订版本, 该版本完全为了适配国内软件环境所打造
- [**12**星][3y] [Py] [keithjjones/cuckoo-modified-api](https://github.com/keithjjones/cuckoo-modified-api) A Python library to interface with a cuckoo-modified instance
- [**10**星][4y] [Py] [tribalchicken/postfix-cuckoolyse](https://github.com/tribalchicken/postfix-cuckoolyse) A Postfix filter which takes a piped message and submits it to Cuckoo Sandbox
- [**8**星][2y] [Py] [kojibhy/cuckoo-yara-auto](https://github.com/kojibhy/cuckoo-yara-auto) simple python script to add yara rules in cuckoo sandbox
- [**8**星][3y] [Py] [threatconnect-inc/cuckoo-reporting-module](https://github.com/threatconnect-inc/cuckoo-reporting-module) Cuckoo reporting module for version 1.2 stable
- [**7**星][2y] [Ruby] [fyhertz/ansible-role-cuckoo](https://github.com/fyhertz/ansible-role-cuckoo) Automated installation of Cuckoo Sandbox with Ansible
- [**6**星][3y] [Py] [xme/cuckoo](https://github.com/xme/cuckoo) Miscellaneous files related to Cuckoo sandbox
- [**4**星][10m] [HTML] [hullgj/report-parser](https://github.com/hullgj/report-parser) Cuckoo Sandbox report parser into ransomware classifier
- [**2**星][3y] [Shell] [harryr/cockatoo](https://github.com/harryr/cockatoo) Torified Cuckoo malware analyser in a Docker container with VirtualBox
- [**2**星][7y] [Shell] [hiddenillusion/cuckoo3.2](https://github.com/hiddenillusion/cuckoo3.2) This repo contains patches for the 0.3.2 release of the cuckoo sandbox (
- [**1**星][2y] [Py] [dc170/mbox-to-cuckoo](https://github.com/dc170/mbox-to-cuckoo) Simple python script to send all executable files extracted from linux postfix mailboxes to the cuckoo sandbox for further automated analysis




***


## <a id="ec0a441206d9a2fe1625dce0a679d466"></a>文章&&视频


- 2019.10 [sectechno] [Cuckoo Sandbox – Automated Malware Analysis Framework](https://sectechno.com/cuckoo-sandbox-automated-malware-analysis-framework-2/)
- 2019.04 [eforensicsmag] [How to Integrate RSA Malware Analysis with Cuckoo Sandbox | By Luiz Henrique Borges](https://eforensicsmag.com/how-to-integrate-rsa-malware-analysis-with-cuckoo-sandbox-by-luiz-henrique-borges/)
- 2019.02 [thehive] [Cortex-Analyzers 1.15.3 get ready for  URLhaus and Cuckoo](https://blog.thehive-project.org/2019/02/26/cortex-analyzers-1-15-3-get-ready-for-urlhaus-and-cuckoo/)
- 2018.07 [360] [一例IRC Bot针对Cuckoo沙箱的猥琐对抗分析](https://www.anquanke.com/post/id/152631/)
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


### <a id="6c4841dd91cb173093ea2c8d0b557e71"></a>工具


#### <a id="3a577a5b4730a1b5b3b325269509bb0a"></a>DynamoRIO


- [**1388**星][4d] [C] [dynamorio/drmemory](https://github.com/dynamorio/drmemory) Memory Debugger for Windows, Linux, Mac, and Android
- [**1228**星][4d] [C] [dynamorio/dynamorio](https://github.com/dynamorio/dynamorio) Dynamic Instrumentation Tool Platform


#### <a id="ff0abe26a37095f6575195950e0b7f94"></a>新添加的


- [**249**星][4m] [C] [ampotos/dynstruct](https://github.com/ampotos/dynstruct) Reverse engineering tool for automatic structure recovering and memory use analysis based on DynamoRIO and Capstone
- [**119**星][5y] [C++] [breakingmalware/selfie](https://github.com/breakingmalware/selfie) 对自修改代码进行脱壳
- [**119**星][4m] [C++] [googleprojectzero/drsancov](https://github.com/googleprojectzero/drsancov) DynamoRIO plugin to get ASAN and SanitizerCoverage compatible output for closed-source executables
- [**53**星][4y] [C] [lgeek/dynamorio_pin_escape](https://github.com/lgeek/dynamorio_pin_escape) 
- [**17**星][18d] [C] [firodj/bbtrace](https://github.com/firodj/bbtrace) 记录bbtrace
- [**14**星][6m] [C++] [vanhauser-thc/afl-dynamorio](https://github.com/vanhauser-thc/afl-dynamorio) run AFL with dynamorio
- [**10**星][2y] [C++] [atrosinenko/afl-dr](https://github.com/atrosinenko/afl-dr) Experiment in implementation of an instrumentation for American Fuzzy Lop using DynamoRIO


#### <a id="928642a55eff34b6b52622c6862addd2"></a>与其他工具交互


- [**52**星][11m] [Py] [cisco-talos/dyndataresolver](https://github.com/cisco-talos/dyndataresolver) 动态数据解析. 在IDA中控制DyRIO执行程序的指定部分, 记录执行过程后传回数据到IDA
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |
    - [DDR](https://github.com/cisco-talos/dyndataresolver/blob/master/VS_project/ddr/ddr.sln) 基于DyRIO的Client
    - [IDA插件](https://github.com/cisco-talos/dyndataresolver/tree/master/IDAplugin) 
- [**20**星][9m] [C++] [secrary/findloop](https://github.com/secrary/findloop) 使用DyRIO查找执行次数过多的代码块
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |
- [**6**星][2y] [C++] [ncatlin/drgat](https://github.com/ncatlin/drgat) The DynamoRIO client for rgat




### <a id="9479ce9f475e4b9faa4497924a2e40fc"></a>文章&&视频


- 2019.10 [freebuf] [DrSemu：基于动态行为的恶意软件检测与分类工具](https://www.freebuf.com/sectool/214277.html)
- 2019.06 [freebuf] [Functrace：使用DynamoRIO追踪函数调用](https://www.freebuf.com/sectool/205989.html)
- 2019.01 [360] [深入浅出——基于DynamoRIO的strace和ltrace](https://www.anquanke.com/post/id/169257/)
- 2018.08 [n0where] [Dynamic API Call Tracer for Windows and Linux Applications: Drltrace](https://n0where.net/dynamic-api-call-tracer-for-windows-and-linux-applications-drltrace)
- 2018.07 [topsec] [动态二进制修改(Dynamic Binary Instrumentation)入门：Pin、DynamoRIO、Frida](http://blog.topsec.com.cn/%e5%8a%a8%e6%80%81%e4%ba%8c%e8%bf%9b%e5%88%b6%e4%bf%ae%e6%94%b9dynamic-binary-instrumentation%e5%85%a5%e9%97%a8%ef%bc%9apin%e3%80%81dynamorio%e3%80%81frida/)
- 2018.07 [topsec] [动态二进制修改(Dynamic Binary Instrumentation)入门：Pin、DynamoRIO、Frida](http://blog.topsec.com.cn/ad_lab/%e5%8a%a8%e6%80%81%e4%ba%8c%e8%bf%9b%e5%88%b6%e4%bf%ae%e6%94%b9dynamic-binary-instrumentation%e5%85%a5%e9%97%a8%ef%bc%9apin%e3%80%81dynamorio%e3%80%81frida/)
- 2018.07 [topsec] [动态二进制修改(Dynamic Binary Instrumentation)入门：Pin、DynamoRIO、Frida](http://blog.topsec.com.cn/%e5%8a%a8%e6%80%81%e4%ba%8c%e8%bf%9b%e5%88%b6%e4%bf%ae%e6%94%b9dynamic-binary-instrumentation%e5%85%a5%e9%97%a8%ef%bc%9apin%e3%80%81dynamorio%e3%80%81frida/)
- 2018.07 [topsec] [动态二进制修改(Dynamic Binary Instrumentation)入门：Pin、DynamoRIO、Frida](http://blog.topsec.com.cn/2018/07/%e5%8a%a8%e6%80%81%e4%ba%8c%e8%bf%9b%e5%88%b6%e4%bf%ae%e6%94%b9dynamic-binary-instrumentation%e5%85%a5%e9%97%a8%ef%bc%9apin%e3%80%81dynamorio%e3%80%81frida/)
- 2017.11 [SECConsult] [The Art of Fuzzing - Demo 10: In-memory Fuzzing HashCalc using DynamoRio](https://www.youtube.com/watch?v=FEJGlgBeUJ8)
- 2017.11 [SECConsult] [The Art of Fuzzing - Demo 6: Extract Coverage Information using DynamoRio](https://www.youtube.com/watch?v=Ur_E9c2vX1A)
- 2016.11 [360] [“Selfie”：利用DynamoRIO实现自修改代码自动脱壳的神器](https://www.anquanke.com/post/id/84999/)
- 2016.09 [securitygossip] [Practical Memory Checking With Dr. Memory](http://securitygossip.com/blog/2016/09/12/2016-09-12/)
- 2016.09 [sjtu] [Practical Memory Checking With Dr. Memory](https://loccs.sjtu.edu.cn/gossip/blog/2016/09/12/2016-09-12/)
- 2016.08 [n0where] [Dynamic Instrumentation Tool Platform: DynamoRIO](https://n0where.net/dynamic-instrumentation-tool-platform-dynamorio)
- 2012.10 [redplait] [building dynamorio](http://redplait.blogspot.com/2012/10/building-dynamorio.html)
- 2011.06 [redplait] [dynamorio](http://redplait.blogspot.com/2011/06/dynamorio.html)




***


## <a id="7b8a493ca344f41887792fcc008573e7"></a>IntelPin


### <a id="fe5a6d7f16890542c9e60857706edfde"></a>工具


#### <a id="78a2edf9aa41eb321436cb150ea70a54"></a>新添加的


- [**424**星][4y] [C++] [jonathansalwan/pintools](https://github.com/jonathansalwan/pintools) Pintool example and PoC for dynamic binary analysis
- [**299**星][2m] [C] [vusec/vuzzer](https://github.com/vusec/vuzzer) depends heavily on a modeified version of DataTracker, which in turn depends on LibDFT pintool.
- [**148**星][5y] [C++] [f-secure/sulo](https://github.com/f-secure/sulo) Dynamic instrumentation tool for Adobe Flash Player built on Intel Pin
- [**123**星][6m] [C++] [hasherezade/tiny_tracer](https://github.com/hasherezade/tiny_tracer) A Pin Tool for tracing API calls etc
- [**65**星][3y] [C++] [m000/dtracker](https://github.com/m000/dtracker) DataTracker: A Pin tool for collecting high-fidelity data provenance from unmodified programs.
- [**60**星][2y] [C++] [hasherezade/mypintools](https://github.com/hasherezade/mypintools) Tools to run with Intel PIN
- [**48**星][9m] [C++] [angorafuzzer/libdft64](https://github.com/angorafuzzer/libdft64) libdft for Intel Pin 3.x and 64 bit platform. (Dynamic taint tracking, taint analysis)
- [**48**星][7y] [C++] [cr4sh/code-coverage-analysis-tools](https://github.com/cr4sh/code-coverage-analysis-tools) Code coverage analysis tools for the PIN Toolkit
- [**39**星][4y] [C++] [corelan/pin](https://github.com/corelan/pin) Collection of pin tools
- [**36**星][3y] [C++] [paulmehta/ablation](https://github.com/paulmehta/ablation) Augmenting Static Analysis Using Pintool: Ablation
- [**30**星][4y] [C++] [0xddaa/pin](https://github.com/0xddaa/pin) Use Intel Pin tools to analysis binary.
- [**27**星][1y] [C++] [fdiskyou/winalloctracer](https://github.com/fdiskyou/WinAllocTracer) Pintool that logs and tracks calls to RtlAllocateHeap, RtlReAllocateHeap, RtlFreeHeap, VirtualAllocEx, and VirtualFreeEx.
- [**26**星][7y] [C++] [jingpu/pintools](https://github.com/jingpu/pintools) 
- [**25**星][2m] [C++] [boegel/mica](https://github.com/boegel/mica) a Pin tool for collecting microarchitecture-independent workload characteristics
- [**22**星][6y] [C++] [jbremer/pyn](https://github.com/jbremer/pyn) Awesome Python bindings for Pintool
- [**18**星][1y] [bash-c/pin-in-ctf](https://github.com/bash-c/pin-in-ctf) 使用intel pin来求解一部分CTF challenge
- [**12**星][3y] [C++] [netspi/pin](https://github.com/netspi/pin) Intel pin tools
- [**6**星][2y] [C++] [spinpx/afl_pin_mode](https://github.com/spinpx/afl_pin_mode) Yet another AFL instrumentation tool implemented by Intel Pin.


#### <a id="e6a829abd8bbc5ad2e5885396e3eec04"></a>与其他工具交互


##### <a id="e129288dfadc2ab0890667109f93a76d"></a>未分类


- [**943**星][1y] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |[DBI->Frida->工具->与其他工具交互->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |[DBI->Frida->工具->与其他工具交互->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**134**星][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) 多功能, 带界面,辅助静态分析、漏洞挖掘、动态追踪(Pin)、导入导出等
    - 重复区段: [IDA->插件->导入导出->IntelPin](#dd0332da5a1482df414658250e6357f8) |[IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |[IDA->插件->漏洞->未分类](#385d6777d0747e79cccab0a19fa90e7e) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**122**星][5y] [C++] [zachriggle/ida-splode](https://github.com/zachriggle/ida-splode) 使用Pin收集动态运行数据, 导入到IDA中查看
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |
    - [IDA插件](https://github.com/zachriggle/ida-splode/tree/master/py) 
    - [PinTool](https://github.com/zachriggle/ida-splode/tree/master/src) 
- [**117**星][2y] [C++] [0xphoenix/mazewalker](https://github.com/0xphoenix/mazewalker) 使用Pin收集数据，导入到IDA中查看
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |
    - [mazeui](https://github.com/0xphoenix/mazewalker/blob/master/MazeUI/mazeui.py) 在IDA中显示界面
    - [PyScripts](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/PyScripts) Python脚本，处理收集到的数据
    - [PinClient](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/src) 
- [**102**星][3m] [Java] [0ffffffffh/dragondance](https://github.com/0ffffffffh/dragondance) 在Ghidra中进行代码覆盖情况的可视化
    - 重复区段: [Ghidra->插件->与其他工具交互->DBI](#60e86981b2c98f727587e7de927e0519) |
    - [Ghidra插件](https://github.com/0ffffffffh/dragondance/blob/master/README.md) 
    - [coverage-pin](https://github.com/0ffffffffh/dragondance/blob/master/coveragetools/README.md) 使用Pin收集信息
- [**89**星][8y] [C] [neuroo/runtime-tracer](https://github.com/neuroo/runtime-tracer) 使用Pin收集运行数据并在IDA中显示
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |
    - [PinTool](https://github.com/neuroo/runtime-tracer/tree/master/tracer) 
    - [IDA插件](https://github.com/neuroo/runtime-tracer/tree/master/ida-pin) 
- [**44**星][3y] [Batchfile] [maldiohead/idapin](https://github.com/maldiohead/idapin) plugin of ida with pin
    - 重复区段: [IDA->插件->导入导出->IntelPin](#dd0332da5a1482df414658250e6357f8) |
- [**15**星][1y] [C++] [agustingianni/instrumentation](https://github.com/agustingianni/instrumentation) PinTool收集。收集数据可导入到IDA中
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |
    - [CodeCoverage](https://github.com/agustingianni/instrumentation/tree/master/CodeCoverage) 
    - [Pinnacle](https://github.com/agustingianni/instrumentation/tree/master/Pinnacle) 
    - [Recoverer](https://github.com/agustingianni/instrumentation/tree/master/Recoverer) 
    - [Resolver](https://github.com/agustingianni/instrumentation/tree/master/Resolver) 






### <a id="226190bea6ceb98ee5e2b939a6515fac"></a>文章&&视频






***


## <a id="f24f1235fd45a1aa8d280eff1f03af7e"></a>Frida


### <a id="a5336a0f9e8e55111bda45c8d74924c1"></a>工具


#### <a id="6d3c24e43835420063f9ca50ba805f15"></a>Frida


- [**4516**星][5d] [Makefile] [frida/frida](https://github.com/frida/frida) Clone this repo to build Frida


#### <a id="54836a155de0c15b56f43634cd9cfecf"></a>新添加的


- [**1193**星][7d] [JS] [alonemonkey/frida-ios-dump](https://github.com/alonemonkey/frida-ios-dump) pull decrypted ipa from jailbreak device
    - 重复区段: [Apple->工具->新添加的](#d0108e91e6863289f89084ff09df39d0) |
- [**895**星][5m] [JS] [dpnishant/appmon](https://github.com/dpnishant/appmon) 用于监视和篡改本地macOS，iOS和android应用程序的系统API调用的自动化框架。基于Frida。
- [**645**星][8d] [Py] [igio90/dwarf](https://github.com/igio90/dwarf) Full featured multi arch/os debugger built on top of PyQt5 and frida
- [**559**星][1m] [JS] [nccgroup/house](https://github.com/nccgroup/house) 运行时手机 App 分析工具包, 带Web GUI
- [**513**星][24d] [JS] [iddoeldor/frida-snippets](https://github.com/iddoeldor/frida-snippets) Hand-crafted Frida examples
- [**422**星][12m] [Py] [dstmath/frida-unpack](https://github.com/dstmath/frida-unpack) 基于Frida的脱壳工具
- [**420**星][5d] [C] [frida/frida-python](https://github.com/frida/frida-python) Frida Python bindings
- [**407**星][2y] [JS] [0xdea/frida-scripts](https://github.com/0xdea/frida-scripts) A collection of my Frida.re instrumentation scripts to facilitate reverse engineering of mobile apps.
- [**405**星][1y] [C++] [vah13/extracttvpasswords](https://github.com/vah13/extracttvpasswords) tool to extract passwords from TeamViewer memory using Frida
- [**332**星][7d] [JS] [chichou/bagbak](https://github.com/ChiChou/bagbak) Yet another frida based iOS dumpdecrypted, works on iOS 13 with checkra1n and supports decrypting app extensions
- [**321**星][29d] [C] [frida/frida-core](https://github.com/frida/frida-core) Frida core library intended for static linking into bindings
- [**317**星][5y] [C++] [frida/cryptoshark](https://github.com/frida/cryptoshark) Self-optimizing cross-platform code tracer based on dynamic recompilation
- [**308**星][4m] [JS] [smartdone/frida-scripts](https://github.com/smartdone/frida-scripts) 一些frida脚本
- [**283**星][8m] [Py] [nightbringer21/fridump](https://github.com/nightbringer21/fridump) A universal memory dumper using Frida
- [**266**星][2y] [Py] [antojoseph/frida-android-hooks](https://github.com/antojoseph/frida-android-hooks) Lets you hook Method Calls in Frida ( Android )
- [**250**星][1y] [Py] [igio90/frick](https://github.com/igio90/frick) aka the first debugger built on top of frida
- [**243**星][11d] [JS] [frenchyeti/dexcalibur](https://github.com/frenchyeti/dexcalibur) Dynamic binary instrumentation tool designed for Android application and powered by Frida. It disassembles dex, analyzes it statically, generates hooks, discovers reflected methods, stores intercepted data and does new things from it. Its aim is to be an all-in-one Android reverse engineering platform.
- [**228**星][5d] [C] [frida/frida-gum](https://github.com/frida/frida-gum) Low-level code instrumentation library used by frida-core
- [**197**星][20d] [JS] [xiaokanghub/frida-android-unpack](https://github.com/xiaokanghub/frida-android-unpack) this unpack script for Android O and Android P
- [**195**星][4m] [C] [nowsecure/frida-cycript](https://github.com/nowsecure/frida-cycript) Cycript fork powered by Frida.
- [**173**星][3d] [JS] [andreafioraldi/frida-fuzzer](https://github.com/andreafioraldi/frida-fuzzer) This experimetal fuzzer is meant to be used for API in-memory fuzzing.
- [**159**星][2m] [JS] [interference-security/frida-scripts](https://github.com/interference-security/frida-scripts) Frida Scripts
- [**141**星][11d] [TS] [chame1eon/jnitrace](https://github.com/chame1eon/jnitrace) A Frida based tool that traces usage of the JNI API in Android apps.
- [**138**星][3y] [JS] [as0ler/frida-scripts](https://github.com/as0ler/frida-scripts) Repository including some useful frida script for iOS Reversing
- [**128**星][7m] [enovella/r2frida-wiki](https://github.com/enovella/r2frida-wiki) This repo aims at providing practical examples on how to use r2frida
- [**124**星][3y] [JS] [antojoseph/diff-gui](https://github.com/antojoseph/diff-gui) GUI for Frida -Scripts
- [**123**星][2y] [Java] [brompwnie/uitkyk](https://github.com/brompwnie/uitkyk) Android Frida库, 用于分析App查找恶意行为
    - 重复区段: [Android->工具->Malware](#f975a85510f714ec3cc2551e868e75b8) |
- [**121**星][21d] [JS] [fuzzysecurity/fermion](https://github.com/fuzzysecurity/fermion) Fermion, an electron wrapper for Frida & Monaco.
- [**112**星][2y] [C] [b-mueller/frida-detection-demo](https://github.com/b-mueller/frida-detection-demo) Some examples for detecting frida on Android
- [**112**星][17d] [C++] [frida/frida-node](https://github.com/frida/frida-node) Frida Node.js bindings
- [**109**星][9m] [Py] [rootbsd/fridump3](https://github.com/rootbsd/fridump3) A universal memory dumper using Frida for Python 3
- [**104**星][1y] [JS] [thecjw/frida-android-scripts](https://github.com/thecjw/frida-android-scripts) Some frida scripts
- [**98**星][2y] [Java] [piasy/fridaandroidtracer](https://github.com/piasy/fridaandroidtracer) A runnable jar that generate Javascript hook script to hook Android classes.
- [**97**星][7d] [JS] [frida/frida-java-bridge](https://github.com/frida/frida-java-bridge) Java runtime interop from Frida
- [**90**星][1y] [C] [grimm-co/notquite0dayfriday](https://github.com/grimm-co/notquite0dayfriday) This is a repo which documents real bugs in real software to illustrate trends, learn how to prevent or find them more quickly.
- [**90**星][2m] [Py] [demantz/frizzer](https://github.com/demantz/frizzer) Frida-based general purpose fuzzer
- [**88**星][2y] [Py] [mind0xp/frida-python-binding](https://github.com/mind0xp/frida-python-binding) Easy to use Frida python binding script
- [**86**星][3y] [JS] [oalabs/frida-wshook](https://github.com/oalabs/frida-wshook) Script analysis tool based on Frida.re
- [**85**星][4m] [TS] [nowsecure/airspy](https://github.com/nowsecure/airspy) AirSpy - Frida-based tool for exploring and tracking the evolution of Apple's AirDrop protocol implementation on i/macOS, from the server's perspective. Released during BH USA 2019 Training
- [**83**星][3y] [JS] [oalabs/frida-extract](https://github.com/oalabs/frida-extract) Frida.re based RunPE (and MapViewOfSection) extraction tool
- [**81**星][4m] [JS] [frida/frida-presentations](https://github.com/frida/frida-presentations) Public presentations given on Frida at conferences
- [**79**星][4m] [C] [oleavr/ios-inject-custom](https://github.com/oleavr/ios-inject-custom) (iOS) 使用Frida注入自定义Payload
- [**76**星][1m] [JS] [andreafioraldi/frida-js-afl-instr](https://github.com/andreafioraldi/frida-js-afl-instr) An example on how to do performant in-memory fuzzing with AFL++ and Frida
- [**75**星][4y] [Py] [antojoseph/diff-droid](https://github.com/antojoseph/diff-droid) 使用 Frida对手机渗透测试的若干脚本
- [**65**星][3m] [Py] [hamz-a/jeb2frida](https://github.com/hamz-a/jeb2frida) Automated Frida hook generation with JEB
- [**58**星][12d] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA等多个工具的多个脚本
    - 重复区段: [IDA->插件->未分类](#c39a6d8598dde6abfeef43faf931beb5) |[IDA->插件->导入导出->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor的多个脚本
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida多个脚本
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA Scripts
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) IDA插件，识别程序中的中文字符
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py) 辅助识别Objective-C成员函数的caller和callee
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) 使用gdbserver和IDA调试Android时，读取module列表和segment
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) 追踪指令流
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) 检测OLLVM，在某些情况下修复（Android/iOS）
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) 分析macho文件中的block结构
- [**57**星][8m] [JS] [hamz-a/frida-android-libbinder](https://github.com/hamz-a/frida-android-libbinder) PoC Frida script to view Android libbinder traffic
- [**53**星][1m] [Py] [hamz-a/frida-android-helper](https://github.com/hamz-a/frida-android-helper) Frida Android utilities
- [**52**星][1m] [Py] [frida/frida-tools](https://github.com/frida/frida-tools) Frida CLI tools
- [**50**星][1y] [JS] [fortiguard-lion/frida-scripts](https://github.com/fortiguard-lion/frida-scripts) 
- [**49**星][6m] [TS] [igio90/hooah-trace](https://github.com/igio90/hooah-trace) Instructions tracing powered by frida
- [**46**星][1y] [JS] [maltek/swift-frida](https://github.com/maltek/swift-frida) Frida library for interacting with Swift programs.
- [**46**星][4m] [JS] [nowsecure/frida-trace](https://github.com/nowsecure/frida-trace) Trace APIs declaratively through Frida.
- [**43**星][8m] [C] [sensepost/frida-windows-playground](https://github.com/sensepost/frida-windows-playground) A collection of Frida hooks for experimentation on Windows platforms.
- [**42**星][2y] [HTML] [digitalinterruption/fridaworkshop](https://github.com/digitalinterruption/fridaworkshop) Break Apps with Frida workshop material
- [**42**星][4m] [Swift] [frida/frida-swift](https://github.com/frida/frida-swift) Frida Swift bindings
- [**40**星][2y] [Py] [agustingianni/memrepl](https://github.com/agustingianni/memrepl) Frida 插件，辅助开发内存崩溃类的漏洞
    - 重复区段: [IDA->插件->导入导出->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |
- [**39**星][21d] [JS] [frida/frida-compile](https://github.com/frida/frida-compile) Compile a Frida script comprised of one or more Node.js modules
- [**39**星][4m] [TS] [oleavr/frida-agent-example](https://github.com/oleavr/frida-agent-example) Example Frida agent written in TypeScript
- [**37**星][] [CSS] [frida/frida-website](https://github.com/frida/frida-website) Frida's website
- [**34**星][2m] [Py] [dmaasland/mcfridafee](https://github.com/dmaasland/mcfridafee) 
- [**29**星][6m] [TS] [igio90/frida-onload](https://github.com/igio90/frida-onload) Frida module to hook module initializations on android
- [**28**星][1y] [JS] [ioactive/bluecrawl](https://github.com/ioactive/bluecrawl) Frida (Android) Script for extracting bluetooth information
- [**28**星][2y] [JS] [versprite/engage](https://github.com/versprite/engage) Tools and Materials for the Frida Engage Blog Series
- [**28**星][5m] [Java] [dineshshetty/fridaloader](https://github.com/dineshshetty/fridaloader) A quick and dirty app to download and launch Frida on Genymotion
- [**28**星][7m] [C++] [frida/v8](https://github.com/frida/v8) Frida depends on V8
- [**26**星][2y] [Py] [androidtamer/frida-push](https://github.com/androidtamer/frida-push) Wrapper tool to identify the remote device and push device specific frida-server binary.
- [**26**星][4m] [C++] [frida/frida-clr](https://github.com/frida/frida-clr) Frida .NET bindings
- [**26**星][3m] [JS] [nowsecure/frida-uikit](https://github.com/nowsecure/frida-uikit) Inspect and manipulate UIKit-based GUIs through Frida.
- [**25**星][9m] [TS] [woza-lab/woza](https://github.com/woza-lab/woza) [Deprecated]Dump application ipa from jailbroken iOS based on frida. (Node edition)
- [**20**星][3y] [JS] [dweinstein/node-frida-contrib](https://github.com/dweinstein/node-frida-contrib) frida utility-belt
- [**20**星][4m] [JS] [nowsecure/frida-uiwebview](https://github.com/nowsecure/frida-uiwebview) Inspect and manipulate UIWebView-hosted GUIs through Frida.
- [**19**星][7m] [JS] [iddoeldor/mplus](https://github.com/iddoeldor/mplus) Intercept android apps based on unity3d (Mono) using Frida
- [**19**星][2m] [Shell] [virb3/magisk-frida](https://github.com/virb3/magisk-frida) 
- [**19**星][18d] [JS] [cynops/frida-hooks](https://github.com/cynops/frida-hooks) 
- [**18**星][5y] [JS] [frida/aurora](https://github.com/frida/aurora) Proof-of-concept web app built on top of Frida
- [**18**星][2y] [Py] [igio90/fridaandroidtracer](https://github.com/igio90/fridaandroidtracer) Android application tracer powered by Frida
- [**18**星][2y] [Py] [notsosecure/dynamic-instrumentation-with-frida](https://github.com/notsosecure/dynamic-instrumentation-with-frida) Dynamic Instrumentation with Frida
- [**18**星][4m] [JS] [nowsecure/frida-screenshot](https://github.com/nowsecure/frida-screenshot) Grab screenshots using Frida.
- [**16**星][4m] [JS] [nowsecure/frida-fs](https://github.com/nowsecure/frida-fs) Create a stream from a filesystem resource.
- [**16**星][5m] [JS] [freehuntx/frida-mono-api](https://github.com/freehuntx/frida-mono-api) All the mono c exports, ready to be used in frida!
- [**11**星][4m] [JS] [nowsecure/mjolner](https://github.com/nowsecure/mjolner) Cycript backend powered by Frida.
- [**11**星][2m] [JS] [freehuntx/frida-inject](https://github.com/freehuntx/frida-inject) This module allows you to easily inject javascript using frida and frida-load.
- [**10**星][1y] [JS] [andreafioraldi/taint-with-frida](https://github.com/andreafioraldi/taint-with-frida) just an experiment
- [**10**星][5y] [JS] [frida/cloudspy](https://github.com/frida/cloudspy) Proof-of-concept web app built on top of Frida
- [**9**星][11m] [JS] [lmangani/node_ssl_logger](https://github.com/lmangani/node_ssl_logger) Decrypt and log process SSL traffic via Frida Injection
- [**9**星][2y] [JS] [random-robbie/frida-docker](https://github.com/random-robbie/frida-docker) Dockerised Version of Frida
- [**9**星][4m] [Py] [melisska/neomorph](https://github.com/melisska/neomorph) Frida Python Tool
- [**9**星][10m] [JS] [rubaljain/frida-jb-bypass](https://github.com/rubaljain/frida-jb-bypass) Frida script to bypass the iOS application Jailbreak Detection
- [**6**星][4m] [JS] [nowsecure/frida-panic](https://github.com/nowsecure/frida-panic) Easy crash-reporting for Frida-based applications.
- [**6**星][10m] [JS] [eybisi/fridascripts](https://github.com/eybisi/fridascripts) 
- [**5**星][2m] [TS] [nowsecure/frida-remote-stream](https://github.com/nowsecure/frida-remote-stream) Create an outbound stream over a message transport.
- [**4**星][5m] [JS] [davuxcom/frida-scripts](https://github.com/davuxcom/frida-scripts) Inject JS and C# into Windows apps, call COM and WinRT APIs
- [**4**星][2y] [JS] [frida/frida-load](https://github.com/frida/frida-load) Load a Frida script comprised of one or more Node.js modules
- [**4**星][29d] [JS] [sipcapture/hepjack.js](https://github.com/sipcapture/hepjack.js) Elegantly Sniff Forward-Secrecy TLS/SIP to HEP at the source using Frida
- [**3**星][4m] [JS] [nowsecure/frida-memory-stream](https://github.com/nowsecure/frida-memory-stream) Create a stream from one or more memory regions.
- [**3**星][t] [Py] [margular/frida-skeleton](https://github.com/margular/frida-skeleton) This repository is supposed to define infrastructure of frida on hook android including some useful functions
- [**3**星][2y] [JS] [myzhan/frida-examples](https://github.com/myzhan/frida-examples) Examples of using frida.
- [**2**星][1y] [rhofixxxx/kick-off-owasp_webapp_security_vulnerabilities](https://github.com/rhofixxxx/kick-off-OWASP_WebApp_Security_Vulnerabilities) Want to keep your Web application from getting hacked? Here's how to get serious about secure apps. So let's do it! Open Friday, Aug 2016 - Presentation Notes.
- [**1**星][1y] [JS] [ddurando/frida-scripts](https://github.com/ddurando/frida-scripts) 


#### <a id="74fa0c52c6104fd5656c93c08fd1ba86"></a>与其他工具交互


##### <a id="00a86c65a84e58397ee54e85ed57feaf"></a>未分类


- [**584**星][1y] [Java] [federicodotta/brida](https://github.com/federicodotta/brida) The new bridge between Burp Suite and Frida!


##### <a id="d628ec92c9eea0c4b016831e1f6852b3"></a>IDA


- [**943**星][1y] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->工具->与其他工具交互->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**128**星][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) 在Frida Client和IDA之间建立连接，将运行时信息直接导入IDA，并可直接在IDA中控制Frida
    - 重复区段: [IDA->插件->导入导出->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |[IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**83**星][5y] [Py] [techbliss/frida_for_ida_pro](https://github.com/techbliss/frida_for_ida_pro) 在IDA中使用Frida, 主要用于追踪函数
    - 重复区段: [IDA->插件->导入导出->Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |


##### <a id="f9008a00e2bbc7535c88602aa79c8fd8"></a>BinaryNinja


- [**943**星][1y] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->工具->与其他工具交互->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**8**星][3m] [Py] [c3r34lk1ll3r/binrida](https://github.com/c3r34lk1ll3r/BinRida) Plugin for Frida in Binary Ninja
    - 重复区段: [BinaryNinja->插件->与其他工具交互->未分类](#c2f94ad158b96c928ee51461823aa953) |


##### <a id="ac053c4da818ca587d57711d2ff66278"></a>Radare2


- [**378**星][19d] [JS] [nowsecure/r2frida](https://github.com/nowsecure/r2frida) Radare2 and Frida better together.
    - 重复区段: [Radare2->插件->与其他工具交互->未分类](#dfe53924d678f9225fc5ece9413b890f) |
- [**34**星][12m] [CSS] [nowsecure/r2frida-book](https://github.com/nowsecure/r2frida-book) The radare2 + frida book for Mobile Application assessment
    - 重复区段: [Radare2->插件->与其他工具交互->未分类](#dfe53924d678f9225fc5ece9413b890f) |






### <a id="a1a7e3dd7091b47384c75dba8f279caf"></a>文章&&视频


- 2019.07 [hackertor] [Dwarf – Full Featured Multi Arch/Os Debugger Built On Top Of PyQt5 And Frida](https://hackertor.com/2019/07/13/dwarf-full-featured-multi-arch-os-debugger-built-on-top-of-pyqt5-and-frida/)
- 2019.05 [nsfocus] [Frida应用基础及 APP https证书验证破解](http://blog.nsfocus.net/frida%e5%ba%94%e7%94%a8%e5%9f%ba%e7%a1%80%e5%8f%8a-app-https%e8%af%81%e4%b9%a6%e9%aa%8c%e8%af%81%e7%a0%b4%e8%a7%a3/)
- 2019.05 [nsfocus] [Frida应用基础及 APP https证书验证破解](http://blog.nsfocus.net/frida-application-foundation-app-https-certificate-verification-cracking-2/)
- 2019.05 [nsfocus] [Frida应用基础及APP https证书验证破解](http://blog.nsfocus.net/frida-application-foundation-app-https-certificate-verification-cracking/)
- 2019.05 [CodeColorist] [Trace child process with frida on macOS](https://medium.com/p/3b8f0f953f3d)
- 2019.05 [360] [FRIDA脚本系列（四）更新篇：几个主要机制的大更新](https://www.anquanke.com/post/id/177597/)
- 2019.03 [360] [FRIDA脚本系列（三）超神篇：百度AI“调教”抖音AI](https://www.anquanke.com/post/id/175621/)
- 2019.03 [securityinnovation] [Setting up Frida Without Jailbreak on the Latest iOS 12.1.4 Device](https://blog.securityinnovation.com/frida)
- 2019.02 [nowsecure] [Frida 12.3 Debuts New Crash Reporting Feature](https://www.nowsecure.com/blog/2019/02/07/frida-12-3-debuts-new-crash-reporting-feature/)
- 2019.01 [fuzzysecurity] [Windows Hacking 之：ApplicationIntrospection & Hooking With Frida](http://fuzzysecurity.com/tutorials/29.html)
- 2019.01 [fuping] [安卓APP测试之HOOK大法-Frida篇](https://fuping.site/2019/01/25/Frida-Hook-SoulAPP/)
- 2019.01 [360] [FRIDA脚本系列（二）成长篇：动静态结合逆向WhatsApp](https://www.anquanke.com/post/id/169315/)
- 2019.01 [pediy] [[原创]介召几个frida在安卓逆向中使用的脚本以及延时Hook手法](https://bbs.pediy.com/thread-248848.htm)
- 2018.12 [360] [FRIDA脚本系列（一）入门篇：在安卓8.1上dump蓝牙接口和实例](https://www.anquanke.com/post/id/168152/)
- 2018.12 [pediy] [[原创]CVE-2017-4901 VMware虚拟机逃逸漏洞分析【Frida Windows实例】](https://bbs.pediy.com/thread-248384.htm)
- 2018.12 [freebuf] [一篇文章带你领悟Frida的精髓（基于安卓8.1）](https://www.freebuf.com/articles/system/190565.html)
- 2018.12 [pediy] [[原创] Frida操作手册-Android环境准备](https://bbs.pediy.com/thread-248293.htm)
- 2018.11 [4hou] [使用FRIDA为Android应用进行脱壳的操作指南](http://www.4hou.com/technology/14404.html)
- 2018.11 [pediy] [[原创]Frida Bypass Android SSL pinning example 1](https://bbs.pediy.com/thread-247967.htm)
- 2018.11 [freebuf] [Frida-Wshook：一款基于Frida.re的脚本分析工具](https://www.freebuf.com/sectool/188726.html)
- 2018.11 [360] [如何使用FRIDA搞定Android加壳应用](https://www.anquanke.com/post/id/163390/)
- 2018.11 [ioactive] [Extracting Bluetooth Metadata in an Object’s Memory Using Frida](https://ioactive.com/extracting-bluetooth-metadata-in-an-objects-memory-using-frida/)
- 2018.11 [fortinet] [How-to Guide: Defeating an Android Packer with FRIDA](https://www.fortinet.com/blog/threat-research/defeating-an-android-packer-with-frida.html)
- 2018.10 [PancakeNopcode] [r2con2018 - Analyzing Swift Apps With swift-frida and radare2 - by Malte Kraus](https://www.youtube.com/watch?v=yp6E9-h6yYQ)
- 2018.10 [serializethoughts] [Bypassing Android FLAG_SECURE using FRIDA](https://serializethoughts.com/2018/10/07/bypassing-android-flag_secure-using-frida/)




***


## <a id="5a9974bfcf7cdf9b05fe7a7dc5272213"></a>其他




# <a id="d3690e0b19c784e104273fe4d64b2362"></a>其他


***


## <a id="9162e3507d24e58e9e944dd3f6066c0e"></a> 文章-新添加的




***


## <a id="1d9dec1320a5d774dc8e0e7604edfcd3"></a>工具-新添加的


- [**19766**星][3m] [Jupyter Notebook] [camdavidsonpilon/probabilistic-programming-and-bayesian-methods-for-hackers](https://github.com/camdavidsonpilon/probabilistic-programming-and-bayesian-methods-for-hackers) aka "Bayesian Methods for Hackers": An introduction to Bayesian methods + probabilistic programming with a computation/understanding-first, mathematics-second point of view. All in pure Python ;)
- [**14349**星][1m] [Py] [corentinj/real-time-voice-cloning](https://github.com/corentinj/real-time-voice-cloning) Clone a voice in 5 seconds to generate arbitrary speech in real-time
- [**11402**星][2d] [Java] [oracle/graal](https://github.com/oracle/graal) Run Programs Faster Anywhere
- [**11213**星][2m] [Jupyter Notebook] [selfteaching/the-craft-of-selfteaching](https://github.com/selfteaching/the-craft-of-selfteaching) One has no future if one couldn't teach themself.
- [**10378**星][3d] [Go] [goharbor/harbor](https://github.com/goharbor/harbor) An open source trusted cloud native registry project that stores, signs, and scans content.
- [**7748**星][2d] [Go] [git-lfs/git-lfs](https://github.com/git-lfs/git-lfs) Git extension for versioning large files
- [**7020**星][6d] [Go] [nats-io/nats-server](https://github.com/nats-io/nats-server) High-Performance server for NATS, the cloud native messaging system.
- [**6894**星][2m] [Go] [sqshq/sampler](https://github.com/sqshq/sampler) A tool for shell commands execution, visualization and alerting. Configured with a simple YAML file.
- [**6454**星][9m] [HTML] [open-power-workgroup/hospital](https://github.com/open-power-workgroup/hospital) OpenPower工作组收集汇总的医院开放数据
- [**6353**星][1m] [Py] [seatgeek/fuzzywuzzy](https://github.com/seatgeek/fuzzywuzzy) Fuzzy String Matching in Python
- [**6055**星][7m] [JS] [haotian-wang/google-access-helper](https://github.com/haotian-wang/google-access-helper) 谷歌访问助手破解版
- [**5876**星][3m] [Gnuplot] [nasa-jpl/open-source-rover](https://github.com/nasa-jpl/open-source-rover) A build-it-yourself, 6-wheel rover based on the rovers on Mars!
- [**5829**星][7m] [JS] [sindresorhus/fkill-cli](https://github.com/sindresorhus/fkill-cli) Fabulously kill processes. Cross-platform.
- [**5753**星][10d] [Go] [casbin/casbin](https://github.com/casbin/casbin) An authorization library that supports access control models like ACL, RBAC, ABAC in Golang
- [**5751**星][8m] [C] [xoreaxeaxeax/movfuscator](https://github.com/xoreaxeaxeax/movfuscator) C编译器，编译的二进制文件只有1个代码块。
- [**5717**星][20d] [JS] [swagger-api/swagger-editor](https://github.com/swagger-api/swagger-editor) Swagger Editor
- [**5420**星][4d] [Py] [mlflow/mlflow](https://github.com/mlflow/mlflow) Open source platform for the machine learning lifecycle
- [**5229**星][4m] [Py] [ytisf/thezoo](https://github.com/ytisf/thezoo) A repository of LIVE malwares for your own joy and pleasure. theZoo is a project created to make the possibility of malware analysis open and available to the public.
- [**5226**星][5d] [Shell] [denisidoro/navi](https://github.com/denisidoro/navi) An interactive cheatsheet tool for the command-line
- [**5116**星][3d] [ASP] [hq450/fancyss](https://github.com/hq450/fancyss) fancyss is a project providing tools to across the GFW on asuswrt/merlin based router.
- [**5007**星][1m] [Py] [snare/voltron](https://github.com/snare/voltron) A hacky debugger UI for hackers
- [**4857**星][5d] [Go] [gcla/termshark](https://github.com/gcla/termshark) A terminal UI for tshark, inspired by Wireshark
- [**4810**星][8m] [Py] [10se1ucgo/disablewintracking](https://github.com/10se1ucgo/disablewintracking) Uses some known methods that attempt to minimize tracking in Windows 10
- [**4747**星][t] [C++] [paddlepaddle/paddle-lite](https://github.com/PaddlePaddle/Paddle-Lite) Multi-platform high performance deep learning inference engine (『飞桨』多平台高性能深度学习预测引擎）
- [**4651**星][5d] [powershell/win32-openssh](https://github.com/powershell/win32-openssh) Win32 port of OpenSSH
- [**4610**星][1y] [C] [upx/upx](https://github.com/upx/upx) UPX - the Ultimate Packer for eXecutables
- [**4600**星][11m] [Py] [ecthros/uncaptcha2](https://github.com/ecthros/uncaptcha2) defeating the latest version of ReCaptcha with 91% accuracy
- [**4597**星][4d] [C++] [mozilla/rr](https://github.com/mozilla/rr) 记录与重放App的调试执行过程
- [**4541**星][4m] [TS] [apis-guru/graphql-voyager](https://github.com/apis-guru/graphql-voyager) 
- [**4352**星][12m] [Py] [lennylxx/ipv6-hosts](https://github.com/lennylxx/ipv6-hosts) Fork of
- [**4314**星][7d] [Rust] [timvisee/ffsend](https://github.com/timvisee/ffsend) Easily and securely share files from the command line
- [**4258**星][12m] [JS] [butterproject/butter-desktop](https://github.com/butterproject/butter-desktop) All the free parts of Popcorn Time
- [**4174**星][2y] [forter/security-101-for-saas-startups](https://github.com/forter/security-101-for-saas-startups) 初学者安全小窍门
- [**4062**星][3m] [Java] [jesusfreke/smali](https://github.com/jesusfreke/smali) smali/baksmali
- [**4060**星][2m] [JS] [sigalor/whatsapp-web-reveng](https://github.com/sigalor/whatsapp-web-reveng) WhatsApp Web API逆向与重新实现
- [**4003**星][3d] [Go] [dexidp/dex](https://github.com/dexidp/dex) OpenID Connect Identity (OIDC) and OAuth 2.0 Provider with Pluggable Connectors
- [**3980**星][27d] [Rust] [svenstaro/genact](https://github.com/svenstaro/genact) a nonsense activity generator
- [**3960**星][3d] [Py] [angr/angr](https://github.com/angr/angr) A powerful and user-friendly binary analysis platform!
- [**3954**星][8d] [Go] [eranyanay/1m-go-websockets](https://github.com/eranyanay/1m-go-websockets) handling 1M websockets connections in Go
- [**3939**星][7d] [C] [aquynh/capstone](https://github.com/aquynh/capstone) Capstone disassembly/disassembler framework: Core (Arm, Arm64, BPF, EVM, M68K, M680X, MOS65xx, Mips, PPC, RISCV, Sparc, SystemZ, TMS320C64x, Web Assembly, X86, X86_64, XCore) + bindings.
- [**3908**星][4d] [C++] [baldurk/renderdoc](https://github.com/baldurk/renderdoc) RenderDoc is a stand-alone graphics debugging tool.
- [**3844**星][2m] [ObjC] [sveinbjornt/sloth](https://github.com/sveinbjornt/sloth) Mac app that shows all open files, directories and sockets in use by all running processes. Nice GUI for lsof.
- [**3773**星][17d] [jjqqkk/chromium](https://github.com/jjqqkk/chromium) Chromium browser with SSL VPN. Use this browser to unblock websites.
- [**3768**星][2m] [Go] [microsoft/ethr](https://github.com/microsoft/ethr) Ethr is a Network Performance Measurement Tool for TCP, UDP & HTTP.
- [**3749**星][4d] [Go] [hashicorp/consul-template](https://github.com/hashicorp/consul-template) Template rendering, notifier, and supervisor for
- [**3690**星][13d] [JS] [lesspass/lesspass](https://github.com/lesspass/lesspass) 
- [**3688**星][21d] [HTML] [hamukazu/lets-get-arrested](https://github.com/hamukazu/lets-get-arrested) This project is intended to protest against the police in Japan
- [**3669**星][1y] [Py] [misterch0c/shadowbroker](https://github.com/misterch0c/shadowbroker) 方程式最新泄露
- [**3627**星][18d] [HTML] [consensys/smart-contract-best-practices](https://github.com/consensys/smart-contract-best-practices) A guide to smart contract security best practices
- [**3608**星][] [Pascal] [cheat-engine/cheat-engine](https://github.com/cheat-engine/cheat-engine) Cheat Engine. A development environment focused on modding
- [**3597**星][2y] [C#] [nummer/destroy-windows-10-spying](https://github.com/nummer/destroy-windows-10-spying) Destroy Windows Spying tool
- [**3597**星][3y] [Perl] [x0rz/eqgrp](https://github.com/x0rz/eqgrp) Decrypted content of eqgrp-auction-file.tar.xz
- [**3538**星][5m] [Shell] [chengr28/revokechinacerts](https://github.com/chengr28/revokechinacerts) Revoke Chinese certificates.
- [**3505**星][8d] [C] [cyan4973/xxhash](https://github.com/cyan4973/xxhash) Extremely fast non-cryptographic hash algorithm
- [**3451**星][10d] [C] [mikebrady/shairport-sync](https://github.com/mikebrady/shairport-sync) AirPlay audio player. Shairport Sync adds multi-room capability with Audio Synchronisation
- [**3320**星][2y] [scanate/ethlist](https://github.com/scanate/ethlist) The Comprehensive Ethereum Reading List
- [**3306**星][11d] [C] [microsoft/windows-driver-samples](https://github.com/microsoft/windows-driver-samples) This repo contains driver samples prepared for use with Microsoft Visual Studio and the Windows Driver Kit (WDK). It contains both Universal Windows Driver and desktop-only driver samples.
- [**3295**星][7d] [JS] [koenkk/zigbee2mqtt](https://github.com/koenkk/zigbee2mqtt) Zigbee
- [**3289**星][7d] [C] [virustotal/yara](https://github.com/virustotal/yara) The pattern matching swiss knife
- [**3280**星][21d] [Java] [oldmanpushcart/greys-anatomy](https://github.com/oldmanpushcart/greys-anatomy) Java诊断工具
- [**3259**星][5y] [C++] [google/lmctfy](https://github.com/google/lmctfy) lmctfy is the open source version of Google’s container stack, which provides Linux application containers.
- [**3243**星][6d] [Shell] [gfw-breaker/ssr-accounts](https://github.com/gfw-breaker/ssr-accounts) 一键部署Shadowsocks服务；免费Shadowsocks账号分享；免费SS账号分享; 翻墙；无界，自由门，SquirrelVPN
- [**3233**星][17d] [C] [tmate-io/tmate](https://github.com/tmate-io/tmate) Instant Terminal Sharing
- [**3219**星][2m] [TS] [google/incremental-dom](https://github.com/google/incremental-dom) An in-place DOM diffing library
- [**3202**星][1y] [Shell] [toyodadoubi/doubi](https://github.com/toyodadoubi/doubi) 一个逗比写的各种逗比脚本~
- [**3188**星][3d] [C] [meetecho/janus-gateway](https://github.com/meetecho/janus-gateway) Janus WebRTC Server
- [**3131**星][1m] [CSS] [readthedocs/sphinx_rtd_theme](https://github.com/readthedocs/sphinx_rtd_theme) Sphinx theme for readthedocs.org
- [**3129**星][5d] [C] [qemu/qemu](https://github.com/qemu/qemu) Official QEMU mirror. Please see
- [**3120**星][2d] [Go] [tencent/bk-cmdb](https://github.com/tencent/bk-cmdb) 蓝鲸智云配置平台(BlueKing CMDB)
- [**3108**星][1m] [C] [unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn) Unicorn CPU emulator framework (ARM, AArch64, M68K, Mips, Sparc, X86)
- [**3066**星][1y] [Swift] [zhuhaow/spechtlite](https://github.com/zhuhaow/spechtlite) A rule-based proxy for macOS
- [**3052**星][4m] [C++] [google/robotstxt](https://github.com/google/robotstxt) The repository contains Google's robots.txt parser and matcher as a C++ library (compliant to C++11).
- [**3010**星][1y] [PHP] [owner888/phpspider](https://github.com/owner888/phpspider) 《我用爬虫一天时间“偷了”知乎一百万用户，只为证明PHP是世界上最好的语言 》所使用的程序
- [**2993**星][10d] [Py] [quantaxis/quantaxis](https://github.com/quantaxis/quantaxis) 支持任务调度 分布式部署的 股票/期货/自定义市场 数据/回测/模拟/交易/可视化 纯本地PAAS量化解决方案
- [**2980**星][6d] [ObjC] [google/santa](https://github.com/google/santa) 用于Mac系统的二进制文件白名单/黑名单系统
- [**2948**星][23d] [C] [libfuse/sshfs](https://github.com/libfuse/sshfs) A network filesystem client to connect to SSH servers
- [**2898**星][7m] [C] [p-h-c/phc-winner-argon2](https://github.com/p-h-c/phc-winner-argon2) The password hash Argon2, winner of PHC
- [**2887**星][4y] [ObjC] [maciekish/iresign](https://github.com/maciekish/iresign) iReSign allows iDevice app bundles (.ipa) files to be signed or resigned with a digital certificate from Apple for distribution. This tool is aimed at enterprises users, for enterprise deployment, when the person signing the app is different than the person(s) developing it.
- [**2872**星][6d] [C] [lxc/lxc](https://github.com/lxc/lxc) LXC - Linux Containers
- [**2854**星][28d] [Py] [espressif/esptool](https://github.com/espressif/esptool) ESP8266 and ESP32 serial bootloader utility
- [**2848**星][6m] [Py] [instantbox/instantbox](https://github.com/instantbox/instantbox) Get a clean, ready-to-go Linux box in seconds.
- [**2833**星][2m] [Assembly] [cirosantilli/x86-bare-metal-examples](https://github.com/cirosantilli/x86-bare-metal-examples) 几十个用于学习 x86 系统编程的小型操作系统
- [**2815**星][12d] [C] [processhacker/processhacker](https://github.com/processhacker/processhacker) A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware.
- [**2808**星][10m] [Py] [plasma-disassembler/plasma](https://github.com/plasma-disassembler/plasma) Plasma is an interactive disassembler for x86/ARM/MIPS. It can generates indented pseudo-code with colored syntax.
- [**2789**星][5d] [C++] [qtox/qtox](https://github.com/qtox/qtox) qTox is a chat, voice, video, and file transfer IM client using the encrypted peer-to-peer Tox protocol.
- [**2772**星][2m] [JS] [trufflesuite/ganache-cli](https://github.com/trufflesuite/ganache-cli) Fast Ethereum RPC client for testing and development
- [**2760**星][] [TS] [webhintio/hint](https://github.com/webhintio/hint) 
- [**2718**星][3m] [Py] [drivendata/cookiecutter-data-science](https://github.com/drivendata/cookiecutter-data-science) A logical, reasonably standardized, but flexible project structure for doing and sharing data science work.
- [**2687**星][2d] [Go] [adguardteam/adguardhome](https://github.com/adguardteam/adguardhome) Network-wide ads & trackers blocking DNS server
- [**2631**星][8m] [leandromoreira/linux-network-performance-parameters](https://github.com/leandromoreira/linux-network-performance-parameters) Learn where some of the network sysctl variables fit into the Linux/Kernel network flow
- [**2627**星][15d] [JS] [popcorn-official/popcorn-desktop](https://github.com/popcorn-official/popcorn-desktop) Popcorn Time is a multi-platform, free software BitTorrent client that includes an integrated media player. Desktop ( Windows / Mac / Linux ) a Butter-Project Fork
- [**2621**星][2m] [pditommaso/awesome-pipeline](https://github.com/pditommaso/awesome-pipeline) A curated list of awesome pipeline toolkits inspired by Awesome Sysadmin
- [**2619**星][2m] [Swift] [zhuhaow/nekit](https://github.com/zhuhaow/nekit) A toolkit for Network Extension Framework
- [**2615**星][1m] [JS] [knownsec/kcon](https://github.com/knownsec/kcon) KCon is a famous Hacker Con powered by Knownsec Team.
- [**2587**星][2d] [C] [esnet/iperf](https://github.com/esnet/iperf) A TCP, UDP, and SCTP network bandwidth measurement tool
- [**2580**星][8y] [C] [id-software/quake](https://github.com/id-software/quake) Quake GPL Source Release
- [**2535**星][2m] [Java] [jboss-javassist/javassist](https://github.com/jboss-javassist/javassist) Java bytecode engineering toolkit
- [**2478**星][11m] [JS] [weixin/miaow](https://github.com/weixin/Miaow) A set of plugins for Sketch include drawing links & marks, UI Kit & Color sync, font & text replacing.
- [**2474**星][17d] [JS] [vitaly-t/pg-promise](https://github.com/vitaly-t/pg-promise) PostgreSQL interface for Node.js
- [**2456**星][3y] [Py] [google/enjarify](https://github.com/google/enjarify) 将Dalvik字节码转换为对应的Java字节码
- [**2395**星][3y] [OCaml] [facebookarchive/pfff](https://github.com/facebookarchive/pfff) 一堆工具的集合，用于执行静态分析、代码可视化、代码导航、保持格式的源码转换（例如：源码重构）。完美支持C、Java、JS、PHP，后续将支持其他一大堆语言。
- [**2391**星][12d] [Java] [mock-server/mockserver](https://github.com/mock-server/mockserver) MockServer enables easy mocking of any system you integrate with via HTTP or HTTPS with clients written in Java, JavaScript and Ruby. MockServer also includes a proxy that introspects all proxied traffic including encrypted SSL traffic and supports Port Forwarding, Web Proxying (i.e. HTTP proxy), HTTPS Tunneling Proxying (using HTTP CONNECT) and…
- [**2364**星][2d] [C] [domoticz/domoticz](https://github.com/domoticz/domoticz) monitor and configure various devices like: Lights, Switches, various sensors/meters like Temperature, Rain, Wind, UV, Electra, Gas, Water and much more
- [**2345**星][3m] [Go] [vuvuzela/vuvuzela](https://github.com/vuvuzela/vuvuzela) Private messaging system that hides metadata
- [**2344**星][8d] [C] [tsl0922/ttyd](https://github.com/tsl0922/ttyd) Share your terminal over the web
- [**2340**星][2m] [JS] [pa11y/pa11y](https://github.com/pa11y/pa11y) Pa11y is your automated accessibility testing pal
- [**2321**星][5y] [C] [abrasive/shairport](https://github.com/abrasive/shairport) Airtunes emulator! Shairport is no longer maintained.
- [**2305**星][2m] [C] [moby/hyperkit](https://github.com/moby/hyperkit) A toolkit for embedding hypervisor capabilities in your application
- [**2301**星][3y] [Py] [lmacken/pyrasite](https://github.com/lmacken/pyrasite) 向运行中的 Python进程注入代码
- [**2286**星][1m] [JS] [talkingdata/inmap](https://github.com/talkingdata/inmap) 大数据地理可视化
- [**2260**星][5d] [dumb-password-rules/dumb-password-rules](https://github.com/dumb-password-rules/dumb-password-rules) Shaming sites with dumb password rules.
- [**2217**星][6d] [Go] [google/mtail](https://github.com/google/mtail) extract whitebox monitoring data from application logs for collection in a timeseries database
- [**2214**星][10d] [getlantern/lantern-binaries](https://github.com/getlantern/lantern-binaries) Lantern installers binary downloads.
- [**2211**星][1m] [C++] [google/bloaty](https://github.com/google/bloaty) Bloaty McBloatface: a size profiler for binaries
- [**2194**星][4d] [C] [armmbed/mbedtls](https://github.com/armmbed/mbedtls) An open source, portable, easy to use, readable and flexible SSL library
- [**2137**星][11d] [Assembly] [pret/pokered](https://github.com/pret/pokered) disassembly of Pokémon Red/Blue
- [**2132**星][12d] [goq/telegram-list](https://github.com/goq/telegram-list) List of telegram groups, channels & bots // Список интересных групп, каналов и ботов телеграма // Список чатов для программистов
- [**2093**星][] [C] [flatpak/flatpak](https://github.com/flatpak/flatpak) Linux application sandboxing and distribution framework
- [**2092**星][18d] [swiftonsecurity/sysmon-config](https://github.com/swiftonsecurity/sysmon-config) Sysmon configuration file template with default high-quality event tracing
- [**2080**星][1m] [Go] [theupdateframework/notary](https://github.com/theupdateframework/notary) Notary is a project that allows anyone to have trust over arbitrary collections of data
- [**2053**星][4m] [Go] [maxmcd/webtty](https://github.com/maxmcd/webtty) Share a terminal session over WebRTC
- [**2053**星][16d] [C#] [mathewsachin/captura](https://github.com/mathewsachin/captura) Capture Screen, Audio, Cursor, Mouse Clicks and Keystrokes
- [**2052**星][5d] [C++] [openthread/openthread](https://github.com/openthread/openthread) OpenThread released by Google is an open-source implementation of the Thread networking protocol
- [**2031**星][10m] [C] [dekunukem/nintendo_switch_reverse_engineering](https://github.com/dekunukem/nintendo_switch_reverse_engineering) A look at inner workings of Joycon and Nintendo Switch
- [**2005**星][4y] [C] [probablycorey/wax](https://github.com/probablycorey/wax) Wax is now being maintained by alibaba
- [**2003**星][2m] [C++] [asmjit/asmjit](https://github.com/asmjit/asmjit) Complete x86/x64 JIT and AOT Assembler for C++
- [**1998**星][1m] [Swift] [github/softu2f](https://github.com/github/softu2f) Software U2F authenticator for macOS
- [**1955**星][3d] [Go] [solo-io/gloo](https://github.com/solo-io/gloo) An Envoy-Powered API Gateway
- [**1949**星][9d] [C] [microsoft/procdump-for-linux](https://github.com/microsoft/procdump-for-linux) Linux 版本的 ProcDump
- [**1944**星][3y] [C#] [lazocoder/windows-hacks](https://github.com/lazocoder/windows-hacks) Creative and unusual things that can be done with the Windows API.
- [**1930**星][14d] [C++] [mhammond/pywin32](https://github.com/mhammond/pywin32) Python for Windows (pywin32) Extensions
- [**1907**星][10d] [Go] [minishift/minishift](https://github.com/minishift/minishift) Run OpenShift 3.x locally
- [**1899**星][17d] [C++] [acidanthera/lilu](https://github.com/acidanthera/Lilu) Arbitrary kext and process patching on macOS
- [**1893**星][5y] [C++] [tum-vision/lsd_slam](https://github.com/tum-vision/lsd_slam) LSD-SLAM
- [**1877**星][17d] [Java] [adoptopenjdk/jitwatch](https://github.com/adoptopenjdk/jitwatch) Log analyser / visualiser for Java HotSpot JIT compiler. Inspect inlining decisions, hot methods, bytecode, and assembly. View results in the JavaFX user interface.
- [**1864**星][4y] [ObjC] [xcodeghostsource/xcodeghost](https://github.com/xcodeghostsource/xcodeghost) "XcodeGhost" Source
- [**1863**星][2d] [C++] [pytorch/glow](https://github.com/pytorch/glow) Compiler for Neural Network hardware accelerators
- [**1859**星][12m] [C++] [googlecreativelab/open-nsynth-super](https://github.com/googlecreativelab/open-nsynth-super) Open NSynth Super is an experimental physical interface for the NSynth algorithm
- [**1854**星][11d] [C] [github/glb-director](https://github.com/github/glb-director) GitHub Load Balancer Director and supporting tooling.
- [**1852**星][1y] [Py] [jinnlynn/genpac](https://github.com/jinnlynn/genpac) PAC/Dnsmasq/Wingy file Generator, working with gfwlist, support custom rules.
- [**1851**星][1y] [Java] [yeriomin/yalpstore](https://github.com/yeriomin/yalpstore) Download apks from Google Play Store
- [**1848**星][9m] [Py] [netflix-skunkworks/stethoscope](https://github.com/Netflix-Skunkworks/stethoscope) Personalized, user-focused recommendations for employee information security.
- [**1846**星][2m] [C] [retroplasma/earth-reverse-engineering](https://github.com/retroplasma/earth-reverse-engineering) Reversing Google's 3D satellite mode
- [**1837**星][3m] [Go] [influxdata/kapacitor](https://github.com/influxdata/kapacitor) Open source framework for processing, monitoring, and alerting on time series data
- [**1827**星][5d] [Py] [trailofbits/manticore](https://github.com/trailofbits/manticore) 动态二进制分析工具，支持符号执行（symbolic execution）、污点分析（taint analysis）、运行时修改。
- [**1816**星][21d] [Go] [gdamore/tcell](https://github.com/gdamore/tcell) Tcell is an alternate terminal package, similar in some ways to termbox, but better in others.
- [**1786**星][26d] [C++] [apitrace/apitrace](https://github.com/apitrace/apitrace) Tools for tracing OpenGL, Direct3D, and other graphics APIs
- [**1781**星][18d] [PHP] [ezyang/htmlpurifier](https://github.com/ezyang/htmlpurifier) Standards compliant HTML filter written in PHP
- [**1779**星][21d] [17mon/china_ip_list](https://github.com/17mon/china_ip_list) 
- [**1771**星][3y] [ObjC] [alibaba/wax](https://github.com/alibaba/wax) Wax is a framework that lets you write native iPhone apps in Lua.
- [**1761**星][1y] [JS] [puppeteer/examples](https://github.com/puppeteer/examples) Use case-driven examples for using Puppeteer and headless chrome
- [**1761**星][4d] [C] [google/wuffs](https://github.com/google/wuffs) Wrangling Untrusted File Formats Safely
- [**1756**星][8d] [PHP] [wordpress/wordpress-coding-standards](https://github.com/wordpress/wordpress-coding-standards) PHP_CodeSniffer rules (sniffs) to enforce WordPress coding conventions
- [**1727**星][t] [TSQL] [brentozarultd/sql-server-first-responder-kit](https://github.com/brentozarultd/sql-server-first-responder-kit) sp_Blitz, sp_BlitzCache, sp_BlitzFirst, sp_BlitzIndex, and other SQL Server scripts for health checks and performance tuning.
- [**1722**星][4m] [Py] [anorov/cloudflare-scrape](https://github.com/anorov/cloudflare-scrape) A Python module to bypass Cloudflare's anti-bot page.
- [**1714**星][27d] [Go] [hashicorp/memberlist](https://github.com/hashicorp/memberlist) Golang package for gossip based membership and failure detection
- [**1698**星][13d] [C++] [microsoft/detours](https://github.com/microsoft/detours) Detours is a software package for monitoring and instrumenting API calls on Windows. It is distributed in source code form.
- [**1694**星][3y] [CoffeeScript] [okturtles/dnschain](https://github.com/okturtles/dnschain) A blockchain-based DNS + HTTP server that fixes HTTPS security, and more!
- [**1676**星][2d] [Java] [apache/geode](https://github.com/apache/geode) Apache Geode
- [**1672**星][7m] [C] [easyhook/easyhook](https://github.com/easyhook/easyhook) The reinvention of Windows API Hooking
- [**1668**星][3m] [Py] [boppreh/keyboard](https://github.com/boppreh/keyboard) Hook and simulate global keyboard events on Windows and Linux.
- [**1665**星][4y] [Java] [dodola/hotfix](https://github.com/dodola/hotfix) 安卓App热补丁动态修复框架
- [**1659**星][16d] [JS] [tylerbrock/mongo-hacker](https://github.com/tylerbrock/mongo-hacker) MongoDB Shell Enhancements for Hackers
- [**1650**星][5d] [sarojaba/awesome-devblog](https://github.com/sarojaba/awesome-devblog) 어썸데브블로그. 국내 개발 블로그 모음(only 실명으로).
- [**1637**星][4d] [JS] [efforg/privacybadger](https://github.com/efforg/privacybadger) Privacy Badger is a browser extension that automatically learns to block invisible trackers.
- [**1624**星][9m] [JS] [localtunnel/server](https://github.com/localtunnel/server) server for localtunnel.me
- [**1620**星][8d] [C++] [lief-project/lief](https://github.com/lief-project/lief) Library to Instrument Executable Formats
- [**1616**星][2y] [JS] [addyosmani/a11y](https://github.com/addyosmani/a11y) Accessibility audit tooling for the web (beta)
- [**1592**星][2m] [ObjC] [ealeksandrov/provisionql](https://github.com/ealeksandrov/provisionql) Quick Look plugin for apps and provisioning profile files
- [**1584**星][1y] [C] [qihoo360/phptrace](https://github.com/qihoo360/phptrace) A tracing and troubleshooting tool for PHP scripts.
- [**1572**星][25d] [C] [codahale/bcrypt-ruby](https://github.com/codahale/bcrypt-ruby)  Ruby binding for the OpenBSD bcrypt() password hashing algorithm, allowing you to easily store a secure hash of your users' passwords.
- [**1562**星][29d] [C] [p-gen/smenu](https://github.com/p-gen/smenu) Terminal utility that reads words from standard input or from a file and creates an interactive selection window just below the cursor. The selected word(s) are sent to standard output for further processing.
- [**1562**星][11d] [Java] [gchq/gaffer](https://github.com/gchq/Gaffer) A large-scale entity and relation database supporting aggregation of properties
- [**1540**星][2y] [C++] [hteso/iaito](https://github.com/hteso/iaito) Radare2 GUI，使用Qt和C++
- [**1015**星][3y] [C++] [aguinet/wannakey](https://github.com/aguinet/wannakey) XP 系统从内存中恢复 Wanacry 最初使用 RSA 私钥（要求主机感染后未重启）
- [**966**星][7m] [PHP] [jenssegers/optimus](https://github.com/jenssegers/optimus)  id transformation With this library, you can transform your internal id's to obfuscated integers based on Knuth's integer has和
- [**906**星][7m] [C++] [dfhack/dfhack](https://github.com/DFHack/dfhack) Memory hacking library for Dwarf Fortress and a set of tools that use it
- [**895**星][11m] [JS] [levskaya/jslinux-deobfuscated](https://github.com/levskaya/jslinux-deobfuscated) An old version of Mr. Bellard's JSLinux rewritten to be human readable, hand deobfuscated and annotated.
- [**706**星][1y] [Jupyter Notebook] [anishathalye/obfuscated-gradients](https://github.com/anishathalye/obfuscated-gradients) Obfuscated Gradients Give a False Sense of Security: Circumventing Defenses to Adversarial Examples
- [**658**星][10m] [Jupyter Notebook] [supercowpowers/data_hacking](https://github.com/SuperCowPowers/data_hacking) Data Hacking Project
- [**657**星][1y] [Rust] [endgameinc/xori](https://github.com/endgameinc/xori) Xori is an automation-ready disassembly and static analysis library for PE32, 32+ and shellcode
- [**637**星][13d] [PS] [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) sysmon配置模块收集
- [**587**星][6m] [nshalabi/sysmontools](https://github.com/nshalabi/sysmontools) Utilities for Sysmon
- [**568**星][11m] [JS] [raineorshine/solgraph](https://github.com/raineorshine/solgraph) Visualize Solidity control flow for smart contract security analysis.
- [**551**星][3y] [Makefile] [veficos/reverse-engineering-for-beginners](https://github.com/veficos/reverse-engineering-for-beginners) translate project of Drops
- [**523**星][1m] [mhaggis/sysmon-dfir](https://github.com/mhaggis/sysmon-dfir) Sources, configuration and how to detect evil things utilizing Microsoft Sysmon.
- [**522**星][4m] [Java] [java-deobfuscator/deobfuscator](https://github.com/java-deobfuscator/deobfuscator) Java 代码反混淆工具
- [**507**星][8m] [JS] [mindedsecurity/jstillery](https://github.com/mindedsecurity/jstillery) Advanced JavaScript Deobfuscation via Partial Evaluation
- [**480**星][1y] [ksluckow/awesome-symbolic-execution](https://github.com/ksluckow/awesome-symbolic-execution) A curated list of awesome symbolic execution resources including essential research papers, lectures, videos, and tools.
- [**449**星][12m] [C++] [ntquery/scylla](https://github.com/ntquery/scylla) Imports Reconstructor
- [**447**星][3m] [Go] [retroplasma/flyover-reverse-engineering](https://github.com/retroplasma/flyover-reverse-engineering) Reversing Apple's 3D satellite mode
- [**446**星][11m] [Batchfile] [ion-storm/sysmon-config](https://github.com/ion-storm/sysmon-config) Advanced Sysmon configuration, Installer & Auto Updater with high-quality event tracing
- [**437**星][2y] [PS] [danielbohannon/revoke-obfuscation](https://github.com/danielbohannon/revoke-obfuscation) PowerShell Obfuscation Detection Framework
- [**408**星][2y] [Py] [fossfreedom/indicator-sysmonitor](https://github.com/fossfreedom/indicator-sysmonitor) Ubuntu application indicator to show various system parameters
- [**408**星][11d] [Py] [crytic/slither](https://github.com/crytic/slither) Static Analyzer for Solidity
- [**383**星][1y] [HTML] [maestron/reverse-engineering-tutorials](https://github.com/maestron/reverse-engineering-tutorials) Reverse Engineering Tutorials
- [**366**星][10y] [C] [brl/obfuscated-openssh](https://github.com/brl/obfuscated-openssh) 
- [**344**星][1y] [Ruby] [calebfenton/dex-oracle](https://github.com/calebfenton/dex-oracle) A pattern based Dalvik deobfuscator which uses limited execution to improve semantic analysis
- [**308**星][16d] [Py] [baderj/domain_generation_algorithms](https://github.com/baderj/domain_generation_algorithms) 域名生成算法
- [**306**星][1m] [C] [nagyd/sdlpop](https://github.com/nagyd/sdlpop) An open-source port of Prince of Persia, based on the disassembly of the DOS version.
- [**291**星][20d] [C] [tomb5/tomb5](https://github.com/tomb5/tomb5) Chronicles Disassembly translated to C source code.
- [**265**星][2m] [Assembly] [pret/pokeyellow](https://github.com/pret/pokeyellow) Disassembly of Pokemon Yellow
- [**240**星][4m] [JS] [consensys/surya](https://github.com/consensys/surya) A set of utilities for exploring Solidity contracts
- [**224**星][2y] [Py] [rub-syssec/syntia](https://github.com/rub-syssec/syntia) Program synthesis based deobfuscation framework for the USENIX 2017 paper "Syntia: Synthesizing the Semantics of Obfuscated Code"
- [**214**星][2m] [Py] [rpisec/llvm-deobfuscator](https://github.com/rpisec/llvm-deobfuscator) 
- [**211**星][12m] [Java] [neo23x0/fnord](https://github.com/neo23x0/fnord) Pattern Extractor for Obfuscated Code
- [**198**星][1m] [F#] [b2r2-org/b2r2](https://github.com/b2r2-org/b2r2) B2R2 is a collection of useful algorithms, functions, and tools for binary analysis.
- [**194**星][3y] [C#] [codeshark-dev/nofuserex](https://github.com/codeshark-dev/nofuserex) Free deobfuscator for ConfuserEx.
- [**180**星][2m] [Py] [eth-sri/debin](https://github.com/eth-sri/debin) Machine Learning to Deobfuscate Binaries
- [**174**星][2y] [C] [geosn0w/reverse-engineering-tutorials](https://github.com/geosn0w/reverse-engineering-tutorials) Some Reverse Engineering Tutorials for Beginners
- [**169**星][1y] [PS] [mattifestation/pssysmontools](https://github.com/mattifestation/pssysmontools) Sysmon Tools for PowerShell
- [**164**星][2m] [JS] [lelinhtinh/de4js](https://github.com/lelinhtinh/de4js) JavaScript Deobfuscator and Unpacker
- [**158**星][6m] [C] [kkamagui/shadow-box-for-x86](https://github.com/kkamagui/shadow-box-for-x86) Lightweight and Practical Kernel Protector for x86 (Presented at BlackHat Asia 2017/2018, beVX 2018 and HITBSecConf 2017)
- [**151**星][8m] [C] [adrianyy/eacreversing](https://github.com/adrianyy/eacreversing) Reversing EasyAntiCheat.
- [**148**星][6m] [olafhartong/sysmon-cheatsheet](https://github.com/olafhartong/sysmon-cheatsheet) All sysmon event types and their fields explained
- [**144**星][1m] [Java] [superblaubeere27/obfuscator](https://github.com/superblaubeere27/obfuscator) A java obfuscator (GUI)
- [**140**星][12m] [C++] [finixbit/elf-parser](https://github.com/finixbit/elf-parser) Lightweight elf binary parser with no external dependencies - Sections, Symbols, Relocations, Segments
- [**139**星][7m] [C] [glv2/bruteforce-wallet](https://github.com/glv2/bruteforce-wallet) Try to find the password of an encrypted Peercoin (or Bitcoin, Litecoin, etc...) wallet file.
- [**137**星][4y] [C] [xairy/kaslr-bypass-via-prefetch](https://github.com/xairy/kaslr-bypass-via-prefetch) A proof-of-concept KASLR bypass for the Linux kernel via timing prefetch (dilettante implementation, better read the original paper:
- [**134**星][1y] [PS] [darkoperator/posh-sysmon](https://github.com/darkoperator/posh-sysmon) PowerShell module for creating and managing Sysinternals Sysmon config files.
- [**129**星][3y] [Swift] [magic-akari/wannacry](https://github.com/magic-akari/wannacry) 
- [**122**星][1y] [PS] [mattifestation/bhusa2018_sysmon](https://github.com/mattifestation/bhusa2018_sysmon) All materials from our Black Hat 2018 "Subverting Sysmon" talk
- [**119**星][5m] [C#] [akaion/jupiter](https://github.com/akaion/jupiter) A Windows virtual memory editing library with support for pattern scanning.
- [**118**星][2y] [Py] [malus-security/sandblaster](https://github.com/malus-security/sandblaster) Reversing the Apple sandbox
- [**117**星][4m] [PS] [thom-s/netsec-ps-scripts](https://github.com/thom-s/netsec-ps-scripts) Collection of PowerShell network security scripts for system administrators.
- [**114**星][4m] [we5ter/flerken](https://github.com/we5ter/flerken) A Solution For Cross-Platform Obfuscated Commands Detection
- [**111**星][2y] [Py] [cfsworks/wavebird-reversing](https://github.com/cfsworks/wavebird-reversing) Reverse-engineering the WaveBird protocol for the betterment of mankind
- [**109**星][1y] [Shell] [jgamblin/blackhat-macos-config](https://github.com/jgamblin/blackhat-macos-config) Configure Your Macbook For Blackhat
- [**109**星][8m] [C#] [virb3/de4dot-cex](https://github.com/virb3/de4dot-cex) de4dot deobfuscator with full support for vanilla ConfuserEx
- [**108**星][3y] [ios-reverse-engineering-dev/swift-apps-reverse-engineering](https://github.com/ios-reverse-engineering-dev/swift-apps-reverse-engineering) Swift Apps Reverse Engineering reading book
- [**107**星][3m] [C#] [matterpreter/shhmon](https://github.com/matterpreter/shhmon) Neutering Sysmon via driver unload
- [**106**星][4m] [Go] [bnagy/gapstone](https://github.com/bnagy/gapstone) gapstone is a Go binding for the capstone disassembly library
- [**99**星][3m] [C++] [marcosd4h/sysmonx](https://github.com/marcosd4h/sysmonx) An Augmented Drop-In Replacement of Sysmon
- [**98**星][1y] [C#] [holly-hacker/eazfixer](https://github.com/holly-hacker/eazfixer) A deobfuscation tool for Eazfuscator.
- [**97**星][3y] [Py] [fdiskyou/kcshell](https://github.com/fdiskyou/kcshell) 交互式汇编/反汇编 Shell，Python3编写，基于Keystone/Capstone
- [**97**星][2d] [PHP] [cybercog/laravel-optimus](https://github.com/cybercog/laravel-optimus) Transform your internal id's to obfuscated integers based on Knuth's integer hash.
- [**88**星][2y] [PS] [danielbohannon/out-fincodedcommand](https://github.com/danielbohannon/out-fincodedcommand) POC Highlighting Obfuscation Techniques used by FIN threat actors based on cmd.exe's replace functionality and cmd.exe/powershell.exe's stdin command invocation capabilities
- [**85**星][11m] [C++] [basketwill/sysmon_reverse](https://github.com/basketwill/sysmon_reverse) 
- [**82**星][3m] [blockchainlabsnz/awesome-solidity](https://github.com/blockchainlabsnz/awesome-solidity) A curated list of awesome Solidity resources
- [**80**星][3m] [sbousseaden/panache_sysmon](https://github.com/sbousseaden/panache_sysmon) A Sysmon Config for APTs Techniques Detection
- [**79**星][5m] [Assembly] [thecodeartist/elf-parser](https://github.com/thecodeartist/elf-parser) Identifying/Extracting various sections of an ELF file
- [**70**星][3y] [Py] [antelox/fopo-php-deobfuscator](https://github.com/antelox/fopo-php-deobfuscator) A simple script to deobfuscate PHP file obfuscated with FOPO Obfuscator -
- [**68**星][5m] [splunk/ta-microsoft-sysmon](https://github.com/splunk/ta-microsoft-sysmon) TA-microsoft-sysmon
- [**67**星][2y] [Py] [sapir/sonare](https://github.com/sapir/sonare) A Qt-based disassembly viewer based on radare2
- [**64**星][11m] [Zeek] [salesforce/bro-sysmon](https://github.com/salesforce/bro-sysmon) How to Zeek Sysmon Logs!
- [**60**星][1y] [Java] [java-deobfuscator/deobfuscator-gui](https://github.com/java-deobfuscator/deobfuscator-gui) An awesome GUI for an awesome deobfuscator
- [**60**星][4y] [Objective-C++] [steven-michaud/reverse-engineering-on-osx](https://github.com/steven-michaud/reverse-engineering-on-osx) Reverse Engineering on OS X
- [**56**星][1y] [Nix] [dapphub/ds-auth](https://github.com/dapphub/ds-auth) Updatable, unobtrusive Solidity authorization pattern
- [**56**星][6m] [TS] [geeksonsecurity/illuminatejs](https://github.com/geeksonsecurity/illuminatejs) IlluminateJs is a static JavaScript deobfuscator
- [**55**星][5m] [basketwill/z0bpctools](https://github.com/basketwill/z0bpctools) 一个windows反汇编工具，界面风格防OllyDbg 利用业余开发了一款类似仿OLlyDbg界面的 IDA静态反编译工具，目前是1.0版本，功能不是很强大但是基本功能有了
- [**55**星][2y] [TeX] [season-lab/survey-symbolic-execution](https://github.com/season-lab/survey-symbolic-execution) 对有关符号执行相关工具和技术的调查
- [**55**星][3m] [C] [resilar/crchack](https://github.com/resilar/crchack) Reversing CRC for fun and profit
- [**53**星][7y] [C++] [eschweiler/proreversing](https://github.com/eschweiler/proreversing) Open and generic Anti-Anti Reversing Framework. Works in 32 and 64 bits.
- [**53**星][3y] [PS] [elevenpaths/telefonica-wannacry-filerestorer](https://github.com/elevenpaths/telefonica-wannacry-filerestorer) Tool to restore some WannaCry files which encryption weren't finish properly
- [**52**星][25d] [C] [danielkrupinski/vac](https://github.com/danielkrupinski/vac) Source code of Valve Anti-Cheat obtained from disassembly of compiled modules
- [**52**星][10m] [Assembly] [pret/pokepinball](https://github.com/pret/pokepinball) disassembly of pokémon pinball
- [**50**星][2y] [JS] [ericr/sol-function-profiler](https://github.com/ericr/sol-function-profiler) Solidity Contract Function Profiler
- [**50**星][2y] [Py] [sfwishes/ollvm_de_fla](https://github.com/sfwishes/ollvm_de_fla) deobfuscation ollvm's fla
- [**47**星][5y] [jameshabben/sysmon-queries](https://github.com/jameshabben/sysmon-queries) Queries to parse sysmon event log file with microsoft logparser
- [**47**星][6m] [C++] [talvos/talvos](https://github.com/talvos/talvos) Talvos is a dynamic-analysis framework and debugger for Vulkan/SPIR-V programs.
- [**45**星][6d] [Assembly] [drenn1/oracles-disasm](https://github.com/Drenn1/oracles-disasm) Disassembly of Oracle of Ages and Seasons
- [**45**星][2m] [Lua] [dsasmblr/cheat-engine](https://github.com/dsasmblr/cheat-engine) Cheat Engine scripts, tutorials, tools, and more.
- [**41**星][2y] [C] [cocoahuke/mackextdump](https://github.com/cocoahuke/mackextdump) mackextdump：从macOS中dump Kext信息
- [**40**星][2m] [jsecurity101/windows-api-to-sysmon-events](https://github.com/jsecurity101/windows-api-to-sysmon-events) A repository that maps API calls to Sysmon Event ID's.
- [**39**星][1y] [Py] [dissectmalware/batch_deobfuscator](https://github.com/dissectmalware/batch_deobfuscator) Deobfuscate batch scripts obfuscated using string substitution and escape character techniques.
- [**38**星][5m] [Assembly] [marespiaut/rayman_disasm](https://github.com/marespiaut/rayman_disasm) Reverse-engineering effort for the 1995 MS-DOS game “Rayman”
- [**36**星][2y] [Py] [extremecoders-re/bytecode_simplifier](https://github.com/extremecoders-re/bytecode_simplifier) A generic deobfuscator for PjOrion obfuscated python scripts
- [**36**星][2y] [Py] [extremecoders-re/pjorion-deobfuscator](https://github.com/extremecoders-re/pjorion-deobfuscator) A deobfuscator for PjOrion, python cfg generator and more
- [**36**星][3y] [C++] [steven-michaud/sandboxmirror](https://github.com/steven-michaud/sandboxmirror) Tool for reverse-engineering Apple's sandbox
- [**35**星][4y] [C#] [bnagy/crabstone](https://github.com/bnagy/crabstone) crabstone is a Ruby binding to the capstone disassembly library by Nguyen Anh Quynh
- [**35**星][3y] [C] [topcss/wannacry](https://github.com/topcss/wannacry) 勒索病毒WannaCry反编译源码
- [**34**星][6y] [JS] [michenriksen/hackpad](https://github.com/michenriksen/hackpad) A web application hacker's toolbox. Base64 encoding/decoding, URL encoding/decoding, MD5/SHA1/SHA256/HMAC hashing, code deobfuscation, formatting, highlighting and much more.
- [**33**星][12m] [ObjC] [jakeajames/reverse-engineering](https://github.com/jakeajames/reverse-engineering) nothing important
- [**32**星][1y] [mhaggis/sysmon-splunk-app](https://github.com/mhaggis/sysmon-splunk-app) Sysmon Splunk App
- [**31**星][3y] [mhaggis/app_splunk_sysmon_hunter](https://github.com/mhaggis/app_splunk_sysmon_hunter) Splunk App to assist Sysmon Threat Hunting
- [**31**星][4y] [Pascal] [pigrecos/codedeobfuscator](https://github.com/pigrecos/codedeobfuscator) Code Deobfuscator
- [**29**星][2y] [C++] [nuand/kalibrate-bladerf](https://github.com/nuand/kalibrate-bladerf) kalibrate-bladeRF
- [**27**星][2m] [JS] [b-mueller/sabre](https://github.com/b-mueller/sabre) Security analyzer for Solidity smart contracts. Uses MythX, the premier smart contract security service.
- [**27**星][1m] [C] [usineur/sdlpop](https://github.com/usineur/SDLPoP) An open-source port of Prince of Persia, based on the disassembly of the DOS version.
- [**24**星][5y] [JS] [vector35/hackinggames](https://github.com/vector35/hackinggames) Hacking Games in a Hacked Game
- [**22**星][2y] [Py] [zigzag2050/mzphp2-deobfuscator](https://github.com/zigzag2050/mzphp2-deobfuscator) A de-obfuscate tool for code generated by mzphp2. 用于解混淆mzphp2加密的php文件的工具。
- [**21**星][1y] [Lua] [yoshifan/ram-watch-cheat-engine](https://github.com/yoshifan/ram-watch-cheat-engine) Lua script framework for RAM watch displays using Cheat Engine, with a focus on Dolphin emulator.
- [**21**星][1m] [Py] [verabe/veriman](https://github.com/verabe/veriman) Analysis tool for Solidity smart contracts. Prototype.
- [**20**星][1y] [Batchfile] [olafhartong/ta-sysmon-deploy](https://github.com/olafhartong/ta-sysmon-deploy) Deploy and maintain Symon through the Splunk Deployment Sever


***


## <a id="bc2b78af683e7ba983205592de8c3a7a"></a>工具-其他


- [**1534**星][3y] [Py] [x0rz/eqgrp_lost_in_translation](https://github.com/x0rz/eqgrp_lost_in_translation) ShadowBrokers泄漏
- [**669**星][3y] [Py] [n1nj4sec/memorpy](https://github.com/n1nj4sec/memorpy) Python库, 使用ctypes搜索/编辑 Windows / Linux / macOS / SunOS 程序内存
- [**159**星][5y] [C#] [radiowar/nfcgui](https://github.com/radiowar/nfcgui) 图形化NFC协议安全分析工具，主要针对Mifare卡，基于libnfc完成


***


## <a id="4fe330ae3e5ce0b39735b1bfea4528af"></a>angr


### <a id="1ede5ade1e55074922eb4b6386f5ca65"></a>工具


- [**534**星][4d] [Py] [angr/angr-doc](https://github.com/angr/angr-doc) Documentation for the angr suite
- [**305**星][2m] [Py] [salls/angrop](https://github.com/salls/angrop) a rop gadget finder and chain builder 
- [**246**星][2y] [Py] [jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf) 
- [**197**星][10d] [Py] [angr/angr-management](https://github.com/angr/angr-management) A GUI for angr. Being developed *very* slowly.
- [**195**星][2y] [PS] [vysecurity/angrypuppy](https://github.com/vysecurity/ANGRYPUPPY) Bloodhound Attack Path Automation in CobaltStrike
- [**169**星][2y] [HTML] [ihebski/angryfuzzer](https://github.com/ihebski/angryfuzzer) Tools for information gathering
- [**122**星][1y] [Py] [axt/angr-utils](https://github.com/axt/angr-utils) Handy utilities for the angr binary analysis framework, most notably CFG visualization
- [**115**星][6m] [Py] [andreafioraldi/angrgdb](https://github.com/andreafioraldi/angrgdb) Use angr inside GDB. Create an angr state from the current debugger state.
- [**106**星][1y] [Py] [sidechannelmarvels/jeangrey](https://github.com/sidechannelmarvels/jeangrey) A tool to perform differential fault analysis attacks (DFA).
- [**91**星][1y] [Py] [fsecurelabs/z3_and_angr_binary_analysis_workshop](https://github.com/FSecureLABS/z3_and_angr_binary_analysis_workshop) Code and exercises for a workshop on z3 and angr
- [**64**星][9d] [Shell] [angr/angr-dev](https://github.com/angr/angr-dev) Some helper scripts to set up an environment for angr development.
- [**64**星][7m] [Assembly] [cdisselkoen/pitchfork](https://github.com/cdisselkoen/pitchfork) Detecting Spectre vulnerabilities using symbolic execution, built on angr (github.com/angr/angr)
- [**61**星][4y] [Shell] [praetorian-code/epictreasure](https://github.com/praetorian-code/epictreasure) radare, angr, pwndbg, binjitsu, ect in a box ready for pwning
- [**47**星][17d] [Py] [ercoppa/symbolic-execution-tutorial](https://github.com/ercoppa/symbolic-execution-tutorial) Tutorial on Symbolic Execution. Hands-on session is based on the angr framework.
- [**33**星][6d] [Py] [angr/angr-platforms](https://github.com/angr/angr-platforms) A collection of extensions to angr to handle new platforms
- [**30**星][4d] [C] [angr/binaries](https://github.com/angr/binaries) A repository with binaries for angr tests and examples.
- [**24**星][7m] [Py] [andreafioraldi/r2angrdbg](https://github.com/andreafioraldi/r2angrdbg) 在 radare2 调试器中使用 angr
- [**23**星][4y] [bannsec/angr-windows](https://github.com/bannsec/angr-Windows) Windows builds for use with angr framework
- [**22**星][15d] [Py] [fmagin/angr-cli](https://github.com/fmagin/angr-cli) Repo for various angr ipython features to give it more of a cli feeling
- [**20**星][2y] [PS] [mdsecactivebreach/angrypuppy](https://github.com/mdsecactivebreach/angrypuppy) Bloodhound Attack Path Automation in CobaltStrike
- [**19**星][2y] [Py] [brandon-everhart/angryida](https://github.com/brandon-everhart/angryida) 在IDA中集成angr二进制分析框架
    - 重复区段: [IDA->插件->导入导出->未分类](#8ad723b704b044e664970b11ce103c09) |
- [**12**星][1y] [Py] [ash09/angr-static-analysis-for-vuzzer64](https://github.com/ash09/angr-static-analysis-for-vuzzer64) Angr-based static analysis tool for vusec/vuzzer64 fuzzing tool
- [**11**星][3y] [Py] [n00py/angryhippo](https://github.com/n00py/angryhippo) Exploiting the HippoConnect protocol for HippoRemote
- [**8**星][1y] [C] [shellphish/patcherex](https://github.com/shellphish/patcherex) please go to angr/patcherex instead of this!
- [**8**星][3y] [C++] [project64/angrylion-rdp](https://github.com/project64/angrylion-rdp) 
- [**3**星][2y] [Py] [futaki-futaba/angr-sample](https://github.com/futaki-futaba/angr-sample) angr 7向けのサンプルプログラムです


### <a id="042ef9d415350eeb97ac2539c2fa530e"></a>文章






***


## <a id="324874bb7c3ead94eae6f1fa1af4fb68"></a>Debug&&调试


### <a id="d22bd989b2fdaeda14b64343b472dfb6"></a>工具


- [**1544**星][6y] [Py] [google/pyringe](https://github.com/google/pyringe) Debugger capable of attaching to and injecting code into python processes.
- [**1450**星][2d] [Go] [google/gapid](https://github.com/google/gapid) Graphics API Debugger
- [**1422**星][9d] [C++] [eteran/edb-debugger](https://github.com/eteran/edb-debugger) edb is a cross platform AArch32/x86/x86-64 debugger.
- [**1413**星][11d] [Go] [cosmos72/gomacro](https://github.com/cosmos72/gomacro) Interactive Go interpreter and debugger with REPL, Eval, generics and Lisp-like macros
- [**1374**星][4y] [C++] [valvesoftware/vogl](https://github.com/valvesoftware/vogl) OpenGL capture / playback debugger.
- [**1275**星][3m] [Go] [solo-io/squash](https://github.com/solo-io/squash) The debugger for microservices
- [**1147**星][5m] [C++] [cgdb/cgdb](https://github.com/cgdb/cgdb) Console front-end to the GNU debugger
- [**1128**星][12d] [C] [blacksphere/blackmagic](https://github.com/blacksphere/blackmagic) In application debugger for ARM Cortex microcontrollers.
- [**899**星][2d] [Py] [derekselander/lldb](https://github.com/derekselander/lldb) A collection of LLDB aliases/regexes and Python scripts to aid in your debugging sessions
- [**836**星][t] [C++] [tasvideos/bizhawk](https://github.com/tasvideos/bizhawk) BizHawk is a multi-system emulator written in C#. BizHawk provides nice features for casual gamers such as full screen, and joypad support in addition to full rerecording and debugging tools for all system cores.
- [**708**星][2y] [Go] [sidkshatriya/dontbug](https://github.com/sidkshatriya/dontbug) Dontbug is a reverse debugger for PHP
- [**627**星][3y] [C] [chokepoint/azazel](https://github.com/chokepoint/azazel) Azazel is a userland rootkit based off of the original LD_PRELOAD technique from Jynx rootkit. It is more robust and has additional features, and focuses heavily around anti-debugging and anti-detection.
- [**573**星][4y] [C++] [microsoft/iediagnosticsadapter](https://github.com/microsoft/iediagnosticsadapter) IE Diagnostics Adapter is a standalone exe that enables tools to debug and diagnose IE11 using the Chrome remote debug protocol.
- [**560**星][13d] [C#] [microsoft/miengine](https://github.com/microsoft/miengine) The Visual Studio MI Debug Engine ("MIEngine") provides an open-source Visual Studio Debugger extension that works with MI-enabled debuggers such as gdb, lldb, and clrdbg.
- [**521**星][1y] [C] [wubingzheng/memleax](https://github.com/wubingzheng/memleax) debugs memory leak of running process. Not maintained anymore, try `libleak` please.
- [**462**星][4m] [C++] [emoon/prodbg](https://github.com/emoon/prodbg) Debugging the way it's meant to be done
- [**430**星][4y] [C] [alonho/pytrace](https://github.com/alonho/pytrace) pytrace is a fast python tracer. it records function calls, arguments and return values. can be used for debugging and profiling.
- [**423**星][3m] [C++] [cobaltfusion/debugviewpp](https://github.com/cobaltfusion/debugviewpp) DebugView++, collects, views, filters your application logs, and highlights information that is important to you!
- [**418**星][18d] [C++] [simonkagstrom/kcov](https://github.com/simonkagstrom/kcov) Code coverage tool for compiled programs, Python and Bash which uses debugging information to collect and report data without special compilation options
- [**377**星][1m] [Py] [pdbpp/pdbpp](https://github.com/pdbpp/pdbpp) pdb++, a drop-in replacement for pdb (the Python debugger)
- [**354**星][2y] [C++] [glsl-debugger/glsl-debugger](https://github.com/glsl-debugger/glsl-debugger) GLSL source level debugger.
- [**354**星][8y] [Py] [openrce/pydbg](https://github.com/openrce/pydbg) A pure-python win32 debugger interface.
- [**332**星][8m] [Py] [romanvm/python-web-pdb](https://github.com/romanvm/python-web-pdb) Web-based remote UI for Python's PDB debugger
- [**306**星][13d] [Java] [widdix/aws-s3-virusscan](https://github.com/widdix/aws-s3-virusscan) Free Antivirus for S3 Buckets
- [**291**星][4d] [Py] [sosreport/sos](https://github.com/sosreport/sos) A unified tool for collecting system logs and other debug information
- [**289**星][3y] [C++] [develbranch/tinyantivirus](https://github.com/develbranch/tinyantivirus) TinyAntivirus is an open source antivirus engine designed for detecting polymorphic virus and disinfecting it.
- [**288**星][2y] [Java] [cnfree/eclipse-class-decompiler](https://github.com/cnfree/eclipse-class-decompiler) Eclipse Class Decompiler integrates JD, Jad, FernFlower, CFR, Procyon seamlessly with Eclipse and allows Java developers to debug class files without source code directly
- [**285**星][2m] [C++] [changeofpace/viviennevmm](https://github.com/changeofpace/viviennevmm) VivienneVMM is a stealthy debugging framework implemented via an Intel VT-x hypervisor.
- [**272**星][4m] [Py] [mariovilas/winappdbg](https://github.com/mariovilas/winappdbg) WinAppDbg Debugger
- [**270**星][13d] [Py] [ionelmc/python-manhole](https://github.com/ionelmc/python-manhole) Debugging manhole for python applications.
- [**267**星][4y] [C] [blankwall/macdbg](https://github.com/blankwall/macdbg) Simple easy to use C and python debugging framework for OSX
- [**255**星][3y] [Py] [airsage/petrel](https://github.com/airsage/petrel) Tools for writing, submitting, debugging, and monitoring Storm topologies in pure Python
- [**250**星][2y] [Py] [dbgx/lldb.nvim](https://github.com/dbgx/lldb.nvim) Debugger integration with a focus on ease-of-use.
- [**250**星][1m] [Py] [quantopian/qdb](https://github.com/quantopian/qdb) Quantopian Remote Debugger for Python
- [**240**星][5m] [C++] [facebook/ds2](https://github.com/facebook/ds2) Debug server for lldb.
- [**239**星][8m] [C++] [strivexjun/xantidebug](https://github.com/strivexjun/xantidebug) VMProtect 3.x Anti-debug Method Improved
- [**239**星][8m] [Py] [beeware/bugjar](https://github.com/beeware/bugjar) A interactive graphical debugger for Python code.
- [**233**星][2m] [Py] [gilligan/vim-lldb](https://github.com/gilligan/vim-lldb) lldb debugger integration plugin for vim
- [**220**星][8m] [letoram/senseye](https://github.com/letoram/senseye) Dynamic Visual Debugging / Reverse Engineering Toolsuite
- [**218**星][1m] [Py] [nteseyes/pylane](https://github.com/nteseyes/pylane) An python vm injector with debug tools, based on gdb.
- [**213**星][3d] [C++] [thalium/icebox](https://github.com/thalium/icebox) Virtual Machine Introspection, Tracing & Debugging
- [**209**星][2m] [C] [joyent/mdb_v8](https://github.com/joyent/mdb_v8) postmortem debugging for Node.js and other V8-based programs
- [**200**星][5m] [C++] [rainers/cv2pdb](https://github.com/rainers/cv2pdb) converter of DMD CodeView/DWARF debug information to PDB files
- [**184**星][6m] [C] [therealsaumil/static-arm-bins](https://github.com/therealsaumil/static-arm-bins) 静态编译的arm二进制文件, 用于调试和运行时分析
- [**182**星][5y] [C] [gdbinit/onyx-the-black-cat](https://github.com/gdbinit/onyx-the-black-cat) Kernel extension to disable anti-debug tricks and other useful XNU "features"
- [**164**星][4d] [C++] [devinacker/bsnes-plus](https://github.com/devinacker/bsnes-plus) debug-oriented fork of bsnes
- [**163**星][3m] [JS] [ant4g0nist/vegvisir](https://github.com/ant4g0nist/vegvisir) 基于浏览器的LLDB 调试器
- [**163**星][22d] [C++] [jrfonseca/drmingw](https://github.com/jrfonseca/drmingw) Postmortem debugging tools for MinGW.
- [**157**星][2y] [C] [armadito/armadito-av](https://github.com/armadito/armadito-av) Armadito antivirus main repository
- [**154**星][4y] [Py] [kbandla/immunitydebugger](https://github.com/kbandla/immunitydebugger) ImmunityDebugger
- [**152**星][5y] [Shell] [hellman/fixenv](https://github.com/hellman/fixenv) Fix stack addresses (when no ASLR) with and without debugging
- [**151**星][2y] [Py] [reswitched/cagetheunicorn](https://github.com/reswitched/cagetheunicorn) Debugging/emulating environment for Switch code
- [**146**星][1m] [Py] [wenzel/pyvmidbg](https://github.com/wenzel/pyvmidbg) LibVMI-based debug server, implemented in Python. Building a guest aware, stealth and agentless full-system debugger
- [**142**星][2y] [C++] [honorarybot/pulsedbg](https://github.com/honorarybot/pulsedbg) Hypervisor-based debugger
- [**137**星][9m] [Py] [nh2/strace-pipes-presentation](https://github.com/nh2/strace-pipes-presentation) 利用strace+管道/socket进行调试
- [**133**星][4y] [C] [jvoisin/pangu](https://github.com/jvoisin/pangu) Toolkit to detect/crash/attack GNU debugging-related tools
- [**125**星][4m] [Py] [igio90/uddbg](https://github.com/igio90/uddbg) A gdb like debugger that provide a runtime env to unicorn emulator and additionals features!
- [**124**星][2y] [Py] [alonemonkey/antiantidebug](https://github.com/alonemonkey/antiantidebug) tweak、 lldb python for anti anti debug
- [**120**星][13d] [C++] [intel/opencl-intercept-layer](https://github.com/intel/opencl-intercept-layer) Intercept Layer for Debugging and Analyzing OpenCL Applications
- [**117**星][4y] [Shell] [dholm/dotgdb](https://github.com/dholm/dotgdb) GDB scripts to add support for low level debugging and reverse engineering
- [**116**星][2y] [C++] [skylined/edgedbg](https://github.com/skylined/edgedbg) A simple command line exe to start and debug the Microsoft Edge browser.
- [**109**星][2m] [C] [david-reguera-garcia-dreg/dbgchild](https://github.com/david-reguera-garcia-dreg/dbgchild) Debug Child Process Tool (auto attach)
- [**108**星][29d] [Pascal] [fenix01/cheatengine-library](https://github.com/fenix01/cheatengine-library) Cheat Engine Library is based on CheatEngine a debugger and coding environment particularly aimed at games, but can also be used for other purposes like debugging applications and used in schools for teaching how computers work
- [**105**星][2y] [C] [formyown/alesense-antivirus](https://github.com/formyown/alesense-antivirus) 一款拥有完整交互界面与驱动级拦截能力的开源杀毒软件
- [**104**星][25d] [C] [checkpointsw/scout](https://github.com/checkpointsw/scout) Instruction based research debugger
- [**103**星][10d] [stonedreamforest/mirage](https://github.com/stonedreamforest/mirage) kernel-mode Anti-Anti-Debug plugin. based on intel vt-x && ept technology
- [**95**星][2y] [C] [cetfor/antidbg](https://github.com/cetfor/antidbg) A bunch of Windows anti-debugging tricks.
- [**93**星][4d] [JS] [microsoftedge/jsdbg](https://github.com/microsoftedge/jsdbg) Debugging extensions for Microsoft Edge and other Chromium-based browsers
- [**86**星][4y] [Py] [sogeti-esec-lab/lkd](https://github.com/sogeti-esec-lab/lkd) Local Kernel Debugger (LKD) is a python wrapper around dbgengine.dll
- [**86**星][2y] [Py] [wasiher/chrome_remote_interface_python](https://github.com/wasiher/chrome_remote_interface_python) Chrome Debugging Protocol interface for Python
- [**86**星][7y] [Py] [stevenseeley/heaper](https://github.com/stevenseeley/heaper) heaper, an advanced heap analysis plugin for Immunity Debugger
- [**85**星][13d] [Py] [rocky/python2-trepan](https://github.com/rocky/python2-trepan) A gdb-like Python 2.x Debugger in the Trepan family
- [**82**星][2m] [C] [taviso/cefdebug](https://github.com/taviso/cefdebug) Minimal code to connect to a CEF debugger.
- [**73**星][5m] [0xd4d/dnspy-unity-mono](https://github.com/0xd4d/dnspy-unity-mono) Fork of Unity mono that's used to compile mono.dll with debugging support enabled
- [**70**星][6m] [C++] [thomasthelen/antidebugging](https://github.com/thomasthelen/antidebugging) A collection of c++ programs that demonstrate common ways to detect the presence of an attached debugger.
- [**70**星][4y] [C++] [waleedassar/antidebug](https://github.com/waleedassar/antidebug) Collection Of Anti-Debugging Tricks
- [**65**星][4m] [C++] [nccgroup/xendbg](https://github.com/nccgroup/xendbg) A feature-complete reference implementation of a modern Xen VMI debugger.
- [**64**星][4y] [C#] [wintellect/procmondebugoutput](https://github.com/wintellect/procmondebugoutput) See your trace statements in Sysinternals Process Monitor
- [**59**星][4y] [JS] [auth0-blog/react-flux-debug-actions-sample](https://github.com/auth0-blog/react-flux-debug-actions-sample) This repository shows how you can use Flux actions to reproduce your user's issues in your own browser
- [**58**星][3m] [Py] [quarkslab/lldbagility](https://github.com/quarkslab/lldbagility) A tool for debugging macOS virtual machines
- [**57**星][6m] [JS] [pownjs/pown-cdb](https://github.com/pownjs/pown-cdb) Automate common Chrome Debug Protocol tasks to help debug web applications from the command-line and actively monitor and intercept HTTP requests and responses.
- [**54**星][3m] [C#] [southpolenator/sharpdebug](https://github.com/southpolenator/SharpDebug) C# debugging automation tool
- [**51**星][2m] [C#] [smourier/tracespy](https://github.com/smourier/tracespy) TraceSpy is a pure .NET, 100% free and open source, alternative to the very popular SysInternals DebugView tool.
- [**49**星][1y] [C++] [alphaseclab/anti-debug](https://github.com/alphaseclab/anti-debug) 
- [**48**星][4m] [blackint3/awesome-debugging](https://github.com/blackint3/awesome-debugging) Why Debugging?（为什么要调试？）
- [**48**星][9m] [C++] [stoyan-shopov/troll](https://github.com/stoyan-shopov/troll) troll：ARM Cortex-M 处理器 C 语言源码调试器
- [**44**星][1y] [C#] [micli/netcoredebugging](https://github.com/micli/netcoredebugging) A repository maintains the book of ".NET Core application debugging" sample code.
- [**44**星][2y] [Py] [zedshaw/zadm4py](https://github.com/zedshaw/zadm4py) Zed's Awesome Debug Macros for Python
- [**43**星][1y] [C++] [johnsonjason/rvdbg](https://github.com/johnsonjason/RVDbg) RVDbg is a debugger/exception handler for Windows processes and has the capability to circumvent anti-debugging techniques. (Cleaner, documented code base being worked on in: core branch)
- [**42**星][28d] [SystemVerilog] [azonenberg/starshipraider](https://github.com/azonenberg/starshipraider) High performance embedded systems debug/reverse engineering platform
- [**42**星][5y] [C] [cemeyer/msp430-emu-uctf](https://github.com/cemeyer/msp430-emu-uctf) msp430 emulator for uctf (with remote GDB debugging, reverse debugging, and optional symbolic execution)
- [**42**星][2m] [Erlang] [etnt/edbg](https://github.com/etnt/edbg) edbg：基于 tty 的 Erlang 调试/追踪接口
- [**41**星][4y] [Py] [crowdstrike/pyspresso](https://github.com/crowdstrike/pyspresso) The pyspresso package is a Python-based framework for debugging Java.
- [**41**星][2y] [C] [seemoo-lab/nexmon_debugger](https://github.com/seemoo-lab/nexmon_debugger) Debugger with hardware breakpoints and memory watchpoints for BCM4339 Wi-Fi chips
- [**39**星][7y] [C] [gdbinit/gimmedebugah](https://github.com/gdbinit/gimmedebugah) A small utility to inject a Info.plist into binaries.
- [**38**星][2y] [C] [shellbombs/strongod](https://github.com/shellbombs/strongod) StrongOD(anti anti-debug plugin) driver source code.
- [**37**星][3y] [C] [0xbadc0de1/vmp_dbg](https://github.com/0xbadc0de1/vmp_dbg) This is a VmProtect integrated debugger, that will essentially allow you to disasm and debug vmp partially virtualized functions at the vmp bytecode level. It was made using TitanEngine for the debug engine and Qt for the gui. Do not expect much of it and feel free to report any bugs.
- [**36**星][2y] [C] [adamgreen/mri](https://github.com/adamgreen/mri) MRI - Monitor for Remote Inspection. The gdb compatible debug monitor for Cortex-M devices.
- [**35**星][2y] [Py] [meyer9/ethdasm](https://github.com/meyer9/ethdasm) Tool for auditing Ethereum contracts
- [**35**星][2m] [C] [gdbinit/efi_dxe_emulator](https://github.com/gdbinit/efi_dxe_emulator) EFI DXE Emulator and Interactive Debugger
- [**34**星][2y] [Py] [g2p/vido](https://github.com/g2p/vido) wrap commands in throwaway virtual machines — easy kernel debugging and regression testing
- [**32**星][3m] [C++] [creaink/ucom](https://github.com/creaink/ucom) A simple Serial-Port/TCP/UDP debugging tool.
- [**32**星][4m] [C++] [imugee/xdv](https://github.com/imugee/xdv) XDV is disassembler or debugger that works based on the extension plugin.
- [**29**星][6m] [C++] [marakew/syser](https://github.com/marakew/syser) syser debugger x32/x64 ring3
- [**29**星][3m] [C++] [vertextoedge/windowfunctiontracer](https://github.com/vertextoedge/windowfunctiontracer) Window Executable file Function tracer using Debugging API
- [**28**星][2y] [PS] [enddo/hatdbg](https://github.com/enddo/hatdbg) Minimal WIN32 Debugger in powershell
- [**28**星][7y] [C] [jonathansalwan/vmndh-2k12](https://github.com/jonathansalwan/vmndh-2k12) Emulator, debugger and compiler for the NDH architecture - Emulator for CTF NDH 2k12
- [**27**星][8y] [Py] [fitblip/pydbg](https://github.com/fitblip/pydbg) A pure-python win32 debugger interface.
- [**27**星][2y] [C] [okazakinagisa/vtbaseddebuggerwin7](https://github.com/okazakinagisa/vtbaseddebuggerwin7) Simple kernelmode driver.
- [**26**星][6y] [Py] [fireeye/pycommands](https://github.com/fireeye/pycommands) PyCommand Scripts for Immunity Debugger
- [**25**星][3y] [C] [jacktang310/kerneldebugonnexus6p](https://github.com/jacktang310/kerneldebugonnexus6p) 
- [**24**星][1y] [Py] [cosine0/amphitrite](https://github.com/cosine0/amphitrite) Symbolic debugging tool using JonathanSalwan/Triton
- [**22**星][8m] [Py] [laanwj/dwarf_to_c](https://github.com/laanwj/dwarf_to_c) Tool to recover C headers (types, function signatures) from DWARF debug data
- [**22**星][1y] [C#] [malcomvetter/antidebug](https://github.com/malcomvetter/antidebug) PoC: Prevent a debugger from attaching to managed .NET processes via a watcher process code pattern.
- [**22**星][3y] [Assembly] [osandamalith/anti-debug](https://github.com/osandamalith/anti-debug) Some of the Anti-Debugging Tricks
- [**20**星][5y] [C] [tongzeyu/hooksysenter](https://github.com/tongzeyu/hooksysenter) hook sysenter，重载内核，下硬件断点到debugport，防止debugport清零


### <a id="136c41f2d05739a74c6ec7d8a84df1e8"></a>文章






***


## <a id="9f8d3f2c9e46fbe6c25c22285c8226df"></a>BAP


### <a id="f10e9553770db6f98e8619dcd74166ef"></a>工具


- [**1106**星][6d] [OCaml] [binaryanalysisplatform/bap](https://github.com/binaryanalysisplatform/bap) Binary Analysis Platform
- [**411**星][5d] [HTML] [w3c/webappsec](https://github.com/w3c/webappsec) Web App安全工作组
- [**299**星][9d] [JS] [w3c/webappsec-trusted-types](https://github.com/w3c/webappsec-trusted-types) A browser API to prevent DOM-Based Cross Site Scripting in modern web applications.
- [**289**星][3y] [Py] [dhilipsiva/webapp-checklist](https://github.com/dhilipsiva/webapp-checklist) Technical details that a programmer of a web application should consider before making the site public.
- [**126**星][7y] [pwnwiki/webappdefaultsdb](https://github.com/pwnwiki/webappdefaultsdb) A DB of known Web Application Admin URLS, Username/Password Combos and Exploits
- [**106**星][11d] [Py] [ajinabraham/webappsec](https://github.com/ajinabraham/webappsec) Web Application Security
- [**101**星][28d] [HTML] [w3c/webappsec-csp](https://github.com/w3c/webappsec-csp) WebAppSec Content Security Policy
- [**61**星][7y] [JS] [enablesecurity/webapp-exploit-payloads](https://github.com/EnableSecurity/Webapp-Exploit-Payloads) a collection of payloads for common webapps
- [**52**星][6y] [Py] [lijiejie/outlook_webapp_brute](https://github.com/lijiejie/outlook_webapp_brute) Microsoft Outlook WebAPP Brute
- [**45**星][9m] [Py] [binaryanalysisplatform/bap-tutorial](https://github.com/binaryanalysisplatform/bap-tutorial) The BAP tutorial
- [**35**星][5y] [OCaml] [argp/bap](https://github.com/argp/bap) Binary Analysis Platform -- I will try to keep this updated with patches, fixes, etc.
- [**28**星][5y] [Py] [infosec-au/webappsec-toolkit](https://github.com/infosec-au/webappsec-toolkit) Web Application Security related tools. Includes backdoors, proof of concepts and tricks
- [**26**星][2y] [JS] [bkimminich/webappsec-nutshell](https://github.com/bkimminich/webappsec-nutshell) An ultra-compact intro (or refresher) to Web Application Security.
- [**16**星][4y] [Py] [redcanaryco/cbapi2](https://github.com/redcanaryco/cbapi2) Red Canary Carbon Black API
- [**16**星][1y] [C#] [jpginc/xbapappwhitelistbypasspoc](https://github.com/jpginc/xbapappwhitelistbypasspoc) 
- [**15**星][2y] [Rust] [maurer/bap-rust](https://github.com/maurer/bap-rust) 
- [**11**星][1m] [OCaml] [binaryanalysisplatform/bap-bindings](https://github.com/binaryanalysisplatform/bap-bindings) C Bindings to BAP
- [**10**星][3y] [Java] [rafaelrpinto/vulnerablejavawebapplication](https://github.com/rafaelrpinto/vulnerablejavawebapplication) A Java Web Application with common legacy security flaws for tests with Arachni Scanner and ModSecurity
- [**9**星][2y] [HTML] [mister2tone/metasploit-webapp](https://github.com/mister2tone/metasploit-webapp) Metasploit framework via HTTP services
- [**7**星][3m] [Py] [binaryanalysisplatform/bap-python](https://github.com/binaryanalysisplatform/bap-python) BAP python bindings
- [**7**星][8y] [PHP] [ircmaxell/xssbadwebapp](https://github.com/ircmaxell/xssbadwebapp) A Intentionally Vulnerable Bad Web Application With XSS Vulnerabilities - *DO NOT USE!!!*
- [**6**星][2y] [HTML] [ambulong/dbapp_ctf_201801](https://github.com/ambulong/dbapp_ctf_201801) 安恒CTF一月赛部分POC
- [**1**星][12d] [C] [binaryanalysisplatform/bap-testsuite](https://github.com/binaryanalysisplatform/bap-testsuite) BAP test suite
- [**1**星][3y] [C] [maurer/libbap](https://github.com/maurer/libbap) C Bindings for BAP
- [**1**星][8m] [spy86/owaspwebapplicationsecuritytestingchecklist](https://github.com/spy86/owaspwebapplicationsecuritytestingchecklist) 
- [**0**星][3y] [C#] [jstillwell/webapppentest](https://github.com/jstillwell/webapppentest) App for testing web apps for vulnerabilities like Sql injection


### <a id="e111826dde8fa44c575ce979fd54755d"></a>文章






***


## <a id="2683839f170250822916534f1db22eeb"></a>BinNavi


### <a id="2e4980c95871eae4ec0e76c42cc5c32f"></a>工具


- [**382**星][18d] [C++] [google/binexport](https://github.com/google/binexport) 将反汇编以Protocol Buffer的形式导出为PostgreSQL数据库, 导入到BinNavi中使用
    - 重复区段: [IDA->插件->导入导出->BinNavi](#11139e7d6db4c1cef22718868f29fe12) |
- [**213**星][4y] [PLpgSQL] [cseagle/freedom](https://github.com/cseagle/freedom) 从IDA中导出反汇编信息, 导入到binnavi中使用
    - 重复区段: [IDA->插件->导入导出->BinNavi](#11139e7d6db4c1cef22718868f29fe12) |
- [**25**星][7y] [Py] [tosanjay/bopfunctionrecognition](https://github.com/tosanjay/bopfunctionrecognition) plugin to BinNavi tool to analyze a x86 binanry file to find buffer overflow prone functions. Such functions are important for vulnerability analysis.
    - 重复区段: [IDA->插件->导入导出->BinNavi](#11139e7d6db4c1cef22718868f29fe12) |


### <a id="ff4dc5c746cb398d41fb69a4f8dfd497"></a>文章






***


## <a id="0971f295b0f67dc31b7aa45caf3f588f"></a>Decompiler&&反编译器


### <a id="e67c18b4b682ceb6716388522f9a1417"></a>工具


- [**20779**星][t] [Java] [skylot/jadx](https://github.com/skylot/jadx) dex 转 java 的反编译器
- [**7733**星][1m] [Java] [java-decompiler/jd-gui](https://github.com/java-decompiler/jd-gui) A standalone Java Decompiler GUI
- [**3135**星][18d] [Java] [deathmarine/luyten](https://github.com/deathmarine/luyten) An Open Source Java Decompiler Gui for Procyon
- [**1867**星][1y] [Java] [jindrapetrik/jpexs-decompiler](https://github.com/jindrapetrik/jpexs-decompiler) JPEXS Free Flash Decompiler
- [**1652**星][12m] [Java] [fesh0r/fernflower](https://github.com/fesh0r/fernflower) Unofficial mirror of FernFlower Java decompiler (All pulls should be submitted upstream)
- [**1466**星][4d] [Py] [rocky/python-uncompyle6](https://github.com/rocky/python-uncompyle6) Python反编译器，跨平台
- [**1109**星][1y] [Py] [wibiti/uncompyle2](https://github.com/wibiti/uncompyle2) Python 2.7 decompiler
- [**1084**星][3m] [Py] [storyyeller/krakatau](https://github.com/storyyeller/krakatau) Java decompiler, assembler, and disassembler
- [**764**星][12m] [C++] [comaeio/porosity](https://github.com/comaeio/porosity) *UNMAINTAINED* Decompiler and Security Analysis tool for Blockchain-based Ethereum Smart-Contracts
- [**678**星][3y] [Batchfile] [ufologist/onekey-decompile-apk](https://github.com/ufologist/onekey-decompile-apk) 一步到位反编译apk工具(onekey decompile apk)
- [**673**星][10d] [C#] [uxmal/reko](https://github.com/uxmal/reko) Reko is a binary decompiler.
- [**671**星][11m] [C++] [zrax/pycdc](https://github.com/zrax/pycdc) C++ python bytecode disassembler and decompiler
- [**573**星][2y] [C++] [zneak/fcd](https://github.com/zneak/fcd) An optimizing decompiler
- [**538**星][5m] [Java] [java-decompiler/jd-eclipse](https://github.com/java-decompiler/jd-eclipse) A Java Decompiler Eclipse plugin
- [**533**星][4y] [Py] [mysterie/uncompyle2](https://github.com/mysterie/uncompyle2) A Python 2.5, 2.6, 2.7 byte-code decompiler
- [**483**星][3y] [Lua] [viruscamp/luadec](https://github.com/viruscamp/luadec) Lua Decompiler for lua 5.1 , 5.2 and 5.3
- [**389**星][3y] [Py] [gstarnberger/uncompyle](https://github.com/gstarnberger/uncompyle) Python decompiler
- [**383**星][3y] [C] [micrictor/stuxnet](https://github.com/micrictor/stuxnet) Open-source decompile of Stuxnet/myRTUs
- [**347**星][8d] [C#] [steamdatabase/valveresourceformat](https://github.com/steamdatabase/valveresourceformat) Valve's Source 2 resource file format (also known as Stupid Valve Format) parser and decompiler.
- [**331**星][3d] [Java] [leibnitz27/cfr](https://github.com/leibnitz27/cfr) This is the public repository for the CFR Java decompiler
- [**327**星][1m] [C++] [silverf0x/rpcview](https://github.com/silverf0x/rpcview) RpcView is a free tool to explore and decompile Microsoft RPC interfaces
- [**306**星][5y] [C++] [draperlaboratory/fracture](https://github.com/draperlaboratory/fracture) an architecture-independent decompiler to LLVM IR
- [**283**星][8m] [Shell] [venshine/decompile-apk](https://github.com/venshine/decompile-apk) APK 反编译
- [**243**星][3m] [Java] [kwart/jd-cmd](https://github.com/kwart/jd-cmd) Command line Java Decompiler
- [**242**星][3d] [C#] [icsharpcode/avaloniailspy](https://github.com/icsharpcode/avaloniailspy) Avalonia-based .NET Decompiler (port of ILSpy)
- [**240**星][2m] [Java] [ata4/bspsrc](https://github.com/ata4/bspsrc) A Source engine map decompiler
- [**234**星][5y] [C] [sztupy/luadec51](https://github.com/sztupy/luadec51) Lua Decompiler for Lua version 5.1
- [**232**星][1y] [C++] [wwwg/wasmdec](https://github.com/wwwg/wasmdec) WebAssembly to C decompiler
- [**226**星][3d] [C++] [boomerangdecompiler/boomerang](https://github.com/BoomerangDecompiler/boomerang) Boomerang Decompiler - Fighting the code-rot :)
- [**196**星][1y] [C++] [cararasu/holodec](https://github.com/cararasu/holodec) Decompiler for x86 and x86-64 ELF binaries
- [**164**星][3y] [C#] [jamesjlinden/unity-decompiled](https://github.com/jamesjlinden/unity-decompiled) 
- [**148**星][3y] [C#] [endgameinc/py2exedecompiler](https://github.com/endgameinc/py2exedecompiler) Decompiles Exe created by Py2Exe using uncompyle6 for both python 2 and 3.
- [**136**星][6y] [Py] [nightnord/ljd](https://github.com/nightnord/ljd) LuaJIT raw-bytecode decompiler
- [**129**星][6y] [Lua] [bobsayshilol/luajit-decomp](https://github.com/bobsayshilol/luajit-decomp) LuaJIT decompiler
- [**113**星][1y] [Java] [despector/despector](https://github.com/despector/despector) Java / Kotlin Decompiler and AST Library
- [**87**星][4m] [Clojure] [clojure-goes-fast/clj-java-decompiler](https://github.com/clojure-goes-fast/clj-java-decompiler) clj-java-decompiler: 将 Clojure 反编译为 Java
- [**87**星][3d] [Py] [pnfsoftware/jeb2-samplecode](https://github.com/pnfsoftware/jeb2-samplecode) Sample extensions for JEB Decompiler
- [**85**星][4y] [C] [electrojustin/triad-decompiler](https://github.com/electrojustin/triad-decompiler) TRiad Is A Decompiler. Triad is a tiny, free and open source, Capstone based x86 decompiler for ELF binaries.
- [**82**星][2y] [C++] [nemerle/dcc](https://github.com/nemerle/dcc) This is a heavily updated version of the old DOS executable decompiler DCC
- [**77**星][3m] [Py] [pfalcon/scratchablock](https://github.com/pfalcon/scratchablock) Yet another crippled decompiler project
- [**67**星][1y] [PHP] [irelance/jsc-decompile-mozjs-34](https://github.com/irelance/jsc-decompile-mozjs-34) A javascript bytecode decoder for mozilla spider-monkey version 34. May decompile jsc file compile by cocos-2dx
- [**57**星][8d] [Py] [matt-kempster/mips_to_c](https://github.com/matt-kempster/mips_to_c) A MIPS decompiler.
- [**57**星][5y] [C] [molnarg/dead0007](https://github.com/molnarg/dead0007) Decompiler for SpiderMonkey 1.8 XDR bytecode
- [**54**星][7m] [Clojure] [bronsa/tools.decompiler](https://github.com/bronsa/tools.decompiler) A decompiler for clojure, in clojure
- [**53**星][7y] [Visual Basic .NET] [vbgamer45/semi-vb-decompiler](https://github.com/vbgamer45/semi-vb-decompiler) Partial decompiler for Visual Basic. Code source of file struture infomation.
- [**49**星][4d] [Py] [rocky/python-decompile3](https://github.com/rocky/python-decompile3) Python decompiler for 3.7+. Stripped down from uncompyle6 so we can refactor and fix up some long-standing problems
- [**40**星][2y] [Py] [wibiti/evedec](https://github.com/wibiti/evedec) Eve Online decrypter/decompiler
- [**32**星][1y] [C++] [fortiguard-lion/rpcview](https://github.com/fortiguard-lion/rpcview) RpcView is a free tool to explore and decompile Microsoft RPC interfaces
- [**31**星][2y] [Visual Basic .NET] [dzzie/myaut_contrib](https://github.com/dzzie/myaut_contrib) mod to myaut2exe decompiler
- [**28**星][7d] [Py] [dottedmag/archmage](https://github.com/dottedmag/archmage) A reader and decompiler for files in the CHM format
- [**28**星][12m] [Java] [minecraftforge/fernflower](https://github.com/minecraftforge/fernflower) Unofficial mirror of FernFlower Java decompiler, Subtree split of:
- [**28**星][20d] [C++] [schdub/protodec](https://github.com/schdub/protodec) Protobuf decompiler
- [**27**星][1y] [C#] [jeffreye/avaloniailspy](https://github.com/jeffreye/avaloniailspy) Avalonia-based .NET Decompiler (port of ILSpy)
- [**25**星][1y] [Py] [nviso-be/decompile-py2exe](https://github.com/nviso-be/decompile-py2exe) Decompile py2exe Python 3 generated EXEs
- [**21**星][6m] [Py] [beched/abi-decompiler](https://github.com/beched/abi-decompiler) Ethereum (EVM) smart contracts reverse engineering helper utility
- [**21**星][1y] [C] [rfalke/decompiler-subjects](https://github.com/rfalke/decompiler-subjects) Tests cases for binary decompilers
- [**19**星][6m] [Java] [pnfsoftware/jeb-plugin-libra](https://github.com/pnfsoftware/jeb-plugin-libra) Libra decompiler plugin for JEB
- [**19**星][15d] [Shell] [gzu-liyujiang/apkdecompiler](https://github.com/gzu-liyujiang/apkdecompiler) 【Linux系统】上apk反编译助手，已打包为ApkDecompiler.deb，支持debian系linux，如debian、ubuntu、mint、deepin等等
- [**11**星][3y] [Emacs Lisp] [xiongtx/jdecomp](https://github.com/xiongtx/jdecomp) Emacs interface to Java decompilers
- [**10**星][6y] [Py] [gdelugre/fupy](https://github.com/gdelugre/fupy) A small and dirty Python 2 decompiler written in Python.
- [**10**星][2y] [C++] [uglyoldbob/decompiler](https://github.com/uglyoldbob/decompiler) A decompiler targeting c and similar languages.
- [**9**星][2y] [C++] [darknesswind/nutcracker](https://github.com/darknesswind/nutcracker) fork from DamianXVI's squirrel decompiler
- [**9**星][2y] [C++] [shauren/protobuf-decompiler](https://github.com/shauren/protobuf-decompiler) 
- [**8**星][7m] [Java] [soxs/osrsupdater](https://github.com/soxs/osrsupdater) A simple (and outdated) Old-School RuneScape decompiler/deobfuscator. Performs field and method analysis which uses ASM and bytecode patterns for identification. Identified fields could be used for creating bot clients or QoL clients. For educational use only.
- [**8**星][10m] [PHP] [vaibhavpandeyvpz/deapk](https://github.com/vaibhavpandeyvpz/deapk) DeAPK is an open-source, online APK decompiler which lets you upload an APK and then decompile it to Smali or Java sources. It is built using Laravel, Vue.js, Bootstrap, FontAwesome, Pusher, Redis, MySQL, apktool, jadx and hosted atop DigitalOcean cloud platform.
- [**5**星][1y] [C#] [fireboyd78/unluacnet](https://github.com/fireboyd78/unluacnet) A Lua 5.1 decompiler library written in C#. Based on the original Java version of "unluac" by tehtmi.
- [**5**星][2m] [Kotlin] [kotcrab/mist](https://github.com/kotcrab/mist) Interactive MIPS disassembler and decompiler
- [**5**星][3m] [TS] [x87/scout](https://github.com/x87/scout) Scout Decompiler
- [**1**星][2y] [Haskell] [wertercatt/mrifk](https://github.com/wertercatt/mrifk) A decompiler and disassembler for the Glulx virtual machine.
- [**1**星][6y] [Haskell] [rel-eng/jdec](https://github.com/rel-eng/jdec) java decompiler written in haskell
- [**1**星][2m] [Java] [maxpixelstudios/minecraftdecompiler](https://github.com/maxpixelstudios/minecraftdecompiler) A useful tool to decompile and deobfuscate Minecraft by CFR and Proguard/SRG/CSRG/TSRG mappings
- [**0**星][2y] [Java] [dgileadi/dg.jdt.ls.decompiler](https://github.com/dgileadi/dg.jdt.ls.decompiler) 
- [**None**星][xdasm/decompiler](https://bitbucket.org/xdasm/decompiler/issues?status=new&status=open) 


### <a id="a748b79105651a8fd8ae856a7dc2b1de"></a>文章






***


## <a id="2df6d3d07e56381e1101097d013746a0"></a>Disassemble&&反汇编


### <a id="59f472c7575951c57d298aef21e7d73c"></a>工具


- [**1374**星][12d] [C] [zyantific/zydis](https://github.com/zyantific/zydis) 快速的轻量级x86/x86-64 反汇编库
- [**1346**星][12m] [Rust] [das-labor/panopticon](https://github.com/das-labor/panopticon) A libre cross-platform disassembler.
- [**877**星][11m] [C++] [wisk/medusa](https://github.com/wisk/medusa) An open source interactive disassembler
- [**835**星][t] [GLSL] [khronosgroup/spirv-cross](https://github.com/khronosgroup/spirv-cross)  a practical tool and library for performing reflection on SPIR-V and disassembling SPIR-V back to high level languages.
- [**828**星][2m] [C++] [redasmorg/redasm](https://github.com/redasmorg/redasm) The OpenSource Disassembler
- [**693**星][5y] [C] [vmt/udis86](https://github.com/vmt/udis86) Disassembler Library for x86 and x86-64
- [**627**星][3m] [C] [gdabah/distorm](https://github.com/gdabah/distorm) Powerful Disassembler Library For x86/AMD64
- [**430**星][1m] [C#] [0xd4d/iced](https://github.com/0xd4d/iced) x86/x64 disassembler, instruction decoder & encoder
- [**351**星][13d] [Ruby] [jjyg/metasm](https://github.com/jjyg/metasm) This is the main repository for metasm, a free assembler / disassembler / compiler written in ruby
- [**268**星][3y] [HTML] [xem/minix86](https://github.com/xem/minix86) x86 (MS-DOS) documentation, disassembler and emulator - WIP
- [**246**星][5m] [Py] [bontchev/pcodedmp](https://github.com/bontchev/pcodedmp) A VBA p-code disassembler
- [**198**星][5m] [Py] [athre0z/wasm](https://github.com/athre0z/wasm) WebAssembly decoder & disassembler library
- [**139**星][9d] [C++] [grammatech/ddisasm](https://github.com/grammatech/ddisasm) A fast and accurate disassembler
- [**136**星][2y] [Java] [tinylcy/classanalyzer](https://github.com/tinylcy/classanalyzer) A Java Class File Disassembler
- [**89**星][5m] [Java] [llvm-but-worse/java-disassembler](https://github.com/LLVM-but-worse/java-disassembler) The Java Disassembler
- [**88**星][8m] [Py] [blacknbunny/peanalyzer](https://github.com/blacknbunny/peanalyzer) Advanced Portable Executable File Analyzer And Disassembler 32 & 64 Bit
- [**86**星][2y] [C++] [rmitton/goaldis](https://github.com/rmitton/goaldis) Jak & Daxter GOAL disassembler
- [**81**星][3y] [Py] [januzellij/hopperscripts](https://github.com/januzellij/hopperscripts) Collection of scripts I use in the Hopper disassembler
- [**80**星][2y] [Py] [rsc-dev/pbd](https://github.com/rsc-dev/pbd) Pbd is a Python module to disassemble serialized protocol buffers descriptors (
- [**69**星][6m] [Py] [tintinweb/ethereum-dasm](https://github.com/tintinweb/ethereum-dasm) An ethereum evm bytecode disassembler and static/dynamic analysis tool
- [**65**星][11m] [Pascal] [mahdisafsafi/univdisasm](https://github.com/mahdisafsafi/univdisasm) x86 Disassembler and Analyzer
- [**62**星][5m] [Py] [crytic/pyevmasm](https://github.com/crytic/pyevmasm) Ethereum Virtual Machine (EVM) disassembler and assembler
- [**57**星][6d] [Py] [rocky/python-xdis](https://github.com/rocky/python-xdis) Python cross-version bytecode library and disassembler
- [**52**星][22d] [C++] [hasherezade/vidi](https://github.com/hasherezade/vidi) ViDi Visual Disassembler (experimental)
- [**32**星][5m] [C++] [vector35/generate_assembler](https://github.com/vector35/generate_assembler) generate assemblers from disassemblers, 2018 jailbreak security summit talk
- [**30**星][3y] [Py] [rmtew/peasauce](https://github.com/rmtew/peasauce) Peasauce Interactive Disassembler
- [**25**星][3m] [HTML] [shahril96/online-assembler-disassembler](https://github.com/shahril96/online-assembler-disassembler) Online assembler and disassembler
- [**24**星][3y] [Py] [0xbc/chiasm-shell](https://github.com/0xbc/chiasm-shell) Python-based interactive assembler/disassembler CLI, powered by Keystone/Capstone.
- [**23**星][2y] [C++] [verideth/repen](https://github.com/verideth/repen) Simple C8 disassembler
- [**22**星][5y] [C#] [tophertimzen/shellcodetester](https://github.com/tophertimzen/shellcodetester) GUI Application in C# to run and disassemble shellcode


### <a id="a6eb5a22deb33fc1919eaa073aa29ab5"></a>文章






***


## <a id="975d9f08e2771fccc112d9670eae1ed1"></a>GDB


### <a id="5f4381b0a90d88dd2296c2936f7e7f70"></a>工具


- [**7019**星][2d] [JS] [cs01/gdbgui](https://github.com/cs01/gdbgui) Browser-based frontend to gdb (gnu debugger). Add breakpoints, view the stack, visualize data structures, and more in C, C++, Go, Rust, and Fortran. Run gdbgui from the terminal and a new tab will open in your browser.
- [**6052**星][5d] [Py] [cyrus-and/gdb-dashboard](https://github.com/cyrus-and/gdb-dashboard) Modular visual interface for GDB in Python
- [**3784**星][11m] [Py] [longld/peda](https://github.com/longld/peda) Python Exploit Development Assistance for GDB
- [**2568**星][30d] [Py] [hugsy/gef](https://github.com/hugsy/gef) gdb增强工具，使用Python API，用于漏洞开发和逆向分析。
- [**2439**星][8d] [Py] [pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) GDB插件，辅助漏洞开发和逆向
- [**1417**星][3m] [Go] [hellogcc/100-gdb-tips](https://github.com/hellogcc/100-gdb-tips) A collection of gdb tips. 100 maybe just mean many here.
- [**452**星][2m] [Py] [scwuaptx/pwngdb](https://github.com/scwuaptx/pwngdb) gdb for pwn
- [**446**星][1y] [Py] [jfoote/exploitable](https://github.com/jfoote/exploitable) The 'exploitable' GDB plugin. I don't work at CERT anymore, but here is the original homepage:
- [**244**星][1m] [JS] [bet4it/hyperpwn](https://github.com/bet4it/hyperpwn) A hyper plugin to provide a flexible GDB GUI with the help of GEF, pwndbg or peda
- [**208**星][2m] [Py] [sakhnik/nvim-gdb](https://github.com/sakhnik/nvim-gdb) Neovim thin wrapper for GDB, LLDB and PDB
- [**196**星][2y] [Py] [sqlab/symgdb](https://github.com/sqlab/symgdb) symbolic execution plugin for gdb
- [**186**星][4y] [Py] [leeyiw/cgdb-manual-in-chinese](https://github.com/leeyiw/cgdb-manual-in-chinese) 《CGDB中文手册》
- [**174**星][13d] [Shell] [rocky/zshdb](https://github.com/rocky/zshdb) gdb-like "trepan" debugger for zsh
- [**152**星][23d] [Py] [rogerhu/gdb-heap](https://github.com/rogerhu/gdb-heap) Heap Analyzer for Python
- [**150**星][27d] [Py] [gdbinit/lldbinit](https://github.com/gdbinit/lldbinit) A gdbinit clone for LLDB
- [**137**星][2y] [kevinsbobo/cheat-sheet](https://github.com/kevinsbobo/cheat-sheet) 速查表包括了 Vim, Git, Shell, Gcc, Gdb 常用命令及快捷键
- [**132**星][4y] [C] [espressif/esp-gdbstub](https://github.com/espressif/esp-gdbstub) 
- [**126**星][2m] [Py] [deroko/lldbinit](https://github.com/deroko/lldbinit) Similar implementation of .gdbinit from fG
- [**101**星][3m] [Py] [cs01/pygdbmi](https://github.com/cs01/pygdbmi) A library to parse gdb mi output, as well as control gdb subprocesses
- [**93**星][2m] [C] [weirdnox/emacs-gdb](https://github.com/weirdnox/emacs-gdb) GDB graphical interface for GNU Emacs
- [**93**星][4y] [Py] [zachriggle/peda](https://github.com/zachriggle/peda) PEDA - Python Exploit Development Assistance for GDB
- [**91**星][5m] [Py] [vuvova/gdb-tools](https://github.com/vuvova/gdb-tools) Various tools to improve the gdb experience
- [**87**星][2m] [Py] [alset0326/peda-arm](https://github.com/alset0326/peda-arm) GDB plugin peda for arm
- [**85**星][2y] [C] [javierhonduco/write-a-strace-and-gdb](https://github.com/javierhonduco/write-a-strace-and-gdb) A tiny system call tracer and debugger implementation
- [**79**星][3m] [Py] [miyagaw61/exgdb](https://github.com/miyagaw61/exgdb) Extension for GDB
- [**73**星][3m] [hugsy/gdb-static](https://github.com/hugsy/gdb-static) Public repository of static GDB and GDBServer
- [**73**星][13d] [Py] [rocky/python3-trepan](https://github.com/rocky/python3-trepan) A gdb-like Python3 Debugger in the Trepan family
- [**69**星][5d] [Py] [koutheir/libcxx-pretty-printers](https://github.com/koutheir/libcxx-pretty-printers) GDB Pretty Printers for libc++ of Clang/LLVM
- [**62**星][4m] [OCaml] [copy/gdbprofiler](https://github.com/copy/gdbprofiler) Rich man's profiler, a profiler for native OCaml and other executables
- [**61**星][1y] [Py] [hq6/gdbshellpipe](https://github.com/hq6/gdbshellpipe) Enable piping of internal command output to external commands
- [**56**星][5m] [Py] [stef/pyrsp](https://github.com/stef/pyrsp) python implementation of the GDB Remote Serial Protocol
- [**54**星][9m] [Shell] [mzpqnxow/embedded-toolkit](https://github.com/mzpqnxow/embedded-toolkit) Prebuilt statically linked gdbserver and gawk executables for Linux on ARMEL, MIPS/MIPSEL and more platforms for use on embedded devices, including for systems with many different ABIs (including more than 20 statically linked gdbserver executables)
- [**52**星][8y] [Py] [crossbowerbt/gdb-python-utils](https://github.com/crossbowerbt/gdb-python-utils) A library for GDB (with python support), that adds useful functions to the standard 'gdb' library.
- [**52**星][2y] [Go] [cyrus-and/gdb](https://github.com/cyrus-and/gdb) Go GDB/MI interface
- [**47**星][6y] [C] [gdbinit/gdb-ng](https://github.com/gdbinit/gdb-ng) Apple's gdb fork with some fixes and enhancements
- [**46**星][11m] [Shell] [mzpqnxow/gdb-static-cross](https://github.com/mzpqnxow/gdb-static-cross) Shell scripts, sourceable "activate" scripts and instructions for building a statically linked gdb-7.12 gdbserver using cross-compile toolchains. Includes more than 20 statically linked gdbserver executables for different architectures, byte orders and ABIs
- [**46**星][29d] [TeX] [zxgio/gdb_gef-cheatsheet](https://github.com/zxgio/gdb_gef-cheatsheet) GDB + GEF cheatsheet for reversing binaries
- [**44**星][1m] [Py] [scwuaptx/peda](https://github.com/scwuaptx/peda) PEDA - Python Exploit Development Assistance for GDB
- [**41**星][4m] [Rust] [cbourjau/cargo-with](https://github.com/cbourjau/cargo-with) A third-party cargo extension to run the build artifacts through tools like `gdb`
- [**39**星][2m] [Py] [sharkdp/stack-inspector](https://github.com/sharkdp/stack-inspector) A gdb command to inspect the size of objects on the stack
- [**38**星][9m] [Py] [wapiflapi/gxf](https://github.com/wapiflapi/gxf) Gdb Extension Framework is a bunch of python code around the gdb api.
- [**37**星][5y] [Py] [philwantsfish/gdb_commands](https://github.com/philwantsfish/gdb_commands) GDB commands to aid exploit development
- [**36**星][] [Ruby] [david942j/gdb-ruby](https://github.com/david942j/gdb-ruby) It's time for Ruby lovers to use Ruby in gdb, and gdb in Ruby!
- [**36**星][2y] [Py] [tromey/gdb-gui](https://github.com/tromey/gdb-gui) A gdb gui written in Python, running inside gdb itself.
- [**33**星][2m] [Py] [akiym/pedal](https://github.com/akiym/pedal) PEDAL - Python Exploit Development Assistance for GDB Lite
- [**33**星][1y] [Py] [damziobro/gdb-automatic-deadlock-detector](https://github.com/DamZiobro/gdb-automatic-deadlock-detector) Script adds new command to GDB which allows automatically detect C/C++ thread locking and deadlocks in GDB debugger
- [**25**星][5d] [C] [mborgerson/gdbstub](https://github.com/mborgerson/gdbstub) A simple, dependency-free GDB stub that can be easily dropped in to your project.
- [**24**星][27d] [Py] [daskol/gdb-colour-filter](https://github.com/daskol/gdb-colour-filter) Colourify backtrace output in GDB with Python API
- [**23**星][28d] [Perl] [occivink/kakoune-gdb](https://github.com/occivink/kakoune-gdb) gdb integration plugin
- [**23**星][2y] [C] [tommythorn/yari](https://github.com/tommythorn/yari) YARI is a high performance open source FPGA soft-core RISC implementation, binary compatible with MIPS I. The distribution package includes a complete SoC, simulator, GDB stub, scripts, and various examples.
- [**23**星][3y] [Py] [zachriggle/pwndbg](https://github.com/zachriggle/pwndbg) GDB插件，辅助漏洞开发和逆向
- [**22**星][3y] [Py] [tromey/gdb-helpers](https://github.com/tromey/gdb-helpers) GDB helper scripts
- [**21**星][14d] [C] [yugr/libdebugme](https://github.com/yugr/libdebugme) Automatically spawn gdb on error.
- [**20**星][6m] [Batchfile] [cldrn/insecureprogrammingdb](https://github.com/cldrn/insecureprogrammingdb) Insecure programming functions database
- [**20**星][2y] [Py] [kelwin/peda](https://github.com/kelwin/peda) PEDA - Python Exploit Development Assistance for GDB
- [**19**星][t] [C#] [sysprogs/bsptools](https://github.com/sysprogs/bsptools) Tools for generating VisualGDB BSPs
- [**18**星][4y] [C] [niklasb/dump-seccomp](https://github.com/niklasb/dump-seccomp) GDB plugin to dump SECCOMP rules set via prctnl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)
- [**15**星][3y] [C] [andyneff/hello-world-gdb](https://github.com/andyneff/hello-world-gdb) Simple hello world program for debugging with gdb
- [**15**星][6y] [gdbinit/kgmacros](https://github.com/gdbinit/kgmacros) Fixed kgmacros to work with VMware kernel gdb stub
- [**15**星][2y] [C] [rkx1209/bitvisor-gdb](https://github.com/rkx1209/bitvisor-gdb) gdbserver implementation on BitVisor
- [**15**星][1m] [C++] [satharus/disass](https://github.com/satharus/disass) [WIP] FOSS GNU Debugger (GDB) interface for GNU/Linux.
- [**14**星][3y] [Py] [0xmitsurugi/gdbscripts](https://github.com/0xmitsurugi/gdbscripts) Python scripts for gdb, reverse engineering oriented
- [**14**星][3y] [JS] [ben-ha/gdbface](https://github.com/ben-ha/gdbface) GDB web frontend written in Javascript
- [**14**星][11m] [TeX] [zxgio/gdb-cheatsheet](https://github.com/zxgio/gdb-cheatsheet) GDB cheatsheet for reversing binaries
- [**13**星][2y] [Py] [pageflt/gdb-memstr](https://github.com/pageflt/gdb-memstr) Generate arbitrary strings out of contents of ELF sections
- [**10**星][3y] [JS] [gogoprog/atom-gdb](https://github.com/gogoprog/atom-gdb) Atom plugin to set gdb breakpoints in .gdbinit file and run an external debugger as QtCreator or ddd
- [**10**星][2y] [Py] [kikimo/pygdb](https://github.com/kikimo/pygdb) pygdb：Linux 调试器，支持 dwarf-2 调试信息，能调试 x86/x64 程序
- [**10**星][18d] [C] [resetnow/esp-gdbstub](https://github.com/resetnow/esp-gdbstub) ESP8266 debugging tool
- [**10**星][2y] [Py] [stephenr/gdb_scripts](https://github.com/stephenr/gdb_scripts) 
- [**8**星][5y] [Py] [ctu-iig/802.11p-wireless-regdb](https://github.com/ctu-iig/802.11p-wireless-regdb) Wireless regulatory database for CRDA
- [**4**星][11m] [C] [adapteva/epiphany-binutils-gdb](https://github.com/adapteva/epiphany-binutils-gdb) Merged gdb and binutils repository
- [**3**星][1y] [Py] [grant-h/gdbscripts](https://github.com/grant-h/gdbscripts) An assorted collection of GDB scripts.
- [**2**星][4m] [Py] [artem-nefedov/uefi-gdb](https://github.com/artem-nefedov/uefi-gdb) UEFI OVMF symbol load script for GDB
- [**2**星][9m] [C#] [sysprogs/visualgdbextensibilityexamples](https://github.com/sysprogs/visualgdbextensibilityexamples) 
- [**2**星][2y] [Py] [tentpegbob/ropgadget](https://github.com/tentpegbob/ropgadget) Extends ROPgadget so that it can be used inside of GDB via Python.
- [**1**星][3y] [elauqsap/vtgdb](https://github.com/elauqsap/vtgdb) vulnerability and threat repository using a graph architecture
- [**1**星][2y] [Py] [monkeyman79/janitor](https://github.com/monkeyman79/janitor) Collection of GDB commands for low-level debugging, aimed at bringing debug.exe flavor into GDB command line interface.
- [**0**星][4y] [Py] [0xd3d0/pygdb](https://github.com/0xd3d0/pygdb) Automatically exported from code.google.com/p/pygdb
- [**0**星][1y] [JS] [pgigis/routingdb](https://github.com/pgigis/routingdb) 
- [**None**星][sha0coder/gdb_automatization](https://bitbucket.org/sha0coder/gdb_automatization) 


### <a id="37b17362d72f9c8793973bc4704893a2"></a>文章






***


## <a id="9526d018b9815156cb001ceee36f6b1d"></a>Captcha&&验证码


### <a id="1c6fda19fd076dcbda3ad733d7349e44"></a>工具


- [**2603**星][2y] [Py] [ecthros/uncaptcha](https://github.com/ecthros/uncaptcha) uncaptcha：绕过谷歌 “I'mnot a robot”reCaptcha 验证，准确率达85%
- [**1620**星][2m] [Ruby] [ambethia/recaptcha](https://github.com/ambethia/recaptcha) ReCaptcha helpers for ruby apps
- [**1561**星][18d] [PHP] [mewebstudio/captcha](https://github.com/mewebstudio/captcha) Captcha for Laravel 5 & 6
- [**1184**星][4m] [PHP] [gregwar/captcha](https://github.com/gregwar/captcha) PHP Captcha library
- [**1015**星][1m] [Py] [mbi/django-simple-captcha](https://github.com/mbi/django-simple-captcha) Django Simple Captcha is an extremely simple, yet highly customizable Django application to add captcha images to any Django form.
- [**897**星][t] [Py] [kerlomz/captcha_trainer](https://github.com/kerlomz/captcha_trainer) 基于深度学习的图片验证码的解决方案
- [**834**星][8y] [JS] [wjcrowcroft/motioncaptcha](https://github.com/wjcrowcroft/motioncaptcha) MotionCAPTCHA jQuery Plugin - Stop Spam, Draw Shapes
- [**757**星][3y] [Py] [eastee/rebreakcaptcha](https://github.com/eastee/rebreakcaptcha) A logic vulnerability, dubbed ReBreakCaptcha, which lets you easily bypass Google's ReCaptcha v2 anywhere on the web
- [**642**星][10d] [Ruby] [markets/invisible_captcha](https://github.com/markets/invisible_captcha) Simple and flexible spam protection solution for Rails applications.

- [**598**星][1y] [C++] [nladuo/captcha-break](https://github.com/nladuo/captcha-break) captcha break based on opencv2, tesseract-ocr and some machine learning algorithm.
- [**533**星][1y] [Py] [jackonyang/captcha-tensorflow](https://github.com/jackonyang/captcha-tensorflow) Image Captcha Solving Using TensorFlow and CNN Model. Accuracy 90%+
- [**423**星][5m] [Java] [bit4woo/recaptcha](https://github.com/bit4woo/recaptcha) reCAPTCHA = REcognize CAPTCHA: A Burp Suite Extender that recognize CAPTCHA and use for intruder payload 自动识别图形验证码并用于burp intruder爆破模块的插件
- [**324**星][9m] [JS] [zyszys/awesome-captcha](https://github.com/zyszys/awesome-captcha) 
- [**283**星][3y] [Go] [geohot/lolrecaptcha](https://github.com/geohot/lolrecaptcha) We try to break the recaptcha for the Merry Christmas for all!
- [**260**星][t] [Py] [kerlomz/captcha_platform](https://github.com/kerlomz/captcha_platform) [验证码识别-部署] This project is based on CNN+BLSTM+CTC to realize verificationtion. This projeccode identificat is only for deployment models.
- [**198**星][3y] [Lua] [arunpatala/captcha.irctc](https://github.com/arunpatala/captcha.irctc) Reading irctc captchas with 98% accuracy using deep learning
- [**168**星][4y] [Jupyter Notebook] [arunpatala/captcha](https://github.com/arunpatala/captcha) Breaking captchas using torch
- [**155**星][11m] [Py] [epsylon/cintruder](https://github.com/epsylon/cintruder) Captcha Intruder (CIntruder) is an automatic pentesting tool to bypass captchas.
- [**146**星][5y] [C++] [stevenhickson/findtheghost](https://github.com/stevenhickson/findtheghost) Quick example of how to break Snapchat's Captcha
- [**144**星][2y] [JS] [theriley106/outcaptcha](https://github.com/theriley106/outcaptcha) Chrome Extension that Solves reCAPTCHA 2.0 Without Human Interaction
- [**120**星][4y] [Ruby] [phatworx/easy_captcha](https://github.com/phatworx/easy_captcha) Captcha-Plugin for Rails
- [**106**星][3y] [Py] [hanc00l/captcha-python-test](https://github.com/hanc00l/captcha-python-test) 学习验证码识别的相关技术，包括opencv、tesseract、机器学习算法（kNN和SVM）等，将原作者的算法改为python
- [**96**星][12m] [Py] [presto412/captcha-cracker](https://github.com/Presto412/Captcha-Cracker) Cracks the Captcha at VIT University's Academics Portal
- [**93**星][5y] [Py] [debasishm89/hack_audio_captcha](https://github.com/debasishm89/hack_audio_captcha) Collection of Scripts written to Solve/Crack Audio reCapcha Challenges
- [**91**星][9m] [JS] [vksrc/captcha_orz](https://github.com/vksrc/captcha_orz) 验证码识别
- [**82**星][4y] [Py] [jinhang/12306_captcha](https://github.com/jinhang/12306_captcha) CNN对12306、sina、baidu的验证码破解。
- [**71**星][4y] [Py] [tum-vision/captcha_recognition](https://github.com/tum-vision/captcha_recognition) 
- [**66**星][2y] [PHP] [josecl/cool-php-captcha](https://github.com/josecl/cool-php-captcha) This is the official GitHub project from code.google.com/p/cool-php-captcha
- [**36**星][24d] [C#] [ryuzakih/cloudflaresolverre](https://github.com/ryuzakih/cloudflaresolverre) Cloudflare Javascript & reCaptcha challenge (I'm Under Attack Mode or IUAM) solving / bypass .NET Standard library.
- [**35**星][1y] [Py] [henryhaohao/slider_captcha_crack](https://github.com/henryhaohao/slider_captcha_crack) 
- [**35**星][6y] [Py] [robindavid/captcha-basic-recognition](https://github.com/robindavid/captcha-basic-recognition) Python module that intent to crack basic captcha engines using OpenCV and Pytesser
- [**30**星][8m] [C++] [kerlomz/captcha_library_c](https://github.com/kerlomz/captcha_library_c) 本项目可以用来调用
- [**27**星][4y] [Py] [hephaest0s/creatorrc](https://github.com/hephaest0s/creatorrc) Create torrc files optimized for speed, security, or avoiding captchas
- [**25**星][3y] [gtank/captcha-draft](https://github.com/gtank/captcha-draft) proposal for blinded-token captchas
- [**23**星][11m] [C#] [kerlomz/captcha_demo_csharp](https://github.com/kerlomz/captcha_demo_csharp) 本项目可以用来调用
- [**23**星][8y] [PHP] [phpgangsta/animatedcaptcha](https://github.com/phpgangsta/animatedcaptcha) This PHP class makes it easy to create animated GIFs, especially CAPTCHAs
- [**22**星][2y] [Py] [evyatarmeged/rarbg-scraper](https://github.com/evyatarmeged/rarbg-scraper) With Selenium headless browsing and CAPTCHA solving
- [**21**星][11m] [Py] [fsecurelabs/captcha_cracking](https://github.com/FSecureLABS/captcha_cracking) Helper scripts and tutorial for cracking text-based CAPTCHAs
- [**18**星][3y] [JS] [cowlicks/bypasser](https://github.com/cowlicks/bypasser) A Chrome Extension that implements Cloudflare's captcha bypass specification for Tor.
- [**17**星][3y] [Py] [kyprizel/testcookie-recaptcha-processor](https://github.com/kyprizel/testcookie-recaptcha-processor) testcookie with recaptcha usage PoC
- [**15**星][7y] [Py] [opensecurityresearch/clipcaptcha](https://github.com/opensecurityresearch/clipcaptcha) A Tool for Impersonating CAPTCHA Providers
- [**15**星][3y] [PHP] [securelayer7/captch-bypass-vulnerable-script](https://github.com/securelayer7/captch-bypass-vulnerable-script) This script is developed for understanding the Captcha Bypass Vulnerabilties.
- [**10**星][2y] [Java] [salesforce/pixel-captcha-project](https://github.com/salesforce/pixel-captcha-project) It's a unicode based visual CAPTCHA scheme that can be solved with 2-4 mouse clicks.
- [**9**星][2y] [Py] [penoxcn/decaptcha](https://github.com/penoxcn/decaptcha) 
- [**7**星][5y] [Py] [shonenada/flask-captcha](https://github.com/shonenada/flask-captcha) Simple captcha for Flask
- [**6**星][1y] [HTML] [terjanq/google-reported-issue](https://github.com/terjanq/google-reported-issue) The raport about discovered bug in Google reCAPTCHA
- [**5**星][4y] [Py] [wgrathwohl/captcha_crusher](https://github.com/wgrathwohl/captcha_crusher) Neural networks for solving image captchas
- [**4**星][2y] [Py] [redhat-infosec/python-recaptcha](https://github.com/redhat-infosec/python-recaptcha) Python module for working with Google's reCAPTCHA v1 and v2
- [**4**星][11m] [Py] [tinusgreen/captcha_cracking](https://github.com/tinusgreen/captcha_cracking) Helper scripts and tutorial for cracking text-based CAPTCHAs
- [**3**星][2y] [Java] [pan-lu/recaptcha](https://github.com/pan-lu/recaptcha) A Burp Extender that auto recognize CAPTCHA and use for Intruder payload
- [**3**星][2y] [JS] [willthornton/bypassjqueryrealpersoncaptcha](https://github.com/willthornton/bypassjqueryrealpersoncaptcha) A Chrome Plugin to Bypass jQuery Real Person Captcha
- [**2**星][1y] [JS] [pownjs/pown-captcha](https://github.com/pownjs/pown-captcha) 
- [**1**星][5m] [PHP] [fl2top/laravel-google-recaptcha](https://github.com/fl2top/laravel-google-recaptcha) Simple integration Google reCAPTCHA v2 with Laravel.
- [**0**星][3y] [Java] [atticuss/captcha-research](https://github.com/atticuss/captcha-research) collection of a few of the scripts written while playing with CATPCHAs
- [**0**星][6y] [PHP] [nikolait/cunningcaptcha](https://github.com/nikolait/cunningcaptcha) A simple, but complete (down to vector graphics) captcha implementation class. Wordpress plugin. In the beginning of development. September 2013.


### <a id="685f244ad7368e43dbde0a0966095066"></a>文章






# <a id="86cb7d8f548ca76534b5828cb5b0abce"></a>Radare2


***


## <a id="0e08f9478ed8388319f267e75e2ef1eb"></a>插件&&脚本


### <a id="ec3f0b5c2cf36004c4dd3d162b94b91a"></a>Radare2


- [**11588**星][4d] [C] [radareorg/radare2](https://github.com/radareorg/radare2) unix-like reverse engineering framework and commandline tools


### <a id="6922457cb0d4b6b87a34caf39aa31dfe"></a>新添加的


- [**410**星][5m] [Py] [itayc0hen/a-journey-into-radare2](https://github.com/itayc0hen/a-journey-into-radare2) A series of tutorials about radare2 framework from
- [**339**星][20d] [TeX] [radareorg/radare2book](https://github.com/radareorg/radare2book) Radare2 official book
- [**259**星][1m] [C] [radareorg/r2dec-js](https://github.com/radareorg/r2dec-js) radare2插件,将汇编代码反编译为C伪代码
- [**258**星][3m] [Rust] [radareorg/radeco](https://github.com/radareorg/radeco) radare2-based decompiler and symbol executor
- [**202**星][2m] [PS] [wiredpulse/posh-r2](https://github.com/wiredpulse/posh-r2) PowerShell - Rapid Response... For the incident responder in you!
- [**183**星][3m] [radareorg/r2con](https://github.com/radareorg/r2con) Radare Congress Stuff
- [**175**星][2m] [C] [radareorg/radare2-extras](https://github.com/radareorg/radare2-extras) Source graveyard and random candy for radare2
- [**155**星][2y] [C] [ifding/radare2-tutorial](https://github.com/ifding/radare2-tutorial) Reverse Engineering using Radare2
- [**149**星][2y] [Py] [mhelwig/apk-anal](https://github.com/mhelwig/apk-anal) Android APK analyzer based on radare2 and others.
    - 重复区段: [Android->工具->新添加的](#883a4e0dd67c6482d28a7a14228cd942) |
- [**126**星][19d] [JS] [radareorg/radare2-r2pipe](https://github.com/radareorg/radare2-r2pipe) Access radare2 via pipe from any programming language!
- [**123**星][12m] [C] [wenzel/r2vmi](https://github.com/wenzel/r2vmi) Hypervisor-Level Debugger based on Radare2 / LibVMI, using VMI IO and debug plugins
- [**108**星][2y] [Py] [guedou/jupyter-radare2](https://github.com/guedou/jupyter-radare2) Just a simple radare2 Jupyter kernel
- [**98**星][2m] [C] [radareorg/radare2-bindings](https://github.com/radareorg/radare2-bindings) Bindings of the r2 api for Valabind and friends
- [**97**星][3y] [C] [s4n7h0/practical-reverse-engineering-using-radare2](https://github.com/s4n7h0/practical-reverse-engineering-using-radare2) Training Materials of Practical Reverse Engineering using Radare2
- [**88**星][1y] [TeX] [zxgio/r2-cheatsheet](https://github.com/zxgio/r2-cheatsheet) Radare2 cheat-sheet
- [**82**星][7m] [C] [nowsecure/dirtycow](https://github.com/nowsecure/dirtycow) radare2 IO plugin for Linux and Android. Modifies files owned by other users via dirtycow Copy-On-Write cache vulnerability
- [**79**星][1m] [Shell] [radareorg/radare2-pm](https://github.com/radareorg/radare2-pm) Package Manager for Radare2
- [**78**星][3y] [Py] [pinkflawd/r2graphity](https://github.com/pinkflawd/r2graphity) Creating function call graphs based on radare2 framwork, plot fancy graphs and extract behavior indicators
- [**68**星][14d] [C] [radareorg/radare2-regressions](https://github.com/radareorg/radare2-regressions) Regression Tests for the Radare2 Reverse Engineer's Debugger
- [**67**星][3y] [Java] [octopus-platform/bjoern](https://github.com/octopus-platform/bjoern) Binary analysis platform based on Octopus and Radare2
- [**63**星][9m] [C] [zigzagsecurity/survival-guide-radare2](https://github.com/zigzagsecurity/survival-guide-radare2) Basic tutorials for reverse engineer with radare2
- [**62**星][2y] [C] [tobaljackson/2017-sit-re-presentation](https://github.com/tobaljackson/2017-sit-re-presentation) Intro to radare2 presentation files.
- [**56**星][2y] [JS] [jpenalbae/r2-scripts](https://github.com/jpenalbae/r2-scripts) Multiple radare2 rpipe scripts
- [**49**星][2y] [JS] [jpenalbae/rarop](https://github.com/jpenalbae/rarop) Graphical ROP chain builder using radare2 and r2pipe
- [**41**星][3y] [C] [bluec0re/reversing-radare2](https://github.com/bluec0re/reversing-radare2) A reversing series with radare2
- [**34**星][3y] [CSS] [monosource/radare2-explorations](https://github.com/monosource/radare2-explorations) A book on learning radare2.
- [**33**星][2y] [Py] [guedou/r2scapy](https://github.com/guedou/r2scapy) a radare2 plugin that decodes packets with Scapy
- [**28**星][12m] [C] [mrmacete/r2scripts](https://github.com/mrmacete/r2scripts) Collection of scripts for radare2
- [**27**星][3y] [Py] [gdataadvancedanalytics/r2graphity](https://github.com/gdataadvancedanalytics/r2graphity) Creating function call graphs based on radare2 framwork, plot fancy graphs and extract behavior indicators
- [**27**星][2y] [C] [yara-rules/r2yara](https://github.com/yara-rules/r2yara) r2yara - Module for Yara using radare2 information
- [**27**星][11m] [radareorg/r2jp](https://github.com/radareorg/r2jp) Japanese Community of radare2
- [**26**星][3y] [C] [monosource/radare2-explorations-binaries](https://github.com/monosource/radare2-explorations-binaries) Supplement to radare2-explorations.
- [**25**星][3y] [ObjC] [kpwn/rapd2](https://github.com/kpwn/rapd2) simple radare2 rap:// server
- [**24**星][2y] [Rust] [sushant94/rune](https://github.com/sushant94/rune) rune - radare2 based symbolic emulator
- [**21**星][5y] [C] [pastcompute/lca2015-radare2-tutorial](https://github.com/pastcompute/lca2015-radare2-tutorial) Examples and demos for my LCA2015 radare2 tutorial
- [**19**星][10m] [Py] [radare/radare2-r2pipe-api](https://github.com/radare/radare2-r2pipe-api) r2pipe-api repo
- [**18**星][2y] [Py] [countercept/radare2-scripts](https://github.com/countercept/radare2-scripts) A collection of useful radare2 scripts!
- [**16**星][2y] [C] [safiire/radare2-dan32](https://github.com/safiire/radare2-dan32) Binary, Analysis, and Disassembler Radare2 Plugins for Dan32 architechture binaries
- [**16**星][5y] [Py] [tyilo/kextd_patcher](https://github.com/tyilo/kextd_patcher) Patch kextd using radare2
- [**15**星][5m] [JS] [securisec/r2retdec](https://github.com/securisec/r2retdec) Use a local instance of retdec to decompile functions in radare2
- [**14**星][1y] [Py] [ndaprela/r2dbg](https://github.com/ndaprela/r2dbg) interface for radare2 based on r2pipe tailored for debugging
- [**13**星][4y] [Py] [shaded-enmity/r2-ropstats](https://github.com/shaded-enmity/r2-ropstats) A set of tools based on radare2 for analysis of ROP gadgets and payloads.
- [**12**星][1y] [C] [radare/radare2-au](https://github.com/radare/radare2-au) Audio Support for radare2
- [**11**星][1y] [Go] [wolfvan/yararet](https://github.com/wolfvan/yararet) Carving tool based in Radare2 & Yara
- [**10**星][4m] [Py] [ps1337/pwntools-r2](https://github.com/ps1337/pwntools-r2) Launch radare2 like a boss from pwntools in tmux
- [**10**星][18d] [Go] [radareorg/r2pm](https://github.com/radareorg/r2pm) Radare2 cross platform package manager
- [**9**星][7m] [Py] [jacobpimental/r2-gohelper](https://github.com/jacobpimental/r2-gohelper) gopclntab finder and analyzer for Radare2
- [**9**星][1y] [Java] [redmed666/mal6raph](https://github.com/redmed666/mal6raph) mal6raph: 结合radare2 和 neo4j, 辅助函数级别的相似性分析
- [**8**星][3y] [Py] [newlog/r2com](https://github.com/newlog/r2com) radare2 script to help on COM objects reverse engineering
- [**8**星][3y] [C] [radare/gradare2](https://github.com/radare/gradare2) Port of gradare GTK/VTE frontend to r2
- [**7**星][12m] [Rust] [radareorg/esil-rs](https://github.com/radareorg/esil-rs) Radare2's ESIL in Rust
- [**7**星][3y] [Py] [thestr4ng3r/bokken](https://github.com/thestr4ng3r/bokken) Bokken is a GUI for radare2. Don't use this, use
- [**6**星][2y] [Py] [d00rt/gootkit_string_patcher](https://github.com/d00rt/gootkit_string_patcher) A python script using radare2 for decrypt and patch the strings of GootKit malware
- [**6**星][2y] [Py] [h4ng3r/r2apktool](https://github.com/h4ng3r/r2apktool) radare2 based alternative to apktool
- [**5**星][2y] [jacobpimental/intro-to-radare2](https://github.com/jacobpimental/intro-to-radare2) 
- [**4**星][4y] [Py] [andrewaeva/strange-functions](https://github.com/andrewaeva/strange-functions) Extract functions and opcodes with radare2
- [**4**星][1y] [Py] [mytbk/radare-uefi](https://github.com/mytbk/radare-uefi) helper radare2 script to analyze UEFI firmware modules
- [**3**星][2y] [Py] [antonin-deniau/bnstrings](https://github.com/antonin-deniau/bnstrings) Binaryninja plugin that use radare2 to find and add strings to binaryninja
- [**2**星][3y] [h4ng3r/r2dextest](https://github.com/h4ng3r/r2dextest) Dalvik tests generator for radare2 using on androguard
- [**2**星][6m] [Py] [javieryuste/radare2-deep-graph](https://github.com/javieryuste/radare2-deep-graph) A Cutter plugin to generate radare2 graphs
- [**2**星][2y] [C++] [jubal-r/ronin](https://github.com/jubal-r/ronin) Radare2 GUI
- [**0**星][1y] [Py] [d4em0n/r2snow](https://github.com/d4em0n/r2snow) Integrate radare2 with snowman decompiler


### <a id="1a6652a1cb16324ab56589cb1333576f"></a>与其他工具交互


#### <a id="dfe53924d678f9225fc5ece9413b890f"></a>未分类


- [**378**星][19d] [JS] [nowsecure/r2frida](https://github.com/nowsecure/r2frida) Radare2 and Frida better together.
    - 重复区段: [DBI->Frida->工具->与其他工具交互->Radare2](#ac053c4da818ca587d57711d2ff66278) |
- [**79**星][8m] [Py] [guedou/r2m2](https://github.com/guedou/r2m2) radare2 + miasm2 = ♥
- [**47**星][11m] [Py] [nowsecure/r2lldb](https://github.com/nowsecure/r2lldb) radare2-lldb integration
- [**34**星][12m] [CSS] [nowsecure/r2frida-book](https://github.com/nowsecure/r2frida-book) The radare2 + frida book for Mobile Application assessment
    - 重复区段: [DBI->Frida->工具->与其他工具交互->Radare2](#ac053c4da818ca587d57711d2ff66278) |


#### <a id="1cfe869820ecc97204a350a3361b31a7"></a>IDA


- [**175**星][6d] [C++] [radareorg/r2ghidra-dec](https://github.com/radareorg/r2ghidra-dec) Ghidra反编译器与Radare2深度集成
    - 重复区段: [Ghidra->插件->与其他工具交互->Radare2](#e1cc732d1388084530b066c26e24887b) |
- [**125**星][8m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) 将IDA Pro和Radare2识别的符号（目前仅函数）导出到ELF符号表
    - 重复区段: [IDA->插件->ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[IDA->插件->导入导出->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[IDA->插件->函数相关->未分类](#347a2158bdd92b00cd3d4ba9a0be00ae) |
- [**123**星][2m] [Py] [radare/radare2ida](https://github.com/radare/radare2ida) Tools, documentation and scripts to move projects from IDA to R2 and viceversa
    - 重复区段: [IDA->插件->导入导出->Radare2](#21ed198ae5a974877d7a635a4b039ae3) |




### <a id="f7778a5392b90b03a3e23ef94a0cc3c6"></a>GUI


- [**6176**星][t] [C++] [radareorg/cutter](https://github.com/radareorg/cutter) 逆向框架 radare2的Qt界面，iaito的升级版
- [**67**星][1y] [JS] [radareorg/radare2-webui](https://github.com/radareorg/radare2-webui) webui repository for radare2
- [**47**星][8y] [Py] [radare/bokken](https://github.com/radare/bokken) python-gtk UI for radare2
- [**35**星][3y] [C#] [m4ndingo/radare2gui_dotnet](https://github.com/m4ndingo/radare2gui_dotnet) Another radare2 gui for windows
- [**23**星][1y] [c++] [dax89/r2gui](https://github.com/dax89/r2gui) Unofficial Qt5 frontend for Radare2




***


## <a id="95fdc7692c4eda74f7ca590bb3f12982"></a>文章&&视频


- 2019.10 [prsecurity] [Radare2 for RE CTF](https://medium.com/p/e0163cb0466e)
- 2019.09 [securityartwork] [YaraRET (I): Carving with Radare2 & Yara](https://www.securityartwork.es/2019/09/02/yararet-i-carving-with-radare2-yara/)
- 2019.07 [freebuf] [教你使用Cutter和Radare2对APT32恶意程序流程图进行反混淆处理](https://www.freebuf.com/articles/network/208019.html)
- 2019.07 [THER] [0x0D - FLARE-On #3 Challenge Part 2 [Reversing with Radare2]](https://www.youtube.com/watch?v=QP9Cepdqf-o)
- 2019.07 [THER] [0x0C - Cutter: FLARE-On #3 Challenge Part 1 [Reversing with Radare2]](https://www.youtube.com/watch?v=hbEpVwD5rJI)
- 2019.07 [THER] [0x09 Cross References [Reversing with Radare2]](https://www.youtube.com/watch?v=yOtx6LL_R08)
- 2019.07 [THER] [0x08 Navigation [Reversing with Radare2]](https://www.youtube.com/watch?v=rkygJSjJbso)
- 2019.07 [THER] [0x04 Target Application [Reversing with Radare2]](https://www.youtube.com/watch?v=jlr3FablVIc)
- 2019.06 [THER] [0x03 Environment Setup [Reversing with Radare2]](https://www.youtube.com/watch?v=qGSFk_CkIaw)
- 2019.06 [THER] [0x02 What is Radare2 [Reversing with Radare2]](https://www.youtube.com/watch?v=9fLfD2fZWiA)
- 2019.06 [THER] [0x00 Intro [Reversing with Radare2]](https://www.youtube.com/watch?v=Lva32dXS0mU)
- 2019.06 [hitbsecconf] [#HITB2019AMS D1T3 - Overcoming Fear: Reversing With Radare2 - Arnau Gamez Montolio](https://www.youtube.com/watch?v=317dNavABKo)
- 2019.05 [X0x0FFB347] [Solving MalwareTech Shellcode challenges with some radare2 magic!](https://medium.com/p/b91c85babe4b)
- 2019.05 [360] [使用Cutter和Radare2对APT32恶意程序流程图进行反混淆处理](https://www.anquanke.com/post/id/178047/)
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
- 2018.05 [megabeets] [使用Radare2和Cutter解密APT33的Dropshot恶意软件](https://www.megabeets.net/decrypting-dropshot-with-radare2-and-cutter-part-1/)
- 2018.04 [moveax] [Dr Von Noizeman’s Nuclear Bomb defused with Radare2](https://moveax.me/dr-von-noizemans-binary-bomb/)
- 2018.04 [reversingminds] [使用radare2分析GootKit银行恶意软件的简单方法](http://reversingminds-blog.logdown.com/posts/7369479)
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
- 2017.12 [n0where] [Qt C++ radare2 GUI: Cutter](https://n0where.net/qt-c-radare2-gui-cutter)
- 2017.12 [radiofreerobotron] [ROPEmporium: Pivot 64-bit CTF Walkthrough With Radare2](http://radiofreerobotron.net/blog/2017/12/04/ropemporium-pivot-ctf-walkthrough2/)
- 2017.12 [PancakeNopcode] [recon2017 - Bubble Struggle Call Graph Visualization with Radare2 - by mari0n](https://www.youtube.com/watch?v=ofRP2PorryU)
- 2017.11 [radiofreerobotron] [ROPEmporium: Pivot 32-bit CTF Walkthrough With Radare2](http://radiofreerobotron.net/blog/2017/11/23/ropemporium-pivot-ctf-walkthrough/)
- 2017.11 [aliyun] [Radare2使用实战](https://xz.aliyun.com/t/1515)
- 2017.11 [aliyun] [Radare2使用全解](https://xz.aliyun.com/t/1514)
- 2017.11 [dustri] [Solving game2 from the badge of Black Alps 2017 with radare2](https://dustri.org/b/solving-game2-from-the-badge-of-black-alps-2017-with-radare2.html)
- 2017.10 [animal0day] [Hack.lu CTF：使用radare2 和 pwntools (ret2libc) 解决 HeapHeaven](https://animal0day.blogspot.com/2017/10/hacklu-heapheaven-write-up-with-radare2.html)
- 2017.10 [megabeets] [使用 radare2 逆向Gameboy ROM](https://www.megabeets.net/reverse-engineering-a-gameboy-rom-with-radare2/)
- 2017.09 [PancakeNopcode] [r2con2017 - Diaphora with radare2 by matalaz and pancake](https://www.youtube.com/watch?v=dAwXrUKaUsw)
- 2017.09 [dustri] [Defeating IOLI with radare2 in 2017](https://dustri.org/b/defeating-ioli-with-radare2-in-2017.html)
- 2017.08 [rkx1209] [GSoC Final: radare2 Timeless Debugger](https://rkx1209.github.io/2017/08/27/gsoc-final-report.html)
- 2017.08 [rootedconmadrid] [ABEL VALERO - Radare2 - 1.0 [Rooted CON 2017 - ENG]](https://www.youtube.com/watch?v=wCDIWllIiag)
- 2017.08 [rootedconmadrid] [ABEL VALERO - Radare2 - 1.0 [Rooted CON 2017 - ESP]](https://www.youtube.com/watch?v=Bt7WJNwXw3M)
- 2017.07 [pediy] [[翻译]Radare2文档(1)](https://bbs.pediy.com/thread-219090.htm)
- 2017.05 [n0where] [Reverse Engineering Framework: radare2](https://n0where.net/reverse-engineering-framework-radare2)
- 2017.04 [kitploit] [radare2 '/format/wasm/wasm.c' Heap Buffer Overflow Vulnerability](https://exploit.kitploit.com/2017/04/radare2-formatwasmwasmc-heap-buffer.html)
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
- 2016.10 [sans] [Radare2: rahash2](https://isc.sans.edu/forums/diary/Radare2+rahash2/21577/)
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
- 2016.03 [techorganic] [30分钟学会Radare2](https://blog.techorganic.com/2016/03/08/radare-2-in-0x1e-minutes/)
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


# <a id="afb7259851922935643857c543c4b0c2"></a>BinaryNinja


***


## <a id="3034389f5aaa9d7b0be6fa7322340aab"></a>插件&&脚本


### <a id="a750ac8156aa0ff337a8639649415ef1"></a>新添加的


- [**2820**星][30d] [Py] [androguard/androguard](https://github.com/androguard/androguard) Reverse engineering, Malware and goodware analysis of Android applications ... and more (ninja !)
- [**498**星][4y] [Py] [vector35/deprecated-binaryninja-python](https://github.com/vector35/deprecated-binaryninja-python) Deprecated Binary Ninja prototype written in Python
- [**328**星][5m] [Py] [vector35/binaryninja-api](https://github.com/vector35/binaryninja-api) Public API, examples, documentation and issues for Binary Ninja
- [**280**星][3m] [Py] [pbiernat/ripr](https://github.com/pbiernat/ripr) Package Binary Code as a Python class using Binary Ninja and Unicorn Engine
- [**201**星][6d] [JS] [ret2got/disasm.pro](https://github.com/ret2got/disasm.pro) A realtime assembler/disassembler (formerly known as disasm.ninja)
- [**177**星][6m] [Py] [trailofbits/binjascripts](https://github.com/trailofbits/binjascripts) Scripts for Binary Ninja
- [**141**星][2y] [Py] [snare/binjatron](https://github.com/snare/binjatron) Binary Ninja plugin for Voltron integration
- [**95**星][3y] [appsecco/defcon24-infra-monitoring-workshop](https://github.com/appsecco/defcon24-infra-monitoring-workshop) Defcon24 Workshop Contents : Ninja Level Infrastructure Monitoring
- [**85**星][3y] [Py] [vector35/binaryninja-plugins](https://github.com/vector35/binaryninja-plugins) Repository to track Binary Ninja Plugins, Themes, and other related tools
- [**56**星][2m] [Py] [forallsecure/bncov](https://github.com/forallsecure/bncov) Scriptable Binary Ninja plugin for coverage analysis and visualization
- [**40**星][1y] [Py] [cetfor/papermachete](https://github.com/cetfor/papermachete) A project that uses Binary Ninja and GRAKN.AI to perform static analysis on binary files with the goal of identifying bugs in software.
- [**37**星][10m] [Py] [carstein/annotator](https://github.com/carstein/Annotator) Binary Ninja Function Annotator
- [**31**星][3y] [Py] [nopdev/binjadock](https://github.com/nopdev/binjadock) An extendable, tabbed, dockable UI widget plugin for BinaryNinja
- [**31**星][30d] [Py] [whitequark/binja_itanium_cxx_abi](https://github.com/whitequark/binja_itanium_cxx_abi) Binary Ninja ItaniumC++ ABI 插件. 提供了一个自定义的 demangler，能够分析解析 RTTI 和 vtables，并发现基于虚函数指针的新函数
- [**31**星][5m] [Py] [withzombies/bnil-graph](https://github.com/withzombies/bnil-graph) A BinaryNinja plugin to graph a BNIL instruction tree
- [**29**星][1y] [Py] [ernw/binja-ipython](https://github.com/ernw/binja-ipython) A plugin to integrate an IPython kernel into Binary Ninja.
- [**28**星][6m] [Py] [fluxchief/binaryninja_avr](https://github.com/fluxchief/binaryninja_avr) Binaryninja AVR architecture plugin with lifting
- [**25**星][4m] [Py] [trailofbits/objcgraphview](https://github.com/trailofbits/objcgraphview) A graph view plugin for Binary Ninja to visualize Objective-C
- [**25**星][11d] [Py] [riverloopsec/hashashin](https://github.com/riverloopsec/hashashin) Hashashin: A Fuzzy Matching Tool for Binary Ninja
- [**24**星][2y] [Py] [nccgroup/binja_dynamics](https://github.com/nccgroup/binja_dynamics) A PyQt5 frontend to the binjatron plugin for Binary Ninja that includes highlighting features aimed at making it easier for beginners to learn about reverse engineering
- [**21**星][6m] [Py] [zznop/binjago](https://github.com/zznop/binjago) Binary Ninja plugin for ROP gadget calculation
- [**19**星][4m] [Py] [joshwatson/binaryninja-msp430](https://github.com/joshwatson/binaryninja-msp430) msp430 Architecture plugin for Binary Ninja
- [**18**星][2y] [Py] [joshwatson/binaryninja-bookmarks](https://github.com/joshwatson/binaryninja-bookmarks) Plugin for BinaryNinja that provides bookmarking functionality
- [**18**星][12m] [Py] [transferwise/pg_ninja](https://github.com/transferwise/pg_ninja) The ninja elephant obfuscation and replica tool
- [**17**星][2y] [Py] [extremecoders-re/bnpy](https://github.com/extremecoders-re/bnpy) An architecture plugin for binary ninja to disassemble raw python bytecode
- [**16**星][5m] [Py] [carstein/syscaller](https://github.com/carstein/syscaller) BinaryNinja 插件，发生系统调用时自动获取调用的参数
- [**16**星][1y] [Py] [lunixbochs/bnrepl](https://github.com/lunixbochs/bnrepl) Run your Binary Ninja Python console in a separate Terminal window.
- [**16**星][3y] [Py] [rootbsd/binaryninja_plugins](https://github.com/rootbsd/binaryninja_plugins) Binary ninja plugins
- [**15**星][3y] [Py] [orndorffgrant/bnhook](https://github.com/orndorffgrant/bnhook) binary ninja plugin for adding custom hooks to executables
- [**15**星][5m] [Py] [zznop/bn-genesis](https://github.com/zznop/bn-genesis) Binary Ninja plugin suite for SEGA Genesis ROM hacking
- [**14**星][3y] [Py] [coldheat/liil](https://github.com/coldheat/liil) Linear IL view for Binary Ninja
- [**12**星][2y] [Py] [gitmirar/binaryninjayaraplugin](https://github.com/gitmirar/binaryninjayaraplugin) Yara Plugin for Binary Ninja
- [**12**星][7m] [Py] [ktn1990/cve-2019-10869](https://github.com/ktn1990/cve-2019-10869) (Wordpress) Ninja Forms File Uploads Extension <= 3.0.22 – Unauthenticated Arbitrary File Upload
- [**11**星][3m] [C++] [0x1f9f1/binja-pattern](https://github.com/0x1f9f1/binja-pattern) 
- [**10**星][2y] [Py] [chokepoint/bnpincoverage](https://github.com/chokepoint/bnpincoverage) Visually analyze basic block code coverage in Binary Ninja using Pin output.
- [**10**星][5y] [Py] [emileaben/scapy-dns-ninja](https://github.com/emileaben/scapy-dns-ninja) Minimal DNS answering machine, for customized/programmable answers
- [**10**星][2m] [Py] [zznop/bn-brainfuck](https://github.com/zznop/bn-brainfuck) Brainfuck architecture module and loader for Binary Ninja
- [**9**星][9m] [Py] [manouchehri/binaryninja-radare2](https://github.com/manouchehri/binaryninja-radare2) DEPRECIATED
- [**8**星][2y] [Py] [cah011/binja-avr](https://github.com/cah011/binja-avr) AVR assembly plugin for Binary Ninja
- [**8**星][5m] [Py] [joshwatson/binaryninja-microcorruption](https://github.com/joshwatson/binaryninja-microcorruption) BinaryView Plugin for Microcorruption CTF memory dumps
- [**8**星][4m] [Py] [whitequark/binja-i8086](https://github.com/whitequark/binja-i8086) 16-bit x86 architecture for Binary Ninja
- [**7**星][1y] [Py] [rick2600/xref_call_finder](https://github.com/rick2600/xref_call_finder) Plugin for binary ninja to find calls to function recursively
- [**6**星][1y] [Py] [kudelskisecurity/binaryninja_cortex](https://github.com/kudelskisecurity/binaryninja_cortex) A Binary Ninja plugin to load Cortex-based MCU firmware
- [**5**星][5m] [Py] [0x1f9f1/binja-msvc](https://github.com/0x1f9f1/binja-msvc) 
- [**5**星][3y] [agnosticlines/binaryninja-plugins](https://github.com/agnosticlines/binaryninja-plugins) A repo with a listing of binary ninja scripts + plugins (massively inspired by
- [**5**星][6m] [Py] [bkerler/annotate](https://github.com/bkerler/annotate) Binary Ninja plugin for annotation of arguments for functions
- [**5**星][5m] [Py] [icecr4ck/bngb](https://github.com/icecr4ck/bnGB) Binary Ninja Game Boy loader and architecture plugin for analysing and disassembling GB ROM.
- [**4**星][10m] [HTML] [evanrichter/base16-binary-ninja](https://github.com/evanrichter/base16-binary-ninja) Base16 Color Template for Binja
- [**3**星][2y] [Py] [nallar/binja-function-finder](https://github.com/nallar/binja-function-finder) Binary ninja plugin which adds simple tools for finding functions
- [**2**星][3m] [Py] [404d/peutils](https://github.com/404d/peutils) Binary Ninja plugin providing various niche utilities for working with PE binaries
- [**2**星][11m] [Py] [blurbdust/binaryninja_plan9_aout](https://github.com/blurbdust/binaryninja_plan9_aout) Binary Ninja Plugin for disassembling plan 9 a.out binaries
- [**2**星][5m] [Py] [icecr4ck/bnmiasm](https://github.com/icecr4ck/bnmiasm) Plugin to visualize Miasm IR graph in Binary Ninja.
- [**2**星][3y] [C] [jhurliman/binaryninja-functionmatcher](https://github.com/jhurliman/binaryninja-functionmatcher) A Binary Ninja plugin to match functions and transplant symbols between similar binaries
- [**2**星][3y] [Py] [rick2600/textify_function](https://github.com/rick2600/textify_function) Plugin for binary ninja to textify function to copy and paste
- [**2**星][6m] [Py] [vasco-jofra/jump-table-branch-editor](https://github.com/vasco-jofra/jump-table-branch-editor) A binary ninja plugin that eases fixing jump table branches
- [**1**星][1y] [Py] [arcnor/binja_search](https://github.com/arcnor/binja_search) Binary Ninja search plugin
- [**1**星][2y] [Py] [kapaw/binaryninja-lc3](https://github.com/kapaw/binaryninja-lc3) LC-3 architecture plugin for Binary Ninja
- [**0**星][2y] [Py] [ehennenfent/binja_spawn_terminal](https://github.com/ehennenfent/binja_spawn_terminal) A tiny plugin for Binary Ninja that enables the ui to spawn terminals on Ubuntu and OS


### <a id="bba1171ac550958141dfcb0027716f41"></a>与其他工具交互


#### <a id="c2f94ad158b96c928ee51461823aa953"></a>未分类


- [**149**星][1y] [Py] [hugsy/binja-retdec](https://github.com/hugsy/binja-retdec) Binary Ninja plugin to decompile binaries using RetDec API
- [**8**星][3m] [Py] [c3r34lk1ll3r/binrida](https://github.com/c3r34lk1ll3r/BinRida) Plugin for Frida in Binary Ninja
    - 重复区段: [DBI->Frida->工具->与其他工具交互->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |


#### <a id="713fb1c0075947956651cc21a833e074"></a>IDA


- [**68**星][8m] [Py] [lunixbochs/revsync](https://github.com/lunixbochs/revsync) IDA和Binja实时同步插件
    - 重复区段: [IDA->插件->导入导出->BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a) |
- [**61**星][6m] [Py] [zznop/bnida](https://github.com/zznop/bnida) 4个脚本，在IDA和BinaryNinja间交互数据
    - 重复区段: [IDA->插件->导入导出->BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a) |
    - [ida_export](https://github.com/zznop/bnida/blob/master/ida/ida_export.py) 将数据从IDA中导入
    - [ida_import](https://github.com/zznop/bnida/blob/master/ida/ida_import.py) 将数据导入到IDA
    - [binja_export](https://github.com/zznop/bnida/blob/master/binja_export.py) 将数据从BinaryNinja中导出
    - [binja_import](https://github.com/zznop/bnida/blob/master/binja_import.py) 将数据导入到BinaryNinja
- [**14**星][6m] [Py] [cryptogenic/idc_importer](https://github.com/cryptogenic/idc_importer) Binary Ninja插件，从IDA中导入IDC数据库转储
    - 重复区段: [IDA->插件->导入导出->BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a) |






***


## <a id="2d24dd6f0c01a084e88580ad22ce5b3c"></a>文章&&视频


- 2018.09 [aliyun] [使用Binary Ninja调试共享库](https://xz.aliyun.com/t/2826)
- 2018.09 [kudelskisecurity] [Analyzing ARM Cortex-based MCU firmwares using Binary Ninja](https://research.kudelskisecurity.com/2018/09/25/analyzing-arm-cortex-based-mcu-firmwares-using-binary-ninja/)
- 2018.04 [trailofbits] [使用Binary Ninja的MLIL和SSA, 挖掘二进制文件的漏洞. (MLIL: Medium Level IL, 中间层IL)(SSA: Single Static Assignment)](https://blog.trailofbits.com/2018/04/04/vulnerability-modeling-with-binary-ninja/)
- 2018.01 [pediy] [[翻译]逆向平台Binary Ninja介绍](https://bbs.pediy.com/thread-224141.htm)
- 2017.11 [] [bnpy - A python architecture plugin for Binary Ninja](https://0xec.blogspot.com/2017/11/bnpy-python-architecture-plugin-for.html)
- 2017.10 [ret2] [Untangling Exotic Architectures with Binary Ninja](http://blog.ret2.io/2017/10/17/untangling-exotic-architectures-with-binary-ninja/)
- 2017.10 [chokepoint] [Pin Visual Coverage Tool for Binary Ninja](http://www.chokepoint.net/2017/10/pin-visual-coverage-tool-for-binary.html)


# <a id="747ddaa20f643da415284bfba9cda3a2"></a>模拟器&&虚拟机


***


## <a id="796b64906655228d8a1ff8c0dd390451"></a>QEMU


### <a id="296c7f25266b25e5ee1107dd76e40dd2"></a>工具


#### <a id="82072558d99a6cf23d4014c0ae5b420a"></a>新添加的


- [**7037**星][2m] [Shell] [kholia/osx-kvm](https://github.com/kholia/osx-kvm) Run macOS on QEMU/KVM. No support is provided at the moment.
- [**1308**星][18d] [C] [cisco-talos/pyrebox](https://github.com/cisco-talos/pyrebox) 逆向沙箱，基于QEMU，Python Scriptable
- [**1070**星][18d] [Shell] [dhruvvyas90/qemu-rpi-kernel](https://github.com/dhruvvyas90/qemu-rpi-kernel) Qemu kernel for emulating Rpi on QEMU
- [**601**星][29d] [Py] [nongiach/arm_now](https://github.com/nongiach/arm_now) 快速创建并运行不同CPU架构的虚拟机, 用于逆向分析或执行二进制文件. 基于QEMU
- [**532**星][7m] [Java] [limboemu/limbo](https://github.com/limboemu/limbo) Limbo is a QEMU-based emulator for Android. It currently supports PC & ARM emulation for Intel x86 and ARM architecture. See our wiki
    - 重复区段: [Android->工具->Emulator](#5afa336e229e4c38ad378644c484734a) |
- [**512**星][5m] [C] [decaf-project/decaf](https://github.com/decaf-project/DECAF) DECAF (short for Dynamic Executable Code Analysis Framework) is a binary analysis platform based on QEMU. This is also the home of the DroidScope dynamic Android malware analysis platform. DroidScope is now an extension to DECAF.
- [**452**星][3y] [C] [nccgroup/triforceafl](https://github.com/nccgroup/triforceafl) AFL/QEMU fuzzing with full-system emulation.
- [**375**星][] [C] [vanhauser-thc/aflplusplus](https://github.com/vanhauser-thc/aflplusplus) 带社区补丁的afl 2.56b
- [**278**星][13d] [Shell] [drtyhlpr/rpi23-gen-image](https://github.com/drtyhlpr/rpi23-gen-image) Advanced Debian "stretch" and "buster" bootstrap script for RPi 0/1/2/3 and QEMU
- [**277**星][1m] [C] [beckus/qemu_stm32](https://github.com/beckus/qemu_stm32) QEMU with an STM32 microcontroller implementation
- [**242**星][10m] [C++] [revng/revng](https://github.com/revng/revng) 二进制分析工具，基于QEMU 和LLVM
- [**175**星][8d] [winmin/awesome-vm-exploit](https://github.com/winmin/awesome-vm-exploit) share some useful archives about vm and qemu escape exploit.
- [**144**星][3y] [HTML] [landley/aboriginal](https://github.com/landley/aboriginal) provides virtual Linux images you can boot under QEMU,  within which you can compile and test any software you like.
- [**138**星][7m] [C] [alephsecurity/xnu-qemu-arm64](https://github.com/alephsecurity/xnu-qemu-arm64) 
- [**100**星][2y] [C] [comsecuris/luaqemu](https://github.com/comsecuris/luaqemu) QEMU-based framework exposing several of QEMU-internal APIs to a LuaJIT core injected into QEMU itself. Among other things, this allows fast prototyping of target systems without any native code and minimal effort in Lua.
- [**85**星][2y] [palmercluff/qemu-images](https://github.com/palmercluff/qemu-images) A collection of disk images and virtual machines that can be used by the QEMU emulator
- [**84**星][2y] [Shell] [viralpoetry/packer-bare-metal](https://github.com/viralpoetry/packer-bare-metal) Building bare metal OS images with Packer, VirtualBox and qemu-img
- [**68**星][7y] [C] [jowinter/qemu-trustzone](https://github.com/jowinter/qemu-trustzone) Experimental version of QEMU with basic support for ARM TrustZone (security extensions)
- [**66**星][4y] [C] [0xabu/qemu](https://github.com/0xabu/qemu) OLD qemu with Raspberry Pi 2 and Windows on ARM support. Retained for reference purposes only -- most of this has been merged upstream.
- [**60**星][1y] [C] [zhuowei/qemu](https://github.com/zhuowei/qemu) Patched version of QEMU for exploring XNU arm64 emulation.
- [**52**星][6d] [Py] [alephsecurity/xnu-qemu-arm64-scripts](https://github.com/alephsecurity/xnu-qemu-arm64-scripts) 
- [**46**星][4y] [C] [intel/qemu-lite](https://github.com/intel/qemu-lite) 
- [**44**星][2y] [Shell] [stayliv3/embedded-device-lab](https://github.com/stayliv3/embedded-device-lab) embedded-device-lab是一个利用qemu模拟真实世界中物联网漏洞的测试环境。由于物联网架构的特殊性，调试分析漏洞通常需要使用qemu模拟执行不同架构的可执行文件。而各种搭建环境，交叉编译是一件费事费力，令人忧伤的工作。 embedded-device-lab利用docker-compose，将各种漏洞调试环境一键化。简单使用两条命令，就可以直接使用gdb或者IDA动态分析相关漏洞。
- [**41**星][3y] [C] [kanglictf/afl-qai](https://github.com/kanglictf/afl-qai) A demo project for AFL with QEMU Augmented Instrumentation (qai)
- [**41**星][3y] [C] [nccgroup/triforceopenbsdfuzzer](https://github.com/nccgroup/triforceopenbsdfuzzer) System call fuzzing of OpenBSD amd64 using TriforceAFL (i.e. AFL and QEMU)
- [**41**星][2y] [VHDL] [texane/vpcie](https://github.com/texane/vpcie) implement PCIE devices using C or VHDL and test them against a QEMU virtualized architecture
- [**38**星][6y] [aquynh/ivm](https://github.com/aquynh/ivm) Run iOS on Android! (QEMU-s5l89xx-port)
- [**32**星][6m] [Py] [shellphish/shellphish-qemu](https://github.com/shellphish/shellphish-qemu) A pip wrapper around our ridiculous amount of qemu forks.
- [**31**星][2y] [C] [frederic/qemu-exynos-bootrom](https://github.com/frederic/qemu-exynos-bootrom) Emulating Exynos 4210 BootROM in QEMU
- [**27**星][12d] [C] [ispras/qemu](https://github.com/ispras/qemu) 
- [**25**星][5d] [Py] [autotest/tp-qemu](https://github.com/autotest/tp-qemu) Virt Test Provider for qemu and other related virtualization backends
- [**24**星][2d] [C] [libyal/libqcow](https://github.com/libyal/libqcow) Library and tools to access the QEMU Copy-On-Write (QCOW) image format
- [**24**星][4y] [C] [intel/kvmgt-qemu](https://github.com/intel/KVMGT-qemu) 
- [**18**星][7y] [C] [pleed/pyqemu](https://github.com/pleed/pyqemu) Dynamic binary instrumentation based crypto detection framework. Implementation of
- [**15**星][9m] [C] [s2e/qemu](https://github.com/s2e/qemu) QEMU VM with generic KVM extensions for symbolic execution
- [**15**星][2y] [HTML] [warewolf/thin-provisioning](https://github.com/warewolf/thin-provisioning) Thin provisioning - utilities for performing Windows malware analysis under a QEMU/libvirt environment
- [**7**星][2y] [intel/xengt-preview-qemu](https://github.com/intel/XenGT-Preview-qemu) 
- [**5**星][2y] [C] [eruffaldi/uefiboot](https://github.com/eruffaldi/uefiboot) Tutorial on making UEFI with CMake and VirtualBox/QEmu
- [**4**星][4y] [C] [firmadyne/qemu-linaro](https://github.com/firmadyne/qemu-linaro) Patched QEMU emulator (optional)
- [**1**星][2y] [C] [davidbuchanan314/cve-2017-13672](https://github.com/davidbuchanan314/cve-2017-13672) POCs for CVE-2017-13672 (OOB read in VGA Cirrus QEMU driver, causing DoS)
- [**0**星][3m] [Shell] [artem-nefedov/uefi-qemu-communicator](https://github.com/artem-nefedov/uefi-qemu-communicator) 
- [**0**星][2y] [Shell] [gencymex/smmtestbuildscript](https://github.com/gencymex/smmtestbuildscript) A script for building the system from Testing SMM with QEMU, KVM and libvirt




### <a id="5df30a166c2473fdadf5a578d1a70e32"></a>文章&&视频






***


## <a id="a13effff89633708c814ae9410da835a"></a>其他




# <a id="2f81493de610f9b796656b269380b2de"></a>Windows


***


## <a id="b478e9a9a324c963da11437d18f04998"></a>工具


### <a id="f9fad1d4d1f0e871a174f67f63f319d8"></a>新添加的




### <a id="1afda3039b4ab9a3a1f60b179ccb3e76"></a>其他


- [**1296**星][4y] [C++] [microsoft/microsoft-pdb](https://github.com/microsoft/microsoft-pdb) Microsoft提供的有关PDB格式的信息
- [**949**星][3m] [C] [basil00/divert](https://github.com/basil00/divert) 用户模式数据包拦截库，适用于Win 7/8/10
- [**863**星][5d] [C++] [henrypp/simplewall](https://github.com/henrypp/simplewall) 为Windows 过滤平台提供的配置界面
- [**726**星][2m] [Py] [diyan/pywinrm](https://github.com/diyan/pywinrm) Python实现的WinRM客户端
- [**578**星][3y] [Pascal] [t-d-k/librecrypt](https://github.com/t-d-k/librecrypt) Windows的透明、即时磁盘加密，兼容LUKS
- [**570**星][24d] [C] [hfiref0x/winobjex64](https://github.com/hfiref0x/winobjex64) Windows对象浏览器. x64
- [**463**星][8m] [C#] [microsoft/dbgshell](https://github.com/microsoft/dbgshell) PowerShell编写的Windows调试器引擎前端
- [**418**星][7d] [C] [samba-team/samba](https://github.com/samba-team/samba) 适用于Linux和Unix的标准Windows interoperability程序套件
- [**405**星][3y] [C++] [rwfpl/rewolf-wow64ext](https://github.com/rwfpl/rewolf-wow64ext) 在64位Windows系统上的WOW64 layer下运行x86程序
- [**403**星][3y] [C#] [zenlulz/memorysharp](https://github.com/zenlulz/memorysharp) Windows程序内存编辑库，C#编写，可向远程进程注入输入和代码，或读取远程进程内存
- [**389**星][2m] [C#] [microsoft/binskim](https://github.com/microsoft/binskim) 二进制静态分析工具，可为PE和ELF二进制格式提供安全性和正确性分析
- [**387**星][11d] [Jupyter Notebook] [microsoft/windowsdefenderatp-hunting-queries](https://github.com/microsoft/windowsdefenderatp-hunting-queries) 在MS Defender ATP中进行高级查询的示例
- [**370**星][19d] [Ruby] [winrb/winrm](https://github.com/winrb/winrm) 在Windows中使用WinRM的功能调用原生对象的SOAP库。Ruby编写
- [**367**星][1y] [PS] [netspi/pesecurity](https://github.com/netspi/pesecurity) 检查PE(EXE/DLL)编译选项是否有：ASLR, DEP, SafeSEH, StrongNaming, Authenticode。PowerShell模块
- [**360**星][4d] [C#] [digitalruby/ipban](https://github.com/digitalruby/ipban) 监视Windows/Linux系统的登录失败和不良行为，并封禁对应的IP地址。高度可配置，精简且功能强大。
- [**353**星][2y] [C++] [zerosum0x0/winrepl](https://github.com/zerosum0x0/winrepl) 实现了“读取->执行->打印 循环”的Windows汇编代码，x86+x64
- [**318**星][3y] [C] [sdhand/x11fs](https://github.com/sdhand/x11fs) 操作X windows
- [**298**星][3y] [C++] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools) 用于测试Windows的各种符号链接类型的一套工具
- [**289**星][2y] [C++] [godaddy/procfilter](https://github.com/godaddy/procfilter) Windows 进程过滤系统。可以使用 Yara 规则匹配进程模块，从而阻止匹配的进程启动
- [**281**星][1y] [C++] [fireeye/flare-wmi](https://github.com/fireeye/flare-wmi) 描述Windows管理规范（WMI）技术的各种文档和代码项目
- [**269**星][12m] [Py] [hakril/pythonforwindows](https://github.com/hakril/pythonforwindows) 简化Python与Windows操作系统交互的库
- [**238**星][5m] [PS] [microsoft/aaronlocker](https://github.com/microsoft/aaronlocker) Windows应用程序白名单
- [**233**星][10m] [Go] [masterzen/winrm](https://github.com/masterzen/winrm) Windows远程命令执行，命令行工具+库，Go编写
- [**232**星][1y] [C++] [ionescu007/simpleator](https://github.com/ionescu007/simpleator) Windows x64用户模式应用程序模拟器
- [**229**星][4m] [C] [tishion/mmloader](https://github.com/tishion/mmloader) 绕过Windows PE Loader，直接从内存中加载DLL模块（x86/x64）
- [**228**星][3m] [C] [leecher1337/ntvdmx64](https://github.com/leecher1337/ntvdmx64) 在64位版本上执行Windows DOS版的 NTVDM
- [**226**星][12m] [C++] [rexdf/commandtrayhost](https://github.com/rexdf/commandtrayhost) 监控Windows systray的命令行工具
- [**222**星][2y] [C++] [intelpt/windowsintelpt](https://github.com/intelpt/windowsintelpt) 实现Intel Skylake架构下的Intel处理器追踪功能的Windows驱动
- [**210**星][3m] [adguardteam/adguardforwindows](https://github.com/adguardteam/adguardforwindows) Windows系统范围的AdBlocker
- [**208**星][10m] [C] [hzqst/unicorn_pe](https://github.com/hzqst/unicorn_pe) 模拟Windows PE文件的代码执行，基于Unicorn
- [**206**星][3y] [C++] [k2/ehtrace](https://github.com/k2/ehtrace) 跟踪Windows上二进制文件的执行。
- [**205**星][3m] [C] [jasonwhite/ducible](https://github.com/jasonwhite/ducible) 使PE和PDB的构建具有可复制性
- [**202**星][2y] [Py] [euske/pyrexecd](https://github.com/euske/pyrexecd) 独立的SSH服务器（Windows）
- [**193**星][11m] [C] [ionescu007/winipt](https://github.com/ionescu007/winipt) 利用Win10 1809添加的Intel处理器追踪功能进行进程追踪
- [**192**星][1m] [C++] [blackint3/openark](https://github.com/blackint3/openark) 反Rootkit工具（Windows）
- [**192**星][3y] [Ruby] [zed-0xff/pedump](https://github.com/zed-0xff/pedump) 转储PE文件，Ruby编写
- [**174**星][3y] [C#] [gangzhuo/kcptun-gui-windows](https://github.com/gangzhuo/kcptun-gui-windows) 隧道工具kcptun的GUI
- [**171**星][2m] [Py] [gleeda/memtriage](https://github.com/gleeda/memtriage) 快速查询Windows计算机上的内存。使用Winpmem驱动访问物理内存，使用Volatility分析
- [**164**星][3y] [C++] [zer0mem0ry/runpe](https://github.com/zer0mem0ry/runpe) 在与主机进程相同的地址空间中运行另一个Windows PE
- [**163**星][1m] [PS] [dsccommunity/activedirectorydsc](https://github.com/dsccommunity/ActiveDirectoryDsc) 包含用于部署和配置Active Directory的DSC资源
- [**158**星][7m] [C#] [wohlstand/destroy-windows-10-spying](https://github.com/wohlstand/destroy-windows-10-spying) 禁用/销毁Windows的间谍功能
- [**151**星][3y] [C] [pustladi/windows-2000](https://github.com/pustladi/windows-2000) Windows 2000专业版的源码
- [**151**星][2y] [Rust] [trailofbits/flying-sandbox-monster](https://github.com/trailofbits/flying-sandbox-monster) 如何将 Windows Defender 放到沙箱中运行，以及关于 Windows 系统上 Rust 的若干思考
- [**149**星][1y] [C++] [justasmasiulis/nt_wrapper](https://github.com/justasmasiulis/nt_wrapper) 对原生Windows系统API的Wrapper
- [**143**星][3d] [C#] [microsoft/windowsprotocoltestsuites](https://github.com/microsoft/windowsprotocoltestsuites) 针对Windows开放规范的实现提供了互操作性测试
- [**137**星][4y] [Py] [pentestmonkey/pysecdump](https://github.com/pentestmonkey/pysecdump) 从Windows系统中转储安全相关信息，Python编写
- [**136**星][6y] [C++] [zer0fl4g/nanomite](https://github.com/zer0fl4g/nanomite) Windows上用于x64和x86的图形调试器
- [**135**星][2m] [C] [nomorefood/putty-cac](https://github.com/nomorefood/putty-cac) Windows 安全Shell客户端，支持智能卡&证书
- [**134**星][2y] [Py] [binarydefense/auto-ossec](https://github.com/binarydefense/auto-ossec) 为Linux和Windows自动配置OSSEC代理
- [**134**星][6m] [CMake] [pothosware/pothossdr](https://github.com/pothosware/pothossdr) Pothos SDR Windows开发环境
- [**133**星][1y] [C++] [3gstudent/eventlogedit-evtx--evolution](https://github.com/3gstudent/eventlogedit-evtx--evolution) 从Windows XML事件日志（EVTX）文件中删除个别行
- [**133**星][3y] [C++] [ioactive/i-know-where-your-page-lives](https://github.com/ioactive/i-know-where-your-page-lives) 对的Windows 10内核进行非随机化
- [**129**星][2y] [Py] [dviros/rat-via-telegram](https://github.com/dviros/rat-via-telegram) 使用Telegram控制已经攻克的Windows主机
- [**124**星][5m] [Py] [fireeye/flare-qdb](https://github.com/fireeye/flare-qdb) 操纵和修改Windows和Linux的软件行为的调试器，包括命令行工具和Python调试器
- [**116**星][3y] [Batchfile] [bartblaze/disable-intel-amt](https://github.com/bartblaze/disable-intel-amt) Windows系统禁用AMT
- [**115**星][8m] [C++] [dragonquesthero/pubg-pak-hacker](https://github.com/dragonquesthero/pubg-pak-hacker) 使用Windows内核驱动隐藏文件及自身，绕过BE
- [**114**星][4y] [C++] [chengchengcc/ark-tools](https://github.com/chengchengcc/ark-tools) Windows Ark 工具的工程和一些demo
- [**111**星][8m] [C] [wbenny/ksocket](https://github.com/wbenny/ksocket) 在Windows驱动中使用WSK建立网络连接的示例
- [**108**星][2m] [PS] [powershell/windowscompatibility](https://github.com/powershell/windowscompatibility) Module that allows Windows PowerShell Modules to be used from PSCore6
- [**107**星][30d] [Py] [ernw/windows-insight](https://github.com/ernw/windows-insight) The content of this repository aims to assist efforts on analysing inner working principles, functionalities, and properties of the Microsoft Windows operating system. This repository stores relevant documentation as well as executable files needed for conducting analysis studies.
- [**107**星][5y] [C] [malwaretech/tinyxpb](https://github.com/malwaretech/tinyxpb) Windows XP 32-Bit Bootkit
- [**106**星][2y] [C++] [zerosum0x0/puppetstrings](https://github.com/zerosum0x0/puppetstrings) Hitch a free ride to Ring 0 on Windows
- [**105**星][3m] [soffensive/windowsblindread](https://github.com/soffensive/windowsblindread) A list of files / paths to probe when arbitrary files can be read on a Microsoft Windows operating system
- [**105**星][11m] [Py] [thelinuxchoice/pyrat](https://github.com/thelinuxchoice/pyrat) Windows Remote Administration Tool (RAT)
- [**104**星][2y] [C++] [iceb0y/windows-container](https://github.com/iceb0y/windows-container) A lightweight sandbox for Windows application
- [**102**星][3m] [C++] [giovannidicanio/winreg](https://github.com/giovannidicanio/winreg) Convenient high-level C++ wrapper around the Windows Registry API
- [**100**星][2y] [C] [shellster/dcsyncmonitor](https://github.com/shellster/dcsyncmonitor) Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events.
- [**100**星][2m] [C#] [tyranid/windowsrpcclients](https://github.com/tyranid/windowsrpcclients) This respository is a collection of C# class libraries which implement RPC clients for various versions of the Windows Operating System from 7 to Windows 10.
- [**98**星][2d] [C] [libyal/libevtx](https://github.com/libyal/libevtx) Library and tools to access the Windows XML Event Log (EVTX) format
- [**97**星][3y] [C++] [luctalpe/wmimon](https://github.com/luctalpe/wmimon) Tool to monitor WMI activity on Windows
- [**96**星][2y] [PS] [australiancybersecuritycentre/windows_event_logging](https://github.com/australiancybersecuritycentre/windows_event_logging) Windows Event Forwarding subscriptions, configuration files and scripts that assist with implementing ACSC's protect publication, Technical Guidance for Windows Event Logging.
- [**96**星][4y] [PS] [nsacyber/certificate-authority-situational-awareness](https://github.com/nsacyber/Certificate-Authority-Situational-Awareness) Identifies unexpected and prohibited certificate authority certificates on Windows systems. #nsacyber
- [**94**星][10m] [PS] [equk/windows](https://github.com/equk/windows)  tweaks for Windows
- [**93**星][2y] [C++] [kentonv/dvorak-qwerty](https://github.com/kentonv/dvorak-qwerty) "Dvorak-Qwerty ⌘" (DQ) keyboard layout for Windows and Unix/Linux/X
- [**89**星][2y] [PS] [realparisi/wmi_monitor](https://github.com/realparisi/wmi_monitor) Log newly created WMI consumers and processes to the Windows Application event log
- [**89**星][9d] [C++] [sinakarvandi/process-magics](https://github.com/sinakarvandi/process-magics) This is a collection of interesting codes about Windows Process creation.
- [**89**星][14d] [C] [vigem/hidguardian](https://github.com/vigem/hidguardian) Windows kernel-mode driver for controlling access to various input devices.
- [**87**星][1y] [PS] [deepzec/win-portfwd](https://github.com/deepzec/win-portfwd) Powershell script to setup windows port forwarding using native netsh client
- [**87**星][8y] [C] [zoloziak/winnt4](https://github.com/zoloziak/winnt4) Windows NT4 Kernel Source code
- [**86**星][1y] [C++] [malwaretech/appcontainersandbox](https://github.com/malwaretech/appcontainersandbox) An example sandbox using AppContainer (Windows 8+)
- [**86**星][4y] [JS] [nsacyber/locklevel](https://github.com/nsacyber/LOCKLEVEL) A prototype that demonstrates a method for scoring how well Windows systems have implemented some of the top 10 Information Assurance mitigation strategies. #nsacyber
- [**84**星][3y] [C++] [outflanknl/netshhelperbeacon](https://github.com/outflanknl/NetshHelperBeacon) Example DLL to load from Windows NetShell
- [**83**星][1y] [Py] [silascutler/lnkparse](https://github.com/silascutler/lnkparse) Windows Shortcut file (LNK) parser
- [**82**星][2m] [C] [0xcpu/winaltsyscallhandler](https://github.com/0xcpu/winaltsyscallhandler) Some research on AltSystemCallHandlers functionality in Windows 10 20H1 18999
- [**82**星][5y] [C] [nukem9/virtualdbghide](https://github.com/nukem9/virtualdbghide) Windows kernel mode driver to prevent detection of debuggers.
- [**82**星][2y] [Go] [snail007/autostart](https://github.com/snail007/autostart) autostart tools to set your application auto startup after desktop login,only for desktop version of linux , windows , mac.
- [**81**星][4d] [C] [andreybazhan/symstore](https://github.com/andreybazhan/symstore) The history of Windows Internals via symbols.
- [**80**星][3y] [C++] [cbayet/poolsprayer](https://github.com/cbayet/poolsprayer) Simple library to spray the Windows Kernel Pool
- [**80**星][3y] [C++] [wpo-foundation/win-shaper](https://github.com/wpo-foundation/win-shaper) Windows traffic-shaping packet filter
- [**75**星][1m] [C++] [sidyhe/dxx](https://github.com/sidyhe/dxx) Windows Kernel Driver with C++ runtime
- [**74**星][2y] [C++] [eyeofra/winconmon](https://github.com/eyeofra/winconmon) Windows Console Monitoring
- [**72**星][5y] [C#] [khr0x40sh/whitelistevasion](https://github.com/khr0x40sh/whitelistevasion) Collection of scripts, binaries and the like to aid in WhiteList Evasion on a Microsoft Windows Network.
- [**71**星][9m] [PS] [iamrootsh3ll/anchorwatch](https://github.com/iamrootsh3ll/anchorwatch) A Rogue Device Detection Script with Email Alerts Functionality for Windows Subsystem
- [**70**星][4y] [C++] [nccgroup/windowsdaclenumproject](https://github.com/nccgroup/windowsdaclenumproject) A collection of tools to enumerate and analyse Windows DACLs
- [**69**星][11m] [PS] [itskindred/winportpush](https://github.com/itskindred/winportpush) A simple PowerShell utility used for pivoting into internal networks via a compromised Windows host.
- [**68**星][12d] [C++] [nmgwddj/learn-windows-drivers](https://github.com/nmgwddj/learn-windows-drivers) Windows drivers 开发的各个基础示例，包含进程、内存、注册表、回调等管理
- [**68**星][1m] [PS] [dsccommunity/certificatedsc](https://github.com/dsccommunity/CertificateDsc) This DSC Resource module can be used to simplify administration of certificates on a Windows Server.
- [**67**星][4m] [Go] [0xrawsec/gene](https://github.com/0xrawsec/gene) Signature Engine for Windows Event Logs
- [**66**星][1y] [C#] [parsingteam/teleshadow2](https://github.com/parsingteam/teleshadow2) TeleShadow - Telegram Desktop Session Stealer (Windows)
- [**66**星][5y] [C++] [rwfpl/rewolf-dllpackager](https://github.com/rwfpl/rewolf-dllpackager) Simple tool to bundle windows DLLs with PE executable
- [**65**星][8m] [C] [xiao70/x70fsd](https://github.com/xiao70/x70fsd) Windows file system filter drivers(minifilter) to encrypt, compress, or otherwise modify file-based data require some of the most complex kernel software developed for Windows.
- [**63**星][6m] [PS] [rgl/windows-domain-controller-vagrant](https://github.com/rgl/windows-domain-controller-vagrant) Example Windows Domain Controller
- [**62**星][3y] [C] [arvanaghi/windows-dll-injector](https://github.com/arvanaghi/windows-dll-injector) A basic Windows DLL injector in C using CreateRemoteThread and LoadLibrary. Implemented for educational purposes.
- [**62**星][4y] [Py] [poorbillionaire/windows-prefetch-parser](https://github.com/poorbillionaire/windows-prefetch-parser) Parse Windows Prefetch files: Supports XP - Windows 10 Prefetch files
- [**62**星][1y] [tyranid/windows-attacksurface-workshop](https://github.com/tyranid/windows-attacksurface-workshop) Workshop material for a Windows Attack Surface Analysis Workshop
- [**61**星][5y] [C] [evilsocket/libpe](https://github.com/evilsocket/libpe) A C/C++ library to parse Windows portable executables written with speed and stability in mind.
- [**61**星][3y] [C++] [maldevel/driver-loader](https://github.com/maldevel/driver-loader) Windows驱动加载器
- [**61**星][1y] [Py] [srounet/pymem](https://github.com/srounet/pymem) A python library for windows, providing the needed functions to start working on your own with memory editing.
- [**61**星][1y] [C++] [tandasat/debuglogger](https://github.com/tandasat/debuglogger) A software driver that lets you log kernel-mode debug output into a file on Windows.
- [**60**星][3y] [PS] [kevin-robertson/conveigh](https://github.com/kevin-robertson/conveigh) Conveigh is a Windows PowerShell LLMNR/NBNS spoofer detection tool
- [**60**星][1m] [Go] [konimarti/opc](https://github.com/konimarti/opc) OPC DA client in Golang for monitoring and analyzing process data based on Windows COM.
- [**59**星][t] [C++] [henrypp/errorlookup](https://github.com/henrypp/errorlookup) Simple tool for retrieving information about Windows errors codes.
- [**59**星][4y] [Py] [psychomario/pyinject](https://github.com/psychomario/pyinject) A python module to help inject shellcode/DLLs into windows processes
- [**58**星][5y] [C] [hackedteam/soldier-win](https://github.com/hackedteam/soldier-win) RCS Soldier for Windows
- [**57**星][6m] [PS] [gnieboer/gnuradio_windows_build_scripts](https://github.com/gnieboer/gnuradio_windows_build_scripts) A series of Powershell scripts to automatically download, build from source, and install GNURadio and -all- it's dependencies as 64-bit native binaries then package as an msi using Visual Studio 2015
- [**57**星][6y] [Assembly] [hackedteam/core-win64](https://github.com/hackedteam/core-win64) RCS Agent for Windows (64bit)
- [**57**星][2y] [C#] [mch2112/sharp80](https://github.com/mch2112/sharp80) TRS80 Emulator for Windows
- [**55**星][3y] [C#] [nccgroup/mnemosyne](https://github.com/nccgroup/mnemosyne) mnemosyne：通用Windows内存抓取工具
- [**55**星][1y] [C#] [tyranid/windowsruntimesecuritydemos](https://github.com/tyranid/windowsruntimesecuritydemos) Demos for Presentation on Windows Runtime Security
- [**54**星][17d] [Go] [giuliocomi/backoori](https://github.com/giuliocomi/backoori) Tool aided persistence via Windows URI schemes abuse
- [**53**星][2y] [C#] [guardicore/azure_password_harvesting](https://github.com/guardicore/azure_password_harvesting) Plaintext Password harvesting from Azure Windows VMs
- [**53**星][5y] [C++] [hackedteam/core-win32](https://github.com/hackedteam/core-win32) RCS Agent for Windows (32bit)
- [**52**星][2m] [TSQL] [horsicq/xntsv](https://github.com/horsicq/xntsv) XNTSV program for detailed viewing of system structures for Windows.
- [**52**星][1y] [PS] [pldmgg/winadmincenterps](https://github.com/pldmgg/winadmincenterps) Copy of Windows Admin Center (
- [**51**星][1y] [C++] [tomladder/winlib](https://github.com/tomladder/winlib) Windows Manipulation Library (x64, User/Kernelmode)
- [**50**星][7m] [C] [hfiref0x/mpenum](https://github.com/hfiref0x/mpenum) Enumerate Windows Defender threat families and dump their names according category
- [**50**星][3y] [Py] [matthewdunwoody/block-parser](https://github.com/matthewdunwoody/block-parser) Parser for Windows PowerShell script block logs
- [**49**星][3y] [Py] [dfirfpi/dpapilab](https://github.com/dfirfpi/dpapilab) Windows DPAPI laboratory
- [**49**星][3y] [PS] [enclaveconsulting/crypto-pki](https://github.com/enclaveconsulting/crypto-pki) Scripts related to Windows cryptography and PKI.
- [**49**星][6m] [C++] [0x00-0x00/cve-2019-0841-bypass](https://github.com/0x00-0x00/cve-2019-0841-bypass) A fully automatic CVE-2019-0841 bypass targeting all versions of Edge in Windows 10.
- [**48**星][2y] [C++] [cherrypill/system_info](https://github.com/cherrypill/system_info) Hardware information tool for Windows
- [**48**星][27d] [PS] [littl3field/audix](https://github.com/littl3field/audix) Audix is a PowerShell tool to quickly configure the Windows Event Audit Policies for security monitoring
- [**47**星][7m] [Go] [hectane/go-acl](https://github.com/hectane/go-acl) Go library for manipulating ACLs on Windows
- [**47**星][1y] [C++] [silica/sandbox](https://github.com/silica/sandbox) Application virtualization tool for Windows
- [**46**星][5m] [C#] [ericzimmerman/prefetch](https://github.com/ericzimmerman/prefetch) Windows Prefetch parser. Supports all known versions from Windows XP to Windows 10.
- [**46**星][2y] [C++] [nccgroup/psr](https://github.com/nccgroup/psr) Pointer Sequence Reverser - enable you to see how Windows C++ application is accessing a particular data member or object.
- [**46**星][2m] [C#] [brunull/pace](https://github.com/brunull/pace) A Remote Access Tool for Windows.
- [**46**星][5d] [Assembly] [borjamerino/windows-one-way-stagers](https://github.com/BorjaMerino/Windows-One-Way-Stagers) Windows Stagers to circumvent restrictive network environments
- [**45**星][3y] [C] [gentilkiwi/basic_rpc](https://github.com/gentilkiwi/basic_rpc) Samples about Microsoft RPC and native API calls in Windows C
- [**45**星][10d] [TSQL] [kacos2000/windowstimeline](https://github.com/kacos2000/windowstimeline) SQLite query & Powershell scripts to parse the Windows 10 (v1803+) ActivitiesCache.db
- [**45**星][3y] [PS] [lazywinadmin/winformps](https://github.com/lazywinadmin/winformps) PowerShell functions for Windows Forms controls
- [**45**星][20d] [C#] [damonmohammadbagher/nativepayload_reverseshell](https://github.com/damonmohammadbagher/nativepayload_reverseshell) This is Simple C# Source code to Bypass almost "all" AVS, (kaspersky v19, Eset v12 v13 ,Trend-Micro v16, Comodo & Windows Defender Bypassed via this method Very Simple)
- [**44**星][5d] [Py] [technowlogy-pushpender/technowhorse](https://github.com/technowlogy-pushpender/technowhorse) TechNowHorse is a RAT (Remote Administrator Trojan) Generator for Windows/Linux systems written in Python 3.
- [**43**星][9m] [C] [souhailhammou/drivers](https://github.com/souhailhammou/drivers) Windows Drivers
- [**42**星][2y] [C] [nixawk/awesome-windows-debug](https://github.com/nixawk/awesome-windows-debug) Debug Windows Application / Kernel
- [**42**星][6m] [Visual Basic .NET] [s1egesystems/ghostsquadhackers-javascript-encrypter-encoder](https://github.com/s1egesystems/ghostsquadhackers-javascript-encrypter-encoder) Encrypt/Encode your Javascript code. (Windows Scripting)
- [**42**星][1y] [C++] [3gstudent/windows-eventlog-bypass](https://github.com/3gstudent/Windows-EventLog-Bypass) Use subProcessTag Value From TEB to identify Event Log Threads
- [**41**星][3y] [PS] [sikkandar-sha/sec-audit](https://github.com/sikkandar-sha/sec-audit) PowerShell Script for Windows Server Compliance / Security Configuration Audit
- [**40**星][1y] [Py] [mnrkbys/vss_carver](https://github.com/mnrkbys/vss_carver) Carves and recreates VSS catalog and store from Windows disk image.
- [**40**星][6m] [Py] [silv3rhorn/artifactextractor](https://github.com/silv3rhorn/artifactextractor) Extract common Windows artifacts from source images and VSCs
- [**39**星][3y] [C] [scubsrgroup/taint-analyse](https://github.com/scubsrgroup/taint-analyse) Windows平台下的细粒度污点分析工具
- [**39**星][6m] [HTML] [sophoslabs/cve-2019-0888](https://github.com/sophoslabs/cve-2019-0888) PoC for CVE-2019-0888 - Use-After-Free in Windows ActiveX Data Objects (ADO)
- [**38**星][1y] [C++] [3gstudent/eventlogedit-evt--general](https://github.com/3gstudent/eventlogedit-evt--general) Remove individual lines from Windows Event Viewer Log (EVT) files
- [**38**星][5m] [C#] [nyan-x-cat/disable-windows-defender](https://github.com/nyan-x-cat/disable-windows-defender) Changing values to bypass windows defender C#
- [**38**星][2y] [Py] [roothaxor/pystat](https://github.com/roothaxor/pystat) Advanced Netstat Using Python For Windows
- [**38**星][3y] [C++] [yejiansnake/windows-sys-base](https://github.com/yejiansnake/windows-sys-base) windows 系统API C++封装库，包含进程间通讯，互斥，内存队列等通用功能
- [**37**星][1y] [C++] [rokups/reflectiveldr](https://github.com/rokups/reflectiveldr) Position-idependent Windows DLL loader based on ReflectiveDLL project.
- [**36**星][4y] [PS] [5alt/zerorat](https://github.com/5alt/zerorat) ZeroRAT是一款windows上的一句话远控
- [**36**星][5y] [C++] [kkar/teamviewer-dumper-in-cpp](https://github.com/kkar/teamviewer-dumper-in-cpp) Dumps TeamViewer ID,Password and account settings from a running TeamViewer instance by enumerating child windows.
- [**36**星][4y] [C++] [n3k/ekoparty2015_windows_smep_bypass](https://github.com/n3k/ekoparty2015_windows_smep_bypass) Windows SMEP Bypass U=S
- [**36**星][1y] [C] [realoriginal/alpc-diaghub](https://github.com/realoriginal/alpc-diaghub) Utilizing the ALPC Flaw in combiniation with Diagnostics Hub as found in Server 2016 and Windows 10.
- [**35**星][4d] [PS] [dsccommunity/xfailovercluster](https://github.com/dsccommunity/xFailOverCluster) This module contains DSC resources for deployment and configuration of Windows Server Failover Cluster.
- [**35**星][6m] [PS] [swisscom/powergrr](https://github.com/swisscom/powergrr) PowerGRR is an API client library in PowerShell working on Windows, Linux and macOS for GRR automation and scripting.
- [**35**星][6m] [C++] [parkovski/wsudo](https://github.com/parkovski/wsudo) Proof of concept sudo for Windows
- [**34**星][5m] [C++] [blackint3/none](https://github.com/blackint3/none) UNONE and KNONE is a couple of open source base library that makes it easy to develop software on Windows.
- [**34**星][30d] [C#] [ericzimmerman/appcompatcacheparser](https://github.com/ericzimmerman/appcompatcacheparser) AppCompatCache (shimcache) parser. Supports Windows 7 (x86 and x64), Windows 8.x, and Windows 10
- [**34**星][1y] [PS] [ptylenda/kubernetes-for-windows](https://github.com/ptylenda/kubernetes-for-windows) Ansible playbooks and Packer templates for creating hybrid Windows/Linux Kubernetes 1.10+ cluster with experimental Flannel pod network (host-gw backend)
- [**34**星][2y] [C++] [swwwolf/obderef](https://github.com/swwwolf/obderef) Decrement Windows Kernel for fun and profit
- [**34**星][18d] [C] [zfigura/semblance](https://github.com/zfigura/semblance) Disassembler for Windows executables. Supports 16-bit NE (New Executable), MZ (DOS), and PE (Portable Executable, i.e. Win32) files.
- [**33**星][2y] [Batchfile] [3gstudent/winpcap_install](https://github.com/3gstudent/winpcap_install) Auto install WinPcap on Windows(command line)
- [**33**星][3y] [C++] [kingsunc/minidump](https://github.com/kingsunc/minidump) windows软件崩溃解决方案
- [**32**星][3y] [C++] [ecologylab/ecotuiodriver](https://github.com/ecologylab/ecotuiodriver) Diver to convert tuio touch events into windows touch events. Started as GSoC 2012 project.
- [**32**星][3y] [C++] [swwwolf/cbtest](https://github.com/swwwolf/cbtest) Windows kernel-mode callbacks tutorial driver
- [**31**星][5m] [C] [csandker/inmemoryshellcode](https://github.com/csandker/inmemoryshellcode) A Collection of In-Memory Shellcode Execution Techniques for Windows
- [**31**星][8y] [C] [hackedteam/driver-win64](https://github.com/hackedteam/driver-win64) Windows (64bit) agent driver
- [**31**星][2y] [C++] [hsluoyz/rmtsvc](https://github.com/hsluoyz/rmtsvc) A web-based remote desktop & control service for Windows.
- [**30**星][3y] [CSS] [botherder/flexikiller](https://github.com/botherder/flexikiller) flexikiller：移除FlexiSpy 木马（Windows/Mac）
- [**30**星][2y] [C#] [modzero/mod0umleitung](https://github.com/modzero/mod0umleitung) modzero DNS Masquerading Server for Windows
- [**29**星][6y] [Shell] [artemdinaburg/optimizevm](https://github.com/artemdinaburg/optimizevm) Make Windows VMs Faster
- [**29**星][1y] [Py] [skelsec/windows_ad_dos_poc](https://github.com/skelsec/windows_ad_dos_poc) PoC code for crashing windows active directory
- [**29**星][3y] [Py] [6e726d/pywiwi](https://github.com/6e726d/pywiwi) Python Windows Wifi
- [**28**星][1y] [C] [bot-man-jl/wfp-traffic-redirection-driver](https://github.com/bot-man-jl/wfp-traffic-redirection-driver) WFP Traffic Redirection Driver is used to redirect NIC traffic on network layer and framing layer, based on Windows Filtering Platform (WFP).
- [**28**星][2y] [defcon-russia/shortcut_auto_bind](https://github.com/defcon-russia/shortcut_auto_bind) Windows LNK/URL shortcut auto-binding hotkey (not a bug, feature)
- [**28**星][8y] [C] [hackedteam/driver-win32](https://github.com/hackedteam/driver-win32) Windows (32bit) agent driver
- [**28**星][4y] [C] [icewall/forcedelete](https://github.com/icewall/forcedelete) Windows driver including couple different techniques for file removal when regular operation isn't possible.
- [**28**星][5y] [C++] [michael4338/tdi](https://github.com/michael4338/tdi) Windows Kernel Driver - Create a driver device in TDI layer of windows kernel to capture network data packets
- [**28**星][10m] [C#] [raandree/managedpasswordfilter](https://github.com/raandree/managedpasswordfilter) Windows Password Filter that uses managed code internally
- [**27**星][4m] [C#] [717021/pcmgr](https://github.com/717021/pcmgr) Windows 任务管理器重制版 A rebulid version for Windows task manager.
- [**27**星][3y] [C++] [int0/ltmdm64_poc](https://github.com/int0/ltmdm64_poc) ltmdm64_poc：利用ltmdm64.sys 的漏洞绕过 Windows 7 SP1 x64 的代码完整性检查
- [**27**星][7m] [C++] [slyd0g/timestomper](https://github.com/slyd0g/TimeStomper) PoC that manipulates Windows file times using SetFileTime() API
- [**27**星][2y] [Py] [the404hacking/windows-python-rat](https://github.com/the404hacking/windows-python-rat) A New Microsoft Windows Remote Administrator Tool [RAT] with Python by Sir.4m1R.
- [**26**星][7y] [C++] [avalon1610/lpc](https://github.com/avalon1610/lpc) windows LPC library
- [**26**星][3y] [Pascal] [martindrab/vrtuletree](https://github.com/martindrab/vrtuletree) VrtuleTree is a tool that displays information about driver and device objects present in the system and relations between them. Its functionality is very similar to famous DeviceTree, however, VrtuleTree emhasises on stability and support of latest Windows versions
- [**26**星][2y] [C++] [strikerx3/whvpclient](https://github.com/strikerx3/whvpclient) Windows Hypervisor Platform client
- [**26**星][4y] [Py] [stratosphereips/stratospherewindowsips](https://github.com/stratosphereips/StratosphereWindowsIps) The Stratosphere IPS is a free software IPS that uses network behavior to detect and block malicious actions.
- [**25**星][2y] [C++] [apriorit/custom-bootloader](https://github.com/apriorit/custom-bootloader) A demo tutorial for low-level and kernel developers - developing a custom Windows boot loader
- [**25**星][6y] [C++] [dominictobias/detourxs](https://github.com/dominictobias/detourxs) A x86/64 library for detouring functions on Windows OS
- [**24**星][4y] [C] [ltangjian/firewall](https://github.com/ltangjian/firewall) Based on the research of Windows network architecture and the core packet filtering firewall technology, using NDIS intermediate driver, the article achieved the filter of the core layer, and completed the Windows Personal Firewall Design and Implementation.
- [**24**星][5y] [C++] [michael4338/ndis](https://github.com/michael4338/ndis) Windows Kernel Driver - Create a driver device in intermediate layer of Windows kernel based on NDIS, which communicates with and connect upper layer (user mode applications) and lower layer (miniport driver/network card). Create self-defined protocols for transmitting data and control communications by simulating very simple HTTP, TCP and ARP p…
- [**24**星][1y] [Py] [rootm0s/casper](https://github.com/rootm0s/casper) 👻 Socket based RAT for Windows with evasion techniques and other features for control
- [**24**星][4y] [C++] [thecybermind/ipredir](https://github.com/thecybermind/ipredir) IP redirection+NAT for Windows
- [**24**星][2m] [C] [hypersine/windowssudo](https://github.com/HyperSine/WindowsSudo) A linux-like su/sudo on Windows. Transferred from
- [**23**星][3y] [C] [hedgeh/sewindows](https://github.com/hedgeh/sewindows) 在Windows上建立一个开源的强制访问控制框架及SDK。使Windows平台的应用开发者，可以不用关心操作系统底层技术，只用进行简单的SDK调用或配置就可以保护自己的应用程序。
- [**23**星][4y] [JS] [kolanich/cleanunwantedupdates](https://github.com/kolanich/cleanunwantedupdates) A set of scripts to detect updates of Microsoft (TM) Windows (TM) OS which harm users' privacy and uninstall them
- [**22**星][1y] [C] [codereba/netmon](https://github.com/codereba/netmon) network filter driver that control network send speed, based on windows tdi framework.
- [**21**星][4y] [C#] [adamcaudill/curvelock](https://github.com/adamcaudill/curvelock) Experimental File & Message Encryption for Windows
- [**21**星][3y] [Visual Basic .NET] [appsecco/winmanipulate](https://github.com/appsecco/winmanipulate) A simple tool to manipulate window objects in Windows
- [**21**星][2y] [C] [microwave89/drvtricks](https://github.com/microwave89/drvtricks) drvtriks kernel driver for Windows 7 SP1 and 8.1 x64, that tricks around in your system.
- [**21**星][1y] [JS] [mindpointgroup/stig-cli](https://github.com/MindPointGroup/stig-cli) A CLI for perusing DISA STIG content Mac, Linux, and Windows Compatible
- [**20**星][3y] [C++] [andrewgaspar/km-stl](https://github.com/andrewgaspar/km-stl) A drop-in replacement for the C++ STL for kernel mode Windows drivers. The goal is to have implementations for things like the standard algorithms that don't require memory allocations or exceptions, and for implementations of type traits and other compile-time related headers. Full implementation of the STL is a non-goal.
- [**20**星][7m] [C] [mtth-bfft/ntsec](https://github.com/mtth-bfft/ntsec) Standalone tool to explore the security model of Windows and its NT kernel. Use it to introspect privilege assignments and access right assignments, enumerate attack surfaces from the point of view of a sandboxed process, etc.
- [**20**星][1m] [C++] [mullvad/libwfp](https://github.com/mullvad/libwfp) C++ library for interacting with the Windows Filtering Platform (WFP)
- [**20**星][3y] [PS] [rasta-mouse/invoke-loginprompt](https://github.com/rasta-mouse/invoke-loginprompt) Invokes a Windows Security Login Prompt and outputs the clear text password.


### <a id="0af4bd8ca0fd27c9381a2d1fa8b71a1f"></a>事件日志&&事件追踪&&ETW


- [**1228**星][] [JS] [jpcertcc/logontracer](https://github.com/jpcertcc/logontracer) 通过可视化和分析Windows事件日志来调查恶意的Windows登录
- [**609**星][11d] [PS] [sbousseaden/evtx-attack-samples](https://github.com/sbousseaden/evtx-attack-samples) 与特定攻击和利用后渗透技术相关的Windows事件样例
- [**504**星][9m] [C#] [lowleveldesign/wtrace](https://github.com/lowleveldesign/wtrace) Command line tracing tool for Windows, based on ETW.
- [**446**星][8m] [PS] [nsacyber/event-forwarding-guidance](https://github.com/nsacyber/Event-Forwarding-Guidance) 帮助管理员使用Windows事件转发（WEF）收集与安全相关的Windows事件日志
- [**393**星][10m] [Py] [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx) 纯Python编写的Windows事件日志解析器
- [**306**星][24d] [C#] [zodiacon/procmonx](https://github.com/zodiacon/procmonx) 通过Windows事件日志获取与Process Monitor显示的相同的信息，无需内核驱动
- [**282**星][10m] [C#] [nsacyber/windows-event-log-messages](https://github.com/nsacyber/Windows-Event-Log-Messages) 检索Windows二进制文件中嵌入的Windows事件日志消息的定义，并以discoverable的格式提供它们
- [**214**星][2y] [Py] [thiber-org/userline](https://github.com/thiber-org/userline) 从Windows安全事件中查询并报告用户登录关系
- [**146**星][5m] [Py] [fireeye/pywintrace](https://github.com/fireeye/pywintrace) Python 编写的 ETW（Event Tracing for Windows） Wrapper
- [**43**星][2y] [C#] [zacbrown/hiddentreasure-etw-demo](https://github.com/zacbrown/hiddentreasure-etw-demo) 在内存取证中，使用 ETW（Windows事件追踪） 挖掘宝藏的新方式


### <a id="d48f038b58dc921660be221b4e302f70"></a>Sysmon


- [**206**星][1y] [JS] [jpcertcc/sysmonsearch](https://github.com/jpcertcc/sysmonsearch) Investigate suspicious activity by visualizing Sysmon's event log
- [**126**星][5m] [JS] [baronpan/sysmonhunter](https://github.com/baronpan/sysmonhunter) An easy ATT&CK-based Sysmon hunting tool, showing in Blackhat USA 2019 Arsenal
- [**19**星][10m] [Py] [jymcheong/sysmonresources](https://github.com/jymcheong/sysmonresources) Consolidation of various resources related to Microsoft Sysmon & sample data/log
- [**17**星][5m] [olafhartong/sysmon-configs](https://github.com/olafhartong/sysmon-configs) Various complete configs
- [**12**星][4y] [defensivedepth/sysmon_ossec](https://github.com/defensivedepth/sysmon_ossec) OSSEC Decoder & Rulesets for Sysmon Events
- [**10**星][6m] [sametsazak/sysmon](https://github.com/sametsazak/sysmon) Sysmon and wazuh integration with Sigma sysmon rules [updated]
- [**9**星][1y] [PS] [davebremer/export-sysmonlogs](https://github.com/davebremer/export-sysmonlogs) 
- [**9**星][2y] [kidcrash22/sysmon-threat-intel](https://github.com/kidcrash22/sysmon-threat-intel) 
- [**8**星][11d] [PS] [hestat/ossec-sysmon](https://github.com/hestat/ossec-sysmon) A Ruleset to enhance detection capabilities of Ossec using Sysmon
- [**1**星][2y] [PS] [nick-c/sysmon-installer](https://github.com/nick-c/sysmon-installer) A Sysmon Install script using the Powershell Application Deployment Toolkit
- [**1**星][3m] [PS] [op7ic/sysmonfencer](https://github.com/op7ic/sysmonfencer) A tool designed to help in deployment and log collection for Sysmon across windows domain
- [**0**星][2y] [PS] [stahler/sysmon_powershell](https://github.com/stahler/sysmon_powershell) Sysmon demo with PowerShell examples


### <a id="8ed6f25b321f7b19591ce2908b30cc88"></a>WSL


- [**8566**星][2m] [microsoft/wsl](https://github.com/microsoft/WSL) Issues found on WSL
- [**2845**星][8m] [Shell] [goreliu/wsl-terminal](https://github.com/goreliu/wsl-terminal) Terminal emulator for Windows Subsystem for Linux (WSL)
- [**732**星][3y] [C++] [ionescu007/lxss](https://github.com/ionescu007/lxss) Win10 Linux 子系统相关
- [**681**星][22d] [Shell] [wslutilities/wslu](https://github.com/wslutilities/wslu) A collection of utilities for Windows 10 Linux Subsystems
- [**610**星][4y] [Batchfile] [windowslies/blockwindows](https://github.com/windowslies/blockwindows) Stop Windows 10 Nagging and Spying. Works with Win7-10
- [**469**星][6m] [Go] [dan-v/awslambdaproxy](https://github.com/dan-v/awslambdaproxy) An AWS Lambda powered HTTP/SOCKS web proxy
- [**402**星][5m] [PS] [stefanscherer/docker-windows-box](https://github.com/stefanscherer/docker-windows-box) Various Vagrant envs with Windows 2019/10 and Docker, Swarm mode, LCOW, WSL2, ...
- [**330**星][3y] [C++] [xilun/cbwin](https://github.com/xilun/cbwin) Launch Windows programs from "Bash on Ubuntu on Windows" (WSL)
- [**196**星][2y] [C] [saaramar/execve_exploit](https://github.com/saaramar/execve_exploit) Hardcore corruption of my execve() vulnerability in WSL
- [**77**星][1y] [Shell] [re4son/wsl-kali-x](https://github.com/re4son/wsl-kali-x) Tweaks to run Kali Linux desktop panels and gui apps on Windows 10
- [**62**星][9m] [Py] [jaksi/awslog](https://github.com/jaksi/awslog) Show the history and changes between configuration versions of AWS resources
- [**41**星][2y] [Py] [m0rtem/mailfail](https://github.com/m0rtem/mailfail) Proof of Concept - Utilize misconfigured newsletter forms to spam / deny service to an inbox
- [**37**星][7m] [Batchfile] [cervoise/abuse-bash-for-windows](https://github.com/cervoise/abuse-bash-for-windows) Pentest scripts for abuse Bash on Windows (Cygwin/WSL) - HackLu 2018
- [**35**星][8m] [offensive-security/kali-wsl-chroot](https://github.com/offensive-security/kali-wsl-chroot) Kali Linux Windows App chroot builder script
- [**27**星][5m] [C] [biswa96/wslreverse](https://github.com/biswa96/wslreverse) Experiments with hidden COM interface and LxBus IPC mechanism in WSL
- [**25**星][7m] [Makefile] [mintty/wsltty.appx](https://github.com/mintty/wsltty.appx) 
- [**14**星][11d] [Shell] [thehackingsage/kali-wsl](https://github.com/thehackingsage/kali-wsl) Update, Upgrade, XFCE4 - GUI Mode & Hacking Tools for Kali Linux Windows App
- [**0**星][2y] [Ruby] [rbnpercy/iron_newsletter](https://github.com/rbnpercy/iron_newsletter) Scheduled developer newsletter with IronWorker and Mailgun


### <a id="d90b60dc79837e06d8ba2a7ee1f109d3"></a>.NET


- [**12676**星][6d] [C#] [0xd4d/dnspy](https://github.com/0xd4d/dnspy) .NET debugger and assembly editor
- [**9261**星][3d] [C#] [icsharpcode/ilspy](https://github.com/icsharpcode/ilspy) .NET Decompiler
- [**3694**星][19d] [C#] [0xd4d/de4dot](https://github.com/0xd4d/de4dot) .NET deobfuscator and unpacker.
- [**3263**星][7m] [JS] [sindresorhus/speed-test](https://github.com/sindresorhus/speed-test) Test your internet connection speed and ping using speedtest.net from the CLI
- [**1657**星][6d] [C#] [jbevain/cecil](https://github.com/jbevain/cecil) C#库, 探查/修改/生成 .NET App/库
- [**251**星][1y] [C#] [brianhama/de4dot](https://github.com/brianhama/de4dot) .NET deobfuscator and unpacker.
- [**217**星][11m] [C#] [rainwayapp/warden](https://github.com/rainwayapp/warden) Warden.NET is an easy to use process management library for keeping track of processes on Windows.
- [**173**星][2m] [ASP] [lowleveldesign/debug-recipes](https://github.com/lowleveldesign/debug-recipes) My notes collected while debugging various .NET and Windows problems.
- [**70**星][8m] [C#] [fsecurelabs/sharpcliphistory](https://github.com/FSecureLABS/SharpClipHistory) SharpClipHistory is a .NET application written in C# that can be used to read the contents of a user's clipboard history in Windows 10 starting from the 1809 Build.
- [**52**星][8d] [C#] [9ee1/capstone.net](https://github.com/9ee1/capstone.net) .NET Core and .NET Framework binding for the Capstone Disassembly Framework


### <a id="6d2fe834b7662ecdd48c17163f732daf"></a>Environment&&环境&&配置


- [**1521**星][10m] [PS] [joefitzgerald/packer-windows](https://github.com/joefitzgerald/packer-windows) 使用Packer创建Vagrant boxes的模板
- [**1347**星][23d] [Go] [securitywithoutborders/hardentools](https://github.com/securitywithoutborders/hardentools) 禁用许多有危险的Windows功能
- [**1156**星][1y] [HTML] [nsacyber/windows-secure-host-baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline) Windows 10和Windows Server 2016 DoD 安全主机基准设置的配置指南
- [**1008**星][6m] [adolfintel/windows10-privacy](https://github.com/adolfintel/windows10-privacy) Win10隐私指南
- [**508**星][8d] [PS] [stefanscherer/packer-windows](https://github.com/stefanscherer/packer-windows) Windows Packer 模板：Win10, Server 2016, 1709, 1803, 1809, 2019, 1903, Insider with Docker


### <a id="8bfd27b42bb75956984994b3419fb582"></a>进程注入




### <a id="b0d50ee42d53b1f88b32988d34787137"></a>DLL注入


- [**713**星][5m] [C++] [darthton/xenos](https://github.com/darthton/xenos) Windows DLL 注入器


### <a id="1c6069610d73eb4246b58d78c64c9f44"></a>代码注入




### <a id="7c1541a69da4c025a89b0571d8ce73d2"></a>内存模块




### <a id="16001cb2fae35b722deaa3b9a8e5f4d5"></a>Shellcode


- [**686**星][10m] [Py] [merrychap/shellen](https://github.com/merrychap/shellen) 交互式Shellcode开发环境
- [**588**星][2m] [PS] [monoxgas/srdi](https://github.com/monoxgas/srdi) Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
- [**536**星][5m] [C++] [nytrorst/shellcodecompiler](https://github.com/nytrorst/shellcodecompiler) 将C/C ++样式代码编译成一个小的、与位置无关且无NULL的Shellcode，用于Windows（x86和x64）和Linux（x86和x64）
    - 重复区段: [Linux->工具](#89e277bca2740d737c1aeac3192f374c) |
- [**509**星][3y] [Py] [reyammer/shellnoob](https://github.com/reyammer/shellnoob) A shellcode writing toolkit
- [**388**星][1y] [Assembly] [hasherezade/pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode) Converts PE into a shellcode
- [**244**星][6y] [C++] [clinicallyinane/shellcode_launcher](https://github.com/clinicallyinane/shellcode_launcher) Shellcode launcher utility
- [**234**星][4y] [Py] [pyana/pyana](https://github.com/pyana/pyana) 使用Unicorn框架模拟执行Shellcode(Windows)
- [**203**星][2y] [Py] [rootlabs/smap](https://github.com/suraj-root/smap) Handy tool for shellcode analysis
- [**189**星][1y] [Py] [thesecondsun/shellab](https://github.com/thesecondsun/shellab) Shellcode开发/丰富工具，支持Windows/Linux
- [**182**星][6m] [C++] [jackullrich/shellcodestdio](https://github.com/jackullrich/shellcodestdio) 辅助编写Windows平台的位置无关Shellcode，支持x86/x64
- [**169**星][17d] [C] [odzhan/shellcode](https://github.com/odzhan/shellcode) 针对Windows/Linux/BSD的Shellcode
- [**154**星][2y] [Py] [secretsquirrel/fido](https://github.com/secretsquirrel/fido) Teaching old shellcode new tricks
- [**153**星][3y] [C] [ixty/xarch_shellcode](https://github.com/ixty/xarch_shellcode) Cross Architecture Shellcode in C
- [**152**星][6m] [Assembly] [peterferrie/win-exec-calc-shellcode](https://github.com/peterferrie/win-exec-calc-shellcode) 执行calc.exe的Shellcode (x86/x64, 所有版本/SPs)
- [**148**星][] [Go] [brimstone/go-shellcode](https://github.com/brimstone/go-shellcode) Load shellcode into a new process
- [**145**星][3m] [Pascal] [coldzer0/cmulator](https://github.com/coldzer0/cmulator) Cmulator is ( x86 - x64 ) Scriptable Reverse Engineering Sandbox Emulator for shellcode and PE binaries . Based on Unicorn & Zydis Engine & javascript
- [**133**星][2m] [C#] [fireeye/duedlligence](https://github.com/fireeye/duedlligence) Shellcode runner for all application whitelisting bypasses
- [**126**星][4y] [Assembly] [osirislab/shellcode](https://github.com/osirislab/Shellcode) a repository of Shellcode written by students in NYU-Polytechnic's ISIS lab.
- [**123**星][6y] [tombkeeper/shellcode_template_in_c](https://github.com/tombkeeper/shellcode_template_in_c) 
- [**123**星][2y] [C#] [zerosum0x0/runshellcode](https://github.com/zerosum0x0/runshellcode) .NET GUI program that runs shellcode
- [**111**星][5y] [C] [mariovilas/shellcode_tools](https://github.com/mariovilas/shellcode_tools) Miscellaneous tools written in Python, mostly centered around shellcodes.
- [**91**星][8m] [C] [fireeye/flare-kscldr](https://github.com/fireeye/flare-kscldr) 内核中加载Shellcode: 实例、方法与工具
- [**91**星][3y] [C++] [gdelugre/shell-factory](https://github.com/gdelugre/shell-factory) C++-based shellcode builder
- [**88**星][4y] [Py] [mothran/unicorn-decoder](https://github.com/mothran/unicorn-decoder) Simple shellcode decoder using unicorn-engine
- [**87**星][2y] [Py] [alexpark07/armscgen](https://github.com/alexpark07/armscgen) ARM Shellcode Generator
- [**78**星][3y] [Py] [hatriot/shellme](https://github.com/hatriot/shellme) simple shellcode generator
- [**76**星][2y] [Py] [blacknbunny/shellcodetoassembly](https://github.com/blacknbunny/shellcodetoassembly) 
- [**75**星][3m] [C++] [shellvm/shellvm](https://github.com/shellvm/shellvm) A collection of LLVM transform and analysis passes to write shellcode in regular C
- [**66**星][3y] [Assembly] [scorchsecurity/systorm](https://github.com/scorchsecurity/systorm) NASM Standard Library for shellcode
- [**65**星][8m] [C] [dimopouloselias/simpleshellcodeinjector](https://github.com/dimopouloselias/simpleshellcodeinjector) SimpleShellcodeInjector receives as an argument a shellcode in hex and executes it. It DOES NOT inject the shellcode in a third party application.
- [**61**星][4y] [Py] [veil-framework/veil-ordnance](https://github.com/veil-framework/veil-ordnance) Veil-Ordnance is a tool designed to quickly generate MSF stager shellcode
- [**59**星][3y] [C] [k2/admmutate](https://github.com/k2/admmutate) Classic code from 1999+ I am fairly sure this is the first public polymorphic shellcode ever (best IMHO and others
- [**56**星][6y] [C] [devzero2000/shellcoderhandbook](https://github.com/devzero2000/shellcoderhandbook) shellcoderhandbook source code : "The Shellcoder's Handbook: Discovering and Exploiting Security Holes"
- [**56**星][3y] [C] [zerosum0x0/shellcodedriver](https://github.com/zerosum0x0/shellcodedriver) Windows driver to execute arbitrary usermode code (essentially same vulnerability as capcom.sys)
- [**54**星][2y] [C++] [sisoma2/shellcodeloader](https://github.com/sisoma2/shellcodeloader) Small tool to load shellcodes or PEs to analyze them
- [**44**星][1y] [Py] [ecx86/shellcode_encoder](https://github.com/ecx86/shellcode_encoder) x64 printable shellcode encoder
- [**43**星][5y] [Py] [borjamerino/tlsinjector](https://github.com/borjamerino/tlsinjector) Python script to inject and run shellcodes through TLS callbacks
- [**43**星][5m] [C] [w1nds/dll2shellcode](https://github.com/w1nds/dll2shellcode) dll转shellcode工具
- [**43**星][2y] [C] [p0cl4bs/shellcodes](https://github.com/p0cl4bs/shellcodes) 
- [**43**星][8y] [C] [hellman/shtest](https://github.com/hellman/shtest) Simple shellcode testing tool.
- [**42**星][1y] [C++] [userexistserror/dllloadershellcode](https://github.com/userexistserror/dllloadershellcode) Shellcode to load an appended Dll
- [**40**星][2y] [Py] [karttoon/trigen](https://github.com/karttoon/trigen) Trigen is a Python script which uses different combinations of Win32 function calls in generated VBA to execute shellcode.
- [**40**星][1y] [Assembly] [therealsaumil/arm_shellcode](https://github.com/therealsaumil/arm_shellcode) Make ARM Shellcode Great Again
- [**37**星][2y] [C++] [3gstudent/shellcode-generater](https://github.com/3gstudent/shellcode-generater) No inline asm,support x86/x64
- [**37**星][3y] [Py] [dungtv543/dutas](https://github.com/dungtv543/dutas) Analysis PE file or Shellcode
- [**36**星][3y] [Assembly] [mortenschenk/token-stealing-shellcode](https://github.com/mortenschenk/token-stealing-shellcode) 
- [**35**星][3y] [Py] [n1nj4sec/pymemimporter](https://github.com/n1nj4sec/pymemimporter) import pyd or execute PE all from memory using only pure python code and some shellcode tricks
- [**34**星][16d] [Py] [skybulk/bin2sc](https://github.com/skybulk/bin2sc) Binary to shellcode
- [**33**星][4y] [C++] [5loyd/makecode](https://github.com/5loyd/makecode) Dll Convert to Shellcode.
- [**33**星][2y] [HTML] [rh0dev/shellcode2asmjs](https://github.com/rh0dev/shellcode2asmjs) Automatically generate ASM.JS JIT-Spray payloads
- [**27**星][6y] [C] [hacksysteam/shellcodeofdeath](https://github.com/hacksysteam/shellcodeofdeath) Shellcode Of Death
- [**27**星][2y] [Py] [ihack4falafel/slink](https://github.com/ihack4falafel/slink) Alphanumeric Shellcode (x86) Encoder
- [**27**星][2y] [Py] [taroballzchen/shecodject](https://github.com/TaroballzChen/shecodject) shecodject is a autoscript for shellcode injection by Python3 programing
- [**26**星][3y] [Ruby] [eik00d/reverse_dns_shellcode](https://github.com/eik00d/reverse_dns_shellcode) Revrese DNS payload for Metasploit: Download Exec x86 shellcode. Also DNS Handler and VBS bot (alsow working over DNS) as PoC included.
- [**26**星][4y] [C] [ufrisk/shellcode64](https://github.com/ufrisk/shellcode64) A minimal tool to extract shellcode from 64-bit PE binaries.
- [**24**星][3y] [C] [osandamalith/shellcodes](https://github.com/osandamalith/shellcodes) My Shellcode Archive
- [**21**星][3y] [Visual Basic .NET] [osandamalith/vbshellcode](https://github.com/osandamalith/vbshellcode) Making shellcode UD -
- [**21**星][3y] [Py] [thomaskeck/pyshellcode](https://github.com/thomaskeck/pyshellcode) Execute ShellCode / "Inline-Assembler" in Python
- [**20**星][2m] [Go] [binject/shellcode](https://github.com/binject/shellcode) Shellcode library as a Go package
- [**20**星][1y] [Py] [danielhenrymantilla/shellcode-factory](https://github.com/danielhenrymantilla/shellcode-factory) Tool to create and test shellcodes from custom assembly sources (with some encoding options)
- [**20**星][2m] [Assembly] [pinkp4nther/shellcodes](https://github.com/pinkp4nther/shellcodes) I'll post my custom shellcode I make here!
- [**20**星][15d] [Py] [zerosteiner/crimson-forge](https://github.com/zerosteiner/crimson-forge) Sustainable shellcode evasion
- [**19**星][4y] [Assembly] [bruce30262/x86_shellcode_tutorial](https://github.com/bruce30262/x86_shellcode_tutorial) A training course for BambooFox
- [**19**星][4y] [C] [jorik041/cymothoa](https://github.com/jorik041/cymothoa) Cymothoa is a backdooring tool, that inject backdoor's shellcode directly into running applications. Stealth and lightweight...
- [**18**星][3y] [Py] [0xyg3n/mem64](https://github.com/0xyg3n/mem64) Run Any Native PE file as a memory ONLY Payload , most likely as a shellcode using hta attack vector which interacts with Powershell.
- [**18**星][3y] [Py] [after1990s/pe2shellcode](https://github.com/after1990s/pe2shellcode) pe2shellcode
- [**16**星][2y] [Py] [hamza-megahed/pentest-with-shellcode](https://github.com/hamza-megahed/pentest-with-shellcode) Penetration testing with shellcode codes
- [**16**星][2y] [PLpgSQL] [michaelburge/redshift-shellcode](https://github.com/michaelburge/redshift-shellcode) Example of injecting x64 shellcode into Amazon Redshift
- [**15**星][3y] [C++] [naxalpha/shellcode-loader](https://github.com/naxalpha/shellcode-loader) Shellcode Loader Engine for Windows
- [**15**星][4y] [Assembly] [novicelive/shellcoding](https://github.com/novicelive/shellcoding) Introduce you to shellcode development.
- [**15**星][2y] [Py] [nullarray/shellware](https://github.com/nullarray/shellware) Persistent bind shell via pythonic shellcode execution, and registry tampering.
- [**14**星][2y] [chango77747/shellcodeinjector_msbuild](https://github.com/chango77747/shellcodeinjector_msbuild) 
- [**12**星][10m] [Perl 6] [anon6372098/faz-shc](https://github.com/anon6372098/faz-shc) Faz-SHC is a program that can be encrypted the text you give to a Shellcode. Simple and coded with Perl. Coded by M.Fazri Nizar.
- [**11**星][5y] [Py] [debasishm89/qhook](https://github.com/debasishm89/qhook) qHooK is very simple python script (dependent on pydbg) which hooks user defined Win32 APIs in any process and monitor then while process is running and at last prepare a CSV report with various interesting information which can help reverse engineer to track down / analyse unknown exploit samples / shellcode.
- [**11**星][5m] [C] [hc0d3r/scdump](https://github.com/hc0d3r/scdump) shellcode dumper
- [**11**星][3y] [zdresearch/zcr-shellcoder-archive](https://github.com/zdresearch/zcr-shellcoder-archive) ZeroDay Cyber Research - ZCR Shellcoder Archive - z3r0d4y.com Shellcode Generator
- [**10**星][4y] [Py] [davinci13/exe2shell](https://github.com/davinci13/exe2shell) Converts exe to shellcode.
- [**10**星][12m] [C++] [egebalci/injector](https://github.com/egebalci/injector) Simple shellcode injector.
- [**10**星][2y] [Perl] [gnebbia/shellcoder](https://github.com/gnebbia/shellcoder) Create shellcode from executable or assembly code
- [**10**星][5m] [Assembly] [egebalci/selfdefense](https://github.com/EgeBalci/SelfDefense) Several self-defense shellcodes
- [**9**星][11m] [C] [eahlstrom/ucui-unicorn](https://github.com/eahlstrom/ucui-unicorn) ncurses shellcode/instructions tester using unicorn-engine
- [**8**星][2y] [Py] [1project/scanr](https://github.com/1project/scanr) Detect x86 shellcode in files and traffic.
- [**8**星][1y] [C#] [antebyte/shellgen](https://github.com/antebyte/shellgen) Dynamic and extensible shell code generator with multiple output types which can be formatted in binary, hexadecimal, and the typical shellcode output standard.
- [**8**星][2y] [Py] [breaktoprotect/shellcarver](https://github.com/breaktoprotect/shellcarver) shellcarver：使用限制字符集在内存雕刻（Carve ） shellcode。手动版的 msfvenom -b
- [**8**星][5y] [hoainam1989/shellcode](https://github.com/hoainam1989/shellcode) Tut for making Linux Shellcode
- [**8**星][1y] [C++] [xiaobo93/unmodule_shellcode_inject](https://github.com/xiaobo93/unmodule_shellcode_inject) 无模块注入工程 VS2008
- [**8**星][4y] [Py] [sectool/python-shellcode-buffer-overflow](https://github.com/sectool/Python-Shellcode-Buffer-Overflow) Shellcode / Buffer Overflow
- [**7**星][3y] [Assembly] [mortenschenk/acl_edit](https://github.com/mortenschenk/acl_edit) Assembly code to use for Windows kernel shellcode to edit winlogon.exe ACL
- [**7**星][11m] [Py] [veritas501/ae64](https://github.com/veritas501/ae64) basic amd64 alphanumeric shellcode encoder
- [**7**星][8m] [C] [lnslbrty/bufflow](https://github.com/lnslbrty/bufflow) A collection of security related code examples e.g. a buffer overflow including an exploit, crypters, shellcodes and more.
- [**6**星][3y] [C] [degrigis/exploitation](https://github.com/degrigis/exploitation) Repo for various exploitation utilities/PoC/Shellcodes/CTF solutions
- [**6**星][5y] [Assembly] [govolution/win32shellcode](https://github.com/govolution/win32shellcode) 
- [**6**星][3y] [Java] [jlxip/shellcode-ide](https://github.com/jlxip/shellcode-ide) An IDE for creating shellcodes.
- [**5**星][8m] [C++] [giantbranch/convert-c-javascript-shellcode](https://github.com/giantbranch/convert-c-javascript-shellcode) C与javascript格式的shellcode相互转换小工具
- [**4**星][4y] [Assembly] [theevilbit/shellcode](https://github.com/theevilbit/shellcode) Some random shellcodes I created
- [**4**星][2y] [Shell] [thepisode/linux-shellcode-generator](https://github.com/thepisode/linux-shellcode-generator) Experiments on Linux Assembly shellcodes injection
- [**3**星][1y] [Py] [manojcode/foxit-reader-rce-with-virualalloc-and-shellcode-for-cve-2018-9948-and-cve-2018-9958](https://github.com/manojcode/foxit-reader-rce-with-virualalloc-and-shellcode-for-cve-2018-9948-and-cve-2018-9958) Foxit Reader version 9.0.1.1049 Use After Free with ASLR and DEP bypass on heap
- [**3**星][2y] [C] [samvartaka/triton_analysis](https://github.com/samvartaka/triton_analysis) Analysis of the TRITON/TRISIS/HatMan multi-stage PowerPC shellcode payload
- [**3**星][1y] [C] [wanttobeno/study_shellcode](https://github.com/wanttobeno/study_shellcode) windows平台下功能性shellcode的编写
- [**2**星][2y] [C] [brimstone/shellload](https://github.com/brimstone/shellload) Load shellcode into a new process, optionally under a false name.
- [**2**星][5y] [Assembly] [govolution/moreshellcode](https://github.com/govolution/moreshellcode) 
- [**2**星][7y] [C] [hamza-megahed/binary2shellcode](https://github.com/hamza-megahed/binary2shellcode) binary to shellcode converter
- [**2**星][4y] [Makefile] [sh3llc0d3r1337/slae32-custom-encoder](https://github.com/sh3llc0d3r1337/slae32-custom-encoder) SLAE32 Assignment #4 - Custom Shellcode
- [**2**星][7y] [hamza-megahed/shellcode](https://github.com/hamza-megahed/shellcode) Linux/x86 Shellcodes
- [**1**星][2y] [orf53975/rig-exploit-for-cve-2018-8174](https://github.com/orf53975/rig-exploit-for-cve-2018-8174) Rig Exploit for CVE-2018-8174 As with its previous campaigns, Rig’s Seamless campaign uses malvertising. In this case, the malvertisements have a hidden iframe that redirects victims to Rig’s landing page, which includes an exploit for CVE-2018-8174 and shellcode. This enables remote code execution of the shellcode obfuscated in the landing page…
- [**1**星][2y] [Ruby] [shayanzare/obj2shellcode](https://github.com/shayanzare/obj2shellcode) Objdump to ShellCode
- [**1**星][6y] [Assembly] [stephenbradshaw/shellcode](https://github.com/stephenbradshaw/shellcode) Various shell code I have written
- [**1**星][28d] [Py] [ins1gn1a/woollymammoth](https://github.com/ins1gn1a/woollymammoth) Toolkit for manual buffer exploitation, which features a basic network socket fuzzer, offset pattern generator and detector, bad character identifier, shellcode carver, and a vanilla EIP exploiter
- [**0**星][2y] [Assembly] [felixzhang00/shellcode_example](https://github.com/felixzhang00/shellcode_example) 
- [**0**星][1y] [Py] [orangepirate/cve-2018-9948-9958-exp](https://github.com/orangepirate/cve-2018-9948-9958-exp) a exp for cve-2018-9948/9958 , current shellcode called win-calc
- [**0**星][7m] [pcsxcetra/equationeditorshellcodedecoder](https://github.com/pcsxcetra/equationeditorshellcodedecoder) Tool to decode the encoded Shellcode of this type found in office documents
- [**0**星][5y] [C] [quantumvm/forkshellcode](https://github.com/quantumvm/forkshellcode) Runs and executable and forks shellcode.
- [**0**星][4y] [Makefile] [sh3llc0d3r1337/slae32-polymorphic-shellcodes](https://github.com/sh3llc0d3r1337/slae32-polymorphic-shellcodes) SLAE32 Assignment #6 - Polymorphic shellcodes
- [**0**星][5y] [Py] [wjlandryiii/shellcode](https://github.com/wjlandryiii/shellcode) my shellcode
- [**0**星][5y] [Py] [yatebyalubaluniyat/rawshellcode2exe](https://github.com/yatebyalubaluniyat/rawshellcode2exe) converts raw shellcode to exe


### <a id="19cfd3ea4bd01d440efb9d4dd97a64d0"></a>VT&&虚拟化&&Hypbervisor


- [**1348**星][14d] [C] [intel/haxm](https://github.com/intel/haxm) Intel 开源的英特尔硬件加速执行管理器，通过硬件辅助的虚拟化引擎，加速 Windows/macOS 主机上的 IA emulation（(x86/ x86_64) ）
- [**1011**星][1y] [C] [ionescu007/simplevisor](https://github.com/ionescu007/simplevisor) 英特尔VT-x虚拟机管理程序，简单、可移植。支持Windows和UEFI
- [**717**星][15d] [C++] [tandasat/hyperplatform](https://github.com/tandasat/hyperplatform) 基于Intel VT-x的虚拟机管理程序，旨在在Windows上提供精简的VM-exit过滤平台
- [**570**星][11m] [C] [asamy/ksm](https://github.com/asamy/ksm) 快速、hackable且简单的x64 VT-x虚拟机管理程序，支持Windows和Linux
    - 重复区段: [Linux->工具](#89e277bca2740d737c1aeac3192f374c) |
- [**449**星][2y] [POV-Ray SDL] [hzqst/syscall-monitor](https://github.com/hzqst/syscall-monitor) 使用Intel VT-X/EPT实现的系统调用追踪工具，类似于Sysinternal的Process Monitor，支持Win7+
    - 重复区段: [Windows->工具->系统调用](#d295182c016bd9c2d5479fe0e98a75df) |
- [**189**星][10m] [C++] [kelvinhack/khypervisor](https://github.com/kelvinhack/khypervisor) 适用于Windows的类似于bluepill的轻量级、嵌套VMM，提供并模拟英特尔VT-x的基本功能


### <a id="c3cda3278305549f4c21df25cbf638a4"></a>内核&&驱动


- [**933**星][9m] [C] [microsoft/windows-driver-frameworks](https://github.com/microsoft/windows-driver-frameworks) Windows驱动框架(WDF)
- [**781**星][11d] [axtmueller/windows-kernel-explorer](https://github.com/axtmueller/windows-kernel-explorer) Windows内核研究工具
- [**510**星][5m] [Py] [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus) Windows内核探索和跟踪工具
- [**479**星][1m] [C] [jkornev/hidden](https://github.com/jkornev/hidden) Windows驱动，带用户模式接口：隐藏文件系统和注册表对象、保护进程等
- [**325**星][2y] [Rust] [pravic/winapi-kmd-rs](https://github.com/pravic/winapi-kmd-rs) Rust编写的Windows内核模式驱动
- [**278**星][2y] [C++] [sam-b/windows_kernel_address_leaks](https://github.com/sam-b/windows_kernel_address_leaks) Windows上从用户模式泄漏内核模式信息的示例
- [**278**星][4d] [PS] [microsoftdocs/windows-driver-docs](https://github.com/MicrosoftDocs/windows-driver-docs) 官方Windows驱动程序工具包文档
- [**232**星][4y] [C] [markjandrews/wrk-v1.2](https://github.com/markjandrews/wrk-v1.2) Windows研究内核


### <a id="920b69cea1fc334bbc21a957dd0d9f6f"></a>注册表


- [**490**星][6d] [Batchfile] [chef-koch/regtweaks](https://github.com/chef-koch/regtweaks) Windows注册表调整（Win 7-Win 10）
- [**288**星][8m] [Py] [williballenthin/python-registry](https://github.com/williballenthin/python-registry) 用于对Windows NT注册表文件进行纯读取访问的Python库
- [**161**星][1y] [msuhanov/regf](https://github.com/msuhanov/regf) Windows注册表文件格式规范


### <a id="d295182c016bd9c2d5479fe0e98a75df"></a>系统调用


- [**725**星][2m] [HTML] [j00ru/windows-syscalls](https://github.com/j00ru/windows-syscalls) Windows 系统调用表(NT/2000/XP/2003/Vista/2008/7/2012/8/10)
- [**449**星][2y] [POV-Ray SDL] [hzqst/syscall-monitor](https://github.com/hzqst/syscall-monitor) 使用Intel VT-X/EPT实现的系统调用追踪工具，类似于Sysinternal的Process Monitor，支持Win7+
    - 重复区段: [Windows->工具->VT](#19cfd3ea4bd01d440efb9d4dd97a64d0) |
- [**328**星][1m] [C] [hfiref0x/syscalltables](https://github.com/hfiref0x/syscalltables) Windows NT x64系统调用表
- [**277**星][2y] [Assembly] [tinysec/windows-syscall-table](https://github.com/tinysec/windows-syscall-table)  Win XP 到 Win 10 的系统调用表，包括 SSDT 和 Shadow SSDT


### <a id="a82bb5fff6cb644fb34db2b257f2061b"></a>加壳&&脱壳


#### <a id="ccd2a4f85dbac99ccbedc745c2768f01"></a>新添加的


- [**261**星][2y] [Py] [countercept/python-exe-unpacker](https://github.com/countercept/python-exe-unpacker) A helper script for unpacking and decompiling EXEs compiled from python code.
- [**212**星][26d] [Shell] [ryran/xsos](https://github.com/ryran/xsos)  instantaneously gather information about a system together in an easy-to-read-summary, whether that system is the localhost on which xsos is being run or a system for which you have an unpacked sosreport
- [**194**星][3m] [Py] [unipacker/unipacker](https://github.com/unipacker/unipacker) Automatic and platform-independent unpacker for Windows binaries based on emulation
- [**134**星][8m] [C] [hfiref0x/wdextract](https://github.com/hfiref0x/wdextract) Extract Windows Defender database from vdm files and unpack it
- [**126**星][5y] [Py] [urule99/jsunpack-n](https://github.com/urule99/jsunpack-n) Automatically exported from code.google.com/p/jsunpack-n
- [**115**星][12m] [C] [d00rt/emotet_research](https://github.com/d00rt/emotet_research)  documentation about the packer of Emotet and its unpacker.
- [**99**星][27d] [Py] [quarkslab/legu_unpacker_2019](https://github.com/quarkslab/legu_unpacker_2019) Scripts to unpack APK protected by Legu
- [**86**星][1y] [Py] [bignerd95/routeros-backup-tools](https://github.com/bignerd95/routeros-backup-tools) Tools to encrypt/decrypt and pack/unpack RouterOS v6.13+ backup files
- [**67**星][1y] [C++] [nickcano/relocbonus](https://github.com/nickcano/relocbonus) An obfuscation tool for Windows which instruments the Windows Loader into acting as an unpacking engine.
- [**64**星][7m] [C++] [fare9/anbu](https://github.com/fare9/anbu) ANBU (Automatic New Binary Unpacker) a tool for me to learn about PIN and about algorithms for generic unpacking.
- [**54**星][2y] [Java] [graxcode/java-unpacker](https://github.com/GraxCode/java-unpacker) Extract Crypted Jar Archives
- [**52**星][2y] [Py] [rolfrolles/finspyvm](https://github.com/rolfrolles/finspyvm) Static unpacker for FinSpy VM
- [**46**星][6d] [C++] [hasherezade/mal_unpack](https://github.com/hasherezade/mal_unpack) Dynamic unpacker based on PE-sieve
- [**35**星][4y] [Py] [laginimaineb/unpack_bootloader_image](https://github.com/laginimaineb/unpack_bootloader_image) Small script to unpack the bootloader image format present in Nexus 5 devices
- [**28**星][6y] [Py] [kholia/exetractor-clone](https://github.com/kholia/exetractor-clone) Unpacker for packed Python executables. Supports PyInstaller and py2exe. This project is not updated anymore. Use "PyInstaller Extractor" and "unpy2exe" instead.
- [**27**星][2y] [C] [1ce0ear/dllloaderunpacker](https://github.com/1ce0ear/dllloaderunpacker) 
- [**21**星][2y] [C] [nviso-be/nexus_5_bootloader_unpacker](https://github.com/nviso-be/nexus_5_bootloader_unpacker) A bootloader imgdata unpacker for Nexus 4, 5 and 7 smartphones as well as imgdata tool for Nexus 5.
- [**15**星][1y] [C++] [mythicmaniac/lol-unpackman](https://github.com/mythicmaniac/lol-unpackman) 
- [**14**星][4y] [Py] [laginimaineb/unpack_motoboot](https://github.com/laginimaineb/unpack_motoboot) Unpacks the Motorola motoboot.img binary
- [**12**星][5y] [Java] [federicodotta/burpjdser-ng-edited](https://github.com/federicodotta/burpjdser-ng-edited) Burp Suite plugin that allow to deserialize Java objects and convert them in an XML format. Unpack also gzip responses. Based on BurpJDSer-ng of omercnet.
- [**12**星][6y] [Ruby] [nvisium/ruby_apk_unpack](https://github.com/nvisium/ruby_apk_unpack) Ruby Gem to Unpack APK(s)
- [**10**星][6y] [C] [frederic/pflupg-tool](https://github.com/frederic/pflupg-tool) Unpacking tool for Philips SmartTV firmware (Fusion platform)
- [**5**星][2y] [Tcl] [greyltc/bitrock-unpacker](https://github.com/greyltc/bitrock-unpacker) this is a tcl script for unpacking bitrock packed archives
- [**4**星][3y] [Py] [rotenkatz/ecos_romfs_unpacker](https://github.com/rotenkatz/ecos_romfs_unpacker) It is a simple ecos ROMFS unpacker for forensics and firmware analysis needs
- [**2**星][2y] [C++] [d00rt/shrinkwrap_unpacker](https://github.com/d00rt/shrinkwrap_unpacker) A simple static unpacker for shrinkwrap


#### <a id="197f3a24a98c86c065273c3121d13f3b"></a>Themida


- [**61**星][4y] [C++] [oowoodone/vmp_odplugin](https://github.com/oowoodone/vmp_odplugin) VMProtect OD Plugin


#### <a id="d4b660c75f60ee317569b6eac48e117f"></a>VMProtect








***


## <a id="3939f5e83ca091402022cb58e0349ab8"></a>文章


### <a id="cd60c8e438bde4b3da791eabf845f679"></a>Themida


- 2018.08 [pediy] [[原创]浅谈VMP、safengine和Themida的反虚拟机](https://bbs.pediy.com/thread-246358.htm)
- 2016.03 [pediy] [[原创]Themida 2260 虚拟机 FISH 初探 （二）](https://bbs.pediy.com/thread-208217.htm)
- 2016.03 [pediy] [[原创]Themida 2260 虚拟机 FISH 初探(一)](https://bbs.pediy.com/thread-208207.htm)
- 2014.09 [pediy] [[原创]菜鸟脱壳---Themida](https://bbs.pediy.com/thread-192834.htm)
- 2013.06 [pediy] [[原创]脱壳手记---Themida（2.1.2.0）](https://bbs.pediy.com/thread-173013.htm)
- 2013.06 [pediy] [脱壳手记---themida(1.8.5.5)](https://bbs.pediy.com/thread-172921.htm)
- 2011.09 [pediy] [[原创]如何中断Themida的MessageBox对话框](https://bbs.pediy.com/thread-140298.htm)
- 2009.09 [pediy] [[原创]说说THEMIDA新版的DIY](https://bbs.pediy.com/thread-98381.htm)
- 2009.08 [pediy] [[分享]Themida + WinLicense 2.0.6.5 (Inline Patching)视频教程和工具](https://bbs.pediy.com/thread-96053.htm)
- 2009.08 [pediy] [[原创] 简单修复Themida加壳的VC7+去除软件自校验](https://bbs.pediy.com/thread-95400.htm)
- 2009.08 [pediy] [[转帖]TheMida - WinLicense Info Script  by  LCF-AT](https://bbs.pediy.com/thread-94993.htm)
- 2009.07 [pediy] [[求助]请问怎么才能让自己的虚拟机避开Themida的检测](https://bbs.pediy.com/thread-93164.htm)
- 2008.12 [pediy] [[原创]Detect all versions of Themida/WinLicense(更新……)](https://bbs.pediy.com/thread-79412.htm)
- 2008.12 [pediy] [[分享]Themida2.0.4.0 DLL脱壳(无SDK）附个查版本号的脚本,可查DLL](https://bbs.pediy.com/thread-79391.htm)
- 2008.12 [pediy] [[原创]inline hook SSDT 躲避 Themida 的ThreadHideFromDebugger  （学习笔记2）](https://bbs.pediy.com/thread-78423.htm)
- 2008.11 [pediy] [[分享]themida跟踪手记第一部分](https://bbs.pediy.com/thread-76107.htm)
- 2008.09 [pediy] [[原创]对Themida1.9.1.0的通法破解一文的补充（再修正）](https://bbs.pediy.com/thread-73425.htm)
- 2008.09 [pediy] [[原创]Themida1.9.1.0版的通法破解](https://bbs.pediy.com/thread-73257.htm)
- 2008.09 [pediy] [[原创]Themida IAT处理部分的简单分析](https://bbs.pediy.com/thread-73227.htm)
- 2008.09 [pediy] [[原创]Themida的另类破解](https://bbs.pediy.com/thread-72152.htm)
- 2008.07 [pediy] [对themida(1.8.5.5)加密VC++程序的完美脱壳](https://bbs.pediy.com/thread-69294.htm)
- 2008.02 [pediy] [[原创]Themida & WinLicen 1.9.1 - 1.9.5 系列脱壳脚本](https://bbs.pediy.com/thread-59186.htm)
- 2008.01 [pediy] [[原创]巧脱Themida 1.8.2+](https://bbs.pediy.com/thread-58929.htm)
- 2008.01 [pediy] [[原创]Themida.V1.9.1.0 手脱XP记事本笔记](https://bbs.pediy.com/thread-57934.htm)
- 2007.12 [pediy] [[原创]发个手脱Themida的参考程序](https://bbs.pediy.com/thread-57402.htm)
- 2007.11 [pediy] [[原创]Themida1950一个不起眼的anti-debug](https://bbs.pediy.com/thread-54264.htm)
- 2007.08 [pediy] [[讨论]关于新版Themida的AntiDebug](https://bbs.pediy.com/thread-50276.htm)
- 2007.08 [pediy] [[原创]ThemidaScript for 1.9.10+](https://bbs.pediy.com/thread-49634.htm)
- 2007.07 [pediy] [[分享]Themida/WinLicense V1.8.2.0 脱壳的祥细过程(不明白细节者适用)](https://bbs.pediy.com/thread-48586.htm)
- 2007.07 [pediy] [[原创]关于对TheMida的MessageBox下断](https://bbs.pediy.com/thread-48030.htm)
- 2007.06 [pediy] [Themida的简单脱壳](https://bbs.pediy.com/thread-46492.htm)
- 2007.04 [pediy] [[分享]Themida脱壳(VC++ 7.0之Stolen Code还原的一种思路)](https://bbs.pediy.com/thread-42397.htm)
- 2007.03 [pediy] [THEMIDA脚本（for IAT restore）](https://bbs.pediy.com/thread-41501.htm)
- 2007.03 [pediy] [[翻译][12月专题]TheMida_defeating_ring0](https://bbs.pediy.com/thread-41074.htm)
- 2006.12 [pediy] [Themida 1.8.0.0 Demo虚拟机分析(完成,共8章)](https://bbs.pediy.com/thread-36453.htm)
- 2006.12 [pediy] [Attacks on Themida AntiHook Protection](https://bbs.pediy.com/thread-35724.htm)
- 2006.11 [pediy] [一个themida加壳的程序LOADER 破解](https://bbs.pediy.com/thread-35431.htm)
- 2006.10 [pediy] [修改regmon/filemon，跳过themida的检测](https://bbs.pediy.com/thread-33634.htm)
- 2006.09 [pediy] [Themida V1.3.5.5脱壳之delphi程序](https://bbs.pediy.com/thread-32164.htm)
- 2006.05 [pediy] [themida 1.0.0.8 驱动程序原代码终于搞定了](https://bbs.pediy.com/thread-25927.htm)
- 2006.05 [pediy] [[讨论]Themida 初步研究(ANTI篇)](https://bbs.pediy.com/thread-25657.htm)
- 2006.05 [pediy] [[小技巧]如何中断Themida的MessageBox对话框](https://bbs.pediy.com/thread-25332.htm)
- 2006.05 [pediy] [Themida Logo显示分析](https://bbs.pediy.com/thread-24959.htm)
- 2006.03 [pediy] [themida demo 1.1.1.0 crack logo 修改办法。。。](https://bbs.pediy.com/thread-23274.htm)
- 2006.03 [pediy] [Unpacked Themida v1.1.1.0 Demo](https://bbs.pediy.com/thread-22991.htm)
- 2005.12 [pediy] [Themida V1.1.1.0 无驱动版试炼普通保护方式脱壳](https://bbs.pediy.com/thread-19172.htm)
- 2005.05 [pediy] [[推荐]对付themida 的工具及文章](https://bbs.pediy.com/thread-19624.htm)
- 2005.03 [pediy] [Themida Kernel Reverse-Engineering](https://bbs.pediy.com/thread-12172.htm)




# <a id="dc664c913dc63ec6b98b47fcced4fdf0"></a>Linux


***


## <a id="89e277bca2740d737c1aeac3192f374c"></a>工具


- [**1544**星][2y] [C] [ezlippi/webbench](https://github.com/ezlippi/webbench) Webbench是Radim Kolar在1997年写的一个在linux下使用的非常简单的网站压测工具。它使用fork()模拟多个客户端同时访问我们设定的URL，测试网站在压力下工作的性能，最多可以模拟3万个并发连接去测试网站的负载能力。官网地址:
- [**1450**星][2m] [C] [feralinteractive/gamemode](https://github.com/feralinteractive/gamemode) Optimise Linux system performance on demand
- [**1413**星][13d] [C++] [google/nsjail](https://github.com/google/nsjail) A light-weight process isolation tool, making use of Linux namespaces and seccomp-bpf syscall filters (with help of the kafel bpf language)
- [**895**星][21d] [C] [buserror/simavr](https://github.com/buserror/simavr) simavr is a lean, mean and hackable AVR simulator for linux & OSX
- [**759**星][30d] [Py] [korcankaraokcu/pince](https://github.com/korcankaraokcu/pince) A reverse engineering tool that'll supply the place of Cheat Engine for linux
- [**741**星][2m] [C] [yrp604/rappel](https://github.com/yrp604/rappel) A linux-based assembly REPL for x86, amd64, armv7, and armv8
- [**731**星][9d] [C] [strace/strace](https://github.com/strace/strace) strace is a diagnostic, debugging and instructional userspace utility for Linux
- [**585**星][3y] [C] [ktap/ktap](https://github.com/ktap/ktap) a new scripting dynamic tracing tool for Linux
- [**570**星][11m] [C] [asamy/ksm](https://github.com/asamy/ksm) 快速、hackable且简单的x64 VT-x虚拟机管理程序，支持Windows和Linux
    - 重复区段: [Windows->工具->VT](#19cfd3ea4bd01d440efb9d4dd97a64d0) |
- [**565**星][4d] [C++] [intel/linux-sgx](https://github.com/intel/linux-sgx) Intel SGX for Linux*
- [**560**星][2m] [Py] [autotest/autotest](https://github.com/autotest/autotest) Fully automated tests on Linux
- [**536**星][5m] [C++] [nytrorst/shellcodecompiler](https://github.com/nytrorst/shellcodecompiler) 将C/C ++样式代码编译成一个小的、与位置无关且无NULL的Shellcode，用于Windows（x86和x64）和Linux（x86和x64）
    - 重复区段: [Windows->工具->Shellcode](#16001cb2fae35b722deaa3b9a8e5f4d5) |
- [**509**星][7m] [C] [iovisor/ply](https://github.com/iovisor/ply) Dynamic Tracing in Linux
- [**506**星][3y] [C] [gaffe23/linux-inject](https://github.com/gaffe23/linux-inject) Tool for injecting a shared object into a Linux process
- [**468**星][] [C] [libreswan/libreswan](https://github.com/libreswan/libreswan) an Internet Key Exchange (IKE) implementation for Linux.
- [**462**星][2y] [C++] [aimtuxofficial/aimtux](https://github.com/aimtuxofficial/aimtux) A large Linux csgo cheat/hack
- [**441**星][4d] [C] [facebook/openbmc](https://github.com/facebook/openbmc) OpenBMC is an open software framework to build a complete Linux image for a Board Management Controller (BMC).
- [**405**星][10m] [Shell] [microsoft/linux-vm-tools](https://github.com/microsoft/linux-vm-tools) Hyper-V Linux Guest VM Enhancements
- [**393**星][1m] [Shell] [yadominjinta/atilo](https://github.com/yadominjinta/atilo) Linux installer for termux
- [**355**星][3y] [C] [adtac/fssb](https://github.com/adtac/fssb) A filesystem sandbox for Linux using syscall intercepts.
- [**354**星][2m] [C] [seccomp/libseccomp](https://github.com/seccomp/libseccomp) an easy to use, platform independent, interface to the Linux Kernel's syscall filtering mechanism
- [**331**星][4m] [Go] [capsule8/capsule8](https://github.com/capsule8/capsule8) 对云本地，容器和传统的基于 Linux 的服务器执行高级的行为监控
- [**318**星][3y] [C] [chobits/tapip](https://github.com/chobits/tapip) user-mode TCP/IP stack based on linux tap device
- [**282**星][1m] [Py] [facebook/fbkutils](https://github.com/facebook/fbkutils) A variety of utilities built and maintained by Facebook's Linux Kernel Team that we wish to share with the community.
- [**233**星][2y] [C] [hardenedlinux/grsecurity-101-tutorials](https://github.com/hardenedlinux/grsecurity-101-tutorials) 增强 Linux 内核安全的内核补丁集
- [**228**星][7m] [C] [wkz/ply](https://github.com/wkz/ply) Light-weight Dynamic Tracer for Linux
- [**203**星][3y] [C] [google/kasan](https://github.com/google/kasan) KernelAddressSanitizer, a fast memory error detector for the Linux kernel
- [**199**星][3y] [C] [dismantl/linux-injector](https://github.com/dismantl/linux-injector) Utility for injecting executable code into a running process on x86/x64 Linux
- [**192**星][7m] [C] [andikleen/simple-pt](https://github.com/andikleen/simple-pt) Simple Intel CPU processor tracing on Linux
- [**173**星][25d] [C] [netoptimizer/network-testing](https://github.com/netoptimizer/network-testing) Network Testing Tools for testing the Linux network stack
- [**147**星][14d] [Shell] [hardenedlinux/debian-gnu-linux-profiles](https://github.com/hardenedlinux/debian-gnu-linux-profiles) Debian GNU/Linux based Services Profiles
- [**144**星][2y] [C] [ixty/mandibule](https://github.com/ixty/mandibule) 向远程进程注入ELF文件
- [**144**星][7d] [Shell] [sclorg/s2i-python-container](https://github.com/sclorg/s2i-python-container) Python container images based on Red Hat Software Collections and intended for OpenShift and general usage, that provide a platform for building and running Python applications. Users can choose between Red Hat Enterprise Linux, Fedora, and CentOS based images.
- [**140**星][7y] [C] [johnath/beep](https://github.com/johnath/beep) beep is a command line tool for linux that beeps the PC speaker
- [**139**星][7m] [C] [dzzie/scdbg](https://github.com/dzzie/scdbg) note: current build is VS_LIBEMU project. This cross platform gcc build is for Linux users but is no longer updated. modification of the libemu sctest project to add basic debugger capabilities and more output useful for manual RE. The newer version will run under WINE
- [**133**星][27d] [C] [arsv/minibase](https://github.com/arsv/minibase) small static userspace tools for Linux
- [**127**星][10y] [C] [spotify/linux](https://github.com/spotify/linux) Spotify's Linux kernel for Debian-based systems
- [**122**星][5m] [C] [dschanoeh/socketcand](https://github.com/dschanoeh/socketcand) A deprecated fork of socketcand. Please got to linux-can for the latest version.
- [**119**星][1m] [Py] [containers/udica](https://github.com/containers/udica) This repository contains a tool for generating SELinux security profiles for containers
- [**116**星][1y] [Shell] [fox-it/linux-luks-tpm-boot](https://github.com/fox-it/linux-luks-tpm-boot) A guide for setting up LUKS boot with a key from TPM in Linux
- [**109**星][2m] [Py] [vstinner/python-ptrace](https://github.com/vstinner/python-ptrace) a debugger using ptrace (Linux, BSD and Darwin system call to trace processes) written in Python
- [**99**星][2y] [Shell] [aoncyberlabs/cexigua](https://github.com/AonCyberLabs/Cexigua) Linux based inter-process code injection without ptrace(2)
- [**97**星][6m] [Shell] [gavinlyonsrepo/cylon](https://github.com/gavinlyonsrepo/cylon) Updates, maintenance, backups and system checks in a TUI menu driven bash shell script for an Arch based Linux distro
- [**93**星][6m] [Shell] [vincentbernat/eudyptula-boot](https://github.com/vincentbernat/eudyptula-boot) Boot a Linux kernel in a VM without a dedicated root filesystem.
- [**83**星][2y] [C] [xobs/novena-linux](https://github.com/xobs/novena-linux) Linux kernel with Novena patches -- expect frequent rebases!
- [**77**星][6m] [Py] [cybereason/linux_plumber](https://github.com/cybereason/linux_plumber) A python implementation of a grep friendly ftrace wrapper
- [**74**星][3y] [Shell] [inquisb/unix-privesc-check](https://github.com/inquisb/unix-privesc-check) Shell script that runs on UNIX systems (tested on Solaris 9, HPUX 11, various Linux distributions, FreeBSD 6.2). It detects misconfigurations that could allow local unprivileged user to escalate to other users (e.g. root) or to access local apps (e.g. databases). This is a collaborative rework of version 1.0
- [**72**星][7m] [C] [hc0d3r/alfheim](https://github.com/hc0d3r/alfheim) a linux process hacker tool
- [**70**星][6d] [Shell] [sclorg/s2i-php-container](https://github.com/sclorg/s2i-php-container) PHP container images based on Red Hat Software Collections and intended for OpenShift and general usage, that provide a platform for building and running PHP applications. Users can choose between Red Hat Enterprise Linux, Fedora, and CentOS based images.
- [**68**星][8d] [drduh/pc-engines-apu-router-guide](https://github.com/drduh/pc-engines-apu-router-guide) Guide to building a Linux or BSD router on the PC Engines APU platform
- [**68**星][2d] [TS] [flathub/linux-store-frontend](https://github.com/flathub/linux-store-frontend) A web application to browse and install applications present in Flatpak repositories. Powers
- [**65**星][2m] [Py] [archlinux/arch-security-tracker](https://github.com/archlinux/arch-security-tracker) Arch Linux Security Tracker
- [**65**星][t] [Shell] [mdrights/liveslak](https://github.com/mdrights/liveslak) 中文化的隐私加强 GNU/Linux 系统 - Forked from Alien Bob's powerful building script for Slackware Live.
- [**61**星][2y] [Perl] [xlogicx/m2elf](https://github.com/xlogicx/m2elf) Converts Machine Code to x86 (32-bit) Linux executable (auto-wrapping with ELF headers)
- [**60**星][1y] [C] [skeeto/ptrace-examples](https://github.com/skeeto/ptrace-examples) Examples for Linux ptrace(2)
- [**58**星][2y] [Go] [evilsocket/ftrace](https://github.com/evilsocket/ftrace) Go library to trace Linux syscalls using the FTRACE kernel framework.
- [**58**星][3m] [Java] [exalab/anlinux-adfree](https://github.com/exalab/anlinux-adfree) AnLinux, Ad free version.
- [**58**星][3y] [CSS] [wizardforcel/sploitfun-linux-x86-exp-tut-zh](https://github.com/wizardforcel/sploitfun-linux-x86-exp-tut-zh) 
- [**54**星][1y] [Py] [k4yt3x/defense-matrix](https://github.com/k4yt3x/defense-matrix) Express security essentials deployment for Linux Servers
- [**53**星][10m] [C] [marcan/lsirec](https://github.com/marcan/lsirec) LSI SAS2008/SAS2108 low-level recovery tool for Linux
- [**52**星][1y] [C] [pymumu/jail-shell](https://github.com/pymumu/jail-shell) Jail-shell is a linux security tool mainly using chroot, namespaces technologies, limiting users to perform specific commands, and access sepcific directories.
- [**49**星][3m] [C] [thibault-69/rat-hodin-v2.9](https://github.com/Thibault-69/RAT-Hodin-v2.9) Remote Administration Tool for Linux
- [**49**星][2y] [C] [cnlohr/wifirxpower](https://github.com/cnlohr/wifirxpower) Linux-based WiFi RX Power Grapher
- [**49**星][3y] [Assembly] [t00sh/assembly](https://github.com/t00sh/assembly) Collection of Linux shellcodes
- [**45**星][2y] [Go] [c-bata/systracer](https://github.com/c-bata/systracer) Linux/x86 系统调用追踪, Go语言实现
- [**45**星][6y] [JS] [cyberpython/wifiscanandmap](https://github.com/cyberpython/wifiscanandmap) A Linux Python application to create maps of 802.11 networks
- [**45**星][4y] [C] [shadowsocks/iptables](https://github.com/shadowsocks/iptables) iptables is the userspace command line program used to configure the Linux 2.4.x and later packet filtering ruleset. It is targeted towards system administrators.
- [**44**星][6m] [C] [junxzm1990/pomp](https://github.com/junxzm1990/pomp) 在 Linux 系统上开发 POMP 系统，分析崩溃后的 artifacts
- [**43**星][6m] [Ruby] [b1ack0wl/linux_mint_poc](https://github.com/b1ack0wl/linux_mint_poc) 
- [**43**星][1y] [C] [gcwnow/linux](https://github.com/gcwnow/linux) Linux kernel for GCW Zero (Ingenic JZ4770)
- [**41**星][3y] [Py] [fnzv/trsh](https://github.com/fnzv/trsh) trsh：使用电报 API 与 Linux 服务器通信，Python编写。
- [**40**星][3d] [Dockerfile] [ironpeakservices/iron-alpine](https://github.com/ironPeakServices/iron-alpine) Hardened alpine linux baseimage for Docker.
- [**39**星][2m] [C] [stephenrkell/trap-syscalls](https://github.com/stephenrkell/trap-syscalls) Monitor, rewrite and/or otherwise trap system calls... on Linux/x86-64 only, for now.
- [**38**星][3m] [PHP] [cesnet/pakiti-server](https://github.com/cesnet/pakiti-server) Pakiti provides a monitoring mechanism to check the patching status of Linux systems.
- [**35**星][8y] [C] [sduverger/ld-shatner](https://github.com/sduverger/ld-shatner) ld-linux code injector
- [**34**星][4m] [C] [peterbjornx/meloader](https://github.com/peterbjornx/meloader) Linux i386 tool to load and execute ME modules.
- [**34**星][3y] [screetsec/dracos](https://github.com/screetsec/dracos) Dracos Linux (
- [**33**星][2y] [C++] [cnrig/cnrig](https://github.com/cnrig/cnrig) Static CryptoNight CPU miner for Linux + automatic updates
- [**33**星][3y] [Go] [egebalci/the-eye](https://github.com/egebalci/the-eye) Simple security surveillance script for linux distributions.
- [**33**星][11m] [C] [p3n3troot0r/socketv2v](https://github.com/p3n3troot0r/socketv2v) Mainline Linux Kernel integration of IEEE 802.11p, IEEE 1609.{3,4}, and developmental userspace utility for using J2735 over WAVE
- [**32**星][6m] [C] [jcsaezal/pmctrack](https://github.com/jcsaezal/pmctrack) an OS-oriented performance monitoring tool for Linux (
- [**32**星][6y] [C] [nbareil/net2pcap](https://github.com/nbareil/net2pcap) 类似于tcpdump的数据包捕获工具，只依赖libc
- [**32**星][1y] [C] [perceptionpoint/suprotect](https://github.com/perceptionpoint/suprotect) Linux内核模块, 修改任意进程的内存保护属性
- [**32**星][4y] [C] [a0rtega/bdldr](https://github.com/a0rtega/bdldr) bdldr is an unofficial engine loader for Bitdefender ® for Linux
- [**30**星][2y] [PHP] [opt-oss/ng-netms](https://github.com/opt-oss/ng-netms) NG-NetMS is a new end-to-end network management platform for your Linux servers, Cisco, Juniper, HP and Extreme routers, switches and firewalls.
- [**27**星][1m] [Shell] [adnanhodzic/anon-hotspot](https://github.com/adnanhodzic/anon-hotspot) On demand Debian Linux (Tor) Hotspot setup tool
- [**27**星][2y] [Py] [morphuslabs/distinct](https://github.com/morphuslabs/distinct) Find potential Indicators of Compromise among similar Linux servers
- [**27**星][2m] [C] [oracle/libdtrace-ctf](https://github.com/oracle/libdtrace-ctf) libdtrace-ctf is the Compact Type Format library used by DTrace on Linux
- [**27**星][1y] [Py] [thesecondsun/pasm](https://github.com/thesecondsun/pasm) Linux assembler/disassembler based on Rasm2
- [**27**星][5y] [Py] [bendemott/captiveportal](https://github.com/bendemott/captiveportal) A captive portal that can be used on most linux distributions.
- [**26**星][12m] [C] [plutonium-dbg/plutonium-dbg](https://github.com/plutonium-dbg/plutonium-dbg) Kernel-based debugger for Linux applications
- [**26**星][2m] [C] [oracle/dtrace-utils](https://github.com/oracle/dtrace-utils) DTrace-utils contains the Userspace portion of the DTrace port to Linux
- [**25**星][8y] [aheadley/logitech-solar-k750-linux](https://github.com/aheadley/logitech-solar-k750-linux) Userspace "driver" for the Logitech k750 Solar Keyboard. A fork of the repo from
- [**24**星][1y] [Py] [m4rktn/jogan](https://github.com/m4rktn/jogan) Pentest Tools & Packages Installer [Linux/Termux]
- [**23**星][5y] [C++] [behzad-a/dytan](https://github.com/behzad-a/dytan) Dytan Taint Analysis Framework on Linux 64-bit
- [**23**星][3y] [Py] [remnux/distro](https://github.com/remnux/distro) This repository contains supplementary files for building and using the REMnux Linux distribution. See
- [**23**星][5y] [Assembly] [zerosum0x0/slae64](https://github.com/zerosum0x0/slae64) x64 Linux Shellcode
- [**22**星][3y] [Shell] [johntroony/luks-ops](https://github.com/johntroony/luks-ops) A bash script to automate the most basic usage of LUKS volumes in Linux VPS
- [**22**星][5y] [munmap/linux-kernel-bugs-db](https://github.com/munmap/linux-kernel-bugs-db) 
- [**21**星][1y] [Py] [syno3/babymux](https://github.com/syno3/babymux) pentesting tool for noob hackers.Runs on linux and termux
- [**20**星][3y] [C] [leixiangwu/cse509-rootkit](https://github.com/leixiangwu/cse509-rootkit) After attackers manage to gain access to a remote (or local) machine and elevate their privileges to "root", they typically want to maintain their access, while hiding their presence from the normal users and administrators of the system. This basic rootkit works on the Linux operating system and is a loadable kernel module which when loaded int…


***


## <a id="f6d78e82c3e5f67d13d9f00c602c92f0"></a>文章




# <a id="3f1fde99538be4662dca6747a365640b"></a>Hook


***


## <a id="cfe974d48bbb90a930bf667c173616c7"></a>工具


- [**1246**星][1y] [Kotlin] [gh0u1l5/wechatspellbook](https://github.com/gh0u1l5/wechatspellbook) 一个使用Kotlin编写的开源微信插件框架，底层需要 Xposed 或 VirtualXposed 等Hooking框架的支持，而顶层可以轻松对接Java、Kotlin、Scala等JVM系语言。让程序员能够在几分钟内编写出简单的微信插件，随意揉捏微信的内部逻辑。
- [**1234**星][3y] [C] [tsudakageyu/minhook](https://github.com/tsudakageyu/minhook) The Minimalistic x86/x64 API Hooking Library for Windows
- [**1117**星][1y] [ObjC] [yulingtianxia/fishchat](https://github.com/yulingtianxia/fishchat) Hook WeChat.app on non-jailbroken devices.
- [**1033**星][5m] [C++] [everdox/infinityhook](https://github.com/everdox/infinityhook) Hook system calls, context switches, page faults and more.
- [**770**星][11d] [Go] [thoughtworks/talisman](https://github.com/thoughtworks/talisman) By hooking into the pre-push hook provided by Git, Talisman validates the outgoing changeset for things that look suspicious - such as authorization tokens and private keys.
- [**680**星][8m] [Java] [pagalaxylab/yahfa](https://github.com/PAGalaxyLab/YAHFA) Yet Another Hook Framework for ART
- [**660**星][9m] [C++] [ysc3839/fontmod](https://github.com/ysc3839/fontmod) Simple hook tool to change Win32 program font.
- [**643**星][3m] [C++] [stevemk14ebr/polyhook](https://github.com/stevemk14ebr/polyhook) x86/x64 C++ Hooking Library
- [**600**星][24d] [C] [mohuihui/antispy](https://github.com/mohuihui/antispy) AntiSpy is a free but powerful anti virus and rootkits toolkit.It offers you the ability with the highest privileges that can detect,analyze and restore various kernel modifications and hooks.With its assistance,you can easily spot and neutralize malwares hidden from normal detectors.
- [**575**星][6d] [C] [yulingtianxia/blockhook](https://github.com/yulingtianxia/blockhook) Hook Objective-C blocks. A powerful AOP tool.
- [**572**星][8m] [ObjC] [rpetrich/captainhook](https://github.com/rpetrich/captainhook) Common hooking/monkey patching headers for Objective-C on Mac OS X and iPhone OS. MIT licensed
- [**548**星][2y] [Java] [littlerich/virtuallocation](https://github.com/littlerich/virtuallocation) 利用Hook技术对APP进行虚拟定位，可修改微信、QQ、以及一些打卡APP等软件，随意切换手机所处位置！
- [**533**星][1y] [Objective-C++] [davidgoldman/inspectivec](https://github.com/davidgoldman/inspectivec) objc_msgSend hook for debugging/inspection purposes.
- [**526**星][2m] [C#] [crosire/scripthookvdotnet](https://github.com/crosire/scripthookvdotnet) An ASI plugin for Grand Theft Auto V, which allows running scripts written in any .NET language in-game.
- [**483**星][1y] [C++] [tandasat/ddimon](https://github.com/tandasat/ddimon) Monitoring and controlling kernel API calls with stealth hook using EPT
- [**483**星][3m] [Java] [windysha/xpatch](https://github.com/windysha/xpatch) 免Root实现app加载Xposed插件工具。This is a tool to repackage apk file, then the apk can load any xposed modules installed in the device. It is another way to hook an app without root device.
- [**468**星][27d] [C] [wilix-team/iohook](https://github.com/wilix-team/iohook) Node.js global keyboard and mouse listener.
- [**466**星][6y] [C] [martona/mhook](https://github.com/martona/mhook) A Windows API hooking library
- [**443**星][13d] [C++] [stevemk14ebr/polyhook_2_0](https://github.com/stevemk14ebr/polyhook_2_0) C++17, x86/x64 Hooking Libary v2.0
- [**410**星][9m] [C] [darthton/hyperbone](https://github.com/darthton/hyperbone) Minimalistic VT-x hypervisor with hooks
- [**393**星][1m] [C++] [0x09al/rdpthief](https://github.com/0x09al/rdpthief) Extracting Clear Text Passwords from mstsc.exe using API Hooking.
- [**373**星][3y] [Py] [androidhooker/hooker](https://github.com/androidhooker/hooker) Hooker is an opensource project for dynamic analyses of Android applications. This project provides various tools and applications that can be use to automaticaly intercept and modify any API calls made by a targeted application.
    - 重复区段: [Android->工具->新添加的1](#63fd2c592145914e99f837cecdc5a67c) |
- [**363**星][2m] [C++] [steven-michaud/hookcase](https://github.com/steven-michaud/hookcase) Tool for reverse engineering macOS/OS X
- [**357**星][2y] [JS] [kamikat/tttfi](https://github.com/kamikat/tttfi) IFTTT 中间件。从 IFTTT webhook 中提取数据传递给脚本，并将脚本的输出发送回 IFTTT。脚本语言支持 Python/Perl/Go。
- [**342**星][6m] [C] [zeex/subhook](https://github.com/zeex/subhook) Simple hooking library for C/C++ (x86 only, 32/64-bit, no dependencies)
- [**334**星][3y] [Py] [jandre/safe-commit-hook](https://github.com/jandre/safe-commit-hook) pre-commit hook for Git that checks for suspicious files.
- [**327**星][2y] [Java] [mar-v-in/arthook](https://github.com/mar-v-in/arthook) Library for hooking on ART
- [**310**星][2y] [ObjC] [jmpews/hookzzmodules](https://github.com/jmpews/hookzzmodules) modules deps on HookZz framework.
- [**302**星][1y] [C] [nektra/deviare2](https://github.com/nektra/deviare2) Deviare API Hook
- [**289**星][6m] [C] [outflanknl/dumpert](https://github.com/outflanknl/dumpert) LSASS memory dumper using direct system calls and API unhooking.
- [**273**星][2y] [C++] [gellin/teamviewer_permissions_hook_v1](https://github.com/gellin/teamviewer_permissions_hook_v1) A proof of concept injectable C++ dll, that uses naked inline hooking and direct memory modification to change your TeamViewer permissions.
- [**262**星][11m] [C] [nbulischeck/tyton](https://github.com/nbulischeck/tyton) Linux内核模式Rootkit Hunter. 可检测隐藏系统模块、系统调用表Hooking、网络协议Hooking等
- [**259**星][2y] [Py] [davidfraser/pyan](https://github.com/davidfraser/pyan) pyan is a Python module that performs static analysis of Python code to determine a call dependency graph between functions and methods. This is different from running the code and seeing which functions are called and how often; there are various tools that will generate a call graph in that way, usually using debugger or profiling trace hooks …
- [**250**星][4m] [C] [gbps/gbhv](https://github.com/gbps/gbhv) Simple x86-64 VT-x Hypervisor with EPT Hooking
- [**249**星][1y] [Py] [boppreh/mouse](https://github.com/boppreh/mouse) Hook and simulate global mouse events in pure Python
- [**236**星][4d] [C] [kubo/plthook](https://github.com/kubo/plthook) Hook function calls by replacing PLT(Procedure Linkage Table) entries.
- [**230**星][1y] [C#] [misaka-mikoto-tech/monohooker](https://github.com/Misaka-Mikoto-Tech/MonoHooker) hook C# method at runtime without modify dll file (such as UnityEditor.dll)
- [**219**星][7m] [Java] [shuihuadx/xposedhook](https://github.com/shuihuadx/xposedhook) 免重启Xposed模块改进
- [**216**星][3y] [C] [silight-jp/mactype-patch](https://github.com/silight-jp/mactype-patch) MacType Patch for DirectWrite Hook
- [**213**星][1y] [C] [suvllian/process-inject](https://github.com/suvllian/process-inject) 在Windows环境下的进程注入方法：远程线程注入、创建进程挂起注入、反射注入、APCInject、SetWindowHookEX注入
- [**177**星][5m] [C#] [justcoding121/windows-user-action-hook](https://github.com/justcoding121/windows-user-action-hook) A .NET library to subscribe for Windows operating system global user actions such mouse, keyboard, clipboard & print events
- [**176**星][12m] [C] [fate0/xmark](https://github.com/fate0/xmark) A PHP7 extension that can hook most functions/classes and parts of opcodes
- [**141**星][7m] [C] [coolervoid/hiddenwall](https://github.com/coolervoid/hiddenwall) Tool to generate a Linux kernel module for custom rules with Netfilter hooking. (block ports, Hidden mode, rootkit functions etc)
- [**141**星][3y] [Py] [ethanhs/pyhooked](https://github.com/ethanhs/pyhooked) Pure Python hotkey hook, with thanks to pyHook and pyhk
- [**138**星][5d] [C++] [hasherezade/iat_patcher](https://github.com/hasherezade/iat_patcher) Persistent IAT hooking application - based on bearparser
- [**138**星][2m] [C] [kubo/funchook](https://github.com/kubo/funchook) Funchook - an API Hook Library
- [**137**星][1y] [C] [alex3434/wmi-static-spoofer](https://github.com/alex3434/wmi-static-spoofer) Spoofing the Windows 10 HDD/diskdrive serialnumber from kernel without hooking
- [**135**星][1m] [C] [davidbuchanan314/tardis](https://github.com/davidbuchanan314/tardis) Trace And Rewrite Delays In Syscalls: Hooking time-related Linux syscalls to warp a process's perspective of time, using ptrace.
- [**132**星][4m] [C] [hoshimin/hooklib](https://github.com/hoshimin/hooklib) The functions interception library written on pure C and NativeAPI with UserMode and KernelMode support
- [**128**星][1y] [C++] [m0n0ph1/iat-hooking-revisited](https://github.com/m0n0ph1/iat-hooking-revisited) Import address table (IAT) hooking is a well documented technique for intercepting calls to imported functions.
- [**126**星][3y] [C] [poliva/ldpreloadhook](https://github.com/poliva/ldpreloadhook) a quick open/close/ioctl/read/write/free function hooker
- [**125**星][6d] [C++] [rebzzel/kiero](https://github.com/rebzzel/kiero) Universal graphical hook for a D3D9-D3D12, OpenGL and Vulcan based games.
- [**123**星][1y] [C] [cylancevulnresearch/reflectivedllrefresher](https://github.com/cylancevulnresearch/reflectivedllrefresher) Universal Unhooking
- [**121**星][3m] [Go] [bshuster-repo/logrus-logstash-hook](https://github.com/bshuster-repo/logrus-logstash-hook) 
- [**116**星][3y] [C] [gdabah/distormx](https://github.com/gdabah/distormx) The ultimate hooking library
- [**116**星][2y] [C#] [tandasat/dotnethooking](https://github.com/tandasat/dotnethooking) Sample use cases of the .NET native code hooking technique
- [**115**星][8m] [JS] [skepticfx/hookish](https://github.com/skepticfx/hookish) Hooks in to interesting functions and helps reverse the web app faster.
- [**111**星][6y] [Ruby] [spiderlabs/beef_injection_framework](https://github.com/spiderlabs/beef_injection_framework) Inject beef hooks into HTTP traffic and track hooked systems from cmdline
- [**109**星][4m] [C++] [tandasat/simplesvmhook](https://github.com/tandasat/simplesvmhook) SimpleSvmHook is a research purpose hypervisor for Windows on AMD processors.
- [**105**星][4y] [Java] [rednaga/dexhook](https://github.com/rednaga/dexhook) DexHook is a xposed module for capturing dynamically loaded dex files.
- [**103**星][2m] [Py] [infertux/zeyple](https://github.com/infertux/zeyple) Postfix filter/hook to automatically encrypt outgoing emails with PGP/GPG
- [**100**星][4y] [Py] [eset/vba-dynamic-hook](https://github.com/eset/vba-dynamic-hook) dynamically analyzes VBA macros inside Office documents by hooking function calls
- [**99**星][4y] [C] [ionescu007/hookingnirvana](https://github.com/ionescu007/hookingnirvana) Recon 2015 Presentation from Alex Ionescu
- [**93**星][3y] [C++] [shmuelyr/captainhook](https://github.com/shmuelyr/captainhook) CaptainHook is perfect x86/x64 hook environment
- [**83**星][5y] [C] [chokepoint/crypthook](https://github.com/chokepoint/crypthook) TCP/UDP symmetric encryption tunnel wrapper
- [**78**星][4d] [C] [milabs/khook](https://github.com/milabs/khook) Linux Kernel hooking engine (x86)
- [**78**星][3y] [C] [stevemk14ebr/unihook](https://github.com/stevemk14ebr/unihook) Intercept arbitrary functions at run-time, without knowing their typedefs
- [**77**星][1m] [C] [apriorit/mhook](https://github.com/apriorit/mhook) A Windows API hooking library
- [**77**星][7m] [Py] [enigmabridge/certbot-external-auth](https://github.com/enigmabridge/certbot-external-auth) Certbot external DNS, HTTP, TLSSNI domain validation plugin with JSON output and scriptable hooks, with Dehydrated compatibility
- [**77**星][3y] [C] [tinysec/iathook](https://github.com/tinysec/iathook) windows kernelmode and usermode IAT hook
- [**75**星][2y] [C++] [hrbust86/hookmsrbysvm](https://github.com/hrbust86/hookmsrbysvm) hook msr by amd svm
- [**73**星][1y] [JS] [pnigos/hookjs](https://github.com/pnigos/hookjs) javascript function hook
- [**72**星][1y] [C] [chinatiny/inlinehooklib](https://github.com/chinatiny/inlinehooklib) 同时支持用户和内核模式的Inlinehook库
- [**67**星][9m] [Java] [bolexliu/apptrack](https://github.com/bolexliu/apptrack) Xposed HookAPP逆向跟踪工具，跟踪Activity与Fragment启动信息等
- [**67**星][5y] [C] [malwaretech/basichook](https://github.com/malwaretech/basichook) x86 Inline hooking engine (using trampolines)
- [**67**星][2y] [C++] [secrary/hooking-via-instrumentationcallback](https://github.com/secrary/hooking-via-instrumentationcallback) codes for my blog post:
- [**64**星][11d] [C] [zyantific/zyan-hook-engine](https://github.com/zyantific/zyan-hook-engine) Advanced x86/x86-64 hooking library (WIP).
- [**63**星][1y] [C] [dodola/fbhookfork](https://github.com/dodola/fbhookfork) 从 fb 的 profilo 项目里提取出来的hook 库，自己用
- [**63**星][3m] [Go] [stakater/gitwebhookproxy](https://github.com/stakater/gitwebhookproxy) A proxy to let webhooks reach running services behind a firewall – [✩Star] if you're using it!
- [**63**星][2y] [C#] [easyhook/easyhook-tutorials](https://github.com/easyhook/easyhook-tutorials) Contains the source code for the EasyHook tutorials found at
- [**62**星][10m] [C++] [urshadow/urmem](https://github.com/urshadow/urmem) C++11 cross-platform library for working with memory (hooks, patches, pointer's wrapper, signature scanner etc.)
- [**61**星][4m] [C++] [changeofpace/mouhidinputhook](https://github.com/changeofpace/mouhidinputhook) MouHidInputHook enables users to filter, modify, and inject mouse input data packets into the input data stream of HID USB mouse devices without modifying the mouse device stacks.
- [**60**星][1y] [C#] [wledfor2/playhooky](https://github.com/wledfor2/playhooky) C# Runtime Hooking Library for .NET/Mono/Unity.
- [**59**星][4y] [C++] [codereversing/directx9hook](https://github.com/codereversing/directx9hook) Runtime DirectX9 Hooking
- [**59**星][6m] [C] [respeak/ts3hook](https://github.com/respeak/ts3hook) Teamspeak 3 Hook
- [**58**星][3y] [C] [codectile/paradise](https://github.com/codectile/paradise) x86/x86-64 hooking library
- [**58**星][2y] [JS] [vah13/win_zip_password](https://github.com/vah13/win_zip_password) Python script to hook ZIP files passwords in Windows 10
- [**57**星][1y] [C++] [petrgeorgievsky/gtarenderhook](https://github.com/petrgeorgievsky/gtarenderhook) GTA SA rendering hook
- [**57**星][1m] [Makefile] [genuinetools/upmail](https://github.com/genuinetools/upmail) Email notification hook for
- [**56**星][2y] [Ruby] [jbjonesjr/letsencrypt-manual-hook](https://github.com/jbjonesjr/letsencrypt-manual-hook) Allows you to use dehydrated (a Let's Encrypt/Acme Client) and DNS challenge response with a DNS provider that requires manual intervention
- [**55**星][15d] [C] [danielkrupinski/vac-hooks](https://github.com/danielkrupinski/vac-hooks) Hook WinAPI functions used by Valve Anti-Cheat. Log calls and intercept arguments & return values. DLL written in C.
- [**54**星][5y] [C++] [malwaretech/fsthook](https://github.com/malwaretech/fsthook) A library for intercepting native functions by hooking KiFastSystemCall
- [**54**星][3y] [C] [passingtheknowledge/ganxo](https://github.com/passingtheknowledge/ganxo) An opensource API hooking framework
- [**53**星][1y] [C] [chen-charles/pedetour](https://github.com/chen-charles/pedetour) modify binary Portable Executable to hook its export functions
- [**52**星][5m] [C++] [gaypig/directx11-hook-with-discord](https://github.com/gaypig/directx11-hook-with-discord) DirectX11 hook with discord
- [**51**星][3y] [breakingmalwareresearch/captain-hook](https://github.com/breakingmalwareresearch/captain-hook) 
- [**51**星][5y] [C++] [ikoz/androidsubstrate_hookingc_examples](https://github.com/ikoz/androidsubstrate_hookingc_examples) AndroidSubstrate_hookingC_examples
- [**48**星][8m] [Java] [greywolf007/mobileq750hook](https://github.com/greywolf007/mobileq750hook) MobileQ750Hook
- [**47**星][10m] [C] [ilammy/ftrace-hook](https://github.com/ilammy/ftrace-hook) Using ftrace for function hooking in Linux kernel
- [**46**星][9m] [C] [jay/gethooks](https://github.com/jay/gethooks) GetHooks is a program designed for the passive detection and monitoring of hooks from a limited user account.
- [**46**星][3y] [C] [zhuhuibeishadiao/pfhook](https://github.com/zhuhuibeishadiao/pfhook) Page fault hook use ept (Intel Virtualization Technology)
- [**45**星][1y] [C++] [coltonon/reghookex](https://github.com/coltonon/reghookex) External mid-function hooking method to retrieve register data
- [**44**星][5m] [C#] [userr00t/universalunityhooks](https://github.com/userr00t/universalunityhooks) A framework designed to hook into and modify methods in unity games via dlls
- [**44**星][1m] [C++] [wopss/renhook](https://github.com/wopss/renhook) An open-source x86 / x86-64 hooking library for Windows.
- [**42**星][19d] [Perl] [theos/logos](https://github.com/theos/logos) Preprocessor that simplifies Objective-C hooking.
- [**41**星][9y] [C++] [cr4sh/ptbypass-poc](https://github.com/cr4sh/ptbypass-poc) Bypassing code hooks detection in modern anti-rootkits via building faked PTE entries.
- [**40**星][10m] [C] [dzzie/hookexplorer](https://github.com/dzzie/hookexplorer) technical tool to analyze a process trying to find various types of runtime hooks. Interface and output is geared torwards security experts. Average users wont be able to decipher its output.
- [**40**星][11m] [JS] [gaoding-inc/runtime-hooks](https://github.com/gaoding-inc/runtime-hooks) 
- [**39**星][2y] [C++] [tanninone/usvfs](https://github.com/tanninone/usvfs) library using api hooking to implement process-local filesystem-independent file links.
- [**38**星][1y] [JS] [lmammino/webhook-tunnel](https://github.com/lmammino/webhook-tunnel) A little HTTP proxy suitable to create tunnels for webhook endpoints protected behind a firewall or a VPN
- [**38**星][7y] [C++] [prekageo/winhook](https://github.com/prekageo/winhook) 
- [**38**星][1y] [C++] [rebzzel/universal-d3d11-hook](https://github.com/rebzzel/universal-d3d11-hook) Universal hook for DX11 based games written in C++
- [**38**星][2m] [Go] [controlplaneio/kubesec-webhook](https://github.com/controlplaneio/kubesec-webhook) Security risk analysis for Kubernetes resources
- [**38**星][5y] [Assembly] [muffins/rookit_playground](https://github.com/muffins/rookit_playground) Educational repository for learning about rootkits and Windows Kernel Hooks.
- [**38**星][9d] [Rust] [verideth/dll_hook-rs](https://github.com/verideth/dll_hook-rs) Rust code to show how hooking in rust with a dll works.
- [**37**星][7m] [C] [ntraiseharderror/antihook](https://github.com/ntraiseharderror/antihook) PoC designed to evade userland-hooking anti-virus.
- [**36**星][2y] [C++] [rolfrolles/wbdeshook](https://github.com/rolfrolles/wbdeshook) DLL-injection based solution to Brecht Wyseur's wbDES challenge (based on SysK's Phrack article)
- [**36**星][2m] [Py] [safebreach-labs/backdoros](https://github.com/safebreach-labs/backdoros) backdorOS is an in-memory OS written in Python 2.7 with a built-in in-memory filesystem, hooks for open() calls and imports, Python REPL etc.
- [**35**星][5y] [C++] [codereversing/wow64syscall](https://github.com/codereversing/wow64syscall) WoW64 Syscall Hooking
- [**35**星][3y] [C] [harvie/libpurple-core-answerscripts](https://github.com/harvie/libpurple-core-answerscripts) Most-hackable Pidgin plugin! Framework for hooking scripts to respond received messages for various libpurple clients such as pidgin or finch
- [**35**星][2y] [C] [jordan9001/superhide](https://github.com/jordan9001/superhide) Example of hooking a linux systemcall
- [**34**星][2y] [C++] [menooker/fishhook](https://github.com/menooker/fishhook) An inline hook platform for Windows x86/x64
- [**34**星][1y] [C++] [nickcano/reloadlibrary](https://github.com/nickcano/reloadlibrary) A quick-and-dirty anti-hook library proof of concept.
- [**34**星][11m] [C++] [niemand-sec/directx11hook](https://github.com/niemand-sec/directx11hook) 
- [**34**星][1y] [C#] [roshly/ayyhook-loader](https://github.com/roshly/ayyhook-loader) A Free Open Source Cheat Loader
- [**33**星][1y] [Py] [eset/volatility-browserhooks](https://github.com/eset/volatility-browserhooks) Volatility Framework plugin to detect various types of hooks as performed by banking Trojans
- [**32**星][2y] [ObjC] [zjjno/interface-inspector-hook](https://github.com/zjjno/interface-inspector-hook) Interface Inspector破解
- [**32**星][11m] [C++] [ganyao114/sandboxhookplugin](https://github.com/ganyao114/sandboxhookplugin) demo for inject & hook in sandbox
- [**31**星][5y] [idkwim/frooksinatra](https://github.com/idkwim/frooksinatra) POC of sysenter x64 LSTAR MSR hook
- [**31**星][4m] [C++] [rokups/hooker](https://github.com/rokups/hooker) Minimalistic hooking library written in C
- [**30**星][30d] [C++] [ayuto/dynamichooks](https://github.com/ayuto/dynamichooks) A C++ library to create function hooks dynamically, so you can easily embed it into other programming languages..
- [**30**星][1y] [C#] [dangbee/dotnethook](https://github.com/dangbee/dotnethook) A hook proof of concept with no native dependencies. Hook both .NET methods (even framework methods) and Native methods entirely in .NET.
- [**30**星][8m] [C#] [thaisenpm/loader2](https://github.com/thaisenpm/loader2) Nova Hook is an open source C# cheat loader currently built for CS:GO
- [**28**星][11m] [C++] [hoangprod/leospecial-veh-hook](https://github.com/hoangprod/leospecial-veh-hook) Vectored Exception Handling Hooking Class
- [**28**星][11m] [JS] [shanselman/daskeyboard-q-nightscout](https://github.com/shanselman/daskeyboard-q-nightscout) Hooking up the DasKeyboard Q REST API to change the key colors in response to diabetic's glucose from NightScout
- [**28**星][3y] [Py] [tr3jer/autohookspider](https://github.com/tr3jer/autohookspider) 将自动爬虫的结果判断是否属于hooks，并不断抓取url爬啊爬。
- [**27**星][2y] [C] [deroko/activationcontexthook](https://github.com/deroko/activationcontexthook) activationcontexthook：Hook 进程，强制进程加载重定向的 DLL
- [**27**星][1y] [HTML] [flyrabbit/winproject](https://github.com/flyrabbit/winproject) Hook, DLLInject, PE_Tool
- [**27**星][7m] [C++] [m-r-j-o-h-n/swh-injector](https://github.com/m-r-j-o-h-n/swh-injector) An Injector that can inject dll into game process protected by anti cheat using SetWindowsHookEx.
- [**27**星][4m] [C++] [netdex/twinject](https://github.com/netdex/twinject) Automated player and hooking framework for bullet hell games from the Touhou Project
- [**27**星][2y] [C] [sentinel-one/minhook](https://github.com/sentinel-one/minhook) The Minimalistic x86/x64 API Hooking Library for Windows
- [**27**星][3y] [C] [tinysec/runwithdll](https://github.com/tinysec/runwithdll) windows create process with a dll load first time via LdrHook
- [**26**星][6d] [Py] [esss/hookman](https://github.com/esss/hookman) A plugin management system in python to applications (in totally or partially) written in C++.
- [**26**星][3y] [C++] [ilyatk/hookengine](https://github.com/ilyatk/hookengine) 
- [**26**星][3y] [C] [scorchsecurity/toast](https://github.com/scorchsecurity/toast) User-mode hook bypassing method
- [**26**星][5y] [C++] [strobejb/sslhook](https://github.com/strobejb/sslhook) OpenSSL hooking
- [**25**星][2y] [Py] [dsnezhkov/octohook](https://github.com/dsnezhkov/octohook) Git Web Hook Tunnel for C2
- [**25**星][5m] [Java] [mx-futhark/hook-any-text](https://github.com/mx-futhark/hook-any-text) The goal of this project is to provide an alternative to well established text hookers, whose features are restrained to a certain number of game engines and emulators.
- [**25**星][2y] [Py] [rbeuque74/letsencrypt-ovh-hook](https://github.com/rbeuque74/letsencrypt-ovh-hook) Let's Encrypt hook for DNS validation for OVH domains
- [**24**星][3y] [C#] [nytrorst/hookme](https://github.com/nytrorst/hookme) Exported from
- [**23**星][3y] [C++] [apriorit/simple-antirootkit-sst-unhooker](https://github.com/apriorit/simple-antirootkit-sst-unhooker) This is a demo project to illustrate the way to verify and restore original SST in case of some malware hooks
- [**23**星][3y] [C] [david-reguera-garcia-dreg/phook](https://github.com/david-reguera-garcia-dreg/phook) Full DLL Hooking, phrack 65
- [**23**星][3y] [Java] [jackuhan/loginhook](https://github.com/jackuhan/loginhook) xposed的hook案例
- [**23**星][6y] [C] [jyang772/hideprocesshookmdl](https://github.com/jyang772/hideprocesshookmdl) A simple rootkit to hide a process
- [**23**星][7m] [C] [maikel233/x-hook-for-csgo](https://github.com/maikel233/x-hook-for-csgo) Aimtux for Windows.
- [**23**星][3y] [C++] [matviy/leaguereplayhook](https://github.com/matviy/leaguereplayhook) Library for interacting with the League of Legends Spectator/Replay Client
- [**23**星][3m] [C++] [legendl3n/smarthooker](https://github.com/legendl3n/smarthooker) The smartest hooking library.
- [**23**星][3y] [C++] [aixxe/cstrike-basehook-linux](https://github.com/aixxe/cstrike-basehook-linux) Internal project base for Counter-Strike: Source on Linux.
- [**23**星][7m] [C] [dodola/traphook](https://github.com/dodola/traphook) 
- [**22**星][3y] [C++] [bronzeme/ssdt_hook_x64](https://github.com/bronzeme/ssdt_hook_x64) 
- [**22**星][5m] [C++] [dodola/dinlinehook](https://github.com/dodola/dinlinehook) simple art inline hook
- [**21**星][4y] [C++] [xbased/xhook](https://github.com/xbased/xhook) Hook Windows API. supports Win7/8/10 x86 and x64 platform.
- [**21**星][1y] [Swift] [kealdishx/swiftloadhook](https://github.com/kealdishx/SwiftLoadHook) Use a hack way to achieve similar functions as Load() or initialize() in OC
- [**20**星][9m] [C#] [michel-pi/lowlevelinput.net](https://github.com/michel-pi/lowlevelinput.net) A thread safe and event driven LowLevelMouse and LowLevelKeyboard Hook
- [**20**星][2y] [ObjC] [zjjno/cornerstonehook](https://github.com/zjjno/cornerstonehook) Cornerstone破解
- [**19**星][2y] [Java] [col-e/simplified-jna](https://github.com/col-e/simplified-jna) Multi-threaded JNA hooks and simplified library access to window/key/mouse functions.
- [**19**星][10m] [Go] [viglesiasce/kubernetes-anchore-image-validator](https://github.com/viglesiasce/kubernetes-anchore-image-validator) Validating webhook for checking images against Anchore Engine Policy
- [**19**星][2y] [C] [xiaofen9/ssdthook](https://github.com/xiaofen9/ssdthook) An SSDT hook for Windows
- [**19**星][6y] [C++] [coreyauger/slimhook](https://github.com/coreyauger/slimhook) Demonstration of dll injection. As well loading .net runtime and calling .net code. Example hijacking d3d9 dll and altering rendering of games.
- [**18**星][5m] [Assembly] [egebalci/hook_api](https://github.com/egebalci/hook_api) Assembly block for hooking windows API functions.
- [**17**星][1y] [C] [adrianyy/kernelhook](https://github.com/adrianyy/kernelhook) Windows inline hooking tool.
- [**17**星][11m] [C] [plexsolutions/readhook](https://github.com/plexsolutions/readhook) Red-team tool to hook libc read syscall with a buffer overflow vulnerability.
- [**17**星][3y] [C] [zhuhuibeishadiao/kernelhooksdetection_x64](https://github.com/zhuhuibeishadiao/kernelhooksdetection_x64) x64 Kernel Hooks Detection
- [**16**星][1y] [JS] [compewter/whoof](https://github.com/compewter/whoof) Web Browser Hooking Framework. Manage, execute and assess web browser vulnerabilities
- [**16**星][3y] [C#] [lontivero/open.winkeyboardhook](https://github.com/lontivero/open.winkeyboardhook) A simple and easy-to-use .NET managed wrapper for Low Level Keyboard hooking.
- [**16**星][4y] [C] [zzy590/basiclibpp](https://github.com/zzy590/basiclibpp) A powerful library for inline-hook,lock,compress etc,and it is useful for anti-virus software.
- [**15**星][3y] [C++] [gfreivasc/vmthook](https://github.com/gfreivasc/vmthook) Virtual Method Table Hook
- [**15**星][2y] [C] [osrdrivers/penter](https://github.com/osrdrivers/penter) penter hook example and driver time recorder
- [**15**星][4y] [C] [sin5678/hidedir](https://github.com/sin5678/hidedir) 使用SSDT HOOK 在windows上隐藏指定文件或者文件夹
- [**15**星][12d] [C#] [reloaded-project/reloaded.hooks](https://github.com/reloaded-project/reloaded.hooks) Advanced native function hooks for x86, x64. Welcome to the next level!
- [**14**星][1y] [Go] [castaneai/hinako](https://github.com/castaneai/hinako) x86 WinAPI hook written in pure Go
- [**14**星][1y] [C++] [hmihaidavid/hooks](https://github.com/hmihaidavid/hooks) A DLL that performs IAT hooking
- [**14**星][1y] [C#] [ulysseswu/vinjex](https://github.com/ulysseswu/vinjex) A simple DLL injection lib using Easyhook, inspired by VInj.
- [**13**星][2y] [C] [hasherezade/loaderine](https://github.com/hasherezade/loaderine) A demo implementation of a well-known technique used by some malware to evade userland hooking, using my library: libpeconv.
- [**13**星][3y] [C++] [jonasblunck/dp](https://github.com/jonasblunck/dp) Win32 API and COM hooking/tracing.
- [**13**星][2y] [C#] [kanegovaert/unknown-logger](https://github.com/kanegovaert/unknown-logger) An advanced Windows Keylogger with features like (Disable CMD, Screenshotter, Client Stub Builder, Low Level Keyhooks, Hide Application, Respawner, Delete Chrome and Firefox data, and more!)
- [**13**星][4y] [C] [manicstreetcoders/appinitglobalhooks-mimikatz](https://github.com/manicstreetcoders/appinitglobalhooks-mimikatz) Hide Mimikatz From Process Lists
- [**13**星][10d] [C] [robotn/gohook](https://github.com/robotn/gohook) GoHook, Go global keyboard and mouse hook
- [**13**星][8m] [Visual Basic .NET] [thaisenpm/loader1](https://github.com/thaisenpm/loader1) Nova Hook is an open source VB.NET cheat loader currently built for CS:GO
- [**12**星][4y] [C++] [mgeeky/prc_xchk](https://github.com/mgeeky/prc_xchk) User-mode process cross-checking utility intended to detect naive malware hiding itself by hooking IAT/EAT.
- [**12**星][5y] [C] [s18leoare/hackshield-driver-bypass](https://github.com/s18leoare/hackshield-driver-bypass) Bypass HackShield several specific SSDT hook in Ring0
- [**12**星][4d] [Py] [thehive-project/thehivehooks](https://github.com/thehive-project/thehivehooks) This is a python tool aiming to make using TheHive webhooks easier.
- [**12**星][5y] [C++] [sin5678/wow64hook](https://github.com/sin5678/wow64hook) wow64 syscall filter
- [**11**星][2y] [C] [david-reguera-garcia-dreg/emuhookdetector](https://github.com/david-reguera-garcia-dreg/emuhookdetector) hook detector using emulation and comparing static with dynamic outputs
- [**11**星][7m] [C++] [scorbutics/iathook](https://github.com/scorbutics/iathook) A library that allows hook any imported function from the IAT (works only in x64)
- [**11**星][8m] [C++] [therena/findthestupidwindow](https://github.com/therena/findthestupidwindow) Windows API hooking project to log all the windows / UIs with the exact timestamp when they are opened.
- [**11**星][6y] [weixu8/registrymonitor](https://github.com/weixu8/registrymonitor) Formely KMon, a Windows Kernel Driver designed to prevent malware attacks by monitoring the creation of registry keys in common autorun locations and prompting the user whether they want to allow the creation of the key. More of an experiment into Kernel level SSDT hooks but a fun project nonetheless
- [**11**星][1y] [C#] [20chan/globalhook](https://github.com/20chan/GlobalHook) Simple global keyboard, mouse hook and simulation library written C#
- [**10**星][3y] [HTML] [lcatro/cross_domain_postmessage_vuln_dig](https://github.com/lcatro/cross_domain_postmessage_vuln_dig) WEB 跨域postMessage() 漏洞挖掘工具,基本原理:使用AJAX 获取页面代码,结合iframe 和data 协议构造测试环境,然后在iframe 下的window.onmessage 中插入hook 监控onmessage 的参数,最后通过能否被原来的onmessage 逻辑引用参数中的data 属性来判断是否可以跨域传递数据..
- [**10**星][7y] [Py] [nitram2342/spooky-hook](https://github.com/nitram2342/spooky-hook) WinAppDbg helper script to catch API calls
- [**9**星][2y] [C++] [david-grs/mtrace](https://github.com/david-grs/mtrace) simple c++ hooks around malloc/realloc/free
- [**9**星][5m] [C++] [guided-hacking/gh_d3d11_hook](https://github.com/guided-hacking/gh_d3d11_hook) Barebones D3D11 hook.
- [**9**星][3y] [C++] [jonasblunck/dynhook](https://github.com/jonasblunck/dynhook) Example library for how to dynamically/statically hook/intercept unmanaged functions and APIs
- [**9**星][3y] [C] [papadp/shd](https://github.com/papadp/shd) Ssdt Hook Detection tool
- [**9**星][4y] [C++] [windy32/win32-console-hook-lib](https://github.com/windy32/win32-console-hook-lib) A light-weight console hook library for convenient console interactions
- [**8**星][2y] [coolervoid/bank_mitigations](https://github.com/coolervoid/bank_mitigations) Anti keylogger, anti screen logger... Strategy to protect with hookings or improve your sandbox with spyware detection... - Demo
- [**8**星][2y] [C] [hollydi/ring0hook](https://github.com/hollydi/ring0hook) 
- [**8**星][1y] [C++] [nybble04/shady-hook](https://github.com/nybble04/shady-hook) Hooking API calls of a Ransomware
- [**8**星][2m] [C] [rafael-santiago/kook](https://github.com/rafael-santiago/kook) A syscall hooking system for FreeBSD, NetBSD and also Linux.
- [**8**星][2y] [Swift] [zhangkn/hookingcmethods](https://github.com/zhangkn/hookingcmethods) Hooking & Executing Code with dlopen & dlsym ---Easy mode:hooking C methods
- [**7**星][5m] [C] [cherryzy/process_protect_module](https://github.com/cherryzy/process_protect_module) Monitor and protect processes use "PsSetCreateProcessNotifyRoutineEx" and kernel ssdt hook.
- [**7**星][5y] [C++] [codereversing/sehveh_hook](https://github.com/codereversing/sehveh_hook) Hooking functions with structured and vectored exception handling
- [**7**星][4y] [C++] [cyrex1337/hook.lib](https://github.com/cyrex1337/hook.lib) easy detour-, vftable-, iat- and eathooking
- [**7**星][4y] [C] [david-reguera-garcia-dreg/cgaty](https://github.com/david-reguera-garcia-dreg/cgaty) Hooking the GDT - Installing a Call Gate. POC for Rootkit Arsenal Book Second Edition
- [**7**星][3y] [Java] [fuhuiliu/xposedhooktarget](https://github.com/fuhuiliu/xposedhooktarget) Xposed 插件基础开发之Hook目标
- [**7**星][1y] [Go] [nanitefactory/hookwin10calc](https://github.com/nanitefactory/hookwin10calc) Reverse engineered Windows 10 Calculator.exe (UWP application) hacker. 한글/漢文을 배운 윈도우 계산기 패치.
- [**6**星][1y] [C] [sizet/lkm_parse_dns_packet](https://github.com/sizet/lkm_parse_dns_packet) linux 核心模組, 使用 netfilter IPv4 hook 監聽和分析 DNS 請求和回應封包.
- [**6**星][6y] [C++] [wyrover/hkkerneldbg](https://github.com/wyrover/hkkerneldbg) F**k ssdt hook in np, tp, hs
- [**6**星][7y] [C++] [wyyqyl/hookiat](https://github.com/wyyqyl/hookiat) 
- [**5**星][6y] [C#] [aristocat/keyhook](https://github.com/aristocat/keyhook) A C# library for general hot keys.
- [**5**星][2y] [C++] [nexus-devs/nexus-hook](https://github.com/nexus-devs/nexus-hook) Hooking functionality for DirectX11 applications
- [**5**星][4m] [Erlang] [pouriya-jahanbakhsh/posthaste](https://github.com/pouriya-jahanbakhsh/posthaste) Blazingly fast Erlang/Elixir hooking library.
- [**5**星][3y] [Java] [lailune/slrrmultiplayer](https://github.com/lailune/slrrmultiplayer) Street Legal: Redline hook-based Multiplayer modification
- [**4**星][1y] [C++] [a7031x/hookapi](https://github.com/a7031x/hookapi) Handy way to hook x86 or x64 API
- [**4**星][1y] [C++] [aschrein/apiparse](https://github.com/aschrein/apiparse) Small project to learn windows dll hooking techniques based on sources of renderdoc and apitrace
- [**4**星][3y] [C++] [blaquee/apchook](https://github.com/blaquee/apchook) hooking KiUserApcDispatcher
- [**4**星][3y] [ObjC] [corzfree/hookwx](https://github.com/corzfree/hookwx) 逆向工具
- [**4**星][1y] [C++] [m0rtale/universal-wndproc-hook](https://github.com/m0rtale/universal-wndproc-hook) Universal WndProc Hook for x86 and x64
- [**4**星][6y] [C] [nikolait/chess-com-cheat](https://github.com/nikolait/chess-com-cheat) Library that hooks into PR_Write() and PR_Read() in firefox processes and manipulates WebSocket Messages to cheat on chess.com
- [**4**星][3y] [C#] [trojaner/rocketplus](https://github.com/trojaner/rocketplus) Adding extra functionality to RocketMod API by using method hooking [Windows x64 only]. Also provides an API for .NET Method detouring
- [**4**星][2y] [C++] [wanttobeno/ade32_inlinehook](https://github.com/wanttobeno/ade32_inlinehook) 基于ADE32的inlineHook
- [**4**星][2y] [C++] [wanttobeno/window_keyandmousehook](https://github.com/wanttobeno/window_keyandmousehook) Window Key And Mouse Hook
- [**3**星][4y] [C] [deb0ch/toorkit](https://github.com/deb0ch/toorkit) A simple useless rootkit for the linux kernel. It is a kernel module which hooks up the open() syscall (or potentially any syscall) to replace it with a custom function.
- [**3**星][2y] [C] [sqdwr/64-bits-inserthook](https://github.com/sqdwr/64-bits-inserthook) insert a ssdt table to hook
- [**3**星][3y] [C++] [zhipeng515/memberfunctionhook](https://github.com/zhipeng515/memberfunctionhook) 类成员函数转成普通函数，SetWindowsHookEx可以使用类成员函数作为回调函数
- [**2**星][3y] [Ruby] [andersondadario/costa-scanner](https://github.com/andersondadario/costa-scanner) Security tool to spot new servers within networks & take action (security scan, email, webhook, etc)
- [**2**星][4y] [C] [microwave89/ntapihook](https://github.com/microwave89/ntapihook) Attempt to Create a Simple and Light-weight Hook Engine Without Use of an LDE
- [**2**星][18d] [Py] [swarren/uboot-test-hooks](https://github.com/swarren/uboot-test-hooks) Example "hook" scripts for the U-Boot test framework
- [**2**星][2y] [C] [synestraa/archultimate.hooklib](https://github.com/synestraa/archultimate.hooklib) ArchUltimate hook library
- [**1**星][2y] [C++] [amazadota/afd-hook-](https://github.com/amazadota/afd-hook-) win32 IAT HOOK 抓包
- [**1**星][10m] [TS] [larkintuckerllc/hello-hooks](https://github.com/larkintuckerllc/hello-hooks) 
- [**1**星][1y] [C++] [smore007/remote-iat-hook](https://github.com/smore007/remote-iat-hook) Remote IAT hook example. Useful for code injection
- [**1**星][2y] [C++] [wanttobeno/mousehook](https://github.com/wanttobeno/mousehook) SetWindowsHookEx的使用例子
- [**1**星][2y] [ObjC] [wpstarnice/hookstatistics](https://github.com/wpstarnice/hookstatistics) 
- [**1**星][2y] [C++] [zuhhcsg0/nebulahook](https://github.com/zuhhcsg0/nebulahook) 
- [**1**星][2y] [C] [chocolateboy/b-hooks-op-annotation](https://github.com/chocolateboy/b-hooks-op-annotation) A Perl module which allows XS modules to annotate and delegate hooked OPs
- [**1**星][12d] [C] [u2400/libc_hook_demo](https://github.com/u2400/libc_hook_demo) 一个通过libc对进程进行hook并获取进程相关信息的demo
- [**0**星][2y] [Rust] [badboy/travis-after-all-rs](https://github.com/badboy/travis-after-all-rs) The missing `after_all_success` hook for Travis
- [**0**星][1y] [C] [cblack-r7/hashcat-hook](https://github.com/cblack-r7/hashcat-hook) A few LD_PRELOAD hooks to fix specific issues with hashcat
- [**0**星][1y] [Py] [ciscose/sparkhelper](https://github.com/ciscose/sparkhelper) A few of functions that help with checking that your bot is being used by an approved organization and for verifying the signature of a web hook request.
- [**0**星][3y] [Py] [howmp/webhook](https://github.com/howmp/webhook) 
- [**0**星][2y] [C] [vallejocc/poc-find-chrome-ktlsprotocolmethod](https://github.com/vallejocc/poc-find-chrome-ktlsprotocolmethod) Proof of Concept code to download chrome.dll symbols from chromium symbols store and find the bssl::kTLSProtocolMethod table of pointers (usually hooked by malware)


# <a id="70e64e3147675c9bcd48d4f475396e7f"></a>Monitor&&监控&&Trace&&追踪


***


## <a id="cd76e644d8ddbd385939bb17fceab205"></a>工具


- [**1419**星][9m] [C] [namhyung/uftrace](https://github.com/namhyung/uftrace) Function (graph) tracer for user-space
- [**186**星][2y] [C++] [sidechannelmarvels/tracer](https://github.com/sidechannelmarvels/tracer) Set of Dynamic Binary Instrumentation and visualization tools for execution traces.
- [**157**星][19d] [C] [immunityinc/libptrace](https://github.com/immunityinc/libptrace) An event driven multi-core process debugging, tracing, and manipulation framework.
- [**138**星][25d] [PS] [lazywinadmin/monitor-adgroupmembership](https://github.com/lazywinadmin/Monitor-ADGroupMembership) PowerShell script to monitor Active Directory groups and send an email when someone is changing the membership
- [**115**星][9y] [C] [ice799/ltrace](https://github.com/ice799/ltrace) ltrace intercepts and records dynamic library calls which are called by an executed process and the signals received by that process. It can also intercept and print the system calls executed by the program.
- [**110**星][2y] [C#] [goldshtn/etrace](https://github.com/goldshtn/etrace) Command-line tool for ETW tracing on files and real-time events
- [**108**星][22d] [ObjC] [objective-see/processmonitor](https://github.com/objective-see/processmonitor) Process Monitor Library (based on Apple's new Endpoint Security Framework)
- [**96**星][6m] [Py] [teemu-l/execution-trace-viewer](https://github.com/teemu-l/execution-trace-viewer) Tool for viewing and analyzing execution traces
- [**91**星][2y] [C++] [epam/nfstrace](https://github.com/epam/nfstrace) Network file system monitor and analyzer
- [**88**星][2m] [Py] [assurancemaladiesec/certstreammonitor](https://github.com/assurancemaladiesec/certstreammonitor) Monitor certificates generated for specific domain strings and associated, store data into sqlite3 database, alert you when sites come online.
- [**83**星][1y] [C] [marcusbotacin/branchmonitoringproject](https://github.com/marcusbotacin/branchmonitoringproject) A branch-monitor-based solution for process monitoring.
- [**82**星][4y] [C] [eklitzke/ptrace-call-userspace](https://github.com/eklitzke/ptrace-call-userspace) Example of how to use the ptrace(2) system call to call a userspace method.
- [**71**星][7m] [C++] [invictus1306/functrace](https://github.com/invictus1306/functrace) A function tracer
- [**68**星][2y] [Py] [ianmiell/autotrace](https://github.com/ianmiell/autotrace) Runs a process, and gives you the output along with other telemetry on the process, all in one terminal window.
- [**62**星][2y] [C++] [finixbit/ftrace](https://github.com/finixbit/ftrace) Simple Function calls tracer
- [**60**星][2y] [DTrace] [brendangregg/dtrace-tools](https://github.com/brendangregg/dtrace-tools) DTrace tools for FreeBSD
- [**52**星][3y] [C] [sciencemanx/ftrace](https://github.com/sciencemanx/ftrace) trace local function calls like strace and ltrace
- [**46**星][6m] [Go] [oscp/openshift-monitoring](https://github.com/oscp/openshift-monitoring) A realtime distributed monitoring tool for OpenShift Enterprise
- [**44**星][5y] [C] [rpaleari/qtrace](https://github.com/rpaleari/qtrace) QTrace, a "zero knowledge" system call tracer
- [**39**星][4y] [C++] [simutrace/simutrace](https://github.com/simutrace/simutrace) Tracing framework for full system simulators
- [**37**星][1y] [C] [egguncle/ptraceinject](https://github.com/egguncle/ptraceinject) 进程注入
- [**35**星][5d] [C] [efficios/babeltrace](https://github.com/efficios/babeltrace) The Babeltrace project provides trace read and write libraries, as well as a trace converter. Plugins can be created for any trace format to allow its conversion to/from another trace format.
- [**32**星][1y] [C] [alex9191/kernelmodemonitor](https://github.com/alex9191/kernelmodemonitor) Kernel-Mode driver and User-Mode application communication project
- [**31**星][1y] [C] [iamgublin/ndis6.30-netmonitor](https://github.com/iamgublin/ndis6.30-netmonitor) NDIS6.30 Filter Library
- [**27**星][1y] [C] [openbsm/bsmtrace](https://github.com/openbsm/bsmtrace) BSM based intrusion detection system
- [**26**星][2y] [Go] [benjojo/traceroute-haiku](https://github.com/benjojo/traceroute-haiku) A thing you can traceroute and it gives you a haiku inside the trace
- [**25**星][2m] [C] [airbus-cert/pstrace](https://github.com/airbus-cert/pstrace) Trace ScriptBlock execution for powershell v2
- [**24**星][2y] [C++] [sshsshy/zerotrace](https://github.com/sshsshy/zerotrace) 
- [**21**星][2y] [C++] [microsoft/firewalleventmonitor](https://github.com/microsoft/firewalleventmonitor) Listens for Firewall rule match events generated by Microsoft Hyper-V Virtual Filter Protocol (VFP) extension.


# <a id="28aa8187f8a1e38ca5a55aa31a5ee0c3"></a>Game&&游戏


***


## <a id="07f0c2cbf63c1d7de6f21fa43443ede3"></a>工具


- [**2457**星][2d] [C#] [netchx/netch](https://github.com/netchx/netch) 游戏加速器。支持:Socks5, Shadowsocks, ShadowsocksR, V2Ray 协议
- [**1461**星][2y] [C++] [acaudwell/logstalgia](https://github.com/acaudwell/logstalgia)  a visualization tool that replays or streams web server access logs as a retro arcade game simulation.
- [**1148**星][4d] [C++] [crosire/reshade](https://github.com/crosire/reshade) A generic post-processing injector for games and video software.
- [**1127**星][3m] [Py] [openai/neural-mmo](https://github.com/openai/neural-mmo) Code for the paper "Neural MMO: A Massively Multiagent Game Environment for Training and Evaluating Intelligent Agents"
- [**1020**星][1m] [C] [bt3gl/pentesting-toolkit](https://github.com/bt3gl/Pentesting-Toolkit) 渗透测试，CTF和战争游戏的工具收集
- [**727**星][6m] [Assembly] [cirosantilli/x86-assembly-cheat](https://github.com/cirosantilli/x86-assembly-cheat) the bulk of the x86 instruction examples with assertions.
- [**545**星][t] [C++] [danielkrupinski/osiris](https://github.com/danielkrupinski/osiris) 开源培训软件/“反恐精英：全球攻势”游戏作弊工具。设计为内部作弊-可将动态链接库（DLL）加载到游戏过程中
- [**522**星][3m] [Kotlin] [jire/charlatano](https://github.com/jire/charlatano) Proves JVM cheats are viable on native games, and demonstrates the longevity against anti-cheat signature detection systems
- [**405**星][1y] [C#] [squalr/squalr](https://github.com/squalr/squalr) 高性能的内存编辑软件，允许用户在Windows桌面游戏中创建和共享作弊文件
- [**399**星][14d] [Py] [moloch--/rootthebox](https://github.com/moloch--/rootthebox) A Game of Hackers (CTF Scoreboard & Game Manager)
- [**395**星][4y] [PHP] [breakthenet/hackme-sql-injection-challenges](https://github.com/breakthenet/hackme-sql-injection-challenges) Pen test your "friend's" online MMORPG game - specific focus, sql injection opportunities
- [**360**星][3y] [C++] [gamehackingbook/gamehackingcode](https://github.com/gamehackingbook/gamehackingcode) 《游戏黑客：为在线游戏开发自主机器人》一书的代码。
- [**352**星][] [C#] [leaguesandbox/gameserver](https://github.com/leaguesandbox/gameserver) League Sandbox's Game Server
- [**352**星][1m] [C] [liji32/sameboy](https://github.com/liji32/sameboy) Game Boy and Game Boy Color emulator written in C
- [**344**星][1y] [valvesoftware/source-1-games](https://github.com/valvesoftware/source-1-games) Source 1 based games such as TF2 and Counter-Strike: Source
- [**300**星][] [C++] [squalr/squally](https://github.com/squalr/squally) 2D Platformer Game for Teaching Game Hacking - C++/cocos2d-x
- [**265**星][18d] [C++] [niemand-sec/anticheat-testing-framework](https://github.com/niemand-sec/anticheat-testing-framework) Framework to test any Anti-Cheat
- [**264**星][t] [C++] [fransbouma/injectablegenericcamerasystem](https://github.com/fransbouma/injectablegenericcamerasystem) This is a generic camera system to be used as the base for cameras for taking screenshots within games. The main purpose of the system is to hijack the in-game 3D camera by overwriting values in its camera structure with our own values so we can control where the camera is located, it's pitch/yaw/roll values, its FoV and the camera's look vector.
- [**249**星][2y] [C] [zer0mem0ry/kernelbhop](https://github.com/zer0mem0ry/kernelbhop) Cheat that uses a driver instead WinAPI for Reading / Writing memory.
- [**247**星][2d] [CSS] [steamdatabase/gametracking-dota2](https://github.com/steamdatabase/gametracking-dota2) 
- [**246**星][1y] [xcsh/unity-game-hacking](https://github.com/xcsh/unity-game-hacking) A guide for hacking unity games
- [**245**星][5y] [C++] [gametutorials/tutorials](https://github.com/gametutorials/tutorials) This holds the tutorials for GameTutorials.com
- [**224**星][6m] [JS] [pavanw3b/sh00t](https://github.com/pavanw3b/sh00t) Security Testing is not as simple as right click > Scan. It's messy, a tough game. What if you had missed to test just that one thing and had to regret later? Sh00t is a highly customizable, intelligent platform that understands the life of bug hunters and emphasizes on manual security testing.
- [**220**星][2y] [Py] [vlall/darksearch](https://github.com/vlall/darksearch) query cached onion sites, irc chatrooms, various pdfs, game chats, blackhat forums etc
- [**215**星][6m] [C#] [erfg12/memory.dll](https://github.com/erfg12/memory.dll) C# Hacking library for making PC game trainers.
- [**215**星][3m] [C] [xyzz/gamecard-microsd](https://github.com/xyzz/gamecard-microsd) microSD adapter for PlayStation Vita
- [**214**星][4m] [C++] [eternityx/deadcell-csgo](https://github.com/eternityx/deadcell-csgo) Full source to the CS:GO cheat
- [**201**星][3y] [Assembly] [vector35/pwnadventurez](https://github.com/vector35/pwnadventurez) NES zombie survival game made to be hacked
- [**196**星][1y] [Java] [nocheatplus/nocheatplus](https://github.com/nocheatplus/nocheatplus) Anti cheating plugin for Minecraft (Bukkit/Spigot).
- [**196**星][10m] [zardus/wargame-nexus](https://github.com/zardus/wargame-nexus) An sorted and updated list of security wargame sites.
- [**195**星][6d] [Shell] [steamdatabase/gametracking](https://github.com/steamdatabase/gametracking) 
- [**190**星][5d] [C++] [s1lentq/regamedll_cs](https://github.com/s1lentq/regamedll_cs) 
- [**188**星][4y] [krmaxwell/coding-entertainment](https://github.com/krmaxwell/coding-entertainment) Puzzles, challenges, games, CTFs, and other entertainment via coding
- [**177**星][3y] [hexorg/cheatenginetables](https://github.com/hexorg/cheatenginetables) Repository of tables for CheatEngine
- [**174**星][7m] [C#] [krzys-h/undertalemodtool](https://github.com/krzys-h/undertalemodtool) The most complete tool for modding, decompiling and unpacking Undertale (and other Game Maker: Studio games!)
- [**168**星][2m] [JS] [bencoder/js13k-2019](https://github.com/bencoder/js13k-2019) xx142-b2.exe. An entry for js13kgames 2019
- [**165**星][5m] [C++] [a5-/gamerfood_csgo](https://github.com/a5-/gamerfood_csgo) Fully featured CSGO cheat by Team Gamerfood
- [**155**星][10d] [C] [ray-cp/vm-escape](https://github.com/ray-cp/vm-escape) some interesting vm-escape game
- [**129**星][1y] [C++] [mq1n/nomercy](https://github.com/mq1n/nomercy) Open source anti cheat
- [**121**星][19d] [portswigger/xss-cheatsheet-data](https://github.com/portswigger/xss-cheatsheet-data) This repository contains all the XSS cheatsheet data to allow contributions from the community.
- [**113**星][2y] [C++] [scgywx/fooking](https://github.com/scgywx/fooking) distributed gateway server(php game server, tcp server, websocket server)
- [**112**星][22d] [C#] [manlymarco/runtimeunityeditor](https://github.com/manlymarco/runtimeunityeditor) In-game inspector and debugging tools for applications made with Unity3D game engine
- [**112**星][1m] [Py] [yuawn/ctf](https://github.com/yuawn/CTF) CTF write-ups and some wargame sites write-ups.
- [**110**星][1y] [mitre/brawl-public-game-001](https://github.com/mitre/brawl-public-game-001) Data from a BRAWL Automated Adversary Emulation Exercise
- [**109**星][25d] [leomaurodesenv/game-datasets](https://github.com/leomaurodesenv/game-datasets) 
- [**95**星][9m] [C] [sagaantheepic/sagaan-anticheat-v2.0](https://github.com/ContionMig/ContionMig-AntiCheat) Anti Cheat i made in my free time. Credits to everyone who helped are in the files and some are in the code. I will definitely improve this Anti Cheat along the way, now its just beta. Enjoy.
- [**92**星][8m] [C++] [huanghongkai/game-helper](https://github.com/huanghongkai/game-helper) 介绍入门级游戏辅助的原理，内附有2018年2月dnf辅助C++源码
- [**87**星][6m] [TeX] [rudymatela/concise-cheat-sheets](https://github.com/rudymatela/concise-cheat-sheets) Cheat Sheets for programming languages and tools
- [**83**星][5m] [Py] [ray-cp/pwn_debug](https://github.com/ray-cp/pwn_debug) Aim to help building exploitation of CTFs pwn game quickly
- [**82**星][3m] [Py] [mattcurrie/mgbdis](https://github.com/mattcurrie/mgbdis) Game Boy ROM disassembler with RGBDS compatible output
- [**80**星][6m] [C] [adangert/spytag-wifi-game](https://github.com/adangert/spytag-wifi-game) WIFI hide and seek tag
- [**80**星][2y] [JS] [vmikhav/antipacman](https://github.com/vmikhav/AntiPacMan) HTML5 Pac-Man game with gesture recognition
- [**77**星][1y] [C] [contionmig/kernelmode-bypass](https://github.com/ContionMig/KernelMode-Bypass) This is a source to a bypass i made for some games, for now this should work f or VAC, BE and EAC. The only downside is that you will need to find a exploit to load the driver
- [**77**星][3m] [ignitetechnologies/web-application-cheatsheet](https://github.com/ignitetechnologies/web-application-cheatsheet) This cheatsheet is aimed at the CTF Players and Beginners to help them understand Web Application Vulnerablity with examples.
- [**63**星][8y] [Java] [yifanlu/psxperia](https://github.com/yifanlu/psxperia) This tool will take a PSX image that you legally own and convert it to be playable on the Xperia Play with the emulator extracted from the packaged game "Crash Bandicoot."
- [**63**星][1m] [C#] [firebaseextended/unity-solutions](https://github.com/FirebaseExtended/unity-solutions) Use Firebase tools to incorporate common features into your games!
- [**61**星][3y] [Shell] [abs0/wargames](https://github.com/abs0/wargames) Shell script to simulate the W.O.P.R. computer from WarGames (wopr)
- [**61**星][8m] [C++] [apexlegendsuc/anti-cheat-emulator](https://github.com/apexlegendsuc/anti-cheat-emulator) 
- [**60**星][8y] [JS] [jbuck/input.js](https://github.com/jbuck/input.js) Input.js is a JavaScript library to map controller and OS-specific USB enumerations provided by the Gamepad API in Mozilla Firefox to an ideal virtual gamepad.
- [**60**星][2y] [C++] [jmasterx/agui](https://github.com/jmasterx/agui) C++ GUI API Aimed at Games
- [**57**星][6m] [JS] [doctormckay/node-globaloffensive](https://github.com/doctormckay/node-globaloffensive) A Node.js module to connect to and interact with the CS:GO game coordinator. Mostly used to get item data.
- [**56**星][2y] [Py] [p1kachu/talking-with-cars](https://github.com/p1kachu/talking-with-cars) CAN analysis - Use your car as a gamepad!
- [**55**星][8m] [JS] [jes/chess-steg](https://github.com/jes/chess-steg) Steganography in chess games
- [**53**星][3y] [C] [jonathanopalise/ppengine](https://github.com/jonathanopalise/ppengine) 3D remake of Atari's Pole Position coin-op, using game logic reverse engineered from the arcade ROMs
- [**50**星][6m] [Rich Text Format] [adamshostack/eop](https://github.com/adamshostack/eop) The Elevation of Privilege Threat Modeling Game
- [**50**星][3y] [C] [ryanmallon/thelostvikingstools](https://github.com/ryanmallon/thelostvikingstools) Reverse Engineered Tools/Library for the DOS game The Lost Vikings
- [**47**星][4y] [Py] [topshed/rpi_8x8griddraw](https://github.com/topshed/rpi_8x8griddraw) A Python Pygame application for creating 8x8 images to load onto the Astro-Pi LED matrix
- [**47**星][8m] [Py] [ctf-o-matic/capture-the-flag](https://github.com/ctf-o-matic/capture-the-flag) Helper scripts to remaster Linux Live CD images for the purpose of creating ready to use security wargames with pre-installed vulnerabilities to exploit.
- [**46**星][1y] [Py] [towerofhanoi/ctfsubmitter](https://github.com/towerofhanoi/ctfsubmitter) A flag submitter service with distributed attackers for attack/defense CTF games.
- [**45**星][9m] [C++] [ncatlin/exilesniffer](https://github.com/ncatlin/exilesniffer) A protocol decryption and dissection tool for the game 'Path of Exile'
- [**45**星][1m] [Py] [skoolkid/skoolkit](https://github.com/skoolkid/skoolkit) A suite of tools for creating disassemblies of ZX Spectrum games.
- [**44**星][2y] [C#] [mythicmaniac/keyboard-minigames](https://github.com/mythicmaniac/keyboard-minigames) A snake game for the corsair RGB keyboards
- [**43**星][2y] [JS] [auth0-blog/aliens-go-home-part-1](https://github.com/auth0-blog/aliens-go-home-part-1) GitHub repository that accompanies the first article of the "Developing Games with React, Redux, and SVG" series.
- [**43**星][3m] [Pawn] [stypr/tmpleak](https://github.com/stypr/tmpleak) Leak off used temporary workspaces for ctf and wargames!
- [**42**星][1m] [JS] [macabeus/klo-gba.js](https://github.com/macabeus/klo-gba.js) 🧢 Reverse engineering tool for the Klonoa's GBA game
- [**41**星][2y] [oscarakaelvis/game-of-thrones-hacking-ctf](https://github.com/oscarakaelvis/game-of-thrones-hacking-ctf) Game of Thrones hacking CTF (Capture the flag)
- [**41**星][4m] [SourcePawn] [splewis/csgo-executes](https://github.com/splewis/csgo-executes) CS:GO SourceMod plugin for a site-execute practice gamemode
- [**39**星][3d] [Shell] [steamdatabase/gametracking-tf2](https://github.com/steamdatabase/gametracking-tf2) 
- [**39**星][2y] [C#] [denikson/cm3d2.maidfiddler](https://github.com/denikson/cm3d2.maidfiddler) A real-time game editor for CM3D2
- [**38**星][2y] [c++] [fluc-uc/emusdk](https://github.com/fluc-uc/emusdk) A simple SDK intended for people new to internal cheats. Written while I was drunk.
- [**38**星][1y] [C++] [contionmig/lsass-usermode-bypass](https://github.com/ContionMig/LSASS-Usermode-Bypass) This bypass is for anti cheats like battleye and EAC. All this does is abuse lsass's handles and use them for yourself. This is quite useful as this is usermode which doesnt require you to find a way to load a driver
- [**37**星][2y] [C] [mlafeldt/ps2rd](https://github.com/mlafeldt/ps2rd) Collection of tools to remotely debug PS2 games
- [**36**星][1m] [Assembly] [dpt/the-great-escape](https://github.com/dpt/the-great-escape) Reverse engineering classic ZX Spectrum game "The Great Escape"
- [**36**星][10m] [C++] [nanoric/pkn](https://github.com/nanoric/pkn) core of pkn game hacking project. Including mainly for process management, memory management, and DLL injecttion. Also PE analysis, windows registry management, compile-time sting encryption, byte-code emulator, etc. Most of them can run under kernel mode.
- [**35**星][4y] [Py] [iiseymour/game-of-life](https://github.com/iiseymour/game-of-life) Conway's Game Of Life with a small evolutionary twist.
- [**35**星][6y] [C++] [scen/ionlib](https://github.com/scen/ionlib) c++11 reverse engineering library. bootstraps common tasks in game hacking and reverse engineering
- [**35**星][2y] [Java] [thecyaniteproject/exit_code_java](https://github.com/thecyaniteproject/exit_code_java) ExitCode - The Free, Open-Source, Desktop & Hacking Simulator Game.
- [**34**星][1y] [vu-aml/adlib](https://github.com/vu-aml/adlib) Game-Theoretic Adversarial Machine Learning Library
- [**34**星][3m] [PHP] [safflower/solveme](https://github.com/safflower/solveme) SolveMe - Jeopardy CTF Platform (for wargame)
- [**33**星][2m] [C++] [chinatiny/gameanticheat](https://github.com/chinatiny/gameanticheat) 反外挂
- [**33**星][29d] [C] [root670/cheatdeviceps2](https://github.com/root670/cheatdeviceps2) Game enhancer for PlayStation 2 similar to Action Replay, GameShark, and CodeBreaker.
- [**31**星][2y] [Py] [benjamincrom/scrabble](https://github.com/benjamincrom/scrabble) Implements Scrabble. Also allows user to recover all game moves from given board and score list as well as brute-force find best move.
- [**30**星][4y] [C#] [aevitas/orion](https://github.com/aevitas/orion) Managed game manipulation framework for Counter Strike: Global Offensive in C#
- [**30**星][1y] [C++] [certt/1000base](https://github.com/certt/1000base) CS:GO cheat base
- [**30**星][2y] [C++] [vic4key/cat-driver](https://github.com/vic4key/cat-driver) CatDriver - The Kernel Mode Driver that written in C++. It is an useful driver and has the highest privilege level on the Windows platform. It can be used for Game Hacking and others.
- [**28**星][4y] [JS] [crisu83/ctf-game](https://github.com/crisu83/ctf-game) Fast-paced hot seat multiplayer game written in modern JavaScript.
- [**26**星][1y] [C++] [cyanidee/snowflake](https://github.com/cyanidee/snowflake) A simple CSGO cheat base written in mind of begginers.
- [**26**星][3y] [Ruby] [qazbnm456/docker-war](https://github.com/qazbnm456/docker-war) Docker based Wargame Platform - To practice your CTF skills
- [**25**星][3y] [C++] [vix597/vulny](https://github.com/vix597/vulny) Vulnerable Linux socket game for educational purposes
- [**24**星][2y] [JS] [auth0-blog/nextjs-got](https://github.com/auth0-blog/nextjs-got) A simple nextjs application that showcases Game of Thrones Characters
- [**24**星][1y] [Py] [gynvael/arcanesector](https://github.com/gynvael/arcanesector) Arcane Sector game - a CTF task, or old-school (MMO)RPG - depending on the perspective. The code is of terrible quality, you have been warned!
- [**24**星][11m] [C++] [shaxzy/nixware-csgo](https://github.com/shaxzy/nixware-csgo) Source code of Nixware. Cheat doesn't inject for some reason, fix it uself or just paste from it
- [**23**星][1y] [C#] [arkhist/hacklinks](https://github.com/arkhist/hacklinks) Hacklinks is an open source online game about hacking.
- [**23**星][8m] [C] [sintech/flip-dot-display](https://github.com/sintech/flip-dot-display) Flip-Dot display reverse engineering, DIY adapter board, Tetris game.
- [**23**星][2y] [JS] [team-copper/captar](https://github.com/team-copper/captar) Augmented Reality Geolocation Capture-the-Flag Mobile Game Capstone Project
- [**22**星][3m] [Ruby] [karneades/defensomania](https://github.com/karneades/defensomania) Defensomania is a card game for security monitoring and incident response teams.
- [**21**星][5y] [C++] [r-lyeh-archived/moon9](https://github.com/r-lyeh-archived/moon9) a game framework. warning: wip, dev, unstable, radiation hazard, defcon 3
- [**20**星][2y] [C] [bisoon/ps4-api-server](https://github.com/bisoon/ps4-api-server) PS4API server to handle client request for read/write to game memory
- [**20**星][2y] [C++] [mrexodia/ceautoattach](https://github.com/mrexodia/ceautoattach) Tool to automatically make Cheat Engine attach to a process via the command line.
- [**20**星][2y] [C] [nkga/cheat-driver](https://github.com/nkga/cheat-driver) Kernel mode driver for reading/writing process memory. C/Win32.
- [**19**星][4y] [C#] [bellapatricia/anothersc2hack](https://github.com/bellapatricia/anothersc2hack) Hacking Blizzard Entertainment's Game "StarCraft II" with external methods
- [**19**星][2y] [PHP] [mchow01/tufts-ctf-fall2014-docker](https://github.com/mchow01/tufts-ctf-fall2014-docker) Files to build Docker image of Capture the Flags (CTF) game
- [**18**星][2y] [C] [1bitsy/1bitsy-1up](https://github.com/1bitsy/1bitsy-1up) 1Bitsy 1UP retro inspired handheld game console.
- [**18**星][6m] [Py] [fausecteam/ctf-gameserver](https://github.com/fausecteam/ctf-gameserver) 
- [**17**星][3y] [C] [fakeaim/d3d-model-recognition](https://github.com/fakeaim/d3d-model-recognition) D3D/DirectX Model recognition values for multiple games, used to create wallhack or chams
- [**17**星][1m] [Py] [junhoyeo/writeups](https://github.com/junhoyeo/writeups) 🏴‍☠️ 각종 대회 문제풀이 / WriteUp files from CTF(Capture The Flag) contests & Wargames, Programming Challenges
- [**17**星][2y] [C] [osandamalith/gamehacking](https://github.com/osandamalith/gamehacking) Some cool game hacks
- [**17**星][6m] [C] [volkanite/push](https://github.com/volkanite/push) Monitor GPU/CPU/RAM performance using in-game overlay.
- [**17**星][6y] [JS] [xiam/shooter-html5](https://github.com/xiam/shooter-html5) HTML5 client for a shooter game.
- [**16**星][3y] [Ruby] [sghctoma/writeups](https://github.com/sghctoma/writeups) Writeups for various crackmes, CTFs, wargames, etc.
- [**15**星][9m] [JS] [auth0-blog/aliens-go-home-part-3](https://github.com/auth0-blog/aliens-go-home-part-3) GitHub repository that accompanies the third article of the "Developing Games with React, Redux, and SVG" series.
- [**15**星][1y] [C++] [disconnect3d/crackme](https://github.com/disconnect3d/crackme) Small crackme game
- [**15**星][10m] [C++] [m-t3k/gamehacking](https://github.com/m-t3k/gamehacking) A Repository with all Things GameHacking.
- [**15**星][10m] [C++] [redmage1993/portal2hack](https://github.com/redmage1993/portal2hack) A hack/trainer for the PC video game Portal 2. Demonstrates C++ and Win32 programming, including multithreading, and external/remote process memory manipulation.
- [**15**星][1y] [C++] [contionmig/sac-anti-debug](https://github.com/ContionMig/SAC-Anti-Debug) Open source Anti Debug methods to use for your games. This uses SAC as an example. Will be sure to update it and / or add new features in the future
- [**15**星][2d] [C++] [wohlsoft/lunalua](https://github.com/wohlsoft/lunalua) LunaLua - LunaDLL with Lua, is a free extension for SMBX game engine
- [**14**星][4y] [C] [maskray/defconctffinalsgameboxadmin](https://github.com/maskray/defconctffinalsgameboxadmin) gamebox admin scripts for DEF CON 22~23 CTF Finals
- [**14**星][1y] [mitre-cyber-academy/2016-ctf-game](https://github.com/mitre-cyber-academy/2016-ctf-game) Repo containing links to all CTF Challenges used in the 2015 MITRE CTF.
- [**13**星][2y] [Py] [2o2l2h/awesome-ctf-wargame](https://github.com/2o2l2h/awesome-ctf-wargame) Writeup oriented CTF
- [**13**星][1y] [c] [sagaantheepic/sac-sagaan-anticheat-driver-](https://github.com/sagaantheepic/sac-sagaan-anticheat-driver-) Open source AC for any game developers who are looking to solve cheaters in their game!
- [**12**星][2y] [CSS] [xelenonz/game](https://github.com/xelenonz/game) ROP Wargame repository
- [**12**星][2m] [C++] [freehackquest/fhq-jury-ad](https://github.com/freehackquest/fhq-jury-ad) Jury System for a attack-defence ctf games
- [**11**星][7m] [Py] [changochen/ctf](https://github.com/changochen/ctf) CTF games I played.
- [**10**星][3y] [PHP] [probely/ctf-game](https://github.com/probely/ctf-game) Capture the flag Game
- [**10**星][1y] [reaperhulk/dsa-ctf](https://github.com/reaperhulk/dsa-ctf) A CTF game for recovering a DSA private key.
- [**9**星][2y] [JS] [auth0-blog/aliens-go-home-part-2](https://github.com/auth0-blog/aliens-go-home-part-2) GitHub repository that accompanies the second article of the "Developing Games with React, Redux, and SVG" series.
- [**9**星][5y] [Lua] [staymanhou/hacking-the-pentest-tutor-game](https://github.com/staymanhou/hacking-the-pentest-tutor-game) 
- [**8**星][5y] [Py] [feix/ctf-writeup](https://github.com/feix/ctf-writeup) some ctf game writeup
- [**8**星][5y] [mitre-cyber-academy/2014-ctf-game](https://github.com/mitre-cyber-academy/2014-ctf-game) Repo containing links to all CTF Challenges used in the 2014 MITRE CTF.
- [**8**星][2d] [ObjC] [scrimpycat/hacking-game](https://github.com/scrimpycat/hacking-game) A WIP game focused on hacking
- [**7**星][4m] [Py] [ray-cp/ctf-pwn](https://github.com/ray-cp/ctf-pwn) just some pwn games in ctf
- [**6**星][5y] [JS] [ethanheilman/flipit](https://github.com/ethanheilman/flipit) The Game of Stealthy Takeover
- [**6**星][1y] [Py] [ryanking13/ctf-cheatsheet](https://github.com/ryanking13/ctf-cheatsheet) My own CTF, wargame cheatsheet
- [**6**星][8y] [C++] [yifanlu/psxperia-wrapper](https://github.com/yifanlu/psxperia-wrapper) Loads injected PSX games on Xperia Play
- [**5**星][1y] [seadog007/smartcontract_ctfgame](https://github.com/seadog007/smartcontract_ctfgame) The CTF questions about smart contracts
- [**5**星][3y] [C] [xiaomagexiao/gamedll](https://github.com/xiaomagexiao/gamedll) gamedll
- [**4**星][3y] [Py] [antonin-deniau/assembly_game_of_life](https://github.com/antonin-deniau/assembly_game_of_life) An assembly game of life application running on unicorn
- [**4**星][2y] [dhn/write_ups](https://github.com/dhn/write_ups) write ups [boot2root|ctf|wargame]
- [**4**星][5y] [PHP] [mimoo/wiitop](https://github.com/mimoo/wiitop) tournament script for many games (counter strike, warcraft, dota...)
- [**4**星][2y] [Py] [tinamous/pawnshy](https://github.com/tinamous/pawnshy) A Have I Been Pwned game based on the fairground Coconut Shy
- [**4**星][1y] [twilightshore/recode](https://github.com/twilightshore/recode) A collection of stuff from reverse engineering games
- [**3**星][1y] [arsho/xss_game](https://github.com/arsho/xss_game) Solution of XSS game by Google.
- [**3**星][7y] [C] [floreks/kalbot](https://github.com/floreks/kalbot) Automatic software interacting with game without human by analyzing data sent between client and server.
- [**3**星][2y] [C] [safflower/writeups](https://github.com/safflower/writeups) Writeups of ctf/wargame
- [**3**星][7y] [Assembly] [patois/nestrainers](https://github.com/patois/nestrainers) NES Game Hacking examples (adding cheating functionality/trainers)
- [**3**星][3m] [JS] [dehydr8/elevation-of-privilege](https://github.com/dehydr8/elevation-of-privilege) An online multiplayer version of the Elevation of Privilege (EoP) threat modeling card game
- [**2**星][1y] [Py] [musalbas/asteroids-on-steroids](https://github.com/musalbas/asteroids-on-steroids) Destroy anything by turning it into a game of Asteroids.
- [**2**星][4y] [Py] [waps101/pisquare](https://github.com/waps101/pisquare) This is a python template allowing two Raspberry Pis to play against each other in a variant of the classic game "dots and boxes". The game was used in the University of York Raspberry Pi challenge 2015.
- [**2**星][4y] [JS] [jackgoh/pirateking-exploit](https://github.com/jackgoh/pirateking-exploit) [PATCHED] Gain access to any Pirateking Game account
- [**2**星][12m] [C++] [vincentjyzhang/tetris-game](https://github.com/vincentjyzhang/tetris-game) Tetris WinAPI Win32 C/C++
- [**1**星][2y] [C++] [alejndalliance/wargames.my-2017-ctf-writeup](https://github.com/alejndalliance/wargames.my-2017-ctf-writeup) Writeup for the challenge
- [**1**星][4m] [C#] [bbqgiraffe/nitemare-3d-dat-extractor](https://github.com/bbqgiraffe/nitemare-3d-dat-extractor) extracts Menu art and sounds from the 1994 FPS game Nitemare 3D
- [**1**星][3y] [janniskirschner/google-xss-game](https://github.com/janniskirschner/google-xss-game) Hello there! :) Here are my solutions to the google xss game. I've noticed that some challenges don't work out with every browser, so try it with multiple ones.
- [**1**星][7m] [Py] [sicklydreaming/ctf-solutions](https://github.com/sicklydreaming/ctf-solutions) solutions for ctf challenges and online wargames
- [**1**星][23d] [JS] [vietnamesecodelovers/nightst0rm-ctf](https://github.com/vietnamesecodelovers/nightst0rm-ctf) The write-up about nightst0rm ctf game
- [**1**星][1y] [Py] [d41jungod/ctf_writeup](https://github.com/D41JUNGOD/CTF_Writeup) wargame,project
- [**1**星][6y] [Visual Basic .NET] [vbgamer45/gmd-recovery](https://github.com/vbgamer45/gmd-recovery) A gamemaker decompiler for versions 5.3a and less
- [**1**星][3m] [Pawn] [nexiustailer/byfly-gta-sa-gangwar](https://github.com/nexiustailer/byfly-gta-sa-gangwar) A TDM GameMode
- [**1**星][8m] [PHP] [sqlsec/xssgame](https://github.com/sqlsec/xssgame) test.xss.tv 的源码，自己删掉了后面失效的Flash XSS题目，替换了一些无聊的表情包
- [**0**星][2y] [HTML] [dianokor/write-up](https://github.com/dianokor/write-up) wargame&ctf write-up
- [**0**星][6y] [Py] [ianzhang1990/disease](https://github.com/ianzhang1990/disease) A game to simulate virus spreading among people. || Still on going..... ||
- [**0**星][3y] [Py] [ike-clinton/trafficgen](https://github.com/ike-clinton/trafficgen) Python traffic generator for cyber wargame
- [**0**星][1y] [Py] [jonobrien/ctf](https://github.com/jonobrien/ctf) single repo of all of my ctf solutions, wargames, WIPs
- [**0**星][4y] [JS] [lukenickerson/net-clicker](https://github.com/lukenickerson/net-clicker) Incremental/Clicker Game of Hacking and Cyberwar for Ludum Dare 32
- [**0**星][1y] [C++] [lyudatan/remote_connect_four](https://github.com/lyudatan/remote_connect_four) Remote controlled Connect Four game with Arduino
- [**0**星][2y] [C] [masonc15/ctf-wargame-writeups](https://github.com/masonc15/ctf-wargame-writeups) Walkthroughs of CTFS I have completed/attempted
- [**0**星][5y] [C++] [raziel23x/apk-gamers-side-shooter](https://github.com/raziel23x/apk-gamers-side-shooter) 
- [**0**星][2y] [Lua] [shloid/kiseki-ctf-classic](https://github.com/shloid/kiseki-ctf-classic) A rescripted/modified version of Clockwork and Conix's game "Kiseki". This is the source code repository in case you wanna see how god awful my coding is.
- [**0**星][3y] [Pascal] [yoie/ngplug-in](https://github.com/yoie/ngplug-in) Net Game Plug-in
- [**0**星][3y] [C#] [kneefer/slowotokgamecheat](https://github.com/kneefer/slowotokgamecheat) Simple Cheat to the game named "Słowotok". Automates sending scores and lets win every time


# <a id="09fa851959ff48f5667a2099c861eab8"></a>Malware&&恶意代码


***


## <a id="e781a59e4f4daab058732cf66f77bfb9"></a>工具


- [**5195**星][11d] [Py] [mobsf/mobile-security-framework-mobsf](https://github.com/MobSF/Mobile-Security-Framework-MobSF) Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.
    - 重复区段: [Android->工具->新添加的1](#63fd2c592145914e99f837cecdc5a67c) |
- [**3369**星][8d] [C] [screetsec/thefatrat](https://github.com/screetsec/thefatrat) Thefatrat a massive exploiting tool : Easy tool to generate backdoor and easy tool to post exploitation attack like browser attack and etc . This tool compiles a malware with popular payload and then the compiled malware can be execute on windows, android, mac . The malware that created with this tool also have an ability to bypass most AV softw…
- [**2459**星][3d] [PHP] [misp/misp](https://github.com/misp/misp) MISP (core software) - Open Source Threat Intelligence and Sharing Platform (formely known as Malware Information Sharing Platform)
- [**1433**星][1y] [TS] [pedronauck/reworm](https://github.com/pedronauck/reworm) 
- [**1268**星][4d] [Shell] [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) Nginx Block Bad Bots, Spam Referrer Blocker, Vulnerability Scanners, User-Agents, Malware, Adware, Ransomware, Malicious Sites, with anti-DDOS, Wordpress Theme Detector Blocking and Fail2Ban Jail for Repeat Offenders
- [**1243**星][10m] [C] [a0rtega/pafish](https://github.com/a0rtega/pafish) Pafish is a demonstration tool that employs several techniques to detect sandboxes and analysis environments in the same way as malware families do.
- [**1090**星][1m] [Go] [looterz/grimd](https://github.com/looterz/grimd) Fast dns proxy that can run anywhere, built to black-hole internet advertisements and malware servers.
- [**1084**星][2m] [PHP] [nbs-system/php-malware-finder](https://github.com/nbs-system/php-malware-finder) Detect potentially malicious PHP files
- [**1017**星][5d] [Rich Text Format] [decalage2/oletools](https://github.com/decalage2/oletools) oletools - python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware analysis, forensics and debugging.
- [**934**星][2y] [Py] [tomchop/malcom](https://github.com/tomchop/malcom) Malcom - Malware Communications Analyzer
- [**930**星][4m] [Py] [airbnb/binaryalert](https://github.com/airbnb/binaryalert) 实时恶意代码检测，无需服务器
- [**802**星][3y] [C#] [netflix/fido](https://github.com/netflix/fido) an orchestration layer used to automate the incident response process by evaluating, assessing and responding to malware
- [**800**星][3m] [sh4hin/androl4b](https://github.com/sh4hin/androl4b) 用于评估Android应用程序，逆向工程和恶意软件分析的虚拟机
    - 重复区段: [Android->工具->新添加的1](#63fd2c592145914e99f837cecdc5a67c) |
- [**779**星][2m] [Py] [gosecure/malboxes](https://github.com/gosecure/malboxes) Builds malware analysis Windows VMs so that you don't have to.
- [**713**星][6d] [Py] [sevagas/macro_pack](https://github.com/sevagas/macro_pack) 自动生成并混淆MS 文档, 用于渗透测试、演示、社会工程评估等
- [**682**星][30d] [Py] [rurik/noriben](https://github.com/rurik/noriben) Portable, Simple, Malware Analysis Sandbox
- [**662**星][8m] [Shell] [rfxn/linux-malware-detect](https://github.com/rfxn/linux-malware-detect) Linux Malware Detection (LMD)
- [**653**星][26d] [YARA] [eset/malware-ioc](https://github.com/eset/malware-ioc) Indicators of Compromises (IOC) of our various investigations
- [**619**星][] [Py] [eliasgranderubio/dagda](https://github.com/eliasgranderubio/dagda) Docker安全套件
- [**600**星][5m] [fabrimagic72/malware-samples](https://github.com/fabrimagic72/malware-samples) 恶意软件样本
- [**574**星][2m] [HTML] [gwillem/magento-malware-scanner](https://github.com/gwillem/magento-malware-scanner) 用于检测 Magento 恶意软件的规则/样本集合
- [**563**星][3m] [Py] [certsocietegenerale/fame](https://github.com/certsocietegenerale/fame) 自动化恶意代码评估
- [**552**星][5y] [Py] [krmaxwell/maltrieve](https://github.com/krmaxwell/maltrieve) A tool to retrieve malware directly from the source for security researchers.
- [**536**星][2m] [Py] [tencent/habomalhunter](https://github.com/tencent/habomalhunter) HaboMalHunter is a sub-project of Habo Malware Analysis System (
- [**494**星][1m] [C] [hasherezade/demos](https://github.com/hasherezade/demos) Demos of various injection techniques found in malware
- [**493**星][5d] [Py] [ctxis/cape](https://github.com/ctxis/cape) Malware Configuration And Payload Extraction
- [**470**星][2y] [C] [leurak/memz](https://github.com/leurak/memz) 为Danooct1的用户制作的恶意软件系列制作的木马。
- [**426**星][2y] [Py] [endgameinc/gym-malware](https://github.com/endgameinc/gym-malware) 基于OpenAI Gym 实现的恶意代码操作环境，其目标是实现可以学习如何修改 PE 文件以达到特定目的（例如绕过AV）的 agent。（OpenAIGym：开发和通过比较强化学习算法的工具包）
- [**417**星][4m] [Py] [misterch0c/malsploitbase](https://github.com/misterch0c/malsploitbase) Malware exploits
- [**405**星][5y] [Py] [paloaltonetworks/wirelurkerdetector](https://github.com/paloaltonetworks/wirelurkerdetector) Script for detecting the WireLurker malware family
- [**404**星][5y] [Ruby] [svent/jsdetox](https://github.com/svent/jsdetox) A Javascript malware analysis tool
- [**401**星][t] [C#] [collinbarrett/filterlists](https://github.com/collinbarrett/filterlists) independent, comprehensive directory of filter and host lists for advertisements, trackers, malware, and annoyances.
- [**395**星][2m] [YARA] [guelfoweb/peframe](https://github.com/guelfoweb/peframe) PEframe is a open source tool to perform static analysis on Portable Executable malware and malicious MS Office documents.
- [**393**星][6m] [JS] [capacitorset/box-js](https://github.com/capacitorset/box-js) A tool for studying JavaScript malware.
- [**384**星][9d] [Py] [alexandreborges/malwoverview](https://github.com/alexandreborges/malwoverview) Malwoverview.py is a first response tool to perform an initial and quick triage in a directory containing malware samples, specific malware sample, suspect URL and domains. Additionally, it allows to download and send samples to main online sandboxes.
- [**375**星][7m] [Py] [secrary/ssma](https://github.com/secrary/ssma) SSMA - Simple Static Malware Analyzer [This project is not maintained anymore]
- [**375**星][] [Shell] [whonix/whonix](https://github.com/whonix/whonix) Whonix is an operating system focused on anonymity, privacy and security. It's based on the Tor anonymity network, Debian GNU/Linux and security by isolation. DNS leaks are impossible, and not even malware with root privileges can find out the user's real IP.
- [**374**星][3m] [AngelScript] [inquest/malware-samples](https://github.com/inquest/malware-samples) A collection of malware samples and relevant dissection information, most probably referenced from
- [**372**星][3y] [PHP] [nikicat/web-malware-collection](https://github.com/nikicat/web-malware-collection) Clone of svn repository of
- [**370**星][5y] [Go] [vishvananda/wormhole](https://github.com/vishvananda/wormhole) A smart proxy to connect docker containers.
- [**368**星][5y] [C] [arialdomartini/morris-worm](https://github.com/arialdomartini/morris-worm) The original Morris Worm source code
- [**365**星][3y] [C] [gbrindisi/malware](https://github.com/gbrindisi/malware) malware source codes
- [**365**星][4m] [Py] [neo23x0/munin](https://github.com/neo23x0/munin) Online hash checker for Virustotal and other services
- [**355**星][3y] [JS] [antimalware/manul](https://github.com/antimalware/manul) Antimalware tool for websites
- [**354**星][5m] [Py] [hasherezade/malware_analysis](https://github.com/hasherezade/malware_analysis) Various snippets created during malware analysis
- [**342**星][9m] [Py] [iphelix/dnschef](https://github.com/iphelix/dnschef) DNS 代理，用于渗透测试和恶意代码分析
- [**337**星][8m] [Py] [rek7/fireelf](https://github.com/rek7/fireelf) Fileless Linux Malware Framework
- [**332**星][20d] [Py] [fireeye/stringsifter](https://github.com/fireeye/stringsifter) A machine learning tool that ranks strings based on their relevance for malware analysis.
- [**331**星][t] [Batchfile] [mitchellkrogza/ultimate.hosts.blacklist](https://github.com/mitchellkrogza/ultimate.hosts.blacklist) The Ultimate Unified Hosts file for protecting your network, computer, smartphones and Wi-Fi devices against millions of bad web sites. Protect your children and family from gaining access to bad web sites and protect your devices and pc from being infected with Malware or Ransomware.
- [**327**星][3y] [mikesiko/practicalmalwareanalysis-labs](https://github.com/mikesiko/practicalmalwareanalysis-labs) Binaries for the book Practical Malware Analysis
- [**326**星][1y] [C++] [m0n0ph1/process-hollowing](https://github.com/m0n0ph1/process-hollowing) Great explanation of Process Hollowing (a Technique often used in Malware)
- [**317**星][1m] [C#] [malware-dev/mdk-se](https://github.com/malware-dev/mdk-se) Malware's Development Kit for SE
- [**305**星][5m] [JS] [hynekpetrak/malware-jail](https://github.com/hynekpetrak/malware-jail) Sandbox for semi-automatic Javascript malware analysis, deobfuscation and payload extraction. Written for Node.js
- [**305**星][2y] [C++] [m0n0ph1/malware-1](https://github.com/m0n0ph1/malware-1) Malware source code samples leaked online uploaded to GitHub for those who want to analyze the code.
- [**301**星][12m] [Assembly] [guitmz/virii](https://github.com/guitmz/virii) Collection of ancient computer virus source codes
- [**301**星][5d] [Shell] [mitchellkrogza/apache-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/apache-ultimate-bad-bot-blocker) Apache Block Bad Bots, (Referer) Spam Referrer Blocker, Vulnerability Scanners, Malware, Adware, Ransomware, Malicious Sites, Wordpress Theme Detectors and Fail2Ban Jail for Repeat Offenders
- [**295**星][2y] [C++] [minhaskamal/trojancockroach](https://github.com/minhaskamal/trojancockroach) A Stealthy Trojan Spyware (keylogger-spyware-malware-worm-spy-virus-fud-undetectable-computer-windows-pc-c-c++)
- [**292**星][10d] [PHP] [phpmussel/phpmussel](https://github.com/phpmussel/phpmussel) PHP-based anti-virus anti-trojan anti-malware solution.
- [**285**星][7m] [Java] [katjahahn/portex](https://github.com/katjahahn/portex) Java library to analyse Portable Executable files with a special focus on malware analysis and PE malformation robustness
- [**283**星][8m] [Py] [phage-nz/ph0neutria](https://github.com/phage-nz/ph0neutria) ph0neutria is a malware zoo builder that sources samples straight from the wild. Everything is stored in Viper for ease of access and manageability.
- [**281**星][4y] [Py] [monnappa22/limon](https://github.com/monnappa22/limon) Limon is a sandbox developed as a research project written in python, which automatically collects, analyzes, and reports on the run time indicators of Linux malware. It allows one to inspect Linux malware before execution, during execution, and after execution (post-mortem analysis) by performing static, dynamic and memory analysis using open s…
- [**278**星][8m] [C] [rieck/malheur](https://github.com/rieck/malheur) A Tool for Automatic Analysis of Malware Behavior
- [**273**星][2m] [JS] [hynekpetrak/javascript-malware-collection](https://github.com/hynekpetrak/javascript-malware-collection) Collection of almost 40.000 javascript malware samples
- [**262**星][2m] [Py] [felixweyne/imaginaryc2](https://github.com/felixweyne/imaginaryc2) Imaginary C2 is a python tool which aims to help in the behavioral (network) analysis of malware. Imaginary C2 hosts a HTTP server which captures HTTP requests towards selectively chosen domains/IPs. Additionally, the tool aims to make it easy to replay captured Command-and-Control responses/served payloads.
- [**259**星][1m] [Py] [diogo-fernan/malsub](https://github.com/diogo-fernan/malsub) A Python RESTful API framework for online malware analysis and threat intelligence services.
- [**256**星][10m] [C++] [ramadhanamizudin/malware](https://github.com/ramadhanamizudin/malware) Malware Samples. Uploaded to GitHub for those want to analyse the code. Code mostly from:
- [**241**星][8m] [C++] [mstfknn/malware-sample-library](https://github.com/mstfknn/malware-sample-library) Malware sample library.
- [**240**星][2m] [Py] [a3sal0n/falcongate](https://github.com/a3sal0n/falcongate) A smart gateway to stop hackers and Malware attacks
- [**240**星][7d] [Shell] [essandess/macos-fortress](https://github.com/essandess/macos-fortress) Firewall and Privatizing Proxy for Trackers, Attackers, Malware, Adware, and Spammers with Anti-Virus On-Demand and On-Access Scanning (PF, squid, privoxy, hphosts, dshield, emergingthreats, hostsfile, PAC file, clamav)
- [**239**星][3y] [Go] [egebalci/egesploit](https://github.com/egebalci/egesploit) EGESPLOIT is a golang library for malware development
- [**239**星][2y] [C] [zerosum0x0/defcon-25-workshop](https://github.com/zerosum0x0/defcon-25-workshop) Windows Post-Exploitation / Malware Forward Engineering DEF CON 25 Workshop
- [**237**星][3m] [C++] [richkmeli/richkware](https://github.com/richkmeli/richkware) Framework for building Windows malware, written in C++
- [**235**星][6y] [Py] [xen0ph0n/yaragenerator](https://github.com/xen0ph0n/yaragenerator) quick, simple, and effective yara rule creation to isolate malware families and other malicious objects of interest
- [**233**星][2m] [C] [elfmaster/libelfmaster](https://github.com/elfmaster/libelfmaster) Secure ELF parsing/loading library for forensics reconstruction of malware, and robust reverse engineering tools
- [**231**星][3y] [Visual Basic .NET] [malwares/crypter](https://github.com/malwares/crypter) Windows Crypter
- [**225**星][5y] [Py] [nanyomy/dht-woodworm](https://github.com/nanyomy/dht-woodworm) this python repo is used to get the info_hash from DHT network, enjoy it
- [**220**星][15d] [Py] [wazuh/wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) ruleset is used to detect attacks, intrusions, software misuse, configuration problems, application errors, malware, rootkits, system anomalies or security policy violations.
- [**219**星][8d] [JS] [strangerealintel/cyberthreatintel](https://github.com/strangerealintel/cyberthreatintel) Analysis of malware and Cyber Threat Intel of APT and cybercriminals groups
- [**217**星][3y] [Py] [mkorman90/volatilitybot](https://github.com/mkorman90/volatilitybot) An automated memory analyzer for malware samples and memory dumps
- [**211**星][2m] [Py] [eset/malware-research](https://github.com/eset/malware-research) 恶意代码分析中用到的代码/工具
- [**208**星][1y] [Py] [malicialab/avclass](https://github.com/malicialab/avclass) AVClass malware labeling tool
- [**207**星][5m] [YARA] [th3hurrican3/pepper](https://github.com/th3hurrican3/pepper) An open source script to perform malware static analysis on Portable Executable
- [**202**星][24d] [Py] [doomedraven/virustotalapi](https://github.com/doomedraven/virustotalapi) VirusTotal Full api
- [**200**星][2m] [C++] [secrary/drsemu](https://github.com/secrary/drsemu) 根据动态行为检测恶意代码并进行分类
- [**198**星][2y] [Py] [alienvault-otx/apiv2](https://github.com/AlienVault-OTX/ApiV2) quickly identify related infrastructure and malware
- [**197**星][4d] [Py] [jpcertcc/malconfscan](https://github.com/jpcertcc/malconfscan) Volatility plugin for extracts configuration data of known malware
- [**196**星][3y] [Ruby] [spiderlabs/malware-analysis](https://github.com/spiderlabs/malware-analysis) A repository of tools and scripts related to malware analysis
- [**195**星][11m] [Visual Basic .NET] [dragokas/hijackthis](https://github.com/dragokas/hijackthis) A free utility that finds malware, adware and other security threats
- [**191**星][7m] [Shell] [gaenserich/hostsblock](https://github.com/gaenserich/hostsblock) an ad- and malware-blocking script for Linux
- [**188**星][2y] [Visual Basic .NET] [joesecurity/pafishmacro](https://github.com/joesecurity/pafishmacro) Pafish Macro is a Macro enabled Office Document to detect malware analysis systems and sandboxes. It uses evasion & detection techniques implemented by malicious documents.
- [**188**星][1y] [Py] [malwarereversebrasil/malwaresearch](https://github.com/malwarereversebrasil/malwaresearch) A command line tool to find malwares on http://openmalware.org
- [**187**星][5y] [Ruby] [m4rco-/dorothy2](https://github.com/m4rco-/dorothy2) A malware/botnet analysis framework written in Ruby.
- [**185**星][12m] [PS] [felixweyne/processspawncontrol](https://github.com/felixweyne/processspawncontrol) a Powershell tool which aims to help in the behavioral (process) analysis of malware. PsC suspends newly launched processes, and gives the analyst the option to either keep the process suspended, or to resume it.
- [**184**星][11m] [sapphirex00/threat-hunting](https://github.com/sapphirex00/threat-hunting) Personal compilation of APT malware from whitepaper releases, documents and own research
- [**183**星][2y] [Smali] [sslab-gatech/avpass](https://github.com/sslab-gatech/avpass) Tool for leaking and bypassing Android malware detection system
    - 重复区段: [Android->工具->新添加的1](#63fd2c592145914e99f837cecdc5a67c) |
- [**183**星][4y] [Py] [xen0ph0n/virustotal_api_tool](https://github.com/xen0ph0n/virustotal_api_tool) A Tool To Leverage Virus Total's Private API Key
- [**181**星][4y] [Pascal] [chiggins/malware_sources](https://github.com/chiggins/malware_sources)  I found all of these samples on MalwareTech through Twitter somewhere
- [**180**星][5m] [Py] [hanul93/kicomav](https://github.com/hanul93/kicomav) KicomAV is an open source (GPL v2) antivirus engine designed for detecting malware and disinfecting it.
- [**178**星][2y] [Py] [woj-ciech/daily-dose-of-malware](https://github.com/woj-ciech/daily-dose-of-malware) Script lets you gather malicious software and c&c servers from open source platforms like Malshare, Malcode, Google, Cymon - vxvault, cybercrime tracker and c2 for Pony.
- [**172**星][2m] [C#] [samueltulach/virustotaluploader](https://github.com/samueltulach/virustotaluploader) C# Open-Source Winforms application for uploading files to VirusTotal
- [**171**星][25d] [JS] [cert-polska/mquery](https://github.com/cert-polska/mquery) YARA malware query accelerator (web frontend)
- [**170**星][2y] [Py] [googulator/teslacrack](https://github.com/googulator/teslacrack) Decryptor for the TeslaCrypt malware
- [**170**星][3y] [C++] [phat3/pindemonium](https://github.com/phat3/pindemonium) A pintool in order to unpack malware
- [**169**星][4y] [Py] [dynetics/malfunction](https://github.com/dynetics/malfunction) Malware Analysis Tool using Function Level Fuzzy Hashing
- [**169**星][5m] [PHP] [scr34m/php-malware-scanner](https://github.com/scr34m/php-malware-scanner) Scans PHP files for malwares and known threats
- [**165**星][11m] [Py] [ghostmanager/domaincheck](https://github.com/ghostmanager/domaincheck) DomainCheck is designed to assist operators with monitoring changes related to their domain names. This includes negative changes in categorization, VirusTotal detections, and appearances on malware blacklists. DomainCheck currently works only with NameCheap.
- [**163**星][3m] [Py] [blacktop/virustotal-api](https://github.com/blacktop/virustotal-api) Virus Total Public/Private/Intel API
- [**162**星][2y] [Py] [aim4r/voldiff](https://github.com/aim4r/voldiff) Malware Memory Footprint Analysis based on Volatility
- [**162**星][3y] [miserlou/mackenzie](https://github.com/miserlou/mackenzie) AWS Lambda Infection Toolkit // Persistent Lambda Malware PoC
- [**161**星][3y] [Py] [504ensicslabs/damm](https://github.com/504ensicslabs/damm) Differential Analysis of Malware in Memory
- [**154**星][3m] [Shell] [countercept/snake](https://github.com/countercept/snake) snake - a malware storage zoo
- [**153**星][] [C] [pkroma/processhacker](https://github.com/pkroma/processhacker) A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware—mirror of
- [**152**星][6y] [onx/cih](https://github.com/onx/cih) The source code of the CIH virus
- [**150**星][2y] [Py] [vduddu/malware](https://github.com/vduddu/malware) Rootkits | Backdoors | Sniffers | Virus | Ransomware | Steganography | Cryptography | Shellcodes | Webshells | Keylogger | Botnets | Worms | Other Network Tools
- [**149**星][2y] [C] [elfmaster/skeksi_virus](https://github.com/elfmaster/skeksi_virus) Devestating and awesome Linux X86_64 ELF Virus
- [**149**星][6y] [C++] [kaiserfarrell/malware](https://github.com/kaiserfarrell/malware) virus collection source code
- [**146**星][11m] [Dockerfile] [remnux/docker](https://github.com/remnux/docker) This repository contains Dockerfiles for building Docker images of popular malware analysis tools. See
- [**145**星][9m] [ObjC] [objective-see/reikey](https://github.com/objective-see/reikey) Malware and other applications may install persistent keyboard "event taps" to intercept your keystrokes. ReiKey can scan, detect, and monitor for such taps!
- [**144**星][3y] [Assembly] [ricardojrdez/anti-analysis-tricks](https://github.com/ricardojrdez/anti-analysis-tricks) Bunch of techniques potentially used by malware to detect analysis environments
- [**143**星][2d] [Py] [codexgigassys/codex-backend](https://github.com/codexgigassys/codex-backend) Codex Gigas malware DNA profiling search engine discovers malware patterns and characteristics assisting individuals who are attracted in malware hunting.
- [**143**星][3y] [Py] [safebreach-labs/pacdoor](https://github.com/safebreach-labs/pacdoor) Proof-of-concept JavaScript malware implemented as a Proxy Auto-Configuration (PAC) File
- [**143**星][11m] [C++] [virustotal/qt-virustotal-uploader](https://github.com/virustotal/qt-virustotal-uploader) VirusTotal Uploader written in C++ using QT framework
- [**139**星][5y] [PHP] [btoplak/joomla-anti-malware-scan-script--jamss-](https://github.com/btoplak/joomla-anti-malware-scan-script--jamss-) a Joomla! and WordPress Security script that automatically scans the Joomla! or Wordpress files for some patterns and "fingerprints" of malware, trojans or other injections into PHP code
- [**138**星][11m] [Py] [gawen/virustotal](https://github.com/gawen/virustotal) 
- [**137**星][9m] [Py] [mdudek-ics/trisis-triton-hatman](https://github.com/MDudek-ICS/TRISIS-TRITON-HATMAN) Repository containting original and decompiled files of TRISIS/TRITON/HATMAN malware
- [**136**星][3m] [YARA] [citizenlab/malware-indicators](https://github.com/citizenlab/malware-indicators) Citizen Lab Malware Reports
- [**134**星][4y] [Py] [korelogicsecurity/mastiff](https://github.com/korelogicsecurity/mastiff) Malware static analysis framework
- [**133**星][3y] [Py] [blacktop/malice](https://github.com/blacktop/malice) VirusTotal Wanna Be
- [**131**星][10m] [HTML] [minhaskamal/cuteviruscollection](https://github.com/minhaskamal/cuteviruscollection) A Collection of Cute But Deadly Viruses (small-unharmful-annoying-harmless-funny-malware-virus-worm-windows-xp-7-10)
- [**128**星][2y] [Py] [fireeye/flare-dbg](https://github.com/fireeye/flare-dbg) to aid malware reverse engineers in rapidly developing debugger scripts.
- [**126**星][5y] [CSS] [merces/aleph](https://github.com/merces/aleph) An Open Source Malware Analysis Pipeline System
- [**125**星][4y] [Py] [bwall/bamfdetect](https://github.com/bwall/bamfdetect) Identifies and extracts information from bots and other malware
- [**125**星][3y] [malwares/dangerouszone](https://github.com/malwares/dangerouszone) Dangerous Malwares
- [**123**星][10m] [Perl] [dave-theunsub/clamtk](https://github.com/dave-theunsub/clamtk) An easy to use, light-weight, on-demand virus scanner for Linux systems
- [**122**星][3y] [Py] [grazfather/practicalmalwarelabs](https://github.com/grazfather/practicalmalwarelabs) Keep track of the labs from the book "Practical Malware Analysis"
- [**122**星][2m] [Py] [yelp/amira](https://github.com/yelp/amira) Automated Malware Incident Response & Analysis
- [**121**星][1m] [Dockerfile] [harvard-itsecurity/docker-misp](https://github.com/harvard-itsecurity/docker-misp) Automated Docker MISP container - Malware Information Sharing Platform and Threat Sharing
- [**120**星][3y] [C] [glacierw/mba](https://github.com/glacierw/mba) Malware Behavior Analyzer
- [**120**星][4m] [neo23x0/vti-dorks](https://github.com/neo23x0/vti-dorks) Awesome VirusTotal Intelligence Search Queries
- [**116**星][7m] [Shell] [moreseclab/ddg_malware_clean_tool](https://github.com/moreseclab/ddg_malware_clean_tool) Watchdogs 、kthrotlds 挖矿蠕虫清理脚本。
- [**114**星][5m] [Py] [marcoramilli/malwaretrainingsets](https://github.com/marcoramilli/malwaretrainingsets) Free Malware Training Datasets for Machine Learning
- [**112**星][7y] [Py] [sroberts/malwarehouse](https://github.com/sroberts/malwarehouse) A warehouse for your malware
- [**111**星][1y] [PHP] [ollyxar/php-malware-detector](https://github.com/ollyxar/php-malware-detector) PHP malware detector
- [**111**星][2y] [Py] [seifreed/malware-scripts](https://github.com/seifreed/malware-scripts) Useful scripts related with malware
- [**110**星][7m] [Py] [evilsocket/ergo-pe-av](https://github.com/evilsocket/ergo-pe-av) 🧠 🦠 An artificial neural network and API to detect Windows malware, based on Ergo and LIEF.
- [**106**星][4y] [Perl] [fastvpseestiou/antidoto](https://github.com/fastvpseestiou/antidoto) Linux antimalware and antirootkit tool
- [**105**星][6y] [Py] [secretsquirrel/recomposer](https://github.com/secretsquirrel/recomposer) Randomly changes Win32/64 PE Files for 'safer' uploading to malware and sandbox sites.
- [**105**星][25d] [Go] [virustotal/vt-cli](https://github.com/virustotal/vt-cli) VirusTotal Command Line Interface
- [**104**星][5y] [Py] [botherder/vxcage](https://github.com/botherder/vxcage) REST API based malware repository (abandoned)
- [**104**星][3y] [glinares/officemalware](https://github.com/glinares/officemalware) 
- [**104**星][6y] [santoku/santoku-linux](https://github.com/santoku/santoku-linux) Linux Distro for Mobile Security, Malware Analysis, and Forensics
- [**100**星][5y] [JS] [malwarelu/malwasm](https://github.com/malwarelu/malwasm) Offline debugger for malware's reverse engineering
- [**99**星][3y] [Py] [bontchev/wlscrape](https://github.com/bontchev/wlscrape) A tool for scrapping the possible malware from the Wikileaks AKP leak
- [**99**星][2y] [PS] [testingpens/malwarepersistencescripts](https://github.com/testingpens/malwarepersistencescripts) A collection of scripts I've written to help red and blue teams with malware persistence techniques.
- [**99**星][2y] [C++] [atxsinn3r/amsiscanner](https://github.com/atxsinn3r/amsiscanner) A C/C++ implementation of Microsoft's Antimalware Scan Interface
- [**96**星][7y] [0day1day/mwcrawler](https://github.com/0day1day/mwcrawler) Python Malware Crawler for Zoos and Repositories
- [**95**星][2y] [Py] [safebreach-labs/mkmalwarefrom](https://github.com/safebreach-labs/mkmalwarefrom) Proof-of-concept two-stage dropper generator that uses bits from external sources
- [**94**星][t] [Py] [endermanch/malwaredatabase](https://github.com/endermanch/malwaredatabase) This repository is one of a few malware collections on the GitHub.
- [**93**星][3y] [Vim script] [citizenlab/malware-signatures](https://github.com/citizenlab/malware-signatures) Yara rules for malware families seen as part of targeted threats project
- [**92**星][2y] [C] [christian-roggia/open-myrtus](https://github.com/christian-roggia/open-myrtus) RCEed version of computer malware / rootkit MyRTUs / Stuxnet.
- [**92**星][2m] [PS] [dbheise/vm_setup](https://github.com/dbheise/vm_setup) A collection of scripts to initialize a windows VM to run all the malwares!
- [**92**星][5y] [Py] [neo23x0/dllrunner](https://github.com/neo23x0/dllrunner) Smart DLL execution for malware analysis in sandbox systems
- [**89**星][4y] [Py] [bindog/toymalwareclassification](https://github.com/bindog/toymalwareclassification) Kaggle微软恶意代码分类
- [**89**星][1y] [C] [chef-koch/malware-research](https://github.com/chef-koch/malware-research) Samples, research and documents about any kind of malware and misc source which should be released to the public
- [**89**星][2y] [HTML] [tigzy/malware-repo](https://github.com/tigzy/malware-repo) Malware Repository Framework
- [**88**星][4y] [Py] [maltelligence/maltelligence](https://github.com/maltelligence/maltelligence) a Malware/Threat Analyst Desktop
- [**88**星][4y] [Py] [malwaremusings/unpacker](https://github.com/malwaremusings/unpacker) Automated malware unpacker
- [**88**星][20d] [CSS] [uvasrg/evademl](https://github.com/uvasrg/evademl) 绕过基于机器学习的恶意软件分类器
- [**88**星][2d] [Py] [yarox24/attack_monitor](https://github.com/yarox24/attack_monitor) Endpoint detection & Malware analysis software
- [**88**星][2y] [Py] [icchy/tracecorn](https://github.com/icchy/tracecorn) Windows API 调用追踪，用作恶意代码分析
- [**87**星][4y] [Py] [necst/aamo](https://github.com/necst/aamo) AAMO: Another Android Malware Obfuscator
    - 重复区段: [Android->工具->新添加的1](#63fd2c592145914e99f837cecdc5a67c) |
- [**86**星][14d] [Py] [fr0gger/vthunting](https://github.com/fr0gger/vthunting) Vthunting is a tiny script used to generate report about Virus Total hunting and send it by email, slack or telegram.
- [**85**星][4y] [Py] [mgoffin/malwarecookbook](https://github.com/mgoffin/malwarecookbook) Malware Analyst's Cookbook stuffs
- [**84**星][3y] [C++] [hasherezade/persistence_demos](https://github.com/hasherezade/persistence_demos) Demos of various (also non standard) persistence methods used by malware
- [**84**星][1y] [C] [marfjeh/coinhive-block](https://github.com/marfjeh/coinhive-block) To block the malware domains of coin-hive systemwide.
- [**81**星][28d] [C] [ntraiseharderror/antimalware-research](https://github.com/ntraiseharderror/antimalware-research) Research on Anti-malware and other related security solutions
- [**81**星][1y] [Py] [silascutler/malpipe](https://github.com/silascutler/malpipe) Malware/IOC ingestion and processing engine
- [**80**星][5m] [C] [angelkitty/computer-virus](https://github.com/angelkitty/computer-virus) 
- [**80**星][2y] [Go] [oftn-oswg/zerodrop](https://github.com/oftn-oswg/zerodrop) A stealth URL toolkit optimized for bypassing censorship filters and/or dropping malware
- [**80**星][17d] [Rust] [warner/magic-wormhole.rs](https://github.com/warner/magic-wormhole.rs) NOT FUNCTIONAL YET. Slowly porting magic-wormhole to Rust. See wiki for game plan.
- [**79**星][3m] [Py] [danieluhricek/lisa](https://github.com/danieluhricek/lisa) Sandbox for automated Linux malware analysis.
- [**79**星][3y] [glinares/hephaestus](https://github.com/glinares/hephaestus) Open Source Office Malware Generation & Polymorphic Engine for Red Teams and QA testing
- [**78**星][3d] [Jupyter Notebook] [k-vitali/malware-misc-re](https://github.com/k-vitali/malware-misc-re) Miscellaneous Malware RE
- [**78**星][6y] [Zeek] [liamrandall/bromalware-exercise](https://github.com/liamrandall/bromalware-exercise) 
- [**77**星][6m] [C] [virustotal/c-vtapi](https://github.com/virustotal/c-vtapi) Official implementation of the VirusTotal API in C programming language
- [**76**星][26d] [Py] [inquest/python-sandboxapi](https://github.com/inquest/python-sandboxapi) Minimal, consistent Python API for building integrations with malware sandboxes.
- [**76**星][7y] [ObjC] [jils/flashbackchecker](https://github.com/jils/flashbackchecker) Quick and easy checker for Mac Flashback malware variants
- [**75**星][2y] [Py] [safebreach-labs/spacebin](https://github.com/safebreach-labs/spacebin) Spacebin is a proof-of-concept malware that exfiltrates data (from No Direct Internet Access environments) via triggering AV on the endpoint and then communicating back from the AV's cloud component.
- [**73**星][8m] [Py] [rmanofcn/ml_malware_detect](https://github.com/RManOfCN/ML_Malware_detect) 阿里云安全恶意程序检测比赛
- [**72**星][6y] [PS] [mattifestation/powerworm](https://github.com/mattifestation/powerworm) Analysis, detection, and removal of the "Power Worm" PowerShell-based malware
- [**70**星][5y] [C] [fireeye/tools](https://github.com/fireeye/tools) general purpose and malware specific analysis tools
- [**70**星][2y] [Py] [malwarereversebrasil/maltran](https://github.com/malwarereversebrasil/maltran) A command line tool to download malware exercises from malware-traffic-analysis.net
- [**70**星][2y] [Py] [minervalabsresearch/mystique](https://github.com/minervalabsresearch/mystique) Mystique may be used to discover infection markers that can be used to vaccinate endpoints against malware. It receives as input a malicious sample and automatically generates a list of mutexes that could be used to as “vaccines” against the sample.
- [**69**星][3y] [PS] [darkoperator/posh-virustotal](https://github.com/darkoperator/posh-virustotal) PowerShell Module to interact with VirusTotal
- [**69**星][11m] [C++] [fr0gger/rocprotect-v1](https://github.com/fr0gger/rocprotect-v1) Emulating Virtual Environment to stay protected against advanced malware
- [**69**星][] [Py] [nmantani/fileinsight-plugins](https://github.com/nmantani/fileinsight-plugins) a decoding toolbox of McAfee FileInsight hex editor for malware analysis
- [**69**星][2y] [Py] [planet-work/php-malware-scanner](https://github.com/planet-work/php-malware-scanner) PHP files analyzer for malware detection
- [**68**星][6m] [Py] [idiom/pftriage](https://github.com/idiom/pftriage) Python tool and library to help analyze files during malware triage and analysis.
- [**68**星][4y] [Py] [robbyfux/ragpicker](https://github.com/robbyfux/ragpicker) Ragpicker is a Plugin based malware crawler with pre-analysis and reporting functionalities. Use this tool if you are testing antivirus products, collecting malware for another analyzer/zoo.
- [**68**星][10m] [YARA] [rootkiter/binary-files](https://github.com/rootkiter/binary-files) EarthWorm/Termite 停止更新
- [**67**星][3m] [doctorwebltd/malware-iocs](https://github.com/doctorwebltd/malware-iocs) 
- [**67**星][] [TSQL] [mitchellkrogza/the-big-list-of-hacked-malware-web-sites](https://github.com/mitchellkrogza/the-big-list-of-hacked-malware-web-sites) This repository contains a list of all web sites I come across that are either hacked with or purposefully hosting malware, ransomware, viruses or trojans.
- [**65**星][30d] [Visual Basic .NET] [blackhacker511/blackworm](https://github.com/blackhacker511/blackworm) Black Worm Offical Repo
- [**65**星][11m] [YARA] [nheijmans/malzoo](https://github.com/nheijmans/malzoo) Mass static malware analysis tool
- [**64**星][6y] [Py] [andrew-morris/stupid_malware](https://github.com/andrew-morris/stupid_malware) Python malware for pentesters that bypasses most antivirus (signature and heuristics) and IPS using sheer stupidity
- [**64**星][7d] [PHP] [bediger4000/php-malware-analysis](https://github.com/bediger4000/php-malware-analysis) Deobfuscation and analysis of PHP malware captured by a WordPress honey pot
- [**64**星][1y] [C++] [paranoidninja/scriptdotsh-malwaredevelopment](https://github.com/paranoidninja/scriptdotsh-malwaredevelopment) This repo will contain code snippets for blogs: Malware on Steroids written by me at
- [**64**星][6m] [Py] [sysopfb/malware_decoders](https://github.com/sysopfb/malware_decoders) Static based decoders for malware samples
- [**63**星][4y] [MATLAB] [konstantinberlin/malware-windows-audit-log-detection](https://github.com/konstantinberlin/malware-windows-audit-log-detection) Detection of malware using dynamic behavior and Windows audit logs
- [**63**星][2m] [Go] [moldabekov/virusgotal](https://github.com/moldabekov/virusgotal) 
- [**63**星][2y] [Go] [yara-rules/yara-endpoint](https://github.com/yara-rules/yara-endpoint) Yara-Endpoint is a tool useful for incident response as well as anti-malware enpoint base on Yara signatures.
- [**62**星][12m] [cmatthewbrooks/r2kit](https://github.com/cmatthewbrooks/r2kit) A set of scripts for a radare-based malware code analysis workflow
- [**61**星][3y] [Py] [adulau/malwareclassifier](https://github.com/adulau/malwareclassifier) Malware Classifier From Network Captures
- [**61**星][3y] [Assembly] [cranklin/cranky-data-virus](https://github.com/cranklin/cranky-data-virus) Educational virus written in Assembly that infects 32-bit ELF executables on Linux using the data segment infection method
- [**61**星][4d] [PHP] [marcocesarato/php-antimalware-scanner](https://github.com/marcocesarato/php-antimalware-scanner) AMWSCAN (Antimalware Scanner) is a php antimalware/antivirus scanner console script written in php for scan your project. This can work on php projects and a lot of others platform.
- [**61**星][4y] [C++] [null--/graviton](https://github.com/null--/graviton) Cross Platform Malware Development Framework
- [**60**星][1y] [C++] [cisco-talos/thanatosdecryptor](https://github.com/cisco-talos/thanatosdecryptor) ThanatosDecryptor is an executable program that attempts to decrypt certain files encrypted by the Thanatos malware.
- [**60**星][2y] [Java] [geeksonsecurity/android-overlay-malware-example](https://github.com/geeksonsecurity/android-overlay-malware-example) Harmless Android malware using the overlay technique to steal user credentials.
    - 重复区段: [Android->工具->新添加的1](#63fd2c592145914e99f837cecdc5a67c) |
- [**60**星][22d] [Vue] [nao-sec/tknk_scanner](https://github.com/nao-sec/tknk_scanner) 基于社区的集成恶意软件识别系统
- [**60**星][4y] [Py] [samvartaka/malware](https://github.com/samvartaka/malware) Various malware, packer, crypter, etc. detection and analysis tools
- [**59**星][3y] [Batchfile] [ayra/zipbomb](https://github.com/ayra/zipbomb) About an old technology that still screws up some anti virus software
- [**59**星][9m] [YARA] [sfaci/masc](https://github.com/sfaci/masc) 扫描网站中的恶意软件, 以及其他一些网站维护功能
- [**58**星][6y] [Py] [malwarelu/tools](https://github.com/malwarelu/tools) Malware.lu tools
- [**58**星][1y] [PHP] [slangji/wp-missed-schedule](https://github.com/slangji/wp-missed-schedule) Find only missed schedule posts, every 15 minutes, and republish correctly 10 items each session. The Original plugin (only this) no longer available on WordPress.org for explicit author request! Compatible with WP 2.1+ to 4.9+ and 5.0-beta3 (100.000+ installs 300.000+ downloads 2016-04-13) Please: do not install unauthorized malware cloned forked!
- [**57**星][6d] [Py] [afagarap/malware-classification](https://github.com/afagarap/malware-classification) Towards Building an Intelligent Anti-Malware System: A Deep Learning Approach using Support Vector Machine for Malware Classification
- [**57**星][28d] [albertzsigovits/malware-writeups](https://github.com/albertzsigovits/malware-writeups) Personal research and publication on malware families
- [**57**星][25d] [C++] [cert-polska/ursadb](https://github.com/cert-polska/ursadb) Trigram database written in C++, suited for malware indexing
- [**57**星][4y] [JS] [gattermeier/nodejs-virus](https://github.com/gattermeier/nodejs-virus) A Node.js Proof of Concept Virus
- [**57**星][4m] [Rust] [guitmz/fe2o3](https://github.com/guitmz/fe2o3) Simple prepender virus written in Rust
- [**57**星][5y] [C] [honeynet/ghost-usb-honeypot](https://github.com/honeynet/ghost-usb-honeypot) A honeypot for malware that propagates via USB storage devices
- [**57**星][6m] [C#] [nyan-x-cat/limeusb-csharp](https://github.com/nyan-x-cat/limeusb-csharp) Malware USB Spread | Example C#
- [**56**星][4y] [Py] [rehints/blackhat_2015](https://github.com/rehints/blackhat_2015) Distributing the REconstruction of High-Level IR for Large Scale Malware Analysis
- [**56**星][8m] [Shell] [malscan/malscan](https://github.com/malscan/malscan) A fully featured malware scanner for Linux desktops and servers.
- [**55**星][4y] [Py] [pidydx/smrt](https://github.com/pidydx/smrt) Sublime Malware Research Tool
- [**54**星][8y] [Py] [cranklin/python-virus](https://github.com/cranklin/python-virus) This is an educational computer virus written in Python to demonstrate how replication is done.
- [**53**星][5m] [Py] [deadbits/malware-analysis-scripts](https://github.com/deadbits/malware-analysis-scripts) Collection of scripts for different malware analysis tasks
- [**53**星][15d] [Py] [pylyf/networm](https://github.com/pylyf/networm) Python network worm that spreads on the local network and gives the attacker control of these machines.
- [**51**星][6y] [C++] [jyang772/xor_crypter](https://github.com/jyang772/xor_crypter) XOR encryption, malware crypter
- [**51**星][1y] [Py] [sysopfb/malware_scripts](https://github.com/sysopfb/malware_scripts) Various scripts for different malware families
- [**51**星][4y] [Py] [znb/malware](https://github.com/znb/malware) Malware related code
- [**50**星][2y] [Py] [adrianherrera/virustotal](https://github.com/adrianherrera/virustotal) A simple command-line script to interact with the virustotal-api
- [**50**星][8m] [Jupyter Notebook] [hija/malwaredatascience](https://github.com/hija/malwaredatascience) Malware Data Science Reading Diary / Notes
- [**50**星][2y] [newlog/r2_malware_unpacking_training](https://github.com/newlog/r2_malware_unpacking_training) 使用 r2 脱壳恶意代码教程
- [**50**星][1y] [JS] [platdrag/unblockablechains](https://github.com/platdrag/unblockablechains) Unblockable Chains - A POC on using blockchain as infrastructure for malware operations
- [**48**星][5m] [PHP] [bediger4000/reverse-php-malware](https://github.com/bediger4000/reverse-php-malware) De-obfuscate and reverse engineer PHP malware
- [**48**星][2y] [Py] [cert-polska/malwarecage](https://github.com/cert-polska/malwarecage) Malware repository component for samples & static configuration with REST API interface
- [**48**星][2y] [Jupyter Notebook] [harrisonpim/bookworm](https://github.com/harrisonpim/bookworm) 
- [**48**星][3y] [C] [malwarelu/malware-lu](https://github.com/malwarelu/malware-lu) Automatically exported from code.google.com/p/malware-lu
- [**48**星][2y] [HTML] [c0nw0nk/coinhive](https://github.com/c0nw0nk/coinhive) A nice friendly simple and easly customizable GUI for coinhives javascript miner to embed onto websites so users of your site can interact with features of the miner on every single page this javascript miner is to help those who have problems with advertisements/advertising/ads popups banners mobile redirects malvertising/malware etc and provid…
- [**46**星][1y] [Py] [aaaddress1/vtmal](https://github.com/aaaddress1/vtmal) Malware Sandbox Emulation in Python @ HITCON 2018
- [**45**星][2y] [Pascal] [0x48piraj/malwarex](https://github.com/0x48piraj/malwarex) Collection of killers !
- [**45**星][4y] [TeX] [gannimo/maldiv](https://github.com/gannimo/maldiv) Malware diversity
- [**45**星][2y] [Ruby] [hammackj/uirusu](https://github.com/hammackj/uirusu) A rubygem for interacting with Virustotal.com's public API v2
- [**45**星][2d] [stamparm/blackbook](https://github.com/stamparm/blackbook) Blackbook of malware domains
- [**45**星][4y] [C++] [tandasat/remotewritemonitor](https://github.com/tandasat/remotewritemonitor) A tool to help malware analysts tell that the sample is injecting code into other process.
- [**44**星][2y] [C] [bartblaze/matire](https://github.com/bartblaze/matire) Malware Analysis, Threat Intelligence and Reverse Engineering: LABS
- [**44**星][3y] [Shell] [mueller-ma/block-ads-via-dns](https://github.com/mueller-ma/block-ads-via-dns) Block ads and malware via local DNS server
- [**44**星][7m] [C#] [nyan-x-cat/lime-downloader](https://github.com/nyan-x-cat/lime-downloader) Simple Malware Downloader
- [**44**星][6m] [YARA] [decalage2/balbuzard](https://github.com/decalage2/balbuzard) Balbuzard is a package of malware analysis tools in python to extract patterns of interest from suspicious files (IP addresses, domain names, known file headers, interesting strings, etc). It can also crack malware obfuscation such as XOR, ROL, etc by bruteforcing and checking for those patterns.
- [**43**星][4y] [Py] [xme/mime2vt](https://github.com/xme/mime2vt) Unpack MIME attachments from a file and check them against virustotal.com
- [**42**星][9y] [Py] [9b/malpdfobj](https://github.com/9b/malpdfobj) Builds json representation of PDF malware sample
- [**42**星][1y] [Py] [alfa-group/robust-adv-malware-detection](https://github.com/alfa-group/robust-adv-malware-detection) Code repository for the paper "Adversarial Deep Learning for Robust Detection of Binary Encoded Malware"
- [**41**星][4y] [Py] [abdesslem/malwarehunter](https://github.com/abdesslem/malwarehunter) Static and automated/dynamic malware analysis
- [**41**星][2y] [deadbits/analyst-casefile](https://github.com/deadbits/analyst-casefile) Maltego CaseFile entities for information security investigations, malware analysis and incident response
- [**41**星][3y] [Py] [dnlongen/reglister](https://github.com/dnlongen/reglister) Recurse through a registry, identifying values with large data -- a registry malware hunter
- [**41**星][4m] [maecproject/malware-behaviors](https://github.com/maecproject/malware-behaviors) A taxonomy and dictionary of malware behaviors.
- [**41**星][2y] [Py] [ntddk/virustream](https://github.com/ntddk/virustream) A script to track malware IOCs with OSINT on Twitter.
- [**40**星][3y] [Py] [fabiobaroni/was](https://github.com/fabiobaroni/was) Automatic USB drive malware scanning tool for the security-minded person
- [**40**星][4y] [Py] [rooklabs/milano](https://github.com/rooklabs/milano) Hacking Team Malware Detection Utility
- [**40**星][4m] [Shell] [tasket/qubes-vm-hardening](https://github.com/tasket/qubes-vm-hardening) Fend off malware at Qubes VM startup
- [**40**星][1y] [Shell] [waja/maldetect](https://github.com/waja/maldetect) Debian packaging of Linux Malware Detect (
- [**39**星][1y] [Py] [dissectmalware/malwarecmdmonitor](https://github.com/dissectmalware/malwarecmdmonitor) Shows command lines used by latest instances analyzed on Hybrid-Analysis
- [**39**星][3y] [Py] [jevalenciap/iptodomain](https://github.com/jevalenciap/iptodomain) This tool extract domains from IP address based in the information saved in virustotal.
- [**39**星][3y] [Java] [kdkanishka/virustotal-public-api-v2.0-client](https://github.com/kdkanishka/virustotal-public-api-v2.0-client) VirusTotal public API 2.0 implementation in Java
- [**39**星][2y] [PHP] [nao-sec/mal_getter](https://github.com/nao-sec/mal_getter) Tool for dropping malware from EK
- [**39**星][3m] [spiderlabs/iocs-idps](https://github.com/spiderlabs/iocs-idps) This repository will hold PCAP IOC data related with known malware samples (owner: Bryant Smith)
- [**38**星][5y] [C++] [adamkramer/rapid_env](https://github.com/adamkramer/rapid_env) Rapid deployment of Windows environment (files, registry keys, mutex etc) to facilitate malware analysis
- [**38**星][3y] [Py] [cysinfo/pymal](https://github.com/cysinfo/pymal) PyMal is a python based interactive Malware Analysis Framework. It is built on the top of three pure python programes Pefile, Pydbg and Volatility.
- [**38**星][1y] [C] [en14c/pivirus](https://github.com/en14c/pivirus) sample linux x86_64 ELF virus
- [**38**星][1y] [Shell] [rordi/docker-antivirus](https://github.com/rordi/docker-antivirus) Docker antivirus & malware scanning (antivirus as a microservice / antivirus as a container)
- [**38**星][1y] [Py] [tanc7/arms-commander](https://github.com/tanc7/arms-commander) Malware Suite/Menu designed for "Speedy and No-Mistakes Penetration Testing", written in Python 2.7.13 and tested on Kali Linux 4.6 & 4.9, originally intended to only perform the Reconnaissance and Enumeration Stages (it's role is dramatically expanded now). Requires Python 2.7 + Pip + Termcolor Module. All code is entirely free to be used in yo…
- [**37**星][25d] [Py] [bytesoverbombs/virusshare-search](https://github.com/bytesoverbombs/virusshare-search) Downloads VirusShare hashes (
- [**37**星][1y] [Py] [lasq88/deobfuscate](https://github.com/lasq88/deobfuscate) Python script to automatically deobfuscate malware code
- [**37**星][4y] [C] [mempodippy/cub3](https://github.com/mempodippy/cub3) Proof of concept for LD_PRELOAD malware that uses extended attributes to protect files.
- [**37**星][4y] [michael-yip/aptmalwarenotes](https://github.com/michael-yip/aptmalwarenotes) A repository of open source reports on different malware families used in targeted cyber intrusions ("APT").
- [**37**星][3y] [C] [mwsrc/mass-malicious-script-dump](https://github.com/mwsrc/mass-malicious-script-dump) Mass malicious script dump/Malware src dump
- [**36**星][5y] [C++] [adamkramer/jmp2it](https://github.com/adamkramer/jmp2it) Transfer EIP control to shellcode during malware analysis investigation
- [**36**星][3y] [Py] [ec-digit-csirc/virustotal-tools](https://github.com/ec-digit-csirc/virustotal-tools) 
- [**36**星][9m] [Py] [phage-nz/malware-hunting](https://github.com/phage-nz/malware-hunting) 与 Malware Hunting 相关的脚本/信息收集
- [**35**星][7y] [C++] [csurage/rootkit](https://github.com/csurage/rootkit) Windows Malware
- [**35**星][3y] [Shell] [huntergregal/malwaresandbox](https://github.com/huntergregal/malwaresandbox) A ready to deploy docker container for a fresh sandbox for on-the-fly malware analysis
- [**35**星][4y] [C] [motazreda/malwarefragmentationtool](https://github.com/motazreda/malwarefragmentationtool) Malware Fragmentation Tool its a tool that simply fragment the PE file and it can disassemble the PE file, etc this tool very useful for people who do malware research or analysis for pe_files
- [**34**星][5y] [C++] [adamkramer/handle_monitor](https://github.com/adamkramer/handle_monitor) Identifying and Disrupting Crypto-Ransomware (and Destructive Malware) using handle heurustics
- [**34**星][1y] [Shell] [hestat/blazescan](https://github.com/hestat/blazescan) Blazescan is a linux webserver malware scanning and incident response tool, with built in support for cPanel servers, but will run on any linux based server.
- [**34**星][3y] [Py] [huntergregal/bothunter](https://github.com/huntergregal/bothunter) Scans the internet for open FTP servers looking for common malware bot droppers and grabs them for sampling. Also provides support for uploading samples to VirusTotal
- [**34**星][5m] [Jupyter Notebook] [malware-revealer/malware-revealer](https://github.com/malware-revealer/malware-revealer) Spot malwares using Machine Learning techniques
- [**34**星][1m] [Dockerfile] [misp/docker-misp](https://github.com/misp/docker-misp) Automated Docker MISP container - Malware Information Sharing Platform and Threat Sharing
- [**34**星][5y] [Py] [shendo/netsink](https://github.com/shendo/netsink) Network sinkhole for isolated malware analysis
- [**34**星][2y] [C] [smh17/bitcoin-hacking-tools](https://github.com/smh17/bitcoin-hacking-tools) The source code of main tools used in Bitcoin "non-malware-based" attacks.
- [**34**星][4y] [C] [soufianetahiri/vault-8-hive](https://github.com/soufianetahiri/vault-8-hive) Hive solves a critical problem for the malware operators at the CIA.
- [**34**星][3y] [C] [nttiton/malware](https://github.com/NTTITON/Malware) 
- [**34**星][12d] [Batchfile] [itskindred/malware-analysis-writeups](https://github.com/itskindred/malware-analysis-writeups) A repository of my completed writeups, along with the samples themselves.
- [**33**星][2y] [Rust] [0xcpu/bonomen](https://github.com/0xcpu/bonomen) BONOMEN - Hunt for Malware Critical Process Impersonation
- [**33**星][3y] [PHP] [gregzem/aibolit](https://github.com/gregzem/aibolit) Free malware and virus scanner for websites and ISP
- [**33**星][4y] [Py] [mansosec/microsoft-malware-challenge](https://github.com/mansosec/microsoft-malware-challenge) 
- [**33**星][2m] [C] [milter-manager/milter-manager](https://github.com/milter-manager/milter-manager) milter manager is a free software to protect you from spam mails and virus mails effectively with milter.
- [**33**星][1y] [C] [thisissecurity/malware](https://github.com/thisissecurity/malware) 
- [**33**星][8m] [C++] [tlgyt/absent-loader](https://github.com/tlgyt/absent-loader) Example Loader to be used as a learning resource for people interested in how commercially available malware is made.
- [**32**星][6m] [Py] [fr0gger/unprotect](https://github.com/fr0gger/unprotect) Unprotect is a python tool for parsing PE malware and extract evasion techniques.
- [**32**星][3d] [C++] [hasherezade/funky_malware_formats](https://github.com/hasherezade/funky_malware_formats) Parsers for custom malware formats ("Funky malware formats")
- [**32**星][6m] [Py] [shouc/knicky](https://github.com/shouc/knicky) A module-based static virus generator
- [**32**星][7m] [Perl] [tripflex/cpsetup](https://github.com/tripflex/cpsetup) Intuitive bash/shell script to setup and harden/configure cPanel CentOS/RHEL server with ConfigServer Firewall, MailManage, MailQueue, Malware Detect, ClamAV, mod_cloudflare, CloudFlare RailGun, and many more applications and security tweaks
- [**31**星][1y] [Py] [bsvineethiitg/malwaregan](https://github.com/bsvineethiitg/malwaregan) Visualizing malware behavior, and proactive protection using GANs against zero-day attacks.
- [**31**星][7y] [C++] [glmcdona/malm](https://github.com/glmcdona/malm) MALM: Malware Monitor
- [**31**星][3y] [Py] [harryr/maltrieve](https://github.com/harryr/maltrieve) A tool to retrieve malware directly from the source for security researchers.
- [**31**星][3y] [CSS] [malwares/malwares.github.io](https://github.com/malwares/malwares.github.io) malwares src dump
- [**31**星][2y] [Py] [medhini/malicious_website_detection](https://github.com/medhini/malicious_website_detection) Uses deep learning and machine learning techniques to detect and classify web pages as spam, malware and phishing
- [**31**星][5y] [Assembly] [th4nat0s/no_sandboxes](https://github.com/th4nat0s/no_sandboxes) Test suite for bypassing Malware sandboxes.
- [**30**星][2y] [Py] [fideliscyber/data_mining](https://github.com/fideliscyber/data_mining) Data Mining Virus Total for threat feed building
- [**30**星][4y] [neu5ron/malware-traffic-analysis-pcaps](https://github.com/neu5ron/malware-traffic-analysis-pcaps) 网站malware-traffic-analysis.net的pcap文件托管
- [**30**星][3y] [JS] [rpgeeganage/file-less-ransomware-demo](https://github.com/rpgeeganage/file-less-ransomware-demo) Demonstrate about file-less malware approach using JavaScript
- [**30**星][3y] [Jupyter Notebook] [surajr/machine-learning-approach-for-malware-detection](https://github.com/surajr/machine-learning-approach-for-malware-detection) A Machine Learning approach for classifying a file as Malicious or Legitimate
- [**29**星][6y] [Py] [hiddenillusion/filelookup](https://github.com/hiddenillusion/filelookup) Quick & dirty script to get info on a file from online resources (VirusTotal, Team Cymru, Shadow Server etc.)
- [**29**星][5m] [Py] [intezer/mop](https://github.com/intezer/mop) MoP - "Master of Puppets" - Advanced malware tracking framework
- [**29**星][5m] [Py] [jacobsoo/threathunting](https://github.com/jacobsoo/threathunting) This is just my personal compilation of APT malware from whitepaper releases, documents and malware samples from my personal research.
- [**29**星][5y] [C] [karottc/linux-virus](https://github.com/karottc/linux-virus) A simple virus of linux. It can get root and destory your system.(这是一个简单的linux下的病毒，它仅能得到root权限和感染文件并进行破坏)
- [**29**星][9m] [C#] [nyan-x-cat/dropless-malware](https://github.com/nyan-x-cat/dropless-malware) Download a payload and make it run from registry without droppng.
- [**29**星][4y] [techbliss/yara_mailware_quick_menu_scanner](https://github.com/techbliss/yara_mailware_quick_menu_scanner) Work Fast With the pattern matching swiss knife for malware researchers.
- [**29**星][1m] [Py] [certtools/malware_name_mapping](https://github.com/certtools/malware_name_mapping) A mapping of used malware names to commonly known family names
- [**28**星][3y] [Shell] [0utrider/malrecon](https://github.com/0utrider/malrecon) malrecon：基本的恶意代码检测和分析工具，Shell 编写
- [**28**星][2y] [Py] [mprhode/malware-prediction-rnn](https://github.com/mprhode/malware-prediction-rnn) RNN implementation with Keras for machine activity data to predict malware
- [**28**星][2y] [tatsui-geek/malware-traffic-analysis.net](https://github.com/tatsui-geek/malware-traffic-analysis.net) Download pcap files from
- [**28**星][2m] [Assembly] [vxunderground/family](https://github.com/vxunderground/family) Collection of Malware source code by Language and Family.
- [**27**星][3y] [Py] [deralexxx/firemisp](https://github.com/deralexxx/firemisp) FireEye Alert json files to MISP Malware information sharing plattform (Alpha)
- [**27**星][2y] [mahmudz/malware](https://github.com/mahmudz/malware) 
- [**27**星][1y] [PHP] [rakshitshah94/wordpress-wp-vcd-malware-attack-solution](https://github.com/rakshitshah94/wordpress-wp-vcd-malware-attack-solution) Another attack on wordpress 4.8
- [**27**星][3y] [Py] [swackhamer/vt_notification_puller](https://github.com/swackhamer/vt_notification_puller) VirusTotal Intelligence Notification Puller
- [**27**星][1y] [Py] [tildedennis/malware](https://github.com/tildedennis/malware) 
- [**26**星][9m] [Py] [byt3bl33d3r/dnschef](https://github.com/byt3bl33d3r/dnschef) DNSChef - DNS proxy for Penetration Testers and Malware Analysts
- [**26**星][6m] [Py] [keithjjones/malgazer](https://github.com/keithjjones/malgazer) A Python malware analysis library.
- [**26**星][4y] [Py] [open-nsm/dockoo](https://github.com/open-nsm/dockoo) Malware analysis using Docker project
- [**26**星][1y] [C++] [psaneme/kung-fu-malware](https://github.com/psaneme/kung-fu-malware) 
- [**25**星][4y] [C++] [herrcore/cmddesktopswitch](https://github.com/herrcore/cmddesktopswitch) CmdDesktopSwitch is a small utility that lists all windows desktops and provides the option to switch between them. This can be used to identify and watch malware that has created a hidden desktop.
- [**25**星][t] [Java] [opticfusion1/mcantimalware](https://github.com/opticfusion1/mcantimalware) Anti-Malware for minecraft
- [**25**星][5y] [Py] [sash-ko/kaggle-malware-classification](https://github.com/sash-ko/kaggle-malware-classification) Kaggle "Microsoft Malware Classification Challenge". 6th place solution
- [**25**星][7m] [Py] [bonnetn/vba-obfuscator](https://github.com/bonnetn/vba-obfuscator) 2018 School project - PoC of malware code obfuscation in Word macros
- [**25**星][8y] [C++] [cr4sh/simpleunpacker](https://github.com/cr4sh/simpleunpacker) Simple tool for unpacking packed/protected malware executables.
- [**24**星][3y] [Ruby] [deadbits/maz](https://github.com/deadbits/maz) Malware Analysis Zoo
- [**24**星][6y] [C++] [edix/malwareresourcescanner](https://github.com/edix/malwareresourcescanner) Scanning and identifying XOR encrypted PE files in PE resources
- [**24**星][1y] [Py] [j40903272/malconv-keras](https://github.com/j40903272/malconv-keras) This is the implementation of MalConv proposed in [Malware Detection by Eating a Whole EXE](
- [**24**星][2y] [Py] [marcusbotacin/anti.analysis](https://github.com/marcusbotacin/anti.analysis) Malware Analysis, Anti-Analysis, and Anti-Anti-Analysis
- [**24**星][5m] [meitar/awesome-malware](https://github.com/meitar/awesome-malware) 
- [**24**星][6d] [CSS] [saferwall/saferwall](https://github.com/saferwall/saferwall) A hackable malware sandbox for the 21st Century
- [**24**星][2y] [silvermoonsecurity/sandboxevasion](https://github.com/silvermoonsecurity/sandboxevasion) Malware sandbox evasion tricks and solution
- [**24**星][3m] [Py] [warner/magic-wormhole-transit-relay](https://github.com/warner/magic-wormhole-transit-relay) Transit Relay server for Magic-Wormhole
- [**23**星][2y] [bxlcity/malware](https://github.com/bxlcity/malware) 
- [**23**星][11m] [Py] [coldshell/malware-scripts](https://github.com/coldshell/malware-scripts) 
- [**23**星][2y] [Jupyter Notebook] [geekonlinecode/malware-machine-learning](https://github.com/geekonlinecode/malware-machine-learning) Malware Machine Learning
- [**23**星][2y] [C++] [grcasanova/supervirus](https://github.com/grcasanova/supervirus) Project aimed at creating a malware able to evolve and adapt to the various host machines through metamorphic modifications, spontaneous mutations, code imitation and DNA programming to enable/disable functionalities
- [**23**星][2y] [C] [ieeeicsg/ieee_taggant_system](https://github.com/ieeeicsg/ieee_taggant_system) Taggant System developed by the Malware Working Group of ICSG (Industry Connections Security Group) under the umbrella of IEEE
- [**23**星][5m] [C++] [mbrengel/memscrimper](https://github.com/mbrengel/memscrimper) Code for the DIMVA 2018 paper: "MemScrimper: Time- and Space-Efficient Storage of Malware Sandbox Memory Dumps"
- [**23**星][3y] [Py] [te-k/malware-classification](https://github.com/te-k/malware-classification) Data and code for malware classification using machine learning (for fun, not production)
- [**23**星][1y] [JS] [veggiedefender/marveloptics_malware](https://github.com/veggiedefender/marveloptics_malware) Deobfuscated + reverse engineered javascript malware
- [**23**星][4m] [PS] [nyan-x-cat/malwareshell](https://github.com/nyan-x-cat/malwareshell) Create a powershell malware loader to run C#.cs code on runtime
- [**22**星][16d] [Py] [endgameinc/malware_evasion_competition](https://github.com/endgameinc/malware_evasion_competition) 
- [**22**星][2y] [PHP] [gr33ntii/malware-collection](https://github.com/gr33ntii/malware-collection) 
- [**22**星][4y] [Py] [infectedpacket/vxvault](https://github.com/infectedpacket/vxvault) Malware management program and tools
- [**22**星][2y] [Go] [integrii/wormhole](https://github.com/integrii/wormhole) 
- [**21**星][8m] [Py] [drbeni/malquarium](https://github.com/drbeni/malquarium) Malquarium - Modern Malware Repository
- [**21**星][3y] [C] [exploit-install/thefatrat](https://github.com/exploit-install/thefatrat) An easy tool to generate backdoor with msfvenom (a part from metasploit framework). This tool compiles a malware with popular payload and then the compiled malware can be execute on windows, android, mac . The malware that created with this tool also have an ability to bypass most AV software protection
- [**21**星][6y] [Py] [ikoniaris/kippo-malware](https://github.com/ikoniaris/kippo-malware) Download all malicious files from a Kippo SSH honeypot database
- [**21**星][2y] [Py] [kudelskisecurity/check_all_apks](https://github.com/kudelskisecurity/check_all_apks) Check All APK's -- scripts for checking your phone for malware
- [**21**星][3y] [C++] [malwares/malware](https://github.com/malwares/malware) Malware Samples. Uploaded to GitHub for those want to analyse the code.
- [**21**星][4m] [Ruby] [pwelch/virustotal_api](https://github.com/pwelch/virustotal_api) Ruby Gem for VirusTotal API
- [**21**星][4y] [C] [warcraft23/virus-and-windows-api-programing](https://github.com/warcraft23/virus-and-windows-api-programing) 中科大13级计算机病毒分析与WindowsAPI编程 授课老师：郭大侠
- [**21**星][2y] [Shell] [wolfvan/some-samples](https://github.com/wolfvan/some-samples) Malware captured with honeypots
- [**20**星][3y] [C++] [dinamsky/malware-botnets](https://github.com/dinamsky/malware-botnets) 
- [**20**星][1y] [seifreed/awesome-sandbox-evasion](https://github.com/seifreed/awesome-sandbox-evasion) A summary about different projects/presentations/tools to test how to evade malware sandbox systems
- [**20**星][1y] [Py] [thisissecurity/sinkhole](https://github.com/thisissecurity/sinkhole) Miscellanous scripts used for malware analysis
- [**20**星][2y] [C] [tkcert/winnti-detector](https://github.com/tkcert/winnti-detector) Network detector for Winnti malware
- [**19**星][10m] [Swift] [alexruperez/safebrowsing](https://github.com/alexruperez/safebrowsing) Protect your users against malware and phishing threats using Google Safe Browsing
- [**19**星][4y] [HTML] [cryptostorm-dev/cleanvpn.xyz](https://github.com/cryptostorm-dev/cleanvpn.xyz) A place to research & publicly certify malware-free, fully operational VPN services
- [**19**星][3y] [Py] [hpe-appliedsecurityresearch/maltese](https://github.com/hpe-appliedsecurityresearch/maltese) Maltese - Malware Traffic Emulator
- [**19**星][5y] [C] [tiago4orion/malelf](https://github.com/tiago4orion/malelf) Malware analysis tool
- [**19**星][3y] [unexpectedby/automated-malware-analysis-list](https://github.com/unexpectedBy/Automated-Malware-Analysis-List) My personal Automated Malware Analysis Sandboxes and Services
- [**19**星][3y] [ulexec/windowsmalwaresourcecode](https://github.com/ulexec/WindowsMalwareSourceCode) Collection of Source Code of Various Malware Targeting the Windows Platform
- [**18**星][3y] [C] [pfohjo/nitro](https://github.com/pfohjo/nitro) KVM-based virtual machine introspection for malware analysis
- [**18**星][1y] [Py] [seymour1/label-virusshare](https://github.com/seymour1/label-virusshare) A project to label the VirusShare malware corpus using VirusTotal's public API.
- [**18**星][2m] [Assembly] [vxunderground/vx-engines](https://github.com/vxunderground/vx-engines) Collection of source code for Polymorphic, Metamorphic, and Permutation Engines used in Malware
- [**18**星][18d] [Py] [cert-polska/malduck](https://github.com/cert-polska/malduck) your ducky companion in malware analysis journeys.
- [**17**星][6m] [Py] [alichtman/malware-techniques](https://github.com/alichtman/malware-techniques) A collection of techniques commonly used in malware to accomplish core tasks.
- [**17**星][2m] [PHP] [ecrider/black-seo-wordpress-malware](https://github.com/ecrider/black-seo-wordpress-malware) Reverse engineered, decrypted source files from the malware targeting WordPress content management systems.
- [**17**星][6m] [Visual Basic .NET] [nyan-x-cat/vbs-shell](https://github.com/nyan-x-cat/vbs-shell) using VBS to download and install a powershell malware
- [**17**星][3y] [C#] [panthere/antinet](https://github.com/panthere/antinet) Anti-.NET Malware/Packers - Detect most .NET Packers (and some native) used for malware.
- [**16**星][3y] [0xc1r3ng/malware-sandboxes-malware-source](https://github.com/0xc1r3ng/malware-sandboxes-malware-source) Malware Sandboxes & Malware Source
- [**16**星][6m] [C++] [adrianherrera/malware-s2e](https://github.com/adrianherrera/malware-s2e) Code for my blog post on using S2E for malware analysis
- [**16**星][1y] [Py] [andreafortuna/malhunt](https://github.com/andreafortuna/malhunt) Hunt malware with Volatility
- [**16**星][3y] [dragosinc/crashoverride](https://github.com/dragosinc/crashoverride) IOCs for CRASHOVERRIDE malware framework
- [**16**星][12m] [Py] [ihiaadj/malware-classifier-pytorch](https://github.com/ihiaadj/malware-classifier-pytorch) A Malware Classifier with PyTorch
- [**16**星][3y] [CSS] [nbs-system/mowr](https://github.com/nbs-system/mowr) More Obvious Webmalware Repository
- [**16**星][2y] [Py] [nogoodconfig/pyarascanner](https://github.com/nogoodconfig/pyarascanner) A simple many-rules to many-files YARA scanner for incident response or malware zoos.
- [**16**星][2m] [Assembly] [adwait1-g/practical-malware-analysis](https://github.com/adwait1-G/Practical-Malware-Analysis) This repository has everything I have learnt so far while reading the book Practical Malware Analysis
- [**16**星][3m] [C#] [splittydev/animus](https://github.com/splittydev/animus) The educational Animus malware
- [**15**星][3y] [PS] [adamdriscoll/amsi](https://github.com/adamdriscoll/amsi) PowerShell Module for the Antimalware Scan Interface (AMSI)
- [**15**星][5y] [C++] [christian-roggia/open-nettraveler](https://github.com/christian-roggia/open-nettraveler) RCEed version of chinese malware NetTraveler / TravNet.
- [**15**星][2y] [Py] [circlez3791117/pemaldetection](https://github.com/circlez3791117/pemaldetection) Malware detection demo using machine learning.
- [**15**星][1y] [C++] [cloudftl/customvirusscripts](https://github.com/cloudftl/customvirusscripts) Common Virus Scripts Used In Malware and Trojan viruses
- [**15**星][5y] [Py] [cloudjunky/malware-traffic](https://github.com/cloudjunky/malware-traffic) Download all packet captures from
- [**15**星][5y] [Py] [john-lin/malware](https://github.com/john-lin/malware) This is a malware analysis project which expecte to generate snort rule via malicious network traffic
- [**15**星][1m] [Py] [kaiiyer/automated-threat-intelligent-model](https://github.com/kaiiyer/automated-threat-intelligent-model) An improvised Automated Threat Intelligent System integrated with McAfee Advanced Threat Defense and Malware Information Sharing Platform.
- [**15**星][12m] [C] [zsshen/meltingpot](https://github.com/zsshen/meltingpot) A tool to cluster similar executables (PEs, DEXs, and etc), extract common signature, and generate Yara patterns for malware detection.
- [**15**星][2m] [C++] [hasherezade/hidden_bee_tools](https://github.com/hasherezade/hidden_bee_tools) Parser for a custom executable format from Hidden Bee malware (first stage)
- [**14**星][2y] [C++] [0xbadbac0n/malware](https://github.com/0xbadbac0n/malware) 
- [**14**星][3y] [0xmitsurugi/sandboxingmalware](https://github.com/0xmitsurugi/sandboxingmalware) A malware sandoxed with gdb
- [**14**星][1y] [Py] [neriberto/hg](https://github.com/neriberto/hg) A tool to download malwares
- [**14**星][2y] [psychotropos/hajime_hashes](https://github.com/psychotropos/hajime_hashes) Automatically compiled list of file hashes associated with the IoT malware Hajime and its components.
- [**14**星][2y] [Py] [secarmalabs/indushell](https://github.com/secarmalabs/indushell) PoC C&C for the Industroyer malware
- [**13**星][2y] [Ruby] [attachmentscanner/carrierwave-attachmentscanner](https://github.com/attachmentscanner/carrierwave-attachmentscanner) Adds the ability to send CarrierWave uploads to Attachment Scanner for virus and malware prevention.
- [**13**星][5y] [C++] [christian-roggia/open-shamoon](https://github.com/christian-roggia/open-shamoon) RCEed version of infamous malware Shamoon / Disttrack.
- [**13**星][11m] [cryptolok/cryptotrooper](https://github.com/cryptolok/cryptotrooper) rant blog about CryptoTrooper ransomware, its history, legacy and MalwareTech case
- [**13**星][3y] [Py] [dhilipsiva/hostscli](https://github.com/dhilipsiva/hostscli) hostscli - A CLI tool to block / unblock websites using /etc/hosts. Super simple and easily extendable. Also block Ads, Tracking & Malware sites.
- [**13**星][8m] [Py] [eybisi/nwaystounpackmobilemalware](https://github.com/eybisi/nwaystounpackmobilemalware) 
- [**13**星][6y] [C] [gdbinit/crisis-analysis-tools](https://github.com/gdbinit/crisis-analysis-tools) Scripts and other material related to OS.X/Crisis malware analysis
- [**13**星][1y] [C++] [kentavv/binary_viewer](https://github.com/kentavv/binary_viewer) A binary visualization tool to aid with reverse engineering and malware detection similar to Cantor.Dust
- [**12**星][2m] [AutoIt] [fortinet/ips-bph-framework](https://github.com/fortinet/ips-bph-framework) BLACKPHENIX is an open source malware analysis automation framework composed of services, scripts, plug-ins, and tools and is based on a Command-and-Control (C&C) architecture
- [**12**星][1y] [C#] [nirex0/ddl](https://github.com/nirex0/ddl) Dark Drop Library, Library to create Ransomware Malware with C#
- [**12**星][2y] [Py] [vallejocc/malware-analysis-scripts](https://github.com/vallejocc/Malware-Analysis-scripts) Scripts targeting specific families
- [**11**星][2m] [JS] [carlospolop/malwareworld](https://github.com/carlospolop/malwareworld) System based on +500 blacklists and 5 external intelligences to detect internet potencially malicious hosts
- [**11**星][5y] [C] [dakotastateuniversity/malware-analysis](https://github.com/dakotastateuniversity/malware-analysis) 
- [**11**星][4y] [Py] [dcmorton/malwaretools](https://github.com/dcmorton/malwaretools) Tools for malware collection
- [**11**星][4y] [Py] [devwerks/static-malware-analyses](https://github.com/devwerks/static-malware-analyses) A open source Python script to perform static analysis on a Malware Binary File (portable executable).
- [**11**星][12m] [fboldewin/fastcashmalwaredissected](https://github.com/fboldewin/fastcashmalwaredissected) Operation Fast Cash - Hidden Cobra‘s AIX PowerPC malware dissected
- [**11**星][1y] [PHP] [mwtracker/cryptam_tools](https://github.com/mwtracker/cryptam_tools) Cryptam document malware analysis tools
- [**11**星][1y] [C] [serializingme/emofishes](https://github.com/serializingme/emofishes) Emofishes is a collection of proof of concepts that help improve, bypass or detect virtualized execution environments (focusing on the ones setup for malware analysis).
- [**11**星][11m] [Py] [theenergystory/malware_analysis](https://github.com/theenergystory/malware_analysis) Tools and code snippets related to malware analysis
- [**11**星][7y] [C++] [wyyqyl/malwareanalysis](https://github.com/wyyqyl/malwareanalysis) The examples in the book - Practical Malware Analysis
- [**11**星][9y] [Ruby] [chrislee35/shadowserver](https://github.com/chrislee35/shadowserver) Queries various Shadowserver services for ASN information, malware hash lookups, and whitelist hash lookups
- [**10**星][2m] [albertzsigovits/learn_mlwr_re](https://github.com/albertzsigovits/learn_mlwr_re) Resources for learning malware analysis and reverse engineering
- [**10**星][2y] [Java] [edwardraff/jlzjd](https://github.com/edwardraff/jlzjd) a Java implementatio of the Lempel-Ziv Jaccard Distance, a distance metric designed for arbitrary byte sequences, and originally used for malware classification. 
- [**10**星][6y] [Tcl] [hbhzwj/imalse](https://github.com/hbhzwj/imalse) Integrated MALware Simulator and Emulator
- [**10**星][7y] [Py] [mboman/mart](https://github.com/mboman/mart) Malware Analyst Research Toolkit
- [**10**星][6y] [Py] [necrosys/zerowine-tryout](https://github.com/necrosys/zerowine-tryout) Zero Wine Tryouts: An open source malware analysis tool
- [**10**星][3y] [Py] [r3mrum/loki-parse](https://github.com/r3mrum/loki-parse) A python script that can detect and parse loki-bot (malware) related network traffic. This script can be helpful to DFIR analysts and security researchers who want to know what data is being exfiltrated to the C2, bot tracking, etc...
- [**10**星][4y] [vectrathreatlab/reyara](https://github.com/vectrathreatlab/reyara) Yara rules for quick reverse engineering of malware.
- [**10**星][3y] [Py] [zengrx/s.m.a.r.t](https://github.com/zengrx/s.m.a.r.t) static malware analysis and report tool open source version for linux
- [**10**星][3y] [Py] [jjo-sec/malware](https://github.com/jjo-sec/malware) Various Malware-Related Utilities
- [**10**星][2y] [C#] [vallejocc/malware-analysis-reports-manual](https://github.com/vallejocc/Malware-Analysis-Reports-Manual) My manual analysis of malware families
- [**9**星][6y] [Py] [blacktop/totalhash-api](https://github.com/blacktop/totalhash-api) #totalhash - Malware Analysis Database API
- [**9**星][4y] [Py] [droptables/carbongraphiti](https://github.com/droptables/carbongraphiti) Visualizing Malware Life Cycle in 3D with OpenGraphiti
- [**9**星][2y] [Py] [g4lb1t/need-less](https://github.com/g4lb1t/need-less) Vaccinating you endpoint against paranoid malware V2.0
- [**9**星][1y] [Go] [malice-plugins/get-mauled](https://github.com/malice-plugins/get-mauled) Download a Bunch of Malware for Demos and Testing
- [**9**星][1m] [Py] [mauronz/malware_analysis](https://github.com/mauronz/malware_analysis) 
- [**9**星][3y] [Py] [p1llus/getfeeds](https://github.com/p1llus/getfeeds) Python malware intelligence feed
- [**9**星][5y] [Py] [pythonwebscrapingmalware/malware](https://github.com/pythonwebscrapingmalware/malware) python web scraping
- [**9**星][1y] [Py] [uppusaikiran/malware-organiser](https://github.com/uppusaikiran/malware-organiser) A simple tool to organise large malicious/benign files into a organised Structure.
- [**9**星][] [Py] [mkb2091/blockconvert](https://github.com/mkb2091/blockconvert) Malware, advert and tracking blacklist
- [**8**星][4y] [Java] [almightymegadeth00/antipiracysupport](https://github.com/almightymegadeth00/antipiracysupport) Automatically disable and remove malware and blacklisted piracy markets to help support developers and themers
- [**8**星][2y] [arthimj/malware-detection-using-supervised-machine-learning-algorithm](https://github.com/arthimj/malware-detection-using-supervised-machine-learning-algorithm) Python Project
- [**8**星][2y] [PHP] [cirku17/wp-vcd-malware-sample](https://github.com/cirku17/wp-vcd-malware-sample) Wordpress malware sample with IOC
- [**8**星][30d] [Py] [cryptogramfan/malware-analysis-scripts](https://github.com/cryptogramfan/malware-analysis-scripts) Handy scripts to speed up malware analysis
- [**8**星][2y] [Py] [fbruzzaniti/capture-py](https://github.com/fbruzzaniti/capture-py) Capture-Py is a malware analysis tool that makes a copy of any files deleted or modified in a given directory and sub-directories. It was intended to be a subsitute for Capture-Bat on 64bit systems.
- [**8**星][2y] [C] [in3o/binclass](https://github.com/in3o/binclass) Recovering Object information from a C++ compiled Binary/Malware (mainly written for PE files) , linked dynamically and completely Stripped.
- [**8**星][6m] [Py] [laurencejbelliott/ensemble_dl_ransomware_detector](https://github.com/laurencejbelliott/ensemble_dl_ransomware_detector) A Deep Learning ensemble that classifies Windows executable files as either benign, ransomware, or other malware.
- [**8**星][3y] [Go] [mcastilho/doktor](https://github.com/mcastilho/doktor) CLI OSX malware scanner
- [**8**星][2y] [Py] [ntmaldetect/ntmaldetect](https://github.com/ntmaldetect/ntmaldetect) Open source malware detection program using machine learning algorithms on system call traces.
- [**8**星][3y] [opsxcq/malware-sample-banker-fefad618eb6177f07826d68a895769a8](https://github.com/opsxcq/malware-sample-banker-fefad618eb6177f07826d68a895769a8) Brazilian banker malware identified by Notificacao_Infracao_De_Transito_99827462345231.js
- [**8**星][1y] [Py] [rsc-dev/pypi_malware](https://github.com/rsc-dev/pypi_malware) PyPI malware packages
- [**8**星][7y] [silascutler/dns-monitor](https://github.com/silascutler/dns-monitor) DNSMonitor is a set of scripts to monitor malware and botnet domains for IP address changes by monitoring TTL values.
- [**8**星][2y] [C++] [gilmansharov/onionmalware](https://github.com/gilmansharov/onionmalware) Multi-layer malware
- [**7**星][3y] [Py] [2015-10-10/malwareclassification](https://github.com/2015-10-10/malwareclassification) 利用机器学习检测恶意代码
- [**7**星][2y] [Py] [ch4meleon/ms17_010_scanner](https://github.com/ch4meleon/ms17_010_scanner) This simple SMB vulnerability MS17-010 scanner is developed to help security professionals to quickly check if a computer is vulnerable to MS17-010 vulnerability which is used by WannaCry and Petya malwares.
- [**7**星][2y] [gosecure/malware-ioc](https://github.com/gosecure/malware-ioc) Indicators of Compromise (IOCs) for malware we have researched
- [**7**星][4m] [Py] [marcusbotacin/malware.variants](https://github.com/marcusbotacin/malware.variants) Additional material for the malware variants identification paper
- [**7**星][2y] [Py] [notnop/your-daily-malware-samples](https://github.com/notnop/your-daily-malware-samples) Download latest malware samples
- [**7**星][3y] [HTML] [pimmytrousers/malwareunicornrecourse](https://github.com/pimmytrousers/malwareunicornrecourse) Notes on the Malware Unicorn Reverse Engineering Course
- [**7**星][5y] [Ruby] [pwelch/chef-yara](https://github.com/pwelch/chef-yara) Chef Cookbook to Install the YARA Malware Research Tool
- [**7**星][4y] [Java] [tryan18/xcom](https://github.com/tryan18/xcom) Cross-referencing network communication for detecting Advanced Persistent Threat (APT) malware
- [**7**星][1m] [HTML] [voxpupuli/puppet-misp](https://github.com/voxpupuli/puppet-misp) This module installs and configures MISP (Malware Information Sharing Platform)
- [**7**星][2y] [zhiyuanwang-chengdu-qihoo360/malwarebytes_poc](https://github.com/zhiyuanwang-chengdu-qihoo360/malwarebytes_poc) Malwarebytes Antivirus CVE
- [**7**星][t] [PHP] [navytitanium/misc-malwares](https://github.com/navytitanium/misc-malwares) Collection of various files collected on infected hosts
- [**7**星][2m] [JS] [ecstatic-nobel/not-anti-virus](https://github.com/ecstatic-nobel/not-anti-virus) An attmept to block malware before AV scans it.
- [**6**星][4y] [0xrnair/malware-analysis](https://github.com/0xrnair/malware-analysis) 
- [**6**星][2y] [C#] [blackvikingpro/aresdoor](https://github.com/blackvikingpro/aresdoor) Advanced command shell backdoor malware written for the Windows OS
- [**6**星][1y] [Assembly] [david-reguera-garcia-dreg/winxpsp2.cermalus](https://github.com/david-reguera-garcia-dreg/winxpsp2.cermalus) Malware WinXPSP2.Cermalus
- [**6**星][1y] [Shell] [ez3r0sec/jamfprothreathunting](https://github.com/ez3r0sec/jamfprothreathunting) Scripts to aid intrusion and malware detection using the Jamf Agent and Jamf Server
- [**6**星][2y] [Py] [fabriciojoc/malware-machinelearning](https://github.com/fabriciojoc/malware-machinelearning) Malware - Machine Learning
- [**6**星][6m] [Shell] [hestat/calamity](https://github.com/hestat/calamity) A script to assist in processing forensic RAM captures for malware triage
- [**6**星][3y] [jacobsoo/j-hunter](https://github.com/jacobsoo/j-hunter) This is just a page to track the malicious malware.
- [**6**星][5y] [CSS] [levitateplatform/levitate](https://github.com/levitateplatform/levitate) Levitate - Reverse Engineering and Static Malware Analysis Platform -
- [**6**星][2y] [Shell] [nshadov/malware-tools-docker](https://github.com/nshadov/malware-tools-docker) Dockerfile with tools for analyzing malicious documents.
- [**6**星][7m] [AutoHotkey] [osandamalith/malware](https://github.com/osandamalith/malware) This is a malware repo. Use them at your own risk. This is strictly for educational purposes only.
- [**6**星][6m] [perfectdotexe/perfect-malware-samples](https://github.com/perfectdotexe/perfect-malware-samples) Fresh malware samples caught in the wild daily from random places.
- [**6**星][2y] [Py] [sontung/drebin-malwares](https://github.com/sontung/drebin-malwares) Malware detection using the Drebin dataset
- [**6**星][3y] [Ruby] [strazzere/ewmami](https://github.com/strazzere/ewmami) A gem will allow you to query the Google Play APK Verification (AntiMalware) service
- [**6**星][4y] [Visual Basic .NET] [xyl2k/malware-auto-downloader](https://github.com/xyl2k/malware-auto-downloader) Lame malware downloader wrote in VB+PHP
- [**6**星][7m] [C#] [ritredteam/windowsplague](https://github.com/ritredteam/windowsplague) Windows Malware monitors and infects specific kinds of files.
- [**5**星][6y] [Py] [digital4rensics/malformity_remote](https://github.com/digital4rensics/malformity_remote) A remote transform package for malware and malicious infrastructure research
- [**5**星][2y] [Py] [erxathos/malware-detector](https://github.com/erxathos/malware-detector) Using neural networks for malware detection
- [**5**星][2y] [Go] [garethjensen/amsi](https://github.com/garethjensen/amsi) Golang implementation of Microsoft Antimalware Scan Interface
- [**5**星][3y] [makflwana/iocs-in-csv-format](https://github.com/makflwana/iocs-in-csv-format) The repository contains IOCs in CSV format for APT, Cyber Crimes, Malware and Trojan and whatever I found as part of hunting and research
- [**5**星][6m] [Py] [motakbiri/malware-detection](https://github.com/motakbiri/malware-detection) Machine Learning-Based Malicious Application Detecting using Low-level Architectural Features
- [**5**星][2y] [Shell] [nshadov/yara-rules](https://github.com/nshadov/yara-rules) My small collection of yara rules for classifying and detecting malware/exploits
- [**5**星][3y] [oalabs/iocs](https://github.com/oalabs/iocs) Machine-digestible malware indicators.
- [**5**星][4y] [Py] [rakeshcorp/anti-malwareid](https://github.com/rakeshcorp/anti-malwareid) Detect Malware with Sandbox/VM evasion and Anti-debugging skills with some heur
- [**5**星][5m] [Visual Basic .NET] [prohacktech/prohack-security-lite](https://github.com/prohacktech/prohack-security-lite) Anti-Malware application for Windows - Archive
- [**4**星][2y] [aboutsecurity/malware-samples](https://github.com/aboutsecurity/malware-samples) Source code, or code snippets of samples found while doing research, when available (no binaries).
- [**4**星][4y] [C#] [danielrteixeira/malware](https://github.com/danielrteixeira/malware) 
- [**4**星][11m] [C++] [gdatasoftwareag/ldpinchunpacker](https://github.com/gdatasoftwareag/ldpinchunpacker) Unpacker for the Ldpinch malware
- [**4**星][7m] [gexos/malrepo](https://github.com/gexos/malrepo) A collection of malware samples caught by DIONAEA Honeypot
- [**4**星][10m] [Py] [gpalazolo/malware_utils](https://github.com/gpalazolo/malware_utils) General scripts related to Malware analysis
- [**4**星][PHP] [graniet/athena](https://github.com/graniet/athena) This malware PoC load an encryptor scripts on all found folders and start all encryptors at once. After that, Athena core adds a code in the index file of application and check if the file is always encrypted.
- [**4**星][2y] [Py] [guchinoma/feature-extractor-malware-detector](https://github.com/guchinoma/feature-extractor-malware-detector) Malware detection systems using non-linear machine learning. Indicates not only detection result, but also concrete part of features attributed to the detection result. THIS IS STILL WIP
- [**4**星][4y] [Py] [lbull/malware-collector](https://github.com/lbull/malware-collector) The goal of this project is monitoring social networks to search malicious urls. The current version is working for Twitter: Based on trending topics tweets in a certain period of time, it searches for malicious urls inside of these tweets. The system parses urls efficiently and scalably. After parsing them, it verifies if they are linked with a…
- [**4**星][3y] [sadfud/yara.rules](https://github.com/sadfud/yara.rules) YARA rules for malware detection
- [**4**星][4y] [Py] [sibichakkaravarthy/malware-analysis](https://github.com/sibichakkaravarthy/malware-analysis) Malware analysis using Sandboxing techniques
- [**4**星][3m] [Py] [siddver007/realtime_attack_malwarespread_scrapers](https://github.com/siddver007/realtime_attack_malwarespread_scrapers) This repository contain scrapers for collecting Real-time Attack and Malware Spread Data provided by Norse Corp, Check Point Software Technologies, Malwarebytes, Fortinet, and LookingGlass Cyber Solutions, Inc. These scrapers were made for educational purposes only.
- [**4**星][3y] [Py] [srozb/malyzer](https://github.com/srozb/malyzer) Malware analysis platform based on winappdbg
- [**3**星][2y] [Py] [bedazzlinghex/memory-analysis](https://github.com/bedazzlinghex/memory-analysis) Contains tools to perform malware and forensic analysis in Memory
- [**3**星][1y] [Visual Basic .NET] [cdiaz1971/malware](https://github.com/cdiaz1971/malware) malware downloaded to a cowrie homeypot
- [**3**星][3y] [C] [chonghw/research-malware](https://github.com/chonghw/research-malware) 
- [**3**星][3m] [Shell] [foospidy/honeydb-malware-downloads](https://github.com/foospidy/honeydb-malware-downloads) Malware samples downloaded from URLs referenced in HoneyDB data.
- [**3**星][3y] [C] [ispoleet/malware](https://github.com/ispoleet/malware) Some of my old malware
- [**3**星][2y] [joseph-giron/recycle_malware](https://github.com/joseph-giron/recycle_malware) my talk on recycling malware
- [**3**星][4y] [Py] [justf0rwork/malware](https://github.com/justf0rwork/malware) 检测
- [**3**星][2y] [Py] [redmed666/malware_analysis_tools](https://github.com/redmed666/malware_analysis_tools) 
- [**3**星][1y] [Py] [skycckk/malware-image-analysis](https://github.com/skycckk/malware-image-analysis) Extract image features from "transformed malware binary" then analyze.
- [**3**星][2y] [Py] [supriyo-biswas/vtlivescan](https://github.com/supriyo-biswas/vtlivescan) VirusTotal-powered Python daemon that watches files in a directory for malware
- [**3**星][2y] [Py] [thekadeshi/thekadeshi.py](https://github.com/thekadeshi/thekadeshi.py) Antimalware software
- [**3**星][3y] [Py] [burnttoast-dfir/malware-tools](https://github.com/BurntToast-DFIR/Malware-Tools) Various tools and scripts to help with malware analysis and reverse engineering
- [**2**星][2y] [Standard ML] [11digits/php-clean-malware](https://github.com/11digits/php-clean-malware) Simple PHP code to assist in cleaning of injected malware PHP code
- [**2**星][2y] [Py] [carbonblack/cb-bluecoat-connector](https://github.com/carbonblack/cb-bluecoat-connector) Carbon Black detonation Integration with Bluecoat Malware Analysis (MAA)
- [**2**星][2y] [Py] [d34ddr34m3r/malware-decoders](https://github.com/d34ddr34m3r/malware-decoders) A collection of decoder scripts that can aid in the malware reverse-engineering.
- [**2**星][2y] [gajasurve/malware-books](https://github.com/gajasurve/malware-books) PDF related to Rev Eng And Malware
- [**2**星][2m] [Py] [jquinn147/analysis-automation](https://github.com/jquinn147/analysis-automation) These are some of the scripts I use to automate my analysis of malware.
- [**2**星][1y] [kan1shka9/practical-malware-analysis](https://github.com/kan1shka9/practical-malware-analysis) 
- [**2**星][7m] [C++] [marcusbotacin/malware.multicore](https://github.com/marcusbotacin/malware.multicore) Additional material for the "Multi-core malware threats" paper/project
- [**2**星][2y] [nao-sec/ioc](https://github.com/nao-sec/ioc) misp format Malware IOCs
- [**2**星][2y] [pr0teus/aleph-docker](https://github.com/pr0teus/aleph-docker) An docker compose to quickly load your Aleph for malware analysis.
- [**2**星][1m] [Assembly] [rickmark/mojo_thor](https://github.com/rickmark/mojo_thor) Research about malware that infects the EFI and SMC of Apple MacBooks.
- [**2**星][2y] [Py] [sfylabs/malware-tools](https://github.com/sfylabs/malware-tools) 
- [**2**星][6y] [Py] [slydon/malware_tools](https://github.com/slydon/malware_tools) A collection of malware tools.
- [**2**星][9m] [HTML] [usmanaura47/viral-tool-site](https://github.com/usmanaura47/viral-tool-site) Official Website of Viral Tool malware generator
- [**1**星][3y] [Java] [aenadon/viruscomplete](https://github.com/aenadon/viruscomplete) VirusComplete is an app based on the VirusTotal API. It can check files and URLs for malware.
- [**1**星][4y] [bedazzlinghex/detection](https://github.com/bedazzlinghex/detection) Contains yara rules and IOCs to detect malware in memory and on disk
- [**1**星][10y] [Ruby] [cedric/safe_browsing](https://github.com/cedric/safe_browsing) Use Google's SafeBrowsingAPI phishing and malware blacklist.
- [**1**星][3y] [C++] [colinmckaycampbell/rapidfilehash](https://github.com/colinmckaycampbell/rapidfilehash) Fast and powerful SHA256 hashing for malware detection and digital forensics.
- [**1**星][1y] [fireh7nter/malware-caged](https://github.com/fireh7nter/malware-caged) My Malware Repository and write ups
- [**1**星][2y] [Py] [jamieres/mz-data-extract](https://github.com/jamieres/mz-data-extract) Simple tool that you can use for collect relevant data of Portable Executable (PE) files that can be used for Intel during a line of research related with malware.
- [**1**星][2y] [Py] [parsiya/malwareadventure](https://github.com/parsiya/malwareadventure) Small python game written in PAWS
- [**1**星][2y] [Py] [psjoshi/malware-static-analysis](https://github.com/psjoshi/malware-static-analysis) Static malware analysis using python
- [**1**星][4y] [Py] [redteamcaliber/webmalwarescanner](https://github.com/redteamcaliber/webmalwarescanner) WebMalwareScanner - A simple malware scanner for web applications
- [**1**星][10m] [serializingme/malware-classification](https://github.com/serializingme/malware-classification) KNIME workflow using Machine Learning to classify Windows malware.
- [**1**星][3y] [PHP] [thekadeshi/thekadeshi.agent](https://github.com/thekadeshi/thekadeshi.agent) ☣ PHP malware scanner
- [**1**星][8m] [undo-ransomware/malware-samples](https://github.com/undo-ransomware/malware-samples) Ransomware samples with meta information and labels.
- [**1**星][5y] [wzr/yar4m](https://github.com/wzr/yar4m) Yara rules repo on malware
- [**1**星][2y] [zhiyuanwang-chengdu-qihoo360/malwarefox_antimalware_poc](https://github.com/zhiyuanwang-chengdu-qihoo360/malwarefox_antimalware_poc) MalwareFox_AntiMalware_CVE
- [**1**星][2y] [zhiyuanwang-chengdu-qihoo360/watchdog_antimalware_poc](https://github.com/zhiyuanwang-chengdu-qihoo360/watchdog_antimalware_poc) WatchDog_AntiMalware_CVE
- [**1**星][2y] [neuai/malwarelibrary](https://github.com/neuai/malwarelibrary) A collection of malware samples.
- [**1**星][3y] [PS] [avdaredevil/songs.pk](https://github.com/avdaredevil/songs.pk) Song.pk is a malware ridden site that has free bollywood songs: This tool downloads songs safely from Songs.PK [By Bruteforcing download URL's], and much more. It Functions like an API for their website!
- [**0**星][4y] [Batchfile] [adeptex/malwares](https://github.com/adeptex/malwares) PoCs and Tests
- [**0**星][2y] [JS] [adityapattani/malwaredetection](https://github.com/adityapattani/malwaredetection) This chrome extension aims at attacking different websites using SQL injection or XSS by selecting the text fields on the webpage using the extension and selecting the type of attack.
- [**0**星][3y] [Java] [avineshwar/disassembled-malware-codes](https://github.com/avineshwar/disassembled-malware-codes) This is purely for the purpose of sharing a malware author's thought process.
- [**0**星][4y] [bedazzlinghex/disk-analysis](https://github.com/bedazzlinghex/disk-analysis) Contains tools to perform malware and forensic analysis on disk
- [**0**星][2y] [chrislazari/malware](https://github.com/chrislazari/malware) 
- [**0**星][2y] [Py] [fbruzzaniti/pdfscope](https://github.com/fbruzzaniti/pdfscope) PDFScope is a wxPython GUI create for malware analysis of PDF files
- [**0**星][2y] [Perl] [hatsuz/knight-ddos](https://github.com/hatsuz/knight-ddos) Perl script to make a malware to DDoS
- [**0**星][2y] [husseinahmed-dev/automated-malware-analysis-in-vr](https://github.com/husseinahmed-dev/automated-malware-analysis-in-vr) 
- [**0**星][3y] [Visual Basic .NET] [kaganisildak/zobajen](https://github.com/kaganisildak/zobajen) deep burial malware project - first section
- [**0**星][12m] [Py] [mohammadnassiri/mama](https://github.com/mohammadnassiri/mama) Multi Agent Malware Analyzer Framework
- [**0**星][12m] [Py] [mohammadnassiri/mama-agent](https://github.com/mohammadnassiri/mama-agent) An agent for MAMA (Multi Agent Malware Analyzer Framework)
- [**0**星][2y] [Makefile] [vukor/docker-maldet](https://github.com/vukor/docker-maldet) This is docker project for check files on malware files using maldet.
- [**0**星][10m] [PS] [0xd3xt3r/analyzed-malware](https://github.com/0xd3xt3r/analyzed-malware) Analyized malware
- [**0**星][4y] [Py] [amit-raut/machinelearningandmalwareclassification](https://github.com/amit-raut/machinelearningandmalwareclassification) ENSuRE Project: Machine Learning and Malware Classification
- [**0**星][3y] [C] [sharpman/izi-locker](https://github.com/sharpman/izi-locker) implementation of crypto-locker malware targeting unix systems


# <a id="5fdcfc70dd87360c2dddcae008076547"></a>Rootkit&&Bootkit


***


## <a id="b8d6f237c04188a10f511cd8988de28a"></a>工具


- [**1527**星][19d] [Py] [zerosum0x0/koadic](https://github.com/zerosum0x0/koadic) 类似于Meterpreter、Powershell Empire 的post-exploitation rootkit，区别在于其大多数操作都是由 Windows 脚本主机 JScript/VBScript 执行
- [**1200**星][10m] [C] [f0rb1dd3n/reptile](https://github.com/f0rb1dd3n/reptile) LKM Linux rootkit
- [**724**星][9m] [C] [mempodippy/vlany](https://github.com/mempodippy/vlany) Linux LD_PRELOAD rootkit (x86 and x86_64 architectures)
- [**587**星][6m] [d30sa1/rootkits-list-download](https://github.com/d30sa1/rootkits-list-download) Rootkit收集
- [**545**星][2y] [Shell] [cloudsec/brootkit](https://github.com/cloudsec/brootkit) Lightweight rootkit implemented by bash shell scripts v0.10
- [**511**星][6m] [C] [nurupo/rootkit](https://github.com/nurupo/rootkit) Linux rootkit，针对 Ubuntu 16.04 及 10.04 (Linux 内核 4.4.0/2.6.32), 支持 i386 和 amd64
- [**501**星][2m] [C] [m0nad/diamorphine](https://github.com/m0nad/diamorphine) 适用于Linux Kernels 2.6.x / 3.x / 4.x（x86和x86_64）的LKM rootkit
- [**441**星][3y] [C] [mncoppola/suterusu](https://github.com/mncoppola/suterusu) An LKM rootkit targeting Linux 2.6/3.x on x86(_64), and ARM
- [**429**星][1y] [C] [novicelive/research-rootkit](https://github.com/novicelive/research-rootkit) LibZeroEvil & the Research Rootkit project.
- [**391**星][2m] [milabs/awesome-linux-rootkits](https://github.com/milabs/awesome-linux-rootkits) awesome-linux-rootkits
- [**378**星][3m] [Shell] [screetsec/vegile](https://github.com/screetsec/vegile) This tool will setting up your backdoor/rootkits when backdoor already setup it will be hidden your spesisifc process,unlimited your session in metasploit and transparent. Even when it killed, it will re-run again. There always be a procces which while run another process,So we can assume that this procces is unstopable like a Ghost in The Shell
- [**371**星][2y] [C] [cr4sh/windowsregistryrootkit](https://github.com/cr4sh/windowsregistryrootkit) Kernel rootkit, that lives inside the Windows registry values data
- [**326**星][2y] [TeX] [ivyl/rootkit](https://github.com/ivyl/rootkit) Sample Rootkit for Linux
- [**284**星][3y] [C] [unix-thrust/beurk](https://github.com/unix-thrust/beurk) BEURK Experimental Unix RootKit
- [**284**星][2y] [Py] [0xislamtaha/python-rootkit](https://github.com/0xIslamTaha/Python-Rootkit) Python Remote Administration Tool (RAT) to gain meterpreter session
- [**264**星][9m] [C] [landhb/hideprocess](https://github.com/landhb/hideprocess) A basic Direct Kernel Object Manipulation rootkit that removes a process from the EPROCESS list, hiding it from the Task Manager
- [**184**星][3y] [Pascal] [bowlofstew/rootkit.com](https://github.com/bowlofstew/rootkit.com) Mirror of users section of rootkit.com
- [**184**星][3y] [CSS] [r00tkillah/horsepill](https://github.com/r00tkillah/horsepill) a PoC of a ramdisk based containerizing root kit
- [**174**星][7m] [C] [ciyze/windows-rootkits](https://github.com/ciyze/Windows-Rootkits) 
- [**164**星][6m] [C] [bytecode77/r77-rootkit](https://github.com/bytecode77/r77-rootkit) Ring 3 Rootkit DLL
- [**155**星][4m] [C] [ajkhoury/uefi-bootkit](https://github.com/ajkhoury/UEFI-Bootkit) A small bootkit which does not rely on x64 assembly.
- [**148**星][9m] [C] [darkabode/zerokit](https://github.com/darkabode/zerokit) Zerokit/GAPZ rootkit (non buildable and only for researching)
- [**143**星][2m] [C] [mak-/mak_it-linux-rootkit](https://github.com/mak-/mak_it-linux-rootkit) This is a linux rootkit using many of the techniques described on
- [**139**星][2y] [C] [eterna1/puszek-rootkit](https://github.com/eterna1/puszek-rootkit) linux rootkit
- [**137**星][7y] [C] [quarkslab/dreamboot](https://github.com/quarkslab/dreamboot) UEFI bootkit
- [**133**星][2y] [C++] [vmcall/latebros](https://github.com/vmcall/latebros) x64 usermode rootkit
- [**131**星][5y] [C++] [slauc91/anticheat](https://github.com/slauc91/anticheat) RootKit & Cheat Scanner - Windows
- [**129**星][8m] [C++] [schnocker/noeye](https://github.com/schnocker/noeye) An usermode BE Rootkit Bypass
- [**117**星][5y] [C] [squiffy/masochist](https://github.com/squiffy/masochist) XNU Rootkit Framework
- [**102**星][4y] [C] [m0n0ph1/win64-rovnix-vbr-bootkit](https://github.com/m0n0ph1/win64-rovnix-vbr-bootkit) Win64/Rovnix - Volume Boot Record Bootkit
- [**97**星][6y] [C] [enzolovesbacon/inficere](https://github.com/enzolovesbacon/inficere) Mac OS X rootkit - for learning purposes
- [**97**星][1y] [Pascal] [fdiskyou/www.rootkit.com](https://github.com/fdiskyou/www.rootkit.com) 
- [**95**星][5y] [C++] [malwaretech/fakembr](https://github.com/malwaretech/fakembr) TDL4 style rootkit to spoof read/write requests to master boot record
- [**94**星][3y] [PS] [fuzzysecurity/capcom-rootkit](https://github.com/fuzzysecurity/capcom-rootkit) Capcom Rootkit POC
- [**93**星][4y] [C] [scumjr/the-sea-watcher](https://github.com/scumjr/the-sea-watcher) Implementation of the SMM rootkit "The Watcher"
- [**87**星][4y] [C] [yaoyumeng/adore-ng](https://github.com/yaoyumeng/adore-ng) linux rootkit adapted for 2.6 and 3.x
- [**86**星][5y] [C] [nyx0/rovnix](https://github.com/nyx0/rovnix) Rovnix Bootkit
- [**80**星][13d] [C] [naworkcaj/bdvl](https://github.com/naworkcaj/bdvl) LD_PRELOAD Linux rootkit (x86 & ARM)
- [**69**星][6y] [C] [kedebug/scdetective](https://github.com/kedebug/scdetective) A kernel level anti-rootkit tool which runs on the windows platform.
- [**66**星][7y] [C] [chokepoint/jynx2](https://github.com/chokepoint/jynx2) JynxKit2 is an LD_PRELOAD userland rootkit based on the original JynxKit. The backdoor has been replaced with an "accept()" system hook.
- [**66**星][2y] [tkmru/awesome-linux-rootkits](https://github.com/tkmru/awesome-linux-rootkits) 
- [**65**星][3y] [C] [quokkalight/rkduck](https://github.com/quokkalight/rkduck) Linux v4.x.x Rootkit
- [**62**星][5y] [C] [jiayy/lkm-rootkit](https://github.com/jiayy/lkm-rootkit) an lkm rootkit support x86/64,arm,mips
- [**62**星][6m] [Py] [thesph1nx/spacecow](https://github.com/thesph1nx/spacecow) Windows Rootkit written in Python
- [**60**星][2y] [C] [croemheld/lkm-rootkit](https://github.com/croemheld/lkm-rootkit) A LKM rootkit for most newer kernel versions.
- [**59**星][9y] [C++] [cr4sh/drvhide-poc](https://github.com/cr4sh/drvhide-poc) Hidden kernel mode code execution for bypassing modern anti-rootkits.
- [**52**星][6y] [C] [dgoulet/kjackal](https://github.com/dgoulet/kjackal) Linux Rootkit Scanner
- [**49**星][3y] [maldevel/rootkits-list-download](https://github.com/maldevel/rootkits-list-download) A curated list of rootkits found on Github and other sites.
- [**49**星][5m] [C] [pinkp4nther/sutekh](https://github.com/pinkp4nther/sutekh) An example rootkit that gives a userland process root permissions
- [**48**星][2y] [C#] [epicrouterss/mssql-fileless-rootkit-warsqlkit](https://github.com/epicrouterss/mssql-fileless-rootkit-warsqlkit) Bildiğiniz üzere uzun zamandır MSSQL üzerine çalışmalar yapmaktayım. Bu yazımda uzun zamandır uğraştığım bir konuyu ele alacağım, MSSQL Rootkit. Bildiğiniz üzere şimdiye kadar MS-SQL için anlatılan post-exploitation işlemlerinin büyük çoğunluğu “xp_cmdshell” ve “sp_OACreate” stored procedure’lerini kullanarak anlatılır. Peki xp_cmdshell ve sp_OA…
- [**47**星][2y] [C] [david-reguera-garcia-dreg/enyelkm](https://github.com/david-reguera-garcia-dreg/enyelkm) LKM rootkit for Linux x86 with the 2.6 kernel. It inserts salts inside system_call and sysenter_entry.
- [**47**星][10m] [Java] [jreframeworker/jreframeworker](https://github.com/jreframeworker/jreframeworker) A practical tool for bytecode manipulation and creating Managed Code Rootkits (MCRs) in the Java Runtime Environment
- [**42**星][3y] [C] [nextsecurity/gozi-mbr-rootkit](https://github.com/nextsecurity/gozi-mbr-rootkit) Gozi-MBR-rootkit Bootkit Modified
- [**41**星][5y] [Py] [bones-codes/the_colonel](https://github.com/bones-codes/the_colonel) an experimental linux kernel module (rootkit) with a keylogger and built-in IRC bot
- [**40**星][C] [d1w0u/arp-rootkit](https://github.com/d1w0u/arp-rootkit) An open source rootkit for the Linux Kernel to develop new ways of infection/detection.
- [**40**星][2y] [C] [david-reguera-garcia-dreg/lsrootkit](https://github.com/david-reguera-garcia-dreg/lsrootkit) Rootkit Detector for UNIX
- [**39**星][3y] [C++] [zibility/anti-rootkits](https://github.com/zibility/anti-rootkits) 内核级ARK工具。
- [**36**星][3y] [C] [nexusbots/umbreon-rootkit](https://github.com/nexusbots/umbreon-rootkit) 
- [**34**星][7y] [C] [chokepoint/jynxkit](https://github.com/chokepoint/jynxkit) JynxKit is an LD_PRELOAD userland rootkit for Linux systems with reverse connection SSL backdoor
- [**34**星][5y] [osiris123/cdriver_loader](https://github.com/osiris123/cdriver_loader) Kernel mode driver loader, injecting into the windows kernel, Rootkit. Driver injections.
- [**33**星][9y] [C] [falk3n/subversive](https://github.com/falk3n/subversive) x86_64 linux rootkit using debug registers
- [**32**星][6y] [Shell] [installation/rkhunter](https://github.com/installation/rkhunter) Rootkit Hunter install script
- [**32**星][8y] [C] [swatkat/arkitlib](https://github.com/swatkat/arkitlib) Windows anti-rootkit library
- [**32**星][6y] [sin5678/a-protect](https://github.com/sin5678/A-Protect) A-Protect Anti Rootkit Tool
- [**31**星][7m] [C] [alex91ar/diamorphine](https://github.com/alex91ar/diamorphine) LKM rootkit for Linux Kernels 2.6.x/3.x/4.x
- [**31**星][5y] [C] [christianpapathanasiou/apache-rootkit](https://github.com/christianpapathanasiou/apache-rootkit) A malicious Apache module with rootkit functionality
- [**31**星][6m] [C] [pentesteracademy/linux-rootkits-red-blue-teams](https://github.com/pentesteracademy/linux-rootkits-red-blue-teams) Linux Rootkits (4.x Kernel)
- [**28**星][4y] [C] [a7vinx/liinux](https://github.com/a7vinx/liinux) A linux rootkit works on kernel 4.0.X or higher
- [**28**星][2y] [C++] [nervous/greenkit-rootkit](https://github.com/nervous/greenkit-rootkit) GreenKit is an userland rootkit hiding its own files and mining bitcoins on compromised computers. Do /NOT/ download or use this rootkit for malicious purposes. Use it only for your own knowledge.
- [**28**星][5y] [C] [qianshanhai/q-shell](https://github.com/qianshanhai/q-shell) Unix remote login tool, rootkit shell tool
- [**27**星][1y] [C] [alex9191/zerobank-ring0-bundle](https://github.com/alex9191/zerobank-ring0-bundle) Kernel-Mode rootkit that connects to a remote server to send & recv commands
- [**26**星][6y] [C] [kacheo/kernelrootkit](https://github.com/kacheo/kernelrootkit) Linux kernel rootkit to hide certain files and processes.
- [**26**星][3y] [Assembly] [cduplooy/rootkit](https://github.com/CDuPlooy/Rootkit) 
- [**25**星][4y] [C] [hanj4096/wukong](https://github.com/hanj4096/wukong) A LKM rootkit for Linux kernel 2.6.x, 3.x and 4.x
- [**25**星][6y] [C] [varshapaidi/kernel_rootkit](https://github.com/varshapaidi/kernel_rootkit) Linux Kernel Rootkit - To hide modules and ssh service
- [**24**星][3y] [Assembly] [rehints/bootkitsbook](https://github.com/rehints/bootkitsbook) repository with additional materials and source code
- [**22**星][5y] [C] [citypw/suterusu](https://github.com/citypw/suterusu) An LKM rootkit targeting Linux 2.6/3.x on x86(_64), and ARM
- [**22**星][3y] [C] [josephjkong/designing-bsd-rootkits](https://github.com/josephjkong/designing-bsd-rootkits) Code from the book "Designing BSD Rootkits: An Introduction to Kernel Hacking"
- [**22**星][3y] [C] [jianpingzju/hypro](https://github.com/jianpingzju/Hypro) VMI on BitVisor to detect hidden rootkits.
- [**21**星][3y] [C++] [apriorit/antirootkit-anti-splicer](https://github.com/apriorit/antirootkit-anti-splicer) The project is a demo solution for one of the anti-rootkit techniques aimed on overcoming splicers
- [**21**星][7y] [C] [dsmatter/brootus](https://github.com/dsmatter/brootus) An educational Linux Kernel Rootkit
- [**20**星][6y] [C++] [antirootkit/bdarkit](https://github.com/antirootkit/bdarkit) just an lite AntiRootkit for interesting
- [**20**星][11m] [C] [blacchat/rkorova](https://github.com/blacchat/rkorova) ld_preload userland rootkit
- [**19**星][5y] [C] [elfmaster/kprobe_rootkit](https://github.com/elfmaster/kprobe_rootkit) Linux kernel rootkit using kprobes (From
- [**19**星][7y] [C] [nnewson/km](https://github.com/nnewson/km) Rootkit tutorial code for the Beneath C Level blog -
- [**19**星][9m] [C++] [mstefanowich/squiddlydiddly](https://github.com/mstefanowich/SquiddlyDiddly) PoC RootKit in the works: SquiddlyDiddly
- [**18**星][5y] [C++] [gdbinit/diagnostic_service](https://github.com/gdbinit/diagnostic_service) OS X rootkit loader version #1
- [**18**星][4y] [C++] [karol-gruszczyk/win-rootkit](https://github.com/karol-gruszczyk/win-rootkit) 
- [**18**星][3y] [C] [w4rh4wk/thor](https://github.com/W4RH4WK/THOR) The Horrific Omnipotent Rootkit
- [**17**星][5y] [Assembly] [ahixon/booty](https://github.com/ahixon/booty) Bootkit for Windows 7
- [**17**星][5m] [reddrip7/usb-bootkit](https://github.com/reddrip7/usb-bootkit) 
- [**17**星][4y] [zhuyue1314/stoned-uefi-bootkit](https://github.com/zhuyue1314/stoned-uefi-bootkit) 
- [**16**星][2y] [C] [aearnus/syscall-rootkit](https://github.com/aearnus/syscall-rootkit) Just a proof of concept Linux rootkit that reads from syscalls.
- [**16**星][6y] [cccssw/jynkbeast](https://github.com/cccssw/jynkbeast) A novel rootkit under linux(test under cents 5.4) combine with preload_inject and sys_table modify
- [**16**星][5y] [Py] [ninnogtonic/out-of-sight-out-of-mind-rootkit](https://github.com/ninnogtonic/out-of-sight-out-of-mind-rootkit) Rootkit
- [**16**星][5y] [C] [rvillordo/libpreload](https://github.com/rvillordo/libpreload) LD_PRELOAD rootkit
- [**15**星][6y] [C] [mak-/keylogger-lkm](https://github.com/mak-/keylogger-lkm) This is a very simple Keylogger, it doesn't hide itself and is a college project building towards developing a rootkit.
- [**15**星][5y] [C] [ring-1/zendar](https://github.com/ring-1/zendar) Zendar is a Linux rootkit based off of the LD_PRELOAD method used by Azazel and Jynx alike
- [**15**星][2m] [JS] [buffermet/sewers](https://github.com/buffermet/sewers) Modular rootkit framework
- [**14**星][6y] [C] [ah450/rootkit](https://github.com/ah450/rootkit) A rootkit for linux kernel >= 3.0
- [**14**星][4y] [C++] [bhassani/alina](https://github.com/bhassani/alina) Alina POS Source Code + Rootkit
- [**14**星][4y] [C] [vrasneur/randkit](https://github.com/vrasneur/randkit) Random number rootkit for the Linux kernel
- [**13**星][2y] [Go] [cblack-r7/coal](https://github.com/cblack-r7/coal) Haxmas-2017 LD_PRELOAD rootkit in Golang
- [**13**星][6m] [HTML] [fdiskyou/rootkitarsenal](https://github.com/fdiskyou/rootkitarsenal) Rootkit Arsenal Book Code Samples
- [**13**星][4y] [C] [nnedkov/swiss_army_rootkit](https://github.com/nnedkov/swiss_army_rootkit) 
- [**13**星][5y] [C] [schischi/slrk](https://github.com/schischi/slrk) Linux rootkit experimentations
- [**12**星][3y] [C] [arciryas/rootkit-sample-code](https://github.com/arciryas/rootkit-sample-code) rootkit sample code of my tutorials on Freebuf.com
- [**12**星][1y] [Py] [evgind/lojax_uefi_rootkit_checker](https://github.com/evgind/lojax_uefi_rootkit_checker) lojax_uefi_rootkit_checker
- [**12**星][3y] [C] [miagilepner/porny](https://github.com/miagilepner/porny) A Unix rootkit
- [**12**星][4y] [TeX] [soad003/rootkit](https://github.com/soad003/rootkit) 
- [**11**星][6y] [Py] [amanone/amark](https://github.com/amanone/amark) lkm rootkit
- [**11**星][5y] [C++] [gdbinit/diagnostic_service2](https://github.com/gdbinit/diagnostic_service2) OS X rootkit loader version #2
- [**11**星][7y] [C] [joshimhoff/toykit](https://github.com/joshimhoff/toykit) A toy Linux rootkit.
- [**11**星][7y] [C] [uzyszkodnik/rootkit](https://github.com/uzyszkodnik/rootkit) simple rootkit for computer security class
- [**11**星][4y] [C] [aidielse/rootkits-playground](https://github.com/aidielse/Rootkits-Playground) fun rootkits stuff!
- [**10**星][3y] [C] [asuar078/raisin](https://github.com/asuar078/raisin) Reverse shell and rootkit
- [**10**星][5y] [C] [kevinkoo001/rootkit](https://github.com/kevinkoo001/rootkit) This project has been done with Chen as part of system security course at SBU CS.
- [**10**星][3y] [C] [t0t3m/afkit](https://github.com/t0t3m/afkit) Anti live forensic linux LKM rootkit
- [**9**星][3y] [C] [matteomattia/moo_rootkit](https://github.com/matteomattia/moo_rootkit) it's a simple LKM rootkit.
- [**9**星][3y] [C] [rbertin/basic-rootkit](https://github.com/rbertin/basic-rootkit) just a basic rootkit for learning how to playing sys_call_table
- [**8**星][1y] [C] [fereh/tacekit](https://github.com/fereh/tacekit) A user mode rootkit research project
- [**8**星][8m] [C] [naworkcaj/betrayed](https://github.com/naworkcaj/betrayed) IRC-controlled LD_PRELOAD Linux rootkit
- [**8**星][9m] [0xd3xt3r/awesome-windows-rootkits](https://github.com/0xd3xt3r/awesome-windows-rootkits) Collection of windows rootkits
- [**7**星][2y] [C] [deviceobject/changedisksector](https://github.com/deviceobject/changedisksector) Debug Bootkit Tool Source
- [**7**星][7y] [C] [dluengo/yarr](https://github.com/dluengo/yarr) Yet Another Repetitive Rootkit
- [**7**星][5y] [C] [m0hamed/lkm-rootkit](https://github.com/m0hamed/lkm-rootkit) A rootkit implemented as a linux kernel module
- [**7**星][2y] [C++] [sisoma2/rootkithashcracker](https://github.com/sisoma2/rootkithashcracker) A little code to crack some hashes found in the HackAV Rootkit
- [**6**星][2y] [C] [cocoahuke/rootkitdev_genheaders](https://github.com/cocoahuke/rootkitdev_genheaders) Build your own complete XNU kernel header set, replaces Kernel.framework. Gain access to kernel private structures and symbols etc with IDE indexing worked.
- [**6**星][2y] [C] [en14c/lilyofthevalley](https://github.com/en14c/lilyofthevalley) Simple LKM linux kernel rootkit (x86 / x86_64)
- [**6**星][2y] [Ruby] [evanilla/ruby-rootkit](https://github.com/evanilla/ruby-rootkit) a simple ruby reverse shell or rootkit
- [**6**星][8m] [C] [jermeyyy/rooty](https://github.com/jermeyyy/rooty) Academic project of Linux rootkit made for Bachelor Engineering Thesis.
- [**6**星][2y] [Py] [mhaskar/linux-root-kit](https://github.com/mhaskar/linux-root-kit) Simple Linux RootKit written in python
- [**4**星][6y] [Java] [hagurekamome/rootkitapp](https://github.com/hagurekamome/rootkitapp) 
- [**4**星][4m] [C] [jtalowell/rootkit](https://github.com/jtalowell/rootkit) A rootkit for FreeBSD 12.0-RELEASE
- [**4**星][1y] [C++] [ntosguy/xenofox](https://github.com/ntosguy/xenofox) XenoFox is a x86 rootkit for Windows operating systems (not finished, fun project)
- [**3**星][3y] [Shell] [codingplanets/easykit](https://github.com/codingplanets/easykit) Rootkit developed via Shell
- [**2**星][3m] [emmaunel/rootkit](https://github.com/emmaunel/rootkit) A Simple rootkit
- [**2**星][6m] [etadata/nordo](https://github.com/etadata/nordo) security stuff, #crypto #rootkit #security
- [**2**星][2y] [C] [jaimelopez/notmyfather-php-rootkit](https://github.com/jaimelopez/notmyfather-php-rootkit) NotMyFather is a PHP extension rootkit PoC
- [**2**星][2y] [C] [pratik32/linux_rkit](https://github.com/pratik32/linux_rkit) A rootkit for linux kernel 4.x+
- [**1**星][2y] [Shell] [aishee/bdeath](https://github.com/aishee/bdeath) The black death backdoor/rootkits
- [**1**星][2y] [C] [cyanitol/reptile](https://github.com/cyanitol/reptile) LKM Linux rootkit
- [**1**星][2y] [Py] [guestguri/rootkit](https://github.com/guestguri/rootkit) This is a quick and dirty rootkit implementation with Python
- [**1**星][10m] [C] [ilee38/root-of-all-evil](https://github.com/ilee38/root-of-all-evil) Kernel-level rootkit to test in Docker Containers
- [**1**星][4y] [C] [richardkavanagh/kernel-dev](https://github.com/richardkavanagh/kernel-dev) A simple linux rootkit(please don't try and use it it's bad)
- [**1**星][C] [zeta314/lkm-rootkit](https://github.com/zeta314/lkm-rootkit) LKM Rootkit
- [**1**星][1m] [Py] [mdenzel/acpi-rootkit-scan](https://github.com/mdenzel/acpi-rootkit-scan) volatility plugin to detect ACPI rootkits
- [**0**星][6y] [fernetmatt/web-rootkit](https://github.com/fernetmatt/web-rootkit) a collection of shell rootkits capable to run on a web server


***


## <a id="8645e29263f0886344127d352ebd6884"></a>文章


- 2019.12 [freebuf] [AntiSpy：一款功能强大的反病毒&反Rootkit免费工具套件](https://www.freebuf.com/articles/system/221820.html)
- 2019.12 [jm33] [Linux Rootkit for Fun and Profit - 0x03 - LKM - Hide from ss/netstat](https://jm33.me/linux-rootkit-for-fun-and-profit-0x03-lkm-hide-from-ssnetstat.html)
- 2019.12 [jm33] [Linux Rootkit for Fun and Profit - 0x02 - LKM - Hide files/procs](https://jm33.me/linux-rootkit-for-fun-and-profit-0x02-lkm-hide-filesprocs.html)
- 2019.12 [jm33] [Linux Rootkit for Fun and Profit - 0x02 - LKM](https://jm33.me/linux-rootkit-for-fun-and-profit-0x02-lkm.html)
- 2019.12 [jm33] [Linux Rootkit for Fun and Profit - 0x01 - LKM](https://jm33.me/linux-rootkit-for-fun-and-profit-0x01-lkm.html)
- 2019.12 [jm33] [Linux Rootkit for Fun and Profit - 0x00 - Design](https://jm33.me/linux-rootkit-for-fun-and-profit-0x00-design.html)
- 2019.11 [hakin9] [Antispy - A Free But Powerful Anti Virus And Rootkits Toolkit](https://hakin9.org/antispy-a-free-but-powerful-anti-virus-and-rootkits-toolkit/)
- 2019.10 [HackersOnBoard] [Black Hat USA 2016 Horse Pill A New Type of Linux Rootkit](https://www.youtube.com/watch?v=RcYcJarMVWI)
- 2019.10 [Kaspersky] [Rootkit Detection and Removal](https://www.youtube.com/watch?v=goyiuyA-Ckw)
- 2019.09 [infosecinstitute] [Malware: What are rootkits?](https://resources.infosecinstitute.com/malware-what-are-rootkits/)
- 2019.09 [trendmicro] [Skidmap Linux Malware Uses Rootkit Capabilities to Hide Cryptocurrency-Mining Payload](https://blog.trendmicro.com/trendlabs-security-intelligence/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload/)
- 2019.08 [KindredSecurity] [Live Malware Analysis | Checking out a User-land Rootkit](https://www.youtube.com/watch?v=FvYjM8eZ7Ck)
- 2019.06 [aliyun] [威胁快报|挖矿团伙8220进化，rootkit挖矿趋势兴起](https://xz.aliyun.com/t/5482)
- 2019.06 [4hou] [威胁快报 | 挖矿团伙8220进化，rootkit挖矿趋势兴起](https://www.4hou.com/system/18409.html)
- 2019.05 [4hou] [使用Rootkit实现恶意挖矿：CVE-2019-3396漏洞新型恶意利用方式分析](https://www.4hou.com/vulnerable/17918.html)
- 2019.05 [trendmicro] [CVE-2019-3396 Redux: Confluence Vulnerability Exploited to Deliver Cryptocurrency Miner With Rootkit](https://blog.trendmicro.com/trendlabs-security-intelligence/cve-2019-3396-redux-confluence-vulnerability-exploited-to-deliver-cryptocurrency-miner-with-rootkit/)
- 2019.04 [h2hconference] [Linux Kernel Rootkits - Matveychikov & f0rb1dd3n - H2HC 2018](https://www.youtube.com/watch?v=8_0_FT-rKfw)
- 2019.04 [mediacccde] [Easterhegg 2019 - Anatomie eines containerfähigen Linux-Kernel-Rootkits](https://www.youtube.com/watch?v=4sPAYgR29E4)
- 2019.04 [freebuf] [BUF早餐铺 | Scranos rootkit从中国扩散到全世界；厄瓜多尔政府和机构网站遭到4千万次攻击；国家网信办启动小众即时通信工具专项整治](https://www.freebuf.com/news/201305.html)
- 2019.01 [fuzzysecurity] [Capcom Rootkit Proof-Of-Concept](http://fuzzysecurity.com/tutorials/28.html)
- 2018.12 [n0where] [Kernel-Mode Rootkit Hunter: Tyton](https://n0where.net/kernel-mode-rootkit-hunter-tyton)
- 2018.11 [aliyun] [加密货币挖矿恶意软件使用rootkit隐藏自己](https://xz.aliyun.com/t/3237)
- 2018.11 [aliyun] [RootkitXSS之ServiceWorker](https://xz.aliyun.com/t/3228)
- 2018.11 [topsec] [Linux下的Rootkit驻留技术分析](http://blog.topsec.com.cn/linux%e4%b8%8b%e7%9a%84rootkit%e9%a9%bb%e7%95%99%e6%8a%80%e6%9c%af%e5%88%86%e6%9e%90/)
- 2018.11 [topsec] [Linux下的Rootkit驻留技术分析](http://blog.topsec.com.cn/archives/3632)
- 2018.11 [topsec] [Linux下的Rootkit驻留技术分析](http://blog.topsec.com.cn/linux%e4%b8%8b%e7%9a%84rootkit%e9%a9%bb%e7%95%99%e6%8a%80%e6%9c%af%e5%88%86%e6%9e%90/)
- 2018.11 [topsec] [Linux下的Rootkit驻留技术分析](http://blog.topsec.com.cn/ad_lab/linux%e4%b8%8b%e7%9a%84rootkit%e9%a9%bb%e7%95%99%e6%8a%80%e6%9c%af%e5%88%86%e6%9e%90/)
- 2018.11 [freebuf] [Linux下的Rootkit驻留技术分析](https://www.freebuf.com/articles/system/188211.html)
- 2018.11 [topsec] [Linux下的Rootkit驻留技术分析](http://blog.topsec.com.cn/2018/11/linux%e4%b8%8b%e7%9a%84rootkit%e9%a9%bb%e7%95%99%e6%8a%80%e6%9c%af%e5%88%86%e6%9e%90/)
- 2018.11 [topsec] [Linux下的Rootkit驻留技术分析](http://blog.topsec.com.cn/?p=3632)
- 2018.11 [aliyun] [PHP extension rootkit](https://xz.aliyun.com/t/3126)
- 2018.11 [jm33] [Write Better Linux Rootkits](https://jm33.me/write-better-linux-rootkits.html)
- 2018.10 [andreafortuna] [Some thoughts about Windows Userland Rootkits](https://www.andreafortuna.org/dfir/malware-analysis/some-thoughts-about-windows-userland-rootkits/)
- 2018.10 [comodo] [Uh Oh – UEFI rootkit malware spotted in the wild](https://blog.comodo.com/uh-oh-uefi-rootkit-malware-spotted-in-the-wild/)
- 2018.10 [comodo] [Uh Oh – UEFI rootkit malware spotted in the wild](https://blog.comodo.com/comodo-news/uh-oh-uefi-rootkit-malware-spotted-in-the-wild/)
- 2018.10 [hispasec] [Nace LoJax, primer rootkit a nivel de UEFI](https://unaaldia.hispasec.com/2018/10/nace-lojax-primer-rootkit-nivel-de-uefi.html)
- 2018.09 [4hou] [俄罗斯Sednit APT首次在野使用UEFI rootkit——LoJax](http://www.4hou.com/web/13841.html)
- 2018.09 [welivesecurity] [LoJax: First UEFI rootkit found in the wild, courtesy of the Sednit group](https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/)
- 2018.08 [aliyun] [CeidPageLock：中国RootKit分析](https://xz.aliyun.com/t/2674)
- 2018.08 [checkpoint] [CeidPageLock: A Chinese RootKit - Check Point Research](https://research.checkpoint.com/ceidpagelock-a-chinese-rootkit/)
- 2018.08 [pediy] [[翻译]内核模式Rootkits：文件删除保护](https://bbs.pediy.com/thread-246378.htm)
- 2018.08 [freebuf] [新Underminer EK使用加密TCP隧道交付Bootkit和挖矿软件](http://www.freebuf.com/news/178974.html)
- 2018.08 [freebuf] [贪狼Rootkit僵尸家族再度活跃：挖矿+DDOS+劫持+暗刷](http://www.freebuf.com/articles/paper/178927.html)
- 2018.07 [4hou] [Underminer通过加密的TCP隧道提供Bootkit以及挖矿恶意软件](http://www.4hou.com/web/12829.html)
- 2018.07 [360] [BootKit, one of the most annoying Trojan, is ready for the next global outbreak](https://blog.360totalsecurity.com/en/bootkit-one-of-the-most-annoying-trojan-is-ready-for-the-next-global-outbreak/)
- 2018.07 [trendmicro] [New Underminer Exploit Kit Delivers Bootkit and Cryptocurrency-mining Malware with Encrypted TCP Tunnel](https://blog.trendmicro.com/trendlabs-security-intelligence/new-underminer-exploit-kit-delivers-bootkit-and-cryptocurrency-mining-malware-with-encrypted-tcp-tunnel/)
- 2018.07 [4hou] [如何利用Rootkit实现文件删除保护](http://www.4hou.com/technology/12714.html)
- 2018.06 [freebuf] [“隐蜂”来袭：金山毒霸截获全球首例Bootkit级挖矿僵尸网络  (下篇)](http://www.freebuf.com/articles/system/174575.html)
- 2018.05 [freebuf] [“隐蜂”来袭：金山毒霸截获全球首例Bootkit级挖矿僵尸网络（上篇）](http://www.freebuf.com/articles/network/173400.html)
- 2018.05 [360] [挖矿程序ScheduledUpdateMiner使用Rootkit关闭杀软, 躲避检测](https://blog.360totalsecurity.com/en/cryptominer-scheduledupdateminer-uses-rootkit-terminate-antivirus-avoid-detection/)
- 2018.04 [OffensiveCon] [OffensiveCon18 -  Alex Ionescu - Advancing the State of UEFI Bootkits](https://www.youtube.com/watch?v=dpG97TBR3Ys)
- 2018.04 [freebuf] [静态分析一款锁首的RootKit样本](http://www.freebuf.com/articles/system/168650.html)
- 2018.04 [pediy] [[原创]---RootKit 核心技术—系统服务调度表挂钩调试（PART III）---](https://bbs.pediy.com/thread-226215.htm)
- 2018.04 [pediy] [[原创]---RootKit 核心技术——利用 NT!_MDL 突破 KiServiceTable 的只读访问限制 PART II ----](https://bbs.pediy.com/thread-226043.htm)
- 2018.04 [pediy] [[原创]ROOTKIT 核心技术——利用 NT!_MDL（内存描述符链表）突破 SSDT（系统服务描述符表）的只读访问限制 PART I](https://bbs.pediy.com/thread-225998.htm)
- 2018.04 [checkpoint] [Return of the Festi Rootkit](https://research.checkpoint.com/return-festi-rootkit/)
- 2018.02 [HackerSploit] [How To Detect Rootkits On Kali Linux - chkrootkit & rkhunter](https://www.youtube.com/watch?v=sFOKz_fd0SA)
- 2017.09 [qq] [从Angelfire文档曝光，看Bootkit木马的持续威胁](https://tav.qq.com/index/newsDetail/300.html)
- 2017.09 [kaspersky] [Quiz: Bootkit or dropper?](https://www.kaspersky.com/blog/security-terms-quiz/19567/)
- 2017.08 [asset] [Book Review: Rootkits and Bootkits: Reversing Modern Malware and Next Generation Threats](http://blog.asset-intertech.com/test_data_out/2017/08/book-review-rootkits-and-bootkits-reversing-modern-malware-and-next-generation-threats.html)
- 2017.08 [freebuf] [CNCERT关于异鬼II Bootkit病毒有关情况的预警通报](http://www.freebuf.com/news/142402.html)
- 2017.07 [qq] [“异鬼Ⅱ”Bootkit木马详细分析](https://tav.qq.com/index/newsDetail/288.html)
- 2017.07 [pediy] [[原创]“异鬼Ⅱ”Bootkit木马详细分析](https://bbs.pediy.com/thread-219751.htm)
- 2017.07 [freebuf] [“异鬼Ⅱ”Bootkit木马详细分析](http://www.freebuf.com/articles/web/141633.html)
- 2017.06 [freebuf] [暗云Ⅲ BootKit 木马分析](http://www.freebuf.com/articles/system/134017.html)
- 2017.05 [qq] [暗云Ⅲ BootKit 木马分析](https://tav.qq.com/index/newsDetail/265.html)
- 2016.08 [qq] [BootKit成“异鬼”：通过感染VBR绕过杀软](https://tav.qq.com/index/newsDetail/255.html)
- 2016.07 [qq] [暗云Ⅱ  BootKit 木马分析](https://tav.qq.com/index/newsDetail/249.html)
- 2016.07 [freebuf] [暗云ⅡBootKit木马分析](http://www.freebuf.com/articles/system/109096.html)
- 2016.06 [cybrary] [Tradecraft Tuesday – HDRoot Bootkit](https://www.cybrary.it/2016/06/tradecraft-tuesday-hdroot-bootkit-analysis/)
- 2016.06 [rootedconmadrid] [Abel Valero - Windows BootKits: Como analizar malware persistente en MBR/VBR [RootedCON 2016 - ESP]](https://www.youtube.com/watch?v=cnHmOw1Q6SI)
- 2016.06 [rootedconmadrid] [Abel Valero - Windows BootKits: Como analizar malware persistente en MBR/VBR [RootedCON 2016 - ENG]](https://www.youtube.com/watch?v=FTE-7CHaAbM)
- 2016.05 [williamshowalter] [A Universal Windows Bootkit](http://williamshowalter.com/a-universal-windows-bootkit/)
- 2015.09 [darknet] [VBootkit Bypasses Vista’s Digital Code Signing](https://www.darknet.org.uk/2007/06/vbootkit-bypasses-vistas-digital-code-signing/)
- 2015.09 [darknet] [Stoned Bootkit – Windows XP, 2003, Vista, 7 MBR Rootkit](https://www.darknet.org.uk/2009/08/stoned-bootkit-windows-xp-2003-vista-7-mbr-rootkit/)
- 2015.06 [malwaretech] [MalwareTech SBK – A Bootkit Capable of Surviving Reformat](https://www.malwaretech.com/2015/06/hard-disk-firmware-rootkit-surviving.html)
- 2015.03 [malwaretech] [Bootkit Disk Forensics – Part 3](https://www.malwaretech.com/2015/03/bootkit-disk-forensics-part-3.html)
- 2015.03 [malwaretech] [Bootkit Disk Forensics – Part 2](https://www.malwaretech.com/2015/03/bootkit-disk-forensics-part-2.html)
- 2015.02 [malwaretech] [Bootkit Disk Forensics – Part 1](https://www.malwaretech.com/2015/02/bootkit-disk-forensics-part-1.html)
- 2015.02 [freebuf] [如何清除Bootkit木马后门](http://www.freebuf.com/sectool/58631.html)
- 2015.01 [qq] [“暗云”BootKit木马](https://tav.qq.com/index/newsDetail/221.html)
- 2015.01 [freebuf] [“暗云”BootKit木马详细技术分析](http://www.freebuf.com/vuls/57868.html)
- 2015.01 [kaspersky] [What You Should Know About the Thunderstrike Mac Bootkit](https://www.kaspersky.com/blog/thunderstrike-mac-osx-bootkit/7164/)
- 2014.11 [virusbulletin] [VB2014 paper: Bootkits: past, present & future](https://www.virusbulletin.com/blog/2014/11/paper-bootkits-past-present-amp-future/)
- 2014.10 [securityintelligence] [Analysis of FinFisher Bootkit](https://securityintelligence.com/analysis-of-finfisher-bootkit/)
- 2014.09 [welivesecurity] [Bootkits, Windigo, and Virus Bulletin](https://www.welivesecurity.com/2014/09/30/bootkits-windigo-virus-bulletin/)
- 2014.07 [securityintelligence] [Bootkits: Deep Dive Into Persistence Mechanisms Used by Bootkits at HOPE X Conference](https://securityintelligence.com/bootkits-deep-dive-into-persistence-mechanisms-used-by-bootkits-at-hope-x-conference/)
- 2014.03 [] [Oldboot.B：与Bootkit技术结合的木马隐藏手段的运用](http://blogs.360.cn/blog/analysis_of_oldboot_b/)
- 2014.01 [pediy] [[原创]新年礼物（bootkits）](https://bbs.pediy.com/thread-184159.htm)
- 2014.01 [checkpoint] [OldBoot: A New Bootkit for Android | Check Point Software Blog](https://blog.checkpoint.com/2014/01/29/oldboot-a-new-bootkit-for-android/)
- 2014.01 [] [Oldboot.B：与Bootkit技术结合的木马隐藏手段的运用](http://blogs.360.cn/post/analysis_of_oldboot_b.html)
- 2014.01 [] [Oldboot：Android平台的第一个bootkit](http://blogs.360.cn/post/oldboot-the-first-bootkit-on-android_cn.html)
- 2014.01 [] [Oldboot: the first bootkit on Android](http://blogs.360.cn/post/oldboot-the-first-bootkit-on-android.html)
- 2014.01 [] [Oldboot.B: the hiding tricks used by bootkit on Android](http://blogs.360.cn/post/analysis_of_oldboot_b_en.html)
- 2013.12 [pediy] [[原创]Carberp Bootkit源码解析](https://bbs.pediy.com/thread-182627.htm)
- 2013.06 [bromium] [Musings from the bootkit underworld](https://blogs.bromium.com/musings-from-the-bootkit-underworld/)
- 2013.06 [securityintelligence] [Carberp Source Code for Sale — Free Bootkit Included!](https://securityintelligence.com/carberp-source-code-sale-free-bootkit-included/)
- 2013.05 [reversinglabs] [Black Hat 2013 Showcases Home Security, Bootkits, Cellular OPSEC Failures](https://www.reversinglabs.com/newsroom/news/black-hat-2013-showcases-home-security-bootkits-cellular-opsec-failures.html)
- 2013.04 [webroot] [A peek inside the ‘Zerokit/0kit/ring0 bundle’ bootkit](https://www.webroot.com/blog/2013/04/08/a-peek-inside-the-zerokit0kitring0-bundle-bootkit/)
- 2013.04 [welivesecurity] [Is Gapz the most complex bootkit yet?](https://www.welivesecurity.com/2013/04/08/is-gapz-the-most-complex-bootkit-yet/)


# <a id="069468057aac03c102abdbeb7a5decf6"></a>硬件


***


## <a id="3574d46dd09566f898b407cebe9df29b"></a>固件


### <a id="649d2aece91551af8b48d29f52943804"></a>Firmware&&固件


- [**6213**星][6m] [rmerl/asuswrt-merlin](https://github.com/rmerl/asuswrt-merlin) Enhanced version of Asus's router firmware (Asuswrt) (legacy code base)
- [**3772**星][5d] [C] [atmosphere-nx/atmosphere](https://github.com/atmosphere-nx/atmosphere) Atmosphère is a work-in-progress customized firmware for the Nintendo Switch.
- [**3247**星][] [C] [betaflight/betaflight](https://github.com/betaflight/betaflight) Open Source Flight Controller Firmware
- [**3166**星][6d] [C++] [px4/firmware](https://github.com/px4/firmware) PX4 Autopilot Software
- [**2834**星][18d] [C] [tmk/tmk_keyboard](https://github.com/tmk/tmk_keyboard) Atmel AVR 和 Cortex-M键盘固件收集
- [**2282**星][2m] [C] [aurorawright/luma3ds](https://github.com/aurorawright/luma3ds) Noob-proof (N)3DS "Custom Firmware"
- [**1473**星][2d] [C] [tianocore/edk2](https://github.com/tianocore/edk2) A modern, feature-rich, cross-platform firmware development environment for the UEFI and PI specifications
- [**797**星][5d] [C] [fwupd/fwupd](https://github.com/fwupd/fwupd) A simple daemon to allow session software to update firmware
- [**634**星][6m] [C] [travisgoodspeed/md380tools](https://github.com/travisgoodspeed/md380tools) Python tools and patched firmware for the TYT-MD380
- [**421**星][5m] [preos-security/awesome-firmware-security](https://github.com/preos-security/awesome-firmware-security) Awesome Firmware Security & Other Helpful Documents
- [**381**星][3d] [Py] [fkie-cad/fact_core](https://github.com/fkie-cad/fact_core) Firmware Analysis and Comparison Tool
- [**294**星][5m] [C++] [rampagex/firmware-mod-kit](https://github.com/rampagex/firmware-mod-kit) Automatically exported from code.google.com/p/firmware-mod-kit
- [**281**星][2m] [Py] [pspreverse/psptool](https://github.com/PSPReverse/psptool) Display, extract, and manipulate PSP firmware inside UEFI images
- [**243**星][10d] [Py] [avatartwo/avatar2](https://github.com/avatartwo/avatar2) targetorchestration 框架，重点是嵌入式设备固件的动态分析
- [**238**星][4y] [C] [jethrogb/uefireverse](https://github.com/jethrogb/uefireverse) Tools to help with Reverse Engineering UEFI-based firmware
- [**234**星][12m] [C] [reisyukaku/reinand](https://github.com/reisyukaku/reinand) Minimalist 3DS custom firmware.
- [**193**星][12m] [Py] [scanlime/coastermelt](https://github.com/scanlime/coastermelt) An effort to make open source firmware for burning anything other than Blu-Ray data onto plastic discs with a BD-R drive.
- [**168**星][4y] [C] [silver13/h8mini-acro](https://github.com/silver13/h8mini-acro) acro firmware for eachine H8 mini
- [**160**星][8y] [C] [poelzi/openchronos](https://github.com/poelzi/openchronos)  Open Source Firmware for the TI EZ430-Chronos Watch
- [**149**星][1y] [C] [theofficialflow/update365](https://github.com/theofficialflow/update365) Custom Firmware 3.65 HENkaku Ensō Updater for PS Vita
- [**121**星][4d] [Shell] [therealsaumil/armx](https://github.com/therealsaumil/armx) ARM-X Firmware Emulation Framework
- [**86**星][3y] [advanced-threat-research/efi-whitelist](https://github.com/advanced-threat-research/efi-whitelist) 一堆EFI 可执行文件的信息（Json格式），文件来自于供应商网站的(U)EFI固件更新镜像，信息包括Hash、GUID、名称、类型。
- [**77**星][17d] [C] [open-power/skiboot](https://github.com/open-power/skiboot) OPAL boot and runtime firmware for POWER
- [**73**星][3y] [C++] [avatarone/avatar-python](https://github.com/avatarone/avatar-python) Dynamic security analysis of embedded systems’ firmwares
- [**66**星][1m] [Assembly] [hardenedlinux/firmware-anatomy](https://github.com/hardenedlinux/firmware-anatomy) Tear the firmware apart with your bare hands;-)
- [**63**星][3y] [C] [seemoo-lab/bcm-public](https://github.com/seemoo-lab/bcm-public) DEPRECATED: Monitor Mode and Firmware patching framework for the Google Nexus 5, development moved to:
- [**60**星][2y] [C] [samuelpowell/cx10-fnrf](https://github.com/samuelpowell/CX10-FNRF) Cheerson CX10 rate mode firmware with integrated RF
- [**60**星][1m] [Shell] [nccgroup/asafw](https://github.com/nccgroup/asafw) Set of scripts to deal with Cisco ASA firmware [pack/unpack etc.]
- [**56**星][5y] [Shell] [ge0rg/samsung-nx-hacks](https://github.com/ge0rg/samsung-nx-hacks) Firmware Hacks for the Linux-based Samsung NX mirrorless camera models (NX300, NX2000, ???)
- [**52**星][7m] [Py] [bkerler/oppo_decrypt](https://github.com/bkerler/oppo_decrypt) 一加手机固件解密脚本
- [**48**星][2y] [Py] [q3k/m16c-interface](https://github.com/q3k/m16c-interface) 绕过Renesas M16C 微控制器的 bootloader security，以及转储固件
- [**46**星][4y] [Assembly] [raspberrypi/rpi-sense](https://github.com/raspberrypi/rpi-sense) Sense HAT firmware and driver
- [**45**星][7m] [Py] [firmadyne/scraper](https://github.com/firmadyne/scraper) Firmware scraper
- [**45**星][9m] [C] [groupgets/purethermal1-firmware](https://github.com/groupgets/purethermal1-firmware) Reference firmware for PureThermal 1 FLIR Lepton Dev Kit
- [**43**星][2y] [C] [rbaron/fitless](https://github.com/rbaron/fitless) A collection of toy firmwares for the ID115 fitness tracker
- [**41**星][3y] [Assembly] [ilovepp/firminsight](https://github.com/ilovepp/firminsight) Automatic collect firmwares from internet,decompress,find binary code,extract info,file relation and function relation
- [**38**星][3y] [Py] [fotisl/utimaco](https://github.com/fotisl/utimaco) Tools for reverse engineering the Utimaco Firmware
- [**37**星][26d] [C] [microsoft/cfu](https://github.com/microsoft/cfu) Component Firmware Update
- [**36**星][3y] [C] [brad-anton/proxbrute](https://github.com/brad-anton/proxbrute) Modified proxmark3 firmware to perform brute forcing of 26-Bit ProxCards
- [**36**星][4y] [C] [sektioneins/xpwntool-lite](https://github.com/sektioneins/xpwntool-lite) Lightweight version of xpwntool just for decrypting IMG3 firmware files
- [**33**星][2y] [Py] [ganapati/firmflaws](https://github.com/ganapati/firmflaws) Firmware analysis website + API
- [**30**星][5m] [Py] [rot42/gnuk-extractor](https://github.com/rot42/gnuk-extractor) Extract PGP secret keys from Gnuk / Nitrokey Start firmwares
- [**26**星][3y] [C++] [marcnewlin/mousejack-nes-controller](https://github.com/marcnewlin/mousejack-nes-controller) MouseJack NES controller firmware and build guide.
- [**25**星][2y] [C] [ktemkin-archive/atmosphere](https://github.com/ktemkin-archive/Atmosphere) Atmosphère is a work-in-progress customized firmware for the Nintendo Switch.


### <a id="fff92e7d304e2c927ef3530f4d327456"></a>Intel


- [**510**星][2m] [Py] [platomav/meanalyzer](https://github.com/platomav/meanalyzer) Intel Engine Firmware Analysis Tool
- [**465**星][1y] [Py] [ptresearch/unme11](https://github.com/ptresearch/unme11) Intel ME 11.x Firmware Images Unpacker
- [**21**星][2m] [Py] [flarn2006/bhstools](https://github.com/flarn2006/bhstools) Tools for interacting with Brinks BHS-3000 and BHS-4000 / IntelliBus, custom firmware for BHS-4000




# <a id="948dbc64bc0ff4a03296988574f5238c"></a>Crypto&&加密&&算法


***


## <a id="a6b0a9b9184fd78c8b87ccfe48a8e544"></a>工具


- [**2374**星][2m] [TeX] [crypto101/book](https://github.com/crypto101/book) Crypto 101, the introductory book on cryptography.
- [**1653**星][6d] [Go] [bitnami-labs/sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) A Kubernetes controller and tool for one-way encrypted Secrets
- [**1484**星][25d] [C++] [microsoft/seal](https://github.com/microsoft/seal) Microsoft SEAL is an easy-to-use and powerful homomorphic encryption library.
- [**832**星][5d] [Haskell] [galoisinc/cryptol](https://github.com/galoisinc/cryptol) The Language of Cryptography
- [**773**星][1y] [pfarb/awesome-crypto-papers](https://github.com/pfarb/awesome-crypto-papers) A curated list of cryptography papers, articles, tutorials and howtos.
- [**693**星][5m] [C++] [stealth/opmsg](https://github.com/stealth/opmsg) opmsg message encryption
- [**673**星][4d] [Java] [google/conscrypt](https://github.com/google/conscrypt) Conscrypt is a Java Security Provider that implements parts of the Java Cryptography Extension and Java Secure Socket Extension.
- [**619**星][4y] [Go] [leo-stone/hack-petya](https://github.com/leo-stone/hack-petya) 搜索key，恢复 petya 加密的 mft
- [**482**星][3m] [C] [microsoft/symcrypt](https://github.com/microsoft/symcrypt) Cryptographic library
- [**469**星][21d] [C] [skeeto/enchive](https://github.com/skeeto/enchive) Encrypted personal archives
- [**467**星][4m] [miscreant/meta](https://github.com/miscreant/meta) 具备错误使用抗性的（Misuse-resistant ）对称加密库，支持 AES-SIV (RFC5297) 和 CHAIN/STREAM
- [**433**星][2m] [Go] [gorilla/securecookie](https://github.com/gorilla/securecookie) Package gorilla/securecookie encodes and decodes authenticated and optionally encrypted cookie values for Go web applications.
- [**395**星][1y] [sweis/crypto-might-not-suck](https://github.com/sweis/crypto-might-not-suck) List of crypto projects that might not suck
- [**381**星][18d] [C++] [msoos/cryptominisat](https://github.com/msoos/cryptominisat) An advanced SAT solver
- [**350**星][8m] [Haskell] [jpmorganchase/constellation](https://github.com/jpmorganchase/constellation) Peer-to-peer encrypted message exchange
- [**341**星][1m] [Shell] [umputun/nginx-le](https://github.com/umputun/nginx-le) Nginx with automatic let's encrypt (docker image)
- [**330**星][10d] [Py] [efforg/starttls-everywhere](https://github.com/efforg/starttls-everywhere) A system for ensuring & authenticating STARTTLS encryption between mail servers
- [**326**星][6m] [JS] [hr/crypter](https://github.com/hr/crypter) An innovative, convenient and secure cross-platform encryption app
- [**316**星][2y] [Py] [ethventures/cryptotracker](https://github.com/ethventures/cryptotracker) A complete open source system for tracking and visualizing cryptocurrency price movements on leading exchanges
- [**309**星][1m] [C] [jhuisi/charm](https://github.com/jhuisi/charm) A Framework for Rapidly Prototyping Cryptosystems
- [**269**星][5y] [C] [conradev/dumpdecrypted](https://github.com/conradev/dumpdecrypted) Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk. This tool is necessary for security researchers to be able to look under the hood of encryption.
- [**268**星][5d] [Py] [nucypher/nucypher](https://github.com/nucypher/nucypher) A decentralized network offering accessible, intuitive, and extensible cryptographic runtimes and interfaces for secrets management and dynamic access control.
- [**261**星][3y] [Py] [pablocelayes/rsa-wiener-attack](https://github.com/pablocelayes/rsa-wiener-attack) A Python implementation of the Wiener attack on RSA public-key encryption scheme.
- [**253**星][13d] [C] [icing/mod_md](https://github.com/icing/mod_md) Let's Encrypt (ACME) support for Apache httpd
- [**248**星][26d] [C++] [evpo/encryptpad](https://github.com/evpo/encryptpad) Minimalist secure text editor and binary encryptor that implements RFC 4880 Open PGP format: symmetrically encrypted, compressed and integrity protected. The editor can protect files with passwords, key files or both.
- [**248**星][1y] [batchfile] [zerodot1/coinblockerlists](https://github.com/zerodot1/coinblockerlists) Simple lists that can help prevent cryptomining in the browser or other applications.
- [**233**星][8m] [C] [ctz/cifra](https://github.com/ctz/cifra) A collection of cryptographic primitives targeted at embedded use.
- [**225**星][5y] [ObjC] [limneos/weak_classdump](https://github.com/limneos/weak_classdump) Cycript real-time classdump . An alternative for encrypted binaries
- [**224**星][12m] [C] [gkdr/lurch](https://github.com/gkdr/lurch) XEP-0384: OMEMO Encryption for libpurple.
- [**224**星][2d] [C] [libyal/libfvde](https://github.com/libyal/libfvde) Library and tools to access FileVault Drive Encryption (FVDE) encrypted volumes
- [**224**星][13d] [vixentael/my-talks](https://github.com/vixentael/my-talks) List of my talks and workshops: security engineering, applied cryptography, secure software development
- [**221**星][3m] [Go] [cloudflare/tls-tris](https://github.com/cloudflare/tls-tris) crypto/tls, now with 100% more 1.3. THE API IS NOT STABLE AND DOCUMENTATION IS NOT GUARANTEED.
- [**215**星][11d] [C] [hypersine/how-does-navicat-encrypt-password](https://github.com/HyperSine/how-does-navicat-encrypt-password) Transferred from
- [**211**星][5m] [Py] [nucypher/nufhe](https://github.com/nucypher/nufhe) NuCypher fully homomorphic encryption (NuFHE) library implemented in Python
- [**205**星][2y] [Java] [facebookresearch/asynchronousratchetingtree](https://github.com/facebookresearch/asynchronousratchetingtree) 用于"端到端的加密群组消息"的协议
- [**202**星][5m] [TeX] [decrypto-org/rupture](https://github.com/decrypto-org/rupture) A framework for BREACH and other compression-based crypto attacks
- [**201**星][3d] [anudeepnd/blacklist](https://github.com/anudeepnd/blacklist) Curated and well-maintained host file to block ads, tracking, cryptomining and more! Updated regularly.
- [**197**星][2y] [ObjC] [alonemonkey/dumpdecrypted](https://github.com/alonemonkey/dumpdecrypted) Dumps decrypted mach-o files from encrypted applications、framework or app extensions.
- [**186**星][4y] [Java] [netspi/weblogicpassworddecryptor](https://github.com/netspi/weblogicpassworddecryptor) PowerShell script and Java code to decrypt WebLogic passwords
- [**180**星][2m] [Py] [nolze/msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool) Python tool and library for decrypting MS Office files with passwords or other keys
- [**173**星][18d] [C] [microsoft/pqcrypto-sidh](https://github.com/microsoft/pqcrypto-sidh) SIDH Library is a fast and portable software library that implements state-of-the-art supersingular isogeny cryptographic schemes. The chosen parameters aim to provide security against attackers running a large-scale quantum computer, and security against classical algorithms.
- [**165**星][1m] [hl2guide/all-in-one-customized-adblock-list](https://github.com/hl2guide/all-in-one-customized-adblock-list) An all-in-one adblock list that thoroughly blocks trackers, popup ads, ads, unwanted cookies, fake news, cookie warning messages, unwanted comment sections, crypto-coin mining, YouTube clutter, Twitter guff and social network hassles. Development is halted at version 2.8.
- [**157**星][17d] [Go] [mimoo/disco](https://github.com/mimoo/disco) a protocol to encrypt communications and a cryptographic library based on Disco
- [**151**星][30d] [C] [microchiptech/cryptoauthlib](https://github.com/microchiptech/cryptoauthlib) Library for interacting with the Crypto Authentication secure elements
- [**150**星][2y] [Go] [kudelskisecurity/cdf](https://github.com/kudelskisecurity/cdf)  automatically test the correctness and security of cryptographic software
- [**148**星][1y] [PS] [nexxai/cryptoblocker](https://github.com/nexxai/cryptoblocker) A script to deploy File Server Resource Manager and associated scripts to block infected users
- [**146**星][3y] [C] [gentilkiwi/wanadecrypt](https://github.com/gentilkiwi/wanadecrypt) A decryptor for Wanacry (you need the private key!)
- [**145**星][19d] [Rust] [brycx/orion](https://github.com/brycx/orion) Easy and usable rust crypto
- [**133**星][1m] [jlopp/physical-bitcoin-attacks](https://github.com/jlopp/physical-bitcoin-attacks) A list of known attacks against Bitcoin / crypto asset owning entities that occurred in meatspace.
- [**129**星][2y] [Ruby] [benlaurie/objecthash](https://github.com/benlaurie/objecthash) A way to cryptographically hash objects (in the JSON-ish sense) that works cross-language. And, therefore, cross-encoding.
- [**127**星][5y] [Py] [fox-it/cryptophp](https://github.com/fox-it/cryptophp) CryptoPHP Indicators of Compromise
- [**116**星][2y] [Py] [blackploit/hash-identifier](https://github.com/blackploit/hash-identifier) Software to identify the different types of hashes used to encrypt data and especially passwords
- [**108**星][2d] [C] [libyal/libbde](https://github.com/libyal/libbde) Library and tools to access the BitLocker Drive Encryption (BDE) encrypted volumes
- [**97**星][6m] [tuupola/branca-spec](https://github.com/tuupola/branca-spec) Authenticated and encrypted API tokens using modern crypto
- [**92**星][2y] [Py] [blackthorne/codetective](https://github.com/blackthorne/codetective) a tool to determine the crypto/encoding algorithm used according to traces from its representation
- [**92**星][14d] [Py] [lockedbyte/cryptovenom](https://github.com/lockedbyte/cryptovenom) Cryptovenom: The Cryptography Swiss Army Knife
- [**89**星][3y] [JS] [particle-iot/spark-protocol](https://github.com/particle-iot/spark-protocol) Node.JS module for hosting direct encrypted CoAP socket connections
- [**88**星][2m] [PHP] [zendframework/zend-crypt](https://github.com/zendframework/zend-crypt) Cryptographic component from Zend Framework
- [**87**星][5d] [Py] [duanhongyi/gmssl](https://github.com/duanhongyi/gmssl) a python crypto for sm2/sm3/sm4
- [**87**星][14d] [Rust] [kzen-networks/curv](https://github.com/kzen-networks/curv) Rust language general purpose elliptic curve cryptography.
- [**87**星][1m] [Py] [tozny/rancher-lets-encrypt](https://github.com/tozny/rancher-lets-encrypt) Automatically create and manage certificates in Rancher using Let's Encrypt webroot verification via a minimal service
- [**84**星][3y] [Shell] [scotthelme/lets-encrypt-smart-renew](https://github.com/scotthelme/lets-encrypt-smart-renew) Check the remaining validity period of a certificate before renewing.
- [**82**星][3y] [Go] [whyrusleeping/zmsg](https://github.com/whyrusleeping/zmsg) A small program for sending messages via zcash encrypted memo fields
- [**74**星][5m] [JS] [zencashofficial/arizen](https://github.com/zencashofficial/arizen) Arizen is the API wallet for Horizen with encrypted and only locally stored files!
- [**72**星][6m] [PHP] [vlucas/pikirasa](https://github.com/vlucas/pikirasa) PKI public/private RSA key encryption using the OpenSSL extension
- [**70**星][2y] [HTML] [brandis-project/brandis](https://github.com/brandis-project/brandis) Brandis: End-to-end encryption for everyone
- [**67**星][2m] [HTML] [deadlyelder/tools-for-cryptanalysis](https://github.com/deadlyelder/tools-for-cryptanalysis) A repository that aims to provide tools for cryptography and cryptanalysis
- [**67**星][6m] [Py] [marcobellaccini/pyaescrypt](https://github.com/marcobellaccini/pyaescrypt) A Python 3 module and script that uses AES256-CBC to encrypt/decrypt files and streams in AES Crypt file format (version 2).
- [**66**星][4y] [PS] [dlwyatt/protecteddata](https://github.com/dlwyatt/protecteddata) PowerShell Module for securely encrypting and sharing secret data such as passwords.
- [**66**星][1m] [C] [gpg/libgcrypt](https://github.com/gpg/libgcrypt) The GNU crypto library
- [**64**星][6m] [Shell] [nodesocket/cryptr](https://github.com/nodesocket/cryptr) A simple shell utility for encrypting and decrypting files using OpenSSL.
- [**64**星][3y] [Ruby] [danielmiessler/caparser](https://github.com/danielmiessler/caparser) A quick and dirty PCAP parser that helps you identify who your applications are sending sensitive data to without encryption.
- [**62**星][1y] [Py] [lclevy/unarcrypto](https://github.com/lclevy/unarcrypto) unarcrypto：描述 zip、rar、7zip 使用的加密算法
- [**60**星][1y] [Shell] [galeone/letsencrypt-lighttpd](https://github.com/galeone/letsencrypt-lighttpd) Renew your let's encrypt certificates monthly, using lighttpd as webserver.
- [**60**星][2y] [C] [gravity-postquantum/gravity-sphincs](https://github.com/gravity-postquantum/gravity-sphincs) Signature scheme submitted to NIST's Post-Quantum Cryptography Project
- [**58**星][2y] [Py] [hasherezade/crypto_utils](https://github.com/hasherezade/crypto_utils) Set of my small utils related to cryptography, encoding, decoding etc
- [**56**星][12m] [C] [smihica/pyminizip](https://github.com/smihica/pyminizip) To create a password encrypted zip file in python.
- [**52**星][1y] [Py] [cisco-talos/pylocky_decryptor](https://github.com/cisco-talos/pylocky_decryptor) 
- [**52**星][3y] [PS] [m-dwyer/cryptoblocker](https://github.com/m-dwyer/cryptoblocker) A script to deploy File Server Resource Manager and associated scripts to block infected users
- [**48**星][19d] [C] [jedisct1/libhydrogen](https://github.com/jedisct1/libhydrogen) A lightweight, secure, easy-to-use crypto library suitable for constrained environments.
- [**48**星][2y] [Shell] [samoshkin/docker-letsencrypt-certgen](https://github.com/samoshkin/docker-letsencrypt-certgen) Docker image to generate, renew, revoke RSA and/or ECDSA SSL certificates from LetsEncrypt CA using certbot and acme.sh clients in automated fashion
- [**46**星][8m] [C] [cossacklabs/hermes-core](https://github.com/cossacklabs/hermes-core) Security framework for building multi-user end-to-end encrypted data storage and sharing/processing with zero leakage risks from storage and transport infrastructure.
- [**44**星][3y] [C] [kudelskisecurity/sgx-reencrypt](https://github.com/kudelskisecurity/sgx-reencrypt) PoC of an SGX enclave performing symmetric reencryption
- [**40**星][10m] [Shell] [jceminer/cn_cpu_miner](https://github.com/jceminer/cn_cpu_miner) Cryptonote CPU Miner
- [**39**星][6y] [C] [smartinm/diskcryptor](https://github.com/smartinm/diskcryptor) DiskCryptor - Open source partition encryption solution
- [**38**星][3y] [Py] [hcamael/ctf-library](https://github.com/hcamael/ctf-library) 之Crypto
- [**38**星][2y] [Py] [jamespayor/vector-homomorphic-encryption](https://github.com/jamespayor/vector-homomorphic-encryption) 6.857 project - implementation of scheme for encrypting integer vectors that allows addition, linear transformation, and weighted inner products.
- [**38**星][6y] [ObjC] [nzn/nsuserdefaults-aesencryptor](https://github.com/nzn/nsuserdefaults-aesencryptor) NSUserDefaults category with AES encrypt/decrypt keys and values.
- [**38**星][2y] [Py] [pegasuslab/wifi-miner-detector](https://github.com/PegasusLab/WiFi-Miner-Detector) Detecting malicious WiFi with mining cryptocurrency.
- [**35**星][2y] [C#] [akalankauk/keep-it-secure-file-encryption](https://github.com/akalankauk/keep-it-secure-file-encryption) Keep It Secure Private Data Encryption & Decryption Tool
- [**35**星][11y] [C] [alanquatermain/appencryptor](https://github.com/alanquatermain/appencryptor) A command-line tool to apply or remove Apple Binary Protection from an application.
- [**34**星][1y] [kudelskisecurity/cryptochallenge18](https://github.com/kudelskisecurity/cryptochallenge18) Kudelski Security's 2018 pre-Black Hat crypto challenge
- [**31**星][4y] [danielmiessler/ctfsolutiontypes](https://github.com/danielmiessler/ctfsolutiontypes) A collection of CTF solution types, i.e. not solutions to specific CTF challenges, but the general categories that those solutions fall under. Includes CTF solution categories for web, binary, network, crypto, and others. Please contribute!
- [**31**星][2y] [Py] [fist0urs/kerberom](https://github.com/fist0urs/kerberom) Kerberom is a tool aimed to retrieve ARC4-HMAC'ed encrypted Tickets Granting Service (TGS) of accounts having a Service Principal Name (SPN) within an Active Directory
- [**30**星][1y] [JS] [1lastbr3ath/drmine](https://github.com/1lastbr3ath/drmine) Dr. Mine is a node script written to aid automatic detection of in-browser cryptojacking.
- [**30**星][1y] [Go] [wybiral/reverseproxy](https://github.com/wybiral/reverseproxy) reverseproxy: Go语言编写的加密反向代理
- [**28**星][1y] [TeX] [gossip-sjtu/k-hunt](https://github.com/gossip-sjtu/k-hunt) K-Hunt: Pinpointing Insecure Crypto Keys
- [**28**星][1y] [Shell] [hestat/minerchk](https://github.com/hestat/minerchk) Bash script to Check for malicious Cryptomining
- [**28**星][10m] [Go] [mimoo/eureka](https://github.com/mimoo/eureka) Need to encrypt a file before sending it to someone? This is it.
- [**27**星][1y] [Rust] [mortendahl/rust-paillier](https://github.com/mortendahl/rust-paillier) A pure-Rust implementation of the Paillier encryption scheme
- [**27**星][1y] [Py] [nucypher/sputnik](https://github.com/nucypher/sputnik) Sputnik is an assembly language and interpreter for Fully Homomorphic Encryption
- [**25**星][3y] [Go] [aead/hydrogen](https://github.com/aead/hydrogen) Go implementation of libhydrogen - a lightweight, easy-to-use crypto library
- [**25**星][1y] [JS] [coincheckup/crypto-supplies](https://github.com/coincheckup/crypto-supplies) Cryptocurrency circulating, maximum and total supplies
- [**25**星][4y] [Shell] [mk-fg/dracut-crypt-sshd](https://github.com/mk-fg/dracut-crypt-sshd) dracut initramfs module to start sshd on early boot to enter encryption passphrase from across the internets
- [**25**星][7m] [C] [underhandedcrypto/entries](https://github.com/underhandedcrypto/entries) A browsable archive of all Underhanded Crypto Contest entries.
- [**25**星][6y] [C] [whyallyn/paythepony](https://github.com/whyallyn/paythepony) Pay the Pony is hilarityware that uses the Reflective DLL injection library to inject into a remote process, encrypt and demand a ransom for files, and inflict My Little Pony madness on a system.
- [**24**星][4y] [PHP] [lt/php-cryptopals](https://github.com/lt/php-cryptopals) The Matasano crypto challenges completed using PHP
- [**24**星][4m] [Py] [blacknbunny/encdecshellcode](https://github.com/blacknbunny/encdecshellcode) Shellcode Encrypter & Decrypter With XOR Cipher
- [**24**星][1m] [cypurr-collective/cypurr-prezes](https://github.com/cypurr-collective/cypurr-prezes) presentation materials for our cryptoparties
- [**23**星][] [C++] [deeponion/deeponion](https://github.com/deeponion/deeponion) Official Source Repo for DeepOnion - Anonymous Cryptocurrency on TOR
- [**23**星][2y] [C] [nucypher/nucypher-pre-python](https://github.com/nucypher/nucypher-pre-python) nucypher-pre-python：Python 实现的“代理重加密（Proxy Re-Encryption）”算法
- [**22**星][3y] [Py] [neurobin/letsacme](https://github.com/neurobin/letsacme) A tiny script to issue and renew TLS/SSL certificate from Let's Encrypt
- [**22**星][2y] [ptresearch/intelme-crypto](https://github.com/ptresearch/intelme-crypto) 
- [**21**星][2y] [Py] [spec-sec/securechat](https://github.com/spec-sec/securechat) Encrypted chat server and client written in Python
- [**21**星][25d] [Shell] [cryptomator/cryptomator-mac](https://github.com/cryptomator/cryptomator-mac) Cryptomator .dmg image for Mac
- [**20**星][2y] [C] [gravity-postquantum/prune-horst](https://github.com/gravity-postquantum/prune-horst) Signature scheme submitted to NIST's Post-Quantum Cryptography Project
- [**20**星][2y] [Py] [kudelskisecurity/cryptochallenge17](https://github.com/kudelskisecurity/cryptochallenge17) Kudelski Security's 2017 crypto challenge


# 贡献
内容为系统自动导出, 有任何问题请提issue