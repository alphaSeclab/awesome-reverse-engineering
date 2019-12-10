# 逆向


- 跟逆向有关的资源收集。当前包括的工具个数3000+，并根据功能进行了粗糙的分类。部分工具添加了中文描述。当前包括文章数600左右。
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
        - [(15) 恶意代码分析](#0b3e1936ad7c4ccc10642e994c653159)
        - [(6) 系列文章-Labeless插件介绍](#04cba8dbb72e95d9c721fe16a3b48783)
        - [(24) 系列文章-使用IDA从零开始学逆向](#1a2e56040cfc42c11c5b4fa86978cc19)
        - [系列文章-IDAPython-让你的生活更美好](#e838a1ecdcf3d068547dd0d7b5c446c6)
            - [(6) 原文](#7163f7c92c9443e17f3f76cc16c2d796)
            - [(5) 译文](#fc62c644a450f3e977af313edd5ab124)
        - [(50) 工具&&插件&&脚本介绍](#3d3bc775abd7f254ff9ff90d669017c9)
        - [(9) Tips&&Tricks](#a4bd25d3dc2f0be840e39674be67d66b)
        - [(146) 未分类](#4187e477ebc45d1721f045da62dbf4e8)
        - [(5) 翻译-TheIDAProBook](#ea11818602eb33e8b165eb18d3710965)
        - [(2) 翻译-ReverseEngineeringCodeWithIDAPro](#ec5f7b9ed06500c537aa25851a3f2d3a)
        - [(5) 系列文章-使用IDA逆向C代码](#8433dd5df40aaf302b179b1fda1d2863)
        - [(7) 逆向实战](#d8e48eb05d72db3ac1e050d8ebc546e1)
        - [(2) 新添加的](#37634a992983db427ce41b37dd9a98c2)
- [Ghidra](#319821036a3319d3ade5805f384d3165)
    - [插件&&脚本](#fa45b20f6f043af1549b92f7c46c9719)
        - [(16) 新添加的](#ce70b8d45be0a3d29705763564623aca)
        - [特定分析目标](#69dc4207618a2977fe8cd919e7903fa5)
            - [(3) 未分类](#da5d2b05da13f8e65aa26d6a1c95a8d0)
            - [(18) Loader&&Processor](#058bb9893323f337ad1773725d61f689)
            - [(2) Xbox](#51a2c42c6d339be24badf52acb995455)
        - [与其他工具交互](#99e3b02da53f1dbe59e0e277ef894687)
            - [(2) Radare2](#e1cc732d1388084530b066c26e24887b)
            - [(1) 未分类](#5923db547e1f04f708272543021701d2)
            - [(5) IDA](#d832a81018c188bf585fcefa3ae23062)
            - [(1) DBI](#60e86981b2c98f727587e7de927e0519)
        - [(1) 外观&&主题](#cccbd06c6b9b03152d07a4072152ae27)
        - [(2) Ghidra](#2ae406afda6602c8f02d73678b2ff040)
    - [文章&&视频](#273df546f1145fbed92bb554a327b87a)
        - [(65) 新添加的](#ce49901b4914f3688ef54585c8f9df1a)
- [x64dbg](#b1a6c053e88e86ce01bbd78c54c63a7c)
    - [插件&&脚本](#b4a856db286f9f29b5a32d477d6b3f3a)
        - [(62) 新添加的](#da5688c7823802e734c39b539aa39df7)
        - [(1) x64dbg](#353ea40f2346191ecb828210a685f9db)
    - [文章&&视频](#22894d6f2255dc43d82dd46bdbc20ba1)
- [OllyDbg](#37e37e665eac00de3f55a13dcfd47320)
    - [插件&&脚本](#7834e399e48e6c64255a1a0fdb6b88f5)
        - [(12) 新添加的](#92c44f98ff5ad8f8b0f5e10367262f9b)
    - [文章&&视频](#8dd3e63c4e1811973288ea8f1581dfdb)
- [WinDBG](#0a506e6fb2252626add375f884c9095e)
    - [插件&&脚本](#37eea2c2e8885eb435987ccf3f467122)
        - [(64) 新添加的](#2ef75ae7852daa9862b2217dca252cc3)
    - [(9) 文章&&视频](#6d8bac8bfb5cda00c7e3bd38d64cbce3)
- [Cuckoo](#0ae4ddb81ff126789a7e08b0768bd693)
    - [工具](#5830a8f8fb3af1a336053d84dd7330a1)
        - [(35) 新添加的](#f2b5c44c2107db2cec6c60477c6aa1d0)
    - [(15) 文章&&视频](#ec0a441206d9a2fe1625dce0a679d466)
- [Radare2](#86cb7d8f548ca76534b5828cb5b0abce)
    - [插件&&脚本](#0e08f9478ed8388319f267e75e2ef1eb)
        - [(33) 新添加的](#6922457cb0d4b6b87a34caf39aa31dfe)
        - [(1) Radare2](#ec3f0b5c2cf36004c4dd3d162b94b91a)
        - [与其他工具交互](#1a6652a1cb16324ab56589cb1333576f)
            - [(4) 未分类](#dfe53924d678f9225fc5ece9413b890f)
            - [(3) IDA](#1cfe869820ecc97204a350a3361b31a7)
        - [(5) GUI](#f7778a5392b90b03a3e23ef94a0cc3c6)
    - [(168) 文章&&视频](#95fdc7692c4eda74f7ca590bb3f12982)
- [BinaryNinja](#afb7259851922935643857c543c4b0c2)
    - [插件&&脚本](#3034389f5aaa9d7b0be6fa7322340aab)
        - [(38) 新添加的](#a750ac8156aa0ff337a8639649415ef1)
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
            - [(15) 新添加的](#78a2edf9aa41eb321436cb150ea70a54)
            - [与其他工具交互](#e6a829abd8bbc5ad2e5885396e3eec04)
                - [(8) 未分类](#e129288dfadc2ab0890667109f93a76d)
        - [文章&&视频](#226190bea6ceb98ee5e2b939a6515fac)
    - [Frida](#f24f1235fd45a1aa8d280eff1f03af7e)
        - [工具](#a5336a0f9e8e55111bda45c8d74924c1)
            - [(97) 新添加的](#54836a155de0c15b56f43634cd9cfecf)
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
            - [(7) 新添加的](#82072558d99a6cf23d4014c0ae5b420a)
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
        - [(42) 新添加的1](#63fd2c592145914e99f837cecdc5a67c)
    - [(2) 文章&&视频](#f0493b259e1169b5ddd269b13cfd30e6)
- [Apple&&iOS&&iXxx](#069664f347ae73b1370c4f5a2ec9da9f)
    - [工具](#58cd9084afafd3cd293564c1d615dd7f)
        - [(204) 新添加的](#d0108e91e6863289f89084ff09df39d0)
        - [(7) XCode](#7037d96c1017978276cb920f65be2297)
    - [文章&&视频](#c97bbe32bbd26c72ceccb43400e15bf1)
- [Windows](#2f81493de610f9b796656b269380b2de)
    - [工具](#b478e9a9a324c963da11437d18f04998)
        - [(213) 其他](#1afda3039b4ab9a3a1f60b179ccb3e76)
        - [(10) 事件日志&&事件追踪&&ETW](#0af4bd8ca0fd27c9381a2d1fa8b71a1f)
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
    - [文章](#3939f5e83ca091402022cb58e0349ab8)
- [Linux](#dc664c913dc63ec6b98b47fcced4fdf0)
    - [(101) 工具](#89e277bca2740d737c1aeac3192f374c)
    - [文章](#f6d78e82c3e5f67d13d9f00c602c92f0)
- [Hook](#3f1fde99538be4662dca6747a365640b)
    - [(109) 工具](#cfe974d48bbb90a930bf667c173616c7)
- [Monitor&&监控&&Trace&&追踪](#70e64e3147675c9bcd48d4f475396e7f)
    - [(29) 工具](#cd76e644d8ddbd385939bb17fceab205)
- [Malware&&恶意代码](#09fa851959ff48f5667a2099c861eab8)
    - [(270) 工具](#e781a59e4f4daab058732cf66f77bfb9)
- [Game&&游戏](#28aa8187f8a1e38ca5a55aa31a5ee0c3)
    - [(58) 工具](#07f0c2cbf63c1d7de6f21fa43443ede3)
- [工具-其他](#d3690e0b19c784e104273fe4d64b2362)
    - [(284) 新添加的](#1d9dec1320a5d774dc8e0e7604edfcd3)
    - [(14) angr](#4fe330ae3e5ce0b39735b1bfea4528af)
    - [(116) Debug&&调试](#324874bb7c3ead94eae6f1fa1af4fb68)
    - [新添加的11](#9d0f15756c4435d1ea79c21fcfda101f)
    - [BAP](#9f8d3f2c9e46fbe6c25c22285c8226df)
    - [(3) BinNavi](#2683839f170250822916534f1db22eeb)
    - [(55) Decompiler&&反编译器](#0971f295b0f67dc31b7aa45caf3f588f)
    - [(30) Disassemble&&反汇编](#2df6d3d07e56381e1101097d013746a0)
    - [(19) GDB](#975d9f08e2771fccc112d9670eae1ed1)
    - [(4) Captcha&&验证码](#9526d018b9815156cb001ceee36f6b1d)
    - [(3) 其他](#bc2b78af683e7ba983205592de8c3a7a)
- [文章](#dd1e42d17eefb275a804584a848b82a6)
    - [新添加的](#48d6a0efe043af4bed4cbba665a4502c)
- [Rootkit&&Bootkit](#5fdcfc70dd87360c2dddcae008076547)
    - [(67) 工具](#b8d6f237c04188a10f511cd8988de28a)
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


- [**1044**星][13d] [Py] [fireeye/flare-ida](https://github.com/fireeye/flare-ida) 多工具
    - [StackStrings](https://github.com/fireeye/flare-ida/blob/master/plugins/stackstrings_plugin.py) 自动恢复手动构造的字符串
    - [Struct Typer](https://github.com/fireeye/flare-ida/blob/master/plugins/struct_typer_plugin.py) implements the struct typing described [here](https://www.mandiant.com/blog/applying-function-types-structure-fields-ida/)
    - [ApplyCalleeType](https://github.com/fireeye/flare-ida/blob/master/python/flare/apply_callee_type.py) specify or choose a function type for indirect calls as described [here](https://www.fireeye.com/blog/threat-research/2015/04/flare_ida_pro_script.html)
    - [argtracker](https://github.com/fireeye/flare-ida/blob/master/python/flare/argtracker.py) 识别函数使用的静态参数
    - [idb2pat](https://github.com/fireeye/flare-ida/blob/master/python/flare/idb2pat.py) FLIRT签名生成
    - [objc2_analyzer](https://github.com/fireeye/flare-ida/blob/master/python/flare/objc2_analyzer.py) 在目标Mach-O可执行文件的与Objective-C运行时相关的部分中定义的选择器引用及其实现之间创建交叉引用
    - [MSDN Annotations](https://github.com/fireeye/flare-ida/tree/master/python/flare/IDB_MSDN_Annotator) 从XML文件中提取MSDN信息，添加到IDB数据库中
    - [ironstrings](https://github.com/fireeye/flare-ida/tree/master/python/flare/ironstrings) 使用代码模拟执行（flare-emu）, 恢复构造的字符串
    - [Shellcode Hashes](https://github.com/fireeye/flare-ida/tree/master/shellcode_hashes) 生成Hash数据库
- [**735**星][6m] [Py] [devttys0/ida](https://github.com/devttys0/ida) IDA插件/脚本/模块收集
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
- [**315**星][2m] [C] [ohjeongwook/darungrim](https://github.com/ohjeongwook/darungrim) 软件补丁分析工具
    - [IDA插件](https://github.com/ohjeongwook/darungrim/tree/master/Src/IDAPlugin) 
    - [DGEngine](https://github.com/ohjeongwook/darungrim/tree/master/Src/DGEngine) 
- [**274**星][3m] [Py] [jpcertcc/aa-tools](https://github.com/jpcertcc/aa-tools) 多脚本
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


### <a id="fb4f0c061a72fc38656691746e7c45ce"></a>结构体&&类的检测&&创建&&恢复


#### <a id="fa5ede9a4f58d4efd98585d3158be4fb"></a>未分类


- [**927**星][12d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) 二进制代码静态分析工具。值分析（寄存器、内存）、污点分析、类型重建和传播（propagation）、前向/后向分析
    - 重复区段: [IDA->插件->污点分析](#34ac84853604a7741c61670f2a075d20) |
- [**656**星][16d] [Py] [igogo-x86/hexrayspytools](https://github.com/igogo-x86/hexrayspytools) 结构体和类重建插件


#### <a id="4900b1626f10791748b20630af6d6123"></a>C++类&&虚表


- [**604**星][3m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) 利用IDA调试获取的信息，自动创建C++的虚表
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






### <a id="a7dac37cd93b8bb42c7d6aedccb751b3"></a>收集


- [**1749**星][2m] [onethawt/idaplugins-list](https://github.com/onethawt/idaplugins-list) IDA插件收集
- [**358**星][9m] [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) IDA x64DBG OllyDBG 插件收集
    - 重复区段: [x64dbg->插件->新添加的](#da5688c7823802e734c39b539aa39df7) |


### <a id="fabf03b862a776bbd8bcc4574943a65a"></a>外观&&主题


- [**720**星][6m] [Py] [zyantific/idaskins](https://github.com/zyantific/idaskins) 皮肤插件


### <a id="a8f5db3ab4bc7bc3d6ca772b3b9b0b1e"></a>固件&&嵌入式设备


- [**5165**星][1m] [Py] [refirmlabs/binwalk](https://github.com/ReFirmLabs/binwalk) 固件分析工具（命令行+IDA插件）
    - [IDA插件](https://github.com/ReFirmLabs/binwalk/tree/master/src/scripts) 
    - [binwalk](https://github.com/ReFirmLabs/binwalk/tree/master/src/binwalk) 
- [**490**星][4m] [Py] [maddiestone/idapythonembeddedtoolkit](https://github.com/maddiestone/idapythonembeddedtoolkit) 自动分析嵌入式设备的固件


### <a id="02088f4884be6c9effb0f1e9a3795e58"></a>签名(FLIRT等)&&比较(Diff)&&匹配


#### <a id="cf04b98ea9da0056c055e2050da980c1"></a>未分类


- [**418**星][17d] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) 汇编代码管理与分析平台(独立工具+IDA插件)
    - 重复区段: [IDA->插件->作为辅助](#83de90385d03ac8ef27360bfcdc1ab48) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 


#### <a id="19360afa4287236abe47166154bc1ece"></a>FLIRT签名


##### <a id="1c9d8dfef3c651480661f98418c49197"></a>FLIRT签名收集


- [**599**星][26d] [Max] [maktm/flirtdb](https://github.com/Maktm/FLIRTDB) A community driven collection of IDA FLIRT signature files
- [**307**星][4m] [push0ebp/sig-database](https://github.com/push0ebp/sig-database) IDA FLIRT Signature Database


##### <a id="a9a63d23d32c6c789ca4d2e146c9b6d0"></a>FLIRT签名生成






#### <a id="161e5a3437461dc8959cc923e6a18ef7"></a>Diff&&Match工具


- [**1542**星][1m] [Py] [joxeankoret/diaphora](https://github.com/joxeankoret/diaphora) program diffing
- [**358**星][12d] [Py] [checkpointsw/karta](https://github.com/checkpointsw/karta) source code assisted fast binary matching plugin for IDA
- [**330**星][12m] [Py] [joxeankoret/pigaios](https://github.com/joxeankoret/pigaios) A tool for matching and diffing source codes directly against binaries.


#### <a id="46c9dfc585ae59fe5e6f7ddf542fb31a"></a>Yara


- [**431**星][1m] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) 使用Yara规则查找加密常量
    - 重复区段: [IDA->插件->加密解密](#06d2caabef97cf663bd29af2b1fe270c) |




### <a id="5e91b280aab7f242cbc37d64ddbff82f"></a>IDB操作


- [**316**星][6m] [Py] [williballenthin/python-idb](https://github.com/williballenthin/python-idb) idb 文件解析和分析工具


### <a id="206ca17fc949b8e0ae62731d9bb244cb"></a>协作逆向&&多人操作相同IDB文件


- [**505**星][11m] [Py] [idarlingteam/idarling](https://github.com/IDArlingTeam/IDArling) 多人协作插件
- [**258**星][1y] [C++] [dga-mi-ssi/yaco](https://github.com/dga-mi-ssi/yaco) 利用Git版本控制，同步多人对相同二进制文件的修改


### <a id="f7d311685152ac005cfce5753c006e4b"></a>与调试器同步&&通信&&交互


- [**457**星][8d] [C] [bootleg/ret-sync](https://github.com/bootleg/ret-sync) 在反汇编工具和调试器之间同步调试会话
    - 重复区段: [x64dbg->插件->新添加的](#da5688c7823802e734c39b539aa39df7) |
    - [GDB插件](https://github.com/bootleg/ret-sync/tree/master/ext_gdb) 
    - [Ghidra插件](https://github.com/bootleg/ret-sync/tree/master/ext_ghidra) 
    - [IDA插件](https://github.com/bootleg/ret-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/bootleg/ret-sync/tree/master/ext_lldb) 
    - [OD](https://github.com/bootleg/ret-sync/tree/master/ext_olly1) 
    - [OD2](https://github.com/bootleg/ret-sync/tree/master/ext_olly2) 
    - [WinDgb](https://github.com/bootleg/ret-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/bootleg/ret-sync/tree/master/ext_x64dbg) 
- [**290**星][10m] [C] [a1ext/labeless](https://github.com/a1ext/labeless) 在IDA和调试器之间无缝同步Label/注释等
    - [IDA插件](https://github.com/a1ext/labeless/tree/master/labeless_ida) 
    - [OD](https://github.com/a1ext/labeless/tree/master/labeless_olly) 
    - [OD2](https://github.com/a1ext/labeless/tree/master/labeless_olly2) 
    - [x64dbg](https://github.com/a1ext/labeless/tree/master/labeless_x64dbg) 


### <a id="6fb7e41786c49cc3811305c520dfe9a1"></a>导入导出&与其他工具交互


#### <a id="8ad723b704b044e664970b11ce103c09"></a>未分类




#### <a id="c7066b0c388cd447e980bf0eb38f39ab"></a>Ghidra


- [**296**星][3m] [Py] [cisco-talos/ghida](https://github.com/cisco-talos/ghida) 在IDA中集成Ghidra反编译器
    - 重复区段: [Ghidra->插件->与其他工具交互->IDA](#d832a81018c188bf585fcefa3ae23062) |
- [**236**星][8m] [Py] [daenerys-sre/source](https://github.com/daenerys-sre/source) 使IDA和Ghidra脚本通用, 无需修改
    - 重复区段: [Ghidra->插件->与其他工具交互->IDA](#d832a81018c188bf585fcefa3ae23062) |


#### <a id="11139e7d6db4c1cef22718868f29fe12"></a>BinNavi


- [**378**星][1m] [C++] [google/binexport](https://github.com/google/binexport) 将反汇编以Protocol Buffer的形式导出为PostgreSQL数据库, 导入到BinNavi中使用
    - 重复区段: [工具-其他->BinNavi](#2683839f170250822916534f1db22eeb) |


#### <a id="d1ff64bee76f6749aef6100d72bfbe3a"></a>BinaryNinja




#### <a id="21ed198ae5a974877d7a635a4b039ae3"></a>Radare2




#### <a id="a1cf7f7f849b4ca2101bd31449c2a0fd"></a>Frida




#### <a id="dd0332da5a1482df414658250e6357f8"></a>IntelPin






### <a id="004c199e1dbf71769fbafcd8e58d1ead"></a>针对特定分析目标


#### <a id="5578c56ca09a5804433524047840980e"></a>未分类




#### <a id="cb59d84840e41330a7b5e275c0b81725"></a>Loader&Processor


- [**204**星][1y] [Py] [fireeye/idawasm](https://github.com/fireeye/idawasm) WebAssembly的加载器和解析器


#### <a id="1b17ac638aaa09852966306760fda46b"></a>GoLang


- [**367**星][9m] [Py] [sibears/idagolanghelper](https://github.com/sibears/idagolanghelper) 解析Go语言编译的二进制文件中的GoLang类型信息
- [**292**星][1m] [Py] [strazzere/golang_loader_assist](https://github.com/strazzere/golang_loader_assist) 辅助Go逆向


#### <a id="4c158ccc5aee04383755851844fdd137"></a>Windows驱动


- [**303**星][1y] [Py] [fsecurelabs/win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) A tool to help when dealing with Windows IOCTL codes or reversing Windows drivers.
- [**218**星][1y] [Py] [nccgroup/driverbuddy](https://github.com/nccgroup/driverbuddy) 辅助逆向Windows内核驱动


#### <a id="315b1b8b41c67ae91b841fce1d4190b5"></a>PS3&&PS4




#### <a id="f5e51763bb09d8fd47ee575a98bedca1"></a>PDB




#### <a id="7d0681efba2cf3adaba2780330cd923a"></a>Flash&&SWF




#### <a id="841d605300beba45c3be131988514a03"></a>特定样本家族




#### <a id="ad44205b2d943cfa2fa805b2643f4595"></a>CTF






### <a id="ad68872e14f70db53e8d9519213ec039"></a>IDAPython本身


#### <a id="2299bc16945c25652e5ad4d48eae8eca"></a>未分类


- [**711**星][25d] [Py] [idapython/src](https://github.com/idapython/src) IDAPython源码
- [**368**星][2m] [Py] [tmr232/sark](https://github.com/tmr232/sark) IDAPython的高级抽象


#### <a id="c42137cf98d6042372b1fd43c3635135"></a>cheatsheets


- [**233**星][7d] [Py] [inforion/idapython-cheatsheet](https://github.com/inforion/idapython-cheatsheet) Scripts and cheatsheets for IDAPython




### <a id="846eebe73bef533041d74fc711cafb43"></a>指令参考&文档


- [**496**星][12m] [PLpgSQL] [nologic/idaref](https://github.com/nologic/idaref) 指令参考插件.
- [**444**星][4m] [C++] [alexhude/friend](https://github.com/alexhude/friend) 反汇编显示增强, 文档增强插件
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |


### <a id="c08ebe5b7eec9fc96f8eff36d1d5cc7d"></a>辅助脚本编写


#### <a id="45fd7cfce682c7c25b4f3fbc4c461ba2"></a>未分类


- [**279**星][25d] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) 结合Unicorn引擎, 简化模拟脚本的编写
    - 重复区段: [IDA->插件->模拟器集成](#b38dab81610be087bd5bc7785269b8cc) |


#### <a id="1a56a5b726aaa55ec5b7a5087d6c8968"></a>Qt




#### <a id="1721c09501e4defed9eaa78b8d708361"></a>控制台&&窗口界面


- [**267**星][17d] [Py] [eset/ipyida](https://github.com/eset/ipyida) 集成IPython控制台


#### <a id="227fbff77e3a13569ef7b007344d5d2e"></a>插件模板




#### <a id="8b19bb8cf9a5bc9e6ab045f3b4fabf6a"></a>其他语言






### <a id="dc35a2b02780cdaa8effcae2b6ce623e"></a>古老的




### <a id="e3e7030efc3b4de3b5b8750b7d93e6dd"></a>调试&&动态运行&动态数据


#### <a id="2944dda5289f494e5e636089db0d6a6a"></a>未分类


- [**391**星][12m] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) 用Unicorn引擎做后端的调试插件
    - 重复区段: [IDA->插件->模拟器集成](#b38dab81610be087bd5bc7785269b8cc) |


#### <a id="0fbd352f703b507853c610a664f024d1"></a>DBI数据


- [**933**星][12m] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - 重复区段: [DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->工具->与其他工具交互->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |[DBI->Frida->工具->与其他工具交互->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja


#### <a id="b31acf6c84a9506066d497af4e702bf5"></a>调试数据


- [**604**星][3m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) 利用IDA调试获取的信息，自动创建C++的虚表
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


- [**385**星][4m] [Py] [ynvb/die](https://github.com/ynvb/die) 使用IDA调试器收集动态运行信息, 辅助静态分析




### <a id="d2166f4dac4eab7fadfe0fd06467fbc9"></a>反编译器&&AST


- [**1668**星][7m] [C++] [yegord/snowman](https://github.com/yegord/snowman) Snowman反编译器，支持x86, AMD64, ARM。有独立的GUI工具、命令行工具、IDA/Radare2/x64dbg插件，也可以作为库使用
    - 重复区段: [x64dbg->插件->新添加的](#da5688c7823802e734c39b539aa39df7) |
    - [IDA插件](https://github.com/yegord/snowman/tree/master/src/ida-plugin) 
    - [snowman](https://github.com/yegord/snowman/tree/master/src/snowman) QT界面
    - [nocode](https://github.com/yegord/snowman/tree/master/src/nocode) 命令行工具
    - [nc](https://github.com/yegord/snowman/tree/master/src/nc) 核心代码，可作为库使用
- [**1321**星][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) 反编译插件, 多功能
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>查看详情</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**406**星][3m] [C++] [avast/retdec-idaplugin](https://github.com/avast/retdec-idaplugin) retdec 的 IDA 插件
- [**229**星][6m] [Py] [patois/dsync](https://github.com/patois/dsync) 反汇编和反编译窗口同步插件
    - 重复区段: [IDA->插件->效率->其他](#c5b120e1779b928d860ad64ff8d23264) |


### <a id="7199e8787c0de5b428f50263f965fda7"></a>反混淆


- [**1360**星][2m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) 自动从恶意代码中提取反混淆后的字符串
    - 重复区段: [IDA->插件->字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**293**星][4m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) 利用Hex-Rays microcode API破解编译器级别的混淆
    - 重复区段: [IDA->插件->Microcode](#7a2977533ccdac70ee6e58a7853b756b) |


### <a id="fcf75a0881617d1f684bc8b359c684d7"></a>效率&&导航&&快速访问&&图形&&图像&&可视化 


#### <a id="c5b120e1779b928d860ad64ff8d23264"></a>其他


- [**1321**星][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) 反编译插件, 多功能
    - 重复区段: [IDA->插件->反编译器](#d2166f4dac4eab7fadfe0fd06467fbc9) |
        <details>
        <summary>查看详情</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**444**星][4m] [C++] [alexhude/friend](https://github.com/alexhude/friend) 反汇编显示增强, 文档增强插件
    - 重复区段: [IDA->插件->指令参考](#846eebe73bef533041d74fc711cafb43) |
- [**364**星][2m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) 若干快速访问功能, 扫描字符串格式化漏洞
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


- [**328**星][3m] [Py] [pfalcon/scratchabit](https://github.com/pfalcon/scratchabit) 交互式反汇编工具, 有与IDAPython兼容的插件API
- [**229**星][6m] [Py] [patois/dsync](https://github.com/patois/dsync) 反汇编和反编译窗口同步插件
    - 重复区段: [IDA->插件->反编译器](#d2166f4dac4eab7fadfe0fd06467fbc9) |


#### <a id="03fac5b3abdbd56974894a261ce4e25f"></a>显示增强


- [**203**星][14d] [Py] [patois/idacyber](https://github.com/patois/idacyber) 交互式数据可视化插件


#### <a id="3b1dba00630ce81cba525eea8fcdae08"></a>图形&&图像


- [**2563**星][5m] [Java] [google/binnavi](https://github.com/google/binnavi) 二进制分析IDE, 对反汇编代码的控制流程图和调用图进行探查/导航/编辑/注释.(IDA插件的作用是导出反汇编)


#### <a id="8f9468e9ab26128567f4be87ead108d7"></a>搜索






### <a id="66052f824f5054aa0f70785a2389a478"></a>Android


- [**244**星][7d] [C++] [strazzere/android-scripts](https://github.com/strazzere/android-scripts) Android逆向脚本收集
    - 重复区段: [Android->工具->ReverseEngineering](#6d2b758b3269bac7d69a2d2c8b45194c) |


### <a id="2adc0044b2703fb010b3bf73b1f1ea4a"></a>Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O


#### <a id="8530752bacfb388f3726555dc121cb1a"></a>未分类




#### <a id="82d0fa2d6934ce29794a651513934384"></a>内核缓存




#### <a id="d249a8d09a3f25d75bb7ba8b32bd9ec5"></a>Mach-O




#### <a id="1c698e298f6112a86c12881fbd8173c7"></a>Swift






### <a id="e5e403123c70ddae7bd904d3a3005dbb"></a>ELF




### <a id="7a2977533ccdac70ee6e58a7853b756b"></a>Microcode


- [**293**星][4m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) 利用Hex-Rays microcode API破解编译器级别的混淆
    - 重复区段: [IDA->插件->反混淆](#7199e8787c0de5b428f50263f965fda7) |


### <a id="b38dab81610be087bd5bc7785269b8cc"></a>模拟器集成


- [**488**星][1y] [Py] [alexhude/uemu](https://github.com/alexhude/uemu) 基于Unicorn的模拟器插件
- [**391**星][12m] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) 用Unicorn引擎做后端的调试插件
    - 重复区段: [IDA->插件->调试->未分类](#2944dda5289f494e5e636089db0d6a6a) |
- [**279**星][25d] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) 结合Unicorn引擎, 简化模拟脚本的编写
    - 重复区段: [IDA->插件->辅助脚本编写->未分类](#45fd7cfce682c7c25b4f3fbc4c461ba2) |


### <a id="83de90385d03ac8ef27360bfcdc1ab48"></a>作为辅助&&构成其他的一环


- [**1531**星][7d] [Py] [lifting-bits/mcsema](https://github.com/lifting-bits/mcsema) 将x86, amd64, aarch64二进制文件转换成LLVM字节码
    - [IDA7插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida7) 用于反汇编二进制文件并生成控制流程图
    - [IDA插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida) 用于反汇编二进制文件并生成控制流程图
    - [Binja插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/binja) 用于反汇编二进制文件并生成控制流程图
    - [mcsema](https://github.com/lifting-bits/mcsema/tree/master/mcsema) 
- [**418**星][17d] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) 汇编代码管理与分析平台(独立工具+IDA插件)
    - 重复区段: [IDA->插件->签名(FLIRT等)->未分类](#cf04b98ea9da0056c055e2050da980c1) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 


### <a id="1ded622dca60b67288a591351de16f8b"></a>漏洞


#### <a id="385d6777d0747e79cccab0a19fa90e7e"></a>未分类


- [**491**星][7m] [Py] [danigargu/heap-viewer](https://github.com/danigargu/heap-viewer) 查看glibc堆, 主要用于漏洞开发
- [**364**星][2m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) 若干快速访问功能, 扫描字符串格式化漏洞
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




#### <a id="cf2efa7e3edb24975b92d2e26ca825d2"></a>ROP






### <a id="7d557bc3d677d206ef6c5a35ca8b3a14"></a>补丁&&Patch


- [**720**星][12m] [Py] [keystone-engine/keypatch](https://github.com/keystone-engine/keypatch) 汇编/补丁插件, 支持多架构, 基于Keystone引擎


### <a id="7dfd8abad50c14cd6bdc8d8b79b6f595"></a>其他




### <a id="90bf5d31a3897400ac07e15545d4be02"></a>函数相关


#### <a id="347a2158bdd92b00cd3d4ba9a0be00ae"></a>未分类




#### <a id="73813456eeb8212fd45e0ea347bec349"></a>重命名&&前缀&&标记


- [**289**星][2m] [Py] [a1ext/auto_re](https://github.com/a1ext/auto_re) 自动化函数重命名


#### <a id="e4616c414c24b58626f834e1be079ebc"></a>导航&&查看&&查找




#### <a id="cadae88b91a57345d266c68383eb05c5"></a>demangle






### <a id="34ac84853604a7741c61670f2a075d20"></a>污点分析&&符号执行


- [**927**星][12d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) 二进制代码静态分析工具。值分析（寄存器、内存）、污点分析、类型重建和传播（propagation）、前向/后向分析
    - 重复区段: [IDA->插件->结构体->未分类](#fa5ede9a4f58d4efd98585d3158be4fb) |


### <a id="9dcc6c7dd980bec1f92d0cc9a2209a24"></a>字符串


- [**1360**星][2m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) 自动从恶意代码中提取反混淆后的字符串
    - 重复区段: [IDA->插件->反混淆](#7199e8787c0de5b428f50263f965fda7) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**364**星][2m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) 若干快速访问功能, 扫描字符串格式化漏洞
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




### <a id="06d2caabef97cf663bd29af2b1fe270c"></a>加密解密


- [**431**星][1m] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) 使用Yara规则查找加密常量
    - 重复区段: [IDA->插件->签名(FLIRT等)->Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |




***


## <a id="18c6a45392d6b383ea24b363d2f3e76b"></a>文章


### <a id="37634a992983db427ce41b37dd9a98c2"></a>新添加的


- 2019.11 [4hou] [反作弊游戏如何破解，看看《黑色沙漠》逆向分析过程：使用 IDAPython 和 FLIRT 签名恢复 IAT](https://www.4hou.com/web/21806.html)
- 2019.11 [aliyun_xz] [使用IDA microcode去除ollvm混淆(下)](https://xz.aliyun.com/t/6795)


### <a id="4187e477ebc45d1721f045da62dbf4e8"></a>未分类


- 2019.10 [amossys] [探秘Hex-Rays microcode](https://blog.amossys.fr/stage-2019-hexraysmicrocode.html)
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


### <a id="a4bd25d3dc2f0be840e39674be67d66b"></a>Tips&&Tricks


- 2019.07 [hexacorn] [Batch decompilation with IDA / Hex-Rays Decompiler](http://www.hexacorn.com/blog/2019/07/04/batch-decompilation-with-ida-hex-rays-decompiler/)
- 2019.06 [openanalysis] [Disable ASLR for Easier Malware Debugging With x64dbg and IDA Pro](https://oalabs.openanalysis.net/2019/06/12/disable-aslr-for-easier-malware-debugging/)
- 2019.06 [youtube_OALabs] [Disable ASLR For Easier Malware Debugging With x64dbg and IDA Pro](https://www.youtube.com/watch?v=DGX7oZvdmT0)
- 2019.06 [openanalysis] [Reverse Engineering C++ Malware With IDA Pro: Classes, Constructors, and Structs](https://oalabs.openanalysis.net/2019/06/03/reverse-engineering-c-with-ida-pro-classes-constructors-and-structs/)
- 2019.06 [youtube_OALabs] [Reverse Engineering C++ Malware With IDA Pro](https://www.youtube.com/watch?v=o-FFGIloxvE)
- 2019.03 [aliyun_xz] [IDA Pro7.0使用技巧总结](https://xz.aliyun.com/t/4205)
- 2018.06 [checkpoint_research] [Scriptable Remote Debugging with Windbg and IDA Pro](https://research.checkpoint.com/scriptable-remote-debugging-windbg-ida-pro/)
- 2015.07 [djmanilaice] [在PyCharm中编写IDAPython脚本时自动提示](http://djmanilaice.blogspot.com/2015/07/pycharm-for-your-ida-development.html)
- 2015.07 [djmanilaice] [使用IDA自动打开当前目录下的DLL和EXE](http://djmanilaice.blogspot.com/2015/07/auto-open-dlls-and-exe-in-current.html)


### <a id="0b3e1936ad7c4ccc10642e994c653159"></a>恶意代码分析


- 2019.04 [360_anquanke_learning] [两种姿势批量解密恶意驱动中的上百条字串](https://www.anquanke.com/post/id/175964/)
- 2019.03 [cyber] [使用IDAPython分析Trickbot](https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/)
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
- 2012.06 [trustwave_SpiderLabs_Blog] [使用IDAPython对Flame的字符串进行反混淆](https://www.trustwave.com/Resources/SpiderLabs-Blog/Defeating-Flame-String-Obfuscation-with-IDAPython/)


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
- 2018.06 [dougallj] [编写IDA反编译插件之: 处理VMX指令](https://dougallj.wordpress.com/2018/06/04/writing-a-hex-rays-plugin-vmx-intrinsics/)
- 2018.05 [freebuf] [HeapViewer：一款专注于漏洞利用开发的IDA Pro插件](http://www.freebuf.com/sectool/171632.html)


### <a id="ea11818602eb33e8b165eb18d3710965"></a>翻译-TheIDAProBook


- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book 第六章](https://bbs.pediy.com/thread-75632.htm)
- 2008.10 [pediy_new_digest] [[翻译]（20081030更新）The IDA Pro Book 第12章：使用FLIRT签名识别库](https://bbs.pediy.com/thread-75422.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book(第二章)](https://bbs.pediy.com/thread-74943.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro book 第5章---IDA DATA DISPLAY](https://bbs.pediy.com/thread-74838.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book(第一章)](https://bbs.pediy.com/thread-74564.htm)


### <a id="ec5f7b9ed06500c537aa25851a3f2d3a"></a>翻译-ReverseEngineeringCodeWithIDAPro


- 2009.01 [pediy_new_digest] [[原创]Reverse Engineering Code with IDA Pro第七章中文译稿](https://bbs.pediy.com/thread-80580.htm)
- 2008.06 [pediy_new_digest] [[翻译]Reverse Engineering Code with IDA Pro(第一、二章)](https://bbs.pediy.com/thread-66010.htm)


### <a id="d8e48eb05d72db3ac1e050d8ebc546e1"></a>逆向实战


- 2019.06 [devco] [破密行動: 以不尋常的角度破解 IDA Pro 偽隨機數](https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way/)
- 2019.04 [venus_seebug] [使用 IDA Pro 的 REobjc 模块逆向 Objective-C 二进制文件](https://paper.seebug.org/887/)
- 2018.11 [somersetrecon] [Introduction to IDAPython for Vulnerability Hunting - Part 2](http://www.somersetrecon.com/blog/2018/8/2/idapython-part-2)
- 2018.07 [360_anquanke_learning] [如何使用 IDAPython 寻找漏洞](https://www.anquanke.com/post/id/151898/)
- 2018.07 [somersetrecon] [如何使用IDAPython挖掘漏洞](http://www.somersetrecon.com/blog/2018/7/6/introduction-to-idapython-for-vulnerability-hunting)
- 2018.03 [duo_blog_duo_labs] [Reversing Objective-C Binaries With the REobjc Module for IDA Pro](https://duo.com/blog/reversing-objective-c-binaries-with-the-reobjc-module-for-ida-pro)
- 2006.05 [pediy_new_digest] [Themida v1008 驱动程序分析,去除花指令的 IDA 文件](https://bbs.pediy.com/thread-25836.htm)




# <a id="319821036a3319d3ade5805f384d3165"></a>Ghidra


***


## <a id="fa45b20f6f043af1549b92f7c46c9719"></a>插件&&脚本


### <a id="2ae406afda6602c8f02d73678b2ff040"></a>Ghidra


- [**18381**星][7d] [Java] [nationalsecurityagency/ghidra](https://github.com/nationalsecurityagency/ghidra) 软件逆向框架


### <a id="ce70b8d45be0a3d29705763564623aca"></a>新添加的


- [**445**星][8m] [YARA] [ghidraninja/ghidra_scripts](https://github.com/ghidraninja/ghidra_scripts) Ghidra脚本
    - [binwalk](https://github.com/ghidraninja/ghidra_scripts/blob/master/binwalk.py) 对当前程序运行BinWalk, 标注找到的内容
    - [yara](https://github.com/ghidraninja/ghidra_scripts/blob/master/yara.py) 使用Yara查找加密常量
    - [swift_demangler](https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py) 自动demangle Swift函数名
    - [golang_renamer](https://github.com/ghidraninja/ghidra_scripts/blob/master/golang_renamer.py) 恢复stripped Go二进制文件的函数名
- [**201**星][7m] [Java] [rolfrolles/ghidrapal](https://github.com/rolfrolles/ghidrapal) Ghidra 程序分析库(无文档)


### <a id="69dc4207618a2977fe8cd919e7903fa5"></a>特定分析目标


#### <a id="da5d2b05da13f8e65aa26d6a1c95a8d0"></a>未分类




#### <a id="058bb9893323f337ad1773725d61f689"></a>Loader&&Processor




#### <a id="51a2c42c6d339be24badf52acb995455"></a>Xbox






### <a id="99e3b02da53f1dbe59e0e277ef894687"></a>与其他工具交互


#### <a id="5923db547e1f04f708272543021701d2"></a>未分类




#### <a id="e1cc732d1388084530b066c26e24887b"></a>Radare2




#### <a id="d832a81018c188bf585fcefa3ae23062"></a>IDA


- [**296**星][3m] [Py] [cisco-talos/ghida](https://github.com/cisco-talos/ghida) 在IDA中集成Ghidra反编译器
    - 重复区段: [IDA->插件->导入导出->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |
- [**236**星][8m] [Py] [daenerys-sre/source](https://github.com/daenerys-sre/source) 使IDA和Ghidra脚本通用, 无需修改
    - 重复区段: [IDA->插件->导入导出->Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |


#### <a id="60e86981b2c98f727587e7de927e0519"></a>DBI






### <a id="cccbd06c6b9b03152d07a4072152ae27"></a>外观&&主题






***


## <a id="273df546f1145fbed92bb554a327b87a"></a>文章&&视频


### <a id="ce49901b4914f3688ef54585c8f9df1a"></a>新添加的


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




# <a id="b1a6c053e88e86ce01bbd78c54c63a7c"></a>x64dbg


***


## <a id="b4a856db286f9f29b5a32d477d6b3f3a"></a>插件&&脚本


### <a id="353ea40f2346191ecb828210a685f9db"></a>x64dbg


- [**34521**星][14d] [C++] [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) Windows平台x32/x64调试器


### <a id="da5688c7823802e734c39b539aa39df7"></a>新添加的


- [**1668**星][7m] [C++] [yegord/snowman](https://github.com/yegord/snowman) Snowman反编译器，支持x86, AMD64, ARM。有独立的GUI工具、命令行工具、IDA/Radare2/x64dbg插件，也可以作为库使用
    - 重复区段: [IDA->插件->反编译器](#d2166f4dac4eab7fadfe0fd06467fbc9) |
    - [IDA插件](https://github.com/yegord/snowman/tree/master/src/ida-plugin) 
    - [snowman](https://github.com/yegord/snowman/tree/master/src/snowman) QT界面
    - [nocode](https://github.com/yegord/snowman/tree/master/src/nocode) 命令行工具
    - [nc](https://github.com/yegord/snowman/tree/master/src/nc) 核心代码，可作为库使用
- [**1348**星][23d] [C] [x64dbg/x64dbgpy](https://github.com/x64dbg/x64dbgpy) Automating x64dbg using Python, Snapshots:
- [**971**星][27d] [Py] [x64dbg/docs](https://github.com/x64dbg/docs) x64dbg文档
- [**457**星][8d] [C] [bootleg/ret-sync](https://github.com/bootleg/ret-sync) 在反汇编工具和调试器之间同步调试会话
    - 重复区段: [IDA->插件->与调试器同步](#f7d311685152ac005cfce5753c006e4b) |
    - [GDB插件](https://github.com/bootleg/ret-sync/tree/master/ext_gdb) 
    - [Ghidra插件](https://github.com/bootleg/ret-sync/tree/master/ext_ghidra) 
    - [IDA插件](https://github.com/bootleg/ret-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/bootleg/ret-sync/tree/master/ext_lldb) 
    - [OD](https://github.com/bootleg/ret-sync/tree/master/ext_olly1) 
    - [OD2](https://github.com/bootleg/ret-sync/tree/master/ext_olly2) 
    - [WinDgb](https://github.com/bootleg/ret-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/bootleg/ret-sync/tree/master/ext_x64dbg) 
- [**358**星][9m] [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) IDA x64DBG OllyDBG 插件收集
    - 重复区段: [IDA->插件->收集](#a7dac37cd93b8bb42c7d6aedccb751b3) |




***


## <a id="22894d6f2255dc43d82dd46bdbc20ba1"></a>文章&&视频




# <a id="37e37e665eac00de3f55a13dcfd47320"></a>OllyDbg


***


## <a id="7834e399e48e6c64255a1a0fdb6b88f5"></a>插件&&脚本


### <a id="92c44f98ff5ad8f8b0f5e10367262f9b"></a>新添加的






***


## <a id="8dd3e63c4e1811973288ea8f1581dfdb"></a>文章&&视频




# <a id="0a506e6fb2252626add375f884c9095e"></a>WinDBG


***


## <a id="37eea2c2e8885eb435987ccf3f467122"></a>插件&&脚本


### <a id="2ef75ae7852daa9862b2217dca252cc3"></a>新添加的


- [**565**星][6m] [C#] [fremag/memoscope.net](https://github.com/fremag/memoscope.net) Dump and analyze .Net applications memory ( a gui for WinDbg and ClrMd )
- [**275**星][13d] [Py] [hugsy/defcon_27_windbg_workshop](https://github.com/hugsy/defcon_27_windbg_workshop) DEFCON 27 workshop - Modern Debugging with WinDbg Preview
- [**227**星][9m] [C++] [microsoft/windbg-samples](https://github.com/microsoft/windbg-samples) Sample extensions, scripts, and API uses for WinDbg.




***


## <a id="6d8bac8bfb5cda00c7e3bd38d64cbce3"></a>文章&&视频


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


## <a id="2110ded2aa5637fa933cc674bc33bf21"></a>工具


### <a id="63fd2c592145914e99f837cecdc5a67c"></a>新添加的1


- [**5948**星][2m] [Java] [google/android-classyshark](https://github.com/google/android-classyshark) 分析基于Android/Java的App或游戏
- [**4872**星][7m] [Java] [guardianproject/haven](https://github.com/guardianproject/haven) 通过Android应用和设备上的传感器保护自己的个人空间和财产而又不损害
- [**4752**星][7d] [C++] [facebook/redex](https://github.com/facebook/redex) Android App字节码优化器
- [**3578**星][24d] [C++] [anbox/anbox](https://github.com/anbox/anbox) 在常规GNU / Linux系统上引导完整的Android系统，基于容器
- [**1114**星][11d] [Java] [huangyz0918/androidwm](https://github.com/huangyz0918/androidwm) 一个支持不可见数字水印（隐写术）的android图像水印库。
- [**873**星][2m] [C] [504ensicslabs/lime](https://github.com/504ensicslabs/lime) LiME (formerly DMD) is a Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, such as those powered by Android. The tool supports acquiring memory either to the file system of the device or over the network. LiME is unique in that it is the first tool that allows full memory captures f…
- [**537**星][27d] [nordicsemiconductor/android-nrf-connect](https://github.com/nordicsemiconductor/android-nrf-connect) Documentation and issue tracker for nRF Connect for Android.
- [**447**星][11m] [Kotlin] [shadowsocks/kcptun-android](https://github.com/shadowsocks/kcptun-android) kcptun for Android.
- [**408**星][2m] [CSS] [angea/pocorgtfo](https://github.com/angea/pocorgtfo) a "PoC or GTFO" mirror with extra article index, direct links and clean PDFs.
- [**404**星][1y] [Java] [testwhat/smaliex](https://github.com/testwhat/smaliex) A wrapper to get de-optimized dex from odex/oat/vdex.
- [**276**星][8m] [Py] [micropyramid/forex-python](https://github.com/micropyramid/forex-python) Foreign exchange rates, Bitcoin price index and currency conversion using ratesapi.io
- [**253**星][3m] [Py] [amimo/dcc](https://github.com/amimo/dcc) DCC (Dex-to-C Compiler) is method-based aot compiler that can translate DEX code to C code.
- [**206**星][2m] [C] [derrekr/fastboot3ds](https://github.com/derrekr/fastboot3ds) A homebrew bootloader for the Nintendo 3DS that is similar to android's fastboot.


### <a id="883a4e0dd67c6482d28a7a14228cd942"></a>新添加的




### <a id="fa49f65b8d3c71b36c6924ce51c2ca0c"></a>HotFix


- [**14478**星][26d] [Java] [tencent/tinker](https://github.com/tencent/tinker) Tinker is a hot-fix solution library for Android, it supports dex, library and resources update without reinstall apk.
- [**3431**星][13d] [Java] [meituan-dianping/robust](https://github.com/meituan-dianping/robust) Robust is an Android HotFix solution with high compatibility and high stability. Robust can fix bugs immediately without a reboot.
- [**1111**星][5m] [Java] [manbanggroup/phantom](https://github.com/manbanggroup/phantom)  唯一零 Hook 稳定占坑类 Android 热更新插件化方案


### <a id="ec395c8f974c75963d88a9829af12a90"></a>打包


- [**5028**星][1m] [Java] [meituan-dianping/walle](https://github.com/meituan-dianping/walle) Android Signature V2 Scheme签名下的新一代渠道包打包神器


### <a id="767078c52aca04c452c095f49ad73956"></a>收集




### <a id="17408290519e1ca7745233afea62c43c"></a>各类App


- [**12203**星][14d] [Java] [signalapp/signal-android](https://github.com/signalapp/Signal-Android) A private messenger for Android.


### <a id="7f353b27e45b5de6b0e6ac472b02cbf1"></a>Xposed


- [**8597**星][26d] [Java] [android-hacker/virtualxposed](https://github.com/android-hacker/virtualxposed) A simple app to use Xposed without root, unlock the bootloader or modify system image, etc.
- [**2470**星][6m] [taichi-framework/taichi](https://github.com/taichi-framework/taichi) A framework to use Xposed module with or without Root/Unlock bootloader, supportting Android 5.0 ~ 10.0
- [**1963**星][27d] [Java] [elderdrivers/edxposed](https://github.com/elderdrivers/edxposed) Elder driver Xposed Framework.
- [**1702**星][1y] [Java] [ac-pm/inspeckage](https://github.com/ac-pm/inspeckage) Android Package Inspector - dynamic analysis with api hooks, start unexported activities and more. (Xposed Module)
- [**1593**星][26d] [Java] [tiann/epic](https://github.com/tiann/epic) Dynamic java method AOP hook for Android(continution of Dexposed on ART), Supporting 4.0~10.0
- [**1291**星][27d] [Java] [android-hacker/exposed](https://github.com/android-hacker/exposed) A library to use Xposed without root or recovery(or modify system image etc..).
- [**782**星][7m] [Java] [blankeer/mdwechat](https://github.com/blankeer/mdwechat) 一个能让微信 Material Design 化的 Xposed 模块
- [**633**星][21d] [Java] [ganyao114/sandhook](https://github.com/ganyao114/sandhook) Android ART Hook/Native Inline Hook/Single Instruction Hook - support 4.4 - 10.0 32/64 bit - Xposed API Compat
- [**475**星][2m] [Java] [tornaco/x-apm](https://github.com/tornaco/x-apm) 应用管理 Xposed
- [**321**星][1y] [C] [smartdone/dexdump](https://github.com/smartdone/dexdump) 一个用来快速脱一代壳的工具（稍微改下就可以脱类抽取那种壳）（Android）
- [**302**星][12d] [bigsinger/androididchanger](https://github.com/bigsinger/androididchanger) Xposed Module for Changing Android Device Info
- [**289**星][14d] [Java] [ganyao114/sandvxposed](https://github.com/ganyao114/sandvxposed) Xposed environment without root (OS 5.0 - 10.0)
- [**213**星][1y] [Kotlin] [paphonb/androidp-ify](https://github.com/paphonb/androidp-ify) [Xposed] Use features introduced in Android P on your O+ Device!
- [**201**星][1y] [C] [gtoad/android_inline_hook](https://github.com/gtoad/android_inline_hook) Build an so file to automatically do the android_native_hook work. Supports thumb-2/arm32 and ARM64 ! With this, tools like Xposed can do android native hook.


### <a id="50f63dce18786069de2ec637630ff167"></a>加壳&&脱壳


- [**1757**星][7m] [C++] [wrbug/dumpdex](https://github.com/wrbug/dumpdex) Android脱壳
- [**1438**星][3m] [C++] [vaibhavpandeyvpz/apkstudio](https://github.com/vaibhavpandeyvpz/apkstudio) Open-source, cross platform Qt based IDE for reverse-engineering Android application packages.
- [**807**星][3m] [C] [strazzere/android-unpacker](https://github.com/strazzere/android-unpacker) Android Unpacker presented at Defcon 22: Android Hacker Protection Level 0
- [**691**星][1m] [YARA] [rednaga/apkid](https://github.com/rednaga/apkid) Android Application Identifier for Packers, Protectors, Obfuscators and Oddities - PEiD for Android
- [**356**星][2m] [Java] [patrickfav/uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) A cli tool that helps signing and zip aligning single or multiple Android application packages (APKs) with either debug or provided release certificates. It supports v1, v2 and v3 Android signing scheme has an embedded debug keystore and auto verifies after signing.
- [**313**星][5m] [Shell] [1n3/reverseapk](https://github.com/1n3/reverseapk) Quickly analyze and reverse engineer Android packages


### <a id="596b6cf8fd36bc4c819335f12850a915"></a>HOOK


- [**1468**星][3m] [C] [iqiyi/xhook](https://github.com/iqiyi/xhook) a PLT (Procedure Linkage Table) hook library for Android native ELF 
- [**1466**星][2m] [C++] [jmpews/hookzz](https://github.com/jmpews/hookzz) a hook framework for arm/arm64/ios/android, and [dev] branch is being refactored.
- [**795**星][7m] [C++] [aslody/whale](https://github.com/aslody/whale) Hook Framework for Android/IOS/Linux/MacOS
- [**524**星][6m] [Java] [aslody/andhook](https://github.com/asLody/AndHook) Android dynamic instrumentation framework
- [**344**星][7m] [C] [turing-technician/fasthook](https://github.com/turing-technician/fasthook) Android ART Hook


### <a id="5afa336e229e4c38ad378644c484734a"></a>Emulator&&模拟器


- [**1474**星][1y] [C++] [f1xpl/openauto](https://github.com/f1xpl/openauto) AndroidAuto headunit emulator
- [**518**星][7m] [Java] [limboemu/limbo](https://github.com/limboemu/limbo) Limbo is a QEMU-based emulator for Android. It currently supports PC & ARM emulation for Intel x86 and ARM architecture. See our wiki
    - 重复区段: [模拟器->QEMU->工具->新添加的](#82072558d99a6cf23d4014c0ae5b420a) |
- [**466**星][3m] [Java] [strazzere/anti-emulator](https://github.com/strazzere/anti-emulator) Android Anti-Emulator


### <a id="0a668d220ce74e11ed2738c4e3ae3c9e"></a>IDA




### <a id="bb9f8e636857320abf0502c19af6c763"></a>Debug&&调试


- [**10738**星][17d] [Java] [konloch/bytecode-viewer](https://github.com/konloch/bytecode-viewer) A Java 8+ Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More)
- [**6708**星][9m] [Java] [amitshekhariitbhu/android-debug-database](https://github.com/amitshekhariitbhu/android-debug-database) A library for debugging android databases and shared preferences - Make Debugging Great Again


### <a id="f975a85510f714ec3cc2551e868e75b8"></a>Malware&&恶意代码


- [**422**星][4m] [Shell] [ashishb/android-malware](https://github.com/ashishb/android-malware) Collection of android malware samples
- [**347**星][2m] [Java] [droidefense/engine](https://github.com/droidefense/engine) Droidefense: Advance Android Malware Analysis Framework


### <a id="1d83ca6d8b02950be10ac8e4b8a2d976"></a>Obfuscate&&混淆


- [**3059**星][1m] [Java] [calebfenton/simplify](https://github.com/calebfenton/simplify) Generic Android Deobfuscator
- [**290**星][4m] [C] [shadowsocks/simple-obfs-android](https://github.com/shadowsocks/simple-obfs-android) A simple obfuscating tool for Android


### <a id="6d2b758b3269bac7d69a2d2c8b45194c"></a>ReverseEngineering


- [**9178**星][10d] [Java] [ibotpeaches/apktool](https://github.com/ibotpeaches/apktool) A tool for reverse engineering Android apk files
- [**1967**星][26d] [Java] [genymobile/gnirehtet](https://github.com/genymobile/gnirehtet) Gnirehtet provides reverse tethering for Android
- [**577**星][2m] [C++] [secrary/andromeda](https://github.com/secrary/andromeda) Andromeda - Interactive Reverse Engineering Tool for Android Applications
- [**437**星][7m] [maddiestone/androidappre](https://github.com/maddiestone/androidappre) Android App Reverse Engineering Workshop
- [**265**星][9m] [Dockerfile] [cryptax/androidre](https://github.com/cryptax/androidre) 用于Android 逆向的 Docker 容器
- [**244**星][7d] [C++] [strazzere/android-scripts](https://github.com/strazzere/android-scripts) Android逆向脚本收集
    - 重复区段: [IDA->插件->Android](#66052f824f5054aa0f70785a2389a478) |




***


## <a id="f0493b259e1169b5ddd269b13cfd30e6"></a>文章&&视频


- 2019.12 [aliyun_xz] [Android智能终端系统的安全加固（上）](https://xz.aliyun.com/t/6852)
- 2019.11 [venus_seebug] [Android勒索病毒分析（上）](https://paper.seebug.org/1085/)


# <a id="069664f347ae73b1370c4f5a2ec9da9f"></a>Apple&&iOS&&iXxx


***


## <a id="58cd9084afafd3cd293564c1d615dd7f"></a>工具


### <a id="d0108e91e6863289f89084ff09df39d0"></a>新添加的


- [**10902**星][12d] [Objective-C] [flipboard/flex](https://github.com/flipboard/flex) An in-app debugging and exploration tool for iOS
- [**7992**星][2m] [Py] [facebook/chisel](https://github.com/facebook/chisel) Chisel is a collection of LLDB commands to assist debugging iOS apps.
- [**5764**星][3m] [Objective-C] [square/ponydebugger](https://github.com/square/ponydebugger) Remote network and data debugging for your native iOS app using Chrome Developer Tools
- [**4627**星][16d] [C] [google/ios-webkit-debug-proxy](https://github.com/google/ios-webkit-debug-proxy) A DevTools proxy (Chrome Remote Debugging Protocol) for iOS devices (Safari Remote Web Inspector).
- [**4343**星][13d] [Swift] [signalapp/signal-ios](https://github.com/signalapp/Signal-iOS) A private messenger for iOS.
- [**3653**星][4m] [C] [facebook/fishhook](https://github.com/facebook/fishhook) A library that enables dynamically rebinding symbols in Mach-O binaries running on iOS.
- [**3280**星][2m] [Swift] [yagiz/bagel](https://github.com/yagiz/bagel) a little native network debugging tool for iOS
- [**3202**星][4m] [Objective-C] [naituw/ipapatch](https://github.com/naituw/ipapatch) Patch iOS Apps, The Easy Way, Without Jailbreak.
- [**2838**星][12d] [Objective-C] [facebook/idb](https://github.com/facebook/idb) idb is a flexible command line interface for automating iOS simulators and devices
- [**2731**星][22d] [Makefile] [theos/theos](https://github.com/theos/theos) A cross-platform suite of tools for building and deploying software for iOS and other platforms.
- [**2683**星][4m] [Objective-C] [dantheman827/ios-app-signer](https://github.com/dantheman827/ios-app-signer) This is an app for OS X that can (re)sign apps and bundle them into ipa files that are ready to be installed on an iOS device.
- [**2681**星][1m] [Objective-C] [kjcracks/clutch](https://github.com/kjcracks/clutch) Fast iOS executable dumper
- [**2020**星][20d] [Objective-C] [ios-control/ios-deploy](https://github.com/ios-control/ios-deploy) Install and debug iPhone apps from the command line, without using Xcode
- [**1774**星][1y] [aozhimin/ios-monitor-platform](https://github.com/aozhimin/ios-monitor-platform) 
- [**1676**星][28d] [Swift] [pmusolino/wormholy](https://github.com/pmusolino/wormholy) iOS network debugging, like a wizard 🧙‍♂️
- [**1574**星][22d] [ivrodriguezca/re-ios-apps](https://github.com/ivrodriguezca/re-ios-apps) A completely free, open source and online course about Reverse Engineering iOS Applications.
- [**1239**星][2m] [michalmalik/osx-re-101](https://github.com/michalmalik/osx-re-101) OSX/iOS逆向资源收集
- [**996**星][2m] [Objective-C] [lmirosevic/gbdeviceinfo](https://github.com/lmirosevic/gbdeviceinfo) Detects the hardware, software and display of the current iOS or Mac OS X device at runtime.
- [**815**星][7d] [JS] [cypress-io/cypress-example-recipes](https://github.com/cypress-io/cypress-example-recipes) Various recipes for testing common scenarios with Cypress
- [**766**星][12d] [Shell] [aqzt/kjyw](https://github.com/aqzt/kjyw) 快捷运维，代号kjyw，项目基于shell、python，运维脚本工具库，收集各类运维常用工具脚本，实现快速安装nginx、mysql、php、redis、nagios、运维经常使用的脚本等等...
- [**634**星][1y] [Swift] [phynet/ios-url-schemes](https://github.com/phynet/ios-url-schemes)  a github solution from my gist of iOS list for urls schemes
- [**498**星][25d] [Swift] [google/science-journal-ios](https://github.com/google/science-journal-ios) Use the sensors in your mobile devices to perform science experiments. Science doesn’t just happen in the classroom or lab—tools like Science Journal let you see how the world works with just your phone.
- [**468**星][8m] [C++] [everettjf/machoexplorer](https://github.com/everettjf/machoexplorer) MachO文件查看器，支持Windows和macOS
- [**466**星][24d] [pixelcyber/thor](https://github.com/pixelcyber/thor) HTTP Sniffer/Capture on iOS for Network Debug & Inspect.
- [**430**星][11m] [captainarash/the_holy_book_of_x86](https://github.com/captainarash/the_holy_book_of_x86) A simple guide to x86 architecture, assembly, memory management, paging, segmentation, SMM, BIOS....
- [**380**星][11m] [C] [coolstar/electra1131](https://github.com/coolstar/electra1131) electra1131: Electra for iOS 11.0 - 11.3.1
- [**337**星][2m] [C] [trailofbits/cb-multios](https://github.com/trailofbits/cb-multios) DARPA Challenges Sets for Linux, Windows, and macOS
- [**305**星][7d] [Swift] [securing/iossecuritysuite](https://github.com/securing/iossecuritysuite) iOS platform security & anti-tampering Swift library
- [**244**星][18d] [C++] [s0uthwest/futurerestore](https://github.com/s0uthwest/futurerestore) iOS upgrade and downgrade tool utilizing SHSH blobs
- [**238**星][6m] [JS] [we11cheng/wcshadowrocket](https://github.com/we11cheng/wcshadowrocket) iOS Shadowrocket(砸壳重签,仅供参考,添加节点存在问题)。另一个fq项目potatso源码参见:
- [**231**星][3m] [Swift] [shadowsocksr-live/ishadowsocksr](https://github.com/shadowsocksr-live/ishadowsocksr) ShadowsocksR for iOS, come from


### <a id="7037d96c1017978276cb920f65be2297"></a>XCode


- [**1388**星][14d] [Swift] [johnno1962/injectioniii](https://github.com/johnno1962/injectioniii) Re-write of Injection for Xcode in (mostly) Swift4
- [**562**星][19d] [Objective-C] [hdb-li/lldebugtool](https://github.com/hdb-li/lldebugtool) LLDebugTool is a debugging tool for developers and testers that can help you analyze and manipulate data in non-xcode situations.




***


## <a id="c97bbe32bbd26c72ceccb43400e15bf1"></a>文章&&视频




# <a id="0ae4ddb81ff126789a7e08b0768bd693"></a>Cuckoo


***


## <a id="5830a8f8fb3af1a336053d84dd7330a1"></a>工具


### <a id="f2b5c44c2107db2cec6c60477c6aa1d0"></a>新添加的


- [**4015**星][3m] [JS] [cuckoosandbox/cuckoo](https://github.com/cuckoosandbox/cuckoo) Cuckoo Sandbox is an automated dynamic malware analysis system
- [**303**星][2m] [Py] [hatching/vmcloak](https://github.com/hatching/vmcloak) Automated Virtual Machine Generation and Cloaking for Cuckoo Sandbox.
- [**236**星][6m] [Py] [cuckoosandbox/community](https://github.com/cuckoosandbox/community) Repository of modules and signatures contributed by the community
- [**236**星][3m] [Py] [brad-sp/cuckoo-modified](https://github.com/brad-sp/cuckoo-modified) Modified edition of cuckoo
- [**222**星][1y] [PHP] [cuckoosandbox/monitor](https://github.com/cuckoosandbox/monitor) The new Cuckoo Monitor.
- [**218**星][3m] [Shell] [blacktop/docker-cuckoo](https://github.com/blacktop/docker-cuckoo) Cuckoo Sandbox Dockerfile




***


## <a id="ec0a441206d9a2fe1625dce0a679d466"></a>文章&&视频


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


### <a id="6c4841dd91cb173093ea2c8d0b557e71"></a>工具


#### <a id="3a577a5b4730a1b5b3b325269509bb0a"></a>DynamoRIO


- [**1373**星][13d] [C] [dynamorio/drmemory](https://github.com/dynamorio/drmemory) Memory Debugger for Windows, Linux, Mac, and Android
- [**1212**星][10d] [C] [dynamorio/dynamorio](https://github.com/dynamorio/dynamorio) Dynamic Instrumentation Tool Platform


#### <a id="ff0abe26a37095f6575195950e0b7f94"></a>新添加的


- [**246**星][4m] [C] [ampotos/dynstruct](https://github.com/ampotos/dynstruct) Reverse engineering tool for automatic structure recovering and memory use analysis based on DynamoRIO and Capstone


#### <a id="928642a55eff34b6b52622c6862addd2"></a>与其他工具交互






### <a id="9479ce9f475e4b9faa4497924a2e40fc"></a>文章&&视频


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


### <a id="fe5a6d7f16890542c9e60857706edfde"></a>工具


#### <a id="78a2edf9aa41eb321436cb150ea70a54"></a>新添加的


- [**298**星][1m] [C] [vusec/vuzzer](https://github.com/vusec/vuzzer) depends heavily on a modeified version of DataTracker, which in turn depends on LibDFT pintool.


#### <a id="e6a829abd8bbc5ad2e5885396e3eec04"></a>与其他工具交互


##### <a id="e129288dfadc2ab0890667109f93a76d"></a>未分类


- [**933**星][12m] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |[DBI->Frida->工具->与其他工具交互->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |[DBI->Frida->工具->与其他工具交互->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja






### <a id="226190bea6ceb98ee5e2b939a6515fac"></a>文章&&视频






***


## <a id="f24f1235fd45a1aa8d280eff1f03af7e"></a>Frida


### <a id="a5336a0f9e8e55111bda45c8d74924c1"></a>工具


#### <a id="6d3c24e43835420063f9ca50ba805f15"></a>Frida


- [**4398**星][9d] [Makefile] [frida/frida](https://github.com/frida/frida) Clone this repo to build Frida


#### <a id="54836a155de0c15b56f43634cd9cfecf"></a>新添加的


- [**1150**星][24d] [JS] [alonemonkey/frida-ios-dump](https://github.com/alonemonkey/frida-ios-dump) pull decrypted ipa from jailbreak device
- [**632**星][9d] [Py] [igio90/dwarf](https://github.com/igio90/dwarf) Full featured multi arch/os debugger built on top of PyQt5 and frida
- [**546**星][19d] [JS] [nccgroup/house](https://github.com/nccgroup/house) 运行时手机 App 分析工具包, 带Web GUI
- [**478**星][12d] [JS] [iddoeldor/frida-snippets](https://github.com/iddoeldor/frida-snippets) Hand-crafted Frida examples
- [**416**星][3m] [C] [frida/frida-python](https://github.com/frida/frida-python) Frida Python bindings
- [**398**星][12m] [Py] [dstmath/frida-unpack](https://github.com/dstmath/frida-unpack) 基于Frida的脱壳工具
- [**316**星][16d] [C] [frida/frida-core](https://github.com/frida/frida-core) Frida core library intended for static linking into bindings
- [**298**星][29d] [JS] [chichou/bagbak](https://github.com/ChiChou/bagbak) Yet another frida based iOS dumpdecrypted
- [**293**星][3m] [JS] [smartdone/frida-scripts](https://github.com/smartdone/frida-scripts) 一些frida脚本
- [**278**星][8m] [Py] [nightbringer21/fridump](https://github.com/nightbringer21/fridump) A universal memory dumper using Frida
- [**250**星][1y] [Py] [igio90/frick](https://github.com/igio90/frick) aka the first debugger built on top of frida
- [**228**星][8d] [JS] [frenchyeti/dexcalibur](https://github.com/frenchyeti/dexcalibur) Dynamic binary instrumentation tool designed for Android application and powered by Frida. It disassembles dex, analyzes it statically, generates hooks, discovers reflected methods, stores intercepted data and does new things from it. Its aim is to be an all-in-one Android reverse engineering platform.
- [**227**星][14d] [C] [frida/frida-gum](https://github.com/frida/frida-gum) Low-level code instrumentation library used by frida-core


#### <a id="74fa0c52c6104fd5656c93c08fd1ba86"></a>与其他工具交互


##### <a id="00a86c65a84e58397ee54e85ed57feaf"></a>未分类


- [**570**星][1y] [Java] [federicodotta/brida](https://github.com/federicodotta/brida) The new bridge between Burp Suite and Frida!


##### <a id="d628ec92c9eea0c4b016831e1f6852b3"></a>IDA


- [**933**星][12m] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->工具->与其他工具交互->BinaryNinja](#f9008a00e2bbc7535c88602aa79c8fd8) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja


##### <a id="f9008a00e2bbc7535c88602aa79c8fd8"></a>BinaryNinja


- [**933**星][12m] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - 重复区段: [IDA->插件->调试->DBI数据](#0fbd352f703b507853c610a664f024d1) |[DBI->IntelPin->工具->与其他工具交互->未分类](#e129288dfadc2ab0890667109f93a76d) |[DBI->Frida->工具->与其他工具交互->IDA](#d628ec92c9eea0c4b016831e1f6852b3) |
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja


##### <a id="ac053c4da818ca587d57711d2ff66278"></a>Radare2


- [**370**星][25d] [JS] [nowsecure/r2frida](https://github.com/nowsecure/r2frida) Radare2 and Frida better together.
    - 重复区段: [Radare2->插件->与其他工具交互->未分类](#dfe53924d678f9225fc5ece9413b890f) |






### <a id="a1a7e3dd7091b47384c75dba8f279caf"></a>文章&&视频


- 2019.07 [hackertor] [Dwarf – Full Featured Multi Arch/Os Debugger Built On Top Of PyQt5 And Frida](https://hackertor.com/2019/07/13/dwarf-full-featured-multi-arch-os-debugger-built-on-top-of-pyqt5-and-frida/)
- 2019.05 [nsfocus_blog] [Frida应用基础及 APP https证书验证破解](http://blog.nsfocus.net/frida%e5%ba%94%e7%94%a8%e5%9f%ba%e7%a1%80%e5%8f%8a-app-https%e8%af%81%e4%b9%a6%e9%aa%8c%e8%af%81%e7%a0%b4%e8%a7%a3/)
- 2019.05 [nsfocus_blog] [Frida应用基础及 APP https证书验证破解](http://blog.nsfocus.net/frida-application-foundation-app-https-certificate-verification-cracking-2/)
- 2019.05 [nsfocus_blog] [Frida应用基础及APP https证书验证破解](http://blog.nsfocus.net/frida-application-foundation-app-https-certificate-verification-cracking/)
- 2019.05 [CodeColorist] [Trace child process with frida on macOS](https://medium.com/p/3b8f0f953f3d)
- 2019.05 [360_anquanke_learning] [FRIDA脚本系列（四）更新篇：几个主要机制的大更新](https://www.anquanke.com/post/id/177597/)
- 2019.03 [360_anquanke_learning] [FRIDA脚本系列（三）超神篇：百度AI“调教”抖音AI](https://www.anquanke.com/post/id/175621/)
- 2019.03 [securityinnovation_blog] [Setting up Frida Without Jailbreak on the Latest iOS 12.1.4 Device](https://blog.securityinnovation.com/frida)
- 2019.02 [nowsecure_blog] [Frida 12.3 Debuts New Crash Reporting Feature](https://www.nowsecure.com/blog/2019/02/07/frida-12-3-debuts-new-crash-reporting-feature/)
- 2019.01 [fuzzysecurity_tutorials] [Windows Hacking 之：ApplicationIntrospection & Hooking With Frida](http://fuzzysecurity.com/tutorials/29.html)
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




***


## <a id="5a9974bfcf7cdf9b05fe7a7dc5272213"></a>其他




# <a id="d3690e0b19c784e104273fe4d64b2362"></a>工具-其他


***


## <a id="1d9dec1320a5d774dc8e0e7604edfcd3"></a>新添加的


- [**19651**星][2m] [Jupyter Notebook] [camdavidsonpilon/probabilistic-programming-and-bayesian-methods-for-hackers](https://github.com/camdavidsonpilon/probabilistic-programming-and-bayesian-methods-for-hackers) aka "Bayesian Methods for Hackers": An introduction to Bayesian methods + probabilistic programming with a computation/understanding-first, mathematics-second point of view. All in pure Python ;)
- [**13183**星][26d] [Py] [corentinj/real-time-voice-cloning](https://github.com/corentinj/real-time-voice-cloning) Clone a voice in 5 seconds to generate arbitrary speech in real-time
- [**11174**星][7d] [Java] [oracle/graal](https://github.com/oracle/graal) Run Programs Faster Anywhere
- [**11106**星][2m] [Jupyter Notebook] [selfteaching/the-craft-of-selfteaching](https://github.com/selfteaching/the-craft-of-selfteaching) One has no future if one couldn't teach themself.
- [**10107**星][8d] [Go] [goharbor/harbor](https://github.com/goharbor/harbor) An open source trusted cloud native registry project that stores, signs, and scans content.
- [**7685**星][7d] [Go] [git-lfs/git-lfs](https://github.com/git-lfs/git-lfs) Git extension for versioning large files
- [**6954**星][13d] [Go] [nats-io/nats-server](https://github.com/nats-io/nats-server) High-Performance server for NATS, the cloud native messaging system.
- [**6844**星][2m] [Go] [sqshq/sampler](https://github.com/sqshq/sampler) A tool for shell commands execution, visualization and alerting. Configured with a simple YAML file.
- [**6440**星][9m] [HTML] [open-power-workgroup/hospital](https://github.com/open-power-workgroup/hospital) OpenPower工作组收集汇总的医院开放数据
- [**6284**星][27d] [Py] [seatgeek/fuzzywuzzy](https://github.com/seatgeek/fuzzywuzzy) Fuzzy String Matching in Python
- [**5870**星][6m] [JS] [haotian-wang/google-access-helper](https://github.com/haotian-wang/google-access-helper) 谷歌访问助手破解版
- [**5845**星][2m] [Gnuplot] [nasa-jpl/open-source-rover](https://github.com/nasa-jpl/open-source-rover) A build-it-yourself, 6-wheel rover based on the rovers on Mars!
- [**5811**星][7m] [JS] [sindresorhus/fkill-cli](https://github.com/sindresorhus/fkill-cli) Fabulously kill processes. Cross-platform.
- [**5715**星][8m] [C] [xoreaxeaxeax/movfuscator](https://github.com/xoreaxeaxeax/movfuscator) C编译器，编译的二进制文件只有1个代码块。
- [**5674**星][22d] [JS] [swagger-api/swagger-editor](https://github.com/swagger-api/swagger-editor) Swagger Editor
- [**5653**星][16d] [Go] [casbin/casbin](https://github.com/casbin/casbin) An authorization library that supports access control models like ACL, RBAC, ABAC in Golang
- [**5317**星][7d] [Py] [mlflow/mlflow](https://github.com/mlflow/mlflow) Open source platform for the machine learning lifecycle
- [**5163**星][3m] [Py] [ytisf/thezoo](https://github.com/ytisf/thezoo) A repository of LIVE malwares for your own joy and pleasure. theZoo is a project created to make the possibility of malware analysis open and available to the public.
- [**4990**星][1m] [Py] [snare/voltron](https://github.com/snare/voltron) A hacky debugger UI for hackers
- [**4928**星][13d] [ASP] [hq450/fancyss](https://github.com/hq450/fancyss) fancyss is a project providing tools to across the GFW on asuswrt/merlin based router.
- [**4868**星][9d] [Shell] [denisidoro/navi](https://github.com/denisidoro/navi) An interactive cheatsheet tool for the command-line
- [**4838**星][10d] [Go] [gcla/termshark](https://github.com/gcla/termshark) A terminal UI for tshark, inspired by Wireshark
- [**4793**星][8m] [Py] [10se1ucgo/disablewintracking](https://github.com/10se1ucgo/disablewintracking) Uses some known methods that attempt to minimize tracking in Windows 10
- [**4710**星][8d] [C++] [paddlepaddle/paddle-lite](https://github.com/PaddlePaddle/Paddle-Lite) Multi-platform high performance deep learning inference engine (『飞桨』多平台高性能深度学习预测引擎）
- [**4630**星][6m] [powershell/win32-openssh](https://github.com/powershell/win32-openssh) Win32 port of OpenSSH
- [**4575**星][11m] [Py] [ecthros/uncaptcha2](https://github.com/ecthros/uncaptcha2) defeating the latest version of ReCaptcha with 91% accuracy
- [**4551**星][1y] [C] [upx/upx](https://github.com/upx/upx) UPX - the Ultimate Packer for eXecutables
- [**4549**星][8d] [C++] [mozilla/rr](https://github.com/mozilla/rr) 记录与重放App的调试执行过程
- [**4485**星][18d] [TypeScript] [apis-guru/graphql-voyager](https://github.com/apis-guru/graphql-voyager) 
- [**4339**星][12m] [Py] [lennylxx/ipv6-hosts](https://github.com/lennylxx/ipv6-hosts) Fork of
- [**4256**星][11m] [JS] [butterproject/butter-desktop](https://github.com/butterproject/butter-desktop) All the free parts of Popcorn Time
- [**4243**星][9d] [Rust] [timvisee/ffsend](https://github.com/timvisee/ffsend) Easily and securely share files from the command line
- [**4039**星][1m] [JS] [sigalor/whatsapp-web-reveng](https://github.com/sigalor/whatsapp-web-reveng) WhatsApp Web API逆向与重新实现
- [**4023**星][2m] [Java] [jesusfreke/smali](https://github.com/jesusfreke/smali) smali/baksmali
- [**3936**星][13d] [Go] [dexidp/dex](https://github.com/dexidp/dex) OpenID Connect Identity (OIDC) and OAuth 2.0 Provider with Pluggable Connectors
- [**3916**星][7d] [Py] [angr/angr](https://github.com/angr/angr) A powerful and user-friendly binary analysis platform!
- [**3908**星][14d] [Rust] [svenstaro/genact](https://github.com/svenstaro/genact) a nonsense activity generator
- [**3907**星][1m] [C] [aquynh/capstone](https://github.com/aquynh/capstone) Capstone disassembly/disassembler framework: Core (Arm, Arm64, BPF, EVM, M68K, M680X, MOS65xx, Mips, PPC, RISCV, Sparc, SystemZ, TMS320C64x, Web Assembly, X86, X86_64, XCore) + bindings.
- [**3876**星][7d] [C++] [baldurk/renderdoc](https://github.com/baldurk/renderdoc) RenderDoc is a stand-alone graphics debugging tool.
- [**3841**星][8m] [Go] [eranyanay/1m-go-websockets](https://github.com/eranyanay/1m-go-websockets) handling 1M websockets connections in Go
- [**3832**星][2m] [Objective-C] [sveinbjornt/sloth](https://github.com/sveinbjornt/sloth) Mac app that shows all open files, directories and sockets in use by all running processes. Nice GUI for lsof.
- [**3749**星][2m] [Go] [microsoft/ethr](https://github.com/microsoft/ethr) Ethr is a Network Performance Measurement Tool for TCP, UDP & HTTP.
- [**3731**星][13d] [Go] [hashicorp/consul-template](https://github.com/hashicorp/consul-template) Template rendering, notifier, and supervisor for
- [**3681**星][11d] [jjqqkk/chromium](https://github.com/jjqqkk/chromium) Chromium browser with SSL VPN. Use this browser to unblock websites.
- [**3675**星][8d] [HTML] [hamukazu/lets-get-arrested](https://github.com/hamukazu/lets-get-arrested) This project is intended to protest against the police in Japan
- [**3647**星][8d] [JS] [lesspass/lesspass](https://github.com/lesspass/lesspass) 
- [**3612**星][17d] [HTML] [consensys/smart-contract-best-practices](https://github.com/consensys/smart-contract-best-practices) A guide to smart contract security best practices
- [**3538**星][4m] [Shell] [chengr28/revokechinacerts](https://github.com/chengr28/revokechinacerts) Revoke Chinese certificates.
- [**3525**星][8d] [Pascal] [cheat-engine/cheat-engine](https://github.com/cheat-engine/cheat-engine) Cheat Engine. A development environment focused on modding
- [**3464**星][15d] [C] [cyan4973/xxhash](https://github.com/cyan4973/xxhash) Extremely fast non-cryptographic hash algorithm
- [**3269**星][27d] [C] [microsoft/windows-driver-samples](https://github.com/microsoft/windows-driver-samples) This repo contains driver samples prepared for use with Microsoft Visual Studio and the Windows Driver Kit (WDK). It contains both Universal Windows Driver and desktop-only driver samples.
- [**3266**星][12d] [C] [virustotal/yara](https://github.com/virustotal/yara) The pattern matching swiss knife
- [**3255**星][7d] [C] [mikebrady/shairport-sync](https://github.com/mikebrady/shairport-sync) AirPlay audio player. Shairport Sync adds multi-room capability with Audio Synchronisation
- [**3234**星][8d] [Java] [oldmanpushcart/greys-anatomy](https://github.com/oldmanpushcart/greys-anatomy) Java诊断工具
- [**3215**星][27d] [JS] [koenkk/zigbee2mqtt](https://github.com/koenkk/zigbee2mqtt) Zigbee
- [**3210**星][1m] [TypeScript] [google/incremental-dom](https://github.com/google/incremental-dom) An in-place DOM diffing library
- [**3210**星][11d] [C] [tmate-io/tmate](https://github.com/tmate-io/tmate) Instant Terminal Sharing
- [**3205**星][2m] [Shell] [gfw-breaker/ssr-accounts](https://github.com/gfw-breaker/ssr-accounts) 一键部署Shadowsocks服务；免费Shadowsocks账号分享；免费SS账号分享; 翻墙；无界，自由门，SquirrelVPN
- [**3145**星][1y] [Shell] [toyodadoubi/doubi](https://github.com/toyodadoubi/doubi) 一个逗比写的各种逗比脚本~
- [**3120**星][10d] [C] [meetecho/janus-gateway](https://github.com/meetecho/janus-gateway) Janus WebRTC Server
- [**3113**星][28d] [CSS] [readthedocs/sphinx_rtd_theme](https://github.com/readthedocs/sphinx_rtd_theme) Sphinx theme for readthedocs.org
- [**3106**星][7d] [C] [qemu/qemu](https://github.com/qemu/qemu) Official QEMU mirror. Please see
- [**3065**星][9d] [Go] [tencent/bk-cmdb](https://github.com/tencent/bk-cmdb) 蓝鲸智云配置平台(BlueKing CMDB)
- [**3062**星][1y] [Swift] [zhuhaow/spechtlite](https://github.com/zhuhaow/spechtlite) A rule-based proxy for macOS
- [**3061**星][20d] [C] [unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn) Unicorn CPU emulator framework (ARM, AArch64, M68K, Mips, Sparc, X86)
- [**3046**星][4m] [C++] [google/robotstxt](https://github.com/google/robotstxt) The repository contains Google's robots.txt parser and matcher as a C++ library (compliant to C++11).
- [**2991**星][1y] [PHP] [owner888/phpspider](https://github.com/owner888/phpspider) 《我用爬虫一天时间“偷了”知乎一百万用户，只为证明PHP是世界上最好的语言 》所使用的程序
- [**2962**星][14d] [Objective-C] [google/santa](https://github.com/google/santa) 用于Mac系统的二进制文件白名单/黑名单系统
- [**2962**星][8d] [Py] [quantaxis/quantaxis](https://github.com/quantaxis/quantaxis) 支持任务调度 分布式部署的 股票/期货/自定义市场 数据/回测/模拟/交易/可视化 纯本地PAAS量化解决方案
- [**2895**星][10d] [C] [libfuse/sshfs](https://github.com/libfuse/sshfs) A network filesystem client to connect to SSH servers
- [**2876**星][7m] [C] [p-h-c/phc-winner-argon2](https://github.com/p-h-c/phc-winner-argon2) The password hash Argon2, winner of PHC
- [**2850**星][8d] [C] [lxc/lxc](https://github.com/lxc/lxc) LXC - Linux Containers
- [**2840**星][5m] [Py] [instantbox/instantbox](https://github.com/instantbox/instantbox) Get a clean, ready-to-go Linux box in seconds.
- [**2825**星][15d] [Py] [espressif/esptool](https://github.com/espressif/esptool) ESP8266 and ESP32 serial bootloader utility
- [**2820**星][1m] [Assembly] [cirosantilli/x86-bare-metal-examples](https://github.com/cirosantilli/x86-bare-metal-examples) 几十个用于学习 x86 系统编程的小型操作系统
- [**2802**星][9m] [Py] [plasma-disassembler/plasma](https://github.com/plasma-disassembler/plasma) Plasma is an interactive disassembler for x86/ARM/MIPS. It can generates indented pseudo-code with colored syntax.
- [**2763**星][1m] [JS] [trufflesuite/ganache-cli](https://github.com/trufflesuite/ganache-cli) Fast Ethereum RPC client for testing and development
- [**2755**星][7d] [C++] [qtox/qtox](https://github.com/qtox/qtox) qTox is a chat, voice, video, and file transfer IM client using the encrypted peer-to-peer Tox protocol.
- [**2746**星][8d] [C] [processhacker/processhacker](https://github.com/processhacker/processhacker) A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware.
- [**2735**星][7d] [TypeScript] [webhintio/hint](https://github.com/webhintio/hint) 
- [**2648**星][3m] [Py] [drivendata/cookiecutter-data-science](https://github.com/drivendata/cookiecutter-data-science) A logical, reasonably standardized, but flexible project structure for doing and sharing data science work.
- [**2619**星][8m] [leandromoreira/linux-network-performance-parameters](https://github.com/leandromoreira/linux-network-performance-parameters) Learn where some of the network sysctl variables fit into the Linux/Kernel network flow
- [**2610**星][2m] [Swift] [zhuhaow/nekit](https://github.com/zhuhaow/nekit) A toolkit for Network Extension Framework
- [**2600**星][21d] [JS] [knownsec/kcon](https://github.com/knownsec/kcon) KCon is a famous Hacker Con powered by Knownsec Team.
- [**2598**星][8d] [JS] [popcorn-official/popcorn-desktop](https://github.com/popcorn-official/popcorn-desktop) Popcorn Time is a multi-platform, free software BitTorrent client that includes an integrated media player. Desktop ( Windows / Mac / Linux ) a Butter-Project Fork
- [**2588**星][1m] [pditommaso/awesome-pipeline](https://github.com/pditommaso/awesome-pipeline) A curated list of awesome pipeline toolkits inspired by Awesome Sysadmin
- [**2555**星][1m] [C] [esnet/iperf](https://github.com/esnet/iperf) A TCP, UDP, and SCTP network bandwidth measurement tool
- [**2495**星][2m] [Java] [jboss-javassist/javassist](https://github.com/jboss-javassist/javassist) Java bytecode engineering toolkit
- [**2480**星][8d] [Go] [adguardteam/adguardhome](https://github.com/adguardteam/adguardhome) Network-wide ads & trackers blocking DNS server
- [**2472**星][11m] [JS] [weixin/miaow](https://github.com/weixin/Miaow) A set of plugins for Sketch include drawing links & marks, UI Kit & Color sync, font & text replacing.
- [**2463**星][13d] [JS] [vitaly-t/pg-promise](https://github.com/vitaly-t/pg-promise) PostgreSQL interface for Node.js
- [**2366**星][7d] [Java] [mock-server/mockserver](https://github.com/mock-server/mockserver) MockServer enables easy mocking of any system you integrate with via HTTP or HTTPS with clients written in Java, JavaScript and Ruby. MockServer also includes a proxy that introspects all proxied traffic including encrypted SSL traffic and supports Port Forwarding, Web Proxying (i.e. HTTP proxy), HTTPS Tunneling Proxying (using HTTP CONNECT) and…
- [**2351**星][8d] [C] [domoticz/domoticz](https://github.com/domoticz/domoticz) monitor and configure various devices like: Lights, Switches, various sensors/meters like Temperature, Rain, Wind, UV, Electra, Gas, Water and much more
- [**2342**星][3m] [Go] [vuvuzela/vuvuzela](https://github.com/vuvuzela/vuvuzela) Private messaging system that hides metadata
- [**2330**星][1m] [JS] [pa11y/pa11y](https://github.com/pa11y/pa11y) Pa11y is your automated accessibility testing pal
- [**2317**星][10d] [C] [tsl0922/ttyd](https://github.com/tsl0922/ttyd) Share your terminal over the web
- [**2272**星][1m] [C] [moby/hyperkit](https://github.com/moby/hyperkit) A toolkit for embedding hypervisor capabilities in your application
- [**2271**星][22d] [JS] [talkingdata/inmap](https://github.com/talkingdata/inmap) 大数据地理可视化
- [**2246**星][16d] [dumb-password-rules/dumb-password-rules](https://github.com/dumb-password-rules/dumb-password-rules) Shaming sites with dumb password rules.
- [**2201**星][11d] [Go] [google/mtail](https://github.com/google/mtail) extract whitebox monitoring data from application logs for collection in a timeseries database
- [**2187**星][21d] [C++] [google/bloaty](https://github.com/google/bloaty) Bloaty McBloatface: a size profiler for binaries
- [**2171**星][14d] [C] [armmbed/mbedtls](https://github.com/armmbed/mbedtls) An open source, portable, easy to use, readable and flexible SSL library
- [**2168**星][16d] [getlantern/lantern-binaries](https://github.com/getlantern/lantern-binaries) Lantern installers binary downloads.
- [**2123**星][16d] [Assembly] [pret/pokered](https://github.com/pret/pokered) disassembly of Pokémon Red/Blue
- [**2105**星][7d] [goq/telegram-list](https://github.com/goq/telegram-list) List of telegram groups, channels & bots // Список интересных групп, каналов и ботов телеграма // Список чатов для программистов
- [**2081**星][8d] [C] [flatpak/flatpak](https://github.com/flatpak/flatpak) Linux application sandboxing and distribution framework
- [**2071**星][30d] [Go] [theupdateframework/notary](https://github.com/theupdateframework/notary) Notary is a project that allows anyone to have trust over arbitrary collections of data
- [**2047**星][6m] [Go] [maxmcd/webtty](https://github.com/maxmcd/webtty) Share a terminal session over WebRTC
- [**2032**星][7d] [C++] [openthread/openthread](https://github.com/openthread/openthread) OpenThread released by Google is an open-source implementation of the Thread networking protocol
- [**2006**星][9m] [C] [dekunukem/nintendo_switch_reverse_engineering](https://github.com/dekunukem/nintendo_switch_reverse_engineering) A look at inner workings of Joycon and Nintendo Switch
- [**1992**星][25d] [Swift] [github/softu2f](https://github.com/github/softu2f) Software U2F authenticator for macOS
- [**1990**星][4m] [swiftonsecurity/sysmon-config](https://github.com/swiftonsecurity/sysmon-config) Sysmon configuration file template with default high-quality event tracing
- [**1983**星][2m] [C++] [asmjit/asmjit](https://github.com/asmjit/asmjit) Complete x86/x64 JIT and AOT Assembler for C++
- [**1958**星][26d] [C#] [mathewsachin/captura](https://github.com/mathewsachin/captura) Capture Screen, Audio, Cursor, Mouse Clicks and Keystrokes
- [**1939**星][2m] [C] [microsoft/procdump-for-linux](https://github.com/microsoft/procdump-for-linux) Linux 版本的 ProcDump
- [**1902**星][7d] [Go] [solo-io/gloo](https://github.com/solo-io/gloo) An Envoy-Powered API Gateway
- [**1901**星][3m] [Go] [minishift/minishift](https://github.com/minishift/minishift) Run OpenShift 3.x locally
- [**1880**星][14d] [C++] [mhammond/pywin32](https://github.com/mhammond/pywin32) Python for Windows (pywin32) Extensions
- [**1861**星][4m] [Java] [adoptopenjdk/jitwatch](https://github.com/adoptopenjdk/jitwatch) Log analyser / visualiser for Java HotSpot JIT compiler. Inspect inlining decisions, hot methods, bytecode, and assembly. View results in the JavaFX user interface.
- [**1849**星][11m] [C++] [googlecreativelab/open-nsynth-super](https://github.com/googlecreativelab/open-nsynth-super) Open NSynth Super is an experimental physical interface for the NSynth algorithm
- [**1848**星][29d] [C] [github/glb-director](https://github.com/github/glb-director) GitHub Load Balancer Director and supporting tooling.
- [**1846**星][8m] [Py] [netflix-skunkworks/stethoscope](https://github.com/Netflix-Skunkworks/stethoscope) Personalized, user-focused recommendations for employee information security.
- [**1841**星][2m] [C] [retroplasma/earth-reverse-engineering](https://github.com/retroplasma/earth-reverse-engineering) Reversing Google's 3D satellite mode
- [**1841**星][13d] [C++] [acidanthera/lilu](https://github.com/acidanthera/Lilu) Arbitrary kext and process patching on macOS
- [**1835**星][1y] [Java] [yeriomin/yalpstore](https://github.com/yeriomin/yalpstore) Download apks from Google Play Store
- [**1830**星][7d] [C++] [pytorch/glow](https://github.com/pytorch/glow) Compiler for Neural Network hardware accelerators
- [**1829**星][1y] [Py] [jinnlynn/genpac](https://github.com/jinnlynn/genpac) PAC/Dnsmasq/Wingy file Generator, working with gfwlist, support custom rules.
- [**1827**星][2m] [Go] [influxdata/kapacitor](https://github.com/influxdata/kapacitor) Open source framework for processing, monitoring, and alerting on time series data
- [**1819**星][13d] [Py] [trailofbits/manticore](https://github.com/trailofbits/manticore) 动态二进制分析工具，支持符号执行（symbolic execution）、污点分析（taint analysis）、运行时修改。
- [**1788**星][28d] [Go] [gdamore/tcell](https://github.com/gdamore/tcell) Tcell is an alternate terminal package, similar in some ways to termbox, but better in others.
- [**1777**星][18d] [PHP] [ezyang/htmlpurifier](https://github.com/ezyang/htmlpurifier) Standards compliant HTML filter written in PHP
- [**1776**星][13d] [C++] [apitrace/apitrace](https://github.com/apitrace/apitrace) Tools for tracing OpenGL, Direct3D, and other graphics APIs
- [**1759**星][12d] [C] [google/wuffs](https://github.com/google/wuffs) Wrangling Untrusted File Formats Safely
- [**1747**星][8d] [17mon/china_ip_list](https://github.com/17mon/china_ip_list) 
- [**1743**星][12m] [JS] [puppeteer/examples](https://github.com/puppeteer/examples) Use case-driven examples for using Puppeteer and headless chrome
- [**1740**星][8d] [PHP] [wordpress/wordpress-coding-standards](https://github.com/wordpress/wordpress-coding-standards) PHP_CodeSniffer rules (sniffs) to enforce WordPress coding conventions
- [**1694**星][14d] [Go] [hashicorp/memberlist](https://github.com/hashicorp/memberlist) Golang package for gossip based membership and failure detection
- [**1693**星][3m] [Py] [anorov/cloudflare-scrape](https://github.com/anorov/cloudflare-scrape) A Python module to bypass Cloudflare's anti-bot page.
- [**1693**星][7d] [TSQL] [brentozarultd/sql-server-first-responder-kit](https://github.com/brentozarultd/sql-server-first-responder-kit) sp_Blitz, sp_BlitzCache, sp_BlitzFirst, sp_BlitzIndex, and other SQL Server scripts for health checks and performance tuning.
- [**1665**星][6m] [C++] [microsoft/detours](https://github.com/microsoft/detours) Detours is a software package for monitoring and instrumenting API calls on Windows. It is distributed in source code form.
- [**1659**星][7d] [Java] [apache/geode](https://github.com/apache/geode) Apache Geode
- [**1655**星][6m] [C] [easyhook/easyhook](https://github.com/easyhook/easyhook) The reinvention of Windows API Hooking
- [**1654**星][3m] [JS] [tylerbrock/mongo-hacker](https://github.com/tylerbrock/mongo-hacker) MongoDB Shell Enhancements for Hackers
- [**1647**星][3m] [Py] [boppreh/keyboard](https://github.com/boppreh/keyboard) Hook and simulate global keyboard events on Windows and Linux.
- [**1627**星][9d] [sarojaba/awesome-devblog](https://github.com/sarojaba/awesome-devblog) 어썸데브블로그. 국내 개발 블로그 모음(only 실명으로).
- [**1620**星][14d] [JS] [efforg/privacybadger](https://github.com/efforg/privacybadger) Privacy Badger is a browser extension that automatically learns to block invisible trackers.
- [**1600**星][8d] [C++] [lief-project/lief](https://github.com/lief-project/lief) Library to Instrument Executable Formats
- [**1599**星][9m] [JS] [localtunnel/server](https://github.com/localtunnel/server) server for localtunnel.me
- [**1580**星][1y] [C] [qihoo360/phptrace](https://github.com/qihoo360/phptrace) A tracing and troubleshooting tool for PHP scripts.
- [**1577**星][1m] [Objective-C] [ealeksandrov/provisionql](https://github.com/ealeksandrov/provisionql) Quick Look plugin for apps and provisioning profile files
- [**1563**星][12d] [C] [codahale/bcrypt-ruby](https://github.com/codahale/bcrypt-ruby)  Ruby binding for the OpenBSD bcrypt() password hashing algorithm, allowing you to easily store a secure hash of your users' passwords.
- [**1562**星][17d] [C] [p-gen/smenu](https://github.com/p-gen/smenu) Terminal utility that reads words from standard input or from a file and creates an interactive selection window just below the cursor. The selected word(s) are sent to standard output for further processing.
- [**1560**星][14d] [Java] [gchq/gaffer](https://github.com/gchq/Gaffer) A large-scale entity and relation database supporting aggregation of properties
- [**960**星][7m] [PHP] [jenssegers/optimus](https://github.com/jenssegers/optimus)  id transformation With this library, you can transform your internal id's to obfuscated integers based on Knuth's integer has和
- [**906**星][7m] [C++] [dfhack/dfhack](https://github.com/DFHack/dfhack) Memory hacking library for Dwarf Fortress and a set of tools that use it
- [**891**星][11m] [JS] [levskaya/jslinux-deobfuscated](https://github.com/levskaya/jslinux-deobfuscated) An old version of Mr. Bellard's JSLinux rewritten to be human readable, hand deobfuscated and annotated.
- [**698**星][1y] [Jupyter Notebook] [anishathalye/obfuscated-gradients](https://github.com/anishathalye/obfuscated-gradients) Obfuscated Gradients Give a False Sense of Security: Circumventing Defenses to Adversarial Examples
- [**656**星][1y] [Rust] [endgameinc/xori](https://github.com/endgameinc/xori) Xori is an automation-ready disassembly and static analysis library for PE32, 32+ and shellcode
- [**653**星][9m] [Jupyter Notebook] [supercowpowers/data_hacking](https://github.com/SuperCowPowers/data_hacking) Data Hacking Project
- [**626**星][13d] [PowerShell] [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) sysmon配置模块收集
- [**576**星][5m] [nshalabi/sysmontools](https://github.com/nshalabi/sysmontools) Utilities for Sysmon
- [**566**星][10m] [JS] [raineorshine/solgraph](https://github.com/raineorshine/solgraph) Visualize Solidity control flow for smart contract security analysis.
- [**520**星][28d] [mhaggis/sysmon-dfir](https://github.com/mhaggis/sysmon-dfir) Sources, configuration and how to detect evil things utilizing Microsoft Sysmon.
- [**519**星][4m] [Java] [java-deobfuscator/deobfuscator](https://github.com/java-deobfuscator/deobfuscator) Java 代码反混淆工具
- [**502**星][8m] [JS] [mindedsecurity/jstillery](https://github.com/mindedsecurity/jstillery) Advanced JavaScript Deobfuscation via Partial Evaluation
- [**472**星][1y] [ksluckow/awesome-symbolic-execution](https://github.com/ksluckow/awesome-symbolic-execution) A curated list of awesome symbolic execution resources including essential research papers, lectures, videos, and tools.
- [**444**星][11m] [C++] [ntquery/scylla](https://github.com/ntquery/scylla) Imports Reconstructor
- [**443**星][11m] [Batchfile] [ion-storm/sysmon-config](https://github.com/ion-storm/sysmon-config) Advanced Sysmon configuration, Installer & Auto Updater with high-quality event tracing
- [**405**星][2m] [Go] [retroplasma/flyover-reverse-engineering](https://github.com/retroplasma/flyover-reverse-engineering) Reversing Apple's 3D satellite mode
- [**403**星][17d] [Py] [crytic/slither](https://github.com/crytic/slither) Static Analyzer for Solidity
- [**382**星][1y] [HTML] [maestron/reverse-engineering-tutorials](https://github.com/maestron/reverse-engineering-tutorials) Reverse Engineering Tutorials
- [**342**星][12m] [Ruby] [calebfenton/dex-oracle](https://github.com/calebfenton/dex-oracle) A pattern based Dalvik deobfuscator which uses limited execution to improve semantic analysis
- [**303**星][1m] [C] [nagyd/sdlpop](https://github.com/nagyd/sdlpop) An open-source port of Prince of Persia, based on the disassembly of the DOS version.
- [**302**星][14d] [Py] [baderj/domain_generation_algorithms](https://github.com/baderj/domain_generation_algorithms) 域名生成算法
- [**281**星][7d] [C] [tomb5/tomb5](https://github.com/tomb5/tomb5) Chronicles Disassembly translated to C source code.
- [**264**星][2m] [Assembly] [pret/pokeyellow](https://github.com/pret/pokeyellow) Disassembly of Pokemon Yellow
- [**236**星][4m] [JS] [consensys/surya](https://github.com/consensys/surya) A set of utilities for exploring Solidity contracts
- [**210**星][11m] [Java] [neo23x0/fnord](https://github.com/neo23x0/fnord) Pattern Extractor for Obfuscated Code


***


## <a id="4fe330ae3e5ce0b39735b1bfea4528af"></a>angr


- [**526**星][7d] [Py] [angr/angr-doc](https://github.com/angr/angr-doc) Documentation for the angr suite


***


## <a id="324874bb7c3ead94eae6f1fa1af4fb68"></a>Debug&&调试


- [**1430**星][7d] [Go] [google/gapid](https://github.com/google/gapid) Graphics API Debugger
- [**1410**星][8d] [Go] [cosmos72/gomacro](https://github.com/cosmos72/gomacro) Interactive Go interpreter and debugger with REPL, Eval, generics and Lisp-like macros
- [**1402**星][7d] [C++] [eteran/edb-debugger](https://github.com/eteran/edb-debugger) edb is a cross platform AArch32/x86/x86-64 debugger.
- [**1262**星][3m] [Go] [solo-io/squash](https://github.com/solo-io/squash) The debugger for microservices
- [**1142**星][4m] [C++] [cgdb/cgdb](https://github.com/cgdb/cgdb) Console front-end to the GNU debugger
- [**1110**星][18d] [C] [blacksphere/blackmagic](https://github.com/blacksphere/blackmagic) In application debugger for ARM Cortex microcontrollers.
- [**868**星][5m] [Py] [derekselander/lldb](https://github.com/derekselander/lldb) A collection of LLDB aliases/regexes and Python scripts to aid in your debugging sessions
- [**822**星][7d] [C++] [tasvideos/bizhawk](https://github.com/tasvideos/bizhawk) BizHawk is a multi-system emulator written in C#. BizHawk provides nice features for casual gamers such as full screen, and joypad support in addition to full rerecording and debugging tools for all system cores.
- [**557**星][1m] [C#] [microsoft/miengine](https://github.com/microsoft/miengine) The Visual Studio MI Debug Engine ("MIEngine") provides an open-source Visual Studio Debugger extension that works with MI-enabled debuggers such as gdb, lldb, and clrdbg.
- [**519**星][1y] [C] [wubingzheng/memleax](https://github.com/wubingzheng/memleax) debugs memory leak of running process. Not maintained anymore, try `libleak` please.
- [**460**星][4m] [C++] [emoon/prodbg](https://github.com/emoon/prodbg) Debugging the way it's meant to be done
- [**415**星][2m] [C++] [simonkagstrom/kcov](https://github.com/simonkagstrom/kcov) Code coverage tool for compiled programs, Python and Bash which uses debugging information to collect and report data without special compilation options
- [**399**星][3m] [C++] [cobaltfusion/debugviewpp](https://github.com/cobaltfusion/debugviewpp) DebugView++, collects, views, filters your application logs, and highlights information that is important to you!
- [**336**星][20d] [Py] [pdbpp/pdbpp](https://github.com/pdbpp/pdbpp) pdb++, a drop-in replacement for pdb (the Python debugger)
- [**331**星][8m] [Py] [romanvm/python-web-pdb](https://github.com/romanvm/python-web-pdb) Web-based remote UI for Python's PDB debugger
- [**306**星][25d] [Java] [widdix/aws-s3-virusscan](https://github.com/widdix/aws-s3-virusscan) Free Antivirus for S3 Buckets
- [**287**星][2m] [Py] [sosreport/sos](https://github.com/sosreport/sos) A unified tool for collecting system logs and other debug information
- [**279**星][1m] [C++] [changeofpace/viviennevmm](https://github.com/changeofpace/viviennevmm) VivienneVMM is a stealthy debugging framework implemented via an Intel VT-x hypervisor.
- [**269**星][3m] [Py] [mariovilas/winappdbg](https://github.com/mariovilas/winappdbg) WinAppDbg Debugger
- [**267**星][11m] [Py] [ionelmc/python-manhole](https://github.com/ionelmc/python-manhole) Debugging manhole for python applications.
- [**248**星][1m] [Py] [quantopian/qdb](https://github.com/quantopian/qdb) Quantopian Remote Debugger for Python
- [**239**星][5m] [C++] [facebook/ds2](https://github.com/facebook/ds2) Debug server for lldb.
- [**239**星][7m] [Py] [beeware/bugjar](https://github.com/beeware/bugjar) A interactive graphical debugger for Python code.
- [**232**星][7m] [C++] [strivexjun/xantidebug](https://github.com/strivexjun/xantidebug) VMProtect 3.x Anti-debug Method Improved
- [**231**星][2m] [Py] [gilligan/vim-lldb](https://github.com/gilligan/vim-lldb) lldb debugger integration plugin for vim
- [**220**星][8m] [letoram/senseye](https://github.com/letoram/senseye) Dynamic Visual Debugging / Reverse Engineering Toolsuite
- [**215**星][25d] [Py] [nteseyes/pylane](https://github.com/nteseyes/pylane) An python vm injector with debug tools, based on gdb.
- [**210**星][8d] [C++] [thalium/icebox](https://github.com/thalium/icebox) Virtual Machine Introspection, Tracing & Debugging
- [**207**星][2m] [C] [joyent/mdb_v8](https://github.com/joyent/mdb_v8) postmortem debugging for Node.js and other V8-based programs
- [**200**星][5m] [C++] [rainers/cv2pdb](https://github.com/rainers/cv2pdb) converter of DMD CodeView/DWARF debug information to PDB files


***


## <a id="9d0f15756c4435d1ea79c21fcfda101f"></a>新添加的11




***


## <a id="9f8d3f2c9e46fbe6c25c22285c8226df"></a>BAP




***


## <a id="2683839f170250822916534f1db22eeb"></a>BinNavi


- [**378**星][1m] [C++] [google/binexport](https://github.com/google/binexport) 将反汇编以Protocol Buffer的形式导出为PostgreSQL数据库, 导入到BinNavi中使用
    - 重复区段: [IDA->插件->导入导出->BinNavi](#11139e7d6db4c1cef22718868f29fe12) |


***


## <a id="0971f295b0f67dc31b7aa45caf3f588f"></a>Decompiler&&反编译器


- [**20619**星][9d] [Java] [skylot/jadx](https://github.com/skylot/jadx) dex 转 java 的反编译器
- [**7628**星][22d] [Java] [java-decompiler/jd-gui](https://github.com/java-decompiler/jd-gui) A standalone Java Decompiler GUI
- [**3091**星][1m] [Java] [deathmarine/luyten](https://github.com/deathmarine/luyten) An Open Source Java Decompiler Gui for Procyon
- [**1842**星][1y] [Java] [jindrapetrik/jpexs-decompiler](https://github.com/jindrapetrik/jpexs-decompiler) JPEXS Free Flash Decompiler
- [**1636**星][11m] [Java] [fesh0r/fernflower](https://github.com/fesh0r/fernflower) Unofficial mirror of FernFlower Java decompiler (All pulls should be submitted upstream)
- [**1428**星][7d] [Py] [rocky/python-uncompyle6](https://github.com/rocky/python-uncompyle6) Python反编译器，跨平台
- [**1075**星][3m] [Py] [storyyeller/krakatau](https://github.com/storyyeller/krakatau) Java decompiler, assembler, and disassembler
- [**762**星][11m] [C++] [comaeio/porosity](https://github.com/comaeio/porosity) *UNMAINTAINED* Decompiler and Security Analysis tool for Blockchain-based Ethereum Smart-Contracts
- [**669**星][7d] [C#] [uxmal/reko](https://github.com/uxmal/reko) Reko is a binary decompiler.
- [**663**星][10m] [C++] [zrax/pycdc](https://github.com/zrax/pycdc) C++ python bytecode disassembler and decompiler
- [**534**星][5m] [Java] [java-decompiler/jd-eclipse](https://github.com/java-decompiler/jd-eclipse) A Java Decompiler Eclipse plugin
- [**340**星][1m] [C#] [steamdatabase/valveresourceformat](https://github.com/steamdatabase/valveresourceformat) Valve's Source 2 resource file format (also known as Stupid Valve Format) parser and decompiler.
- [**319**星][25d] [C++] [silverf0x/rpcview](https://github.com/silverf0x/rpcview) RpcView is a free tool to explore and decompile Microsoft RPC interfaces
- [**309**星][11d] [Java] [leibnitz27/cfr](https://github.com/leibnitz27/cfr) This is the public repository for the CFR Java decompiler
- [**271**星][7m] [Shell] [venshine/decompile-apk](https://github.com/venshine/decompile-apk) APK 反编译
- [**239**星][2m] [Java] [kwart/jd-cmd](https://github.com/kwart/jd-cmd) Command line Java Decompiler
- [**238**星][1m] [Java] [ata4/bspsrc](https://github.com/ata4/bspsrc) A Source engine map decompiler
- [**229**星][14d] [C#] [icsharpcode/avaloniailspy](https://github.com/icsharpcode/avaloniailspy) Avalonia-based .NET Decompiler (port of ILSpy)
- [**228**星][1y] [C++] [wwwg/wasmdec](https://github.com/wwwg/wasmdec) WebAssembly to C decompiler
- [**223**星][24d] [C++] [boomerangdecompiler/boomerang](https://github.com/BoomerangDecompiler/boomerang) Boomerang Decompiler - Fighting the code-rot :)


***


## <a id="2df6d3d07e56381e1101097d013746a0"></a>Disassemble&&反汇编


- [**1363**星][29d] [C] [zyantific/zydis](https://github.com/zyantific/zydis) 快速的轻量级x86/x86-64 反汇编库
- [**1347**星][11m] [Rust] [das-labor/panopticon](https://github.com/das-labor/panopticon) A libre cross-platform disassembler.
- [**874**星][10m] [C++] [wisk/medusa](https://github.com/wisk/medusa) An open source interactive disassembler
- [**823**星][2m] [C++] [redasmorg/redasm](https://github.com/redasmorg/redasm) The OpenSource Disassembler
- [**819**星][7d] [GLSL] [khronosgroup/spirv-cross](https://github.com/khronosgroup/spirv-cross)  a practical tool and library for performing reflection on SPIR-V and disassembling SPIR-V back to high level languages.
- [**621**星][3m] [C] [gdabah/distorm](https://github.com/gdabah/distorm) Powerful Disassembler Library For x86/AMD64
- [**427**星][26d] [C#] [0xd4d/iced](https://github.com/0xd4d/iced) x86/x64 disassembler, instruction decoder & encoder
- [**348**星][21d] [Ruby] [jjyg/metasm](https://github.com/jjyg/metasm) This is the main repository for metasm, a free assembler / disassembler / compiler written in ruby
- [**244**星][4m] [Py] [bontchev/pcodedmp](https://github.com/bontchev/pcodedmp) A VBA p-code disassembler


***


## <a id="975d9f08e2771fccc112d9670eae1ed1"></a>GDB


- [**6968**星][2m] [JS] [cs01/gdbgui](https://github.com/cs01/gdbgui) Browser-based frontend to gdb (gnu debugger). Add breakpoints, view the stack, visualize data structures, and more in C, C++, Go, Rust, and Fortran. Run gdbgui from the terminal and a new tab will open in your browser.
- [**6002**星][11d] [Py] [cyrus-and/gdb-dashboard](https://github.com/cyrus-and/gdb-dashboard) Modular visual interface for GDB in Python
- [**1343**星][3m] [Go] [hellogcc/100-gdb-tips](https://github.com/hellogcc/100-gdb-tips) A collection of gdb tips. 100 maybe just mean many here.
- [**448**星][2m] [Py] [scwuaptx/pwngdb](https://github.com/scwuaptx/pwngdb) gdb for pwn
- [**231**星][26d] [JS] [bet4it/hyperpwn](https://github.com/bet4it/hyperpwn) A hyper plugin to provide a flexible GDB GUI with the help of GEF, pwndbg or peda


***


## <a id="9526d018b9815156cb001ceee36f6b1d"></a>Captcha&&验证码


- [**1544**星][3m] [PHP] [mewebstudio/captcha](https://github.com/mewebstudio/captcha) Captcha for Laravel 5 & 6
- [**623**星][24d] [Ruby] [markets/invisible_captcha](https://github.com/markets/invisible_captcha) Simple and flexible spam protection solution for Rails applications.



***


## <a id="bc2b78af683e7ba983205592de8c3a7a"></a>其他




# <a id="86cb7d8f548ca76534b5828cb5b0abce"></a>Radare2


***


## <a id="0e08f9478ed8388319f267e75e2ef1eb"></a>插件&&脚本


### <a id="ec3f0b5c2cf36004c4dd3d162b94b91a"></a>Radare2


- [**11490**星][7d] [C] [radareorg/radare2](https://github.com/radareorg/radare2) unix-like reverse engineering framework and commandline tools


### <a id="6922457cb0d4b6b87a34caf39aa31dfe"></a>新添加的


- [**407**星][5m] [Py] [itayc0hen/a-journey-into-radare2](https://github.com/itayc0hen/a-journey-into-radare2) A series of tutorials about radare2 framework from
- [**329**星][11d] [TeX] [radareorg/radare2book](https://github.com/radareorg/radare2book) r1 book transcription to r2
- [**257**星][3m] [Rust] [radareorg/radeco](https://github.com/radareorg/radeco) radare2-based decompiler and symbol executor
- [**256**星][19d] [C] [radareorg/r2dec-js](https://github.com/radareorg/r2dec-js) radare2插件,将汇编代码反编译为C伪代码
- [**204**星][2m] [PowerShell] [wiredpulse/posh-r2](https://github.com/wiredpulse/posh-r2) PowerShell - Rapid Response... For the incident responder in you!


### <a id="1a6652a1cb16324ab56589cb1333576f"></a>与其他工具交互


#### <a id="dfe53924d678f9225fc5ece9413b890f"></a>未分类


- [**370**星][25d] [JS] [nowsecure/r2frida](https://github.com/nowsecure/r2frida) Radare2 and Frida better together.
    - 重复区段: [DBI->Frida->工具->与其他工具交互->Radare2](#ac053c4da818ca587d57711d2ff66278) |


#### <a id="1cfe869820ecc97204a350a3361b31a7"></a>IDA






### <a id="f7778a5392b90b03a3e23ef94a0cc3c6"></a>GUI


- [**5850**星][8d] [C++] [radareorg/cutter](https://github.com/radareorg/cutter) 逆向框架 radare2的Qt界面，iaito的升级版




***


## <a id="95fdc7692c4eda74f7ca590bb3f12982"></a>文章&&视频


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


# <a id="afb7259851922935643857c543c4b0c2"></a>BinaryNinja


***


## <a id="3034389f5aaa9d7b0be6fa7322340aab"></a>插件&&脚本


### <a id="a750ac8156aa0ff337a8639649415ef1"></a>新添加的


- [**2787**星][17d] [Py] [androguard/androguard](https://github.com/androguard/androguard) Reverse engineering, Malware and goodware analysis of Android applications ... and more (ninja !)
- [**320**星][10d] [Py] [vector35/binaryninja-api](https://github.com/vector35/binaryninja-api) Public API, examples, documentation and issues for Binary Ninja
- [**279**星][2m] [Py] [pbiernat/ripr](https://github.com/pbiernat/ripr) Package Binary Code as a Python class using Binary Ninja and Unicorn Engine


### <a id="bba1171ac550958141dfcb0027716f41"></a>与其他工具交互


#### <a id="c2f94ad158b96c928ee51461823aa953"></a>未分类




#### <a id="713fb1c0075947956651cc21a833e074"></a>IDA








***


## <a id="2d24dd6f0c01a084e88580ad22ce5b3c"></a>文章&&视频


- 2018.09 [aliyun_xz] [使用Binary Ninja调试共享库](https://xz.aliyun.com/t/2826)
- 2018.09 [kudelskisecurity] [Analyzing ARM Cortex-based MCU firmwares using Binary Ninja](https://research.kudelskisecurity.com/2018/09/25/analyzing-arm-cortex-based-mcu-firmwares-using-binary-ninja/)
- 2018.04 [trailofbits] [使用Binary Ninja的MLIL和SSA, 挖掘二进制文件的漏洞. (MLIL: Medium Level IL, 中间层IL)(SSA: Single Static Assignment)](https://blog.trailofbits.com/2018/04/04/vulnerability-modeling-with-binary-ninja/)
- 2018.01 [pediy_new_digest] [[翻译]逆向平台Binary Ninja介绍](https://bbs.pediy.com/thread-224141.htm)
- 2017.11 [_0xec] [bnpy - A python architecture plugin for Binary Ninja](https://0xec.blogspot.com/2017/11/bnpy-python-architecture-plugin-for.html)
- 2017.10 [ret2] [Untangling Exotic Architectures with Binary Ninja](http://blog.ret2.io/2017/10/17/untangling-exotic-architectures-with-binary-ninja/)
- 2017.10 [chokepoint] [Pin Visual Coverage Tool for Binary Ninja](http://www.chokepoint.net/2017/10/pin-visual-coverage-tool-for-binary.html)


# <a id="dd1e42d17eefb275a804584a848b82a6"></a>文章


***


## <a id="48d6a0efe043af4bed4cbba665a4502c"></a>新添加的




# <a id="747ddaa20f643da415284bfba9cda3a2"></a>模拟器&&虚拟机


***


## <a id="796b64906655228d8a1ff8c0dd390451"></a>QEMU


### <a id="296c7f25266b25e5ee1107dd76e40dd2"></a>工具


#### <a id="82072558d99a6cf23d4014c0ae5b420a"></a>新添加的


- [**518**星][7m] [Java] [limboemu/limbo](https://github.com/limboemu/limbo) Limbo is a QEMU-based emulator for Android. It currently supports PC & ARM emulation for Intel x86 and ARM architecture. See our wiki
    - 重复区段: [Android->工具->Emulator](#5afa336e229e4c38ad378644c484734a) |
- [**273**星][19d] [C] [beckus/qemu_stm32](https://github.com/beckus/qemu_stm32) QEMU with an STM32 microcontroller implementation
- [**242**星][10m] [C++] [revng/revng](https://github.com/revng/revng) 二进制分析工具，基于QEMU 和LLVM




### <a id="5df30a166c2473fdadf5a578d1a70e32"></a>文章&&视频






***


## <a id="a13effff89633708c814ae9410da835a"></a>其他




# <a id="2f81493de610f9b796656b269380b2de"></a>Windows


***


## <a id="b478e9a9a324c963da11437d18f04998"></a>工具


### <a id="f9fad1d4d1f0e871a174f67f63f319d8"></a>新添加的




### <a id="1afda3039b4ab9a3a1f60b179ccb3e76"></a>其他


- [**940**星][2m] [C] [basil00/divert](https://github.com/basil00/divert) 用户模式数据包拦截库，适用于Win 7/8/10
- [**840**星][21d] [C++] [henrypp/simplewall](https://github.com/henrypp/simplewall) 为Windows 过滤平台提供的配置界面
- [**712**星][1m] [Py] [diyan/pywinrm](https://github.com/diyan/pywinrm) Python实现的WinRM客户端
- [**556**星][11d] [C] [hfiref0x/winobjex64](https://github.com/hfiref0x/winobjex64) Windows对象浏览器. x64
- [**462**星][7m] [C#] [microsoft/dbgshell](https://github.com/microsoft/dbgshell) PowerShell编写的Windows调试器引擎前端
- [**411**星][9d] [C] [samba-team/samba](https://github.com/samba-team/samba) 适用于Linux和Unix的标准Windows interoperability程序套件
- [**381**星][1m] [C#] [microsoft/binskim](https://github.com/microsoft/binskim) 二进制静态分析工具，可为PE和ELF二进制格式提供安全性和正确性分析
- [**379**星][1m] [Jupyter Notebook] [microsoft/windowsdefenderatp-hunting-queries](https://github.com/microsoft/windowsdefenderatp-hunting-queries) 在MS Defender ATP中进行高级查询的示例
- [**367**星][1m] [Ruby] [winrb/winrm](https://github.com/winrb/winrm) 在Windows中使用WinRM的功能调用原生对象的SOAP库。Ruby编写
- [**364**星][1y] [PowerShell] [netspi/pesecurity](https://github.com/netspi/pesecurity) 检查PE(EXE/DLL)编译选项是否有：ASLR, DEP, SafeSEH, StrongNaming, Authenticode。PowerShell模块
- [**349**星][8d] [C#] [digitalruby/ipban](https://github.com/digitalruby/ipban) 监视Windows/Linux系统的登录失败和不良行为，并封禁对应的IP地址。高度可配置，精简且功能强大。
- [**264**星][11m] [Py] [hakril/pythonforwindows](https://github.com/hakril/pythonforwindows) 简化Python与Windows操作系统交互的库
- [**233**星][4m] [PowerShell] [microsoft/aaronlocker](https://github.com/microsoft/aaronlocker) Windows应用程序白名单
- [**232**星][9m] [Go] [masterzen/winrm](https://github.com/masterzen/winrm) Windows远程命令执行，命令行工具+库，Go编写
- [**230**星][12m] [C++] [ionescu007/simpleator](https://github.com/ionescu007/simpleator) Windows x64用户模式应用程序模拟器
- [**228**星][4m] [C] [tishion/mmloader](https://github.com/tishion/mmloader) 绕过Windows PE Loader，直接从内存中加载DLL模块（x86/x64）
- [**220**星][12m] [C++] [rexdf/commandtrayhost](https://github.com/rexdf/commandtrayhost) 监控Windows systray的命令行工具
- [**211**星][2m] [C] [leecher1337/ntvdmx64](https://github.com/leecher1337/ntvdmx64) 在64位版本上执行Windows DOS版的 NTVDM
- [**209**星][2m] [adguardteam/adguardforwindows](https://github.com/adguardteam/adguardforwindows) Windows系统范围的AdBlocker
- [**205**星][2m] [C] [jasonwhite/ducible](https://github.com/jasonwhite/ducible) 使PE和PDB的构建具有可复制性
- [**201**星][10m] [C] [hzqst/unicorn_pe](https://github.com/hzqst/unicorn_pe) 模拟Windows PE文件的代码执行，基于Unicorn


### <a id="0af4bd8ca0fd27c9381a2d1fa8b71a1f"></a>事件日志&&事件追踪&&ETW


- [**1207**星][8d] [JS] [jpcertcc/logontracer](https://github.com/jpcertcc/logontracer) 通过可视化和分析Windows事件日志来调查恶意的Windows登录
- [**526**星][14d] [PowerShell] [sbousseaden/evtx-attack-samples](https://github.com/sbousseaden/evtx-attack-samples) 与特定攻击和利用后渗透技术相关的Windows事件样例
- [**502**星][9m] [C#] [lowleveldesign/wtrace](https://github.com/lowleveldesign/wtrace) Command line tracing tool for Windows, based on ETW.
- [**436**星][8m] [PowerShell] [nsacyber/event-forwarding-guidance](https://github.com/nsacyber/Event-Forwarding-Guidance) 帮助管理员使用Windows事件转发（WEF）收集与安全相关的Windows事件日志
- [**389**星][9m] [Py] [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx) 纯Python编写的Windows事件日志解析器
- [**295**星][11d] [C#] [zodiacon/procmonx](https://github.com/zodiacon/procmonx) 通过Windows事件日志获取与Process Monitor显示的相同的信息，无需内核驱动
- [**281**星][9m] [C#] [nsacyber/windows-event-log-messages](https://github.com/nsacyber/Windows-Event-Log-Messages) 检索Windows二进制文件中嵌入的Windows事件日志消息的定义，并以discoverable的格式提供它们


### <a id="d48f038b58dc921660be221b4e302f70"></a>Sysmon




### <a id="8ed6f25b321f7b19591ce2908b30cc88"></a>WSL


- [**8495**星][1m] [microsoft/wsl](https://github.com/microsoft/WSL) Issues found on WSL
- [**2825**星][8m] [Shell] [goreliu/wsl-terminal](https://github.com/goreliu/wsl-terminal) Terminal emulator for Windows Subsystem for Linux (WSL)
- [**660**星][9d] [Shell] [wslutilities/wslu](https://github.com/wslutilities/wslu) A collection of utilities for Windows 10 Linux Subsystems


### <a id="d90b60dc79837e06d8ba2a7ee1f109d3"></a>.NET


- [**12453**星][7d] [C#] [0xd4d/dnspy](https://github.com/0xd4d/dnspy) .NET debugger and assembly editor
- [**9141**星][8d] [C#] [icsharpcode/ilspy](https://github.com/icsharpcode/ilspy) .NET Decompiler
- [**3645**星][26d] [C#] [0xd4d/de4dot](https://github.com/0xd4d/de4dot) .NET deobfuscator and unpacker.
- [**3253**星][7m] [JS] [sindresorhus/speed-test](https://github.com/sindresorhus/speed-test) Test your internet connection speed and ping using speedtest.net from the CLI
- [**1643**星][1m] [C#] [jbevain/cecil](https://github.com/jbevain/cecil) C#库, 探查/修改/生成 .NET App/库
- [**215**星][11m] [C#] [rainwayapp/warden](https://github.com/rainwayapp/warden) Warden.NET is an easy to use process management library for keeping track of processes on Windows.


### <a id="6d2fe834b7662ecdd48c17163f732daf"></a>Environment&&环境&&配置


- [**1519**星][10m] [PowerShell] [joefitzgerald/packer-windows](https://github.com/joefitzgerald/packer-windows) 使用Packer创建Vagrant boxes的模板
- [**1341**星][10d] [Go] [securitywithoutborders/hardentools](https://github.com/securitywithoutborders/hardentools) 禁用许多有危险的Windows功能
- [**1145**星][1y] [HTML] [nsacyber/windows-secure-host-baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline) Windows 10和Windows Server 2016 DoD 安全主机基准设置的配置指南
- [**1000**星][5m] [adolfintel/windows10-privacy](https://github.com/adolfintel/windows10-privacy) Win10隐私指南
- [**488**星][23d] [PowerShell] [stefanscherer/packer-windows](https://github.com/stefanscherer/packer-windows) Windows Packer 模板：Win10, Server 2016, 1709, 1803, 1809, 2019, 1903, Insider with Docker


### <a id="8bfd27b42bb75956984994b3419fb582"></a>进程注入




### <a id="b0d50ee42d53b1f88b32988d34787137"></a>DLL注入


- [**699**星][4m] [C++] [darthton/xenos](https://github.com/darthton/xenos) Windows DLL 注入器


### <a id="1c6069610d73eb4246b58d78c64c9f44"></a>代码注入




### <a id="7c1541a69da4c025a89b0571d8ce73d2"></a>内存模块




### <a id="16001cb2fae35b722deaa3b9a8e5f4d5"></a>Shellcode


- [**533**星][4m] [C++] [nytrorst/shellcodecompiler](https://github.com/nytrorst/shellcodecompiler) 将C/C ++样式代码编译成一个小的、与位置无关且无NULL的Shellcode，用于Windows（x86和x64）和Linux（x86和x64）
    - 重复区段: [Linux->工具](#89e277bca2740d737c1aeac3192f374c) |


### <a id="19cfd3ea4bd01d440efb9d4dd97a64d0"></a>VT&&虚拟化&&Hypbervisor


- [**1311**星][18d] [C] [intel/haxm](https://github.com/intel/haxm) Intel 开源的英特尔硬件加速执行管理器，通过硬件辅助的虚拟化引擎，加速 Windows/macOS 主机上的 IA emulation（(x86/ x86_64) ）
- [**1003**星][1y] [C] [ionescu007/simplevisor](https://github.com/ionescu007/simplevisor) 英特尔VT-x虚拟机管理程序，简单、可移植。支持Windows和UEFI
- [**708**星][3m] [C++] [tandasat/hyperplatform](https://github.com/tandasat/hyperplatform) 基于Intel VT-x的虚拟机管理程序，旨在在Windows上提供精简的VM-exit过滤平台
- [**561**星][11m] [C] [asamy/ksm](https://github.com/asamy/ksm) 快速、hackable且简单的x64 VT-x虚拟机管理程序，支持Windows和Linux
    - 重复区段: [Linux->工具](#89e277bca2740d737c1aeac3192f374c) |


### <a id="c3cda3278305549f4c21df25cbf638a4"></a>内核&&驱动


- [**928**星][9m] [C] [microsoft/windows-driver-frameworks](https://github.com/microsoft/windows-driver-frameworks) Windows驱动框架(WDF)
- [**760**星][13d] [axtmueller/windows-kernel-explorer](https://github.com/axtmueller/windows-kernel-explorer) Windows内核研究工具
- [**506**星][5m] [Py] [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus) Windows内核探索和跟踪工具
- [**459**星][22d] [C] [jkornev/hidden](https://github.com/jkornev/hidden) Windows驱动，带用户模式接口：隐藏文件系统和注册表对象、保护进程等
- [**278**星][7d] [PowerShell] [microsoftdocs/windows-driver-docs](https://github.com/MicrosoftDocs/windows-driver-docs) 官方Windows驱动程序工具包文档


### <a id="920b69cea1fc334bbc21a957dd0d9f6f"></a>注册表


- [**479**星][7d] [Batchfile] [chef-koch/regtweaks](https://github.com/chef-koch/regtweaks) Windows注册表调整（Win 7-Win 10）
- [**288**星][7m] [Py] [williballenthin/python-registry](https://github.com/williballenthin/python-registry) 用于对Windows NT注册表文件进行纯读取访问的Python库


### <a id="d295182c016bd9c2d5479fe0e98a75df"></a>系统调用


- [**712**星][2m] [HTML] [j00ru/windows-syscalls](https://github.com/j00ru/windows-syscalls) Windows 系统调用表(NT/2000/XP/2003/Vista/2008/7/2012/8/10)
- [**316**星][30d] [C] [hfiref0x/syscalltables](https://github.com/hfiref0x/syscalltables) Windows NT x64系统调用表




***


## <a id="3939f5e83ca091402022cb58e0349ab8"></a>文章




# <a id="dc664c913dc63ec6b98b47fcced4fdf0"></a>Linux


***


## <a id="89e277bca2740d737c1aeac3192f374c"></a>工具


- [**1422**星][2m] [C] [feralinteractive/gamemode](https://github.com/feralinteractive/gamemode) Optimise Linux system performance on demand
- [**1406**星][1m] [C++] [google/nsjail](https://github.com/google/nsjail) A light-weight process isolation tool, making use of Linux namespaces and seccomp-bpf syscall filters (with help of the kafel bpf language)
- [**884**星][8d] [C] [buserror/simavr](https://github.com/buserror/simavr) simavr is a lean, mean and hackable AVR simulator for linux & OSX
- [**751**星][17d] [Py] [korcankaraokcu/pince](https://github.com/korcankaraokcu/pince) A reverse engineering tool that'll supply the place of Cheat Engine for linux
- [**740**星][1m] [C] [yrp604/rappel](https://github.com/yrp604/rappel) A linux-based assembly REPL for x86, amd64, armv7, and armv8
- [**717**星][11d] [C] [strace/strace](https://github.com/strace/strace) strace is a diagnostic, debugging and instructional userspace utility for Linux
- [**561**星][11m] [C] [asamy/ksm](https://github.com/asamy/ksm) 快速、hackable且简单的x64 VT-x虚拟机管理程序，支持Windows和Linux
    - 重复区段: [Windows->工具->VT](#19cfd3ea4bd01d440efb9d4dd97a64d0) |
- [**559**星][1m] [Py] [autotest/autotest](https://github.com/autotest/autotest) Fully automated tests on Linux
- [**552**星][13d] [C++] [intel/linux-sgx](https://github.com/intel/linux-sgx) Intel SGX for Linux*
- [**533**星][4m] [C++] [nytrorst/shellcodecompiler](https://github.com/nytrorst/shellcodecompiler) 将C/C ++样式代码编译成一个小的、与位置无关且无NULL的Shellcode，用于Windows（x86和x64）和Linux（x86和x64）
    - 重复区段: [Windows->工具->Shellcode](#16001cb2fae35b722deaa3b9a8e5f4d5) |
- [**502**星][7m] [C] [iovisor/ply](https://github.com/iovisor/ply) Dynamic Tracing in Linux
- [**466**星][7d] [C] [libreswan/libreswan](https://github.com/libreswan/libreswan) an Internet Key Exchange (IKE) implementation for Linux.
- [**437**星][7d] [C] [facebook/openbmc](https://github.com/facebook/openbmc) OpenBMC is an open software framework to build a complete Linux image for a Board Management Controller (BMC).
- [**385**星][9m] [Shell] [microsoft/linux-vm-tools](https://github.com/microsoft/linux-vm-tools) Hyper-V Linux Guest VM Enhancements
- [**384**星][27d] [Shell] [yadominjinta/atilo](https://github.com/yadominjinta/atilo) Linux installer for termux
- [**346**星][1m] [C] [seccomp/libseccomp](https://github.com/seccomp/libseccomp) an easy to use, platform independent, interface to the Linux Kernel's syscall filtering mechanism
- [**328**星][4m] [Go] [capsule8/capsule8](https://github.com/capsule8/capsule8) 对云本地，容器和传统的基于 Linux 的服务器执行高级的行为监控
- [**280**星][24d] [Py] [facebook/fbkutils](https://github.com/facebook/fbkutils) A variety of utilities built and maintained by Facebook's Linux Kernel Team that we wish to share with the community.
- [**227**星][7m] [C] [wkz/ply](https://github.com/wkz/ply) Light-weight Dynamic Tracer for Linux


***


## <a id="f6d78e82c3e5f67d13d9f00c602c92f0"></a>文章




# <a id="3f1fde99538be4662dca6747a365640b"></a>Hook


***


## <a id="cfe974d48bbb90a930bf667c173616c7"></a>工具


- [**1228**星][1y] [Kotlin] [gh0u1l5/wechatspellbook](https://github.com/gh0u1l5/wechatspellbook) 一个使用Kotlin编写的开源微信插件框架，底层需要 Xposed 或 VirtualXposed 等Hooking框架的支持，而顶层可以轻松对接Java、Kotlin、Scala等JVM系语言。让程序员能够在几分钟内编写出简单的微信插件，随意揉捏微信的内部逻辑。
- [**1114**星][1y] [Objective-C] [yulingtianxia/fishchat](https://github.com/yulingtianxia/fishchat) Hook WeChat.app on non-jailbroken devices.
- [**1004**星][5m] [C++] [everdox/infinityhook](https://github.com/everdox/infinityhook) Hook system calls, context switches, page faults and more.
- [**757**星][20d] [Go] [thoughtworks/talisman](https://github.com/thoughtworks/talisman) By hooking into the pre-push hook provided by Git, Talisman validates the outgoing changeset for things that look suspicious - such as authorization tokens and private keys.
- [**670**星][7m] [Java] [pagalaxylab/yahfa](https://github.com/PAGalaxyLab/YAHFA) Yet Another Hook Framework for ART
- [**640**星][3m] [C++] [stevemk14ebr/polyhook](https://github.com/stevemk14ebr/polyhook) x86/x64 C++ Hooking Library
- [**568**星][7m] [Objective-C] [rpetrich/captainhook](https://github.com/rpetrich/captainhook) Common hooking/monkey patching headers for Objective-C on Mac OS X and iPhone OS. MIT licensed
- [**530**星][1y] [Objective-C++] [davidgoldman/inspectivec](https://github.com/davidgoldman/inspectivec) objc_msgSend hook for debugging/inspection purposes.
- [**509**星][11d] [C] [mohuihui/antispy](https://github.com/mohuihui/antispy) AntiSpy is a free but powerful anti virus and rootkits toolkit.It offers you the ability with the highest privileges that can detect,analyze and restore various kernel modifications and hooks.With its assistance,you can easily spot and neutralize malwares hidden from normal detectors.
- [**475**星][1y] [C++] [tandasat/ddimon](https://github.com/tandasat/ddimon) Monitoring and controlling kernel API calls with stealth hook using EPT
- [**436**星][16d] [C++] [stevemk14ebr/polyhook_2_0](https://github.com/stevemk14ebr/polyhook_2_0) C++17, x86/x64 Hooking Libary v2.0
- [**401**星][8m] [C] [darthton/hyperbone](https://github.com/darthton/hyperbone) Minimalistic VT-x hypervisor with hooks
- [**366**星][26d] [C++] [0x09al/rdpthief](https://github.com/0x09al/rdpthief) Extracting Clear Text Passwords from mstsc.exe using API Hooking.
- [**361**星][1m] [C++] [steven-michaud/hookcase](https://github.com/steven-michaud/hookcase) Tool for reverse engineering macOS/OS X
- [**339**星][5m] [C] [zeex/subhook](https://github.com/zeex/subhook) Simple hooking library for C/C++ (x86 only, 32/64-bit, no dependencies)
- [**260**星][11m] [C] [nbulischeck/tyton](https://github.com/nbulischeck/tyton) Linux内核模式Rootkit Hunter. 可检测隐藏系统模块、系统调用表Hooking、网络协议Hooking等
- [**245**星][4m] [C] [gbps/gbhv](https://github.com/gbps/gbhv) Simple x86-64 VT-x Hypervisor with EPT Hooking
- [**238**星][5m] [C] [outflanknl/dumpert](https://github.com/outflanknl/dumpert) LSASS memory dumper using direct system calls and API unhooking.
- [**233**星][22d] [C] [kubo/plthook](https://github.com/kubo/plthook) Hook function calls by replacing PLT(Procedure Linkage Table) entries.
- [**217**星][1y] [C#] [easy66/monohooker](https://github.com/easy66/monohooker) hook C# method at runtime without modify dll file (such as UnityEditor.dll)
- [**211**星][1y] [C] [suvllian/process-inject](https://github.com/suvllian/process-inject) 在Windows环境下的进程注入方法：远程线程注入、创建进程挂起注入、反射注入、APCInject、SetWindowHookEX注入


# <a id="70e64e3147675c9bcd48d4f475396e7f"></a>Monitor&&监控&&Trace&&追踪


***


## <a id="cd76e644d8ddbd385939bb17fceab205"></a>工具


- [**1407**星][7d] [C] [namhyung/uftrace](https://github.com/namhyung/uftrace) Function (graph) tracer for user-space


# <a id="28aa8187f8a1e38ca5a55aa31a5ee0c3"></a>Game&&游戏


***


## <a id="07f0c2cbf63c1d7de6f21fa43443ede3"></a>工具


- [**1124**星][12d] [C++] [crosire/reshade](https://github.com/crosire/reshade) A generic post-processing injector for games and video software.
- [**1122**星][3m] [Py] [openai/neural-mmo](https://github.com/openai/neural-mmo) Code for the paper "Neural MMO: A Massively Multiagent Game Environment for Training and Evaluating Intelligent Agents"
- [**723**星][6m] [Assembly] [cirosantilli/x86-assembly-cheat](https://github.com/cirosantilli/x86-assembly-cheat) the bulk of the x86 instruction examples with assertions.
- [**515**星][2m] [Kotlin] [jire/charlatano](https://github.com/jire/charlatano) Proves JVM cheats are viable on native games, and demonstrates the longevity against anti-cheat signature detection systems
- [**353**星][18d] [C] [liji32/sameboy](https://github.com/liji32/sameboy) Game Boy and Game Boy Color emulator written in C
- [**351**星][11d] [C#] [leaguesandbox/gameserver](https://github.com/leaguesandbox/gameserver) League Sandbox's Game Server
- [**260**星][5m] [C++] [niemand-sec/anticheat-testing-framework](https://github.com/niemand-sec/anticheat-testing-framework) Framework for testing any Anti-Cheat
- [**215**星][2m] [C] [xyzz/gamecard-microsd](https://github.com/xyzz/gamecard-microsd) microSD adapter for PlayStation Vita
- [**204**星][4m] [C++] [eternityx/deadcell-csgo](https://github.com/eternityx/deadcell-csgo) Full source to the CS:GO cheat


# <a id="09fa851959ff48f5667a2099c861eab8"></a>Malware&&恶意代码


***


## <a id="e781a59e4f4daab058732cf66f77bfb9"></a>工具


- [**1433**星][1y] [TypeScript] [pedronauck/reworm](https://github.com/pedronauck/reworm) 
- [**927**星][4m] [Py] [airbnb/binaryalert](https://github.com/airbnb/binaryalert) 实时恶意代码检测，无需服务器
- [**777**星][2m] [Py] [gosecure/malboxes](https://github.com/gosecure/malboxes) Builds malware analysis Windows VMs so that you don't have to.
- [**679**星][17d] [Py] [rurik/noriben](https://github.com/rurik/noriben) Portable, Simple, Malware Analysis Sandbox
- [**654**星][8m] [Shell] [rfxn/linux-malware-detect](https://github.com/rfxn/linux-malware-detect) Linux Malware Detection (LMD)
- [**591**星][5m] [fabrimagic72/malware-samples](https://github.com/fabrimagic72/malware-samples) 恶意软件样本
- [**563**星][2m] [Py] [certsocietegenerale/fame](https://github.com/certsocietegenerale/fame) 自动化恶意代码评估
- [**534**星][2m] [Py] [tencent/habomalhunter](https://github.com/tencent/habomalhunter) HaboMalHunter is a sub-project of Habo Malware Analysis System (
- [**488**星][29d] [C] [hasherezade/demos](https://github.com/hasherezade/demos) Demos of various injection techniques found in malware
- [**392**星][1m] [YARA] [guelfoweb/peframe](https://github.com/guelfoweb/peframe) PEframe is a open source tool to perform static analysis on Portable Executable malware and malicious MS Office documents.
- [**390**星][6m] [JS] [capacitorset/box-js](https://github.com/capacitorset/box-js) A tool for studying JavaScript malware.
- [**386**星][7d] [C#] [collinbarrett/filterlists](https://github.com/collinbarrett/filterlists) independent, comprehensive directory of filter and host lists for advertisements, trackers, malware, and annoyances.
- [**375**星][7m] [Py] [secrary/ssma](https://github.com/secrary/ssma) SSMA - Simple Static Malware Analyzer [This project is not maintained anymore]
- [**366**星][2m] [AngelScript] [inquest/malware-samples](https://github.com/inquest/malware-samples) A collection of malware samples and relevant dissection information, most probably referenced from
- [**363**星][3m] [Py] [neo23x0/munin](https://github.com/neo23x0/munin) Online hash checker for Virustotal and other services
- [**353**星][5m] [Py] [hasherezade/malware_analysis](https://github.com/hasherezade/malware_analysis) Various snippets created during malware analysis
- [**331**星][8m] [Py] [rek7/fireelf](https://github.com/rek7/fireelf) Fileless Linux Malware Framework
- [**325**星][7d] [Py] [fireeye/stringsifter](https://github.com/fireeye/stringsifter) A machine learning tool that automatically ranks strings based on their relevance for malware analysis.
- [**310**星][21d] [C#] [malware-dev/mdk-se](https://github.com/malware-dev/mdk-se) Malware's Development Kit for SE
- [**307**星][1y] [C++] [m0n0ph1/process-hollowing](https://github.com/m0n0ph1/process-hollowing) Great explanation of Process Hollowing (a Technique often used in Malware)
- [**302**星][11m] [Assembly] [guitmz/virii](https://github.com/guitmz/virii) Collection of ancient computer virus source codes
- [**302**星][4m] [JS] [hynekpetrak/malware-jail](https://github.com/hynekpetrak/malware-jail) Sandbox for semi-automatic Javascript malware analysis, deobfuscation and payload extraction. Written for Node.js
- [**283**星][7m] [Java] [katjahahn/portex](https://github.com/katjahahn/portex) Java library to analyse Portable Executable files with a special focus on malware analysis and PE malformation robustness
- [**281**星][8m] [Py] [phage-nz/ph0neutria](https://github.com/phage-nz/ph0neutria) ph0neutria is a malware zoo builder that sources samples straight from the wild. Everything is stored in Viper for ease of access and manageability.
- [**277**星][7m] [C] [rieck/malheur](https://github.com/rieck/malheur) A Tool for Automatic Analysis of Malware Behavior
- [**268**星][2m] [JS] [hynekpetrak/javascript-malware-collection](https://github.com/hynekpetrak/javascript-malware-collection) Collection of almost 40.000 javascript malware samples
- [**252**星][10m] [C++] [ramadhanamizudin/malware](https://github.com/ramadhanamizudin/malware) Malware Samples. Uploaded to GitHub for those want to analyse the code. Code mostly from:
- [**240**星][1m] [Py] [a3sal0n/falcongate](https://github.com/a3sal0n/falcongate) A smart gateway to stop hackers and Malware attacks
- [**237**星][8m] [C++] [mstfknn/malware-sample-library](https://github.com/mstfknn/malware-sample-library) Malware sample library.
- [**230**星][2m] [C++] [richkmeli/richkware](https://github.com/richkmeli/richkware) Framework for building Windows malware, written in C++
- [**212**星][2m] [Py] [eset/malware-research](https://github.com/eset/malware-research) 恶意代码分析中用到的代码/工具
- [**202**星][12d] [Py] [doomedraven/virustotalapi](https://github.com/doomedraven/virustotalapi) VirusTotal Full api


# <a id="5fdcfc70dd87360c2dddcae008076547"></a>Rootkit&&Bootkit


***


## <a id="b8d6f237c04188a10f511cd8988de28a"></a>工具


- [**1191**星][9m] [C] [f0rb1dd3n/reptile](https://github.com/f0rb1dd3n/reptile) LKM Linux rootkit
- [**722**星][8m] [C] [mempodippy/vlany](https://github.com/mempodippy/vlany) Linux LD_PRELOAD rootkit (x86 and x86_64 architectures)
- [**509**星][5m] [C] [nurupo/rootkit](https://github.com/nurupo/rootkit) Linux rootkit，针对 Ubuntu 16.04 及 10.04 (Linux 内核 4.4.0/2.6.32), 支持 i386 和 amd64
- [**426**星][1y] [C] [novicelive/research-rootkit](https://github.com/novicelive/research-rootkit) LibZeroEvil & the Research Rootkit project.
- [**387**星][2m] [milabs/awesome-linux-rootkits](https://github.com/milabs/awesome-linux-rootkits) awesome-linux-rootkits


# <a id="069468057aac03c102abdbeb7a5decf6"></a>硬件


***


## <a id="3574d46dd09566f898b407cebe9df29b"></a>固件


### <a id="649d2aece91551af8b48d29f52943804"></a>Firmware&&固件


- [**6170**星][6m] [rmerl/asuswrt-merlin](https://github.com/rmerl/asuswrt-merlin) Enhanced version of Asus's router firmware (Asuswrt) (legacy code base)
- [**3621**星][2m] [C] [atmosphere-nx/atmosphere](https://github.com/atmosphere-nx/atmosphere) Atmosphère is a work-in-progress customized firmware for the Nintendo Switch.
- [**3209**星][8d] [C] [betaflight/betaflight](https://github.com/betaflight/betaflight) Open Source Flight Controller Firmware
- [**3108**星][4m] [C++] [px4/firmware](https://github.com/px4/firmware) PX4 Autopilot Software
- [**2810**星][28d] [C] [tmk/tmk_keyboard](https://github.com/tmk/tmk_keyboard) Atmel AVR 和 Cortex-M键盘固件收集
- [**2267**星][1m] [C] [aurorawright/luma3ds](https://github.com/aurorawright/luma3ds) Noob-proof (N)3DS "Custom Firmware"
- [**1441**星][19d] [C] [tianocore/edk2](https://github.com/tianocore/edk2) A modern, feature-rich, cross-platform firmware development environment for the UEFI and PI specifications
- [**784**星][8d] [C] [fwupd/fwupd](https://github.com/fwupd/fwupd) A simple daemon to allow session software to update firmware
- [**633**星][6m] [C] [travisgoodspeed/md380tools](https://github.com/travisgoodspeed/md380tools) Python tools and patched firmware for the TYT-MD380
- [**415**星][5m] [preos-security/awesome-firmware-security](https://github.com/preos-security/awesome-firmware-security) Awesome Firmware Security & Other Helpful Documents
- [**370**星][12d] [Py] [fkie-cad/fact_core](https://github.com/fkie-cad/fact_core) Firmware Analysis and Comparison Tool
- [**284**星][5m] [C++] [rampagex/firmware-mod-kit](https://github.com/rampagex/firmware-mod-kit) Automatically exported from code.google.com/p/firmware-mod-kit
- [**279**星][1m] [Py] [cwerling/psptool](https://github.com/cwerling/psptool) Display, extract, and manipulate PSP firmware inside UEFI images
- [**237**星][11d] [Py] [avatartwo/avatar2](https://github.com/avatartwo/avatar2) targetorchestration 框架，重点是嵌入式设备固件的动态分析
- [**234**星][11m] [C] [reisyukaku/reinand](https://github.com/reisyukaku/reinand) Minimalist 3DS custom firmware.


### <a id="fff92e7d304e2c927ef3530f4d327456"></a>Intel


- [**507**星][1m] [Py] [platomav/meanalyzer](https://github.com/platomav/meanalyzer) Intel Engine Firmware Analysis Tool
- [**465**星][1y] [Py] [ptresearch/unme11](https://github.com/ptresearch/unme11) Intel ME 11.x Firmware Images Unpacker




# <a id="948dbc64bc0ff4a03296988574f5238c"></a>Crypto&&加密&&算法


***


## <a id="a6b0a9b9184fd78c8b87ccfe48a8e544"></a>工具


- [**2369**星][2m] [TeX] [crypto101/book](https://github.com/crypto101/book) Crypto 101, the introductory book on cryptography.
- [**1580**星][7d] [Go] [bitnami-labs/sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) A Kubernetes controller and tool for one-way encrypted Secrets
- [**1433**星][12d] [C++] [microsoft/seal](https://github.com/microsoft/seal) Microsoft SEAL is an easy-to-use and powerful homomorphic encryption library.
- [**832**星][13d] [Haskell] [galoisinc/cryptol](https://github.com/galoisinc/cryptol) The Language of Cryptography
- [**758**星][1y] [pfarb/awesome-crypto-papers](https://github.com/pfarb/awesome-crypto-papers) A curated list of cryptography papers, articles, tutorials and howtos.
- [**693**星][5m] [C++] [stealth/opmsg](https://github.com/stealth/opmsg) opmsg message encryption
- [**660**星][26d] [Java] [google/conscrypt](https://github.com/google/conscrypt) Conscrypt is a Java Security Provider that implements parts of the Java Cryptography Extension and Java Secure Socket Extension.
- [**482**星][3m] [C] [microsoft/symcrypt](https://github.com/microsoft/symcrypt) Cryptographic library
- [**466**星][3m] [miscreant/meta](https://github.com/miscreant/meta) 具备错误使用抗性的（Misuse-resistant ）对称加密库，支持 AES-SIV (RFC5297) 和 CHAIN/STREAM
- [**463**星][8d] [C] [skeeto/enchive](https://github.com/skeeto/enchive) Encrypted personal archives
- [**432**星][1m] [Go] [gorilla/securecookie](https://github.com/gorilla/securecookie) Package gorilla/securecookie encodes and decodes authenticated and optionally encrypted cookie values for Go web applications.
- [**380**星][21d] [C++] [msoos/cryptominisat](https://github.com/msoos/cryptominisat) An advanced SAT solver
- [**349**星][7m] [Haskell] [jpmorganchase/constellation](https://github.com/jpmorganchase/constellation) Peer-to-peer encrypted message exchange
- [**334**星][26d] [Shell] [umputun/nginx-le](https://github.com/umputun/nginx-le) Nginx with automatic let's encrypt (docker image)
- [**328**星][10d] [Py] [efforg/starttls-everywhere](https://github.com/efforg/starttls-everywhere) A system for ensuring & authenticating STARTTLS encryption between mail servers
- [**323**星][5m] [JS] [hr/crypter](https://github.com/hr/crypter) An innovative, convenient and secure cross-platform encryption app
- [**305**星][18d] [C] [jhuisi/charm](https://github.com/jhuisi/charm) A Framework for Rapidly Prototyping Cryptosystems
- [**265**星][13d] [Py] [nucypher/nucypher](https://github.com/nucypher/nucypher) A decentralized network offering accessible, intuitive, and extensible cryptographic runtimes and interfaces for secrets management and dynamic access control.
- [**253**星][13d] [C] [icing/mod_md](https://github.com/icing/mod_md) Let's Encrypt (ACME) support for Apache httpd
- [**244**星][14d] [C++] [evpo/encryptpad](https://github.com/evpo/encryptpad) Minimalist secure text editor and binary encryptor that implements RFC 4880 Open PGP format: symmetrically encrypted, compressed and integrity protected. The editor can protect files with passwords, key files or both.
- [**229**星][7m] [C] [ctz/cifra](https://github.com/ctz/cifra) A collection of cryptographic primitives targeted at embedded use.
- [**223**星][1m] [C] [libyal/libfvde](https://github.com/libyal/libfvde) Library and tools to access FileVault Drive Encryption (FVDE) encrypted volumes
- [**222**星][2m] [vixentael/my-talks](https://github.com/vixentael/my-talks) List of my talks and workshops: security engineering, applied cryptography, secure software development
- [**221**星][12m] [C] [gkdr/lurch](https://github.com/gkdr/lurch) XEP-0384: OMEMO Encryption for libpurple.
- [**220**星][2m] [Go] [cloudflare/tls-tris](https://github.com/cloudflare/tls-tris) crypto/tls, now with 100% more 1.3. THE API IS NOT STABLE AND DOCUMENTATION IS NOT GUARANTEED.
- [**203**星][5m] [Py] [nucypher/nufhe](https://github.com/nucypher/nufhe) NuCypher fully homomorphic encryption (NuFHE) library implemented in Python
- [**202**星][5m] [TeX] [decrypto-org/rupture](https://github.com/decrypto-org/rupture) A framework for BREACH and other compression-based crypto attacks
- [**200**星][7m] [C] [doublelabyrinth/how-does-navicat-encrypt-password](https://github.com/doublelabyrinth/how-does-navicat-encrypt-password) This repository tells you how Navicat encrypts database password.


# 贡献
内容为系统自动导出, 有任何问题请提issue