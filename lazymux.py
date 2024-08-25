## lazymux.py - Lazymux v4.0
##
import os, sys
import readline
from time import sleep as timeout
from core.lzmcore import *

def main():
    banner()
    print("   [01] 信息收集")
    print("   [02] 漏洞分析")
    print("   [03] 网络黑客攻击")
    print("   [04] 数据库评估")
    print("   [05] 密码攻击")
    print("   [06] 无线攻击")
    print("   [07] 逆向工程")
    print("   [08] 漏洞利用工具")
    print("   [09] 嗅探和欺骗")
    print("   [10] 报告工具")
    print("   [11] 取证工具")
    print("   [12] 压力测试")
    print("   [13] 安装 Linux Distro")
    print("   [14] Termux 实用程序")
    print("   [15] Shell 函数 [.bashrc]")
    print("   [16] 安装 CLI 游戏")
    print("   [17] 恶意软件分析")
    print("   [18] 编译器/解释器")
    print("   [19] 社会工程工具")
    print("\n   [99] 更新 Lazymux")
    print("   [00] 退出 Lazymux\n")
    lazymux = input("lzmx > set_install ")

    # 01 - Information Gathering
    if lazymux.strip() == "1" or lazymux.strip() == "01":
        print("\n    [01] Nmap: 用于网络发现和安全审计的实用程序")
        print("    [02] Red Hawk: 信息收集、漏洞扫描和爬网")
        print("    [03] D-TECT: 用于渗透测试的一体化工具")
        print("    [04] sqlmap: 自动 SQL 注入和数据库接管工具")
        print("    [05] Infoga: 用于收集电子邮件帐户信息的工具")
        print("    [06] ReconDog: 信息收集和漏洞扫描程序工具")
        print("    [07] AndroZenmap")
        print("    [08] sqlmate: SQLmap 的朋友，它将满足您对 SQLmap 的期望")
        print("    [09] AstraNmap: 用于查找计算机网络上的主机和服务的安全扫描程序")
        print("    [10] MapEye: 准确的 GPS 位置跟踪器（Android、IOS、Windows 手机）")
        print("    [11] Easymap: Nmap 快捷方式")
        print("    [12] BlackBox: 渗透测试框架")
        print("    [13] XD3v: 强大的工具，让您了解有关手机的所有基本详细信息")
        print("    [14] Crips: 该工具是在线 IP 工具的集合，可用于快速获取有关 IP 地址、网页和 DNS 记录的信息")
        print("    [15] SIR: 从网络解析 Skype 名称的最后一个已知 IP")
        print("    [16] EvilURL: 为 IDN 同形异义词攻击生成 unicode 邪恶域并对其进行检测")
        print("    [17] Striker: 侦查和漏洞扫描套件")
        print("    [18] Xshell: 工具箱")
        print("    [19] OWScan: OVID Web 扫描仪")
        print("    [20] OSIF: 开源信息 Facebook")
        print("    [21] Devploit: 简单的信息收集工具")
        print("    [22] Namechk: 基于 namechk.com 的 Osint 工具，用于检查 100 多个网站、论坛和社交网络上的用户名")
        print("    [23] AUXILE: Web 应用程序分析框架")
        print("    [24] inther: 使用 shodan、censys 和 hackertarget 收集信息")
        print("    [25] GINF: GitHub 信息收集工具")
        print("    [26] GPS 跟踪")
        print("    [27] ASU: Facebook 黑客工具包")
        print("    [28] fim: Facebook 图片下载器")
        print("    [29] MaxSubdoFinder: 用于发现子域的工具")
        print("    [30] pwnedOrNot: 用于查找受感染电子邮件帐户密码的 OSINT 工具")
        print("    [31] Mac-Lookup: 查找有关特定 Mac 地址的信息")
        print("    [32] BillCipher: 网站或 IP 地址的信息收集工具")
        print("    [33] dnsrecon: 安全评估和网络故障排除")
        print("    [34] zphisher: 自动网络钓鱼工具")
        print("    [35] Mr.SIP: 基于 SIP 的审核和攻击工具")
        print("    [36] Sherlock: 按用户名寻找社交媒体帐户")
        print("    [37] userrecon: 在超过 75 个社交网络中查找用户名")
        print("    [38] PhoneInfoga: 仅使用免费资源扫描电话号码的最先进的工具之一")
        print("    [39] SiteBroker: 基于 python 的跨平台实用程序，用于信息收集和渗透测试自动化")
        print("    [40] maigret: 从数千个网站按用户名收集某人的档案")
        print("    [41] GatheTOOL: 信息收集 - API hackertarget.com")
        print("    [42] ADB-ToolKit")
        print("    [43] TekDefense-Automater: Automater - IP URL 和 MD5 OSINT 分析")
        print("    [44] EagleEye: 跟踪你的朋友。使用图像识别和反向图像搜索查找他们的 Instagram、FB 和 Twitter 个人资料")
        print("    [45] EyeWitness: EyeWitness 旨在截取网站的屏幕截图，提供一些服务器标头信息，并在可能的情况下识别默认凭据")
        print("    [46] InSpy: 基于 python 的 LinkedIn 枚举工具")
        print("    [47] Leaked: 泄露？2.1 - 哈希码、密码和电子邮件泄露的检查工具")
        print("    [48] fierce: 用于查找非连续 IP 空间的 DNS 侦查工具")
        print("    [49] gasmask: 信息收集工具 - OSINT")
        print("    [50] osi.ig: 信息收集 （Instagram）")
        print("    [51] proxy-checker: 简单的脚本，用于检查好的和坏的代理")
        print("\n    [00] 返回主菜单\n")
        infogathering = input("lzmx > set_install ")
        if infogathering == "@":
            infogathering = ""
            for x in range(1,201):
                infogathering += f"{x} "
        if len(infogathering.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for infox in infogathering.split():
            if infox.strip() == "01" or infox.strip() == "1": nmap()
            elif infox.strip() == "02" or infox.strip() == "2": red_hawk()
            elif infox.strip() == "03" or infox.strip() == "3": dtect()
            elif infox.strip() == "04" or infox.strip() == "4": sqlmap()
            elif infox.strip() == "05" or infox.strip() == "5": infoga()
            elif infox.strip() == "06" or infox.strip() == "6": reconDog()
            elif infox.strip() == "07" or infox.strip() == "7": androZenmap()
            elif infox.strip() == "08" or infox.strip() == "8": sqlmate()
            elif infox.strip() == "09" or infox.strip() == "9": astraNmap()
            elif infox.strip() == "10": mapeye()
            elif infox.strip() == "11": easyMap()
            elif infox.strip() == "12": blackbox()
            elif infox.strip() == "13": xd3v()
            elif infox.strip() == "14": crips()
            elif infox.strip() == "15": sir()
            elif infox.strip() == "16": evilURL()
            elif infox.strip() == "17": striker()
            elif infox.strip() == "18": xshell()
            elif infox.strip() == "19": owscan()
            elif infox.strip() == "20": osif()
            elif infox.strip() == "21": devploit()
            elif infox.strip() == "22": namechk()
            elif infox.strip() == "23": auxile()
            elif infox.strip() == "24": inther()
            elif infox.strip() == "25": ginf()
            elif infox.strip() == "26": gpstr()
            elif infox.strip() == "27": asu()
            elif infox.strip() == "28": fim()
            elif infox.strip() == "29": maxsubdofinder()
            elif infox.strip() == "30": pwnedOrNot()
            elif infox.strip() == "31": maclook()
            elif infox.strip() == "32": billcypher()
            elif infox.strip() == "33": dnsrecon()
            elif infox.strip() == "34": zphisher()
            elif infox.strip() == "35": mrsip()
            elif infox.strip() == "36": sherlock()
            elif infox.strip() == "37": userrecon()
            elif infox.strip() == "38": phoneinfoga()
            elif infox.strip() == "39": sitebroker()
            elif infox.strip() == "40": maigret()
            elif infox.strip() == "41": gathetool()
            elif infox.strip() == "42": adbtk()
            elif infox.strip() == "43": tekdefense()
            elif infox.strip() == "44": eagleeye()
            elif infox.strip() == "45": eyewitness()
            elif infox.strip() == "46": inspy()
            elif infox.strip() == "47": leaked()
            elif infox.strip() == "48": fierce()
            elif infox.strip() == "49": gasmask()
            elif infox.strip() == "50": osi_ig()
            elif infox.strip() == "51": proxy_checker()
            elif infox.strip() == "00" or infox.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)

    # 02 - Vulnerability Analysis
    elif lazymux.strip() == "2" or lazymux.strip() == "02":
        print("\n    [01] Nmap: 用于网络发现和安全审计的实用程序")
        print("    [02] AndroZenmap")
        print("    [03] AstraNmap: 用于查找计算机网络上的主机和服务的安全扫描程序")
        print("    [04] Easymap: Nmap 快捷方式")
        print("    [05] Red Hawk: 信息收集、漏洞扫描和爬网")
        print("    [06] D-TECT: 用于渗透测试的一体化工具")
        print("    [07] Damn Small SQLi Scanner: 功能齐全的 SQL 注入漏洞扫描程序（支持 GET 和 POST 参数），用不到 100 行代码编写")
        print("    [08] SQLiv: 大规模 SQL 注入漏洞扫描程序")
        print("    [09] sqlmap: 自动 SQL 注入和数据库接管工具")
        print("    [10] sqlscan: Quick SQL Scanner、Dorker、Webshell 注入器 PHP")
        print("    [11] Wordpresscan: 用 Python 重写的 WPScan + 一些 WPSeku 想法")
        print("    [12] WPScan: 免费的 wordPress 安全扫描程序")
        print("    [13] sqlmate: SQLmap 的朋友，它将满足您对 SQLmap 的期望")
        print("    [14] termux-wordpresscan")
        print("    [15] TM-scanner: 适用于 Termux 的网站漏洞扫描程序")
        print("    [16] Rang3r: 多线程 IP + 端口扫描器")
        print("    [17] Striker: 侦查和漏洞扫描套件")
        print("    [18] Routersploit: 嵌入式设备的漏洞利用框架")
        print("    [19] Xshell: 工具箱")
        print("    [20] SH33LL: Shell 扫描程序")
        print("    [21] BlackBox: 渗透测试框架")
        print("    [22] XAttacker: 网站漏洞扫描器和自动漏洞利用者")
        print("    [23] OWScan: OVID Web 扫描仪")
        print("    [24] XPL-SEARCH: 在多个漏洞利用数据库中搜索漏洞")
        print("    [25] AndroBugs_Framework: 一款高效的 Android 漏洞扫描程序，可帮助开发人员或黑客发现 Android 应用中的潜在安全漏洞")
        print("    [26] Clickjacking-Tester: 一个 python 脚本，旨在检查网站是否容易受到点击劫持并创建 poc")
        print("    [27] Sn1per: 攻击面管理平台 |Sn1perSecurity 有限责任公司")
        print("\n    [00] 返回主菜单\n")
        vulnsys = input("lzmx > set_install ")
        if vulnsys == "@":
            vulnsys = ""
            for x in range(1,201):
                vulnsys += f"{x} "
        if len(vulnsys.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for vulnx in vulnsys.split():
            if vulnsys.strip() == "01" or vulnsys.strip() == "1": nmap()
            elif vulnsys.strip() == "02" or vulnsys.strip() == "2": androZenmap()
            elif vulnsys.strip() == "03" or vulnsys.strip() == "3": astraNmap()
            elif vulnsys.strip() == "04" or vulnsys.strip() == "4": easyMap()
            elif vulnsys.strip() == "05" or vulnsys.strip() == "5": red_hawk()
            elif vulnsys.strip() == "06" or vulnsys.strip() == "6": dtect()
            elif vulnsys.strip() == "07" or vulnsys.strip() == "7": dsss()
            elif vulnsys.strip() == "08" or vulnsys.strip() == "8": sqliv()
            elif vulnsys.strip() == "09" or vulnsys.strip() == "9": sqlmap()
            elif vulnsys.strip() == "10": sqlscan()
            elif vulnsys.strip() == "11": wordpreSScan()
            elif vulnsys.strip() == "12": wpscan()
            elif vulnsys.strip() == "13": sqlmate()
            elif vulnsys.strip() == "14": wordpresscan()
            elif vulnsys.strip() == "15": tmscanner()
            elif vulnsys.strip() == "16": rang3r()
            elif vulnsys.strip() == "17": striker()
            elif vulnsys.strip() == "18": routersploit()
            elif vulnsys.strip() == "19": xshell()
            elif vulnsys.strip() == "20": sh33ll()
            elif vulnsys.strip() == "21": blackbox()
            elif vulnsys.strip() == "22": xattacker()
            elif vulnsys.strip() == "23": owscan()
            elif vulnsys.strip() == "24": xplsearch()
            elif vulnsys.strip() == "25": androbugs()
            elif vulnsys.strip() == "26": clickjacking()
            elif vulnsys.strip() == "27": sn1per()
            elif vulnsys.strip() == "00" or vulnsys.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)

    # 03 - Web Hacking
    elif lazymux.strip() == "3" or lazymux.strip() == "03":
        print("\n    [01] sqlmap: 自动 SQL 注入和数据库接管工具")
        print("    [02] WebDAV: WebDAV 文件上传漏洞利用程序")
        print("    [03] MaxSubdoFinder: 用于发现子域的工具")
        print("    [04] Webdav Mass Exploit")
        print("    [05] Atlas: Quick SQLMap 篡改建议器")
        print("    [06] sqldump: 轻松转储 sql 结果站点")
        print("    [07] Websploit: 先进的 MiTM 框架")
   print("    [08] sqlmate: SQLmap 的一个助手，它将实现你对 SQLmap 所期望的功能")
    print("    [09] inther: 使用 shodan, censys 和 hackertarget 进行信息收集")
    print("    [10] HPB: HTML 页面构建器")
    print("    [11] Xshell: 工具箱")
    print("    [12] SH33LL: Shell 扫描器")
    print("    [13] XAttacker: 网站漏洞扫描器和自动漏洞利用工具")
    print("    [14] XSStrike: 最先进的 XSS 扫描器")
    print("    [15] Breacher: 一个高级的多线程管理面板查找器")
    print("    [16] OWScan: OVID Web 扫描器")
    print("    [17] ko-dork: 一个简单的漏洞网站扫描器")
    print("    [18] ApSca: 强大的 Web 渗透应用程序")
    print("    [19] amox: 通过字典攻击在网站上查找后门或 shell")
    print("    [20] FaDe: 使用 kindeditor, fckeditor 和 webdav 的假页面篡改")
    print("    [21] AUXILE: Auxile 框架")
    print("    [22] xss-payload-list: 跨站脚本（XSS）漏洞有效载荷列表")
    print("    [23] Xadmin: 管理面板查找器")
    print("    [24] CMSeeK: CMS 检测与利用套件 - 扫描 WordPress, Joomla, Drupal 以及超过 180 其他 CMS")
    print("    [25] CMSmap: 一个自动化检测最流行 CMS 安全漏洞的 Python 开源 CMS 扫描器")
    print("    [26] CrawlBox: 简易的 Web 目录暴力破解工具")
    print("    [27] LFISuite: 完全自动的 LFI 利用工具（+ 反向 Shell）和扫描器")
    print("    [28] Parsero: Robots.txt 审计工具")
    print("    [29] Sn1per: 攻击面管理平台 | Sn1perSecurity LLC")
    print("    [30] Sublist3r: 快速子域枚举工具，适用于渗透测试人员")
    print("    [31] WP-plugin-scanner: 一个列出 WordPress 网站上安装的插件的工具")
    print("    [32] WhatWeb: 新一代 Web 扫描器")
    print("    [33] fuxploider: 文件上传漏洞扫描器和利用工具")
    print("\n    [00] 返回主菜单\n")
        webhack = input("lzmx > set_install ")
        if webhack == "@":
            webhack = ""
            for x in range(1,201):
                webhack += f"{x} "
        if len(webhack.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for webhx in webhack.split():
            if webhx.strip() == "01" or webhx.strip() == "1": sqlmap()
            elif webhx.strip() == "02" or webhx.strip() == "2": webdav()
            elif webhx.strip() == "03" or webhx.strip() == "3": maxsubdofinder()
            elif webhx.strip() == "04" or webhx.strip() == "4": webmassploit()
            elif webhx.strip() == "05" or webhx.strip() == "5": atlas()
            elif webhx.strip() == "06" or webhx.strip() == "6": sqldump()
            elif webhx.strip() == "07" or webhx.strip() == "7": websploit()
            elif webhx.strip() == "08" or webhx.strip() == "8": sqlmate()
            elif webhx.strip() == "09" or webhx.strip() == "9": inther()
            elif webhx.strip() == "10": hpb()
            elif webhx.strip() == "11": xshell()
            elif webhx.strip() == "12": sh33ll()
            elif webhx.strip() == "13": xattacker()
            elif webhx.strip() == "14": xsstrike()
            elif webhx.strip() == "15": breacher()
            elif webhx.strip() == "16": owscan()
            elif webhx.strip() == "17": kodork()
            elif webhx.strip() == "18": apsca()
            elif webhx.strip() == "19": amox()
            elif webhx.strip() == "20": fade()
            elif webhx.strip() == "21": auxile()
            elif webhx.strip() == "22": xss_payload_list()
            elif webhx.strip() == "23": xadmin()
            elif webhx.strip() == "24": cmseek()
            elif webhx.strip() == "25": cmsmap()
            elif webhx.strip() == "26": crawlbox()
            elif webhx.strip() == "27": lfisuite()
            elif webhx.strip() == "28": parsero()
            elif webhx.strip() == "29": sn1per()
            elif webhx.strip() == "30": sublist3r()
            elif webhx.strip() == "31": wppluginscanner()
            elif webhx.strip() == "32": whatweb()
            elif webhx.strip() == "33": fuxploider()
            elif webhx.strip() == "00" or webhx.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 04 - Database Assessment
    elif lazymux.strip() == "4" or lazymux.strip() == "04":
        print("\n    [01] DbDat: DbDat 对数据库执行大量检查以评估安全性")
        print("    [02] sqlmap: 自动 SQL 注入和数据库接管工具")
        print("    [03] NoSQLMap: 自动化 NoSQL 数据库枚举和 Web 应用程序开发工具")
        print("    [04] audit_couchdb: 检测 CouchDB 服务器中或大或小的安全问题")
        print("    [05] mongoaudit: 一个自动渗透测试工具，可让您知道 MongoDB 实例是否得到适当保护")
        print("\n    [00] 返回主菜单\n")
        dbssm = input("lzmx > set_install ")
        if dbssm == "@":
            dbssm = ""
            for x in range(1,201):
                dbssm += f"{x} "
        if len(dbssm.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for dbsx in dbssm.split():
            if dbsx.strip() == "01" or dbsx.strip() == "1": dbdat()
            elif dbsx.strip() == "02" or dbsx.strip() == "2": sqlmap()
            elif dbsx.strip() == "03" or dbsx.strip() == "3": nosqlmap
            elif dbsx.strip() == "04" or dbsx.strip() == "4": audit_couchdb()
            elif dbsx.strip() == "05" or dbsx.strip() == "5": mongoaudit()
            elif dbsx.strip() == "00" or dbsx.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 05 - Password Attacks
    elif lazymux.strip() == "5" or lazymux.strip() == "05":
 print("\n    [01] Hydra: 支持不同服务的网络登录破解工具")
    print("    [02] FMBrute: Facebook 多账户暴力破解")
    print("    [03] HashID: 用于识别不同类型哈希的软件")
    print("    [04] Facebook Brute Force 3: Facebook 暴力破解 3")
    print("    [05] Black Hydra: 一个小型程序，用于缩短在 Hydra 上的暴力破解会话")
    print("    [06] Hash Buster: 几秒钟内破解哈希")
    print("    [07] FBBrute: Facebook 暴力破解")
    print("    [08] Cupp: 常用用户密码分析器")
    print("    [09] InstaHack: Instagram 暴力破解")
    print("    [10] Indonesian Wordlist: 印尼词库列表")
    print("    [11] Xshell: Xshell 工具")
    print("    [12] Aircrack-ng: WiFi 安全审计工具套件")
    print("    [13] BlackBox: 渗透测试框架")
    print("    [14] Katak: 开源软件登录暴力破解工具包和哈希解密器")
    print("    [15] Hasher: 自动检测哈希的哈希破解器")
    print("    [16] Hash-Generator: 漂亮的哈希生成器")
    print("    [17] nk26: Nkosec 编码")
    print("    [18] Hasherdotid: 寻找加密文本的工具")
    print("    [19] Crunch: 高度可定制的密码表生成器")
    print("    [20] Hashcat: 世界上最快且最先进的密码恢复工具")
    print("    [21] ASU: Facebook 黑客工具包")
    print("    [22] Credmap: 一个开源工具，旨在提高人们对凭证重用危险的认识")
    print("    [23] BruteX: 自动对目标上运行的所有服务进行暴力破解")
    print("    [24] Gemail-Hack: 针对 Gmail 账户暴力破解的 Python 脚本")
    print("    [25] GoblinWordGenerator: Python 密码表生成器")
    print("    [26] PyBozoCrack: 一个有趣且有效的 Python MD5 破解器")
    print("    [27] brutespray: 从 Nmap 输出进行暴力破解 - 自动尝试在发现的服务上使用默认凭据")
    print("    [28] crowbar: Crowbar 是一个可以在渗透测试中使用的暴力破解工具")
    print("    [29] elpscrk: 一个基于用户画像、排列组合和统计数据的智能密码表生成器")
    print("    [30] fbht: Facebook 黑客工具")
    print("\n    [00] 返回主菜单\n")
        passtak = input("lzmx > set_install ")
        if passtak == "@":
            passtak = ""
            for x in range(1,201):
                passtak += f"{x} "
        if len(passtak.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for passx in passtak.split():
            if passx.strip() == "01" or passx.strip() == "1": hydra()
            elif passx.strip() == "02" or passx.strip() == "2": fmbrute()
            elif passx.strip() == "03" or passx.strip() == "3": hashid()
            elif passx.strip() == "04" or passx.strip() == "4": fbBrute()
            elif passx.strip() == "05" or passx.strip() == "5": black_hydra()
            elif passx.strip() == "06" or passx.strip() == "6": hash_buster()
            elif passx.strip() == "07" or passx.strip() == "7": fbbrutex()
            elif passx.strip() == "08" or passx.strip() == "8": cupp()
            elif passx.strip() == "09" or passx.strip() == "9": instaHack()
            elif passx.strip() == "10": indonesian_wordlist()
            elif passx.strip() == "11": xshell()
            elif passx.strip() == "12": aircrackng()
            elif passx.strip() == "13": blackbox()
            elif passx.strip() == "14": katak()
            elif passx.strip() == "15": hasher()
            elif passx.strip() == "16": hashgenerator()
            elif passx.strip() == "17": nk26()
            elif passx.strip() == "18": hasherdotid()
            elif passx.strip() == "19": crunch()
            elif passx.strip() == "20": hashcat()
            elif passx.strip() == "21": asu()
            elif passx.strip() == "22": credmap()
            elif passx.strip() == "23": brutex()
            elif passx.strip() == "24": gemailhack()
            elif passx.strip() == "25": goblinwordgenerator()
            elif passx.strip() == "26": pybozocrack()
            elif passx.strip() == "27": brutespray()
            elif passx.strip() == "28": crowbar()
            elif passx.strip() == "29": elpscrk()
            elif passx.strip() == "30": fbht()
            elif passx.strip() == "00" or passx.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 06 - Wireless Attacks
    elif lazymux.strip() == "6" or lazymux.strip() == "06":
        print("\n    [01] Aircrack-ng: WiFi 安全审计工具套件")
        print("    [02] Wifite: 自动化无线攻击工具")
        print("    [03] Wifiphisher: Rogue 接入点框架")
        print("    [04] Routersploit: 嵌入式设备的漏洞利用框架")
        print("    [05] PwnSTAR: (Pwn SofT-AP scRipt) - 满足您所有的假 AP 需求!")
        print("    [06] Pyrit: 著名的 WPA 预计算破解器，从 Google 迁移而来")
        print("\n    [00] 返回主菜单\n")
        wiretak = input("lzmx > set_install ")
        if wiretak == "@":
            wiretak = ""
            for x in range(1,201):
                wiretak += f"{x} "
        if len(wiretak.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for wirex in wiretak.split():
            if wirex.strip() == "01" or wirex.strip() == "1": aircrackng()
            elif wirex.strip() == "02" or wirex.strip() == "2": wifite()
            elif wirex.strip() == "03" or wirex.strip() == "3": wifiphisher()
            elif wirex.strip() == "04" or wirex.strip() == "4": routersploit()
            elif wirex.strip() == "05" or wirex.strip() == "5": pwnstar()
            elif wirex.strip() == "06" or wirex.strip() == "6": pyrit()
            elif wirex.strip() == "00" or wirex.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 07 - Reverse Engineering
    elif lazymux.strip() == "7" or lazymux.strip() == "07":
 print("\n    [01] 二进制漏洞利用")
    print("    [02] jadx: DEX 到 JAVA 的反编译器")
    print("    [03] apktool: 可用于 Android 应用逆向工程的实用工具")
    print("    [04] uncompyle6: Python 跨版本字节码反编译器")
    print("    [05] ddcrypt: DroidScript APK 去混淆器")
    print("    [06] CFR: 又一个 JAVA 反编译器")
    print("    [07] UPX: 终极可执行文件打包器")
    print("    [08] pyinstxtractor: PyInstaller 提取器")
    print("    [09] innoextract: 解包由 Inno Setup 创建的安装程序的工具")
    print("    [10] pycdc: C++ Python 字节码反汇编器和反编译器")
    print("    [11] APKiD: Android 应用的打包器、保护器、混淆器和异常检测标识 - Android 的 PEiD")
    print("    [12] DTL-X: Python APK 逆向工程 & 补丁工具")
    print("    [13] APKLeaks: 扫描 APK 文件以查找 URI、端点和密钥")
    print("    [14] apk-mitm: 一个命令行应用程序，自动准备 Android APK 文件进行 HTTPS 检查")
    print("    [15] ssl-pinning-remover: Android 应用的 SSL 固定移除器")
    print("    [16] GEF: GEF (GDB 增强功能) - 为 Linux 上的漏洞开发者和逆向工程师提供具有高级调试功能的现代 GDB 体验")
    print("\n    [00] 返回主菜单\n")
        reversi = input("lzmx > set_install ")
        if reversi == "@":
            reversi = ""
            for x in range(1,201):
                reversi += f"{x} "
        if len(reversi.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for revex in reversi.split():
            if revex.strip() == "01" or revex.strip() == "1": binploit()
            elif revex.strip() == "02" or revex.strip() == "2": jadx()
            elif revex.strip() == "03" or revex.strip() == "3": apktool()
            elif revex.strip() == "04" or revex.strip() == "4": uncompyle()
            elif revex.strip() == "05" or revex.strip() == "5": ddcrypt()
            elif revex.strip() == "06" or revex.strip() == "6": cfr()
            elif revex.strip() == "07" or revex.strip() == "7": upx()
            elif revex.strip() == "08" or revex.strip() == "8": pyinstxtractor()
            elif revex.strip() == "09" or revex.strip() == "9": innoextract()
            elif revex.strip() == "10": pycdc()
            elif revex.strip() == "11": apkid()
            elif revex.strip() == "12": dtlx()
            elif revex.strip() == "13": apkleaks()
            elif revex.strip() == "14": apkmitm()
            elif revex.strip() == "15": ssl_pinning_remover()
            elif revex.strip() == "16": gef()
            elif revex.strip() == "00" or revex.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 08 - Exploitation Tools
    elif lazymux.strip() == "8" or lazymux.strip() == "08":
 print("\n    [01] Metasploit: 用于开发、测试和使用漏洞利用代码的高级开源平台")
    print("    [02] commix: 自动化的一体化 OS 命令注入和利用工具")
    print("    [03] BlackBox: 一个渗透测试框架")
    print("    [04] Brutal: 类似于橡胶鸭的 teensy 有效载荷，但语法不同")
    print("    [05] TXTool: 一个简单的渗透测试工具")
    print("    [06] XAttacker: 网站漏洞扫描器 & 自动漏洞利用器")  
    print("    [07] Websploit: 先进的中间人攻击框架")
    print("    [08] Routersploit: 嵌入式设备的漏洞利用框架")
    print("    [09] A-Rat: 远程管理工具")
    print("    [10] BAF: 盲目攻击框架")
    print("    [11] Gloom-Framework: Linux 渗透测试框架")
    print("    [12] Zerodoor: 一个为即时生成跨平台后门而懒洋洋编写的脚本 :)")
    print("\n    [00] 返回主菜单\n")
        exploitool = input("lzmx > set_install ")
        if exploitool == "@":
            exploitool = ""
            for x in range(1,201):
                exploitool += f"{x} "
        if len(exploitool.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for explx in exploitool.split():
            if explx.strip() == "01" or explx.strip() == "1": metasploit()
            elif explx.strip() == "02" or explx.strip() == "2": commix()
            elif explx.strip() == "03" or explx.strip() == "3": blackbox()
            elif explx.strip() == "04" or explx.strip() == "4": brutal()
            elif explx.strip() == "05" or explx.strip() == "5": txtool()
            elif explx.strip() == "06" or explx.strip() == "6": xattacker()
            elif explx.strip() == "07" or explx.strip() == "7": websploit()
            elif explx.strip() == "08" or explx.strip() == "8": routersploit()
            elif explx.strip() == "09" or explx.strip() == "9": arat()
            elif explx.strip() == "10": baf()
            elif explx.strip() == "11": gloomframework()
            elif explx.strip() == "12": zerodoor()
            elif explx.strip() == "00" or explx.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 09 - Sniffing and Spoofing
    elif lazymux.strip() == "9" or lazymux.strip() == "09":
        print("\n    [01] KnockMail: 验证电子邮件是否存在")
        print("    [02] tcpdump: 强大的命令行数据包分析器")
        print("    [03] Ettercap: 用于 MITM 攻击的综合套件，可以嗅探实时连接、动态进行内容过滤等等")
        print("    [04] hping3: hping 是一个面向命令行的 TCP/IP 数据包汇编器/分析器")
        print("    [05] tshark: 网络协议分析器和嗅探器")
        print("\n    [00] 返回主菜单\n")
        sspoof = input("lzmx > set_install ")
        if sspoof == "@":
            sspoof = ""
            for x in range(1,201):
                sspoof += f"{x} "
        if len(sspoof.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for sspx in sspoof.split():
            if sspx.strip() == "01" or sspx.strip() == "1": knockmail()
            elif sspx.strip() == "02" or sspx.strip() == "2": tcpdump()
            elif sspx.strip() == "03" or sspx.strip() == "3": ettercap()
            elif sspx.strip() == "04" or sspx.strip() == "4": hping3()
            elif sspx.strip() == "05" or sspx.strip() == "5": tshark()
            elif sspx.strip() == "00" or sspx.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 10 - Reporting Tools
    elif lazymux.strip() == "10":
        print("\n    [01] dos2unix: 在 DOS 和 Unix 文本文件之间转换")
        print("    [02] exiftool: 用于读取、写入和编辑各种文件中的元信息的实用程序")
        print("    [03] iconv: 在不同字符编码之间转换的实用程序")
        print("    [04] mediainfo: 用于从媒体文件中读取信息的命令行实用程序")
        print("    [05] pdfinfo: PDF 文档信息提取器")
        print("\n    [00] 返回主菜单\n")
        reportls = input("lzmx > set_install ")
        if reportls == "@":
            reportls = ""
            for x in range(1,201):
                reportls += f"{x} "
        if len(reportls.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for reportx in reportls.split():
            if reportx.strip() == "01" or reportx.strip() == "1": dos2unix()
            elif reportx.strip() == "02" or reportx.strip() == "2": exiftool()
            elif reportx.strip() == "03" or reportx.strip() == "3": iconv()
            elif reportx.strip() == "04" or reportx.strip() == "4": mediainfo()
            elif reportx.strip() == "05" or reportx.strip() == "5": pdfinfo()
            elif reportx.strip() == "00" or reportx.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 11 - Forensic Tools
    elif lazymux.strip() == "11":
        print("\n    [01] steghide: 通过替换一些最低有效位在文件中嵌入消息")
        print("    [02] tesseract: Tesseract 可能是可用的最准确的开源 OCR 引擎")
        print("    [03] sleuthkit: Sleuth Kit （TSK） 是一个数字取证工具库")
        print("    [04] CyberScan: Network 的取证工具包")
        print("    [05] binwalk: 固件分析工具")
        print("\n    [00] 返回主菜单\n")
        forensc = input("lzmx > set_install ")
        if forensc == "@":
            forensc = ""
            for x in range(1,201):
                forensc += f"{x} "
        if len(forensc.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for forenx in forensc.split():
            if forenx.strip() == "01" or forenx.strip() == "1": steghide()
            elif forenx.strip() == "02" or forenx.strip() == "2": tesseract()
            elif forenx.strip() == "03" or forenx.strip() == "3": sleuthkit()
            elif forenx.strip() == "04" or forenx.strip() == "4": cyberscan()
            elif forenx.strip() == "05" or forenx.strip() == "5": binwalk()
            elif forenx.strip() == "00" or forenx.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 12 - Stress Testing
    elif lazymux.strip() == "12":
        print("\n    [01] Torshammer: 慢速发布 DDOS 工具")
        print("    [02] Slowloris: 低带宽 DoS 工具")
        print("    [03] Fl00d & Fl00d2: UDP 泛洪工具")
        print("    [04] GoldenEye: Goldeneye 第 7 层 （Kipalive + Nokache） DOS 测试工具")
        print("    [05] Xerxes: 最强大的 DoS 工具")
        print("    [06] Planetwork-DDOS")
        print("    [07] Xshell")
        print("    [08] santet-online: 社会工程工具")
        print("    [09] dost-attack: WebServer 攻击工具")
        print("    [10] DHCPig: 使用 scapy 网络库用 python 编写的 DHCP 耗尽脚本")
        print("\n    [00] 返回主菜单\n")
        stresstest = input("lzmx > set_install ")
        if stresstest == "@":
            stresstest = ""
            for x in range(1,201):
                stresstest += f"{x} "
        if len(stresstest.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for stressx in stresstest.split():
            if stressx.strip() == "01" or stressx.strip() == "1": torshammer()
            elif stressx.strip() == "02" or stressx.strip() == "2": slowloris()
            elif stressx.strip() == "03" or stressx.strip() == "3": fl00d12()
            elif stressx.strip() == "04" or stressx.strip() == "4": goldeneye()
            elif stressx.strip() == "05" or stressx.strip() == "5": xerxes()
            elif stressx.strip() == "06" or stressx.strip() == "6": planetwork_ddos()
            elif stressx.strip() == "07" or stressx.strip() == "7": xshell()
            elif stressx.strip() == "08" or stressx.strip() == "8": sanlen()
            elif stressx.strip() == "09" or stressx.strip() == "9": dostattack()
            elif stressx.strip() == "10": dhcpig()
            elif stressx.strip() == "00" or stressx.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 13 - Install Linux Distro
    elif lazymux.strip() == "13":
        print("\n    [01] Ubuntu (impish)")
        print("    [02] Fedora")
        print("    [03] Kali Nethunter")
        print("    [04] Parrot")
        print("    [05] Arch Linux")
        print("    [06] Alpine Linux (edge)")
        print("    [07] Debian (bullseye)")
        print("    [08] Manjaro AArch64")
        print("    [09] OpenSUSE (Tumbleweed)")
        print("    [10] Void Linux")
        print("\n    [00] 返回主菜单\n")
        innudis = input("lzmx > set_install ")
        if innudis == "@":
            innudis = ""
            for x in range(1,201):
                innudis += f"{x} "
        if len(innudis.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for innux in innudis.split():
            if innux.strip() == "01" or innux.strip() == "1": ubuntu()
            elif innux.strip() == "02" or innux.strip() == "2": fedora()
            elif innux.strip() == "03" or innux.strip() == "3": nethunter()
            elif innux.strip() == "04" or innux.strip() == "4": parrot()
            elif innux.strip() == "05" or innux.strip() == "5": archlinux()
            elif innux.strip() == "06" or innux.strip() == "6": alpine()
            elif innux.strip() == "07" or innux.strip() == "7": debian()
            elif innux.strip() == "08" or innux.strip() == "8": manjaroArm64()
            elif innux.strip() == "09" or innux.strip() == "9": opensuse()
            elif innux.strip() == "10": voidLinux()
            elif innux.strip() == "00" or innux.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 14 - Termux Utility
    elif lazymux.strip() == "14":
    print("\n    [01] SpiderBot: 使用随机代理和用户代理爬取网站的 Curl 机器人")
    print("    [02] Ngrok: 将本地端口隧道到公共 URL 并检查流量")
    print("    [03] Sudo: Android 的 sudo 安装器")
    print("    [04] google: 绑定到 Google 搜索引擎的 Python 接口")
    print("    [05] kojawafft") 
    print("    [06] ccgen: 信用卡生成器")
    print("    [07] VCRT: 病毒创建器")
    print("    [08] E-Code: PHP 脚本编码器")
    print("    [09] Termux-Styling: Termux 样式设置")
    print("    [11] xl-py: XL 直接购买包")
    print("    [12] BeanShell: 一个小巧、免费、可嵌入的 Java 源代码解释器，具有对象脚本语言特性，用 Java 编写")
    print("    [13] vbug: 病毒制造者")
    print("    [14] Crunch: 高度可定制的密码表生成器")
    print("    [15] Textr: 运行文本的简单工具")
    print("    [16] heroku: 与 Heroku 交互的命令行界面")
    print("    [17] RShell: 用于单次监听的反向 shell")
    print("    [18] TermPyter: 修复 Termux 上 Jupyter 安装的所有错误")
    print("    [19] Numpy: 用于 Python 科学计算的基础包")
    print("    [20] BTC-to-IDR-checker: 通过 Bitcoin.co.id API 检查虚拟货币兑换成印尼盾的汇率")
    print("    [21] ClickBot: 使用 Telegram 机器人赚钱")
    print("    [22] pandas: 强大的开源数据操作和分析库")
    print("    [23] jupyter-notebook: 允许用户创建和共享包含实时代码、方程、可视化和叙述文本的文档的交互式网络应用程序")
    print("\n    [00] 返回主菜单\n")
        moretool = input("lzmx > set_install ")
        if moretool == "@":
            moretool = ""
            for x in range(1,201):
                moretool += f"{x} "
        if len(moretool.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for moret in moretool.split():
            if moret.strip() == "01" or moret.strip() == "1": spiderbot()
            elif moret.strip() == "02" or moret.strip() == "2": ngrok()
            elif moret.strip() == "03" or moret.strip() == "3": sudo()
            elif moret.strip() == "04" or moret.strip() == "4": google()
            elif moret.strip() == "05" or moret.strip() == "5": kojawafft()
            elif moret.strip() == "06" or moret.strip() == "6": ccgen()
            elif moret.strip() == "07" or moret.strip() == "7": vcrt()
            elif moret.strip() == "08" or moret.strip() == "8": ecode()
            elif moret.strip() == "09" or moret.strip() == "9": stylemux()
            elif moret.strip() == "10": passgencvar()
            elif moret.strip() == "11": xlPy()
            elif moret.strip() == "12": beanshell()
            elif moret.strip() == "13": vbug()
            elif moret.strip() == "14": crunch()
            elif moret.strip() == "15": textr()
            elif moret.strip() == "16": heroku()
            elif moret.strip() == "17": rshell()
            elif moret.strip() == "18": termpyter()
            elif moret.strip() == "19": numpy()
            elif moret.strip() == "20": btc2idr()
            elif moret.strip() == "21": clickbot()
            elif moret.strip() == "22": pandas()
            elif moret.strip() == "23": notebook()
            elif moret.strip() == "00" or moret.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 15 - Shell Function [.bashrc]
    elif lazymux.strip() == "15":
        print("\n    [01] FBVid (FB 视频下载器)")
        print("    [02] cast2video (Asciinema 铸造转换器)")
        print("    [03] iconset (AIDE 应用程序图标)")
        print("    [04] readme (GitHub README.md)")
        print("    [05] makedeb (DEB 包生成器)")
        print("    [06] quikfind (搜索文件)")
        print("    [07] pranayama (4-7-8 放松呼吸)")
        print("    [08] sqlc (SQLite 查询处理器)")
        print("\n    [00] 返回主菜单\n")
        myshf = input("lzmx > set_install ")
        if myshf == "@":
            myshf = ""
            for x in range(1,201):
                myshf += f"{x} "
        if len(myshf.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for mysh in myshf.split():
            if mysh.strip() == "01" or mysh.strip() == "1": fbvid()
            elif mysh.strip() == "02" or mysh.strip() == "2": cast2video()
            elif mysh.strip() == "03" or mysh.strip() == "3": iconset()
            elif mysh.strip() == "04" or mysh.strip() == "4": readme()
            elif mysh.strip() == "05" or mysh.strip() == "5": makedeb()
            elif mysh.strip() == "06" or mysh.strip() == "6": quikfind()
            elif mysh.strip() == "07" or mysh.strip() == "7": pranayama()
            elif mysh.strip() == "08" or mysh.strip() == "8": sqlc()
            elif mysh.strip() == "00" or mysh.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 16 - Install CLI Games
    elif lazymux.strip() == "16":
        print("\n    [01] Flappy Bird")
        print("    [02] Street Car")
        print("    [03] Speed Typing")
        print("    [04] NSnake: 带有文本界面的经典贪吃蛇游戏")
        print("    [05] Moon buggy: 驾驶汽车穿越月球表面的简单游戏")
        print("    [06] Nudoku: 基于 ncurses 的数独游戏")
        print("    [07] tty-solitaire")
        print("    [08] Pacman4Console")
        print("\n    [00] 返回主菜单\n")
        cligam = input("lzmx > set_install ")
        if cligam == "@":
            cligam = ""
            for x in range(1,201):
                cligam += f"{x} "
        if len(cligam.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for clig in cligam.split():
            if clig.strip() == "01" or clig.strip() == "1": flappy_bird()
            elif clig.strip() == "02" or clig.strip() == "2": street_car()
            elif clig.strip() == "03" or clig.strip() == "3": speed_typing()
            elif clig.strip() == "04" or clig.strip() == "4": nsnake()
            elif clig.strip() == "05" or clig.strip() == "5": moon_buggy()
            elif clig.strip() == "06" or clig.strip() == "6": nudoku()
            elif clig.strip() == "07" or clig.strip() == "7": ttysolitaire()
            elif clig.strip() == "08" or clig.strip() == "8": pacman4console()
            elif clig.strip() == "00" or clig.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 17 - Malware Analysis
    elif lazymux.strip() == "17":
        print("\n    [01] Lynis: 安全审计和 Rootkit 扫描程序")
        print("    [02] Chkrootkit: A Linux Rootkit 扫描程序")
        print("    [03] ClamAV: 防病毒软件工具包")
        print("    [04] Yara: 旨在帮助恶意软件研究人员识别和分类恶意软件样本的工具")
        print("    [05] VirusTotal-CLI: VirusTotal 的命令行界面")
        print("    [06] avpass: 用于泄漏和绕过 Android 恶意软件检测系统的工具")
        print("    [07] DKMC: Don't kill my cat - 恶意负载规避工具")
        print("\n    [00] 返回主菜单\n")
        malsys = input("lzmx > set_install ")
        if malsys == "@":
            malsys = ""
            for x in range(1,201):
                malsys += f"{x} "
        if len(malsys.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for malx in malsys.split():
            if malx.strip() == "01" or malx.strip() == "1": lynis()
            elif malx.strip() == "02" or malx.strip() == "2": chkrootkit()
            elif malx.strip() == "03" or malx.strip() == "3": clamav()
            elif malx.strip() == "04" or malx.strip() == "4": yara()
            elif malx.strip() == "05" or malx.strip() == "5": virustotal()
            elif malx.strip() == "06" or malx.strip() == "6": avpass()
            elif malx.strip() == "07" or malx.strip() == "7": dkmc()
            elif malx.strip() == "00" or malx.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 18 - Compiler/Interpreter
    elif lazymux.strip() == "18":
  print("\n    [01] Python2: 旨在使程序更加清晰的 Python 2 程序语言")
    print("    [02] ecj: Eclipse 编译器，用于 Java")
    print("    [03] Golang: Go 程序语言编译器")
    print("    [04] ldc: 使用 LLVM 构建的 D 程序语言编译器")
    print("    [05] Nim: Nim 程序语言编译器")
    print("    [06] shc: Shell 脚本编译器")
    print("    [07] TCC: Tiny C 编译器")
    print("    [08] PHP: 服务器端，HTML 嵌入的脚本语言")
    print("    [09] Ruby: 一种以简洁和生产力为重点的动态程序语言")
    print("    [10] Perl: 功能强大的程序语言")
    print("    [11] Vlang: 简单、快速、安全，用于开发可维护软件的编译语言")
    print("    [12] BeanShell: 一个小巧、免费、可嵌入的 Java 源码解释器，具有基于对象的脚本语言特性，用 Java 编写")
    print("    [13] fp-compiler: Free Pascal 是一个专业的 32、64 和 16 位 Pascal 编译器")
    print("    [14] Octave: 科学程序语言")
    print("    [15] BlogC: 一个博客编译器")
    print("    [16] Dart: 通用程序语言")
    print("    [17] Yasm: 支持 x86 和 AMD64 指令集的汇编器")
    print("    [18] Nasm: 一个跨平台的 x86 汇编器，具有类似 Intel 的语法")
    print("\n    [00] 返回主菜单\n")
        compter = input("lzmx > set_install ")
        if compter == "@":
            compter = ""
            for x in range(1,201):
                compter += f"{x} "
        if len(compter.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for compt in compter.split():
            if compt.strip() == "01" or compt.strip() == "1": python2()
            elif compt.strip() == "02" or compt.strip() == "2": ecj()
            elif compt.strip() == "03" or compt.strip() == "3": golang()
            elif compt.strip() == "04" or compt.strip() == "4": ldc()
            elif compt.strip() == "05" or compt.strip() == "5": nim()
            elif compt.strip() == "06" or compt.strip() == "6": shc()
            elif compt.strip() == "07" or compt.strip() == "7": tcc()
            elif compt.strip() == "08" or compt.strip() == "8": php()
            elif compt.strip() == "09" or compt.strip() == "9": ruby()
            elif compt.strip() == "10": perl()
            elif compt.strip() == "11": vlang()
            elif compt.strip() == "12": beanshell()
            elif compt.strip() == "13": fpcompiler()
            elif compt.strip() == "14": octave()
            elif compt.strip() == "15": blogc()
            elif compt.strip() == "16": dart()
            elif compt.strip() == "17": yasm()
            elif compt.strip() == "18": nasm()
            elif compt.strip() == "00" or compt.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 19 - Social Engineering Tools
    elif lazymux.strip() == "19":
   print("\n    [01] weeman: 用于网络钓鱼的 Python HTTP 服务器")
    print("    [02] SocialFish: 教育性网络钓鱼工具 & 信息收集器")
    print("    [03] santet-online: 社会工程工具")
    print("    [04] SpazSMS: 在同一个电话号码上重复发送垃圾短信")
    print("    [05] LiteOTP: 多通道垃圾短信 OTP 发送器")
    print("    [06] F4K3: 假用户数据生成器")
    print("    [07] Hac")  # 此项保持原文不变
    print("    [08] Cookie-stealer: 简单的 Cookie 窃取工具")
    print("    [09] zphisher: 自动化网络钓鱼工具")
    print("    [10] Evilginx: 带有两种因素认证绕过的高级网络钓鱼工具")
    print("    [11] ghost-phisher: 来自 code.google.com/p/ghost-phisher 的自动导出工具")
    print("\n    [00] 返回主菜单\n")
        soceng = input("lzmx > set_install ")
        if soceng == "@":
            soceng = ""
            for x in range(1,201):
                soceng += f"{x} "
        if len(soceng.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for socng in soceng.split():
            if socng.strip() == "01" or socng.strip() == "1": weeman()
            elif socng.strip() == "02" or socng.strip() == "2": socfish()
            elif socng.strip() == "03" or socng.strip() == "3": sanlen()
            elif socng.strip() == "04" or socng.strip() == "4": spazsms()
            elif socng.strip() == "05" or socng.strip() == "5": liteotp()
            elif socng.strip() == "06" or socng.strip() == "6": f4k3()
            elif socng.strip() == "07" or socng.strip() == "7": hac()
            elif socng.strip() == "08" or socng.strip() == "8": cookiestealer()
            elif socng.strip() == "09" or socng.strip() == "9": zphisher()
            elif socng.strip() == "10": evilginx()
            elif socng.strip() == "11": ghostphisher()
            elif socng.strip() == "00" or socng.strip() == "0": restart_program()
            else: print("\n错误：输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    elif lazymux.strip() == "99":
        os.system("git pull")
    elif lazymux.strip() == "0" or lazymux.strip() == "00":
        sys.exit()
    
    else:
        print("\n错误：输入错误")
        timeout(1)
        restart_program()

if __name__ == "__main__":
    os.system("clear")
    main()
