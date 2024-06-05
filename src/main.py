from optparse import OptionParser
import os


def extract_ip(buf: bytes) -> list[str]:
    str_list = extract_str(buf, target="ip")
    ip_list = ip_search(str_list)
    # print(ip_list)
    return ip_list


def extract_domain(buf: bytes) -> list[str]:
    str_list = extract_str(buf, target="ip")
    domain_list = domain_search(str_list)
    return domain_list


def extract_str(buf: bytes, target="str", mode="strong") -> list[str]:
    """旨在从任意二进制映像中提取字符串。默认进行ip提取，
    边遍历边进行字符的提取，该函数**只提取可见ascii码**。
    即byte大小>= 0x20 and <= 0x7f 的字符 

    Args: buf -> 目标二进制映像
          target -> 需要提取的字符串类型，目前仅可提取ip和str。
          这个选项具体影响的其实是字符串的长度，str至少提取2位，ip至少提取6位。
          mode -> 该模式决定是否吃掉\x00字符。部分字符串(如C#)存储时，可能是带着\x00。

    Return: 提取的字符串列表

    """
    str_list = []
    ptr = 0

    while ptr < len(buf):  # 整体循环，当字符串提取循环退出后会在这里重置tmp变量
        str_tmp = ""
        if buf[ptr] >= 0x20 and buf[ptr] < 0x7f:  # 进入字符串提取循环
            while buf[ptr] >= 0x20 and buf[ptr] < 0x7f:
                str_tmp += chr(buf[ptr])
                ptr += 1
                if mode == "strong" and buf[ptr] == 0:  # Mode
                    ptr += 1
                    continue
            if target == "ip":  # target
                if len(str_tmp) > 5:
                    str_list.append(str_tmp)
            elif target == "str":
                if len(str_tmp) > 3:
                    str_list.append(str_tmp)
        else:
            ptr += 1

    return str_list


def ip_search(str_list: list) -> list[str]:
    """在字符串列表中使用正则匹配ip。

    Args: str_list->字符串列表源

    Return: 目的ip列表

    """

    pattern = r"((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}"
    # pattern = r'(?<![\.\d])(([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.){3}([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])(?![\.\d])'
    # 匹配 0-255的表达式书写方法
    # pattern = r'([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])'

    import re
    ip_list = []
    for s in str_list:
        # s = "https://36.123.123.123:9443"
        ip = re.search(pattern, s)
        while ip != None:  # 如go可能会出现一个极长字符串的情况，因此做了一条字符串的遍历多次查询
            match_ip = s[ip.start():ip.end()]
            ip_list.append(match_ip)
            s = s[ip.end()::]
            # print(s)
            ip = re.search(pattern, s)
            # print(match_ip)
            # print()

    return ip_list


def domain_search(str_list: list) -> list[str]:
    """在字符串列表中使用正则匹配域名，并使用tld库进行一次顶级域名校验。

    Args: str_list->字符串列表源

    Return: 目的域名列表

    """
    import tld
    import re
    pattern = r'([a-zA-Z0-9]([a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.){2,4}[a-zA-Z]{2,11}'


# r'(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$'
    domain_list = []

    for s in str_list:
        domain = re.search(pattern, s)
        while domain != None:  # 同ip search，做循环取
            match_domain = s[domain.start():domain.end()]
            if tld.get_tld(match_domain, fail_silently=True, fix_protocol=True) != None:
                domain_list.append(match_domain)

            s = s[domain.end()::]
            domain = re.search(pattern, s)
            # print(domain.string)
            # print(tld.get_tld("bj.cmgly.com", fail_silently=True, fix_protocol=True))

    return domain_list


if __name__ == "__main__":
    parser = OptionParser(usage="python3 main.py -t target -o output.txt")
    parser.add_option("-t", "--target", dest="target",
                      default="..//target//exp.exe.1", type="string")
    # parser.add_option("-o", "--output", dest="output",
    #                 default="..//", type="string")
    options, args = parser.parse_args()
    target = options.target  # "..\\target\\Test5.dll"  # parser.target
    # output = options.output  # "output.txt"  # parser.output

    f_target = open(target, "rb")

    buf = f_target.read()

    str_list = extract_str(buf)
    ip_list = extract_ip(buf)  # ip_search(str_list)
    domain_list = extract_domain(buf)  # domain_search(str_list)

    f_str = open("output.txt", "w")
    # f_str.write("--------str-------\r")
    # for s in str_list:
    #    f_str.write(s+"\r")
    # f_ip = open("ip.txt", "w")
    f_str.write("--------ip--------\r")
    for i in ip_list:
        f_str.write(i+"\r")
    f_str.write("------domain------\r")
    for d in domain_list:
        f_str.write(d+"\r")
    pass
