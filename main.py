from multiprocessing import Pool
from multiprocess import *
from optparse import OptionParser
import os

key_list = ["passwd", "password", "secret",
            "key:\"", "key:\'", "key :\"", "key :\'",
            "key=\"", "key=\'", "key =\"", "key =\'",
            "key\'", "key\""
            "token"]


def extract_ip(buf: bytes) -> list[str]:
    """从bytes流中导出ip的接口。会调用extract_str导出字符串后再挨个查。
    如果是需要考虑性能的场景，建议不用此接口。
    :param buf: 目标字节流
    :return: 包含ip列表的list
    """
    str_list = extract_str(buf, target="ip")
    ip_list = ip_search(str_list)
    return ip_list


def extract_domain(buf: bytes) -> list[str]:
    """从bytes流中导出域名的接口。会调用extract_str导出字符串后再挨个查。
    如果是需要考虑性能的场景，建议不用此接口。
    :param buf: 目标字节流
    :return: 包含domain列表的list
    """
    str_list = extract_str(buf, target="ip")
    domain_list = domain_search(str_list)
    return domain_list


def extract_str(buf: bytes, target="str", mode="strong") -> list[str]:
    """旨在从任意二进制映像中提取字符串。默认进行ip提取，
    边遍历边进行字符的提取，该函数**只提取可见ascii码**。
    即byte大小>= 0x20 and <= 0x7f 的字符。

    如果是需要考虑性能的场景，建议不使用此接口。

    Args: buf -> 目标二进制映像
          target -> 需要提取的字符串类型，目前仅可提取ip和str。
          这个选项具体影响的其实是字符串的长度，str至少提取2位，ip至少提取6位。
          mode -> 该模式决定是否吃掉\x00字符。部分字符串(如C#)存储时，可能是带着\x00。

    Return: 提取的字符串列表

    """
    str_list = []
    ptr = 0  # 读取指针

    while ptr < len(buf):  # 整体循环，当字符串提取循环退出后会在这里重置tmp变量
        str_tmp = ""
        if buf[ptr] >= 0x20 and buf[ptr] < 0x7f:  # 进入字符串提取循环
            while buf[ptr] >= 0x20 and buf[ptr] < 0x7f:
                str_tmp += chr(buf[ptr])  # 确认是字符，添加
                ptr += 1
                if ptr >= len(buf):
                    break
                if ptr == len(buf):  # 历史遗留
                    # str_list.append(str_tmp)
                    break
                if mode == "strong" and buf[ptr] == 0:  # Mode
                    ptr += 1  # 这里不是很完整。在unicode模式下，ascii以word字长存储，低位是ascii，高位是0。这里应该对长度做限制。
                    if ptr >= len(buf):  # 防止指针过长，可优化
                        break
                    continue
            if target == "ip":  # target
                if len(str_tmp) > 6:  # 为ip筛选长度合适的字符串：0.0.0.0
                    str_list.append(str_tmp)
            elif target == "str":  # 去除二进制流中可能被解释为ascii的字符，但这个方法其实比较朴素。
                if len(str_tmp) > 3:
                    str_list.append(str_tmp)
        else:
            ptr += 1

    return str_list


def extract_code_str(buf: bytes) -> list[str]:
    """旨在提取代码文件中的字符串信息（用引号包裹的字符串）
    尚不能匹配中文。

    如果是需要考虑性能的场景，建议不使用此接口。
    :param buf: 目标字节流
    :return: 包含代码的字符串列表的list
    """
    ptr = 0
    check = 0
    code_strs = []
    code_str = ""
    while ptr < len(buf):
        # print(p, len(buf))
        if check == 1:
            "找到字符串头后，匹配字符串"
            if buf[ptr] == ord("\""):
                "找到字符串尾，退出"
                check = 0
                code_strs.append(code_str)
               # print(code_strs)
                code_str = ""
                ptr += 1
                continue
            if buf[ptr] >= 0x20 and buf[ptr] < 0x7f:
                "匹配字符"
                code_str += chr(buf[ptr])
                ptr += 1

                continue
            else:
                "非明文字符串"
                check = 0
                code_str = ""
                ptr += 1
                continue
        if buf[ptr] == ord("\""):
            "找到字符串头"
            check = 1
            ptr += 1
            continue
        ptr += 1

    ptr = 0
    check = 0
    check = 0
    while ptr != len(buf):
        # print(buf[p])
        if check == 1:
            "找到字符串头后，匹配字符串"
            if buf[ptr] == ord("\'"):
                "找到字符串尾，退出"
                check = 0
                code_strs.append(code_str)
                code_str = ""
                ptr += 1
                continue
            if buf[ptr] >= 0x20 and buf[ptr] < 0x7f:
                "匹配字符"
                code_str += chr(buf[ptr])
                ptr += 1
                continue
            else:
                "非明文字符串"
                check = 0
                code_str = ""
                ptr += 1
                continue

        if buf[ptr] == ord("\'"):
            "找到字符串头"
            check = 1
            ptr += 1
            continue
        ptr += 1

    pass
    return code_strs


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
    domain_list = []

    for s in str_list:
        domain = re.search(pattern, s)
        while domain != None:  # 同ip search，做循环取
            match_domain = s[domain.start():domain.end()]
            if tld.get_tld(match_domain, fail_silently=True, fix_protocol=True) != None:
                domain_list.append(match_domain)

            s = s[domain.end()::]
            domain = re.search(pattern, s)

    return domain_list


def output(buf: list, name: str):
    f = open(name+".txt", "w")
    f.write("----------"+name+"----------\r")
    for i in buf:
        f.write(i+"\r")
    f.close()


def total_search(buf: bytes):
    str_list = extract_str(buf)
    ip_list = ip_search(str_list)
    domain_list = domain_search(str_list)

    # 简单去重
    domain_list = [domain for domain in {}.fromkeys(domain_list).keys()]
    ip_list = [ip for ip in {}.fromkeys(ip_list).keys()]
    str_list = [s for s in {}.fromkeys(str_list).keys()]

    output(domain_list, "domain")
    output(ip_list, "ip")
    output(str_list, "str")
    # f_str = open("str.txt", "w")
    # f_str.write("--------str-------\r")
    # for s in str_list:
    #     f_str.write(s+"\r")
    # f_str.close()
    # f_ip = open("ip.txt", "w")
    # f_ip.write("--------ip--------\r")
    # for i in ip_list:
    #     f_ip.write(i+"\r")
    # f_ip.close()
    # f_domain = open("domain.txt", "w")
    # f_domain.write("------domain------\r")
    # for d in domain_list:
    #     f_domain.write(d+"\r")
    # f_domain.close()


if __name__ == "__main__":
    parser = OptionParser(usage="python3 main.py -t target")
    parser.add_option("-t", "--target", dest="target",
                      type="string")
    # parser.add_option("-o", "--output", dest="output",
    #                 default="..//", type="string")
    options, args = parser.parse_args()
    target = options.target  # "..\\target\\Test5.dll"  # parser.target
    # output = options.output  # "output.txt"  # parser.output

    f_target = open(target, "rb")

    buf = f_target.read()

    total_search(buf)
    pass
