from optparse import OptionParser


def extract_str(buf: bytes, target="ip", mode="strong") -> list[str]:
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
        if buf[ptr] >= 0x20 and buf[ptr] <= 0x7f:  # 进入字符串提取循环
            while buf[ptr] >= 0x20 and buf[ptr] <= 0x7f:
                str_tmp += chr(buf[ptr])
                ptr += 1
                if mode == "strong" and buf[ptr] == 0:  # Mode
                    ptr += 1
                    continue
            if target == "ip":  # target
                if len(str_tmp) > 5:
                    str_list.append(str_tmp)
            elif target == "str":
                if len(str_tmp) > 1:
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
    import re
    ip_list = []
    for s in str_list:
        ip = re.match(pattern, s)
        if ip != None:
            ip_list.append(ip.string)

    return ip_list


def domain_search(str_list: list) -> list[str]:
    """在字符串列表中使用正则匹配域名，并使用tld库进行一次顶级域名校验。

    Args: str_list->字符串列表源

    Return: 目的域名列表

    """
    import tld
    import re
    pattern = r'^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$'
    domain_list = []

    for s in str_list:
        domain = re.match(pattern, s)
        if domain != None:
            if tld.get_tld(domain.string, fail_silently=True, fix_protocol=True) != None:
                domain_list.append(domain.string)

    return domain_list


def result_check():
    pass


if __name__ == "__main__":
    parser = OptionParser(usage="python3 main.py -t target -o output.txt")
    parser.add_option("-t", "--target", dest="target",
                      default="target", type="string")
    parser.add_option("-o", "--output", dest="output",
                      default="output", type="string")
    options, args = parser.parse_args()
    target = options.target  # "..\\target\\Test5.dll"  # parser.target
    output = options.output  # "output.txt"  # parser.output

    f_target = open(target, "rb")
    f_output = open(output, "w")
    buf = f_target.read()

    str_list = extract_str(buf)
    ip_list = ip_search(str_list)
    domain_list = domain_search(str_list)
    f_output.write("--------str-------\r\n")
    for s in str_list:
        f_output.write(s+"\r")
    f_output.write("--------ip--------\r\n")
    for i in ip_list:
        f_output.write(i+"\r")
    f_output.write("------domain------\r\n")
    for d in domain_list:
        f_output.write(d+"\r")
    pass
