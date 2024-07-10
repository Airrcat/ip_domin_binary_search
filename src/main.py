from multiprocessing import Pool
from multiprocess import *
from optparse import OptionParser
import os

key_list = ["passwd", "password", "secret", "key", "token"]


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
                if ptr >= len(buf):
                    break
                if ptr == len(buf):
                    # str_list.append(str_tmp)
                    break
                if mode == "strong" and buf[ptr] == 0:  # Mode
                    ptr += 1
                    if ptr >= len(buf):
                        break
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


def extract_code_str(buf: bytes) -> list[str]:
    """旨在提取代码文件中的字符串信息（用引号包裹的字符串）
    尚不能匹配中文。
    :param buf: 提取源
    :return: 字符串列表
    """
    p = 0
    check = 0
    code_strs = []
    code_str = ""
    while p < len(buf):
        # print(p, len(buf))
        if check == 1:
            "找到字符串头后，匹配字符串"
            if buf[p] == ord("\""):
                "找到字符串尾，退出"
                check = 0
                code_strs.append(code_str)
               # print(code_strs)
                code_str = ""
                p += 1
                continue
            if buf[p] >= 0x20 and buf[p] < 0x7f:
                "匹配字符"
                code_str += chr(buf[p])
                p += 1

                continue
            else:
                "非明文字符串"
                check = 0
                code_str = ""
                p += 1
                continue
        if buf[p] == ord("\""):
            "找到字符串头"
            check = 1
            p += 1
            continue
        p += 1

    p = 0
    check = 0
    check = 0
    while p != len(buf):
        # print(buf[p])
        if check == 1:
            "找到字符串头后，匹配字符串"
            if buf[p] == ord("\'"):
                "找到字符串尾，退出"
                check = 0
                code_strs.append(code_str)
                code_str = ""
                p += 1
                continue
            if buf[p] >= 0x20 and buf[p] < 0x7f:
                "匹配字符"
                code_str += chr(buf[p])
                p += 1
                continue
            else:
                "非明文字符串"
                check = 0
                code_str = ""
                p += 1
                continue

        if buf[p] == ord("\'"):
            "找到字符串头"
            check = 1
            p += 1
            continue
        p += 1

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


def keyword_search2(path: str) -> list[str]:
    about_keyword_list = [""]
    f = open(path, "rb")
    buf = f.read()
    f.close()
    str_list = extract_str(buf)
    for s in str_list:
        # print(s)
        tmp = s
        count = 0
        for k in key_list:
            # print(f"k:{k}")
            while tmp.find(k) != -1:
                index = tmp.find(k)
                # print(f"index:{index}")
                prefix = 25 if index > 25 else index
                suffix = 25 if len(tmp) - index - \
                    len(k) > 25 else len(tmp) - index - len(k)
                # if len(about_keyword_list) > 0:
                if about_keyword_list[-1] == tmp:
                    break
                about_keyword_list.append(
                    tmp[index-prefix:index+len(k)+suffix])
                tmp = tmp[index+len(k)+suffix::]
                # print(f"tmp:{tmp}")
                # print(
                #    f"tmp:{tmp}\r\nlen:{len(tmp)}\r\nindex2:{index+len(k)+suffix}")

    return about_keyword_list


def keyword_search(keywords: list, strs: list) -> list[str]:
    keyword_list = []
    check = 0
    for s in strs:
        for k in keywords:
            if check == 1:
                check = 0
                keyword_list.append(s)
            if k in s:
                keyword_list.append(s)
                check = 1
                break
    return keyword_list


def search_document(path: str):
    f_str = open("output2.txt", "w")
    keyword_list = []
    ip_list = []
    domain_list = []
    for filepath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            tmp = os.path.join(filepath, filename)
            if ".git" in tmp:
                break
            if os.stat(tmp).st_size > 1 * 1024*1024:
                continue
            # print(tmp)
            f = open(tmp, "rb")
            buf = f.read()
            f.close()

            s0 = extract_str(buf)

            # print(os.path.join(filepath, filename))
            s1 = keyword_search(key_list, extract_code_str(buf))
            s2 = extract_ip(buf)
            s3 = extract_domain(buf)
            keyword_list.append(s1)
            ip_list.append(s2)
            domain_list.append(s3)

    f_str.write("-----keyword------\r")
    for s in keyword_list:
        for i in s:
            f_str.write(i+"\r")
    f_str.write("--------ip--------\r")
    for s in ip_list:
        for i in s:
            f_str.write(i+"\r")
    f_str.write("------domain------\r")
    for s in domain_list:
        for i in s:
            f_str.write(i+"\r")
    f_str.close()
    pass


def search_in_file_list(file_list: list[str]):
    keyword_list = []
    ip_list = []
    domain_list = []
    # print(file_list)
    for file in file_list:
        f = open(file, "rb")
        # print(file)
        if os.stat(file).st_size > 1 * 1024 * 1024:
            continue

        buf = f.read()
        f.close()
        if len(buf) > 4*1024*1024:
            continue
        # s0 = extract_str(buf)

        # print(os.path.join(filepath, filename))
        # s1 = keyword_search(key_list, extract_code_str(buf))
        s1 = keyword_search2(file)
        s2 = extract_ip(buf)
        s3 = extract_domain(buf)
        keyword_list.append(s1)
        ip_list.append(s2)
        domain_list.append(s3)
    return [keyword_list, ip_list, domain_list]
    pass


def remove_same_in_list(lst: list):
    new_lst = []
    for i in lst:
        for l in i:
            if l not in new_lst:
                new_lst.append(l)
    return new_lst


def search_in_document_by_multi(path: str):
    f_str = open("output3.txt", "w")
    file_list = []
    keyword_list = []
    ip_list = []
    domain_list = []
    for filepath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            tmp = os.path.join(filepath, filename)
            if ".git" in tmp:
                break
            if os.stat(tmp).st_size > 1 * 1024*1024:
                continue
            file_list.append(tmp)
    process_count = len(file_list) // 1000
    if process_count == 0:
        process_count = 1
    # print(process_count)
    for p in range(0, process_count, 5):

        pool = Pool(processes=5)
        for i in range(5):
            print(p+i)
            # print(list(file_list[(p+i)*1000:(p+i+1)*1000]))
            if p + i >= process_count:
                # print((p+i)*1000, len(file_list))
                tmp = pool.apply_async(
                    search_in_file_list, (file_list[(p+i)*1000:],)).get()
            else:
                # print((p+i+1)*1000, len(file_list))
                tmp = pool.apply_async(
                    search_in_file_list, (file_list[(p+i)*1000:(p+i+1)*1000],)).get()

            keywords = tmp[0]
            ips = tmp[1]
            domains = tmp[2]
            keyword_list += (keywords)
            ip_list += (ips)
            domain_list += (domains)
            if p + i >= process_count:
                break
        pool.close()
        pool.join()
    keyword_list = remove_same_in_list(keyword_list)
    ip_list = remove_same_in_list(ip_list)
    domain_list = remove_same_in_list(domain_list)
    # keyword_list.sort()
    # ip_list.sort()
    # domain_list.sort()
    f_str.write("-----keyword------\r")
    for s in keyword_list:
        # for i in s:
        if len(s) != 0:
            f_str.write(s+"\r")
    f_str.write("--------ip--------\r")
    for s in ip_list:
        if len(s) != 0:
            f_str.write(s+"\r")
    f_str.write("------domain------\r")
    for s in domain_list:
        if len(s) != 0:
            f_str.write(s+"\r")
    f_str.close()
    pass
    pass


def test():
    search_document(r"E:\Code\Python\\")


def test2():
    search_in_document_by_multi(r"D:\\work")


if __name__ == "__main__":
    # f = open("./main.py", "rb")
    # buf = f.read()
    # code_str_list = extract_code_str(buf)
    # print(code_str_list)
    test2()
    exit()
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
