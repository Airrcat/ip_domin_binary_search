from optparse import OptionParser


def extract_str(buf):
    # buf = open(file, "rb").read()
    str_list = []
    ptr = 0
    while ptr < len(buf):
        str_tmp = ""
        if buf[ptr] >= 0x20 and buf[ptr] <= 0x7f:
            # str_tmp += chr(buf[ptr])
            while buf[ptr] >= 0x20 and buf[ptr] <= 0x7f:
                str_tmp += chr(buf[ptr])
                ptr += 1
                if buf[ptr] == 0:  # Strong Mode
                    ptr += 1
                    continue
            if len(str_tmp) > 5:
                str_list.append(str_tmp)
        else:
            ptr += 1
    return str_list


def ip_search(str_list: list):
    pattern = r"((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}"
    import re
    ip_list = []
    for s in str_list:
        try:
            # print(s)
            ip = re.match(pattern, s)
            # print(ip)
            # for i in ip:
            if ip != None:
                ip_list.append(ip.string)
        except:
            pass
        # print(ip)

    return ip_list


def domain_search(str_list: list):
    import tld
    import re
    pattern = r'^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$'
    domain_list = []

    for s in str_list:
        try:
            # print(s)
            domain = re.match(pattern, s)

            if domain != None:
                # print(domain)
                if tld.get_tld(domain.string, fail_silently=True, fix_protocol=True) != None:
                    domain_list.append(domain.string)
        except:
            pass
    return domain_list


def result_check():
    pass


if __name__ == "__main__":
    parser = OptionParser(usage="python3 main.py -t target -o output")
    parser.add_option("-t", "--target", dest="target",
                      default="target", type="string")
    parser.add_option("-o", "--output", dest="output",
                      default="output", type="string")
    options, args = parser.parse_args()
    target = "..\\target\\Test5.dll"  # parser.target
    output = "output.txt"  # parser.output

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
