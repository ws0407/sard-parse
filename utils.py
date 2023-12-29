import xml.etree.ElementTree as ET

# CWE编号：样本数量
cwe_cnt = {'122': 3486, '121': 3048, '78': 2800, '190': 2448, '762': 2072, '191': 1860, '134': 1680, '590': 1675,
           '23': 1400, '36': 1400, '124': 1228, '127': 1228, '401': 1032, '126': 912, '457': 817, '253': 684,
           '194': 672, '195': 672, '252': 630, '758': 581, '415': 560, '690': 560, '789': 560, '197': 504, '369': 504,
           '400': 420, '416': 398, '563': 366, '114': 336, '680': 336, '761': 336, '427': 280, '606': 280, '90': 280,
           '272': 252, '476': 236, '404': 224, '284': 216, '617': 186, '398': 181, '506': 158, '377': 144, '319': 112,
           '426': 112, '665': 112, '675': 112, '390': 90, '546': 90, '666': 90, '123': 84, '773': 84, '775': 84,
           '226': 72, '244': 72, '325': 72, '511': 72, '510': 70, '256': 56, '259': 56, '321': 56, '591': 56, '327': 54,
           '328': 54, '391': 54, '396': 54, '467': 54, '681': 54, '588': 50, '843': 50, '468': 37, '188': 36, '273': 36,
           '366': 36, '367': 36, '459': 36, '469': 36, '475': 36, '534': 36, '535': 36, '15': 28, '176': 28, '464': 28,
           '672': 27, '397': 20, '483': 20, '196': 18, '222': 18, '223': 18, '242': 18, '247': 18, '338': 18, '364': 18,
           '478': 18, '479': 18, '480': 18, '481': 18, '482': 18, '484': 18, '526': 18, '587': 18, '605': 18, '615': 18,
           '620': 18, '667': 18, '676': 18, '685': 18, '688': 18, '780': 18, '785': 18, '832': 18, '570': 16, '571': 16,
           '835': 6, '562': 3, '561': 2, '674': 2, '440': 1}


def count_samples():
    tree = ET.parse('/data/data/ws/sard-parse/C/manifest.xml')
    root = tree.getroot()
    cnt = {}
    for child in root:
        cnt_head = 0
        for grandchild in child:
            suffix = grandchild.attrib['path'][grandchild.attrib['path'].find('.') + 1:]
            if suffix == 'h':
                cnt_head += 1
        cwe = child[0].attrib['path'][:child[0].attrib['path'].find('_')]
        if len(child) - cnt_head == 1:
            cnt[cwe] = 1 if cwe not in cnt else cnt[cwe] + 1
    cnt = {k: v for k, v in sorted(cnt.items(), key=lambda x: x[1], reverse=True)}
    for k in cnt.keys():
        print('{}: {}'.format(k, cnt[k]))


def extract_single_cwe(cwe: int | str):
    tree = ET.parse('/data/data/ws/sard-parse/C/manifest.xml')
    root = tree.getroot()
    flaws = []
    for child in root:
        cwe_num = child[0].attrib['path'][3:child[0].attrib['path'].find('_')]
        if cwe_num != str(cwe) or len(child) != 1:  # 同下面注释
            continue
        # 实际上不需要考虑这个，因为带有.h的都有多个c或cpp文件，直接忽略
        # cnt_head = 0
        # for grandchild in child:
        #     suffix = grandchild.attrib['path'][grandchild.attrib['path'].find('.') + 1:]
        #     if suffix == 'h':
        #         cnt_head += 1
        # if len(child) - cnt_head != 1:
        #     continue
        flaw_line = None
        flaw_name = cwe
        path = []
        for grandchild in child:
            path.append(grandchild.attrib['path'])
            if len(grandchild) == 1:
                flaw_line = grandchild[0].attrib['line']
                flaw_name = grandchild[0].attrib['name']
        flaws.append({'name': flaw_name, 'line': flaw_line, 'path': path})
    return flaws


if __name__ == '__main__':
    for k in cwe_cnt.keys():
        flaw = extract_single_cwe(k)
        print(k, len(flaw))
        for f in flaw:
            if len(f['path']) > 1:
                print(f)
