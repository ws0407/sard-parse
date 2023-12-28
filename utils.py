import xml.etree.ElementTree as ET


def count_samples():
    tree = ET.parse('/data/data/ws/sard-parse/C/manifest.xml')
    root = tree.getroot()
    cnt = {}
    for child in root:
        cnt_head = 0
        for grandchild in child:
            suffix = grandchild.attrib['path'][grandchild.attrib['path'].find('.')+1:]
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
    cnt = {}
    for child in root:
        cwe_num = child[0].attrib['path'][3:child[0].attrib['path'].find('_')]
        if cwe_num != str(cwe):
            continue
        cnt_head = 0
        for grandchild in child:
            suffix = grandchild.attrib['path'][grandchild.attrib['path'].find('.') + 1:]
            if suffix == 'h':
                cnt_head += 1
        if len(child) - cnt_head != 1:
            continue


