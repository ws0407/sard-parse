import xml.etree.ElementTree as ET
import os
import re
import tqdm
import json
from typing import List
import codecs

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


def find_nth_str(s, sub, n, index=-1):
    """
    递归查找子字符串在字符串中第n次出现的位置（不包含字串重复，如ababa中没有第二次出现aba）
    :param s: 原始字符串
    :param sub: 子字符串
    :param n: 第n次出现的位置
    :param index: 当前查找的起始位置
    :return: 子字符串在字符串中第n次出现的位置，如果子字符串未出现n次，则返回-1
    """
    if n == 0:
        return index
    index = s.find(sub, index + len(sub))
    if index == -1:
        return -1
    return find_nth_str(s, sub, n - 1, index)


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


def extract_cwe_info(cwe: int | str) -> list[dict]:
    """
    :param cwe: CWE编号
    :return: 从xml中提取的所有cwe信息（漏洞位置 + 文件名）
    """
    tree = ET.parse('/data/data/ws/sard-parse/C/manifest.xml')
    root = tree.getroot()
    cwe_info = []
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
        name = []
        for grandchild in child:
            name.append(grandchild.attrib['path'])
            if len(grandchild) >= 1:
                flaw_line = grandchild[0].attrib['line']
        cwe_info.append({'line': flaw_line, 'name': name[0]})
    return cwe_info


def split_good(program: str) -> list[str]:
    """
    1. 提取出good函数名列表
    2. 针对每个good函数，删除其他good函数内容，并将主函数中calling good换成此good函数
    :param program:
    :return:
    """
    program = program.replace(' \n', '\n')
    # 1. 提取出good函数名列表出good函数名列表
    s_str = 'printLine("Calling good()...");'
    e_str = 'printLine("Finished good()");'
    start = program.find(s_str) + len(s_str)
    if start == 30:
        return []
    end = program.find(e_str)
    main_good_name = [_ for _ in program[start:end].split('\n') if not (_.isspace() or len(_) == 0)][0]
    main_good_name = main_good_name.replace(' ', '').replace(';', '')  # good()
    s_str = main_good_name + '\n{'
    start = program.find(s_str) + len(s_str)
    end = program.find('\n}', start)
    good_func_list = [_.replace(' ', '').replace(';', '')
                      for _ in program[start:end].split('\n') if not (_.isspace() or len(_) == 0)]
    good_program_list = []
    start = program[:start - 2].rfind('\n')
    program = program[:start] + program[end + 2:]
    for good_func in good_func_list:
        good_program = program.replace(main_good_name, good_func)  # good1()
        for other_good_func in good_func_list:
            if other_good_func != good_func:
                start = good_program.find(other_good_func + '\n{')
                start = good_program[:start].rfind('\n')
                end = good_program.find('\n}', start)
                good_program = good_program[:start] + good_program[end + 2:]
        good_program_list.append(re.sub(f"\n+", "\n", good_program))
    return good_program_list


def save_single_cwe_sample(line: int | str | None, name: str | list, out_path: str) -> bool:
    """
    :param line: 漏洞行号
    :param name: 文件名
    :param out_path: 输出路径
    :return:
    """
    # 输出json的路径
    out_path = '{}/{}'.format(out_path, name[:name.find('__')])
    json_path = '{}/{}.json'.format(out_path, name[:name.find('.')])
    if not os.path.exists(out_path):
        os.makedirs(out_path)
    if os.path.exists(json_path):
        # with open(json_path, 'r') as f:
        #     json_file = json.dumps(json.load(f))
        # if '_WIN32' not in json_file:
        return True

    # 搜索文件位置
    base_path = '/data/data/ws/sard-parse/C/testcases/' + name[:name.find("__")]
    file_path = None
    for root, dirs, files in os.walk(base_path):
        if name in files:
            file_path = os.path.join(root, name)
            break
    if file_path is None:
        print('[file] not exist:', name)
        return False

    # 漏洞行号
    try:
        line = int(line)
    except Exception as e:
        print('[error]', e, name)
        return False

    # 暂时只考虑单文件的样本
    if type(name) == list:
        name = name[0]

    with open(file_path, 'r') as f:
        program = f.read()
    # 在替换前用***标注定位
    flaw_start = find_nth_str(program, '\n', line - 1)
    program = program[:flaw_start + 1] + '***' + program[flaw_start + 1:]
    if program.find('#ifdef INCLUDEMAIN'):
        program = (program[:program.find("#ifdef INCLUDEMAIN")] +
                   re.sub(f"\n\n#endif", "", program[program.rfind("#ifdef INCLUDEMAIN") + 18:]))

    # 去除宏定义，如#ifdef/ifndef _WIN32中的内容，默认在linux执行
    program = re.sub(r'(#ifdef _WIN32)(.*?)(#else)(.*?)(#endif)',
                     lambda match: match.group(4)
                     if re.compile(r'^((?!.+#endif).)+', flags=re.DOTALL).match(match.group(2))
                     else ''.join([match.group(_) for _ in range(1, 6)]),
                     program, flags=re.DOTALL)
    program = re.sub(r'(#ifdef _WIN32)(.*?)(#endif)', '', program, flags=re.DOTALL)
    program = re.sub(r'(#ifndef _WIN32)(.*?)(#else)(.*?)(#endif)',
                     lambda match: match.group(4)
                     if re.compile(r'^((?!.+#endif).)+', flags=re.DOTALL).match(match.group(2))
                     else ''.join([match.group(_) for _ in range(1, 6)]),
                     program, flags=re.DOTALL)
    program = re.sub(r'(#ifndef _WIN32)(.*?)(#endif)', lambda match: match.group(2), program, flags=re.DOTALL)

    # 分割good和bad
    good = re.sub(f"#ifndef OMITBAD.*?#endif /\* OMITBAD \*/", "", program, flags=re.DOTALL)
    good = good.replace('#ifndef OMITGOOD', '').replace('#endif /* OMITGOOD */', '')
    bad = re.sub(f"#ifndef OMITGOOD.*?#endif /\* OMITGOOD \*/", "", program, flags=re.DOTALL)
    bad = bad.replace('#ifndef OMITBAD', '').replace('#endif /* OMITBAD */', '')

    # 多个good分离开来，另外把多标注的***定位去除
    good = [_.replace('***', '', 1) for _ in split_good(good)]

    # 去除注释
    good = [re.sub(r'(/\*([^*]|(\*+[^*/]))*\*+/)|(//.*)', '', _) for _ in good]
    bad = re.sub(r'(/\*([^*]|(\*+[^*/]))*\*+/)|(//.*)', '', bad)

    # 利用re去除printLine语句，如果printLine中只有常量字符串
    good = [re.sub(r'printLine\("([^"\\\n]|\\.|\\\n)*"\);', '', _) for _ in good]
    bad = re.sub(r'printLine\("([^"\\\n]|\\.|\\\n)*"\);', '', bad)
    # 去除多余的换行符
    good = [re.sub(f"\n(\s*)\n", "\n", _) for _ in good]
    good = [_[1:] if _[0] == '\n' else _ for _ in good]
    bad = re.sub(f"\n(\s*)\n", "\n", bad)
    bad = bad[1:] if bad[0] == '\n' else bad

    # 标注
    line = bad[:bad.find('***')].count('\n') + 1
    bad = bad.replace('***', '', 1)
    output = {
        'line': line,
        'type': name[name.find('.') + 1:],
        'bad': bad,
        'good': good
    }
    try:
        with open(json_path, 'w') as f:
            json.dump(output, f)
    except Exception as e:
        print('[error]', e, name)
        return False
    return True


def process_data():
    for cwe in cwe_cnt.keys():
        # if cwe in ['122', '121', '78', '190', '762', '191', '134', '590', '23']:
        #     continue
        flaw = extract_cwe_info(cwe)
        cnt = 0
        for f in tqdm.tqdm(flaw, desc=f'[CWE{cwe}]'):
            res = save_single_cwe_sample(f['line'], f['name'], '/data/data/ws/sard-parse/output/clean')
            cnt = cnt + 1 if res else cnt
        print('[cwe]', cwe, 'success:', cnt, 'fail:', len(flaw) - cnt)


def gen_std_program(program) -> str:
    """自定义变量、函数匿名化
    1.查找所有自定义的变量、函数（根据数据类型、返回值类型定位）
    2.匹配所有上述变量、函数进行替换（非字母）
    3.替换成VAR1,2,3..., FUNC1,2,3...

    # 函数: type func_name(...){}
    # 类: class
    # struct: typedef struct s_name {} xxx 已验证所有的struct都带有typedef
    # typedef: 已验证所有的typedef只有struct和union
    # namespace xxx
    # goto: goto address_name
    # 变量: type var_name[ = ; ...
    # type: 可跟 *，表示指针

    :param program:
    :return:

    """
    type_set = ['int', '_int16', '_int32', '_int64', '_int8', '__int16', '__int32', '__int64', '__int8',
                'char', 'char16_t', 'char32_t', 'wchar_t', 'void', 'short', 'float', 'double', 'long']

    others_set = ['namespace', 'goto']

    # 识别class，替换， # 加入type_set(暂时不用)
    re_class = re.compile(r'(\W)(class)(\s+)([_A-Za-z]\w*)(\W)')
    class_names = [_[3] for _ in re_class.findall(program)]
    for i, class_name in enumerate(class_names):
        re_class_name = re.compile(r'(\W)(' + class_name + r')(\W)')
        program = re.sub(re_class_name, lambda m: m.group(1) + 'CLASS' + str(i + 1) + m.group(3), program)
        # type_set.append('CLASS' + str(i+1))

    # 识别struct，替换，加入type_set
    re_struct = re.compile(r'(\W)(struct)(\s+)([_A-Za-z]\w*)(\s*?)({)(.*?)(})(\s*?)([_A-Za-z].*?)(;)', flags=re.DOTALL)
    struct_all = re_struct.findall(program)
    struct_names = [_[3] for _ in struct_all]
    for i, struct_name in enumerate(struct_names):
        re_struct_name = re.compile(r'(\W)(' + struct_name + r')(\W)')
        program = re.sub(re_struct_name, lambda m: m.group(1) + 'STRUCT' + str(i + 1) + m.group(3), program)
        type_set.append('STRUCT' + str(i + 1))

    # 识别typedef，替换，加入type_set
    re_typedef = re.compile(r'(\W)(typedef)(.*?)(})(\s*?)([_A-Za-z].*?)(;)', flags=re.DOTALL)
    typedef_names = [_[-2] for _ in re_typedef.findall(program)]
    for i, typedef_name in enumerate(typedef_names):
        re_typedef_name = re.compile(r'(\W)(' + typedef_name + r')(\W)')
        program = re.sub(re_typedef_name, lambda m: m.group(1) + 'TYPEDEF' + str(i + 1) + m.group(3), program)
        type_set.append('TYPEDEF' + str(i + 1))

    # namespace，goto，替换
    re_others = re.compile(r'(\W)(' + '|'.join(others_set) + r')(\s+)([_A-Za-z]\w*)(\W)')
    others_names = [_[-2] for _ in re_others.findall(program)]
    for i, others_name in enumerate(others_names):
        re_others_name = re.compile(r'(\W)(' + others_name + r')(\W)')
        program = re.sub(re_others_name, lambda m: m.group(1) + 'OTHERS' + str(i + 1) + m.group(3), program)

    # 识别函数定义，替换
    re_func = re.compile(r'(\W)(' + '|'.join(type_set) + r')(\s+)([_A-Za-z]\w*)(\s*?)(\()(.*?)(\))(\s*?)({)(.*?)(})',
                         flags=re.DOTALL)
    func_names = [_[3] for _ in re_func.findall(program) if _[3] != 'main']
    std_func_names = []
    for i, func_name in enumerate(func_names):
        re_func_name = re.compile(r'(\W)(' + func_name + r')(\W)')
        program = re.sub(re_func_name, lambda m: m.group(1) + 'FUNC' + str(i + 1) + m.group(3), program)
        std_func_names.append('FUNC' + str(i + 1))

    # type，这些词定义的变量都需要替换，这些词后面有 * （指针），也需要替换
    re_type = re.compile(r'(\W)(' + '|'.join(type_set) + r')((\s+)|(\s*?\*\s*?))([_A-Za-z]\w*)(\W)')
    var_names = [_[-2] for _ in re_type.findall(program) if _[-2] not in ['main', 'argc', 'argv'] + std_func_names]
    for i, var_name in enumerate(var_names):
        re_var_name = re.compile(r'(\W)(' + var_name + r')(\W)')
        program = re.sub(re_var_name, lambda m: m.group(1) + 'VAR' + str(i + 1) + m.group(3), program)

    return program


def std_all(in_path='/data/data/ws/sard-parse/output/clean', out_path='/data/data/ws/sard-parse/output/std'):
    for root, dirs, files in os.walk(in_path):
        for file in tqdm.tqdm(files):
            file_path = os.path.join(root, file)
            with open(file_path, 'r') as f:
                sample = json.load(f)
            sample['bad'] = gen_std_program(sample['bad'])
            sample['good'] = [gen_std_program(_) for _ in sample['good']]
            out_file_path = '{}/{}'.format(out_path, root[root.rfind('/') + 1:])
            if not os.path.exists(out_file_path):
                os.makedirs(out_file_path)
            with open('{}/{}'.format(out_file_path, file), 'w') as f:
                json.dump(sample, f)
        print(root, 'done')


if __name__ == '__main__':
    std_all()
    # process_data()
    # p = '''#include \"std_testcase.h\"\n#ifndef _WIN32\n#include <wchar.h>\n#endif\n#define SRC_STR \"0123456789abcdef0123456789abcde\"\ntypedef struct _charVoid\n{\n    char charFirst[16];\n    void * voidSecond;\n    void * voidThird;\n} charVoid;\nvoid CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_02_bad()\n{\n    if(1)\n    {\n        {\n            charVoid structCharVoid;\n            structCharVoid.voidSecond = (void *)SRC_STR;\n            printLine((char *)structCharVoid.voidSecond);\n            memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid));\n            structCharVoid.charFirst[(sizeof(structCharVoid.charFirst)/sizeof(char))-1] = '\\0'; \n            printLine((char *)structCharVoid.charFirst);\n            printLine((char *)structCharVoid.voidSecond);\n        }\n    }\n}\nint main(int argc, char * argv[])\n{\n    srand( (unsigned)time(NULL) );\n    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_02_bad();\n    return 0;\n}\n'''
    # print(p)
    # print(gen_std_program(p))

    # s = "ababababab"
    # sub = "aba"
    # n = 2
    # print(find_nth_str(s, sub, n, -len(sub)))
    # save_single_cwe_sample(685, 'CWE15_External_Control_of_System_or_Configuration_Setting__w32_02.c')
    # print(extract_cwe_info(685))
    # for k in cwe_cnt.keys():
    #     flaw = extract_cwe_info(k)
    #     print(k, len(flaw))
    #     for f in flaw:
    #         if len(f['path']) > 1:
    #             print(f)

    pass
