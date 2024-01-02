from utils import *


def test_data_match():
    """
    已验证数据集中的关键词都匹配
    :return:
    """
    for cwe in cwe_cnt.keys():
        flaw = extract_cwe_info(cwe)
        for f in flaw:
            base_path = '/data/data/ws/sard-parse/C/testcases/' + f['name'][:f['name'].find("__")]
            file_path = None
            for root, dirs, files in os.walk(base_path):
                if f['name'] in files:
                    file_path = os.path.join(root, f['name'])
            if file_path is None:
                print('not exist:', f['name'])
                continue
            with open(file_path, 'r') as f1:
                program = str(f1.read())
            program = re.sub(f"#ifndef OMITBAD.*?#endif /\* OMITBAD \*/", "", program, flags=re.DOTALL)
            program = re.sub(f"#ifndef OMITGOOD.*?#endif /\* OMITGOOD \*/", "", program, flags=re.DOTALL)
            if program.find('#ifdef INCLUDEMAIN'):
                program = (program[:program.find("#ifdef INCLUDEMAIN")] +
                           re.sub(f"#endif", "", program[program.find("#ifdef INCLUDEMAIN") + 18:]))
            program = re.sub(f"\n+", "\n", program)
            if program.find("#ifdef INCLUDEMAIN") != -1:
                if program[program.find("#ifdef INCLUDEMAIN"):].count('#endif') != 1:
                    print(program[program.find("#ifdef INCLUDEMAIN"):].count('#endif'))
                    print('ifdef main not match:', f['name'])
        print('[cwe]', cwe, 'done')


def test_location() -> None:
    """
    已验证数据集中大部分样本都【不】匹配
    :return:
    """
    for cwe in cwe_cnt.keys():
        flaw = extract_cwe_info(cwe)
        for f in flaw:
            base_path = '/data/data/ws/sard-parse/C/testcases/' + f['name'][:f['name'].find("__")]
            file_path = None
            for root, dirs, files in os.walk(base_path):
                if f['name'] in files:
                    file_path = os.path.join(root, f['name'])
            if file_path is None:
                print('[file] not exist:', f['name'])
                continue
            with open(file_path, 'r') as f1:
                program = str(f1.read())
            if program.find('/* FLAW: ') != -1:
                program = program[:program.find('/* FLAW: ')]
                total_line = program.count('\n')
                if int(f['line']) != total_line + 2:
                    print('[line] not match:', f['name'])
            else:
                print('[flaw] not found:', f['name'])
        print('[cwe]', cwe, 'done')


def test_special_char(s) -> None:
    """
    已验证数据集中不包含***和$$$
    :return:
    """
    for cwe in cwe_cnt.keys():
        flaw = extract_cwe_info(cwe)
        for f in flaw:
            base_path = '/data/data/ws/sard-parse/C/testcases/' + f['name'][:f['name'].find("__")]
            file_path = None
            for root, dirs, files in os.walk(base_path):
                if f['name'] in files:
                    file_path = os.path.join(root, f['name'])
            if file_path is None:
                print('[file] not exist:', f['name'])
                continue
            with open(file_path, 'r') as f1:
                program = str(f1.read())
            if program.find(s) != -1:
                print('[special_char] found:', f['name'])
        print('[cwe]', cwe, 'done')


def test_get_func() -> None:
    for cwe in cwe_cnt.keys():
        flaw = extract_cwe_info(cwe)
        for f in flaw:
            base_path = '/data/data/ws/sard-parse/C/testcases/' + f['name'][:f['name'].find("__")]
            file_path = None
            for root, dirs, files in os.walk(base_path):
                if f['name'] in files:
                    file_path = os.path.join(root, f['name'])
            if file_path is None:
                print('[file] not exist:', f['name'])
                continue
            with open(file_path, 'r') as f1:
                program = str(f1.read())
            if program.find('good()') == -1:
                print('[func] not found:', f['name'])
            else:
                good = program[program.find('good()'):program.find('}', program.find('good()'))]
                print(good)
        print('[cwe]', cwe, 'done')

test_get_func()