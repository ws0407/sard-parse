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
    """
    除了一些文件没有good函数（只有bad），其他的都是没有参数的good函数
    所有的文件都有bad函数，且都没有参数
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
                program = program.replace(' \n', '\n')
            if program.find('printLine("Calling good()...");') == -1:
                print('[func good()] not found:', f['name'])
            else:
                s_str = 'printLine("Calling good()...");'
                e_str = 'printLine("Finished good()");'
                start = program.find(s_str) + len(s_str)
                end = program.find(e_str)
                good_content = [_ for _ in program[start:end].split('\n') if not (_.isspace() or len(_) == 0)][0]
                good_content = good_content.replace(';', '')
                good_content = good_content.replace(' ', '')
                s_str = good_content + '\n{'
                start = program.find(s_str) + len(s_str)
                end = program.find('\n}', start)
                good_func_list = [_ for _ in program[start:end].split('\n') if not (_.isspace() or len(_) == 0)]
                good_func_std = [_ for _ in good_func_list if _.find('();') != -1]
                if len(good_func_list) != len(good_func_std):
                    print('[func good()] not standard:', f['name'], good_func_list)

        print('[cwe]', cwe, 'done')


def test_remove_win32() -> None:
    """已验证通过
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
            program = re.sub(r'(#ifdef _WIN32)(.*?)(#else)(.*?)(#endif)',
                             lambda match: match.group(4), program, flags=re.DOTALL)
            program = re.sub(r'(#ifdef _WIN32)(.*?)(#endif)', '', program, flags=re.DOTALL)
            print(program)


def test_std_program(program: str) -> None:
    """自定义变量、函数匿名化
    1.查找所有自定义的变量、函数（根据数据类型、返回值类型定位）
    2.匹配所有上述变量、函数进行替换（非字母）
    3.替换成VAR1,2,3..., FUNC1,2,3...
    :param program:
    :return:

    """
    keywords = {'__asm', '__builtin', '__cdecl', '__declspec', '__except', '__export', '__far16', '__far32',
                '__fastcall', '__finally', '__import', '__inline', '__int16', '__int32', '__int64', '__int8',
                '__leave', '__optlink', '__packed', '__pascal', '__stdcall', '__system', '__thread', '__try',
                '__unaligned', '_asm', '_Builtin', '_Cdecl', '_declspec', '_except', '_Export', '_Far16',
                '_Far32', '_Fastcall', '_finally', '_Import', '_inline', '_int16', '_int32', '_int64',
                '_int8', '_leave', '_Optlink', '_Packed', '_Pascal', '_stdcall', '_System', '_try', 'alignas',
                'alignof', 'and', 'and_eq', 'asm', 'auto', 'bitand', 'bitor', 'bool',
                'catch', 'char', 'char16_t', 'char32_t', 'class', 'compl', 'decltype',
                'double', 'dynamic_cast', 'enum',
                'explicit', 'export', 'extern', 'false', 'final', 'float', 'friend',
                'inline', 'int', 'long', 'mutable', 'noexcept', 'nullptr',
                'operator', 'or_eq', 'override', 'private', 'protected', 'public', 'register',
                'reinterpret_cast', 'return', 'short', 'static_assert',
                'static_cast', 'struct', 'template','thread_local', 'throw',
                'typedef', 'typeid', 'typename', 'union', 'unsigned', 'virtual', 'void', 'volatile',
                'wchar_t', }
    test_keys = {
        'struct *', 'struct*', 'struct  *'
    }
    for cwe in cwe_cnt.keys():
        flaw = extract_cwe_info(cwe)
        exist_key = []
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
            for key in test_keys:
                if key in program:
                    print('[key]', key, f['name'])
        print('[cwe]', cwe, exist_key)


test_std_program('')
