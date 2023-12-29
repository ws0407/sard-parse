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
        print(cwe, 'ok')


if __name__ == '__main__':
    test_data_match()