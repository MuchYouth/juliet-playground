from typing import Dict, Generator, List, Optional, Set, Tuple

from paths import PROJECT_HOME, JULIET_TESTCASE_DIR, INFER_BIN, RESULT_DIR, GLOBAL_RESULT_DIR, PULSE_TAINT_CONFIG

import csv
import datetime
import os
import subprocess
import time
import typer

NUM_CORES = 20
VALID_EXTENSIONS = {'c', 'cpp'}
WINDOWS_SPECIFIC_MARKERS = ('w32', 'wchar_t')


CaseGroup = Tuple[str, str, str, str]  # (directory, head, number, extension)


def find_cwe_dir(cwe_number: int) -> Optional[str]:
    prefix = f'CWE{cwe_number}_'
    for entry in os.listdir(JULIET_TESTCASE_DIR):
        if entry.startswith(prefix):
            return entry
    return None


def iter_candidate_files(target_dir: str) -> Generator[str, None, None]:
    for entry in os.listdir(target_dir):
        file_path = os.path.join(target_dir, entry)
        if os.path.isdir(file_path):
            yield from iter_candidate_files(file_path)
            continue

        if '.' not in entry or 'CWE' not in entry:
            continue
        if any(marker in entry for marker in WINDOWS_SPECIFIC_MARKERS):
            continue

        _, extension = entry.rsplit('.', 1)
        if extension in VALID_EXTENSIONS:
            yield file_path


def parse_case_group(file_path: str) -> Optional[Tuple[CaseGroup, str, str, str, str]]:
    filename = os.path.basename(file_path)
    name_without_ext, extension = filename.rsplit('.', 1)

    split_pos = name_without_ext.rfind('_')
    if split_pos == -1:
        return None

    filename_head = name_without_ext[:split_pos]
    cwe_num = filename_head[0:filename_head.find('_')]
    filename_suffix = name_without_ext[split_pos + 1:]

    filename_num = filename_suffix[:-1] if filename_suffix[-1].isalpha() else filename_suffix
    group_key: CaseGroup = (os.path.dirname(file_path), filename_head, filename_num, extension)
    return group_key, cwe_num, filename_head, filename_num, extension


def build_infer_command(file_path: str, filename_head: str, filename_num: str,
                        extension: str) -> str:
    testcasesupport_dir = os.path.join(PROJECT_HOME, 'juliet-test-suite-v1.3',
                                       'C', 'testcasesupport')
    io_c = os.path.join(testcasesupport_dir, 'io.c')

    file_path_prefix_pos = file_path.rfind('/')
    file_path_prefix = file_path[:file_path_prefix_pos]
    target_file = os.path.join(file_path_prefix,
                               f'{filename_head}_{filename_num}*.{extension}')
    compiler = 'clang++' if extension == 'cpp' else 'clang'
    link_flag = ' -lm' if extension == 'cpp' else ''

    compile_cmd = f'{compiler} -I {testcasesupport_dir} -D INCLUDEMAIN {io_c} {target_file}{link_flag}'
    return f'{INFER_BIN} run -j {NUM_CORES} --pulse-taint-config {PULSE_TAINT_CONFIG} -- {compile_cmd}'


def run_infer_all(cwe_dir,
                  result_dir,
                  max_cases: Optional[int] = None,
                  executed_cases: Optional[List[int]] = None,
                  processed_groups: Optional[set] = None):
    if executed_cases is None:
        executed_cases = [0]
    if processed_groups is None:
        processed_groups = set()

    summary: Dict[str, object] = {
        'issue': 0,
        'no_issue': 0,
        'error': 0,
        'no_issue_files': []
    }
    start_time = time.time()
    target_dir = os.path.join(JULIET_TESTCASE_DIR, cwe_dir)
    for file_path in iter_candidate_files(target_dir):
        if max_cases is not None and executed_cases[0] >= max_cases:
            break

        parsed = parse_case_group(file_path)
        if parsed is None:
            continue

        group_key, cwe_num, filename_head, filename_num, extension = parsed
        if group_key in processed_groups:
            continue

        processed_groups.add(group_key)
        result_path = os.path.join(result_dir, f'{cwe_num}_{filename_num}-{filename_head}')
        os.makedirs(result_path, exist_ok=True)

        previous_cwd = os.getcwd()
        try:
            os.chdir(result_path)
            executed_cases[0] += 1
            infer_cmd = build_infer_command(file_path, filename_head, filename_num,
                                            extension)
            result = subprocess.check_output(infer_cmd, shell=True)
            if b'No issues found' in result:
                summary['no_issue'] += 1
                summary['no_issue_files'].append(file_path)
            else:
                summary['issue'] += 1
        except subprocess.CalledProcessError:
            summary['error'] += 1
        finally:
            os.chdir(previous_cwd)

    summary['time'] = time.time() - start_time
    return summary


def generate_result_csv(result_map, result_dir):
    csv_path = os.path.join(result_dir, 'result.csv')
    with open(csv_path, 'w') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow([
            'CWE NUMBER', 'ALL_TESTCASES', 'TIME(s)', 'ISSUE', 'NO ISSUE',
            'ERROR'
        ])

        for cwe_number in result_map:
            cwe_number_info = result_map[cwe_number]

            elapsed_sec = cwe_number_info['time']
            issue = cwe_number_info['issue']
            no_issue = cwe_number_info['no_issue']
            error = cwe_number_info['error']
            total_cases = issue + no_issue + error

            writer.writerow([cwe_number, total_cases, elapsed_sec, issue, no_issue, error])


def generate_no_issue_files(result_map, result_dir):
    txt_path = os.path.join(result_dir, 'no_issue_files.txt')
    with open(txt_path, 'w') as f:
        for cwe_number in result_map:
            no_issue_files = result_map[cwe_number]['no_issue_files']

            for file in no_issue_files:
                f.write(file)
                f.write('\n')


def main(cwes: List[int],
         generate_csv: bool = typer.Option(False),
         global_result: bool = typer.Option(False),
         max_cases: Optional[int] = typer.Option(
             None, help='Maximum number of testcases to run for each CWE')):

    if not os.path.exists(PULSE_TAINT_CONFIG):
        raise typer.BadParameter(
            f'Pulse taint config not found: {PULSE_TAINT_CONFIG}')

    result_dir = GLOBAL_RESULT_DIR if global_result else RESULT_DIR
    os.makedirs(result_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')
    juliet_result_dir = os.path.join(result_dir, f'juliet-result-{timestamp}')
    os.makedirs(juliet_result_dir, exist_ok=True)

    result_map: Dict[int, Dict[str, object]] = {}
    for cwe_number in cwes:
        cwe_dir = find_cwe_dir(cwe_number)
        if cwe_dir is None:
            continue
        result_map[cwe_number] = run_infer_all(cwe_dir,
                                               juliet_result_dir,
                                               max_cases=max_cases)

    if generate_csv:
        generate_result_csv(result_map, juliet_result_dir)

    generate_no_issue_files(result_map, juliet_result_dir)


if __name__ == '__main__':
    typer.run(main)
