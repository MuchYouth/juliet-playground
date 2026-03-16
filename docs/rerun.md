# Re-run and operations guide

재실행, 자주 쓰는 명령, 운영상 주의사항을 정리한 문서입니다.
산출물 구조는 [`artifacts.md`](artifacts.md), 전체 문서 맵은 [`pipeline-runbook.md`](pipeline-runbook.md), 현재 단계 계약은 [`stage-contracts.md`](stage-contracts.md)를 참고하세요.
아래 예시는 현재 `tools/run_pipeline.py --help` / `tools/compare-artifacts.py --help` 기준입니다.

## 자주 쓰는 명령

### 1) Infer / Signature

```bash
# Infer + signature만 빠르게 실행
python tools/run_pipeline.py stage03 78

# 특정 파일(해당 flow variant 그룹)만 실행
python tools/run_pipeline.py stage03 --files juliet-test-suite-v1.3/C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_console_execlp_52a.c

# 기존 infer 결과에서 signature만 생성
python tools/run_pipeline.py stage03-signature --input-dir artifacts/infer-results/infer-2026.03.08-18:04:18
```

### 2) 전체 파이프라인

```bash
# CWE 여러 개
python tools/run_pipeline.py full 78 89

# 전체 CWE
python tools/run_pipeline.py full --all

# 재현성 옵션 예시
python tools/run_pipeline.py full 78 \
  --run-id run-my-fixed-id \
  --pair-split-seed 1234 \
  --pair-train-ratio 0.8 \
  --dedup-mode row
```

### 3) Pair / Slice만 따로 실행

```bash
# strict trace 결과만으로 paired trace dataset 생성
python tools/run_pipeline.py stage05 \
  --trace-jsonl artifacts/pipeline-runs/run-2026.03.09-22:18:32/04_trace_flow/trace_flow_match_strict.jsonl \
  --output-dir /tmp/paired-trace-ds

# 옵션 없이 실행하면 최신 pipeline run의 strict trace를 찾아
# 같은 run 아래 05_pair_trace_ds/ 로 출력
python tools/run_pipeline.py stage05

# 특정 run 기준으로 표준 경로에 다시 생성
python tools/run_pipeline.py stage05 \
  --run-dir artifacts/pipeline-runs/run-2026.03.09-22:18:32

# paired_signatures로부터 slice 생성
python tools/run_pipeline.py stage06 \
  --signature-db-dir artifacts/pipeline-runs/run-2026.03.09-22:18:32/05_pair_trace_ds/paired_signatures \
  --output-dir /tmp/paired-slices

# 옵션 없이 실행하면 최신 pipeline run의 paired_signatures를 찾아
# 같은 run 아래 06_slices/ 로 출력
python tools/run_pipeline.py stage06

# 특정 run 기준으로 표준 경로에 다시 생성
python tools/run_pipeline.py stage06 \
  --run-dir artifacts/pipeline-runs/run-2026.03.09-22:18:32
```

### 4) Patched counterpart export / Step 07 재실행

```bash
RUN_DIR=artifacts/pipeline-runs/run-2026.03.10-00:49:21

# 기존 run의 Step 07 재생성
python tools/run_pipeline.py stage07 \
  --pairs-jsonl "$RUN_DIR/05_pair_trace_ds/pairs.jsonl" \
  --paired-signatures-dir "$RUN_DIR/05_pair_trace_ds/paired_signatures" \
  --slice-dir "$RUN_DIR/06_slices/slice" \
  --output-dir "$RUN_DIR/07_dataset_export"

# 기존 train_val 샘플들에 대응하는 patched counterpart 평가셋 재생성
python tools/run_pipeline.py stage07b \
  --run-dir "$RUN_DIR" \
  --overwrite \
  --dataset-export-dir "$RUN_DIR/07_dataset_export"

# 표준 run layout이면 pair dir 기준으로도 재실행 가능
python tools/run_pipeline.py stage07b \
  --pair-dir "$RUN_DIR/05_pair_trace_ds" \
  --dataset-export-dir "$RUN_DIR/07_dataset_export" \
  --overwrite
```

### 5) 산출물 비교

```bash
# 두 pipeline run 비교
python tools/compare-artifacts.py \
  artifacts/pipeline-runs/run-before \
  artifacts/pipeline-runs/run-after

# 두 dataset export 디렉터리만 비교
python tools/compare-artifacts.py \
  artifacts/pipeline-runs/run-before/07_dataset_export \
  artifacts/pipeline-runs/run-after/07_dataset_export
```

## 운영 메모

### `stage03-signature`의 추출 대상

- `infer-out/report.json`의 모든 이슈를 저장하지 않습니다.
- 현재 구현은 `bug_type == TAINT_ERROR`만 대상으로 하며,
  그중 `bug_trace`가 empty가 아닌 레코드만 `non_empty/`에 저장합니다.

### Step 07 / 07b의 tokenizer 의존성

- `tools/run_pipeline.py stage07`, `tools/run_pipeline.py stage07b`는 내부적으로
  `microsoft/codebert-base` tokenizer를 로드합니다.
- 먼저 로컬 캐시를 찾고, 캐시가 없으면 원격 다운로드를 시도합니다.
- 네트워크가 제한된 환경에서는 **미리 모델 캐시를 준비해 두는 것**이 안전합니다.

### `--overwrite`가 필요한 경우

다음 스크립트는 출력 디렉터리/파일이 이미 존재하면 기본적으로 실패합니다.

- `tools/run_pipeline.py stage05`
- `tools/run_pipeline.py stage06`
- `tools/run_pipeline.py stage07b`

재실행 시 기존 산출물을 교체하려면 `--overwrite`를 명시하세요.

### 경로를 옮긴 뒤 재사용할 때

signature의 `bug_trace[].filename`은 원래 경로를 포함할 수 있습니다.
아티팩트를 다른 머신/다른 루트 경로로 옮긴 뒤 slice를 다시 만들면
원본 경로를 못 찾아 실패할 수 있습니다.

이 경우 아래 옵션을 사용합니다.

- `tools/run_pipeline.py stage06 --old-prefix ... --new-prefix ...`
- `tools/run_pipeline.py stage07b --old-prefix ... --new-prefix ...`

### 재현성 옵션

- `--run-id`: pipeline run 디렉터리 이름을 고정
- `--pair-split-seed`: pair-level train/test split 난수 시드
- `--pair-train-ratio`: train_val 비율 (`0 < ratio < 1`)
- `--dedup-mode`:
  - `row`: normalized slice 기준 row-level dedup 적용
  - `none`: dedup 비활성화

현재 구현에서 `row` 모드는
`md5("".join(normalized_code.split()))` 기준으로 해시를 만들고,
중복 또는 label collision이 발생한 pair를 걸러냅니다.

## Step 07 / 07b 직접 재실행 메모

- `rerun-step07` wrapper는 제거되었습니다.
- 이제 Step 07은 `run_pipeline.py stage07`, Step 07b는 `run_pipeline.py stage07b`를 직접 호출합니다.
- Step 07 결과를 다른 디렉터리에 만들었다면, Step 07b 실행 시 같은 경로를 `--dataset-export-dir`로 넘겨야 합니다.
- `stage05`, `stage06`, `stage07b`는 표준 pipeline run layout이면 `--run-dir` 또는 `--pair-dir`로 기본 경로를 유추할 수 있습니다.
- Step 07b 출력도 분리하고 싶으면 `--signature-output-dir`, `--slice-output-dir`,
  `--output-pairs-jsonl`, `--selection-summary-json`를 직접 지정하세요.
