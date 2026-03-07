# epic001_manifest_comment_scan

`manifest.xml`의 각 `file` 항목을 실제 소스 파일로 매핑해 아래 주석 시작 라인을 탐지합니다.

- `/* ... FLAW`
- `/* FIX`

탐지 결과는 각 `file` 하위에 다음 태그로 추가됩니다.

- `<comment_flaw line="N" code="..." function="..."/>`
- `<comment_fix line="N" code="..." function="..."/>`

속성 의미:
- `line`: 주석 시작 라인 번호
- `code`: 해당 라인 코드(양끝 공백 제거)
- `function`: 해당 라인이 속한 함수명(tree-sitter 기반)

함수 본문 내부가 아닌 주석(예: 필드 선언/함수 정의 직전 전역 주석)이나 tree-sitter 파싱 실패 케이스는 결과 XML에서 제거됩니다.
요약 통계의 `dropped_comment_lines`로 제거 건수를 확인할 수 있습니다.

## 구조
- `scripts/scan_manifest_comments.py`: 핵심 스캔/태깅 실행
- `scripts/report.py`: 통계 누적/요약 출력 유틸
- `requirements-ts.txt`: tree-sitter 관련 의존성(버전 고정)
- `inputs/manifest.xml`: 입력 manifest 사본
- `outputs/manifest_with_comments.xml`: 결과 XML

## 설치
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r experiments/epic001_manifest_comment_scan/requirements-ts.txt
```

## 실행
```bash
python experiments/epic001_manifest_comment_scan/scripts/scan_manifest_comments.py \
  --manifest experiments/epic001_manifest_comment_scan/inputs/manifest.xml \
  --source-root juliet-test-suite-v1.3/C \
  --output-xml experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml
```

실행 후 콘솔에 요약 통계(JSON)가 출력됩니다.

참고:
- 함수 컨텍스트 tree-sitter 파싱은 `.c`, `.cpp`에 대해 수행합니다 (`.h`는 함수 파싱 생략).
