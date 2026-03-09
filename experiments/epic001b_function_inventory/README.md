# epic001b_function_inventory

## 1) 인벤토리 추출
```bash
python experiments/epic001b_function_inventory/scripts/extract_function_inventory.py
```

## 2) flow_family / operation_role 분류 + 중첩 그룹 출력
```bash
python experiments/epic001b_function_inventory/scripts/categorize_function_names.py
```

출력:
- `outputs/function_names_categorized.jsonl` (함수 1개당 1라인)
  - 필드: `function_name,count,simple_name,flow_family,operation_role,role_variant`
- `outputs/grouped_family_role.json`
  - 구조: **1뎁스 `flow_families` → 2뎁스 `operation_roles` → 3뎁스 `role_variants`**
- `outputs/category_summary.json`

`flow_family`:
- `g2b_family`, `b2g_family`, `g2g_family`, `b2b_family`
- `helper_family`, `class_family`, `misc_family`

`operation_role`:
- `source`, `sink`, `source_sink`

`role_variant`:
- `source`: `source`
- `sink`: `direct_sink`, `va_sink`, `action_sink`
- `source_sink`: `source_func_only`, `sink_func_only`, `both_func_included`, `both_func_excluded`

`source_sink`의 `role_variant`는 함수 본문 호출 기준으로 계산합니다.
(본문에 source 계열 호출 포함 여부 + sink 계열 호출 포함 여부)
