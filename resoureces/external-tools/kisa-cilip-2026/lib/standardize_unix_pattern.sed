
# Usage: sed -i -f standardize_unix_pattern.sed file.sh
# Safety: 단순 문자열 치환만 사용, 정규식 없음

# 1. Run-all 모드 확인 주석 제거
/# Run-all 모드 확인/d

# 2. if [ "${UNIX_RUNALL_MODE:-0}" = "1" ]; then 라인 제거
/if \[ "\$\{UNIX_RUNALL_MODE:-0\}" = "1" \]; then/d

# 3. run_all 모드 주석 제거
/# run_all 모드: JSON만 stdout로 출력/d

# 4. generate_json_content 블록 제거 (연속된 \로 끝나는 라인들)
/\\[[:space:]]*"${ITEM_ID}"/{
    # 현재 라인 저장
    x
    # 플래그 설정
    s/.*/1/
    x
    # 현재 라인 삭제
    d
}

# 플래그가 1이고 백슬래시로 끝나는 라인 계속 삭제
x
s/^1$//
t delete_continue
b

:delete_continue
x
/\\$/{
    N
    s/.*\n//
    x
    s/^1$/1/
    x
    d
}

# 플래그 초기화
x
s/^1$/0/
x

# 5. else 라인 제거
/else/d

# 6. 개별 실행 모드 주석 제거
/# 개별 실행 모드: 파일로 저장/d

# 7. fi 라인 제거
/^    fi$/d

# 8. verify_result_saved 라인 뒤에 빈 줄 추가
/verify_result_saved/a\

