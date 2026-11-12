{ lines[NR]=$0 }
END {
  n=NR; inbold=0; bad=0; prob=""
  if (n < LO || n > HI) { prob=prob sprintf("  LINES=%d need %d-%d\n", n, LO, HI); bad=1 }
  infence=0
  for (i=1; i<=n; i++) {
    s=lines[i]; gsub(/^[ \t]+|[ \t]+$/, "", s)
    if (s ~ /^```/) { infence = (infence ? 0 : 1); continue }
    if (infence) continue
    if (index(s, "**") > 0) { prob=prob sprintf("  bold L%d: %s\n", i, substr(s,1,60)); bad=1 }
    if (s ~ /^\|.*\|$/) { prob=prob sprintf("  table L%d: %s\n", i, substr(s,1,60)); bad=1 }
    for (j=1; j<=6; j++) {
      b=(j==1?"합법적인 대상":j==2?"합법적인 보안 테스트":j==3?"오직 교육 목적":j==4?"법적 주의사항":j==5?"합법적 사용":"합법성")
      if (index(s, b) > 0) { prob=prob sprintf("  forbidden L%d: %s\n", i, b); bad=1 }
    }
  }
  status = bad ? "BAD" : "OK "
  printf "%s %3d %s\n", status, n, FILE
  if (bad) printf "%s", prob
}
