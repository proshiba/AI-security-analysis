rule Donut_Call_Over_Instance_2026 {
  meta:
    description = "Structurally identifies reviewed Donut call-over-instance shellcode prologues"
    author = "AI-security-analysis"
    confidence = "high"
    false_positive = "Other position-independent shellcode using the same call/pop and function prologue"
  condition:
    filesize > 0x240 and filesize < 32MB and
    uint8(0) == 0xe8 and
    uint32(1) > 0x230 and
    uint32(1) < filesize - 10 and
    (
      (
        uint8(5 + uint32(1)) == 0x59 and
        uint8(6 + uint32(1)) == 0x55 and
        uint8(7 + uint32(1)) == 0x48 and
        uint8(8 + uint32(1)) == 0x89 and
        uint8(9 + uint32(1)) == 0xe5
      ) or
      (
        uint8(5 + uint32(1)) == 0x59 and
        uint8(6 + uint32(1)) == 0x31 and
        uint8(7 + uint32(1)) == 0xc0 and
        uint8(8 + uint32(1)) == 0x48 and
        uint8(9 + uint32(1)) == 0x0f
      ) or
      (
        uint8(5 + uint32(1)) == 0x59 and
        uint8(6 + uint32(1)) == 0x48 and
        uint8(7 + uint32(1)) == 0x89 and
        uint8(8 + uint32(1)) == 0x5c and
        uint8(9 + uint32(1)) == 0x24
      )
    )
}
