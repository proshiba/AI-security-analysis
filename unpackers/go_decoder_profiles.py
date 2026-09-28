"""安全なsource snapshotへ固定できる、レビュー済みGo decoder形状。

公開JSONとの差分は同期testで拒否する。検体hash、鍵、乱数関数名は含めない。
runtimeでfile読込、書込、実行、通信を行わない。
"""

PROFILE_FIELDS = (
    "profile_id", "algorithm", "shape_sha256", "function_size",
    "instruction_count", "switch_table_count", "description",
)

PROFILE_ROWS = (
    ("go5-full-shape-01", "go_full_decoder_shape_v1", "62a1739e0ce3df2775549a5442e634852b7b22f9fba8f0cdbe0962ed2a4d72cf", 43776, 8516, 10,
     "全decoder本文、内部branch、runtime call、暗黙register、switch表を静的レビューしたcompiler形状"),
    ("go5-full-shape-02", "go_full_decoder_shape_v1", "3c233410d07f0dd2aafa73ceb65ca9e757c11f05369574a2a2446894384282e5", 31456, 6089, 0,
     "全decoder本文、内部branch、runtime call、暗黙register、switch表を静的レビューしたcompiler形状"),
    ("go5-full-shape-03", "go_full_decoder_shape_v1", "7ee63d705bab4be805030ba7062af9c075f214657b226c71a2dfa7ab4a0e9b4c", 31424, 6078, 0,
     "全decoder本文、内部branch、runtime call、暗黙register、switch表を静的レビューしたcompiler形状"),
    ("go5-full-shape-04", "go_full_decoder_shape_v1", "faea7b1682ef822bdaab4da37a2dd3fee4116ac87a0ff49058a360cadaf8cd5d", 26336, 5106, 0,
     "全decoder本文、内部branch、runtime call、暗黙register、switch表を静的レビューしたcompiler形状"),
    ("go5-full-shape-05", "go_full_decoder_shape_v1", "5678cd4b10dfbc40306fec6bf74aee53896484ed4638ee7739297482e46179ca", 41792, 8660, 0,
     "全decoder本文、内部branch、runtime call、暗黙register、switch表を静的レビューしたcompiler形状"),
    ("go5-full-shape-06", "go_full_decoder_shape_v1", "928f81168781f6206dee325f2694e609252a67e96f5fa2e51a2785622a557de0", 31456, 6091, 0,
     "全decoder本文、内部branch、runtime call、暗黙register、switch表を静的レビューしたcompiler形状"),
)
