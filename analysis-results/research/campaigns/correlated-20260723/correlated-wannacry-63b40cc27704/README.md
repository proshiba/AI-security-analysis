# campaign候補：correlated-wannacry-63b40cc27704

> **無効化（2026-09-22）**: 本件は同一campaignの根拠になりません。旧相関器が`0.oj`等の任意文字列と`c.wnry`等のWannaCry構成ファイル名をdomainとして扱い、共通初期値と配布物内の文字列を過大評価しました。以下の旧score・共有指標は監査履歴であり、IOC、C2、campaign fingerprintとして使用しません。5件の同一攻撃活動・同一アクターは未立証です。

現在の相関器では`IOC-LIST.md`を優先し、旧caseのJSON fallbackでも明示的なC2 key以外を受け入れません。再評価には、正規化された検体固有の配布・設定・通信・コード根拠が必要です。

- 分類: `same_family_campaign_candidate`
- 確度: `high`
- ファミリー: `wannacry`
- case数: 5
- 最大pair score: 173

## 相関したcase

- `32c9bf96fb8c0d6ad0d3a3d2707a8a9ae0b95ccefaa26ad0e33b518d9fd0a608`
- `656f08c0cf09e32acc0729536a32da8ad61079d29fee18bcb3a1792e3ee5e5c6`
- `88a9d62d3cc2290f33ecb40ed5d266792aaf0438b042e0e6998f88cd1b0e8d14`
- `89f2bd29e1493bba4ca3d25a1a155cc1aa4ed3360a5855be06e90ad81fd28ae5`
- `91cd12ce85d9e32f75f732ea090a1385ab4e31ef0dd6904ccdf7b5d1623ddba8`

## 共有証拠

| 種別 | 値 | case支持数 |
|---|---|---:|
| domain | `0.oj` | 3 |
| domain | `1.ng` | 3 |
| domain | `18.noq` | 3 |
| domain | `2.uy` | 3 |
| domain | `53q.zl` | 5 |
| domain | `57g7spgrzlojinas.onion` | 4 |
| domain | `6.gz` | 3 |
| domain | `7.hk` | 5 |
| domain | `7.jce` | 3 |
| domain | `76jdd2ir2embyv47.onion` | 4 |
| domain | `8.ax` | 5 |
| domain | `8.uq` | 5 |
| domain | `a.pe` | 3 |
| domain | `ax.id` | 5 |
| domain | `b.wnryp` | 5 |
| domain | `b.ya` | 3 |
| domain | `bh.mr` | 2 |
| domain | `c.nc` | 2 |
| domain | `c.wnry` | 5 |
| domain | `cwwnhwhlz52maqm7.onion` | 4 |
| domain | `d.um` | 5 |
| domain | `d.yh` | 5 |
| domain | `dj.dy` | 3 |
| domain | `e.bt` | 3 |
| domain | `e.ip` | 3 |
| domain | `f.hy` | 3 |
| domain | `f.pk` | 5 |
| domain | `g.ro` | 3 |
| domain | `gx7ekbenv2riucmf.onion` | 4 |
| domain | `hs.uk` | 2 |
| domain | `i.gcvo` | 4 |
| domain | `i.zl` | 5 |
| domain | `ibg.yf` | 2 |
| domain | `j.jx` | 3 |
| domain | `j.td` | 3 |
| domain | `ld.yn` | 4 |
| domain | `m.co` | 5 |
| domain | `n.myj` | 5 |
| domain | `o.av` | 4 |
| domain | `o.otk` | 3 |
| domain | `os.fg` | 3 |
| domain | `oz.mzr` | 5 |
| domain | `p.vw` | 3 |
| domain | `pk.ks` | 2 |
| domain | `pph.datja` | 5 |
| domain | `psl.nw` | 3 |
| domain | `r.abd` | 3 |
| domain | `r.wnry` | 5 |
| domain | `s.wnry` | 5 |
| domain | `t.hc` | 5 |
| domain | `t.wnry` | 5 |
| domain | `u.my` | 4 |
| domain | `v.bi` | 4 |
| domain | `w.ceg` | 3 |
| domain | `w.ry` | 3 |
| domain | `www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com` | 4 |
| domain | `x.ib` | 2 |
| domain | `xxlvbrloxvriy2c5.onion` | 4 |
| domain | `y.sn` | 3 |
| domain | `z.dq` | 3 |
| domain | `z.hevo` | 5 |
| domain | `zhn.ban` | 3 |
| url | `http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/` | 4 |

## 制約

- 同一アクターまたは同一運用者への帰属を意味しません。
- 共有インフラが再利用・転売されている可能性を排除できません。
- 収集バッチ、ファミリー名、ファイル名だけでは相関していません。
