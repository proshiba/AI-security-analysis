# ValleyRAT通信フローの隔離試験

Kali上のDockerで実行します。既存の外部observerとは別の試験用構成であり、常駐serviceや外部C2接続を開始しません。検体をimageへ含めず、networkは`none`、root filesystemはread-only、非rootで実行します。

repository rootから実行します。

```bash
sudo docker compose -f analysis-framework/docker/valleyrat-protocol-lab/compose.yaml build
sudo docker compose -f analysis-framework/docker/valleyrat-protocol-lab/compose.yaml run --rm flow-tests
```

privateなsource directoryを使う場合は、公開読取権限を広げず、その所有者の非root UID/GIDを`VALLEY_LAB_UID`／`VALLEY_LAB_GID`で指定します。今回のKaliでは`1000:1002`で検証しました。UID 0は使用しません。

```bash
sudo env VALLEY_LAB_UID=1000 VALLEY_LAB_GID=1002 \
  docker compose -f analysis-framework/docker/valleyrat-protocol-lab/compose.yaml run --rm flow-tests
```

試験peerとemulatorは同じcontainerのloopbackを使用します。port公開、host network、Docker socket mount、検体の実行、外部通信はありません。静的解析用の依存関係を含むため、imageのbuildはpackage取得を伴います。Ghidra本体はimageへ含めず、Kaliに導入済みの解析toolだけを別のnetwork無効containerへread-only mountして使用しました。

`Dockerfile`だけで隔離が成立するわけではありません。直接`docker run`する場合も、Composeと同じnetwork、権限、memory、process、mount制限が必要です。imageの依存関係はrepositoryのrequirementsに従い、完全な再現にはbuild時のimage digestとpackage inventoryも保持してください。

動作と未解決事項は[通信フロー・時間の検証](../../malware/valleyrat/docs/FLOW-TIMING-LAB.md)を参照してください。
