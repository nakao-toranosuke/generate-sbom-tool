# SBOM Generator

言語: [English](README.md) | 日本語

SBOM Generator は、パッケージ情報、単体ファイル、Project ZIP から SPDX JSON 形式の SBOM を生成する Streamlit ベースのツールです。

小規模な SBOM 生成や、ローカル環境・コンテナ環境での利用を想定しています。

## 主な機能

- 個別パッケージ情報から SPDX JSON SBOM を生成
- CSV / Excel のパッケージ一覧から SPDX JSON SBOM を生成
- 単体ファイルから SPDX JSON SBOM を生成
- Project ZIP から SPDX JSON SBOM を生成
- 生成結果を ZIP ファイルとして出力
- symlink や path traversal を含む危険な ZIP 入力を拒否
- 再現性を高めるため、runtime / CLI バージョンを固定

## 対応 package ecosystem

| Ecosystem | 表示名 | 入力例 |
| --- | --- | --- |
| `pypi` | Python | `idna` `3.7` |
| `npm` | Node.js | `is-number` `7.0.0` |
| `maven` | Java | `junit:junit` `4.13.2` |
| `composer` | PHP | `psr/log` `3.0.2` |
| `gem` | Ruby | `rake` `13.2.1` |
| `cargo` | Rust | `itoa` `1.0.11` |
| `golang` | Go | `github.com/google/uuid` `v1.6.0` |
| `nuget` | .NET | `Newtonsoft.Json` `13.0.3` |
| `file` | File | 選択した単体ファイル |

`go` は `golang` の alias として利用できます。

## Project ZIP で検出する依存定義ファイル

Project ZIP 生成では、以下のような依存定義ファイルを検出します。

- `requirements.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `Pipfile.lock`
- `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json`
- `pom.xml`
- `go.mod`, `go.sum`
- `composer.json`, `composer.lock`
- `Gemfile`, `Gemfile.lock`
- `Cargo.toml`, `Cargo.lock`
- `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.lock.json`, `packages.config`

対応する依存定義ファイルが含まれていない Project ZIP は拒否されます。

## Toolchain versions

| Tool | Version |
| --- | --- |
| Python | 3.14.6 |
| Streamlit | 1.58.0 |
| uv | 0.11.26 |
| Node.js | 24.18.0 |
| npm | Node.js bundled version |
| JDK | 25 LTS |
| Maven | 3.9.16 |
| PHP | 8.5.8 |
| Composer | 2.10.2 |
| Ruby | 4.0.5 |
| Bundler | Ruby-compatible bundled version |
| Rust | 1.96.0 |
| Cargo | Rust bundled version |
| Go | 1.26.4 |
| .NET SDK | 10.0.301 |
| Trivy | 0.72.0 |

## Build

`app` ディレクトリで実行します。

```bash
cd app
docker build -t sbom-generator:v3.1 .
```

## Run

```bash
cd app
docker run --rm -p 8501:8501 sbom-generator:v3.1
```

コンテナログに表示される Streamlit URL をブラウザで開きます。

Health check:

```bash
curl -f http://127.0.0.1:8501/_stcore/health
```

期待値:

```text
ok
```

## 入力モード

### Package input

`Package input` タブでは、1パッケージずつ SBOM を生成します。

必須項目:

- `Ecosystem`
- `Package name`
- `Version`

任意項目:

- `Output label`
- `Maven groupId`
- `Maven artifactId`

Maven の場合は、以下のどちらかで指定します。

- `Package name` に `groupId:artifactId` を入力
- `Maven groupId` と `Maven artifactId` をそれぞれ入力

### CSV/Excel input

`CSV/Excel input` タブでは、複数パッケージをまとめて生成します。

必須列:

- `ecosystem`
- `name`
- `version`

任意列:

- `output_label`
- `group_id`
- `artifact_id`

CSV 例:

```csv
ecosystem,name,version,output_label,group_id,artifact_id
pypi,idna,3.7,pkg-pypi,,
npm,is-number,7.0.0,pkg-npm,,
maven,junit:junit,4.13.2,pkg-maven,,
```

### File input

`File input` タブでは、単体ファイルから SBOM を生成します。

入力項目:

- 選択ファイル
- `Output label`
- `Display name`
- `Version`

### Project ZIP input

`Project ZIP input` タブでは、1つのプロジェクトルートを含む ZIP から SBOM を生成します。

入力項目:

- 選択 ZIP ファイル
- `Output label`
- `Project name`
- `Project version`

ZIP に対する安全確認:

- 壊れた ZIP を拒否
- absolute path を拒否
- path traversal を拒否
- symlink を拒否
- ファイル数・サイズ制限を適用
- 依存キャッシュや build output などの重いディレクトリを除外

## 出力

生成結果は ZIP ファイルとして出力されます。

典型的な出力構成:

```text
sbom/
  <generated>.spdx.json
manifest/
  result_manifest.json
input/
  input_summary.json
error/
  error_summary.txt
```

生成に失敗した場合は、`error/error_summary.txt` が含まれます。

## Smoke tests

Docker image build 後、`app` ディレクトリで実行します。

```bash
docker run --rm sbom-generator:v3.1 python /app/scripts/smoke_project_zip.py
docker run --rm sbom-generator:v3.1 python /app/scripts/smoke_symlink_reject.py
docker run --rm sbom-generator:v3.1 python /app/scripts/smoke_package_units.py
docker run --rm sbom-generator:v3.1 python /app/scripts/smoke_file_unit.py
```

期待される最終出力:

```text
smoke_project_zip: ok
smoke_symlink_reject: ok
smoke_package_units: ok
smoke_file_unit: ok
```

## Version check

```bash
docker run --rm sbom-generator:v3.1 /app/scripts/check_versions.sh
```

この script は、インストール済み tool の version を表示し、`pip check` を実行します。

## Development checks

repository root で実行します。

```bash
python -m compileall app/src app/streamlit_app.py app/scripts
git diff --check
```

## 注意事項

- 本ツールの標準workflowは SBOM 生成です。脆弱性、secret、misconfiguration の scan は標準workflowには含めていません。
- 選択した ecosystem によっては、package registry への network access が必要です。
- ブラウザベースのファイル選択は、利用環境によって失敗または停止する場合があります。その場合は、file selector 横の reset button を押してから再度ファイルを選択してください。
- 大きな入力は処理に時間がかかる場合があり、サイズまたはファイル数の制限により失敗することがあります。
