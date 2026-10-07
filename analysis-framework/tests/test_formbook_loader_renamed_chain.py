"""FormBook PowerShell loaderのidentifier rename耐性を検証する。"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

from Cryptodome.Cipher import AES

FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
for trusted in (FRAMEWORK, COMMON):
    if str(trusted) not in sys.path:
        sys.path.insert(0, str(trusted))

from malware.formbook_loader import extract_config as facade  # noqa: E402


def _minimal_pe(label: bytes) -> bytes:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    return bytes(data) + label


def _renamed_stage() -> tuple[bytes, bytes, bytes]:
    managed = _minimal_pe(b"managed")
    native = _minimal_pe(b"native")
    phrase = "synthetic-phrase"
    coated = bytes(
        value ^ phrase.encode()[index % len(phrase)]
        for index, value in enumerate(base64.b64encode(managed))
    )
    native_array = ",".join(str(value) for value in native)
    script = f'''function Reveal-CloakedData {{
param([string]$CloakedData,[string]$RevealPhrase)
$coatedBytes=[System.Convert]::FromBase64String($CloakedData)
$bakedPhrase=[System.Text.Encoding]::UTF8.GetBytes($RevealPhrase)
for($cell=0;$cell-lt $coatedBytes.Length;$cell++){{$coatedBytes[$cell]=$coatedBytes[$cell] -bxor $bakedPhrase[$cell % $bakedPhrase.Length]}}
return [System.Text.Encoding]::UTF8.GetString($coatedBytes)
}}
function Deploy-AssemblyPayload {{
$image=[System.Reflection.Assembly]::Load($PayloadImage)
$type=$image.GetType($TypeLocator)
$entry=$type.GetMethod($EntrySelector)
$entry.Invoke($null,$DeploymentArgs)
}}
$vaultSecret="{phrase}"
$cloakedData='{base64.b64encode(coated).decode()}'
$revealedData=Reveal-CloakedData -CloakedData $cloakedData -RevealPhrase $vaultSecret
$payloadImage=[System.Convert]::FromBase64String($revealedData)
$hostExecutable='C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\aspnet_compiler.exe'
[Byte[]]$renamedNative=({native_array})
'''.encode()
    return script, managed, native


def _aes_envelope(plaintext: bytes) -> bytes:
    key = bytes(range(32))
    vector = bytes(range(16))
    padding = 16 - len(plaintext) % 16
    ciphertext = AES.new(key, AES.MODE_CBC, vector).encrypt(
        plaintext + bytes([padding]) * padding
    )
    return f'''$State=@{{
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
$x=[Convert]::FromBase64String($flat)
$managed.Mode=[System.Security.Cryptography.CipherMode]::CBC
$managed.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7
$block=[ScriptBlock]::Create($State.PlainText)
'''.encode()


def test_identifier_renamed_xor_reflection_chain_recovers_both_pe_layers() -> None:
    stage, managed, native = _renamed_stage()

    result = facade.extract_config(_aes_envelope(stage))

    assert result["variant"] == "powershell_aes_to_ghosted_payload"
    assert result["recovered_artifacts"][0]["size"] == len(managed)
    assert result["terminal_payload_recovered"] is False
    assert result["recovered_payload"]["role"] == "recovered_payload"
    assert result["recovered_payload"]["data"] == native
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
