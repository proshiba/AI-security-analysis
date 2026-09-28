"""実検体を含めず、無害なPEと静的命令fixtureでARX20抽出境界を試験する。"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import capstone
import pytest

REPOSITORY=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPOSITORY))
from unpackers import arx20_chunk_unpacker as arx


def _pe(text: bytes, rdata: bytes | None=None) -> bytes:
    """実行しない最小PE外形。entryにはRETしか含めない。"""
    parts=[(b'.text',0x1000,0x60000020,text)]
    if rdata is not None: parts.append((b'.rdata',0x3000,0x40000040,rdata))
    headers=bytearray(0x200)
    headers[:2]=b'MZ'; struct.pack_into('<I',headers,0x3c,0x80)
    headers[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',headers,0x84,0x8664,len(parts),0,0,0,0xf0,0x22)
    optional=0x98
    struct.pack_into('<H',headers,optional,0x20b)
    struct.pack_into('<I',headers,optional+16,0x1000)
    struct.pack_into('<Q',headers,optional+24,0x140000000)
    struct.pack_into('<II',headers,optional+32,0x1000,0x200)
    struct.pack_into('<II',headers,optional+56,0x5000 if rdata is not None else 0x2000,0x200)
    struct.pack_into('<I',headers,optional+108,16)
    raw=bytearray(); section_offset=optional+0xf0
    for i,(name,rva,flags,content) in enumerate(parts):
        size=(len(content)+0x1ff)&~0x1ff
        struct.pack_into('<8sIIIIIIHHI',headers,section_offset+40*i,name,len(content),rva,size,0x200+len(raw),0,0,0,0,flags)
        raw+=content+b'\0'*(size-len(content))
    return bytes(headers+raw)


def _state_decoder(constants=(1,2,3,4), *, wrong_rotation=False) -> bytes:
    """暗号状態初期化と20-round構造だけを持つ非実行fixture。"""
    code=bytearray(b'\x90')
    for index,value in zip(arx.CONSTANT_WORDS,constants):
        code+=b'\xc7\x84\x24'+struct.pack('<II',0x180+index*4,value)
    for i,index in enumerate(arx.KEY_WORDS):
        code+=b'\x44\x8b\x89'+struct.pack('<I',i*4)
        code+=b'\x44\x89\x8c\x24'+struct.pack('<I',0x180+index*4)
    for i,index in enumerate(arx.NONCE_WORDS):
        code+=b'\x8b\x8a'+struct.pack('<I',i*4)
        code+=b'\x89\x8c\x24'+struct.pack('<I',0x180+index*4)
    code+=b'\x44\x89\x84\x24'+struct.pack('<I',0x180+arx.COUNTER_WORD*4)
    # 運算形fingerprint試験用の無害なADD/XOR、feedforward、counter increment。
    code+=b'\x01\xd8\x31\xd1\x05\x11\x22\x33\x44\x83\xc1\x01'
    beginning=len(code)
    indexes={'eax':0,'ecx':1,'edx':2,'ebx':3,'ebp':5,'esi':6,'edi':7,
             'r8d':0,'r9d':1,'r10d':2,'r11d':3,'r12d':4,'r13d':5,'r14d':6,'r15d':7}
    for i,(register,rotation) in enumerate(zip(arx.ROTATION_REGISTERS,(16,12,8,7)*8)):
        code+=(b'\x41' if register.startswith('r') else b'')+b'\xc1'+bytes([0xc0+indexes[register],rotation+(1 if wrong_rotation and i==0 else 0)])
    code+=b'\x48\x89\xc8\x48\x83\xc0\x02\x48\x83\xf9\x12'
    code+=b'\x0f\x82'+struct.pack('<i',beginning-(len(code)+6))+b'\xc3'
    return bytes(code)


@pytest.fixture(autouse=True)
def _approve_only_harmless_fixture_shape(monkeypatch):
    """実装の暗号profileへfixtureを混入せず、テスト中だけ無害形を許可する。"""
    machine=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    machine.detail=True
    instructions=list(machine.disasm(_state_decoder(),0x1600))
    shape=arx._shape_hash(instructions,0x180,0x1600)
    monkeypatch.setattr(arx,'VERIFIED_COMPILER_SHAPES',frozenset({shape}))


def _fixture(*, constants=(1,2,3,4), wrong_rotation=False, invalid_output=False,
             huge_chunk=False, overlap=False, duplicate=False, corrupt_key=False,
             truncate=False, data_base=0x3100) -> tuple[bytes,bytes]:
    child=_pe(b'\xc3'+b'\x90'*0x1ff)
    if invalid_output: child=b'not-a-pe'+b'\x00'*(len(child)-8)
    text=bytearray(b'\x90'*0x1000)
    decoder_rva=0x1600
    text[decoder_rva-0x1000:decoder_rva-0x1000+len(_state_decoder(constants,wrong_rotation=wrong_rotation))]=_state_decoder(constants,wrong_rotation=wrong_rotation)
    caller_rva=0x1100
    code=(b'\x4c\x8d\x0d'+struct.pack('<i',data_base-(caller_rva+7))+
          b'\x4c\x89\xca\x48\x81\xc2'+struct.pack('<I',0x40)+
          b'\x45\x31\xc0\x49\x83\xc1\x02\x48\x8d\x84\x24\x80\x00\x00\x00'+
          b'\x48\x89\xd1\x48\x89\x44\x24\x20\x48\xc7\x44\x24\x28'+struct.pack('<I',32))
    code+=b'\xe8'+struct.pack('<i',decoder_rva-(caller_rva+len(code)+5))
    text[0x100:0x100+len(code)]=code
    chunk_rva=caller_rva+0x90
    chunk=(b'\x4c\x8d\x0d'+struct.pack('<i',data_base-(chunk_rva+7))+
           b'\x4c\x03\x08\x48\x8b\x40\x08\x48\x89\x44\x24\x40\x4c\x89\xc9'+
           b'\x48\x01\xc1\x48\x89\xca\x48\x83\xc2\x1c\x45\x31\xc0'+
           b'\x4c\x89\x54\x24\x20\x48\x89\x44\x24\x28')
    chunk+=b'\xe8'+struct.pack('<i',decoder_rva-(chunk_rva+len(chunk)+5))+b'\x48\x83\xfa\x02\xc3'
    text[0x190:0x190+len(chunk)]=chunk
    if duplicate: text[0x300:0x300+len(code)]=code
    rdata=bytearray(0x1000)
    local=data_base-0x3000
    table_key=hashlib.sha256(b'fixture-index-key').digest()
    rdata[local+0x40:local+0x60]=table_key
    entries=[]; cursor=0x80
    for i,part in enumerate((child[:len(child)//2],child[len(child)//2:])):
        key=hashlib.sha256(bytes([i])+b'fixture-key').digest()
        nonce=key[-4:]+hashlib.sha256(bytes([i])+b'fixture-nonce').digest()[:8]
        cipher=arx._transform(part,key,nonce,constants,output_limit=arx.MAX_OUTPUT_BYTES)
        rdata[local+cursor:local+cursor+len(cipher)]=cipher
        rdata[local+cursor+len(cipher):local+cursor+len(cipher)+40]=key+nonce[4:]
        entries.append((cursor,len(cipher))); cursor+=len(cipher)+56
    if huge_chunk: entries[1]=(entries[1][0],2**40)
    if overlap: entries[1]=(entries[0][0],entries[1][1])
    table=b''.join(struct.pack('<QQ',*entry) for entry in entries)
    rdata[local+2:local+34]=arx._transform(table,table_key,table_key[:12],constants,output_limit=1024)
    if corrupt_key: rdata[local+0x40]^=1
    source=_pe(bytes(text),bytes(rdata))
    if truncate: source=source[:-600]
    return source,child


def test_structural_recovery_uses_code_parameters_not_hashes():
    source,child=_fixture()
    result=arx.recover_arx20_chunk_payloads(source)
    assert len(result)==1 and result[0].payload==child
    assert result[0].evidence['payload_format']=='pe'
    assert result[0].evidence['chunk_count']==2
    assert result[0].evidence['family_attribution_confirmed'] is False


def test_changed_constants_and_relocated_data_are_extracted():
    source,child=_fixture(constants=(0x11223344,0x55667788,0x12345678,0x0badcafe),data_base=0x3200)
    result=arx.recover_arx20_chunk_payloads(source)
    assert len(result)==1 and result[0].payload==child
    assert result[0].evidence['cipher_rva']==0x3200


def test_overlay_is_not_scanned_or_decrypted():
    source,child=_fixture()
    overlay=b'\x4c\x8d\x0d'+b'overlay-ignore'*100
    result=arx.recover_arx20_chunk_payloads(source+overlay)
    assert result[0].payload==child
    assert result[0].evidence['overlay_ignored_bytes']==len(overlay)


@pytest.mark.parametrize('option',['wrong_rotation','invalid_output','huge_chunk','overlap','corrupt_key'])
def test_invalid_candidates_are_rejected(option):
    source,_=_fixture(**{option:True})
    assert arx.recover_arx20_chunk_payloads(source)==[]


def test_candidate_overflow_is_not_silently_truncated():
    source,_=_fixture(duplicate=True)
    with pytest.raises(arx.Arx20ChunkError,match='候補数'):
        arx.recover_arx20_chunk_payloads(source,max_candidates=1)


def test_truncated_section_is_rejected_before_decrypt():
    source,_=_fixture(truncate=True)
    with pytest.raises(arx.Arx20ChunkError,match='raw範囲'):
        arx.recover_arx20_chunk_payloads(source)


def test_input_and_output_limits():
    source,_=_fixture()
    with pytest.raises(arx.Arx20ChunkError): arx.recover_arx20_chunk_payloads(source,max_input_bytes=10)
    assert arx.recover_arx20_chunk_payloads(source,max_output_bytes=100)==[]
    with pytest.raises(arx.Arx20ChunkError): arx.recover_arx20_chunk_payloads(source,max_candidates=True)


def test_round_transform_is_symmetric_and_spans_blocks():
    key=bytes(range(32)); nonce=bytes(range(12)); value=bytes(range(251))
    cipher=arx._transform(value,key,nonce,(1,2,3,4),output_limit=1024)
    assert cipher!=value
    assert arx._transform(cipher,key,nonce,(1,2,3,4),output_limit=1024)==value


@pytest.mark.parametrize('before,after',[
    (b'\x01\xd8',b'\x29\xd8'),  # ADD→SUB
    (b'\x31\xd1',b'\x09\xd1'),  # XOR→OR
    (b'\x05\x11\x22\x33\x44',b'\x05\x11\x22\x33\x45'), # arithmetic immediate
    (b'\x83\xc1\x01',b'\x83\xc1\x02'), # counter increment
    (b'\x48\x83\xf9\x12',b'\x48\x83\xf9\x13'), # round数
])
def test_arithmetic_and_counter_mutations_are_fail_closed(before,after):
    source,_=_fixture()
    assert before in source
    changed=source.replace(before,after,1)
    assert arx.recover_arx20_chunk_payloads(changed)==[]


def test_internal_branch_mutation_changes_profile():
    source,_=_fixture()
    offset=source.index(b'\x0f\x82')+2
    changed=bytearray(source); changed[offset]^=1
    assert arx.recover_arx20_chunk_payloads(bytes(changed))==[]


def test_external_jump_is_rejected_before_profile_normalization():
    source,_=_fixture()
    offset=source.index(b'\x0f\x82')+2
    changed=bytearray(source)
    struct.pack_into('<i',changed,offset,0x4000)
    assert arx.recover_arx20_chunk_payloads(bytes(changed))==[]
    machine=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    machine.detail=True
    instructions=list(machine.disasm(b'\xe9\x00\x40\x00\x00\xc3',0x1600))
    with pytest.raises(arx.Arx20ChunkError,match='外部jump'):
        arx._shape_hash(instructions,0x180,0x1600)


def test_cipher_work_limit_is_explicit_and_returns_no_partial_result():
    source,_=_fixture()
    with pytest.raises(arx.Arx20ChunkLimitError) as error:
        arx.recover_arx20_chunk_payloads(source,max_cipher_work_bytes=500)
    assert error.value.constraint=='cipher_work_bytes'


def test_wall_timeout_is_explicit_and_not_a_decode_rejection(monkeypatch):
    source,_=_fixture()
    calls=iter([0.0,9.0,9.0])
    monkeypatch.setattr(arx.time,'monotonic',lambda:next(calls))
    with pytest.raises(arx.Arx20ChunkLimitError) as error:
        arx.recover_arx20_chunk_payloads(source)
    assert error.value.constraint=='wall_seconds'


@pytest.mark.parametrize('metadata',[
    {'compression':2,'length':8,'zlen':8},
    {'compression':1,'length':2**32,'zlen':8},
    {'compression':1,'length':8,'zlen':2**32},
])
def test_donut_unbounded_decompress_is_never_called(monkeypatch,metadata):
    from types import SimpleNamespace

    from unpackers import donut_unpacker
    instance=bytearray(0x1000)
    struct.pack_into('<Q',instance,0,1400)
    monkeypatch.setattr(donut_unpacker,'decrypt_instance',lambda _: (bytes(instance),SimpleNamespace(module=16,module_length=0,name='synthetic')))
    monkeypatch.setattr(donut_unpacker,'parse_module',lambda _:metadata)
    def unexpected(_):
        pytest.fail('bounded検証前に伸長関数へ入りました')
    monkeypatch.setattr(donut_unpacker,'recover_module_payload',unexpected)
    with pytest.raises(arx.Arx20ChunkError):
        arx._payload_format(b'\xe8'+b'\0'*7,output_limit=2048)
