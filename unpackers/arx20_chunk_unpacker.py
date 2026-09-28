"""x64のコード参照で裏付けたARX20 chunkを静的復号する。

検体の実行、CPU命令の解釈実行、外部通信を行わない。入力SHAや外部profileの
鍵には依存せず、index caller、暗号状態初期化、double-round、chunk callerを
照合する。巨大overlayは走査・復号対象とせず、PE sectionだけを参照する。
既知の状態word配置とregister allocationに合わない暗号実装は棄却する。
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
import time
from dataclasses import dataclass
from itertools import pairwise

import capstone
import pefile
from capstone.x86_const import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_R8D,
    X86_REG_RCX,
    X86_REG_RDX,
    X86_REG_RSP,
)

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_SECTION_BYTES = 16 * 1024 * 1024
MAX_CODE_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_CANDIDATES = 4
MAX_CHUNKS = 64
MAX_DECODER_BYTES = 0x8000
MAX_CIPHER_WORK_BYTES = 1024 * 1024
MAX_WALL_SECONDS = 8.0
MASK32 = 0xffffffff

# sigma値・相対配置を除いた暗号演算そのものの検証済みcompiler形。
# 別compiler/MBA変形は、個別の静的検証なしでは対応対象に加えない。
VERIFIED_COMPILER_SHAPES: frozenset[str] = frozenset({
    'd22f394d0edff9a668c922398764b5d6067b6be1adc478b049cf804cf226e90f',
})

# 暗号word wiring。数値のsigmaは検体の状態初期化コードから毎回取得する。
KEY_WORDS = (9, 4, 1, 7, 6, 13, 12, 2)
NONCE_WORDS = (5, 3, 0)
CONSTANT_WORDS = (8, 11, 14, 15)
COUNTER_WORD = 10
QUARTERS = ((9,14,5,0),(15,10,7,1),(6,12,2,11),(3,4,8,13),
            (9,10,2,13),(15,12,8,0),(6,4,5,1),(3,14,7,11))
ROTATION_REGISTERS = ('ebp','eax','r10d','r9d','r12d','ecx','eax','r12d',
                      'edx','r13d','r15d','edx','r11d','r14d','esi','esi',
                      'r14d','r14d','ecx','ecx','r14d','r10d','ebx','ebx',
                      'r11d','r10d','esi','r12d','edi','edx','r14d','eax')

# 固定するのは命令形式だけ。RIP相対参照、offset、length、関数位置は可変。
INDEX_CALL = re.compile(
    rb'\x4c\x8d\x0d(?P<base>.{4})\x4c\x89\xca\x48\x81\xc2(?P<key>.{4})'
    rb'\x45\x31\xc0\x49\x83\xc1(?P<input>.{1})\x48\x8d\x84\x24.{4}'
    rb'\x48\x89\xd1\x48\x89\x44\x24\x20\x48\xc7\x44\x24\x28(?P<size>.{4})'
    rb'\xe8(?P<decoder>.{4})', re.DOTALL)
CHUNK_CALL = re.compile(
    rb'\x4c\x8d\x0d(?P<base>.{4})\x4c\x03\x08\x48\x8b\x40\x08'
    rb'\x48\x89\x44\x24.{1}\x4c\x89\xc9\x48\x01\xc1\x48\x89\xca'
    rb'\x48\x83\xc2(?P<nonce>.{1})\x45\x31\xc0\x4c\x89\x54\x24\x20'
    rb'\x48\x89\x44\x24\x28\xe8(?P<decoder>.{4})', re.DOTALL)


class Arx20ChunkError(ValueError):
    """コードまたはデータの安全な構造検証に失敗した。"""


class Arx20ChunkLimitError(Arx20ChunkError):
    """timeout/work上限を通常の非一致から区別し、部分成功を返さない。"""
    def __init__(self, constraint: str, observed: float, limit: float):
        self.constraint, self.observed, self.limit = constraint, observed, limit
        super().__init__(f'ARX20制約超過: {constraint} ({observed} > {limit})')


@dataclass
class _Budget:
    started: float
    seconds: float
    cipher_limit: int
    cipher_used: int = 0

    def check(self):
        elapsed = time.monotonic()-self.started
        if elapsed > self.seconds:
            raise Arx20ChunkLimitError('wall_seconds',elapsed,self.seconds)

    def reserve(self, amount: int):
        self.check()
        if self.cipher_used+amount > self.cipher_limit:
            raise Arx20ChunkLimitError('cipher_work_bytes',self.cipher_used+amount,self.cipher_limit)
        self.cipher_used+=amount


@dataclass(frozen=True)
class Arx20ChunkResult:
    """親子hashとコード根拠を持つ非実行の復号結果。"""
    payload: bytes
    evidence: dict


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _positive(value: int, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise Arx20ChunkError(f'{label}の上限が不正です')
    return value


def _pe_sections(data: bytes, *, input_limit: int = MAX_INPUT_BYTES):
    if len(data) > input_limit or data[:2] != b'MZ':
        raise Arx20ChunkError('入力サイズまたはMZが不正です')
    try:
        image = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise Arx20ChunkError('PEヘッダーを検証できません') from exc
    if image.FILE_HEADER.Machine != 0x8664 or image.OPTIONAL_HEADER.Magic != 0x20b:
        raise Arx20ChunkError('x64 PEではありません')
    if not 1 <= len(image.sections) <= 32:
        raise Arx20ChunkError('section数が不正です')
    image_size = int(image.OPTIONAL_HEADER.SizeOfImage)
    headers = int(image.OPTIONAL_HEADER.SizeOfHeaders)
    if not 0 < headers <= min(len(data), image_size) or not image_size <= MAX_SECTION_BYTES:
        raise Arx20ChunkError('PE image/headerサイズが上限外です')
    raw_ranges, virtual_ranges = [], []
    raw_total, code_total = 0, 0
    for section in image.sections:
        size, offset, rva = int(section.SizeOfRawData), int(section.PointerToRawData), int(section.VirtualAddress)
        span = max(size, int(section.Misc_VirtualSize))
        if rva < headers or rva + span > image_size:
            raise Arx20ChunkError('section仮想範囲が不正です')
        virtual_ranges.append((rva,rva+span))
        if size:
            if offset < headers or offset + size > len(data):
                raise Arx20ChunkError('section raw範囲が不正です')
            raw_ranges.append((offset,offset+size))
            raw_total += size
            if section.Characteristics & 0x20000000:
                code_total += size
    if raw_total > MAX_SECTION_BYTES or code_total > MAX_CODE_BYTES:
        raise Arx20ChunkError('section/code総量が上限外です')
    for ranges in (raw_ranges, virtual_ranges):
        ordered = sorted(ranges)
        if any(a[1] > b[0] for a,b in pairwise(ordered)):
            raise Arx20ChunkError('section範囲が重複しています')
    return image


def _section(image, rva: int, length: int, *, executable: bool | None = None):
    if rva < 0 or length <= 0:
        raise Arx20ChunkError('RVA/lengthが不正です')
    hits = [s for s in image.sections if int(s.VirtualAddress) <= rva and
            rva + length <= int(s.VirtualAddress) + int(s.SizeOfRawData)]
    if len(hits) != 1:
        raise Arx20ChunkError('参照が単一のfile-backed section内にありません')
    section = hits[0]
    if executable is not None and bool(section.Characteristics & 0x20000000) != executable:
        raise Arx20ChunkError('参照先sectionの実行属性が不正です')
    return section


def _read(data: bytes, image, rva: int, length: int, *, executable: bool | None = None) -> bytes:
    section = _section(image,rva,length,executable=executable)
    offset = int(section.PointerToRawData) + rva - int(section.VirtualAddress)
    return data[offset:offset+length]


def _stack(operand):
    if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RSP and operand.mem.index == 0:
        return int(operand.mem.disp)
    return None


def _shape_hash(instructions, state_base: int, decoder_rva: int) -> str:
    """算術opcode/immediate/stack/内部分岐を保持したコードprofile digest。"""
    last=instructions[-1].address+instructions[-1].size
    normalized=[]
    for ins in instructions:
        operands=[]
        sigma_store=(ins.mnemonic=='mov' and len(ins.operands)==2 and
                     _stack(ins.operands[0]) in {state_base+4*i for i in CONSTANT_WORDS} and
                     ins.operands[0].size==4 and ins.operands[1].type==X86_OP_IMM)
        for operand in ins.operands:
            if operand.type==X86_OP_REG:
                operands.append(['reg',ins.reg_name(operand.reg),operand.size])
            elif operand.type==X86_OP_MEM:
                mem=operand.mem
                operands.append(['mem',ins.reg_name(mem.base),ins.reg_name(mem.index),mem.scale,mem.disp,operand.size])
            elif operand.type==X86_OP_IMM:
                if sigma_store:
                    operands.append(['sigma',operand.size])
                elif ins.mnemonic.startswith('j') or ins.mnemonic=='call':
                    target=int(operand.imm)
                    if ins.mnemonic.startswith('j') and not decoder_rva<=target<last:
                        raise Arx20ChunkError('decoder外部jumpは対応対象外です')
                    operands.append(['internal-target',target-decoder_rva] if decoder_rva<=target<last else ['external-memcpy-target'])
                else:
                    operands.append(['imm',int(operand.imm),operand.size])
            else:
                raise Arx20ChunkError('未対応operandをコードprofileへ正規化できません')
        normalized.append([ins.address-decoder_rva,ins.size,ins.mnemonic,operands])
    return _sha(json.dumps(normalized,separators=(',',':')).encode('utf-8'))


def _memcpy_calls(data: bytes, image, instructions, decoder_rva: int):
    """暗号関数の唯一の外部callを、非実行のmemcpy IAT thunkに限定する。"""
    end=instructions[-1].address+instructions[-1].size
    calls=[int(ins.operands[0].imm) for ins in instructions if ins.mnemonic=='call' and
           ins.operands and ins.operands[0].type==X86_OP_IMM and not decoder_rva<=ins.operands[0].imm<end]
    if not calls: return
    image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    imports={int(entry.address)-int(image.OPTIONAL_HEADER.ImageBase):(bytes(lib.dll).lower(),bytes(entry.name or b''))
             for lib in getattr(image,'DIRECTORY_ENTRY_IMPORT',[]) for entry in lib.imports}
    for target in calls:
        thunk=_read(data,image,target,6,executable=True)
        if thunk[:2] != b'\xff\x25':
            raise Arx20ChunkError('decoder外部callがIAT thunkではありません')
        iat=target+6+struct.unpack_from('<i',thunk,2)[0]
        _section(image,iat,8,executable=False)
        dll,name=imports.get(iat,(b'',b''))
        if name != b'memcpy' or dll not in {b'msvcrt.dll',b'ucrtbase.dll',b'vcruntime140.dll'}:
            raise Arx20ChunkError('decoder外部callがmemcpyとして検証できません')


def _decoder_profile(data: bytes, image, decoder_rva: int) -> dict:
    section = _section(image,decoder_rva,1,executable=True)
    available = int(section.VirtualAddress)+int(section.SizeOfRawData)-decoder_rva
    code = _read(data,image,decoder_rva,min(available,MAX_DECODER_BYTES),executable=True)
    machine = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    machine.detail = True
    instructions = []
    for instruction in machine.disasm(code,decoder_rva):
        instructions.append(instruction)
        if instruction.mnemonic == 'ret':
            break
        if len(instructions) > 7000:
            raise Arx20ChunkError('decoder命令数が上限外です')
    if not instructions or instructions[-1].mnemonic != 'ret':
        raise Arx20ChunkError('decoder終端を検証できません')
    initial = [ins for ins in instructions if ins.address < decoder_rva+0x180]
    loads, stores = {}, {}
    for i,ins in enumerate(initial[:-1]):
        operands = ins.operands
        following = initial[i+1]
        if ins.mnemonic != 'mov' or len(operands) != 2:
            continue
        dest,src = operands
        dest_stack = _stack(dest)
        if dest_stack is not None and dest.size == 4:
            if src.type == X86_OP_IMM:
                stores[dest_stack] = ('constant',int(src.imm)&MASK32)
            elif src.type == X86_OP_REG and src.reg == X86_REG_R8D:
                stores[dest_stack] = ('counter',0)
        if dest.type != X86_OP_REG or src.type != X86_OP_MEM or src.size != 4:
            continue
        if src.mem.base not in (X86_REG_RCX,X86_REG_RDX) or src.mem.index != 0:
            continue
        if following.mnemonic != 'mov' or len(following.operands) != 2:
            continue
        f_dest,f_src = following.operands
        target = _stack(f_dest)
        if target is None or f_dest.size != 4 or f_src.type != X86_OP_REG or f_src.reg != dest.reg:
            continue
        origin = 'key' if src.mem.base == X86_REG_RCX else 'nonce'
        loads[(origin,int(src.mem.disp)//4)] = target
    state_base = loads.get(('nonce',2))
    if state_base is None:
        raise Arx20ChunkError('stateのnonce配置が未対応です')
    for kind, wiring in (('key',KEY_WORDS),('nonce',NONCE_WORDS)):
        expected = {(kind,i):state_base+index*4 for i,index in enumerate(wiring)}
        if any(loads.get(key) != value for key,value in expected.items()):
            raise Arx20ChunkError('key/nonce word wiringが一致しません')
    if stores.get(state_base+4*COUNTER_WORD) != ('counter',0):
        raise Arx20ChunkError('counter配置が一致しません')
    constants = []
    for index in CONSTANT_WORDS:
        entry = stores.get(state_base+4*index)
        if not entry or entry[0] != 'constant':
            raise Arx20ChunkError('state定数がコードから取得できません')
        constants.append(entry[1])
    rotations = []
    for ins in instructions:
        if ins.mnemonic == 'rol' and len(ins.operands)==2 and ins.operands[0].type==X86_OP_REG and ins.operands[1].type==X86_OP_IMM:
            rotations.append((ins.reg_name(ins.operands[0].reg),int(ins.operands[1].imm)))
    if rotations != list(zip(ROTATION_REGISTERS,(16,12,8,7)*8)):
        raise Arx20ChunkError('double-round回転配線が一致しません')
    # counterを0,2,...,18としてdouble-roundを10回行うループを照合する。
    round_test = [i for i,ins in enumerate(instructions) if ins.mnemonic=='cmp' and ins.op_str=='rcx, 0x12']
    if len(round_test)!=1:
        raise Arx20ChunkError('20-roundの比較が一致しません')
    idx = round_test[0]
    if idx < 2 or instructions[idx-1].mnemonic != 'add' or instructions[idx-1].op_str != 'rax, 2':
        raise Arx20ChunkError('double-round counter更新が一致しません')
    back = [ins for ins in instructions[idx+1:idx+32] if ins.mnemonic=='jb' and ins.operands[0].type==X86_OP_IMM and decoder_rva < ins.operands[0].imm < instructions[idx].address]
    if len(back)!=1:
        raise Arx20ChunkError('double-round loopの分岐が一致しません')
    shape=_shape_hash(instructions,state_base,decoder_rva)
    if shape not in VERIFIED_COMPILER_SHAPES:
        raise Arx20ChunkError('暗号演算の検証済みcompiler-shapeではありません')
    _memcpy_calls(data,image,instructions,decoder_rva)
    return {'constants':tuple(constants),'decoder_size':instructions[-1].address+instructions[-1].size-decoder_rva,
            'state_stack_base':state_base,'instruction_count':len(instructions),'round_count':20,'compiler_shape_sha256':shape}


def _rot(value: int, bits: int) -> int:
    return ((value<<bits)|(value>>(32-bits))) & MASK32


def _quarter(words, a, b, c, d):
    words[a]=(words[a]+words[b])&MASK32; words[d]=_rot(words[d]^words[a],16)
    words[c]=(words[c]+words[d])&MASK32; words[b]=_rot(words[b]^words[c],12)
    words[a]=(words[a]+words[b])&MASK32; words[d]=_rot(words[d]^words[a],8)
    words[c]=(words[c]+words[d])&MASK32; words[b]=_rot(words[b]^words[c],7)


def _transform(cipher: bytes, key: bytes, nonce: bytes, constants: tuple[int,...], *, output_limit: int, budget: _Budget | None=None) -> bytes:
    if len(key)!=32 or len(nonce)!=12 or len(constants)!=4 or len(cipher)>output_limit:
        raise Arx20ChunkError('ARX数式入力の制約違反です')
    if budget is not None: budget.reserve(len(cipher))
    state=[0]*16
    for word,value in zip(KEY_WORDS,struct.unpack('<8I',key)): state[word]=value
    for word,value in zip(NONCE_WORDS,struct.unpack('<3I',nonce)): state[word]=value
    for word,value in zip(CONSTANT_WORDS,constants): state[word]=value
    output=bytearray(len(cipher))
    for start in range(0,len(cipher),64):
        if budget is not None and start%1024==0: budget.check()
        current=state.copy()
        for _ in range(10):
            for group in QUARTERS: _quarter(current,*group)
        stream=struct.pack('<16I',*[(a+b)&MASK32 for a,b in zip(state,current)])
        for i,value in enumerate(cipher[start:start+64]): output[start+i]=value^stream[i]
        state[COUNTER_WORD]=(state[COUNTER_WORD]+1)&MASK32
    return bytes(output)


def _payload_format(payload: bytes, *, output_limit: int) -> tuple[str,list[dict]]:
    if payload.startswith(b'MZ'):
        _pe_sections(payload,input_limit=MAX_OUTPUT_BYTES)
        return 'pe',[{'sha256':_sha(payload),'size':len(payload)}]
    # Donutの外形・暗号instance・module・最終PEまで既存のstrict parserで検証する。
    if not payload.startswith(b'\xe8') or len(payload)<8:
        raise Arx20ChunkError('復号出力がPE/Donutではありません')
    from unpackers.donut_unpacker import (
        decrypt_instance,
        parse_module,
        recover_module_payload,
    )
    instance,layout=decrypt_instance(payload)
    if layout.module < 0 or layout.module_length < 0:
        raise Arx20ChunkError('Donut配列layoutは未対応です')
    module_length=struct.unpack_from('<Q',instance,layout.module_length)[0]
    if not 1320<=module_length<=min(len(instance)-layout.module,output_limit):
        raise Arx20ChunkError('Donut module長が上限外です')
    module=instance[layout.module:layout.module+module_length]
    metadata=parse_module(module)
    # 既存aPLib helperには伸長上限引数がないため、このrouteでは未圧縮だけ対応。
    if metadata['compression']!=1 or not 0<metadata['length']<=output_limit:
        raise Arx20ChunkError('Donut圧縮形式またはdeclared長が有界条件を満たしません')
    stored=metadata['zlen'] or metadata['length']
    if not 0<stored<=min(output_limit,len(module)-1320):
        raise Arx20ChunkError('Donut stored長が上限外です')
    terminal=recover_module_payload(module)
    _pe_sections(terminal,input_limit=output_limit)
    return 'donut',[{'sha256':_sha(terminal),'size':len(terminal),'layout':layout.name}]


def recover_arx20_chunk_payloads(data: bytes, *, max_input_bytes: int=MAX_INPUT_BYTES,
                               max_output_bytes: int=MAX_OUTPUT_BYTES, max_candidates: int=MAX_CANDIDATES,
                               max_cipher_work_bytes: int=MAX_CIPHER_WORK_BYTES,
                               max_wall_seconds: float=MAX_WALL_SECONDS) -> list[Arx20ChunkResult]:
    """コード由来の暗号状態と有界index/chunkだけを復号して構造検証する。

    candidateが上限を超える場合は先頭結果への切り捨てをせず全体を棄却する。
    未対応の暗号レジスタ配置、壊れたsection、重複chunk、巨大宣言も棄却する。
    """
    _positive(max_input_bytes,MAX_INPUT_BYTES,'max_input_bytes')
    _positive(max_output_bytes,MAX_OUTPUT_BYTES,'max_output_bytes')
    _positive(max_candidates,MAX_CANDIDATES,'max_candidates')
    _positive(max_cipher_work_bytes,MAX_CIPHER_WORK_BYTES,'max_cipher_work_bytes')
    if type(max_wall_seconds) not in (int,float) or not 0<max_wall_seconds<=MAX_WALL_SECONDS:
        raise Arx20ChunkError('max_wall_secondsが不正です')
    budget=_Budget(time.monotonic(),float(max_wall_seconds),max_cipher_work_bytes)
    image=_pe_sections(data,input_limit=max_input_bytes)
    candidates=[]
    for section in image.sections:
        if not section.Characteristics&0x20000000: continue
        raw_offset=int(section.PointerToRawData)
        code=data[raw_offset:raw_offset+int(section.SizeOfRawData)]
        for match in INDEX_CALL.finditer(code):
            budget.check()
            if len(candidates)>=max_candidates:
                raise Arx20ChunkError('コード候補数が上限を超えています')
            candidates.append((int(section.VirtualAddress)+match.start(),match,code[match.end():match.end()+0x1000]))
    recovered=[]
    for caller_rva,match,following in candidates:
        try:
            base_rva=caller_rva+7+struct.unpack('<i',match.group('base'))[0]
            decoder_rva=caller_rva+len(match.group())+struct.unpack('<i',match.group('decoder'))[0]
            key_delta=struct.unpack('<i',match.group('key'))[0]
            cipher_delta=match.group('input')[0]
            table_size=struct.unpack('<i',match.group('size'))[0]
            if not 32<=table_size<=MAX_CHUNKS*16 or table_size%16 or not 0<cipher_delta<=64 or key_delta<0:
                raise Arx20ChunkError('index長またはoffsetが範囲外です')
            if b'\x48\x83\xfa'+bytes([table_size//16]) not in following:
                raise Arx20ChunkError('chunk個数のloop比較が一致しません')
            profile=_decoder_profile(data,image,decoder_rva)
            budget.check()
            chunks_match=CHUNK_CALL.search(following)
            if chunks_match is None or chunks_match.group('nonce')[0] != 28:
                raise Arx20ChunkError('chunk呼び出し構造が未対応です')
            chunk_rva=caller_rva+len(match.group())+chunks_match.start()
            chunk_base=chunk_rva+7+struct.unpack('<i',chunks_match.group('base'))[0]
            chunk_decoder=chunk_rva+len(chunks_match.group())+struct.unpack('<i',chunks_match.group('decoder'))[0]
            if chunk_base!=base_rva or chunk_decoder!=decoder_rva:
                raise Arx20ChunkError('index/chunkの基点またはdecoderが一致しません')
            region=_section(image,base_rva,1,executable=False)
            constants=profile['constants']
            table_key=_read(data,image,base_rva+key_delta,32,executable=False)
            table_nonce=table_key[:12]
            table=_transform(_read(data,image,base_rva+cipher_delta,table_size,executable=False),table_key,table_nonce,constants,output_limit=max_output_bytes,budget=budget)
            entries=[struct.unpack_from('<QQ',table,i) for i in range(0,len(table),16)]
            total=0; previous_end=cipher_delta+table_size; chunk_records=[]; payloads=[]
            # 全declared範囲を、復号メモリ確保前に検証する。
            for offset,length in entries:
                if length<=0 or offset<previous_end or length>max_output_bytes:
                    raise Arx20ChunkError('chunk長・順序・重複が不正です')
                total+=length
                if total>max_output_bytes:
                    raise Arx20ChunkError('復号出力総量が上限外です')
                target=_section(image,base_rva+offset,length+40,executable=False)
                if target is not region:
                    raise Arx20ChunkError('chunkが元のdata section外です')
                previous_end=offset+length+40
            if budget.cipher_used+total>budget.cipher_limit:
                raise Arx20ChunkLimitError('cipher_work_bytes',budget.cipher_used+total,budget.cipher_limit)
            for index,(offset,length) in enumerate(entries):
                cipher=_read(data,image,base_rva+offset,length,executable=False)
                key=_read(data,image,base_rva+offset+length,32,executable=False)
                nonce=_read(data,image,base_rva+offset+length+28,12,executable=False)
                payload=_transform(cipher,key,nonce,constants,output_limit=max_output_bytes,budget=budget)
                payloads.append(payload)
                chunk_records.append({'index':index,'offset':offset,'size':length,'sha256':_sha(payload)})
            payload=b''.join(payloads)
            format_name,children=_payload_format(payload,output_limit=min(max_output_bytes,max_cipher_work_bytes))
            budget.check()
            raw_end=max(int(s.PointerToRawData)+int(s.SizeOfRawData) for s in image.sections)
            evidence={'schema_version':1,'parent_sha256':_sha(data),'parent_size':len(data),
                      'decoder_rva':decoder_rva,'index_call_rva':caller_rva,'chunk_call_rva':chunk_rva,
                      'cipher_rva':base_rva,'index_size':table_size,'index_sha256':_sha(table),
                      'chunk_count':len(entries),'chunks':chunk_records,'payload_sha256':_sha(payload),
                      'payload_size':len(payload),'payload_format':format_name,'validated_children':children,
                      'round_count':profile['round_count'],'state_constants_sha256':_sha(struct.pack('<4I',*constants)),
                      'decoder_instruction_count':profile['instruction_count'],'overlay_ignored_bytes':max(0,len(data)-raw_end),
                      'compiler_shape_sha256':profile['compiler_shape_sha256'],'compiler_profile_scope':'verified_fixed_arithmetic_shape_dynamic_sigma',
                      'cipher_work_bytes':budget.cipher_used,'max_cipher_work_bytes':max_cipher_work_bytes,'max_wall_seconds':max_wall_seconds,
                      'sample_executed':False,'cpu_emulation_used':False,'network_contacted':False,
                      'key_values_published':False,'family_attribution_confirmed':False}
            recovered.append(Arx20ChunkResult(payload,evidence))
        except Arx20ChunkLimitError:
            raise
        except (Arx20ChunkError,ValueError,struct.error,OverflowError):
            continue
    budget.check()
    return recovered
