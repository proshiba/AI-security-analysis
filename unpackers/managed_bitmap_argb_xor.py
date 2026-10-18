"""二段のmanaged Bitmap loaderを、CLRやBinaryFormatterを実行せず復元する。

対象recipeは次をすべて静的に確認した場合だけ受理する。

* outer CILが ``GetPixel(x, y)`` のR/G/Bをx-majorで連結し、明示長で切る。
* outerの同一methodが、field literalをdelimiterで分割して3引数constructorへ渡す。
* 第一段childがレビュー済みのBitmap crop／ARGB／XOR／``Assembly.Load`` CIL profileと一致する。
* root ResourceSetの対象Bitmapが、限定NRBF envelope内の単一 ``byte[]`` である。
* PNG、crop、length prefix、XOR後のmanaged PE境界が一意に成立する。

BinaryFormatter、CLR、CIL、復元PEは実行しない。NRBFは必要なrecord列だけを
byte-levelで読み、未知record、重複候補、上限超過を安全側へ拒否する。
復元成功はloader lineageの証拠であり、malware family、C2、終端到達の確証には
使わない。
"""

from __future__ import annotations

import hashlib
import logging
import re
import struct
import time
import warnings
import zlib
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.error import MethodBodyFormatError
from pefile import PEFormatError

from extractors.managed_pe import has_clr_metadata
from unpackers.bounded_pe_scan import inspect_structural_pe_extent
from unpackers.managed_constructor_guard import preflight_clr_declarations

MAX_INPUT_BYTES = 32 << 20
MAX_METHODS = 8_192
MAX_METHOD_BYTES = 256 << 10
MAX_SIGNATURE_BYTES = 512
MAX_TOTAL_METHOD_BYTES = 16 << 20
MAX_METHOD_INSTRUCTIONS = 20_000
MAX_TOTAL_INSTRUCTIONS = 250_000
MAX_RESOURCE_SETS = 256
MAX_RESOURCE_ENTRIES = 4_096
MAX_RESOURCE_BYTES = 32 << 20
MAX_BITMAP_BYTES = 16 << 20
MAX_IMAGE_DIMENSION = 4_096
MAX_IMAGE_PIXELS = 8_000_000
MAX_PNG_CHUNKS = 4_096
MAX_PNG_CHUNK_BYTES = 16 << 20
MAX_PNG_COMPRESSED_BYTES = 32 << 20
MAX_IMAGE_BYTES = 64 << 20
MAX_OUTPUT_BYTES = 64 << 20
MAX_OVERLAY_BYTES = 4_096
MAX_LITERAL_CHARACTERS = 8_192
MAX_ELAPSED_SECONDS = 10.0
MAX_V2_ROOT_METHOD_CANDIDATES = 64
MAX_V2_LOAD_SINK_CANDIDATES = 64
MAX_V2_BITMAP_GETTER_CANDIDATES = 64
MAX_V2_GETTYPES_CANDIDATES = 64
MAX_V2_SPLIT_CANDIDATES = 64
MAX_V2_ARGUMENT_ARRAY_CANDIDATES = 64
MAX_V2_HANDOFF_CANDIDATES = 64
MAX_V2_RECIPE_COMBINATIONS = 4_096
MAX_V2_LOADER_ROLE_CANDIDATES = 64

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
SYSTEM_DRAWING_IDENTITY = (
    "System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
)

# このprofileはroot hashやprovider labelではなく、第一段loader assemblyの
# exact method bodyを照合する。token参照先とdataflowは別途semantic検証する。
LOADER_PROFILE_ID = "managed-bitmap-argb-xor-v1"
LOADER_METHOD_BODY_SHA256 = {
    "entry": "46f04f13b35809eba53c7700fb2b08f2436c21cf5c25dd6ec2375ea586b7163e",
    "decode_resource_argument": "87009bdc4d5b0768af979ab95e6526520ec92324251a237ffa5506c711d23a65",
    "decode_key_argument": "e90a7443b487ed6732be1bfdef77ad99ddcfe52e1d901678e180020ae6945368",
    "resource_wrapper": "f9758f277394875f39e573b3ccde437101e46d598b40d7a54fcc74c78994eb28",
    "crop_and_argb": "d4eba862bb8ab8ea6a7ac99b5d1610ea77e141fd2d6696a8ec29db8d19b5edc0",
    "load_wrapper": "36e02581ab3519e7018072ef071e0325a080764623c6154cf968ae36e45f322c",
    "invoke_wrapper": "b7b4fef911545e31a7438fae843f70c2926cc337f6010264d0693e0cc83e75bb",
    "invoke_target": "67edb37b6ed6fe59ad50f7ab854a0b63916c62ea0f2b5ff1b91a3d7dff45a41e",
    "assembly_load": "c9ed8fddd1e44e27c722438a6911c09e2f5d15342f746826072d42904ba09105",
    "xor_wrapper": "9cefd66e7da0bb73c252d355e1cdec7e6aff9565b55922043f5079ba6a7595a8",
    "key_bytes": "8f7efbac0fcf94803d4c45718c5f3d8093ee31c8a21189c0e439fb785c02ef57",
    "mask": "590b914bd933c9e508a7c43bfa9b9134ac985dfbcac3fa3b0994148de96af617",
    "key_index": "6fd1b3d3dd4cd6a7da80c59d431dec0458f2d3734775336ca2c2af6060fe1014",
    "xor_loop": "05daddc5f06d88f0ffa5ac037ab563138ea142a906815ea00a252f33034ef05c",
    "drop_sentinel": "bec3d5af27f8199a83d3ab0c7d1d2a891fc1473c1bd153820998c8d93ecffb3c",
    "hex_text": "71f8cb4ac0882cde5005f9130249f2071480ceb3ef4bb4be92e95d9592626579",
    "resource_lookup": "b404ab4026ae97f15f1aa048c7e3f424b0f7ef38d62e3c702c12f897674bcfff",
    "argb_bytes": "9483b13252bf4737a9f51e0221e22364f1db84b7941c73092bf9826f4c44d617",
    "crop_bitmap": "e61720786a4280396c4ad2a93bed39011cc8555276c9e0c9194290f8ce5e0f28",
}

# ``GetTypes()[1]`` 系rootは、復元byte列を作るRGB extractor自体もexact CIL
# bodyとAPI/dataflowで照合する。名前、provider label、root hashだけでは選ばない。
# ``method_shape`` はsignature、TypeDef owner token／export index、MethodAttributesを
# review済みbuildへ固定する。metadata row再採番を伴う別buildは自動で緩和せず、
# 新しいprofileとして静的レビューする。
ROOT_V2_RGB_PROFILES: dict[str, dict[str, object]] = {
    "cf8a64ef71d08ff807f64dfb7bcb33a0bb2de13c13a5c4cabfc0ba97389d1ab1": {
        "profile_id": "linq-grouped-rgb-v2",
        "method_shape": {
            "signature": "000215128179010512816d08",
            "owner_token": 0x02000010,
            "owner_export_index": 10,
            "flags": (True, True, False, False),
        },
        "required_calls": (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
            "System.Math::Min",
            "System.Linq.Enumerable::Range",
            "System.Linq.Enumerable::GroupBy",
            "System.Linq.Enumerable::SelectMany",
            "System.Linq.Enumerable::ToList",
        ),
        "related_body_sha256": (
            "8f70689b552f488537d01597ed57d2204d982949fb30c71a9f6a1ee0d8221b06",
            "84fb31c2dc8c98c549d33a3bd01418286d0cb7c33f337a1737e14ac12c395aca",
            "9c7f0ecef238d34199076982e96f77a7010c3e514d47fb53f706f18dcf21fd92",
        ),
        "related_method_shapes": (
            {
                "signature": "20010808",
                "owner_token": 0x02000012,
                "owner_export_index": None,
                "flags": (False, False, False, False),
            },
            {
                "signature": "200115128181010515128185020808",
                "owner_token": 0x02000013,
                "owner_export_index": None,
                "flags": (False, False, False, False),
            },
            {
                "signature": "20010508",
                "owner_token": 0x02000014,
                "owner_export_index": None,
                "flags": (False, False, False, False),
            },
        ),
        "required_method_edges": (
            ("root", 0, ("ldftn",)),
            ("root", 1, ("ldftn",)),
            (1, 2, ("ldftn",)),
        ),
        "related_calls": (
            "System.Drawing.Bitmap::GetPixel",
            "System.Drawing.Color::get_R",
            "System.Drawing.Color::get_G",
            "System.Drawing.Color::get_B",
        ),
    },
    "d625ea63918200bfab5907955c72967e6a3c5d18b84f703b2657c9d892a5a1fc": {
        "profile_id": "accumulator-loop-rgb-v2",
        "method_shape": {
            "signature": "00021512550105124908",
            "owner_token": 0x0200000B,
            "owner_export_index": 6,
            "flags": (True, True, False, False),
        },
        "required_calls": (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
            "System.Drawing.Bitmap::GetPixel",
            "System.Drawing.Color::get_R",
            "System.Drawing.Color::get_G",
            "System.Drawing.Color::get_B",
            "TrimExcess",
        ),
        "related_body_sha256": (),
        "related_method_shapes": (),
        "required_method_edges": (),
        "related_calls": (),
    },
    "9a89b81cfa8f9321203c61968b473dfdbffdafe67883c48fd92d46fe0fe3e480": {
        "profile_id": "iterator-rgb-a-v2",
        "method_shape": {
            "signature": "000215128159010512809108",
            "owner_token": 0x02000004,
            "owner_export_index": 1,
            "flags": (True, True, False, False),
        },
        "required_calls": (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
            "System.Collections.IEnumerator::MoveNext",
        ),
        # factory bodyは共通だが、review済みcorpusには同じiterator意味形の
        # MoveNextが2種ある。各groupからassembly内で一意な1 methodを要求する。
        "related_body_sha256_groups": (
            ("5fbc5b1adacd64e0101ff08b597bc8d94a5a718732872c0b4688770bf266e24b",),
            (
                "83e306b041c882d1f88ed11edda5ad37ef256153185e9218aedee89ce5bf0f74",
                "41e0a6d4aaf23cee97b8bcd1dfc839fab10d0b2cf9939ef8e979027934317fb6",
            ),
        ),
        "related_method_shapes": (
            {
                "signature": "000215128089010512809108",
                "owner_token": 0x02000003,
                "owner_export_index": 0,
                "flags": (True, False, False, False),
            },
            {
                "signature": "200002",
                "owner_token": 0x02000005,
                "owner_export_index": None,
                "flags": (False, False, False, False),
            },
        ),
        "required_method_edges": (("root", 0, ("call",)),),
        "iterator_owner_binding": {
            "factory_related_index": 0,
            "move_next_related_index": 1,
            "constructor_body_sha256": "3c732762770ada8ac9b6b743f6aa538b7a0504c2b61f45ffcf6df820c44cf70d",
            "constructor_signature": "20010108",
            "constructor_flags": (False, True, True, True),
        },
        "related_calls": (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
            "System.Drawing.Bitmap::GetPixel",
            "System.Drawing.Color::get_R",
            "System.Drawing.Color::get_G",
            "System.Drawing.Color::get_B",
        ),
    },
    "aceb7f2931982400b6f1c38d946c3355cdef18f61a04d1bd03cc428f0e31cc83": {
        "profile_id": "sliding-window-rgb-v2",
        "method_shape": {
            "signature": "000215127101051280bd08",
            "owner_token": 0x0200001E,
            "owner_export_index": 25,
            "flags": (True, True, False, False),
        },
        "required_calls": (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
            "System.Drawing.Bitmap::GetPixel",
            "System.Drawing.Color::get_R",
            "System.Drawing.Color::get_G",
            "System.Drawing.Color::get_B",
            "TrimExcess",
        ),
        "related_body_sha256": (),
        "related_method_shapes": (),
        "required_method_edges": (),
        "related_calls": (),
    },
    "34325bf75540054a1f74e2bccbe4fbe61290c8640133c9bcea14c248f9472b9a": {
        "profile_id": "iterator-rgb-b-v2",
        "method_shape": {
            "signature": "0002151280a10105127108",
            "owner_token": 0x0200000A,
            "owner_export_index": 5,
            "flags": (True, True, False, False),
        },
        "required_calls": (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
            "System.Collections.IEnumerator::MoveNext",
        ),
        "related_body_sha256": (
            "199155e36ceefdecf8c51bad59719cbd3d28c402ed1f3de329151526af7d229b",
            "32f8774a7af5c278960852cbc8c3d476fe939bec7f5bd8f901d862a60c2c7b75",
        ),
        "related_method_shapes": (
            {
                "signature": "000215126d0105127108",
                "owner_token": 0x02000003,
                "owner_export_index": 0,
                "flags": (True, False, False, False),
            },
            {
                "signature": "200002",
                "owner_token": 0x0200000B,
                "owner_export_index": None,
                "flags": (False, False, False, False),
            },
        ),
        "required_method_edges": (("root", 0, ("call",)),),
        "iterator_owner_binding": {
            "factory_related_index": 0,
            "move_next_related_index": 1,
            "constructor_body_sha256": "36ed8a03ab9f6ccc6c1b88ab360375b69b90d476b7cb3c9d132680e906f64c12",
            "constructor_signature": "20010108",
            "constructor_flags": (False, True, True, True),
        },
        "related_calls": (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
            "System.Drawing.Bitmap::GetPixel",
            "System.Drawing.Color::get_R",
            "System.Drawing.Color::get_G",
            "System.Drawing.Color::get_B",
        ),
    },
}

# strongly-typed resource getterは、GetObject/cast文字列の散在だけでなく、
# review済みbodyと戻り値signatureを一体で照合する。これによりdead codeへ
# decoy API参照を置いた別戻り値getterを受理しない。
ROOT_V2_BITMAP_GETTER_PROFILES: dict[str, bytes] = {
    "5d17a51a9ce1814af27bb5f6ce77a492b907cb6c2b2b595c45cf96c49423e5e8": bytes.fromhex(
        "000012816d"
    ),
    "bdb27c80d343421b6f382c317df74d8d36b2411804d642e6f7ab5a5057508393": bytes.fromhex(
        "00001249"
    ),
    "89603848609084f7abe2f7e8b180a86937dd700633a43af1aa6d4aa47d859ea5": bytes.fromhex(
        "0000128091"
    ),
    "b800402d4eab1a0ce1c79f9114509d17357d312701d60063e784313bd91af327": bytes.fromhex(
        "00001271"
    ),
}

# v2 childはdynamic proxyを含むため、文字列や一部APIだけでは受理しない。
# 既知child SHAでは完全inventoryも照合し、未知SHAではreview済みMethodDef body、
# signature、同一owner、TypeRef/MemberRef、resource getter、実call edgeを一体で
# 照合する。復元後のPE境界、crop、ARGB、XOR、key periodも必ず検証する。
LOADER_V2_PROFILES: dict[str, dict[str, object]] = {
    "a191d02ea8e94d4e60af487303704e362981530ded0c3f0199f6c5878ce2d82e": {
        "profile_id": "managed-bitmap-argb-xor-v2-a191d02e",
        "cil_inventory_sha256": "9fd32aec80484ed6087ad999de9ad970f7f3d3e82399388a083d03280243a98a",
        "constructor_body_sha256": "33fd671f0fcc42ea9702c7b355c273965d1317eee93c10a6cf2a7befc6889582",
        "entry_body_sha256": "ef5b265c13abd406649c38f84fe26b4de5ae7731a06aa30e5dd2cd107d016686",
        "dispatch_body_sha256": "ef5b265c13abd406649c38f84fe26b4de5ae7731a06aa30e5dd2cd107d016686",
        "crop_body_sha256": "a086b25760a3382e1fcbfa4853ca62a43a683fc91a5082cfabd52891940146a4",
        "mask_body_sha256": "5129a1fddf9424b974aa2b4bfbf8a9c395eba188bfaaec0d55c248e3ed81d515",
        "load_wrapper_body_sha256": "dbfe9293735d3e387e76558409b80c86998efc45b422623c7dd78ac7c7c2bf63",
        "load_inner_body_sha256": "294ed544d871c774abf75a20cc2f153a00a23f7502264a83ba98a63da3b19b5c",
        "resource_getter_body_sha256": "37a0c7657cb543923546c8efc8afa2060e6cb7af25d6d68b3daf5b2c3c0eadf4",
        "role_signatures": {
            "constructor": "2003010e0e0e",
            "entry": "0003010e0e0e",
            "dispatch": "0003010e0e0e",
            "crop": "00011d051259",
            "mask": "00021d051d050e",
            "load_wrapper": "0001125d1d05",
            "load_inner": "0001125d1d05",
            "resource_getter": "000212590e0e",
        },
        "required_role_edges": (
            ("constructor", "dispatch"),
            ("dispatch", "crop"),
            ("dispatch", "mask"),
            ("dispatch", "load_wrapper"),
            ("load_wrapper", "load_inner"),
        ),
    },
    "783064541c490386ad9fe5b9660b68b09ddf4a203789612ccacc5924e327c0ef": {
        "profile_id": "managed-bitmap-argb-xor-v2-78306454",
        "cil_inventory_sha256": "724d53ade6a35243c5407cdd5c4614dbf949f65f0f8a518b393e5cebb9d768ca",
        "constructor_body_sha256": "5bcf084de34b382f73edffcbcb69705d0856756716b74388b6b9b1fe8a842d48",
        "entry_body_sha256": "ce0e3267f0c779122b8d35f640fc808eb1e81cc1d7f5962c1e6bcf7817ca7621",
        "dispatch_body_sha256": "05241d1fbfc9784decdd6b7a00d6178b072fd65db7febc2ae8c111a4f4d82889",
        "crop_body_sha256": "fbc717a23402b3e5722ec29b66235bbc934e224e1f90b6d4271dc39919068ec3",
        "mask_body_sha256": "f6f8cd7c53a23ad59cb22c676a37b94676763164c5dd6e080304b645c01be55e",
        "load_wrapper_body_sha256": "6ba7b8f445600ea830434d4cf1002019688178eb03f4f49f5afeabfb6a6756a9",
        "load_inner_body_sha256": "23218cb02eea580a3a2c396b0050f2d815aec080d01615913a1af8571ff462f0",
        "resource_getter_body_sha256": "899bff76dccc38636255fba7c3031a4ee253fbc091e02408941cd70c4499add3",
        "role_signatures": {
            "constructor": "2003010e0e0e",
            "entry": "0003010e0e0e",
            "dispatch": "0004010e0e0e1280b0",
            "crop": "00011d0512809d",
            "mask": "00021d051d050e",
            "load_wrapper": "00011280991d05",
            "load_inner": "00011280991d05",
            "resource_getter": "000212809d0e0e",
        },
        "required_role_edges": (("constructor", "dispatch"),),
    },
    "405d0dcbe8454646de26e8b2db78435803b99dccdcbcdaa1028c56c7c0c6c3ec": {
        "profile_id": "managed-bitmap-argb-xor-v2-405d0dcb",
        "cil_inventory_sha256": "62828771fc85411169e9eca0493f15561c7af5450e7e9637e4848db3b9a222fb",
        "constructor_body_sha256": "bdc2e03385a293d5dcf262bae55be2843b96b40bf69ef4d13e43c95757e7564b",
        "entry_body_sha256": "a148e0856ff7eae70a21548a80295cac743fd73cdbdbe96453bb5cbbbbf3541a",
        "dispatch_body_sha256": "7a68caaa12222f2a6c8db47c29900055381a4c15fef96ab759a6ec19a1e346aa",
        "crop_body_sha256": "3281a54c0e1f0afdbd9d4cf3e6ea244eaf777a1f15b994214a386f0a7e1b001b",
        "mask_body_sha256": "cfb70c4b94bd55d4165f86be2bae521115583de727f6bcde679a526b07085005",
        "load_wrapper_body_sha256": "0c2eeaf4d2056acdf9e6c03bd39e0ddc1e5e6102886589da111228e88e9a3794",
        "load_inner_body_sha256": "a0ce745100c874fb176f959d0571ba387d4db0d87498986c244bf4874b500af8",
        "resource_getter_body_sha256": "b06fc4cd35c8a7798f615b8fdd7b657ad47539ec1ee155db568977ddade614a0",
        "role_signatures": {
            "constructor": "2003010e0e0e",
            "entry": "0003010e0e0e",
            "dispatch": "0004010e0e0e1280b4",
            "crop": "00011d05128099",
            "mask": "00021d051d050e",
            "load_wrapper": "00011280a11d05",
            "load_inner": "00011280a11d05",
            "resource_getter": "00021280990e0e",
        },
        "required_role_edges": (("constructor", "dispatch"),),
    },
    "d4b398de0a87c2c75b007d5d37531502475c183374db0fa2a387e7fbc7232956": {
        "profile_id": "managed-bitmap-argb-xor-v2-d4b398de",
        "cil_inventory_sha256": "7b58cd507184cf50d438745ed032fbd4aa387edf80ba676cb32338fd85cf6dc6",
        "constructor_body_sha256": "fe4e61ef2355922978639f4b260192c1011bf30a2be54de74095db33b9ae253e",
        "entry_body_sha256": "db240a42a97def7d3ddd7ab55a4175c5fa3624f48d52d3035e56a8d449f72a48",
        "dispatch_body_sha256": "cd4b5240dc5e09070e8cd36029b0f11fca553ad5e4d7c14fb36f2ac59cdaa7d4",
        "crop_body_sha256": "2293656fdd22bb031e015f8bf5ddb655538535ab907a9a3e6a4a36532e9b6af1",
        "mask_body_sha256": "258b37404165832f7b24ce472b85a96d4ec9b25d955a5e9d3bd10c2822e7cf46",
        "load_wrapper_body_sha256": "21c7c14ae72b6757cf8c555013b753464cd368f7263b419345a250e82eaf7152",
        "load_inner_body_sha256": "d052b007967a3e6144ba94c1856404b92126a1c6fffa1b2befbe9a77dcd0c2db",
        "resource_getter_body_sha256": "32d5f67fd7396c355f5b7f21df217e0576485820b76cd85cf7d3b6db427b8c2d",
        "role_signatures": {
            "constructor": "2003010e0e0e",
            "entry": "0003010e0e0e",
            "dispatch": "0004010e0e0e1280ac",
            "crop": "00011d05128099",
            "mask": "00021d051d050e",
            "load_wrapper": "00011280a11d05",
            "load_inner": "00011280a11d05",
            "resource_getter": "00021280990e0e",
        },
        "required_role_edges": (("constructor", "dispatch"),),
    },
}

# v2 semantic profileはMethodDef bodyだけでなく、TypeRef/MemberRefの解決先も
# 固定する。dynamic proxy名はbuildごとに変わるため、意味を担うframework型と
# memberだけを要求し、未知の参照が追加されたこと自体では受理しない／拒否しない。
LOADER_V2_REQUIRED_RESOLUTION_TARGETS: dict[str, frozenset[str]] = {
    "constructor": frozenset({"System.Windows.Forms.Form::.ctor", "System.String"}),
    "mask": frozenset({"System.Byte"}),
    "load_inner": frozenset(
        {
            "System.Reflection.Assembly",
            "System.Char",
            "System.Object",
            "System.String::.ctor",
        }
    ),
    "resource_getter": frozenset(
        {"System.Drawing.Bitmap", "System.Resources.ResourceManager::.ctor"}
    ),
}


class RecoveryError(ValueError):
    """未知の形、曖昧性、上限超過をfail-closedで表す。"""


class IncompleteRecoveryError(RecoveryError):
    """deadlineまたは探索上限により、完全走査できなかったことを表す。"""

    def __init__(
        self,
        reason: str,
        *,
        incomplete_type: str,
        stage: str,
        role: str | None = None,
        observed: int | None = None,
        limit: float | None = None,
    ) -> None:
        super().__init__(reason)
        self.incomplete_type = incomplete_type
        self.stage = stage
        self.role = role
        self.observed = observed
        self.limit = limit

    def report_details(self) -> dict[str, object]:
        """秘密値を含まない、機械判定可能な未完了理由を返す。"""

        details: dict[str, object] = {
            "type": self.incomplete_type,
            "stage": self.stage,
        }
        if self.role is not None:
            details["role"] = self.role
        if self.observed is not None:
            details["observed"] = self.observed
        if self.limit is not None:
            details["limit"] = self.limit
        return details


@dataclass(frozen=True)
class Instruction:
    """公開文字列を保持しない、有界CIL instruction model。"""

    offset: int
    opcode: str
    token: int | None
    resolved: str
    integer: int | None
    user_string: str | None
    local: int | None


@dataclass(frozen=True)
class MethodModel:
    """MethodDef bodyとtoken参照を結び付けた静的model。"""

    token: int
    owner: str
    name: str
    rva: int
    body_size: int
    body_sha256: str
    instructions: tuple[Instruction, ...]
    owner_token: int = 0
    owner_export_index: int | None = None
    signature: bytes = b""
    is_static: bool = False
    is_public: bool = False
    is_special_name: bool = False
    is_runtime_special_name: bool = False


@dataclass(frozen=True)
class RootRecipe:
    """outer CILから一意に得たconstructor引数と第一段変換。"""

    caller_token: int
    rgb_method_token: int
    bitmap_getter_token: int
    first_child_length: int
    first_bitmap_name: str
    resource_argument_hex: str
    key_argument_hex: str
    resource_namespace: str
    handoff_profile: str = "getexportedtypes0-constructor-v1"
    rgb_profile_id: str = "linq-rgb-v1"
    first_resource_set_name: str | None = None


@dataclass(frozen=True)
class LoaderRecipe:
    """レビュー済み第一段childから得た変換定数。"""

    crop_right: int
    crop_bottom: int
    mask_xor: int
    method_tokens: dict[str, int]
    constructor_token: int
    profile_id: str = LOADER_PROFILE_ID
    evidence_method_body_sha256: tuple[tuple[str, str], ...] = ()
    exact_child_profile_verified: bool = False
    semantic_child_profile_verified: bool = False
    call_graph_verified: bool = False


@dataclass(frozen=True)
class _V2MethodIndex:
    """v2探索で再利用するMethodDef token/body hash索引。"""

    by_token: dict[int, tuple[MethodModel, ...]]
    by_body_sha256: dict[str, tuple[MethodModel, ...]]


@dataclass(frozen=True)
class ResourceEntry:
    """ResourceSet entryの境界検証済みraw bytes。"""

    resource_set_name: str
    entry_name: str
    type_name: str
    data: bytes


def _base_report(size: int) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "not_candidate",
        "input_size": size,
        "profile_id": LOADER_PROFILE_ID,
        "sample_executed": False,
        "clr_loaded": False,
        "binaryformatter_deserialized": False,
        "instruction_emulation_performed": False,
        "network_contacted": False,
        "raw_resource_content_in_report": False,
        "raw_payload_content_in_report": False,
        "secret_material_in_report": False,
        "private_recursive_artifact_returned": False,
        "artifact_visibility": "private_recursive_analysis_only",
        "runtime_reachability_confirmed": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_promotion_eligible": False,
    }


def _deadline(deadline: float, clock: Callable[[], float]) -> None:
    if clock() > deadline:
        raise IncompleteRecoveryError(
            "elapsed_time_limit",
            incomplete_type="deadline",
            stage="managed_bitmap_argb_xor",
            limit=MAX_ELAPSED_SECONDS,
        )


def _loop_deadline(
    index: int,
    deadline: float | None,
    clock: Callable[[], float],
) -> None:
    """大きな探索loopを64反復ごとに協調停止する。"""

    if deadline is not None and index % 64 == 0:
        _deadline(deadline, clock)


def _v2_candidate_limit(
    role: str,
    observed: int,
    limit: int,
) -> None:
    """role別探索上限を通常のrecipe不一致と区別して停止する。"""

    if observed > limit:
        raise IncompleteRecoveryError(
            "outer_gettypes1_candidate_limit",
            incomplete_type="candidate_limit",
            stage="outer_gettypes1_root_recipe",
            role=role,
            observed=observed,
            limit=limit,
        )


def _accumulate_v2_candidates(
    counts: Counter[str],
    role: str,
    added: int,
    limit: int,
) -> None:
    """method/profileをまたぐrole候補総数にも同じ上限を適用する。"""

    counts[role] += added
    _v2_candidate_limit(role, counts[role], limit)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text(value: object, *, limit: int = 1_024) -> str:
    raw = getattr(value, "value", value)
    if not isinstance(raw, str) or len(raw) > limit:
        return ""
    return raw


def _type_name(row: object | None) -> str:
    if row is None:
        return ""
    namespace = _text(getattr(row, "TypeNamespace", None))
    name = _text(getattr(row, "TypeName", None))
    return f"{namespace}.{name}" if namespace and name else name


def _operand_value(operand: object) -> int | None:
    value = getattr(operand, "value", None)
    return value if type(value) is int else None


def _integer(opcode: str, operand: object) -> int | None:
    if opcode == "ldc.i4.m1":
        return -1
    match = re.fullmatch(r"ldc\.i4\.([0-8])", opcode)
    if match:
        return int(match.group(1))
    if opcode not in {"ldc.i4", "ldc.i4.s"}:
        return None
    value = _operand_value(operand)
    if value is not None:
        return value
    try:
        return int(str(operand), 0)
    except ValueError:
        return None


def _local(opcode: str, operand: object) -> int | None:
    match = re.fullmatch(r"(?:ld|st)loc\.([0-3])", opcode)
    if match:
        return int(match.group(1))
    if opcode not in {"ldloc", "ldloc.s", "stloc", "stloc.s", "ldloca", "ldloca.s"}:
        return None
    match = re.fullmatch(r"local\(0x([0-9a-fA-F]+)\)", str(operand))
    return int(match.group(1), 16) if match else None


def _row_tokens(
    tables: object,
    deadline: float,
    clock: Callable[[], float],
) -> dict[int, int]:
    result: dict[int, int] = {}
    total = 0
    for name, prefix in (
        ("TypeRef", 0x01000000),
        ("TypeDef", 0x02000000),
        ("Field", 0x04000000),
        ("MethodDef", 0x06000000),
        ("MemberRef", 0x0A000000),
        ("MethodSpec", 0x2B000000),
    ):
        table = getattr(tables, name, None)
        for index, row in enumerate(getattr(table, "rows", ()) or (), 1):
            total += 1
            if total & 0xFF == 0:
                _deadline(deadline, clock)
            result[id(row)] = prefix | index
    return result


def _metadata_names(
    pe: object,
    rows: dict[int, int],
    deadline: float,
    clock: Callable[[], float],
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    tables = pe.net.mdtables
    type_names: dict[int, str] = {}
    method_names: dict[int, str] = {}
    field_names: dict[int, str] = {}
    method_owners: dict[int, str] = {}
    field_owners: dict[int, str] = {}

    for table_name, prefix in (("TypeRef", 0x01000000), ("TypeDef", 0x02000000)):
        table = getattr(tables, table_name, None)
        for index, row in enumerate(getattr(table, "rows", ()) or (), 1):
            if index & 0xFF == 0:
                _deadline(deadline, clock)
            type_names[prefix | index] = _type_name(row)

    for index, row in enumerate(
        getattr(getattr(tables, "TypeDef", None), "rows", ()) or (), 1
    ):
        if index & 0xFF == 0:
            _deadline(deadline, clock)
        owner = _type_name(row)
        for reference in getattr(row, "MethodList", ()) or ():
            method_owners[int(reference.row_index)] = owner
        for reference in getattr(row, "FieldList", ()) or ():
            field_owners[int(reference.row_index)] = owner

    for index, row in enumerate(
        getattr(getattr(tables, "MethodDef", None), "rows", ()) or (), 1
    ):
        if index & 0xFF == 0:
            _deadline(deadline, clock)
        name = _text(getattr(row, "Name", None))
        owner = method_owners.get(index, "")
        method_names[0x06000000 | index] = f"{owner}::{name}" if owner else name
    for index, row in enumerate(
        getattr(getattr(tables, "Field", None), "rows", ()) or (), 1
    ):
        if index & 0xFF == 0:
            _deadline(deadline, clock)
        name = _text(getattr(row, "Name", None))
        owner = field_owners.get(index, "")
        field_names[0x04000000 | index] = f"{owner}::{name}" if owner else name
    for index, row in enumerate(
        getattr(getattr(tables, "MemberRef", None), "rows", ()) or (), 1
    ):
        if index & 0xFF == 0:
            _deadline(deadline, clock)
        parent = getattr(getattr(row, "Class", None), "row", None)
        parent_token = rows.get(id(parent), 0)
        owner = type_names.get(parent_token, method_names.get(parent_token, ""))
        name = _text(getattr(row, "Name", None))
        method_names[0x0A000000 | index] = f"{owner}::{name}" if owner else name
    for index, row in enumerate(
        getattr(getattr(tables, "MethodSpec", None), "rows", ()) or (), 1
    ):
        if index & 0xFF == 0:
            _deadline(deadline, clock)
        target = getattr(getattr(row, "Method", None), "row", None)
        target_token = rows.get(id(target), 0)
        method_names[0x2B000000 | index] = method_names.get(target_token, "")
    return type_names, method_names, field_names


def _method_raw_window(pe: object, data: bytes, rva: int) -> tuple[int, int]:
    matches: list[tuple[int, int]] = []
    for section in pe.sections:
        virtual = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        raw_offset = int(section.PointerToRawData)
        delta = rva - virtual
        if 0 <= delta < raw_size:
            start = raw_offset + delta
            available = min(MAX_METHOD_BYTES, raw_size - delta)
            if 0 <= start < start + available <= len(data):
                matches.append((start, start + available))
    if len(matches) != 1:
        raise RecoveryError("method_span_ambiguous_or_unbacked")
    return matches[0]


@contextmanager
def _contained_parser_diagnostics() -> Iterator[None]:
    logger = logging.getLogger("dnfile")
    previous = logger.level
    logger.setLevel(logging.CRITICAL)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield
    finally:
        logger.setLevel(previous)


def _normalize_methods(
    pe: object,
    data: bytes,
    deadline: float,
    clock: Callable[[], float],
) -> list[MethodModel]:
    tables = pe.net.mdtables
    rows = list(getattr(getattr(tables, "MethodDef", None), "rows", ()) or ())
    if not rows or len(rows) > MAX_METHODS:
        raise RecoveryError("method_count_limit")
    metadata_rows = _row_tokens(tables, deadline, clock)
    type_names, method_names, field_names = _metadata_names(
        pe,
        metadata_rows,
        deadline,
        clock,
    )
    method_owner_tokens: dict[int, int] = {}
    exported_type_indices: dict[int, int] = {}
    exported_index = 0
    type_rows = list(getattr(getattr(tables, "TypeDef", None), "rows", ()) or ())
    for type_index, type_row in enumerate(type_rows, 1):
        type_token = 0x02000000 | type_index
        flags = getattr(type_row, "Flags", None)
        if bool(getattr(flags, "tdPublic", False)) or bool(
            getattr(flags, "tdNestedPublic", False)
        ):
            exported_type_indices[type_token] = exported_index
            exported_index += 1
        for reference in getattr(type_row, "MethodList", ()) or ():
            method_row = getattr(reference, "row", None)
            method_token = metadata_rows.get(id(method_row), 0)
            if method_token >> 24 == 6:
                if method_token in method_owner_tokens:
                    raise RecoveryError("method_owner_ambiguous")
                method_owner_tokens[method_token] = type_token
    models: list[MethodModel] = []
    total_bytes = 0
    total_instructions = 0
    for index, row in enumerate(rows, 1):
        _deadline(deadline, clock)
        rva = int(getattr(row, "Rva", 0) or 0)
        if not rva:
            continue
        start, end = _method_raw_window(pe, data, rva)
        try:
            body = read_method_body_from_bytes(data[start:end])
        except MethodBodyFormatError as exc:
            raise RecoveryError("method_body_parse_incomplete") from exc
        body_size = int(body.size)
        if not 0 < body_size <= end - start:
            raise RecoveryError("method_body_bounds")
        instructions = list(body.instructions)
        total_bytes += body_size
        total_instructions += len(instructions)
        if (
            body_size > MAX_METHOD_BYTES
            or total_bytes > MAX_TOTAL_METHOD_BYTES
            or len(instructions) > MAX_METHOD_INSTRUCTIONS
            or total_instructions > MAX_TOTAL_INSTRUCTIONS
        ):
            raise RecoveryError("method_body_budget")
        normalized: list[Instruction] = []
        for item in instructions:
            opcode = str(item.opcode.name)
            value = _operand_value(item.operand)
            token = (
                value
                if value is not None and value >> 24 in {1, 2, 4, 6, 10, 43}
                else None
            )
            user_string = None
            if opcode == "ldstr" and value is not None:
                try:
                    candidate = str(pe.net.user_strings.get(value & 0xFFFFFF))
                except Exception as exc:
                    raise RecoveryError("user_string_unavailable") from exc
                if len(candidate) > MAX_LITERAL_CHARACTERS:
                    raise RecoveryError("user_string_limit")
                user_string = candidate
            resolved = ""
            if token is not None:
                resolved = method_names.get(
                    token, field_names.get(token, type_names.get(token, ""))
                )
            normalized.append(
                Instruction(
                    offset=int(item.offset),
                    opcode=opcode,
                    token=token,
                    resolved=resolved,
                    integer=_integer(opcode, item.operand),
                    user_string=user_string,
                    local=_local(opcode, item.operand),
                )
            )
        token = 0x06000000 | index
        owner_token = method_owner_tokens.get(token, 0)
        if owner_token == 0:
            raise RecoveryError("method_owner_missing")
        raw_signature = getattr(getattr(row, "Signature", None), "value", None)
        if not isinstance(raw_signature, (bytes, bytearray)):
            raise RecoveryError("method_signature_unavailable")
        signature = bytes(raw_signature)
        if not 0 < len(signature) <= MAX_SIGNATURE_BYTES:
            raise RecoveryError("method_signature_bounds")
        flags = getattr(row, "Flags", None)
        owner, _, name = method_names.get(token, "").partition("::")
        models.append(
            MethodModel(
                token=token,
                owner=owner,
                name=name,
                rva=rva,
                body_size=body_size,
                body_sha256=_sha256(data[start : start + body_size]),
                instructions=tuple(normalized),
                owner_token=owner_token,
                owner_export_index=exported_type_indices.get(owner_token),
                signature=signature,
                is_static=bool(getattr(flags, "mdStatic", False)),
                is_public=bool(getattr(flags, "mdPublic", False)),
                is_special_name=bool(getattr(flags, "mdSpecialName", False)),
                is_runtime_special_name=bool(getattr(flags, "mdRTSpecialName", False)),
            )
        )
    return models


def _meaningful(method: MethodModel) -> list[Instruction]:
    return [item for item in method.instructions if item.opcode != "nop"]


def _build_v2_method_index(
    methods: list[MethodModel],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> _V2MethodIndex:
    """MethodDefを一度だけ走査し、tokenとbody hashの多重度を保持する。"""

    by_token_lists: dict[int, list[MethodModel]] = {}
    by_body_lists: dict[str, list[MethodModel]] = {}
    for index, method in enumerate(methods):
        _loop_deadline(index, deadline, clock)
        by_token_lists.setdefault(method.token, []).append(method)
        by_body_lists.setdefault(method.body_sha256, []).append(method)
    return _V2MethodIndex(
        by_token={token: tuple(items) for token, items in by_token_lists.items()},
        by_body_sha256={
            digest: tuple(items) for digest, items in by_body_lists.items()
        },
    )


def _calls(method: MethodModel) -> list[Instruction]:
    return [
        item
        for item in method.instructions
        if item.opcode in {"call", "callvirt", "newobj"}
    ]


def _call_suffix(method: MethodModel, suffix: str) -> bool:
    return any(item.resolved.endswith(suffix) for item in _calls(method))


def _bounded_call_suffix(
    method: MethodModel,
    suffix: str,
    *,
    deadline: float | None,
    clock: Callable[[], float],
) -> bool:
    """deadlineを検査しながらcall target suffixを照合する。"""

    for index, item in enumerate(method.instructions):
        _loop_deadline(index, deadline, clock)
        if item.opcode in {"call", "callvirt", "newobj"} and item.resolved.endswith(
            suffix
        ):
            return True
    return False


def _method_tokens(method: MethodModel, opcode: str) -> list[int]:
    return [
        int(item.token)
        for item in method.instructions
        if item.opcode == opcode and item.token is not None and item.token >> 24 == 6
    ]


def _find_first_rgb_recipe(
    methods: list[MethodModel],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[MethodModel, int]:
    if deadline is not None:
        _deadline(deadline, clock)
    rgb_candidates: list[MethodModel] = []
    for method_index, method in enumerate(methods):
        _loop_deadline(method_index, deadline, clock)
        il = _meaningful(method)
        if (
            [item.opcode for item in il]
            == [
                "ldc.i4.3",
                "newarr",
                "dup",
                "ldc.i4.0",
                "ldarga.s",
                "call",
                "stelem.i1",
                "dup",
                "ldc.i4.1",
                "ldarga.s",
                "call",
                "stelem.i1",
                "dup",
                "ldc.i4.2",
                "ldarga.s",
                "call",
                "stelem.i1",
                "ret",
            ]
            and il[1].resolved == "System.Byte"
            and [il[index].resolved for index in (5, 10, 15)]
            == [
                "System.Drawing.Color::get_R",
                "System.Drawing.Color::get_G",
                "System.Drawing.Color::get_B",
            ]
            and [item.integer for item in il if item.integer is not None]
            == [3, 0, 1, 2]
        ):
            rgb_candidates.append(method)
    if len(rgb_candidates) != 1:
        raise RecoveryError("outer_rgb_lambda_ambiguous")
    rgb = rgb_candidates[0]

    pixel_candidates: list[tuple[MethodModel, int]] = []
    height_candidates: list[tuple[MethodModel, int]] = []
    for method_index, method in enumerate(methods):
        _loop_deadline(method_index, deadline, clock)
        il = _meaningful(method)
        if (
            [item.opcode for item in il]
            == ["ldarg.0", "ldfld", "ldarg.1", "ldarg.2", "callvirt", "ret"]
            and il[1].token is not None
            and il[4].resolved == "System.Drawing.Bitmap::GetPixel"
        ):
            pixel_candidates.append((method, int(il[1].token)))
        if (
            [item.opcode for item in il]
            == ["ldc.i4.0", "ldarg.0", "ldfld", "callvirt", "call", "ret"]
            and il[2].token is not None
            and il[3].resolved == "System.Drawing.Image::get_Height"
            and il[4].resolved == "System.Linq.Enumerable::Range"
        ):
            height_candidates.append((method, int(il[2].token)))

    if len(pixel_candidates) != 1 or len(height_candidates) != 1:
        raise RecoveryError("outer_pixel_or_height_lambda_ambiguous")
    pixel, pixel_field = pixel_candidates[0]
    height, height_field = height_candidates[0]
    if pixel_field != height_field:
        raise RecoveryError("outer_bitmap_field_mismatch")

    main_candidates: list[tuple[MethodModel, int]] = []
    for method_index, method in enumerate(methods):
        _loop_deadline(method_index, deadline, clock)
        il = _meaningful(method)
        if [item.opcode for item in il] != [
            "newobj",
            "stloc.0",
            "ldloc.0",
            "ldarg.0",
            "stfld",
            "ldc.i4.0",
            "ldloc.0",
            "ldfld",
            "callvirt",
            "call",
            "ldloc.0",
            "ldftn",
            "newobj",
            "ldloc.0",
            "ldftn",
            "newobj",
            "call",
            "ldsfld",
            "dup",
            "brtrue.s",
            "pop",
            "ldsfld",
            "ldftn",
            "newobj",
            "dup",
            "stsfld",
            "call",
            "ldarg.1",
            "call",
            "call",
            "stloc.1",
            "br.s",
            "ldloc.1",
            "ret",
        ]:
            continue
        if not (
            il[4].token == il[7].token == pixel_field
            and il[11].token == height.token
            and il[14].token == pixel.token
            and il[22].token == rgb.token
            and il[17].token == il[25].token
            and il[8].resolved == "System.Drawing.Image::get_Width"
            and il[9].resolved == "System.Linq.Enumerable::Range"
            and il[16].resolved == "System.Linq.Enumerable::SelectMany"
            and il[26].resolved == "System.Linq.Enumerable::SelectMany"
            and il[28].resolved == "System.Linq.Enumerable::Take"
            and il[29].resolved
            in {
                "System.Linq.Enumerable::ToArray",
                "System.Linq.Enumerable::ToList",
            }
        ):
            continue
        main_candidates.append((method, pixel_field))
    unique = {(item.token, field): (item, field) for item, field in main_candidates}
    if len(unique) != 1:
        raise RecoveryError("outer_rgb_recipe_ambiguous")
    return next(iter(unique.values()))


def _match_split_arguments(
    method: MethodModel,
    assignments: dict[int, list[str]],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[str, str, str] | None:
    if deadline is not None:
        _deadline(deadline, clock)
    il = _meaningful(method)
    matches: list[tuple[str, str, str]] = []
    for start in range(max(0, len(il) - 31)):
        _loop_deadline(start, deadline, clock)
        window = il[start : start + 32]
        if (
            len(window) != 32
            or window[0].opcode != "ldstr"
            or window[0].user_string is None
        ):
            continue
        delimiter = window[0].user_string
        delimiter_local = (
            window[1].local if window[1].opcode.startswith("stloc") else None
        )
        field_token = window[3].token
        split_local = (
            window[12].local if window[12].opcode.startswith("stloc") else None
        )
        args_local = window[31].local if window[31].opcode.startswith("stloc") else None
        if None in {delimiter_local, field_token, split_local, args_local}:
            continue
        checks = (
            window[2].opcode == "ldarg.0",
            window[3].opcode == "ldfld",
            window[4].integer == 1,
            window[5].opcode == "newarr" and window[5].resolved == "System.String",
            window[6].opcode == "dup",
            window[7].integer == 0,
            window[8].opcode.startswith("ldloc") and window[8].local == delimiter_local,
            window[9].opcode == "stelem.ref",
            window[10].integer == 0,
            window[11].opcode == "callvirt"
            and window[11].resolved == "System.String::Split",
            window[13].integer == 3,
            window[14].opcode == "newarr" and window[14].resolved == "System.String",
            window[15].opcode == "dup",
            window[16].integer == 0,
            window[17].opcode.startswith("ldloc") and window[17].local == split_local,
            window[18].integer == 1,
            window[19].opcode == "ldelem.ref",
            window[20].opcode == "stelem.ref",
            window[21].opcode == "dup",
            window[22].integer == 1,
            window[23].opcode.startswith("ldloc") and window[23].local == split_local,
            window[24].integer == 2,
            window[25].opcode == "ldelem.ref",
            window[26].opcode == "stelem.ref",
            window[27].opcode == "dup",
            window[28].integer == 2,
            window[29].opcode.startswith("ldloc")
            and window[29].local == delimiter_local,
            window[30].opcode == "stelem.ref",
        )
        if not all(checks):
            continue
        values = assignments.get(int(field_token), [])
        if len(values) != 1:
            continue
        combined = values[0]
        parts = combined.split(delimiter)
        if (
            not delimiter
            or parts[:1] != [""]
            or parts[3:] != ["", ""]
            or len(parts) != 5
        ):
            continue
        first, second = parts[1], parts[2]
        if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}){1,128}", first) or not re.fullmatch(
            r"(?:[0-9A-Fa-f]{2}){1,128}", second
        ):
            continue
        if start == 0 or not il[start - 1].opcode.startswith("stloc"):
            continue
        exported_type_local = il[start - 1].local
        tail = il[start + 32 : start + 52]
        if len(tail) != 20:
            continue
        constructor_local = tail[14].local
        invoke_argument_local = tail[17].local
        if None in {exported_type_local, constructor_local, invoke_argument_local}:
            continue
        tail_checks = (
            tail[0].opcode.startswith("ldloc") and tail[0].local == exported_type_local,
            tail[1].opcode.startswith("ldloc") and tail[1].local == args_local,
            tail[2].opcode == "ldsfld" and tail[2].token is not None,
            tail[3].opcode == "dup",
            tail[4].opcode == "brtrue.s",
            tail[5].opcode == "pop",
            tail[6].opcode == "ldsfld",
            tail[7].opcode == "ldftn",
            tail[8].opcode == "newobj",
            tail[9].opcode == "dup",
            tail[10].opcode == "stsfld" and tail[10].token == tail[2].token,
            tail[11].opcode == "call"
            and tail[11].resolved == "System.Linq.Enumerable::Select",
            tail[12].opcode == "call"
            and tail[12].resolved == "System.Linq.Enumerable::ToArray",
            tail[13].opcode == "callvirt"
            and tail[13].resolved == "System.Type::GetConstructor",
            tail[14].opcode.startswith("stloc"),
            tail[15].opcode.startswith("ldloc") and tail[15].local == constructor_local,
            tail[16].opcode.startswith("ldloc") and tail[16].local == args_local,
            tail[17].opcode.startswith("stloc"),
            tail[18].opcode.startswith("ldloc")
            and tail[18].local == invoke_argument_local,
            tail[19].opcode == "callvirt"
            and tail[19].resolved == "System.Reflection.ConstructorInfo::Invoke",
        )
        if not all(tail_checks):
            continue
        matches.append((first, second, delimiter))
    return matches[0] if len(matches) == 1 else None


def _bitmap_getter(
    methods: list[MethodModel],
    token: int,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> str:
    if deadline is not None:
        _deadline(deadline, clock)
    matches: list[MethodModel] = []
    for method_index, method in enumerate(methods):
        _loop_deadline(method_index, deadline, clock)
        if method.token == token:
            matches.append(method)
    if len(matches) != 1:
        raise RecoveryError("outer_bitmap_getter_missing")
    method = matches[0]
    strings: list[str] = []
    resource_getter = False
    bitmap_cast = False
    for instruction_index, item in enumerate(method.instructions):
        _loop_deadline(instruction_index, deadline, clock)
        if item.user_string is not None:
            strings.append(item.user_string)
        if item.opcode in {"call", "callvirt"} and item.resolved.endswith(
            "System.Resources.ResourceManager::GetObject"
        ):
            resource_getter = True
        if item.opcode == "castclass" and item.resolved == "System.Drawing.Bitmap":
            bitmap_cast = True
    if len(strings) != 1 or not 0 < len(strings[0]) <= 256:
        raise RecoveryError("outer_bitmap_name_ambiguous")
    if not resource_getter or not bitmap_cast:
        raise RecoveryError("outer_bitmap_getter_shape")
    return strings[0]


def _v2_bitmap_getter(
    methods: list[MethodModel],
    token: int,
    *,
    method_index: _V2MethodIndex | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[str, str]:
    """review済みgetterの戻り値dataflowとresource set ownerを束縛する。"""

    if deadline is not None:
        _deadline(deadline, clock)
    index = method_index or _build_v2_method_index(
        methods,
        deadline=deadline,
        clock=clock,
    )
    matches = index.by_token.get(token, ())
    if len(matches) != 1:
        raise RecoveryError("outer_v2_bitmap_getter_missing")
    method = matches[0]
    expected_signature = ROOT_V2_BITMAP_GETTER_PROFILES.get(method.body_sha256)
    if (
        expected_signature is None
        or method.signature != expected_signature
        or not method.is_static
        or method.is_public
        or not method.is_special_name
        or method.is_runtime_special_name
        or not method.owner.endswith(".Properties.Resources")
    ):
        raise RecoveryError("outer_v2_bitmap_getter_profile_mismatch")
    il = _meaningful(method)
    strings: list[str] = []
    resource_manager_call_count = 0
    get_object_call_count = 0
    bitmap_cast_count = 0
    return_count = 0
    for instruction_index, item in enumerate(il):
        _loop_deadline(instruction_index, deadline, clock)
        if item.user_string is not None:
            strings.append(item.user_string)
        if item.opcode in {"call", "callvirt"} and item.resolved == (
            f"{method.owner}::get_ResourceManager"
        ):
            resource_manager_call_count += 1
        if (
            item.opcode in {"call", "callvirt"}
            and item.resolved == "System.Resources.ResourceManager::GetObject"
        ):
            get_object_call_count += 1
        if item.opcode == "castclass" and item.resolved == "System.Drawing.Bitmap":
            bitmap_cast_count += 1
        if item.opcode == "ret":
            return_count += 1
    if len(strings) != 1 or not 0 < len(strings[0]) <= 256:
        raise RecoveryError("outer_v2_bitmap_name_ambiguous")
    bitmap_name = strings[0]
    if method.name != f"get_{bitmap_name}":
        raise RecoveryError("outer_v2_bitmap_property_binding_mismatch")
    if (
        resource_manager_call_count != 1
        or get_object_call_count != 1
        or bitmap_cast_count != 1
        or return_count != 1
        or not il
        or il[-1].opcode != "ret"
    ):
        raise RecoveryError("outer_v2_bitmap_getter_semantic_shape_mismatch")
    return bitmap_name, f"{method.owner}.resources"


def _method_profile_shape(
    method: MethodModel,
    raw_shape: object,
    *,
    mismatch_reason: str,
) -> None:
    """review済みmethodのsignature、owner identity、flagsを完全照合する。"""

    if not isinstance(raw_shape, dict):
        raise RecoveryError("outer_v2_rgb_profile_invalid")
    raw_signature = raw_shape.get("signature")
    raw_owner_token = raw_shape.get("owner_token")
    raw_owner_export_index = raw_shape.get("owner_export_index")
    raw_flags = raw_shape.get("flags")
    if (
        not isinstance(raw_signature, str)
        or type(raw_owner_token) is not int
        or raw_owner_token >> 24 != 2
        or (
            raw_owner_export_index is not None
            and type(raw_owner_export_index) is not int
        )
        or not isinstance(raw_flags, tuple)
        or len(raw_flags) != 4
        or any(type(flag) is not bool for flag in raw_flags)
    ):
        raise RecoveryError("outer_v2_rgb_profile_invalid")
    try:
        signature = bytes.fromhex(raw_signature)
    except ValueError as exc:
        raise RecoveryError("outer_v2_rgb_profile_invalid") from exc
    if (
        not signature
        or method.signature != signature
        or method.owner_token != raw_owner_token
        or method.owner_export_index != raw_owner_export_index
        or (
            method.is_static,
            method.is_public,
            method.is_special_name,
            method.is_runtime_special_name,
        )
        != raw_flags
    ):
        raise RecoveryError(mismatch_reason)


def _v2_profile_method_edges(
    root: MethodModel,
    related: list[MethodModel],
    raw_edges: object,
    *,
    deadline: float | None,
    clock: Callable[[], float],
) -> None:
    """exact bodyの存在だけでなく、実MethodDef token edgeを一意に束縛する。"""

    if not isinstance(raw_edges, tuple):
        raise RecoveryError("outer_v2_rgb_profile_invalid")

    def selected(value: object) -> MethodModel:
        if value == "root":
            return root
        if type(value) is not int or not 0 <= value < len(related):
            raise RecoveryError("outer_v2_rgb_profile_invalid")
        return related[value]

    for edge_index, raw_edge in enumerate(raw_edges):
        _loop_deadline(edge_index, deadline, clock)
        if (
            not isinstance(raw_edge, tuple)
            or len(raw_edge) != 3
            or not isinstance(raw_edge[2], tuple)
            or not raw_edge[2]
            or any(not isinstance(opcode, str) for opcode in raw_edge[2])
        ):
            raise RecoveryError("outer_v2_rgb_profile_invalid")
        source = selected(raw_edge[0])
        target = selected(raw_edge[1])
        matches = 0
        for instruction_index, item in enumerate(source.instructions):
            _loop_deadline(instruction_index, deadline, clock)
            if item.opcode in raw_edge[2] and item.token == target.token:
                matches += 1
        if matches != 1:
            raise RecoveryError("outer_v2_rgb_related_edge_mismatch")


def _v2_iterator_owner_binding(
    method_index: _V2MethodIndex,
    related: list[MethodModel],
    raw_binding: object,
    *,
    deadline: float | None,
    clock: Callable[[], float],
) -> None:
    """iterator factoryのnewobj先ownerをreview済みMoveNext ownerへ束縛する。"""

    if raw_binding is None:
        return
    if not isinstance(raw_binding, dict):
        raise RecoveryError("outer_v2_rgb_profile_invalid")
    factory_index = raw_binding.get("factory_related_index")
    move_next_index = raw_binding.get("move_next_related_index")
    constructor_digest = raw_binding.get("constructor_body_sha256")
    constructor_signature = raw_binding.get("constructor_signature")
    constructor_flags = raw_binding.get("constructor_flags")
    if (
        type(factory_index) is not int
        or type(move_next_index) is not int
        or not 0 <= factory_index < len(related)
        or not 0 <= move_next_index < len(related)
        or not isinstance(constructor_digest, str)
        or not isinstance(constructor_signature, str)
        or not isinstance(constructor_flags, tuple)
        or len(constructor_flags) != 4
        or any(type(flag) is not bool for flag in constructor_flags)
    ):
        raise RecoveryError("outer_v2_rgb_profile_invalid")
    try:
        signature = bytes.fromhex(constructor_signature)
        bytes.fromhex(constructor_digest)
    except ValueError as exc:
        raise RecoveryError("outer_v2_rgb_profile_invalid") from exc
    if len(constructor_digest) != 64 or not signature:
        raise RecoveryError("outer_v2_rgb_profile_invalid")

    factory = related[factory_index]
    move_next = related[move_next_index]
    matches: list[MethodModel] = []
    for instruction_index, item in enumerate(factory.instructions):
        _loop_deadline(instruction_index, deadline, clock)
        if item.opcode != "newobj" or item.token is None:
            continue
        targets = method_index.by_token.get(item.token, ())
        if len(targets) != 1:
            continue
        constructor = targets[0]
        flags = (
            constructor.is_static,
            constructor.is_public,
            constructor.is_special_name,
            constructor.is_runtime_special_name,
        )
        if (
            constructor.body_sha256 == constructor_digest
            and constructor.signature == signature
            and flags == constructor_flags
            and constructor.name == ".ctor"
            and constructor.owner_token == move_next.owner_token
            and constructor.owner_export_index == move_next.owner_export_index
        ):
            matches.append(constructor)
    if len(matches) != 1:
        raise RecoveryError("outer_v2_rgb_iterator_owner_binding_mismatch")


def _v2_rgb_profile(
    methods: list[MethodModel],
    token: int,
    *,
    method_index: _V2MethodIndex | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> str:
    """review済みRGB extractorをexact bodyとAPI/dataflowの双方で照合する。"""

    if deadline is not None:
        _deadline(deadline, clock)
    index = method_index or _build_v2_method_index(
        methods,
        deadline=deadline,
        clock=clock,
    )
    matches = index.by_token.get(token, ())
    if len(matches) != 1:
        raise RecoveryError("outer_v2_rgb_method_missing")
    method = matches[0]
    profile = ROOT_V2_RGB_PROFILES.get(method.body_sha256)
    if profile is None:
        raise RecoveryError("outer_v2_rgb_profile_mismatch")
    _method_profile_shape(
        method,
        profile.get("method_shape"),
        mismatch_reason="outer_v2_rgb_profile_mismatch",
    )
    required_calls = tuple(profile["required_calls"])
    if not all(
        _bounded_call_suffix(
            method,
            str(suffix),
            deadline=deadline,
            clock=clock,
        )
        for suffix in required_calls
    ):
        raise RecoveryError("outer_v2_rgb_framework_reference_mismatch")

    related: list[MethodModel] = []
    digest_groups = profile.get("related_body_sha256_groups")
    if digest_groups is None:
        digest_groups = tuple(
            (str(digest),) for digest in tuple(profile["related_body_sha256"])
        )
    raw_related_shapes = profile.get("related_method_shapes")
    if not isinstance(raw_related_shapes, tuple) or len(raw_related_shapes) != len(
        tuple(digest_groups)
    ):
        raise RecoveryError("outer_v2_rgb_profile_invalid")
    for group_index, raw_group in enumerate(tuple(digest_groups)):
        _loop_deadline(group_index, deadline, clock)
        digest_group = tuple(str(digest) for digest in tuple(raw_group))
        if not digest_group or len(set(digest_group)) != len(digest_group):
            raise RecoveryError("outer_v2_rgb_related_profile_invalid")
        body_matches = [
            item
            for digest in digest_group
            for item in index.by_body_sha256.get(digest, ())
        ]
        if len(body_matches) != 1:
            raise RecoveryError("outer_v2_rgb_related_body_ambiguous")
        related_method = body_matches[0]
        _method_profile_shape(
            related_method,
            raw_related_shapes[group_index],
            mismatch_reason="outer_v2_rgb_related_method_shape_mismatch",
        )
        related.append(related_method)
    _v2_profile_method_edges(
        method,
        related,
        profile.get("required_method_edges"),
        deadline=deadline,
        clock=clock,
    )
    _v2_iterator_owner_binding(
        index,
        related,
        profile.get("iterator_owner_binding"),
        deadline=deadline,
        clock=clock,
    )
    related_calls = tuple(profile["related_calls"])
    if not all(
        any(
            _bounded_call_suffix(
                item,
                str(suffix),
                deadline=deadline,
                clock=clock,
            )
            for item in related
        )
        for suffix in related_calls
    ):
        raise RecoveryError("outer_v2_rgb_related_reference_mismatch")
    profile_id = profile["profile_id"]
    if not isinstance(profile_id, str):
        raise RecoveryError("outer_v2_rgb_profile_invalid")
    return profile_id


def _static_string_assignments(
    methods: list[MethodModel],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[int, list[str]]:
    """全CILで一度だけ書かれる ``ldstr; stsfld`` をfield値として扱う。"""

    assignments: dict[int, list[str]] = {}
    write_counts: dict[int, int] = {}
    instruction_index = 0
    for method_index, method in enumerate(methods):
        _loop_deadline(method_index, deadline, clock)
        for item in _meaningful(method):
            _loop_deadline(instruction_index, deadline, clock)
            instruction_index += 1
            if item.opcode == "stsfld" and item.token is not None:
                write_counts[item.token] = write_counts.get(item.token, 0) + 1
        if (
            method.name != ".cctor"
            or not method.is_static
            or not method.is_special_name
            or not method.is_runtime_special_name
            or method.signature != b"\x00\x00\x01"
        ):
            continue
        il = _meaningful(method)
        for cil_index in range(len(il) - 1):
            _loop_deadline(cil_index, deadline, clock)
            literal, store = il[cil_index : cil_index + 2]
            if (
                literal.opcode == "ldstr"
                and literal.user_string is not None
                and store.opcode == "stsfld"
                and store.token is not None
                and store.resolved.partition("::")[0] == method.owner
            ):
                assignments.setdefault(store.token, []).append(literal.user_string)
    return {
        token: values
        for token, values in assignments.items()
        if write_counts.get(token) == 1 and len(values) == 1
    }


def _local_store_counts(
    method: MethodModel,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> Counter[int]:
    """method内local定義数を1回の走査で索引化する。"""

    counts: Counter[int] = Counter()
    for index, item in enumerate(_meaningful(method)):
        _loop_deadline(index, deadline, clock)
        if item.opcode.startswith("stloc") and item.local is not None:
            counts[int(item.local)] += 1
    return counts


def _local_store_count(
    method: MethodModel,
    local: int,
    *,
    local_store_counts: Counter[int] | None = None,
) -> int:
    """同一method内で指定localへの定義数を数える。"""

    if local_store_counts is not None:
        return local_store_counts[local]
    return sum(
        item.opcode.startswith("stloc") and item.local == local
        for item in _meaningful(method)
    )


def _v2_load_sinks(
    method: MethodModel,
    handoff_profile: str,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> list[tuple[int, int, int, int]]:
    """Assembly.Load相当sinkをbitmap local、長さ、RGB token、assembly localへ束縛する。"""

    il = _meaningful(method)
    matches: list[tuple[int, int, int, int]] = []
    if handoff_profile == "gettypes1-latecall":
        for start in range(len(il) - 18):
            _loop_deadline(start, deadline, clock)
            window = il[start : start + 19]
            if not all(
                (
                    window[0].opcode == "call"
                    and window[0].resolved == "System.Threading.Thread::GetDomain",
                    window[1].opcode == "ldnull",
                    window[2].opcode == "ldstr",
                    window[3].opcode == "ldstr",
                    window[2].user_string is not None,
                    window[3].user_string is not None,
                    (window[2].user_string or "") + (window[3].user_string or "")
                    == "Load",
                    window[4].opcode == "call"
                    and window[4].resolved == "System.String::Concat",
                    window[5].integer == 1,
                    window[6].opcode == "newarr"
                    and window[6].resolved == "System.Object",
                    window[7].opcode == "dup",
                    window[8].integer == 0,
                    window[9].opcode.startswith("ldloc"),
                    window[10].integer is not None,
                    window[11].opcode in {"call", "callvirt"}
                    and window[11].token is not None
                    and window[11].token >> 24 == 6,
                    window[12].opcode == "call"
                    and window[12].resolved == "System.Linq.Enumerable::ToArray",
                    window[13].opcode == "stelem.ref",
                    window[14].opcode == "ldnull",
                    window[15].opcode == "ldnull",
                    window[16].opcode == "call"
                    and window[16].resolved
                    == "Microsoft.VisualBasic.CompilerServices.LateBinding::LateGet",
                    window[17].opcode == "castclass"
                    and window[17].resolved == "System.Reflection.Assembly",
                    window[18].opcode.startswith("stloc"),
                )
            ):
                continue
            if window[9].local is None or window[18].local is None:
                continue
            matches.append(
                (
                    window[9].local,
                    int(window[10].integer),
                    int(window[11].token),
                    window[18].local,
                )
            )
            _v2_candidate_limit(
                "load_sink",
                len(matches),
                MAX_V2_LOAD_SINK_CANDIDATES,
            )
    elif handoff_profile == "gettypes1-type-invokemember":
        for start in range(len(il) - 17):
            _loop_deadline(start, deadline, clock)
            window = il[start : start + 18]
            if not all(
                (
                    window[0].opcode == "ldtoken"
                    and window[0].resolved == "System.Reflection.Assembly",
                    window[1].opcode == "call"
                    and window[1].resolved == "System.Type::GetTypeFromHandle",
                    window[2].opcode == "ldstr" and window[2].user_string == "Load",
                    window[3].integer == 256,
                    window[4].opcode == "ldnull",
                    window[5].opcode == "ldnull",
                    window[6].integer == 1,
                    window[7].opcode == "newarr"
                    and window[7].resolved == "System.Object",
                    window[8].opcode == "dup",
                    window[9].integer == 0,
                    window[10].opcode.startswith("ldloc"),
                    window[11].integer is not None,
                    window[12].opcode in {"call", "callvirt"}
                    and window[12].token is not None
                    and window[12].token >> 24 == 6,
                    window[13].opcode == "call"
                    and window[13].resolved == "System.Linq.Enumerable::ToArray",
                    window[14].opcode == "stelem.ref",
                    window[15].opcode == "call"
                    and window[15].resolved == "System.Type::InvokeMember",
                    window[16].opcode == "isinst"
                    and window[16].resolved == "System.Reflection.Assembly",
                    window[17].opcode.startswith("stloc"),
                )
            ):
                continue
            if window[10].local is None or window[17].local is None:
                continue
            matches.append(
                (
                    window[10].local,
                    int(window[11].integer),
                    int(window[12].token),
                    window[17].local,
                )
            )
            _v2_candidate_limit(
                "load_sink",
                len(matches),
                MAX_V2_LOAD_SINK_CANDIDATES,
            )
    elif handoff_profile == "gettypes1-activator":
        for start in range(len(il) - 14):
            _loop_deadline(start, deadline, clock)
            window = il[start : start + 15]
            if not all(
                (
                    window[0].opcode == "call"
                    and window[0].resolved == "System.AppDomain::get_CurrentDomain",
                    window[1].opcode == "ldstr" and window[1].user_string == "Load",
                    window[2].integer == 2,
                    window[3].integer == 1,
                    window[4].opcode == "newarr"
                    and window[4].resolved == "System.Object",
                    window[5].opcode == "dup",
                    window[6].integer == 0,
                    window[7].opcode.startswith("ldloc"),
                    window[8].integer is not None,
                    window[9].opcode in {"call", "callvirt"}
                    and window[9].token is not None
                    and window[9].token >> 24 == 6,
                    window[10].opcode == "call"
                    and window[10].resolved == "System.Linq.Enumerable::ToArray",
                    window[11].opcode == "stelem.ref",
                    window[12].opcode == "call"
                    and window[12].resolved
                    == "Microsoft.VisualBasic.Interaction::CallByName",
                    window[13].opcode == "isinst"
                    and window[13].resolved == "System.Reflection.Assembly",
                    window[14].opcode.startswith("stloc"),
                )
            ):
                continue
            if window[7].local is None or window[14].local is None:
                continue
            matches.append(
                (
                    window[7].local,
                    int(window[8].integer),
                    int(window[9].token),
                    window[14].local,
                )
            )
            _v2_candidate_limit(
                "load_sink",
                len(matches),
                MAX_V2_LOAD_SINK_CANDIDATES,
            )
        for start in range(len(il) - 5):
            _loop_deadline(start, deadline, clock)
            window = il[start : start + 6]
            if not all(
                (
                    window[0].opcode.startswith("ldloc")
                    and window[0].local is not None,
                    window[1].integer is not None,
                    window[2].opcode in {"call", "callvirt"}
                    and window[2].token is not None
                    and window[2].token >> 24 == 6,
                    window[3].opcode == "call"
                    and window[3].resolved == "System.Linq.Enumerable::ToArray",
                    window[4].opcode == "call"
                    and window[4].resolved == "System.Reflection.Assembly::Load",
                    window[5].opcode.startswith("stloc")
                    and window[5].local is not None,
                )
            ):
                continue
            matches.append(
                (
                    int(window[0].local),
                    int(window[1].integer),
                    int(window[2].token),
                    int(window[5].local),
                )
            )
            _v2_candidate_limit(
                "load_sink",
                len(matches),
                MAX_V2_LOAD_SINK_CANDIDATES,
            )
    return matches


def _v2_gettypes_locals(
    method: MethodModel,
    assembly_local: int,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> list[int]:
    il = _meaningful(method)
    matches: list[int] = []
    for start in range(len(il) - 4):
        _loop_deadline(start, deadline, clock)
        window = il[start : start + 5]
        if all(
            (
                window[0].opcode.startswith("ldloc")
                and window[0].local == assembly_local,
                window[1].opcode == "callvirt"
                and window[1].resolved == "System.Reflection.Assembly::GetTypes",
                window[2].integer == 1,
                window[3].opcode == "ldelem.ref",
                window[4].opcode.startswith("stloc") and window[4].local is not None,
            )
        ):
            matches.append(int(window[4].local))
            _v2_candidate_limit(
                "selected_type",
                len(matches),
                MAX_V2_GETTYPES_CANDIDATES,
            )
    return matches


def _v2_bitmap_getters(
    method: MethodModel,
    methods: list[MethodModel],
    bitmap_local: int,
    *,
    method_index: _V2MethodIndex | None = None,
    local_store_counts: Counter[int] | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> list[tuple[int, str, str]]:
    il = _meaningful(method)
    matches: dict[tuple[int, str, str], tuple[int, str, str]] = {}
    for index in range(len(il) - 1):
        _loop_deadline(index, deadline, clock)
        call, store = il[index : index + 2]
        if not (
            call.opcode == "call"
            and call.token is not None
            and call.token >> 24 == 6
            and store.opcode.startswith("stloc")
            and store.local == bitmap_local
        ):
            continue
        try:
            name, resource_set_name = _v2_bitmap_getter(
                methods,
                int(call.token),
                method_index=method_index,
                deadline=deadline,
                clock=clock,
            )
        except IncompleteRecoveryError:
            raise
        except RecoveryError:
            continue
        candidate = (int(call.token), name, resource_set_name)
        matches[candidate] = candidate
        _v2_candidate_limit(
            "bitmap_getter",
            len(matches),
            MAX_V2_BITMAP_GETTER_CANDIDATES,
        )
    resource_manager_locals: dict[int, str] = {}
    for index in range(len(il) - 3):
        _loop_deadline(index, deadline, clock)
        window = il[index : index + 4]
        type_name = window[0].resolved
        if all(
            (
                window[0].opcode == "ldtoken"
                and window[0].token is not None
                and window[0].token >> 24 == 2,
                re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
                    type_name,
                )
                is not None,
                window[1].opcode == "call"
                and window[1].resolved == "System.Type::GetTypeFromHandle",
                window[2].opcode == "newobj"
                and window[2].resolved
                == "System.ComponentModel.ComponentResourceManager::.ctor",
                window[3].opcode.startswith("stloc") and window[3].local is not None,
            )
        ):
            resource_manager_local = int(window[3].local)
            if (
                _local_store_count(
                    method,
                    resource_manager_local,
                    local_store_counts=local_store_counts,
                )
                == 1
            ):
                resource_manager_locals[resource_manager_local] = (
                    f"{type_name}.resources"
                )
    for index in range(len(il) - 4):
        _loop_deadline(index, deadline, clock)
        window = il[index : index + 5]
        if not all(
            (
                window[0].opcode.startswith("ldloc")
                and window[0].local in resource_manager_locals,
                window[1].opcode == "ldstr"
                and window[1].user_string is not None
                and 0 < len(window[1].user_string) <= 256,
                window[2].opcode == "callvirt"
                and window[2].token is not None
                and window[2].resolved == "System.Resources.ResourceManager::GetObject",
                window[3].opcode == "isinst"
                and window[3].resolved == "System.Drawing.Bitmap",
                window[4].opcode.startswith("stloc")
                and window[4].local == bitmap_local,
            )
        ):
            continue
        resource_set_name = resource_manager_locals[int(window[0].local)]
        candidate = (
            int(window[2].token),
            str(window[1].user_string),
            resource_set_name,
        )
        matches[candidate] = candidate
        _v2_candidate_limit(
            "bitmap_getter",
            len(matches),
            MAX_V2_BITMAP_GETTER_CANDIDATES,
        )
    return list(matches.values())


def _v2_split_locals(
    method: MethodModel,
    handoff_profile: str,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> list[tuple[int, int, str]]:
    il = _meaningful(method)
    matches: list[tuple[int, int, str]] = []
    if handoff_profile in {"gettypes1-latecall", "gettypes1-activator"}:
        for start in range(len(il) - 3):
            _loop_deadline(start, deadline, clock)
            window = il[start : start + 4]
            if not all(
                (
                    window[0].opcode == "ldsfld" and window[0].token is not None,
                    window[1].opcode == "ldstr" and window[1].user_string is not None,
                    window[2].opcode == "call"
                    and window[2].resolved
                    == "System.Text.RegularExpressions.Regex::Split",
                    window[3].opcode.startswith("stloc")
                    and window[3].local is not None,
                )
            ):
                continue
            matches.append(
                (int(window[0].token), int(window[3].local), str(window[1].user_string))
            )
            _v2_candidate_limit(
                "split",
                len(matches),
                MAX_V2_SPLIT_CANDIDATES,
            )
    elif handoff_profile == "gettypes1-type-invokemember":
        for start in range(len(il) - 9):
            _loop_deadline(start, deadline, clock)
            window = il[start : start + 10]
            if not all(
                (
                    window[0].opcode == "ldsfld" and window[0].token is not None,
                    window[1].integer == 1,
                    window[2].opcode == "newarr"
                    and window[2].resolved == "System.String",
                    window[3].opcode == "dup",
                    window[4].integer == 0,
                    window[5].opcode == "ldstr" and window[5].user_string is not None,
                    window[6].opcode == "stelem.ref",
                    window[7].integer == 0,
                    window[8].opcode == "callvirt"
                    and window[8].resolved == "System.String::Split",
                    window[9].opcode.startswith("stloc")
                    and window[9].local is not None,
                )
            ):
                continue
            matches.append(
                (int(window[0].token), int(window[9].local), str(window[5].user_string))
            )
            _v2_candidate_limit(
                "split",
                len(matches),
                MAX_V2_SPLIT_CANDIDATES,
            )
    return matches


def _v2_argument_arrays(
    method: MethodModel,
    split_local: int,
    first_index: int,
    second_index: int,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> list[tuple[int, str]]:
    il = _meaningful(method)
    matches: list[tuple[int, str]] = []
    for start in range(len(il) - 18):
        _loop_deadline(start, deadline, clock)
        window = il[start : start + 19]
        if not all(
            (
                window[0].integer == 3,
                window[1].opcode == "newarr" and window[1].resolved == "System.String",
                window[2].opcode == "dup",
                window[3].integer == 0,
                window[4].opcode.startswith("ldloc") and window[4].local == split_local,
                window[5].integer == first_index,
                window[6].opcode == "ldelem.ref",
                window[7].opcode == "stelem.ref",
                window[8].opcode == "dup",
                window[9].integer == 1,
                window[10].opcode.startswith("ldloc")
                and window[10].local == split_local,
                window[11].integer == second_index,
                window[12].opcode == "ldelem.ref",
                window[13].opcode == "stelem.ref",
                window[14].opcode == "dup",
                window[15].integer == 2,
                window[16].opcode == "ldstr" and window[16].user_string is not None,
                window[17].opcode == "stelem.ref",
                window[18].opcode.startswith("stloc") and window[18].local is not None,
            )
        ):
            continue
        namespace = str(window[16].user_string)
        if not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
            namespace,
        ):
            continue
        matches.append((int(window[18].local), namespace))
        _v2_candidate_limit(
            "argument_array",
            len(matches),
            MAX_V2_ARGUMENT_ARRAY_CANDIDATES,
        )
    return matches


def _v2_handoff_pairs(
    method: MethodModel,
    handoff_profile: str,
    *,
    local_store_counts: Counter[int] | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> Counter[tuple[int, int]]:
    """handoff callsiteを1回だけ走査し、束縛local pair別に数える。"""

    il = _meaningful(method)
    store_counts = local_store_counts or _local_store_counts(
        method,
        deadline=deadline,
        clock=clock,
    )
    pairs: Counter[tuple[int, int]] = Counter()
    observed = 0
    if handoff_profile == "gettypes1-activator":
        for start in range(len(il) - 4):
            _loop_deadline(start, deadline, clock)
            window = il[start : start + 5]
            alias_local = window[2].local
            selected_type_local = window[0].local
            args_local = window[1].local
            if None in {alias_local, selected_type_local, args_local}:
                continue
            if all(
                (
                    window[0].opcode.startswith("ldloc")
                    and window[0].local == selected_type_local,
                    window[1].opcode.startswith("ldloc")
                    and window[1].local == args_local,
                    window[2].opcode.startswith("stloc"),
                    window[3].opcode.startswith("ldloc")
                    and window[3].local == alias_local,
                    window[4].opcode == "call"
                    and window[4].resolved == "System.Activator::CreateInstance",
                    store_counts[int(alias_local)] == 1,
                )
            ):
                pairs[(int(selected_type_local), int(args_local))] += 1
                observed += 1
                _v2_candidate_limit(
                    "handoff",
                    observed,
                    MAX_V2_HANDOFF_CANDIDATES,
                )
    elif handoff_profile == "gettypes1-latecall":
        for start in range(len(il) - 21):
            _loop_deadline(start, deadline, clock)
            window = il[start : start + 22]
            method_local = window[4].local
            selected_type_local = window[0].local
            args_local = window[17].local
            if None in {method_local, selected_type_local, args_local}:
                continue
            if all(
                (
                    window[0].opcode.startswith("ldloc")
                    and window[0].local == selected_type_local,
                    window[1].opcode == "callvirt"
                    and window[1].resolved == "System.Type::GetMethods",
                    window[2].integer == 0,
                    window[3].opcode == "ldelem.ref",
                    window[4].opcode.startswith("stloc"),
                    window[5].opcode.startswith("ldloc")
                    and window[5].local == method_local,
                    window[6].opcode == "ldnull",
                    window[7].opcode == "ldstr" and window[7].user_string == "Invoke",
                    window[8].integer == 2,
                    window[9].opcode == "newarr"
                    and window[9].resolved == "System.Object",
                    window[10].opcode == "dup",
                    window[11].integer == 0,
                    window[12].integer == 0,
                    window[13].opcode == "box"
                    and window[13].resolved == "System.Int32",
                    window[14].opcode == "stelem.ref",
                    window[15].opcode == "dup",
                    window[16].integer == 1,
                    window[17].opcode.startswith("ldloc")
                    and window[17].local == args_local,
                    window[18].opcode == "stelem.ref",
                    window[19].opcode == "ldnull",
                    window[20].opcode == "ldnull",
                    window[21].opcode == "call"
                    and window[21].resolved
                    == "Microsoft.VisualBasic.CompilerServices.LateBinding::LateCall",
                    store_counts[int(method_local)] == 1,
                )
            ):
                pairs[(int(selected_type_local), int(args_local))] += 1
                observed += 1
                _v2_candidate_limit(
                    "handoff",
                    observed,
                    MAX_V2_HANDOFF_CANDIDATES,
                )
    elif handoff_profile == "gettypes1-type-invokemember":
        for start in range(len(il) - 38):
            _loop_deadline(start, deadline, clock)
            window = il[start : start + 39]
            fragments: list[str] = []
            valid_fragments = True
            for index in range(5):
                offset = 4 + index * 4
                fragment = window[offset + 2].user_string
                if not all(
                    (
                        window[offset].opcode == "dup",
                        window[offset + 1].integer == index,
                        window[offset + 2].opcode == "ldstr",
                        fragment is not None,
                        window[offset + 3].opcode == "stelem.ref",
                    )
                ):
                    valid_fragments = False
                    break
                fragments.append(str(fragment))
            if not valid_fragments or "".join(fragments) != "CreateInstance":
                continue
            selected_type_local = window[32].local
            args_local = window[36].local
            if selected_type_local is None or args_local is None:
                continue
            if all(
                (
                    window[0].opcode == "ldtoken"
                    and window[0].resolved == "System.Activator",
                    window[1].opcode == "call"
                    and window[1].resolved == "System.Type::GetTypeFromHandle",
                    window[2].integer == 5,
                    window[3].opcode == "newarr"
                    and window[3].resolved == "System.String",
                    window[24].opcode == "call"
                    and window[24].resolved == "System.String::Concat",
                    window[25].integer == 256,
                    window[26].opcode == "ldnull",
                    window[27].opcode == "ldnull",
                    window[28].integer == 2,
                    window[29].opcode == "newarr"
                    and window[29].resolved == "System.Object",
                    window[30].opcode == "dup",
                    window[31].integer == 0,
                    window[32].opcode.startswith("ldloc")
                    and window[32].local == selected_type_local,
                    window[33].opcode == "stelem.ref",
                    window[34].opcode == "dup",
                    window[35].integer == 1,
                    window[36].opcode.startswith("ldloc")
                    and window[36].local == args_local,
                    window[37].opcode == "stelem.ref",
                    window[38].opcode == "call"
                    and window[38].resolved == "System.Type::InvokeMember",
                )
            ):
                pairs[(int(selected_type_local), int(args_local))] += 1
                observed += 1
                _v2_candidate_limit(
                    "handoff",
                    observed,
                    MAX_V2_HANDOFF_CANDIDATES,
                )
    return pairs


def _v2_handoff_count(
    method: MethodModel,
    handoff_profile: str,
    selected_type_local: int,
    args_local: int,
    *,
    local_store_counts: Counter[int] | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    return _v2_handoff_pairs(
        method,
        handoff_profile,
        local_store_counts=local_store_counts,
        deadline=deadline,
        clock=clock,
    )[(selected_type_local, args_local)]


def _v2_split_arguments(
    literal: str,
    delimiter: str,
    first_index: int,
    second_index: int,
) -> tuple[str, str] | None:
    if not re.fullmatch(
        r"[0-9A-Fa-f]{2}(?P<separator>[ ,])[0-9A-Fa-f]{2}"
        r"(?:(?P=separator)[0-9A-Fa-f]{2})*",
        delimiter,
    ):
        return None
    parts = literal.split(delimiter)
    if (first_index, second_index) == (0, 1):
        expected_length = 5
    elif (first_index, second_index) == (1, 3):
        expected_length = 8
    else:
        return None
    if len(parts) != expected_length or any(
        value
        for index, value in enumerate(parts)
        if index not in {first_index, second_index}
    ):
        return None
    first, second = parts[first_index], parts[second_index]
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}){1,128}", first) or not re.fullmatch(
        r"(?:[0-9A-Fa-f]{2}){1,128}", second
    ):
        return None
    return first, second


def _root_recipe_v2(
    methods: list[MethodModel],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> RootRecipe:
    """v2 roleを索引化し、有界なlocal joinだけでroot recipeを選ぶ。"""

    profiles = (
        ("gettypes1-latecall", 0, 1),
        ("gettypes1-type-invokemember", 1, 3),
        ("gettypes1-activator", 1, 3),
    )
    if deadline is not None:
        _deadline(deadline, clock)
    method_index = _build_v2_method_index(
        methods,
        deadline=deadline,
        clock=clock,
    )
    assignments = _static_string_assignments(
        methods,
        deadline=deadline,
        clock=clock,
    )
    root_methods: list[MethodModel] = []
    for method_number, method in enumerate(methods):
        _loop_deadline(method_number, deadline, clock)
        if not _bounded_call_suffix(
            method,
            "System.Reflection.Assembly::GetTypes",
            deadline=deadline,
            clock=clock,
        ):
            continue
        root_methods.append(method)
        _v2_candidate_limit(
            "root_method",
            len(root_methods),
            MAX_V2_ROOT_METHOD_CANDIDATES,
        )

    candidates: list[RootRecipe] = []
    rgb_profiles: dict[int, str | None] = {}
    combination_count = 0
    role_candidate_counts: Counter[str] = Counter()
    for method_number, method in enumerate(root_methods):
        _loop_deadline(method_number, deadline, clock)
        local_store_counts = _local_store_counts(
            method,
            deadline=deadline,
            clock=clock,
        )
        getters_by_bitmap_local: dict[int, list[tuple[int, str, str]]] = {}
        selected_types_by_assembly_local: dict[int, list[int]] = {}
        for profile_number, (handoff_profile, first_index, second_index) in enumerate(
            profiles
        ):
            _loop_deadline(profile_number, deadline, clock)
            sinks = _v2_load_sinks(
                method,
                handoff_profile,
                deadline=deadline,
                clock=clock,
            )
            _accumulate_v2_candidates(
                role_candidate_counts,
                "load_sink",
                len(sinks),
                MAX_V2_LOAD_SINK_CANDIDATES,
            )
            splits = _v2_split_locals(
                method,
                handoff_profile,
                deadline=deadline,
                clock=clock,
            )
            _accumulate_v2_candidates(
                role_candidate_counts,
                "split",
                len(splits),
                MAX_V2_SPLIT_CANDIDATES,
            )
            handoff_pairs = _v2_handoff_pairs(
                method,
                handoff_profile,
                local_store_counts=local_store_counts,
                deadline=deadline,
                clock=clock,
            )
            _accumulate_v2_candidates(
                role_candidate_counts,
                "handoff",
                sum(handoff_pairs.values()),
                MAX_V2_HANDOFF_CANDIDATES,
            )
            argument_arrays_by_split: dict[int, list[tuple[int, str]]] = {}
            decoded_splits: list[tuple[int, str, str, str, list[tuple[int, str]]]] = []
            for split_number, (field_token, split_local, delimiter) in enumerate(
                splits
            ):
                _loop_deadline(split_number, deadline, clock)
                values = assignments.get(field_token, [])
                if len(values) != 1:
                    continue
                arguments = _v2_split_arguments(
                    values[0],
                    delimiter,
                    first_index,
                    second_index,
                )
                if arguments is None:
                    continue
                if split_local not in argument_arrays_by_split:
                    argument_arrays_by_split[split_local] = _v2_argument_arrays(
                        method,
                        split_local,
                        first_index,
                        second_index,
                        deadline=deadline,
                        clock=clock,
                    )
                    _accumulate_v2_candidates(
                        role_candidate_counts,
                        "argument_array",
                        len(argument_arrays_by_split[split_local]),
                        MAX_V2_ARGUMENT_ARRAY_CANDIDATES,
                    )
                first, second = arguments
                decoded_splits.append(
                    (
                        split_local,
                        first,
                        second,
                        delimiter,
                        argument_arrays_by_split[split_local],
                    )
                )

            for sink_number, (
                bitmap_local,
                length,
                rgb_token,
                assembly_local,
            ) in enumerate(sinks):
                _loop_deadline(sink_number, deadline, clock)
                if not 0 < length <= MAX_OUTPUT_BYTES:
                    continue
                if rgb_token not in rgb_profiles:
                    try:
                        rgb_profiles[rgb_token] = _v2_rgb_profile(
                            methods,
                            rgb_token,
                            method_index=method_index,
                            deadline=deadline,
                            clock=clock,
                        )
                    except IncompleteRecoveryError:
                        raise
                    except RecoveryError:
                        rgb_profiles[rgb_token] = None
                rgb_profile_id = rgb_profiles[rgb_token]
                if rgb_profile_id is None:
                    continue
                if bitmap_local not in getters_by_bitmap_local:
                    getters_by_bitmap_local[bitmap_local] = _v2_bitmap_getters(
                        method,
                        methods,
                        bitmap_local,
                        method_index=method_index,
                        local_store_counts=local_store_counts,
                        deadline=deadline,
                        clock=clock,
                    )
                    _accumulate_v2_candidates(
                        role_candidate_counts,
                        "bitmap_getter",
                        len(getters_by_bitmap_local[bitmap_local]),
                        MAX_V2_BITMAP_GETTER_CANDIDATES,
                    )
                if assembly_local not in selected_types_by_assembly_local:
                    selected_types_by_assembly_local[assembly_local] = (
                        _v2_gettypes_locals(
                            method,
                            assembly_local,
                            deadline=deadline,
                            clock=clock,
                        )
                    )
                    _accumulate_v2_candidates(
                        role_candidate_counts,
                        "selected_type",
                        len(selected_types_by_assembly_local[assembly_local]),
                        MAX_V2_GETTYPES_CANDIDATES,
                    )
                getters = getters_by_bitmap_local[bitmap_local]
                selected_types = selected_types_by_assembly_local[assembly_local]
                join_width = (
                    len(getters)
                    * len(selected_types)
                    * sum(
                        len(argument_arrays)
                        for _split_local, _first, _second, _delimiter, argument_arrays in decoded_splits
                    )
                )
                combination_count += join_width
                if combination_count > MAX_V2_RECIPE_COMBINATIONS:
                    raise IncompleteRecoveryError(
                        "outer_gettypes1_combination_limit",
                        incomplete_type="combination_limit",
                        stage="outer_gettypes1_root_recipe",
                        role="recipe_join",
                        observed=combination_count,
                        limit=MAX_V2_RECIPE_COMBINATIONS,
                    )
                for getter_token, bitmap_name, first_resource_set_name in getters:
                    for selected_type_local in selected_types:
                        for (
                            split_local,
                            first,
                            second,
                            _delimiter,
                            argument_arrays,
                        ) in decoded_splits:
                            for args_local, namespace in argument_arrays:
                                if deadline is not None:
                                    _deadline(deadline, clock)
                                bound_locals = (
                                    bitmap_local,
                                    assembly_local,
                                    selected_type_local,
                                    split_local,
                                    args_local,
                                )
                                if any(
                                    local_store_counts[local] != 1
                                    for local in bound_locals
                                ) or (
                                    handoff_pairs[(selected_type_local, args_local)]
                                    != 1
                                ):
                                    continue
                                candidates.append(
                                    RootRecipe(
                                        caller_token=method.token,
                                        rgb_method_token=rgb_token,
                                        bitmap_getter_token=getter_token,
                                        first_child_length=length,
                                        first_bitmap_name=bitmap_name,
                                        resource_argument_hex=first,
                                        key_argument_hex=second,
                                        resource_namespace=namespace,
                                        handoff_profile=handoff_profile,
                                        rgb_profile_id=rgb_profile_id,
                                        first_resource_set_name=(
                                            first_resource_set_name
                                        ),
                                    )
                                )
    if len(candidates) != 1:
        raise RecoveryError("outer_gettypes1_recipe_ambiguous")
    return candidates[0]


def _root_recipe_v1(
    methods: list[MethodModel],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> RootRecipe:
    if deadline is not None:
        _deadline(deadline, clock)
    rgb_method, _bitmap_field = _find_first_rgb_recipe(
        methods,
        deadline=deadline,
        clock=clock,
    )

    def reaches_assembly_load(il: list[Instruction], index: int) -> bool:
        window = il[index : index + 21]
        if len(window) != 21:
            return False
        result_local = window[1].local
        assembly_local = window[16].local
        if result_local is None or assembly_local is None:
            return False
        return all(
            (
                window[0].opcode in {"call", "callvirt"}
                and window[0].token == rgb_method.token,
                window[1].opcode.startswith("stloc"),
                window[2].opcode == "call"
                and window[2].resolved == "System.Threading.Thread::GetDomain",
                window[3].opcode == "ldnull",
                window[4].opcode == "ldstr" and window[4].user_string == "Load",
                window[5].integer == 1,
                window[6].opcode == "newarr" and window[6].resolved == "System.Object",
                window[7].opcode == "dup",
                window[8].integer == 0,
                window[9].opcode.startswith("ldloc")
                and window[9].local == result_local,
                window[10].opcode == "call"
                and window[10].resolved == "System.Linq.Enumerable::ToArray",
                window[11].opcode == "stelem.ref",
                window[12].opcode == "ldnull",
                window[13].opcode == "ldnull",
                window[14].opcode == "call"
                and window[14].resolved
                == "Microsoft.VisualBasic.CompilerServices.LateBinding::LateGet",
                window[15].opcode == "castclass"
                and window[15].resolved == "System.Reflection.Assembly",
                window[16].opcode.startswith("stloc"),
                window[17].opcode.startswith("ldloc")
                and window[17].local == assembly_local,
                window[18].opcode == "callvirt"
                and window[18].resolved
                == "System.Reflection.Assembly::GetExportedTypes",
                window[19].integer == 0,
                window[20].opcode == "ldelem.ref",
            )
        )

    assignments: dict[int, list[str]] = {}
    for method_index, method in enumerate(methods):
        _loop_deadline(method_index, deadline, clock)
        if method.name != ".ctor":
            continue
        il = _meaningful(method)
        for index in range(len(il) - 2):
            _loop_deadline(index, deadline, clock)
            first, literal, store = il[index : index + 3]
            if (
                first.opcode == "ldarg.0"
                and literal.opcode == "ldstr"
                and literal.user_string is not None
                and store.opcode == "stfld"
                and store.token is not None
            ):
                assignments.setdefault(store.token, []).append(literal.user_string)

    candidates: list[RootRecipe] = []
    for method_index, method in enumerate(methods):
        _loop_deadline(method_index, deadline, clock)
        calls_rgb = False
        has_load_literal = False
        for instruction_index, item in enumerate(method.instructions):
            _loop_deadline(instruction_index, deadline, clock)
            calls_rgb = calls_rgb or (
                item.opcode in {"call", "callvirt"} and item.token == rgb_method.token
            )
            has_load_literal = has_load_literal or item.user_string == "Load"
        if not calls_rgb:
            continue
        if not (
            _bounded_call_suffix(
                method,
                "System.Reflection.Assembly::GetExportedTypes",
                deadline=deadline,
                clock=clock,
            )
            and _bounded_call_suffix(
                method,
                "System.Reflection.ConstructorInfo::Invoke",
                deadline=deadline,
                clock=clock,
            )
            and has_load_literal
        ):
            continue
        arguments = _match_split_arguments(
            method,
            assignments,
            deadline=deadline,
            clock=clock,
        )
        if arguments is None:
            continue
        il = _meaningful(method)
        callsites: list[tuple[int, int]] = []
        for index, item in enumerate(il):
            _loop_deadline(index, deadline, clock)
            if (
                item.opcode not in {"call", "callvirt"}
                or item.token != rgb_method.token
                or index < 2
            ):
                continue
            getter, length = il[index - 2], il[index - 1]
            if (
                getter.opcode == "call"
                and getter.token is not None
                and length.integer is not None
                and reaches_assembly_load(il, index)
            ):
                callsites.append((getter.token, length.integer))
        if len(callsites) != 1:
            continue
        getter_token, output_length = callsites[0]
        if not 0 < output_length <= MAX_OUTPUT_BYTES:
            continue
        bitmap_name = _bitmap_getter(
            methods,
            getter_token,
            deadline=deadline,
            clock=clock,
        )
        first, second, namespace = arguments
        candidates.append(
            RootRecipe(
                caller_token=method.token,
                rgb_method_token=rgb_method.token,
                bitmap_getter_token=getter_token,
                first_child_length=output_length,
                first_bitmap_name=bitmap_name,
                resource_argument_hex=first,
                key_argument_hex=second,
                resource_namespace=namespace,
            )
        )
    if len(candidates) != 1:
        raise RecoveryError("outer_constructor_recipe_ambiguous")
    return candidates[0]


def _root_recipe(
    methods: list[MethodModel],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> RootRecipe:
    """v1/v2を独立評価し、完全recipeが一意な場合だけ選ぶ。"""

    has_v1 = False
    has_v2 = False
    for index, method in enumerate(methods):
        _loop_deadline(index, deadline, clock)
        has_v1 = has_v1 or _bounded_call_suffix(
            method,
            "System.Reflection.Assembly::GetExportedTypes",
            deadline=deadline,
            clock=clock,
        )
        has_v2 = has_v2 or _bounded_call_suffix(
            method,
            "System.Reflection.Assembly::GetTypes",
            deadline=deadline,
            clock=clock,
        )
    if not has_v1 and not has_v2:
        raise RecoveryError("outer_type_selection_profile_ambiguous")

    candidates: list[RootRecipe] = []
    failures: list[RecoveryError] = []
    if has_v1:
        try:
            candidates.append(
                _root_recipe_v1(
                    methods,
                    deadline=deadline,
                    clock=clock,
                )
            )
        except IncompleteRecoveryError:
            raise
        except RecoveryError as exc:
            failures.append(exc)
    if has_v2:
        try:
            candidates.append(
                _root_recipe_v2(
                    methods,
                    deadline=deadline,
                    clock=clock,
                )
            )
        except IncompleteRecoveryError:
            raise
        except RecoveryError as exc:
            failures.append(exc)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise RecoveryError("outer_type_selection_recipe_ambiguous")
    if has_v1 != has_v2 and failures:
        raise failures[0]
    raise RecoveryError("outer_type_selection_profile_ambiguous")


def _sequence(
    method: MethodModel,
    predicates: tuple[Callable[[Instruction], bool], ...],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    if deadline is not None:
        _deadline(deadline, clock)
    il = _meaningful(method)
    for start in range(len(il) - len(predicates) + 1):
        _loop_deadline(start, deadline, clock)
        if all(
            predicate(il[start + offset]) for offset, predicate in enumerate(predicates)
        ):
            return True
    return False


def _loader_recipe_v1(
    methods: list[MethodModel],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> LoaderRecipe:
    if deadline is not None:
        _deadline(deadline, clock)
    by_digest: dict[str, list[MethodModel]] = {}
    for method_index, method in enumerate(methods):
        _loop_deadline(method_index, deadline, clock)
        by_digest.setdefault(method.body_sha256, []).append(method)
    selected: dict[str, MethodModel] = {}
    for role_index, (role, digest) in enumerate(LOADER_METHOD_BODY_SHA256.items()):
        _loop_deadline(role_index, deadline, clock)
        matches = by_digest.get(digest, [])
        if len(matches) != 1:
            raise RecoveryError("loader_method_profile_incomplete_or_ambiguous")
        selected[role] = matches[0]

    entry = selected["entry"]
    if (
        entry.owner_token == 0
        or entry.owner_export_index != 0
        or not entry.is_public
        or not entry.is_static
        or entry.signature != b"\x00\x03\x01\x0e\x0e\x0e"
        or any(
            method.owner_token != entry.owner_token or not method.is_static
            for method in selected.values()
        )
    ):
        raise RecoveryError("loader_entry_owner_or_signature_mismatch")
    constructors: list[MethodModel] = []
    for method_index, method in enumerate(methods):
        _loop_deadline(method_index, deadline, clock)
        if (
            method.owner_token == entry.owner_token
            and method.owner_export_index == 0
            and method.name == ".ctor"
            and method.is_public
            and not method.is_static
            and method.is_special_name
            and method.is_runtime_special_name
            and method.signature == b"\x20\x03\x01\x0e\x0e\x0e"
            and _sequence(
                method,
                (
                    lambda item: item.opcode == "ldarg.1",
                    lambda item: item.opcode == "ldarg.2",
                    lambda item: item.opcode == "ldarg.3",
                    lambda item: (
                        item.opcode in {"call", "callvirt"}
                        and item.token == entry.token
                    ),
                ),
                deadline=deadline,
                clock=clock,
            )
        ):
            constructors.append(method)
    if len(constructors) != 1:
        raise RecoveryError("loader_constructor_entry_link_ambiguous")

    required_calls = {
        "resource_lookup": (
            "System.Reflection.Assembly::GetEntryAssembly",
            "System.Resources.ResourceManager::.ctor",
            "System.Resources.ResourceManager::GetObject",
        ),
        "crop_bitmap": (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
            "System.Drawing.Bitmap::GetPixel",
            "System.Drawing.Bitmap::SetPixel",
        ),
        "argb_bytes": (
            "System.Drawing.Bitmap::GetPixel",
            "System.Drawing.Color::ToArgb",
            "System.BitConverter::GetBytes",
            "System.BitConverter::ToInt32",
            "System.Array::Copy",
        ),
        "key_bytes": (
            "System.Text.Encoding::get_BigEndianUnicode",
            "System.Text.Encoding::GetBytes",
        ),
        "hex_text": (
            "System.String::Substring",
            "System.Convert::ToInt32",
            "System.Text.StringBuilder::Append",
        ),
        "assembly_load": ("System.Reflection.Assembly::Load",),
    }
    for role_index, (role, suffixes) in enumerate(required_calls.items()):
        _loop_deadline(role_index, deadline, clock)
        if not all(
            _bounded_call_suffix(
                selected[role],
                suffix,
                deadline=deadline,
                clock=clock,
            )
            for suffix in suffixes
        ):
            raise RecoveryError("loader_framework_reference_mismatch")
    resource_strings: list[str] = []
    for instruction_index, item in enumerate(selected["resource_lookup"].instructions):
        _loop_deadline(instruction_index, deadline, clock)
        if item.user_string is not None:
            resource_strings.append(item.user_string)
    if resource_strings != [".Properties.Resources"]:
        raise RecoveryError("loader_resource_suffix_mismatch")

    def calls_role(source: str, target: str) -> bool:
        token = selected[target].token
        for instruction_index, item in enumerate(selected[source].instructions):
            _loop_deadline(instruction_index, deadline, clock)
            if item.opcode in {"call", "callvirt"} and item.token == token:
                return True
        return False

    edges = (
        ("entry", "decode_resource_argument"),
        ("entry", "decode_key_argument"),
        ("entry", "resource_wrapper"),
        ("entry", "crop_and_argb"),
        ("entry", "xor_wrapper"),
        ("entry", "load_wrapper"),
        ("entry", "invoke_wrapper"),
        ("decode_resource_argument", "hex_text"),
        ("decode_key_argument", "hex_text"),
        ("resource_wrapper", "resource_lookup"),
        ("crop_and_argb", "crop_bitmap"),
        ("crop_and_argb", "argb_bytes"),
        ("xor_wrapper", "key_bytes"),
        ("xor_wrapper", "mask"),
        ("xor_wrapper", "xor_loop"),
        ("xor_wrapper", "drop_sentinel"),
        ("xor_loop", "key_index"),
        ("load_wrapper", "assembly_load"),
        ("invoke_wrapper", "invoke_target"),
    )
    for edge_index, (source, target) in enumerate(edges):
        _loop_deadline(edge_index, deadline, clock)
        if not calls_role(source, target):
            raise RecoveryError("loader_call_graph_mismatch")
    if not _bounded_call_suffix(
        selected["xor_wrapper"],
        "System.String::get_Length",
        deadline=deadline,
        clock=clock,
    ):
        raise RecoveryError("loader_key_period_dataflow_mismatch")
    xor_count = 0
    for instruction_index, item in enumerate(selected["xor_loop"].instructions):
        _loop_deadline(instruction_index, deadline, clock)
        xor_count += item.opcode == "xor"
    if xor_count < 2:
        raise RecoveryError("loader_xor_shape_mismatch")

    crop_method = selected["crop_and_argb"]
    crop_matches: list[tuple[int, int]] = []
    il = _meaningful(crop_method)
    for index in range(len(il) - 4):
        _loop_deadline(index, deadline, clock)
        window = il[index : index + 5]
        if (
            window[0].opcode == "ldarg.0"
            and window[1].integer is not None
            and window[2].integer is not None
            and window[3].opcode in {"call", "callvirt"}
            and window[3].token == selected["crop_bitmap"].token
            and window[4].opcode in {"call", "callvirt"}
            and window[4].token == selected["argb_bytes"].token
        ):
            crop_matches.append((window[1].integer, window[2].integer))
    if len(crop_matches) != 1:
        raise RecoveryError("loader_crop_constants_ambiguous")
    crop_right, crop_bottom = crop_matches[0]
    if (
        not 0 <= crop_right < MAX_IMAGE_DIMENSION
        or not 0 <= crop_bottom < MAX_IMAGE_DIMENSION
    ):
        raise RecoveryError("loader_crop_constants_bounds")

    mask_method = selected["mask"]
    mask_values: set[int] = set()
    for instruction_index, item in enumerate(mask_method.instructions):
        _loop_deadline(instruction_index, deadline, clock)
        if item.integer is not None and 0 <= item.integer <= 255:
            mask_values.add(item.integer)
    if 112 not in mask_values or not _sequence(
        mask_method,
        (
            lambda item: item.opcode.startswith("ldloc"),
            lambda item: item.integer == 112,
            lambda item: item.opcode == "xor",
        ),
        deadline=deadline,
        clock=clock,
    ):
        raise RecoveryError("loader_mask_constant_mismatch")
    return LoaderRecipe(
        crop_right=crop_right,
        crop_bottom=crop_bottom,
        mask_xor=112,
        method_tokens={role: method.token for role, method in selected.items()},
        constructor_token=constructors[0].token,
        evidence_method_body_sha256=tuple(sorted(LOADER_METHOD_BODY_SHA256.items())),
        call_graph_verified=True,
    )


def _cil_inventory_sha256(
    methods: list[MethodModel],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> str:
    """token順のCIL body/owner/signature/flags inventoryを曖昧性なくhash化する。"""

    digest = hashlib.sha256()
    seen: set[int] = set()
    for index, method in enumerate(sorted(methods, key=lambda item: item.token)):
        _loop_deadline(index, deadline, clock)
        if method.token in seen:
            raise RecoveryError("loader_method_token_ambiguous")
        seen.add(method.token)
        flags = (
            int(method.is_static)
            | (int(method.is_public) << 1)
            | (int(method.is_special_name) << 2)
            | (int(method.is_runtime_special_name) << 3)
        )
        export_index = (
            0xFFFFFFFF
            if method.owner_export_index is None
            else method.owner_export_index
        )
        if not 0 < len(method.signature) <= MAX_SIGNATURE_BYTES:
            raise RecoveryError("loader_method_signature_bounds")
        digest.update(
            struct.pack(
                ">IIIIBH",
                method.token,
                method.body_size,
                method.owner_token,
                export_index,
                flags,
                len(method.signature),
            )
        )
        digest.update(method.signature)
        try:
            digest.update(bytes.fromhex(method.body_sha256))
        except ValueError as exc:
            raise RecoveryError("loader_method_body_digest_invalid") from exc
    return digest.hexdigest()


def _v2_constructor_dispatch_verified(
    constructor: MethodModel,
    entry: MethodModel,
    dispatch: MethodModel,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    il = _meaningful(constructor)
    matches = 0
    for start in range(len(il) - 3):
        _loop_deadline(start, deadline, clock)
        if [item.opcode for item in il[start : start + 3]] != [
            "ldarg.1",
            "ldarg.2",
            "ldarg.3",
        ]:
            continue
        direct = il[start + 3]
        if (
            direct.opcode in {"call", "callvirt"}
            and direct.token == entry.token
            and dispatch.token == entry.token
        ):
            matches += 1
            continue
        if start + 4 >= len(il):
            continue
        field, call = il[start + 3 : start + 5]
        if (
            field.opcode == "ldsfld"
            and field.token is not None
            and call.opcode in {"call", "callvirt"}
            and call.token == dispatch.token
        ):
            matches += 1
    return matches == 1


def _loader_v2_profile_recipe(
    methods: list[MethodModel],
    method_index: _V2MethodIndex,
    *,
    known_child_sha256: str,
    profile: dict[str, object],
    assembly_sha256: str | None,
    deadline: float | None,
    clock: Callable[[], float],
) -> LoaderRecipe:
    """1件のreview済みsemantic profileを完全照合する。"""

    exact_child = assembly_sha256 == known_child_sha256
    if exact_child and _cil_inventory_sha256(
        methods,
        deadline=deadline,
        clock=clock,
    ) != profile.get("cil_inventory_sha256"):
        raise RecoveryError("loader_v2_cil_inventory_mismatch")

    role_signatures = profile.get("role_signatures")
    required_edges = profile.get("required_role_edges")
    if not isinstance(role_signatures, dict) or not isinstance(required_edges, tuple):
        raise RecoveryError("loader_v2_profile_invalid")

    selected: dict[str, MethodModel] = {}
    roles = (
        "constructor",
        "entry",
        "dispatch",
        "crop",
        "mask",
        "load_wrapper",
        "load_inner",
        "resource_getter",
    )
    for role_index, role in enumerate(roles):
        _loop_deadline(role_index, deadline, clock)
        digest_key = (
            "resource_getter_body_sha256"
            if role == "resource_getter"
            else f"{role}_body_sha256"
        )
        expected_digest = profile.get(digest_key)
        expected_signature = role_signatures.get(role)
        if not isinstance(expected_digest, str) or not isinstance(
            expected_signature, str
        ):
            raise RecoveryError("loader_v2_profile_invalid")
        matches = method_index.by_body_sha256.get(expected_digest, ())
        if len(matches) > MAX_V2_LOADER_ROLE_CANDIDATES:
            raise IncompleteRecoveryError(
                "loader_v2_role_candidate_limit",
                incomplete_type="candidate_limit",
                stage="loader_v2_semantic_profile",
                role=role,
                observed=len(matches),
                limit=MAX_V2_LOADER_ROLE_CANDIDATES,
            )
        if len(matches) != 1:
            raise RecoveryError("loader_v2_role_body_ambiguous")
        method = matches[0]
        try:
            signature = bytes.fromhex(expected_signature)
        except ValueError as exc:
            raise RecoveryError("loader_v2_profile_invalid") from exc
        if method.signature != signature:
            raise RecoveryError("loader_v2_role_signature_mismatch")
        selected[role] = method

    constructor = selected["constructor"]
    entry = selected["entry"]
    dispatch = selected["dispatch"]
    crop = selected["crop"]
    mask = selected["mask"]
    load_wrapper = selected["load_wrapper"]
    load_inner = selected["load_inner"]
    resource_getter = selected["resource_getter"]
    if (
        constructor.owner_token == 0
        or constructor.owner_token != entry.owner_token
        or constructor.owner_export_index != 1
        or entry.owner_export_index != 1
        or not constructor.is_public
        or constructor.is_static
        or not constructor.is_special_name
        or not constructor.is_runtime_special_name
        or constructor.name != ".ctor"
        or not entry.is_public
        or not entry.is_static
        or any(
            method.owner_token != entry.owner_token or not method.is_static
            for method in (
                crop,
                mask,
                load_wrapper,
                load_inner,
                resource_getter,
            )
        )
    ):
        raise RecoveryError("loader_v2_ctor_entry_owner_or_signature_mismatch")
    if not _v2_constructor_dispatch_verified(
        constructor,
        entry,
        dispatch,
        deadline=deadline,
        clock=clock,
    ):
        raise RecoveryError("loader_v2_constructor_argument_binding_mismatch")

    instruction_views: dict[str, tuple[Instruction, ...]] = {}
    for role_index, (role, method) in enumerate(selected.items()):
        view: list[Instruction] = []
        for instruction_index, item in enumerate(method.instructions):
            _loop_deadline(instruction_index, deadline, clock)
            if item.opcode != "nop":
                view.append(item)
        instruction_views[role] = tuple(view)
        _loop_deadline(role_index, deadline, clock)

    for role, required_targets in LOADER_V2_REQUIRED_RESOLUTION_TARGETS.items():
        resolved_targets = {
            item.resolved
            for item in instruction_views[role]
            if item.token is not None and item.token >> 24 in {1, 10}
        }
        if not required_targets.issubset(resolved_targets):
            raise RecoveryError("loader_v2_resolution_target_mismatch")

    for edge_index, edge in enumerate(required_edges):
        _loop_deadline(edge_index, deadline, clock)
        if (
            not isinstance(edge, tuple)
            or len(edge) != 2
            or edge[0] not in selected
            or edge[1] not in selected
        ):
            raise RecoveryError("loader_v2_profile_invalid")
        source, target = edge
        if not any(
            item.opcode in {"call", "callvirt", "newobj"}
            and item.token == selected[target].token
            for item in instruction_views[source]
        ):
            raise RecoveryError("loader_v2_required_call_edge_mismatch")

    entry_opcodes = {item.opcode for item in instruction_views["entry"]}
    if not {"ldarg.0", "ldarg.1", "ldarg.2"}.issubset(entry_opcodes):
        raise RecoveryError("loader_v2_entry_argument_use_mismatch")
    crop_integers = {item.integer for item in instruction_views["crop"]}
    if not {177, 225}.issubset(crop_integers):
        raise RecoveryError("loader_v2_crop_constants_mismatch")
    if (
        112 not in {item.integer for item in instruction_views["mask"]}
        or sum(item.opcode == "xor" for item in instruction_views["mask"]) < 2
    ):
        raise RecoveryError("loader_v2_mask_xor_shape_mismatch")

    load_il = instruction_views["load_inner"]
    argument_array_matches = 0
    for start in range(len(load_il) - 5):
        _loop_deadline(start, deadline, clock)
        window = load_il[start : start + 6]
        if (
            window[0].integer == 1
            and window[1].opcode == "newarr"
            and window[1].resolved == "System.Object"
            and window[2].opcode == "dup"
            and window[3].integer == 0
            and window[4].opcode == "ldarg.0"
            and window[5].opcode == "stelem.ref"
        ):
            argument_array_matches += 1
    if not (
        any(
            item.opcode == "newarr" and item.resolved == "System.Char"
            for item in load_il
        )
        and any(
            item.opcode == "ldtoken"
            and item.token is not None
            and item.token >> 24 == 4
            for item in load_il
        )
        and any(
            item.opcode in {"call", "callvirt", "newobj"}
            and item.resolved.endswith("System.String::.ctor")
            for item in load_il
        )
        and argument_array_matches == 1
        and any(
            item.opcode == "castclass" and item.resolved == "System.Reflection.Assembly"
            for item in load_il
        )
    ):
        raise RecoveryError("loader_v2_assembly_load_semantic_shape_mismatch")

    profile_id = profile.get("profile_id")
    if not isinstance(profile_id, str):
        raise RecoveryError("loader_v2_profile_invalid")
    evidence = tuple((role, selected[role].body_sha256) for role in sorted(selected))
    return LoaderRecipe(
        crop_right=177,
        crop_bottom=225,
        mask_xor=112,
        method_tokens={role: method.token for role, method in selected.items()},
        constructor_token=constructor.token,
        profile_id=profile_id,
        evidence_method_body_sha256=evidence,
        exact_child_profile_verified=exact_child,
        semantic_child_profile_verified=True,
        # dynamic proxy越しのentry→各roleは静的に完全検証していない。
        call_graph_verified=False,
    )


def _loader_recipe_v2(
    methods: list[MethodModel],
    assembly_sha256: str | None,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> LoaderRecipe:
    """known SHAを優先し、未知SHAは既知4形状のsemantic profileを照合する。"""

    method_index = _build_v2_method_index(
        methods,
        deadline=deadline,
        clock=clock,
    )
    if assembly_sha256 in LOADER_V2_PROFILES:
        profile_items = (
            (str(assembly_sha256), LOADER_V2_PROFILES[str(assembly_sha256)]),
        )
    else:
        profile_items = tuple(sorted(LOADER_V2_PROFILES.items()))

    candidates: list[LoaderRecipe] = []
    failures: list[RecoveryError] = []
    for profile_index, (known_child_sha256, profile) in enumerate(profile_items):
        _loop_deadline(profile_index, deadline, clock)
        try:
            candidates.append(
                _loader_v2_profile_recipe(
                    methods,
                    method_index,
                    known_child_sha256=known_child_sha256,
                    profile=profile,
                    assembly_sha256=assembly_sha256,
                    deadline=deadline,
                    clock=clock,
                )
            )
        except IncompleteRecoveryError:
            raise
        except RecoveryError as exc:
            failures.append(exc)
            continue
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise RecoveryError("loader_v2_semantic_profile_ambiguous")
    if assembly_sha256 in LOADER_V2_PROFILES and failures:
        raise failures[0]
    raise RecoveryError("loader_v2_semantic_profile_missing")


def _loader_recipe(
    methods: list[MethodModel],
    *,
    assembly_sha256: str | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> LoaderRecipe:
    """v1/v2を独立評価し、完全recipeが一意な場合だけ選ぶ。"""

    candidates: list[LoaderRecipe] = []
    v1_failure: RecoveryError | None = None
    v2_failure: RecoveryError | None = None
    try:
        candidates.append(
            _loader_recipe_v1(
                methods,
                deadline=deadline,
                clock=clock,
            )
        )
    except IncompleteRecoveryError:
        raise
    except RecoveryError as exc:
        v1_failure = exc
    try:
        candidates.append(
            _loader_recipe_v2(
                methods,
                assembly_sha256,
                deadline=deadline,
                clock=clock,
            )
        )
    except IncompleteRecoveryError:
        raise
    except RecoveryError as exc:
        v2_failure = exc
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        raise RecoveryError("loader_recipe_profile_ambiguous")
    if assembly_sha256 in LOADER_V2_PROFILES and v2_failure is not None:
        raise v2_failure
    if v1_failure is not None:
        raise v1_failure
    if v2_failure is not None:
        raise v2_failure
    raise RecoveryError("loader_recipe_profile_missing")


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset > len(self.data) - size:
            raise RecoveryError("nrbf_truncated")
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def i32(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def u7(self) -> int:
        value = 0
        for index, shift in enumerate(range(0, 35, 7)):
            byte = self.u8()
            if index == 4 and byte > 0x0F:
                raise RecoveryError("nrbf_7bit_integer_invalid")
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                if index and value < 1 << (index * 7):
                    raise RecoveryError("nrbf_7bit_integer_noncanonical")
                return value
        raise RecoveryError("nrbf_7bit_integer_invalid")

    def string(self, *, maximum: int = 1_024) -> str:
        size = self.u7()
        if not 0 <= size <= maximum:
            raise RecoveryError("nrbf_string_limit")
        try:
            return self.take(size).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RecoveryError("nrbf_string_invalid_utf8") from exc


def _parse_bitmap_nrbf(data: bytes) -> bytes:
    """限定System.Drawing.Bitmap NRBFからbyte[]だけを完全走査して返す。"""

    if type(data) is not bytes or not 0 < len(data) <= MAX_RESOURCE_BYTES:
        raise RecoveryError("nrbf_input_bounds")
    reader = _Reader(data)
    resource_type_code = reader.u7()
    if resource_type_code < 64:
        raise RecoveryError("nrbf_resource_type_code")
    if reader.u8() != 0:
        raise RecoveryError("nrbf_stream_header_record")
    root_id = reader.i32()
    header_id = reader.i32()
    major = reader.i32()
    minor = reader.i32()
    if root_id <= 0 or header_id != -1 or (major, minor) != (1, 0):
        raise RecoveryError("nrbf_stream_header_values")
    if reader.u8() != 12:
        raise RecoveryError("nrbf_library_record")
    library_id = reader.i32()
    if (
        library_id <= 0
        or library_id == root_id
        or reader.string() != SYSTEM_DRAWING_IDENTITY
    ):
        raise RecoveryError("nrbf_library_identity")
    if reader.u8() != 5:
        raise RecoveryError("nrbf_class_record")
    object_id = reader.i32()
    if object_id != root_id or reader.string() != "System.Drawing.Bitmap":
        raise RecoveryError("nrbf_bitmap_class_identity")
    if reader.i32() != 1 or reader.string(maximum=64) != "Data":
        raise RecoveryError("nrbf_bitmap_member_shape")
    if reader.u8() != 7 or reader.u8() != 2 or reader.i32() != library_id:
        raise RecoveryError("nrbf_bitmap_member_type")
    if reader.u8() != 9:
        raise RecoveryError("nrbf_member_reference")
    array_reference = reader.i32()
    if array_reference <= 0 or array_reference in {object_id, library_id}:
        raise RecoveryError("nrbf_array_reference")
    if reader.u8() != 15:
        raise RecoveryError("nrbf_array_record")
    if reader.i32() != array_reference:
        raise RecoveryError("nrbf_array_object_id")
    size = reader.i32()
    if not 0 < size <= MAX_BITMAP_BYTES or reader.u8() != 2:
        raise RecoveryError("nrbf_byte_array_bounds_or_type")
    payload = reader.take(size)
    if reader.u8() != 11 or reader.offset != len(data):
        raise RecoveryError("nrbf_message_end_or_trailing")
    return payload


def _resource_entries(
    pe: object, deadline: float, clock: Callable[[], float]
) -> list[ResourceEntry]:
    resources = list(getattr(pe.net, "resources", ()) or ())
    if len(resources) > MAX_RESOURCE_SETS:
        raise RecoveryError("resource_set_count_limit")
    result: list[ResourceEntry] = []
    total_entries = 0
    total_bytes = 0
    for resource in resources:
        _deadline(deadline, clock)
        resource_set = getattr(resource, "data", None)
        entries = list(getattr(resource_set, "entries", ()) or ())
        raw_value = getattr(resource_set, "_data", None)
        if not entries:
            continue
        if not isinstance(raw_value, (bytes, bytearray)):
            raise RecoveryError("resource_set_raw_data_unavailable")
        raw = bytes(raw_value)
        total_entries += len(entries)
        total_bytes += len(raw)
        if total_entries > MAX_RESOURCE_ENTRIES or total_bytes > MAX_RESOURCE_BYTES:
            raise RecoveryError("resource_inventory_budget")
        header = getattr(resource_set, "struct", None)
        base = int(getattr(header, "DataSectionOffset", 0) or 0)
        offsets: list[int] = []
        for entry_index, entry in enumerate(entries):
            if entry_index & 0xFF == 0:
                _deadline(deadline, clock)
            value = int(getattr(getattr(entry, "struct", None), "DataOffset", -1))
            start = base + value
            if value < 0 or not 0 <= start < len(raw):
                raise RecoveryError("resource_entry_offset_bounds")
            offsets.append(start)
        if len(set(offsets)) != len(offsets):
            raise RecoveryError("resource_entry_offset_ambiguous")
        sorted_offsets = sorted(offsets)
        _deadline(deadline, clock)
        end_by_start = {
            start: (
                sorted_offsets[index + 1]
                if index + 1 < len(sorted_offsets)
                else len(raw)
            )
            for index, start in enumerate(sorted_offsets)
        }
        for entry_index, (entry, start) in enumerate(
            zip(entries, offsets, strict=True)
        ):
            if entry_index & 0xFF == 0:
                _deadline(deadline, clock)
            end = end_by_start[start]
            if not start < end <= len(raw):
                raise RecoveryError("resource_entry_bounds")
            name = _text(getattr(entry, "name", None))
            type_name = _text(getattr(entry, "type_name", None))
            resource_name = _text(getattr(resource, "name", None))
            if not name or not type_name or not resource_name:
                raise RecoveryError("resource_entry_identity_missing")
            result.append(ResourceEntry(resource_name, name, type_name, raw[start:end]))
    return result


def _find_bitmap_entry(
    entries: list[ResourceEntry],
    *,
    resource_set_name: str | None,
    entry_name: str,
) -> ResourceEntry:
    matches = [
        entry
        for entry in entries
        if entry.entry_name == entry_name
        and entry.type_name == "System.Drawing.Bitmap"
        and (resource_set_name is None or entry.resource_set_name == resource_set_name)
    ]
    if len(matches) != 1:
        raise RecoveryError("bitmap_resource_entry_ambiguous")
    return matches[0]


def _bmp_rgb_take(
    data: bytes,
    take: int,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[bytes, dict[str, int | bool]]:
    if (
        type(data) is not bytes
        or not 54 <= len(data) <= MAX_BITMAP_BYTES
        or data[:2] != b"BM"
    ):
        raise RecoveryError("bmp_header_missing")
    declared_size = struct.unpack_from("<I", data, 2)[0]
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    dib_size = struct.unpack_from("<I", data, 14)[0]
    width, signed_height = struct.unpack_from("<ii", data, 18)
    planes, bits = struct.unpack_from("<HH", data, 26)
    compression = struct.unpack_from("<I", data, 30)[0]
    if (
        declared_size != len(data)
        or dib_size != 40
        or not 0 < width <= MAX_IMAGE_DIMENSION
        or signed_height == 0
        or abs(signed_height) > MAX_IMAGE_DIMENSION
        or planes != 1
        or bits not in {24, 32}
        or compression != 0
    ):
        raise RecoveryError("bmp_shape_unsupported")
    height = abs(signed_height)
    pixels = width * height
    if pixels > MAX_IMAGE_PIXELS:
        raise RecoveryError("bmp_pixel_limit")
    stride = ((width * bits + 31) // 32) * 4
    if pixel_offset < 54 or pixel_offset + stride * height != len(data):
        raise RecoveryError("bmp_pixel_extent")
    if not 0 < take <= pixels * 3 or take > MAX_OUTPUT_BYTES:
        raise RecoveryError("outer_rgb_take_bounds")
    bytes_per_pixel = bits // 8
    output = bytearray()
    for x in range(width):
        _deadline(deadline, clock)
        for y in range(height):
            file_y = height - 1 - y if signed_height > 0 else y
            offset = pixel_offset + file_y * stride + x * bytes_per_pixel
            blue, green, red = data[offset : offset + 3]
            output.extend((red, green, blue))
            if len(output) >= take:
                return bytes(output[:take]), {
                    "width": width,
                    "height": height,
                    "bits_per_pixel": bits,
                    "pixel_count": pixels,
                }
    raise RecoveryError("outer_rgb_take_incomplete")


def _paeth(left: int, above: int, upper_left: int) -> int:
    prediction = left + above - upper_left
    left_distance = abs(prediction - left)
    above_distance = abs(prediction - above)
    upper_left_distance = abs(prediction - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    return above if above_distance <= upper_left_distance else upper_left


def _decode_rgba_png(
    data: bytes,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[int, int, bytes, dict[str, object]]:
    if (
        type(data) is not bytes
        or not len(PNG_MAGIC) + 25 <= len(data) <= MAX_BITMAP_BYTES
    ):
        raise RecoveryError("png_input_bounds")
    if not data.startswith(PNG_MAGIC):
        raise RecoveryError("png_signature_missing")
    offset = len(PNG_MAGIC)
    chunk_count = 0
    saw_ihdr = False
    saw_idat = False
    idat_closed = False
    width = height = 0
    compressed = bytearray()
    while offset < len(data):
        _deadline(deadline, clock)
        if chunk_count >= MAX_PNG_CHUNKS or offset + 12 > len(data):
            raise RecoveryError("png_chunk_count_or_bounds")
        size = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4 : offset + 8]
        if size > MAX_PNG_CHUNK_BYTES or not all(
            65 <= value <= 90 or 97 <= value <= 122 for value in kind
        ):
            raise RecoveryError("png_chunk_shape")
        payload_start = offset + 8
        payload_end = payload_start + size
        crc_end = payload_end + 4
        if payload_end < payload_start or crc_end > len(data):
            raise RecoveryError("png_chunk_bounds")
        payload = data[payload_start:payload_end]
        expected_crc = struct.unpack_from(">I", data, payload_end)[0]
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != expected_crc:
            raise RecoveryError("png_crc_mismatch")
        chunk_count += 1
        if chunk_count == 1 and kind != b"IHDR":
            raise RecoveryError("png_ihdr_not_first")
        if kind == b"IHDR":
            if saw_ihdr or size != 13:
                raise RecoveryError("png_ihdr_invalid")
            width, height, depth, color, compression, filtering, interlace = (
                struct.unpack(">IIBBBBB", payload)
            )
            if (
                not 0 < width <= MAX_IMAGE_DIMENSION
                or not 0 < height <= MAX_IMAGE_DIMENSION
                or width * height > MAX_IMAGE_PIXELS
                or (depth, color, compression, filtering, interlace) != (8, 6, 0, 0, 0)
            ):
                raise RecoveryError("png_rgba_shape_unsupported")
            saw_ihdr = True
        elif kind == b"IDAT":
            if not saw_ihdr or idat_closed:
                raise RecoveryError("png_idat_order")
            saw_idat = True
            if len(compressed) > MAX_PNG_COMPRESSED_BYTES - len(payload):
                raise RecoveryError("png_compressed_byte_limit")
            compressed.extend(payload)
        elif kind == b"IEND":
            if size != 0 or not saw_idat or crc_end != len(data):
                raise RecoveryError("png_iend_or_trailing")
            offset = crc_end
            break
        else:
            if saw_idat:
                idat_closed = True
            if kind[0] & 0x20 == 0:
                raise RecoveryError("png_unknown_critical_chunk")
        offset = crc_end
    if offset != len(data) or not saw_ihdr or not saw_idat or width <= 0 or height <= 0:
        raise RecoveryError("png_incomplete")

    row_bytes = width * 4
    expected_size = height * (row_bytes + 1)
    if expected_size > MAX_IMAGE_BYTES:
        raise RecoveryError("png_decompressed_byte_limit")
    inflater = zlib.decompressobj()
    filtered = inflater.decompress(bytes(compressed), expected_size + 1)
    if (
        len(filtered) != expected_size
        or not inflater.eof
        or inflater.unused_data
        or inflater.unconsumed_tail
    ):
        raise RecoveryError("png_zlib_size_or_eof")
    output = bytearray(width * height * 4)
    previous = bytearray(row_bytes)
    filter_counts: Counter[int] = Counter()
    source = 0
    destination = 0
    for _row in range(height):
        _deadline(deadline, clock)
        filter_type = filtered[source]
        source += 1
        if filter_type > 4:
            raise RecoveryError("png_filter_unsupported")
        filter_counts[filter_type] += 1
        encoded = filtered[source : source + row_bytes]
        source += row_bytes
        row = bytearray(row_bytes)
        for index, value in enumerate(encoded):
            left = row[index - 4] if index >= 4 else 0
            above = previous[index]
            upper_left = previous[index - 4] if index >= 4 else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            else:
                predictor = _paeth(left, above, upper_left)
            row[index] = (value + predictor) & 0xFF
        output[destination : destination + row_bytes] = row
        destination += row_bytes
        previous = row
    return (
        width,
        height,
        bytes(output),
        {
            "chunk_count": chunk_count,
            "idat_size": len(compressed),
            "filtered_size": len(filtered),
            "filter_counts": {
                str(key): value for key, value in sorted(filter_counts.items())
            },
        },
    )


def _decode_hex_text(value: str) -> str:
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}){1,128}", value):
        raise RecoveryError("constructor_hex_argument_invalid")
    decoded = bytes.fromhex(value)
    return "".join(chr(byte) for byte in decoded)


def _argb_xor_transform(
    rgba: bytes,
    width: int,
    height: int,
    *,
    crop_right: int,
    crop_bottom: int,
    key_text: str,
    mask_xor: int,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[bytes, dict[str, int]]:
    if (
        type(rgba) is not bytes
        or len(rgba) != width * height * 4
        or not 0 <= crop_right < width
        or not 0 <= crop_bottom < height
        or not 0 < len(key_text) <= 128
        or not 0 <= mask_xor <= 255
    ):
        raise RecoveryError("argb_xor_model_bounds")
    cropped_width = width - crop_right
    cropped_height = height - crop_bottom
    if (
        cropped_width != cropped_height
        or cropped_width * cropped_height > MAX_IMAGE_PIXELS
    ):
        raise RecoveryError("argb_crop_not_square_or_too_large")
    stream_size = cropped_width * cropped_height * 4
    if stream_size > MAX_IMAGE_BYTES:
        raise RecoveryError("argb_stream_byte_limit")
    stream = bytearray(stream_size)
    position = 0
    for x in range(cropped_width):
        _deadline(deadline, clock)
        for y in range(cropped_height):
            source = (y * width + x) * 4
            red, green, blue, alpha = rgba[source : source + 4]
            stream[position : position + 4] = bytes((blue, green, red, alpha))
            position += 4
    if len(stream) < 5:
        raise RecoveryError("argb_stream_too_short")
    declared = struct.unpack_from("<i", stream)[0]
    if not 0 < declared <= MAX_OUTPUT_BYTES or declared > len(stream) - 4:
        raise RecoveryError("argb_declared_length_bounds")
    key_bytes = key_text.encode("utf-16-be", errors="strict")
    period = len(key_text)
    if period > len(key_bytes):
        raise RecoveryError("argb_key_period_bounds")
    encoded_start = 4
    encoded_end = encoded_start + declared
    mask = stream[encoded_end - 1] ^ mask_xor
    for index in range(declared):
        if index & 0xFFFF == 0:
            _deadline(deadline, clock)
        stream[encoded_start + index] ^= mask ^ key_bytes[index % period]
    decoded = bytes(stream[encoded_start:encoded_end])
    return decoded, {
        "cropped_width": cropped_width,
        "cropped_height": cropped_height,
        "argb_stream_size": len(stream),
        "declared_output_size": declared,
        "unused_argb_bytes": len(stream) - 4 - declared,
        "key_text_length": len(key_text),
        "key_byte_length": len(key_bytes),
        "key_period": period,
        "mask_constant_verified": True,
    }


def _parse_managed(
    data: bytes,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[object, list[MethodModel], dict[str, object]]:
    preflight = preflight_clr_declarations(data, max_input_bytes=MAX_INPUT_BYTES)
    if preflight.get("accepted") is not True:
        raise RecoveryError("metadata_preflight_rejected")
    _deadline(deadline, clock)
    with _contained_parser_diagnostics():
        pe = dnfile.dnPE(data=data, clr_lazy_load=False)
    if getattr(pe, "net", None) is None or getattr(pe.net, "mdtables", None) is None:
        raise RecoveryError("managed_metadata_unavailable")
    return pe, _normalize_methods(pe, data, deadline, clock), preflight


def recover_managed_bitmap_argb_xor(
    data: bytes,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """outerから二段目 ``Assembly.Load`` 入力を有界な静的解析だけで復元する。

    時間上限は主要なPython探索loopで検査する協調deadlineであり、dnfileや
    zlibの単一blocking呼出しをhard interruptするものではない。
    """

    report = _base_report(len(data) if type(data) is bytes else 0)
    if type(data) is not bytes or not 0 < len(data) <= MAX_INPUT_BYTES:
        report.update(status="rejected", reason="input_bounds")
        return report, []
    if not (
        b"System.Drawing.Bitmap" in data
        and b"GetPixel" in data
        and (b"GetExportedTypes" in data or b"GetTypes" in data)
    ):
        report.update(reason="outer_marker_prefilter_not_matched")
        return report, []
    deadline = clock() + MAX_ELAPSED_SECONDS
    try:
        root_pe, root_methods, root_preflight = _parse_managed(data, deadline, clock)
        root_recipe = _root_recipe(
            root_methods,
            deadline=deadline,
            clock=clock,
        )
        root_entries = _resource_entries(root_pe, deadline, clock)

        first_entry = _find_bitmap_entry(
            root_entries,
            resource_set_name=root_recipe.first_resource_set_name,
            entry_name=root_recipe.first_bitmap_name,
        )
        first_bitmap = _parse_bitmap_nrbf(first_entry.data)
        first_child, first_bitmap_shape = _bmp_rgb_take(
            first_bitmap,
            root_recipe.first_child_length,
            deadline,
            clock,
        )
        first_extent = inspect_structural_pe_extent(
            first_child,
            max_extent=MAX_OUTPUT_BYTES,
        )
        if first_extent.extent != len(first_child) or not has_clr_metadata(first_child):
            raise RecoveryError("first_child_managed_pe_boundary")

        _first_pe, first_methods, first_preflight = _parse_managed(
            first_child,
            deadline,
            clock,
        )
        loader_recipe = _loader_recipe(
            first_methods,
            assembly_sha256=_sha256(first_child),
            deadline=deadline,
            clock=clock,
        )
        resource_name = _decode_hex_text(root_recipe.resource_argument_hex)
        key_text = _decode_hex_text(root_recipe.key_argument_hex)
        resource_set_name = (
            root_recipe.resource_namespace + ".Properties.Resources.resources"
        )
        nested_entry = _find_bitmap_entry(
            root_entries,
            resource_set_name=resource_set_name,
            entry_name=resource_name,
        )
        png = _parse_bitmap_nrbf(nested_entry.data)
        width, height, rgba, png_shape = _decode_rgba_png(
            png,
            deadline,
            clock,
        )
        load_input, transform = _argb_xor_transform(
            rgba,
            width,
            height,
            crop_right=loader_recipe.crop_right,
            crop_bottom=loader_recipe.crop_bottom,
            key_text=key_text,
            mask_xor=loader_recipe.mask_xor,
            deadline=deadline,
            clock=clock,
        )
        extent_result = inspect_structural_pe_extent(
            load_input,
            max_extent=MAX_OUTPUT_BYTES,
        )
        extent = extent_result.extent
        if extent is None or not 0 < extent <= len(load_input):
            raise RecoveryError("decoded_pe_extent_invalid")
        overlay = load_input[extent:]
        child = load_input[:extent]
        if len(overlay) > MAX_OVERLAY_BYTES or not has_clr_metadata(child):
            raise RecoveryError("decoded_managed_pe_or_overlay_invalid")
        child_preflight = preflight_clr_declarations(
            child, max_input_bytes=MAX_OUTPUT_BYTES
        )
        if child_preflight.get("accepted") is not True:
            raise RecoveryError("decoded_metadata_preflight_rejected")
        _deadline(deadline, clock)

        report.update(
            status="recovered_managed_pe",
            profile_id=loader_recipe.profile_id,
            sample_sha256=_sha256(data),
            root_metadata_preflight=root_preflight,
            first_child_metadata_preflight=first_preflight,
            decoded_child_metadata_preflight=child_preflight,
            static_lineage={
                "outer_sha256": _sha256(data),
                "outer_size": len(data),
                "first_transform": "bitmap-rgb-x-major-take",
                "first_child_sha256": _sha256(first_child),
                "first_child_size": len(first_child),
                "second_transform": "bitmap-nrbf-png-crop-argb-xor",
                "assembly_load_input_sha256": _sha256(load_input),
                "assembly_load_input_size": len(load_input),
                "managed_pe_sha256": _sha256(child),
                "managed_pe_size": len(child),
                "overlay_size": len(overlay),
                "overlay_content_returned": False,
                "lineage_complete_to_assembly_load_input": True,
            },
            outer_recipe={
                "caller_token": f"0x{root_recipe.caller_token:08x}",
                "rgb_method_token": f"0x{root_recipe.rgb_method_token:08x}",
                "bitmap_getter_token": f"0x{root_recipe.bitmap_getter_token:08x}",
                "first_child_length": root_recipe.first_child_length,
                "constructor_argument_count": 3,
                "resource_argument_length": len(root_recipe.resource_argument_hex),
                "key_argument_length": len(root_recipe.key_argument_hex),
                "namespace_argument_length": len(root_recipe.resource_namespace),
                "handoff_profile": root_recipe.handoff_profile,
                "rgb_profile_id": root_recipe.rgb_profile_id,
                "raw_constructor_arguments_returned": False,
                "constructor_argument_hashes_returned": False,
            },
            loader_recipe={
                "profile_id": loader_recipe.profile_id,
                "method_body_sha256": dict(loader_recipe.evidence_method_body_sha256),
                "method_tokens": {
                    role: f"0x{token:08x}"
                    for role, token in sorted(loader_recipe.method_tokens.items())
                },
                "constructor_token": f"0x{loader_recipe.constructor_token:08x}",
                "crop_right": loader_recipe.crop_right,
                "crop_bottom": loader_recipe.crop_bottom,
                "mask_constant_verified": True,
                "mask_constant_returned": False,
                "scan_order": "x-major-y-minor",
                "pixel_byte_order": "BGRA-from-Color.ToArgb-little-endian",
                "key_encoding": "UTF-16BE",
                "key_period_source": "decoded-key-string-length",
                "framework_references_verified": True,
                "call_graph_verified": loader_recipe.call_graph_verified,
                "call_graph_verification_scope": (
                    "reviewed_role_edges"
                    if loader_recipe.call_graph_verified
                    else (
                        "registered_direct_edges_partial"
                        if loader_recipe.semantic_child_profile_verified
                        else "constructor_argument_binding_only"
                    )
                ),
                "gettypes_selected_constructor_verified": (
                    root_recipe.handoff_profile.startswith("gettypes1-")
                ),
                "first_exported_type_constructor_verified": (
                    root_recipe.handoff_profile == "getexportedtypes0-constructor-v1"
                ),
                "exact_child_profile_verified": (
                    loader_recipe.exact_child_profile_verified
                ),
                "semantic_child_profile_verified": (
                    loader_recipe.semantic_child_profile_verified
                ),
            },
            resources={
                "first_resource_entry_sha256": _sha256(first_entry.data),
                "first_bitmap_sha256": _sha256(first_bitmap),
                "first_bitmap_size": len(first_bitmap),
                "first_bitmap_shape": first_bitmap_shape,
                "nested_resource_entry_sha256": _sha256(nested_entry.data),
                "png_sha256": _sha256(png),
                "png_size": len(png),
                "png_width": width,
                "png_height": height,
                "png_shape": png_shape,
                "nrbf_fully_consumed": True,
                "binaryformatter_runtime_used": False,
                "raw_names_returned": False,
                "name_hashes_returned": False,
            },
            transform=transform,
            assembly_load_input={
                "sha256": _sha256(load_input),
                "size": len(load_input),
                "content_in_report": False,
                "static_sink_verified": True,
                "retained_as_private_artifact": True,
            },
            structural_pe={
                "sha256": _sha256(child),
                "size": len(child),
                "format": "managed-pe",
                "pe_extent_reason": extent_result.reason,
                "content_returned_in_report": False,
                "retained_separately": False,
            },
            candidate_only=True,
            assembly_load_input_statically_reconstructed=True,
            private_recursive_artifact_returned=True,
            family_attribution_allowed=False,
            c2_confirmation_allowed=False,
            terminal_promotion_eligible=False,
        )
        return report, [("managed-bitmap-argb-xor-load-input", load_input)]
    except IncompleteRecoveryError as exc:
        report.update(
            status="analysis_incomplete",
            reason=str(exc),
            incomplete=exc.report_details(),
        )
        return report, []
    except RecoveryError as exc:
        report.update(status="rejected", reason=str(exc))
        return report, []
    except (
        AttributeError,
        IndexError,
        KeyError,
        OverflowError,
        PEFormatError,
        struct.error,
        TypeError,
        ValueError,
        zlib.error,
    ):
        report.update(status="rejected", reason="invalid_static_recipe_structure")
        return report, []


__all__ = [
    "LOADER_METHOD_BODY_SHA256",
    "LOADER_PROFILE_ID",
    "MAX_ELAPSED_SECONDS",
    "MAX_V2_LOADER_ROLE_CANDIDATES",
    "MAX_V2_LOAD_SINK_CANDIDATES",
    "MAX_V2_RECIPE_COMBINATIONS",
    "IncompleteRecoveryError",
    "RecoveryError",
    "recover_managed_bitmap_argb_xor",
]
