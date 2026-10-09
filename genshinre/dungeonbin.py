"""7.1 Dungeon row wire, recovered from LGLHLMDKIEO.GMENPOPMKAA.

Values are keyed by native object displacement. Field names/semantic aliases
are deliberately separate from this byte decoder. Absent fields are omitted.
"""
from __future__ import annotations
from dataclasses import dataclass
from .binconfig import BinaryConfigReader, decode_native_chunks

U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF

class DungeonBinParseError(ValueError):
    pass

# offset, tested bit, mask XOR, kind, transform arguments (in native read order).
# 'u': uint32, 'b': byte != sentinel, 's': native UTF-8, 'a': uint32 array,
# 'd': wrapped uint32 -> uint32 map, 'p': two-uint32 value-type array,
# 't': native string array. Mask XOR alters presence polarity, not value decoding.
SCHEMA = (
 (0x8c,6,0,'b',0x88), (0x84,34,0,'u',('xor',0xc3fd737f)),
 (0x104,36,0,'u',('xor',0x2bbecbb3)), (0x108,54,0,'u',('xor',0xe23d0cea)),
 (0x8d,1,0xd3d96c23,'b',0x16), (0xa3,60,0,'b',0xf5),
 (0x58,4,0,'u',('xor',0x979969b0)), (0x8e,7,0,'b',0xbf),
 (0xda,43,0,'b',0xfc), (0x88,57,0,'u',('add',0x8436af9c)),
 (0xc4,21,0,'u',('xor',0x94880aae,'add',0xcf1c2259)),
 (0x28,39,0,'a',(('add',0x7eb27c2f),('xor',0xeeb1c703,'add',0x9713a172))),
 (0x74,50,0,'u',('add',0xdfb6d77d)), (0xf4,25,0xd3d96c23,'u',('xor',0x9278b92d)),
 (0x5c,3,0,'u',('add',0xeb2b0732)), (0xe4,12,0,'u',('add',0x7e455ad5)),
 (0x38,7,0,'a',(('add',0xd8ba0eb9),('xor',0x71f71b85))),
 (0xac,2,0,'u',('xor',0x4e21b163)), (0x70,61,0,'u',('add',0xe3a174dc)),
 (0xec,47,0,'u',('add',0xb52958b4)), (0x98,17,0,'u',('add',0x5b7b0e1d)),
 (0x40,59,0,'s',(('add',0xec1c),0x89cdaf94c3f2ec1c,'xor')),
 (0xb8,11,0xd3d96c23,'u',('add',0x05945d5b)),
 (0xa0,14,0xd3d96c23,'b',0xc5), (0xdb,28,0xd3d96c23,'b',0xfb),
 (0x90,5,0xd3d96c23,'u',('add',0x57cefdd7)), (0xf9,16,0xd3d96c23,'b',0x53),
 (0xbc,49,0,'u',('add',0x6d25755b)),
 (0x100,23,0xd3d96c23,'u',('xor',0xb63bab61,'add',0x4b5cb44d)),
 (0x7c,2,0,'u',('add',0x0a5f0152)), (0x110,24,0xd3d96c23,'u',('add',0xfdfa9fc3)),
 (0x20,4,0,'a',(('add',0xee38c5cb),('add',0xe8510fc9))),
 (0xfa,27,0,'b',0x89), (0x10,52,0,'s',(('xor',0xa582),0xb1c02170ff48a582,'add')),
 (0xd0,55,0,'u',('xor',0x43cc1d4e)), (0xa4,15,0,'u',('xor',0xf9ed49b6)),
 (0xd4,31,0xd3d96c23,'u',('xor',0xf265be27)), (0xa2,48,0,'b',0xce),
 (0xfc,35,0,'u',('add',0xb0fae4e0)),
 (0xc0,1,0xd3d96c23,'u',('add',0xc8262f2f)), (0x9c,42,0,'u',('add',0x6f533dd2)),
 (0xb0,33,0,'u',('xor',0x197ccd74)), (0xb4,19,0xd3d96c23,'u',('add',0xb765cf5e)),
 (0xe8,13,0xd3d96c23,'u',('xor',0x2dbb0c2f)),
 (0x80,58,0,'u',('xor',0x165d7ec6,'add',0x60e5951e)),
 (0x8f,40,0,'b',0xd5), (0xe0,45,0,'u',('add',0x7d096e66)),
 (0xd8,0,0xd3d96c23,'b',0xcb), (0xf8,29,0,'b',0x9a),
 (0x50,53,0,'s',(('xor',0xb7d3),0x59bd031c0320b7d3,'add')),
 (0xd9,56,0,'b',0xe6), (0x6c,62,0,'u',('xor',0x6fe6e61b)),
 (0x68,0,0xd3d96c23,'u',('add',0x0ed55f43,'xor',0x67a3ddcb)),
 (0x30,37,0,'d',None), (0x60,3,0,'u',('add',0xab1cae49)),
 (0x94,18,0,'u',('xor',0x4c837f9b)), (0x48,8,0,'p',None),
 (0xdc,22,0xd3d96c23,'u',('xor',0x5608330b,'add',0x342b34d6)),
 (0xc8,5,0xd3d96c23,'u',('xor',0x252e7183)), (0xa1,20,0xd3d96c23,'b',0x53),
 (0x64,9,0,'u',('add',0xa7aaa6b6,'xor',0x7e034583)),
 (0x18,10,0xd3d96c23,'t',None),
 (0xf0,30,0xd3d96c23,'u',('xor',0x7308887c)),
 (0x10c,41,0,'u',('xor',0xd67e3e46,'add',0xea5d233c)),
 (0xcc,51,0,'u',('add',0xec10f75b)),
 (0xa8,38,0,'u',('add',0xba0616b2,'xor',0x09fe2d68)),
 (0x78,63,0,'u',('add',0xeaf319cf)),
)


def transform(value: int, operations: tuple, width: int = 32) -> int:
    bound = (1<<width)-1
    for op, constant in zip(operations[::2],operations[1::2]):
        if op == 'xor':
            value ^= constant
        elif op == 'add':
            value += constant
        else:
            raise DungeonBinParseError(f'unknown transform operation: {op}')
        value &= bound
    return value


def count(reader: BinaryConfigReader, ops: tuple, minimum: int) -> int:
    n = transform(reader.u32(),ops)
    # Independent input-length bound, rather than a guessed corpus count.
    if n > (len(reader.data)-reader.pos)//minimum:
        raise DungeonBinParseError(f'container count {n} exceeds remaining input at 0x{reader.pos:X}')
    return n


def string(reader: BinaryConfigReader, args: tuple) -> str:
    ops,key,op = args
    n = transform(reader.u16(),ops,16)
    raw = reader.take(n)
    decoded = decode_native_chunks(raw,key,op)
    try:
        return decoded.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise DungeonBinParseError(f'invalid Dungeon UTF-8 at 0x{reader.pos-n:X}') from exc


def value(reader: BinaryConfigReader, kind: str, args) -> object:
    if kind=='u':return transform(reader.u32(),args)
    if kind=='b':return reader.u8()!=args
    if kind=='s':return string(reader,args)
    if kind=='a':
        length_ops,item_ops=args
        return [transform(reader.u32(),item_ops) for _ in range(count(reader,length_ops,4))]
    if kind=='d':
        out=[]
        for _ in range(count(reader,('xor',0xe006e2d7),8)):
            key=reader.u32()^0x9618f3df
            val=transform(reader.u32(),('add',0x22cfeba4,'xor',0xe0d3653a))
            out.append([key,val])
        return out
    if kind=='p':
        out=[]
        for _ in range(count(reader,('add',0xbec1575e),2)):
            m=(reader.u16()+0x6eb)&0xffff
            first=transform(reader.u32(),('xor',0x82d98720,'add',0x96f1a4f9)) if m&8 else 0
            second=reader.u32()^0xe7641f38 if m&4 else 0
            out.append({'mask':m,'offset0':second,'offset4':first})
        return out
    if kind=='t':
        return [string(reader,(('add',0x9186),0xabaa33a895329186,'xor'))
                for _ in range(count(reader,('xor',0xe4db6143),2))]
    raise DungeonBinParseError('unknown Dungeon field kind '+kind)


@dataclass(frozen=True)
class DungeonRow:
    mask: int
    fields: dict[int, object]
    spans: dict[int, tuple[int,int]]
    start: int
    end: int


def read_dungeon_row(reader: BinaryConfigReader) -> DungeonRow:
    start=reader.pos
    mask=(reader.u64()+0x85b5ff59)&U64
    fields,spans={},{}
    for offset,bit,mask_xor,kind,args in SCHEMA:
        if (mask^mask_xor)&(1<<bit):
            before=reader.pos
            fields[offset]=value(reader,kind,args)
            spans[offset]=(before,reader.pos)
    return DungeonRow(mask,fields,spans,start,reader.pos)


def parse_dungeon_row(data: bytes, start: int = 0) -> DungeonRow:
    if start<0 or start>len(data):raise DungeonBinParseError('invalid row start')
    reader=BinaryConfigReader(data,error_type=DungeonBinParseError,label='Dungeon')
    reader.pos=start
    return read_dungeon_row(reader)


@dataclass(frozen=True)
class DungeonTableScan:
    """Rows after an opaque four-byte prefix; table count is NOT decoded."""
    header_hex: str
    rows: tuple[DungeonRow, ...]
    bytes_consumed: int

    def to_dict(self) -> dict:
        return {
            "status": "ROW_WIRE_DECODED_HEADER_UNRESOLVED",
            "headerHex": self.header_hex,
            "headerCountDecoded": False,
            "observedRowCount": len(self.rows),
            "bytesConsumed": self.bytes_consumed,
            "rows": [{
                "start": row.start, "end": row.end, "mask": f"0x{row.mask:016X}",
                "fields": {f"0x{offset:X}": val for offset, val in row.fields.items()},
                "spans": {f"0x{offset:X}": list(span) for offset, span in row.spans.items()},
            } for row in self.rows],
        }


def scan_dungeon_table(data: bytes, *, allow_opaque_header: bool = False) -> DungeonTableScan:
    """Scan complete rows to EOF. Requires explicit acknowledgement of framing gap.

    Input is the unwrapped 7.1 DungeonExcel payload, not MiHoYoBinData export.
    Scalars expose unsigned wire values; enum names and wrapper memory layouts
    are not reconstructed here. Dictionary entries retain wire order/duplicates.
    This is not a generic version-independent decoder or a decoded count check.
    """
    if not allow_opaque_header:
        raise DungeonBinParseError("Dungeon table header is unresolved; pass allow_opaque_header=True to scan rows")
    reader = BinaryConfigReader(data, error_type=DungeonBinParseError, label="Dungeon")
    header = reader.take(4).hex()
    rows = []
    while reader.pos < len(data):
        rows.append(read_dungeon_row(reader))
    return DungeonTableScan(header, tuple(rows), reader.pos)
