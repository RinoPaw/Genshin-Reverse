from __future__ import annotations

import struct
import unittest

from genshinre.worldareabin import WorldAreaBinError, decode_world_area

U32 = 0xffffffff


def enc_vec(x, y, z):
    bits = lambda v: struct.unpack("<I", struct.pack("<f",v))[0]
    return bytes([ (0x46-0xA7)&255 ]) + struct.pack(
        "<III",
        ((bits(y)^0x3E98C6BE)-0x66D8B127)&U32,
        (bits(z)-0x25F781DF)&U32,
        bits(x)^0xDF729864,
    )


def enc_shape(points, min_xyz=(-10.0,-1000.0,-20.0),
              max_xyz=(10.0,1000.0,20.0)):
    mask=0xA1 # two Vector3 bounds + vertex array
    encoded_count=(((len(points)^0xC19205C3)-0x1E26A455)&U32)
    return (
        bytes([(mask-0x5F)&255]) + enc_vec(*min_xyz) + enc_vec(*max_xyz)
        + struct.pack("<I",encoded_count)
        + b"".join(enc_vec(*p) for p in points)
    )


def enc_record(first, second=None, points=((0.,0.,0.),)):
    mask = 0x84|(0x20 if second is not None else 0)
    return (
        bytes([(mask-0xFC)&255])
        + enc_shape(points)
        + struct.pack("<I",(first-0x7B4A79A4)&U32)
        + (struct.pack("<I",second^0xB3B8156D) if second is not None else b"")
    )


def enc_payload(parents):
    header=b"\xcb"+struct.pack("<I",(len(parents)-0x91B65B45)&U32)
    for parent,children in parents:
        mask = 0x40|(1 if children else 0)
        header+=bytes([((mask^0x55)-0x15)&255])
        header+=enc_record(parent)
        if children:
            header+=struct.pack("<I",len(children)^0xFBD01BCE)
            for first,second in children:
                header+=enc_record(first,second)
    return header


class WorldAreaNativeWireTests(unittest.TestCase):
    def test_full_original_native_read_order_and_xyz(self):
        data=enc_payload([(210,[(210,21001),(210,21002)]),
                          (300,[])])
        scene=decode_world_area(data)
        self.assertEqual(len(data),scene["consumedBytes"])
        self.assertEqual(2,scene["parentCount"])
        p=scene["parents"][0]
        self.assertEqual(210,p["area_record"]["offset_0x18_u32"])
        self.assertEqual(2,p["child_array"]["count"])
        c=p["child_array"]["values"][0]
        self.assertEqual(210,c["offset_0x18_u32"])
        self.assertEqual(21001,c["offset_0x1C_u32"])
        self.assertEqual(
            {"x":-10.,"y":-1000.,"z":-20.},
            c["offset_0x10_shape"]["offset_0x24_vector"]["coordinates"]
        )
        self.assertEqual(
            {"x":10.,"y":1000.,"z":20.},
            c["offset_0x10_shape"]["offset_0x30_vector"]["coordinates"]
        )
        self.assertEqual({"x":0.,"y":0.,"z":0.},
                         c["offset_0x10_shape"]["offset_0x18_vertices"]["points"][0]["coordinates"])
        self.assertIsNone(scene["parents"][1]["child_array"])

    def test_empty_original_array(self):
        scene=decode_world_area(enc_payload([]))
        self.assertEqual(0,scene["parentCount"])
        self.assertEqual([],scene["parents"])

    def test_reject_truncated_and_extra_data(self):
        raw=enc_payload([(1,[])])
        with self.assertRaises(WorldAreaBinError):
            decode_world_area(raw[:-1])
        with self.assertRaisesRegex(WorldAreaBinError,"unconsumed trailing bytes"):
            decode_world_area(raw+b"garbage")

    def test_wrong_marker(self):
        with self.assertRaisesRegex(WorldAreaBinError,"root marker"):
            decode_world_area(b"\x00"+enc_payload([])[1:])


if __name__ == "__main__":
    unittest.main()
