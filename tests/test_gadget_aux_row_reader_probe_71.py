"""Original Global 7.1 auxiliary Gadget row reader native candidate screening."""
from importlib import util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=util.spec_from_file_location("gadget_aux_reader", ROOT / "scripts/probe-7.1-gadget-aux-row-readers.py")
mod=util.module_from_spec(spec)
spec.loader.exec_module(mod)


class GadgetAuxNativeRowReaderTests(unittest.TestCase):
    def test_verbatim_source_key_offsets(self):
        self.assertEqual(mod.SOURCES["GadgetPropExcelConfigData"]["keyOffset"],0x1C)
        self.assertEqual(mod.SOURCES["GadgetInteractExcelConfigData"]["keyOffset"],0x28)
        self.assertEqual(mod.writer.WRITER,0xBB16020)

    def test_native_class_static_positive_controls(self):
        rows={"exeSha256":mod.PROFILE_71.exe_sha256,
              "methodsGitBlob":mod.writer.METHODS_BLOB,
              "wrappedUint32WriterRva":"0xBB16020",
              "directNativeWriterCalls":1,"sameNameAndArgumentCalls":1,
              "keyOffsetCandidates":{name:{"memoryOffset":f"0x{spec['keyOffset']:X}",
                                           "methods":[],"methodCount":0}
                                     for name,spec in mod.SOURCES.items()}}
        refs={"matches":{f"0x{spec['typeInfoSlotRva']:X}":[
            {"instruction_rva":f"0x{spec['nativeClassLoadRva']:X}",
             "instruction_hex":"488b0d00000000","caller_methods":[]}]
            for name,spec in mod.SOURCES.items()}}
        actual=mod.summarize(rows,refs)
        for result in actual["tables"].values():
            self.assertFalse(result["concreteVirtualRowReaderVerified"])
            self.assertEqual(result["matchingNativeWrapperAndKeyStoreMethods"],0)
        refs["matches"]["0x57DAF50"]=[]
        with self.assertRaisesRegex(ValueError,"positive control"):
            mod.summarize(rows,refs)


if __name__=="__main__":
    unittest.main()
