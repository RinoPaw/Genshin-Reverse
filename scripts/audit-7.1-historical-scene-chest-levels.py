#!/usr/bin/env python3
"""Measure scene-chest instance level coverage in one PINNED SERVER RESOURCE COPY.

Important provenance boundary:
  MeChen618/AstaPS-Resource@85b81a691fcf3d9e8e7db50a8febc8f9043bc084
  RinoPaw/AstaPS scanner@e2541630f5ae4d4c95b81f7440293d3419a776d1

This is NOT Global 7.1 original-client scene-instance data. Do not use any
Lua field, drop_tag or GadgetExcel type to infer official level or grade.
The counted scene objects are exactly the historically-scanned 14,084
non-boss, community-copy Chest-type gadget candidates.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re

RESOURCE_COMMIT="85b81a691fcf3d9e8e7db50a8febc8f9043bc084"
CURRENT_RESOURCE_COMMIT="c0213668889ed05cbeb86660f424c3daf18bfacd"
SCANNER_COMMIT="e2541630f5ae4d4c95b81f7440293d3419a776d1"
SCANNER_BLOB="6ed19ab829c31cac762f5da6132fd44b8900350a"
EXPECTED_LUA_FILES=41110
EXPECTED_HISTORICAL_CHESTS=14084
EXPECTED_EXCLUDED_BOSS=43
LEVEL=re.compile(r"(?<![A-Za-z_0-9])level\s*=\s*([+-]?\d+)(?![\w.])")
LEVEL_PREFIX=re.compile(r"(?<![A-Za-z_0-9])level\s*=")
OUTPUT=Path("versions/7.1.0-global/analyses/progression/economy/7.1-historical-scene-chest-level-coverage.json")


def direct_level(entry:str)->tuple[str,int|None]:
    """Read a top-level Lua gadget property, not a nested explore/monster.level.

    entry is one brace-wrapped gadget extracted by the pinned scanner.
    Quotes, escapes, line comments and inner table levels cannot change
    the result. A malformed or duplicate direct level is rejected.
    """
    depth=0
    quote=None
    comment=False
    escaped=False
    found=[]
    index=0
    while index<len(entry):
        ch=entry[index]
        if comment:
            if ch=="\n":comment=False
            index+=1
            continue
        if quote is not None:
            if escaped:escaped=False
            elif ch=="\\":escaped=True
            elif ch==quote:quote=None
            index+=1
            continue
        if entry[index:index+2]=="--":
            comment=True
            index+=2
            continue
        if ch in ('"',"'"):
            quote=ch
            index+=1
            continue
        if ch=="{":depth+=1
        elif ch=="}":depth-=1
        if depth==1:
            match=LEVEL_PREFIX.match(entry,index)
            if match:
                value=LEVEL.match(entry,index)
                if not value:
                    return ("malformed",None)
                found.append(int(value.group(1)))
                index=value.end()
                continue
        index+=1
    if depth or quote:
        raise ValueError("malformed original historical scene Lua entry")
    if len(found)>1:
        raise ValueError("duplicate top-level level in historical gadget entry")
    return ("explicit",found[0]) if found else ("missing",None)


def pinned_scanner(scanner_path:Path):
    data=scanner_path.read_bytes()
    expected=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
    if expected!=SCANNER_BLOB:
        raise ValueError("pinned AstaPS scanner Git blob identity changed")
    spec=importlib.util.spec_from_file_location("pinned_audit_scene",scanner_path)
    mod=importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def audit(resources:Path,scanner_path:Path,*,commit:str)->dict:
    if commit not in (RESOURCE_COMMIT,CURRENT_RESOURCE_COMMIT):
        raise ValueError("not an authenticated pinned server resource source commit")
    scanner=pinned_scanner(scanner_path)
    excel=resources/"ExcelBinOutput/GadgetExcelConfigData.json"
    chest_ids=scanner.chest_types(json.loads(excel.read_text(encoding="utf-8-sig")))
    counts=Counter()
    level_counts=Counter()
    by_source={}
    by_scene={}
    examples={"positive":[],"missing":[],"explicitZero":[]}
    for file in sorted((resources/"Scripts/Scene").rglob("*.lua")):
        counts["luaFiles"]+=1
        name=file.name
        found=re.search(r"scene(\d+)_group",name)
        scene=found.group(1) if found else "unparsed"
        content=file.read_text(encoding="utf-8",errors="replace")
        for entry in scanner.gadget_entries(content):
            gid=scanner.num(entry,"gadget_id")
            if gid not in chest_ids:continue
            if "boss_chest" in entry:
                counts["excludedBoss"]+=1
                continue
            counts["chestCandidates"]+=1
            scope,number=direct_level(entry)
            if scope=="malformed":raise ValueError(f"non-numeric top-level level in {file.name}")
            drop_id=scanner.num(entry,"chest_drop_id")
            tag=bool(scanner.TAG_RE.search(entry))
            source="explicit_id" if drop_id else ("drop_tag" if tag else "no_metadata")
            key="missing" if scope=="missing" else f"explicit:{number}"
            level_counts[key]+=1
            by_source.setdefault(source,Counter())[key]+=1
            by_scene.setdefault(scene,Counter())[key]+=1
            if scope=="missing":
                counts["defaultJavaZero"]+=1
                slot="missing"
            elif number==0:
                counts["explicitZero"]+=1
                slot="explicitZero"
            else:
                counts["explicitNonzero"]+=1
                slot="positive"
                if number<0:counts["negativeLevel"]+=1
            if len(examples[slot])<8:
                examples[slot].append({
                    "scene":scene,
                    "file":str(file.relative_to(resources)).replace("\\","/"),
                    "configId":scanner.num(entry,"config_id"),
                    "gadgetId":gid,
                    "sourceGroup":source,
                    "explicitLevel":number if scope=="explicit" else None,
                })
    if commit==RESOURCE_COMMIT and (counts["luaFiles"]!=EXPECTED_LUA_FILES or counts["chestCandidates"]!=EXPECTED_HISTORICAL_CHESTS or counts["excludedBoss"]!=EXPECTED_EXCLUDED_BOSS):
        raise ValueError(f"historical source census failed pinned controls: {dict(counts)}")
    if not counts["luaFiles"] or not counts["chestCandidates"]:
        raise ValueError("empty original source-snapshot controls")
    if counts["defaultJavaZero"]+counts["explicitZero"]+counts["explicitNonzero"]!=counts["chestCandidates"]:
        raise ValueError("level classification did not account for every candidate")
    return {
      "schemaVersion":1,
      "status":("HISTORICAL_ASTAPS_SCENE_LEVEL_COVERAGE__NOT_ORIGINAL_7_1_INSTANCES" if commit==RESOURCE_COMMIT else "CURRENT_UPSTREAM_ASTAPS_SCENE_LEVEL_COVERAGE__NOT_ORIGINAL_7_1_INSTANCES"),
      "source":{
         "repository":"MeChen618/AstaPS-Resource","commit":commit,
         "scannerRepository":"RinoPaw/AstaPS","scannerCommit":SCANNER_COMMIT,
         "scannerGitBlob":SCANNER_BLOB,
         "classifier":"community GadgetExcel Chest type; historical resource only",
      },
      "totals":dict(sorted(counts.items())),
      "levelValueDistribution":dict(sorted(level_counts.items())),
      "bySource":{k:dict(sorted(v.items())) for k,v in sorted(by_source.items())},
      "byScene":{k:dict(sorted(v.items())) for k,v in sorted(by_scene.items(),key=lambda x:int(x[0]) if x[0].isdigit() else 999999)},
      "examples":examples,
      "javaScriptLevelAbsentDefaultsToZero":True,
      "originalGlobal71ClientInstanceLevelVerified":False,
      "originalOfficialServerSceneOwnershipVerified":False,
      "limits":[
        "This is a static pinned AstaPS server resource snapshot; source pinning is not official Global 7.1 resource authentication.",
        "Selection uses a public-copy GadgetExcel Chest label to match the exact historical 14,084-candidate census, not native source Gadget categories.",
        "Only direct numeric level assignments on the Lua gadget object are counted; nested fields and strings are excluded.",
        "A missing Lua level becomes 0 in the current fork's Java SceneObject, but actual server game behavior/reward effects require separate tests.",
        "No official loot classification, grade, rewards, probabilities or original-client scene-instance level can be inferred."
      ]
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--resources",type=Path,required=True)
    p.add_argument("--scanner",type=Path,required=True)
    p.add_argument("--resource-commit",required=True)
    p.add_argument("--output",type=Path,default=OUTPUT)
    a=p.parse_args()
    result=audit(a.resources,a.scanner,commit=a.resource_commit)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({"status":result["status"],"totals":result["totals"],
      "levels":result["levelValueDistribution"],"bySource":result["bySource"],
      "examples":result["examples"]},ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
