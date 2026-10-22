#!/usr/bin/env python3
"""Verify the AstaPS chest-level ownership boundary against exact Git blobs.

This probe concerns SERVER/FORK source contracts and must not be described
as native original-client field recovery. Source identity uses immutable Git
commit hashes and Git blob SHA-1, with no fallback to the branch tip.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.request import urlopen

from genshinre.nativeprofile import PROFILE_71

OWNER_REPO="RinoPaw/AstaPS"
PATHS={
  "SceneObject": "src/main/java/emu/grasscutter/scripts/data/SceneObject.java",
  "SceneGadget": "src/main/java/emu/grasscutter/scripts/data/SceneGadget.java",
  "SceneGroup": "src/main/java/emu/grasscutter/scripts/data/SceneGroup.java",
  "SceneScriptManager": "src/main/java/emu/grasscutter/scripts/SceneScriptManager.java",
  "EntityGadget": "src/main/java/emu/grasscutter/game/entity/EntityGadget.java",
  "PlayerProperty": "src/main/java/emu/grasscutter/game/props/PlayerProperty.java",
  "WorldChestLootHelper": "src/main/java/emu/grasscutter/game/entity/gadget/chest/WorldChestLootHelper.java"
}
SOURCES={
  "upstreamMain": {
    "commit": "dcf04369a356486a07be976b244b83d7208c3992",
    "files": {
      "SceneObject": "d15b16192382595fe3675dd7cfeb359c53a58667",
      "SceneGadget": "cd0eb4713c364153a8947ecdb0a2517bbadf43c0",
      "SceneGroup": "dcad300d86ea10569f1780042d54c05bcf887435",
      "SceneScriptManager": "a32c79602d8792479b59289c71760548e06fab96",
      "EntityGadget": "79a538a6a593b6e67e22708dc90f918570554e26",
      "PlayerProperty": "b64a6c93634688906e42128f37bcab20df5e728d"
    }
  },
  "rewardExperiment": {
    "commit": "d6d8718442cf2c785bf1bd5b5950dbe59a1accbe",
    "files": {
      "SceneObject": "d15b16192382595fe3675dd7cfeb359c53a58667",
      "SceneGadget": "f250378e914eae163733324e8be918f3a5fe3fa9",
      "SceneGroup": "dcad300d86ea10569f1780042d54c05bcf887435",
      "SceneScriptManager": "87a0238fd28c667803df4e85b710288e80d5cdd9",
      "EntityGadget": "94c20809e7699d3219fbacaf9210532f23524d29",
      "PlayerProperty": "b64a6c93634688906e42128f37bcab20df5e728d",
      "WorldChestLootHelper": "bae74426492f8eacea73298185dba63a52790eea"
    }
  }
}
ORIGINAL_CLIENT_EXE_SHA256=PROFILE_71.exe_sha256
OUTPUT=Path("versions/7.1.0-global/analyses/progression/economy/7.1-chest-level-source-ownership.json")

def git_blob_sha1(data:bytes)->str:
    return hashlib.sha1(b"blob "+str(len(data)).encode("ascii")+b"\0"+data).hexdigest()

def check_source(profile:str, files:dict[str,bytes])->dict:
    expected=SOURCES[profile]["files"]
    if set(files)!=set(expected):
        raise ValueError(f"{profile}: missing or extra pinned AstaPS files")
    decoded={}
    for key,expected_sha in expected.items():
        got=git_blob_sha1(files[key])
        if got!=expected_sha:
            raise ValueError(f"{profile}: source Git blob mismatch {key}: {got}")
        decoded[key]=files[key].decode("utf-8")
    # Validate the actual source path rather than accepting prose about it.
    observations={
        "sceneObjectDeclaresLevel":bool(re.search(r"public\s+int\s+level\s*;",decoded["SceneObject"])),
        "sceneGadgetInheritsSceneObject":bool(re.search(r"class\s+SceneGadget\s+extends\s+SceneObject",decoded["SceneGadget"])),
        "sceneGroupUsesLuaFile":'Scene/%s/scene%s_group%s.lua' in decoded["SceneGroup"],
        "sceneGroupDeserializesGadgets":bool(re.search(r"toList\(\s*SceneGadget\.class\s*,\s*this\.bindings\.get\(\"gadgets\"\)\s*\)",decoded["SceneGroup"])),
        "sceneScriptManagerAttachesOriginalObject":'entity.setMetaGadget(g);' in decoded["SceneScriptManager"],
        "gadgetNetworkPropLevelId4001":bool(re.search(r"PROP_LEVEL\s*\(\s*4001\s*,",decoded["PlayerProperty"])),
        "gadgetNetworkLevelHardcodedOne":bool(re.search(r"newPropValue\(PlayerProperty\.PROP_LEVEL\s*,\s*1\s*\)",decoded["EntityGadget"])),
        "gadgetNetworkPropAttached":'entityInfo.addPropList(pair);' in decoded["EntityGadget"],
    }
    if profile=="rewardExperiment":
        observations.update({
            "lootcssUsesSceneLevel":bool(re.search(r'props\.put\(\s*"level"\s*,\s*meta\.level\s*\)',decoded["WorldChestLootHelper"])),
            "lootcssAddsLevelOnlyWhenMetaPresent":bool(re.search(r'if\s*\(\s*meta\s*!=\s*null\s*\)\s*\{\s*props\.put\(\s*"level"\s*,\s*meta\.level\s*\);',decoded["WorldChestLootHelper"])),
        })
    failed=[key for key,value in observations.items() if not value]
    if failed:
        raise ValueError(f"{profile}: source contract changed: {failed}")
    return observations

def build_report(contents:dict[str,dict[str,bytes]])->dict:
    if set(contents)!=set(SOURCES):
        raise ValueError("both pinned AstaPS snapshots are required")
    verified={name:check_source(name,raw) for name,raw in contents.items()}
    return {
        "schemaVersion":1,
        "status":"VERIFIED_ASTAPS_SOURCE_LEVEL_OWNERSHIP__ORIGINAL_71_INSTANCE_LEVEL_UNPROVEN",
        "evidenceKind":"FORK_SOURCE_NOT_ORIGINAL_CLIENT",
        "originalClientTarget":PROFILE_71.identity,
        "originalClientExeSha256":ORIGINAL_CLIENT_EXE_SHA256,
        "ownerRepo":OWNER_REPO,
        "snapshots":{name:{"commit":item["commit"],
                           "fileGitBlobs":{key:{"path":PATHS[key],"sha1":val}
                                          for key,val in item["files"].items()},
                           "verifiedAnchors":verified[name]}
                     for name,item in SOURCES.items()},
        "sourceGraph":[
            "Scene/<scene>/scene<scene>_group<group>.lua (AstaPS script loader)",
            "SceneGroup.bindings['gadgets'] -> LuaSerializer.toList(SceneGadget.class, ...)",
            "SceneGadget extends SceneObject -> inherited Java int level",
            "SceneScriptManager.createGadget -> EntityGadget.setMetaGadget(g)",
            "WorldChestLootHelper -> loot attribute level = meta.level, if metadata exists",
        ],
        "networkGraph":[
            "EntityGadget.toProto -> SceneEntityInfo.propList",
            "PlayerProperty.PROP_LEVEL numeric property ID 4001 (AstaPS constant)",
            "ProtoHelper.newPropValue(PlayerProperty.PROP_LEVEL, 1) (both AstaPS snapshots)",
        ],
        "boundaries":{
            "networkLevelEqualsSceneScriptLevelProven":False,
            "originalClientSceneInstanceLevelFieldProven":False,
            "originalOfficialServerChestLevelOwnershipProven":False,
            "forkSceneObjectUnspecifiedJavaIntDefaultsToZero":True,
            "forkLootLevelZeroCanBePassedWhenMetadataExists":True,
            "clientNativeNetworkFieldIdentityProven":False,
            "originalScenePlacementSourceProven":False,
        },
        "nextProofGate":"Identify an original Global 7.1 scene-instance source or independently identify original packet/consumer fields and connect them to chest-specific level behavior; never equate a PROP_LEVEL value 1 with the server script instance level.",
        "limits":[
            "AstaPS Lua scene-group scripts and their schema belong to the private-server fork; they do not prove native official client or server asset provenance.",
            "Source pinning confirms branch behavior, not how often actual scenes supply a nonzero level; resource distributions were not inspected.",
            "A separate original-client native protocol field/consumer and original scene level owner remain unresolved.",
            "No LootCSS reward grade, type, payout or probability is inferred or changed.",
        ],
    }

def fetch_sources()->dict:
    fetched={}
    for profile,ref in SOURCES.items():
        fetched[profile]={}
        for key in ref["files"]:
            url=f"https://raw.githubusercontent.com/{OWNER_REPO}/{ref['commit']}/{PATHS[key]}"
            with urlopen(url,timeout=30) as stream:
                fetched[profile][key]=stream.read(2*1024*1024+1)
            if len(fetched[profile][key])>2*1024*1024:
                raise ValueError("oversized AstaPS file")
    return fetched

def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fetch",action="store_true",required=True)
    p.add_argument("--output",type=Path,default=OUTPUT)
    p.add_argument("--check",action="store_true")
    args=p.parse_args()
    report=build_report(fetch_sources())
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8"))!=report:
            raise SystemExit("source-verified AstaPS level graph drift")
    else:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({"status":report["status"],
                      "anchors":{name:s["verifiedAnchors"] for name,s in report["snapshots"].items()},
                      "boundaries":report["boundaries"]},indent=2))

if __name__=="__main__":
    main()
