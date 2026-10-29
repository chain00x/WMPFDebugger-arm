#!/usr/bin/env python3
"""WMPF macOS(arm64) 偏移自动定位（capstone，不需要 IDA）。

用法:
    python3 scripts/find-offsets.py [WeChatAppEx\ Framework 二进制路径]

流程（对应 ADAPTATION.md §8/§14）:
  1. lipo -thin arm64 提取切片（已是单架构则直接用）。
  2. 用 numpy 向量化扫描 ADRP+ADD，找到目标字符串的 xref，避免全量反汇编。
  3. OnLoadStart 签名串 xref → 向前找 `cbz w20` + `ldr x8,[x19,#0x38]`
     链路 = tailGate 打点；同一块里的 bl 目标 = 会话工厂。
  4. WAPCAdapterAppIndex.js（资源名列表里的首个）→ xref 所在函数入口。
  5. SendToClientFilter → xref 所在函数（mac 上默认 DisableCDPFilter，仅供参考）。

输出即为 config/addresses.<版本>.darwin.json 的内容，但**必须人工复核**
（用 python3 - 或 a64 反汇编确认指令边界与寄存器语义，见 ADAPTATION.md）。
"""

import json
import os
import re
import struct
import subprocess
import sys
import tempfile

import numpy as np

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.exit("需要 capstone: python3 -m pip install capstone")

DEFAULT_FW = ("/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/"
              "Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework")

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def thin_binary(src):
    """返回 (文件路径, 是否临时文件)"""
    out = subprocess.run(["lipo", "-info", src], capture_output=True, text=True).stdout
    if "Architectures in the fat file" not in out:
        return src, False
    tmp = os.path.join(tempfile.mkdtemp(prefix="wmpf-"), "fw-arm64")
    subprocess.run(["lipo", src, "-thin", "arm64", "-output", tmp], check=True)
    return tmp, True


class Image:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        text = subprocess.run(
            ["otool", "-l", path], capture_output=True, text=True).stdout
        # 找 __TEXT 段 fileoff/filesize：arm64 上 vmaddr==fileoff，偏移可直接当虚拟地址用
        self.text_size = None
        cur = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("segname"):
                cur = line.split()[1]
            elif cur == "__TEXT" and line.startswith("filesize") and self.text_size is None:
                self.text_size = int(line.split()[1], 16)
        self.words = np.frombuffer(self.data[: self.text_size], dtype="<u4").astype(np.uint64)

    # ---------- 字符串 & xref ----------
    def find_strings(self, needle: bytes):
        res = []
        i = self.data.find(needle)
        while i != -1:
            s = i
            while s > 0 and self.data[s - 1] != 0:
                s -= 1
            e = i
            while e < len(self.data) and self.data[e] != 0:
                e += 1
            res.append((s, self.data[s:e]))
            i = self.data.find(needle, i + 1)
        return res

    def xrefs_to(self, target: int):
        """ADRP+ADD 相邻配对命中 target 的位置列表（指令地址）。"""
        w = self.words
        n = len(w)
        is_adrp = (w & np.uint64(0x9F000000)) == np.uint64(0x90000000)
        idx = np.nonzero(is_adrp)[0]
        word = w[idx]
        immlo = (word >> 29) & 3
        immhi = (word >> 5) & 0x7FFFF
        imm = np.where(immhi >= (1 << 19), immhi.astype(np.int64) - (1 << 20),
                       immhi.astype(np.int64))
        imm = ((imm << 2) | immlo.astype(np.int64)) << 12
        page = ((idx.astype(np.int64) * 4) & ~0xFFF) + imm
        rd = word & 0x1F
        w2 = w[np.minimum(idx + 1, n - 1)]
        is_add = ((w2 & np.uint64(0xFF800000)) == np.uint64(0x91000000)) & (idx + 1 < n)
        rn = (w2 >> 5) & 0x1F
        imm12 = (w2 >> 10) & 0xFFF
        hit = is_add & (rd == rn) & (page + imm12.astype(np.int64) == target)
        return [int(i * 4) for i in idx[hit]]

    # ---------- 反汇编辅助 ----------
    def dis(self, start, size):
        return list(MD.disasm(self.data[start:start + size], start))

    def bl_targets_all(self):
        """全二进制 bl 目标集合（numpy 向量化，~0.3s）。用于反推函数入口。"""
        if getattr(self, "_bl_targets", None) is not None:
            return self._bl_targets
        w = self.words.astype(np.int64)
        idx = np.nonzero((w & 0xFC000000) == 0x94000000)[0]
        imm = w[idx] & 0x03FFFFFF
        imm = np.where(imm >= (1 << 25), imm - (1 << 26), imm)
        self._bl_targets = set(int(t) for t in (idx * 4 + imm * 4).tolist())
        return self._bl_targets

    def enclosing_entry(self, addr, window=0x4000):
        """反推包含 addr 的函数入口：addr 之前最近的、带合法 prologue 的 bl 目标。"""
        cands = [t for t in self.bl_targets_all()
                 if addr - window <= t < addr and self.prologue_at(t)]
        return max(cands) if cands else None

    def prologue_at(self, a):
        ins = self.dis(a, 8)
        if not ins:
            return None
        s = ins[0].mnemonic + " " + ins[0].op_str
        if ins[0].mnemonic == "sub" and ins[0].op_str.startswith("sp, sp,"):
            return s
        if ins[0].mnemonic == "stp" and "x29, x30" in ins[0].op_str:
            return s
        if ins[0].mnemonic == "pacibsp":
            return s
        return None


def find_tail_gate(img: Image):
    """签名串 xref → tailGate 打点 + 会话工厂。"""
    sigs = img.find_strings(b"AppletIndexContainer::OnLoadStart")
    for saddr, text in sigs:
        for xref in img.xrefs_to(saddr):
            ins = img.dis(xref, 0x400)
            for i, ins_i in enumerate(ins):
                # 找门禁链: ldr x8,[x19,#0x38] / ldr x9,[x8,#0x5f0] / ldr x9,[x9,#0x10]
                if not (ins_i.mnemonic == "ldr" and re.match(r"x\d+, \[x19, #0x38\]", ins_i.op_str)):
                    continue
                chain = ins[i:i + 3]
                if not (len(chain) == 3
                        and chain[1].mnemonic == "ldr" and "#0x5f0]" in chain[1].op_str
                        and chain[2].mnemonic == "ldr" and "#0x10]" in chain[2].op_str):
                    continue
                prev = ins[i - 1] if i > 0 else None
                gate = None
                if prev and prev.mnemonic == "cbz" and prev.op_str.startswith("w"):
                    gate = prev.address
                if gate is None:
                    continue
                # 门禁链后面的第一个 bl = 会话工厂
                factory = None
                for j in range(i + 3, min(i + 40, len(ins))):
                    if ins[j].mnemonic == "bl":
                        factory = int(ins[j].op_str.lstrip("#"), 0)
                        break
                if factory is None:
                    continue
                return {
                    "sig_string": hex(saddr),
                    "sig_xref": hex(xref),
                    "LoadStartHookOffset": hex(gate),
                    "LoadStartHookOffset2": hex(factory),
                    "gate_chain": [f"{x.mnemonic} {x.op_str}" for x in chain],
                }
    return None


def find_resource_cache(img: Image):
    """WAPCAdapterAppIndex.js（首个）xref 所在函数入口（最近的前置 bl 目标 + 合法 prologue）。"""
    for saddr, text in img.find_strings(b"WAPCAdapterAppIndex.js"):
        xrefs = img.xrefs_to(saddr)
        if not xrefs:
            continue
        for xref in xrefs:
            entry = img.enclosing_entry(xref)
            if not entry:
                continue
            return {"string": hex(saddr), "xref": hex(xref),
                    "ResourceCachePolicyHookOffset": hex(entry)}
    return None


def find_cdp_filter(img: Image):
    """best-effort：字符串 xref 所在函数的第一个 bl（mac 上默认禁用，仅供参考）。"""
    for saddr, text in img.find_strings(b"SendToClientFilter"):
        xrefs = img.xrefs_to(saddr)
        for xref in xrefs:
            entry = img.enclosing_entry(xref)
            if not entry:
                continue
            for ins in img.dis(entry, xref - entry + 0x40):
                if ins.mnemonic == "bl":
                    return {"string": hex(saddr), "xref": hex(xref),
                            "entry": hex(entry),
                            "CDPFilterHookOffset(approx)": hex(int(ins.op_str.lstrip("#"), 0))}
    return None


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FW
    path, tmp = thin_binary(src)
    if tmp:
        print(f"[+] arm64 slice: {path}")
    img = Image(path)
    print(f"[+] __TEXT size: {hex(img.text_size)}")

    gate = find_tail_gate(img)
    cache = find_resource_cache(img)
    cdp = find_cdp_filter(img)

    print("[+] OnLoadStart gate:", json.dumps(gate, ensure_ascii=False, indent=2))
    print("[+] resource cache:", json.dumps(cache, ensure_ascii=False, indent=2))
    print("[+] cdp filter:", json.dumps(cdp, ensure_ascii=False, indent=2))

    if gate:
        cfg = {
            "Version": 0,
            "Arch": {
                "arm64": {
                    "LoadStartHookOffset": gate["LoadStartHookOffset"],
                    "LoadStartHookOffset2": gate["LoadStartHookOffset2"],
                    "StructOffset": 1520,
                    "SceneOffset": 456,
                    "DisableCDPFilter": True,
                }
            },
        }
        if cache:
            cfg["Arch"]["arm64"]["ResourceCachePolicyHookOffset"] = \
                cache["ResourceCachePolicyHookOffset"]
        print("\n[config 模板] 把 Version 改成 WMPF 版本号并人工复核：")
        print(json.dumps(cfg, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
