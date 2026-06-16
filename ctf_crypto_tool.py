#!/usr/bin/env python3
"""Offline CTF crypto helper implemented with Python standard library only."""
from __future__ import annotations
import argparse, hashlib, itertools, string, sys
from math import gcd

BLOCK_ALGS = {"aes":16,"des":8,"sm4":16}


def decode_value(value: str, typ: str) -> bytes:
    if typ == "text":
        return value.encode()
    if typ == "hex":
        s = ''.join(value.split())
        if len(s) % 2:
            s = '0' + s
        return bytes.fromhex(s)
    if typ == "decimal":
        if not value.strip(): return b""
        out=[]
        for p in value.replace(',', ' ').split():
            n=int(p,10)
            if not 0 <= n <= 255: raise ValueError(f"decimal byte out of range: {n}")
            out.append(n)
        return bytes(out)
    raise ValueError(f"unsupported type: {typ}")

def encode_value(data: bytes, typ: str) -> str:
    if typ == "text":
        return data.decode(errors="replace")
    if typ == "hex":
        return data.hex()
    if typ == "decimal":
        return ' '.join(str(b) for b in data)
    raise ValueError(f"unsupported type: {typ}")


def pkcs7_pad(data: bytes, bs: int) -> bytes:
    n = bs - (len(data) % bs)
    return data + bytes([n])*n

def pkcs7_unpad(data: bytes, bs: int) -> bytes:
    if not data or len(data)%bs: raise ValueError("invalid PKCS7 data length")
    n=data[-1]
    if n < 1 or n > bs or data[-n:] != bytes([n])*n: raise ValueError("invalid PKCS7 padding")
    return data[:-n]

def apply_padding(data: bytes, bs: int, padding: str) -> bytes:
    if padding == "pkcs7": return pkcs7_pad(data, bs)
    if padding == "zero":
        n=(-len(data))%bs
        return data + b"\0"*n
    if padding == "none":
        if len(data)%bs: raise ValueError("padding=none requires input length to be a block multiple")
        return data
    raise ValueError("unsupported padding")

def remove_padding(data: bytes, bs: int, padding: str) -> bytes:
    if padding == "pkcs7": return pkcs7_unpad(data, bs)
    if padding == "zero": return data.rstrip(b"\0")
    if padding == "none": return data
    raise ValueError("unsupported padding")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if not b: raise ValueError("xor key/counterpart must not be empty")
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))

def rc4_crypt(data: bytes, key: bytes) -> bytes:
    if not key: raise ValueError("rc4 key must not be empty")
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&255; S[i],S[j]=S[j],S[i]
    i=j=0; out=bytearray()
    for ch in data:
        i=(i+1)&255; j=(j+S[i])&255; S[i],S[j]=S[j],S[i]
        out.append(ch ^ S[(S[i]+S[j])&255])
    return bytes(out)

def affine_encrypt(data: bytes, key: bytes) -> bytes:
    a,b=parse_affine_key(key)
    return bytes(((a*x+b)%256) for x in data)

def affine_decrypt(data: bytes, key: bytes) -> bytes:
    a,b=parse_affine_key(key); inv=pow(a, -1, 256)
    return bytes((inv*(y-b))%256 for y in data)

def parse_affine_key(key: bytes) -> tuple[int,int]:
    txt=key.decode(errors='ignore').replace(',', ' ')
    parts=txt.split()
    if len(parts)!=2: raise ValueError("affine key must contain two integers: 'a b'")
    a,b=map(int, parts)
    if gcd(a,256)!=1: raise ValueError("affine parameter a must be coprime with 256")
    return a%256,b%256

def affine_recover_key(p: bytes, c: bytes) -> bytes:
    if len(p)!=len(c): raise ValueError("plaintext and ciphertext lengths must match")
    for a in range(1,256,2):
        if gcd(a,256)!=1: continue
        b=(c[0]-a*p[0])%256 if p else 0
        if all((a*x+b)%256 == y for x,y in zip(p,c)):
            return f"{a} {b}".encode()
    raise ValueError("no affine key found for the provided byte pairs")


def crypto(args):
    p = decode_value(args.plaintext,args.plaintext_type) if args.plaintext is not None else None
    c = decode_value(args.ciphertext,args.ciphertext_type) if args.ciphertext is not None else None
    k = decode_value(args.key,args.key_type) if args.key is not None else None
    count=sum(x is not None for x in (p,c,k))
    if count != 2: raise ValueError("provide exactly two of --plaintext, --ciphertext, --key")
    alg=args.alg
    if p is not None and c is not None and k is None:
        if alg == "xor": res=xor_bytes(p,c)
        elif alg == "affine": res=affine_recover_key(p,c)
        else: raise ValueError("无法仅凭明文和密文唯一恢复密钥")
    elif p is not None and k is not None:
        if alg == "xor": res=xor_bytes(p,k)
        elif alg == "rc4": res=rc4_crypt(p,k)
        elif alg == "affine": res=affine_encrypt(p,k)
        elif alg in BLOCK_ALGS: raise ValueError(f"{alg.upper()} is declared for ECB/CBC + pkcs7/zero/none, but this offline stdlib-only build does not vendor a pure-Python implementation")
    elif c is not None and k is not None:
        if alg == "xor": res=xor_bytes(c,k)
        elif alg == "rc4": res=rc4_crypt(c,k)
        elif alg == "affine": res=affine_decrypt(c,k)
        elif alg in BLOCK_ALGS: raise ValueError(f"{alg.upper()} is declared for ECB/CBC + pkcs7/zero/none, but this offline stdlib-only build does not vendor a pure-Python implementation")
    else:
        raise ValueError("unhandled argument combination")
    print(encode_value(res,args.output_type))

def hash_cmd(args):
    data=decode_value(args.input,args.input_type)
    print(hashlib.new(args.alg, data).hexdigest())

def charset_value(name: str) -> str:
    presets={"ascii_lowercase":string.ascii_lowercase,"digits":string.digits,"hex":string.hexdigits.lower()[:16],"printable":string.printable}
    return presets.get(name, name)

def hash_bruteforce(args):
    length=args.length
    if length is None:
        length=int(input("请输入待爆破输入的字节数:"))
    chars=charset_value(args.charset)
    target=args.hash.lower()
    for tup in itertools.product(chars, repeat=length):
        s=''.join(tup).encode()
        if hashlib.new(args.alg, s).hexdigest().lower()==target:
            print(s.decode(errors='replace'))
            return
    print("NOT FOUND")
    sys.exit(1)

def convert(args):
    print(encode_value(decode_value(args.input,args.input_type), args.output_type))

def build_parser():
    p=argparse.ArgumentParser(description="Offline CTF encoding, crypto, and hash helper")
    sub=p.add_subparsers(dest='cmd', required=True)
    co=sub.add_parser('convert'); co.add_argument('--input-type',choices=['hex','text','decimal'],required=True); co.add_argument('--output-type',choices=['hex','text','decimal'],required=True); co.add_argument('--input',required=True); co.set_defaults(func=convert)
    cr=sub.add_parser('crypto'); cr.add_argument('--alg',choices=['xor','affine','rc4','des','aes','sm4'],required=True); cr.add_argument('--plaintext'); cr.add_argument('--plaintext-type',choices=['hex','text','decimal'],default='text'); cr.add_argument('--ciphertext'); cr.add_argument('--ciphertext-type',choices=['hex','text','decimal'],default='hex'); cr.add_argument('--key'); cr.add_argument('--key-type',choices=['hex','text','decimal'],default='text'); cr.add_argument('--output-type',choices=['hex','text','decimal'],default='hex'); cr.add_argument('--mode',choices=['ecb','cbc'],default='ecb'); cr.add_argument('--iv'); cr.add_argument('--padding',choices=['pkcs7','zero','none'],default='pkcs7'); cr.set_defaults(func=crypto)
    ha=sub.add_parser('hash'); ha.add_argument('--alg',choices=['md5','sha256'],required=True); ha.add_argument('--input',required=True); ha.add_argument('--input-type',choices=['hex','text','decimal'],default='text'); ha.set_defaults(func=hash_cmd)
    hb=sub.add_parser('hash-bruteforce'); hb.add_argument('--alg',choices=['md5','sha256'],required=True); hb.add_argument('--hash',required=True); hb.add_argument('--length',type=int); hb.add_argument('--charset',default='ascii_lowercase'); hb.set_defaults(func=hash_bruteforce)
    return p

def main(argv=None):
    args=build_parser().parse_args(argv)
    try: args.func(args)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr); return 2
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
