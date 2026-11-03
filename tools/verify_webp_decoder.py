"""Hash-pinned WebP dependency and Glide 4.12 linkage inspection; never signs APKs."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools/webpdecoder-inputs.json"

def elf(data):
    if len(data)<64 or data[:4] != b'\x7fELF' or data[4] not in (1,2) or data[5] != 1:
        raise ValueError('Expected little-endian ELF32/ELF64')
    bits = data[4] * 32
    machine = struct.unpack_from('<H', data, 18)[0]
    if bits == 64:
        po, so = struct.unpack_from('<QQ', data, 32)
        pe, pn, se, sn = struct.unpack_from('<HHHH', data, 54)
        ph = [struct.unpack_from('<IIQQQQQQ', data, po+i*pe) for i in range(pn)]
        sh = [struct.unpack_from('<IIQQQQIIQQ', data, so+i*se) for i in range(sn)]
        loads = [{'offset':p[2], 'vaddr':p[3], 'align':p[7]} for p in ph if p[0]==1]
    else:
        po, so = struct.unpack_from('<II', data, 28)
        pe, pn, se, sn = struct.unpack_from('<HHHH', data, 42)
        ph = [struct.unpack_from('<IIIIIIII', data, po+i*pe) for i in range(pn)]
        sh = [struct.unpack_from('<IIIIIIIIII', data, so+i*se) for i in range(sn)]
        loads = [{'offset':p[1], 'vaddr':p[2], 'align':p[7]} for p in ph if p[0]==1]
    version = None
    code = None
    for s in sh:
        if s[1] not in (2,11): continue
        strings = sh[s[6]]
        names = data[strings[4]:strings[4]+strings[5]]
        for off in range(s[4],s[4]+s[5],s[9]):
            if bits==64:
                name,info,other,sec,val,size=struct.unpack_from('<IBBHQQ',data,off)
            else:
                name,val,size,info,other,sec=struct.unpack_from('<IIIBBH',data,off)
            if names[name:].split(b'\0',1)[0]!=b'WebPGetDecoderVersion' or not sec: continue
            section=sh[sec]; o=section[4]+(val&~1)-section[3]
            code=data[o:o+size]
            if machine==183:
                words=struct.unpack('<'+'I'*(len(code)//4),code)
                result=0
                for w in words:
                    if w&0xff80001f==0x52800000:
                        result=((w>>5)&65535)<<(16*((w>>21)&3))
                    elif w&0xff80001f==0x72800000:
                        shift=16*((w>>21)&3)
                        result=(result&~(65535<<shift))|(((w>>5)&65535)<<shift)
                    elif w!=0xd65f03c0: raise ValueError('Unexpected version instructions')
                version='%d.%d.%d'%(result>>16,(result>>8)&255,result&255)
            elif machine==40:
                words=struct.unpack('<'+'I'*(len(code)//4),code)
                if len(words)==3 and words[0]&0xfff0f000==0xe3000000 and words[1]&0xfff0f000==0xe3400000 and words[2]==0xe12fff1e:
                    imm=lambda w: ((w>>4)&0xf000)|(w&0xfff)
                    result=imm(words[0]) | (imm(words[1])<<16)
                    version='%d.%d.%d'%(result>>16,(result>>8)&255,result&255)
    needed=[]
    for section in sh:
        if section[1] != 6: continue
        strings=sh[section[6]]
        names=data[strings[4]:strings[4]+strings[5]]
        for off in range(section[4],section[4]+section[5],section[9]):
            tag,val=struct.unpack_from('<QQ' if bits==64 else '<II',data,off)
            if tag==1: needed.append(names[val:].split(b'\0',1)[0].decode('ascii'))
    return {'needed':needed,'bits':bits,'machine':machine,'loads':loads,'version':version,'versionCode':code.hex() if code else None,'sha256':hashlib.sha256(data).hexdigest().upper()}

def class_file(data):
    stream=io.BytesIO(data)
    def read(n):
        b=stream.read(n)
        if len(b)!=n: raise ValueError('truncated class')
        return b
    def u2(): return struct.unpack('>H',read(2))[0]
    if read(4)!=b'\xca\xfe\xba\xbe': raise ValueError('Invalid Java class')
    read(4); cp=[None]*u2(); i=1
    while i<len(cp):
        tag=read(1)[0]
        if tag==1: item=read(u2()).decode('utf8','replace')
        elif tag in (7,8,16,19,20): item=u2()
        elif tag in (9,10,11,12,17,18): item=(u2(),u2())
        elif tag in (3,4): item=read(4)
        elif tag in (5,6): item=read(8)
        elif tag==15: item=(read(1)[0],u2())
        else: raise ValueError(tag)
        cp[i]=(tag,item);i+=2 if tag in(5,6) else 1
    def name(i): return cp[cp[i][1]][1]
    access=u2();this=name(u2());sup=u2();sup=name(sup) if sup else None
    interfaces=[name(u2()) for _ in range(u2())]
    def attrs():
        for _ in range(u2()): read(2);read(struct.unpack('>I',read(4))[0])
    fields=set();methods=set()
    for dest in (fields,methods):
        for _ in range(u2()):
            read(2); dest.add((cp[u2()][1],cp[u2()][1])); attrs()
    refs=set()
    for item in cp:
        if item and item[0] in (9,10,11):
            c,nt=item[1];n,d=cp[nt][1]
            refs.add((item[0],name(c),cp[n][1],cp[d][1]))
    return {'name':this,'super':sup,'interfaces':interfaces,'fields':fields,'methods':methods,'refs':refs}

def jar_classes(path):
    with zipfile.ZipFile(path) as z:
        return {c['name']:c for c in (class_file(z.read(n)) for n in z.namelist() if n.endswith('.class'))}


def linkage(decoder, glide):
    """Resolve actual member descriptors, including inherited members."""
    def find(owner, kind, key, seen=None):
        seen = set() if seen is None else seen
        if owner in seen:
            return False
        seen.add(owner)
        cls = glide.get(owner) or decoder.get(owner)
        if cls is None:
            return False
        if key in cls['fields' if kind == 9 else 'methods']:
            return True
        if key[0] == '<init>':
            return False
        return any(find(parent, kind, key, seen)
                   for parent in [cls['super']] + cls['interfaces'] if parent)

    external, missing = set(), set()
    for cls in decoder.values():
        for kind, owner, name, descriptor in cls['refs']:
            if owner.startswith('com/bumptech/glide/') and owner not in decoder:
                external.add((kind, owner, name, descriptor))
                if not find(owner, kind, (name, descriptor)):
                    missing.add((owner, name, descriptor))
    return len(external), sorted(missing)


def checked_hash(path, expected):
    if hashlib.sha256(Path(path).read_bytes()).hexdigest().upper() != expected:
        raise ValueError('Artifact SHA-256 mismatch')


def verify(aar, glide, gif, previous=None, apk=None):
    policy = json.loads(MANIFEST.read_text(encoding='utf-8'))
    for path, name in [(aar, 'webpdecoder-2.7.4.16.0.aar'),
                       (glide, 'glide-4.12.0.jar'), (gif, 'gifdecoder-4.12.0.jar')]:
        checked_hash(path, policy['artifacts'][name]['sha256'])
    classes = jar_classes(glide)
    classes.update(jar_classes(gif))
    with zipfile.ZipFile(aar) as z:
        decoder = jar_classes(io.BytesIO(z.read('classes.jar')))
        count, missing = linkage(decoder, classes)
        if missing:
            raise ValueError('Unresolved Glide 4.12.0 members: ' + repr(missing))
        if previous:
            checked_hash(previous, policy['replacedArtifact']['classesSha256'])
            for name, cls in jar_classes(previous).items():
                if name.endswith('/BuildConfig'):
                    continue
                now = decoder.get(name)
                if now is None or not cls['methods'] <= now['methods'] or not cls['fields'] <= now['fields']:
                    raise ValueError('Removed decoder API: ' + name)
        native = {}
        for name, expected in policy['native'].items():
            data = z.read(name)
            info = elf(data)
            if info['sha256'] != expected['sha256']:
                raise ValueError('Native SHA-256 mismatch: ' + name)
            abi = name.split('/')[1]
            if abi in ('arm64-v8a', 'armeabi-v7a'):
                if info['version'] != policy['libwebpVersion']:
                    raise ValueError('Unexpected libwebp version: ' + name)
                if (info['bits'], info['machine']) != ((64, 183) if abi == 'arm64-v8a' else (32, 40)):
                    raise ValueError('Incorrect native architecture: ' + name)
            if abi in ('arm64-v8a', 'x86_64'):
                if not info['loads'] or any(p['align'] < 16384 or (p['offset']-p['vaddr']) % 16384 for p in info['loads']):
                    raise ValueError('Invalid 16 KB ELF alignment: ' + name)
            if set(info['needed']) - {'libc.so', 'libm.so', 'libdl.so', 'liblog.so', 'libjnigraphics.so'}:
                raise ValueError('Unexpected native dependency: ' + name)
            native[abi] = info
        if {n for n in z.namelist() if n.endswith('.so')} != set(policy['native']):
            raise ValueError('Unexpected native inventory')
        if apk:
            with zipfile.ZipFile(apk) as built:
                names = built.namelist()
                if len(names) != len(set(names)) or built.testzip() is not None:
                    raise ValueError('Invalid APK ZIP')
                for name in policy['native']:
                    if name.split('/')[1] not in policy['packagedAbis']:
                        continue
                    target = name.replace('jni/', 'lib/', 1)
                    if built.read(target) != z.read(name) or built.getinfo(target).compress_type != zipfile.ZIP_STORED:
                        raise ValueError('Rebuilt native differs or is compressed: ' + target)
                if any(n.startswith('lib/') and n != 'lib/' and n.split('/')[1] not in policy['packagedAbis'] for n in names):
                    raise ValueError('Unexpected packaged ABI')
    return {'glideVersion': policy['glideVersion'], 'resolvedGlideMembers': count,
            'unresolvedGlideMembers': missing, 'native': native}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('aar', 'glide', 'gif'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--previous', type=Path)
    parser.add_argument('--apk', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.aar, args.glide, args.gif, args.previous, args.apk), indent=2))
