#!/usr/bin/env python3
"""Exhaustive per-context attribution for ctgrind memcheck logs.

Classes:
  A  test harness (libtest / ::tests::)
  B  the new engine (src/ec/p256.rs or p256_ladder_run)
  C  generic bignum (src/bn/*)
  D  pre-existing generic EC/ECDSA driver (ec/mult.rs, ec/ecdsa_ossl.rs, ec/smpl.rs)
  E  allocator/runtime/other (core/std/alloc/libc/valgrind)
"engine-on-path" means a p256 frame appears anywhere in the stack.
"""
import re, sys, json, os
from collections import Counter, defaultdict

KINDS = re.compile(r"^==\d+== (Conditional jump or move|Use of uninitialised value|Syscall param|Invalid read|Invalid write|Invalid free|Mismatched free|Jump to the invalid address|Source and destination overlap|Invalid alignment)")
FRAME = re.compile(r"^==\d+==\s+(at|by) 0x[0-9A-F]+: (.*)$")

def parse(path):
    recs=[]; cur=None
    for raw in open(path, errors='replace'):
        line=raw.rstrip('\n'); m=FRAME.match(line)
        if m:
            rest=m.group(2); lm=re.search(r'\(([^()]*)\)\s*$', rest)
            loc=lm.group(1) if lm else ''
            fn=re.sub(r'\s*\([^()]*\)\s*$','',rest).strip()
            if fn.startswith('in '): fn=fn[3:]
            if cur is None:
                cur={'kind':'unknown','frames':[]}; recs.append(cur)
            cur['frames'].append((m.group(1),fn,loc)); continue
        km=KINDS.match(line)
        if km:
            cur={'kind':km.group(1),'frames':[]}; recs.append(cur)
    return [r for r in recs if r['frames']]

def classify(fn):
    if '::ec::p256::' in fn or 'p256_ladder_run' in fn: return 'B'
    if '::bn::' in fn: return 'C'
    if any(x in fn for x in ('::ec::mult::','::ec::ecdsa_ossl::','::ec::smpl::','::ec::field::','::ec::curve::','::ec::lib::')): return 'D'
    if '::tests::' in fn or 'test::' in fn or 'libtest' in fn: return 'A'
    return 'E'

def nearest_crate(frames):
    for k,fn,loc in frames:
        if 'openssl_rs::' in fn or '<openssl_rs::' in fn:
            return fn, loc
    return '', ''

def norm_stack(frames):
    out=[]
    for k,fn,loc in frames:
        if 'in /work' in loc or loc.startswith('in '): loc='BINARY'
        out.append(fn)
    return ' <- '.join(out)

def run(path, outdir):
    recs=parse(path); rows=[]
    for i,r in enumerate(recs,1):
        top=r['frames'][0]
        cls=classify(top[1])
        text=' '.join(f+' '+l for _,f,l in r['frames'])
        eng=('::ec::p256::' in text) or ('p256_ladder_run' in text)
        bn=('::bn::' in text)
        nfn,nloc=nearest_crate(r['frames'])
        rows.append({'i':i,'kind':r['kind'],'class':cls,'origin_fn':top[1],'origin_loc':top[2],
                     'engine_on_path':int(eng),'bn_on_path':int(bn),
                     'nearest_fn':nfn,'nearest_loc':nloc,'stack':norm_stack(r['frames'])})
    base=os.path.basename(path).replace('.out','')
    with open(os.path.join(outdir, base+'.tsv'),'w') as f:
        f.write('idx\tkind\tclass\torigin_loc\torigin_fn\tengine_on_path\tbn_on_path\tnearest_loc\tnearest_fn\tstack\n')
        for x in rows:
            f.write('%d\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n'%(x['i'],x['kind'],x['class'],x['origin_loc'],x['origin_fn'],x['engine_on_path'],x['bn_on_path'],x['nearest_loc'],x['nearest_fn'],x['stack']))
    per=Counter(x['class'] for x in rows)
    sites=Counter((x['origin_loc'],x['origin_fn']) for x in rows)
    summary={'log':path,'contexts':len(rows),'per_class':dict(per),
             'engine_on_path':sum(x['engine_on_path'] for x in rows),
             'origin_in_engine':per.get('B',0),
             'top_origins':[{'contexts':n,'loc':l,'fn':f} for (l,f),n in sites.most_common(20)]}
    with open(os.path.join(outdir, base+'.summary.json'),'w') as f:
        json.dump(summary,f,indent=2)
    return summary

if __name__=='__main__':
    outdir=sys.argv[1]; os.makedirs(outdir,exist_ok=True)
    for p in sys.argv[2:]:
        s=run(p,outdir)
        print(json.dumps({'log':os.path.basename(p),'contexts':s['contexts'],'per_class':s['per_class'],'engine_on_path':s['engine_on_path']}))
