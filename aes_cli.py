import argparse, csv, os, secrets, sys, time, tracemalloc
from logger_setup import get_logger
from key_manager import KeyManager
from crypto_aes import encrypt_file, decrypt_file, SUPPORTED_MODES, SUPPORTED_PADDINGS
from config import BLOCK_SIZE_BITS

logger = get_logger()
MODE_LABELS = {"gcm": "GCM", "cbc": "CBC-HMAC", "ctr": "CTR-HMAC"}

def cmd_key(args):
    km = KeyManager()
    if args.action == 'new':
        try:
            meta = km.new_key(args.label, args.password, key_bits=args.key_bits)
            logger.info('key_created', extra={'extra': {'label': meta['label'], 'key_id': meta['key_id'], 'key_bits': meta['key_bits']}})
            print('CREATED:', meta)
        except ValueError as e:
            logger.warning('key_policy_violation', extra={'extra': {'label': args.label, 'error': str(e)}})
            print('KEY POLICY ERROR:', e, file=sys.stderr)
            sys.exit(2)
    elif args.action == 'list':
        for k in km.list_keys():
            print(k)

def cmd_enc(args):
    km = KeyManager()
    try:
        meta, enc_key, mac_key = km.derive_keypair(args.label, args.password)
        aad = args.aad.encode('utf-8') if args.aad else None
        t0 = time.perf_counter()
        info = encrypt_file(
            args.infile, args.outfile, enc_key, mac_key,
            mode=args.mode, pad_scheme=args.pad, iv_hex=args.iv,
            aad=aad, block_bits=args.block_bits
        )
        dt = time.perf_counter() - t0
        km.inc_use(meta['key_id'])
        logger.info('enc_ok', extra={'extra': {
            'mode': info['mode'], 'key_id': meta['key_id'], 'key_bits': meta['key_bits'],
            'pad': info['pad'], 'in': args.infile, 'out': args.outfile,
            'sec': round(dt, 5), 'tag_len': info['tag_len']
        }})
        print(f"Encrypted [{info['mode']}, AES-{meta['key_bits']}, pad={info['pad']}, tag={info['tag_len']}B] in {dt:.4f}s -> {args.outfile}")
    except Exception as e:
        logger.error('enc_fail', extra={'extra': {'mode': args.mode, 'in': args.infile, 'error': str(e)}})
        print('ENCRYPT ERROR:', e, file=sys.stderr)
        sys.exit(2)

def cmd_dec(args):
    km = KeyManager()
    try:
        meta, enc_key, mac_key = km.derive_keypair(args.label, args.password)
        aad = args.aad.encode('utf-8') if args.aad else None
        t0 = time.perf_counter()
        info = decrypt_file(
            args.infile, args.outfile, enc_key, mac_key,
            expected_mode=args.mode, aad=aad
        )
        dt = time.perf_counter() - t0
        logger.info('dec_ok', extra={'extra': {
            'mode': info['mode'], 'key_id': meta['key_id'],
            'in': args.infile, 'out': args.outfile, 'sec': round(dt, 5), 'bytes': info['bytes']
        }})
        print(f"Decrypted [{info['mode']}, {info['bytes']}B] in {dt:.4f}s -> {args.outfile}")
    except Exception as e:
        logger.error('dec_fail', extra={'extra': {'in': args.infile, 'error': str(e)}})
        print('DECRYPT SECURITY ALERT:', e, file=sys.stderr)
        sys.exit(2)

def cmd_bench(args):
    km = KeyManager()
    meta, enc_key, mac_key = km.derive_keypair(args.label, args.password)
    sizes = []
    for s in args.sizes:
        sl = s.lower()
        if sl.endswith('mb'):
            sizes.append(int(float(sl[:-2]) * 1024 * 1024))
        elif sl.endswith('kb'):
            sizes.append(int(float(sl[:-2]) * 1024))
        else:
            sizes.append(int(s))

    os.makedirs('outputs', exist_ok=True)
    raw_rows = []
    summary_rows = []

    for size in sizes:
        path = f'outputs/bench_{size}.bin'
        if not os.path.exists(path):
            with open(path, 'wb') as f:
                f.write(secrets.token_bytes(size))
        for mode in args.modes:
            enc_times, dec_times, cpu_times, peak_kbs = [], [], [], []
            all_ok = True
            for _ in range(args.repeat):
                enc_out = f'{path}.{mode}.enc'
                dec_out = f'{path}.{mode}.dec'
                tracemalloc.start()
                c0 = time.process_time()
                t0 = time.perf_counter()
                encrypt_file(path, enc_out, enc_key, mac_key, mode=mode)
                enc_dt = time.perf_counter() - t0

                t1 = time.perf_counter()
                try:
                    decrypt_file(enc_out, dec_out, enc_key, mac_key, expected_mode=mode)
                    ok = True
                except Exception:
                    ok = False
                    all_ok = False
                dec_dt = time.perf_counter() - t1
                cpu_dt = time.process_time() - c0
                _, peak_bytes = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                peak_kb = round(peak_bytes / 1024.0, 1)
                enc_times.append(enc_dt)
                dec_times.append(dec_dt)
                cpu_times.append(cpu_dt)
                peak_kbs.append(peak_kb)
                raw_rows.append((size, mode.upper(), round(enc_dt, 5), round(dec_dt, 5), round(cpu_dt, 5), peak_kb, ok))

            avg_enc = sum(enc_times) / len(enc_times)
            avg_dec = sum(dec_times) / len(dec_times)
            avg_cpu = sum(cpu_times) / len(cpu_times)
            max_ram = max(peak_kbs)
            mb = size / (1024 * 1024)
            enc_mbps = mb / avg_enc if avg_enc > 0 else 0.0
            dec_mbps = mb / avg_dec if avg_dec > 0 else 0.0
            summary_rows.append((f"{mb:.1f} MB", MODE_LABELS[mode], avg_enc, avg_dec, enc_mbps, dec_mbps, avg_cpu, max_ram, all_ok))

    with open('outputs/bench.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['size_bytes', 'mode', 'enc_sec', 'dec_sec', 'cpu_sec', 'peak_ram_kb', 'ok'])
        w.writerows(raw_rows)

    lines = [
        "| Розмір файлу | Режим AES | Enc (с) | Dec (с) | Enc (MB/с) | Dec (MB/с) | CPU (с) | Peak RAM (KB) | Статус |",
        "|---|---|---:|---:|---:|---:|---:|---:|:--:|"
    ]
    for sz_lbl, m_lbl, ae, ad, emb, dmb, acpu, mram, ok in summary_rows:
        lines.append(f"| {sz_lbl} | {m_lbl} | {ae:.4f} | {ad:.4f} | {emb:.1f} | {dmb:.1f} | {acpu:.4f} | {mram:.1f} | {'PASS' if ok else 'FAIL'} |")

    md_table = "\n".join(lines)
    with open('outputs/bench.md', 'w', encoding='utf-8') as f:
        f.write(md_table + "\n")
    logger.info('bench_done', extra={'extra': {'sizes': args.sizes, 'modes': args.modes, 'repeat': args.repeat}})
    print(md_table)
    print('\nSaved -> outputs/bench.csv, outputs/bench.md')

def repl(args):
    km = KeyManager()
    label = args.label or input('Key label: ').strip()
    password = args.password or input('Password: ').strip()
    meta, enc_key, mac_key = km.derive_keypair(label, password)
    mode = 'gcm'
    pad_scheme = 'pkcs7'
    aad_bytes = None
    print(f"AES-Lab Interactive Shell (key={label}, AES-{meta['key_bits']}). Commands: mode [gcm|cbc|ctr], pad [pkcs7|ansix923], aad [text|none], status, enc IN OUT, dec IN OUT, quit")
    while True:
        try:
            line = input(f"[{mode}|pad={pad_scheme}]> ").strip()
        except EOFError:
            break
        if not line:
            continue
        parts = line.split()
        cmd = parts[0].lower()
        if cmd in ('quit', 'exit'):
            break
        elif cmd == 'status':
            print(f"Active config -> mode={mode.upper()}, pad={pad_scheme.upper()}, key={label} (AES-{meta['key_bits']}), aad={aad_bytes.decode() if aad_bytes else 'None'}")
        elif cmd == 'mode' and len(parts) >= 2 and parts[1].lower() in SUPPORTED_MODES:
            mode = parts[1].lower()
            print(f"Switched mode -> {mode.upper()}")
        elif cmd == 'pad' and len(parts) >= 2 and parts[1].lower() in ('pkcs7', 'ansix923'):
            pad_scheme = parts[1].lower()
            print(f"Switched padding -> {pad_scheme.upper()}")
        elif cmd == 'aad' and len(parts) >= 2:
            aad_bytes = None if parts[1].lower() == 'none' else " ".join(parts[1:]).encode('utf-8')
            print(f"Updated AAD -> {aad_bytes.decode() if aad_bytes else 'None'}")
        elif cmd == 'enc' and len(parts) >= 3:
            info = encrypt_file(parts[1], parts[2], enc_key, mac_key, mode=mode, pad_scheme=pad_scheme, aad=aad_bytes)
            km.inc_use(meta['key_id'])
            logger.info('shell_enc', extra={'extra': {'mode': info['mode'], 'in': parts[1], 'out': parts[2]}})
            print(f"OK encrypted [{info['mode']}, pad={info['pad']}] -> {parts[2]}")
        elif cmd == 'dec' and len(parts) >= 3:
            try:
                info = decrypt_file(parts[1], parts[2], enc_key, mac_key, expected_mode=mode, aad=aad_bytes)
                logger.info('shell_dec', extra={'extra': {'mode': info['mode'], 'in': parts[1], 'out': parts[2]}})
                print(f"OK decrypted [{info['mode']}, {info['bytes']}B] -> {parts[2]}")
            except Exception as e:
                logger.error('shell_dec_fail', extra={'extra': {'in': parts[1], 'error': str(e)}})
                print('ERR:', e)
        else:
            print('Unknown command or invalid arguments')

def main():
    p = argparse.ArgumentParser(description='AES-Lab Symmetric Encryption CLI')
    sp = p.add_subparsers(dest='cmd', required=True)

    pk = sp.add_parser('key')
    pksp = pk.add_subparsers(dest='action', required=True)
    pk_new = pksp.add_parser('new')
    pk_new.add_argument('--label', required=True)
    pk_new.add_argument('--password', required=True)
    pk_new.add_argument('--key-bits', type=int, default=256, choices=[128, 192, 256])
    pksp.add_parser('list')

    pe = sp.add_parser('enc')
    pe.add_argument('--in', dest='infile', required=True)
    pe.add_argument('--out', dest='outfile', required=True)
    pe.add_argument('--mode', choices=['gcm', 'cbc', 'ctr'], default='gcm')
    pe.add_argument('--pad', choices=['pkcs7', 'ansix923'], default='pkcs7')
    pe.add_argument('--iv', help='Optional hex IV/Nonce')
    pe.add_argument('--block-bits', type=int, default=BLOCK_SIZE_BITS)
    pe.add_argument('--label', required=True)
    pe.add_argument('--password', required=True)
    pe.add_argument('--aad')

    pd = sp.add_parser('dec')
    pd.add_argument('--in', dest='infile', required=True)
    pd.add_argument('--out', dest='outfile', required=True)
    pd.add_argument('--mode', choices=['gcm', 'cbc', 'ctr'])
    pd.add_argument('--label', required=True)
    pd.add_argument('--password', required=True)
    pd.add_argument('--aad')

    pb = sp.add_parser('bench')
    pb.add_argument('--sizes', nargs='+', default=['1MB', '5MB', '10MB'])
    pb.add_argument('--modes', nargs='+', choices=['gcm', 'cbc', 'ctr'], default=['gcm', 'cbc', 'ctr'])
    pb.add_argument('--repeat', type=int, default=3)
    pb.add_argument('--label', required=True)
    pb.add_argument('--password', required=True)

    ps = sp.add_parser('shell')
    ps.add_argument('--label')
    ps.add_argument('--password')

    args = p.parse_args()
    if args.cmd == 'key':
        cmd_key(args)
    elif args.cmd == 'enc':
        cmd_enc(args)
    elif args.cmd == 'dec':
        cmd_dec(args)
    elif args.cmd == 'bench':
        cmd_bench(args)
    elif args.cmd == 'shell':
        repl(args)

if __name__ == '__main__':
    main()
