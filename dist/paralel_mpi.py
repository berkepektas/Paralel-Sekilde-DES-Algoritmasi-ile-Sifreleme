from mpi4py import MPI
from array import array
import os, sys, hashlib, struct, time

CHUNK_BYTES = 16 * 1024 * 1024  # Dosyayı bloklar halinde alıyoruz

#Toplam byte ı belirledğimiz proses arasında eşit dağıtabilmek için fonksiyon
def split_counts(total: int, size: int):
    base = total // size #Alınacak min miktar
    rem = total % size #Kalan byte sayısı
    counts = [base + (1 if r < rem else 0) for r in range(size)] #porsesin alacağı byte sayısı
    displs = [0] * size
    s = 0
    for i in range(size):
        displs[i] = s
        s += counts[i]
    return counts, displs
#Paroladan türetilen 32 byte lık anhtar
def keystream(key: bytes, nonce: bytes, length: int, counter0: int):
    out = bytearray()
    counter = counter0
    while len(out) < length:
        out.extend(hashlib.sha256(key + nonce + struct.pack("<Q", counter)).digest())
        counter += 1
    return bytes(out[:length])
#xor ile şifreleme
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
#Btiiğinde çıktı vermesi için yoksa sürekli çıktı verir
def usage():
    if MPI.COMM_WORLD.rank == 0:
        print("Kullanim:")
        print("  mpiexec -n 8 python paralel_mpi.py encrypt_inplace_rename <infile> <password>")
        print("  mpiexec -n 8 python paralel_mpi.py decrypt_inplace_rename <infile.enc> <password>")
        print("\nOrnek:")
        print('  mpiexec -n 8 python paralel_mpi.py encrypt_inplace_rename "timer.mp4" "sifrem123"')
        print('  mpiexec -n 8 python paralel_mpi.py decrypt_inplace_rename "timer.mp4.enc" "sifrem123"')
#MPI ile bölme ve proses işlemleri
def main():
    comm = MPI.COMM_WORLD
    rank = comm.rank
    size = comm.size

    if len(sys.argv) < 4:
        usage()
        sys.exit(1)

    mode = sys.argv[1].lower().strip()
    infile = sys.argv[2]
    password = sys.argv[3].encode("utf-8")

    if mode not in ("encrypt_inplace_rename", "decrypt_inplace_rename"):
        usage()
        sys.exit(1)

    base_mode = "encrypt" if mode == "encrypt_inplace_rename" else "decrypt"

    #Dosyayı şifreledikten sonra .enc çözdükten sonra siliyor
    if base_mode == "encrypt":
        final_out = infile + ".enc"
    else:
        if infile.lower().endswith(".enc"):
            final_out = infile[:-4]  # .enc kaldır
        else:
            final_out = infile + ".dec"

    #Şifrelemeyi yapabilmek için önce yedek dosya oluşturuyor bitince siliyor
    tmp_out = final_out + ".tmp_mpi"
    #Porseslerin aynı anda başlaması için 
    t0 = time.perf_counter() if rank == 0 else None
    comm.Barrier()
    #Parolayı direkt kullanıp güvenlik açığı oluşturmak yerine SHA256 ile 32 byte anahtar üretiyor
    key = hashlib.sha256(password).digest()
    #Okuma yazma 
    nonce = None
    fin = None
    fout = None
    #Rastgele 16 byte oluşturuyor dosya başına yazıyor çözerken ilk 16 byte ı okumayıp sonrasını okuyor(çözülemesin diye)
    if rank == 0:
        if base_mode == "encrypt":
            nonce = os.urandom(16)
        else:
            with open(infile, "rb") as ftmp:
                nonce = ftmp.read(16)
            if nonce is None or len(nonce) != 16:
                raise ValueError("Girdi bozuk: nonce yok/eksik (16 byte).")

        fin = open(infile, "rb")
        fout = open(tmp_out, "wb")

        if base_mode == "encrypt":
            fout.write(nonce)
        else:
            # decrypt: inputtaki nonce'u atla
            fin.seek(16, os.SEEK_SET)
    #Her proses aynı nonce ı bilmesi lazım yoksa dosya düzgün şifrelenmez bozulur
    nonce = comm.bcast(nonce, root=0)
    #İşlenen byte ı sayıyor 
    global_offset = 0
    #Dosyayı bölüm bölüm işliyor 
    while True:
        if rank == 0:
            chunk = fin.read(CHUNK_BYTES)
            chunk_len = len(chunk)
        else:
            chunk = None
            chunk_len = 0
        #Chunk boyutunu bildiriyor
        chunk_len = comm.bcast(chunk_len, root=0)
        if chunk_len == 0:
            break
        #Chunkları proseslere paylaştırıyor
        counts, displs = split_counts(chunk_len, size)
        counts_a = array("i", counts)
        displs_a = array("i", displs)

        local_n = counts[rank]
        local_buf = bytearray(local_n)

        if rank == 0:
            comm.Scatterv([chunk, counts_a, displs_a, MPI.BYTE], local_buf, root=0)
        else:
            comm.Scatterv([None, counts_a, displs_a, MPI.BYTE], local_buf, root=0)

        my_global_offset = global_offset + displs[rank]
        counter0 = my_global_offset // 32
        shift = my_global_offset % 32

        if local_n == 0:
            enc_local = b""
        else:
            if shift == 0:
                ks = keystream(key, nonce, local_n, counter0)
            else:
                ks = keystream(key, nonce, local_n + shift, counter0)[shift:]
            enc_local = xor_bytes(bytes(local_buf), ks)
        #Tüm çıktıları rank=0 da (çıktıda) birleştiriyor
        out_chunk = bytearray(chunk_len) if rank == 0 else None
        if rank == 0:
            comm.Gatherv(enc_local, [out_chunk, counts_a, displs_a, MPI.BYTE], root=0)
        else:
            comm.Gatherv(enc_local, None, root=0)

        if rank == 0:
            fout.write(out_chunk)

        global_offset += chunk_len
    #Tüm proseslerin işi bitirmesi
    comm.Barrier()

    if rank == 0:
        fin.close()
        fout.close()

        #Oluşan yedek dosyayı sil ana dosyayı değiştir
        os.replace(tmp_out, final_out)
        try:
            os.remove(infile)
        except Exception:
            
            pass
        #rank=0 (çıktı) sonucu kaç sn sürdü kaç proses kulanıldı
        elapsed = time.perf_counter() - t0
        print(f"[OK] {mode.upper()} bitti. Proses={size} Sure={elapsed:.3f} sn")
        print(f" - Giris (silindi): {infile}")
        print(f" - Cikti: {final_out}")

if __name__ == "__main__":
    main()
