# Cyber-Jcode

Klasik terminal menüsüyle çalışan, Jcode'un gerçek araç ve model motorunu
kullanan bağımsız TryHackMe/CTF lab arayüzü.

```bash
cyber-jcode
```

Açılışta ASCII banner ve numaralı menü görünür. `1` ile hedefini ayarla;
`2` servis keşfi, `3` web keşfi, `4` zafiyet inceleme, `5` flag arama,
`6` yerel dosya inceleme çalıştırır. Menüde olmayan bir görev için aynı
`cyber >` satırına doğrudan metin yaz.

Araçlar arka planda çalışır. Araç çıktıları ve en fazla dört kısa bulgu işin
sonunda gösterilir. Sohbet, planlama, düşünce ve akış metinleri gösterilmez.
Flaglar yalnızca araç çıktısında gözlemlenmişlerse `[FLAG]` olarak etiketlenir.

`menu` menüyü, `sonuc` son sonucu gösterir. `kaydet`, tam araç çıktılarının
bulunduğu yerel JSON dosyasının yolunu verir. `temizle` ekranı temizler.
`9` yeni oturum açar; `0` çıkar. İşlem sırasında `Ctrl+C` motoru durdurur ve
menüye döner. Hedef değişince önceki hedefin oturumu kullanılmaz.

`8` ile sağlayıcı/model seçimi, bağlantı kontrolü, sağlayıcı girişi ve model
listesi açılır. Model listesi Jcode'un sağlayıcı keşfinden alınır.

```bash
cyber-jcode --check
cyber-jcode --target 10.10.10.10
cyber-jcode --run 'Bu dosyayı incele: /tmp/lab-notes.txt'
cyber-jcode --model MODEL_ADI
cyber-jcode --full-output
```

Kurulum:

```bash
cd ~/cyber-jcode
python3 cyber/install.py
```

Motor, bu depodan `target/selfdev/jcode` olarak derlenir. Kurulum yalnızca
`~/.local/bin/cyber-jcode` bağlantısını oluşturur. Bu dizin PATH'te yoksa
`sudo python3 cyber/install.py --link-system` ayrıca
`/usr/local/bin/cyber-jcode` bağlantısını oluşturur; mevcut bir komutu ezmez.
İlk kurulumda mevcut model
ayarları ve kimlik bilgileri özel izinlerle **kopyalanır**; sonraki kurulumlar
bu kopyaları ezmez. `~/.local/bin/jcode` ve `~/.jcode` değiştirilmez.

Cyber-Jcode verileri `~/.cyber-jcode` altında tutulur: `engine` model ayarları
ve Jcode oturumları, `run` özel soket, `labs` lab çalışma klasörleri, `results`
araç çıktıları ve kısa sonuçlar. Özel bir lab klasörü için `--cwd PATH` kullan.
Özel veri klasörü için `CYBER_JCODE_HOME` kullanılabilir. Kaynak motorunun
oturum kayıtları arka planda kalır; ön yüz sonuç kayıtlarına sohbet/düşünce
akışı yazılmaz. Gerçek ana dizin değişkeni değiştirilmez.

Kontroller:

```bash
python3 -m unittest cyber.test_console -v
python3 cyber/install.py --verify-original
cyber-jcode --check
```
