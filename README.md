
Kompresi service menggunakan metode : Lz-string
Enkripsi menggunakan metode : AES 256 (mode CBC) - SHA256 dan key enkripsi: consid + conspwd + timestamp request (concatenate string)

Langkah proses dalam melakukan decrypt data response sebagai berikut :
1. Dekripsi : AES 256 (mode CBC) - SHA256
2. Dekompresi : Lz-string (decompressFromEncodedURIComponent)
