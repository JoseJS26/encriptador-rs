# ENCRIPTADOR-RS

<p align="center">
    <img src="https://img.shields.io/badge/rust-1.70+-orange.svg" alt="Rust Version" />
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License" />
    <img src="https://img.shields.io/badge/platform-linux-ff69b4.svg" alt="Platform" />
    <img src="https://img.shields.io/github/stars/JoseJS26/encriptador-rs?style=social" alt="Stars" />
</p>

<p align="center">
    <b> Encriptador Profesional para Linux escrito en Rust </b>
</p>

<p align="center">
  <i>AES-256-GCM • Argon2id • Multi-threading • Compresión • CLI profesional</i>
</p>

---

## 📸 Vista Previa

```bash
$ encriptador encriptar documento.pdf --comprimir --verificar

🔐 INICIANDO ENCRIPTACIÓN
══════════════════════════════
📦 Archivos a encriptar: 1
🔑 Algoritmo: AES-256-GCM
🗜️  Compresión: Sí (nivel 6)

⠸ [00:02] [████████████████████] 1/1 (2s) documento.pdf
✓ documento.pdf.encrypted.z

✅ Encriptación completada en 2.3s
